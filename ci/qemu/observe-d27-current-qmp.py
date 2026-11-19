#!/usr/bin/env python3
"""Take one read-only live QMP snapshot without stopping or steering the VM."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import socket
import sys
import time

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'ci/qemu'))
from d27_user_memory import read_kernel_memory,kernel_pointer_view


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--threads',action='store_true',help='Read live UI threads using actual native kernel and task page tables')
    a=p.parse_args();run=a.run.resolve();a.out.mkdir(parents=True,exist_ok=False)
    candidates=[]
    for item in Path('/proc').iterdir():
        if not item.name.isdecimal():continue
        try:args=(item/'cmdline').read_bytes().split(b'\0')
        except (OSError,PermissionError):continue
        if not args or not args[0].endswith(b'qemu-system-aarch64'):continue
        if not any(('fat:'+str(run/'esp')).encode() in value for value in args):continue
        try:at=args.index(b'-qmp');target=args[at+1].decode().split('unix:',1)[1].split(',',1)[0]
        except (ValueError,IndexError):continue
        candidates.append((int(item.name),target))
    if len(candidates)!=1:raise ValueError('Require exactly the requested live guest')
    pid,target=candidates[0]
    record=dict(qemu_pid=pid,qmp_socket=target,read_only=True,guest_stopped=False,device_operations=False,
                snapshot_consistency='live/non-atomic',timestamp=time.time(),
                limits='Running-guest samples may race task/process transitions; owner mismatches do not prove a guest bug')
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
        sock.settimeout(20);sock.connect(target);f=sock.makefile('rwb',buffering=0);f.readline()
        def qmp(command,**args):
            if command not in ('qmp_capabilities','human-monitor-command','pmemsave','query-status','screendump'):raise ValueError('Read-only QMP commands only')
            if command=='human-monitor-command' and args.get('command-line') not in ('info registers','info registers -a'):raise ValueError('Register reads only')
            f.write((json.dumps(dict(execute=command,arguments=args))+'\n').encode())
            while True:
                result=json.loads(f.readline())
                if 'error' in result:raise RuntimeError(str(result['error']))
                if 'return' in result:return result['return']
        qmp('qmp_capabilities');record['status']=qmp('query-status')
        hmp=qmp('human-monitor-command',**{'command-line':'info registers -a'})
        (a.out/'registers.txt').write_text(hmp)
        registers={key:int(value,16) for key,value in re.findall(r'\b(TCR_EL1|TTBR0_EL1|TTBR1_EL1|TPIDR_EL1|CNTFRQ_EL0|PC|SP)\s*=\s*([0-9a-fA-F]+)',hmp)}
        record['registers']={key:hex(value) for key,value in registers.items()}
        scratch=a.out/'physical.bin';physical_mode=False
        def physical(address,size):
            qmp('pmemsave',val=address,size=size,filename=str(scratch))
            raw=scratch.read_bytes()
            if len(raw)!=size:raise RuntimeError('Physical read length differs')
            return raw
        if not {'TCR_EL1','TTBR1_EL1'}<=registers.keys():
            # QMP omits architectural translation registers. Read the live
            # kernel's own table root and immutable native geometry through the
            # exact loader-reported linear load addresses. Do not invent a TCR
            # sample or pass a reconstructed register to the stopped helpers.
            inputs=json.loads((run/'inputs.json').read_text());names=json.loads((run/'symbols.json').read_text())
            uart=(run/'observation/gdb-uart.log').read_text()
            loaded=re.search(r'kernel +va 0x([0-9A-Fa-f]+) +pa 0x([0-9A-Fa-f]+)',uart)
            if not loaded:raise ValueError('Actual kernel load mapping unavailable')
            kernel_va,kernel_pa=(int(v,16) for v in loaded.groups())
            def boot_read(address,size):return physical(kernel_pa+address-kernel_va,size)
            root=int.from_bytes(boot_read(int(names['_cpu_ttep'],16),8),'little')
            attr=int.from_bytes(boot_read(int(names['_native_pt_attr'],16),8),'little')
            raw=boot_read(attr,120);first=int.from_bytes(raw[64:68],'little');last=int.from_bytes(raw[72:76],'little')
            shift=int.from_bytes(raw[104:112],'little');mask=int.from_bytes(raw[112:120],'little')
            bits=mask.bit_length()
            if shift!=12 or not 25<=bits<=48 or mask!=(1<<bits)-1 or not 0<=first<=last==3:
                raise ValueError('Native live page geometry is not the selected bounded 4K shape')
            root_alignment=1<<(bits-(12+9*(3-first))+3)
            root&=0x0000ffffffffffff&~(root_alignment-1)
            record['kernel_table_geometry']=dict(source='Actual loaded cpu_ttep/native_pt_attr; no architectural TCR sample',
                root=hex(root),root_level=first,last_level=last,page_shift=shift,address_bits=bits,va_mask=hex(mask))
            def canonical(value):return (value&mask)|(((1<<64)-1)^mask) if value else 0
            def read_live(address,size):
                data=b''
                while len(data)<size:
                    va=address+len(data);table=root
                    for level in range(first,last+1):
                        s=12+9*(3-level);count_mask=(1<<(bits-s))-1 if level==first else 511
                        descriptor=int.from_bytes(physical(table+((va>>s)&count_mask)*8,8),'little')
                        if not descriptor&1:raise ValueError('Live kernel page is unmapped')
                        if level<3 and descriptor&3==3:table=descriptor&0x0000fffffffff000;continue
                        if (level==3 and descriptor&3!=3) or (level<3 and descriptor&3!=1):raise ValueError('Invalid live leaf')
                        pa=(descriptor&0x0000fffffffff000&~((1<<s)-1))|(va&((1<<s)-1));break
                    count=min(size-len(data),4096-(va&4095));data+=physical(pa,count)
                return data
            def liveword(address,size=8):return int.from_bytes(read_live(address,size),'little')
            values={}
            for name,field in inputs['fields'].items():
                try:values[name]=liveword(int(field['address'],16),field['bytes'])
                except (ValueError,RuntimeError) as error:values[name]=dict(error=str(error))
            for name in ('_native_ram_block_bytes','_native_ram_block_resident_bytes',
                         '_native_ram_block_reads','_native_ram_block_writes','_native_ram_block_failures'):
                if name in names:
                    try:values[name]=liveword(int(names[name],16),8)
                    except (ValueError,RuntimeError) as error:values[name]=dict(error=str(error))
            record['values']=values;layout=json.loads((run/'process-layout.json').read_text())['process_layout']
            entries=[];node=canonical(liveword(int(names['_allproc'],16)));seen=set()
            while node and node not in seen and len(entries)<512:
                seen.add(node)
                try:
                    entries.append(dict(address=hex(node),pid=liveword(node+layout['pid'],4),state=liveword(node+100,1),
                        name=read_live(node+layout['comm'],17).split(b'\0')[0].decode('utf-8','replace')))
                    node=canonical(liveword(node))
                except (ValueError,RuntimeError) as error:record['process_list_error']=str(error);break
            record['processes']=entries
            if a.threads:
                try:
                    from d27_user_memory import read_native_pages
                    from d27_thread_snapshot import capture_with_readers
                    user_attr=canonical(liveword(int(names['_native_user_pt_attr'],16)))
                    user_raw=read_live(user_attr,120)
                    user_first=int.from_bytes(user_raw[64:68],'little')
                    user_shift=int.from_bytes(user_raw[104:112],'little')
                    user_mask=int.from_bytes(user_raw[112:120],'little');user_bits=user_mask.bit_length()
                    if user_shift!=12 or user_mask!=(1<<user_bits)-1:raise ValueError('Actual native user geometry differs')
                    record['user_table_geometry']=dict(source='Actual native_user_pt_attr, not a TCR sample',
                        root_level=user_first,address_bits=user_bits,page_shift=user_shift)
                    def read_user(root,address,size):
                        return read_native_pages(physical,root,address,size,bits=user_bits,first_level=user_first)
                    plan=json.loads((run/'process-layout.json').read_text())
                    record['ui_thread_snapshots']=capture_with_readers(entries,plan,read_live,canonical,read_user,
                        user_bits=user_bits,root_level=user_first,consistency=record['snapshot_consistency'])
                except (ValueError,RuntimeError) as error:record['thread_snapshot_error']=str(error)
            try:
                from d27_mount_lock import capture
                record['mount_list_mutex']=capture(read_live,names,layout,va_bits=bits,consistency=record['snapshot_consistency'])
            except (ValueError,RuntimeError) as error:record['mount_list_mutex_error']=str(error)
            try:
                from d27_mount_lock import capture_thread
                loop=canonical(liveword(int(names['__ZL13gIOPMWorkLoop'],16)))
                pm_thread=canonical(liveword(loop+48))
                record['pm_workloop_thread']=capture_thread(read_live,names,layout,pm_thread,va_bits=bits,consistency=record['snapshot_consistency'])
                record['pm_workloop_thread']['workloop']=hex(loop)
            except (ValueError,RuntimeError) as error:record['pm_workloop_thread_error']=str(error)
            try:
                pointer=canonical(liveword(int(names['_msgbufp'],16)));header=read_live(pointer,24)
                magic,size,write,index=struct_unpack(header[:16]);pointer=canonical(int.from_bytes(header[16:24],'little'))
                if magic!=0x63061 or not 0<size<=1024**2 or not 0<=write<size:raise ValueError('Live msgbuf not bounded')
                data=read_live(pointer,size);(a.out/'kernel.log').write_bytes((data[write:]+data[:write]).replace(b'\0',b''))
            except (ValueError,RuntimeError) as error:record['kernel_log_error']=str(error)
            try:qmp('screendump',filename=str((a.out/'screen.png').resolve()),format='png')
            except RuntimeError as error:record['screen_error']=str(error)
            scratch.unlink(missing_ok=True);record['capture_finished']=time.time()
            (a.out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
            print(json.dumps(dict(process_count=len(entries),ui=[p for p in entries if p['name'] in ('SpringBoard','backboardd','launchd')],
                values={key:value for key,value in values.items() if key in ('_native_legacy_stage','_native_legacy_frame_count','_native_legacy_pm_stage','_native_legacy_pm_callbacks','_native_virtio_read_requests','_native_virtio_read_failures','_native_owner_data_stage','_native_owner_cache_stage')},
                snapshot_consistency=record['snapshot_consistency'],kernel_log_error=record.get('kernel_log_error')),indent=2))
            return
        def packet(request):
            nonlocal physical_mode
            if request=='qqemu.PhyMemMode':return '1' if physical_mode else '0'
            if request.startswith('Qqemu.PhyMemMode:'):physical_mode=request.endswith('1');return 'OK'
            if not request.startswith('m'):raise ValueError('Memory reads only')
            address,size=(int(v,16) for v in request[1:].split(','))
            if not physical_mode:raise ValueError('Use explicit physical translation')
            return physical(address,size).hex()
        def read(address,size):
            response=read_kernel_memory(packet,registers,address,size)
            data=bytes.fromhex(response['bytes'])
            if len(data)!=size:raise ValueError('Actual kernel field is not mapped')
            return data
        def word(address,size=8):return int.from_bytes(read(address,size),'little')
        def kp(value):return kernel_pointer_view(value,registers['TCR_EL1']) if value else 0
        inputs=json.loads((run/'inputs.json').read_text());names=json.loads((run/'symbols.json').read_text())
        values={}
        for name,field in inputs['fields'].items():
            try:values[name]=word(int(field['address'],16),field['bytes'])
            except (ValueError,RuntimeError) as error:values[name]=dict(error=str(error))
        record['values']=values
        layout=json.loads((run/'process-layout.json').read_text())['process_layout']
        entries=[];node=kp(word(int(names['_allproc'],16)));seen=set()
        while node and node not in seen and len(entries)<512:
            seen.add(node)
            entries.append(dict(address=hex(node),pid=word(node+layout['pid'],4),state=word(node+layout['stat'],1),
                                name=read(node+layout['comm'],17).split(b'\0')[0].decode('utf-8','replace')))
            node=kp(word(node+layout['list']))
        record['processes']=entries
        try:
            from d27_display_pm import capture_display_pm
            record['display_pm']=capture_display_pm(packet,registers,int(names['_native_legacy_object'],16),json.loads((run/'pm-plan.json').read_text()))
        except (ValueError,RuntimeError) as error:record['display_pm_error']=str(error)
        plan_path=Path('/mnt/e/UniXNU-sheng27-sony-20261113/tmp/qemu-process-observer-002/plan.json')
        if plan_path.exists():
            try:
                plan=json.loads(plan_path.read_text());plan['native_sha256']=inputs['native_sha256'];plan['thread_snapshot_native_user_pt_attr']=names['_native_user_pt_attr']
                for item in plan['object_inputs']:
                    with Path(item['object']).open('rb') as fobj:
                        if hashlib.file_digest(fobj,'sha256').hexdigest()!=item['sha256']:raise ValueError('Current thread object differs')
                from d27_thread_snapshot import capture
                record['ui_thread_snapshots']=capture(packet,entries,plan,registers)
            except (ValueError,RuntimeError) as error:record['thread_snapshot_error']=str(error)
        # Exact msgbuf header is four ints and a pointer in the linked source.
        try:
            buf=kp(word(int(names['_msgbufp'],16)));header=read(buf,24)
            magic,size,write,index=struct_unpack(header[:16])
            pointer=kp(int.from_bytes(header[16:24],'little'))
            if not 0<size<=1024**2 or not 0<=write<size:raise ValueError('Message ring is unbounded')
            data=b''
            for offset in range(0,size,4096):data+=read(pointer+offset,min(4096,size-offset))
            (a.out/'kernel.log').write_bytes((data[write:]+data[:write]).replace(b'\0',b''))
        except (ValueError,RuntimeError) as error:record['kernel_log_error']=str(error)
        scratch.unlink(missing_ok=True)
    (a.out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({k:v for k,v in record.items() if k not in ('ui_thread_snapshots','display_pm','values')},indent=2))
    print(json.dumps(record['values'],indent=2))

def struct_unpack(raw):
    import struct
    return struct.unpack('<4I',raw)

if __name__=='__main__':main()
