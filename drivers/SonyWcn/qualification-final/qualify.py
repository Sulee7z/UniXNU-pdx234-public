#!/usr/bin/env python3
"""Read-only ABI/startup qualification of frozen Sony radio002 objects.

All generated reports/copies stay below this new directory. No compiler,
linker, firmware tool or device operation is used. Frozen sources/objects and
their receipts are never changed. A final strict kernel can be audited later.
"""
from __future__ import annotations

import argparse
import bisect
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')
BUILD = BASE / 'sony-wcn-067-002'
CACHE = ROOT / '.cache/iphone14-ios27/ipsw/24A446/kernelcache.decompressed'
ORIGINAL = 'c28f4fc9b83cde00087e81f890c82d566b9e98b5ac228dfecd83afdf34070445'
BOARD_SHA = '6cf62fdf57c7ffa34985857e37f4e57ebdcafe7f8f3ba482d8033da50bfdf566'


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load(path):
    return json.loads(Path(path).read_text())


def command(args):
    r = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=120)
    if r.returncode:
        raise RuntimeError(r.stderr[-6000:])
    return r.stdout


def pac(word):
    return dict(auth=word >> 63, key=(word >> 49) & 3,
                diversity=(word >> 32) & 0xffff, address_diversity=(word >> 48) & 1)


class Object:
    def __init__(self, path):
        self.path = Path(path)
        self.raw = raw = self.path.read_bytes()
        if struct.unpack_from('<I', raw)[0] != 0xfeedfacf:
            raise ValueError('Expected arm64e Mach-O: ' + str(path))
        self.sections, self.symbols = [], []
        at = 32
        for _ in range(struct.unpack_from('<I', raw, 16)[0]):
            kind, size = struct.unpack_from('<II', raw, at)
            if kind == 0x19:
                for i in range(struct.unpack_from('<I', raw, at + 64)[0]):
                    s = at + 72 + 80 * i
                    va, length, offset, align, rel, count, flags = struct.unpack_from('<QQIIIII', raw, s + 32)
                    self.sections.append(dict(name=raw[s:s+16].rstrip(b'\0').decode(),
                                              segment=raw[s+16:s+32].rstrip(b'\0').decode(),
                                              va=va, size=length, offset=offset, align=align,
                                              reloc=rel, count=count, flags=flags))
            elif kind == 2:
                sy, count, st, _ = struct.unpack_from('<4I', raw, at + 8)
                for i in range(count):
                    ix, typ, section, desc, va = struct.unpack_from('<IBBHQ', raw, sy + 16 * i)
                    self.symbols.append(dict(name=raw[st+ix:raw.index(b'\0', st+ix)].decode(),
                                             type=typ, section=section, desc=desc, va=va))
            at += size
        self.names = {s['name']: s for s in self.symbols}
        self.relocations = {}
        for sec in self.sections:
            for i in range(sec['count']):
                off, bits = struct.unpack_from('<II', raw, sec['reloc'] + 8*i)
                extern, kind, length, pcrel = (bits >> 27) & 1, bits >> 28, (bits >> 25) & 3, (bits >> 24) & 1
                symbol = self.symbols[bits & 0xffffff]['name'] if extern else '@section' + str(bits & 0xffffff)
                word = struct.unpack_from('<Q', raw, sec['offset'] + off)[0] if length == 3 else None
                self.relocations[sec['va'] + off] = dict(symbol=symbol, type=kind, length=length,
                                                        external=extern, pcrel=pcrel, word=word)

    def read(self, va, size):
        sec = next(s for s in self.sections if s['va'] <= va and va + size <= s['va'] + s['size'])
        if sec['flags'] & 255 in (1, 12):
            return bytes(size)
        off = sec['offset'] + va - sec['va']
        return self.raw[off:off+size]

    def table(self, name):
        symbol = self.names[name]
        start = symbol['va'] + 16
        rows = []
        while (r := self.relocations.get(start + 8*len(rows))) and r['type'] == 11 and r['length'] == 3:
            rows.append(dict(slot=len(rows), symbol=r['symbol'], site=hex(start+8*len(rows)), raw_word=hex(r['word']), **pac(r['word'])))
        return dict(symbol=name, symbol_va=hex(symbol['va']), address_point=hex(start),
                    prefix_bytes=16, slots=len(rows), method_bytes=8*len(rows), total_bytes=16+8*len(rows), rows=rows)


def disassemble(image, va, size):
    raw = image.read(va, size)
    text = '\n'.join(' '.join(f'0x{x:02x}' for x in raw[i:i+4]) for i in range(0, len(raw), 4))
    r = subprocess.run(['llvm-mc-23', '--disassemble', '--triple=aarch64', '--mattr=+v8.3a,+pauth,+lse'],
                       input=text, capture_output=True, text=True, check=True, timeout=30)
    return r.stdout


def code_for(image, name, names=None):
    if names is None:
        names = {n: va for va, group in image.symbols().items() for n in group}
    at = names[name]
    starts = image.function_starts()
    end = starts[bisect.bisect_right(starts, at)]
    return at, end-at, disassemble(image, at, end-at)


def original_classes(kc, out):
    from kc_image import scan
    fixups = kc.fixups()
    classes = {
        'IOService': dict(vptr=0xfffffff007c5cfc8, meta=0xfffffff00ad58758, slots=168, instance_bytes=136,
                          name=0xfffffff0070afd69,constructor=0xfffffff00a8ec484,constructor_bytes=64,
                          superclass_meta=0xfffffff00ad56728,metaclass_vptr=0xfffffff007c1c450),
        'IOUserClient': dict(vptr=0xfffffff007c2e3f0, meta=0xfffffff00ad58160, slots=186, instance_bytes=216,
                             name=0xfffffff0070b4cdf, constructor=0xfffffff00a964ae8, constructor_bytes=68,
                             superclass_meta=0xfffffff00ad58758,metaclass_vptr=0xfffffff007c2bae0),
    }
    result = {}
    for classname, c in classes.items():
        start = c['vptr']
        rows = []
        while (r := fixups.get(start+8*len(rows))) and r[1] == 1 and r[2] == 0 and r[4] == 1:
            rows.append(dict(slot=len(rows), target=hex(r[0]), auth=r[1], key=r[2], diversity=r[3], address_diversity=r[4]))
        if len(rows) != c['slots']:
            raise ValueError('Original class table extent changed: ' + classname)
        getter = int(rows[7]['target'], 16)
        if not any(target == c['meta'] for site, target, kind in scan(kc.read(getter, 16), getter)[1]):
            raise ValueError('Original getMetaClass identity changed: ' + classname)
        identity = dict(classname=classname, vptr=hex(start), metaclass=hex(c['meta']),
                        getter=hex(getter), getter_sha256=hashlib.sha256(kc.read(getter,16)).hexdigest(),
                        slots=len(rows), method_bytes=8*len(rows), instance_bytes=c['instance_bytes'], rows=rows)
        if 'name' in c:
            if kc.read(c['name'],len(classname)+1) != classname.encode()+b'\0':
                raise ValueError('Original class name differs')
            refs = scan(kc.read(c['constructor'],c['constructor_bytes']),c['constructor'])[1]
            if not all(any(target == want for _, target, _ in refs) for want in (c['name'],c['meta'],c['superclass_meta'])):
                raise ValueError('Original named IOUserClient/super constructor differs')
            asm = disassemble(kc,c['constructor'],c['constructor_bytes'])
            if not re.search(r'mov\s+w3, #'+str(c['instance_bytes'])+r'\b',asm):
                raise ValueError('Original allocation size differs: '+classname)
            if 'pacda' not in asm or '#52641' not in asm:
                raise ValueError('Original vptr DA/cda1 schema differs')
            (out/('original-'+classname+'-constructor.asm')).write_text(asm)
            identity.update(name_address=hex(c['name']),constructor=hex(c['constructor']),
                            constructor_bytes=c['constructor_bytes'],constructor_sha256=hashlib.sha256(kc.read(c['constructor'],c['constructor_bytes'])).hexdigest(),
                            vptr_schema=dict(key='DA',diversity='0xcda1',address_diversity=1))
        meta_rows=[]
        for i in range(14):
            r=fixups.get(c['metaclass_vptr']+8*i)
            if not r or r[1:3]!=(1,0) or r[4]!=1:
                raise ValueError('Original metaclass PAC invalid')
            meta_rows.append(dict(slot=i,target=hex(r[0]),auth=r[1],key=r[2],diversity=r[3],address_diversity=r[4]))
        if fixups.get(c['metaclass_vptr']+14*8):
            raise ValueError('Original metaclass extends beyond14')
        identity['metaclass_table']=dict(vptr=hex(c['metaclass_vptr']),slots=14,method_bytes=112,total_bytes=128,rows=meta_rows)
        result[classname] = identity
    return result


def audit_tables(out, originals, object_path):
    obj = Object(object_path)
    objects = {}
    for classname, parent in [('IO80211Controller','IOService'),('IONetworkInterface','IOService'),
                              ('IO80211Interface','IOService'),('IONetworkStack','IOService'),
                              ('IONetworkStackUserClient','IOUserClient')]:
        table = obj.table('__ZTV'+str(len(classname))+classname)
        orig = originals[parent]
        if table['slots'] != orig['slots']:
            raise ValueError('Generated table extent differs: ' + classname)
        for a,b in zip(table['rows'],orig['rows']):
            if any(a[k]!=b[k] for k in ('auth','key','diversity','address_diversity')):
                raise ValueError(f'Generated PAC schema differs {classname} slot{a["slot"]}')
        dwarf = command(['llvm-dwarfdump-23','--debug-info','--name='+classname,'--show-children',obj.path])
        (out/(classname+'.dwarf.txt')).write_text(dwarf)
        size = re.search(r'DW_AT_byte_size\s+\((0x[0-9a-f]+)\)',dwarf)
        if not size or int(size[1],16)!=orig['instance_bytes']:
            raise ValueError('Generated instance extent differs: '+classname)
        overrides = [r for r in table['rows'] if r['symbol'].startswith('__ZN'+str(len(classname))+classname) or
                     r['symbol'].startswith('__ZNK'+str(len(classname))+classname)]
        table.update(classname=classname,original_base=parent,instance_bytes=int(size[1],16),
                     all_pac_slots_match=True,overrides=overrides)
        objects[classname] = table
    # MetaClass tables are also compiler-generated authenticated virtual tables.
    metaclasses = {}
    for classname in objects:
        name='__ZTVN'+str(len(classname))+classname+'9MetaClassE'
        table=obj.table(name)
        parent=objects[classname]['original_base']
        if table['slots']!=14 or any(any(a[k]!=b[k] for k in ('auth','key','diversity','address_diversity'))
                                     for a,b in zip(table['rows'],originals[parent]['metaclass_table']['rows'])):
            raise ValueError('Generated metaclass PAC differs: '+classname)
        table.update(classname=classname+'::MetaClass',all_pac_slots_match=True,instance_bytes=40)
        metaclasses[classname] = table
    (out/'compiled-tables.json').write_text(json.dumps(dict(classes=objects,metaclasses=metaclasses),indent=2)+'\n')
    return objects,metaclasses


def startup_object(out):
    obj=Object(BUILD/'objects/qbt_transport.o')
    sec=next(s for s in obj.sections if (s['segment'],s['name'])==('__BOOTDATA','__init_entry_set'))
    if sec['size'] != 5*24:
        raise ValueError('Qca startup records extent differs')
    rows=[]
    for symbol in sorted((s for s in obj.symbols if s['section'] and s['name'].startswith('___startup_') and
                          obj.sections[s['section']-1]['name']=='__init_entry_set'),key=lambda s:s['va']):
        at=symbol['va'];subsystem,rank=struct.unpack_from('<II',obj.read(at,8))
        func,arg=obj.relocations[at+8],obj.relocations[at+16]
        if func['type'] != 11 or func['length'] != 3 or func['pcrel']:
            raise ValueError('Startup callback must retain authenticated relocation')
        rows.append(dict(symbol=symbol['name'],object_va=hex(at),subsystem=subsystem,rank=rank,
                         bytes=24,no_dead_strip=bool(symbol['desc']&0x20),function=func['symbol'],
                         function_pac=pac(func['word']),argument_symbol=arg['symbol'],
                         argument_relocation=arg['type'],argument_addend=arg['word']))
    expected=[(3,1,'_lck_grp_startup_init'),(3,3,'_lck_mtx_startup_init'),
              (16,1,'_sysctl_register_oid_early'),(16,1,'_sysctl_register_oid_early'),(16,1,'_sysctl_register_oid_early')]
    if [(r['subsystem'],r['rank'],r['function']) for r in rows] != expected:
        raise ValueError('Startup subsystem/rank/function differs: '+repr(rows))
    if not all(r['no_dead_strip'] for r in rows):
        raise ValueError('Startup record lost no-dead-strip mark')
    for r in rows:
        if r['function_pac']!=dict(auth=1,key=0,diversity=0x2abe,address_diversity=0):
            raise ValueError('Startup function type schema differs from actual consumer')
    group=obj.names['___startup_lck_grp_spec_bt_sk_grp']['va']
    mutex=obj.names['___startup_lck_mtx_spec_bt_sk_lock']['va']
    if obj.relocations[group]['symbol']!='_bt_sk_grp' or obj.read(group+8,64).split(b'\0')[0]!=b'unixnu.bt.uart.sk':
        raise ValueError('Lock group spec does not name actual lock group')
    if obj.relocations[mutex]['symbol']!='_bt_sk_lock' or obj.relocations[mutex+8]['symbol']!='_bt_sk_grp' or obj.read(mutex+16,8)!=bytes(8):
        raise ValueError('Mutex spec no longer binds actual group and mutex')
    oids=[]
    for name,handler in [('qbt_boot','_bt_sk_boot_sysctl'),('qbt_firmware','_sysctl_handle_string'),('qbt_power_on','_bt_sk_power_on_sysctl')]:
        at=obj.names['_sysctl__kern_'+name]['va']
        parent,func=obj.relocations[at],obj.relocations[at+48]
        if parent['symbol']!='_sysctl__kern_children' or pac(parent['word'])!=dict(auth=1,key=2,diversity=0xdb49,address_diversity=1):
            raise ValueError('sysctl parent pointer PAC differs')
        if func['symbol']!=handler or pac(func['word'])!=dict(auth=1,key=0,diversity=0xe2e,address_diversity=0):
            raise ValueError('sysctl handler pointer PAC differs')
        if struct.unpack('<I',obj.read(at+72,4))[0]!=1:
            raise ValueError('sysctl OID version mismatch')
        oids.append(dict(name='kern.'+name,bytes=80,parent_offset=0,parent_pac=pac(parent['word']),
                         handler_offset=48,handler=handler,handler_pac=pac(func['word']),version_offset=72,version=1))
    (out/'qca-startup-object.json').write_text(json.dumps(dict(section=sec,records=rows,
        group_spec=dict(bytes=80,group_offset=0,name_offset=8,flags_offset=72,name='unixnu.bt.uart.sk'),
        mutex_spec=dict(bytes=24,mutex_offset=0,group_offset=8,attr_offset=16),sysctl_oids=oids),indent=2)+'\n')
    return rows


def linked_audit(path,out,classes,entries,metas,strict=False):
    from kc_image import Image,scan
    raw=Path(path).read_bytes();collection=Image(raw)
    image=Image(raw,collection.entries['com.apple.kernel'][1]) if collection.entries else collection
    names={n:va for va,group in image.symbols().items() for n in group}
    fixups=collection.fixups()
    record=dict(path=str(path),sha256=sha(path),strict=strict,classes={},startup={},metaclasses={})
    link_record=Path(path).parent/'native-link.command.json'
    if link_record.exists():
        selected=load(link_record)
        record['selected_radio_archive']=[token.split('-Wl,-force_load,',1)[1] for token in selected
                                          if token.startswith('-Wl,-force_load,') and token.endswith('/libSonyWcn.a')]
    for classname,c in [*classes.items(),*[(n+'::MetaClass',t) for n,t in metas.items()]]:
        table=names[c['symbol']]+16
        rows=[]
        for original in c['rows']:
            site=table+original['slot']*8
            if fixups:
                r=fixups.get(site)
                if not r or r[1:]!=(1,0,original['diversity'],1):
                    raise ValueError(f'Linked strict PAC mismatch: {classname} slot{original["slot"]}')
                target=r[0]
            else:
                target=struct.unpack('<Q',image.read(site,8))[0]
            symbol=original['symbol']
            if symbol in names and target!=names[symbol]:
                raise ValueError(f'Linked table resolves wrong target: {classname} {symbol}')
            rows.append(dict(slot=original['slot'],site=hex(site),target=hex(target),symbol=symbol))
        section='metaclasses' if classname.endswith('::MetaClass') else 'classes'
        record[section][classname]=dict(vptr=hex(table),slots=len(rows),instance_bytes=c['instance_bytes'],
                                       compiled_slots_resolved=True,linked_pac_verified=bool(fixups),strict_pac_verified=strict,rows=rows)
    sec=next(s for s in image.sections if (s['segment'],s['name'])==('__BOOTDATA','__init_entry_set'))
    start,end=sec['va'],sec['va']+sec['size']
    if sec['size']%24:
        raise ValueError('Linked startup section invalid24-byte extent')
    linked=[]
    for e in entries:
        at=names[e['symbol']]
        if not start<=at<end or (at-start)%24:
            raise ValueError('Radio record is outside actual startup section')
        subsys,rank=struct.unpack('<II',image.read(at,8))
        if (subsys,rank)!=(e['subsystem'],e['rank']):
            raise ValueError('Linked startup order fields differ')
        if fixups:
            r=fixups.get(at+8)
            p=e['function_pac']
            if not r or r[1:]!=(p['auth'],p['key'],p['diversity'],p['address_diversity']):
                raise ValueError('Linked startup PAC differs')
            target=r[0]
        else:
            target=struct.unpack('<Q',image.read(at+8,8))[0]
        if target!=names[e['function']]:
            raise ValueError('Startup function does not point to actual linked constructor')
        arg=fixups[at+16][0] if fixups else struct.unpack('<Q',image.read(at+16,8))[0]
        if arg!=names[e['argument_symbol']]:
            raise ValueError('Startup argument pointer does not resolve to its exact spec/OID')
        linked.append({**e,'linked_va':hex(at),'linked_function':hex(target),'linked_argument':hex(arg)})
    functions={}
    for name in ('_kernel_startup_bootstrap','_kernel_startup_initialize_upto',
                 '_lck_grp_startup_init','_lck_mtx_startup_init','_sysctl_register_oid_early',
                 '_native_sony_wifi_start','_native_sony_bluetooth_start','_qbt_transport_init',
                 '_arm_init','_kernel_bootstrap','_kernel_bootstrap_thread','_bsd_init',
                 '_native_legacy_display_late_probe','__GLOBAL__sub_I_WifiNet.cpp'):
        at,size,asm=code_for(image,name,names)
        dest=out/(('strict-' if strict else 'native-')+name+'.asm');dest.write_text(asm)
        calls,refs,_=scan(image.read(at,size),at)
        reverse={va:n for n,va in names.items()}
        functions[name]=dict(address=hex(at),bytes=size,code_sha256=hashlib.sha256(image.read(at,size)).hexdigest(),disassembly=str(dest),
                             calls=[dict(site=hex(site),target=hex(target),symbol=reverse.get(target)) for site,target,_ in calls],
                             references=[dict(site=hex(site),target=hex(target),kind=kind) for site,target,kind in refs])
    bootstrap=Path(functions['_kernel_startup_bootstrap']['disassembly']).read_text()
    upto=Path(functions['_kernel_startup_initialize_upto']['disassembly']).read_text()
    if not any(int(r['target'],16)==start for r in functions['_kernel_startup_bootstrap']['references']) or not any(
        int(r['target'],16)==end for r in functions['_kernel_startup_bootstrap']['references']):
        raise ValueError('Bootstrap does not iterate actual section boundaries')
    if not re.search(r'mov\s+w2, #24\b',bootstrap) or not re.search(r'mov\s+w0, #3\b',bootstrap):
        raise ValueError('Bootstrap entry size/LOCKS phase differs')
    if 'blraa\tx8, x17' not in upto or '#10942' not in upto or not re.search(r'add\s+x22, x22, #24',upto):
        raise ValueError('Startup consumer does not authenticate2abe/iterate24-byte entries')
    cursor=fixups[names['_startup_entry_cur']][0]
    if cursor!=start:
        raise ValueError('Startup cursor does not begin at section start')
    if not any(r['symbol']=='_kernel_startup_initialize_upto' for r in functions['_kernel_bootstrap_thread']['calls']):
        raise ValueError('Native thread startup does not invoke subsystem initialization')
    phase_text=Path(functions['_kernel_bootstrap_thread']['disassembly']).read_text()
    if not re.search(r'mov\s+w0, #16\b',phase_text):
        raise ValueError('Native startup never requests SYSCTL16')
    late={r['symbol'] for r in functions['_native_legacy_display_late_probe']['calls']}
    if not {'_native_sony_wifi_start','_native_sony_bluetooth_start'}.issubset(late):
        raise ValueError('Both C-linkage late hooks are not called')
    def require_call(caller,callee):
        if not any(c['symbol']==callee for c in functions[caller]['calls']):
            raise ValueError('Mandatory native call missing: '+caller+' -> '+callee)
    require_call('_arm_init','_kernel_startup_bootstrap')
    require_call('_kernel_startup_bootstrap','_kernel_startup_initialize_upto')
    require_call('_kernel_bootstrap_thread','_bsd_init')
    require_call('_bsd_init','_native_legacy_display_late_probe')
    # Walk actual calls for the Wi-Fi static initializer and UART.SK worker.
    # Optimization may inline wifiStack/netStart into endpointProbe; report the
    # actual emitted caller rather than demand an old source symbol survives.
    wanted={names['__GLOBAL__sub_I_WifiNet.cpp'],names['_qbt_transport_init']}
    starts=image.function_starts();reverse={va:n for n,va in names.items()};actual_callers={}
    for index,at in enumerate(starts[:-1]):
        size=starts[index+1]-at
        if size>0x20000:continue
        try:body=image.read(at,size)
        except ValueError:continue
        hits=[dict(site=hex(s),target=hex(t),symbol=reverse.get(t)) for s,t,_ in scan(body,at)[0] if t in wanted]
        if hits:
            name=reverse.get(at,hex(at));actual_callers[name]=dict(address=hex(at),bytes=size,calls=hits)
            dest=out/(('strict-' if strict else 'native-')+'caller-'+name+'.asm')
            dest.write_text(disassemble(image,at,size))
    if {c['target'] for v in actual_callers.values() for c in v['calls']}!={hex(x) for x in wanted}:
        raise ValueError('Wi-Fi class initializer or qbt transport not reachable by actual caller')
    constructors={}
    for classname,c in classes.items():
        ctor='__ZN'+str(len(classname))+classname+'C2Ev'
        allocate='__ZNK'+str(len(classname))+classname+'9MetaClass5allocEv'
        for name in (ctor,allocate):
            at,size,asm=code_for(image,name,names)
            if 'pacda' not in asm or '#52641' not in asm or 'pacibsp' not in asm:
                raise ValueError('Class constructor does not retain DA/cda1 signing')
            if name==allocate and not re.search(r'mov\s+w1, #'+str(c['instance_bytes'])+r'\b',asm):
                raise ValueError('Class allocator instance extent differs')
            dest=out/(('strict-' if strict else 'native-')+name+'.asm');dest.write_text(asm)
            constructors[name]=dict(address=hex(at),code_sha256=hashlib.sha256(image.read(at,size)).hexdigest(),disassembly=str(dest),
                                    vptr_schema=dict(key='DA',diversity='0xcda1',address_diversity=1))
    record['constructors']=constructors
    record['startup']=dict(section=sec,record_count=sec['size']//24,qca_records=linked,implementations=functions,
                           cursor_starts_at_section=True,bootstrap_qsort_entry_bytes=24,LOCKS_before_late_hooks=True,
                           native_SYSCTL_phase_called=True,actual_callback_auth='IA/0x2abe/no-address-diversity',
                           both_radio_late_hooks_called=True,actual_radio_worker_callers=actual_callers,
                           mandatory_call_paths=[['_arm_init','_kernel_startup_bootstrap','_kernel_startup_initialize_upto(3)'],
                             ['_kernel_bootstrap_thread','_kernel_startup_initialize_upto(16)','_sysctl_register_oid_early'],
                             ['_kernel_bootstrap_thread','_bsd_init','_native_legacy_display_late_probe','_native_sony_wifi_start'],
                             ['_kernel_bootstrap_thread','_bsd_init','_native_legacy_display_late_probe','_native_sony_bluetooth_start']],
                           explicit_late_lock_sysctl_constructor_calls_needed=False)
    (out/('strict-linked.json' if strict else 'native-linked.json')).write_text(json.dumps(record,indent=2)+'\n')
    return record


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--native',type=Path,required=True)
    p.add_argument('--strict',type=Path)
    p.add_argument('--wifi-object',type=Path,default=BUILD/'objects/WifiNet.late.o')
    p.add_argument('--size-build',type=Path,help='read-only isolated -Oz result binding the replacement object')
    a=p.parse_args();out=a.out.resolve()
    if not out.is_relative_to(HERE) or out==HERE:
        raise ValueError('Reports must stay within qualification-final')
    out.mkdir(parents=True,exist_ok=False)
    if sha(CACHE)!=ORIGINAL or sha(BUILD/'libSonyWcn.a')!=BOARD_SHA:
        raise ValueError('Original D27 or frozen board archive changed')
    receipt=load(BUILD/'result.json')
    for path,digest in receipt['objects'].items():
        if sha(path)!=digest:raise ValueError('Frozen object changed: '+path)
    sys.path.insert(0,str(ROOT/'ci/XnuPrelink'))
    from kc_image import Image
    original=Image(CACHE.read_bytes())
    originals=original_classes(original,out)
    (out/'original-tables.json').write_text(json.dumps(originals,indent=2)+'\n')
    if a.size_build:
        size=load(a.size_build/'result.json')
        if not size['passed'] or not size['frozen_inputs_modified'] is False or not size['other_members_byte_identical']:
            raise ValueError('Isolated size build receipt invalid')
        if sha(size['archive'])!=size['sha256']:
            raise ValueError('Isolated archive changed')
        replacement=next(r for r in size['replacements'] if r['member']=='WifiNet.late.o')
        if a.wifi_object.resolve()!=Path(replacement['new_object']).resolve() or sha(a.wifi_object)!=replacement['new_sha256']:
            raise ValueError('WifiNet size object is not the hash-bound replacement')
    classes,metas=audit_tables(out,originals,a.wifi_object)
    entries=startup_object(out)
    native=linked_audit(a.native,out,classes,entries,metas)
    strict=linked_audit(a.strict,out,classes,entries,metas,True) if a.strict else None
    inputs={str(BUILD/'result.json'):sha(BUILD/'result.json'),str(BUILD/'libSonyWcn.a'):BOARD_SHA,
            str(CACHE):ORIGINAL,str(a.native):sha(a.native),str(a.wifi_object):sha(a.wifi_object),str(Path(__file__)):sha(__file__)}
    for name in ('WifiNet.cpp','BluetoothProbe.cpp','WifiProbe.cpp'):
        path=BUILD/'source'/name;inputs[str(path)]=sha(path)
    # Independent immutable text copies bind the exact source/header contracts
    # consumed by the frozen radio objects. No original path is rewritten.
    snapshots=out/'source-snapshots';snapshots.mkdir()
    wanted={}
    for key in ('WifiNet.cpp','qbt_transport.c'):
        record=receipt['commands'][key]
        for path,digest in record['dependencies'].items():
            if any(path.endswith(suffix) for suffix in ('/IOService.h','/IOUserClient.h','/startup.h','/lock_group.h','/locks.h','/sysctl.h','/qbt_transport.c','/WifiNet.cpp')):
                if sha(path)!=digest:raise ValueError('Frozen selected ABI header changed: '+path)
                wanted[path]=digest
    work=BASE/'sources/UniXNU/out/pdx234/ios-27.0.1-24A446-iphone14/pdx234_sheng27_bulk/tree/.cache/xnu-work'
    for relative in ('osfmk/kern/startup.c','osfmk/kern/lock_group.c','osfmk/arm/locks.c','bsd/kern/kern_sysctl.c'):
        path=work/relative
        if path.exists():wanted[str(path)]=sha(path)
    copies=[]
    for i,(path,digest) in enumerate(sorted(wanted.items())):
        dest=snapshots/(str(i).zfill(2)+'-'+Path(path).name)
        shutil.copyfile(path,dest)
        if sha(dest)!=digest:raise ValueError('Snapshot copy differs')
        inputs[path]=digest
        copies.append(dict(original=path,path=str(dest),sha256=digest))
    (out/'source-snapshots.json').write_text(json.dumps(copies,indent=2)+'\n')
    result=dict(passed=True,compiled_class_tables=5,method_slots=4*168+186,
                metaclass_table_extents={k:v['slots'] for k,v in metas.items()},
                native_linked=True,strict_linked=bool(strict),hardware_verified=False,
                wifi_object=str(a.wifi_object),wifi_object_sha256=sha(a.wifi_object),
                changed_optimization_only=bool(a.size_build),
                optimization_replacement_selected_in_native=(not a.size_build or str(a.size_build/'libSonyWcn.a') in native.get('selected_radio_archive',[])),
                classes={k:{f:c[f] for f in ('slots','method_bytes','total_bytes','instance_bytes')} for k,c in classes.items()},
                qca_startup_records=entries,inputs=inputs,
                strict_layout_refusal_not_missing_imports=True,
                frozen_inputs_modified=False,device_operations=False)
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('inputs','qca_startup_records')},indent=2))


if __name__=='__main__':
    main()
