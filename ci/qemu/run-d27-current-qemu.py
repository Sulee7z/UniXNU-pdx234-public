#!/usr/bin/env python3
"""Run the actual current-derived D27 launchd with immutable original OS inputs."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time

DEVICE=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')

def sha(path):
    with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def save(path,data):path.write_text(json.dumps(data,indent=2)+'\n')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--work',type=Path,default=BASE/'qemu-current-20261117-005')
    p.add_argument('--seed',type=Path,required=True)
    p.add_argument('--timeout',type=int,default=2400)
    p.add_argument('--checkpoint',default='_reboot',help='Exact selected native symbol; default allows full userland runtime')
    p.add_argument('--cpus',type=int,default=8)
    p.add_argument('--memory-mib',type=int,default=8192,choices=(4096,8192))
    p.add_argument('--owned-bytes',type=lambda v:int(v,0),default=0x100000000)
    p.add_argument('--boot-arg',action='append',default=[])
    p.add_argument('--virtual-input',action='store_true',help='Attach real QEMU tablet/keyboard with the qualified D27 input archive')
    p.add_argument('--capture-data',action='store_true',help='Save actual bounded sparse Data at the final stopped guest state')
    p.add_argument('--local-disks',type=Path,help='Hash-qualified readonly EXT4 copies of the original OS/SystemOS disks')
    a=p.parse_args()
    if (not 1<=a.cpus<=8 or not 60<=a.timeout<=14400 or
        (a.checkpoint=='_reboot' and a.timeout<1200)):raise ValueError('Use bounded real guest parameters')
    for drive in ('e','f'):
        mount=Path('/mnt/host-'+drive);mount.mkdir(exist_ok=True)
        if not os.path.ismount(mount):subprocess.run(['mount','-t','drvfs',drive.upper()+':',str(mount),'-o','metadata'+(',ro' if drive=='e' else '')],check=True)
    if shutil.disk_usage('/mnt/g').free<8*1024**3:raise RuntimeError('G reserve below8GiB')
    a.out.mkdir(parents=True,exist_ok=False)
    out=a.out.resolve();work=a.work.resolve()
    nr=json.loads((work/'native/result.json').read_text());sr=json.loads((work/'strict/result.json').read_text())
    if a.virtual_input:
        hid=nr.get('qemu_virtual_input')
        if not hid or sha(hid['archive'])!=hid['sha256']:raise ValueError('Qualified virtual input archive required')
    strict=json.loads((work/'strict/kernel.json').read_text())
    if (sha(work/'native/native.macho')!=nr['native_sha256'] or sha(work/'strict/kernel.macho')!=sr['candidate_sha256']
        or strict['missing'] or strict['stubbed'] or strict['allow_missing'] or not strict['candidate_written']
        or nr['qemu_block_pac_slots_checked']!=190 or sr['auth_instruction_patches']):raise ValueError('Strict current qualification required')
    esp=out/'esp';payload=esp/'EFI/UniXNU/Payloads';payload.mkdir(parents=True)
    old=Path('/root/unixnu-build/pdx234-strict5-native-001/qemu-004/esp')
    for relative in ('EFI/BOOT/BOOTAA64.EFI','EFI/UniXNU/Drivers/DarwinBoot.efi'):
        dest=esp/relative;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(old/relative,dest)
    kernel=payload/'kernel.macho';shutil.copyfile(work/'strict/kernel.macho',kernel)
    retained=Path('/mnt/host-e/UniXNU-Port-artifacts/qemu-validation-20261117-002/esp/EFI/UniXNU/Payloads')
    expected={'kernel.macho.vroot':'f3eb4efbe4c6116c30dca5fbc0b83ed3c4bf52c821a15dbd29859d2aa004f98d',
              'kernel.macho.trustcache':'98d8d532d9d43baaaa4e8a6599f2770c63d647675690224e856440faf039627f'}
    for name,digest in expected.items():
        if sha(retained/name)!=digest:raise ValueError('Original sidecar differs: '+name)
        shutil.copyfile(retained/name,payload/name)
    seed_result=json.loads((a.seed.parent/'result.json').read_text())
    if sha(a.seed)!=seed_result['private_seed_sha256'] or not seed_result['original_seed_unchanged']:
        raise ValueError('Prepared private D27 seed required')
    if seed_result.get('native_mount_check_required') and a.checkpoint!='_load_init_program_at_path':
        raise ValueError('This captured Data must pass the original D27 APFS mount checkpoint before userland continuation')
    if seed_result.get('apfsck_exit',0)!=0 and a.checkpoint!='_load_init_program_at_path':
        qualification_path=seed_result.get('native_mount_qualification')
        if not qualification_path or sha(qualification_path)!=seed_result.get('native_mount_qualification_sha256'):
            raise ValueError('Captured Data needs its actual original APFS mount qualification')
        qualification=json.loads(Path(qualification_path).read_text())
        if (qualification.get('source_seed_sha256')!=seed_result['private_seed_sha256'] or
                qualification.get('actual_original_d27_apfs_mount_accepted') is not True or
                qualification.get('actual_read_write_data_mount') is not True or
                sha(qualification['observation'])!=qualification['observation_sha256']):
            raise ValueError('Native Data mount evidence differs')
    shutil.copyfile(a.seed,payload/'scratch-data.img')
    disks={}
    local_inputs=json.loads((a.local_disks/'result.json').read_text()) if a.local_disks else None
    for label,relative,size,digest in (
        ('OS','qemu-root-recovery-20261115/043-68793-664.dmg',9537847296,'5371e392912dbc5f6f9677d4987c726e15fd7afc519b3644d8d6694777182ad5'),
        ('SystemOS','qemu-systemos-recovery-20261117-001/043-69730-712.dmg',6012534784,'34b6010eb6329ca1c942c374df1b157c40cfc36b1120b0c2ec811ea69ed3b686')):
        original_path=Path('/mnt/host-e/UniXNU-Port-artifacts')/relative
        path=original_path
        if local_inputs:
            selected=[row for row in local_inputs['disks'] if row['label']==label]
            if len(selected)!=1 or selected[0]['sha256']!=digest or selected[0]['bytes']!=size or not selected[0]['readonly']:
                raise ValueError('Local original-disk receipt differs: '+label)
            path=Path(selected[0]['path'])
            if path.stat().st_mode&0o222:raise ValueError('Local original disk must be readonly')
        if path.stat().st_size!=size or sha(path)!=digest:raise ValueError('Original disk differs: '+label)
        disks[label]=dict(path=str(path),original_path=str(original_path),bytes=size,sha256=digest,readonly=True)
    save(out/'disks.json',disks)
    fdt=out/'virt.dtb'
    fdt_command=['qemu-system-aarch64','-M',f'virt,virtualization=off,secure=off,gic-version=3,dumpdtb={fdt}',
                    '-cpu','cortex-a710','-m',str(a.memory_mib),'-smp',str(a.cpus),'-display','none','-nodefaults']
    if a.virtual_input:fdt_command+=['-global','virtio-mmio.force-legacy=false','-device','virtio-tablet-device','-device','virtio-keyboard-device']
    subprocess.run(fdt_command,check=True)
    adt=payload/'kernel.macho.adt'
    make_dt=Path('/mnt/g/UniXNU-Port/sources/UniXNU-main-20261109/scripts/qemu-entry/make-dt.py')
    subprocess.run(['python3','-B',str(make_dt),'--armvirt','--armcpu','--smp',str(a.cpus),
        '--nvram-proxy','--qemu-vmm-present','--crypto-hash-method','sha2-384','--osenvironment','main',
        '--amfi-platform-only','--dram-size',str(a.memory_mib*1024**2),'--owned-memory-size',str(a.owned_bytes),
        '--virtio-mmio-fdt',str(fdt),'--root-match-volume-uuid','CA0FF65B-3E73-4D62-9000-EC719E1B6DB1',
        '--data-ramdisk','--trust-cache','--output',str(adt)],check=True)
    spec=importlib.util.spec_from_file_location('qemu_adt_codec','/mnt/g/UniXNU-Port/sources/UniXNU-qemu-20261110/scripts/make-qemu-adt.py')
    codec=importlib.util.module_from_spec(spec);spec.loader.exec_module(codec)
    tree,end=codec.parse(adt.read_bytes())
    if end!=adt.stat().st_size:raise ValueError('ADT parse incomplete')
    arm=codec.child(tree,'arm-io');arm[2]=[node for node in arm[2] if node[0] not in ('ufshc','ufsphy')]
    codec.put(tree,'model',b'iPhone14,7\0');codec.put(tree,'target-type',b'D27\0')
    chosen=codec.child(tree,'chosen')
    identity_source=BASE/'tmp/qemu-058-identity-001/kernel.macho.adt'
    if sha(identity_source)!='86e1c9093e1faa3ac0842f462f089e4bc2e8e828a93bd936039879215114435a':
        raise ValueError('Preserved current058 identity ADT differs')
    identity_tree,identity_end=codec.parse(identity_source.read_bytes())
    if identity_end!=identity_source.stat().st_size:raise ValueError('Identity ADT parse incomplete')
    def node(name):
        for child in tree[2]:
            if child[0]==name:return child
        child=[name,[],[]];tree[2].append(child);return child
    product=node('product');product[1]=[]
    for key,value in codec.child(identity_tree,'product')[1]:
        if key in ('name','product-name','product-description','artwork-device-idiom'):codec.put(product,key,value)
    buttons=node('buttons');buttons[1]=list(codec.child(identity_tree,'buttons')[1])
    unique=dict(codec.child(identity_tree,'chosen')[1])['unique-chip-id']
    if len(unique)!=8 or not int.from_bytes(unique,'little'):raise ValueError('Preserved platform identity absent')
    codec.put(chosen,'unique-chip-id',unique)
    seed_identity=BASE/'payload-pac-abi-033/platform-seed'
    if sha(seed_identity)!='6c9e5ee6eec9045c054a87b57405f3d63bb775cba85f2719da6e5dfc893d09f7':
        raise ValueError('Preserved platform seed differs')
    shutil.copyfile(seed_identity,out/'platform-seed')
    save(out/'identity.json',dict(source_adt=str(identity_source),source_adt_sha256=sha(identity_source),
        product={k:v.hex() for k,v in product[1]},buttons={k:v.hex() for k,v in buttons[1]},
        unique_chip_id=unique.hex(),platform_seed_sha256=sha(seed_identity),
        hardware_compatible='linux,dummy-virt',only_portable_identity_copied=True,device_operations=False))
    for key,value in (('kernel-ctrr-to-be-enabled',0),('chip-id',0x8110),('board-id',0x18),
                      ('security-domain',1),('certificate-production-status',0),('effective-production-status-ap',0),
                      ('certificate-security-mode',1),('effective-security-mode-sep',1)):
        codec.put(chosen,key,struct.pack('<I',value))
    mem=codec.child(chosen,'memory-map');mem[1]=[(key,value) for key,value in mem[1] if key!='RAMDisk']
    codec.put(mem,'PackedRAMDisk',bytes(16));codec.put(mem,'RootPolicies',bytes(16))
    defaults=codec.child(tree,'defaults');codec.put(defaults,'kern.maxvnodes',struct.pack('<I',78848))
    codec.put(defaults,'sleep-disabled',struct.pack('<I',1))
    # A710 is a performance-class core. Keep one actual virt cluster and its
    # real MPIDR affinities; the current kernel's qualified single-cluster path
    # handles the missing efficiency role without importing Sony topology.
    for cpu in codec.child(tree,'cpus')[2]:codec.put(cpu,'cluster-type',struct.pack('<I',ord('P')))
    adt.write_bytes(codec.serialize(tree))
    def flatten(node,parent=''):
        path=parent+'/'+node[0]
        return [dict(path=path,properties={k:v.hex() for k,v in node[1]})]+[item for child in node[2] for item in flatten(child,path)]
    nodes=flatten(tree)
    if any(any(word in node['path'].lower() for word in ('ufshc','ufsphy','spmi','adreno','dwc3','dsi')) for node in nodes):raise ValueError('Sony hardware node in virt ADT')
    save(out/'adt-audit.json',nodes)
    arguments=['native-qemu-storage=1','-v','serial=3',f'cpus={a.cpus}','debug=0x14e','kt_fixed_zones=120',
       '-no_slto_panic','use_contiguous_hint=0','native-source-storage=0','native-ufs-root=0',
       'sheng-data-persist=0','data-persist=0','interrupt-masked-debug-mode=1','sched_preemption_disable_debug_mode=1',
       'qcom-usb-debug=0','gpu-power=0','gpu-metal=0','gpu-bringup=0','sheng-gpu-addon=0','fb-gpu=0',
       'dpu=0','dpu-scanout=0','cpufreq=0','log=0','autoreset=0','pmgr=0',
       'offline-mobile-graphics-load=1','offline-legacy-register=1','offline-legacy-gop=1','offline-legacy-unit-scale=1',
       'offline-legacy-pm=1','offline-legacy-validate=1','offline-legacy-transfer=1','offline-legacy-cpu-present=1',
       'offline-legacy-phase=4','vsync=60','vsync-fixed=1','aks=1','aks-sls=3','offline-key-events=1',
       'offline-keystore=0','smp=1','sheng-smp=1','armcpu-self-ipi=1','armcpu-diagnostics=1',
       'disable-watchdogd=1','lite=1','no-lc=1','sheng-no-lc=1','boot-progress=0','banner=0']
    for argument in a.boot_arg:
        key=argument.split('=',1)[0];arguments=[item for item in arguments if item.split('=',1)[0]!=key]+[argument]
    if a.virtual_input:
        for item in ('qemu-input=1','touch-hid=1'):
            key=item.split('=',1)[0];arguments=[v for v in arguments if v.split('=',1)[0]!=key]+[item]
    if any(item.startswith('launchdsuffix=') for item in arguments):raise ValueError('Use real original launchd')
    bootargs=' '.join(arguments)
    (esp/'EFI/UniXNU/unixnu.toml').write_text('version=1\n[boot]\ntimeout=1\ndefault="native"\n[kits]\nautoload=false\n[[driver]]\npath="Drivers/DarwinBoot.efi"\n[[entry]]\nid="native"\ntitle="Current058-derived D27 verified VirtIO launchd"\ntype="xnu"\npath="Payloads/kernel.macho"\ninitrd="Payloads/scratch-data.img"\nargs="'+bootargs+'"\n')
    seal=Path('/mnt/g/UniXNU-Port/references/pdx234-mainline-20261108/scripts/seal-source-crypto-kernel.py')
    with (out/'seal.log').open('x') as f:subprocess.run(['python3','-B',str(seal),str(kernel),'--kernel-args',bootargs],stdout=f,stderr=subprocess.STDOUT,env=dict(os.environ,UNIXNU_XNU_ARCH='arm64e',UNIXNU_IOS_VERSION='27.0'),check=True)
    sys.path.insert(0,str(DEVICE/'ci/XnuPrelink'));from kc_image import Image
    collection=Image(kernel.read_bytes());native=Image(kernel.read_bytes(),collection.entries['com.apple.kernel'][1])
    names={name:hex(address) for address,symbols in native.symbols().items() for name in symbols}
    save(out/'symbols.json',names)
    layout=json.loads((BASE/'tmp/qemu-process-observer-002/plan.json').read_text())
    filelist=Path(json.loads((work/'native/native-link.command.json').read_text())[json.loads((work/'native/native-link.command.json').read_text()).index('-filelist')+1]).read_text().splitlines()
    for item in layout['object_inputs']:
        if (item['object'] not in filelist or sha(item['object'])!=item['sha256'] or
            sha(item['receipt'])!=item['receipt_sha256']):raise ValueError('Actual linked current layout input differs')
    layout['native_sha256']=nr['native_sha256']
    layout['thread_snapshot_native_user_pt_attr']=names['_native_user_pt_attr']
    save(out/'process-layout.json',layout)
    observer_source=Path('/mnt/host-f/UniXNU-Port-artifacts/qemu-dlopen20261117/run004/observer.py')
    text=observer_source.read_text()
    if a.virtual_input:
        marker="    command += ['-device', 'ramfb']"
        if text.count(marker)!=1:raise ValueError('Actual QEMU display device site changed')
        text=text.replace(marker,marker+"\n    command += ['-global','virtio-mmio.force-legacy=false','-device','virtio-tablet-device','-device','virtio-keyboard-device']")
    # Keep the existing read-only observer and all evidence limits. Add bounded
    # TTBR1 reads so an arbitrary final EL0 stop can read the native data too.
    text=text.replace('from d27_user_memory import read_user_memory, kernel_pointer_view',
                       'from d27_user_memory import read_user_memory, read_kernel_memory, kernel_pointer_view')
    text=text.replace("from d27_user_memory import read_user_memory, read_kernel_memory, kernel_pointer_view",
        "from d27_user_memory import read_user_memory, read_kernel_memory, kernel_pointer_view\n"
        "sys.path.insert(0, '/mnt/g/UniXNU-Port/ports/UniXNU-pdx234/ci/qemu/display')")
    text=text.replace('from thread_snapshot import capture','from d27_thread_snapshot import capture')
    start=text.index('            def process_identity():')
    end=text.index('\n            for address in dict.fromkeys',start)
    replacement='''            def process_identity():
                layout=process_plan['process_layout']
                registers={}
                for include in feature('target.xml').findall('{http://www.w3.org/2001/XInclude}include'):
                    for reg in feature(include.attrib['href']).findall('reg'):
                        if reg.attrib['name'] in ('TCR_EL1','TTBR1_EL1','TTBR0_EL1','TPIDR_EL1'):
                            registers[reg.attrib['name']]=int.from_bytes(bytes.fromhex(packet(f'p{int(reg.attrib["regnum"]):x}')),'little')
                def read(address,size):
                    result=read_kernel_memory(packet,registers,address,size)
                    raw=bytes.fromhex(result['bytes'])
                    if len(raw)!=size:raise RuntimeError('Current native process field not mapped')
                    return raw
                def pointer(address):
                    value=int.from_bytes(read(address,8),'little')
                    return kernel_pointer_view(value,registers['TCR_EL1']) if value else 0
                thread=kernel_pointer_view(registers['TPIDR_EL1'],registers['TCR_EL1'])
                ro=pointer(thread+layout['thread_ro'])
                if pointer(ro+layout['ro_owner'])!=thread:raise RuntimeError('Actual read-only thread owner differs')
                proc=pointer(ro+layout['ro_proc']);task=pointer(ro+layout['ro_task'])
                if not proc:return dict(thread=hex(thread),thread_ro=hex(ro),task=hex(task),pid=None,name=None,bsd_process=False)
                region=pointer(task+layout['task_region']) if task else 0
                return dict(thread=hex(thread),thread_ro=hex(ro),proc=hex(proc),task=hex(task),
                    user_state=hex(pointer(thread+layout['thread_user_state'])),shared_region=hex(region),
                    shared_region_slide=int.from_bytes(read(region+layout['region_slide'],4),'little') if region else None,
                    pid=int.from_bytes(read(proc+layout['pid'],4),'little'),name=read(proc+layout['comm'],17).split(b'\\0')[0].decode('utf-8','replace'))
'''
    text=text[:start]+replacement+text[end:]
    marker="                report['process_list'] = entries"
    if text.count(marker)!=1:raise ValueError('Observer process-list site changed')
    text=text.replace("                    raw = packet(f'm{address:x},{length:x}')\n                    if len(raw) != length * 2 or raw.startswith('E'):\n                        return None\n                    return bytes.fromhex(raw)",
        "                    try:\n                        regs={k:int(v,16) for k,v in report['system_registers'].items()}\n                        observed=read_kernel_memory(packet,regs,address,length)\n                        raw=bytes.fromhex(observed['bytes'])\n                        return raw if len(raw)==length else None\n                    except (ValueError,RuntimeError):return None")
    text=text.replace("                    node = int.from_bytes(next_raw, 'little')", "                    value = int.from_bytes(next_raw, 'little')\n                    node = kernel_pointer_view(value,int(report['system_registers']['TCR_EL1'],16)) if value else 0")
    text=text.replace("                    node = int.from_bytes(head, 'little')", "                    value = int.from_bytes(head, 'little')\n                    node = kernel_pointer_view(value,int(report['system_registers']['TCR_EL1'],16)) if value else 0")
    pm_plan=BASE/'tmp/qemu-pm-observer-001/plan.json';pm=json.loads(pm_plan.read_text())
    if sha(pm['object'])!='8afdb84a2edd2632027bcdec2e8f4228ab020ce13c18eb194700f2cfd88ae021':raise ValueError('PM object differs')
    save(out/'pm-plan.json',pm)
    attach="""
            if args.system_registers:
                try:
                    from d27_display_pm import capture_display_pm
                    pm_plan=json.loads(Path(__file__).with_name('pm-plan.json').read_text())
                    regs={k:int(v,16) for k,v in report['system_registers'].items()}
                    report['display_pm']=capture_display_pm(packet,regs,PM_OBJECT_SYMBOL,pm_plan)
                except (ValueError,RuntimeError) as error:report['display_pm_error']=str(error)
                try:
                    from capture_display import capture_display
                    selected_symbols=json.loads(Path(__file__).with_name('symbols.json').read_text())
                    report['qemu_display']=capture_display(packet,regs,selected_symbols)
                except (ValueError,RuntimeError) as error:report['qemu_display_error']=str(error)
                try:
                    from d27_pm_workloop import capture as capture_pm_workloop
                    selected_symbols=json.loads(Path(__file__).with_name('symbols.json').read_text())
                    report['pm_workloop']=capture_pm_workloop(packet,regs,selected_symbols,process_plan)
                except (ValueError,RuntimeError) as error:report['pm_workloop_error']=str(error)
                # Retry every selected native scalar via actual TTBR1 at the
                # same final stop, including when the active CPU stopped in EL0.
                report['ttbr1_memory_errors']={}
                for request in args.read_memory:
                    try:
                        address,length=(int(v,16) for v in request.split(':'))
                        result=read_kernel_memory(packet,regs,address,length)
                        report['memory'][request]=result['bytes']
                    except (ValueError,RuntimeError) as error:report['ttbr1_memory_errors'][request]=str(error)
                try:
                    def kread(address,size):
                        data=bytes.fromhex(read_kernel_memory(packet,regs,address,size)['bytes'])
                        if len(data)!=size:raise ValueError('Kernel log field not mapped')
                        return data
                    ptr=int.from_bytes(kread(MSG_BUF_SYMBOL,8),'little')
                    ptr=kernel_pointer_view(ptr,regs['TCR_EL1'])
                    header=kread(ptr,24);magic,size,write,index=struct.unpack('<4I',header[:16])
                    if not 0<size<=1024*1024 or not 0<=write<size:raise ValueError('Unbounded msgbuf ring')
                    pointer=kernel_pointer_view(int.from_bytes(header[16:24],'little'),regs['TCR_EL1'])
                    # The QEMU GDB transport can reject a full4096-byte physical
                    # reply while serving smaller reads at the same mapped page.
                    data=b''.join(kread(pointer+offset,min(1024,size-offset)) for offset in range(0,size,1024))
                    log=(data[write:]+data[:write]).replace(b'\\0',b'')
                    (fixture/'kernel.log').write_bytes(log)
                    report['kernel_log']=dict(bytes=len(log),sha256=hashlib.sha256(log).hexdigest(),read_only=True)
                except (ValueError,RuntimeError) as error:report['kernel_log_error']=str(error)
""".replace('PM_OBJECT_SYMBOL',names['_native_legacy_object']).replace('MSG_BUF_SYMBOL',names['_msgbufp'])
    text=text.replace("            (fixture / 'gdb-stop.json').write_text",attach+"            (fixture / 'gdb-stop.json').write_text")
    observer=out/'observer.py';observer.write_text(text)
    if a.capture_data:
        marker="            (fixture / 'gdb-stop.json').write_text"
        if text.count(marker)!=1:raise ValueError('Final Data capture requires the unique stopped observation site')
        hook='''            try:
                import importlib.util
                spec=importlib.util.spec_from_file_location('d27_data_capture', '/mnt/g/UniXNU-Port/ports/UniXNU-pdx234/ci/qemu/capture-d27-data.py')
                data_capture_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(data_capture_module)
                selected_symbols=json.loads(Path(__file__).with_name('symbols.json').read_text())
                regs={key:int(value,16) for key,value in report['system_registers'].items()}
                report['data_snapshot']=data_capture_module.capture_qmp(regs,selected_symbols,fixture/'captured-data.dbr')
            except (ValueError,RuntimeError,OSError) as error:report['data_snapshot_error']=str(error)
'''
        text=text.replace(marker,hook+marker);observer.write_text(text)
    command=['python3','-B',str(observer),names[a.checkpoint],'--esp',str(esp),'--kernel',str(kernel),
        '--fixture',str(out/'observation'),'--gic-version','3','--qemu-memory-mib',str(a.memory_mib),'--smp',str(a.cpus),
        '--system-registers','--qemu-ramfb','--firmware','/usr/share/AAVMF/AAVMF_CODE.fd','--timeout',str(a.timeout),
        '--virtio-block-image',disks['OS']['path'],'--virtio-extra-block-image',disks['SystemOS']['path'],
        '--capture-screen','--process-layout-plan',str(out/'process-layout.json'),'--allproc-address',names['_allproc'],
        '--proc-pid-offset',str(layout['process_layout']['pid']),'--proc-comm-offset',str(layout['process_layout']['comm']),
        '--proc-stat-offset',str(layout['process_list_layout']['state']),'--proc-list-offset',str(layout['process_list_layout']['next']),
        '--proc-list-max','512','--read-frame-locals','--inspect-ui-threads']
    if a.checkpoint!='_load_init_program_at_path':command+=['--trace-address',names['_load_init_program_at_path']]
    for name in ('_panic','_panic_with_options','_Assert','_unixnu_fileset_unmapped'):command+=['--also-stop',names[name]]
    fields={}
    prefixes=('_native_owner_root_','_native_owner_cache_','_native_owner_data_','_native_qemu_storage_',
              '_native_virtio_','_native_legacy_','_native_keystore_','_native_aks_','_native_keyevents_',
              '_armcpu_smp_','_native_gpu_power_','_native_cpufreq_','_native_ufs_probe_',
              '_native_hid_','_native_touch_','_native_virtio_input_')
    # Read scalar globals using symbol extent, never assume pointer/array widths.
    native_symbols=native.symbols()
    sorted_symbols=sorted(native_symbols)
    for index,address in enumerate(sorted_symbols):
        for name in native_symbols[address]:
            if not name.startswith(prefixes):continue
            section=native.section(address)
            if not section or section['segment'] in ('__TEXT_EXEC','__TEXT'):continue
            width=sorted_symbols[index+1]-address if index+1<len(sorted_symbols) else 0
            if width in (4,8):fields[name]=dict(address=hex(address),bytes=width)
    for name,field in fields.items():command+=['--read-memory',field['address'][2:]+':'+format(field['bytes'],'x')]
    save(out/'inputs.json',dict(command=command,native_sha256=nr['native_sha256'],strict_sha256=sr['candidate_sha256'],
         sealed_kernel_sha256=sha(kernel),original_os_disks=disks,fields=fields,boot_arguments=bootargs,
         observer_sha256=sha(observer),observer_parent_sha256=sha(observer_source),process_layout=layout,
         current_derived=True,real_init_path='/sbin/launchd',device_operations=False,desktop_verified=False))
    print('START actual current-derived D27 launchd, deadline'+str(a.timeout)+'s '+str(out),flush=True)
    start=time.monotonic()
    with (out/'run.log').open('x') as f:done=subprocess.run(command,stdout=f,stderr=subprocess.STDOUT,env=dict(os.environ,TMPDIR='/run',PYTHONDONTWRITEBYTECODE='1'),timeout=a.timeout+(900 if a.capture_data else 90))
    observed=out/'observation/gdb-stop.json'
    obs=json.loads(observed.read_text()) if observed.exists() else {}
    values={}
    for name,field in fields.items():
        value=obs.get('memory',{}).get(field['address'][2:]+':'+format(field['bytes'],'x'))
        if value and not value.startswith('E'):values[name]=int.from_bytes(bytes.fromhex(value),'little')
    result=dict(exit_code=done.returncode,elapsed_seconds=round(time.monotonic()-start,2),pc=obs.get('pc'),
        bounded_timeout_interrupted=obs.get('bounded_timeout_interrupted'),actual_process=obs.get('actual_process'),
        processes=obs.get('process_list'),trace_events=obs.get('trace_events'),values=values,display_pm=obs.get('display_pm'),
         ui_thread_snapshots=obs.get('ui_thread_snapshots'),
         qemu_display=obs.get('qemu_display'),
         pm_workloop=obs.get('pm_workloop'),
        current_derived=True,real_init_path='/sbin/launchd',desktop_verified=False,device_operations=False,
        original_seed_unchanged=sha(retained/'scratch-data.img')=='23cd7aa2db7b26eae5d30b956d840f475c45017893077005a8b8ce87e44b584d')
    save(out/'result.json',result)
    display=result.get('qemu_display') or {}
    print(json.dumps(dict(exit_code=done.returncode,elapsed_seconds=result['elapsed_seconds'],pc=result['pc'],
        process_count=len(result.get('processes') or []),
        ui=[row for row in result.get('processes') or [] if row['name'] in ('launchd','SpringBoard','backboardd')],
        display=display.get('counters'),pm=(result.get('display_pm') or {}).get('pm'),
        kernel_log=obs.get('kernel_log'),kernel_log_error=obs.get('kernel_log_error'),
        desktop_verified=False,report=str(out/'result.json')),indent=2),flush=True)

if __name__=='__main__':main()
