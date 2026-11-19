#!/usr/bin/env python3
"""Repack only the D27 menu OS title/default; preserve every executable input."""
import argparse
import hashlib
import json
import lzma
from pathlib import Path
import runpy
import struct
import subprocess
import sys
import zlib
import tomllib

ROOT=Path(__file__).resolve().parents[2]
def sha(data):return hashlib.sha256(data).hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--release',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--work',type=Path,required=True)
    p.add_argument('--disable-cdc-firmware',type=Path,help='Package050 with verified CDC-free firmware and qcom-usb-debug=0')
    p.add_argument('--enable-gpu',action='store_true',help='Package051 from049 retaining CDC and enabling the Sony GPU/Metal path')
    p.add_argument('--desktop-cdc-off',action='store_true',help='Package054 from053 retaining its repaired native/display kernel')
    a=p.parse_args()
    if a.enable_gpu and a.disable_cdc_firmware:p.error('GPU051 retains its baseline CDC firmware')
    if a.desktop_cdc_off and (not a.disable_cdc_firmware or a.enable_gpu):p.error('--desktop-cdc-off requires CDC-free firmware')
    sys.path.insert(0,str(ROOT/'ci'))
    from sony_menu_identity import select_ios_default
    sys.argv=['verify','--release',str(a.release)]
    v=runpy.run_path(str(Path(__file__).with_name('verify-delivered-high-memory.py')))
    original=v['get']('EFI/UniXNU/unixnu.toml').decode()
    corrected=select_ios_default(original)
    firmware=v['fd'];firmware_checks=None
    if a.enable_gpu:
        if v['j']['sha256']!='522684f3afe72d30df1bfe26ce41c561d811d1bc0181989b07a7ef4b30ca2a94':
            raise ValueError('GPU051 requires qualified049 baseline')
        old_args=v['j']['kernel_args'];tokens=old_args.split()
        replacements={'gpu-power=0':'gpu-power=9','gpu-metal=0':'gpu-metal=1',
            'sheng-gpu-addon=0':'sheng-gpu-addon=1','fb-gpu=0':'fb-gpu=1','build-tag=PDX034':'build-tag=PDX051'}
        for old in replacements:
            if tokens.count(old)!=1:raise ValueError('Unexpected GPU baseline '+old)
        if any(t.startswith('dpu-scanout=') for t in tokens):raise ValueError('Unexpected direct scanout selection')
        tokens=[replacements.get(t,t) for t in tokens]+['dpu-scanout=0']
        new_args=' '.join(tokens)
        if corrected.count(old_args)!=1:raise ValueError('Ambiguous boot arguments')
        corrected=corrected.replace(old_args,new_args)
        before=tomllib.loads(original);after=tomllib.loads(corrected)
        next(e for e in after['entry'] if e['id']=='xnu')['args']=old_args
        if before!=after:raise ValueError('Unexpected GPU configuration change')
    if a.disable_cdc_firmware:
        subprocess.run([sys.executable,'-B',str(Path(__file__).with_name('verify-sony-usb-firmware.py')),
                        '--build',str(a.disable_cdc_firmware)],check=True,stdout=subprocess.DEVNULL)
        fw=json.loads((a.disable_cdc_firmware/'result.json').read_text())
        firmware_checks=json.loads((a.disable_cdc_firmware/'usb-verification.json').read_text())
        if not firmware_checks.get('cdc_disabled_verified'):raise ValueError('CDC exclusion not verified')
        firmware=Path(fw['fd']).read_bytes()
        if len(firmware)!=len(v['fd']) or sha(firmware)!=firmware_checks['fd_sha256']:raise ValueError('Firmware differs')
        old_args=v['j']['kernel_args']
        old_tag='PDX053' if a.desktop_cdc_off else 'PDX034'
        label='054' if a.desktop_cdc_off else '050'
        if a.desktop_cdc_off and v['j']['sha256']!='49dfab1de6255e714aceeac98b1d9bd00be596b90e5dad67fa892c8e84e46649':raise ValueError('Require consolidated053 baseline')
        if old_args.split().count('qcom-usb-debug=1')!=1 or old_args.split().count('build-tag='+old_tag)!=1:
            raise ValueError('Unexpected baseline arguments')
        new_args=old_args.replace('qcom-usb-debug=1','qcom-usb-debug=0').replace('build-tag='+old_tag,'build-tag=PDX'+label)
        if corrected.count(old_args)!=1:raise ValueError('Ambiguous boot entry')
        corrected=corrected.replace(old_args,new_args)
        before=tomllib.loads(original);after=tomllib.loads(corrected)
        next(e for e in after['entry'] if e['id']=='xnu')['args']=old_args
        if before!=after:raise ValueError('Unexpected CDC-off configuration changes')
        if a.desktop_cdc_off:
            old_title=tomllib.loads(corrected)['ui']['title']
            if corrected.count(old_title)!=1 or 'PAC-ABI-053' not in old_title:raise ValueError('Unexpected053 menu title')
            corrected=corrected.replace(old_title,old_title.replace('PAC-ABI-053','PAC-ABI-054'))
    a.work.mkdir(parents=True,exist_ok=False)
    config=a.work/'unixnu.toml';config.write_text(corrected)
    fatfile=a.work/'payload.fat';fatfile.write_bytes(v['fat'])
    subprocess.run(['mcopy','-o','-i',str(fatfile),str(config),'::/EFI/UniXNU/unixnu.toml'],check=True)
    roundtrip=a.work/'roundtrip.toml'
    subprocess.run(['mcopy','-i',str(fatfile),'::/EFI/UniXNU/unixnu.toml',str(roundtrip)],check=True)
    if roundtrip.read_bytes()!=config.read_bytes():raise ValueError('Menu FAT mismatch')
    fat=fatfile.read_bytes();compressed=bytearray(lzma.compress(fat,format=lzma.FORMAT_ALONE,preset=6))
    compressed[5:13]=struct.pack('<Q',len(fat))
    blob=struct.pack('<8s4IQ',b'PDXFAT02',32,len(compressed),len(fat),zlib.crc32(fat),0)+compressed
    bundle=a.work/'payload.bundle';bundle.write_bytes(blob)
    android=a.work/'Android.Image';android.write_bytes(v['android'])
    fd=a.work/'firmware.fd';fd.write_bytes(firmware)
    memory,flags=struct.unpack_from('<QQ',v['android'],16)
    inputs=a.work/'Pdx234ComboInputs.h'
    inputs.write_text('\n'.join([
        f'#define ANDROID_INPUT_PATH "{android}"',f'#define UEFI_FD_INPUT_PATH "{fd}"',
        f'#define XNU_BUNDLE_INPUT_PATH "{bundle}"',f'#define ANDROID_MEMORY_BYTES {memory}',
        f'#define ANDROID_IMAGE_FLAGS {flags}',f'#define ANDROID_IMAGE_BYTES {len(v["android"])}',
        f'#define ANDROID_IMAGE_CRC32 {zlib.crc32(v["android"])}',
        '#define ANDROID_PAYLOAD_OFFSET 0x200000','#define SPMI_CORE_BASE 0xc400000',
        '#define SPMI_OBSERVER_BASE 0xc440000','#define FD_BASE 0xa7100000','#define FD_SIZE 0x300000'])+'\n')
    source=ROOT.parent/'uefi-pdx234/BootShim/Pdx234Combo.S'
    subprocess.run(['clang','--target=aarch64-none-elf','-I',str(a.work),'-c',str(source),'-o',str(a.work/'combo.o')],check=True)
    subprocess.run(['ld.lld','-Ttext=0','-e','_Head',str(a.work/'combo.o'),'-o',str(a.work/'combo.elf')],check=True)
    subprocess.run(['llvm-objcopy','-O','binary',str(a.work/'combo.elf'),str(a.work/'combo.Image')],check=True)
    combo=(a.work/'combo.Image').read_bytes();header=bytearray(v['raw'][:4096])
    # The wrapper instructions and Android/FD extents must match. Only the
    # Linux Image size word and bundle-dependent literal/metadata may vary.
    if combo[0x200000:0x200000+len(v['android'])]!=v['android']:raise ValueError('Android changed')
    if combo[0x200000+memory:0x200000+memory+len(firmware)]!=firmware:raise ValueError('Firmware changed')
    struct.pack_into('<II',header,8,len(combo),0);struct.pack_into('<I',header,1580,0)
    image=header+combo+bytes(-len(combo)%4096)
    if len(image)>128*1024*1024:raise ValueError('Image exceeds boot capacity')
    a.out.mkdir(parents=True,exist_ok=False)
    target=a.out/('boot-pdx234-pac-abi-054.img' if a.desktop_cdc_off else 'boot-pdx234-pac-abi-051.img' if a.enable_gpu else 'boot-pdx234-pac-abi-050.img' if a.disable_cdc_firmware else 'boot-pdx234-pac-abi-047-menu.img');target.write_bytes(image)
    record=v['j'];record.update(image=str(target),sha256=sha(image),bytes=len(image),
        label='PAC-ABI-047-MENU',source_image_sha256=sha(v['raw']),
        menu_title='Sony PDX234 iOS 27 D27 XNU PAC-ABI-034 PANIC SCREEN',menu_default='xnu',
        correction='Menu title iPadOS27 -> iOS 27; default restart -> xnu only',
        cdc_poweroff_fixed=False,hardware_boot_verified=False,usb_hardware_verified=False)
    if a.disable_cdc_firmware:
        record.update(label='PAC-ABI-'+label,firmware_sha256=sha(firmware),kernel_args=new_args,
            correction='Disable UEFI CDC producer/menu consumer and XNU CDC startup; resume desktop bring-up',
            vendor_usb_firmware=firmware_checks,uefi_cdc_frontend=False,cdc_application=False,
            cdc_provider_wait=False,cdc_boundary_diagnostic=False,cdc_core_snapshot=False,
            cdc_disabled=True,xnu_cdc_enabled=False,desktop_verified=False,
            arguments_removed=['qcom-usb-debug=1','build-tag='+old_tag],
            arguments_added=['qcom-usb-debug=0','build-tag=PDX'+label])
        if a.desktop_cdc_off:
            record.update(menu_title=tomllib.loads(corrected)['ui']['title'],usb_core_errors_fixed=False,
                usb_core_trace=False,usb_prepare_errors=False,firmware_build=str(a.disable_cdc_firmware))
            for key in ['usb_core_errors_tests','usb_poll_errors_tests','usb_prepare_errors_tests']:record.pop(key,None)
    if a.enable_gpu:
        record.update(label='PAC-ABI-051',kernel_args=new_args,
            correction='Enable Sony GPU/Metal and retain049 CDC; explicitly disable unadapted sheng direct scanout',
            gpu_enabled=True,software_rendering_control=False,cdc_disabled=False,xnu_cdc_enabled=True,
            desktop_verified=False,arguments_removed=list(replacements),
            arguments_added=list(replacements.values())+['dpu-scanout=0'])
    (a.out/'release.json').write_text(json.dumps(record,indent=2)+'\n')
    (a.out/'SHA256SUMS').write_text(sha(image)+'  '+target.name+'\n')
    print(json.dumps(dict(image=str(target),sha256=sha(image),cdc_poweroff_fixed=False),indent=2))

if __name__=='__main__':main()
