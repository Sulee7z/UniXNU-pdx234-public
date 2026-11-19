#!/usr/bin/env python3
"""Finalize the local AMFI-platform-corrected diagnostic after actual checks."""
import hashlib
import importlib.util
import json
import lzma
from pathlib import Path
import shutil
import struct
import subprocess
import zlib

DEVICE = Path(__file__).resolve().parents[2]


def main():
    def read(relative):
        return json.loads((DEVICE / relative).read_text())

    def sha(blob):
        return hashlib.sha256(blob).hexdigest()

    payload = DEVICE / 'out/sony-ufs-test-payload-005'
    candidate = DEVICE / 'out/sony-ufs-test-candidate-003'
    info = read('out/sony-ufs-test-payload-005/report.json')
    image_info = read('out/sony-ufs-test-candidate-003/report.json')
    selector = read('out/sony-ufs-test-candidate-003/selector-report.json')
    transport = read('out/sony-ufs-transport-check-003/report.json')
    branch = read('out/d27-amfi-platform-001/report.json')
    if not (info['adt_vmm_present'] == 1 and info['fat_adt_byte_identity'] and
            selector['passed'] and len(selector['cases']) == 11 and
            transport['actual_sony_adapter_executed'] and transport['actual_shared_fat_path'] and
            branch['passed'] and not info['strict_report']['missing'] and
            not info['strict_report']['stubbed'] and not info['strict_report']['allow_missing']):
        raise ValueError('Required release evidence did not pass')
    image = (candidate / 'boot-pdx234-dual-xnu-entry-CANDIDATE.img').read_bytes()
    if sha(image) != image_info['image_sha256']:
        raise ValueError('Final image identity differs')
    field = image[4096:4096 + struct.unpack_from('<I', image, 8)[0]]
    off, length = image_info['bundle_offset'], image_info['bundle_bytes']
    bundle = field[off:off + length]
    magic, header, compressed, expanded, crc, reserved = struct.unpack_from('<8s4IQ', bundle)
    fat = lzma.decompress(bundle[header:], format=lzma.FORMAT_ALONE)
    if (magic != b'PDXFAT02' or header != 32 or reserved or compressed != len(bundle)-32 or
            len(fat) != expanded or zlib.crc32(fat) != crc or sha(fat) != info['payload_sha256']):
        raise ValueError('Final image FAT identity differs')
    out = DEVICE / 'out/sony-ufs-test-release-003'
    out.mkdir(exist_ok=False)
    final_fat = out / 'final-unpack.fat'
    final_fat.write_bytes(fat)
    for member, target in [('Payloads/kernel.macho', 'kernel.macho'),
                           ('Payloads/kernel.macho.adt', 'kernel.macho.adt'),
                           ('unixnu.toml', 'unixnu.toml')]:
        subprocess.run(['mcopy', '-i', str(final_fat), f'::/EFI/UniXNU/{member}', str(out / target)], check=True)
        if (out / target).read_bytes() != (payload / 'stage/EFI/UniXNU' / member).read_bytes():
            raise ValueError(f'Final image FAT member differs: {member}')
    final_fat.unlink()
    spec = importlib.util.spec_from_file_location('apple_device_tree', DEVICE / 'scripts/apple-device-tree.py')
    codec = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(codec)
    if codec.u32(codec.parse((out / 'kernel.macho.adt').read_bytes()), '/defaults', 'vmm-present') != 1:
        raise ValueError('Final image ADT is not the corrected platform')
    if (out / 'kernel.macho').read_bytes() != (DEVICE / 'out/sony-ufs-test-release-002/kernel.macho').read_bytes():
        raise ValueError('ADT-only fix unexpectedly changed the kernel')
    name = 'boot-pdx234-UFS-TEST-003.img'
    (out / name).write_bytes(image)
    copies = {
        'image-report.json': 'out/sony-ufs-test-candidate-003/report.json',
        'selector-report.json': 'out/sony-ufs-test-candidate-003/selector-report.json',
        'transport-report.json': 'out/sony-ufs-transport-check-003/report.json',
        'amfi-platform-report.json': 'out/d27-amfi-platform-001/report.json',
        'strict-report.json': 'out/sony-ufs-test-release-002/strict-report.json',
        'host-checks.json': 'out/sony-ufs-test-release-002/host-checks.json',
        'gpt-diagnostic-checks.json': 'out/sony-ufs-test-release-002/gpt-diagnostic-checks.json',
        'entry-bars-check.json': 'out/sony-ufs-test-release-002/entry-bars-check.json',
        'qemu-read-result.json': 'out/sony-ufs-test-release-002/qemu-read-result.json',
        'qemu-heap-display-result.json': 'out/sony-ufs-test-release-002/qemu-heap-display-result.json',
        'qemu-heap-display.png': 'out/sony-ufs-test-release-002/qemu-heap-display.png',
        'driver-route.md': 'docs/SHENG27-DRIVER-ROUTE-20261110.md',
        'sheng27-upstream.json': 'out/sheng27-route-audit-001/upstream.json',
    }
    for target, source in copies.items():
        shutil.copyfile(DEVICE / source, out / target)
    photo = Path('/mnt/g/DSC_0000_BURST20261110180834203_COVER.JPG')
    observation = dict(photo=str(photo), photo_sha256=sha(photo.read_bytes()),
        tested_image_sha256=read('out/sony-ufs-test-release-002/release.json')['hashes']['boot-pdx234-UFS-TEST-002.img'],
        message='AMFI: No PMGR?', location='ConfigurationSettings.cpp:392',
        frames=['0xfffffff008eaac40', '0xfffffff008e8985c', '0xfffffff008e89450',
                '0xfffffff008e93cac', '0xfffffff00a227adc', '0xfffffff00a2293cc', '0xfffffff00a3e45d0'],
        thread='AMFI async thread-call; native thread_call_invoke+0xb0/thread_call_thread+0x220',
        sony_gpt_read_success_observed=False, agent_device_operations=False)
    (out / 'handset002-observation.json').write_text(json.dumps(observation, indent=2)+'\n')
    release = dict(image=name, bytes=len(image), image_sha256=sha(image),
        kernel_sha256=sha((out/'kernel.macho').read_bytes()),
        adt_sha256=sha((out/'kernel.macho.adt').read_bytes()), adt_vmm_present=1,
        final_boot_fat_members_independently_unpacked=True, same_kernel_as_test002=True,
        original_amfi_positive_negative_branches_passed=True, selector_cases_passed=11,
        actual_fat_transport_passed=True, strict_missing={}, strict_stubbed={}, allow_missing=False,
        sheng27_revision='00ba90984e831e4c6ce30ec3d8a56e6434e9f1af',
        driver_route='docs/SHENG27-DRIVER-ROUTE-20261110.md',
        android_kernel_sha256=info['android_sha256'],
        sony_gpt_read_success_observed=False, root_mounted=False, springboard_verified=False,
        media_write_windows_disabled=True, agent_device_operations=False, github_actions_invoked=False,
        inherited_unchanged_kernel_checks_from='out/sony-ufs-test-release-002')
    (out/'release.json').write_text(json.dumps(release, indent=2)+'\n')
    (DEVICE/'evidence/sony-ufs-test-candidate-003.json').write_text(json.dumps(release, indent=2)+'\n')
    readme = f'''# Sony PDX234 UFS TEST 003

镜像：`{name}`，{len(image):,} 字节。

SHA256：

```
{sha(image)}
```

修正测试002的 ADT 平台错误：按 sheng27 保留 `vmm-present=1`，避免原 AMFI 等待不存在的 ApplePMGRNub。
D27 原 AMFI 代码不变。同一内核正负对照已确认该属性决定其真实分支。
最终 boot 已独立解包 FAT，逐字节核对内核、ADT、菜单，并再次解析 vmm-present=1。

默认启动原 Android；按住音量上进入 UEFI。菜单选择一次：

**Sony UFS - complete read-only check**

依次检查控制器、空闲队列、SMMU、NOP/LUN、容量、GPT CRC/固定 Sony 身份及重复读取。
成功停屏显示 `SONY_UFS GPT READ PASS`；LUN0 blocks=62461952、block=4096、entries=97，
header SHA256=2bbaf33a84c91dfb0e97d42d9ba7ad7a4e0feeb4efe08681ce187a7eb1a059b9，table CRC=7b5b5756。
不自动重启；失败保留实际错误画面。保持原 init_boot/vendor_boot/DTBO，不把裸 kernel.macho 当 boot 镜像。

只读诊断未开启 Data/日志媒体写窗口，不修改 GPT/F2FS。Sony GPT 读盘、根挂载及 SpringBoard 尚未验证。
SMMU SID 迁移仍是待实机确认的板级适配。所有驱动和依赖统一沿用 sheng27 路线，见 driver-route.md；
当前包不表示显示/GPU/HID/网络等已全部完成。

本轮 AMFI 双分支、11项 selector、真实 Sony 适配器/共享 RAM-disk/FAT 均通过。
9组 sanitizer、10种 probe10 输入、QEMU 首扇区和堆显示记录复用测试002：内核 SHA 完全相同，未冒充重跑。
代理未执行手机刷写、重启、RAM boot，也未触发 Actions。
'''
    (out/'README.md').write_text(readme)
    (out/'SHA256SUMS').write_text(''.join(f'{sha(f.read_bytes())}  {f.name}\n'
        for f in sorted(out.iterdir()) if f.is_file() and f.name != 'SHA256SUMS'))
    print(json.dumps(release, indent=2))


if __name__ == '__main__':
    main()
