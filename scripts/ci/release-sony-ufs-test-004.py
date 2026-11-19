#!/usr/bin/env python3
"""Finalize the slot-state-tolerant, read-only Sony GPT diagnostic."""
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
    def read(path):
        return json.loads((DEVICE / path).read_text())

    def sha(data):
        return hashlib.sha256(data).hexdigest()

    payload = DEVICE / 'out/sony-ufs-test-payload-006'
    candidate = DEVICE / 'out/sony-ufs-test-candidate-004'
    info = read('out/sony-ufs-test-payload-006/report.json')
    image_info = read('out/sony-ufs-test-candidate-004/report.json')
    checks = {
        'selector-report.json': 'out/sony-ufs-test-candidate-004/selector-report.json',
        'transport-report.json': 'out/sony-ufs-transport-check-004/report.json',
        'entry-bars-check.json': 'out/sony-ufs-test-candidate-004/entry-bars-check.json',
        'gpt-diagnostic-checks.json': 'out/sony-gpt-diagnostic-host-003/report.json',
        'gpt-current-checks.json': 'out/sony-gpt-diagnostic-host-current-001/report.json',
        'qemu-read-result.json': 'out/qemu-sony-runtime-read-004/result.json',
        'qemu-heap-display-result.json': 'out/qemu-sony-heap-display-003/result.json',
        'slot-audit.json': 'out/sony-ufs-test-observation-003/slot-audit.json',
    }
    rows = {name: read(path) for name, path in checks.items()}
    strict = info['strict_report']
    if (strict['missing'] or strict['stubbed'] or strict['allow_missing'] or
            not rows['selector-report.json']['passed'] or len(rows['selector-report.json']['cases']) != 11 or
            not rows['transport-report.json']['actual_shared_fat_path'] or
            not rows['entry-bars-check.json']['passed'] or
            not rows['gpt-diagnostic-checks.json']['passed'] or not rows['gpt-current-checks.json']['passed'] or
            not rows['slot-audit.json']['passed'] or
            not rows['qemu-read-result.json']['actual_virtio_first_sector_read'] or
            not rows['qemu-heap-display-result.json']['reached_requested_checkpoint'] or
            rows['qemu-heap-display-result.json']['kernel_sha256'] != info['kernel_sha256']):
        raise ValueError('Required release checks failed')
    image = (candidate / 'boot-pdx234-dual-xnu-entry-CANDIDATE.img').read_bytes()
    if sha(image) != image_info['image_sha256']:
        raise ValueError('Final boot identity changed')
    field = image[4096:4096 + struct.unpack_from('<I', image, 8)[0]]
    start, size = image_info['bundle_offset'], image_info['bundle_bytes']
    bundle = field[start:start+size]
    magic, header, compressed, expanded, crc, reserved = struct.unpack_from('<8s4IQ', bundle)
    fat = lzma.decompress(bundle[header:], format=lzma.FORMAT_ALONE)
    if (magic != b'PDXFAT02' or header != 32 or reserved or compressed != len(bundle)-32 or
            len(fat) != expanded or zlib.crc32(fat) != crc or sha(fat) != info['payload_sha256']):
        raise ValueError('Final boot bundle changed')
    out = DEVICE / 'out/sony-ufs-test-release-004'
    out.mkdir(exist_ok=False)
    temporary = out / 'unpacked.fat'
    temporary.write_bytes(fat)
    for source, target in [('Payloads/kernel.macho', 'kernel.macho'),
                           ('Payloads/kernel.macho.adt', 'kernel.macho.adt'), ('unixnu.toml', 'unixnu.toml')]:
        subprocess.run(['mcopy', '-i', str(temporary), '::/EFI/UniXNU/'+source, str(out/target)], check=True)
        if (out/target).read_bytes() != (payload/'stage/EFI/UniXNU'/source).read_bytes():
            raise ValueError('Final FAT member changed: '+source)
    temporary.unlink()
    spec = importlib.util.spec_from_file_location('apple_device_tree', DEVICE/'scripts/apple-device-tree.py')
    codec = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(codec)
    if codec.u32(codec.parse((out/'kernel.macho.adt').read_bytes()), '/defaults', 'vmm-present') != 1:
        raise ValueError('Final ADT platform differs')
    name = 'boot-pdx234-UFS-TEST-004.img'
    (out/name).write_bytes(image)
    for target, source in checks.items():
        shutil.copyfile(DEVICE/source, out/target)
    for target, source in {
        'image-report.json': 'out/sony-ufs-test-candidate-004/report.json',
        'qemu-heap-display.png': 'out/qemu-sony-heap-display-003/observation/screen.png',
        'handset003-observation.json': 'evidence/sony-ufs-handset-003.json',
        'driver-route.md': 'docs/SHENG27-DRIVER-ROUTE-20261110.md',
        'adapter-report.json': 'out/sony-ufs-adapter-007/report.json',
    }.items():
        shutil.copyfile(DEVICE/source, out/target)
    (out/'strict-report.json').write_text(json.dumps(strict, indent=2)+'\n')
    release = dict(image=name, image_bytes=len(image), image_sha256=sha(image),
        kernel_sha256=info['kernel_sha256'], strict_source_sha256=strict['candidate_sha256'],
        strict_missing={}, strict_stubbed={}, allow_missing=False, final_adt_vmm_present=1,
        final_boot_members_independently_unpacked=True, actual_fat_transport_passed=True,
        selector_cases=11, old_capture_gpt_cases=50, fresh_capture_gpt_cases=50,
        normalized_boot_attributes_mask='boot_a/b only: 0x78 << 48 (retry/success)',
        stable_geometry_guid_name_attributes_sha_bound=True, live_header_table_crc_required=True,
        repeated_header_compares_to_first_actual_read=True,
        previous_handset_header_table_crc_passed=True, new_handset_repeated_read_verified=False,
        root_mounted=False, springboard_verified=False, media_write_windows_disabled=True,
        android_kernel_sha256=info['android_sha256'], agent_device_operations=False, github_actions_invoked=False)
    (out/'release.json').write_text(json.dumps(release, indent=2)+'\n')
    (DEVICE/'evidence/sony-ufs-test-candidate-004.json').write_text(json.dumps(release, indent=2)+'\n')
    (out/'README.md').write_text(f'''# Sony PDX234 UFS TEST 004

镜像：`{name}`，{len(image):,}字节。

SHA256：

```
{sha(image)}
```

测试003已在Sony读到有效GPT并通过header/table CRC，随后因boot_a动态槽位状态改变而误拒绝。
本包保留实时CRC和稳定磁盘身份SHA，仅归一化boot_a/boot_b的retry/success位。
分区范围、GUID、名称、priority/active/unbootable和其他属性变化仍拒绝。
重复读取与本次第一次真实header逐SHA比较。不会修改GPT或启动槽位状态。

默认启动原Android；音量上进入UEFI，选择 **Sony UFS - complete read-only check**。
成功显示 `SONY_UFS GPT READ PASS`、容量、实际header SHA、table CRC及 `Repeated header matches.`。
实际SHA/CRC随Android启动状态变化，不应要求等于旧包README中的固定值。
失败保留完整错误画面；不自动重启。保持原init_boot/vendor_boot/DTBO。

本包仍是只读诊断，Data/日志媒体写窗口关闭；不缩分区、不改GPT、不挂根盘。
所有驱动依赖沿用sheng27路线，硬件输入属于Sony，系统/ABI属于D27/24A446。
strict无缺失/占位，旧/当前GPT各50项故障与身份测试、190 PAC槽、QEMU目标OS首扇区、
同交付SHA的堆错误显示、最终FAT运输、11项selector及入口色条检查通过。
Sony完整重复读取、owner根挂载、Data和SpringBoard仍待证据。代理未刷写或重启手机。
''')
    (out/'SHA256SUMS').write_text(''.join(f'{sha(f.read_bytes())}  {f.name}\n'
        for f in sorted(out.iterdir()) if f.is_file() and f.name != 'SHA256SUMS'))
    print(json.dumps(release, indent=2))


if __name__ == '__main__':
    main()
