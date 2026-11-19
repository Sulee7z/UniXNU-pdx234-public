#!/usr/bin/env python3
"""Capture Linux-owned Sony UFS facts and bounded known blocks without takeover."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', required=True)
    parser.add_argument('--serial', default='PDX_DEVICE_SERIAL')
    parser.add_argument('--official-scripts', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    adb = [args.adb, '-s', args.serial]
    captures = {}

    def read(name, command, length=None):
        r = subprocess.run([*adb, 'exec-out', command], capture_output=True, timeout=30)
        if r.returncode or length is not None and len(r.stdout) != length:
            raise RuntimeError(name + ': ' + r.stderr.decode(errors='replace'))
        (args.out / name).write_bytes(r.stdout)
        captures[name] = dict(command=command, bytes=len(r.stdout), sha256=hashlib.sha256(r.stdout).hexdigest())
        return r.stdout

    if read('uid.txt', 'id -u').strip() != b'0':
        raise ValueError('Requires existing root adbd')
    live = read('live.dtb', 'cat /sys/firmware/fdt')
    read('ufs-sysfs.txt',
         'for p in /sys/bus/platform/devices/1d84000.ufshc/attributes/current_power_mode '
         '/sys/bus/platform/devices/1d84000.ufshc/attributes/reference_clock_frequency '
         '/sys/bus/platform/devices/1d84000.ufshc/qcom/bus_speed_mode '
         '/sys/bus/platform/devices/1d84000.ufshc/qcom/power_mode '
         '/sys/bus/platform/devices/1d84000.ufshc/qcom/clk_status '
         '/sys/bus/platform/devices/1d84000.ufshc/device_descriptor/specification_version '
         '/sys/bus/platform/devices/1d84000.ufshc/device_descriptor/queue_depth '
         '/sys/bus/platform/devices/1d84000.ufshc/device_descriptor/number_of_luns '
         '/sys/bus/platform/devices/1d84000.ufshc/interconnect_descriptor/mphy_version '
         '/sys/bus/platform/devices/1d84000.ufshc/interconnect_descriptor/unipro_version '
         '/sys/class/block/sda/device/vendor /sys/class/block/sda/device/model '
         '/sys/class/block/sda/device/rev /sys/class/block/sda/device/queue_depth '
         '/sys/class/block/sda/queue/logical_block_size /sys/class/block/sda/size; '
         'do echo "$p"; cat "$p"; done')
    read('iommu-links.txt',
         'readlink -f /sys/bus/platform/devices/1d84000.ufshc/iommu; '
         'readlink -f /sys/bus/platform/devices/1d84000.ufshc/iommu_group; '
         'ls -l /sys/kernel/iommu_groups/0/devices')
    read('interrupts.txt', 'cat /proc/interrupts')
    read('block-devices.txt',
         'for p in /sys/class/block/sd?; do echo "$p"; readlink -f "$p/device"; '
         'cat "$p/size" "$p/queue/logical_block_size"; done')
    for name, first, count in [('gpt-header', 1, 1), ('gpt-table', 2, 4), ('gpt-backup', 62461947, 5)]:
        data = read(name + '.bin', f'dd if=/dev/block/sda bs=4096 skip={first} count={count} 2>/dev/null', count * 4096)
        again = read(name + '-again.bin', f'dd if=/dev/block/sda bs=4096 skip={first} count={count} 2>/dev/null', count * 4096)
        if data != again:
            raise ValueError('Known block data changed: ' + name)
    sys.path.insert(0, str(args.official_scripts.resolve()))
    from unixnu.devicetree import read_fdt, registers, physical
    root = read_fdt(live)
    handles = {n.scalar('phandle'): n for n in root.walk() if 'phandle' in n.properties}

    def path(n):
        return path(n.parent).rstrip('/') + '/' + n.name if n.parent else '/'

    def references(n, key, cell_name):
        cells = n.cells(key)
        result = []
        at = 0
        while at < len(cells):
            provider = handles[cells[at]]
            count = provider.scalar(cell_name)
            if at + 1 + count > len(cells):
                raise ValueError('Truncated phandle specifier: ' + key)
            result.append(dict(provider=path(provider), arguments=cells[at + 1:at + 1 + count]))
            at += 1 + count
        return result

    hardware = []
    for n in root.walk():
        if n.name not in ('ufshc@1d84000', 'ufsphy_mem@1d80000', 'apps-smmu@15000000'):
            continue
        row = dict(path=path(n), compatible=n.strings('compatible'), enabled=n.enabled(),
                   registers=[dict(physical=hex(physical(n.parent, a, s)), bytes=s) for a, s in registers(n)])
        for key in ('reg-names', 'clock-names', 'reset-names', 'interconnect-names'):
            if key in n.properties:
                row[key] = n.strings(key)
        for key in ('interrupts', 'limit-tx-hs-gear', 'limit-rx-hs-gear', 'limit-rate', 'lanes-per-direction'):
            if key in n.properties:
                row[key] = n.cells(key)
        for key, count in [('clocks', '#clock-cells'), ('iommus', '#iommu-cells'), ('resets', '#reset-cells'),
                           ('phys', '#phy-cells'), ('interconnects', '#interconnect-cells')]:
            if key in n.properties:
                row[key] = references(n, key, count)
        row['supplies'] = {key: path(handles[n.scalar(key)]) for key in n.properties if key.endswith('-supply')}
        row['dma-coherent'] = 'dma-coherent' in n.properties
        hardware.append(row)
    report = dict(serial=args.serial, hardware=hardware, captures=captures,
                  known_blocks_repeated_reads_match=True, evidence_scope='Linux-owned observations only',
                  xnu_ufs_qualified=False, firmware_handoff_qualified=False,
                  mmio_accessed=False, device_writes=False, rebooted=False)
    (args.out / 'survey.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'captures'}, indent=2))


if __name__ == '__main__':
    main()
