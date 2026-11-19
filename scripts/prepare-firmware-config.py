#!/usr/bin/env python3
"""Generate numeric firmware parameters from Sony OEM cfg, with documented software-only overrides."""
import hashlib
import json
from pathlib import Path
import re

DEVICE = Path(__file__).resolve().parents[1]
PROJECT = DEVICE.parents[1]
UEFI = PROJECT / 'ports/uefi-pdx234'


def main():
    source = PROJECT / 'diagnostics/pdx234-vendor-uefiplat.cfg'
    section, values = '', {}
    for line in source.read_text().splitlines():
        line = line.split('#', 1)[0].strip()
        if line.startswith('['):
            section = line
        if section != '[ConfigParameters]':
            continue
        match = re.fullmatch(r'([A-Za-z0-9_]+)\s*=\s*(0x[0-9a-fA-F]+|[0-9]+)', line)
        if match:
            values[match[1]] = int(match[2], 0)
    overrides = {'NumActiveCores': 1, 'EnableMultiThreading': 0, 'EnableMultiCoreFvDecompression': 0,
                 'EnableLogFsSyncInRetail': 0, 'EnableDisplayThread': 0}
    values.update(overrides)
    output = UEFI / 'Platforms/Sony/pdx234Pkg/Library/ConfigurationMapLib/ConfigurationMapLib.c'
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise RuntimeError('Preserve existing generated firmware parameters')
    lines = ['// SPDX-License-Identifier: BSD-2-Clause-Patent',
             '// Sony OEM numeric configuration, with single-core/nonpersistent software overrides.',
             '#include <Library/ConfigurationMapLib.h>',
             'STATIC EFI_CONFIGURATION_ENTRY_DESCRIPTOR gConfigurationDescriptor[] = {']
    lines.extend(f'  {{"{name}", 0x{value:X}}},' for name, value in sorted(values.items()))
    lines.extend(['};', 'VOID GetConfigurationMap (OUT EFI_CONFIGURATION_ENTRY_DESCRIPTOR **Map, OUT UINT8 *Count) {',
                  '  *Map = gConfigurationDescriptor; *Count = ARRAY_SIZE(gConfigurationDescriptor);', '}'])
    output.write_text('\n'.join(lines)+'\n')
    (DEVICE / 'evidence/sony-firmware-parameters.json').write_text(json.dumps(dict(
        source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(), parameters=values,
        overrides=overrides, generated_source_sha256=hashlib.sha256(output.read_bytes()).hexdigest(),
        hardware_tested=False), indent=2))
    print('Sony firmware parameters generated:', len(values))


if __name__ == '__main__':
    main()
