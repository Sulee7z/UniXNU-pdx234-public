#!/usr/bin/env python3
"""Read-only startup source evidence for the D27 Metal adapter."""
from pathlib import Path
import shutil

base = Path('/mnt/e/UniXNU-sheng27-sony-20261113')
print('disk', shutil.disk_usage(base))
root = base / 'metal-runtime-001'
for directory, names, terms in [
    (root / '.cache/gpu-reference/metal2vulkan/crates/metal2vulkan-runtime/src', '*.rs',
     ('METAL2VULKAN_SHADER_CACHE_OPTIONAL', 'struct CacheSetup', 'impl CacheSetup')),
    (base / 'metal-d27-qualified-001/drivers/AdrenoMetal', '*.h', ('void streamText',)),
    (root / '.cache/mesa-work/src/freedreno/vulkan', 'tu_knl_darwin.cc', ('IOServiceOpen',)),
]:
    for path in directory.rglob(names):
        lines = path.read_text().splitlines()
        for i, line in enumerate(lines):
            if any(term in line for term in terms):
                print(path)
                for n in range(max(0, i-8), min(len(lines), i+65)):
                    print(f'{n+1}: {lines[n]}')
