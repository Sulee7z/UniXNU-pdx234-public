#!/usr/bin/env python3
"""Summarize retained current build receipts without changing any inputs."""
import json
from pathlib import Path

base = Path('/mnt/e/UniXNU-sheng27-sony-20261113')
native = base / 'native-first-frame-058-001'
r = json.loads((native / 'result.json').read_text())
print(json.dumps({k:v for k,v in r.items() if k not in ('native_source_patches','sources','reused_objects','boot_screen','generated_iig_compat','archive_sources','compile_results')}, indent=2)[:15000])
plan = json.loads((base / 'native-screen007-055-001/plan.json').read_text())
print('STORAGE_JOBS')
for job in plan['jobs']:
    if job['group'] == 'storage' or job['source'].endswith('/bsd_init.c'):
        print(json.dumps({k:job[k] for k in ('group','source','source_sha256','output','directory')}))
print('SOURCE_PATCHES')
for item in r.get('native_source_patches', []): print(json.dumps(item))
