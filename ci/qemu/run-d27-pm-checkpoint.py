#!/usr/bin/env python3
"""Run an already qualified private ESP to a bounded original PM checkpoint."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import os


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base-run', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--checkpoint', default='_load_init_program_at_path')
    p.add_argument('--timeout', type=int, default=180)
    a = p.parse_args()
    inputs = json.loads((a.base_run / 'inputs.json').read_text())
    names = json.loads((a.base_run / 'symbols.json').read_text())
    command = list(inputs['command'])
    kernel = Path(command[command.index('--kernel') + 1])
    with kernel.open('rb') as f:
        if hashlib.file_digest(f, 'sha256').hexdigest() != inputs['sealed_kernel_sha256']:
            raise ValueError('Qualified kernel bytes differ')
    a.out.mkdir(parents=True, exist_ok=False)
    for name in ('symbols.json', 'pm-plan.json', 'process-layout.json'):
        shutil.copyfile(a.base_run / name, a.out / name)
    text = (a.base_run / 'observer.py').read_text()
    marker = "            (fixture / 'gdb-stop.json').write_text"
    if text.count(marker) != 1:
        raise ValueError('Unique final observation required')
    attach = '''            try:
                from d27_pm_workloop import capture as capture_pm_workloop
                regs={key:int(value,16) for key,value in report['system_registers'].items()}
                selected_symbols=json.loads(Path(__file__).with_name('symbols.json').read_text())
                report['pm_workloop']=capture_pm_workloop(packet,regs,selected_symbols,process_plan)
            except (ValueError,RuntimeError) as error:report['pm_workloop_error']=str(error)
'''
    text = text.replace(marker, attach + marker)
    observer = a.out / 'observer.py'
    observer.write_text(text)
    command[2] = str(observer)
    command[3] = names[a.checkpoint]
    command[command.index('--fixture') + 1] = str(a.out / 'observation')
    command[command.index('--timeout') + 1] = str(a.timeout)
    while '--trace-address' in command:
        i = command.index('--trace-address')
        del command[i:i + 2]
    record = dict(command=command, parent_run=str(a.base_run), checkpoint=a.checkpoint,
                  selected_kernel_sha256=inputs['sealed_kernel_sha256'], device_operations=False)
    (a.out / 'inputs.json').write_text(json.dumps(record, indent=2) + '\n')
    print('START actual PM checkpoint', a.checkpoint, flush=True)
    with (a.out / 'run.log').open('x') as log:
        done = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                              env=dict(os.environ, TMPDIR='/run', PYTHONDONTWRITEBYTECODE='1'), timeout=a.timeout + 120)
    observed = json.loads((a.out / 'observation/gdb-stop.json').read_text())
    print(json.dumps(dict(exit=done.returncode, pc=observed['pc'], process=observed.get('actual_process'),
                          pm_workloop=observed.get('pm_workloop'), pm_workloop_error=observed.get('pm_workloop_error')),
                     indent=2), flush=True)


if __name__ == '__main__':
    main()
