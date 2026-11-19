#!/usr/bin/env python3
"""Run official policy regression bodies against the selected069 source; mock syscalls."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'ci/platform069/crashes'))
from audit import FRESH, sha


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build', type=Path, default=FRESH / 'crashes-build-001')
    p.add_argument('--out', type=Path, default=FRESH / 'crashes-policy-tests-001')
    a = p.parse_args()
    out = a.out.resolve()
    if not out.is_relative_to(FRESH) or out.exists():
        raise ValueError('Require fresh069artifact output')
    official = FRESH / 'sheng/scripts/check-boot-watchdog-policy.py'
    tree = ast.parse(official.read_text())
    values = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in ('prefix', 'main'):
                    values[target.id] = node.value.value
    if set(values) != {'prefix', 'main'}:
        raise ValueError('Unknown official host harness')
    text = (a.build / 'BootWatchdogPolicy.c').read_text()
    body = text[text.index('static const char policy'):]
    # Official stand-in duplicates static jobs[200]; production owns it too.
    # Rename only the fake boot-argument input, keeping tested production intact.
    prefix = values['prefix'].replace('static char jobs[200];', 'static char input_jobs[200];')
    prefix = prefix.replace('memcpy(out,jobs,200);return jobs[0]!=0;', 'memcpy(out,input_jobs,200);return input_jobs[0]!=0;')
    main = values['main'].replace('jobs[0]=0;', 'input_jobs[0]=0;').replace('strcpy(jobs,', 'strcpy(input_jobs,').replace('memset(jobs,', 'memset(input_jobs,')
    # Existing cache-env scratch sentinels are part of the official tests.
    prefix = prefix.replace('typedef void *proc_t;', 'typedef uintptr_t user_addr_t;\ntypedef long user_ssize_t;\ntypedef void *proc_t;')
    extra = r'''
static void extra_policy_cases(void) {
 reset();enabled=0;lite_arg=1;assert(!run());
 assert(!strstr((char*)written_data,"com.apple.bluetoothd</key>"));
 assert(!strstr((char*)written_data,"com.apple.filesystems.fskitd</key>"));
 assert(!strstr((char*)written_data,"com.apple.pfd</key>"));
 assert(!strstr((char*)written_data,"com.apple.iconservices.iconservicesagent</key>"));
 /* Explicit enable is ordered after exact disabled entries; no global allow. */
 reset();enabled=0;strcpy(input_jobs,"com.example.exact");strcpy(enable_arg,"com.example.exact");assert(!run());
 assert(strstr((char*)written_data,"<key>com.example.exact</key><true/><key>com.example.exact</key><false/>"));
 reset();enabled=0;strcpy(enable_arg,"a&b");assert(run()==EINVAL && !opens);
}
'''
    main = main.replace('int main(void){', 'static void extra_policy_cases(void);\nint main(void){')
    main = main.replace(' return 0;\n}', ' extra_policy_cases();return 0;\n}') + extra
    out.mkdir()
    source = out / 'test.c'
    source.write_text('#define _GNU_SOURCE\n' + prefix + body + main)
    cmd = ['clang-18', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O1', '-g',
           '-fsanitize=address,undefined', str(source), '-o', str(out / 'test')]
    for command, filename in [(cmd, 'compile.log'), ([str(out / 'test')], 'run.log')]:
        done = subprocess.run(command, capture_output=True, text=True, timeout=90)
        (out / filename).write_text(done.stdout + done.stderr)
        if done.returncode:
            raise RuntimeError(done.stdout + done.stderr)
    result = {'passed': True, 'official_harness': str(official), 'official_harness_sha256': sha(official),
              'source_sha256': sha(a.build / 'BootWatchdogPolicy.c'), 'command': cmd,
              'sanitizers': ['address', 'undefined'], 'original_official_cases': True,
              'no_new_automatic_bluetooth_fskit_pfd_or_icons_disable': True,
              'syscalls_modeled_only': True, 'device_operations': False, 'source_body_sha256': hashlib.sha256(body.encode()).hexdigest()}
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'passed': True, 'out': str(out), 'official_cases': True}))


if __name__ == '__main__':
    main()
