#!/usr/bin/env python3
"""Rebase the existing D27 ABI overlays onto the complete upstream27 series.

Reconcile the upstream appsync include and Darwin26 spawn dispatch with the
already audited D27 fixed-prefix behavior. Stack fix is not applied twice.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

DEVICE = Path(__file__).resolve().parents[2]


def rebase_sanitizer(raw):
    before = '''@@ -114,6 +114,7 @@
 #include <sys/ubc_internal.h>           /* ubc_map() */
 #include <sys/spawn.h>
 #include <sys/spawn_internal.h>
+#include <sys/d27_spawn_wire.h>
 #include <sys/process_policy.h>
 #include <sys/codesign.h>
 #include <sys/random.h>
'''
    after = '''@@ -114,7 +114,8 @@
 #include <sys/ubc_internal.h>           /* ubc_map() */
 #include <sys/spawn.h>
 #include <sys/spawn_internal.h>
+#include <sys/d27_spawn_wire.h>
 #include <sys/process_policy.h>
 #include <sys/codesign.h>
 #include <sys/trust_caches.h>          /* appsync_is_user_code() */
 #include <sys/random.h>
'''
    if raw.count(before) != 1:
        raise ValueError('Expected the exact reviewed pre-appsync include context')
    result = raw.replace(before, after)
    # The complete upstream sequence already dispatches Darwin26's256-byte
    # attrs. D27's audited original snapshots200 bytes for EVERY nonzero size,
    # so replace that entire dispatch, not just the old native fallback leaf.
    old_dispatch = '''@@ -4452,7 +4470,13 @@
 \t\t\t * This is a bit fragile: <rdar://problem/16427422>
 \t\t\t */
 
-\t\t\tif ((error = copyin(px_args.attrp, &px_sa, px_sa_offset)) != 0) {
'''
    new_dispatch = '''@@ -4452,12 +4470,13 @@
 \t\t\t * This is a bit fragile: <rdar://problem/16427422>
 \t\t\t */
 
-\t\t\tif (px_args.attr_size == PSA_DARWIN26_SIZE) {
-\t\t\t\t/* Darwin 26 libsystem layout: convert the fields after psa_launch_type (see psa_from_darwin26). */
-\t\t\t\tif ((error = psa_from_darwin26(px_args.attrp, &px_sa)) != 0) {
-\t\t\t\t\tgoto bad;
-\t\t\t\t}
-\t\t\t} else if ((error = copyin(px_args.attrp, &px_sa, px_sa_offset)) != 0) {
'''
    if result.count(old_dispatch) != 1:
        raise ValueError('Unknown original D27 spawn copyin hunk')
    result = result.replace(old_dispatch, new_dispatch)
    added = lambda text: [line for line in text.splitlines() if line.startswith('+')]
    if added(raw) != added(result):
        raise ValueError('Rebase changed D27 added source behavior')
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--apply', action='store_true')
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    original = DEVICE / 'patches/xnu/ios27-d27-sanitizer-state.patch'
    rebased = args.out / 'ios27-d27-sanitizer-full-sheng27.patch'
    rebased.write_text(rebase_sanitizer(original.read_text()))
    kpi = DEVICE / 'patches/xnu/ios27-strict5-native-kpi.patch'
    stack = DEVICE / 'patches/xnu/ios27-sheng-stack-alignment.patch'
    subprocess.run(['git', '-C', str(args.source), 'apply', '--reverse', '--check', str(stack)], check=True)
    command = ['git', '-C', str(args.source), 'apply']
    subprocess.run([*command, '--check', str(kpi), str(rebased)], check=True)
    report = dict(stack_already_upstream=True, stack_reapplied=False,
                  source=str(args.source.resolve()), d27_added_source_behavior_preserved=True,
                  upstream_spawn_dispatch_rebased=True,
                  rebased_patch_sha256=hashlib.sha256(rebased.read_bytes()).hexdigest(),
                  kpi_patch_sha256=hashlib.sha256(kpi.read_bytes()).hexdigest(),
                  native_objects_rebuilt=False, applied=False, device_operations=False)
    if args.apply:
        subprocess.run([*command, str(kpi), str(rebased)], check=True)
        report['applied'] = True
    (args.out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
