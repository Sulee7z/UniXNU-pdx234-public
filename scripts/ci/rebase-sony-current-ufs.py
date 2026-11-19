#!/usr/bin/env python3
"""Port the proven Sony hardware delta to sheng27's CURRENT UFS gitlink.

Keep the newer manifest-v2 data-object and header-only policy implementation.
This stages source only; it neither compiles nor touches a phone.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

DEVICE = Path(__file__).resolve().parents[2]
CURRENT = '57f031c99d7f69ffa611626bebaeab0731e93254'


def rebase(raw):
    old = '''@@ -2,6 +2,7 @@
 // Native sheng SM8550 UFS bring-up. Default-off: no MMIO is touched unless
 // native-ufs-probe=1 is present. This is a register probe, not a storage driver.
 #include <IOKit/IOService.h>
+#include <IOKit/IODeviceTreeSupport.h>
 #include <IOKit/IOPlatformExpert.h>
 #include <IOKit/storage/IOBlockStorageDevice.h>
 #include <libkern/crypto/sha2.h>
'''
    new = old.replace('@@ -2,6 +2,7 @@', '@@ -2,7 +2,8 @@').replace(
        ' #include <libkern/crypto/sha2.h>\n',
        ' #include <IOKit/storage/IOStorageDeviceCharacteristics.h>\n #include <libkern/crypto/sha2.h>\n')
    if raw.count(old) != 1:
        raise ValueError('Unexpected reviewed Sony hardware delta')
    result = raw.replace(old, new)
    changed = lambda text: [line for line in text.splitlines() if line.startswith(('+', '-'))]
    if changed(raw) != changed(result):
        raise ValueError('Hardware source behavior changed during context rebase')
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--apply', action='store_true')
    p.add_argument('--verify-applied', action='store_true', help='Inspect a prior owned application; never apply it twice')
    args = p.parse_args()
    source = args.source.resolve()
    if subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip() != CURRENT:
        raise ValueError('Require the current sheng27 UFS source, not the older documented driver')
    if not args.verify_applied and subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain'], text=True).strip():
        raise ValueError('Preserve dirty UFS source; do not apply again')
    args.out.mkdir(parents=True, exist_ok=False)
    original = DEVICE / 'out/sony-ufs-adapter-007/sony-board-adaptation.patch'
    patch = args.out / 'sony-current-ufs.patch'
    patch.write_text(rebase(original.read_text()))
    # One unchanged include-context line moved in the current revision. Require
    # at least one context line, then independently prove every changed line is
    # the reviewed delta; newer upstream code must not be removed or replaced.
    command = ['git', '-C', str(source), 'apply', '-C1']
    subprocess.run([*command, *(['--reverse'] if args.verify_applied else []), '--check', str(patch)], check=True)
    report = dict(upstream_current_ufs=CURRENT, source=str(source),
                  original_sony_delta_sha256=hashlib.sha256(original.read_bytes()).hexdigest(),
                  rebased_delta_sha256=hashlib.sha256(patch.read_bytes()).hexdigest(),
                  hardware_added_removed_lines_preserved=True, applied=False, compiled=False,
                  device_operations=False)
    if args.apply or args.verify_applied:
        if not args.verify_applied:
            subprocess.run([*command, str(patch)], check=True)
        diff = subprocess.check_output(['git', '-C', str(source), 'diff', '--no-ext-diff', '--unified=0'], text=True)
        def net(text):
            changes = Counter()
            for line in text.splitlines():
                if line.startswith(('+', '-')) and not line.startswith(('+++', '---')):
                    changes[line[1:]] += 1 if line[0] == '+' else -1
            return {line: count for line, count in changes.items() if count}
        # Git can align unchanged closing braces differently inside a replaced
        # diagnostic block. Check its full bytes, plus the signed source delta.
        reviewed = (DEVICE / 'out/sony-ufs-adapter-007/source/NativeUfs.cpp').read_text()
        actual = (source / 'NativeUfs.cpp').read_text()
        def diagnostic(text):
            start = text.index('  if (probe == 10) {')
            return text[start:text.index('  if (probe == 11) {', start)]
        if net(diff) != net(patch.read_text()) or diagnostic(actual) != diagnostic(reviewed):
            raise ValueError('Applied hardware delta or complete diagnostic body differs from review')
        (args.out / 'applied-source.diff').write_text(diff)
        shutil.copyfile(DEVICE / 'ci/ufs/SonySmmuTakeover.h', source / 'SonySmmuTakeover.h')
        layout, code = (source / 'RootLayout.h').read_text(), (source / 'NativeUfs.cpp').read_text()
        if not ('RootWindow object[4]' in layout and 'policyTableLba' in code and
                'static const char wanted[] = "unixnu";' in layout and 'planSonyUfsSmmu' in code):
            raise ValueError('Current storage capability or Sony boundary selector lost')
        report.update(applied=True, manifest_v2_objects_retained=True,
                      header_only_policy_tables_retained=True, android_userdata_fallback=False,
                      actual_net_source_delta_matches_review=True,
                      diagnostic_body_byte_identical_to_review=True,
                      reapplication_performed=not args.verify_applied)
    (args.out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
