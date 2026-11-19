"""Run the actual transaction shell on sparse regular files, never devices/ADB."""
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CONFIRM = 'PDX_DEVICE_SERIAL DISCARD-DATA unixnu 68719476736'


@unittest.skipUnless(os.name == 'posix', 'Run in WSL/Linux on sparse regular files')
class DiscardTransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='sony-discard-offline-')
        self.root = Path(self.tmp.name)
        self.bundle = self.root / 'bundle'
        self.bundle.mkdir()
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.block = self.root / 'dev/block'
        self.block.mkdir(parents=True)
        (self.block / 'by-name').mkdir()
        self.sys = self.root / 'sys/class/block'
        for n, dev in [('sda96', '259:80'), ('sda52', '8:52')]:
            target = self.sys / n
            (target / 'holders').mkdir(parents=True)
            (target / 'dev').write_text(dev + '\n')
        (self.sys / 'sda96/start').write_text('47467184\n')
        for name, n in [('userdata', 'sda96'), ('metadata', 'sda52'), ('rddata', 'sda97')]:
            (self.block / 'by-name' / name).symlink_to(self.block / n)
            (self.block / n).write_bytes(bytes(2 << 20))
        self.proc = self.root / 'proc/1'
        self.proc.mkdir(parents=True)
        (self.proc / 'mountinfo').write_text('1 0 0:1 / / rw - rootfs rootfs rw\n')
        boot = self.root / 'proc/sys/kernel/random'
        boot.mkdir(parents=True)
        (boot / 'boot_id').write_text('offline-test\n')
        self.lockroot = self.root / 'tmp'
        self.lockroot.mkdir()
        script = (ROOT / 'ci/dual_sys/sony-discard-apply.sh').read_text()
        for old, new in [('/tmp/', str(self.lockroot) + '/'),
                         ('/dev/block/', str(self.block) + '/'),
                         ('/sys/class/block/', str(self.sys) + '/'),
                         ('/proc/', str(self.root / 'proc') + '/')]:
            script = script.replace(old, new)
        (self.bundle / 'sony-discard-apply.sh').write_text(script)
        for name, byte, size in [('gpt-primary.before', 0x11, 24576), ('gpt-backup.before', 0x22, 20480),
                                 ('gpt-primary.after', 0x33, 24576), ('gpt-backup.after', 0x44, 20480)]:
            (self.bundle / name).write_bytes(bytes([byte]) * size)
        (self.bundle / 'zero-marker.bin').write_bytes(bytes(1 << 20))
        (self.bundle / 'plan.env').write_text('KERNEL=offline-kernel\nBOOT_ID=offline-test\n')
        self.disk = self.block / 'sda'
        with self.disk.open('wb') as stream:
            stream.truncate(255844155392)
            stream.seek(0)
            stream.write((self.bundle / 'gpt-primary.before').read_bytes())
            stream.seek(62461947 * 4096)
            stream.write((self.bundle / 'gpt-backup.before').read_bytes())
        protected = ''.join(hashlib.sha256((self.block / n).read_bytes()).hexdigest() + '  ' + str(self.block / n) + '\n'
                            for n in ['sda52', 'sda97'])
        (self.bundle / 'PROTECTED').write_text(protected)
        self.tool('getprop', '''case "$1" in
ro.product.device) echo XQ-DQ72;; ro.serialno) echo PDX_DEVICE_SERIAL;; esac
''')
        self.tool('uname', 'echo offline-kernel\n')
        self.tool('blockdev', '''case "$1:$2" in
--getsize64:*/sda) echo 255844155392;;
--getsize64:*/sda96) echo 231519965184;;
--getss:*/sda) echo 4096;; *) exit 88;; esac
''')
        self.tool('dd', '''echo "$*" >> "$TEST_LOG"
case "$*" in
*of=*/sda*seek=62461947*)
  [ "${TEST_FAIL:-}" != backup-write ] || exit 91
  /usr/bin/dd "$@" || exit $?
  if [ "${TEST_FAIL:-}" = backup-corrupt ]; then
    printf x | /usr/bin/dd of="$TEST_DISK" bs=1 seek=255844134912 conv=notrunc status=none
  fi
  exit 0;;
*if=gpt-primary.after*) [ "${TEST_FAIL:-}" != primary-write ] || exit 92;;
esac
exec /usr/bin/dd "$@"
''')
        self.tool('sync', '[ "${TEST_FAIL:-}" != sync ] || exit 93\n')
        self.env = dict(os.environ, PATH=str(self.bin) + ':' + os.environ['PATH'],
                        TEST_LOG=str(self.root / 'dd.log'), TEST_DISK=str(self.disk))
        self.hashes()

    def tearDown(self):
        self.tmp.cleanup()

    def tool(self, name, body):
        file = self.bin / name
        file.write_text('#!/bin/sh\n' + body)
        file.chmod(0o755)

    def hashes(self):
        (self.bundle / 'SHA256SUMS').write_text(''.join(hashlib.sha256(f.read_bytes()).hexdigest() + '  ' + f.name + '\n'
            for f in sorted(self.bundle.iterdir()) if f.is_file() and f.name != 'SHA256SUMS'))

    def run_apply(self, fail='', confirm=CONFIRM, action='apply'):
        return subprocess.run(['bash', str(self.bundle / 'sony-discard-apply.sh'), action, confirm],
                              env=dict(self.env, TEST_FAIL=fail), capture_output=True, text=True, timeout=15)

    def writes(self):
        log = self.root / 'dd.log'
        return [s for s in log.read_text().splitlines() if 'of=' + str(self.block) in s] if log.exists() else []

    def copies(self):
        with self.disk.open('rb') as stream:
            a = stream.read(24576)
            stream.seek(62461947 * 4096)
            b = stream.read(20480)
        return a, b

    def test_success_is_marker_backup_primary_only(self):
        result = self.run_apply()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        writes = self.writes()
        self.assertEqual(len(writes), 3)
        self.assertIn('of=' + str(self.block / 'sda96'), writes[0])
        self.assertIn('if=gpt-backup.after', writes[1])
        self.assertIn('if=gpt-primary.after', writes[2])
        self.assertEqual(self.copies(), ((self.bundle / 'gpt-primary.after').read_bytes(),
                                        (self.bundle / 'gpt-backup.after').read_bytes()))

    def test_backup_write_failure_never_writes_primary(self):
        self.assertNotEqual(self.run_apply('backup-write').returncode, 0)
        self.assertEqual(len(self.writes()), 2)
        self.assertEqual(self.copies()[0], (self.bundle / 'gpt-primary.before').read_bytes())

    def test_backup_readback_failure_never_writes_primary(self):
        result = self.run_apply('backup-corrupt')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('backup readback failed', result.stderr)
        self.assertEqual(len(self.writes()), 2)

    def test_sync_failure_never_writes_primary(self):
        self.assertNotEqual(self.run_apply('sync').returncode, 0)
        self.assertEqual(len(self.writes()), 2)

    def test_primary_write_failure_stops_with_new_backup(self):
        self.assertNotEqual(self.run_apply('primary-write').returncode, 0)
        a, b = self.copies()
        self.assertEqual(a, (self.bundle / 'gpt-primary.before').read_bytes())
        self.assertEqual(b, (self.bundle / 'gpt-backup.after').read_bytes())

    def test_session_lock_prevents_all_writes(self):
        (self.lockroot / 'unixnu-dual.lock').mkdir()
        self.assertNotEqual(self.run_apply().returncode, 0)
        self.assertEqual(self.writes(), [])

    def test_wrong_confirmation_prevents_all_writes(self):
        self.assertNotEqual(self.run_apply(confirm='yes').returncode, 0)
        self.assertEqual(self.writes(), [])

    def test_mount_in_another_namespace_prevents_all_writes(self):
        other = self.root / 'proc/2'
        other.mkdir()
        (other / 'mountinfo').write_text('2 0 259:80 / /somewhere rw - f2fs /dev/block/sda96 rw\n')
        self.assertNotEqual(self.run_apply().returncode, 0)
        self.assertEqual(self.writes(), [])

    def test_holder_prevents_all_writes(self):
        (self.sys / 'sda96/holders/dm-99').touch()
        self.assertNotEqual(self.run_apply().returncode, 0)
        self.assertEqual(self.writes(), [])

    def test_protected_hash_change_prevents_all_writes(self):
        (self.block / 'sda52').write_bytes(b'changed')
        self.assertNotEqual(self.run_apply().returncode, 0)
        self.assertEqual(self.writes(), [])

    def test_fresh_gpt_change_prevents_all_writes(self):
        with self.disk.open('r+b') as stream:
            stream.write(b'changed')
        self.assertNotEqual(self.run_apply().returncode, 0)
        self.assertEqual(self.writes(), [])

    def test_plan_file_change_prevents_all_writes(self):
        (self.bundle / 'gpt-primary.after').write_bytes(b'changed')
        self.assertNotEqual(self.run_apply().returncode, 0)
        self.assertEqual(self.writes(), [])

    def test_check_mode_has_no_device_writes(self):
        result = self.run_apply(action='check')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.writes(), [])

    def test_reinvocation_after_success_does_not_write_again(self):
        self.assertEqual(self.run_apply().returncode, 0)
        self.assertNotEqual(self.run_apply().returncode, 0)
        self.assertEqual(len(self.writes()), 3)


class InstallManifestTests(unittest.TestCase):
    def test_official_manifest_format_and_bounded_readonly_windows(self):
        spec = importlib.util.spec_from_file_location('sony_install', ROOT / 'ci/dual_sys/sony_install.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        raw, plan = module.manifest()
        self.assertEqual(len(raw), 4096)
        self.assertEqual(raw[:8], b'SHNGROOT')
        self.assertEqual(raw[4064:], hashlib.sha256(raw[:4064]).digest())
        self.assertEqual([w['name'] for w in plan['windows']], ['OS', 'SystemOS'])
        self.assertEqual(plan['windows'][0]['offset'], 1 << 20)
        self.assertLessEqual(plan['image_bytes'], 64 << 30)
        a, b = plan['windows']
        self.assertLessEqual(a['offset'] + a['bytes'], b['offset'])
        self.assertTrue(all(w['readonly'] for w in [a, b]))
        self.assertFalse(plan['persistent_data_enabled'])
        self.assertFalse(plan['persistent_logs_enabled'])


if __name__ == '__main__':
    unittest.main()
