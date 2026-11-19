"""Keep live prelink I/O on ext4 and verify cross-filesystem byte transfers."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT=Path(__file__).resolve().parents[1]/'scripts/prelink-iphone14-native.py'
spec=importlib.util.spec_from_file_location('prelink_iphone14',SCRIPT)
prelink=importlib.util.module_from_spec(spec)
spec.loader.exec_module(prelink)


class HostStagingTests(unittest.TestCase):
    def test_snapshot_preserves_crlf_bytes_and_includes_target_fixtures(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            source=root/'source'
            source.mkdir()
            (source/'fixtures').mkdir()
            (source/'emit_prelink.py').write_bytes(b'print("test")\r\n')
            (source/'fixtures/fileset-d27-symbols.json').write_bytes(b'{"inputs":{}}\n')
            (source/'unrelated.bin').write_bytes(b'not analysis source')
            records=prelink.snapshot_tool(source,root/'target')
            self.assertEqual(set(records),{'emit_prelink.py','fixtures/fileset-d27-symbols.json'})
            self.assertEqual((root/'target/emit_prelink.py').read_bytes(),b'print("test")\r\n')
            self.assertFalse((root/'target/unrelated.bin').exists())

    def test_copy_rejects_changed_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            source,target=Path(directory)/'source',Path(directory)/'target'
            source.write_bytes(b'original')
            with patch.object(prelink.shutil,'copyfile',side_effect=lambda a,b:b.write_bytes(b'changed')):
                with self.assertRaisesRegex(RuntimeError,'Copy changed bytes'):
                    prelink.checked_copy(source,target)

    def test_drvfs_is_not_an_accepted_live_workspace(self):
        for name in ('9p','drvfs','ntfs3'):
            with self.subTest(filesystem=name),patch.object(prelink.subprocess,'check_output',return_value=name+'\n'):
                with self.assertRaisesRegex(RuntimeError,'must be ext4'):
                    prelink.work_filesystem(Path('/mnt/g'))
        with patch.object(prelink.subprocess,'check_output',return_value='ext4\n'):
            self.assertEqual(prelink.work_filesystem(Path('/root/unixnu-build')),'ext4')

    def test_native_runner_seals_final_payload_before_qemu(self):
        script=(SCRIPT.parent/'run-qemu27-native-entry.sh').read_text()
        self.assertLess(script.index('seal-source-crypto-kernel.py'),script.index('if python3 "$WORK/qemu-run.py"'))
        self.assertIn('OUT=$WORK/result',script)
        self.assertIn('UNIXNU_XNU_ARCH=arm64e UNIXNU_IOS_VERSION=27.0',script)

    def test_strict_prelink_seals_staged_input_and_records_its_hash(self):
        script=SCRIPT.read_text()
        self.assertLess(script.index('native-seal.log'),script.index("command=[sys.executable,'-u'"))
        self.assertIn("'native_sha256':digest(staging/'native.macho')",script)
        self.assertIn("'source_native_sha256':native_input_sha256",script)
        self.assertIn("str(work/'kernel.macho'),'--kernel-args',boot_args",script)


if __name__=='__main__':unittest.main()
