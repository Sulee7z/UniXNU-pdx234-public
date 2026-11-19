import importlib.util
from pathlib import Path
import struct
import unittest

PATH=Path(__file__).resolve().parents[1]/'scripts/check-native-entry-format.py'
spec=importlib.util.spec_from_file_location('native_entry_format',PATH)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture(*,threaded=False,chained=False,kind=2,subtype=2):
    commands=[]
    if threaded:
        commands.append(struct.pack('<II16s4Q4I',0x19,152,b'__TEXT',0,0,0,0,0,0,1,0)+
                        struct.pack('<16s16sQQ8I',b'__thread_starts',b'__TEXT',0,8,0,0,0,0,0,0,0,0))
    if chained:commands.append(struct.pack('<4I',0x80000034,16,0,0))
    blob=b''.join(commands)
    return struct.pack('<8I',0xfeedfacf,0x100000c,subtype,kind,len(commands),len(blob),0,0)+blob


class NativeFormatTests(unittest.TestCase):
    def test_threaded_native_is_not_prelinked_ios(self):
        result=module.inspect(fixture(threaded=True))
        self.assertEqual(result['format'],'standalone-threaded')
        self.assertFalse(result['original_kexts_added'])
        self.assertFalse(result['springboard_verified'])

    def test_chained_or_unfixed_arm64e_is_refused(self):
        for data in [fixture(chained=True),fixture(),fixture(threaded=True,chained=True)]:
            with self.assertRaisesRegex(ValueError,'belongs to fileset prelink'):
                module.inspect(data)

    def test_fileset_and_arm64_have_distinct_roles(self):
        self.assertFalse(module.inspect(fixture(kind=12))['standalone_native_only'])
        self.assertEqual(module.inspect(fixture(subtype=0))['format'],'standalone-arm64')

    def test_truncated_commands_are_refused(self):
        with self.assertRaises(ValueError):module.inspect(fixture(threaded=True)[:-1])


if __name__=='__main__':unittest.main()
