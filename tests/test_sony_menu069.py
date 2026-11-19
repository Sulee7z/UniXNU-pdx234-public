import copy
from pathlib import Path
import sys
import tomllib
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'ci'))
from darwin_boot_args import validate
from platform069.menu import PROTECTED,render,updated_arguments,validate_choices

ARGS=' '.join([*(name+'='+value for name,value in PROTECTED.items()),'build-tag=PDX068','cpufreq=4','wifi=0','bluetooth=0'])
MENU='''version = 1
[boot]
timeout = -1
default = "xnu"
[ui]
title = "Sony PDX234 iOS 27 PAC-ABI-068"
[kits]
autoload = false
[[entry]]
id = "xnu"
title = "Boot D27 XNU"
type = "xnu"
path = "Payloads/kernel.macho"
initrd = "Payloads/scratch-data.img"
args = ARGS
[[entry]]
id = "restart"
title = "Restart"
type = "action"
action = "reset"
'''.replace('args = ARGS','args = "'+ARGS+'"')


class Menu069(unittest.TestCase):
    def test_optional_choice_changes_only_seed_and_title(self):
        arguments=updated_arguments(ARGS,{'wifi':1,'bluetooth':1})
        text,checks=render(MENU,arguments);parsed=tomllib.loads(text)
        self.assertEqual([entry['id'] for entry in parsed['entry']],['xnu','xnu-skip-setup','restart'])
        self.assertEqual(parsed['boot']['default'],'xnu')
        self.assertEqual(parsed['entry'][0]['initrd'],'Payloads/scratch-data.img')
        self.assertEqual(parsed['entry'][1]['initrd'],'Payloads/scratch-data-skip-setup.img')
        self.assertEqual(parsed['entry'][0]['args'],parsed['entry'][1]['args'])
        self.assertEqual(set(checks),{'xnu','xnu-skip-setup'})
        self.assertEqual(parsed['entry'][2],tomllib.loads(MENU)['entry'][1])

    def test_no_protected_argument_override(self):
        for key in PROTECTED:
            with self.subTest(key=key),self.assertRaises(ValueError):updated_arguments(ARGS,{key:1})

    def test_rejects_overlong_arguments_before_rendering(self):
        with self.assertRaises(ValueError):updated_arguments(ARGS+' filler='+'x'*1024,{})
        with self.assertRaises(ValueError):render(MENU,updated_arguments(ARGS,{})+'\0')

    def test_invalid_skip_choice_cannot_silently_drop_request_policy(self):
        arguments=updated_arguments(ARGS,{})
        text,_=render(MENU,arguments);parsed=tomllib.loads(text)
        for key,value in [('args',arguments+' data-persist=1'),('initrd','Payloads/scratch-data.img'),('confirm',True)]:
            corrupt=copy.deepcopy(parsed);corrupt['entry'][1][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):validate_choices(corrupt,arguments)

    def test_actual1023_byte_boundary_is_checked_for_both_choices(self):
        arguments=updated_arguments(ARGS,{})
        arguments+=' filler='+'x'*(1023-len(arguments)-8)
        self.assertEqual(len(arguments),1023)
        text,checks=render(MENU,arguments)
        self.assertTrue(all(row['ascii_bytes']==1023 for row in checks.values()))
        with self.assertRaises(ValueError):render(MENU,arguments+'x')


if __name__=='__main__':unittest.main()
