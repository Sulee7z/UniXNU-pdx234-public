#!/usr/bin/env python3
"""Stage private Linux-to-iOS27 compiler wrappers and Mesa Python dependencies."""
import json
from pathlib import Path
import shutil
import subprocess

BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
ROOT=BASE/'metal-runtime-001'


def main():
    tools=ROOT/'host-bin';tools.mkdir(exist_ok=True)
    sdk=BASE/'user-sdk-002/repository/iPhoneOS27.0.sdk'
    assert (sdk/'usr/include/stdio.h').stat().st_size > 0
    assert json.loads((sdk/'SDKSettings.json').read_text())
    clang=Path('/root/unixnu-build/pdx234-pac-toolchain/llvm/bin/clang-24')
    for name in ('clang','clang++'):
        content='#!/usr/bin/env python3\nimport os,sys\n'
        content+='args=sys.argv[1:]\n'
        content+=f'exe={str(clang)!r}\n'
        content+='extra=[] if any(x in args for x in ("-c","-E","-S")) else ["--ld-path=/mnt/e/UniXNU-sheng27-sony-20261113/user-linker-001/install/bin/ld","-mlinker-version=956.6"]\n'
        if name=='clang++':content+='extra+=["--driver-mode=g++"]\n'
        content+='os.execv(exe,[exe,"-target","arm64e-apple-ios27.0",*extra,*args])\n'
        (tools/name).write_text(content);(tools/name).chmod(0o755)
    for name,exe in {'ar':'/usr/bin/llvm-ar','nm':'/usr/bin/llvm-nm',
                     'strip':'/usr/bin/llvm-strip','llvm-as':'/usr/lib/llvm-23/bin/llvm-as',
                     'llvm-objcopy':'/usr/lib/llvm-23/bin/llvm-objcopy'}.items():
        p=tools/name
        if not p.exists():p.symlink_to(exe)
    (tools/'xcrun').write_text('''#!/usr/bin/env python3
import os,sys
from pathlib import Path
tools=Path(__file__).resolve().parent
args=sys.argv[1:]
if args[:1] in (['--sdk'],['-sdk']):args=args[2:]
if args==['--show-sdk-path']:print(SDK);sys.exit(0)
if args==['--show-sdk-version']:print('27.0');sys.exit(0)
if args[:1] in (['--find'],['-find']):
 p=tools/args[1]
 if not p.is_file():raise SystemExit('Unsupported tool '+args[1])
 print(p);sys.exit(0)
exe=str(tools/args[0]);os.execv(exe,[exe,*args[1:]])
'''.replace('print(SDK)',f'print({str(sdk)!r})'))
    (tools/'xcrun').chmod(0o755)
    venv=ROOT/'.cache/mesa-venv'
    if not (venv/'bin/python').exists():subprocess.run(['python3','-m','venv',str(venv)],check=True)
    subprocess.run([str(venv/'bin/pip'),'install','-r',str(ROOT/'scripts/requirements-adreno-compiler.txt')],check=True)
    print('Private cross tools:',tools)


if __name__=='__main__':main()
