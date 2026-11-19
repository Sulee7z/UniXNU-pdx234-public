#!/usr/bin/env python3
"""Compile the existing owner-root BSD path without altering baseline objects."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tomllib

DEVICE = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tree', type=Path, required=True)
    parser.add_argument('--mainline', type=Path, required=True)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--data-seed', type=Path, help='Enable upstream SystemOS/Data startup using this populated D27 seed report')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    out = args.out.resolve()
    obj = args.tree / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837'
    record = json.JSONDecoder().raw_decode((obj/'bsd/DEVELOPMENT/bsd_init.o.json').read_text())[0]
    source = args.tree / '.cache/xnu-work/bsd/kern/bsd_init.c'
    text = source.read_text()
    for name in ('native_verified_block_root_authorized', 'native_owner_root_accepted_checkpoint'):
        if name not in text:
            raise ValueError('Missing upstream owner path: '+name)
    spec = importlib.util.spec_from_file_location('owner_bsd_compile', args.mainline/'scripts/build-sheng-source-drivers.py')
    compiler = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(compiler)
    output = out/'bsd_init.o'
    command = compiler.compile_command(record, source, output, [],
        ['-DXNU_OWNER_ROOT_AUDIT=1', '-DXNU_OWNER_ROOT_TRUST=1',
         '-Wno-unknown-warning-option', '-Wno-sign-compare', '-Wno-missing-designated-field-initializers'])
    (out/'compile.command.json').write_text(json.dumps(command, indent=2)+'\n')
    env = dict(os.environ, TMPDIR=str(out), PYTHONDONTWRITEBYTECODE='1')
    with (out/'compile.log').open('w') as log:
        done = subprocess.run(command, cwd=record['directory'], env=env, stdout=log, stderr=subprocess.STDOUT)
    if done.returncode:
        raise RuntimeError((out/'compile.log').read_text()[-6000:])
    paths = (obj/'link.filelist').read_text().splitlines()
    hits = [i for i, path in enumerate(paths) if path.endswith('/bsd/DEVELOPMENT/bsd_init.o')]
    if len(hits) != 1:
        raise ValueError('Ambiguous BSD object in filelist')
    paths[hits[0]] = str(output)
    if args.data_seed:
        seed = json.loads(args.data_seed.read_text())
        profile = tomllib.loads((DEVICE/'profiles/ios-27.0.1-24A446-iphone14/profile.toml').read_text())
        if not seed['populated'] or seed['os_sha256'] != profile['root']['os_image_sha256']:
            raise ValueError('Need populated target-matched Data')
        header = out/'owner-data-volume.h'
        header.write_text('#define XNU_OWNER_DATA_VOLUME_UUID "'+seed['volume_uuid']+'"\n'
                          '#define XNU_OWNER_CACHE_VOLUME_UUID "'+profile['root']['systemos_volume_uuid']+'"\n'
                          '#define XNU_OWNER_ROOT_VOLUME_UUID "'+profile['root']['os_volume_uuid']+'"\n')
        for recipe, stem, definitions in [
            ('bsd/DEVELOPMENT/kern_exec.o.json', 'kern_exec',
             {'XNU_OWNER_CACHE_MOUNT':1, 'XNU_OWNER_CACHE_STARTUP':1, 'XNU_OWNER_BOOT_MANIFEST':1,
              'XNU_OWNER_DATA_MOUNT':1, 'XNU_NATIVE_RAM_BLOCK':1, 'XNU_OWNER_UNION_SYSTEMOS':1}),
            ('iokit/DEVELOPMENT/IOKitBSDInit.cpo.json', 'IOKitBSDInit', {'XNU_OWNER_BOOT_MANIFEST':1})]:
            saved = json.JSONDecoder().raw_decode((obj/recipe).read_text())[0]
            argv = []
            index = 0
            while index < len(saved['arguments']):
                value = saved['arguments'][index]
                if value == '-D' and saved['arguments'][index+1].split('=')[0] in definitions:
                    index += 2
                    continue
                if value.startswith('-D') and value[2:].split('=')[0] in definitions:
                    index += 1
                    continue
                if value.endswith('/owner-data-volume.h'):
                    value = str(header)
                argv.append(value)
                index += 1
            saved['arguments'] = argv
            target = out/(stem+('.o' if stem=='kern_exec' else '.cpo'))
            extra = ['-D'+key+'='+str(value) for key,value in definitions.items()]
            extra += ['-Wno-unknown-warning-option','-Wno-sign-compare','-Wno-missing-designated-field-initializers',
                      '-Wno-unused-but-set-variable']
            command = compiler.compile_command(saved, Path(saved['file']), target, [], extra)
            # Rebuilding an existing kernel unit retains its established
            # warning policy, including private-header deprecation handling.
            command += [value for value in argv if value.startswith('-Wno-')]
            (out/(stem+'.command.json')).write_text(json.dumps(command,indent=2)+'\n')
            with (out/(stem+'.log')).open('w') as log:
                done = subprocess.run(command, cwd=saved['directory'], env=env, stdout=log, stderr=subprocess.STDOUT)
            if done.returncode:
                raise RuntimeError((out/(stem+'.log')).read_text()[-6000:])
            old = str(obj/recipe.removesuffix('.json'))
            if paths.count(old)!=1:
                raise ValueError('Cannot select startup object: '+old)
            paths[paths.index(old)] = str(target)
    filelist = out/'link.filelist'
    filelist.write_text('\n'.join(paths)+'\n')
    command = json.loads((DEVICE/'out/d27-owner-root-native-001/native-link.command.json').read_text())
    command[command.index('-filelist')+1] = str(filelist)
    command[command.index('-o')+1] = str(out/'native.macho')
    old = '-Wl,-force_load,'+str(DEVICE/'out/d27-owner-root-runtime-001/libSonyUfsTestRuntime.a')
    if command.count(old) != 1:
        raise ValueError('Ambiguous runtime')
    command[command.index(old)] = '-Wl,-force_load,'+str(args.runtime.resolve())
    (out/'native-link.command.json').write_text(json.dumps(command, indent=2)+'\n')
    env.update(CROSS_CLANG='/root/unixnu-build/pdx234-pac-toolchain/llvm/bin/clang-24',
               DARWIN_TRIPLE='arm64e-apple-ios27.0')
    env['PATH'] = '/root/unixnu-build/pdx234-pac-toolchain/CommandLineTools/usr/bin:'+env['PATH']
    with (out/'native-link.log').open('w') as log:
        done = subprocess.run(command, cwd=obj, env=env, stdout=log, stderr=subprocess.STDOUT)
    if done.returncode:
        raise RuntimeError((out/'native-link.log').read_text()[-6000:])
    report = dict(source=str(source), source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                  native_sha256=hashlib.sha256((out/'native.macho').read_bytes()).hexdigest(),
                  owner_root_audit=True, owner_root_trust=True, baseline_objects_unchanged=True,
                  owner_systemos_data_startup_enabled=bool(args.data_seed),
                  root_mounted=False, device_operations=False)
    (out/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
