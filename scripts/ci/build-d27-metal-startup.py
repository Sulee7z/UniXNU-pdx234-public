#!/usr/bin/env python3
"""Build/sign the isolated D27 cache/startup correction; never overwrite a build."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

DEVICE = Path(__file__).resolve().parents[2]
BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=BASE / 'metal-d27-startup-001')
    parser.add_argument('--prepare-only', action='store_true')
    parser.add_argument('--dlopen-diagnostic',action='store_true',help='Own dyld errors before logging and emit cause-first bounded summaries')
    args = parser.parse_args()
    previous = BASE / 'metal-d27-qualified-001'
    root = BASE / 'metal-runtime-001'
    source = previous / 'drivers/AdrenoMetal/NativeAdrenoMetalPlugin.mm'
    receipt = json.loads((previous / 'result.json').read_text())
    if digest(source) != receipt['adapted_source_sha256']:
        raise ValueError('Qualified source differs from its recorded digest')
    archive = root / 'build/adreno-metal-bridge/ios27/libadreno_metal_bridge.a'
    if digest(archive) != 'fb327d28dd50db55a35d65e099eb46f03d9fc267b8f87008ed33829e252a409d':
        raise ValueError('Bridge archive differs from qualified build')
    sys.path.insert(0, str(DEVICE / 'ci'))
    from d27_metal_startup import adapt, adapt_frontend
    adapted = adapt(source.read_text())
    if args.dlopen_diagnostic:
        from d27_dlopen_diagnostic import adapt as adapt_dlopen, stage_header
        adapted=adapt_dlopen(adapted)
    frontend = previous / 'drivers/AdrenoMetal/NativeBridgeMetalFrontend.mm'
    adapted_frontend = adapt_frontend(frontend.read_text())
    # All inputs are checked before creating the new isolated tree.
    args.out.mkdir(parents=True, exist_ok=False)
    sources = args.out / 'drivers/AdrenoMetal'
    shutil.copytree(previous / 'drivers/AdrenoMetal', sources)
    (args.out / 'drivers/GopFramebuffer').symlink_to(
        BASE / 'display-source-005/drivers/GopFramebuffer', target_is_directory=True)
    (sources / 'NativeAdrenoMetalPlugin.mm').write_text(adapted)
    (sources / 'NativeBridgeMetalFrontend.mm').write_text(adapted_frontend)
    shutil.copyfile(DEVICE / 'ci/D27MetalStartup.h', sources / 'D27MetalStartup.h')
    if args.dlopen_diagnostic:stage_header(sources)
    script = (previous / 'build-plugin.py').read_text().replace(str(previous), str(args.out))
    # LLVM18 strip generated a4-byte-aligned LC_SYMTAB string pool rejected
    # by actual D27 dyld. Use a checked target-aware strip for both binaries.
    for variable in ['exe','turnip_lib']:
        old="subprocess.run(['strip', '-x', "+variable+"], check=True)"
        new="subprocess.run(['python3', "+repr(str(DEVICE/'scripts/ci/strip-d27-macho.py'))+", '-x', "+variable+"], check=True)"
        if script.count(old)!=1:raise ValueError('Unknown strip invocation')
        script=script.replace(old,new)
    compile(script, str(args.out / 'build-plugin.py'), 'exec')
    (args.out / 'build-plugin.py').write_text(script)
    result = dict(previous=receipt, adapted_source_sha256=digest(sources / 'NativeAdrenoMetalPlugin.mm'),
                  frontend_original_sha256=digest(frontend), frontend_adapted_sha256=digest(sources / 'NativeBridgeMetalFrontend.mm'),
                  cache_helper_sha256=digest(sources / 'D27MetalStartup.h'),
                  plugin=str(args.out / 'plugin'), runtime_verified=False, build_verified=False)
    result['macho_strip_validator_sha256']=digest(DEVICE/'scripts/ci/strip-d27-macho.py')
    if args.dlopen_diagnostic:
        result['dlopen_diagnostic']=dict(header_sha256=digest(sources/'D27DlopenDiagnostic.h'),
            adapter_sha256=digest(DEVICE/'ci/d27_dlopen_diagnostic.py'),raw_capacity=4096,
            path_capacity=1024,screen_summary_bytes=126,hardware_verified=False)
    (args.out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    if args.prepare_only:
        print(json.dumps(result, indent=2))
        return
    rust = BASE / 'rust-userspace-002'
    env = dict(os.environ, PATH=str(root / 'host-bin') + ':' + str(rust / 'cargo/bin') + ':' + os.environ['PATH'],
               RUSTUP_HOME=str(rust / 'rustup'), CARGO_HOME=str(rust / 'cargo'),
               SDKROOT=str(BASE / 'user-sdk-002/repository/iPhoneOS27.0.sdk'),
               CCC_OVERRIDE_OPTIONS='# +-Wno-unused-but-set-global')
    with (args.out / 'build.log').open('w') as log:
        subprocess.run(['python3', '-B', str(args.out / 'build-plugin.py'), '--target', 'ios27', '--no-replay'],
                       env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    result['build_verified'] = True
    (args.out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
