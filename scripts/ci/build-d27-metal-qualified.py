#!/usr/bin/env python3
"""Build isolated D27 Metal sources without J820 private-address accesses."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
DEVICE=Path(__file__).resolve().parents[2]


def main():
    root=BASE/'metal-runtime-001';out=BASE/'metal-d27-qualified-001';out.mkdir(exist_ok=False)
    sources=out/'drivers/AdrenoMetal';shutil.copytree(root/'drivers/AdrenoMetal',sources)
    (out/'drivers/GopFramebuffer').symlink_to(BASE/'display-source-005/drivers/GopFramebuffer',target_is_directory=True)
    sys.path.insert(0,str(DEVICE/'ci'));from d27_metal_source import adapt
    source=sources/'NativeAdrenoMetalPlugin.mm';original=source.read_bytes()
    module=Path('/root/unixnu-build/sheng27-sony-bulk-20261111-001/UniXNU/drivers/AdrenoMetal')
    expected=subprocess.check_output(['git','-C',str(module),'show','243d63cf43305a85c8119b66b49cb7df4b30b019:NativeAdrenoMetalPlugin.mm'])
    if original!=expected:raise ValueError('Plugin differs from recorded upstream pin')
    source.write_text(adapt(original.decode()))
    script=(root/'scripts/build-adreno-metal-plugin.py').read_text()
    # Use its unchanged compile/link/sign logic with isolated sources/output.
    script=script.replace("ROOT = Path(__file__).resolve().parents[1]",'ROOT = Path('+repr(str(root))+')')
    script=script.replace("OUT = ROOT / ('build/adreno-metal-plugin27' if IOS27 else 'build/adreno-metal-plugin')",'OUT = Path('+repr(str(out/'plugin'))+')')
    script=script.replace("ROOT / 'drivers/AdrenoMetal'",'Path('+repr(str(sources))+')')
    script=script.replace("ROOT / 'drivers/AdrenoMetal/",'Path('+repr(str(sources))+') / \u0027')
    # Reuse the verified Rust bridge; it does not depend on the Objective-C
    # source adapter, and rebuilding it would consume unrelated disk space.
    line="subprocess.run(['python3', ROOT / 'scripts/build-adreno-metal-bridge.py', '--target', BRIDGE_TARGET], check=True)"
    assert script.count(line)==1
    archive=root/'build/adreno-metal-bridge/ios27/libadreno_metal_bridge.a'
    assert hashlib.sha256(archive.read_bytes()).hexdigest()=='fb327d28dd50db55a35d65e099eb46f03d9fc267b8f87008ed33829e252a409d'
    script=script.replace(line,'# Verified unchanged Rust bridge reused by D27 builder.')
    staged=out/'build-plugin.py';staged.write_text(script)
    compile(script,str(staged),'exec')
    rust=BASE/'rust-userspace-002'
    env=dict(os.environ,PATH=str(root/'host-bin')+':'+str(rust/'cargo/bin')+':'+os.environ['PATH'],
        RUSTUP_HOME=str(rust/'rustup'),CARGO_HOME=str(rust/'cargo'),
        SDKROOT=str(BASE/'user-sdk-002/repository/iPhoneOS27.0.sdk'),CCC_OVERRIDE_OPTIONS='# +-Wno-unused-but-set-global')
    with (out/'build.log').open('w') as log:
        q=subprocess.run(['python3','-B',str(staged),'--target','ios27','--no-replay'],env=env,stdout=log,stderr=subprocess.STDOUT)
    if q.returncode:raise RuntimeError((out/'build.log').read_text()[-6000:])
    result=dict(plugin=str(out/'plugin'),upstream_pin='243d63cf43305a85c8119b66b49cb7df4b30b019',
        upstream_source_sha256=hashlib.sha256(original).hexdigest(),adapted_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        j820_private_accesses_removed=True,environment_options_retained=True,runtime_verified=False)
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
