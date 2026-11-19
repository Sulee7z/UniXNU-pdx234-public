#!/usr/bin/env python3
"""Stage a signed, brightness-only D27 backboardd adapter; never edit a cache."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
DRIVER = ROOT / 'drivers/SonyOledBacklight/platform069'
SNAP = Path('/mnt/f/UniXNU-Port-artifacts/platform069-20261118')
OLD = SNAP.parent / 'platform067-20261118'
BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')
ORIGINAL_SHA = 'fbba7fd2925990dd859b24629ecab5cdbf6f2fac8c1c357ec0f9e412ded75559'
ABI_SHA = '6017f80848a3f0c73f90f6c26b7c10c4f475c0076a15410b39e21d4adb928136'
HOOK_SHA = 'a0ca3d1cb42ad549690fb4610549091f747ca6129ccdefc5dba15b4c5be2fb18'
ROUTER_SHA = '223107b811c2a8f816f5fa84ccbdb495c8c0ec9ab6806329d4461191fd11631a'
METHOD_SHA = 'af2585e67ed2c8c22f108779b9bc7412652b71fcd0647f3ea53a3ee4c1536170'
DYLIB = '/usr/lib/UniXNUBacklight.dylib'
FOUNDATION = '/System/Library/Frameworks/Foundation.framework/Foundation'
sys.path.insert(0, str(ROOT / 'ci'))
from platform069.codesign import inspect


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require(condition, message):
    if not condition:
        raise ValueError(message)


def commands(data):
    require(len(data) >= 32 and struct.unpack_from('<I', data)[0] == 0xfeedfacf, 'Thin Mach-O required')
    count, size = struct.unpack_from('<II', data, 16)
    at, end = 32, 32 + size
    require(end <= len(data), 'Load commands out of bounds')
    rows = []
    for _ in range(count):
        require(at + 8 <= end, 'Truncated command')
        kind, length = struct.unpack_from('<II', data, at)
        require(length >= 8 and length % 8 == 0 and at + length <= end, 'Invalid command')
        rows.append((kind, at, length))
        at += length
    require(at == end, 'Command extent mismatch')
    return rows


def blobs(data):
    rows = [(at, length) for kind, at, length in commands(data) if kind == 0x1d]
    require(len(rows) == 1, 'One embedded signature required')
    offset, size = struct.unpack_from('<II', data, rows[0][0] + 8)
    signature = data[offset:offset + size]
    require(len(signature) == size and len(signature) >= 12, 'Invalid signature extent')
    magic, length, count = struct.unpack_from('>III', signature)
    require(magic == 0xfade0cc0 and length <= size and 12 + 8 * count <= length, 'Invalid signature superblob')
    result = {}
    for i in range(count):
        kind, start = struct.unpack_from('>II', signature, 12 + 8 * i)
        require(start + 8 <= length and kind not in result, 'Invalid signature index')
        _, n = struct.unpack_from('>II', signature, start)
        require(n >= 8 and start + n <= length, 'Invalid signature blob')
        result[kind] = signature[start:start + n]
    return result


def regions(data):
    result = {}
    for kind, at, length in commands(data):
        if kind == 0x19:
            name = data[at + 8:at + 24].rstrip(b'\0').decode()
            offset, size = struct.unpack_from('<QQ', data, at + 40)
            require(offset + size <= len(data), 'Invalid segment: ' + name)
            result[name] = (offset, size, data[offset:offset + size])
    return result


def load_dylibs(data):
    dylibs = []
    for kind, at, size in commands(data):
        if kind not in (0xc, 0xd, 0x80000018, 0x8000001f, 0x80000023):
            continue
        offset, _, current, compatibility = struct.unpack_from('<4I', data, at + 8)
        require(24 <= offset < size, 'Invalid dylib name offset')
        raw = data[at + offset:at + size]
        require(b'\0' in raw, 'Unterminated dylib name')
        dylibs.append((kind, raw.split(b'\0', 1)[0].decode(), current, compatibility))
    return dylibs


def check_reexport(data):
    require(struct.unpack_from('<4I', data) == (0xfeedfacf, 0x100000c, 0x80000002, 6),
            'Brightness adapter must be an arm64e MH_DYLIB')
    require(not struct.unpack_from('<I', data, 24)[0] & 0x100000, 'Adapter suppresses re-exports')
    deps = load_dylibs(data)
    require([(kind, name) for kind, name, _, _ in deps] == [
        (0xd, DYLIB), (0xc, '/usr/lib/libobjc.A.dylib'), (0x8000001f, FOUNDATION),
        (0xc, '/usr/lib/libSystem.B.dylib')], 'Missing or unexpected Foundation re-export/dependency')
    return deps


def run(command, output, timeout=120):
    with output.open('x') as stream:
        done = subprocess.run([str(x) for x in command], stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
    if done.returncode:
        raise RuntimeError(output.read_text()[-12000:])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    out = args.out.resolve()
    stage = out / 'runtime'
    for name in ('display-lib', 'display-bin'):
        (stage / name).mkdir(parents=True)
    source = DRIVER / 'BacklightMode069.m'
    official = SNAP / 'UniXNU/scripts/appsync/BacklightMode.m'
    router_path = SNAP / 'UniXNU/scripts/appsync/macho.py'
    original = SNAP / 'd27-display-runtime-original-001/files/os/usr/libexec/backboardd'
    abi_path = OLD / 'sony-oled-corebrightness-abi-003/result.json'
    require(sha(original) == ORIGINAL_SHA and sha(abi_path) == ABI_SHA and sha(official) == HOOK_SHA and
            sha(router_path) == ROUTER_SHA, 'Frozen D27/official inputs differ')
    abi = json.loads(abi_path.read_text())
    require(abi['image_uuid'] == 'b983d2784458311d93de081e4c75f986' and
            abi['class_info']['name'] == 'BrightnessSystemInternal' and
            abi['method']['name'] == 'initBLControl:' and abi['method']['types'] == 'B24@0:8q16', 'Wrong D27 CoreBrightness ABI')
    method = OLD / 'sony-oled-corebrightness-abi-003/initBLControl.bin'
    require(sha(method) == abi['method_sha256'] == METHOD_SHA, 'D27 method bytes differ')
    image_path = OLD / 'sony-oled-corebrightness-002/image.json'
    require(sha(image_path) == abi['original_image_sha256'], 'CoreBrightness image provenance changed')
    image = json.loads(image_path.read_text())
    for segment in image['segments']:
        require(sha(segment['copy']) == segment['sha256'], 'Original CoreBrightness segment differs')
    text = next(x for x in image['segments'] if x['name'] == '__TEXT')
    body = Path(text['copy']).read_bytes()
    offset = abi['method']['imp'] - text['va']
    require(body[offset:offset + abi['method_bytes']] == method.read_bytes(), 'Method is not from the pinned original image')

    host = out / 'host'
    host_command = ['clang++', '-std=c++20', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    ROOT / 'tests/sony_corebrightness069_host.cpp', '-o', host]
    run(host_command, out / 'host.compile.log')
    run([host], out / 'host.log', 30)
    cc = BASE / 'metal-runtime-001/host-bin/clang'
    sdk = BASE / 'user-sdk-002/repository/iPhoneOS27.0.sdk'
    dylib = stage / 'display-lib/UniXNUBacklight.dylib'
    compile_command = [cc, '-target', 'arm64e-apple-ios27.0', '-isysroot', sdk, '-std=gnu11', '-O2',
                       '-Wall', '-Wextra', '-Werror', '-fvisibility=hidden', '-dynamiclib', source,
                       '-lobjc', '-install_name', DYLIB,
                       '-Wl,-reexport_framework,Foundation', '-Wl,-compatibility_version,3000',
                       '-Wl,-current_version,5027.0.69', '-o', dylib]
    run(compile_command, out / 'compile.log')
    # Passing an additional -framework Foundation to the retained ld64 causes
    # it to emit a normal load command and MH_NO_REEXPORTED_DYLIBS instead.
    check_reexport(dylib.read_bytes())
    router = load('d69_official_macho', router_path)
    before = original.read_bytes()
    redirected = router.add_dylib(before, DYLIB, ORIGINAL_SHA)
    daemon = stage / 'display-bin/backboardd'
    daemon.write_bytes(redirected)
    original_blobs = blobs(before)
    entitlements = plistlib.loads(original_blobs[5][8:])
    entfile = out / 'backboardd.entitlements.plist'
    entfile.write_bytes(plistlib.dumps(entitlements, fmt=plistlib.FMT_XML))
    cd = original_blobs[0]
    identifier_at = struct.unpack_from('>I', cd, 20)[0]
    identifier = cd[identifier_at:cd.index(b'\0', identifier_at)].decode()
    signer = Path(json.loads((BASE / 'user-signing-001/source.json').read_text())['executable'])
    files, signed, checks = [], [], {}
    for path, identity, ent in [(dylib, 'org.unixnu.sony.brightness069', None), (daemon, identifier, entfile)]:
        command = [signer, 'sign', '--digest', 'sha256', '--binary-identifier', identity]
        if ent:
            command += ['--entitlements-xml-file', ent]
        run([*command, path], out / (path.name + '.sign.log'))
        path.chmod(0o755)
        checked = inspect(path)
        actual_entitlements = checked.pop('entitlements')
        if ent:
            require(plistlib.loads(actual_entitlements) == entitlements, 'D27 backboardd entitlements changed')
        relative = path.relative_to(stage).as_posix()
        eh = hashlib.sha256(actual_entitlements).hexdigest()
        files.append(dict(path=relative, source=str(path), sha256=sha(path), mode=0o755))
        signed.append(dict(path=relative, entitlements_sha256=eh))
        checks[relative] = dict(checked, entitlements_sha256=eh)
    after = daemon.read_bytes()
    require(struct.unpack_from('<4I', after) == struct.unpack_from('<4I', before), 'D27 architecture/kind changed')
    prior_regions, current_regions = regions(before), regions(after)
    immutable = {}
    for name, (start, size, data) in prior_regions.items():
        if name in ('__TEXT', '__LINKEDIT'):
            continue
        require(current_regions.get(name) == (start, size, data), 'Original segment changed: ' + name)
        immutable[name] = hashlib.sha256(data).hexdigest()
    # Re-signing may move signature data and update __LINKEDIT extent. All other
    # commands and the entire original payload before the signature stay fixed,
    # except the official single Foundation dependency name.
    old_commands, new_commands = commands(redirected), commands(after)
    require(len(old_commands) == len(new_commands), 'Load command count changed')
    exclusions = []
    for (kind, at, size), (nk, na, ns) in zip(old_commands, new_commands):
        require((kind, at, size) == (nk, na, ns), 'Command layout changed')
        if kind == 0x1d:
            exclusions.append((at, at + size))
        elif kind == 0x19 and redirected[at + 8:at + 24].rstrip(b'\0') == b'__LINKEDIT':
            exclusions.append((at, at + size))
        else:
            require(after[at:at + size] == redirected[at:at + size], 'Non-signature load command changed')
    old_sig = next(at for kind, at, _ in old_commands if kind == 0x1d)
    old_sig_offset = struct.unpack_from('<I', redirected, old_sig + 8)[0]
    lhs, rhs = bytearray(redirected[:old_sig_offset]), bytearray(after[:old_sig_offset])
    for first, last in exclusions:
        lhs[first:last] = bytes(last - first)
        rhs[first:last] = bytes(last - first)
    require(lhs == rhs, 'Original D27 instructions/fixups/linkedit payload changed')
    final_blobs = blobs(after)
    require(struct.unpack_from('>I', final_blobs[0], 12)[0] == struct.unpack_from('>I', cd, 12)[0], 'Signature flags changed')
    require(final_blobs.get(2) == original_blobs.get(2), 'Designated code requirements changed')
    require(final_blobs.get(7) == original_blobs.get(7), 'DER entitlements changed')
    require(all(k in (0, 2, 5, 7, 0x10000) for k in original_blobs), 'Unqualified launch/library constraint blob')
    dylib_deps = check_reexport(dylib.read_bytes())
    daemon_deps = load_dylibs(after)
    expected_deps = [(kind, DYLIB if name == FOUNDATION else name, current, compat)
                     for kind, name, current, compat in load_dylibs(before)]
    require(daemon_deps == expected_deps, 'D27 Foundation import ordinal or unrelated dependency changed')
    require(sum(name == DYLIB for _, name, _, _ in daemon_deps) == 1, 'One exact backboardd adapter path required')
    daemon_ordinal = next(i for i, dep in enumerate(daemon_deps, 1) if dep[1] == DYLIB)
    manifest = dict(
        schema='unixnu.sony-corebrightness-stage.v1', passed=True, target='arm64e-apple-ios27.0',
        official_revision='563595abedfdfa413ad583b66b6176d82007e633',
        official_source=str(official), official_source_sha256=HOOK_SHA,
        source=str(source), source_sha256=sha(source),
        original_backboardd=str(original), original_backboardd_sha256=ORIGINAL_SHA,
        corebrightness_uuid=abi['image_uuid'], corebrightness_abi='B24@0:8q16',
        abi_receipt=str(abi_path), abi_receipt_sha256=ABI_SHA, method_sha256=METHOD_SHA,
        host_command=[str(x) for x in host_command], compile_command=[str(x) for x in compile_command],
        host_log_sha256=sha(out / 'host.log'), files=files, signed_files=signed, signature_checks=checks,
        original_entitlements_preserved=True, original_identifier=identifier, signature_flags_preserved=True,
        original_requirements_preserved=True, original_der_entitlements_preserved=True,
        original_code_and_pac_fixups_preserved=True, immutable_segments=immutable,
        foundation_route=DYLIB, foundation_import_ordinal=daemon_ordinal, adapter_dependencies=dylib_deps,
        foundation_reexport_verified=True, user_signature_checks_unchanged=True,
        merged_cache_edited=False, launchd=dict(label='com.apple.backboardd', changes={},
            program_arguments=['/usr/libexec/backboardd'], dyld_environment_required=False,
            note='Keep the original system job and entry point. Main must implement the ordered union hooks below.'),
        main_loader_requirement=dict(guard={'backlight': 1, 'backlight-control': 1, 'sheng-gpu-addon': 1},
            backlight_control_default=1, before='launchd/backboardd execution, after complete addon staging',
            ordered_union_mounts=[dict(source='/private/var/ngpu/display-lib', destination='/usr/lib',
                                      lower_probe='/usr/lib/dyld', own_probe=DYLIB),
                                  dict(source='/private/var/ngpu/display-bin', destination='/usr/libexec',
                                      lower_probe='/usr/libexec/launchd_cache_loader',
                                      own_probe='/usr/libexec/SonyBacklight069.runtime')],
            before_exec_union=['Require signed backboardd and runtime marker in the display-bin source',
                               'Keep the existing wifi-bin union visible when present'],
            failure='Only expose the executable union after library stage5/status0; preserve original backboardd otherwise',
            addon_integrity='Verify both staged Mach-O hashes and signature pages. Append their cdhashes to an owner trust module with all existing modules retained.'),
        hardware_verified=False, backboardd_load_observed=False, linked_into_native=False, device_operations=False)
    marker = stage / 'display-bin/SonyBacklight069.runtime'
    marker.write_text(json.dumps(dict(build='24A446', scope='brightness-only', files={x['path']:x['sha256'] for x in files}), sort_keys=True) + '\n')
    files.append(dict(path=marker.relative_to(stage).as_posix(), source=str(marker), sha256=sha(marker), mode=0o644))
    manifest['inputs'] = {str(p): sha(p) for p in [source, official, router_path, original, abi_path, method, image_path, cc, signer]}
    (out / 'result.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({k: v for k, v in manifest.items() if k not in ('host_command', 'compile_command', 'inputs', 'immutable_segments')}, indent=2))


if __name__ == '__main__':
    main()
