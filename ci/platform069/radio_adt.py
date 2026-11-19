#!/usr/bin/env python3
"""Host-only Sony069 radio ADT overlay over the frozen physical068 ADT."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import re
import subprocess
import struct


ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = Path('/mnt/f/UniXNU-Port-artifacts/platform069-20261118')
BASE_ADT = ARTIFACTS / 'runtime068-inputs-001/kernel.macho.adt'
CAPTURE = ARTIFACTS / 'device-post068-readonly-001'
LIVE_DTB = CAPTURE / 'live.dtb'
BOARD_INPUTS = ARTIFACTS / 'radio-inputs069-002/board-inputs.json'
SOURCE_PINS = ARTIFACTS / 'source-pins.json'
SHENG_REPO = ARTIFACTS / 'sheng'
UNIXNU_REPO = ARTIFACTS / 'UniXNU'
D27_LAUNCHD = ARTIFACTS / 'd27-radio-userland-original-003/files/os/System/Library/xpc/launchd.plist'
BASE_ADT_SHA256 = '86e1c9093e1faa3ac0842f462f089e4bc2e8e828a93bd936039879215114435a'
LIVE_DTB_SHA256 = '6ab06c177a7131338cd8cc374b304838738497bf0d709a48ed50f0282c03bb8a'
D27_LAUNCHD_SHA256 = 'ba3565e6f0682df14a46bcb50c72b1a39bd7aa4fb166064506e0057a262e39cd'
UPSTREAM_INPUTS = {
    'sheng/dts/sheng.dts': '7407181ec4c2a6207b039e2aa88869f70a414eaa35d0cacc231b41b69e041130',
    'sheng/package/WifiProbe.cpp': 'e449a40b423ed0f4b0750cb5c1edcd8139cbe9bd11b73a82d2885c8ad21060a5',
    'sheng/package/BluetoothProbe.cpp': 'e66a4a8328f878fc7bd59c2e158c3e69d4a65b680df264a548d200225e61a652',
    'UniXNU/scripts/unixnu/devicetree.py': 'dd72d2e5dfa8183c9ea320a52017d424c1dee70b057972b1ad91225686c49606',
}
PINS = {
    'UniXNU': '563595abedfdfa413ad583b66b6176d82007e633',
    'sheng': 'c8f92b208068eeaa4cd2b0f592671f04ee70076e',
    'sm8550': '2dc650ca76ae38715cd0712e60a44b14fe251745',
    'Ath12kWifi': '84e02e0c0a3354c341c76affef582c7c41883f1f',
    'QcaBluetooth': 'fa528145aee3073c47533d74ea260eb2818b6b63',
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def live_fdt():
    parser = load_module('sony069_radio_fdt', ROOT / 'drivers/SonyWcn/board_inputs.py')
    fdt = parser.Fdt(LIVE_DTB)
    if fdt.sha256 != LIVE_DTB_SHA256:
        raise ValueError('Sony live.dtb SHA-256 mismatch')
    return fdt


def decode_hamilton_nvm_address(blob: bytes) -> tuple[int, bytes]:
    """Qualify the one BD_ADDR tag in the captured type-2 Hamilton NVM format."""
    if not 4 <= len(blob) <= 65536:
        raise ValueError('Unexpected Hamilton NVM length')
    header, = struct.unpack_from('<I', blob)
    if header & 0xff != 2 or header >> 8 != len(blob) - 4:
        raise ValueError('Expected one complete type-2 Hamilton NVM TLV')
    offset, address = 4, None
    while offset < len(blob):
        if offset + 12 > len(blob):
            raise ValueError('Truncated Hamilton NVM tag header')
        tag, size, _, _ = struct.unpack_from('<HHII', blob, offset)
        offset += 12
        if offset + size > len(blob):
            raise ValueError('Truncated Hamilton NVM tag payload')
        if tag == 2:  # EDL_TAG_ID_BD_ADDR in the selected btqca.h; stored as bdaddr_t.
            if size != 6 or address is not None:
                raise ValueError('Invalid or duplicate Hamilton BD_ADDR tag')
            address = (offset, blob[offset:offset + size])
        offset += size
    if address is None:
        raise ValueError('No Hamilton BD_ADDR tag')
    return address


def audit_addresses(fdt) -> dict:
    suspicious = re.compile(r'(?:mac[-_,]?addr|bd[-_,]?addr|bluetooth[-_,]?address|wlan[-_,]?addr|wifi[-_,]?addr)', re.I)
    if any(suspicious.search(key) for props in fdt.nodes.values() for key in props):
        raise ValueError('Unexpected radio address key in the frozen Sony FDT')

    dmesg = (CAPTURE / 'android-dmesg.txt').read_bytes()
    if sha256(dmesg) != '8bd4abfa7937111c6fef6648fb7b521c91460545da310796f3fc7762c8385cb3':
        raise ValueError('Sony Android log provenance differs')
    if b'QMI_DMS_GET_MAC_ADDRESS_REQ_V01 failed' not in dmesg or b'WLAN MAC address is not set, type 0' not in dmesg:
        raise ValueError('Sony Android log lacks its factory-MAC lookup boundary')
    if b'hdd_initialize_mac_address: using MAC address from wlan_mac.bin' not in dmesg:
        raise ValueError('Sony Android log lacks its WLAN address file selection')
    station_matches = re.findall(rb'wlan0\(vdevid-0\): ((?:[0-9a-f]{2}:){5}[0-9a-f]{2}) Connect with ', dmesg, re.I)
    if len(station_matches) != 1 or int(station_matches[0][:2], 16) & 3 != 2:
        raise ValueError('Sony Android log lacks the expected locally administered station observation')

    directory = CAPTURE / 'bluetooth-firmware'
    manifest = (directory / 'manifest.json').read_bytes()
    if sha256(manifest) != 'b92cc52856a395ed933196788c98fbb86ce30e5d3b0e82a6c7bdf7fbb5be88ed':
        raise ValueError('Captured Sony Bluetooth firmware manifest differs')
    tags = {}
    for row in json.loads(manifest)['files']:
        name = row['android_path'].rsplit('/', 1)[-1]
        if not re.fullmatch(r'hmtnv20\.(?:bin|b[0-9a-f]{2,3})', name):
            continue
        blob = (directory / name).read_bytes()
        if (row['phone_hash_matches'] is not True or len(blob) != row['bytes'] or
                sha256(blob) != row['sha256'] or name in tags):
            raise ValueError('Sony Hamilton NVM capture identity differs: ' + name)
        tags[name] = decode_hamilton_nvm_address(blob)
    if len(tags) != 47 or set(tags.values()) != {(0x5c, b'\xad\x5a\0\0\0\0')}:
        raise ValueError('Captured Hamilton NVM tag evidence differs')
    return {
        'live_fdt_nodes_checked': len(fdt.nodes),
        'physical_wifi_mac': 'not qualified; QMI lookup fails and driver uses wlan_mac.bin; neither address-file payload was captured',
        'android_wlan0_associated_mac': 'observed local unicast, not proof of the factory/permanent address; not used or copied',
        'physical_bluetooth_bd_addr': 'not qualified; no live controller public address in the capture',
        'hamilton_nvm_shared_default': {'verified_variants': len(tags), 'tag_id': 2, 'value_offset': '0x5c',
                                        'raw_le_hex': 'ad5a00000000', 'display_order': '00:00:00:00:5a:ad',
                                        'used_as_sony_bd_addr': False},
    }


def _name(raw: bytes) -> str:
    if not raw.endswith(b'\0') or b'\0' in raw[:-1]:
        raise ValueError('ADT node name is not one terminated ASCII string')
    return raw[:-1].decode('ascii')


def _scan_node(blob: bytes, offset: int = 0, depth: int = 0) -> tuple[dict, int]:
    """Parse enough of Apple's ADT wire format to validate and locate exact node spans."""
    if depth > 64 or offset < 0 or offset + 8 > len(blob):
        raise ValueError('Truncated or overdeep ADT node')
    property_count, child_count = struct.unpack_from('<II', blob, offset)
    cursor = offset + 8
    props: dict[str, bytes] = {}
    prop_offsets: dict[str, int] = {}
    for _ in range(property_count):
        if cursor + 36 > len(blob):
            raise ValueError('Truncated ADT property header')
        raw_name, size = struct.unpack_from('<32sI', blob, cursor)
        if b'\0' not in raw_name:
            raise ValueError('Unterminated ADT property name')
        key = raw_name.split(b'\0', 1)[0].decode('ascii')
        value_at = cursor + 36
        end = value_at + size
        padded_end = value_at + ((size + 3) & ~3)
        if key in props or padded_end > len(blob):
            raise ValueError('Duplicate or truncated ADT property')
        props[key] = blob[value_at:end]
        prop_offsets[key] = cursor
        cursor = padded_end
    if 'name' not in props:
        raise ValueError('ADT node is missing its name property')
    children: list[dict] = []
    child_names: set[str] = set()
    for _ in range(child_count):
        child, cursor = _scan_node(blob, cursor, depth + 1)
        child_name = _name(child['properties']['name'])
        if child_name in child_names:
            raise ValueError('Duplicate ADT child name: ' + child_name)
        child_names.add(child_name)
        children.append(child)
    return {
        'name': _name(props['name']), 'properties': props,
        'property_offsets': prop_offsets, 'children': children,
        'start': offset, 'end': cursor, 'child_count_offset': offset + 4,
    }, cursor


def parse_adt(blob: bytes) -> dict:
    root, end = _scan_node(blob)
    if end != len(blob) or root['name'] != 'device-tree':
        raise ValueError('ADT has trailing bytes or unexpected root')
    return root


def at_path(root: dict, path: str) -> dict:
    node = root
    parts = [p for p in path.strip('/').split('/') if p]
    if parts and parts[0] == root['name']:
        parts.pop(0)
    for part in parts:
        matches = [child for child in node['children'] if child['name'] == part]
        if len(matches) != 1:
            raise ValueError(f'ADT path is absent or ambiguous: {path}')
        node = matches[0]
    return node


def _encode_node(name: str, properties: list[tuple[str, bytes]]) -> bytes:
    values = [('name', name.encode('ascii') + b'\0'), *properties]
    if len({key for key, _ in values}) != len(values):
        raise ValueError('Duplicate ADT property in generated node')
    output = bytearray(struct.pack('<II', len(values), 0))
    for key, value in values:
        key_bytes = key.encode('ascii')
        if not key_bytes or len(key_bytes) > 31:
            raise ValueError('ADT property key must fit the Apple 32-byte field')
        output += struct.pack('<32sI', key_bytes, len(value))
        output += value
        output += bytes(-len(value) % 4)
    return bytes(output)


def expected_nodes() -> dict[str, bytes]:
    """Use the pinned upstream board-to-ADT ABI; no address or identity is supplied."""
    return {
        'wlan': _encode_node('wlan', [
            ('compatible', b'qcom,wcn7850\0'),
        ]),
        'bluetooth': _encode_node('bluetooth', [
            ('device_type', b'bluetooth\0'),
            ('compatible', b'qcom,wcn7850-bt\0'),
            ('transport-encoding', struct.pack('<I', 1)),
            ('transport-speed', struct.pack('<I', 3_200_000)),
        ]),
    }


def overlay_adt(original: bytes) -> tuple[bytes, dict]:
    """Append missing Apple-consumer nodes under arm-io without rebuilding frozen ADT data."""
    root = parse_adt(original)
    arm_io = at_path(root, '/device-tree/arm-io')
    current = {child['name']: child for child in arm_io['children']}
    wanted = expected_nodes()
    additions: list[bytes] = []
    added: list[str] = []
    for name, encoded in wanted.items():
        if name in current:
            expected, end = _scan_node(encoded)
            actual = current[name]
            if actual['properties'] != expected['properties'] or actual['children']:
                raise ValueError(f'Existing /arm-io/{name} conflicts with selected source ABI')
            continue
        additions.append(encoded)
        added.append(name)
    if not additions:
        return original, {'added': [], 'idempotent': True}

    insertion = arm_io['end']
    updated = bytearray(original[:insertion] + b''.join(additions) + original[insertion:])
    count_offset = arm_io['child_count_offset']
    child_count = struct.unpack_from('<I', original, count_offset)[0]
    struct.pack_into('<I', updated, count_offset, child_count + len(additions))
    result = bytes(updated)

    # Confirm both wire validity and exact preservation outside the one count word
    # plus the inserted child records. In particular, /chosen identity/NVRAM and
    # every pre-existing ADT property/value are not regenerated.
    reparsed = parse_adt(result)
    for name, encoded in wanted.items():
        wanted_node, _ = _scan_node(encoded)
        actual = at_path(reparsed, '/device-tree/arm-io/' + name)
        if actual['properties'] != wanted_node['properties'] or actual['children']:
            raise ValueError('Generated radio ADT node failed exact source-ABI readback: ' + name)
    if at_path(reparsed, '/device-tree/chosen')['properties'] != at_path(root, '/device-tree/chosen')['properties']:
        raise ValueError('Overlay changed /chosen properties')
    return result, {'added': added, 'idempotent': False, 'insert_offset': insertion,
                    'old_arm_io_children': child_count, 'new_arm_io_children': child_count + len(additions),
                    'inserted_bytes': sum(map(len, additions)), 'child_count_field_offset': count_offset}


def verify_inputs() -> dict:
    if sha256(BASE_ADT.read_bytes()) != BASE_ADT_SHA256:
        raise ValueError('Frozen original068 ADT SHA-256 mismatch')
    if sha256(LIVE_DTB.read_bytes()) != LIVE_DTB_SHA256:
        raise ValueError('Sony live.dtb SHA-256 mismatch')
    source_pins = json.loads(SOURCE_PINS.read_text())
    if any(source_pins.get(key) != value for key, value in PINS.items()):
        raise ValueError('Official source-pins.json differs from selected radio ABI pins')
    revisions = {}
    for name in ('sheng', 'UniXNU'):
        revisions[name] = subprocess.run(['git', '-C', str(ARTIFACTS / name), 'rev-parse', 'HEAD'],
                                         check=True, capture_output=True, text=True, timeout=15).stdout.strip()
        if revisions[name] != PINS[name]:
            raise ValueError('Official snapshot revision differs: ' + name)
    for name, digest in UPSTREAM_INPUTS.items():
        if sha256((ARTIFACTS / name).read_bytes()) != digest:
            raise ValueError('Pinned board/ADT source bytes changed: ' + name)
    board = json.loads(BOARD_INPUTS.read_text())
    if (board.get('sha256') != LIVE_DTB_SHA256 or
            board.get('wifi_node') != '/soc/qcom,cnss-qca-converged/chip_cfg@1' or
            board.get('bluetooth_node') != '/soc/bt-qca-converged/bt_kiwi'):
        raise ValueError('Resolved Sony radio-node provenance differs from the captured live.dtb')
    fdt = live_fdt()
    nodes = fdt.nodes
    wifi_path, bt_path = board['wifi_node'], board['bluetooth_node']
    if wifi_path not in nodes or bt_path not in nodes:
        raise ValueError('The captured Sony live.dtb lacks one of the resolved radio nodes')
    if nodes[bt_path].get('compatible') != b'qcom,kiwi\0':
        raise ValueError('Sony Bluetooth selection is not the captured qcom,kiwi node')
    if nodes[wifi_path].get('qcom,wlan') != b'' or fdt.cells(wifi_path, 'supported-ids') != [0x1107]:
        raise ValueError('Sony WLAN flag/endpoint device ID differs')
    for platform in ('linux', 'windows'):
        receipt = ARTIFACTS.parent / 'platform068-menu-20261118' / (platform + '-final-001/readback.json')
        if json.loads(receipt.read_text()).get('kernel.macho.adt') != BASE_ADT_SHA256:
            raise ValueError('Original068 independent ADT readback identity differs: ' + platform)
    launchd_bytes = D27_LAUNCHD.read_bytes()
    if sha256(launchd_bytes) != D27_LAUNCHD_SHA256:
        raise ValueError('Original D27 launchd.plist read-only input differs')
    def jobs(value):
        if isinstance(value, dict):
            if value.get('Label') == 'com.apple.wifid':
                yield value
            for child in value.values():
                yield from jobs(child)
        elif isinstance(value, list):
            for child in value:
                yield from jobs(child)
    wifi_jobs = list(jobs(plistlib.loads(launchd_bytes)))
    if len(wifi_jobs) != 1 or 'wlan' not in wifi_jobs[0].get('_LimitLoadToDeviceTree', []):
        raise ValueError('Original D27 wifid device-tree condition differs')
    return {'base_adt_sha256': BASE_ADT_SHA256, 'sony_live_dtb_sha256': LIVE_DTB_SHA256,
            'source_pins': PINS, 'upstream_revisions': revisions, 'upstream_sources': UPSTREAM_INPUTS,
            'original_wifid': {'launchd_plist_sha256': D27_LAUNCHD_SHA256,
                               '_LimitLoadToDeviceTree': wifi_jobs[0]['_LimitLoadToDeviceTree']},
            'address_capture': audit_addresses(fdt),
            'sony_nodes': {'wlan': board['wifi_node'], 'bluetooth': board['bluetooth_node']}}


def build(out: Path) -> dict:
    inputs = verify_inputs()
    out = out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    original = BASE_ADT.read_bytes()
    updated, delta = overlay_adt(original)
    output = out / 'kernel.macho.adt'
    output.write_bytes(updated)
    # Independent file readback of the produced artifact and strict node/property checks.
    readback = output.read_bytes()
    parsed = parse_adt(readback)
    wifi = at_path(parsed, '/device-tree/arm-io/wlan')['properties']
    bluetooth = at_path(parsed, '/device-tree/arm-io/bluetooth')['properties']
    chosen = at_path(parsed, '/device-tree/chosen')['properties']
    if (wifi.get('compatible') != b'qcom,wcn7850\0' or
            bluetooth.get('device_type') != b'bluetooth\0' or
            bluetooth.get('compatible') != b'qcom,wcn7850-bt\0' or
            bluetooth.get('transport-encoding') != struct.pack('<I', 1) or
            bluetooth.get('transport-speed') != struct.pack('<I', 3_200_000)):
        raise ValueError('Final ADT readback does not match the pinned source ABI')
    if any(key.startswith('mac-address-') for key in chosen) or any(
            'local-mac-address' in node['properties'] for node in (at_path(parsed, '/device-tree/arm-io/wlan'),
                                                                  at_path(parsed, '/device-tree/arm-io/bluetooth'))):
        raise ValueError('Static ADT must not invent a radio MAC address')
    result = {
        'passed': True, 'host_only': True, 'device_operations': False,
        'base': str(BASE_ADT), 'base_bytes': len(original),
        'output': str(output), 'output_bytes': len(readback),
        'output_sha256': sha256(readback), 'readback_matches_overlay': readback == updated,
        'delta': delta, 'inputs': inputs,
        'consumer_abi': {
            'wifi': {'path': '/arm-io/wlan', 'properties': {'compatible': 'qcom,wcn7850'}},
            'bluetooth': {'path': '/arm-io/bluetooth', 'properties': {
                'device_type': 'bluetooth', 'compatible': 'qcom,wcn7850-bt',
                'transport-encoding': 1, 'transport-speed': 3_200_000}},
        },
        'address_provenance': {
            'physical_wifi_mac': 'not qualified; Android logs show a local association address and wlan_mac.bin selection, not factory-address-file bytes',
            'wifi_software_identity': 'pinned sheng WifiProbe boardMac contract: FNV-1a over the 8-byte little-endian /chosen/unique-chip-id, locally administered unicast; source-derived software identity, not a Sony OTP/hardware address',
            'physical_bluetooth_bd_addr': 'not qualified; all47 NVM variants carry the same non-unit-specific tag2 default 00:00:00:00:5a:ad at0x5c; not used',
            'bluetooth_software_identity': 'pinned sheng BluetoothProbe address contract: FNV-1a with domain unixnu-bluetooth over /chosen/unique-chip-id bytes, locally administered unicast; source-derived software identity, not a recovered Sony public BD_ADDR',
            'adt_mac_properties_added': False,
            'adt_identity_modified': False,
        },
        'existing_early_publication': {
            'bluetooth': {
                'publisher': 'native_sony_bluetooth_publish',
                'existing_call': 'native_sony_radio_platform069_init in SonySharedResources.cpp',
                'main_startup_integration': 'build-sony-shared-owners069.py inserts native_sony_radio_platform069_init before native_sony_touch_start in LegacyDisplayProbe startup',
                'properties': ['/chosen/mac-address-bluetooth0', '/arm-io/bluetooth/local-mac-address',
                               'bluetooth IOService transport-encoding/transport-speed/local-mac-address'],
                'qualification': 'host source/integration only; runtime not verified',
            },
            'wifi': {
                'current_publisher': 'adapted WifiProbe publishMac at wifiThread entry',
                'timing': 'late radio worker, not an early pre-userland guarantee',
                'proposed_dedicated_entry': 'native_sony_wifi_publish in SonyWifiAddress069.cpp; guarded Wi-Fi source overlay calls it synchronously after prerequisites and before worker scheduling; main owns selection',
                'properties': ['/chosen/mac-address-wifi0', '/arm-io/wlan/local-mac-address'],
                'qualification': 'standalone source and FNV ABI host fixture; invocation still requires main-owned integration',
            },
        },
        'limitations': [
            'No physical Sony MAC/BD_ADDR is fabricated or embedded in static ADT; deterministic local software identities follow the selected pinned sheng ABI and must not be called hardware addresses.',
            'The Bluetooth early publisher is present in the current 069 owner integration, but hardware/runtime property consumption remains unverified.',
            'Wi-Fi publisher and guarded source overlay are not selected by main yet; the shared startup owner is unchanged.',
            'No radio hardware startup, scan, association, pairing or userland verification was performed.',
        ],
    }
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True, help='new, empty host artifact directory')
    args = parser.parse_args()
    print(json.dumps(build(args.out), indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
