"""Source-pinned D27 launchd cache transform, binary serialization and signing.

This module stages only System/Library/xpc/launchd.plist and its detached
signature. It does not alter the kernel, AMFI, trust cache, or runtime addon.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import shutil
import struct
import subprocess
import tempfile


ICON_LABEL = "com.apple.iconservices.iconservicesagent"
BLUETOOL_LABEL = "com.apple.BlueTool"
WIFI_LABEL = "org.unixnu.wifi.supplicant"
WIFI_CACHE_KEY = "/System/Library/LaunchDaemons/org.unixnu.wifi.supplicant.plist"
ICON_ENVIRONMENT = {"FORCE_SOFTWARE_RENDERER": "0", "CI_ENABLE_METAL_GPU": "0"}
BLUETOOL_OVERRIDES = {
    "UserName": "root",
    "ThrottleInterval": 3,
    "EnablePressuredExit": False,
    "EnableTransactions": True,
}
WIFI_JOB = {
    "Label": WIFI_LABEL,
    "ProgramArguments": [
        "/usr/libexec/unixnu-wpa_supplicant",
        "-Dsheng",
        "-ien0",
        "-c/private/var/ngpu/etc/wifi/wpa_supplicant.conf",
        "-q",
        "-s",
    ],
    "RunAtLoad": True,
    "KeepAlive": True,
    "ThrottleInterval": 3,
    "UserName": "root",
    "Umask": 0o77,
    "ProcessType": "Interactive",
}

EXPECTED_CODEDIRECTORY_VERSION = 0x20500
EXPECTED_HASH_SIZE = 32
EXPECTED_HASH_TYPE = 2  # SHA-256
EXPECTED_PAGE_EXPONENT = 12  # 4096 bytes
CSSLOT_SIGNATURESLOT = 0x10000
CSSLOT_IDENTIFICATIONSLOT = 0x10001
CSMAGIC_BLOBWRAPPER = 0xFADE0B01

# Canonical Apple signer behavior, not evidence of running D27 Security.framework.
APPLE_SECURITY_REVISION = "db15acbe6a7f257a859ad9a3bb86097bfe0679d9"
APPLE_SECURITY_SOURCE_BASE = (
    "https://raw.githubusercontent.com/apple-oss-distributions/Security/"
    + APPLE_SECURITY_REVISION + "/OSX/libsecurity_codesigning/lib/"
)
APPLE_SECURITY_SOURCES = {
    "codedirectory.h": {
        "sha256": "dfc86acb9a1aaacdaf0f37aae0902df854c6cb384831caf8ca230eaa89189804",
        "lines": [111, 124],
        "finding": "0x10000 CMS and 0x10001 identification are distinct virtual slots, outside the CodeDirectory hash array",
    },
    "singlediskrep.cpp": {
        "sha256": "321835f049a1b0dfef3d74559142a43d79a3205cb7e2f81285b968f1bb29baf4",
        "lines": [47, 59],
        "finding": "SingleDiskRep::identification hashes the entire raw file with SHA-1",
    },
    "filediskrep.h": {
        "sha256": "587fcff600a535f38131ec855d78289bf3b00b348ca6d7eeb78155a860542c70",
        "lines": [39, 57],
        "finding": "generic FileDiskRep inherits SingleDiskRep",
    },
    "signer.cpp": {
        "sha256": "83c1cd525934c0b7d0c5f08322b02e347a5cbf9f521a67edd36023387a8559a2",
        "lines": [759, 775],
        "additional_lines": [885, 894],
        "finding": "detached non-Mach-O signing writes rep->identification into 0x10001; ad-hoc signing uses an empty CMS payload",
    },
    "sigblob.cpp": {
        "sha256": "8f896422df3e7f17d4498873cbb987069e4d7ac925f0b388d77a6c43b731541c",
        "lines": [45, 62],
        "finding": "raw virtual components are stored in BlobWrapper objects",
    },
    "codedirectory.cpp": {
        "sha256": "9a4b47e6cee40983d71e3214286415ed7b83b22b403d5a7e89fad50d776646af",
        "lines": [347, 358],
        "finding": "cdhash hashes only the CodeDirectory, using its selected digest, truncated to 20 bytes",
    },
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _find_job(jobs: dict, label: str) -> tuple[str, dict]:
    found = [(key, job) for key, job in jobs.items() if isinstance(job, dict) and job.get("Label") == label]
    if len(found) != 1:
        raise ValueError(f"expected exactly one launchd job labeled {label}, found {len(found)}")
    return found[0]


def transform_cache_bytes(raw: bytes) -> tuple[dict, dict]:
    """Apply the single Wi-Fi addition and source-qualified OS-job settings."""
    if not raw.startswith(b"bplist00"):
        raise ValueError("original launchd cache must be Apple's binary plist")
    original = plistlib.loads(raw)
    if not isinstance(original, dict) or original.get("VersionNumber") != 7:
        raise ValueError("unexpected D27 launchd cache root/version")
    if not isinstance(original.get("LaunchDaemons"), dict):
        raise ValueError("D27 LaunchDaemons is not a dictionary")

    before_jobs = original["LaunchDaemons"]
    icon_key, icon = _find_job(before_jobs, ICON_LABEL)
    blue_key, blue = _find_job(before_jobs, BLUETOOL_LABEL)
    if WIFI_CACHE_KEY in before_jobs or any(
        isinstance(job, dict) and job.get("Label") == WIFI_LABEL for job in before_jobs.values()
    ):
        raise ValueError("Wi-Fi launchd job already exists in the source cache")

    after = copy.deepcopy(original)
    jobs = after["LaunchDaemons"]
    icon = jobs[icon_key]
    environment = icon.setdefault("EnvironmentVariables", {})
    if not isinstance(environment, dict):
        raise ValueError("iconservices EnvironmentVariables is not a dictionary")
    for key, value in ICON_ENVIRONMENT.items():
        if key in environment and environment[key] != value:
            raise ValueError(f"conflicting iconservices environment value: {key}")
        environment[key] = value

    blue = jobs[blue_key]
    for key, value in BLUETOOL_OVERRIDES.items():
        blue[key] = value
    jobs[WIFI_CACHE_KEY] = copy.deepcopy(WIFI_JOB)

    expected = copy.deepcopy(original)
    expected_icon = expected["LaunchDaemons"][icon_key]
    expected_icon.setdefault("EnvironmentVariables", {}).update(ICON_ENVIRONMENT)
    expected["LaunchDaemons"][blue_key].update(BLUETOOL_OVERRIDES)
    expected["LaunchDaemons"][WIFI_CACHE_KEY] = copy.deepcopy(WIFI_JOB)
    if after != expected:
        raise ValueError("launchd cache mutation exceeded the three source-qualified job changes")

    return after, {
        "source_jobs": len(before_jobs),
        "staged_jobs": len(jobs),
        "added_job_key": WIFI_CACHE_KEY,
        "icon_environment": copy.deepcopy(ICON_ENVIRONMENT),
        "bluetooth_job_overrides": copy.deepcopy(BLUETOOL_OVERRIDES),
        "original_jobs_and_limits_preserved_except_explicit_overrides": True,
        "changed_original_jobs": [icon_key, blue_key],
    }


def serialize_binary_plist(value: dict, destination: Path, plutil: str = "plutil") -> None:
    """Use the pinned project's Apple plutil binary1 serializer convention."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(plistlib.dumps(value, fmt=plistlib.FMT_XML, sort_keys=False))
    subprocess.run([plutil, "-convert", "binary1", str(destination)], check=True, capture_output=True)
    encoded = destination.read_bytes()
    if not encoded.startswith(b"bplist00") or plistlib.loads(encoded) != value:
        raise ValueError("binary1 serializer output did not round-trip exactly")


def serializer_receipt(plutil: str = "plutil") -> dict:
    executable = shutil.which(plutil)
    if executable is None:
        raise FileNotFoundError("plutil binary1 serializer is unavailable")
    path = Path(executable).resolve()
    return {
        "command": [executable, "-convert", "binary1"],
        "executable_sha256": sha256_file(path),
        "host_roundtrip_parser": "Python plistlib",
        "apple_plutil_or_libxpc_validation": "NOT_RUN",
    }


def _parse_superblob(raw: bytes) -> dict[int, bytes]:
    if len(raw) < 12:
        raise ValueError("truncated detached signature superblob")
    magic, length, count = struct.unpack_from(">III", raw)
    if magic != 0xFADE0CC0 or length != len(raw) or count > 64 or 12 + count * 8 > length:
        raise ValueError("invalid detached signature superblob header")
    blobs = {}
    for index in range(count):
        slot, offset = struct.unpack_from(">II", raw, 12 + index * 8)
        if slot in blobs or offset + 8 > length:
            raise ValueError("duplicate or out-of-range detached signature blob")
        blob_magic, blob_length = struct.unpack_from(">II", raw, offset)
        if blob_length < 8 or offset + blob_length > length:
            raise ValueError("invalid detached signature blob bounds")
        blobs[slot] = raw[offset:offset + blob_length]
        if blob_magic == 0:
            raise ValueError("invalid zero-magic signature blob")
    if 0 not in blobs:
        raise ValueError("detached signature has no primary CodeDirectory")
    return blobs


def _inspect_detached_wrappers(blobs: dict[int, bytes], raw_sha1: bytes) -> dict:
    cms = blobs.get(CSSLOT_SIGNATURESLOT)
    if cms != struct.pack(">II", CSMAGIC_BLOBWRAPPER, 8):
        raise ValueError("D27 ad-hoc signature requires a distinct empty 0x10000 CMS BlobWrapper")
    identification = blobs.get(CSSLOT_IDENTIFICATIONSLOT)
    if (identification is None or len(identification) != 28
            or identification[:8] != struct.pack(">II", CSMAGIC_BLOBWRAPPER, 28)):
        raise ValueError("D27 detached signature requires a 20-byte 0x10001 identification BlobWrapper")
    if identification[8:] != raw_sha1:
        raise ValueError("stale 0x10001 identification: payload differs from SHA1(raw plist)")
    return {
        "signature_wrapper": {"slot": "0x10000", "magic": "0xfade0b01", "bytes": 8,
                              "payload_bytes": 0, "ad_hoc_empty_cms_verified": True},
        "identification_wrapper": {"slot": "0x10001", "magic": "0xfade0b01", "bytes": 28,
                                   "payload_bytes": 20, "payload_sha1": raw_sha1.hex(),
                                   "matches_raw_plist_sha1": True},
    }


def inspect_detached_signature(cache: bytes, signature: bytes, expected_identifier: str | None = None) -> dict:
    """Check page/special hashes plus the separate CMS and identification slots."""
    blobs = _parse_superblob(signature)
    cd = blobs[0]
    if len(cd) < 44:
        raise ValueError("truncated CodeDirectory")
    magic, cd_length, version, flags = struct.unpack_from(">IIII", cd)
    if magic != 0xFADE0C02 or cd_length != len(cd):
        raise ValueError("invalid primary CodeDirectory")
    hash_offset, ident_offset, special_slots, code_slots, code_limit = struct.unpack_from(">IIIII", cd, 16)
    hash_size, hash_type, _platform, page_exponent = struct.unpack_from(">BBBB", cd, 36)
    if (version, hash_size, hash_type, page_exponent) != (
        EXPECTED_CODEDIRECTORY_VERSION, EXPECTED_HASH_SIZE, EXPECTED_HASH_TYPE, EXPECTED_PAGE_EXPONENT
    ):
        raise ValueError("CodeDirectory version/hash/page ABI differs from the D27 loader input")
    page_size = 1 << page_exponent
    if code_limit != len(cache) or code_slots != (code_limit + page_size - 1) // page_size:
        raise ValueError("CodeDirectory cache bounds or page count differs")
    if hash_offset < special_slots * hash_size or hash_offset + code_slots * hash_size > len(cd):
        raise ValueError("CodeDirectory hash table is out of range")
    if ident_offset >= len(cd):
        raise ValueError("CodeDirectory identifier offset is out of range")
    ident_end = cd.find(b"\0", ident_offset)
    if ident_end < 0:
        raise ValueError("unterminated CodeDirectory identifier")
    identifier = cd[ident_offset:ident_end].decode("utf-8")
    if expected_identifier is not None and identifier != expected_identifier:
        raise ValueError("CodeDirectory identity does not match SHA-1 of staged raw plist")

    for index in range(code_slots):
        start = index * page_size
        expected = cd[hash_offset + index * hash_size:hash_offset + (index + 1) * hash_size]
        actual = hashlib.sha256(cache[start:min(start + page_size, code_limit)]).digest()
        if actual != expected:
            raise ValueError(f"CodeDirectory page hash mismatch at page {index}")

    # Special-slot hashes are stored backwards from hashOffset: slot 1 is
    # immediately before the code hashes, slot 2 precedes slot 1, and so on.
    for slot in range(special_slots, 0, -1):
        expected = cd[hash_offset - slot * hash_size:hash_offset - (slot - 1) * hash_size]
        content = blobs.get(slot)
        if content is None:
            if any(expected):
                raise ValueError(f"unverified CodeDirectory special slot {slot}")
        elif hashlib.sha256(content).digest() != expected:
            raise ValueError(f"CodeDirectory special-slot hash mismatch at slot {slot}")

    raw_sha1 = hashlib.sha1(cache).digest()
    canonical_identifier = "launchd-" + raw_sha1.hex()
    if identifier != canonical_identifier:
        raise ValueError("CodeDirectory identity does not match SHA-1 of staged raw plist")
    wrappers = _inspect_detached_wrappers(blobs, raw_sha1)
    cdhash = hashlib.sha256(cd).digest()[:20].hex()
    return {
        "identifier": identifier,
        "codedirectory_version": f"0x{version:05x}",
        "codedirectory_flags": f"0x{flags:08x}",
        "hash_algorithm": "sha256",
        "hash_size": hash_size,
        "page_size": page_size,
        "code_slots": code_slots,
        "code_limit": code_limit,
        "special_slots_verified": special_slots,
        "cdhash": cdhash,
        **wrappers,
    }


def build_detached_signature(cache: bytes, template: bytes) -> bytes:
    """Rebuild the D27 CodeDirectory and refresh detached file identification.

    The build WSL has a no-op ``/usr/bin/codesign`` shim, so invoking it would
    silently leave an unsigned cache. This routine uses the original detached
    signature as the format/flags/requirements template and regenerates its
    CodeDirectory identity, special-slot hashes, every 4K code-page hash, and
    the distinct 0x10001 raw-file SHA-1 identification wrapper. The empty
    0x10000 CMS wrapper and source requirements remain byte-identical.
    """
    source_blobs = _parse_superblob(template)
    source_cd = source_blobs[0]
    if len(source_cd) < 96:
        raise ValueError("D27 CodeDirectory template lacks the 0x20500 extended header")
    if struct.unpack_from(">I", source_cd, 8)[0] != EXPECTED_CODEDIRECTORY_VERSION:
        raise ValueError("D27 CodeDirectory template version differs")
    if struct.unpack_from(">I", source_cd, 12)[0] != 0x00010002:
        raise ValueError("D27 ad-hoc CodeDirectory flags differ from the original")
    if struct.unpack_from(">Q", source_cd, 56)[0] != 0:
        raise ValueError("unexpected original 64-bit CodeDirectory limit")
    ident_offset = struct.unpack_from(">I", source_cd, 20)[0]
    ident_end = source_cd.find(b"\0", ident_offset)
    source_identity = source_cd[ident_offset:ident_end] if ident_end >= 0 else b""
    prefix = b"launchd-"
    if len(source_identity) != len(prefix) + 40 or not source_identity.startswith(prefix):
        raise ValueError("unexpected D27 template CodeDirectory identifier")
    try:
        template_sha1 = bytes.fromhex(source_identity[len(prefix):].decode("ascii"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError("invalid D27 template CodeDirectory SHA-1 identifier") from error
    _inspect_detached_wrappers(source_blobs, template_sha1)

    identifier = b"launchd-" + hashlib.sha1(cache).hexdigest().encode("ascii") + b"\0"
    special_slots = struct.unpack_from(">I", source_cd, 24)[0]
    if special_slots > 16:
        raise ValueError("unexpected D27 CodeDirectory special-slot count")
    header_size = 96
    hash_size = EXPECTED_HASH_SIZE
    hash_offset = header_size + len(identifier) + special_slots * hash_size
    code_slots = (len(cache) + 4095) // 4096
    cd_length = hash_offset + code_slots * hash_size

    cd = bytearray(source_cd[:header_size])
    struct.pack_into(">I", cd, 4, cd_length)
    struct.pack_into(">IIIII", cd, 16, hash_offset, header_size, special_slots, code_slots, len(cache))
    struct.pack_into(">BBBB", cd, 36, hash_size, EXPECTED_HASH_TYPE, source_cd[38], EXPECTED_PAGE_EXPONENT)
    struct.pack_into(">Q", cd, 56, 0)
    cd.extend(identifier)
    for slot in range(special_slots, 0, -1):
        content = source_blobs.get(slot)
        digest = hashlib.sha256(content).digest() if content is not None else bytes(hash_size)
        if len(digest) != hash_size:
            raise ValueError("invalid special-slot digest length")
        cd.extend(digest)
    if len(cd) != hash_offset:
        raise ValueError("CodeDirectory header/identifier/special-slot layout mismatch")
    for start in range(0, len(cache), 4096):
        cd.extend(hashlib.sha256(cache[start:start + 4096]).digest())
    if len(cd) != cd_length:
        raise ValueError("CodeDirectory code-page hash layout mismatch")

    blobs = {slot: value for slot, value in source_blobs.items() if slot != 0}
    blobs[0] = bytes(cd)
    blobs[CSSLOT_IDENTIFICATIONSLOT] = (
        struct.pack(">II", CSMAGIC_BLOBWRAPPER, 28) + hashlib.sha1(cache).digest()
    )
    original_order = [
        struct.unpack_from(">I", template, 12 + i * 8)[0]
        for i in range(struct.unpack_from(">I", template, 8)[0])
    ]
    entries = [(slot, blobs[slot]) for slot in original_order]
    output = bytearray(12 + 8 * len(entries))
    offset = len(output)
    for index, (slot, blob) in enumerate(entries):
        struct.pack_into(">II", output, 12 + index * 8, slot, offset)
        output.extend(blob)
        offset += len(blob)
    struct.pack_into(">III", output, 0, 0xFADE0CC0, len(output), len(entries))
    return bytes(output)


def sign_detached(cache: Path, signature: Path, signature_template: Path) -> dict:
    raw = cache.read_bytes()
    identifier = "launchd-" + hashlib.sha1(raw).hexdigest()
    signature.parent.mkdir(parents=True, exist_ok=True)
    signature.write_bytes(build_detached_signature(raw, signature_template.read_bytes()))
    signature_report = inspect_detached_signature(raw, signature.read_bytes(), identifier)
    return {
        **signature_report,
        "raw_plist_sha1": hashlib.sha1(raw).hexdigest(),
        "detached_signature_sha256": sha256_file(signature),
        "detached_signature_bytes": signature.stat().st_size,
        "signer": "ad-hoc D27 CodeDirectory and raw-file identification regeneration using original detached superblob template",
        "verification": "host superblob/CodeDirectory/page/special-slot/CMS-wrapper/raw-file-identification verification: PASS; Apple SecStaticCodeCheckValidity: NOT RUN",
        "apple_codesign_secstatic_check": "NOT_RUN; UniXNU-Build /usr/bin/codesign is a no-op shim",
    }


def verify_source_pins(source_pins: Path, unixnu: Path, sheng: Path) -> dict:
    pins = json.loads(source_pins.read_text(encoding="utf-8"))
    expected = {"UniXNU": pins["UniXNU"], "sheng": pins["sheng"]}
    actual = {}
    for name, checkout in (("UniXNU", unixnu), ("sheng", sheng)):
        actual[name] = subprocess.check_output(
            ["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True
        ).strip()
        if actual[name] != expected[name]:
            raise ValueError(f"{name} checkout differs from the recorded source pin")
    return {"pins": expected, "checked_out_commits": actual}


def verify_runtime_inputs(
    *, wifi_result_path: Path, wifi_binary: Path, radio_result_path: Path, radio_root: Path,
    verifier_path: Path,
) -> dict:
    """Bind the cache receipt to the already built arm64e radio executables."""
    wifi_result = json.loads(wifi_result_path.read_text(encoding="utf-8"))
    radio_result = json.loads(radio_result_path.read_text(encoding="utf-8"))
    if wifi_result.get("passed") is not True or wifi_result.get("target") != "arm64e-apple-ios27.0":
        raise ValueError("Wi-Fi supplicant receipt is not a passing iOS 27 arm64e build")
    if radio_result.get("passed") is not True or radio_result.get("target") != "arm64e-apple-ios27.0":
        raise ValueError("Bluetooth userspace receipt is not a passing iOS 27 arm64e build")
    if radio_result.get("hardware_verified") or radio_result.get("device_operations"):
        raise ValueError("unexpected Bluetooth hardware/device status in host input receipt")
    if radio_result.get("patch", {}).get("adapter_ready") is not True:
        raise ValueError("Bluetooth native adapter input is not marked ready")

    spec = importlib.util.spec_from_file_location("platform069_codesign_verifier", verifier_path)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load project Mach-O signature verifier")
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)

    def check(path: Path, expected_sha256: str, expected_cdhash: str, name: str, expected_entitlements: str | None = None) -> dict:
        raw_hash = sha256_file(path)
        if raw_hash != expected_sha256:
            raise ValueError(f"{name} binary SHA-256 differs from its build receipt")
        signature = verifier.inspect(path)
        if signature["cdhash"] != expected_cdhash or signature["pagesize"] != 4096:
            raise ValueError(f"{name} signature differs from its build receipt")
        entitlements_hash = hashlib.sha256(signature["entitlements"]).hexdigest()
        if expected_entitlements is not None and entitlements_hash != expected_entitlements:
            raise ValueError(f"{name} entitlements digest differs from its build receipt")
        return {
            "path": str(path),
            "sha256": raw_hash,
            "cdhash": signature["cdhash"],
            "pagesize": signature["pagesize"],
            "verified_code_pages": signature["verified_code_pages"],
            "entitlements_sha256": entitlements_hash,
            "host_macho_code_directory_verification": "PASS",
        }

    wifi_signature = wifi_result["signature"]
    identities = {
        "unixnu-wpa_supplicant": check(
            wifi_binary,
            wifi_result["sha256"],
            wifi_signature["cdhash"],
            "unixnu-wpa_supplicant",
            wifi_result.get("entitlements_sha256"),
        )
    }
    radio_files = {row["path"]: row for row in radio_result.get("files", [])}
    for relative in ("bluetooth-bin/BlueTool", "bluetooth-bin/bluetoothd", "bluetooth-lib/QcaBTType0.dylib"):
        file_row = radio_files.get(relative)
        signature_row = radio_result.get("signature_checks", {}).get(relative)
        if not file_row or not signature_row:
            raise ValueError("Bluetooth build receipt lacks signed runtime input: " + relative)
        identities[relative] = check(
            radio_root / "runtime" / relative,
            file_row["sha256"],
            signature_row["cdhash"],
            relative,
            signature_row.get("entitlements_sha256"),
        )
    return {
        "wifi_build_receipt": {"path": str(wifi_result_path), "sha256": sha256_file(wifi_result_path)},
        "bluetooth_build_receipt": {"path": str(radio_result_path), "sha256": sha256_file(radio_result_path)},
        "signed_arm64e_inputs": identities,
        "built_by_main_assembler": False,
        "runtime_packaging_or_trust_mutation_performed": False,
    }


def _require_source_evidence(unixnu: Path, sheng: Path, project_root: Path) -> dict:
    serializer = unixnu / "scripts/build-boot-runtime.py"
    wifi = sheng / "scripts/build-wifi-userspace.py"
    bluetooth = sheng / "reports/ipados27-bluetooth-startup.md"
    icon_docs = unixnu / "docs/zh/guide/skip-setup.md"
    icon_runtime = project_root / "ci/platform069/crashes/runtime.py"
    inputs = {"UniXNU_serializer_signer": serializer, "sheng_wifi_job": wifi,
              "sheng_bluetooth_job_policy": bluetooth, "sheng_iconservices_policy": icon_docs,
              "port_iconservices_transform": icon_runtime}
    if any(not path.is_file() for path in inputs.values()):
        raise FileNotFoundError("a source-pinned launchd input is missing")
    source = serializer.read_text(encoding="utf-8")
    wifi_source = wifi.read_text(encoding="utf-8")
    bluetooth_source = bluetooth.read_text(encoding="utf-8")
    icon_source = icon_docs.read_text(encoding="utf-8")
    runtime_source = icon_runtime.read_text(encoding="utf-8")
    required = (
        ("plutil binary1 serializer", "run('plutil', '-convert', 'binary1'", source),
        ("detached codesign convention", "'--detached', signature", source),
        ("4096-byte SHA-256 signing", "'--pagesize', '4096'", source),
        ("source Wi-Fi job", '"/usr/libexec/unixnu-wpa_supplicant"', wifi_source),
        ("source Wi-Fi job budget", '"ThrottleInterval": 3', wifi_source),
        ("BlueTool root policy", "UserName root, ThrottleInterval 3", bluetooth_source),
        ("BlueTool transaction policy", "EnableTransactions true", bluetooth_source),
        ("official iconservices renderer policy", "FORCE_SOFTWARE_RENDERER=0", icon_source),
        ("port-selected iconservices environment", "CI_ENABLE_METAL_GPU", runtime_source),
    )
    for name, marker, content in required:
        if marker not in content:
            raise ValueError("source-pinned evidence missing: " + name)
    result = {}
    for name, path in inputs.items():
        row = {"path": str(path), "sha256": sha256_file(path)}
        checkout = unixnu if path.is_relative_to(unixnu) else sheng if path.is_relative_to(sheng) else None
        if checkout is not None:
            relative = path.relative_to(checkout).as_posix()
            pinned_bytes = subprocess.check_output(["git", "-C", str(checkout), "show", "HEAD:" + relative])
            if path.read_bytes() != pinned_bytes:
                raise ValueError("launchd source file differs from its pinned commit: " + relative)
            row["bytes_match_pinned_commit"] = True
        result[name] = row
    return result


def stage_cache(
    *, original_cache: Path, original_signature: Path, loader: Path, output: Path,
    source_pins: Path, unixnu: Path, sheng: Path, project_root: Path,
    wifi_result: Path, wifi_binary: Path, radio_result: Path, radio_root: Path,
    plutil: str = "plutil",
) -> dict:
    """Stage a new output tree; existing output is never overwritten."""
    output = output.resolve()
    if output.exists():
        raise FileExistsError(f"refusing to overwrite existing cache staging directory: {output}")
    if not original_cache.is_file() or not original_signature.is_file() or not loader.is_file():
        raise FileNotFoundError("original cache, detached signature, or loader is missing")
    source_revisions = verify_source_pins(source_pins, unixnu, sheng)
    source_evidence = _require_source_evidence(unixnu, sheng, project_root)
    runtime_inputs = verify_runtime_inputs(
        wifi_result_path=wifi_result,
        wifi_binary=wifi_binary,
        radio_result_path=radio_result,
        radio_root=radio_root,
        verifier_path=project_root / "ci/platform069/codesign.py",
    )

    original_raw = original_cache.read_bytes()
    original_signature_bytes = original_signature.read_bytes()
    original_signature_info = inspect_detached_signature(original_raw, original_signature_bytes)
    original_identity_sha1 = hashlib.sha1(original_raw).hexdigest()
    if original_signature_info["identifier"] != "launchd-" + original_identity_sha1:
        raise ValueError("original cache detached-signature identity is not launchd-SHA1(raw plist)")
    if build_detached_signature(original_raw, original_signature_bytes) != original_signature_bytes:
        raise ValueError("signer did not reproduce the original D27 detached signature byte-for-byte")

    value, transform = transform_cache_bytes(original_raw)
    stage = output / "stage/xpc"
    cache = stage / "launchd.plist"
    signature = stage / "launchd.plist.sig"
    output.mkdir(parents=True, exist_ok=False)
    try:
        serialize_binary_plist(value, cache, plutil)
        signature_report = sign_detached(cache, signature, original_signature)
        # The stage is complete only if its plist still has exactly the allowed diff.
        staged_value = plistlib.loads(cache.read_bytes())
        expected_value, _ = transform_cache_bytes(original_raw)
        if staged_value != expected_value:
            raise ValueError("serialized launchd cache differs from the validated transform")
        if cache.read_bytes() == original_raw:
            raise ValueError("launchd transform unexpectedly produced the original cache")

        receipt = {
            "schema": "unixnu.launchd-cache-stage.v1",
            "status": "HOST_FORMAT_AND_CODEDIRECTORY_HASHES_VERIFIED; AMFI_TRUST_ACCEPTANCE_PENDING_MAIN",
            "target": "Xperia PDX234 / iPadOS 27 build 24A446 / D27",
            "implementation": {
                "module_path": str(Path(__file__).resolve()),
                "module_sha256": sha256_file(Path(__file__)),
                "host_tests_path": str(project_root / "tests/test_launchd_cache069.py"),
                "host_tests_sha256": sha256_file(project_root / "tests/test_launchd_cache069.py"),
            },
            "source_revisions": source_revisions,
            "source_evidence": source_evidence,
            "canonical_signing_source": {
                "repository": "https://github.com/apple-oss-distributions/Security",
                "revision": APPLE_SECURITY_REVISION,
                "evidence_type": "reviewed canonical source; not a D27 Security.framework execution",
                "sources": {name: {"url": APPLE_SECURITY_SOURCE_BASE + name, **row}
                            for name, row in APPLE_SECURITY_SOURCES.items()},
            },
            "runtime_inputs": runtime_inputs,
            "original": {
                "cache_path": str(original_cache),
                "cache_sha256": hashlib.sha256(original_raw).hexdigest(),
                "cache_bytes": len(original_raw),
                "raw_plist_sha1": original_identity_sha1,
                "signature_path": str(original_signature),
                "signature_sha256": sha256_file(original_signature),
                "signature_identity": original_signature_info["identifier"],
                "signature_cdhash": original_signature_info["cdhash"],
                "signature_verification": "host superblob/CodeDirectory/page/special-slot/CMS-wrapper/raw-file-identification verification: PASS; Apple SecStaticCodeCheckValidity: NOT RUN",
                "signature_regeneration_byte_identical": True,
                "signature_wrapper": original_signature_info["signature_wrapper"],
                "identification_wrapper": original_signature_info["identification_wrapper"],
            },
            "loader": {
                "original_path": str(loader),
                "sha256": sha256_file(loader),
                "staged_or_modified": False,
                "runtime_acceptance_proven": False,
            },
            "transform": transform,
            "binary_plist_semantic_roundtrip_verified": True,
            "serializer": serializer_receipt(plutil),
            "staged": {
                "cache_path": str(cache),
                "cache_sha256": sha256_file(cache),
                "cache_bytes": cache.stat().st_size,
                "signature_path": str(signature),
                "signature": signature_report,
                "staging_root": str(output),
                "addon_relative_paths": ["xpc/launchd.plist", "xpc/launchd.plist.sig"],
            },
            "trust": {
                "original_trust_cache_modified": False,
                "required_cdhash_for_main_trust_assembly": signature_report["cdhash"],
                "trust_assembly_owner": "main",
                "amfi_trust_acceptance": "NOT_PROVEN; pending main trust-cache assembly and loader/runtime validation",
            },
            "security_invariants": {
                "detached_signature_required": True,
                "host_signature_format_and_hashes_verified": True,
                "apple_secstatic_code_check_run": False,
                "signature_verification_weakened": False,
                "amfi_bypassed": False,
                "pac_changed": False,
                "original_trust_cache_changed": False,
                "jobs_removed_or_disabled": False,
                "non_target_job_budget_or_identity_changed": False,
                "device_operations": False,
                "qemu_or_guest_runtime_test": False,
            },
        }
        receipt_path = output / "staging-receipt.json"
        receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return receipt
    except BaseException:
        # Only this newly-created, isolated output tree is removed on local failure.
        shutil.rmtree(output)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original-cache", type=Path, required=True)
    parser.add_argument("--original-signature", type=Path, required=True)
    parser.add_argument("--loader", type=Path, required=True)
    parser.add_argument("--source-pins", type=Path, required=True)
    parser.add_argument("--unixnu", type=Path, required=True)
    parser.add_argument("--sheng", type=Path, required=True)
    parser.add_argument("--wifi-result", type=Path, required=True)
    parser.add_argument("--wifi-binary", type=Path, required=True)
    parser.add_argument("--radio-result", type=Path, required=True)
    parser.add_argument("--radio-root", type=Path, required=True)
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    receipt = stage_cache(
        original_cache=args.original_cache,
        original_signature=args.original_signature,
        loader=args.loader,
        output=args.output,
        source_pins=args.source_pins,
        unixnu=args.unixnu,
        sheng=args.sheng,
        project_root=args.project_root,
        wifi_result=args.wifi_result,
        wifi_binary=args.wifi_binary,
        radio_result=args.radio_result,
        radio_root=args.radio_root,
    )
    print(json.dumps({
        "status": receipt["status"],
        "cache": receipt["staged"]["cache_path"],
        "signature": receipt["staged"]["signature_path"],
        "cdhash": receipt["staged"]["signature"]["cdhash"],
        "receipt": str(args.output / "staging-receipt.json"),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
