"""Host tests for the isolated D27 launchd-cache transform and signing stage."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import shutil
import struct
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "launchd_cache069", ROOT / "ci/platform069/launchd_cache.py"
)
cache = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cache)

ARTIFACTS = Path("/mnt/f/UniXNU-Port-artifacts/platform069-20261118")
ORIGINAL = ARTIFACTS / "d27-display-runtime-original-001/files/os"
UNIXNU = ARTIFACTS / "UniXNU"
SHENG = ARTIFACTS / "sheng"
WIFI = ARTIFACTS / "wifi-supplicant069-001"
RADIO = ARTIFACTS / "radio-userland069-002"
PREVIOUS = ARTIFACTS / "launchd-cache069-003"


class LaunchdCacheTransformTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (ORIGINAL / "System/Library/xpc/launchd.plist").read_bytes()
        cls.original = plistlib.loads(cls.raw)

    def test_binary_cache_changes_only_three_source_qualified_job_values(self):
        transformed, report = cache.transform_cache_bytes(self.raw)
        expected = copy.deepcopy(self.original)
        icon_key, icon = cache._find_job(expected["LaunchDaemons"], cache.ICON_LABEL)
        icon.setdefault("EnvironmentVariables", {}).update(cache.ICON_ENVIRONMENT)
        blue_key, blue = cache._find_job(expected["LaunchDaemons"], cache.BLUETOOL_LABEL)
        blue.update(cache.BLUETOOL_OVERRIDES)
        expected["LaunchDaemons"][cache.WIFI_CACHE_KEY] = copy.deepcopy(cache.WIFI_JOB)
        self.assertEqual(transformed, expected)
        self.assertEqual(report["source_jobs"], 729)
        self.assertEqual(report["staged_jobs"], 730)
        self.assertEqual(report["changed_original_jobs"], [icon_key, blue_key])
        for key, job in self.original["LaunchDaemons"].items():
            if key not in (icon_key, blue_key):
                self.assertEqual(transformed["LaunchDaemons"][key], job)

    def test_only_binary_plist_source_is_accepted(self):
        with self.assertRaisesRegex(ValueError, "binary plist"):
            cache.transform_cache_bytes(plistlib.dumps(self.original, fmt=plistlib.FMT_XML))

    def test_wifi_collision_is_rejected(self):
        changed = copy.deepcopy(self.original)
        changed["LaunchDaemons"][cache.WIFI_CACHE_KEY] = copy.deepcopy(cache.WIFI_JOB)
        with self.assertRaisesRegex(ValueError, "already exists"):
            cache.transform_cache_bytes(plistlib.dumps(changed, fmt=plistlib.FMT_BINARY))

    def test_conflicting_icon_renderer_setting_is_rejected(self):
        changed = copy.deepcopy(self.original)
        _, icon = cache._find_job(changed["LaunchDaemons"], cache.ICON_LABEL)
        icon["EnvironmentVariables"] = {"CI_ENABLE_METAL_GPU": "1"}
        with self.assertRaisesRegex(ValueError, "conflicting iconservices"):
            cache.transform_cache_bytes(plistlib.dumps(changed, fmt=plistlib.FMT_BINARY))

    def test_sha1_identity_and_original_signature_structure(self):
        raw_sig = (ORIGINAL / "System/Library/xpc/launchd.plist.sig").read_bytes()
        report = cache.inspect_detached_signature(
            self.raw,
            raw_sig,
            "launchd-" + hashlib.sha1(self.raw).hexdigest(),
        )
        self.assertEqual(report["codedirectory_version"], "0x20500")
        self.assertEqual(report["page_size"], 4096)
        self.assertEqual(report["hash_algorithm"], "sha256")
        self.assertEqual(report["special_slots_verified"], 2)
        self.assertEqual(report["identification_wrapper"]["payload_sha1"], hashlib.sha1(self.raw).hexdigest())
        self.assertEqual(report["signature_wrapper"]["slot"], "0x10000")
        self.assertEqual(report["signature_wrapper"]["payload_bytes"], 0)
        self.assertEqual(cache.build_detached_signature(self.raw, raw_sig), raw_sig)

    def test_003_stale_identification_is_refused_despite_unchanged_good_codedirectory(self):
        raw = (PREVIOUS / "stage/xpc/launchd.plist").read_bytes()
        stale_signature = (PREVIOUS / "stage/xpc/launchd.plist.sig").read_bytes()
        # 003 has good code-page hashes and the right CodeDirectory identifier,
        # but its separate identification wrapper is still bound to the original.
        with self.assertRaisesRegex(ValueError, "stale 0x10001 identification"):
            cache.inspect_detached_signature(raw, stale_signature, "launchd-" + hashlib.sha1(raw).hexdigest())
        with self.assertRaisesRegex(ValueError, "stale 0x10001 identification"):
            cache.build_detached_signature(raw, stale_signature)

    def test_updated_identification_leaves_codedirectory_cms_and_cache_unchanged(self):
        raw = (PREVIOUS / "stage/xpc/launchd.plist").read_bytes()
        previous = (PREVIOUS / "stage/xpc/launchd.plist.sig").read_bytes()
        source = (ORIGINAL / "System/Library/xpc/launchd.plist.sig").read_bytes()
        corrected = cache.build_detached_signature(raw, source)
        before = cache._parse_superblob(previous)
        after = cache._parse_superblob(corrected)
        self.assertEqual(after[0], before[0])
        self.assertEqual(after[2], before[2])
        self.assertEqual(after[0x10000], bytes.fromhex("fade0b0100000008"))
        self.assertEqual(after[0x10000], before[0x10000])
        self.assertEqual(after[0x10001], struct.pack(">II", 0xFADE0B01, 28) + hashlib.sha1(raw).digest())
        self.assertNotEqual(after[0x10001], before[0x10001])
        report = cache.inspect_detached_signature(raw, corrected)
        self.assertEqual(report["cdhash"], "bb8d7676c2e58a43f01dbf8b2be7cce5afcf62ff")
        self.assertEqual(corrected, cache.build_detached_signature(raw, source))

    def test_missing_malformed_stale_and_swapped_identification_slots_are_refused(self):
        signature = (ORIGINAL / "System/Library/xpc/launchd.plist.sig").read_bytes()
        entries = [struct.unpack_from(">II", signature, 12 + index * 8)
                   for index in range(struct.unpack_from(">I", signature, 8)[0])]
        index, offset = next((index, offset) for index, (slot, offset) in enumerate(entries) if slot == 0x10001)
        cms_index, cms_offset = next((index, offset) for index, (slot, offset) in enumerate(entries) if slot == 0x10000)
        bad_signatures = []
        missing = bytearray(signature)
        struct.pack_into(">I", missing, 12 + index * 8, 0x10002)
        bad_signatures.append(missing)
        wrong_wrapper_magic = bytearray(signature)
        struct.pack_into(">I", wrong_wrapper_magic, offset, 0xFADE0C01)
        bad_signatures.append(wrong_wrapper_magic)
        truncated_payload = bytearray(signature)
        struct.pack_into(">I", truncated_payload, offset + 4, 27)
        bad_signatures.append(truncated_payload)
        stale_payload = bytearray(signature)
        stale_payload[offset + 8] ^= 1
        bad_signatures.append(stale_payload)
        swapped = bytearray(signature)
        struct.pack_into(">I", swapped, 12 + index * 8, 0x10000)
        struct.pack_into(">I", swapped, 12 + cms_index * 8, 0x10001)
        bad_signatures.append(swapped)
        invalid_cms_magic = bytearray(signature)
        struct.pack_into(">I", invalid_cms_magic, cms_offset, 0xFADE0C01)
        bad_signatures.append(invalid_cms_magic)
        for corrupted in bad_signatures:
            with self.subTest(corruption=bad_signatures.index(corrupted)):
                with self.assertRaises(ValueError):
                    cache.inspect_detached_signature(self.raw, bytes(corrupted))

    def test_staged_signature_hashes_every_page_and_rejects_tamper(self):
        if shutil.which("plutil") is None:
            self.skipTest("UniXNU-Build plutil tool unavailable")
        with tempfile.TemporaryDirectory(prefix="launchd-cache069-test-", dir=ARTIFACTS) as temporary:
            work = Path(temporary)
            original = work / "launchd.plist"
            original.write_bytes(self.raw)
            # Sign a local copy with the same source code-signing convention.
            original_signature = original.with_suffix(".plist.sig")
            original_signature.write_bytes((ORIGINAL / "System/Library/xpc/launchd.plist.sig").read_bytes())
            loader = ORIGINAL / "usr/libexec/launchd_cache_loader"
            output = work / "stage-result"
            receipt = cache.stage_cache(
                original_cache=original,
                original_signature=original_signature,
                loader=loader,
                output=output,
                source_pins=ARTIFACTS / "source-pins.json",
                unixnu=UNIXNU,
                sheng=SHENG,
                project_root=ROOT,
                wifi_result=WIFI / "result.json",
                wifi_binary=WIFI / "unixnu-wpa_supplicant",
                radio_result=RADIO / "result.json",
                radio_root=RADIO,
            )
            staged = Path(receipt["staged"]["cache_path"])
            signature = Path(receipt["staged"]["signature_path"])
            self.assertEqual(receipt["status"], "HOST_FORMAT_AND_CODEDIRECTORY_HASHES_VERIFIED; AMFI_TRUST_ACCEPTANCE_PENDING_MAIN")
            self.assertEqual(receipt["staged"]["signature"]["identifier"],
                             "launchd-" + hashlib.sha1(staged.read_bytes()).hexdigest())
            self.assertTrue(receipt["security_invariants"]["signature_verification_weakened"] is False)
            self.assertEqual(len(receipt["runtime_inputs"]["signed_arm64e_inputs"]), 4)
            self.assertTrue(receipt["original"]["signature_regeneration_byte_identical"])
            self.assertTrue(receipt["binary_plist_semantic_roundtrip_verified"])
            self.assertEqual(receipt["canonical_signing_source"]["revision"], cache.APPLE_SECURITY_REVISION)
            self.assertTrue(receipt["staged"]["signature"]["identification_wrapper"]["matches_raw_plist_sha1"])
            valid = cache.inspect_detached_signature(staged.read_bytes(), signature.read_bytes())
            self.assertEqual(valid["page_size"], 4096)
            tampered_signature = bytearray(signature.read_bytes())
            blobs = cache._parse_superblob(bytes(tampered_signature))
            cd = blobs[0]
            hash_offset = int.from_bytes(cd[16:20], "big")
            tampered_signature[44 + hash_offset] ^= 1
            with self.assertRaisesRegex(ValueError, "page hash mismatch"):
                cache.inspect_detached_signature(staged.read_bytes(), bytes(tampered_signature))
            untouched = staged.read_bytes()
            tampered = bytearray(untouched)
            tampered[128] ^= 1
            staged.write_bytes(tampered)
            with self.assertRaisesRegex(ValueError, "page hash mismatch"):
                cache.inspect_detached_signature(bytes(tampered), signature.read_bytes())
            staged.write_bytes(untouched)
            self.assertEqual(staged.read_bytes(), untouched)
            self.assertEqual(json.loads((output / "staging-receipt.json").read_text()), receipt)


if __name__ == "__main__":
    unittest.main()
