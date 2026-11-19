#!/usr/bin/env python3
"""Compile the existing SM8550 transport for D27 with Sony-only root selection.

This builds a deferred adapter archive, not a kernel or bootable image. The BSD
caller, policy loader and hardware takeover still require separate integration.
"""
import argparse
import difflib
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

DEVICE = Path(__file__).resolve().parents[2]
REVISION = 'fd420df000f43213d9cd019725abff0849c98c72'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tree', type=Path, required=True)
    parser.add_argument('--mainline', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--interface-audit', type=Path, required=True)
    parser.add_argument('--survey', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve()
    if (subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip() != REVISION or
            subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain'], text=True).strip()):
        parser.error('Require the clean documentation-pinned ShengUfs revision')
    survey = json.loads(args.survey.read_text())
    host = next(n for n in survey['hardware'] if n['path'] == '/soc/ufshc@1d84000')
    if (host['registers'][0] != dict(physical='0x1d84000', bytes=0x3000) or
            host['interrupts'] != [0, 265, 4] or
            host['iommus'] != [dict(provider='/soc/apps-smmu@15000000', arguments=[0x60, 0])] or
            not host['dma-coherent']):
        parser.error('Actual Sony hardware differs from the selected transport')
    interface = json.loads(args.interface_audit.read_text())
    if (interface['kernelcache_sha256'] != 'c28f4fc9b83cde00087e81f890c82d566b9e98b5ac228dfecd83afdf34070445' or
            interface['method_slots'] != 190 or not interface['pac_layout_matches']):
        parser.error('Require the exact D27 block dispatch audit')
    args.output.mkdir(parents=True, exist_ok=False)
    out = args.output.resolve()
    staged = out / 'source'
    staged.mkdir()
    sources = {}
    for name in ('NativeUfs.cpp', *sorted(p.name for p in source.glob('*.h'))):
        shutil.copyfile(source / name, staged / name)
        sources[name] = sha(source / name)
    shutil.copyfile(DEVICE / 'ci/ufs/SonySmmuTakeover.h', staged / 'SonySmmuTakeover.h')
    layout = staged / 'RootLayout.h'
    text = layout.read_text()
    marker = 'static const char wanted[] = "userdata";'
    if text.count(marker) != 1:
        raise ValueError('Original root partition selector changed')
    scratch = 'static uint8_t gScratch[kDataMax];'
    if text.count(scratch) != 1:
        raise ValueError('Original UFS scratch allocation changed')
    text = text.replace(scratch, '''#if defined(SONY_UFS_HEAP_SCRATCH) && SONY_UFS_HEAP_SCRATCH
static uint8_t *gScratch;
#else
static uint8_t gScratch[kDataMax];
#endif''')
    layout.write_text(text.replace(marker, 'static const char wanted[] = "unixnu";'))
    transport = staged / 'NativeUfs.cpp'
    text = transport.read_text()
    text = text.replace('#include "SmmuTakeover.h"',
                        '#include "SmmuTakeover.h"\n#include "SonySmmuTakeover.h"')
    original_plan = 'UfsSmmuPlan plan = planUfsSmmu (stream, dma, bytes, [smmu](unsigned offset) { return read32 (smmu, offset); });'
    if text.count(original_plan) != 1:
        raise ValueError('Original SMMU planning call changed')
    text = text.replace(original_plan, '''SonyUfsSmmuPlan sonyPlan = planSonyUfsSmmu (stream, dma, bytes,
    [smmu](unsigned offset) { return read32 (smmu, offset); });
  UfsSmmuPlan plan = sonyPlan.mapping;''')
    text = text.replace('configureUfsSmmu (plan, stream,', 'configureSonyUfsSmmu (sonyPlan, stream,')
    # Preserve readable details even if a downstream formatter refuses heap strings.
    fail = '    rootDiagnosticFailure (plan.error);'
    if text.count(fail) != 1:
        raise ValueError('Original SMMU planning failure changed')
    text = text.replace(fail, '''    panic ("SONY UFS SMMU PLAN FAILED\\n%s\\n"
      "ID0=%08x ID1=%08x ID2=%08x\\nDMA=%llx bytes=%llx\\n"
      "slot=%u bank=%u SMR=%08x S2CR=%08x",
      plan.error, read32 (smmu, 0x20), read32 (smmu, 0x24), read32 (smmu, 0x28),
      dma, bytes, plan.slot, plan.bank, plan.smr, plan.s2cr);''')
    fail = '    rootDiagnosticFailure (failure);'
    if text.count(fail) != 1:
        raise ValueError('Original SMMU configure failure changed')
    text = text.replace(fail, '''    panic ("SONY UFS SMMU CONFIG FAILED\\n%s\\n"
      "slot=%u bank=%u reroute=%u\\nSMR=%08x S2CR=%08x\\nCBAR=%08x SCTLR=%08x CBA2R=%08x",
      failure, index, bank, sonyPlan.reroute, smr, s2cr, cbar, sctlr, gRootDiagnostic.cba2r);''')
    marker = 'bool NativeUfs::start (IOService *provider)\n{\n'
    if text.count(marker) != 1:
        raise ValueError('Original UFS start signature changed')
    guard = '''  // Sony-owned platform selection before any transport/MMIO operation.
  IORegistryEntry *root = IORegistryEntry::fromPath ("/", gIODTPlane);
  OSData *compatible = root ? OSDynamicCast (OSData, root->getProperty ("compatible")) : nullptr;
  const char *identity = compatible ? static_cast<const char *> (compatible->getBytesNoCopy ()) : nullptr;
  static const char sony[] = "somc,pdx234-generic";
  const bool sonyPlatform = identity && compatible->getLength () >= sizeof (sony) &&
    !memcmp (identity, sony, sizeof (sony));
  OSSafeReleaseNULL (root);
  if (!sonyPlatform) return false;
#if defined(SONY_UFS_HEAP_SCRATCH) && SONY_UFS_HEAP_SCRATCH
  // Lifetime scratch belongs to this single host, allocated before any I/O.
  if (!gScratch) gScratch = static_cast<uint8_t *>(IOMallocData (kDataMax));
  if (!gScratch) return false;
#endif
'''
    text = text.replace('#include <IOKit/IOService.h>',
                        '#include <IOKit/IOService.h>\n#include <IOKit/IODeviceTreeSupport.h>')
    text = text.replace(marker, marker + guard)
    check_marker = '''    RootLayout *layout = static_cast<RootLayout *> (IOMalloc (sizeof (RootLayout)));
    if (!layout || !findRootLayout (layout, &why)) {'''
    probe_start = text.index('  if (probe == 10) {')
    probe_end = text.index('  if (probe == 11) {', probe_start)
    old_probe = text[probe_start:probe_end]
    if old_probe.count(check_marker) != 1:
        raise ValueError('Original read-only UFS diagnostic changed')
    # Exact captured geometry/identity remains pinned. Only boot_a/boot_b's
    # retry-count and successful-boot bits vary across normal Android boots.
    new_probe = '''  if (probe == 10) {
    const char *why = "";
    if (!hostBringUp (&why)) {
      rootDiagnosticFailure (why);
      panic ("SONY_UFS GPT: bring-up failed: %s", why);
    }
    uint8_t capacityCdb[10] = {0x25};
    uint32_t scsi = 0;
    if (hostScsi (0, capacityCdb, 10, true, 8, 1000000, &scsi) != kIOReturnSuccess) {
      rootDiagnosticFailure ("LUN0 READ CAPACITY failed");
      panic ("SONY_UFS GPT: capacity command failed scsi=%x", scsi);
    }
    const uint8_t *capacityData = ufsSlot (0).data;
    const uint64_t lunBlocks = uint64_t (getBe32 (capacityData)) + 1;
    const uint32_t blockBytes = getBe32 (capacityData + 4);
    if (lunBlocks != 62461952ULL || blockBytes != 4096)
      panic ("SONY_UFS GPT: LUN0 capacity differs blocks=%llu block=%u", lunBlocks, blockBytes);
    if (hostRead4k (0, 1, 1, gScratch) != kIOReturnSuccess)
      panic ("SONY_UFS GPT: LUN0 header read failed");
    uint8_t digest[32]; SHA256_CTX context;
    SHA256_Init (&context); SHA256_Update (&context, gScratch, 4096); SHA256_Final (digest, &context);
    static const char digits[] = "0123456789abcdef";
    char encoded[65];
    for (unsigned i = 0; i < 32; ++i) {
      encoded[i * 2] = digits[digest[i] >> 4]; encoded[i * 2 + 1] = digits[digest[i] & 15];
    }
    encoded[64] = 0;
    const uint32_t count = le32 (gScratch + 80), expectedCrc = le32 (gScratch + 88);
    const uint64_t entries = le64 (gScratch + 72);
    const bool header = !memcmp (gScratch, "EFI PART", 8) && le32 (gScratch + 12) == 92 &&
      rootCrc32 (gScratch, 92, true) == le32 (gScratch + 16) && le64 (gScratch + 24) == 1 &&
      entries == 2 && count && count <= 128 && le32 (gScratch + 84) == 128;
    if (!header) panic ("SONY_UFS GPT: header rejected SHA256 %s", encoded);
    uint8_t stableHeader[32];
    const uint32_t zero = 0;
    SHA256_Init (&context);
    SHA256_Update (&context, gScratch, 16); SHA256_Update (&context, &zero, 4);
    SHA256_Update (&context, gScratch + 20, 68); SHA256_Update (&context, &zero, 4);
    SHA256_Update (&context, gScratch + 92, 4096 - 92); SHA256_Final (stableHeader, &context);
    if (hostRead4k (0, entries, (count * 128 + 4095) / 4096, gScratch) != kIOReturnSuccess)
      panic ("SONY_UFS GPT: table read failed SHA256 %s", encoded);
    if (rootCrc32 (gScratch, count * 128) != expectedCrc)
      panic ("SONY_UFS GPT: table CRC rejected SHA256 %s", encoded);
    // Keep both on-media CRC checks above. Normalize only their derived header
    // fields and retry/success bits at the two captured boot partition slots.
    const uint8_t expectedHeader[32] = {0x87,0x6d,0x85,0x9c,0xad,0x4c,0x65,0x46,
      0x97,0xa7,0xa1,0x51,0x25,0xe9,0x8b,0x79,0x9b,0xaf,0xc1,0x06,0x98,0x30,0x0e,0xea,
      0x78,0x04,0x33,0xc2,0x68,0xd7,0x1c,0x9f};
    const uint8_t expectedTable[32] = {0x22,0x95,0xf9,0xc7,0xfd,0xb7,0x1c,0xcb,
      0x8d,0x18,0x82,0xc4,0x72,0x82,0x50,0xce,0xe5,0x67,0x89,0x8f,0x0c,0x14,0x9c,0xd2,
      0x95,0x13,0xa2,0xf2,0xd7,0x8b,0xa4,0xae};
    uint8_t stableTable[32];
    SHA256_Init (&context);
    for (uint32_t index = 0; index < count; ++index) {
      const uint8_t *entry = gScratch + index * 128;
      SHA256_Update (&context, entry, 48);
      uint64_t attributes = le64 (entry + 48);
      if (index == 67 || index == 82) attributes &= ~(0x78ULL << 48);
      uint8_t encodedAttributes[8];
      for (unsigned byte = 0; byte < 8; ++byte) encodedAttributes[byte] = uint8_t (attributes >> (byte * 8));
      SHA256_Update (&context, encodedAttributes, 8);
      SHA256_Update (&context, entry + 56, 72);
    }
    SHA256_Final (stableTable, &context);
    if (count != 97 || memcmp (stableHeader, expectedHeader, 32) || memcmp (stableTable, expectedTable, 32))
      panic ("SONY_UFS GPT: valid GPT differs from captured Sony disk\\nSHA256 %s", encoded);
    if (hostRead4k (0, 1, 1, gScratch) != kIOReturnSuccess)
      panic ("SONY_UFS GPT: repeated header read failed");
    uint8_t repeatedDigest[32];
    SHA256_Init (&context); SHA256_Update (&context, gScratch, 4096); SHA256_Final (repeatedDigest, &context);
    if (memcmp (digest, repeatedDigest, 32)) panic ("SONY_UFS GPT: repeated header differs");
    panic ("SONY_UFS GPT READ PASS\\nLUN0 blocks=%llu block=%u entries=%u\\nheader SHA256\\n%s\\n"
           "table CRC=%08x verified\\nRepeated header matches.\\nNo disk writes. No root mount.",
           lunBlocks, blockBytes, count, encoded, expectedCrc);
  }
'''
    text = text[:probe_start] + new_probe + text[probe_end:]
    asm = load('sony_ufs_macho_asm', DEVICE / 'scripts/ci/macho-inline-asm.py')
    text, asm_count = asm.normalize(text)
    transport.write_text(text)
    patch = ''.join(''.join(difflib.unified_diff(
        (source / name).read_text().splitlines(keepends=True),
        (staged / name).read_text().splitlines(keepends=True),
        fromfile='a/' + name, tofile='b/' + name)) for name in ('NativeUfs.cpp', 'RootLayout.h'))
    (out / 'sony-board-adaptation.patch').write_text(patch)
    compiler = load('sony_ufs_compile', args.mainline / 'scripts/build-sheng-source-drivers.py')
    block = load('sony_ufs_block_audit', DEVICE / 'scripts/ci/audit-d27-block-interface.py')
    builder = load('sony_ufs_late', DEVICE / 'scripts/ci/build-qemu-source-block.py')
    recipe = args.tree / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json'
    record = json.JSONDecoder().raw_decode(recipe.read_text())[0]
    if not any('arm64e-apple-ios27.' in a for a in record['arguments']):
        raise ValueError('Compilation recipe is not the D27 target')
    base = staged / 'IOBlockStorageDevice.cpp'
    base.write_text(builder.late_source((args.tree / 'refer/IOStorageFamily/IOBlockStorageDevice.cpp').read_text()))
    includes = ['-I', str(args.tree / 'build/storage-abi/include'),
                '-I', str(args.tree / '.cache/xnu-work/osfmk'),
                '-I', str(args.mainline / 'kits/VerifiedRoot/include'),
                '-I', str(args.mainline / 'drivers/VirtioMmioBlock')]
    objects = []
    for item in (base, transport):
        output = out / (item.stem + '.o')
        flags = ['-DSONY_UFS_HEAP_SCRATCH=1', '-DNATIVE_UFS_SOURCE_API=1', '-DNATIVE_VERIFIED_BLOCK=1',
                 '-DNATIVE_VERIFIED_BLOCK_MULTI_POLICY=1', '-DNATIVE_VERIFIED_POLICY_HANDOFF=1',
                 '-Wno-missing-designated-field-initializers']
        if item == base:
            flags.append('-Wno-error')
        command = compiler.compile_command(record, item, output, includes, flags)
        (out / (item.stem + '.command.json')).write_text(json.dumps(command, indent=2) + '\n')
        r = subprocess.run(command, cwd=record['directory'], capture_output=True, text=True, timeout=180)
        (out / (item.stem + '.log')).write_text(r.stdout + r.stderr)
        if r.returncode:
            raise RuntimeError((r.stdout + r.stderr)[-7000:])
        if not builder.has_module_initializers(output.read_bytes()):
            raise ValueError('Missing source class initializers')
        late = output.with_suffix('.late.o')
        subprocess.run(['/root/unixnu-build/pdx234-pac-clang-build/bin/llvm-objcopy',
                        '--remove-section=__DATA,__mod_init_func',
                        '--globalize-symbol=__GLOBAL__sub_I_' + item.name, str(output), str(late)], check=True)
        if builder.has_module_initializers(late.read_bytes()):
            raise ValueError('Source classes would register before the original storage family')
        objects.append(late)
    base_table = block.object_vtable(objects[0].read_bytes(), '__ZTV20IOBlockStorageDevice')
    concrete = block.object_vtable(objects[1].read_bytes(), '__ZTV14NativeUfsBlock')
    builder.validate_tables(interface['methods'], base_table, concrete)
    archive = out / 'libSonyUfsAdapter.a'
    subprocess.run(['/usr/lib/llvm-18/bin/llvm-ar', 'rcs', str(archive), *map(str, objects)], check=True)
    undefined = subprocess.check_output(['/usr/lib/llvm-18/bin/llvm-nm', '-u', str(archive)], text=True)
    (out / 'undefined-symbols.txt').write_text(undefined)
    report = dict(archive=str(archive), archive_sha256=sha(archive), upstream_revision=REVISION,
                  upstream_sources_sha256=sources,
                  staged_sources_sha256={p.name: sha(p) for p in staged.iterdir()},
                  hardware_survey_sha256=sha(args.survey), block_pac_slots_checked=190,
                  automatic_class_initializers_removed=True, sony_platform_guard=True,
                  root_partition_name='unixnu', fallback_to_android_userdata=False,
                  verified_root_enabled=True, source_api_enabled=True,
                  scratch_bytes=131072, scratch_allocation='IOMallocData before transport start',
                  macho_asm_separators_fixed=asm_count,
                  policy_runtime_linked=False, bsd_caller_integrated=False, kernel_linked=False,
                  xnu_ufs_reads_verified=False, device_operations=False)
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
