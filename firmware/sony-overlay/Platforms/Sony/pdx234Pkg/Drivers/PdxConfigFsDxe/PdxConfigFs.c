// SPDX-License-Identifier: BSD-2-Clause-Patent
// Sony BootShim transport adapter. The shared RAM-disk/FAT drivers read the payload.
#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/FdtLib.h>
#include <Library/HobLib.h>
#include "../../Include/PdxBootSource.h"

// Interfaces of the selected Mu_Basecore LzmaCustomDecompressLib (not an XZ decoder).
RETURN_STATUS EFIAPI LzmaUefiDecompressGetInfo(CONST VOID *, UINT32, UINT32 *, UINT32 *);
RETURN_STATUS EFIAPI LzmaUefiDecompress(CONST VOID *, UINTN, VOID *, VOID *);

STATIC EFI_GUID mEntryGuid = {0xDAEE82E6,0x8090,0x4E72,{0xBF,0xB9,0x78,0xC1,0x3C,0xD4,0xE3,0x59}};

EFI_STATUS EFIAPI PdxConfigFsEntry(EFI_HANDLE Image, EFI_SYSTEM_TABLE *Table) {
  PDX_BOOT_SOURCE Source;
  EFI_HOB_GUID_TYPE *Hob;
  EFI_STATUS Status;
  RETURN_STATUS Result;
  CONST UINT8 *Bundle;
  VOID *Payload = NULL, *Scratch = NULL, *Tree = NULL;
  CONST VOID *OriginalTree;
  UINT32 DecodedBytes, ScratchBytes, CompressedBytes, ExpectedCrc, ActualCrc;
  UINT64 Start, End, TreeAddress;
  UINT32 TreeBytes;
  INT32 Chosen;
  (VOID)Image; (VOID)Table;

  Status = PdxGetBootSource(&Source);
  if (EFI_ERROR(Status)) return Status;
  if (Source.Version != 2 || Source.BundleBytes < 32 + 13 || Source.BundleBytes > MAX_UINT32 ||
      Source.BundleOffset < 0x200000 + Source.AndroidBytes ||
      Source.BundleOffset > Source.ImageBytes - sizeof(Source) ||
      Source.BundleBytes > Source.ImageBytes - sizeof(Source) - Source.BundleOffset ||
      !PdxReadable(Source.Image + Source.BundleOffset, Source.BundleBytes)) return EFI_COMPROMISED_DATA;
  Bundle = (CONST UINT8 *)(UINTN)(Source.Image + Source.BundleOffset);
  // PDXFAT02, header size 32, compressed bytes, FAT bytes, CRC32(FAT).
  if (CompareMem(Bundle, "PDXFAT02", 8) || ReadUnaligned32((CONST UINT32 *)(Bundle + 8)) != 32)
    return EFI_COMPROMISED_DATA;
  CompressedBytes = ReadUnaligned32((CONST UINT32 *)(Bundle + 12));
  DecodedBytes = ReadUnaligned32((CONST UINT32 *)(Bundle + 16));
  ExpectedCrc = ReadUnaligned32((CONST UINT32 *)(Bundle + 20));
  if (CompressedBytes != Source.BundleBytes - 32 || DecodedBytes < SIZE_1MB ||
      DecodedBytes > 128 * SIZE_1MB || (DecodedBytes % 512) ||
      ReadUnaligned64((CONST UINT64 *)(Bundle + 24)) != 0) return EFI_COMPROMISED_DATA;
  {
    UINT32 LibraryBytes;
    Result = LzmaUefiDecompressGetInfo(Bundle + 32, CompressedBytes, &LibraryBytes, &ScratchBytes);
    if (RETURN_ERROR(Result) || LibraryBytes != DecodedBytes || ScratchBytes > 16 * SIZE_1MB)
      return EFI_COMPROMISED_DATA;
  }
  Payload = AllocatePages(EFI_SIZE_TO_PAGES(DecodedBytes));
  Scratch = AllocatePool(ScratchBytes ? ScratchBytes : 1);
  if (!Payload || !Scratch) { Status = EFI_OUT_OF_RESOURCES; goto Fail; }
  Result = LzmaUefiDecompress(Bundle + 32, CompressedBytes, Payload, Scratch);
  FreePool(Scratch); Scratch = NULL;
  if (RETURN_ERROR(Result)) { Status = EFI_COMPROMISED_DATA; goto Fail; }
  Status = gBS->CalculateCrc32(Payload, DecodedBytes, &ActualCrc);
  if (EFI_ERROR(Status) || ActualCrc != ExpectedCrc ||
      ((CONST UINT8 *)Payload)[510] != 0x55 || ((CONST UINT8 *)Payload)[511] != 0xAA) {
    Status = EFI_COMPROMISED_DATA; goto Fail;
  }
  Hob = GetFirstGuidHob(&mEntryGuid);
  if (!Hob || GET_GUID_HOB_DATA_SIZE(Hob) != sizeof(UINT64)) { Status = EFI_NOT_FOUND; goto Fail; }
  OriginalTree = (CONST VOID *)(UINTN)Source.Fdt;
  if (FdtCheckHeader(OriginalTree) || FdtTotalSize(OriginalTree) > SIZE_2MB) {
    Status = EFI_COMPROMISED_DATA; goto Fail;
  }
  TreeBytes = FdtTotalSize(OriginalTree) + 4096;
  Tree = AllocatePages(EFI_SIZE_TO_PAGES(TreeBytes));
  if (!Tree) { Status = EFI_OUT_OF_RESOURCES; goto Fail; }
  if (FdtOpenInto(OriginalTree, Tree, TreeBytes)) { Status = EFI_COMPROMISED_DATA; goto Fail; }
  Chosen = FdtPathOffset(Tree, "/chosen");
  Start = CpuToFdt64((UINT64)(UINTN)Payload);
  End = CpuToFdt64((UINT64)(UINTN)Payload + DecodedBytes);
  if (Chosen < 0 || FdtSetProp(Tree, Chosen, "linux,initrd-start", &Start, sizeof(Start)) ||
      FdtSetProp(Tree, Chosen, "linux,initrd-end", &End, sizeof(End))) {
    Status = EFI_COMPROMISED_DATA; goto Fail;
  }
  // Only the shared RAM-disk driver sees this clone. The original Android FDT is untouched.
  TreeAddress = (UINT64)(UINTN)Tree;
  WriteUnaligned64((UINT64 *)GET_GUID_HOB_DATA(Hob), TreeAddress);
  DEBUG((DEBUG_ERROR,"PDXPAYLOAD: verified FAT %u bytes CRC32=%08x; shared initrd handoff ready\n",
         DecodedBytes, ActualCrc));
  return EFI_SUCCESS;
Fail:
  if (Scratch) FreePool(Scratch);
  if (Payload) FreePages(Payload, EFI_SIZE_TO_PAGES(DecodedBytes));
  if (Tree) FreePages(Tree, EFI_SIZE_TO_PAGES(TreeBytes));
  DEBUG((DEBUG_ERROR,"PDXPAYLOAD: payload refused %r\n",Status));
  return Status;
}
