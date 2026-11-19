// SPDX-License-Identifier: BSD-2-Clause-Patent
#ifndef PDX_BOOT_SOURCE_H
#define PDX_BOOT_SOURCE_H
#include <Uefi.h>
#include <PiDxe.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/HobLib.h>
#include <Library/DxeServicesTableLib.h>

typedef struct {
  UINT64 Magic;
  UINT32 Version, Size;
  UINT64 Android, AndroidBytes, Fdt;
  UINT32 AndroidCrc32, Reserved;
  UINT64 Image, ImageBytes;
  UINT64 BundleOffset, BundleBytes;
} PDX_BOOT_SOURCE;

STATIC EFI_GUID mPdxSourceHobGuid = {0xE19C7B76,0x8C74,0x41A0,{0xA9,0x20,0x6E,0x97,0x22,0xCA,0xD4,0x07}};

STATIC BOOLEAN PdxReadable (UINT64 Address, UINT64 Bytes) {
  EFI_GCD_MEMORY_SPACE_DESCRIPTOR Descriptor;
  UINT64 End;
  if (Bytes == 0 || Address + Bytes < Address) return FALSE;
  End = Address + Bytes;
  for (UINTN Count = 0; Address < End && Count < 128; Count++) {
    if (EFI_ERROR(gDS->GetMemorySpaceDescriptor(Address, &Descriptor)) ||
        (Descriptor.GcdMemoryType != EfiGcdMemoryTypeSystemMemory &&
         Descriptor.GcdMemoryType != EfiGcdMemoryTypeReserved) ||
        Descriptor.BaseAddress + Descriptor.Length <= Address) return FALSE;
    Address = MIN(End, Descriptor.BaseAddress + Descriptor.Length);
  }
  return Address == End;
}

STATIC EFI_STATUS PdxGetBootSource (PDX_BOOT_SOURCE *Source) {
  VOID *Hob = GetFirstGuidHob(&mPdxSourceHobGuid);
  UINT64 *Args;
  PDX_BOOT_SOURCE *Original;
  CONST UINT8 FdtMagic[4] = {0xD0,0x0D,0xFE,0xED};
  if (Hob == NULL || GET_GUID_HOB_DATA_SIZE(Hob) != 4*sizeof(UINT64)) return EFI_NOT_FOUND;
  Args = GET_GUID_HOB_DATA(Hob);
  if ((Args[2] & 0xFFF) || Args[3] < 0x200000 + 50964992 + sizeof(PDX_BOOT_SOURCE) || Args[3] > 96*SIZE_1MB ||
      Args[2] + Args[3] < Args[2] || Args[1] != Args[2] + Args[3] - sizeof(PDX_BOOT_SOURCE) ||
      !PdxReadable(Args[1], sizeof(PDX_BOOT_SOURCE))) return EFI_COMPROMISED_DATA;
  Original = (PDX_BOOT_SOURCE *)(UINTN)Args[1];
  if (Original->Magic != SIGNATURE_64('P','X','C','B','H','O','F','1') || Original->Version != 2 ||
      Original->Size != sizeof(PDX_BOOT_SOURCE) || Original->Image != Args[2] ||
      Original->ImageBytes != Args[3] || Original->Android != Args[2] + 0x200000 ||
      Original->AndroidBytes != 50964992 || Original->Fdt != Args[0] ||
      !PdxReadable(Original->Android, Original->AndroidBytes) || !PdxReadable(Original->Fdt, 40))
    return EFI_COMPROMISED_DATA;
  if (CompareMem((VOID *)(UINTN)(Original->Android+56), "ARM\x64", 4) != 0 ||
      CompareMem((VOID *)(UINTN)Original->Fdt, FdtMagic, 4) != 0) return EFI_COMPROMISED_DATA;
  CopyMem(Source, Original, sizeof(*Source));
  return EFI_SUCCESS;
}
#endif
