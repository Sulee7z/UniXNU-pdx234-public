// SPDX-License-Identifier: BSD-2-Clause-Patent
// Resume the exact original Linux Image using the preserved bootloader FDT/ramdisks.
#include <Uefi.h>
#include <Library/ArmLib.h>
#include <Library/CacheMaintenanceLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include "../../Include/PdxBootSource.h"

extern UINT64 EFIAPI PdxCurrentEl(VOID);
extern VOID EFIAPI PdxAndroidEnter(UINT64 Kernel,UINT64 Fdt);

STATIC EFI_STATUS LeaveBootServices(EFI_HANDLE Image) {
  EFI_MEMORY_DESCRIPTOR *Map=NULL;UINTN Size=0,Key,DescriptorSize;UINT32 Version;EFI_STATUS Status;
  Status=gBS->GetMemoryMap(&Size,Map,&Key,&DescriptorSize,&Version);
  if (Status!=EFI_BUFFER_TOO_SMALL) return Status;
  Size+=16*DescriptorSize;Map=AllocatePool(Size);if (!Map) return EFI_OUT_OF_RESOURCES;
  for (UINTN Attempt=0;Attempt<2;Attempt++) {
    UINTN Available=Size;
    Status=gBS->GetMemoryMap(&Available,Map,&Key,&DescriptorSize,&Version);
    if (EFI_ERROR(Status)) break;
    Status=gBS->ExitBootServices(Image,Key);
    if (!EFI_ERROR(Status)) return EFI_SUCCESS;
    if (Status!=EFI_INVALID_PARAMETER) break;
  }
  FreePool(Map);return Status;
}
EFI_STATUS EFIAPI PdxAndroidResumeEntry(EFI_HANDLE Image,EFI_SYSTEM_TABLE *Table) {
  PDX_BOOT_SOURCE Source;EFI_STATUS Status;UINT32 Crc;UINTN FdtBytes;CONST UINT8 *Fdt;(VOID)Table;
  Status=PdxGetBootSource(&Source);if (EFI_ERROR(Status)) return Status;
  if (PdxCurrentEl()!=4) {Print(L"Android return requires EL1.\n");return EFI_UNSUPPORTED;}
  Status=gBS->CalculateCrc32((VOID *)(UINTN)Source.Android,(UINTN)Source.AndroidBytes,&Crc);
  if (EFI_ERROR(Status)||Crc!=Source.AndroidCrc32) {Print(L"Retained Android checksum failed.\n");return EFI_COMPROMISED_DATA;}
  Fdt=(CONST UINT8 *)(UINTN)Source.Fdt;
  FdtBytes=((UINT32)Fdt[4]<<24)|((UINT32)Fdt[5]<<16)|((UINT32)Fdt[6]<<8)|Fdt[7];
  if ((Source.Fdt&7)||FdtBytes<40||FdtBytes>SIZE_2MB||!PdxReadable(Source.Fdt,FdtBytes)) {
    Print(L"Retained Android device tree bounds invalid.\n");return EFI_COMPROMISED_DATA;
  }
  Print(L"Starting retained current Android kernel.\n");
  Status=LeaveBootServices(Image);if (EFI_ERROR(Status)) return Status;
  // ArmCacheMaintenanceLib's whole-cache APIs deliberately ASSERT(FALSE).
  // Linux requires the loaded Image cleaned to PoC by VA, not a set/way sweep.
  // These range operations need no Boot Services; validate their bounds above.
  WriteBackDataCacheRange((VOID *)(UINTN)Source.Android,(UINTN)Source.AndroidBytes);
  WriteBackDataCacheRange((VOID *)(UINTN)Source.Fdt,FdtBytes);
  ArmInvalidateInstructionCache();
  PdxAndroidEnter(Source.Android,Source.Fdt);
  CpuDeadLoop();return EFI_ABORTED;
}
