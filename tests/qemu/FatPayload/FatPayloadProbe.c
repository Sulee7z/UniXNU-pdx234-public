// SPDX-License-Identifier: BSD-2-Clause-Patent
// Execute the real Sony decompressor -> shared initrd driver -> firmware FAT stack.
#include <Uefi.h>
#include <PiDxe.h>
#include <Guid/FileInfo.h>
#include <Guid/HobList.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DevicePathLib.h>
#include <Library/FdtLib.h>
#include <Library/HobLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/SimpleFileSystem.h>
#include "ExpectedPayload.h"

typedef struct {
  UINT64 Magic; UINT32 Version,Size; UINT64 Android,AndroidBytes,Fdt;
  UINT32 AndroidCrc,Reserved; UINT64 Image,ImageBytes,BundleOffset,BundleBytes;
} SOURCE;
STATIC EFI_GUID SourceGuid={0xE19C7B76,0x8C74,0x41A0,{0xA9,0x20,0x6E,0x97,0x22,0xCA,0xD4,0x07}};
STATIC EFI_GUID EntryGuid={0xDAEE82E6,0x8090,0x4E72,{0xBF,0xB9,0x78,0xC1,0x3C,0xD4,0xE3,0x59}};

STATIC EFI_STATUS Read(EFI_FILE_PROTOCOL *Root, CONST CHAR16 *Name, VOID **Data, UINTN *Bytes) {
  EFI_FILE_PROTOCOL *File; EFI_STATUS Status; UINT8 Buffer[1024]; UINTN Size=sizeof(Buffer);
  EFI_FILE_INFO *Info=(EFI_FILE_INFO *)Buffer;
  Status=Root->Open(Root,&File,(CHAR16 *)Name,EFI_FILE_MODE_READ,0);
  if(EFI_ERROR(Status))return Status;
  Status=File->GetInfo(File,&gEfiFileInfoGuid,&Size,Info);
  if(!EFI_ERROR(Status)) {
    if(Info->FileSize==0 || Info->FileSize>128*SIZE_1MB)Status=EFI_BAD_BUFFER_SIZE;
    else {
      *Bytes=(UINTN)Info->FileSize; *Data=AllocatePages(EFI_SIZE_TO_PAGES(*Bytes));
      if(!*Data)Status=EFI_OUT_OF_RESOURCES;
      else {Size=*Bytes;Status=File->Read(File,&Size,*Data);if(Size!=*Bytes)Status=EFI_DEVICE_ERROR;}
    }
  }
  File->Close(File);return Status;
}
STATIC EFI_STATUS Start(EFI_HANDLE Parent,EFI_HANDLE Volume,CONST CHAR16 *Name) {
  EFI_HANDLE Child=NULL;EFI_DEVICE_PATH_PROTOCOL *Path=FileDevicePath(Volume,Name);EFI_STATUS Status;
  if(!Path)return EFI_OUT_OF_RESOURCES;
  Status=gBS->LoadImage(FALSE,Parent,Path,NULL,0,&Child);FreePool(Path);
  if(!EFI_ERROR(Status)) {
    EFI_LOADED_IMAGE_PROTOCOL *Loaded;
    if(!EFI_ERROR(gBS->HandleProtocol(Child,&gEfiLoadedImageProtocolGuid,(VOID **)&Loaded)))
      Print(L"FAT-PAYLOAD: loading %s base=%p size=%lx\n",Name,Loaded->ImageBase,Loaded->ImageSize);
    Status=gBS->StartImage(Child,NULL,NULL);
  }
  return Status;
}
STATIC EFI_STATUS Hobs(VOID *Image,UINTN Bytes,VOID *Fdt) {
  EFI_HOB_GENERIC_HEADER *At=GetHobList(),*End;EFI_HOB_GUID_TYPE *Guid;
  UINTN OldBytes=0,Size;UINT8 *Copy;SOURCE *Source=(SOURCE *)((UINT8 *)Image+Bytes-sizeof(SOURCE));
  if(Source->Version!=2 || Source->Size!=sizeof(SOURCE))return EFI_COMPROMISED_DATA;
  Source->Android=(UINTN)Image+SIZE_2MB;Source->Fdt=(UINTN)Fdt;Source->Image=(UINTN)Image;Source->ImageBytes=Bytes;
  for(UINTN I=0;I<16384 && At->HobType!=EFI_HOB_TYPE_END_OF_HOB_LIST;I++) {
    if(At->HobLength<sizeof(*At) || OldBytes>SIZE_1MB)return EFI_COMPROMISED_DATA;
    OldBytes+=At->HobLength;At=(EFI_HOB_GENERIC_HEADER *)((UINT8 *)At+At->HobLength);
  }
  if(At->HobType!=EFI_HOB_TYPE_END_OF_HOB_LIST)return EFI_COMPROMISED_DATA;
  Size=OldBytes+2*sizeof(EFI_HOB_GUID_TYPE)+5*sizeof(UINT64)+sizeof(*End);
  Copy=AllocateZeroPool(Size);if(!Copy)return EFI_OUT_OF_RESOURCES;
  CopyMem(Copy,GetHobList(),OldBytes);Guid=(EFI_HOB_GUID_TYPE *)(Copy+OldBytes);
  Guid->Header.HobType=EFI_HOB_TYPE_GUID_EXTENSION;Guid->Header.HobLength=sizeof(*Guid)+4*sizeof(UINT64);
  CopyMem(&Guid->Name,&SourceGuid,sizeof(SourceGuid));
  {UINT64 *Args=(UINT64 *)(Guid+1);Args[0]=(UINTN)Fdt;Args[1]=(UINTN)Source;Args[2]=(UINTN)Image;Args[3]=Bytes;}
  Guid=(EFI_HOB_GUID_TYPE *)((UINT8 *)Guid+Guid->Header.HobLength);
  Guid->Header.HobType=EFI_HOB_TYPE_GUID_EXTENSION;Guid->Header.HobLength=sizeof(*Guid)+sizeof(UINT64);
  CopyMem(&Guid->Name,&EntryGuid,sizeof(EntryGuid));WriteUnaligned64((UINT64 *)(Guid+1),(UINTN)Fdt);
  End=(EFI_HOB_GENERIC_HEADER *)((UINT8 *)Guid+Guid->Header.HobLength);
  End->HobType=EFI_HOB_TYPE_END_OF_HOB_LIST;End->HobLength=sizeof(*End);
  return gBS->InstallConfigurationTable(&gEfiHobListGuid,Copy);
}
EFI_STATUS EFIAPI FatPayloadProbeEntry(EFI_HANDLE Image,EFI_SYSTEM_TABLE *Table) {
  EFI_LOADED_IMAGE_PROTOCOL *Loaded;EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs;EFI_FILE_PROTOCOL *Root;
  VOID *Raw=NULL,*Fdt;UINTN Bytes=0;EFI_STATUS Status;EFI_HANDLE *Handles;UINTN Count;BOOLEAN Found=FALSE;
  CONST CHAR16 *Stage=L"read composite";(VOID)Table;
  Status=gBS->HandleProtocol(Image,&gEfiLoadedImageProtocolGuid,(VOID **)&Loaded);if(EFI_ERROR(Status))return Status;
  Status=gBS->HandleProtocol(Loaded->DeviceHandle,&gEfiSimpleFileSystemProtocolGuid,(VOID **)&Fs);if(EFI_ERROR(Status))return Status;
  Status=Fs->OpenVolume(Fs,&Root);if(EFI_ERROR(Status))return Status;
  Status=Read(Root,L"\\combo.Image",&Raw,&Bytes);if(EFI_ERROR(Status))goto Done;
  Fdt=AllocatePages(1);if(!Fdt){Status=EFI_OUT_OF_RESOURCES;goto Done;}
  if(FdtCreateEmptyTree(Fdt,4096) || FdtAddSubnode(Fdt,0,"chosen")<0){Status=EFI_COMPROMISED_DATA;goto Done;}
  Stage=L"prepare handoff";Status=Hobs(Raw,Bytes,Fdt);if(EFI_ERROR(Status))goto Done;
  Stage=L"real Sony adapter";Status=Start(Image,Loaded->DeviceHandle,L"\\EFI\\Drivers\\PdxConfigFsDxe.efi");if(EFI_ERROR(Status))goto Done;
  Stage=L"shared RAM-disk";Status=Start(Image,Loaded->DeviceHandle,L"\\EFI\\Drivers\\UniXNURamDiskDxe.efi");if(EFI_ERROR(Status))goto Done;
  Status=gBS->LocateHandleBuffer(AllHandles,NULL,NULL,&Count,&Handles);if(EFI_ERROR(Status))goto Done;
  for(UINTN I=0;I<Count;I++)gBS->ConnectController(Handles[I],NULL,NULL,TRUE);
  FreePool(Handles);
  Stage=L"FAT kernel identity";
  Status=gBS->LocateHandleBuffer(ByProtocol,&gEfiSimpleFileSystemProtocolGuid,NULL,&Count,&Handles);if(EFI_ERROR(Status))goto Done;
  for(UINTN I=0;I<Count;I++) {
    EFI_FILE_PROTOCOL *Volume;VOID *Kernel;UINTN KernelBytes;UINT32 Crc;
    if(Handles[I]==Loaded->DeviceHandle)continue;
    if(EFI_ERROR(gBS->HandleProtocol(Handles[I],&gEfiSimpleFileSystemProtocolGuid,(VOID **)&Fs)))continue;
    if(EFI_ERROR(Fs->OpenVolume(Fs,&Volume)))continue;
    Status=Read(Volume,L"\\EFI\\UniXNU\\Payloads\\kernel.macho",&Kernel,&KernelBytes);
    if(!EFI_ERROR(Status)) {
      Status=gBS->CalculateCrc32(Kernel,KernelBytes,&Crc);
      Found=!EFI_ERROR(Status) && KernelBytes==EXPECTED_KERNEL_BYTES && Crc==EXPECTED_KERNEL_CRC;
      FreePages(Kernel,EFI_SIZE_TO_PAGES(KernelBytes));
    }
    Volume->Close(Volume);if(Found)break;
  }
  FreePool(Handles);Status=Found?EFI_SUCCESS:EFI_COMPROMISED_DATA;
Done:
  Root->Close(Root);
  if(EFI_ERROR(Status))Print(L"FAT-PAYLOAD: FAIL %s %r\n",Stage,Status);
  else Print(L"FAT-PAYLOAD: PASS real Sony LZMA -> shared initrd -> firmware FAT -> exact XNU bytes\n");
  gRT->ResetSystem(EfiResetShutdown,Status,0,NULL);return Status;
}
