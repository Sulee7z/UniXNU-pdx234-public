// SPDX-License-Identifier: BSD-2-Clause-Patent
// Stage virtual bootloader inputs, run the actual Sony FS driver, then official UniXNU.
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
#include <Library/UefiLib.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/SimpleFileSystem.h>

typedef struct {
  UINT64 Magic;UINT32 Version,Size;UINT64 Android,AndroidBytes,Fdt;
  UINT32 AndroidCrc32,Reserved;UINT64 Image,ImageBytes;
} SOURCE;
STATIC EFI_GUID SourceGuid={0xE19C7B76,0x8C74,0x41A0,{0xA9,0x20,0x6E,0x97,0x22,0xCA,0xD4,0x07}};
STATIC CONST CHAR8 Args[]="console=ttyAMA0,115200 earlycon=pl011,0x09000000 loglevel=8 nokaslr rdinit=/init panic=-1";

STATIC EFI_STATUS ReadFile(EFI_FILE_PROTOCOL *Root,CONST CHAR16 *Name,VOID **Data,UINTN *Bytes) {
  EFI_FILE_PROTOCOL *File;UINT8 InfoBuffer[1024];EFI_FILE_INFO *Info=(EFI_FILE_INFO *)InfoBuffer;
  EFI_STATUS Status;UINTN Size=sizeof(InfoBuffer);EFI_PHYSICAL_ADDRESS Address=0;
  Status=Root->Open(Root,&File,(CHAR16 *)Name,EFI_FILE_MODE_READ,0);if(EFI_ERROR(Status))return Status;
  Status=File->GetInfo(File,&gEfiFileInfoGuid,&Size,Info);
  if(!EFI_ERROR(Status)) {
    if(!Info->FileSize||Info->FileSize>128*SIZE_1MB)Status=EFI_BAD_BUFFER_SIZE;
    else {
      *Bytes=(UINTN)Info->FileSize;
      BOOLEAN IsFdt=!StrCmp(Name,L"\\EFI\\UniXNU\\Android\\virt.dtb");
      UINTN Capacity=*Bytes+(IsFdt?64*SIZE_1KB:0);
      Status=gBS->AllocatePages(AllocateAnyPages,EfiReservedMemoryType,EFI_SIZE_TO_PAGES(Capacity),&Address);
      if(!EFI_ERROR(Status)) {
        *Data=(VOID *)(UINTN)Address;Size=*Bytes;
        Status=File->Read(File,&Size,*Data);
        if(!EFI_ERROR(Status)&&Size!=*Bytes)Status=EFI_DEVICE_ERROR;
        if(!EFI_ERROR(Status)&&IsFdt&&FdtOpenInto(*Data,*Data,(INT32)Capacity))Status=EFI_COMPROMISED_DATA;
      }
    }
  }
  File->Close(File);return Status;
}
STATIC EFI_STATUS StartFile(EFI_HANDLE Parent,EFI_HANDLE Volume,CONST CHAR16 *Name) {
  EFI_HANDLE Child=NULL;EFI_STATUS Status;EFI_DEVICE_PATH_PROTOCOL *Path=FileDevicePath(Volume,Name);
  if(!Path)return EFI_OUT_OF_RESOURCES;
  Status=gBS->LoadImage(FALSE,Parent,Path,NULL,0,&Child);FreePool(Path);
  if(!EFI_ERROR(Status))Status=gBS->StartImage(Child,NULL,NULL);
  return Status;
}
STATIC EFI_STATUS PrepareHob(VOID *Kernel,UINTN KernelBytes,VOID *Fdt,VOID *Initrd,UINTN InitrdBytes) {
  EFI_PHYSICAL_ADDRESS Image=0,Hobs=0;EFI_STATUS Status;
  UINTN ImageBytes=SIZE_2MB+KernelBytes+sizeof(SOURCE),OldBytes=0,NewBytes;
  SOURCE *Source;EFI_HOB_GENERIC_HEADER *Hob,*End;EFI_HOB_GUID_TYPE *GuidHob;UINT64 *InputArgs;
  INT32 Chosen=FdtPathOffset(Fdt,"/chosen");UINT64 Value;
  if(Chosen<0)return EFI_COMPROMISED_DATA;
  Value=CpuToFdt64((UINTN)Initrd);
  if(FdtSetProp(Fdt,Chosen,"linux,initrd-start",&Value,sizeof(Value)))return EFI_COMPROMISED_DATA;
  Value=CpuToFdt64((UINTN)Initrd+InitrdBytes);
  if(FdtSetProp(Fdt,Chosen,"linux,initrd-end",&Value,sizeof(Value))||
     FdtSetProp(Fdt,Chosen,"bootargs",Args,sizeof(Args)))return EFI_COMPROMISED_DATA;
  Status=gBS->AllocatePages(AllocateAnyPages,EfiReservedMemoryType,EFI_SIZE_TO_PAGES(ImageBytes),&Image);
  if(EFI_ERROR(Status))return Status;
  ZeroMem((VOID *)(UINTN)Image,ImageBytes);CopyMem((VOID *)(UINTN)(Image+SIZE_2MB),Kernel,KernelBytes);
  Source=(SOURCE *)(UINTN)(Image+ImageBytes-sizeof(SOURCE));
  Source->Magic=SIGNATURE_64('P','X','C','B','H','O','F','1');Source->Version=1;Source->Size=sizeof(SOURCE);
  Source->Android=Image+SIZE_2MB;Source->AndroidBytes=KernelBytes;Source->Fdt=(UINTN)Fdt;
  Source->Image=Image;Source->ImageBytes=ImageBytes;
  Status=gBS->CalculateCrc32((VOID *)(UINTN)Source->Android,KernelBytes,&Source->AndroidCrc32);
  if(EFI_ERROR(Status))return Status;
  Hob=GetHobList();
  for(UINTN Count=0;Hob->HobType!=EFI_HOB_TYPE_END_OF_HOB_LIST&&Count<16384;Count++) {
    if(Hob->HobLength<sizeof(*Hob)||OldBytes>SIZE_1MB)return EFI_COMPROMISED_DATA;
    OldBytes+=Hob->HobLength;Hob=(EFI_HOB_GENERIC_HEADER *)((UINT8 *)Hob+Hob->HobLength);
  }
  if(Hob->HobType!=EFI_HOB_TYPE_END_OF_HOB_LIST)return EFI_COMPROMISED_DATA;
  NewBytes=OldBytes+sizeof(EFI_HOB_GUID_TYPE)+4*sizeof(UINT64)+sizeof(*End);
  Status=gBS->AllocatePages(AllocateAnyPages,EfiReservedMemoryType,EFI_SIZE_TO_PAGES(NewBytes),&Hobs);
  if(EFI_ERROR(Status))return Status;
  ZeroMem((VOID *)(UINTN)Hobs,NewBytes);CopyMem((VOID *)(UINTN)Hobs,GetHobList(),OldBytes);
  GuidHob=(EFI_HOB_GUID_TYPE *)(UINTN)(Hobs+OldBytes);
  GuidHob->Header.HobType=EFI_HOB_TYPE_GUID_EXTENSION;GuidHob->Header.HobLength=sizeof(*GuidHob)+4*sizeof(UINT64);
  CopyMem(&GuidHob->Name,&SourceGuid,sizeof(SourceGuid));InputArgs=(UINT64 *)(GuidHob+1);
  InputArgs[0]=(UINTN)Fdt;InputArgs[1]=(UINTN)Source;InputArgs[2]=Image;InputArgs[3]=ImageBytes;
  End=(EFI_HOB_GENERIC_HEADER *)((UINT8 *)GuidHob+GuidHob->Header.HobLength);
  End->HobType=EFI_HOB_TYPE_END_OF_HOB_LIST;End->HobLength=sizeof(*End);
  return gBS->InstallConfigurationTable(&gEfiHobListGuid,(VOID *)(UINTN)Hobs);
}
STATIC EFI_STATUS CheckReadonlyVolume(EFI_HANDLE OriginalVolume) {
  EFI_HANDLE *Handles;UINTN Count;EFI_STATUS Status;
  Status=gBS->LocateHandleBuffer(ByProtocol,&gEfiSimpleFileSystemProtocolGuid,NULL,&Count,&Handles);
  if(EFI_ERROR(Status))return Status;
  Status=EFI_NOT_FOUND;
  for(UINTN Index=0;Index<Count;Index++) {
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs;EFI_FILE_PROTOCOL *Root,*File;EFI_DEVICE_PATH_PROTOCOL *Path;
    if(Handles[Index]==OriginalVolume)continue;
    if(EFI_ERROR(gBS->HandleProtocol(Handles[Index],&gEfiDevicePathProtocolGuid,(VOID **)&Path)))continue;
    if(Path->Type!=HARDWARE_DEVICE_PATH||Path->SubType!=HW_VENDOR_DP)continue;
    if(EFI_ERROR(gBS->HandleProtocol(Handles[Index],&gEfiSimpleFileSystemProtocolGuid,(VOID **)&Fs)))continue;
    Status=Fs->OpenVolume(Fs,&Root);if(EFI_ERROR(Status))break;
    Status=Root->Open(Root,&File,L"\\EFI\\UniXNU\\Android\\Image",EFI_FILE_MODE_READ|EFI_FILE_MODE_WRITE,0);
    if(Status!=EFI_WRITE_PROTECTED){Root->Close(Root);Status=EFI_PROTOCOL_ERROR;break;}
    Status=Root->Open(Root,&File,L"\\EFI\\UniXNU\\Android\\Image",EFI_FILE_MODE_READ,0);
    if(!EFI_ERROR(Status)) {
      UINT8 Header[64];UINTN Size=sizeof(Header);
      Status=File->Read(File,&Size,Header);File->Close(File);
      if(!EFI_ERROR(Status)&&(Size!=64||CompareMem(Header+56,"ARM\x64",4)))Status=EFI_COMPROMISED_DATA;
    }
    Root->Close(Root);break;
  }
  FreePool(Handles);return Status;
}
EFI_STATUS EFIAPI ConfigFsProbeEntry(EFI_HANDLE Image,EFI_SYSTEM_TABLE *Table) {
  EFI_STATUS Status;EFI_LOADED_IMAGE_PROTOCOL *Loaded;EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs;EFI_FILE_PROTOCOL *Root;
  VOID *Kernel,*Fdt,*Initrd;UINTN KernelBytes,FdtBytes,InitrdBytes;CONST CHAR16 *Stage=L"read inputs";(VOID)Table;
  Status=gBS->HandleProtocol(Image,&gEfiLoadedImageProtocolGuid,(VOID **)&Loaded);if(EFI_ERROR(Status))return Status;
  Status=gBS->HandleProtocol(Loaded->DeviceHandle,&gEfiSimpleFileSystemProtocolGuid,(VOID **)&Fs);if(EFI_ERROR(Status))return Status;
  Status=Fs->OpenVolume(Fs,&Root);if(EFI_ERROR(Status))return Status;
  Status=ReadFile(Root,L"\\EFI\\UniXNU\\Android\\Image",&Kernel,&KernelBytes);if(EFI_ERROR(Status))goto Done;
  Status=ReadFile(Root,L"\\EFI\\UniXNU\\Android\\virt.dtb",&Fdt,&FdtBytes);if(EFI_ERROR(Status))goto Done;
  Status=ReadFile(Root,L"\\EFI\\UniXNU\\Android\\initrd.img",&Initrd,&InitrdBytes);if(EFI_ERROR(Status))goto Done;
  Stage=L"prepare HOB";Status=PrepareHob(Kernel,KernelBytes,Fdt,Initrd,InitrdBytes);if(EFI_ERROR(Status))goto Done;
  Stage=L"start source driver";
  Status=StartFile(Image,Loaded->DeviceHandle,L"\\EFI\\Drivers\\PdxConfigFsDxe.efi");if(EFI_ERROR(Status))goto Done;
  Stage=L"check readonly volume";
  Status=CheckReadonlyVolume(Loaded->DeviceHandle);if(EFI_ERROR(Status))goto Done;
  Print(L"QEMU-CONFIGFS: PASS actual readonly volume and inherited inputs\n");
  Root->Close(Root);
  return StartFile(Image,Loaded->DeviceHandle,L"\\EFI\\UniXNU\\UniXNU.efi");
Done:
  Print(L"QEMU-CONFIGFS: FAIL %s: %r\n",Stage,Status);Root->Close(Root);return Status;
}
