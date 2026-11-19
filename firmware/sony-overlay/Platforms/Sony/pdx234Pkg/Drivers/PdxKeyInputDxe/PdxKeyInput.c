// SPDX-License-Identifier: BSD-2-Clause-Patent
// Reuse the shared SPMI core, but map its semantic bits to Sony's actual key wiring.
#include <Uefi.h>
#include <Protocol/SimpleTextIn.h>
#include <Protocol/DevicePath.h>
#include <Guid/EventGroup.h>
#include <Guid/GlobalVariable.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DevicePathLib.h>
#include <Library/UefiLib.h>
#include "../../../../Xiaomi/shengPkg/Drivers/ShengKeyInputDxe/ShengSpmiKeys.h"

STATIC struct sk_arbiter mArbiter;
STATIC struct sk_keys mKeys;
STATIC struct sk_filter mFilter;
STATIC EFI_INPUT_KEY mQueue[16];
STATIC UINTN mHead,mCount,mFailures;
STATIC EFI_EVENT mTimer;
STATIC EFI_SIMPLE_TEXT_INPUT_PROTOCOL mInput;
typedef struct {VENDOR_DEVICE_PATH Vendor;EFI_DEVICE_PATH_PROTOCOL End;} KEY_PATH;
STATIC KEY_PATH mPath={
 {{HARDWARE_DEVICE_PATH,HW_VENDOR_DP,{sizeof(VENDOR_DEVICE_PATH),0}},
  {0x2E812F53,0x1695,0x4DE5,{0xA8,0x61,0x47,0x45,0x8A,0x99,0x01,0xEF}}},
 {END_DEVICE_PATH_TYPE,END_ENTIRE_DEVICE_PATH_SUBTYPE,{sizeof(EFI_DEVICE_PATH_PROTOCOL),0}}};

STATIC EFI_STATUS EFIAPI Reset(EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This,BOOLEAN Check) {
  EFI_TPL Tpl=gBS->RaiseTPL(TPL_NOTIFY);(VOID)This;(VOID)Check;
  mHead=mCount=0;ZeroMem(&mFilter,sizeof(mFilter));gBS->RestoreTPL(Tpl);return EFI_SUCCESS;
}
STATIC EFI_STATUS EFIAPI Read(EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This,EFI_INPUT_KEY *Key) {
  EFI_TPL Tpl=gBS->RaiseTPL(TPL_NOTIFY);(VOID)This;
  if (!mCount) {gBS->RestoreTPL(Tpl);return EFI_NOT_READY;}
  *Key=mQueue[mHead];mHead=(mHead+1)%16;mCount--;gBS->RestoreTPL(Tpl);return EFI_SUCCESS;
}
STATIC VOID EFIAPI Wait(EFI_EVENT Event,VOID *Context) {(VOID)Context;if (mCount) gBS->SignalEvent(Event);}
STATIC VOID Push(UINT16 Scan,CHAR16 Unicode) {
  if (mCount==16) return;
  mQueue[(mHead+mCount)%16].ScanCode=Scan;mQueue[(mHead+mCount)%16].UnicodeChar=Unicode;
  mCount++;gBS->SignalEvent(mInput.WaitForKey);
}
STATIC VOID EFIAPI Poll(EFI_EVENT Event,VOID *Context) {
  UINT8 Sample,Out;(VOID)Event;(VOID)Context;
  if (sk_sample(&mArbiter,&mKeys,&Sample)) {
    if (++mFailures==50) {gBS->SetTimer(mTimer,TimerCancel,0);DEBUG((DEBUG_ERROR,"PDXKEY: failed read, polling stopped\n"));}
    return;
  }
  mFailures=0;Out=sk_step(&mFilter,Sample,25,7);
  // Shared helper calls RESIN 'voldown' and GPIO6 'volup'; Sony has them reversed.
  if (Out&SK_KEY_VOLDOWN) Push(SCAN_UP,0);
  if (Out&SK_KEY_VOLUP) Push(SCAN_DOWN,0);
  if (Out&SK_KEY_POWER) Push(SCAN_NULL,CHAR_CARRIAGE_RETURN);
}
STATIC VOID EFIAPI Exit(EFI_EVENT Event,VOID *Context) {(VOID)Event;(VOID)Context;gBS->SetTimer(mTimer,TimerCancel,0);}
STATIC EFI_STATUS RegisterConsole(VOID) {
  UINTN Size=0;UINT32 Attributes=EFI_VARIABLE_BOOTSERVICE_ACCESS|EFI_VARIABLE_RUNTIME_ACCESS;
  EFI_DEVICE_PATH_PROTOCOL *Old=NULL,*Combined;EFI_STATUS Status;
  Status=gRT->GetVariable(L"ConIn",&gEfiGlobalVariableGuid,&Attributes,&Size,NULL);
  if (Status==EFI_NOT_FOUND)
    return gRT->SetVariable(L"ConIn",&gEfiGlobalVariableGuid,Attributes,sizeof(mPath),&mPath);
  if (Status!=EFI_BUFFER_TOO_SMALL) return Status;
  Old=AllocatePool(Size);if (!Old) return EFI_OUT_OF_RESOURCES;
  Status=gRT->GetVariable(L"ConIn",&gEfiGlobalVariableGuid,&Attributes,&Size,Old);
  if (EFI_ERROR(Status)) {FreePool(Old);return Status;}
  Combined=AppendDevicePathInstance(Old,(EFI_DEVICE_PATH_PROTOCOL *)&mPath);FreePool(Old);
  if (!Combined) return EFI_OUT_OF_RESOURCES;
  Status=gRT->SetVariable(L"ConIn",&gEfiGlobalVariableGuid,Attributes,GetDevicePathSize(Combined),Combined);
  FreePool(Combined);return Status;
}
EFI_STATUS EFIAPI PdxKeyInputEntry(EFI_HANDLE Image,EFI_SYSTEM_TABLE *Table) {
  EFI_STATUS Status;EFI_HANDLE Handle=NULL;EFI_EVENT ExitEvent;(VOID)Image;(VOID)Table;
  mArbiter.core=(volatile UINT32 *)(UINTN)0xC400000;mArbiter.obs=(volatile UINT32 *)(UINTN)0xC440000;mArbiter.ee=0;
  if (sk_open(&mArbiter,&mKeys)) return EFI_UNSUPPORTED;
  mInput.Reset=Reset;mInput.ReadKeyStroke=Read;
  Status=gBS->CreateEvent(EVT_NOTIFY_WAIT,TPL_NOTIFY,Wait,NULL,&mInput.WaitForKey);if (EFI_ERROR(Status)) return Status;
  Status=gBS->CreateEvent(EVT_TIMER|EVT_NOTIFY_SIGNAL,TPL_CALLBACK,Poll,NULL,&mTimer);if (EFI_ERROR(Status)) return Status;
  Status=gBS->CreateEventEx(EVT_NOTIFY_SIGNAL,TPL_NOTIFY,Exit,NULL,&gEfiEventExitBootServicesGuid,&ExitEvent);if (EFI_ERROR(Status)) return Status;
  Status=gBS->InstallMultipleProtocolInterfaces(&Handle,&gEfiSimpleTextInProtocolGuid,&mInput,&gEfiDevicePathProtocolGuid,&mPath,NULL);
  if (EFI_ERROR(Status)) return Status;
  Status=RegisterConsole();if (EFI_ERROR(Status)) return Status;
  gBS->ConnectController(Handle,NULL,NULL,TRUE);
  gBS->SetTimer(mTimer,TimerPeriodic,200000);DEBUG((DEBUG_ERROR,"PDXKEY: Sony up/down/power ready\n"));return EFI_SUCCESS;
}
