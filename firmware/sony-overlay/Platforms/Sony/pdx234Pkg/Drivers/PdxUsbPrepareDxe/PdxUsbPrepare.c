// SPDX-License-Identifier: BSD-2-Clause-Patent
// Like Sony Fastboot, initialize and poll the USB client at TPL_APPLICATION.
// The menu consumes this private service. A timer only wakes WaitForEvent;
// there is no timer notification executing vendor USB code.
#include <Uefi.h>
#include <Guid/EventGroup.h>
#include <Protocol/UsbFunctionIo.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include "PdxUsbService.h"

STATIC EFI_GUID mStartGroup={0x1c0cffce,0xfc8d,0x4e44,{0x8c,0x78,0x9c,0x9e,0x5b,0x53,0x0d,0x36}};
STATIC EFI_GUID mServiceGuid=PDX_USB_SERVICE_GUID;
STATIC BOOLEAN mAttempted,mExited;
STATIC BOOLEAN mClientStarted;
STATIC UINTN mProviderChecks;
STATIC EFI_GUID mUsbfnGuid=EFI_USBFN_IO_PROTOCOL_GUID;
STATIC EFI_GUID mUsbDeviceGuid={0xd9d9ce48,0x44b8,0x4f49,{0x8e,0x3e,0x2a,0x3b,0x92,0x7d,0xc6,0xc1}};
STATIC EFI_STATUS mStatus=EFI_NOT_READY;
EFI_STATUS PdxUsbCdcStart(VOID);
EFI_STATUS PdxUsbCdcPump(VOID);
STATIC EFI_STATUS EFIAPI Service(VOID);
STATIC PDX_USB_SERVICE mService={1,NULL,Service};

STATIC VOID EFIAPI EmptyNotify(EFI_EVENT Event,VOID *Context)
{
  (VOID)Event;(VOID)Context;
}

STATIC EFI_STATUS WaitForProvider(VOID)
{
  // Bounded application wakeups, not a blocking wait in a notification. Return
  // success while pending so the menu retains our wake event. The client has
  // not started yet; errors become terminal only after the retry budget.
  if(++mProviderChecks>500) {
    DEBUG((DEBUG_ERROR,"PDX USB: USBFN provider wait exhausted\n"));
    mStatus=EFI_TIMEOUT;
  } else {
    mStatus=gBS->SetTimer(mService.WakeEvent,TimerRelative,100000); //10ms
  }
  return mStatus;
}

STATIC VOID EFIAPI ExitService(EFI_EVENT Event,VOID *Context)
{
  (VOID)Event;(VOID)Context;mExited=TRUE;
}

STATIC EFI_STATUS EFIAPI Service(VOID)
{
  EFI_TPL OldTpl;
  EFI_EVENT Event;
  if(mExited) return EFI_UNSUPPORTED;
  OldTpl=gBS->RaiseTPL(TPL_HIGH_LEVEL);
  gBS->RestoreTPL(OldTpl);
  if(OldTpl!=TPL_APPLICATION) return EFI_UNSUPPORTED;
  if(!mAttempted) {
    mAttempted=TRUE;
    DEBUG((DEBUG_ERROR,"PDX053 USB: preparation event enter at TPL_APPLICATION\n"));
    // This Mu CoreSignalEvent only broadcasts event groups for SIGNAL events.
    // Use an empty notification like Sony's SignalToEnumerate, not a type0
    // signal-only event. Protocol publication remains the readiness condition.
    mStatus=gBS->CreateEventEx(EVT_NOTIFY_SIGNAL,TPL_CALLBACK,EmptyNotify,NULL,&mStartGroup,&Event);
    if(EFI_ERROR(mStatus)) return mStatus;
    mStatus=gBS->SignalEvent(Event);
    DEBUG((DEBUG_ERROR,"PDX053 USB: preparation event return %r; awaiting provider\n",mStatus));
    gBS->CloseEvent(Event);
    if(EFI_ERROR(mStatus)) return mStatus;
    return WaitForProvider(); //yield before probing asynchronous driver binding
  }
  if(EFI_ERROR(mStatus)) return mStatus;
  if(!mClientStarted) {
    VOID *Provider=NULL;
    mStatus=gBS->LocateProtocol(&mUsbfnGuid,NULL,&Provider);
    if(mStatus==EFI_NOT_FOUND || mStatus==EFI_NOT_READY) return WaitForProvider();
    if(EFI_ERROR(mStatus)) return mStatus;
    if(Provider==NULL) {mStatus=EFI_DEVICE_ERROR;return mStatus;}
    Provider=NULL;
    mStatus=gBS->LocateProtocol(&mUsbDeviceGuid,NULL,&Provider);
    if(mStatus==EFI_NOT_FOUND || mStatus==EFI_NOT_READY) return WaitForProvider();
    if(EFI_ERROR(mStatus)) return mStatus;
    if(Provider==NULL) {mStatus=EFI_DEVICE_ERROR;return mStatus;}
    mStatus=PdxUsbCdcStart();
    DEBUG((DEBUG_ERROR,"PDX USB: application CDC start: %r\n",mStatus));
    if(EFI_ERROR(mStatus)) return mStatus;
    mClientStarted=TRUE;
  }
  if(EFI_ERROR(mStatus)) return mStatus;
  mStatus=PdxUsbCdcPump();
  if(!EFI_ERROR(mStatus)) mStatus=gBS->SetTimer(mService.WakeEvent,TimerRelative,10000);
  return mStatus;
}

EFI_STATUS EFIAPI PdxUsbPrepareEntry(EFI_HANDLE ImageHandle,EFI_SYSTEM_TABLE *SystemTable)
{
  EFI_STATUS Status;
  EFI_EVENT ExitEvent;
  EFI_HANDLE Handle=NULL;
  (VOID)ImageHandle;(VOID)SystemTable;
  Status=gBS->CreateEvent(EVT_TIMER,0,NULL,NULL,&mService.WakeEvent);
  if(EFI_ERROR(Status)) return Status;
  Status=gBS->CreateEventEx(EVT_NOTIFY_SIGNAL,TPL_NOTIFY,ExitService,NULL,&gEfiEventExitBootServicesGuid,&ExitEvent);
  if(EFI_ERROR(Status)) {gBS->CloseEvent(mService.WakeEvent);return Status;}
  Status=gBS->InstallProtocolInterface(&Handle,&mServiceGuid,EFI_NATIVE_INTERFACE,&mService);
  if(EFI_ERROR(Status)) {gBS->CloseEvent(ExitEvent);gBS->CloseEvent(mService.WakeEvent);}
  return Status;
}
