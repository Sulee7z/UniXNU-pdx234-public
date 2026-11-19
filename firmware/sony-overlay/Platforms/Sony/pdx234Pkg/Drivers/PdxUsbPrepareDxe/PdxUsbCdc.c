// SPDX-License-Identifier: BSD-2-Clause-Patent
// Sony UsbDeviceDxe owns Chapter9; this client supplies CDC ACM descriptors,
// class requests and a bounded event pump. No device-specific MMIO is used.
#include <Uefi.h>
#include <Guid/EventGroup.h>
#include <IndustryStandard/Usb.h>
// The old Qualcomm extension header duplicates four modern MdePkg names.
// Namespace only those declarations; the protocol layout remains unchanged.
#define USB_BOS_DESCRIPTOR QCOM_USB_BOS_DESCRIPTOR
#define USB_INTERFACE_ASSOCIATION_DESCRIPTOR QCOM_USB_INTERFACE_ASSOCIATION_DESCRIPTOR
#define USB_DESC_TYPE_INTERFACE_ASSOCIATION QCOM_USB_DESC_TYPE_INTERFACE_ASSOCIATION
#define USB_DESC_TYPE_BOS QCOM_USB_DESC_TYPE_BOS
#include <Protocol/EFIUsbDevice.h>
#undef USB_BOS_DESCRIPTOR
#undef USB_INTERFACE_ASSOCIATION_DESCRIPTOR
#undef USB_DESC_TYPE_INTERFACE_ASSOCIATION
#undef USB_DESC_TYPE_BOS
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>

STATIC EFI_GUID mSetupGuid = {0x11418746,0xca3b,0x4106,{0xbb,0x5a,0x7c,0xc9,0xd8,0x2d,0xe6,0x91}};
STATIC EFI_USB_DEVICE_PROTOCOL *mDevice;
VOID PdxUsbBoundaryInit(VOID);
VOID PdxUsbBoundaryPhase(UINTN Phase);
VOID PdxUsbBoundaryStop(VOID);
VOID PdxUsbBoundaryProbeCore(UINTN Sequence);
VOID PdxUsbBoundaryProbePrepared(VOID);
STATIC UINTN mPollCalls;
STATIC EFI_EVENT mExitEvent;
STATIC EFI_STATUS mPollStatus;
STATIC VOID *mControl, *mTx, *mRx;
STATIC BOOLEAN mStarted, mConnected, mDtr, mTxBusy, mRxBusy, mBannerSent;
STATIC BOOLEAN mControlBusy, mSetupPending, mAborting, mStartAttempted;
STATIC BOOLEAN mTxStale, mControlStale;
STATIC UINT8 mControlEndpoint;
STATIC EFI_USB_DEVICE_REQUEST mPendingSetup;
STATIC UINTN mTxSize, mTxDone;
STATIC UINT8 mControlStage;
STATIC UINT8 mLineCoding[7] = {0x00,0xc2,0x01,0x00,0,0,8}; //115200 8N1
STATIC CONST CHAR8 mBanner[] = "PDX234 UEFI CDC active; XNU transport starts separately after handoff.\r\n";

// One CDC function, control interface0 and data interface1. Notification EP1,
// bulk OUT EP2 and bulk IN EP3. VID/PID match the existing Sony research CDC.
STATIC UINT8 mDeviceHs[] = {18,1,0x00,0x02,2,0,0,64,0x09,0x12,0x6d,0x31,0x00,0x01,1,2,3,1};
STATIC UINT8 mDeviceSs[] = {18,1,0x00,0x03,2,0,0,9,0x09,0x12,0x6d,0x31,0x00,0x01,1,2,3,1};
STATIC UINT8 mQualifier[] = {10,6,0,2,2,0,0,64,1,0};
STATIC UINT8 mConfigHs[] = {
  9,2,67,0,2,1,0,0x80,50,
  9,4,0,0,1,2,2,1,0,
  5,0x24,0,0x10,1, 5,0x24,1,0,1, 4,0x24,2,2, 5,0x24,6,0,1,
  7,5,0x81,3,16,0,9,
  9,4,1,0,2,0x0a,0,0,0,
  7,5,0x02,2,0,2,0, 7,5,0x83,2,0,2,0
};
STATIC UINT8 mConfigSs[] = {
  9,2,85,0,2,1,0,0x80,13,
  9,4,0,0,1,2,2,1,0,
  5,0x24,0,0x10,1, 5,0x24,1,0,1, 4,0x24,2,2, 5,0x24,6,0,1,
  7,5,0x81,3,16,0,9, 6,0x30,0,0,16,0,
  9,4,1,0,2,0x0a,0,0,0,
  7,5,0x02,2,0,4,0, 6,0x30,0,0,0,0,
  7,5,0x83,2,0,4,0, 6,0x30,0,0,0,0
};
STATIC UINT8 mBos[] = {5,15,22,0,2, 7,16,2,0,0,0,0, 10,16,3,0,0x0e,0,1,0,0,0};
STATIC UINT8 mLanguage[] = {4,3,9,4};
#pragma pack(1)
STATIC struct {UINT8 Length,Type; CHAR16 Text[7];} mManufacturer = {14,3,L"UniXNU"};
STATIC struct {UINT8 Length,Type; CHAR16 Text[16];} mProduct = {32,3,L"PDX234 UEFI log"};
STATIC struct {UINT8 Length,Type; CHAR16 Text[13];} mSerial = {26,3,L"PDX234UEFI01"};
#pragma pack()
STATIC VOID *mHsConfigs[] = {mConfigHs};
STATIC VOID *mSsConfigs[] = {mConfigSs};
STATIC EFI_USB_STRING_DESCRIPTOR *mStrings[] = {
  (VOID *)mLanguage,(VOID *)&mManufacturer,(VOID *)&mProduct,(VOID *)&mSerial
};
STATIC USB_DEVICE_DESCRIPTOR_SET mDescriptors = {
  (VOID *)mDeviceHs,mHsConfigs,(VOID *)mDeviceSs,mSsConfigs,
  (VOID *)mQualifier,mBos,4,mStrings
};

STATIC VOID StallControl (VOID)
{
  mControlStage=0;
  mDevice->SetEndpointStallState(0,TRUE);
}

STATIC EFI_STATUS SubmitControl (UINT8 Endpoint, UINTN Size)
{
  EFI_STATUS Status=mDevice->Send(Endpoint,Size,mControl);
  if (!EFI_ERROR(Status)) {mControlBusy=TRUE;mControlStale=FALSE;mControlEndpoint=Endpoint;}
  return Status;
}

STATIC VOID BeginSetup (EFI_USB_DEVICE_REQUEST *Request)
{
  EFI_STATUS Status=EFI_UNSUPPORTED;
  mControlStage=0;
  if (Request->Index!=0) {StallControl();return;}
  if (Request->RequestType==0x21 && Request->Request==0x20 && Request->Value==0 && Request->Length==7) {
    mControlStage=1; // data OUT, then status IN
    Status=SubmitControl(0,7);
  } else if (Request->RequestType==0xa1 && Request->Request==0x21 && Request->Value==0 && Request->Length==7) {
    CopyMem(mControl,mLineCoding,7);
    mControlStage=2; // data IN, then status OUT
    Status=SubmitControl(0x80,7);
  } else if (Request->RequestType==0x21 && Request->Request==0x22 && Request->Length==0 && (Request->Value&~3U)==0) {
    mDtr=(Request->Value&1)!=0;
    mControlStage=3;
    Status=SubmitControl(0x80,0);
  }
  if (EFI_ERROR(Status)) StallControl();
}

STATIC VOID Setup (EFI_USB_DEVICE_REQUEST *Request)
{
  // UEFI 17.3.11: AbortTransfer is not a buffer ownership handback. Wait for
  // the matching terminal notification before touching the shared EP0 buffer.
  if (mControlBusy) {
    CopyMem(&mPendingSetup,Request,sizeof(*Request));mSetupPending=TRUE;
    if (!mAborting) {
      EFI_STATUS Status=mDevice->AbortXfer(mControlEndpoint);
      if (EFI_ERROR(Status)) {mPollStatus=Status;mStarted=FALSE;return;}
      mAborting=TRUE;
    }
    return;
  }
  BeginSetup(Request);
}

STATIC VOID Completion (USB_DEVICE_TRANSFER_OUTCOME *Result)
{
  EFI_STATUS Status;
  // Active is an update, not completion. Unknown status retains ownership too.
  if (Result->Status!=UsbDeviceTransferStatusCompleteOK &&
      Result->Status!=UsbDeviceTransferStatusCancelled &&
      Result->Status!=UsbDeviceTransferStatusCompleteError) return;
  if ((Result->EndpointIndex&0x7f)==0 && Result->DataBuffer==mControl) {
    if (!mControlBusy || Result->EndpointIndex!=mControlEndpoint) return;
    mControlBusy=FALSE;mAborting=FALSE;
    if (mSetupPending) {
      mSetupPending=FALSE;BeginSetup(&mPendingSetup);return;
    }
    // A completion from before disconnect only returns buffer ownership.
    if (mControlStale) {mControlStale=FALSE;mControlStage=0;return;}
    if (Result->Status!=UsbDeviceTransferStatusCompleteOK) {mControlStage=0;return;}
    if (mControlStage==1 && Result->EndpointIndex==0 && Result->BytesCompleted==7) {
      CopyMem(mLineCoding,mControl,7);mControlStage=3;
      Status=SubmitControl(0x80,0);
      if (EFI_ERROR(Status)) StallControl();
    } else if (mControlStage==2 && Result->EndpointIndex==0x80 && Result->BytesCompleted==7) {
      mControlStage=3;
      Status=SubmitControl(0,0);
      if (EFI_ERROR(Status)) StallControl();
    } else if (mControlStage==1 || mControlStage==2) {StallControl();}
    else {mControlStage=0;}
  } else if (Result->EndpointIndex==0x83 && Result->DataBuffer==mTx) {
    if (!mTxBusy) return;
    mTxBusy=FALSE;
    if (mTxStale) {mTxStale=FALSE;return;}
    if (Result->Status==UsbDeviceTransferStatusCompleteOK && Result->BytesCompleted<=mTxSize-mTxDone) {
      mTxDone+=Result->BytesCompleted;
      if (mTxDone==mTxSize) mBannerSent=TRUE;
    }
  } else if (Result->EndpointIndex==2 && Result->DataBuffer==mRx) {
    if (!mRxBusy) return;
    mRxBusy=FALSE; // Input is consumed; firmware exposes no command/reset channel.
  }
}

STATIC VOID Poll (VOID)
{
  EFI_STATUS Status;
  if (!mStarted) return;
  for (UINTN Index=0;Index<32;++Index) {
    USB_DEVICE_EVENT Kind=UsbDeviceEventNoEvent;
    USB_DEVICE_EVENT_DATA Data;
    UINTN Size=sizeof(Data);
    ZeroMem(&Data,sizeof(Data));
    if(mPollCalls<4) DEBUG((DEBUG_ERROR,"PDX USB boundary: HandleEvent[%u] enter\n",(UINT32)mPollCalls));
    PdxUsbBoundaryPhase(3);
    if(mPollCalls==0) PdxUsbBoundaryProbeCore(0);
    Status=mDevice->HandleEvent(&Kind,&Size,&Data);
    PdxUsbBoundaryPhase(4);
    if(mPollCalls<4) DEBUG((DEBUG_ERROR,"PDX USB boundary: HandleEvent[%u] return %r event=%u\n",(UINT32)mPollCalls,Status,(UINT32)Kind));
    mPollCalls++;
    if (EFI_ERROR(Status)) {
      DEBUG((DEBUG_ERROR,"PDX CDC: HandleEvent: %r\n",Status));
      mPollStatus=Status;mStarted=FALSE;return;
    }
    // Sony returns the size of the active union member, not the entire union.
    // Validate before reading fields, freeing an OEM pointer or returning DMA
    // ownership. A truncated completion cannot release an outstanding buffer.
    if (Size>sizeof(Data) ||
        (Kind==UsbDeviceEventDeviceStateChange && Size<sizeof(Data.DeviceState)) ||
        (Kind==UsbDeviceEventTransferNotification && Size<sizeof(Data.TransferOutcome)) ||
        (Kind==UsbDeviceEventOemEvent && Size<sizeof(Data.OemData))) {
      mPollStatus=EFI_BAD_BUFFER_SIZE;mStarted=FALSE;return;
    }
    if (Kind==UsbDeviceEventNoEvent) break;
    if (Kind==UsbDeviceEventDeviceStateChange) {
      mConnected=Data.DeviceState==UsbDeviceStateConnected;
      // A state event does not release outstanding DMA buffers. Their matching
      // canceled/completed notifications release ownership independently.
      if (!mConnected) {
        mDtr=FALSE;mSetupPending=FALSE;mControlStage=0;
        mControlStale=mControlBusy;mTxStale=mTxBusy;
        // Start the next connection at byte zero, but keep the old DMA buffer
        // busy until its terminal event. Reconnect does not make it reusable.
        mBannerSent=FALSE;mTxDone=0;
      }
      DEBUG((DEBUG_ERROR,"PDX CDC: configured=%u\n",mConnected));
    } else if (Kind==UsbDeviceEventOemEvent) {
      if (CompareMem(&Data.OemData.DataGuid,&mSetupGuid,sizeof(EFI_GUID))==0 &&
          Data.OemData.Context!=NULL && Data.OemData.Size==sizeof(EFI_USB_DEVICE_REQUEST)) {
        Setup(Data.OemData.Context);
      }
      if (Data.OemData.Context!=NULL) FreePool(Data.OemData.Context);
    } else if (Kind==UsbDeviceEventTransferNotification) Completion(&Data.TransferOutcome);
    if (!mStarted) return;
  }
  if (mConnected && mDtr && !mTxBusy && !mBannerSent) {
    // Retry only the uncompleted suffix; do not advance on queue submission.
    CopyMem(mTx,mBanner+mTxDone,mTxSize-mTxDone);
    Status=mDevice->Send(0x83,mTxSize-mTxDone,mTx);
    if (!EFI_ERROR(Status)) {mTxBusy=TRUE;mTxStale=FALSE;}
  }
  if (mConnected && !mRxBusy) {
    Status=mDevice->Send(2,1024,mRx); // whole packet at HS (512) and SS (1024)
    if (!EFI_ERROR(Status)) mRxBusy=TRUE;
  }
}

EFI_STATUS PdxUsbCdcPump (VOID)
{
  EFI_TPL OldTpl=gBS->RaiseTPL(TPL_HIGH_LEVEL);
  gBS->RestoreTPL(OldTpl);
  if(OldTpl!=TPL_APPLICATION) return EFI_UNSUPPORTED;
  if(!mStarted) return EFI_ERROR(mPollStatus)?mPollStatus:EFI_NOT_READY;
  Poll();
  return mStarted?EFI_SUCCESS:(EFI_ERROR(mPollStatus)?mPollStatus:EFI_DEVICE_ERROR);
}

STATIC VOID EFIAPI Exit (EFI_EVENT Event, VOID *Context)
{
  (VOID)Event;(VOID)Context;
  // Do not free DMA buffers in EBS notification. Vendor owns its shutdown;
  // stopping the event pump prevents any further protocol calls after handoff.
  mStarted=FALSE;
  DEBUG((DEBUG_ERROR,"PDX CDC: ExitBootServices pump stopped; vendor shutdown owns DMA\n"));
  PdxUsbBoundaryStop();
  // UEFI 7.1.2: timer services have already been deactivated at EBS. Do not
  // depend on them here or call vendor services with unspecified callback order.
}

EFI_STATUS PdxUsbCdcStart (VOID)
{
  EFI_STATUS Status;
  EFI_TPL OldTpl=gBS->RaiseTPL(TPL_HIGH_LEVEL);
  gBS->RestoreTPL(OldTpl);
  if(OldTpl!=TPL_APPLICATION) return EFI_UNSUPPORTED;
  if (mStartAttempted) return EFI_ALREADY_STARTED;
  mStartAttempted=TRUE;
  PdxUsbBoundaryInit();
  PdxUsbBoundaryPhase(1);
  Status=gBS->LocateProtocol(&gEfiUsbDeviceProtocolGuid,NULL,(VOID **)&mDevice);
  if (EFI_ERROR(Status)) goto FailBoundary;
  if (mDevice==NULL || mDevice->Revision<EFI_USB_DEVICE_PROTOCOL_REVISION || mDevice->StartEx==NULL ||
      mDevice->HandleEvent==NULL || mDevice->AllocateTransferBuffer==NULL ||
      mDevice->Send==NULL || mDevice->Stop==NULL || mDevice->FreeTransferBuffer==NULL || mDevice->AbortXfer==NULL ||
      mDevice->SetEndpointStallState==NULL) {Status=EFI_UNSUPPORTED;goto FailBoundary;}
  Status=mDevice->StartEx(&mDescriptors);
  PdxUsbBoundaryPhase(2);
  DEBUG((DEBUG_ERROR,"PDX CDC: StartEx descriptors: %r\n",Status));
  if (EFI_ERROR(Status)) goto FailBoundary;
  PdxUsbBoundaryProbePrepared();
  Status=mDevice->AllocateTransferBuffer(512,&mControl);
  if (!EFI_ERROR(Status)) Status=mDevice->AllocateTransferBuffer(512,&mTx);
  if (!EFI_ERROR(Status)) Status=mDevice->AllocateTransferBuffer(1024,&mRx);
  if (EFI_ERROR(Status)) goto Fail;
  DEBUG((DEBUG_ERROR,"PDX CDC: client DMA control=%p tx=%p rx=%p\n",mControl,mTx,mRx));
  Status=gBS->CreateEventEx(EVT_NOTIFY_SIGNAL,TPL_CALLBACK,Exit,NULL,&gEfiEventExitBootServicesGuid,&mExitEvent);
  if (EFI_ERROR(Status)) goto Fail;
  mTxSize=sizeof(mBanner)-1;mStarted=TRUE;
  mPollStatus=EFI_SUCCESS;
  return EFI_SUCCESS;
Fail:
  mStarted=FALSE;
  if (mExitEvent!=NULL) {gBS->CloseEvent(mExitEvent);mExitEvent=NULL;}
  // No client transfers have been queued before successful timer setup.
  // EFIUsbDevice.h: no protocol calls are allowed after Stop(), so release
  // these idle client buffers first. Vendor internal buffers belong to Stop.
  if (mDevice->FreeTransferBuffer!=NULL) {
    if (mControl!=NULL) mDevice->FreeTransferBuffer(mControl);
    if (mTx!=NULL) mDevice->FreeTransferBuffer(mTx);
    if (mRx!=NULL) mDevice->FreeTransferBuffer(mRx);
  }
  mControl=NULL;mTx=NULL;mRx=NULL;
  mDevice->Stop();
FailBoundary:
  mPollStatus=Status;
  PdxUsbBoundaryStop();
  return Status;
}
