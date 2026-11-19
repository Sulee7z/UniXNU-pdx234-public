// Actual CDC source compiled against EDK II headers with modeled protocol I/O.
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "PdxUsbCdc.c"

EFI_BOOT_SERVICES *gBS;
EFI_GUID gEfiUsbDeviceProtocolGuid;
EFI_GUID gEfiEventExitBootServicesGuid;
static int boundary_inits,boundary_stops,boundary_active,prepared_probes;
VOID PdxUsbBoundaryInit(VOID) {++boundary_inits;boundary_active=1;}
VOID PdxUsbBoundaryPhase(UINTN Phase) {(void)Phase;}
VOID PdxUsbBoundaryStop(VOID) {++boundary_stops;boundary_active=0;}
VOID PdxUsbBoundaryProbeCore(UINTN Sequence) {(void)Sequence;}
VOID PdxUsbBoundaryProbePrepared(VOID) {++prepared_probes;}
VOID *EFIAPI CopyMem(VOID *d,CONST VOID *s,UINTN n) {return memmove(d,s,n);}
VOID *EFIAPI ZeroMem(VOID *d,UINTN n) {return memset(d,0,n);}
INTN EFIAPI CompareMem(CONST VOID *a,CONST VOID *b,UINTN n) {return memcmp(a,b,n);}
VOID EFIAPI FreePool(VOID *p) {free(p);}
BOOLEAN EFIAPI DebugPrintEnabled(VOID) {return FALSE;}
BOOLEAN EFIAPI DebugPrintLevelEnabled(CONST UINTN n) {(void)n;return FALSE;}
VOID EFIAPI DebugPrint(UINTN n,CONST CHAR8 *s,...) {(void)n;(void)s;}

static UINT8 endpoint;
static UINTN length;
static int sends,stalls,aborts;
static EFI_STATUS send_status,abort_status;
static EFI_TPL current_tpl=TPL_APPLICATION;
static EFI_TPL EFIAPI Raise(EFI_TPL value) {EFI_TPL old=current_tpl;assert(value>=old);current_tpl=value;return old;}
static VOID EFIAPI Restore(EFI_TPL value) {assert(value<=current_tpl);current_tpl=value;}
static EFI_USB_DEVICE_PROTOCOL startup_proto;
static int startup_step,fail_step,allocated,freed,stopped,created,closed;
static int null_provider;
static EFI_STATUS Step(void) {return ++startup_step==fail_step?EFI_DEVICE_ERROR:EFI_SUCCESS;}
static EFI_STATUS EFIAPI Locate(EFI_GUID *guid,VOID *registration,VOID **interface) {
  (void)guid;(void)registration;assert(!stopped);EFI_STATUS s=Step();
  if(!EFI_ERROR(s))*interface=null_provider?NULL:&startup_proto;return s;
}
static EFI_STATUS Start(USB_DEVICE_DESCRIPTOR_SET *desc) {
  assert(!stopped&&allocated==0&&desc==&mDescriptors);return Step();
}
static EFI_STATUS EFIAPI Allocate(UINTN size,VOID **buffer) {
  assert(!stopped);EFI_STATUS s=Step();if(!EFI_ERROR(s)){*buffer=calloc(1,size);assert(*buffer);++allocated;}return s;
}
static EFI_STATUS EFIAPI Release(VOID *buffer) {assert(!stopped);++freed;free(buffer);return EFI_SUCCESS;}
static EFI_STATUS Stop(void) {assert(!stopped&&freed==allocated);stopped=1;return EFI_SUCCESS;}
static EFI_STATUS EFIAPI Create(UINT32 type,EFI_TPL tpl,EFI_EVENT_NOTIFY notify,VOID *context,EFI_EVENT *event) {
  (void)context;(void)type;(void)tpl;(void)notify;assert(0 && "CDC must not create a timer callback");
  EFI_STATUS s=Step();if(!EFI_ERROR(s)){*event=(VOID *)(UINTN)(++created); }return s;
}
static EFI_STATUS EFIAPI CreateEx(UINT32 type,EFI_TPL tpl,EFI_EVENT_NOTIFY notify,CONST VOID *context,CONST EFI_GUID *group,EFI_EVENT *event) {
  (void)context;assert(type==EVT_NOTIFY_SIGNAL&&tpl==TPL_CALLBACK&&notify==Exit&&group==&gEfiEventExitBootServicesGuid);
  EFI_STATUS s=Step();if(!EFI_ERROR(s)){*event=(VOID *)(UINTN)(++created);}return s;
}
static EFI_STATUS EFIAPI Close(EFI_EVENT event) {assert(event!=NULL);++closed;return EFI_SUCCESS;}
static EFI_STATUS EFIAPI StartTimer(EFI_EVENT event,EFI_TIMER_DELAY type,UINT64 delay) {
  assert(event!=NULL&&type==TimerRelative&&delay==10000&&allocated==3);return Step();
}
static int polls,timers,in_handler,fail_handler,continuous_events;
static struct {USB_DEVICE_EVENT kind;UINTN size;USB_DEVICE_EVENT_DATA data;} events[16];
static unsigned event_count,event_index;
static void Queue(USB_DEVICE_EVENT kind,UINTN size,USB_DEVICE_EVENT_DATA data) {
  assert(event_count<16);events[event_count].kind=kind;events[event_count].size=size;
  events[event_count++].data=data;
}
static void State(USB_DEVICE_STATE state) {
  USB_DEVICE_EVENT_DATA data={0};data.DeviceState=state;
  Queue(UsbDeviceEventDeviceStateChange,sizeof(data.DeviceState),data);
}
static void Transfer(UINT8 ep,UINTN n,USB_DEVICE_TRANSFER_STATUS status,VOID *buffer) {
  USB_DEVICE_EVENT_DATA data={0};
  data.TransferOutcome=(USB_DEVICE_TRANSFER_OUTCOME){status,ep,n,buffer};
  Queue(UsbDeviceEventTransferNotification,sizeof(data.TransferOutcome),data);
}
static void PumpEvents(void) {
  assert(PdxUsbCdcPump()==EFI_SUCCESS);assert(event_index==event_count);
  event_count=event_index=0;
}
static EFI_TIMER_DELAY timer_type;
static EFI_STATUS EFIAPI Timer(EFI_EVENT e,EFI_TIMER_DELAY type,UINT64 delay) {
  (void)e;assert(!in_handler);++timers;timer_type=type;
  assert(type==TimerCancel || (type==TimerRelative && delay==10000));return 0;
}
static EFI_STATUS EFIAPI Event(USB_DEVICE_EVENT *kind,UINTN *size,USB_DEVICE_EVENT_DATA *data) {
  assert(current_tpl==TPL_APPLICATION);
  in_handler=1;++polls;
  // Simulate a vendor call that occupies many 1ms periods. There must be no
  // outstanding periodic timer to replenish this same callback's queue.
  assert(timers==0);
  if(event_index<event_count) {
    *kind=events[event_index].kind;*size=events[event_index].size;
    *data=events[event_index++].data;in_handler=0;return EFI_SUCCESS;
  }
  *kind=continuous_events?UsbDeviceEventTransferNotification:UsbDeviceEventNoEvent;
  *size=sizeof(*data);memset(data,0,sizeof(*data));
  data->TransferOutcome.EndpointIndex=0x81;
  in_handler=0;return fail_handler?EFI_DEVICE_ERROR:0;
}
static EFI_STATUS Send(UINT8 ep,UINTN size,VOID *buffer) {
  assert(buffer!=NULL);endpoint=ep;length=size;++sends;return send_status;
}
static EFI_STATUS EFIAPI Stall(UINT8 ep,BOOLEAN state) {assert(ep==0&&state);++stalls;return 0;}
static EFI_STATUS Abort(UINT8 ep) {(void)ep;++aborts;return abort_status;}
static void Complete(UINT8 ep,UINTN n,USB_DEVICE_TRANSFER_STATUS status,VOID *buffer) {
  USB_DEVICE_TRANSFER_OUTCOME r={status,ep,n,buffer};Completion(&r);
}
static void Descriptors(UINT8 *d,UINTN size,int superspeed) {
  assert(d[2]+256*d[3]==size && d[4]==2);
  unsigned interfaces=0,endpoints=0,companions=0;
  for(UINTN pos=0;pos<size;) {
    assert(d[pos]>=2&&pos+d[pos]<=size);
    if(d[pos+1]==4) ++interfaces;
    if(d[pos+1]==5) {
      ++endpoints;
      if(superspeed) assert(d[pos+8]==0x30);
    }
    if(d[pos+1]==0x30) ++companions;
    pos+=d[pos];
  }
  assert(interfaces==2&&endpoints==3&&companions==(superspeed?3:0));
}
int main(void) {
  static EFI_USB_DEVICE_PROTOCOL proto;
  static EFI_BOOT_SERVICES bs;
  static UINT8 control[512],tx[512],rx[1024];
  proto.Send=Send;proto.SetEndpointStallState=Stall;proto.AbortXfer=Abort;
  mDevice=&proto;mControl=control;mTx=tx;
  Descriptors(mConfigHs,sizeof(mConfigHs),0);Descriptors(mConfigSs,sizeof(mConfigSs),1);
  assert(mManufacturer.Length==14&&mProduct.Length==32&&mSerial.Length==26);
  EFI_USB_DEVICE_REQUEST r={0x21,0x20,0,0,7};
  Setup(&r);assert(endpoint==0&&length==7&&mControlStage==1);
  UINT8 coding[]={0x80,0x25,0,0,0,0,8};memcpy(control,coding,7);
  Complete(0,7,UsbDeviceTransferStatusCompleteOK,control);
  assert(endpoint==0x80&&length==0&&memcmp(mLineCoding,coding,7)==0);
  Complete(0x80,0,UsbDeviceTransferStatusCompleteOK,control);assert(mControlStage==0);
  r.RequestType=0xa1;r.Request=0x21;Setup(&r);
  assert(endpoint==0x80&&length==7&&memcmp(control,coding,7)==0);
  Complete(0x80,7,UsbDeviceTransferStatusCompleteOK,control);assert(endpoint==0&&length==0);
  Complete(0,0,UsbDeviceTransferStatusCompleteOK,control);assert(mControlStage==0);
  r.RequestType=0x21;r.Request=0x22;r.Value=3;r.Length=0;Setup(&r);assert(mDtr&&endpoint==0x80&&length==0);
  Complete(0x80,0,UsbDeviceTransferStatusCompleteOK,control);
  int before=sends;r.Index=1;Setup(&r);assert(stalls==1&&sends==before);
  r.Index=0;r.Request=0x20;r.Value=0;r.Length=6;Setup(&r);assert(stalls==2);
  r.Length=7;Setup(&r);before=sends;Setup(&r);assert(aborts==1&&sends==before&&mControlBusy);
  Complete(0,0,UsbDeviceTransferStatusActive,control);assert(mControlBusy&&sends==before);
  Complete(0,0,UsbDeviceTransferStatusCancelled,control);assert(mControlStage==1&&mControlBusy&&sends==before+1);
  Complete(0,0,UsbDeviceTransferStatusCancelled,control);assert(mControlStage==0&&!mControlBusy);
  send_status=EFI_DEVICE_ERROR;Setup(&r);assert(stalls==3&&mControlStage==0);send_status=0;
  Setup(&r);Complete(0,3,UsbDeviceTransferStatusCompleteOK,control);assert(stalls==4&&mControlStage==0);
  mTxSize=10;mTxDone=0;mTxBusy=TRUE;
  Complete(0x83,2,UsbDeviceTransferStatusActive,tx);assert(mTxBusy&&mTxDone==0);
  Complete(0x83,10,UsbDeviceTransferStatusCancelled,tx);assert(!mTxBusy&&mTxDone==0&&!mBannerSent);
  mTxBusy=TRUE;
  Complete(0x83,4,UsbDeviceTransferStatusCompleteOK,tx);assert(mTxDone==4&&!mBannerSent);
  mTxBusy=TRUE;
  Complete(0x83,7,UsbDeviceTransferStatusCompleteOK,tx);assert(mTxDone==4);
  mTxBusy=TRUE;
  Complete(0x83,6,UsbDeviceTransferStatusCompleteOK,tx);assert(mTxDone==10&&mBannerSent);
  gBS=&bs;bs.SetTimer=Timer;bs.RaiseTPL=Raise;bs.RestoreTPL=Restore;proto.HandleEvent=Event;
  mStarted=TRUE;mConnected=FALSE;
  current_tpl=TPL_CALLBACK;assert(PdxUsbCdcPump()==EFI_UNSUPPORTED&&polls==0);
  assert(PdxUsbCdcStart()==EFI_UNSUPPORTED&&!mStartAttempted);
  current_tpl=TPL_APPLICATION;
  assert(PdxUsbCdcPump()==EFI_SUCCESS);assert(polls==1&&timers==0);
  polls=timers=0;continuous_events=1;
  assert(PdxUsbCdcPump()==EFI_SUCCESS);assert(polls==32&&timers==0);
  polls=timers=0;continuous_events=0;fail_handler=1;
  assert(PdxUsbCdcPump()==EFI_DEVICE_ERROR);assert(polls==1&&timers==0&&!mStarted);
  timers=0;Exit(NULL,NULL);assert(!mStarted&&timers==0);
  polls=timers=0;PdxUsbCdcPump();assert(polls==0&&timers==0);
  // A new connection must get the entire banner even when the old transfer
  // completes successfully after reconnect. No state event releases its DMA.
  fail_handler=0;mStarted=TRUE;mPollStatus=EFI_SUCCESS;mConnected=TRUE;
  mDtr=TRUE;mTx=tx;mRx=rx;mRxBusy=TRUE;mTxSize=sizeof(mBanner)-1;
  mTxDone=5;mBannerSent=FALSE;mTxBusy=TRUE;
  memset(tx,0x5a,sizeof(tx));before=sends;
  State(UsbDeviceStateDisconnected);State(UsbDeviceStateConnected);PumpEvents();
  assert(!mDtr&&mTxBusy&&mRxBusy&&mTxDone==0&&!mBannerSent&&sends==before);
  for(unsigned i=0;i<sizeof(tx);++i)assert(tx[i]==0x5a);
  mDtr=TRUE;
  Transfer(0x83,mTxSize-5,UsbDeviceTransferStatusCompleteOK,tx);PumpEvents();
  assert(mTxBusy&&mTxDone==0&&!mBannerSent&&sends==before+1);
  assert(endpoint==0x83&&length==mTxSize&&memcmp(tx,mBanner,mTxSize)==0);
  Transfer(0x83,4,UsbDeviceTransferStatusCompleteOK,tx);PumpEvents();
  assert(mTxDone==4&&length==mTxSize-4&&memcmp(tx,mBanner+4,length)==0);
  // A duplicate connected notification cannot restart partial accounting.
  State(UsbDeviceStateConnected);PumpEvents();assert(mTxDone==4&&mTxBusy);
  Transfer(0x83,mTxSize-4,UsbDeviceTransferStatusCompleteOK,tx);PumpEvents();
  assert(mBannerSent&&!mTxBusy&&mTxDone==mTxSize);
  // Cancel-before-reconnect and late error completions also restart at zero.
  State(UsbDeviceStateDisconnected);PumpEvents();assert(mTxDone==0&&!mBannerSent);
  State(UsbDeviceStateConnected);mDtr=TRUE;PumpEvents();assert(mTxBusy);
  State(UsbDeviceStateDisconnected);
  Transfer(0x83,0,UsbDeviceTransferStatusCancelled,tx);PumpEvents();
  assert(!mTxBusy&&mTxDone==0);
  State(UsbDeviceStateConnected);mDtr=TRUE;PumpEvents();assert(mTxBusy);
  State(UsbDeviceStateDisconnected);State(UsbDeviceStateConnected);
  Transfer(0x83,0,UsbDeviceTransferStatusCompleteError,tx);PumpEvents();
  assert(!mTxBusy&&mTxDone==0&&!mBannerSent);
  // Old SET_LINE_CODING completion must not update state or submit status.
  mControl=control;mControlBusy=FALSE;r=(EFI_USB_DEVICE_REQUEST){0x21,0x20,0,0,7};
  Setup(&r);before=sends;memset(control,0xff,7);
  State(UsbDeviceStateDisconnected);State(UsbDeviceStateConnected);
  Transfer(0,7,UsbDeviceTransferStatusCompleteOK,control);PumpEvents();
  assert(!mControlBusy&&mControlStage==0&&sends==before&&memcmp(mLineCoding,coding,7)==0);
  // A new SETUP waits for the old generation's ownership return, then runs.
  Setup(&r);State(UsbDeviceStateDisconnected);State(UsbDeviceStateConnected);PumpEvents();
  before=sends;Setup(&r);assert(mSetupPending&&mControlBusy&&sends==before);
  Transfer(0,0,UsbDeviceTransferStatusCancelled,control);PumpEvents();
  assert(mControlBusy&&!mSetupPending&&mControlStage==1&&sends==before+1);
  Complete(0,0,UsbDeviceTransferStatusCancelled,control);
  // Preserve the original AbortXfer failure through the actual event pump.
  Setup(&r);abort_status=EFI_TIMEOUT;
  USB_DEVICE_EVENT_DATA data={0};data.OemData.DataGuid=mSetupGuid;
  data.OemData.Size=sizeof(r);data.OemData.Context=malloc(sizeof(r));
  memcpy(data.OemData.Context,&r,sizeof(r));
  Queue(UsbDeviceEventOemEvent,sizeof(data.OemData),data);
  assert(PdxUsbCdcPump()==EFI_TIMEOUT&&!mStarted&&mControlBusy);
  assert(PdxUsbCdcPump()==EFI_TIMEOUT);event_count=event_index=0;abort_status=0;
  mSetupPending=FALSE;Complete(0,0,UsbDeviceTransferStatusCancelled,control);
  // Reject every truncated union member and oversized event before accessing
  // fields. An invalid OEM pointer must never be freed on a malformed event.
  USB_DEVICE_EVENT kinds[]={UsbDeviceEventDeviceStateChange,UsbDeviceEventTransferNotification,UsbDeviceEventOemEvent};
  UINTN sizes[]={sizeof(data.DeviceState),sizeof(data.TransferOutcome),sizeof(data.OemData)};
  for(unsigned k=0;k<3;++k)for(unsigned bad=0;bad<3;++bad) {
    mStarted=TRUE;mPollStatus=EFI_SUCCESS;mTxBusy=TRUE;
    memset(&data,0,sizeof(data));data.OemData.Context=(VOID *)(UINTN)1;
    Queue(kinds[k],bad==0?0:bad==1?sizes[k]-1:sizeof(data)+1,data);
    assert(PdxUsbCdcPump()==EFI_BAD_BUFFER_SIZE&&!mStarted&&mTxBusy);
    assert(PdxUsbCdcPump()==EFI_BAD_BUFFER_SIZE);event_count=event_index=0;
  }
  // Exercise actual startup, including every error exit. No I/O buffer may
  // be released after Stop, and EBS must perform no timer/protocol operation.
  startup_proto=proto;startup_proto.Revision=EFI_USB_DEVICE_PROTOCOL_REVISION;
  startup_proto.StartEx=Start;startup_proto.AllocateTransferBuffer=Allocate;
  startup_proto.FreeTransferBuffer=Release;startup_proto.Stop=Stop;
  bs.LocateProtocol=Locate;bs.CreateEvent=Create;bs.CreateEventEx=CreateEx;
  bs.CloseEvent=Close;bs.SetTimer=StartTimer;
  for(int failure=1;failure<=6;++failure) {
    startup_step=allocated=freed=stopped=created=closed=0;fail_step=failure;
    mStartAttempted=mStarted=FALSE;mExitEvent=NULL;mControl=mTx=mRx=NULL;
    int bi=boundary_inits,bc=boundary_stops;
    assert(EFI_ERROR(PdxUsbCdcStart()));assert(allocated==freed&&created==closed);
    assert(!mStarted&&stopped==(failure>=3));
    assert(boundary_inits==bi+1&&boundary_stops==bc+1&&!boundary_active);
    assert(PdxUsbCdcPump()==EFI_DEVICE_ERROR);
  }
  for(int invalid=0;invalid<3;++invalid) {
    startup_step=allocated=freed=stopped=created=closed=0;fail_step=0;
    mStartAttempted=mStarted=FALSE;mExitEvent=NULL;mControl=mTx=mRx=NULL;
    null_provider=invalid==0;
    startup_proto.Revision=invalid==1?0:EFI_USB_DEVICE_PROTOCOL_REVISION;
    startup_proto.StartEx=invalid==2?NULL:Start;
    int bc=boundary_stops;
    assert(PdxUsbCdcStart()==EFI_UNSUPPORTED&&!stopped&&!allocated);
    assert(boundary_stops==bc+1&&!boundary_active);
  }
  null_provider=0;startup_proto.StartEx=Start;
  startup_step=allocated=freed=stopped=created=closed=0;fail_step=0;
  mStartAttempted=mStarted=FALSE;mExitEvent=NULL;mControl=mTx=mRx=NULL;
  int prepared=prepared_probes;
  assert(PdxUsbCdcStart()==EFI_SUCCESS&&mStarted&&allocated==3);
  assert(prepared_probes==prepared+1&&boundary_active);
  assert(PdxUsbCdcStart()==EFI_ALREADY_STARTED);
  int steps=startup_step;Exit(NULL,NULL);assert(!mStarted&&startup_step==steps&&!stopped);
  assert(!boundary_active);
  // Model firmware reclaim only after device DMA has stopped.
  free(mControl);free(mTx);free(mRx);
  puts("PASS actual CDC descriptors, class stages, stalls, aborts and completion accounting");
  puts("PASS application-only polling/start, callback refusal, 32-event budget and EBS stop");
  puts("PASS all startup failures, free-before-stop, one-shot start and EBS without external calls");
  puts("PASS disconnect/reconnect DMA ownership, stale control/TX completions and full-banner restart");
  puts("PASS malformed event sizes, AbortXfer error preservation and startup boundary cleanup");
}
