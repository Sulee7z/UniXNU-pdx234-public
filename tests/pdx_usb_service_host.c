// Exercise the actual application-service glue with modeled Boot Services.
#include <assert.h>
#include <stdio.h>
#include "PdxUsbPrepare.c"
EFI_BOOT_SERVICES *gBS;
EFI_GUID gEfiEventExitBootServicesGuid;
BOOLEAN EFIAPI DebugPrintEnabled(VOID) {return FALSE;}
BOOLEAN EFIAPI DebugPrintLevelEnabled(CONST UINTN n) {(void)n;return FALSE;}
VOID EFIAPI DebugPrint(UINTN n,CONST CHAR8 *s,...) {(void)n;(void)s;}
static EFI_TPL tpl=TPL_APPLICATION;
static int started,pumped,signaled,armed,closed;
static int provider_ready,device_ready,notifications;
static UINT32 signal_type;
static EFI_STATUS start_result,pump_result;
static EFI_TPL EFIAPI Raise(EFI_TPL t) {EFI_TPL old=tpl;assert(t>=old);tpl=t;return old;}
static VOID EFIAPI Restore(EFI_TPL t) {assert(t<=tpl);tpl=t;}
EFI_STATUS PdxUsbCdcStart(VOID) {assert(tpl==TPL_APPLICATION&&signaled==1&&notifications==1&&provider_ready&&device_ready);++started;return start_result;}
EFI_STATUS PdxUsbCdcPump(VOID) {assert(tpl==TPL_APPLICATION&&started==1);++pumped;return pump_result;}
static EFI_STATUS EFIAPI Create(UINT32 type,EFI_TPL t,EFI_EVENT_NOTIFY fn,VOID *ctx,EFI_EVENT *e) {
  (void)t;(void)ctx;assert(type==EVT_TIMER&&fn==NULL);*e=(VOID *)1;return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI CreateEx(UINT32 type,EFI_TPL t,EFI_EVENT_NOTIFY fn,CONST VOID *ctx,CONST EFI_GUID *g,EFI_EVENT *e) {
  (void)ctx;
  if(g==&mStartGroup) {assert(type==EVT_NOTIFY_SIGNAL&&fn==EmptyNotify&&t==TPL_CALLBACK);signal_type=type;*e=(VOID *)2;}
  else {assert(g==&gEfiEventExitBootServicesGuid&&type==EVT_NOTIFY_SIGNAL&&t==TPL_NOTIFY&&fn==ExitService);*e=(VOID *)3;}
  return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI Signal(EFI_EVENT e) {
  assert(e==(VOID *)2);++signaled;
  // Model Mu CoreSignalEvent: type0 does not broadcast a group.
  if(signal_type&EVT_NOTIFY_SIGNAL) ++notifications;
  return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI Locate(EFI_GUID *g,VOID *registration,VOID **p) {
  (void)registration;assert(tpl==TPL_APPLICATION&&notifications==1);
  assert(g==&mUsbfnGuid||g==&mUsbDeviceGuid);
  if((g==&mUsbfnGuid&&!provider_ready)||(g==&mUsbDeviceGuid&&!device_ready))return EFI_NOT_FOUND;
  *p=(VOID *)4;return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI Close(EFI_EVENT e) {assert(e==(VOID *)2);++closed;return EFI_SUCCESS;}
static EFI_STATUS EFIAPI Install(EFI_HANDLE *h,EFI_GUID *g,EFI_INTERFACE_TYPE t,VOID *p) {
  (void)h;assert(g==&mServiceGuid&&t==EFI_NATIVE_INTERFACE&&p==&mService);return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI Timer(EFI_EVENT e,EFI_TIMER_DELAY t,UINT64 delay) {
  assert(e==(VOID *)1&&t==TimerRelative);
  assert((delay==100000&&!mClientStarted)||(delay==10000&&pumped>0));++armed;return EFI_SUCCESS;
}
static void ResetService(void) {
  mExited=mAttempted=mClientStarted=FALSE;mProviderChecks=0;mStatus=EFI_NOT_READY;
  started=pumped=signaled=armed=closed=notifications=0;provider_ready=device_ready=0;
  start_result=pump_result=EFI_SUCCESS;
}
int main(void) {
  EFI_BOOT_SERVICES bs={0};gBS=&bs;
  bs.RaiseTPL=Raise;bs.RestoreTPL=Restore;bs.CreateEvent=Create;bs.CreateEventEx=CreateEx;
  bs.SignalEvent=Signal;bs.CloseEvent=Close;bs.InstallProtocolInterface=Install;bs.SetTimer=Timer;bs.LocateProtocol=Locate;
  assert(PdxUsbPrepareEntry(NULL,NULL)==EFI_SUCCESS&&started==0&&pumped==0);
  tpl=TPL_CALLBACK;assert(Service()==EFI_UNSUPPORTED&&!mAttempted&&started==0);
  tpl=TPL_APPLICATION;
  assert(Service()==EFI_SUCCESS&&started==0&&pumped==0&&signaled==1&&closed==1&&armed==1);
  assert(Service()==EFI_SUCCESS&&started==0&&armed==2); //delayed binding
  provider_ready=1;
  assert(Service()==EFI_SUCCESS&&started==0&&armed==3); //device protocol missing
  device_ready=1;
  assert(Service()==EFI_SUCCESS&&started==1&&pumped==1&&armed==4);
  assert(Service()==EFI_SUCCESS&&started==1&&pumped==2&&signaled==1&&armed==5);
  pump_result=EFI_DEVICE_ERROR;assert(Service()==EFI_DEVICE_ERROR&&pumped==3&&armed==5);
  assert(Service()==EFI_DEVICE_ERROR&&pumped==3&&armed==5);
  ExitService(NULL,NULL);assert(Service()==EFI_UNSUPPORTED&&pumped==3);
  ResetService();provider_ready=device_ready=1;
  start_result=EFI_NOT_FOUND;
  assert(Service()==EFI_SUCCESS&&started==0);
  assert(Service()==EFI_NOT_FOUND&&started==1&&pumped==0&&armed==1);
  assert(Service()==EFI_NOT_FOUND&&started==1);
  ResetService();
  for(int i=0;i<500;i++)assert(Service()==EFI_SUCCESS&&started==0);
  assert(Service()==EFI_TIMEOUT&&started==0&&signaled==1&&armed==500);
  assert(Service()==EFI_TIMEOUT&&armed==500);
  ResetService();assert(Service()==EFI_SUCCESS);ExitService(NULL,NULL);
  provider_ready=device_ready=1;assert(Service()==EFI_UNSUPPORTED&&started==0);
  puts("PASS real application service: SIGNAL broadcast, delayed/missing providers, single start, bounded wait, errors and EBS");
}
