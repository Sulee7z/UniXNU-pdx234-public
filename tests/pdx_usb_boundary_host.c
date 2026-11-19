// Test the actual passive ResetNotification observer; no reset hook/replacement.
#include <assert.h>
#include <stdio.h>
#include "PdxUsbBoundary.c"
EFI_BOOT_SERVICES *gBS;
static EFI_RESET_SYSTEM registered;
static EFI_STATUS locate_status,register_status;
static int registrations;
static unsigned reads;
static unsigned prepared_reads;
static int prepared;
UINT32 EFIAPI MmioRead32(UINTN address) {
  static const UINTN prep[]={0xa6f8808,0xa6f8810,0xa6f8830,0xa60c110,0xa60c118,0xa60c140,0xa60c1a0,0xa60c200,0xa60c2c0,0xa60c700};
  if(prepared) {assert(prepared_reads<sizeof(prep)/sizeof(prep[0]));assert(address==prep[prepared_reads++]);return 0;}
  static const UINTN addresses[]={0x0A60C120,0x0A60C144,0x0A60C704,0x0A60C70C,0x0A60C40C};
  assert(address==addresses[reads%5]);++reads;return 0;
}
static int queries;
static EFI_STATUS query_status;
static EFI_STATUS EFIAPI Query(UINT8 port,UINT32 *type) {assert(port==0&&mPhase==5);++queries;if(type)*type=3;return query_status;}
static PDX_POWER_PREFIX power={0x10003,NULL,NULL,NULL,Query};
BOOLEAN EFIAPI DebugPrintEnabled(VOID) {return FALSE;}
BOOLEAN EFIAPI DebugPrintLevelEnabled(CONST UINTN n) {(void)n;return FALSE;}
VOID EFIAPI DebugPrint(UINTN n,CONST CHAR8 *s,...) {(void)n;(void)s;}
static EFI_STATUS EFIAPI Register(EFI_RESET_NOTIFICATION_PROTOCOL *p,EFI_RESET_SYSTEM fn) {
  assert(p!=NULL);++registrations;registered=fn;return register_status;
}
static EFI_STATUS EFIAPI Locate(EFI_GUID *g,VOID *r,VOID **p) {
  static EFI_RESET_NOTIFICATION_PROTOCOL proto={Register,NULL};
  assert(r==NULL);
  if(g==&mPowerGuid) {*p=&power;return EFI_SUCCESS;}
  assert(g==&mResetGuid);if(!EFI_ERROR(locate_status))*p=&proto;return locate_status;
}
int main(void) {
  EFI_BOOT_SERVICES bs={0};gBS=&bs;bs.LocateProtocol=Locate;
  locate_status=EFI_NOT_FOUND;PdxUsbBoundaryInit();assert(registrations==0);
  UINT32 type=0;PdxUsbBoundaryPhase(3);
  assert(power.GetHsUsbChgPortType(0,&type)==EFI_SUCCESS&&type==3&&queries==1&&mPhase==3);
  query_status=EFI_DEVICE_ERROR;assert(power.GetHsUsbChgPortType(0,NULL)==EFI_DEVICE_ERROR&&queries==2);
  PdxUsbBoundaryStop();assert(power.GetHsUsbChgPortType==Query);
  assert(reads==5); // only first query sampled
  PdxUsbBoundaryProbeCore(0);assert(reads==10);
  prepared=1;PdxUsbBoundaryProbePrepared();prepared=0;assert(prepared_reads==10);
  locate_status=EFI_SUCCESS;PdxUsbBoundaryInit();assert(registrations==1&&registered==ResetObserved);
  PdxUsbBoundaryPhase(3);registered(EfiResetShutdown,EFI_SUCCESS,0,NULL);assert(mPhase==3);
  PdxUsbBoundaryPhase(4);registered(EfiResetCold,EFI_TIMEOUT,0,NULL);assert(mPhase==4);
  PdxUsbBoundaryStop();register_status=EFI_OUT_OF_RESOURCES;PdxUsbBoundaryInit();assert(registrations==2);
  PdxUsbBoundaryStop();assert(power.GetHsUsbChgPortType==Query);
  puts("PASS passive reset observer: registration failure and notifications return without reset/service calls");
}
