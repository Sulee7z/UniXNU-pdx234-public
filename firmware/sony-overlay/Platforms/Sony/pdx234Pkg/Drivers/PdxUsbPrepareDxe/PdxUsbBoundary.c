// SPDX-License-Identifier: BSD-2-Clause-Patent
// Bounded evidence for the unresolved first-attach power-off. Observe the
// standard reset notification; never replace ResetSystem or change its result.
#include <Uefi.h>
#include <Protocol/ResetNotification.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/IoLib.h>

STATIC EFI_GUID mResetGuid=EFI_RESET_NOTIFICATION_PROTOCOL_GUID;
STATIC UINTN mPhase;
VOID PdxUsbBoundaryProbeCore(UINTN Sequence);
// ABI prefix from Sony BOOT.MXF.2.1.1 EFIUsbPwrCtrl.h. Only the query slot
// at offset0x20 is instrumented; other methods and the original table remain.
typedef EFI_STATUS (EFIAPI *PDX_CHARGER_QUERY)(UINT8 Port,UINT32 *Type);
typedef struct {
  UINT64 Revision;
  VOID *GetHwInfo;
  VOID *GetVbusDetectStatus;
  VOID *GetVbusSrcOkStatus;
  PDX_CHARGER_QUERY GetHsUsbChgPortType;
} PDX_POWER_PREFIX;
STATIC EFI_GUID mPowerGuid={0xe07df17e,0xe79e,0x4150,{0x93,0x78,0x50,0x62,0x3a,0x14,0x99,0x4a}};
STATIC PDX_POWER_PREFIX *mPower;
STATIC PDX_CHARGER_QUERY mQuery;
STATIC UINTN mQueryCount;

STATIC EFI_STATUS EFIAPI ObserveQuery(UINT8 Port,UINT32 *Type)
{
  EFI_STATUS Status;
  UINTN Previous=mPhase;
  UINTN Sequence=mQueryCount++;
  mPhase=5;
  if(Sequence<4) DEBUG((DEBUG_ERROR,"PDX USB boundary: charger[%u] enter port=%u\n",(UINT32)Sequence,Port));
  Status=mQuery(Port,Type);
  mPhase=6;
  if(Sequence<4) DEBUG((DEBUG_ERROR,"PDX USB boundary: charger[%u] return %r type=%u\n",(UINT32)Sequence,Status,
                       (!EFI_ERROR(Status)&&Type!=NULL)?*Type:MAX_UINT32));
  if(Sequence==0) PdxUsbBoundaryProbeCore(1);
  mPhase=Previous;
  return Status;
}

VOID PdxUsbBoundaryStop(VOID)
{
  if(mPower!=NULL && mPower->GetHsUsbChgPortType==ObserveQuery) mPower->GetHsUsbChgPortType=mQuery;
}

STATIC VOID EFIAPI ResetObserved(EFI_RESET_TYPE Type,EFI_STATUS Status,UINTN Size,VOID *Data)
{
  (VOID)Size;(VOID)Data;
  DEBUG((DEBUG_ERROR,"PDX USB boundary: ResetSystem type=%u status=%r phase=%u\n",(UINT32)Type,Status,(UINT32)mPhase));
}

VOID PdxUsbBoundaryPhase(UINTN Phase)
{
  mPhase=Phase;
}

VOID PdxUsbBoundaryProbeCore(UINTN Sequence)
{
  UINT32 id,params,dctl,dsts,evt;
  DEBUG((DEBUG_ERROR,"PDX USB boundary: core[%u] read begin\n",(UINT32)Sequence));
  id=MmioRead32(0x0A60C120);params=MmioRead32(0x0A60C144);
  dctl=MmioRead32(0x0A60C704);dsts=MmioRead32(0x0A60C70C);evt=MmioRead32(0x0A60C40C);
  DEBUG((DEBUG_ERROR,"PDX USB boundary: core[%u] id=%08x params=%08x dctl=%08x dsts=%08x evt=%08x\n",
         (UINT32)Sequence,id,params,dctl,dsts,evt));
}

// One startup snapshot only, after the vendor preparation event completed.
// Each access is preceded by its address so a missing return is unambiguous.
VOID PdxUsbBoundaryProbePrepared(VOID)
{
  STATIC CONST UINTN Registers[]={
    0x0a6f8808,0x0a6f8810,0x0a6f8830,
    0x0a60c110,0x0a60c118,0x0a60c140,0x0a60c1a0,
    0x0a60c200,0x0a60c2c0,0x0a60c700
  };
  for(UINTN Index=0;Index<sizeof(Registers)/sizeof(Registers[0]);++Index) {
    UINT32 Value;
    DEBUG((DEBUG_ERROR,"PDX prep read %lx enter\n",Registers[Index]));
    Value=MmioRead32(Registers[Index]);
    DEBUG((DEBUG_ERROR,"PDX prep read %lx = %08x\n",Registers[Index],Value));
  }
}

VOID PdxUsbBoundaryInit(VOID)
{
  EFI_RESET_NOTIFICATION_PROTOCOL *Reset=NULL;
  EFI_STATUS Status=gBS->LocateProtocol(&mResetGuid,NULL,(VOID **)&Reset);
  if(!EFI_ERROR(Status) && Reset!=NULL) Status=Reset->RegisterResetNotify(Reset,ResetObserved);
  DEBUG((DEBUG_ERROR,"PDX USB boundary: reset observer: %r\n",Status));
  Status=gBS->LocateProtocol(&mPowerGuid,NULL,(VOID **)&mPower);
  if(!EFI_ERROR(Status) && mPower!=NULL && mPower->Revision==0x10003 && mPower->GetHsUsbChgPortType!=NULL) {
    mQuery=mPower->GetHsUsbChgPortType;
    mPower->GetHsUsbChgPortType=ObserveQuery;
    DEBUG((DEBUG_ERROR,"PDX USB boundary: charger query observer installed\n"));
  } else {
    mPower=NULL;
    DEBUG((DEBUG_ERROR,"PDX USB boundary: charger query observer unavailable %r\n",Status));
  }
}
