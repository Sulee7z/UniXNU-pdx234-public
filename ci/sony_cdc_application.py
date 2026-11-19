"""Source-qualified optional menu service for application-context USB polling."""
import hashlib

ORIGINAL_SHA='55584eaae32fab3c25afe390c785310f7769512a17d5b84c7b7be43d3d50ec5b'

def apply(text):
    if hashlib.sha256(text.encode()).hexdigest()!=ORIGINAL_SHA:
        raise ValueError('Unknown UniXNU Menu.c input')
    header='''
// Sony optional USB service: execute vendor I/O at application TPL only.
typedef struct {
  UINT64 Revision;
  EFI_EVENT WakeEvent;
  EFI_STATUS (EFIAPI *Service)(VOID);
} PDX_USB_SERVICE;
STATIC EFI_GUID mPdxUsbServiceGuid = {0x765f0768,0xb70e,0x43cc,{0x91,0x7d,0x8f,0x21,0x31,0x69,0xdc,0x42}};
'''
    anchor='#include "Internal.h"'
    if text.count(anchor)!=1:raise ValueError('Unknown menu include')
    text=text.replace(anchor,anchor+'\n'+header)
    text=text.replace('  EFI_EVENT      Events[2];','  EFI_EVENT      Events[3];\n  PDX_USB_SERVICE *UsbService = NULL;\n  UINTN          UsbEventIndex = MAX_UINTN;',1)
    anchor='''  UserActive      = FALSE;
  RotateAccum     = 0;'''
    replacement='''  Status = gBS->LocateProtocol (&mPdxUsbServiceGuid, NULL, (VOID **)&UsbService);
  if (!EFI_ERROR (Status) && UsbService != NULL && UsbService->Revision == 1 &&
      UsbService->WakeEvent != NULL && UsbService->Service != NULL) {
    Status = UsbService->Service ();
    if (!EFI_ERROR (Status)) {
      UsbEventIndex = EventCount;
      Events[EventCount++] = UsbService->WakeEvent;
    } else {
      UniXNULog ("USB application service start: %r", Status);
      UsbService = NULL;
    }
  } else {
    UsbService = NULL;
  }

  UserActive      = FALSE;
  RotateAccum     = 0;'''
    if text.count(anchor)!=1:raise ValueError('Unknown menu event setup')
    text=text.replace(anchor,replacement)
    anchor='''    Previous = Selected;
    if (Signaled == 0) {'''
    replacement='''    if (UsbService != NULL && Signaled == UsbEventIndex) {
      Status = UsbService->Service ();
      if (EFI_ERROR (Status)) {
        UniXNULog ("USB application service stopped: %r", Status);
        // USB wake is appended last. Input/countdown event indexes stay valid.
        EventCount--;
        UsbService = NULL;
      }
      continue;
    }
    Previous = Selected;
    if (Signaled == 0) {'''
    if text.count(anchor)!=1:raise ValueError('Unknown menu dispatch')
    return text.replace(anchor,replacement)
