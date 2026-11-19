// SPDX-License-Identifier: BSD-2-Clause-Patent
#ifndef PDX_USB_SERVICE_H
#define PDX_USB_SERVICE_H
#include <Uefi.h>
#define PDX_USB_SERVICE_GUID {0x765f0768,0xb70e,0x43cc,{0x91,0x7d,0x8f,0x21,0x31,0x69,0xdc,0x42}}
typedef struct {
  UINT64 Revision;
  EFI_EVENT WakeEvent;
  EFI_STATUS (EFIAPI *Service)(VOID);
} PDX_USB_SERVICE;
#endif
