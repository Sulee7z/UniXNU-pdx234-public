// SPDX-License-Identifier: BSD-2-Clause-Patent
// QEMU-only guest CPU observation. Never embedded in the Sony handset firmware.
#include <Uefi.h>
#include <Protocol/SerialIo.h>
#include <Library/BaseLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

STATIC EFI_SERIAL_IO_PROTOCOL *mSerial;
STATIC UINT64 mPointerTarget;
#define READ_REGISTER(Name) ({ UINT64 Value; __asm__ volatile ("mrs %0, " #Name : "=r" (Value)); Value; })
#define WRITE_REGISTER(Name, Value) __asm__ volatile ("msr " #Name ", %0" :: "r" ((UINT64)(Value)) : "memory")

STATIC VOID Log(CONST CHAR8 *Text) {
  if (mSerial != NULL) {
    UINTN Bytes = AsciiStrLen(Text);
    mSerial->Write(mSerial, &Bytes, (VOID *)Text);
  }
  if (gST->ConOut != NULL) Print(L"%a", Text);
}

#define CHECK_KEY(Prefix) do { \
  UINT64 SavedLo = READ_REGISTER(Prefix##KeyLo_EL1); \
  UINT64 SavedHi = READ_REGISTER(Prefix##KeyHi_EL1); \
  WRITE_REGISTER(Prefix##KeyLo_EL1, SavedLo ^ 0x13579BDF2468ACE0ULL); \
  WRITE_REGISTER(Prefix##KeyHi_EL1, SavedHi ^ 0xFEDCBA9876543210ULL); \
  UINT64 ActualLo = READ_REGISTER(Prefix##KeyLo_EL1); \
  UINT64 ActualHi = READ_REGISTER(Prefix##KeyHi_EL1); \
  WRITE_REGISTER(Prefix##KeyLo_EL1, SavedLo); \
  WRITE_REGISTER(Prefix##KeyHi_EL1, SavedHi); \
  __asm__ volatile ("isb" ::: "memory"); \
  if (ActualLo != (SavedLo ^ 0x13579BDF2468ACE0ULL) || \
      ActualHi != (SavedHi ^ 0xFEDCBA9876543210ULL)) { \
    Log("QEMU-PAC-PROBE: FAIL " #Prefix " key roundtrip\n"); return EFI_DEVICE_ERROR; \
  } \
  Log("QEMU-PAC-PROBE: key " #Prefix " read/write/restore PASS\n"); \
} while (0)

EFI_STATUS EFIAPI PacProbeEntry(EFI_HANDLE Image, EFI_SYSTEM_TABLE *Table) {
  CHAR8 Line[200]; UINT64 El, Features, Mmfr, SavedLo, SavedHi, SavedSctlr, ActiveSctlr;
  UINT64 FirstRaw = 0, FirstSigned = 0, FirstAuthenticated = 0;
  UINTN Changed = 0; BOOLEAN Good = TRUE;
  (VOID)Image; (VOID)Table;
  gBS->LocateProtocol(&gEfiSerialIoProtocolGuid, NULL, (VOID **)&mSerial);
  El = READ_REGISTER(CurrentEL);
  Features = READ_REGISTER(ID_AA64ISAR1_EL1);
  Mmfr = READ_REGISTER(ID_AA64MMFR0_EL1);
  AsciiSPrint(Line, sizeof(Line), "QEMU-PAC-PROBE: EL%lu ISAR1=%lx MMFR0=%lx TCR=%lx\n",
              El >> 2, Features, Mmfr, READ_REGISTER(TCR_EL1));
  Log(Line);
  if (El != 4 || ((Features >> 4) & 0xFF) == 0 || ((Features >> 24) & 0xFF) == 0) {
    Log("QEMU-PAC-PROBE: SKIP EL1/PAuth address and generic features required\n");
    return EFI_UNSUPPORTED;
  }
  CHECK_KEY(APIA); CHECK_KEY(APIB); CHECK_KEY(APDA); CHECK_KEY(APDB); CHECK_KEY(APGA);
  SavedLo = READ_REGISTER(APIAKeyLo_EL1); SavedHi = READ_REGISTER(APIAKeyHi_EL1);
  SavedSctlr = READ_REGISTER(SCTLR_EL1);
  WRITE_REGISTER(APIAKeyLo_EL1, 0x123456789ABCDEF0ULL);
  WRITE_REGISTER(APIAKeyHi_EL1, 0x0FEDCBA987654321ULL);
  // Arm SCTLR_EL1.EnIA (bit31) enables AddPACIA/AuthIA; without it both are NOPs.
  WRITE_REGISTER(SCTLR_EL1, SavedSctlr | BIT31);
  __asm__ volatile ("isb" ::: "memory");
  ActiveSctlr = READ_REGISTER(SCTLR_EL1);
  if ((ActiveSctlr & BIT31) == 0) Good = FALSE;
  for (UINT64 Index = 1; Index <= 8; Index++) {
    UINT64 Raw = (UINT64)(UINTN)&mPointerTarget, Pointer = Raw, Modifier = Index * 0x1357;
    __asm__ volatile ("pacia %0, %1" : "+r" (Pointer) : "r" (Modifier));
    if (Index == 1) { FirstRaw = Raw; FirstSigned = Pointer; }
    if (Pointer != Raw) Changed++;
    __asm__ volatile ("autia %0, %1" : "+r" (Pointer) : "r" (Modifier));
    if (Index == 1) FirstAuthenticated = Pointer;
    if (Pointer != Raw) Good = FALSE;
  }
  WRITE_REGISTER(APIAKeyLo_EL1, SavedLo); WRITE_REGISTER(APIAKeyHi_EL1, SavedHi);
  WRITE_REGISTER(SCTLR_EL1, SavedSctlr);
  __asm__ volatile ("isb" ::: "memory");
  AsciiSPrint(Line, sizeof(Line), "QEMU-PAC-PROBE: SCTLR saved=%lx active=%lx changed=%lu raw=%lx signed=%lx authenticated=%lx\n",
              SavedSctlr, ActiveSctlr, (UINT64)Changed, FirstRaw, FirstSigned, FirstAuthenticated);
  Log(Line);
  if (!Good || Changed == 0 || ((Mmfr >> 28) & 0xF) == 0xF) {
    Log("QEMU-PAC-PROBE: FAIL PACIA/AUTIA or 4KiB support\n"); return EFI_DEVICE_ERROR;
  }
  Log("QEMU-PAC-PROBE: PASS EL1 keys5 PACIA AUTIA; virtual CPU only, not SpringBoard\n");
  // Park this guest until the bounded QMP runner captures it and stops QEMU.
  CpuDeadLoop(); return EFI_SUCCESS;
}
