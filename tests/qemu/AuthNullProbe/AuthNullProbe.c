// Execute the repaired compiler's actual PACDA/AUTDA code, not a model of it.
#include <Uefi.h>
#include <Protocol/SerialIo.h>
#include <Library/BaseLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include "BlobOffsets.h"

extern CONST UINT8 AuthNullBlob[];
typedef VOID (*STORE_ZERO)(VOID *);
typedef VOID *(*LOAD_VALUE)(VOID *);
typedef VOID (*STORE_VALUE)(VOID *, VOID *);
typedef VOID (*COPY_VALUE)(VOID *, VOID *);
#define CALL(Name, Type) ((Type)(UINTN)(AuthNullBlob + OFFSET_##Name))
#define READ_REG(Name) ({ UINT64 V; __asm__ volatile ("mrs %0, " #Name : "=r" (V)); V; })
#define WRITE_REG(Name, V) __asm__ volatile ("msr " #Name ", %0" :: "r" ((UINT64)(V)) : "memory")
STATIC EFI_SERIAL_IO_PROTOCOL *mSerial;
STATIC UINT64 mTarget;

STATIC VOID Log(CONST CHAR8 *Text) {
  if (mSerial != NULL) {
    UINTN Bytes = AsciiStrLen(Text);
    mSerial->Write(mSerial, &Bytes, (VOID *)Text);
  }
  if (gST->ConOut != NULL) Print(L"%a", Text);
}

EFI_STATUS EFIAPI AuthNullProbeEntry(EFI_HANDLE Image, EFI_SYSTEM_TABLE *Table) {
  UINT64 First = 0, Second = 0, Ordinary = 0, NullEncoding;
  UINT64 SavedLo, SavedHi, SavedControl;
  BOOLEAN NullOk, PointerOk, CopyOk, NullCopyOk, ImportOk, ExportOk;
  CHAR8 Line[160];
  (VOID)Image; (VOID)Table;
  gBS->LocateProtocol(&gEfiSerialIoProtocolGuid, NULL, (VOID **)&mSerial);
  if (READ_REG(CurrentEL) != 4) {
    Log("QEMU-AUTH-NULL: FAIL requires actual EL1\n"); return EFI_UNSUPPORTED;
  }
  SavedLo = READ_REG(APDAKeyLo_EL1); SavedHi = READ_REG(APDAKeyHi_EL1);
  SavedControl = READ_REG(SCTLR_EL1);
  WRITE_REG(APDAKeyLo_EL1, 0x4242424242424242ULL);
  WRITE_REG(APDAKeyHi_EL1, 0x123456789ABCDEF0ULL);
  WRITE_REG(SCTLR_EL1, SavedControl | BIT27); // EnDA: actual data-pointer authentication.
  __asm__ volatile ("isb" ::: "memory");

  CALL(AUTH_STORE_ZERO, STORE_ZERO)(&First);
  NullEncoding = First;
  NullOk = First != 0 && CALL(AUTH_LOAD, LOAD_VALUE)(&First) == NULL;
  CALL(AUTH_STORE_POINTER, STORE_VALUE)(&First, &mTarget);
  PointerOk = First != (UINT64)(UINTN)&mTarget && CALL(AUTH_LOAD, LOAD_VALUE)(&First) == &mTarget;
  CALL(AUTH_COPY, COPY_VALUE)(&Second, &First);
  CopyOk = CALL(AUTH_LOAD, LOAD_VALUE)(&Second) == &mTarget;
  CALL(AUTH_STORE_ZERO, STORE_ZERO)(&First);
  CALL(AUTH_COPY, COPY_VALUE)(&Second, &First);
  NullCopyOk = Second != 0 && CALL(AUTH_LOAD, LOAD_VALUE)(&Second) == NULL;
  CALL(ORDINARY_STORE_ZERO, STORE_ZERO)(&Ordinary);
  CALL(ORDINARY_TO_AUTH, COPY_VALUE)(&First, &Ordinary);
  ImportOk = First != 0 && CALL(AUTH_LOAD, LOAD_VALUE)(&First) == NULL;
  CALL(AUTH_TO_ORDINARY, COPY_VALUE)(&Ordinary, &First);
  ExportOk = Ordinary == 0 && CALL(ORDINARY_LOAD, LOAD_VALUE)(&Ordinary) == NULL;

  WRITE_REG(APDAKeyLo_EL1, SavedLo); WRITE_REG(APDAKeyHi_EL1, SavedHi);
  WRITE_REG(SCTLR_EL1, SavedControl);
  __asm__ volatile ("isb" ::: "memory");
  AsciiSPrint(Line, sizeof(Line), "QEMU-AUTH-NULL: stored null=%lx checks=%u%u%u%u%u%u\n",
              NullEncoding, NullOk, PointerOk, CopyOk, NullCopyOk, ImportOk, ExportOk);
  Log(Line);
  if (!(NullOk && PointerOk && CopyOk && NullCopyOk && ImportOk && ExportOk)) {
    Log("QEMU-AUTH-NULL: FAIL compiled data-pointer behavior\n"); return EFI_DEVICE_ERROR;
  }
  Log("QEMU-AUTH-NULL: PASS compiled signed-null store/load/copy/transitions\n");
  CpuDeadLoop(); return EFI_SUCCESS;
}
