"""Compile the actual loader entry; model Boot Services and an absent BDS console."""
import ctypes
from pathlib import Path
import subprocess
import tempfile
import unittest
import os

DEVICE = Path(__file__).resolve().parents[1]
ERROR = 1 << 63
NOT_FOUND = ERROR | 14
DEVICE_ERROR = ERROR | 7
ALREADY_STARTED = ERROR | 20

PREAMBLE = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <wchar.h>
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef uintptr_t UINTN;
typedef uint64_t EFI_STATUS;
typedef void *EFI_HANDLE;
typedef void VOID;
typedef struct { unsigned Value; } EFI_GUID;
typedef struct { VOID *ConOut; } EFI_SYSTEM_TABLE;
typedef struct { unsigned Value; } UNIXNU_LOADER_PROTOCOL;
typedef struct { EFI_STATUS (*Unload)(EFI_HANDLE); } EFI_LOADED_IMAGE_PROTOCOL;
typedef struct {
  EFI_STATUS (*LocateProtocol)(EFI_GUID *, VOID *, VOID **);
  EFI_STATUS (*HandleProtocol)(EFI_HANDLE, EFI_GUID *, VOID **);
  EFI_STATUS (*InstallMultipleProtocolInterfaces)(EFI_HANDLE *, ...);
} EFI_BOOT_SERVICES;
#define EFIAPI
#define EFI_ERROR(Status) (((EFI_STATUS)(Status) >> 63) != 0)
#define EFI_ALREADY_STARTED (UINT64_C(0x8000000000000000) | 20)
#define DEBUG_ERROR UINT64_C(0x80000000)
#define DEBUG(Arguments) DebugPrint Arguments
static EFI_SYSTEM_TABLE mTable;
static EFI_SYSTEM_TABLE *gST = &mTable;
static EFI_LOADED_IMAGE_PROTOCOL mLoaded;
static UNIXNU_LOADER_PROTOCOL mLoader;
static EFI_GUID gUniXNULoaderProtocolGuid, gEfiLoadedImageProtocolGuid;
static EFI_HANDLE mImage;
static EFI_STATUS mLocateStatus, mHandleStatus, mInstallStatus;
static UINT64 mCurrentEl;
static unsigned mCounts[7];
static char mLog[128];
static EFI_STATUS Unload(EFI_HANDLE Image) { (void)Image; return 0; }
static UINT64 DarwinCurrentEl(void) { return mCurrentEl; }
static UINTN Print(const wchar_t *Format, ...) {
  (void)Format; ++mCounts[3];
  if (gST->ConOut == NULL) ++mCounts[4]; /* UefiLibPrint.c(63)'s assertion condition */
  return 0;
}
static void DebugPrint(UINTN Level, const char *Format, ...) {
  va_list Args; (void)Level; ++mCounts[5];
  va_start(Args, Format); vsnprintf(mLog, sizeof(mLog), Format, Args); va_end(Args);
}
static EFI_STATUS Locate(EFI_GUID *Guid, VOID *Registration, VOID **Existing) {
  (void)Guid; (void)Registration; ++mCounts[0]; *Existing = &mLoader;
  return mLocateStatus;
}
static EFI_STATUS Handle(EFI_HANDLE Image, EFI_GUID *Guid, VOID **Loaded) {
  (void)Image; (void)Guid; ++mCounts[1]; *Loaded = &mLoaded;
  return mHandleStatus;
}
static EFI_STATUS Install(EFI_HANDLE *Image, ...) {
  va_list Args; (void)Image; ++mCounts[2];
  va_start(Args, Image);
  EFI_GUID *Guid = va_arg(Args, EFI_GUID *);
  UNIXNU_LOADER_PROTOCOL *Loader = va_arg(Args, UNIXNU_LOADER_PROTOCOL *);
  if (Guid != &gUniXNULoaderProtocolGuid || Loader != &mLoader) ++mCounts[6];
  va_end(Args); return mInstallStatus;
}
static EFI_BOOT_SERVICES mServices = {Locate, Handle, Install};
static EFI_BOOT_SERVICES *gBS = &mServices;
'''
WRAPPER = r'''
EFI_STATUS fixture_run(int Console, EFI_STATUS LocateStatus, EFI_STATUS HandleStatus,
                       EFI_STATUS InstallStatus, UINT64 CurrentEl) {
  for (unsigned Index = 0; Index < 7; ++Index) mCounts[Index] = 0;
  mLog[0] = 0; mLoaded.Unload = NULL; mImage = NULL;
  mTable.ConOut = Console ? &mLoaded : NULL;
  mLocateStatus = LocateStatus; mHandleStatus = HandleStatus; mInstallStatus = InstallStatus;
  mCurrentEl = CurrentEl;
  return DarwinBootEntry((EFI_HANDLE)(uintptr_t)0x12340000, &mTable);
}
unsigned fixture_count(unsigned Index) { return Index < 7 ? mCounts[Index] : 0; }
int fixture_unload_set(void) { return mLoaded.Unload == Unload; }
const char *fixture_log(void) { return mLog; }
'''


class LoaderEntry(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='darwinboot-entry-', dir='/root/unixnu-build')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.work = Path(cls.temp.name)
        cls.old = cls.compile_entry('old', DEVICE / '.cache/firmware-components/DarwinBoot/DarwinBootPkg/Driver/DarwinBoot.c')
        cls.new = cls.compile_entry('new', Path(os.environ['PDX_DARWIN_SOURCE']) if os.environ.get('PDX_DARWIN_SOURCE') else DEVICE / 'out/firmware-007/DarwinBoot.patched.c')

    @classmethod
    def compile_entry(cls, name, path):
        source = path.read_text()
        entry = source[source.index('\nEFI_STATUS\nEFIAPI\nDarwinBootEntry ('):]
        fixture = cls.work / (name + '.c')
        fixture.write_text(PREAMBLE + entry + WRAPPER)
        library = cls.work / (name + '.so')
        subprocess.run(['clang', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                        '-shared', '-fPIC', str(fixture), '-o', str(library)], check=True)
        lib = ctypes.CDLL(str(library))
        lib.fixture_run.argtypes = [ctypes.c_int] + [ctypes.c_uint64] * 4
        lib.fixture_run.restype = ctypes.c_uint64
        lib.fixture_count.argtypes = [ctypes.c_uint]
        lib.fixture_count.restype = ctypes.c_uint
        lib.fixture_log.restype = ctypes.c_char_p
        return lib

    def run_entry(self, lib, console=0, locate=NOT_FOUND, handle=0, install=0, el=4):
        return lib.fixture_run(console, locate, handle, install, el)

    def test_original_reproduces_null_console_call(self):
        self.assertEqual(self.run_entry(self.old), 0)
        self.assertEqual(self.old.fixture_count(3), 1)
        self.assertEqual(self.old.fixture_count(4), 1)

    def test_headless_registration_succeeds_without_print(self):
        self.assertEqual(self.run_entry(self.new), 0)
        self.assertEqual([self.new.fixture_count(i) for i in range(7)], [1, 1, 1, 0, 0, 1, 0])
        self.assertEqual(self.new.fixture_unload_set(), 1)
        self.assertEqual(self.new.fixture_log(), b'DARWINBOOT: loader v2 installed EL1\n')

    def test_existing_console_registration_still_succeeds(self):
        self.assertEqual(self.run_entry(self.new, console=1), 0)
        self.assertEqual(self.new.fixture_count(3), 0)
        self.assertEqual(self.new.fixture_count(5), 1)

    def test_already_installed_is_not_registered_again(self):
        self.assertEqual(self.run_entry(self.new, locate=0), ALREADY_STARTED)
        self.assertEqual([self.new.fixture_count(i) for i in range(7)], [1, 0, 0, 0, 0, 0, 0])
        self.assertEqual(self.new.fixture_unload_set(), 0)

    def test_missing_loaded_image_preserves_error(self):
        self.assertEqual(self.run_entry(self.new, handle=DEVICE_ERROR), DEVICE_ERROR)
        self.assertEqual(self.new.fixture_count(2), 0)
        self.assertEqual(self.new.fixture_count(5), 0)

    def test_install_failure_does_not_report_success(self):
        self.assertEqual(self.run_entry(self.new, install=DEVICE_ERROR), DEVICE_ERROR)
        self.assertEqual(self.new.fixture_count(5), 0)
        self.assertEqual(self.new.fixture_unload_set(), 0)

    def test_exception_level_diagnostic_unchanged(self):
        self.assertEqual(self.run_entry(self.new, el=8), 0)
        self.assertEqual(self.new.fixture_log(), b'DARWINBOOT: loader v2 installed EL2\n')


if __name__ == '__main__':
    unittest.main(verbosity=2)
