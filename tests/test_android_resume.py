"""Compile the real resume C and pinned cache library; only hardware/BS are modeled."""
import ctypes
from pathlib import Path
import subprocess
import tempfile
import unittest

DEVICE = Path(__file__).resolve().parents[1]
UEFI = DEVICE.parent / 'uefi-pdx234'
EDK = Path('/root/unixnu-build/uefi-pdx234/Mu_Basecore')
SOURCE = 'Platforms/Sony/pdx234Pkg/Applications/PdxAndroidResume/AndroidResume.c'
ERROR = 1 << 63
COMPROMISED = ERROR | 33
UNSUPPORTED = ERROR | 3
DEVICE_ERROR = ERROR | 7
OUT_OF_RESOURCES = ERROR | 9

PREAMBLE = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <wchar.h>
typedef uint8_t UINT8;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef uintptr_t UINTN;
typedef uint64_t EFI_STATUS;
typedef void *EFI_HANDLE;
typedef void VOID;
typedef int BOOLEAN;
typedef struct { UINT64 Fields[5]; } EFI_MEMORY_DESCRIPTOR;
typedef struct {
  UINT64 Magic; UINT32 Version, Size; UINT64 Android, AndroidBytes, Fdt;
  UINT32 AndroidCrc32, Reserved; UINT64 Image, ImageBytes;
} PDX_BOOT_SOURCE;
typedef VOID (*LINE_OPERATION)(UINTN);
typedef struct { int Unused; } EFI_SYSTEM_TABLE;
typedef struct {
  EFI_STATUS (*GetMemoryMap)(UINTN *, EFI_MEMORY_DESCRIPTOR *, UINTN *, UINTN *, UINT32 *);
  EFI_STATUS (*ExitBootServices)(EFI_HANDLE, UINTN);
  EFI_STATUS (*CalculateCrc32)(VOID *, UINTN, UINT32 *);
} EFI_BOOT_SERVICES;
#define STATIC static
#define CONST const
#define IN
#define EFIAPI
#define FALSE 0
#define EFI_SUCCESS 0
#define EFI_ERROR(s) (((EFI_STATUS)(s) >> 63) != 0)
#define EFI_INVALID_PARAMETER (UINT64_C(0x8000000000000000) | 2)
#define EFI_UNSUPPORTED (UINT64_C(0x8000000000000000) | 3)
#define EFI_BUFFER_TOO_SMALL (UINT64_C(0x8000000000000000) | 5)
#define EFI_DEVICE_ERROR (UINT64_C(0x8000000000000000) | 7)
#define EFI_OUT_OF_RESOURCES (UINT64_C(0x8000000000000000) | 9)
#define EFI_COMPROMISED_DATA (UINT64_C(0x8000000000000000) | 33)
#define EFI_ABORTED (UINT64_C(0x8000000000000000) | 21)
#define SIZE_2MB (2U << 20)
static jmp_buf mJump;
static unsigned mCase, mAssert, mExited, mEntered, mMapCalls, mExitCalls, mFreed;
static unsigned mPostExitBs, mCleanCalls, mIcCalls, mOrder[32], mOrderCount;
static UINTN mFirstClean, mLastClean;
static UINT64 mKernel, mFdtArg;
static _Alignas(8) UINT8 mFdt[128];
static void Event(unsigned Value) { if (mOrderCount < 32) mOrder[mOrderCount++] = Value; }
static void AssertFailure(void) { mAssert = 1; longjmp(mJump, 1); }
#define ASSERT(condition) do { if (!(condition)) AssertFailure(); } while (0)
static UINTN ArmDataCacheLineLength(void) { return 64; }
static UINTN ArmInstructionCacheLineLength(void) { return 64; }
static void ArmDataSynchronizationBarrier(void) { Event(8); }
static void ArmInstructionSynchronizationBarrier(void) { Event(9); }
static void ArmCleanDataCacheEntryByMVA(UINTN Address) {
  if (!mCleanCalls) mFirstClean = Address;
  mLastClean = Address; ++mCleanCalls;
}
static void ArmCleanDataCacheEntryToPoUByMVA(UINTN Address) { ArmCleanDataCacheEntryByMVA(Address); }
static void ArmInvalidateInstructionCacheEntryToPoUByMVA(UINTN Address) { (void)Address; }
static void ArmCleanInvalidateDataCacheEntryByMVA(UINTN Address) { ArmCleanDataCacheEntryByMVA(Address); }
static void ArmInvalidateDataCacheEntryByMVA(UINTN Address) { (void)Address; }
static void ArmInvalidateInstructionCache(void) { ++mIcCalls; Event(10); }
static UINT64 PdxCurrentEl(void) { return mCase == 1 ? 8 : 4; }
static BOOLEAN PdxReadable(UINT64 Address, UINT64 Bytes) {
  return mCase != 7 && Address == (UINTN)mFdt && Bytes == sizeof(mFdt);
}
static EFI_STATUS PdxGetBootSource(PDX_BOOT_SOURCE *Source) {
  if (mCase == 8) return EFI_DEVICE_ERROR;
  memset(Source, 0, sizeof(*Source));
  Source->Android = 0x80400000; Source->AndroidBytes = 128;
  Source->AndroidCrc32 = 0x12345678;
  Source->Fdt = (UINTN)mFdt + (mCase == 6 ? 1 : 0);
  return 0;
}
static UINTN Print(const wchar_t *Format, ...) { (void)Format; if (mExited) ++mPostExitBs; Event(1); return 0; }
static VOID *AllocatePool(UINTN Size) { Event(2); return mCase == 10 ? NULL : malloc(Size); }
static VOID FreePool(VOID *Memory) { ++mFreed; if (mExited) ++mPostExitBs; free(Memory); }
static EFI_STATUS GetMap(UINTN *Size, EFI_MEMORY_DESCRIPTOR *Map, UINTN *Key, UINTN *DescSize, UINT32 *Version) {
  ++mMapCalls; if (mExited) ++mPostExitBs; Event(3);
  *DescSize = sizeof(*Map); *Version = 1; *Key = mMapCalls;
  if (mCase == 9) return EFI_DEVICE_ERROR;
  if (!Map) { *Size = sizeof(*Map); return EFI_BUFFER_TOO_SMALL; }
  if (mCase == 11) return EFI_DEVICE_ERROR;
  return 0;
}
static EFI_STATUS Exit(EFI_HANDLE Image, UINTN Key) {
  (void)Image; (void)Key; ++mExitCalls; if (mExited) ++mPostExitBs; Event(4);
  if (mCase == 12) return EFI_DEVICE_ERROR;
  if (mCase == 13 && mExitCalls == 1) return EFI_INVALID_PARAMETER;
  if (mCase == 14) return EFI_INVALID_PARAMETER;
  mExited = 1; return 0;
}
static EFI_STATUS Crc(VOID *Buffer, UINTN Size, UINT32 *Value) {
  if (mExited) ++mPostExitBs;
  if ((UINTN)Buffer != 0x80400000 || Size != 128) return EFI_DEVICE_ERROR;
  *Value = mCase == 2 ? 0 : 0x12345678;
  return mCase == 3 ? EFI_DEVICE_ERROR : 0;
}
static EFI_BOOT_SERVICES mBs = {GetMap, Exit, Crc};
static EFI_BOOT_SERVICES *gBS = &mBs;
static VOID PdxAndroidEnter(UINT64 Kernel, UINT64 Fdt) {
  mEntered = 1; mKernel = Kernel; mFdtArg = Fdt; Event(11); longjmp(mJump, 2);
}
static VOID CpuDeadLoop(void) { longjmp(mJump, 3); }
'''
WRAPPER = r'''
EFI_STATUS fixture_run(unsigned Case) {
  mCase = Case; mAssert = mExited = mEntered = mMapCalls = mExitCalls = mFreed = 0;
  mPostExitBs = mCleanCalls = mIcCalls = mOrderCount = 0;
  mFirstClean = mLastClean = mKernel = mFdtArg = 0;
  memset(mFdt, 0, sizeof(mFdt)); mFdt[7] = sizeof(mFdt);
  if (Case == 4) mFdt[7] = 39;
  if (Case == 5) mFdt[4] = 1;
  int Stop = setjmp(mJump);
  if (Stop) return Stop == 2 ? 0 : EFI_ABORTED;
  return PdxAndroidResumeEntry((EFI_HANDLE)(UINTN)0x1234, NULL);
}
UINT64 fixture_value(unsigned Index) {
  switch (Index) {
    case 0: return mAssert; case 1: return mExited; case 2: return mEntered;
    case 3: return mMapCalls; case 4: return mExitCalls; case 5: return mFreed;
    case 6: return mPostExitBs; case 7: return mCleanCalls; case 8: return mIcCalls;
    case 9: return mKernel; case 10: return mFdtArg; case 11: return (UINTN)mFdt;
    case 12: return mFirstClean; case 13: return mLastClean; case 14: return mOrderCount;
    default: return 0;
  }
}
unsigned fixture_event(unsigned Index) { return Index < mOrderCount ? mOrder[Index] : 0; }
'''


def without_includes(source):
    return '\n'.join(line for line in source.splitlines() if not line.lstrip().startswith('#include'))


class AndroidResume(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pdx-resume-test-', dir='/root/unixnu-build')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.work = Path(cls.temp.name)
        cache = (EDK / 'ArmPkg/Library/ArmCacheMaintenanceLib/ArmCacheMaintenanceLib.c').read_text()
        old = subprocess.check_output(['git', '-C', str(UEFI), 'show', '209e87fa254243ebc5eca6a7d3a23c2d5062982a:' + SOURCE], text=True)
        cls.old = cls.compile('old', old, cache)
        cls.new = cls.compile('new', (UEFI / SOURCE).read_text(), cache)

    @classmethod
    def compile(cls, name, source, cache):
        fixture = cls.work / (name + '.c')
        fixture.write_text(PREAMBLE + without_includes(cache) + '\n' + without_includes(source) + WRAPPER)
        library = cls.work / (name + '.so')
        subprocess.run(['clang', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                        '-shared', '-fPIC', str(fixture), '-o', str(library)], check=True)
        lib = ctypes.CDLL(str(library))
        lib.fixture_run.argtypes = [ctypes.c_uint]
        lib.fixture_run.restype = ctypes.c_uint64
        lib.fixture_value.argtypes = [ctypes.c_uint]
        lib.fixture_value.restype = ctypes.c_uint64
        lib.fixture_event.argtypes = [ctypes.c_uint]
        lib.fixture_event.restype = ctypes.c_uint
        return lib

    def test_original_reproduces_real_library_assert_after_exit(self):
        self.assertEqual(self.old.fixture_run(0), ERROR | 21)
        self.assertEqual([self.old.fixture_value(i) for i in range(3)], [1, 1, 0])

    def test_fixed_path_cleans_image_fdt_before_handoff(self):
        self.assertEqual(self.new.fixture_run(0), 0)
        self.assertEqual([self.new.fixture_value(i) for i in range(3)], [0, 1, 1])
        self.assertEqual(self.new.fixture_value(6), 0)
        self.assertEqual(self.new.fixture_value(7), 2 + ((self.new.fixture_value(11) % 64 + 128 + 63) // 64))
        self.assertEqual(self.new.fixture_value(8), 1)
        self.assertEqual(self.new.fixture_value(9), 0x80400000)
        self.assertEqual(self.new.fixture_value(10), self.new.fixture_value(11))
        self.assertEqual(self.new.fixture_value(12), 0x80400000)
        events = [self.new.fixture_event(i) for i in range(self.new.fixture_value(14))]
        self.assertEqual(events[-5:], [4, 8, 8, 10, 11])

    def test_invalid_input_refuses_before_exit_or_cache(self):
        for case, status in ((1, UNSUPPORTED), (2, COMPROMISED), (3, COMPROMISED),
                             (4, COMPROMISED), (5, COMPROMISED), (6, COMPROMISED),
                             (7, COMPROMISED), (8, DEVICE_ERROR)):
            with self.subTest(case=case):
                self.assertEqual(self.new.fixture_run(case), status)
                self.assertEqual([self.new.fixture_value(i) for i in (0, 1, 2, 4, 7, 8)], [0] * 6)

    def test_memory_map_and_allocation_errors_preserved(self):
        for case, status in ((9, DEVICE_ERROR), (10, OUT_OF_RESOURCES), (11, DEVICE_ERROR)):
            with self.subTest(case=case):
                self.assertEqual(self.new.fixture_run(case), status)
                self.assertEqual([self.new.fixture_value(i) for i in (1, 2, 4, 7)], [0] * 4)

    def test_exit_error_prevents_cache_and_kernel(self):
        self.assertEqual(self.new.fixture_run(12), DEVICE_ERROR)
        self.assertEqual(self.new.fixture_value(5), 1)
        self.assertEqual([self.new.fixture_value(i) for i in (1, 2, 7, 8)], [0] * 4)

    def test_stale_map_key_retries_without_post_exit_bs(self):
        self.assertEqual(self.new.fixture_run(13), 0)
        self.assertEqual(self.new.fixture_value(3), 3)
        self.assertEqual(self.new.fixture_value(4), 2)
        self.assertEqual(self.new.fixture_value(6), 0)

    def test_repeated_stale_key_stops_after_two_exits(self):
        self.assertEqual(self.new.fixture_run(14), ERROR | 2)
        self.assertEqual(self.new.fixture_value(4), 2)
        self.assertEqual(self.new.fixture_value(5), 1)
        self.assertEqual([self.new.fixture_value(i) for i in (1, 2, 7, 8)], [0] * 4)


if __name__ == '__main__':
    unittest.main(verbosity=2)
