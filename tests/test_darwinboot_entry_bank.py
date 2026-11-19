"""Run the patched production allocator against sparse EFI memory maps."""
import ctypes
from pathlib import Path
import subprocess
import tempfile
import unittest

DEVICE = Path(__file__).resolve().parents[1]
PROJECT = DEVICE.parents[1]
PREAMBLE = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdarg.h>
typedef uint64_t UINT64; typedef size_t UINTN; typedef int EFI_STATUS;
typedef uint32_t UINT32; typedef uint16_t CHAR16; typedef uint8_t UINT8;
typedef uint64_t EFI_PHYSICAL_ADDRESS;
typedef struct { UINT32 Type; UINT32 Pad; UINT64 PhysicalStart; UINT64 VirtualStart;
                 UINT64 NumberOfPages; UINT64 Attribute; } EFI_MEMORY_DESCRIPTOR;
typedef struct { UINT64 Base; } KERNEL;
#define STATIC static
#define EFI_ERROR(x) ((x)!=0)
#define EFI_OUT_OF_RESOURCES 9
#define EfiConventionalMemory 7
#define EfiLoaderCode 1
#define AllocateAddress 2
#define EFI_PAGES_TO_SIZE(n) ((n)*4096ULL)
#define EFI_SIZE_TO_PAGES(n) (((n)+4095)/4096)
#define BLOCK_SIZE 0x200000ULL
#define ALIGN_VALUE(n,a) (((n)+(a)-1)&~((a)-1))
#define PDX234_ENTRY_DRAM_BASE 0x880000000ULL
#define PDX234_ENTRY_DRAM_BYTES 0x39d00000ULL
static EFI_MEMORY_DESCRIPTOR descriptors[4];
static UINTN descriptor_count;
static UINT64 attempted;
static EFI_STATUS allocate(int mode,int type,UINTN pages,UINT64 *address) {
  (void)mode;(void)type;
  attempted=*address;
  if (*address < PDX234_ENTRY_DRAM_BASE || *address > PDX234_ENTRY_DRAM_BASE+PDX234_ENTRY_DRAM_BYTES ||
      pages*4096 > PDX234_ENTRY_DRAM_BASE+PDX234_ENTRY_DRAM_BYTES-*address) return 9;
  return 0;
}
static struct { EFI_STATUS (*AllocatePages)(int,int,UINTN,UINT64*); } boot={allocate}, *gBS=&boot;
static EFI_STATUS GetMap(EFI_MEMORY_DESCRIPTOR **map,UINTN *cap,UINTN *size,UINTN *key,UINTN *stride) {
  *map=descriptors;*cap=*size=descriptor_count*sizeof(*descriptors);*key=0;*stride=sizeof(*descriptors);return 0;
}
static UINT64 RunEnd(void *map,UINTN size,UINTN stride,UINT64 start,UINT64 end) {
  (void)map;(void)size;(void)stride;(void)start;return end;
}
static void FreePool(void *p) {(void)p;}
static void DiagDraw(const void *line,UINTN row) {(void)line;(void)row;}
static void UnicodeSPrint(void *line,UINTN size,const void *fmt,...) {(void)line;(void)size;(void)fmt;}
'''
WRAPPER = r'''
int check(uint64_t high_start,uint64_t high_bytes,uint64_t kernel_base,uint64_t window,uint64_t *result) {
  descriptors[0]=(EFI_MEMORY_DESCRIPTOR){.Type=7,.PhysicalStart=0xbab00000,.NumberOfPages=0x30000000/4096};
  descriptors[1]=(EFI_MEMORY_DESCRIPTOR){.Type=7,.PhysicalStart=high_start,.NumberOfPages=high_bytes/4096};
  descriptor_count=2;attempted=0;
  KERNEL k={kernel_base};return AllocateWindow(&k,window,result);
}
uint64_t last_attempt(void) {return attempted;}
'''


class EntryBankTests(unittest.TestCase):
    bank_base=0x880000000
    bank_bytes=0x39d00000
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='entry-bank-', dir=PROJECT / 'tmp')
        cls.work = Path(cls.temp.name)
        source = DEVICE / '.cache/firmware-components/DarwinBoot/DarwinBootPkg/Driver/DarwinBoot.c'
        target = cls.work / 'DarwinBootPkg/Driver/DarwinBoot.c'
        target.parent.mkdir(parents=True)
        target.write_text(source.read_text())
        subprocess.run(['git','apply',str(DEVICE/'patches/firmware/darwinboot-sony-entry-bank.patch')],
                       cwd=cls.work,check=True)
        text = target.read_text()
        at = text.index('STATIC\nEFI_STATUS\nAllocateWindow')
        end = text.index('\nSTATIC\nEFI_STATUS\nEFIAPI\nBoot',at)
        preamble=PREAMBLE.replace('0x880000000ULL',hex(cls.bank_base)+'ULL').replace('0x39d00000ULL',hex(cls.bank_bytes)+'ULL')
        c = cls.work/'allocator.c';c.write_text(preamble+text[at:end]+WRAPPER)
        lib = cls.work/'allocator.so'
        subprocess.run(['clang','-shared','-fPIC','-Wall','-Wextra','-Werror',str(c),'-o',str(lib)],check=True)
        cls.lib=ctypes.CDLL(str(lib));cls.lib.check.argtypes=[ctypes.c_uint64]*4+[ctypes.POINTER(ctypes.c_uint64)]
        cls.lib.last_attempt.restype=ctypes.c_uint64

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_low_bank_skipped_even_when_larger(self):
        result=ctypes.c_uint64()
        self.assertEqual(self.lib.check(0x880000000,0x39d00000,0xfffffff007004000,0x10000000,ctypes.byref(result)),0)
        self.assertEqual(result.value,0x880004000)

    def test_no_space_in_selected_bank_refuses_low_bank(self):
        result=ctypes.c_uint64()
        self.assertNotEqual(self.lib.check(0x880000000,0x08000000,0xfffffff007004000,0x10000000,ctypes.byref(result)),0)
        self.assertEqual(result.value,0)
        self.assertEqual(self.lib.last_attempt(),0)

    def test_window_cannot_extend_past_selected_bank(self):
        result=ctypes.c_uint64()
        self.assertNotEqual(self.lib.check(0x8b0000000,0x30000000,0xfffffff007004000,0x10000000,ctypes.byref(result)),0)
        self.assertEqual(self.lib.last_attempt(),0)

    def test_896_mib_window_fits_captured_bank(self):
        result=ctypes.c_uint64()
        self.assertEqual(self.lib.check(0x880000000,0x39d00000,0xfffffff007004000,0x38000000,ctypes.byref(result)),0)
        self.assertEqual(result.value,0x880004000)
        self.assertLessEqual(result.value+0x38000000,0x8b9d00000)

    def test_896_mib_refuses_fragment_too_small(self):
        result=ctypes.c_uint64()
        self.assertNotEqual(self.lib.check(0x880000000,0x37000000,0xfffffff007004000,0x38000000,ctypes.byref(result)),0)
        self.assertEqual(self.lib.last_attempt(),0)


class HighBankTests(EntryBankTests):
    bank_base=0x980000000
    bank_bytes=0x180000000

    def test_low_bank_skipped_even_when_larger(self):
        result=ctypes.c_uint64()
        self.assertEqual(self.lib.check(self.bank_base,self.bank_bytes,0xfffffff007004000,0x130000000,ctypes.byref(result)),0)
        self.assertEqual(result.value,self.bank_base+0x4000)

    def test_no_space_in_selected_bank_refuses_low_bank(self):
        result=ctypes.c_uint64()
        self.assertNotEqual(self.lib.check(self.bank_base,0x100000000,0xfffffff007004000,0x130000000,ctypes.byref(result)),0)
        self.assertEqual(self.lib.last_attempt(),0)

    def test_window_cannot_extend_past_selected_bank(self):
        result=ctypes.c_uint64()
        self.assertNotEqual(self.lib.check(0xac0000000,0x200000000,0xfffffff007004000,0x130000000,ctypes.byref(result)),0)
        self.assertEqual(self.lib.last_attempt(),0)

    def test_896_mib_window_fits_captured_bank(self):
        result=ctypes.c_uint64()
        self.assertEqual(self.lib.check(self.bank_base,self.bank_bytes,0xfffffff007004000,0x38000000,ctypes.byref(result)),0)

    def test_896_mib_refuses_fragment_too_small(self):
        result=ctypes.c_uint64()
        self.assertNotEqual(self.lib.check(self.bank_base,0x37000000,0xfffffff007004000,0x38000000,ctypes.byref(result)),0)
        self.assertEqual(self.lib.last_attempt(),0)


if __name__=='__main__':
    unittest.main(verbosity=2)
