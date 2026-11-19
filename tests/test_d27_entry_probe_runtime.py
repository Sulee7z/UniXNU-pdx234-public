"""Execute official diagnostic cave instructions on the actual patched kernel copy."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import unittest

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X20, UC_ARM64_REG_PC

DEVICE = Path(__file__).resolve().parents[1]
KERNEL = DEVICE/'out/entry-diagnostic-006/kernel.macho'
RESULTS = []
POST_MMU = False


def segments(data):
    result=[];at=32
    for _ in range(struct.unpack_from('<I',data,16)[0]):
        c,n=struct.unpack_from('<II',data,at)
        if c==0x19:
            va,vs,fo,fs=struct.unpack_from('<4Q',data,at+24)
            result.append((va,vs,fo,fs))
        at+=n
    return result


class EntryProbeRuntime(unittest.TestCase):
    def exercise(self, stage):
        data=KERNEL.read_bytes();table=segments(data)
        low=min(va for va,vs,fo,fs in table if vs)
        def offset(va):
            for a,vs,fo,fs in table:
                if a<=va<a+fs:return fo+va-a
            raise ValueError('Unbacked probe address')
        entry=None;at=32
        for _ in range(struct.unpack_from('<I',data,16)[0]):
            c,n=struct.unpack_from('<II',data,at)
            if c==5:entry=struct.unpack_from('<Q',data,at+16+32*8)[0]
            at+=n
        self.assertIsNotNone(entry)
        if stage==1:
            site=entry
        else:
            # The official patch's stage2 cave ends by replaying MSR SCTLR_EL1,x0.
            sites=[]
            for va in range(entry+0x1800,entry+0x3000,4):
                word=struct.unpack_from('<I',data,offset(va))[0]
                if word&0xfc000000!=0x14000000:continue
                imm=word&0x3ffffff
                if imm&0x2000000:imm-=0x4000000
                dest=va+imm*4
                if entry<dest<entry+0x300:
                    cave=data[offset(dest):offset(dest)+0x60]
                    if struct.pack('<I',0xd5181000) in cave:sites.append(va)
            self.assertEqual(len(sites),1);site=sites[0]
        word=struct.unpack_from('<I',data,offset(site))[0]
        self.assertEqual(word&0xfc000000,0x14000000)
        imm=word&0x3ffffff
        if imm&0x2000000:imm-=0x4000000
        cave_va=site+imm*4
        physical_base=0x880004000
        def pa(va):return physical_base+va-low
        uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        mapped=set()
        for va in (site,cave_va):
            page=pa(va)&~4095
            if page not in mapped:uc.mem_map(page,4096);mapped.add(page)
        uc.mem_write(pa(site),data[offset(site):offset(site)+4])
        uc.mem_write(pa(cave_va),data[offset(cave_va):offset(cave_va)+0x60])
        args,fb=0x90000000,0xb8000000
        uc.mem_map(args,4096);uc.mem_map(fb,16384)
        uc.mem_write(fb,b'\x5a'*16384)
        uc.mem_write(args+0x28,struct.pack('<Q',fb))
        uc.mem_write(args+0x38,struct.pack('<Q',256))  # rowbytes
        uc.mem_write(args+0x48,struct.pack('<Q',64))
        x0=args if stage==1 else 0x30d0180d
        uc.reg_write(UC_ARM64_REG_X0,x0);uc.reg_write(UC_ARM64_REG_X20,args)
        stopped=[]
        def hook(engine,address,size,_):
            # Stop after the paint loop before the restored SCTLR write/continuation.
            if address>pa(cave_va) and address<pa(cave_va)+0x60:
                instruction=struct.unpack('<I',bytes(engine.mem_read(address,4)))[0]
                if instruction==0xd5181000 or instruction&0xfc000000==0x14000000:
                    stopped.append(address);engine.emu_stop()
        uc.hook_add(UC_HOOK_CODE,hook)
        uc.emu_start(pa(site),0,count=100000)
        self.assertEqual(len(stopped),1)
        self.assertEqual(uc.reg_read(UC_ARM64_REG_X0),x0)
        actual=bytes(uc.mem_read(fb,16384));band=1024
        color=0xff0000ff if stage==1 else 0xffff00ff
        expected=bytearray(b'\x5a'*16384)
        expected[stage*band:(stage+1)*band]=struct.pack('<I',color)*(band//4)
        self.assertEqual(actual,bytes(expected))
        RESULTS.append(dict(stage=stage,kernel_site=hex(site),physical_site=hex(pa(site)),
                            cave=hex(cave_va),painted_only_expected_band=True,x0_preserved=True))

    def test_kernel_entry_blue_from_high_physical_address(self):self.exercise(1)
    def test_before_mmu_magenta_preserves_sctlr_value(self):self.exercise(2)

    def test_post_mmu_six_second_psci_request(self):
        if not POST_MMU:
            self.skipTest('No post-MMU reset selected for this artifact')
        data=KERNEL.read_bytes();table=segments(data)
        def offset(va):
            for a,vs,fo,fs in table:
                if a<=va<a+fs:return fo+va-a
            raise ValueError('Unbacked cave')
        at=32;entry=None
        for _ in range(struct.unpack_from('<I',data,16)[0]):
            c,n=struct.unpack_from('<II',data,at)
            if c==5:entry=struct.unpack_from('<Q',data,at+16+32*8)[0]
            at+=n
        cave=entry+0x138  # Official stage3 cave: entry+0x5c0-0x488.
        uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);base=0x10000000
        uc.mem_map(base,4096);uc.mem_write(base,data[offset(cave):offset(cave)+0x60])
        reads=[];reset=[];ticks=19200000
        from unicorn.arm64_const import UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3
        def hook(engine,address,size,_):
            word=struct.unpack('<I',bytes(engine.mem_read(address,4)))[0]
            if word==0xd53be021:  # MRS x1,CNTPCT_EL0; model exact Sony 19.2 MHz counter.
                value=0 if not reads else (len(reads)-1)*ticks
                reads.append(value);engine.reg_write(UC_ARM64_REG_X1,value)
                engine.reg_write(UC_ARM64_REG_PC,address+4)
            elif word==0xd4000003:  # SMC #0: intercept, never invoke a device reset.
                reset.append(tuple(engine.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3)))
                engine.emu_stop()
        uc.hook_add(UC_HOOK_CODE,hook);uc.emu_start(base,0,count=1000)
        self.assertEqual(reads[-1],6*ticks)
        self.assertEqual(reset,[(0x84000009,0,0,0)])
        RESULTS.append(dict(stage=3,checkpoint_cave=hex(cave),simulated_counter_hz=ticks,
                            elapsed_ticks=reads[-1],psci_system_reset_intercepted=True,
                            actual_mmu_transition_tested=False,actual_reset_executed=False))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--report',type=Path,required=True)
    parser.add_argument('--kernel',type=Path);parser.add_argument('--post-mmu',action='store_true');args=parser.parse_args()
    if args.kernel:KERNEL=args.kernel
    POST_MMU=args.post_mmu
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(EntryProbeRuntime))
    args.report.write_text(json.dumps(dict(passed=result.wasSuccessful(),kernel_sha256=hashlib.sha256(KERNEL.read_bytes()).hexdigest(),cases=RESULTS,software_cpu_emulation=True,handset_executed=False),indent=2)+'\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
