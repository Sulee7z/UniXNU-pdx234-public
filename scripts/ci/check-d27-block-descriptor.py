#!/usr/bin/env python3
"""Run exact selected Blocks source in a short PAC-enabled QEMU EL1 fixture."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
CLANG='/root/unixnu-build/pdx234-pac-toolchain/llvm/bin/clang-24'
TREE=BASE/'sources/UniXNU/out/pdx234/ios-27.0.1-24A446-iphone14/pdx234_sheng27_bulk/tree/.cache/xnu-work'


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    a=parser.parse_args();a.out.mkdir(parents=True,exist_ok=False);out=a.out.resolve();include=out/'include'
    files={
      'Availability.h':'#define __OSX_AVAILABLE_STARTING(...)\n#define __IGNORE_WCASTALIGN(x) (x)\n#define ptrauth_key_block_function ptrauth_key_asia\n',
      'AvailabilityMacros.h':'',
      'sys/systm.h':'#include <stddef.h>\n#define __unused __attribute__((unused))\n#define __assert_only\nextern "C" void block_test_fail(void) __attribute__((noreturn));\n#define assert(x) ((x)?(void)0:block_test_fail())\n#define __BEGIN_DECLS extern "C" {\n#define __END_DECLS }\n',
      'kern/kalloc.h':'#include <stddef.h>\n#define KT_DEFAULT 0\n#define Z_WAITOK_ZERO_NOFAIL 0\n#define KALLOC_TYPE_VAR_DEFINE(name,...) static int name;\nvoid *test_alloc(size_t);\nvoid test_free(void *,size_t);\nstatic inline void *kalloc_type_var_impl(int,size_t size,int,void *){return test_alloc(size);}\nstatic inline void kfree_type_var_impl(int,void *p,size_t size){test_free(p,size);}\n',
      'machine/atomic.h':'#define os_atomic_cmpxchg(ptr,oldv,newv,order) __sync_bool_compare_and_swap(ptr,oldv,newv)\n',
      'string.h':'#include <stddef.h>\nextern "C" void *memmove(void *,const void *,size_t);\n',
    }
    for name,text in files.items():
        p=include/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
    for name in ('Block.h','Block_private.h'):
        p=include/'libkern'/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((TREE/'libkern/libkern'/name).read_bytes())
    common=[CLANG,'-target','aarch64-none-elf','-march=armv8.3-a','-O2','-g','-fblocks','-ffreestanding','-fno-builtin',
        '-fno-exceptions','-fno-rtti','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables',
        '-Xclang','-fptrauth-intrinsics','-Xclang','-fptrauth-calls',
        '-Xclang','-fptrauth-function-pointer-type-discrimination',
        '-Xclang','-fptrauth-block-descriptor-pointers','-DKERNEL=1','-I',str(include),'-std=c++17']
    runtime=TREE/'libkern/libclosure/runtime.cpp';test=ROOT/'tests/qemu/d27-block-descriptor-runtime.cpp'
    commands=[]
    for source,stem in ((runtime,'runtime'),(test,'test')):
        cmd=common+['-c',str(source),'-o',str(out/(stem+'.o'))];commands.append(cmd)
        done=subprocess.run(cmd,capture_output=True,text=True,timeout=60)
        (out/(stem+'.log')).write_text(done.stdout+done.stderr)
        if done.returncode:raise RuntimeError(done.stderr)
    start=ROOT/'tests/qemu/d27-block-descriptor-start.S'
    subprocess.run(['aarch64-linux-gnu-as','-march=armv8.3-a',str(start),'-o',str(out/'start.o')],check=True)
    script=out/'link.ld';script.write_text('ENTRY(_start)\nSECTIONS { . = 0x40080000; .text : { *(.text .text.*) } .rodata : { *(.rodata .rodata.*) } .data : { *(.data .data.*) } .bss : { *(.bss .bss.* COMMON) } /DISCARD/ : { *(.comment .note* .eh_frame*) } }\n')
    subprocess.run(['ld.lld','-T',str(script),str(out/'start.o'),str(out/'runtime.o'),str(out/'test.o'),'-o',str(out/'fixture.elf')],check=True)
    assembly=subprocess.check_output(['llvm-objdump-23','-d','--no-show-raw-insn',str(out/'fixture.elf')],text=True)
    (out/'fixture.asm').write_text(assembly)
    if 'autda' not in assembly or 'pacda' not in assembly:raise ValueError('Actual descriptor PAC instructions missing')
    command=['qemu-system-aarch64','-machine','virt,virtualization=off','-cpu','max,pauth-impdef=on',
        '-accel','tcg','-m','128M','-nographic','-monitor','none','-semihosting-config','enable=on,target=native',
        '-kernel',str(out/'fixture.elf')]
    try:done=subprocess.run(command,capture_output=True,text=True,timeout=15)
    except subprocess.TimeoutExpired as error:
        (out/'qemu.log').write_bytes((error.stdout or b'')+(error.stderr or b''));raise
    (out/'qemu.log').write_text(done.stdout+done.stderr)
    if done.returncode or 'D27-BLOCK-DESCRIPTOR: PASS' not in done.stdout or 'FAIL' in done.stdout:
        raise RuntimeError(done.stdout+done.stderr)
    # Same original-style producer, but062's old runtime feature setting. This
    # must fail during the first descriptor read, before stage B or heap copying.
    old_flags=common.copy();index=old_flags.index('-fptrauth-block-descriptor-pointers')
    del old_flags[index-1:index+1]
    negative_compile=old_flags+['-c',str(runtime),'-o',str(out/'runtime-old.o')]
    subprocess.run(negative_compile,check=True,capture_output=True,text=True,timeout=60)
    subprocess.run(['ld.lld','-T',str(script),str(out/'start.o'),str(out/'runtime-old.o'),str(out/'test.o'),'-o',str(out/'negative.elf')],check=True)
    negative_command=command[:-1]+[str(out/'negative.elf')]
    negative=subprocess.run(negative_command,capture_output=True,text=True,timeout=15)
    (out/'negative.log').write_text(negative.stdout+negative.stderr)
    if not negative.returncode or 'D27-BLOCK-DESCRIPTOR: PASS' in negative.stdout or not negative.stdout.startswith('A0000000096000000 '):
        raise RuntimeError('The old runtime did not reproduce a first-copy data abort: '+negative.stdout+negative.stderr)
    record=dict(passed=True,scope='Exact selected runtime/header with fixture allocator and real QEMU EL1 PAC; not a full iOS boot',
        source_sha256=sha(runtime),header_sha256=sha(TREE/'libkern/libkern/Block_private.h'),test_sha256=sha(test),
        fixture_sha256=sha(out/'fixture.elf'),commands=commands,qemu_command=command,output=done.stdout,
        stack_heap_copy_resign=True,retain_release=True,nested_copy_dispose=True,global_passthrough=True,
        tampered_or_wrong_slot_signature_rejected=True,hardware_runtime_verified=False,
        old_runtime_data_abort_reproduced=True,negative_command=negative_command,
        negative_compile=negative_compile,negative_output=negative.stdout,negative_fixture_sha256=sha(out/'negative.elf'))
    (out/'result.json').write_text(json.dumps(record,indent=2)+'\n');print(done.stdout,end='')


if __name__=='__main__':main()
