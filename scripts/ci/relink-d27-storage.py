#!/usr/bin/env python3
"""Relink existing native objects with real ArmCpu and readonly assert placement."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess

DEVICE = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tree', type=Path, required=True)
    parser.add_argument('--armcpu', type=Path, required=True)
    parser.add_argument('--mainline', type=Path, required=True)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--storage-archive', type=Path)
    parser.add_argument('--panic-renderer', action='store_true', help='Link the official diagnostic renderer as normal native code')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    out = args.out.resolve()
    revision = subprocess.check_output(['git', '-C', str(args.armcpu), 'rev-parse', 'HEAD'], text=True).strip()
    if revision != '696e09214b37640b9245b917de5d6d237222207b':
        raise ValueError('Unexpected ArmCpu revision')
    if subprocess.check_output(['git', '-C', str(args.armcpu), 'status', '--porcelain'], text=True).strip():
        raise ValueError('Require clean ArmCpu source')
    obj = args.tree.resolve() / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837'
    record = json.JSONDecoder().raw_decode((obj / 'iokit/DEVELOPMENT/IOPlatformExpert.cpo.json').read_text())[0]
    compiler = load('storage_compile', args.mainline / 'scripts/build-sheng-source-drivers.py')
    asm = load('macho_asm_fix', DEVICE / 'scripts/ci/macho-inline-asm.py')
    source, output = out / 'ArmCpu.cpp', out / 'ArmCpu.o'
    text, asm_count = asm.normalize((args.armcpu / 'ArmCpu.cpp').read_text())
    source.write_text(text)
    command = compiler.compile_command(record, source, output,
        ['-I', str(args.armcpu), '-I', str(args.tree / '.cache/xnu-work/osfmk')],
        ['-Wno-missing-designated-field-initializers', '-Wno-unused-but-set-global'])
    (out / 'armcpu.command.json').write_text(json.dumps(command, indent=2) + '\n')
    r = subprocess.run(command, cwd=record['directory'], capture_output=True, text=True, timeout=180)
    (out / 'armcpu.log').write_text(r.stdout + r.stderr)
    r.check_returncode()
    archive = out / 'libArmCpu.a'
    subprocess.run(['/usr/lib/llvm-18/bin/llvm-ar', 'rcs', str(archive), str(output)], check=True)
    names = subprocess.check_output(['/usr/lib/llvm-18/bin/llvm-nm', '-g', '--defined-only', str(archive)], text=True)
    for name in ('_armcpu_spi_mask', '_armcpu_spi_attach'):
        if name not in names.split():
            raise ValueError('Actual ArmCpu object lacks ' + name)
    saved = json.loads(args.inputs.read_text())
    env = dict(os.environ)
    env.update(saved['environment'])
    env.update(TMPDIR=str(out), PYTHONDONTWRITEBYTECODE='1')
    command = shlex.split((obj / '.LDFLAGS').read_text().rstrip('\0\n'))
    command += ['-filelist', 'link.filelist', 'lastkerneldataconst.o', 'lastkernelconstructor.o',
                'nonlto.o', 'version.o', '-o', str(out / 'native.macho')]
    previous = obj / 'mach.development.bcm2837.link/mach.development.bcm2837.linkarchives'
    archives = shlex.split(previous.read_text())
    replaced = 0
    for i, value in enumerate(archives):
        if value.endswith('/build/armcpu/libArmCpu.a'):
            archives[i] = '-Wl,-force_load,' + str(archive)
            replaced += 1
        elif args.storage_archive and 'libQemuSourceBlock.a' in value:
            archives[i] = '-Wl,-force_load,' + str(args.storage_archive.resolve())
    if replaced != 1:
        raise ValueError('Cannot identify the original ArmCpu archive')
    # Assert text stays read-only and all linker-authored references are retained.
    # Nothing enumerates this section by name; it is addressed by assertion sites.
    command += ['-Wl,-rename_section,__DATA_CONST,__assert,__TEXT,__assert', *archives]
    if args.panic_renderer:
        original = args.mainline / 'scripts/xnu-panic-screen.c'
        text, renderer_asm_count = asm.normalize(original.read_text())
        # Mach-O's AArch64 assembler treats ';' as a comment. Keep every
        # instruction in multi-instruction inline asm on its own physical line.
        text = text.replace('at s1e1r, %1; isb; mrs %0, par_el1',
                            'at s1e1r, %1\\n\\tisb\\n\\tmrs %0, par_el1')
        for section in ('.text.b_main', '.text.a_entry', '.text.a_common'):
            text = text.replace(f'section("{section}")', 'section("__TEXT_EXEC,__text")')
        text = text.replace('section(".text.z_font")', 'section("__TEXT,__const")')
        text = text.replace('b panic_screen_main', 'b _panic_screen_main')
        text = text.replace('__attribute__((noreturn)) static void park (void)',
                            '__attribute__((noreturn,noinline,used)) void sony_panic_screen_park (void)')
        text = text.replace('park ();', 'sony_panic_screen_park ();')
        # D27 has a 36-bit kernel VA region. Strip every PAC bit before printing.
        text = text.replace('0x0000007fffffffffUL', '0x0000000fffffffffUL')
        text = text.replace('0xffffff8000000000UL', '0xfffffff000000000UL')
        # Normal linker relocations resolve these current native symbols.
        prefix = '''extern unsigned char sony_vinfo[] __asm__("_vinfo");
extern unsigned int sony_pages __asm__("_vm_page_pages");
extern unsigned int sony_free __asm__("_vm_page_free_count");
#define VINFO ((unsigned long)sony_vinfo)
#define MAX_MEM 0UL
#define PAGE_TOTAL ((unsigned long)&sony_pages)
#define PAGE_FREE ((unsigned long)&sony_free)
'''
        renderer = out / 'SonyPanicScreen.c'
        renderer.write_text(prefix + text)
        font = DEVICE.parents[1] / 'ports/uefi-pdx234/Silicon/Silicium/SiliciumPkg/Library/FrameBufferSerialPortLib'
        renderer_object = out / 'SonyPanicScreen.o'
        renderer_command = [record['arguments'][0], '--target=arm64e-apple-ios27.0', '-ffreestanding',
            '-fno-builtin', '-fno-stack-protector', '-mgeneral-regs-only', '-Oz', '-I', str(font),
            '-c', str(renderer), '-o', str(renderer_object)]
        result = subprocess.run(renderer_command, capture_output=True, text=True)
        (out / 'panic-renderer.log').write_text(result.stdout + result.stderr)
        result.check_returncode()
        disassembly = subprocess.check_output(['/usr/lib/llvm-18/bin/llvm-objdump',
            '--disassemble-all', str(renderer_object)], text=True)
        (out / 'panic-renderer.disassembly.txt').write_text(disassembly)
        if 'PAR_EL1' not in disassembly or 's1e1r' not in disassembly:
            raise ValueError('Compiled renderer lacks actual AT/PAR readability check')
        command.append(str(renderer_object))
    (out / 'native-link.command.json').write_text(json.dumps(command, indent=2) + '\n')
    with (out / 'native-link.log').open('xb') as log:
        r = subprocess.run(command, cwd=obj, env=env, stdout=log, stderr=subprocess.STDOUT)
    r.check_returncode()
    report = dict(native=str(out / 'native.macho'),
        native_sha256=hashlib.sha256((out / 'native.macho').read_bytes()).hexdigest(),
        armcpu_revision=revision, armcpu_archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        real_spi_mask_exported=True, assert_strings_retained=True, assertions_disabled=False,
        linker_readonly_assert_section='__TEXT,__assert', kernel_objects_recompiled=False,
        armcpu_asm_separators_fixed=asm_count,
        device_operations=False)
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
