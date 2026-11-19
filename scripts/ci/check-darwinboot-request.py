#!/usr/bin/env python3
"""Execute actual loader request validation, before any file/UEFI access.

The production preamble and packed-ramdisk parser are compiled verbatim with
bounded host services. A sentinel represents reaching the first file operation;
this is not an XNU boot, hardware test or allocation success claim.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tomllib

ROOT=Path(__file__).resolve().parents[2]
DEFAULT=ROOT/'.cache/firmware-components/DarwinBoot'
sys.path.insert(0,str(ROOT/'ci'))
from darwin_boot_args import validate

PREAMBLE=r'''
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdarg.h>
#include <wchar.h>
typedef uint8_t UINT8;typedef uint16_t UINT16;typedef uint32_t UINT32;
typedef uint64_t UINT64;typedef uintptr_t UINTN;typedef void VOID;
typedef uint64_t EFI_STATUS;typedef int BOOLEAN;typedef char CHAR8;typedef uint16_t CHAR16;
typedef struct {unsigned unused;} UNIXNU_LOADER_PROTOCOL;
typedef struct {VOID *Volume;CHAR16 *KernelPath;CHAR16 *BootArgs;VOID *Ramdisk;
  UINTN RamdiskSize,KextCount;VOID *DeviceTree;UINTN DeviceTreeSize;} UNIXNU_LOADER_BOOT_REQUEST;
#define STATIC static
#define CONST const
#define TRUE 1
#define FALSE 0
#define SIZE_256MB (256ULL<<20)
#define EFI_PAGE_SIZE 4096
#define EFI_INVALID_PARAMETER (UINT64_C(0x8000000000000000)|2)
#define EFI_UNSUPPORTED (UINT64_C(0x8000000000000000)|3)
#define EFI_BAD_BUFFER_SIZE (UINT64_C(0x8000000000000000)|4)
#define CompareMem memcmp
#define CopyMem memcpy
#define ZeroMem(p,n) memset(p,0,n)
static UINT32 ReadUnaligned32(CONST UINT32 *p){UINT32 v;memcpy(&v,p,4);return v;}
static UINT64 ReadUnaligned64(CONST UINT64 *p){UINT64 v;memcpy(&v,p,8);return v;}
static UINT64 DarwinCurrentEl(void){return 4;}
static UINTN rejected=UINT64_MAX;
static unsigned filesystem_entries;
static UINTN observed_logical;
static BOOLEAN observed_packed;
static CHAR8 observed_arguments[1024];
static UINTN Print(CONST wchar_t *format,...){
  if(wcsstr(format,L"boot args rejected")!=NULL){va_list args;va_start(args,format);rejected=va_arg(args,UINT64);va_end(args);}
  return 0;
}
'''


def source_parts(repo):
    path=repo/'DarwinBootPkg/Driver/DarwinBoot.c';text=path.read_text()
    # Bind the stack field and public boot_args ABI, not a guessed menu bound.
    field=re.findall(r'CHAR8\s+CommandLine\[(\d+)\];',text)
    header=(repo/'DarwinBootPkg/Driver/BootArgs.h').read_text()
    abi=re.findall(r'CHAR8\s+CommandLine\[(\d+)\];',header)
    if field!=['1024'] or abi!=['1024']:raise ValueError('Retained loader/boot_args capacity changed')
    start=text.index('  (VOID)This;',text.index('\nBoot ('))
    end=text.index('  Root = NULL;',start)
    checks=text[start:end]
    if checks.count('return EFI_BAD_BUFFER_SIZE;')!=2 or 'Index >= sizeof (CommandLine) - 1' not in checks:
        raise ValueError('Unexpected production request boundary')
    packed=(repo/'DarwinBootPkg/Driver/PackedRamdisk.h').read_text()
    function='''\n+EFI_STATUS fixture_request(const CHAR16 *args,const VOID *ramdisk,UINTN bytes){
  UNIXNU_LOADER_PROTOCOL protocol={0};UNIXNU_LOADER_PROTOCOL *This=&protocol;
  UNIXNU_LOADER_BOOT_REQUEST request={0};CONST UNIXNU_LOADER_BOOT_REQUEST *Request=&request;
  CHAR8 CommandLine[1024];UINTN Index,RamdiskExpandedSize;BOOLEAN RamdiskPacked;
  request.Volume=(VOID *)1;request.KernelPath=(CHAR16 *)1;request.BootArgs=(CHAR16 *)args;
  request.Ramdisk=(VOID *)ramdisk;request.RamdiskSize=bytes;
'''.replace('\n+','\n')+checks+'''
  observed_logical=RamdiskExpandedSize;observed_packed=RamdiskPacked;
  CopyMem(observed_arguments,CommandLine,sizeof(CommandLine));
  ++filesystem_entries;return 0x4452424f;
}
UINTN fixture_rejected(void){return rejected;}
unsigned fixture_filesystem_entries(void){return filesystem_entries;}
UINTN fixture_ramdisk_logical(void){return observed_logical;}
BOOLEAN fixture_ramdisk_packed(void){return observed_packed;}
const CHAR8 *fixture_command_line(void){return observed_arguments;}
void fixture_reset(void){rejected=UINT64_MAX;filesystem_entries=0;observed_logical=0;observed_packed=FALSE;}
'''.replace('\n+','\n')
    return PREAMBLE+packed+function,checks


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--darwinboot',type=Path,default=DEFAULT)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--release',type=Path,action='append',default=[])
    parser.add_argument('--expect-rejected',type=Path,help='Preserved known-bad067 release, negative control only')
    parser.add_argument('--ramdisk',type=Path,help='Actual packed RAM seed, validated without expansion')
    parser.add_argument('--config',type=Path,help='Actual FAT-readback unixnu.toml; test every XNU choice with its own initrd')
    parser.add_argument('--payload-root',type=Path,help='Readback EFI/UniXNU directory containing the config-relative initrd files')
    options=parser.parse_args()
    if bool(options.config)!=bool(options.payload_root):parser.error('--config and --payload-root must be supplied together')
    options.out.mkdir(parents=True,exist_ok=False)
    text,checks=source_parts(options.darwinboot)
    source=options.out/'production-request.c';source.write_text(text)
    library=options.out/'production-request.so'
    command=['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function',
             '-shared','-fPIC',str(source),'-o',str(library)]
    done=subprocess.run(command,capture_output=True,text=True,timeout=30)
    (options.out/'compile.log').write_text(done.stdout+done.stderr)
    if done.returncode:raise RuntimeError(done.stdout+done.stderr)
    lib=ctypes.CDLL(str(library));lib.fixture_request.argtypes=[ctypes.POINTER(ctypes.c_uint16),ctypes.c_void_p,ctypes.c_size_t]
    lib.fixture_request.restype=ctypes.c_uint64;lib.fixture_rejected.restype=ctypes.c_uint64
    lib.fixture_filesystem_entries.restype=ctypes.c_uint
    lib.fixture_ramdisk_logical.restype=ctypes.c_size_t;lib.fixture_ramdisk_packed.restype=ctypes.c_int
    lib.fixture_command_line.restype=ctypes.c_void_p
    cases=[];error=(1<<63)|4;sentinel=0x4452424f
    def run(name,value,wanted,seed=None):
        lib.fixture_reset();encoded=None if value is None else value.encode('utf-16-le')+b'\0\0'
        array=None if encoded is None else (ctypes.c_uint16*(len(encoded)//2)).from_buffer_copy(encoded)
        memory=None if seed is None else ctypes.create_string_buffer(seed)
        status=lib.fixture_request(array,memory,0 if seed is None else len(seed))
        reads=lib.fixture_filesystem_entries();at=lib.fixture_rejected()
        if status!=wanted or reads!=int(wanted==sentinel):raise ValueError('Production request control failed: '+name)
        if wanted==error and value is not None and len(value)>=1024 and at!=1023:
            raise ValueError('Wrong production overflow index')
        command_line_sha=None
        if wanted==sentinel:
            raw=b'' if value is None else value.encode('ascii')
            actual=ctypes.string_at(lib.fixture_command_line(),1024)
            if actual!=raw.ljust(1024,b'\0'):raise ValueError('Actual loader copy or NUL differs: '+name)
            command_line_sha=hashlib.sha256(actual[:len(raw)]).hexdigest()
        cases.append(dict(name=name,status=hex(status),rejected_index=None if at==(1<<64)-1 else at,
                          filesystem_operations_reached=reads,ascii_bytes=None if value is None else len(value.encode('utf-8')),
                          copied_command_line_sha256=command_line_sha,
                          ramdisk_logical_bytes=lib.fixture_ramdisk_logical(),ramdisk_packed=bool(lib.fixture_ramdisk_packed())))
        return cases[-1]
    run('null arguments',None,sentinel)
    for count in (0,1,1022,1023):run('ASCII length'+str(count),'a'*count,sentinel)
    for count in (1024,1041,4096):run('ASCII overflow'+str(count),'a'*count,error)
    run('nonASCII','serial=3 \u0080',error);run('DEL ASCII boundary','\x7f',sentinel)
    selected=[]
    corrected_arguments=''
    for path in options.release:
        receipt=json.loads((path/'release.json').read_text());validation=validate(receipt['kernel_args'])
        run(path.name,receipt['kernel_args'],sentinel)
        corrected_arguments=receipt['kernel_args']
        selected.append(dict(release=str(path),release_sha256=hashlib.sha256((path/'release.json').read_bytes()).hexdigest(),validation=validation))
    if options.expect_rejected:
        receipt=json.loads((options.expect_rejected/'release.json').read_text())
        if len(receipt['kernel_args'].encode('ascii'))!=1041:raise ValueError('Require exact1041-byte067 negative control')
        run('actual delivered067 overflow',receipt['kernel_args'],error)
        try:validate(receipt['kernel_args'])
        except ValueError:pass
        else:raise ValueError('Python guard failed to reject actual067')
    ramdisk=None
    if options.ramdisk:
        if not 0<options.ramdisk.stat().st_size<=256*1024**2:raise ValueError('RAM disk exceeds actual loader input bound')
        data=options.ramdisk.read_bytes()
        run('actual packed RAM disk request',corrected_arguments,sentinel,data)
        if data[:8]==b'DBRDISK1':run('truncated packed RAM disk rejected',corrected_arguments,error,data[:-1])
        ramdisk=dict(path=str(options.ramdisk),sha256=hashlib.sha256(data).hexdigest(),bytes=len(data),
                      logical_bytes=int.from_bytes(data[16:24],'little') if data[:8]==b'DBRDISK1' else len(data))
    entries=[]
    config_identity=None
    if options.config:
        root=options.payload_root.resolve();config_bytes=options.config.read_bytes();config=tomllib.loads(config_bytes.decode())
        config_identity=dict(path=str(options.config),sha256=hashlib.sha256(config_bytes).hexdigest())
        ids=[entry.get('id') for entry in config.get('entry',[])]
        if any(not isinstance(name,str) or not name for name in ids) or len(ids)!=len(set(ids)):
            raise ValueError('Unique named menu entries required')
        for entry in config['entry']:
            if entry.get('type')!='xnu':continue
            name=entry['id'];arguments=entry['args'];validation=validate(arguments)
            relative=entry.get('initrd');path=PurePosixPath(relative) if isinstance(relative,str) else None
            if (path is None or not relative or path.is_absolute() or str(path)!=relative or
                    any(part in ('.','..') for part in path.parts) or '\\' in relative):
                raise ValueError('Unsafe or missing menu initrd: '+name)
            seed=(root/relative).resolve()
            if not seed.is_relative_to(root) or not seed.is_file():raise ValueError('Menu initrd escapes readback root: '+name)
            if not 0<seed.stat().st_size<=256*1024**2:raise ValueError('Menu initrd exceeds actual loader input bound')
            data=seed.read_bytes();accepted=run('config '+name+' with actual initrd',arguments,sentinel,data)
            if data[:8]==b'DBRDISK1':run('config '+name+' truncated initrd rejected',arguments,error,data[:-1])
            entries.append(dict(id=name,validation=validation,initrd=relative,seed_sha256=hashlib.sha256(data).hexdigest(),
                encoded_bytes=len(data),logical_bytes=accepted['ramdisk_logical_bytes'],packed=accepted['ramdisk_packed'],
                copied_command_line_sha256=accepted['copied_command_line_sha256'],
                arguments_and_selected_seed_tested_together=True))
        if not entries:raise ValueError('No XNU choices in actual configuration')
    result=dict(passed=True,command=command,production_checks_sha256=hashlib.sha256(checks.encode()).hexdigest(),
        production_source={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in
            [options.darwinboot/'DarwinBootPkg/Driver'/name for name in ('DarwinBoot.c','BootArgs.h','PackedRamdisk.h')]},
        cases=cases,releases=selected,ramdisk=ramdisk,entries=entries,
        config=config_identity,
        actual067_rejection_reproduced=options.expect_rejected is not None,
        execution_scope='Actual production loader request guards and packed-input parser; file services modeled as a sentinel',
        no_uefi_or_xnu_boot=True,hardware_verified=False,device_operations=False)
    (options.out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(passed=True,cases=len(cases),actual067_rejection_reproduced=result['actual067_rejection_reproduced'],releases=selected),indent=2))


if __name__=='__main__':main()
