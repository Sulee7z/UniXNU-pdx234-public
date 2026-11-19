#!/usr/bin/env python3
"""Compare Sony's verbatim boot check with the production SW82907 policy."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
VENDOR=ROOT.parents[1]/'references/sony-sw82907-20261118/yodo-1.2.0-rel/vendor/semc/hardware/kernel-modules/msm/lxs_ts'


def method(text,signature):
    start=text.index(signature);end=text.index('{',start)+1;depth=1
    while depth:
        depth+=(text[end]=='{')-(text[end]=='}');end+=1
    return text[start:end]


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    vendor=VENDOR/'lxs_ts_hal.c';header=VENDOR/'lxs_ts.h';text=vendor.read_text();h=header.read_text()
    definitions='\n'.join(method(h,s) for s in ('static inline u32 lxs_hal_boot_sts_pos_busy(',
        'static inline u32 lxs_hal_boot_sts_pos_dump_err(','static inline u32 lxs_hal_boot_sts_mask_empty('))
    definitions+='\n'+'\n'.join(method(text,s) for s in ('int lxs_hal_get_boot_result(',
        'static int lxs_hal_chk_boot_result(','static int lxs_hal_chk_boot_status(','static int lxs_hal_chk_boot('))
    fixture=r'''
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "Sw82907Boot.h"
typedef uint32_t u32;
#define BIT(n) (1u<<(n))
#define t_dev_err(...) ((void)0)
enum {BOOT_STS_POS_BUSY=1,BOOT_STS_POS_DUMP_ERR=3,BOOT_CHK_SKIP=1<<16,
      BOOT_CHK_MODE_RETRY=2,BOOT_CHK_STS_RETRY=2,BOOT_CHK_MODE_DELAY=10,BOOT_CHK_STS_DELAY=10};
struct lxs_ts;
struct lxs_hal_ops_quirk {int (*boot_result)(struct lxs_ts *,u32 *);};
struct lxs_hal_reg {u32 spr_boot_status,tc_status;};
struct lxs_hal_status_mask_bit {u32 valid_cfg_crc,valid_code_crc;};
struct lxs_ts_chip {struct lxs_hal_ops_quirk ops_quirk;struct lxs_hal_reg *reg;
    struct lxs_hal_status_mask_bit status_mask_bit;struct {unsigned t_boot_mode;} opt;};
struct lxs_ts {struct lxs_ts_chip chip;};
static uint32_t boot,code=0x00508060;
static int io_error;static unsigned reads,delays;
static int lxs_hal_read_value(struct lxs_ts *ts,u32 reg,u32 *value){
    ++reads;if(io_error)return io_error;*value=reg==ts->chip.reg->spr_boot_status?boot:code;return 0;
}
static void lxs_ts_delay(unsigned ms){delays+=ms;}
''' + definitions + r'''
static int normalized(int result){return result==BOOT_CHK_SKIP?Sw82907BootSkip:result?Sw82907BootCrcError:Sw82907BootOk;}
int main(void){
    struct lxs_hal_reg reg={0x11,0x601};struct lxs_ts ts={0};ts.chip.reg=&reg;ts.chip.status_mask_bit.valid_code_crc=0x40;
    for(uint32_t value=0;value<65536;++value){boot=value;assert(sw82907_boot_result(value)==normalized(lxs_hal_chk_boot_result(&ts)));}
    uint32_t seed=7;
    for(unsigned i=0;i<100000;++i){seed=seed*1664525u+1013904223u;boot=seed;code=seed;
        assert(sw82907_boot_result(boot)==normalized(lxs_hal_chk_boot_result(&ts)));
        assert(sw82907_code_crc_result(code)==normalized(lxs_hal_chk_boot_status(&ts)));}
    boot=UINT32_MAX;assert(sw82907_boot_result(boot)==normalized(lxs_hal_chk_boot_result(&ts)));
    code=UINT32_MAX;assert(sw82907_code_crc_result(code)==normalized(lxs_hal_chk_boot_status(&ts)));
    boot=0;code=0;reads=delays=0;assert(lxs_hal_chk_boot(&ts)==0 && reads==1 && !delays);
    assert((boot&14)!=4 && sw82907_boot_result(boot)==Sw82907BootSkip);
    boot=0xc;code=0x00508060;reads=delays=0;assert(lxs_hal_chk_boot(&ts)!=0 && delays==20);
    boot=4;code=0x00508020;reads=delays=0;assert(lxs_hal_chk_boot(&ts)!=0 && delays==20);
    io_error=-5;assert(lxs_hal_chk_boot(&ts)==-5);
    assert(sw82907_version_supported(0x040a0112) && sw82907_version_supported(0x140a0100));
    assert(!sw82907_version_supported(0) && !sw82907_version_supported(UINT32_MAX) && !sw82907_version_supported(0x040b0112));
    puts("PASS verbatim Sony boot-check differential: all16bit statuses+100k32bit, zero/busy/unavailable skips, CRC retries and IO errors; old065 rejects measuredboot0");
}
'''
    generated=a.out/'vendor-boot.c';generated.write_text(fixture)
    driver=ROOT/'drivers/SonyLxsTouch';source=driver/'Sw82907Boot.c'
    # Vendor source deliberately compares u32 against ~0; keep its body verbatim.
    subprocess.run(['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-sign-compare','-fsanitize=address,undefined',
        '-I',str(driver),str(generated),str(source),'-o',str(a.out/'boot-policy')],check=True,timeout=30)
    done=subprocess.run([str(a.out/'boot-policy')],capture_output=True,text=True,timeout=15)
    (a.out/'run.log').write_text(done.stdout+done.stderr)
    if done.returncode:raise RuntimeError(done.stdout+done.stderr)
    files=[vendor,header,source,driver/'Sw82907Boot.h',Path(__file__)]
    result=dict(passed=True,verbatim_vendor_boot_check=True,zero_boot_old_condition_rejects=True,
        crc_and_io_error_paths_preserved=True,compared_cases=165538,sources={str(p):sha(p) for p in files},
        sanitizers=['address','undefined'],handset_runtime_verified=False,output=done.stdout)
    (a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(done.stdout,end='')


if __name__=='__main__':main()
