#!/usr/bin/env python3
"""Run production Session clock/init/transfers and SW82907->HID over bounded device models."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def method(text,signature):
    start=text.index(signature);at=text.index('{',start)+1;depth=1
    while depth:
        depth+=(text[at]=='{')-(text[at]=='}');at+=1
    return text[start:at]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--driver',type=Path,default=ROOT/'drivers/SonyLxsTouch')
    p.add_argument('--expect-old-timeout',action='store_true')
    p.add_argument('--expect-old-boot-reject',action='store_true')
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    text=(a.driver/'SonyTouch.cpp').read_text()
    globals='\n'.join(line for line in text.splitlines() if line.startswith(('volatile ','char native_','constexpr uint32_t kDmaPage=')))
    session=method(text,'struct Session')+';'
    callbacks='\n'.join(method(text,s) for s in ['uint32_t engineRead(', 'void engineWrite(',
        'int engineAttach(', 'int engineMask(', 'void engineInterrupt('])
    fixture=(ROOT/'tests/sony_touch_chain.cpp').read_text().replace('/* PRODUCTION_GLOBALS */',globals)
    fixture=fixture.replace('/* PRODUCTION_CALLBACKS */',callbacks).replace('/* PRODUCTION_SESSION */',session)
    c=a.out/'actual-session.cpp';c.write_text(fixture)
    objects=[]
    flags=['-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer',
           '-I',str(a.driver),'-I',str(BASE/'sources/sheng/package')]
    stems=['Sw82907','GeniI2c','HidTouchReport','GeniInit','SonyTouchIrq']
    if (a.driver/'Sw82907Boot.c').exists():stems.append('Sw82907Boot');flags.append('-DSONY_BOOT_POLICY_FIXTURE=1')
    for stem in stems:
        obj=a.out/(stem+'.o');objects.append(obj)
        subprocess.run(['clang','-std=c11',*flags,'-c',str(a.driver/(stem+'.c')),'-o',str(obj)],check=True,timeout=60)
    # The generated OEM bytes are test input only; no firmware loader is modeled.
    firmware=BASE/'sony-geni-firmware-001/sony-geni-i2c.bin';raw=firmware.read_bytes()
    fw=a.out/'firmware.cpp';fw.write_text('extern const unsigned char native_sony_geni_firmware[]={'+
        ','.join(map(str,raw))+'};\nextern const unsigned native_sony_geni_firmware_size='+str(len(raw))+';\n')
    exe=a.out/'actual-session'
    subprocess.run(['clang++','-std=c++17',*flags,'-Wno-unused-function',str(c),str(fw),*map(str,objects),'-o',str(exe)],check=True,timeout=60)
    mode=['old-timeout'] if a.expect_old_timeout else ['old-boot'] if a.expect_old_boot_reject else []
    done=subprocess.run([str(exe),*mode],text=True,capture_output=True,timeout=20)
    (a.out/'run.log').write_text(done.stdout+done.stderr)
    if done.returncode:raise RuntimeError(done.stdout+done.stderr)
    files=[a.driver/'SonyTouch.cpp',ROOT/'tests/sony_touch_chain.cpp',*a.driver.glob('*.c'),*a.driver.glob('*.h'),firmware]
    result=dict(passed=True,old_dma_timeout_reproduced=a.expect_old_timeout,old_boot_zero_rejection_reproduced=a.expect_old_boot_reject,
        vendor_boot_policy_cases_executed='-DSONY_BOOT_POLICY_FIXTURE=1' in flags,
        actual_session_methods_extracted=True,hardware_services_modeled=True,handset_runtime_verified=False,
        sources={str(path):sha(path) for path in files},sanitizers=['address','undefined'],output=done.stdout)
    (a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(done.stdout,end='')


if __name__=='__main__':main()
