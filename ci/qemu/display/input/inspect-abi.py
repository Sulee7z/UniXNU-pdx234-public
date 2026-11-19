#!/usr/bin/env python3
"""Read-only D27 HID symbol and authenticated-vtable inventory."""
import json
from pathlib import Path
import struct
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'XnuPrelink'))
from kc_image import Image,scan
base=Path('/mnt/e/UniXNU-sheng27-sony-20261113')
raw=Path('/mnt/g/UniXNU-Port/ports/UniXNU-pdx234/.cache/iphone14-ios27/ipsw/24A446/kernelcache.decompressed').read_bytes()
collection=Image(raw);fixups=collection.fixups()
family=Image(raw,collection.entries['com.apple.iokit.IOHIDFamily'][1])
names={n:a for a,values in family.symbols().items() for n in values}
for name,address in names.items():
    if any(v in name for v in ('IOHIDEventDriver','AppleUserHIDEventService','IOHIDEvent')):
        print(hex(address),name)
print('FAMILY',len(names),family.segments)
# A whole ordered diversity table identifies candidates; class identities must
# then be checked against the original constructors/metadata, never guessed.
source=(base/'qemu-input-001/source/NativeHidInput.cpp').read_text()
import re
div=[int(v,16) for v in re.findall(r'0x([0-9a-f]+)',source.split('static const uint16_t kSlotDiversity[]={',1)[1].split('};',1)[0])]
matches=[]
for address,row in fixups.items():
    if row[1:]!=(1,0,div[0],1):continue
    if all(fixups.get(address+8*i,(None,))[1:]==(1,0,d,1) for i,d in enumerate(div)):
        matches.append(address)
print('EVENTSERVICE TABLE CANDIDATES',[hex(a) for a in matches])
for address in matches:
    print('TABLE',hex(address),'slots',len(div),'next',fixups.get(address+8*len(div)))
    print('FIRST',[(i,hex(fixups[address+8*i][0])) for i in [0,1,7,14,89,90,198]])
eventmatches=[]
for address,row in fixups.items():
    if row[1:]!=(1,0,0x3771,1):continue
    if all(fixups.get(address+8*i,(None,))[1:]==(1,0,d,1) for i,d in [(18,0x8758),(23,0x02c5),(24,0x130e),(25,0xf637)]):
        eventmatches.append(address)
print('EVENT TABLE CANDIDATES',[hex(a) for a in eventmatches])
def read(address,size):
    return collection.read(address,size)
for address in matches+eventmatches:
    if not family.section(address):continue
    getter=fixups[address+7*8][0]
    body=read(getter,16)
    print('META GETTER',hex(address),hex(getter),body.hex(),scan(body,getter)[1])
    for site,target,kind in scan(body,getter)[1]:
        print('META BYTES',hex(target),read(target,64).hex())
for classname in ('IOHIDEventDriver','AppleUserHIDEventService','IOHIDEvent'):
    needle=classname.encode()+b'\0';at=0;addresses=[]
    while True:
        at=raw.find(needle,at)
        if at<0:break
        for section in collection.segments:
            if section['fileoff']<=at<section['fileoff']+section['filesize']:
                addresses.append(section['va']+at-section['fileoff'])
        at+=len(needle)
    print('CLASS NAME',classname,[hex(v) for v in addresses])
    for section in family.sections:
        if section['name']!='__text':continue
        code=family.read(section['va'],section['size'])
        for offset in range(0,len(code),4):
            word=int.from_bytes(code[offset:offset+4],'little')
            if word&0x9f000000!=0x90000000:continue
            chunk=code[offset:offset+128];pc=section['va']+offset
            refs=scan(chunk,pc)[1]
            if any(ref[1] in addresses for ref in refs):
                print('CLASS INIT',classname,hex(pc),chunk.hex(),refs)
out=base/'qemu-input-001/cache-candidates.json'
out.write_text(json.dumps(dict(event_service_tables=matches,event_tables=eventmatches),indent=2)+'\n')
