#!/usr/bin/env python3
"""Independent native/strict radio-byte readback using only Python stdlib.

Reads direct file offsets exported from actual final chained fixups. Can run on
Windows against the strict kernel extracted from a final image; --ignore-full-
hash permits expected non-radio packaging edits, but never changes a radio word.
All outputs must be a new file and all inspected inputs are read-only.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct


def digest(data):return hashlib.sha256(data).hexdigest()


def ar_members(path):
    data=path.read_bytes()
    if not data.startswith(b'!<arch>\n'):raise ValueError('Not an archive')
    at=8;strings=b'';result={}
    while at<len(data):
        h=data[at:at+60]
        if len(h)!=60 or h[58:]!=b'`\n':raise ValueError('Malformed ar header')
        size=int(h[48:58]);name=h[:16].decode().strip();body=data[at+60:at+60+size]
        if len(body)!=size:raise ValueError('Truncated member')
        if name=='//':strings=body
        elif name not in ('/','/SYM64/'):
            if name.startswith('#1/'):
                count=int(name[3:]);name=body[:count].rstrip(b'\0').decode();body=body[count:]
            elif name.startswith('/') and name[1:].isdigit():name=strings[int(name[1:]):].split(b'/\n',1)[0].decode()
            else:name=name.rstrip('/')
            if not name.startswith('__.SYMDEF'):
                if name in result:raise ValueError('Duplicate member')
                result[name]=digest(body)
        at+=60+size+(size&1)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--expectations',type=Path,required=True)
    p.add_argument('--kind',choices=('native','strict'),required=True)
    p.add_argument('--image',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--ignore-full-hash',action='store_true',help='permit packaging edits outside checked radio bytes; report actual hash')
    p.add_argument('--native-metadata',type=Path)
    p.add_argument('--board-archive',type=Path)
    p.add_argument('--core-archive',type=Path)
    a=p.parse_args()
    if a.output.exists():raise ValueError('Preserve prior readback')
    expectation_bytes=a.expectations.read_bytes();expected=json.loads(expectation_bytes)[a.kind]
    data=a.image.read_bytes();whole=digest(data)
    if whole!=expected['sha256'] and not a.ignore_full_hash:raise ValueError('Image hash differs')
    if data[:4]!=b'\xcf\xfa\xed\xfe':raise ValueError('Expected Mach-O')
    checked=0
    def pointer(row):
        nonlocal checked
        actual=struct.unpack_from('<Q',data,row['file_offset'])[0]
        if actual!=int(row['raw_word'],16):raise ValueError('Radio pointer changed at '+hex(row['file_offset']))
        auth=actual>>63
        wanted=row.get('authenticated',False)
        if bool(auth)!=wanted:raise ValueError('Pointer auth differs')
        if auth and ((actual>>49)&3,(actual>>32)&0xffff,(actual>>48)&1)!=(row['key'],row['diversity'],row['address_diversity']):
            raise ValueError('Pointer PAC schema differs')
        checked+=1
    methods=0
    for table in expected['tables'].values():
        if len(table['rows'])!=table['slots']:raise ValueError('Bad expectation table extent')
        for row in table['rows']:pointer(row);methods+=1
    if methods!=928:raise ValueError('Not928 virtual method/metaclass slots')
    startup=expected['startup']
    if len(startup['radio_records'])!=5:raise ValueError('Not5 Qca init records')
    for row in startup['radio_records']:
        offset=row['file_offset']
        if data[offset:offset+8].hex()!=row['order_fields_hex']:raise ValueError('Init subsystem/rank changed')
        pointer(row['function_fixup']);pointer(row['argument_fixup'])
    for row in startup['lock_spec_fixups']:pointer(row)
    for row in startup['sysctl_oids']:pointer(row['parent']);pointer(row['handler'])
    pointer(startup['startup_cursor'])
    manifest=None
    if a.native_metadata:
        meta=json.loads(a.native_metadata.read_text());radio=meta['platform067_radio']
        if not a.board_archive or not a.core_archive:raise ValueError('Both actual archives required for metadata audit')
        actual=ar_members(a.board_archive)
        selected={Path(p).name:h for p,h in radio['objects'].items()}
        if actual!=selected or digest(a.board_archive.read_bytes())!=radio['sha256']:
            raise ValueError('Board actual archive does not match selected metadata')
        core=radio['wifi_core'];core_actual=ar_members(a.core_archive)
        if len(core_actual)!=125 or core_actual!={Path(p).name:h for p,h in core['objects'].items()} or digest(a.core_archive.read_bytes())!=core['sha256']:
            raise ValueError('Core actual archive does not match selected metadata')
        historical=[]
        for replacement in meta['platform067_radio_board_size']['replacements']:
            name=Path(replacement['old_object']).name.removesuffix('.late.o').removesuffix('.o')+'.cpp'
            old=radio['commands'].get(name)
            if old:
                historical.append(dict(field='platform067_radio.commands.'+name,
                    recorded_object=old['object'],recorded_sha256=old['object_sha256'],
                    optimization=[x for x in old['command'] if x.startswith('-O')],
                    selected_member=replacement['member'],selected_object=replacement['new_object'],
                    selected_sha256=replacement['new_sha256'],actual_member_sha256=actual[replacement['member']],
                    historical_command_not_selection=True))
        manifest=dict(board_members_match=True,board_members=len(actual),core_members_match=True,core_members=len(core_actual),
                      stale_BluetoothProbe_object_entry=False,historical_O2_commands=historical,metadata_modified=False)
    result=dict(passed=True,host='Windows' if __import__('os').name=='nt' else 'Linux',kind=a.kind,
                image=str(a.image),image_sha256=whole,expected_image_sha256=expected['sha256'],
                image_hash_matches=whole==expected['sha256'],packaging_nonradio_edits_permitted=a.ignore_full_hash,
                expectations=str(a.expectations),expectations_sha256=digest(expectation_bytes),
                virtual_PAC_slots=methods,qca_startup_records=5,all_checked_pointer_words=checked,
                method_startup_lock_sysctl_pointer_bytes_match=True,manifest=manifest,
                hardware_verified=False,inputs_modified=False,device_operations=False)
    a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
