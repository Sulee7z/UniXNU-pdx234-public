#!/usr/bin/env python3
"""Read-only full002 radio closure, including -Oz outlined signing helpers.

Does not edit or replace any earlier helper, receipt, source, object or archive.
All output lives in a new qualification-final run. Exports actual native and
strict fixup sites/file offsets for independent final-image readback.
"""
from __future__ import annotations
import argparse
import bisect
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import struct
import sys

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
FRESH=Path('/mnt/f/UniXNU-Port-artifacts/platform067-20261118')
BUILD=Path('/mnt/e/UniXNU-sheng27-sony-20261113/sony-wcn-067-002')
NATIVE_SHA='734bb8fc84437371c34f4e2afc43ef4a0b4191d1bfbcd4b6cf1d52d5080c37dd'
STRICT_SHA='55ac950130c34bf82c9b157868c98b0efa335bd6a9f5a7ff4add66f923e26dcb'

def sha(path):
    with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def load(path):return json.loads(Path(path).read_text())

def import_file(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod

sys.path.insert(0,str(ROOT/'ci/XnuPrelink'))
from kc_image import Image,scan
prior=import_file('sony_frozen_abi_helper',HERE/'qualify.py')


class Linked:
    def __init__(self,path,out,label):
        self.path=path;self.out=out;self.label=label
        self.raw=path.read_bytes();self.collection=Image(self.raw)
        self.image=Image(self.raw,self.collection.entries['com.apple.kernel'][1]) if self.collection.entries else self.collection
        self.names={n:va for va,g in self.image.symbols().items() for n in g}
        self.reverse=self.image.symbols();self.starts=self.image.function_starts();self.fixups=self.collection.fixups()
        self.codes={}

    def code(self,name_or_va):
        at=self.names[name_or_va] if isinstance(name_or_va,str) else name_or_va
        if at not in self.codes:
            end=self.starts[bisect.bisect_right(self.starts,at)]
            raw=self.image.read(at,end-at);asm=prior.disassemble(self.image,at,end-at)
            names=self.reverse.get(at,[hex(at)]);name=names[0]
            filename=self.label+'-'+name+'.asm';dest=self.out/filename;dest.write_text(asm)
            calls,refs,_=scan(raw,at)
            self.codes[at]=dict(address=hex(at),bytes=len(raw),symbols=names,code_sha256=hashlib.sha256(raw).hexdigest(),
                disassembly=str(dest),asm=asm,
                calls=[dict(site=hex(s),target=hex(t),symbols=self.reverse.get(t,[]),link=l) for s,t,l in calls],
                references=[dict(site=hex(s),target=hex(t),kind=k) for s,t,k in refs])
        return self.codes[at]

    def fixup(self,site,target=None,schema=None):
        if site not in self.fixups:raise ValueError('Missing actual chained fixup '+hex(site))
        row=self.fixups[site]
        if target is not None and row[0]!=target:raise ValueError('Wrong chained target '+hex(site))
        if schema is not None and row[1:]!=tuple(schema):raise ValueError('Wrong PAC schema '+hex(site)+' '+repr(row))
        return dict(site=hex(site),file_offset=self.image.offset(site,8),raw_word=hex(struct.unpack('<Q',self.image.read(site,8))[0]),
            target=hex(row[0]),authenticated=bool(row[1]),key=row[2],diversity=row[3],address_diversity=row[4])

    def call(self,caller,callee):
        c=self.code(caller);wanted=self.names[callee]
        matches=[r for r in c['calls'] if int(r['target'],16)==wanted]
        if not matches:raise ValueError('Actual call absent '+caller+' -> '+callee)
        return dict(caller=caller,callee=callee,sites=[r['site'] for r in matches])

    def outlined_vptr(self,classname,table):
        ctor='__ZN'+str(len(classname))+classname+'C2Ev'
        allocate='__ZNK'+str(len(classname))+classname+'9MetaClass5allocEv'
        c=self.code(ctor);a=self.code(allocate)
        if 'pacibsp' not in c['asm'] or 'retab' not in c['asm']:raise ValueError('Constructor lost return authentication')
        if not any(int(r['target'],16)==table for r in c['references']):raise ValueError('Constructor names wrong instance vptr')
        helpers=[]
        # -Oz performs instance signing in a tiny outlined helper. Check actual
        # direct call and full helper body; never infer loss of PAC from inlining.
        for call in c['calls']:
            target=int(call['target'],16)
            try:h=self.code(target)
            except (ValueError,IndexError):continue
            text=h['asm']
            if all(s in text for s in ('mov\tx16, x0','movk\tx16, #52641, lsl #48','pacda\tx8, x16','str\tx8, [x0]')):
                helpers.append(dict(callsite=call['site'],helper=hex(target),code_sha256=h['code_sha256']))
        if not helpers and not all(s in c['asm'] for s in ('#52641','pacda')):
            raise ValueError('No actual DA/cda1 instance vptr signer')
        size=216 if classname=='IONetworkStackUserClient' else 136
        if not re.search(r'mov\s+w[01], #'+str(size)+r'\b',a['asm']):raise ValueError('Allocator extent differs')
        # Size is passed to this class's operator new. The allocator tail-calls
        # its constructor after authenticating its own return address.
        names={s for r in a['calls'] for s in r['symbols']}
        operator='__ZN'+str(len(classname))+classname+'nwEm'
        if not {operator,ctor}.issubset(names):raise ValueError('Allocator no longer reaches own operator new and constructor')
        return dict(classname=classname,instance_bytes=size,constructor=hex(self.names[ctor]),allocator=hex(self.names[allocate]),
                    vptr_schema=dict(key='DA',diversity='0xcda1',address_diversity=1),outlined_signers=helpers,
                    actual_allocator_tailcalls_own_constructor=True)

    def tables(self,classes,metas):
        result={};rows=[];constructors=[]
        for name,table in [*classes.items(),*[(n+'::MetaClass',t) for n,t in metas.items()]]:
            start=self.names[table['symbol']]+16;entries=[]
            for slot in table['rows']:
                symbol=slot['symbol'];target=self.names.get(symbol)
                row=self.fixup(start+8*slot['slot'],target,(1,0,slot['diversity'],1))
                row.update(slot=slot['slot'],symbol=symbol,table=name);entries.append(row);rows.append(row)
            result[name]=dict(vtable_symbol=table['symbol'],address_point=hex(start),slots=len(entries),instance_bytes=table['instance_bytes'],
                              method_bytes=8*len(entries),total_table_bytes=16+8*len(entries),rows=entries)
            if name in classes:constructors.append(self.outlined_vptr(name,start))
        if len(rows)!=928:raise ValueError('Expected928 actual final PAC slots')
        return result,rows,constructors

    def startup(self,entries):
        sec=next(s for s in self.image.sections if (s['segment'],s['name'])==('__BOOTDATA','__init_entry_set'))
        begin,end=sec['va'],sec['va']+sec['size']
        if sec['size']%24:raise ValueError('Startup section not24-byte records')
        rows=[]
        for e in entries:
            at=self.names[e['symbol']]
            if not begin<=at<end or (at-begin)%24:raise ValueError('Qca record outside actual section')
            fields=struct.unpack('<II',self.image.read(at,8))
            if fields!=(e['subsystem'],e['rank']):raise ValueError('Startup order fields differ')
            func=self.fixup(at+8,self.names[e['function']],(1,0,0x2abe,0))
            arg=self.fixup(at+16,self.names[e['argument_symbol']],(0,None,None,None))
            rows.append(dict(name=e['symbol'],site=hex(at),file_offset=self.image.offset(at,24),bytes=24,
                             subsystem=fields[0],rank=fields[1],function_symbol=e['function'],argument_symbol=e['argument_symbol'],
                             function_fixup=func,argument_fixup=arg,order_fields_hex=self.image.read(at,8).hex()))
        bootstrap=self.code('_kernel_startup_bootstrap');upto=self.code('_kernel_startup_initialize_upto')
        refs={int(r['target'],16) for r in bootstrap['references']}
        if not {begin,end}.issubset(refs):raise ValueError('Bootstrap does not use actual startup section boundaries')
        if not re.search(r'mov\s+w2, #24\b',bootstrap['asm']) or not re.search(r'mov\s+w0, #3\b',bootstrap['asm']):
            raise ValueError('Bootstrap qsort stride/LOCKS phase differs')
        self.call('_kernel_startup_bootstrap','_qsort')
        comparator=self.code('_startup_entry_cmp') if '_startup_entry_cmp' in self.names else self.code(next(
            int(r['target'],16) for r in bootstrap['references'] if int(r['target'],16) in self.starts))
        if not all(re.search(p,comparator['asm']) for p in (r'ldr\s+w\d+, \[x0\]',r'ldr\s+w\d+, \[x1\]',
                                                        r'ldr\s+w\d+, \[x0, #4\]',r'ldr\s+w\d+, \[x1, #4\]')):
            raise ValueError('Actual qsort comparator does not compare subsystem and rank')
        if not all(s in upto['asm'] for s in ('ldp\tx8, x0, [x22, #8]','mov\tx17, #10942','blraa\tx8, x17','add\tx22, x22, #24')):
            raise ValueError('Actual startup consumer2abe/24-byte path differs')
        cursor=self.fixup(self.names['_startup_entry_cur'],begin,(0,None,None,None))
        thread=self.code('_kernel_bootstrap_thread')
        if not re.search(r'mov\s+w0, #16\b',thread['asm']):raise ValueError('Native boot lacks SYSCTL16 phase')
        paths=[self.call('_arm_init','_kernel_startup_bootstrap'),
               self.call('_kernel_startup_bootstrap','_kernel_startup_initialize_upto'),
               self.call('_kernel_bootstrap_thread','_kernel_startup_initialize_upto'),
               self.call('_kernel_bootstrap_thread','_bsd_init'),self.call('_bsd_init','_native_legacy_display_late_probe'),
               self.call('_native_legacy_display_late_probe','_native_sony_wifi_start'),
               self.call('_native_legacy_display_late_probe','_native_sony_bluetooth_start')]
        for n in ('_lck_grp_startup_init','_lck_mtx_startup_init','_sysctl_register_oid_early'):
            self.code(n)
        # Verify the exact pointed-to lock specs and OID schemas too.
        group=self.names['___startup_lck_grp_spec_bt_sk_grp'];mutex=self.names['___startup_lck_mtx_spec_bt_sk_lock']
        specs=[self.fixup(group,self.names['_bt_sk_grp'],(0,None,None,None)),
               self.fixup(mutex,self.names['_bt_sk_lock'],(0,None,None,None)),
               self.fixup(mutex+8,self.names['_bt_sk_grp'],(0,None,None,None))]
        if self.image.read(group+8,64).split(b'\0')[0]!=b'unixnu.bt.uart.sk' or self.image.read(mutex+16,8)!=bytes(8):
            raise ValueError('Actual lock spec fields differ')
        oids=[]
        for n,handler in [('qbt_boot','_bt_sk_boot_sysctl'),('qbt_firmware','_sysctl_handle_string'),('qbt_power_on','_bt_sk_power_on_sysctl')]:
            at=self.names['_sysctl__kern_'+n]
            if struct.unpack('<I',self.image.read(at+72,4))[0]!=1:raise ValueError('Actual OID version differs')
            oids.append(dict(name='kern.'+n,address=hex(at),bytes=80,
                        parent=self.fixup(at,self.names['_sysctl__kern_children'],(1,2,0xdb49,1)),
                        handler=self.fixup(at+48,self.names[handler],(1,0,0xe2e,0)),version=1))
        return dict(section=sec,record_count=sec['size']//24,radio_records=rows,lock_spec_fixups=specs,sysctl_oids=oids,
                    startup_cursor=cursor,actual_sort_stride=24,actual_sort_compares_subsystem_rank=True,
                    group_before_mutex=True,LOCKS_early=True,SYSCTL16_before_BSD=True,mandatory_calls=paths,
                    callback_PAC='IA/0x2abe/no-address-diversity',explicit_late_constructor_recall_required=False)

    def write_codes(self):
        result={hex(at):{k:v for k,v in row.items() if k!='asm'} for at,row in self.codes.items()}
        return result


def members(archive):
    # Read bytes directly rather than trust an object-path metadata map.
    sys.path.insert(0,str(ROOT/'ci/platform067/arm64e'))
    from audit import ar_members
    return {name:dict(sha256=h,bytes=size) for name,h,size in ar_members(archive)}


def manifest(native,out):
    meta=load(native.parent/'result.json');radio=meta['platform067_radio'];archive=Path(radio['archive'])
    actual=members(archive);objects=radio['objects'];matching={};stale=[]
    if sha(archive)!=radio['sha256']:raise ValueError('Selected board archive hash differs')
    for path,digest in objects.items():
        name=Path(path).name
        if name in matching:raise ValueError('Duplicate manifest member')
        if sha(path)!=digest or actual[name]['sha256']!=digest:raise ValueError('Selected board object manifest stale: '+path)
        matching[name]=dict(path=path,sha256=digest,archive_member_sha256=actual[name]['sha256'])
    if set(matching)!=set(actual):raise ValueError('Selected archive membership differs from manifest')
    size=load(FRESH/'radio-board-size-002/result.json')
    for replacement in size['replacements']:
        name=Path(replacement['old_object']).stem
        key=name+'.cpp'
        record=radio['commands'].get(key)
        if record and record.get('object_sha256')!=replacement['new_sha256']:
            stale.append(dict(field='platform067_radio.commands.'+key,role='historical original-O2 provenance, not selected object',
                recorded_object=record['object'],recorded_sha256=record['object_sha256'],
                selected_member=replacement['member'],selected_object=replacement['new_object'],
                selected_sha256=replacement['new_sha256'],metadata_not_modified=True))
    link=load(native.parent/'native-link.command.json')
    selected=[v.split('-Wl,-force_load,',1)[1] for v in link if v.startswith('-Wl,-force_load,')]
    if str(archive) not in selected:raise ValueError('Correct board archive not linked')
    core=radio['wifi_core'];corearchive=Path(core['archive'])
    if str(corearchive) not in selected or sha(corearchive)!=core['sha256']:raise ValueError('Correct core archive not selected')
    coremembers=members(corearchive)
    coremap={Path(p).name:h for p,h in core['objects'].items()}
    if len(coremembers)!=125 or {n:v['sha256'] for n,v in coremembers.items()}!=coremap:
        raise ValueError('125 selected core members differ from metadata')
    result=dict(board_archive=str(archive),board_sha256=sha(archive),board_members=matching,
                board_objects_manifest_matches_actual_archive=True,stale_BluetoothProbe_object_entry=False,
                core_archive=str(corearchive),core_sha256=sha(corearchive),core_members=125,
                core_objects_manifest_matches_actual_archive=True,historical_commands_requiring_explicit_provenance=stale,
                commands_not_selection_authority=True,metadata_modified=False)
    (out/'manifest-audit.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--native',type=Path,required=True);p.add_argument('--strict',type=Path,required=True)
    a=p.parse_args();out=a.out.resolve()
    if not out.is_relative_to(HERE) or out==HERE:raise ValueError('Output must stay below qualification-final')
    out.mkdir(exist_ok=False)
    if sha(a.native)!=NATIVE_SHA or sha(a.strict)!=STRICT_SHA:raise ValueError('Exact main full002 native/strict required')
    frozen=load(BUILD/'result.json')
    if sha(BUILD/'libSonyWcn.a')!=prior.BOARD_SHA or sha(BUILD/'result.json')!='6265e4438272233bab223b02f7bba0f355b751100bc887b8218b4e5a3f014d49':
        raise ValueError('Frozen002 inputs changed')
    for path,h in frozen['objects'].items():
        if sha(path)!=h:raise ValueError('Frozen object changed')
    if sha(prior.CACHE)!=prior.ORIGINAL:raise ValueError('Original D27 cache changed')
    originals=prior.original_classes(Image(prior.CACHE.read_bytes()),out)
    (out/'original-tables.json').write_text(json.dumps(originals,indent=2)+'\n')
    wifi=FRESH/'radio-board-size-001/objects/WifiNet.late.o'
    classes,metas=prior.audit_tables(out,originals,wifi);entries=prior.startup_object(out)
    audited={};readback={};allrows=[]
    for label,path in [('native',a.native),('strict',a.strict)]:
        im=Linked(path,out,label);tables,rows,constructors=im.tables(classes,metas);startup=im.startup(entries)
        audited[label]=dict(path=str(path),sha256=sha(path),tables=tables,constructors=constructors,startup=startup,
                            functions=im.write_codes(),PAC_slots=928,passed=True)
        (out/(label+'-linked.json')).write_text(json.dumps(audited[label],indent=2)+'\n')
        readback[label]=dict(path=str(path),sha256=sha(path),tables=tables,startup=startup,constructors=constructors)
        allrows.extend(rows)
    # Selected object/member identities are checked independently of call/PAC
    # code. Old command records are reported, never silently overwritten.
    metadata=manifest(a.native,out)
    strict_meta=load(a.strict.parent/'result.json')
    if strict_meta['strict_missing'] or strict_meta['strict_stubbed'] or strict_meta['native_sha256']!=NATIVE_SHA:
        raise ValueError('Strict receipts do not bind actual final native or contain missing/stubbed')
    windows=out/'windows-readback.json';windows.write_text(json.dumps(dict(schema=1,kind='actual chained fixup expectations',
        native=readback['native'],strict=readback['strict'],method_and_metaclass_slots_per_image=928,
        qca_startup_records_per_image=5,hardware_verified=False),indent=2)+'\n')
    inputs={str(a.native):NATIVE_SHA,str(a.strict):STRICT_SHA,str(BUILD/'result.json'):sha(BUILD/'result.json'),
            str(BUILD/'libSonyWcn.a'):prior.BOARD_SHA,str(prior.CACHE):prior.ORIGINAL,
            str(wifi):sha(wifi),str(HERE/'qualify.py'):sha(HERE/'qualify.py'),str(Path(__file__)):sha(__file__),
            str(a.native.parent/'result.json'):sha(a.native.parent/'result.json'),
            str(a.native.parent/'native-link.command.json'):sha(a.native.parent/'native-link.command.json')}
    for path in [FRESH/'radio-board-size-002/libSonyWcn.a',FRESH/'radio-board-size-002/result.json',
                 FRESH/'radio-core-size-002/libSonyAth12kCore.a',FRESH/'radio-core-size-002/result.json']:
        inputs[str(path)]=sha(path)
    # Bind all prior immutable source/header snapshots without changing them.
    snapshots=load(HERE/'run008-native/source-snapshots.json')
    for r in snapshots:
        if sha(r['path'])!=r['sha256']:raise ValueError('Earlier immutable ABI source snapshot changed')
        inputs[r['path']]=r['sha256']
    result=dict(schema=1,passed=True,native_sha256=NATIVE_SHA,strict_sha256=STRICT_SHA,original_layout_retained=True,
        actual_selected_archive=metadata['board_archive'],archive_sha256=metadata['board_sha256'],
        method_slots=858,metaclass_slots=70,total_PAC_slots_per_image=928,total_PAC_slots_verified=1856,
        qca_init_records_per_image=5,actual_boot_calls_and_sorting_verified=True,
        outlined_Oz_vptr_signer_verified=True,vptr_schema='DA/0xcda1/address-diverse',
        startup_callback_schema='IA/0x2abe/no-address-diversity',strict_missing=[],strict_stubbed=[],
        object_manifest_matches_actual_archive=True,stale_BluetoothProbe_object_entry=False,
        historical_O2_command_provenance_entries=metadata['historical_commands_requiring_explicit_provenance'],
        firmware_providers_qualified=False,production_arguments=['wifi=0','bluetooth=0'],
        hardware_verified=False,association_verified=False,pairing_verified=False,
        frozen_inputs_modified=False,previous_helpers_modified=False,device_operations=False,
        windows_readback=str(windows),windows_readback_sha256=sha(windows),inputs=inputs,
        reports={str(out/(name+'.json')):sha(out/(name+'.json')) for name in ['native-linked','strict-linked','compiled-tables','original-tables','qca-startup-object','manifest-audit']})
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('inputs','reports','historical_O2_command_provenance_entries')},indent=2))

if __name__=='__main__':main()
