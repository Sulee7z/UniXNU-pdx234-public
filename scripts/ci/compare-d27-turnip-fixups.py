#!/usr/bin/env python3
"""Read-only semantic comparison of legacy arm64e and modern userland24 chains."""
import argparse
import collections
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

spec = importlib.util.spec_from_file_location('dependency_audit', Path(__file__).with_name('audit-d27-turnip-dependencies.py'))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')


def image(path):
    data = path.read_bytes()
    commands = {}; segments = []; sections = {}; at = 32
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        command, size = struct.unpack_from('<II', data, at)
        commands[command] = data[at:at+size]
        if command == 0x19:
            name = data[at+8:at+24].split(b'\0')[0].decode()
            va, length, off, file_size = struct.unpack_from('<4Q', data, at+24)
            seg = dict(name=name, va=va, size=length, off=off, file_size=file_size)
            segments.append(seg)
            for j in range(struct.unpack_from('<I', data, at+64)[0]):
                s = at+72+j*80
                sn = data[s:s+16].split(b'\0')[0].decode()
                addr, length, off = struct.unpack_from('<QQI', data, s+32)
                sections[(name, sn)] = dict(va=addr, size=length, off=off)
        at += size
    meta = audit.macho(data)
    sym, count, strings, length = meta['symtab']
    undefs = {}
    for i in range(count):
        ix, kind, _, desc, _ = struct.unpack_from('<IBBHQ', data, sym+i*16)
        if kind & 14 or kind & 0xe0:
            continue
        ordinal = desc >> 8
        if ordinal >= 0xfe:
            ordinal -= 256
        undefs[audit.cstr(data, strings+ix)] = (ordinal, bool(desc & 0x40))
    return dict(path=path, data=data, commands=commands, segments=segments, sections=sections,
                metadata=meta, undefs=undefs, string_offset=strings, string_size=length)


def chains(img):
    data = img['data']; table = []; sites = {}; formats = set()
    def add_chain(segment, start, ordinal_bits):
        seg = img['segments'][segment]; position = start; seen = set()
        while True:
            assert position not in seen and 0 <= position <= seg['file_size']-8
            seen.add(position)
            word = struct.unpack_from('<Q', data, seg['off']+position)[0]
            authenticated = bool(word >> 63)
            bind = bool((word >> 62) & 1)
            va = seg['va']+position
            section, si = next((key, val) for key, val in img['sections'].items()
                               if val['va'] <= va and va+8 <= val['va']+val['size'])
            key = (section[0], section[1], va-si['va'])
            value = dict(bind=bind, authenticated=authenticated)
            if authenticated:
                value.update(diversity=(word>>32)&65535, address_diversity=bool((word>>48)&1), key=(word>>49)&3)
            if bind:
                ordinal = word & ((1 << ordinal_bits)-1)
                assert ordinal < len(table)
                name, library, weak, import_addend = table[ordinal]
                value.update(symbol=name, library=library, weak=weak, import_addend=import_addend)
                if not authenticated:
                    addend = (word>>32)&((1<<19)-1)
                    value['pointer_addend'] = addend-(1<<19) if addend&(1<<18) else addend
            else:
                value['target'] = word & 0xffffffff if authenticated else (word&((1<<43)-1)) | (((word>>43)&255)<<56)
            assert key not in sites
            sites[key] = value
            delta = (word>>51)&2047
            if not delta:
                break
            position += delta*8

    if 0x80000034 in img['commands']:
        off, size = struct.unpack_from('<II', img['commands'][0x80000034], 8)
        version, starts, imports, symbols, count, format_, symbol_format = struct.unpack_from('<7I', data, off)
        assert version == 0 and symbol_format == 0 and format_ == 1
        for i in range(count):
            entry = struct.unpack_from('<I', data, off+imports+4*i)[0]
            library = entry&255
            if library>=128:
                library -= 256
            table.append((audit.cstr(data, off+symbols+(entry>>9)), library, bool(entry&256), 0))
        base = off+starts
        segments = struct.unpack_from('<I', data, base)[0]
        for i in range(segments):
            relative = struct.unpack_from('<I', data, base+4+4*i)[0]
            if not relative:
                continue
            at = base+relative
            length, page_size, pointer_format, segment_offset, _, page_count = struct.unpack_from('<IHHQIH', data, at)
            formats.add(pointer_format)
            assert pointer_format == 12 and segment_offset == img['segments'][i]['va']
            for page in range(page_count):
                start = struct.unpack_from('<H', data, at+22+page*2)[0]
                if start == 0xffff:
                    continue
                assert not start&0x8000, 'Unsupported multi-start page'
                add_chain(i, page*page_size+start, 24)
        kind = 'LC_DYLD_CHAINED_FIXUPS'
    else:
        off, size = struct.unpack_from('<II', img['commands'][0x80000022], 16)
        cursor = off; end = off+size
        library = 0; name = ''; weak = False; addend = 0
        def leb(signed=False):
            nonlocal cursor
            value = 0; shift = 0
            while True:
                byte = data[cursor]; cursor += 1
                value |= (byte&127)<<shift; shift += 7
                if byte<128:
                    return value-(1<<shift) if signed and byte&64 else value
        while cursor<end:
            byte = data[cursor]; cursor += 1; op = byte&240; imm = byte&15
            if op==0x10: library=imm
            elif op==0x20: library=leb()
            elif op==0x30: library=imm-16 if imm else 0
            elif op==0x40:
                name=audit.cstr(data,cursor);cursor+=len(name.encode())+1;weak=bool(imm&1)
            elif op==0x50: assert imm==1
            elif op==0x60: addend=leb(True)
            elif op==0x70: segment=imm;position=leb()
            elif op==0x80: position+=leb()
            elif op==0x90: table.append((name,library,weak,addend))
            elif op==0xd0 and imm==0: expected=leb()
            elif op==0xd0 and imm==1: add_chain(segment,position,16)
            elif op==0: pass
            else: raise ValueError(f'Unsupported bind opcode {byte:x}')
        assert len(table)==expected
        kind='LC_DYLD_INFO_ONLY threaded arm64e'
    return dict(kind=kind,formats=sorted(formats),table=table,sites=sites)


def run(args):
    old=image(args.original); new=image(args.candidate)
    a=chains(old);b=chains(new)
    references = lambda x: collections.Counter(v['symbol'] for v in x['sites'].values() if v['bind'])
    oldrefs,newrefs=references(a),references(b)
    differences=[]
    for key in a['sites'].keys()|b['sites'].keys():
        if a['sites'].get(key)!=b['sites'].get(key):
            differences.append(dict(site=key,original=a['sites'].get(key),candidate=b['sites'].get(key)))
    # The export command gives on-disk offsets for these standalone dylibs.
    def exported(img):
        meta=img['metadata'];at=meta['export_offset']
        return audit.exports(img['data'][at:at+meta['export_size']])
    e1,e2=exported(old),exported(new)
    def normalized_section(img, decoded, key):
        sec=img['sections'][key]
        blob=bytearray(img['data'][sec['off']:sec['off']+sec['size']])
        for site in decoded['sites']:
            if site[:2]==key:
                blob[site[2]:site[2]+8]=bytes(8)
        return blob
    const_key=('__DATA_CONST','__const')
    weak_sites_equal=all(b['sites'].get(k)==v for k,v in a['sites'].items() if v.get('weak'))
    tlv_only=all(x['site'][:2]==('__DATA','__thread_vars') and
                 x['original'].get('symbol')==x['candidate'].get('symbol')=='__tlv_bootstrap' and
                 not x['original']['authenticated'] and x['candidate']['authenticated'] and
                 x['candidate']['diversity']==0 and not x['candidate']['address_diversity'] and
                 x['candidate']['key']==0 for x in differences)
    resolver=object.__new__(audit.Audit)
    resolver.loaded=json.loads(args.cache_metadata.read_text())
    resolved=[];missing=[]
    for name,(ordinal,weak) in new['undefs'].items():
        if weak:continue
        assert 1<=ordinal<=len(new['metadata']['dependencies'])
        library=new['metadata']['dependencies'][ordinal-1]['path']
        resolution=resolver.resolve(library,name)
        (resolved if resolution else missing).append(dict(symbol=name,library=library,resolution=resolution))
    version_checks=[]
    for dep in new['metadata']['dependencies']:
        provider=resolver.loaded[dep['path']]['identity']
        version_checks.append(dict(path=dep['path'],required=dep['compatibility'],actual=provider['current'],passes=provider['current']>=dep['compatibility']))
    optional=[n for n,(o,w) in old['undefs'].items() if o==-2 and w]
    systemweak=[n for n,(o,w) in old['undefs'].items() if o>0 and w]
    checks=dict(undefined_symbol_contract_equal=old['undefs']==new['undefs'],import_table_equal=a['table']==b['table'],
                import_table_multiset_equal=collections.Counter(a['table'])==collections.Counter(b['table']),
                referenced_symbol_counts_equal=oldrefs==newrefs,pointer_sites_equal=not differences,
                weak_pointer_sites_equal=weak_sites_equal,
                constant_table_pointer_sites_equal=all(b['sites'].get(k)==v for k,v in a['sites'].items() if k[:2]==const_key),
                constant_table_nonfixup_bytes_equal=normalized_section(old,a,const_key)==normalized_section(new,b,const_key),
                only_documented_tlv_signing_differences=tlv_only,
                exported_names_flags_targets_equal=e1==e2,
                dependencies_equal=old['metadata']['dependencies']==new['metadata']['dependencies'],
                code_bytes_equal=all(old['data'][s['off']:s['off']+s['size']]==new['data'][new['sections'][k]['off']:new['sections'][k]['off']+new['sections'][k]['size']]
                                     for k,s in old['sections'].items() if k==('__TEXT','__text')),
                strong_imports_resolved=len(resolved)==272 and not missing,
                dependency_versions_pass=all(v['passes'] for v in version_checks),
                optional_weak_all_preserved=all(new['undefs'].get(n)==(-2,True) and newrefs[n]==oldrefs[n] for n in optional),
                system_weak_all_preserved=all(new['undefs'].get(n)==old['undefs'][n] and newrefs[n]==oldrefs[n] for n in systemweak),
                candidate_stringpool_8_aligned=new['string_offset']%8==0)
    result=dict(original_sha256=hashlib.sha256(old['data']).hexdigest(),candidate_sha256=hashlib.sha256(new['data']).hexdigest(),
                original_fixups=a['kind'],candidate_fixups=b['kind'],candidate_pointer_formats=b['formats'],
                original_string_offset=hex(old['string_offset']),candidate_string_offset=hex(new['string_offset']),
                optional_weak_count=len(optional),system_weak_symbols=systemweak,
                original_pointer_site_count=len(a['sites']),candidate_pointer_site_count=len(b['sites']),
                original_bind_site_count=sum(oldrefs.values()),candidate_bind_site_count=sum(newrefs.values()),
                checks=checks,pointer_differences=differences,missing_strong=missing,versions=version_checks,
                resolved_strong=resolved,
                scope='offline structural/pointer/import equivalence; candidate neither signed nor executed by this audit')
    args.out.mkdir(parents=True,exist_ok=False)
    (args.out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    for label,chain in [('original',a),('candidate',b)]:
        (args.out/(label+'-sites.json')).write_text(json.dumps([dict(site=k,**v) for k,v in sorted(chain['sites'].items())],indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('resolved_strong','pointer_differences')},indent=2))
    if differences:print('FIRST POINTER DIFFERENCES',json.dumps(differences[:5],indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--original',type=Path,default=BASE/'metal-d27-startup-003/plugin/NativeAdrenoMetal.bundle/libvulkan_freedreno.dylib')
    parser.add_argument('--candidate',type=Path,required=True)
    parser.add_argument('--cache-metadata',type=Path,default=BASE/'turnip-dependency-audit-003/images.json')
    parser.add_argument('--out',type=Path,required=True)
    run(parser.parse_args())
