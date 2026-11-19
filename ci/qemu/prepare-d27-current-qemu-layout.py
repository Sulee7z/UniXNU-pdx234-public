#!/usr/bin/env python3
"""Read current process offsets from exact linked-object debug types."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')


def sha(path):
    with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    # Read debug types from the exact linked current objects. No header-selection
    # probe is necessary and the guest receives no diagnostic object.
    def dump(name,group,file):
        obj=BASE/'native-screen007-055-001/objects/xnu'/group/'DEVELOPMENT'/file
        receipt=json.loads(Path(str(obj)+'.json').read_text())
        if receipt['exit'] or sha(obj)!=receipt['sha256']:raise ValueError('Object provenance differs')
        command=['/usr/lib/llvm-18/bin/llvm-dwarfdump','--debug-info',str(obj)]
        text=subprocess.check_output(command,text=True,timeout=45)
        (a.out/(name+'.dwarf.txt')).write_text(text)
        nodes={};current=None;stack=[]
        for line in text.splitlines():
            match=re.match(r'^(0x[0-9a-f]+): ( *)(DW_TAG_\w+|NULL)',line)
            if match:
                ident,spaces,tag=match.groups();depth=len(spaces)//2
                while stack and stack[-1]['depth']>=depth:stack.pop()
                current=dict(id=ident,tag=tag,depth=depth,children=[],attrs={})
                if stack:stack[-1]['children'].append(current)
                nodes[ident]=current
                if tag!='NULL':stack.append(current)
            elif current:
                attr=re.search(r'DW_AT_(\w+)\s+\((.*)\)',line)
                if attr:current['attrs'][attr.group(1)]=attr.group(2)
        roots=[node for node in nodes.values() if node['tag']=='DW_TAG_structure_type'
               and node['attrs'].get('name')=='"'+name+'"' and 'byte_size' in node['attrs']]
        if len(roots)!=1:raise ValueError('Require one complete '+name+' type')
        def target(node):
            value=node['attrs'].get('type','').split(' ')[0]
            return nodes.get(value)
        def member(node,field,depth=0):
            if depth>7:return []
            found=[]
            first,_,rest=field.partition('.')
            for child in node['children']:
                if child['tag']!='DW_TAG_member':continue
                offset=int(child['attrs'].get('data_member_location','0'),0)
                if child['attrs'].get('name')=='"'+first+'"':
                    if not rest:found.append(offset)
                    elif (dest:=target(child)):found.extend(offset+value for value in member(dest,rest,depth+1))
                elif (dest:=target(child)) and dest['tag'] in ('DW_TAG_structure_type','DW_TAG_union_type'):
                    found.extend(offset+value for value in member(dest,field,depth+1))
            return found
        def field(key):
            matches=set(member(roots[0],key))
            if len(matches)!=1:raise ValueError('Missing/ambiguous '+name+'.'+key+': '+repr(matches))
            return matches.pop()
        return field,dict(object=str(obj),object_sha256=sha(obj),dwarf_sha256=sha(a.out/(name+'.dwarf.txt')))
    proc,rp=dump('proc','bsd','bsd_init.o')
    thread,rt=dump('thread','osfmk','thread.o')
    tro,rr=dump('thread_ro','osfmk','thread.o')
    task,rta=dump('task','osfmk','task.o')
    region,rs=dump('vm_shared_region','osfmk','vm_shared_region.o')
    machine,rm=dump('machine_thread','osfmk','thread.o')
    values=dict(thread_ro=thread('t_tro'),ro_owner=tro('tro_owner'),ro_proc=tro('tro_proc'),
                ro_task=tro('tro_task'),task_region=task('shared_region'),region_slide=region('sr_slide'),
                pid=proc('p_pid'),comm=proc('p_comm'),stat=proc('p_stat'),list=proc('p_list.le_next'),
                thread_user_state=thread('machine')+machine('upcb'))
    result=dict(process_layout=values,objects=[rp,rt,rr,rta,rs,rm],compiler_qualified=True,
                current_native_parent_sha256='2ce2ed908371689c5d41e4da9c2cf8d23c96450084c91718aaa5dc440c9ff1e8',
                probe_linked_or_executed=False,device_operations=False)
    (a.out/'plan.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
