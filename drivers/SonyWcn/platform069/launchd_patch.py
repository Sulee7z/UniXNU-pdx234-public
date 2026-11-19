"""Composable radio069 launchd mapping: accepts current068/app-patched bytes.

Does not sign or replace a shared addon/cache. Main serializes with the actual
target Apple-compatible serializer and signs its once-merged final bytes.
"""
from __future__ import annotations
import copy, hashlib, json, plistlib
from pathlib import Path

BLUE_FIELDS={'UserName':'root','EnableTransactions':True,'EnablePressuredExit':False,'ThrottleInterval':3}
WIFI_JOB={'Label':'org.unixnu.wifi.supplicant','ProgramArguments':[
    '/usr/libexec/unixnu-wpa_supplicant','-Dsheng','-ien0','-c/private/var/ngpu/etc/wifi/wpa_supplicant.conf','-q','-s'],
    'RunAtLoad':True,'KeepAlive':True,'ThrottleInterval':3,'UserName':'root','Umask':0o77,'ProcessType':'Interactive'}

def patch_mapping(original:dict)->tuple[dict,dict]:
    merged=copy.deepcopy(original);jobs=merged['LaunchDaemons'];before={};after={}
    matches=[k for k,v in jobs.items() if v.get('Label')=='com.apple.BlueTool']
    if len(matches)!=1:raise ValueError('One real com.apple.BlueTool job required')
    name=matches[0];before[name]=copy.deepcopy(jobs[name]);jobs[name].update(BLUE_FIELDS);after[name]=copy.deepcopy(jobs[name])
    name='/System/Library/LaunchDaemons/org.unixnu.wifi.supplicant.plist'
    before[name]=copy.deepcopy(jobs.get(name))
    if before[name] is not None and before[name]!=WIFI_JOB:raise ValueError('Conflicting supplicant owner job')
    jobs[name]=copy.deepcopy(WIFI_JOB);after[name]=copy.deepcopy(jobs[name])
    # Preserve every unrelated field/job from the supplied current cache,
    # including main/app changes. Not a reset to original D27 contents.
    assert all(merged[k]==v for k,v in original.items() if k!='LaunchDaemons')
    assert all(jobs[k]==v for k,v in original['LaunchDaemons'].items() if k not in before)
    return merged,{'jobs_before':before,'jobs_after':after,'must_sign_once_after_main_merge':True,
                   'bluetoothd_job_unchanged':True,'original_input_type':'current supplied cache mapping'}

def patch_bytes(data:bytes)->tuple[bytes,dict]:
    merged,record=patch_mapping(plistlib.loads(data))
    record['input_sha256']=hashlib.sha256(data).hexdigest()
    xml=plistlib.dumps(merged,fmt=plistlib.FMT_XML,sort_keys=False)
    record['output_xml_sha256']=hashlib.sha256(xml).hexdigest()
    return xml,record

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',type=Path,required=True)
    p.add_argument('--xml',type=Path,required=True);p.add_argument('--record',type=Path,required=True);a=p.parse_args()
    if a.xml.exists() or a.record.exists():raise ValueError('Preserve previous patch output')
    xml,record=patch_bytes(a.input.read_bytes());a.xml.write_bytes(xml);a.record.write_text(json.dumps(record,indent=2)+'\n')
