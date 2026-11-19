"""Qualified069 deltas over the exact067full002/068 physical native input."""
import hashlib
import importlib
import json
from pathlib import Path
import re

BASELINE_SHA='734bb8fc84437371c34f4e2afc43ef4a0b4191d1bfbcd4b6cf1d52d5080c37dd'
ROOT=Path(__file__).resolve().parents[2]


def sha(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def validate(record):
    from block_descriptor_abi import enabled
    from compile_dependencies import valid
    if (record.get('baseline_native_sha256')!=BASELINE_SHA or
            record.get('virtual_backends_selected') is not False or
            record.get('device_operations') is not False or
            record.get('inherited_block_descriptor_objects')!=66 or
            record.get('all_baseline_archive_members_retained') is not True):
        raise ValueError('069 must preserve the exact full physical068/PAC/Blocks baseline')
    if not record.get('inputs'):raise ValueError('069 integration lacks hash-bound inputs')
    for path,digest in record['inputs'].items():
        if sha(path)!=digest:raise ValueError('069 integration input changed: '+path)
    for path in record.get('compile_receipts',[]):
        receipt=json.loads(Path(path).read_text());command=receipt['command']
        if (not valid(receipt) or not enabled(command) or
                '-fptrauth-function-pointer-type-discrimination' not in command or
                sha(receipt['object'])!=receipt['object_sha256']):
            raise ValueError('069 selected compile identity/PAC ABI differs: '+path)


def expected_adapters(record):
    """Load only named, hash-bound069 qualifiers; retain all inherited checks."""
    result={}
    for row in record.get('source_qualifiers',[]):
        module=row['module']
        if not re.fullmatch(r'platform069(?:\.[A-Za-z_][A-Za-z_0-9]*)+',module):
            raise ValueError('Source qualifier must be an explicit069 Python module')
        filename=(ROOT/'ci').joinpath(*module.split('.')).with_suffix('.py')
        if sha(filename)!=row['sha256'] or record['inputs'].get(str(filename))!=row['sha256']:
            raise ValueError('069 source qualifier identity differs')
        adapters=getattr(importlib.import_module(module),'ADAPTERS',None)
        if (not isinstance(adapters,dict) or not adapters or
                any(not isinstance(name,str) or not callable(adapter) for name,adapter in adapters.items()) or
                result.keys()&adapters.keys()):
            raise ValueError('Missing, duplicate or invalid069 source adapters')
        result.update(adapters)
    return result
