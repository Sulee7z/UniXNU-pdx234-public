"""Hash-bound source/object/archive boundary for the physical066-derived refresh."""
import hashlib
import json
from pathlib import Path

BASE_SHA = '80b2b18120eafde479aa2eaebd4017a677a67405b0ba0fe33e8d00ad6b6bc3dc'


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def validate(record):
    from compile_dependencies import valid
    from block_descriptor_abi import enabled
    if record.get('baseline_native_sha256') != BASE_SHA:
        raise ValueError('Platform refresh must inherit exact physical066 and signed Blocks closure')
    for path, expected in record['inputs'].items():
        if sha(path) != expected:
            raise ValueError('Platform integration input changed: ' + path)
    for path in record.get('compile_receipts', []):
        dependency = json.loads(Path(path).read_text())
        if (not valid(dependency) or not enabled(dependency['command']) or
                '-fptrauth-function-pointer-type-discrimination' not in dependency['command'] or
                sha(dependency['object']) != dependency['object_sha256']):
            raise ValueError('Platform compile identity/PAC ABI differs: ' + path)
    if record.get('virtual_backends_selected') is not False:
        raise ValueError('Platform candidate cannot select virtual backends')
