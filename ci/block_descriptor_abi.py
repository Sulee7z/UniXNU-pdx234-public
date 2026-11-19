"""Original D27 Blocks descriptor ABI, enabled at the LLVM frontend boundary."""
from pathlib import Path
import hashlib
import json

FLAGS = ['-Xclang', '-fptrauth-block-descriptor-pointers']
FEATURE = 'ptrauth_signed_block_descriptors'


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def enabled(command):
    return any(command[i:i+2] == FLAGS for i in range(len(command)-1))


def validate_record(record):
    """Bind flag-only repairs to actual sources, original objects and all linked replacements."""
    from compile_dependencies import valid
    if not record.get('passed') or record.get('compiler_flags') != FLAGS:
        raise ValueError('Unqualified Blocks descriptor ABI record')
    if not record.get('all_selected_producers_rebuilt') or not record.get('all_private_header_consumers_rebuilt'):
        raise ValueError('Incomplete Block producer/consumer closure')
    for row in record['replacements']:
        if digest(row['old_object']) != row['old_sha256'] or digest(row['new_object']) != row['new_sha256']:
            raise ValueError('Block object identity changed')
        if digest(row['source']) != row['source_sha256']:
            raise ValueError('Block producer/consumer source changed')
        receipt = json.loads(Path(row['dependency_receipt']).read_text())
        if not valid(receipt) or not enabled(receipt['command']):
            raise ValueError('Signed Block compile dependencies changed')
