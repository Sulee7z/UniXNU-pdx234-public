"""Optional qualifiers for main's logging metadata integration; never mutates main helpers."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('sony_logging067_source', HERE / 'source.py')
logging = importlib.util.module_from_spec(spec)
spec.loader.exec_module(logging)


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def composed_bsd(text):
    from usb_console import adapt_worker
    return logging.adapt_bsd_init(adapt_worker(text))


def composed_exec(text):
    from platform067.arm64e.source import adapt_source
    return logging.adapt_exec(adapt_source(text))


def expected_adapters():
    """Apply after existing adapters iff official_logging_067 is selected."""
    return {'usb27-worker': composed_bsd, 'audit-d27-addon-reference': composed_exec,
            'official067-log-startup': logging.adapt_startup,
            'official067-log-debug': logging.adapt_debug,
            'official067-log-exit': logging.adapt_exit}


def validate(record):
    from compile_dependencies import valid
    from block_descriptor_abi import enabled
    if not record.get('passed') or record.get('platform_sleep_enabled') or record.get('device_operations'):
        raise ValueError('Unqualified logging integration record')
    for path, expected in record['inputs'].items():
        with Path(path).open('rb') as stream:
            actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        if actual != expected:
            raise ValueError('Logging input identity changed: ' + path)
    for path in record['compile_receipts']:
        receipt = json.loads(Path(path).read_text())
        if not valid(receipt) or not enabled(receipt['command']) or '-fptrauth-function-pointer-type-discrimination' not in receipt['command']:
            raise ValueError('Logging PAC/dependency receipt changed')
    for row in record['source_overlay_rows']:
        text = Path(row['original_source']).read_text()
        actual = Path(row['source']).read_text()
        if digest(text) != row['original_source_sha256'] or digest(actual) != row['source_sha256']:
            raise ValueError('Logging source overlay hash changed')
        if expected_adapters()[row['native_source_patch']](text) != actual:
            raise ValueError('Logging source overlay no longer matches the composed qualified source')
