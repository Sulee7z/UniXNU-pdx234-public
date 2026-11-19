"""The retained DarwinBoot and XNU boot_args share a1024-byte ASCII field.

The final NUL occupies one byte. Never truncate: silently dropping the tail can
change driver and storage policy. This check belongs before image publication,
not only in the menu TOML parser or the kernel Mach-O structural check.
"""
import hashlib

COMMAND_LINE_CAPACITY=1024
MAX_ARGUMENT_BYTES=COMMAND_LINE_CAPACITY-1


def validate(arguments):
    if not isinstance(arguments,str):raise ValueError('Darwin boot arguments must be a string')
    if '\0' in arguments:raise ValueError('Darwin boot arguments contain an embedded NUL')
    try:raw=arguments.encode('ascii')
    except UnicodeEncodeError as error:raise ValueError('DarwinBoot accepts ASCII boot arguments only') from error
    if len(raw)>MAX_ARGUMENT_BYTES:
        raise ValueError(f'DarwinBoot rejects {len(raw)} argument bytes; maximum{MAX_ARGUMENT_BYTES} plus one NUL')
    return dict(passed=True,ascii_bytes=len(raw),capacity_bytes=COMMAND_LINE_CAPACITY,
        terminator_bytes=1,remaining_argument_bytes=MAX_ARGUMENT_BYTES-len(raw),
        sha256=hashlib.sha256(raw).hexdigest(),truncated=False)
