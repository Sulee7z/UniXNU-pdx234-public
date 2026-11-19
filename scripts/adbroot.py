"""Minimal ADB helpers for the Sony recovery shell.

Windows host notes (see AGENTS.md): `exec-out` preserves bytes but drops the
remote exit status, so it is only used for length-verified binary reads;
`shell -T` propagates the exit status and is used for checked control.
"""
import hashlib
import subprocess

ADB = r'G:\UniXNU-Port\tools\platform-tools\adb.exe'
SERIAL = 'PDX_DEVICE_SERIAL'


def _base():
    return [ADB, '-s', SERIAL]


def sh(command, timeout=300):
    """Checked control command. Raises on a non-zero remote exit status."""
    done = subprocess.run([*_base(), 'shell', '-T', command], capture_output=True, timeout=timeout)
    if done.returncode:
        raise RuntimeError(f'remote exit {done.returncode}: {command}\n{done.stderr.decode(errors="replace")}')
    return done.stdout.replace(b'\r\n', b'\n')


def text(command, timeout=300):
    return sh(command, timeout).decode(errors='replace')


def binary(command, expect, timeout=1800):
    """Exact-length binary read. The length is verified before the bytes are used."""
    done = subprocess.run([*_base(), 'exec-out', command], capture_output=True, timeout=timeout)
    if len(done.stdout) != expect:
        raise RuntimeError(f'expected {expect} bytes, got {len(done.stdout)}: {command}')
    return done.stdout


def sha256_file(path, chunk=1 << 22):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        while True:
            block = stream.read(chunk)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def push(local, remote, timeout=600):
    done = subprocess.run([*_base(), 'push', local, remote], capture_output=True, timeout=timeout)
    if done.returncode:
        raise RuntimeError(f'push failed: {local} -> {remote}\n{done.stdout.decode(errors="replace")}\n{done.stderr.decode(errors="replace")}')
    return done.stdout + done.stderr


def range_sha256(offset, length):
    """Device-side SHA256 of a byte range; the data never crosses the ADB link."""
    command = (f'dd if=/dev/block/sda98 bs=1048576 skip={offset} count={length} '
               f'iflag=skip_bytes,count_bytes status=none | sha256sum')
    parts = text(command, timeout=3600).split()
    if len(parts) != 2 or len(parts[0]) != 64:
        raise RuntimeError('malformed device readback digest')
    return parts[0]
