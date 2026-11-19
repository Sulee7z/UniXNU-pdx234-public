"""Compiler-emitted dependency receipts; legacy source-only caches are misses."""
import hashlib
from pathlib import Path
import shlex
import json
import subprocess


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def capture(depfile, directory, compiler):
    # The caller uses a fixed -MT token, avoiding drive/path colons in the target.
    text = Path(depfile).read_text().replace('\\\n', '')
    target, separator, body = text.partition(':')
    if not separator or target.strip() != 'pdx_object':
        raise ValueError('Invalid compiler dependency target')
    paths = shlex.split(body.replace('$$', '$'), comments=False, posix=True)
    if not paths:
        raise ValueError('Empty compiler dependency list')
    dependencies = {}
    for name in paths:
        path = Path(name)
        if not path.is_absolute():
            path = Path(directory) / path
        # Keep lexical paths: retargeting a symlink must invalidate the receipt.
        dependencies[str(path.absolute())] = digest(path)
    return dict(dependency_schema=1, dependencies=dependencies,
                dependency_compiler=str(compiler), dependency_compiler_sha256=digest(compiler))


def valid(receipt):
    if receipt.get('dependency_schema') != 1 or not receipt.get('dependencies'):
        return False
    try:
        return (digest(receipt['dependency_compiler']) == receipt['dependency_compiler_sha256'] and
                all(digest(path) == expected for path, expected in receipt['dependencies'].items()))
    except (OSError, KeyError):
        return False


def run_recorded(command, **kwargs):
    """subprocess.run-compatible compiler invocation for isolated archive recipes."""
    command = list(map(str, command))
    sources = [Path(v) for v in command if Path(v).suffix in ('.c', '.cpp', '.mm', '.cc')]
    tracked = '-c' in command and '-o' in command and len(sources) == 1
    if tracked:
        output = Path(command[command.index('-o') + 1])
        deps = output.with_name(output.name + '.d')
        command += ['-MD', '-MF', str(deps), '-MT', 'pdx_object']
    result = subprocess.run(command, **kwargs)
    if tracked and result.returncode == 0:
        receipt = capture(deps, kwargs.get('cwd', Path.cwd()), command[0])
        receipt.update(source=str(sources[0]), object=str(output), object_sha256=digest(output), command=command)
        output.with_name(output.name + '.dependencies.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return result
