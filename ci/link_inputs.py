"""Enumerate the actual file inputs of the recorded native linker command."""
from pathlib import Path


def collect_link_inputs(command, *, cwd=None):
    """Include filelists, direct objects, ordinary archives, and -Wl paths.

    Do not use a previous input receipt as the authority: older receipts omitted
    the trailing objects and archives passed outside -filelist/-force_load.
    Missing files fail closed, rather than silently disappearing from an export.
    """
    if not command:
        raise ValueError('Empty linker command')
    base = Path(cwd or Path.cwd())
    files = {}
    library_dirs = []
    libraries = []

    def add(value, role):
        path = Path(value)
        if not path.is_absolute():
            path = base/path
        path = path.absolute()
        if str(path) == '/dev/null':
            return
        if not path.is_file():
            raise FileNotFoundError(f'Missing linker {role}: {path}')
        files.setdefault(path, set()).add(role)

    def filelist(value):
        add(value, 'filelist')
        path = Path(value)
        if not path.is_absolute():
            path = base/path
        for name in path.read_text().splitlines():
            if name.strip():
                add(name.strip(), 'filelist-member')

    add(command[0], 'driver')
    index = 1
    while index < len(command):
        token = command[index]
        if token == '-o':
            index += 2
            continue
        if token in ('-filelist', '-L'):
            if index + 1 == len(command):
                raise ValueError('Missing value for ' + token)
            value = command[index + 1]
            if token == '-filelist':
                filelist(value)
            else:
                library_dirs.append(Path(value))
            index += 2
            continue
        if token.startswith('-L'):
            library_dirs.append(Path(token[2:]))
        elif token.startswith('-l'):
            libraries.append(token[2:])
        elif token.startswith('@'):
            raise ValueError('Expand the linker response file before exporting: ' + token)
        elif token.startswith('-Wl,'):
            parts = token[4:].split(',')
            if parts[0] == '-filelist':
                if len(parts) != 2:
                    raise ValueError('Unsupported linker filelist syntax: ' + token)
                filelist(parts[1])
            elif parts[0] == '-o':
                pass
            elif parts[0] == '-L' and len(parts) == 2:
                library_dirs.append(Path(parts[1]))
            else:
                for part in parts:
                    if part.startswith('/'):
                        add(part, 'linker-option')
        elif token.startswith('/') or not token.startswith('-') and Path(token).suffix in ('.o', '.cpo', '.a'):
            add(token, 'direct-input')
        index += 1
    for name in libraries:
        matches = [directory/('lib' + name + '.a') for directory in library_dirs]
        found = next((path for path in matches if path.is_file()), None)
        if found is None:
            raise FileNotFoundError('Static linker library not found: -l' + name)
        add(found, 'searched-library')
    return {path: sorted(roles) for path, roles in sorted(files.items())}
