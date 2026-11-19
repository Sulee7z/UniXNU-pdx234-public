#!/usr/bin/env python3
"""Read-only official patch/effective object audit for the exact delivered 066 kernel.

No checkout, patch application, compiler, linker, or device command is executed.
Patch replay uses immutable Git blobs and Python strings, never the source tree.
Only --output and --details beneath this helper's directory may be written.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass
import difflib
import hashlib
from functools import lru_cache
import json
from pathlib import Path
import re
import shlex
import struct
import subprocess
import sys
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')
FRESH = Path('/mnt/f/UniXNU-Port-artifacts/platform067-20261118')
TREE_REL = 'sources/UniXNU/out/pdx234/ios-27.0.1-24A446-iphone14/pdx234_sheng27_bulk/tree'
PINS = {'UniXNU': 'b79adcbf881fae3c952206fdd53132ad99e9355a',
        'sheng': '6c42e1055ffb3b335fda991190ad221edaa7af3c'}
XNU_PIN = 'ac9718fb1af618d5ce8678d0dc6e8a58f252216f'
NATIVE_SHA = '80b2b18120eafde479aa2eaebd4017a677a67405b0ba0fe33e8d00ad6b6bc3dc'
STRICT_SHA = '0855e4bb87d6d22e974cd07f28cf3d62de14f07eb10d43f3a1de7458c5da7cf3'


@lru_cache(maxsize=None)
def sha(path: Path | str) -> str:
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load(path: Path) -> Any:
    return json.loads(path.read_text())


def command(args: list[str], **kwargs: Any) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          timeout=90, **kwargs).stdout


def path_info(path: Path) -> dict[str, Any]:
    return {'path': str(path), 'sha256': sha(path), 'bytes': path.stat().st_size}


@dataclass
class Hunk:
    old_start: int
    new_start: int
    lines: list[tuple[str, str]]
    label: str

    def old(self) -> list[str]:
        return [line for tag, line in self.lines if tag != '+']

    def new(self) -> list[str]:
        return [line for tag, line in self.lines if tag != '-']


@dataclass
class FileDiff:
    path: str
    created: bool
    hunks: list[Hunk]


def parse_patch(text: str) -> list[FileDiff]:
    result: list[FileDiff] = []
    old_name = ''
    current: FileDiff | None = None
    hunk: Hunk | None = None
    for line in text.splitlines():
        if line.startswith('diff --git '):
            hunk = None
            current = None
        elif line.startswith('--- '):
            old_name = line[4:].split('\t', 1)[0]
            hunk = None
        elif line.startswith('+++ '):
            name = line[4:].split('\t', 1)[0]
            if name.startswith('b/'):
                name = name[2:]
            current = FileDiff(name, old_name == '/dev/null', [])
            result.append(current)
            hunk = None
        elif line.startswith('@@ '):
            match = re.match(r'@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@(.*)', line)
            if not match or current is None:
                raise ValueError('Malformed hunk: ' + line)
            hunk = Hunk(int(match[1]), int(match[2]), [], match[3].strip())
            current.hunks.append(hunk)
        elif hunk is not None and line[:1] in (' ', '+', '-'):
            hunk.lines.append((line[0], line[1:]))
        elif hunk is not None and line and not line.startswith('\\ No newline'):
            hunk = None
    if not result:
        raise ValueError('No file diffs')
    return result


def locate(lines: list[str], needle: list[str], near: int) -> int | None:
    if not needle:
        return min(max(near, 0), len(lines))
    if lines[near:near + len(needle)] == needle:
        return near
    starts = [i for i, value in enumerate(lines) if value == needle[0] and
              lines[i:i + len(needle)] == needle]
    return min(starts, key=lambda i: abs(i - near)) if starts else None


class Replay:
    """Apply official changes in memory, keeping the last writer of every line."""
    def __init__(self, pristine: Path):
        self.pristine = pristine
        self.files: dict[str, list[tuple[str, str | None]]] = {}
        self.errors: list[dict[str, Any]] = []

    def get(self, relative: str, created: bool = False) -> list[tuple[str, str | None]]:
        if relative not in self.files:
            try:
                raw = subprocess.run(['git', '-C', str(self.pristine), 'show', XNU_PIN + ':' + relative],
                                     check=True, capture_output=True, timeout=30).stdout
                lines = raw.decode().splitlines()
            except subprocess.CalledProcessError:
                if not created:
                    raise
                lines = []
            self.files[relative] = [(line, None) for line in lines]
        return self.files[relative]

    def apply(self, patch_id: str, diffs: list[FileDiff]) -> None:
        for diff in diffs:
            try:
                owned = self.get(diff.path, diff.created)
            except (subprocess.CalledProcessError, UnicodeError) as exc:
                self.errors.append({'patch': patch_id, 'file': diff.path, 'error': str(exc)[:300]})
                continue
            offset = 0
            for index, hunk in enumerate(diff.hunks):
                old, new = hunk.old(), hunk.new()
                texts = [line for line, _ in owned]
                near = hunk.old_start - 1 + offset
                at = locate(texts, old, near)
                # Current architecture already carries this SoC MAX_CPUS=8 line.
                if at is None and locate(texts, new, hunk.new_start - 1 + offset) is not None:
                    continue
                # Unified patches tolerate outdated edge context. Never drop a changed line.
                dropped_left = dropped_right = 0
                body = list(hunk.lines)
                if at is None:
                    leading = next((i for i, (tag, _) in enumerate(body) if tag != ' '), len(body))
                    trailing = next((i for i, (tag, _) in enumerate(reversed(body)) if tag != ' '), len(body))
                    for fuzz in range(1, max(leading, trailing) + 1):
                        left, right = min(fuzz, leading), min(fuzz, trailing)
                        trial = body[left:len(body) - right if right else None]
                        trial_old = [line for tag, line in trial if tag != '+']
                        if old and not any(line.strip() for line in trial_old):
                            continue
                        # Never use a generic #else/#endif/brace as the sole
                        # surviving anchor after discarding target-specific code.
                        # Otherwise an additive hunk can be "applied" elsewhere.
                        semantic = [line.strip() for line in trial_old if line.strip() and
                                    not line.lstrip().startswith(('#', '//', '/*', '*')) and
                                    re.search(r'[A-Za-z_]', line)]
                        if old and not semantic:
                            continue
                        trial_at = locate(texts, trial_old, near + left)
                        if trial_at is not None:
                            at, body, dropped_left, dropped_right = trial_at, trial, left, right
                            old = trial_old
                            new = [line for tag, line in body if tag != '-']
                            break
                if at is None:
                    self.errors.append({'patch': patch_id, 'file': diff.path, 'hunk': index,
                                        'label': hunk.label, 'error': 'old hunk not found in ordered pristine replay'})
                    continue
                replacement = []
                cursor = at
                for tag, line in body:
                    if tag == '+':
                        replacement.append((line, patch_id))
                    elif tag == ' ':
                        replacement.append(owned[cursor])
                        cursor += 1
                    else:
                        cursor += 1
                owned[at:at + len(old)] = replacement
                offset = at - (hunk.old_start - 1) + len(new) - len(old) - dropped_left


def series_paths(fresh: Path, tree: Path | None = None) -> list[tuple[str, Path, str]]:
    core = fresh / 'UniXNU'
    declarations = [('architecture', core / 'profiles/arch/arm64e/patches/xnu/series')]
    if tree:
        declarations.append(('soc-replay-input', tree / 'patches/xnu/series'))
    declarations += [
        ('os', core / 'profiles/os/ipados-27.0.1-24A446/patches/xnu/series'),
        ('sheng-board', fresh / 'sheng/patches/xnu-12377/series')]
    rows = []
    for category, series in declarations:
        for line in series.read_text().splitlines():
            name = line.split('#', 1)[0].strip()
            if not name:
                continue
            path = (core / 'profiles/arch/arm64e' / name[5:]) if name.startswith('arch:') else series.parent / name
            rows.append((category, path.resolve(), str(series)))
    return rows


def ar_members(path: Path) -> list[tuple[str, str, int]]:
    raw = path.read_bytes()
    if not raw.startswith(b'!<arch>\n'):
        raise ValueError('Not a regular archive: ' + str(path))
    at, strings, rows = 8, b'', []
    while at < len(raw):
        header = raw[at:at + 60]
        if len(header) != 60 or header[58:] != b'`\n':
            raise ValueError('Malformed archive member: ' + str(path))
        name = header[:16].decode().strip()
        size = int(header[48:58])
        body = raw[at + 60:at + 60 + size]
        if len(body) != size:
            raise ValueError('Truncated archive: ' + str(path))
        if name == '//':
            strings = body
        elif name not in ('/', '/SYM64/'):
            if name.startswith('#1/'):
                count = int(name[3:])
                name, body = body[:count].rstrip(b'\0').decode(), body[count:]
            elif name.startswith('/') and name[1:].isdigit():
                name = strings[int(name[1:]):].split(b'/\n', 1)[0].decode()
            else:
                name = name.rstrip('/')
            if not name.startswith('__.SYMDEF'):
                rows.append((name, hashlib.sha256(body).hexdigest(), len(body)))
        at += 60 + size + (size & 1)
    return rows


def selected_inputs(native: Path) -> tuple[list[str], list[str]]:
    link = load(native / 'native-link.command.json')
    inputs = []
    for index, value in enumerate(link):
        if value == '-filelist':
            inputs += shlex.split(Path(link[index + 1]).read_text())
        elif value.startswith('-Wl,-force_load,'):
            inputs.append(value.split('-Wl,-force_load,', 1)[1])
        elif value.endswith(('.o', '.a')) and not value.startswith('-'):
            inputs.append(value)
    return link, list(dict.fromkeys(inputs))


def source_for_record(record: dict[str, Any]) -> str | None:
    source = record.get('source')
    if source:
        return source
    values = [s for s in record.get('command', []) if Path(s).suffix in ('.c', '.cpp', '.s', '.S', '.cc', '.mm')]
    return values[0] if len(values) == 1 else None


def read_receipt(obj: str) -> tuple[Path | None, dict[str, Any]]:
    for suffix in ('.dependencies.json', '.json'):
        path = Path(obj + suffix)
        if path.is_file():
            return path, load(path)
    return None, {}


def build_effective_index(base: Path, native: Path) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    result = load(native / 'result.json')
    plan = load(base / 'native-screen007-055-001/plan.json')
    tree = base / TREE_REL
    work = tree / '.cache/xnu-work'
    _, inputs = selected_inputs(native)
    xnu_map = {row['source']: row['original_source'] for row in result['native_source_patches']}
    xnu_map.update({row['source']: row.get('original_source', row['source'])
                    for row in plan['jobs'] if row.get('original_source')})
    index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    receipt_counts = Counter()
    objects = []
    for name in inputs:
        if name.endswith('.a'):
            continue
        receipt_path, rec = read_receipt(name)
        source = source_for_record(rec)
        expected = rec.get('object_sha256', rec.get('sha256'))
        actual = sha(name)
        row = {'object': name, 'object_sha256': actual, 'receipt': str(receipt_path) if receipt_path else None,
               'object_receipt_matches': bool(expected and expected == actual), 'source': source,
               'command': rec.get('command', []), 'dependencies': rec.get('dependencies', {}),
               'source_hash_matches': None, 'dependency_schema': rec.get('dependency_schema')}
        if source:
            row['source_sha256'] = sha(source)
            source_expected = rec.get('source_sha256') or rec.get('dependencies', {}).get(source)
            row['source_hash_matches'] = bool(source_expected and source_expected == row['source_sha256'])
            original = xnu_map.get(source, source)
            try:
                relative = str(Path(original).relative_to(work))
            except ValueError:
                relative = None
            if relative:
                row['xnu_relative'] = relative
                index[relative].append(row)
        for dependency, digest in row['dependencies'].items():
            try:
                relative = str(Path(dependency).relative_to(work))
            except ValueError:
                continue
            if dependency == source:
                continue
            dep_row = {'object': name, 'object_sha256': actual, 'receipt': str(receipt_path),
                       'object_receipt_matches': row['object_receipt_matches'], 'source': dependency,
                       'source_sha256': sha(dependency), 'source_hash_matches': sha(dependency) == digest,
                       'role': 'compiler-dependency', 'consumer_source': source}
            index[relative].append(dep_row)
        receipt_counts['objects'] += 1
        receipt_counts['with_receipt'] += receipt_path is not None
        receipt_counts['with_dependency_schema'] += rec.get('dependency_schema') == 1
        receipt_counts['object_mismatch'] += bool(expected and expected != actual)
        receipt_counts['object_receipt_missing'] += expected is None
        receipt_counts['source_mismatch_or_unrecorded'] += row['source_hash_matches'] is not True
        objects.append(row)
    # Retain each source once in the per-file comparison; all consumer identities stay in the details.
    dependency_expected: dict[str, set[str]] = defaultdict(set)
    for row in objects:
        for path, digest in row['dependencies'].items():
            dependency_expected[path].add(digest)
    dependency_status = [{'path': p, 'expected_sha256': sorted(expected), 'actual_sha256': sha(p),
                          'valid': expected == {sha(p)}} for p, expected in sorted(dependency_expected.items())]
    receipt_counts['unique_dependency_paths'] = len(dependency_status)
    receipt_counts['dependency_mismatches'] = sum(not r['valid'] for r in dependency_status)
    return index, {'counts': dict(receipt_counts), 'objects': objects, 'inputs': inputs,
                   'dependency_validation': dependency_status,
                   'archive_inputs': [path_info(Path(p)) for p in inputs if p.endswith('.a')],
                   'work': str(work), 'plan': path_info(base / 'native-screen007-055-001/plan.json')}


def archive_audit(base: Path, native: Path, inventory: dict[str, Any]) -> dict[str, Any]:
    plan = load(base / 'native-screen007-055-001/plan.json')
    candidates: set[Path] = {Path(j['output']) for j in plan['jobs']}
    roots = [base / 'native-screen007-055-001/objects', base / 'display-source-009/build',
             base / 'boot-screen-015', base / 'gpu-source-006/build', base / 'sony-touch-driver-014', native]
    for root in roots:
        candidates.update(root.rglob('*.o'))
    by_hash: dict[str, list[Path]] = defaultdict(list)
    for obj in sorted(candidates):
        if obj.is_file():
            by_hash[sha(obj)].append(obj)
    archives = []
    dependencies: dict[str, set[str]] = defaultdict(set)
    for archive in inventory['archive_inputs']:
        path = Path(archive['path'])
        members = []
        for name, digest, size in ar_members(path):
            matches = by_hash.get(digest, [])
            row: dict[str, Any] = {'name': name, 'sha256': digest, 'bytes': size,
                                   'matching_objects': [str(p) for p in matches]}
            if matches:
                obj = matches[0]
                receipt, rec = read_receipt(str(obj))
                transformed = False
                if receipt is None and '.late.o' in obj.name:
                    receipt, rec = read_receipt(str(obj).replace('.late.o', '.o'))
                    transformed = receipt is not None
                if receipt:
                    source = source_for_record(rec)
                    row.update(receipt=path_info(receipt), source=source,
                               source_hash_valid=bool(source and (rec.get('source_sha256') or rec.get('dependencies', {}).get(source)) == sha(source)),
                               dependency_count=len(rec.get('dependencies', {})),
                               command_sha256=hashlib.sha256(json.dumps(rec.get('command', [])).encode()).hexdigest(),
                               pac_flags=[s for s in rec.get('command', []) if 'ptrauth' in s or 'arm64e' in s],
                               late_section_transformation=transformed,
                               object_receipt_matches=(rec.get('object_sha256', rec.get('sha256')) == digest) if not transformed else None)
                    for dep, value in rec.get('dependencies', {}).items():
                        dependencies[dep].add(value)
            members.append(row)
        archives.append({**archive, 'members': members, 'member_count': len(members),
                         'members_hash_bound_to_object': sum(bool(r['matching_objects']) for r in members)})
    validation = [{'path': path, 'expected_sha256': sorted(values), 'actual_sha256': sha(path),
                   'valid': values == {sha(path)}} for path, values in sorted(dependencies.items())]
    return {'archives': archives, 'unique_dependencies': len(validation),
            'dependency_mismatches': [v for v in validation if not v['valid']],
            'members': sum(a['member_count'] for a in archives),
            'hash_bound_members': sum(a['members_hash_bound_to_object'] for a in archives)}


def extend_dependency_index(index: dict[str, list[dict[str, Any]]], inventory: dict[str, Any],
                            archives: dict[str, Any], work: Path) -> None:
    """Connect exported header copies and source files supplied through archives."""
    for archive in archives['archives']:
        for member in archive['members']:
            source = member.get('source')
            if not source:
                continue
            try:
                relative = str(Path(source).relative_to(work))
            except ValueError:
                continue
            index[relative].append({'object': archive['path'] + '(' + member['name'] + ')',
                                    'source': source, 'role': 'archive-translation-unit'})
    exports: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in inventory['objects']:
        for dependency, digest in row['dependencies'].items():
            if '/EXPORT_HDRS/' not in dependency:
                continue
            exports[Path(dependency).name].append({'object': row['object'], 'source': dependency,
                                                   'role': 'exported-compiler-dependency', 'digest': digest})
    # Only hash-identical copies qualify; a matching basename alone is never proof.
    for path in work.rglob('*.h'):
        matches = exports.get(path.name)
        if matches:
            digest = sha(path)
            index[str(path.relative_to(work))].extend({k: v for k, v in row.items() if k != 'digest'}
                                                     for row in matches if row['digest'] == digest)


def changed_chunks(hunk: Hunk) -> list[list[str]]:
    chunks, current = [], []
    for tag, line in hunk.lines:
        if tag == '+':
            current.append(line)
        elif current:
            chunks.append(current)
            current = []
    if current:
        chunks.append(current)
    return chunks


def normalize(lines: list[str]) -> list[str]:
    return [line.strip() for line in lines]


def compare_diffs(diffs: list[FileDiff], index: dict[str, list[dict[str, Any]]],
                  work: Path) -> list[dict[str, Any]]:
    output = []
    for diff in diffs:
        candidates: dict[str, dict[str, Any]] = {}
        for rec in index.get(diff.path, []):
            candidates.setdefault(rec['source'], rec)
        if not candidates:
            path = work / diff.path
            if path.is_file():
                candidates[str(path)] = {'source': str(path), 'role': 'unlinked-work-tree'}
        if not candidates:
            output.append({'file': diff.path, 'status': 'file-absent', 'hunks': []})
            continue
        file_rows = []
        for source, rec in candidates.items():
            text = Path(source).read_text()
            lines = text.splitlines()
            norms = normalize(lines)
            hunks = []
            for number, hunk in enumerate(diff.hunks):
                new, old = hunk.new(), hunk.old()
                new_at = locate(lines, new, hunk.new_start - 1)
                old_at = locate(lines, old, hunk.old_start - 1) if old else None
                chunks = changed_chunks(hunk)
                present = [locate(lines, part, 0) for part in chunks]
                normalized = [locate(norms, normalize(part), 0) for part in chunks]
                if new_at is not None:
                    status = 'exact-new-hunk'
                elif chunks and all(at is not None for at in present):
                    status = 'added-chunks-present-context-changed'
                elif chunks and all(at is not None for at in normalized):
                    status = 'added-chunks-present-whitespace-changed'
                elif old and old_at is not None:
                    status = 'old-hunk-present'
                else:
                    status = 'changed-or-partial'
                hunks.append({'index': number, 'label': hunk.label, 'status': status,
                              'new_hunk_line': new_at + 1 if new_at is not None else None,
                              'old_hunk_line': old_at + 1 if old_at is not None else None,
                              'addition_chunks': len(chunks),
                              'present_addition_chunks': sum(at is not None for at in present),
                              'missing_additions': ['\n'.join(part) for part, at in zip(chunks, normalized) if at is None]})
            file_rows.append({'source': source, 'sha256': sha(source), 'role': rec.get('role', 'translation-unit'),
                              'selected_objects': sorted({r['object'] for r in index.get(diff.path, []) if r['source'] == source}),
                              'hunks': hunks})
        output.append({'file': diff.path, 'sources': file_rows})
    return output


def audit_logs(logdir: Path) -> dict[str, Any]:
    terms = {'enospc': r'ENOSPC|No space left on device\(28\)',
             'fatal_memory_limit': r'exceeded mem limit: .*\(fatal\)',
             'per_process_kill': r'killing_specific_process.*per-process-limit',
             'highwater_kill': r'killing_highwater_process',
             'long_idle_reap': r'killing_idle_process.*long-idle-exit',
             'exc_guard': r'EXC_GUARD AST:', 'pac_exception': r'PAC_EXCEPTION|PAC exception|ptrauth failure',
             'sigtrap_literal': r'SIGTRAP',
             'metal_sandbox_write_denial': r'deny\(1\) file-write-create /private/var/mobile/Library/Caches/org\.unixnu\.metal'}
    output = {'files': {}, 'limits': 'slots are truncated periodic excerpts; msgbuf is a rolling tail, not a complete per-app crash report'}
    for filename in ('header.txt', 'latest.txt', 'slots.txt', 'msgbuf.txt'):
        path = logdir / filename
        lines = path.read_text(errors='replace').splitlines()
        row: dict[str, Any] = path_info(path)
        if filename.endswith('txt') and filename in ('header.txt', 'latest.txt'):
            row['text'] = '\n'.join(lines)
        else:
            row['events'] = {}
            for name, regex in terms.items():
                matches = [{'line': i + 1, 'text': line[:1500]} for i, line in enumerate(lines) if re.search(regex, line)]
                row['events'][name] = {'matching_lines': len(matches), 'examples': matches[:3] + matches[-3:] if len(matches) > 6 else matches}
        output['files'][filename] = row
    return output


def safe_write(path: Path, value: Any) -> None:
    path = path.resolve()
    allowed = [HERE, REPO / 'evidence']
    if not any(path.is_relative_to(p) for p in allowed):
        raise ValueError('Output outside assigned audit paths: ' + str(path))
    if path.is_relative_to(REPO / 'evidence') and path.name != 'd27-platform067-arm64e.json':
        raise ValueError('Only the assigned evidence file may be written')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, default=BASE)
    parser.add_argument('--fresh', type=Path, default=FRESH)
    parser.add_argument('--native', type=Path)
    parser.add_argument('--strict', type=Path)
    parser.add_argument('--logdir', type=Path, default=Path('/mnt/g/UniXNU-Port/evidence/Xperia-XQ-DQ72/20261118-platform-post066-readonly-001/decoded/PDX066-3e181303'))
    parser.add_argument('--output', type=Path, default=REPO / 'evidence/d27-platform067-arm64e.json')
    parser.add_argument('--details', type=Path, default=HERE / 'details.json')
    args = parser.parse_args()
    base, fresh = args.base, args.fresh
    native = args.native or base / 'native-sony-touch-066-002'
    strict = args.strict or base / 'strict-sony-touch-066-002'
    tree, work = base / TREE_REL, base / TREE_REL / '.cache/xnu-work'
    for name, pin in PINS.items():
        observed = command(['git', '-C', str(fresh / name), 'rev-parse', 'HEAD']).strip()
        if observed != pin:
            raise ValueError(name + ' snapshot pin mismatch')
    if sha(native / 'native.macho') != NATIVE_SHA or sha(strict / 'kernel.macho') != STRICT_SHA:
        raise ValueError('Not the exact delivered066 native/strict pair')
    print('Exact official pins and native066/strict066 verified', flush=True)
    index, inventory = build_effective_index(base, native)
    archive_records = archive_audit(base, native, inventory)
    extend_dependency_index(index, inventory, archive_records, work)
    patches = []
    replay = Replay(tree / 'refer/xnu')
    for category, path, series in series_paths(fresh, tree):
        diffs = parse_patch(path.read_text())
        patch_id = category + '/' + path.name
        before = len(replay.errors)
        replay.apply(patch_id, diffs)
        compared = compare_diffs(diffs, index, work)
        counts = Counter(h['status'] for f in compared for s in f.get('sources', []) for h in s['hunks'])
        patches.append({'id': patch_id, 'category': category, 'name': path.name, **path_info(path),
                        'declaring_series': series, 'hunk_counts': dict(counts), 'files': compared,
                        'replay_errors': replay.errors[before:]})
        print(patch_id, dict(counts), 'replay_errors', len(replay.errors) - before, flush=True)
    final_files = []
    for relative, owned in replay.files.items():
        sources = sorted({row['source'] for row in index.get(relative, [])})
        if not sources and (work / relative).is_file():
            sources = [str(work / relative)]
        expected = [line for line, _ in owned]
        rows = []
        for source in sources:
            actual = Path(source).read_text().splitlines()
            delta = list(difflib.unified_diff(expected, actual, fromfile='official/' + relative,
                                            tofile='effective/' + relative, n=3))
            edits = []
            for tag, i, j, a, b in difflib.SequenceMatcher(a=expected, b=actual, autojunk=False).get_opcodes():
                if tag == 'equal':
                    continue
                owners = sorted({owner for _, owner in owned[i:j] if owner})
                edits.append({'operation': tag, 'official_lines': [i + 1, j], 'actual_lines': [a + 1, b],
                              'patch_owners': owners, 'official': expected[i:j], 'actual': actual[a:b]})
            rows.append({'source': source, 'sha256': sha(source), 'exact_final_official_file': expected == actual,
                         'delta': delta, 'edits': edits})
        final_files.append({'file': relative, 'sources': rows})
    # Keep the machine-readable audit bounded: command/dependency hashes refer
    # to immutable receipts rather than duplicating half a million paths.
    for row in inventory['objects']:
        row['command_sha256'] = hashlib.sha256(json.dumps(row['command']).encode()).hexdigest()
        row['pac_flags'] = [v for v in row['command'] if 'ptrauth' in v or 'arm64e' in v]
        row['security_flags'] = [v for v in row['command'] if v in ('CONFIG_ENFORCE_LIBRARY_VALIDATION', 'CONFIG_MACF', 'CONFIG_DYNAMIC_CODE_SIGNING', 'CONFIG_ENFORCE_SIGNED_CODE')]
        row['dependency_count'] = len(row['dependencies'])
        if row['receipt']:
            row['receipt_sha256'] = sha(row['receipt'])
        del row['command'], row['dependencies']
    details = {'schema': 1, 'inventory': inventory, 'archives': archive_records,
               'patches': patches, 'ordered_replay_errors': replay.errors,
               'final_official_comparison': final_files,
               'logs': audit_logs(args.logdir)}
    safe_write(args.details, details)
    summary = {'schema': 1, 'date': '2026-11-18', 'scope': 'official architecture/OS/sheng patch parity and app crash diagnosis; read-only',
               'pins': PINS, 'native': path_info(native / 'native.macho'), 'strict': path_info(strict / 'kernel.macho'),
               'counts': dict(Counter(p['category'] for p in patches)), 'object_receipts': inventory['counts'],
               'details': path_info(args.details), 'ordered_replay_errors': replay.errors,
               'patches': [{k: v for k, v in row.items() if k != 'files'} for row in patches],
               'logs': details['logs'], 'source_mutated': False, 'device_operations': False,
               'compile_or_link_executed': False, 'parity_complete': False,
               'limits': ['Automated hunk presence is not semantic or final-instruction proof; changed/partial hunks require manual disposition.',
                          'Legacy assembly records may lack full compiler dependency receipts; this audit reports that gap.',
                          'The exact selected object and source identities take precedence over old copied patch files.']}
    safe_write(args.output, summary)
    print(json.dumps({'details': str(args.details), 'output': str(args.output), 'patches': len(patches),
                      'replay_errors': len(replay.errors), 'object_receipts': inventory['counts']}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
