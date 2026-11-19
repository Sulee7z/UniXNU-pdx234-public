#!/usr/bin/env python3
"""Hash-bound actual068 app-exit audit. Counts unique PIDs, not repeated lines."""
from __future__ import annotations
from collections import defaultdict, Counter
from decimal import Decimal
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
FRESH = Path('/mnt/f/UniXNU-Port-artifacts/platform069-20261118')
NATIVE = Path('/mnt/f/UniXNU-Port-artifacts/platform067-20261118/native-platform067-full-002')
PINS = {'UniXNU': '563595abedfdfa413ad583b66b6176d82007e633',
        'sheng': 'c8f92b208068eeaa4cd2b0f592671f04ee70076e',
        'AdrenoMetal': 'cc0a4e8e57d20f4a4698753c2530875f2b10c0ca'}
RAW_SHA = 'bd03b40fe2d8beb1b2a860ae786b8fa81d98a898e9e8e6ce90b99651b10b2c6a'
NATIVE_SHA = '734bb8fc84437371c34f4e2afc43ef4a0b4191d1bfbcd4b6cf1d52d5080c37dd'
EXIT = re.compile(r'unixnu-exit: ([^\[\r\n]+)\[(\d+)\] status=0x([0-9a-fA-F]+) reason=(\d+)/0x([0-9a-fA-F]+) csflags=0x([0-9a-fA-F]+) description=([^\r\n]*)')
KILL = re.compile(r'memorystatus: (killing_[a-z_]+) pid (\d+) \[([^\]]+)\] \(([^)]*)\)(?: (\d+)KB)?')
TIME = re.compile(r'^\[\s*(\d+)\.(\d+)\]:')


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def timestamp(line):
    match = TIME.match(line)
    if not match:
        return None
    # Startup printf can print an unnormalized >6-digit fractional microsecond
    # count. Treat it as seconds + that count/1e6, not a decimal fraction.
    return int(match[1]) + int(match[2]) / 1_000_000


def decode_wait_status(raw):
    sig = raw & 0x7f
    if sig == 0:
        return {'kind': 'ordinary-exit', 'exit_code': (raw >> 8) & 0xff, 'signal': None}
    if sig == 0x7f:
        return {'kind': 'stopped', 'exit_code': None, 'signal': (raw >> 8) & 0xff}
    return {'kind': 'signal', 'exit_code': None, 'signal': sig, 'core_flag': bool(raw & 0x80)}


def analyze(logdir):
    exits, kills, births, corpses, guards, limits, shutdown = {}, {}, {}, [], [], [], []
    occurrences = Counter()
    stats = {}
    for filename in ('msgbuf.txt', 'slots.txt'):
        p = logdir / filename
        lines = p.read_text(errors='replace').splitlines()
        stats[filename] = {'path': str(p), 'sha256': sha(p), 'bytes': p.stat().st_size, 'lines': len(lines)}
        for i, line in enumerate(lines, 1):
            time = timestamp(line)
            where = {'file': filename, 'line': i, 'timestamp': time}
            for m in EXIT.finditer(line):
                name, pid, raw, space, code, flags, desc = m.groups()
                pid, raw, space, code = int(pid), int(raw, 16), int(space), int(code, 16)
                key = (pid, raw, space, code)
                occurrences['exit_lines'] += 1
                if key not in exits:
                    exits[key] = {'name': name, 'pid': pid, 'raw_status': hex(raw), **decode_wait_status(raw),
                                  'reason_namespace': space, 'reason_code': hex(code), 'csflags': flags,
                                  'description': desc[:512], 'evidence': []}
                exits[key]['evidence'].append(where)
            for m in KILL.finditer(line):
                method, pid, name, reason, kb = m.groups()
                key = int(pid)
                if key not in kills:
                    kills[key] = {'name': name, 'pid': key, 'method': method, 'reason': reason,
                                  'reported_kib': int(kb) if kb else None, 'evidence': []}
                kills[key]['evidence'].append(where)
            for m in re.finditer(r'(/(?:Applications|System|usr)/[^\r\n]*?)/([^/\[ ]+)\[(\d+)\] ==> ([^\r\n]*?)(?=(?:/Applications/|/System/|/usr/|Sandbox:|Autobox:|Protobox:|unixnu-exit:)|$)', line):
                path, name, pid, profile = m.groups()
                births[int(pid)] = {'name': name, 'pid': int(pid), 'path': path + '/' + name, 'profile': profile[:100], 'evidence': where}
            for m in re.finditer(r'(Lightweight|Full) corpse enqueued for ([A-Za-z0-9_.-]+)', line):
                corpses.append({'type': m[1], 'name': m[2], 'evidence': where,
                                'meaning': 'corpse report is not on its own a verified process termination'})
            if 'EXC_GUARD AST:' in line:
                guards.append({'text': line[:1600], 'evidence': where})
            if 'exceeded mem limit:' in line:
                limits.append({'text': line[:1600], 'evidence': where})
            if 'System shutdown initiated by:' in line:
                m = re.search(r'System shutdown initiated by: ([A-Za-z0-9_.]+)\[(\d+)\]', line)
                if m:
                    event = {'name': m[1], 'pid': int(m[2]), 'evidence': where}
                    # PID1 cached text repeats every slot; keep one event per
                    # initiator, preferring a timestamped live msgbuf record.
                    if not shutdown or time is not None:
                        shutdown = [event]
    cutoff = shutdown[0]['evidence']['timestamp'] if shutdown else None
    for event in exits.values():
        ts = [e['timestamp'] for e in event['evidence'] if e['timestamp'] is not None]
        event['first_timestamp'] = min(ts) if ts else None
        event['after_shutdown_request'] = bool(cutoff is not None and ts and min(ts) >= cutoff)
        event['process_kind'] = 'application-or-extension' if births.get(event['pid'], {}).get('path', '').startswith('/Applications/') else 'daemon-or-unknown'
    exit_by_name = {}
    for name in sorted({e['name'] for e in exits.values()}):
        values = [e for e in exits.values() if e['name'] == name]
        times = sorted(e['first_timestamp'] for e in values if e['first_timestamp'] is not None)
        gaps = [round(b - a, 6) for a, b in zip(times, times[1:])]
        exit_by_name[name] = {'unique_pids': sorted({e['pid'] for e in values}),
                              'pid_count': len({e['pid'] for e in values}),
                              'wait_statuses': sorted({e['raw_status'] for e in values}),
                              'classification': sorted({e['kind'] for e in values}),
                              'first_s': times[0] if times else None, 'last_s': times[-1] if times else None,
                              'inter_exit_seconds': gaps}
    return {'files': stats, 'exit_events': list(exits.values()), 'exit_by_name': exit_by_name,
            'kill_events': list(kills.values()), 'births': list(births.values()), 'corpse_notifications': corpses,
            'guard_reports': guards, 'memory_limit_reports': limits, 'shutdown_requests': shutdown,
            'shutdown_timestamp_s': cutoff, 'raw_exit_occurrences': occurrences['exit_lines'],
            'unique_exit_pids': len({e['pid'] for e in exits.values()}),
            'unique_killed_pids': len(kills),
            'counts_are_lower_bounds': True,
            'scope': 'Actual068 retained131072-byte msgbuf tail plus periodic slots; early overwritten messages are not reconstructed from old066',
            'limits': ['gpu-trace=0 makes periodic slots omit diagnostic message excerpts; only the last kernel ring survives.',
                       'Corpse notification without PID/status is retained separately, not counted as another unique app crash.',
                       'Unix exit status is a wait status:0x100=exit1,0x300=exit3,0xa=SIGBUS; no assumption that all nonzero statuses are PAC.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--logdir', type=Path, default=FRESH / 'device-post068-readonly-001/decoded/PDX068-3fbe8890')
    parser.add_argument('--output', type=Path, default=HERE / 'actual068.json')
    a = parser.parse_args()
    if not a.output.resolve().is_relative_to(HERE):
        raise ValueError('Audit output must stay in assigned directory')
    raw = a.logdir.parents[1] / 'ios-log-window.bin'
    if sha(raw) != RAW_SHA or sha(NATIVE / 'native.macho') != NATIVE_SHA:
        raise ValueError('Actual068 raw log/native identity mismatch')
    for name, expected in PINS.items():
        actual = subprocess.check_output(['git', '-C', str(FRESH / name), 'rev-parse', 'HEAD'], text=True).strip()
        if actual != expected:
            raise ValueError('Fresh pin mismatch:' + name)
    report = analyze(a.logdir)
    report.update(raw_log={'path': str(raw), 'sha256': RAW_SHA}, baseline_native_sha256=NATIVE_SHA, pins=PINS,
                  header=(a.logdir / 'header.txt').read_text(), latest_sha256=sha(a.logdir / 'latest.txt'),
                  device_operations=False, source_mutated=False)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'exit_by_name': report['exit_by_name'], 'unique_killed_pids': report['unique_killed_pids'],
                      'shutdown': report['shutdown_requests'], 'output': str(a.output)}, indent=2))


if __name__ == '__main__':
    main()
