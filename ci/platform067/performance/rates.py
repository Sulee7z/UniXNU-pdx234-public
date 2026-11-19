"""Separate requested vsync, present throughput and measured DPU interface cadence."""
from __future__ import annotations
import re


def interface_rate(line: str) -> dict:
    values = dict(re.findall(r'([a-z-]+)=([^ ]+)', line))
    elapsed = int(values['elapsed-us'])
    delta = int(values['delta'])
    enable = int(values['timing'], 16)
    count = int(values['counter-enable'], 16)
    rate = delta * 1000000 / elapsed if elapsed > 0 else 0
    valid = elapsed >= 1000000 and 0 < delta < 0x80000000 and 0 < rate <= 240 and bool(enable & 1) and bool(count & 1)
    return dict(interface=int(values['interface']), counter_valid=valid,
                observed_interface_hz=rate if valid else None, panel_refresh_hz=None,
                panel_refresh_verified=False,
                reason='DPU counter cadence; command-mode/self-refresh panel needs independent TE evidence'
                       if valid else 'disabled, nonmoving, reset, too short or implausible counter sample')


def present_rate(line: str) -> dict:
    values = dict(re.findall(r'([a-z-]+)=([^ ]+)', line))
    elapsed = int(values['elapsed-us'])
    if elapsed <= 0:
        raise ValueError('Positive measured interval required')
    return dict(requested_vsync_hz=int(values['requested-vsync']),
                copies_per_second=int(values['copy-delta']) * 1000000 / elapsed,
                retirements_per_second=int(values['retire-delta']) * 1000000 / elapsed,
                actual_panel_hz=None, compositor_fps=None)
