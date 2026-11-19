"""Hash-bound official performance source integration, not an alternative governor."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re

SHENG_REV = '6c42e1055ffb3b335fda991190ad221edaa7af3c'
CPU_SHA = '1c54f5279df0144394e5d0fc91a3a19535132cf2787592305f3cc7f509e5d91c'
GPU_SHA = 'fdb17ffe29c852cf3c0a53c96e18a0cab5c67ed0a6415141a9532ade66ab2f0a'
BASE_NATIVE_SHA = '80b2b18120eafde479aa2eaebd4017a677a67405b0ba0fe33e8d00ad6b6bc3dc'
BASE_GPU_SHA = 'e2b272351bd3edd3e1d18762ebbcaec2dfe94fba5f33cc5cb3d09b628b584a04'
BASE_DISPLAY_SHA = 'aee38f34ecfdcf7fca64900ce96f0afff89d9640f3ef924908a0fdaff42bd2dc'
LIVE_SHA = '9dc4b4512490d77ef0e6230815ceb731937bcd65b74397e718970f2ab91c37ef'


def sha(path: Path | str) -> str:
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def replace_once(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise ValueError('Official source anchor changed: ' + old[:120])
    return text.replace(old, new)


def touch_input(text: str) -> str:
    text = '#include "SonyPerformanceTouch.h"\n' + text
    # Preserve the official governor and its boost duration. Only the producer
    # of its report counter changes to the Sony contact-qualified snapshot.
    text = text.replace('&native_hid_input_events ? native_hid_input_events[6] : 0',
                        'pdx_performance_touch_sequence()')
    text = text.replace('&native_hid_input_events && native_hid_input_events[6] != touches',
                        'pdx_performance_touch_sequence() != touches')
    text = text.replace('touches = native_hid_input_events[6];',
                        'touches = pdx_performance_touch_sequence();')
    # One snapshot per window; a producer racing between the comparison and
    # assignment must not consume a second event without applying its boost.
    anchor = '        if (boostAbs && pdx_performance_touch_sequence() != touches) {\n            touches = pdx_performance_touch_sequence();'
    text = replace_once(text, anchor,
                        '        const uint32_t touchNow = pdx_performance_touch_sequence();\n'
                        '        if (boostAbs && touchNow != touches) {\n            touches = touchNow;')
    if 'native_hid_input_events[6]' in text:
        raise ValueError('Unadapted touch counter consumer')
    return text


def cpu_source(text: str) -> str:
    if hashlib.sha256(text.encode()).hexdigest() != CPU_SHA:
        raise ValueError('CPU official source hash changed')
    return touch_input(text)


def gpu_source(text: str, opps: list[tuple[int, ...]]) -> str:
    # The snapshot differs from gpu-source-006 only in one SGI comment. No new
    # core API, firmware, SMMU implementation or recovery path is substituted.
    if hashlib.sha256(text.encode()).hexdigest() != GPU_SHA:
        raise ValueError('GPU official source hash changed')
    if len(opps) != 9 or opps[0][0] != 0 or any(a[0] >= b[0] for a, b in zip(opps, opps[1:])):
        raise ValueError('Unsupported qualified Sony HFI table')
    text = touch_input(text)
    mhz = ', '.join(str(row[0] // 1000000) for row in opps)
    text = replace_once(text, 'constexpr uint32_t kGpuMHz[9] = {0, 220, 295, 348, 401, 475, 550, 615, 680};',
                        '// Sony HFI index order, generated from the already-linked, live-DT-qualified table.\n'
                        '// Policy arithmetic uses integer MHz as upstream; HFI retains exact Hz/voltage/bandwidth.\n'
                        f'constexpr uint32_t kGpuMHz[9] = {{{mhz}}};')
    floor = next(i for i, row in enumerate(opps) if row[0] >= 348000000)
    text = replace_once(text, 'unsigned floor = bootArg("gpu-dcvs-min", 3);',
                        f'unsigned floor = bootArg("gpu-dcvs-min", {floor});')
    # A boot argument is a request, not a measurement. Keep the successful
    # vote helper and its bandwidth coupling; do not invent a 680 MHz Sony bin.
    return text


def parse_opps(text: str) -> list[tuple[int, ...]]:
    body = text.split('static const ShengGmuOpp sheng_gpu_opps[]={', 1)[1].split('};', 1)[0]
    return [tuple(map(int, m)) for m in re.findall(r'\{(\d+),(\d+),(\d+),(\d+),(\d+)\}', body)]
