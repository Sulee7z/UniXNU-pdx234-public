#!/usr/bin/env python3
"""Differential execution of the qualified original/patched UsbConfig PE.

Run real SSUsb1InitCommon, rail validation, ConfigPowerDomain and InitHSUSBPhy;
model external protocols, clocks, PHY, NPA, IoLib and debug. No device access.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pe', type=Path, required=True)
    p.add_argument('--source', type=Path, required=True, help='Exact UsbConfigUsbCores.c')
    p.add_argument('--python-tools', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    sys.path.insert(0, str(a.python_tools))
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'ci'))
    from sony_usb_prepare_errors import (adapt_pe, ORIGINAL_SHA, SOURCE_SHA, CHECKS, BASE, END,
                                        TRACE_BASE, TRACE_COUNTER, TRACE_CALLS, TRACE_LIMIT)
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
    from unicorn import arm64_const as r
    original = a.pe.read_bytes()
    assert hashlib.sha256(original).hexdigest() == ORIGINAL_SHA
    assert hashlib.sha256(a.source.read_bytes()).hexdigest() == SOURCE_SHA
    patched = adapt_pe(original)
    traced = adapt_pe(original, trace=True)
    allowed = set(range(BASE, END)) | set(range(0x94a4, 0x94a8)) | set(range(0xad84, 0xad88))
    for site in CHECKS:
        allowed.update(range(site, site + 4))
    changed = [i for i, (x, y) in enumerate(zip(original, patched)) if x != y]
    assert len(original) == len(patched) and set(changed) <= allowed
    trace_allowed = allowed | set(range(TRACE_BASE, 0x15000))
    for site in TRACE_CALLS:
        trace_allowed.update(range(site, site + 4))
    assert len(traced) == len(original)
    assert all(x == y or i in trace_allowed for i, (x, y) in enumerate(zip(original, traced)))
    # Fail closed for a stale call, occupied cave, unrelated mutation, truncation,
    # and a second application. All are rejected by the exact input digest.
    rejected = []
    for label, raw in [('call', original[:0x9548] + bytes([original[0x9548] ^ 1]) + original[0x9549:]),
                       ('cave', original[:BASE] + b'X' + original[BASE + 1:]),
                       ('unrelated', original[:-1] + b'X'),
                       ('truncated', original[:-1]), ('reapply', patched)]:
        try:
            adapt_pe(raw)
        except ValueError:
            rejected.append(label)
        else:
            raise AssertionError('Accepted unknown input: ' + label)

    error = 0x8000000000000007
    invalid = 0x8000000000000002
    cases = [dict(name='ready'), dict(name='high-speed-only', hs_only=True),
             dict(name='ss-fallback', ss_failure=True), dict(name='reset-only', reset=True),
             dict(name='existing-clock-reference', refcount=2), dict(name='eud-active', eud=True),
             dict(name='virtio', platform=16), dict(name='rumi-ready', platform=15),
             dict(name='null-this', null_this=True), dict(name='wrong-core', core_type=6),
             dict(name='missing-clock', no_clock=True, expected=0x800000000000000e),
             dict(name='null-ss-client', null_ss=True, expected=invalid),
             dict(name='null-hs-client', null_hs=True, expected=invalid),
             dict(name='reset-skips-null-clients', reset=True, null_ss=True, null_hs=True),
             dict(name='missing-bus-client', null_bus=True),
             # Opaque shared PHY x0 is deliberately varied: never invent a
             # return contract for the unavailable declaration/implementation.
             dict(name='opaque-phy-x0-zero', phy_x0=0),
             dict(name='opaque-phy-x0-error', phy_x0=error),
             dict(name='rumi-failure-existing-policy', platform=15, rumi_failure=True)]
    for index in range(1, 4):
        cases.append(dict(name='gdsc-lookup-failure-' + str(index), id_fail=index, expected=error))
        cases.append(dict(name='gdsc-operation-failure-' + str(index), gdsc_fail=index, expected=error))
        cases.append(dict(name='gdsc-warning-' + str(index), gdsc_warning=index))

    def run(raw, case, counter=0):
        u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        u.mem_map(0, 0x20000)
        u.mem_write(0, raw)
        u.mem_write(TRACE_COUNTER, struct.pack('<I', counter))
        u.mem_map(0x100000, 0x20000)
        u.mem_map(0x400000, 0x20000)
        obj, protocol, bs = 0x400000, 0x401000, 0x402000
        stop_at, stall, get_id, enable, disable = 0x410000, 0x410010, 0x410020, 0x410030, 0x410040
        def q(at, value):
            u.mem_write(at, struct.pack('<Q', value))
        q(0x157d8, 0 if case.get('no_clock') else protocol)
        q(0x157e8, 0 if case.get('null_ss') else 0x403000)
        q(0x157f0, 0 if case.get('null_hs') else 0x404000)
        q(0x157f8, 0 if case.get('null_bus') else 0x405000)
        q(0x156e8, bs)
        q(bs + 0xf8, stall)
        q(protocol + 0x50, get_id)
        q(protocol + 0x58, enable)
        q(protocol + 0x60, disable)
        u.mem_write(0x156a8, struct.pack('<I', case.get('platform', 1)))
        u.mem_write(0x15782, bytes([case.get('hs_only', False)]))
        u.mem_write(obj + 0x80, struct.pack('<I', case.get('core_type', 5)))
        q(obj + 0x88, 0xa600000)
        q(obj + 0x90, 4)
        q(obj + 0x98, 0x406000)
        q(obj + 0xa0, 2)
        q(obj + 0xa8, 0x407000)
        q(obj + 0xb0, case.get('refcount', 0))
        u.reg_write(r.UC_ARM64_REG_X0, 0 if case.get('null_this') else obj)
        u.reg_write(r.UC_ARM64_REG_X1, int(case.get('reset', False)))
        u.reg_write(r.UC_ARM64_REG_SP, 0x110000)
        u.reg_write(r.UC_ARM64_REG_X30, stop_at)
        saved = {getattr(r, 'UC_ARM64_REG_X' + str(i)): 0xabc000 + i for i in range(19, 30)}
        for reg, value in saved.items():
            u.reg_write(reg, value)
        calls, writes, boundaries, logs = [], [], [], []
        mmio, done, gdsc_index = {}, [], 0

        def hook(uc, at, size, context):
            nonlocal gdsc_index
            if at == stop_at:
                done.append(True)
                uc.emu_stop()
                return
            if at in (0x87c0, 0xad00, 0x8b00):
                boundaries.append(hex(at))
            args = [uc.reg_read(getattr(r, 'UC_ARM64_REG_X' + str(i))) for i in range(4)]
            x0, x1, x2, _ = args
            ret = None
            label = None
            if at == get_id:
                gdsc_index += 1
                assert x0 == protocol and x1 == 0x12678
                # Sentinel makes use of an output from a failed lookup visible.
                q(x2, 0xdead if case.get('id_fail') == gdsc_index else 0x42)
                ret, label = error if case.get('id_fail') == gdsc_index else 0, 'GetClockPowerDomainID'
            elif at in (enable, disable):
                assert x0 == protocol and x1 == (0xdead if case.get('id_fail') == gdsc_index else 0x42)
                assert (at == disable) == (gdsc_index == 3)
                ret = error if case.get('gdsc_fail') == gdsc_index else (1 if case.get('gdsc_warning') == gdsc_index else 0)
                label = 'EnableClockPowerDomain' if at == enable else 'DisableClockPowerDomain'
            elif at == 0xe924:
                assert x0 in (0x403000, 0x404000) and x1 == 2
                ret, label = 0xdeadbeef, 'npa_issue_required_request:void'
            elif at == 0xe99c:
                assert x0 == 0x405000 and x1 == 8 and x2 == 0x133c8
                ret, label = 0xdeadbeef, 'npa_issue_vector_request:void'
            elif at in (0x84c0, 0x8650):
                assert (x0, x1) == ((4, 0x406000) if at == 0x84c0 else (2, 0x407000))
                ret, label = 0, 'InitUsbClocks' if at == 0x84c0 else 'DisableUsbClocks'
            elif at == 0xf024:
                ret, label = int(case.get('eud', False)), 'usb_shared_is_eud_active'
            elif at == 0xf068:
                assert x0 in (0, 1)
                ret, label = 0xdeadbeef, 'usb_shared_refclk_enable:opaque'
            elif at == 0xe6b8:
                assert x0 == 0
                ret, label = 0, 'DALSYS_InitMod'
            elif at in (0x8990, 0x8f90):
                ret, label = 0xdeadbeef, 'SynopsysGccReset:void' if at == 0x8990 else 'USbEudSwAttachDetSet:opaque'
            elif at == 0xc7f4:
                assert x0 == 0x127fc and x1 in (0, 1)
                ret, label = 0, 'ResetClock'
            elif at == 0xea1c:
                ret, label = case.get('phy_x0', 1), 'usb_shared_hs_phy_init:opaque'
            elif at == 0xeda0:
                assert x0 == 0 and x1 == 0
                ret, label = 0 if case.get('rumi_failure') else 1, 'usb_shared_hs_phy_rumi_init:boolean'
            elif at == 0xaf00:
                assert x0 == obj
                ret, label = error if case.get('ss_failure') else 0, 'InitSSUSBPhy'
            elif at in (0xcdb0, 0xcde0, 0xce10):
                assert 0xa600000 <= x0 < 0xa700000
                old = mmio.get(x0, 0x200)
                value = ((old | x1) if at == 0xcdb0 else
                         ((old & x1) if at == 0xcde0 else ((old & x1) | x2))) & 0xffffffff
                mmio[x0] = value
                writes.append([hex(x0), hex(value)])
                ret, label = value, 'IoLib:' + hex(at)
            elif at == stall:
                assert x0 == 100
                ret, label = 0, 'Stall'
            elif at == 0x1d0c:
                ret = 0
                fmt = bytes(uc.mem_read(x1, 80)).split(b'\0')[0].decode()
                if fmt.startswith('PDX prep '):
                    count = 3 if 'enter' in fmt else 1
                    values = [hex(uc.reg_read(getattr(r, 'UC_ARM64_REG_X' + str(i))))
                              for i in range(3, 3 + count)]
                    logs.append(dict(format=fmt, site=hex(x2), values=values))
                # A conforming callee may overwrite all volatile arguments.
                for index in range(1, 18):
                    uc.reg_write(getattr(r, 'UC_ARM64_REG_X' + str(index)), 0xaabbccdd)
                for index in range(8):
                    uc.reg_write(getattr(r, 'UC_ARM64_REG_Q' + str(index)), 0x123456789abcdef)
            if ret is not None:
                if label:
                    # Only actual API arguments, excluding unspecified register contents.
                    argc = 3 if at in (get_id, 0xe99c, 0xce10) else (1 if at in (stall, 0xaf00, 0x8990, 0xe6b8, 0xf068) else 2)
                    if at in (0xea1c, 0xf024, 0x8f90):
                        argc = 0
                    values = [hex(v) for v in args[:argc]]
                    if at == get_id:
                        assert 0x100000 <= x2 < 0x110000
                        values[2] = 'stack-output'
                    calls.append(dict(api=label, args=values, x0=hex(ret)))
                uc.reg_write(r.UC_ARM64_REG_X0, ret)
                uc.reg_write(r.UC_ARM64_REG_PC, uc.reg_read(r.UC_ARM64_REG_X30))

        u.hook_add(UC_HOOK_CODE, hook)
        try:
            u.emu_start(0x9410, stop_at + 4, count=100000)
        except Exception as exc:
            raise RuntimeError(case['name'] + ' PC=' + hex(u.reg_read(r.UC_ARM64_REG_PC))) from exc
        assert done == [True], case['name']
        assert u.reg_read(r.UC_ARM64_REG_SP) == 0x110000
        assert all(u.reg_read(reg) == value for reg, value in saved.items())
        final_counter = struct.unpack('<I', bytes(u.mem_read(TRACE_COUNTER, 4)))[0]
        assert counter <= final_counter <= TRACE_LIMIT
        assert len(logs) == 2 * (final_counter - counter)
        return dict(status=hex(u.reg_read(r.UC_ARM64_REG_X0)), calls=calls,
                    writes=writes, boundaries=boundaries,
                    clock_reference=struct.unpack('<Q', bytes(u.mem_read(obj + 0xb0, 8)))[0]), logs

    results = []
    for case in cases:
        before, _ = run(original, case)
        after, _ = run(patched, case)
        observed, logs = run(traced, case)
        assert observed == after, ('trace semantic difference', case['name'])
        if 'expected' in case:
            assert before['status'] == '0x0', (case, before)
            assert after['status'] == hex(case['expected']), (case, after)
            assert not after['writes']
            assert after['calls'] == before['calls'][:len(after['calls'])]
            assert '0x8b00' not in after['boundaries']
        else:
            assert before == after, case['name']
            assert after['status'] == (hex(invalid) if case.get('null_this') or case.get('core_type') == 6 else '0x0')
        results.append(dict(scenario=case['name'], original=before, patched=after, runtime_trace=logs))
    for counter in (TRACE_LIMIT - 1, TRACE_LIMIT):
        observed, logs = run(traced, cases[0], counter)
        expected, _ = run(patched, cases[0])
        assert observed == expected and len(logs) == 2 * (TRACE_LIMIT - counter)
    a.out.mkdir(parents=True, exist_ok=False)
    (a.out / 'UsbConfigDxe.prepare-errors.efi').write_bytes(patched)
    (a.out / 'UsbConfigDxe.prepare-trace.efi').write_bytes(traced)
    report = dict(passed=True, original_sha256=ORIGINAL_SHA, source_sha256=SOURCE_SHA,
                  patched_sha256=hashlib.sha256(patched).hexdigest(), cases=results,
                  traced_sha256=hashlib.sha256(traced).hexdigest(), trace_limit=TRACE_LIMIT,
                  trace_sites={hex(s): hex(t) for s, t in sorted(TRACE_CALLS.items())},
                  trace_bound_tests=[TRACE_LIMIT - 1, TRACE_LIMIT],
                  rejected_inputs=rejected, changed_byte_offsets=changed,
                  patch_ranges=[[hex(0x94a4), 4], [hex(0xad84), 4]] + [[hex(s), 4] for s in CHECKS] + [[hex(BASE), END - BASE]],
                  hardware_verified=False,
                  limits='Real ARM64 common init, rail helper, power-domain helper and HS init. External NPA/clock/PHY/IoLib/debug/stall are modeled. No live MMIO, DMA or board-power evidence. Existing warning-continue policy and shared-PHY opaque return are preserved.')
    (a.out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS', len(results), 'original/patched preparation cases;', len(rejected), 'input rejections;', report['patched_sha256'])


if __name__ == '__main__':
    main()
