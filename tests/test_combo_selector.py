"""Emulate the compiled selector, never the phone; cache operations are software-modeled."""
import hashlib
import argparse
import json
from pathlib import Path
import struct
import unittest

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X9, UC_ARM64_REG_SP, UC_ARM64_REG_PC

DEVICE = Path('/mnt/g/UniXNU-Port/ports/UniXNU-pdx234')
OUT = DEVICE / 'out/combo-probe-001'
MENU = False
VOLUME_UP = False
LOAD, CORE, OBS, FD = 0x40000000, 0xc400000, 0xc440000, 0xa7100000
ANDROID_OFFSET = 2 << 20


class Selector(unittest.TestCase):
    results = []

    def exercise(self, label, *, version=0x70000000, apids=64, status=1, key=None, match=True, expected=None):
        if key is None:
            key = 1 if MENU else 0
        if expected is None:
            expected = 'uefi' if MENU else 'android'
        with_descriptor = MENU or VOLUME_UP
        raw = (OUT / 'combo.Image').read_bytes()
        original = (OUT / 'Android.original.Image').read_bytes()
        self.assertEqual(hashlib.sha256(original).hexdigest(), '92321cba44b4d5f32355e694ed918125b8e56810ff2580b7a904cef0f719549f')
        self.assertEqual(raw[ANDROID_OFFSET:ANDROID_OFFSET+len(original)], original)
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        uc.mem_map(LOAD, (len(raw)+4095)&~4095)
        uc.mem_write(LOAD, raw)
        uc.mem_map(CORE, 0x4000)
        uc.mem_map(OBS, 0x100000)
        uc.mem_map(FD, 0x300000)
        uc.mem_write(CORE, struct.pack('<II', version, apids))
        if match:
            uc.mem_write(CORE+0x2000+5*4, struct.pack('<I', 0x18d01 if MENU else 0x1301))
        if VOLUME_UP:
            # GPIO6 volume-down may be held; only PON RESIN is the boot selector.
            uc.mem_write(CORE+0x2000+6*4, struct.pack('<I', 0x18d01))
        uc.mem_write(OBS+5*32+8, struct.pack('<I', status))
        uc.mem_write(OBS+5*32+0x18, struct.pack('<I', key))
        regs = (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3)
        values = (0x48100000, 0x11223344, 0x55667788, 0x99aabbcc)
        for reg,value in zip(regs, values):
            uc.reg_write(reg, value)
        uc.reg_write(UC_ARM64_REG_SP, 0xdead0000)
        reached = []

        def code(engine, address, size, _):
            if address in (LOAD+ANDROID_OFFSET, FD):
                reached.append('android' if address == LOAD+ANDROID_OFFSET else 'uefi')
                engine.emu_stop()
                return
            word = struct.unpack('<I', bytes(engine.mem_read(address, 4)))[0]
            if word == 0xd53b0029:  # CTR_EL0: model 64-byte data/instruction cache lines.
                engine.reg_write(UC_ARM64_REG_X9, 0x00040004)
                engine.reg_write(UC_ARM64_REG_PC, address+4)
            elif word in (0xd50b7a28, 0xd508751f):  # DC CVAC x8 / IC IALLU: not hardware-tested here.
                engine.reg_write(UC_ARM64_REG_PC, address+4)

        uc.hook_add(UC_HOOK_CODE, code)
        uc.emu_start(LOAD, 0, count=3000000)
        self.assertEqual(reached, [expected])
        if expected == 'android' or not with_descriptor:
            self.assertEqual(tuple(uc.reg_read(reg) for reg in regs), values)
        else:
            self.assertEqual(uc.reg_read(UC_ARM64_REG_X0), values[0])
            self.assertEqual(uc.reg_read(UC_ARM64_REG_X2), LOAD)
            self.assertEqual(uc.reg_read(UC_ARM64_REG_X3), len(raw))
            descriptor = bytes(uc.mem_read(LOAD+len(raw)-64,64))
            self.assertEqual(descriptor[:8], b'PXCBHOF1')
            self.assertEqual(struct.unpack_from('<QQQ',descriptor,16), (LOAD+ANDROID_OFFSET,len(original),values[0]))
        self.assertEqual(uc.reg_read(UC_ARM64_REG_SP), 0xdead0000)
        if expected == 'uefi':
            self.assertEqual(bytes(uc.mem_read(FD, 0x300000)), raw[-0x300000-64:-64] if with_descriptor else raw[-0x300000:])
        self.results.append({'case': label, 'selected': expected, 'boot_args_and_sp_preserved': True})

    def test_no_key(self):
        self.exercise('no_key')

    def test_volume_down(self):
        if VOLUME_UP:
            self.exercise('volume_down_not_a_selector',key=0,expected='android')
        else:
            self.exercise('volume_down', key=0 if MENU else 0x40, expected='android' if MENU else 'uefi')

    def test_volume_up(self):
        if VOLUME_UP:
            self.exercise('volume_up',key=0x40,expected='uefi')

    def test_power_alone(self):
        if VOLUME_UP:
            self.exercise('power_without_volume_up',key=0x80,expected='android')

    def test_volume_up_and_power(self):
        if VOLUME_UP:
            self.exercise('volume_up_and_power',key=0xc0,expected='uefi')

    def test_unknown_controller(self):
        self.exercise('unknown_controller', version=0x80000000, key=0x40)

    def test_zero_apids(self):
        self.exercise('zero_apids', apids=0, key=0x40)

    def test_excessive_apids(self):
        self.exercise('excessive_apids', apids=1025, key=0x40)

    def test_timeout(self):
        self.exercise('timeout', status=0, key=0x40)

    def test_error(self):
        self.exercise('error', status=3, key=0x40)

    def test_no_pon(self):
        self.exercise('no_pon', match=False, key=0x40)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--menu-attempt')
    parser.add_argument('--volume-up-attempt')
    args = parser.parse_args()
    if args.menu_attempt and args.volume_up_attempt:
        parser.error('Choose only one selector mode')
    if args.volume_up_attempt:
        if not args.volume_up_attempt.isalnum():
            raise ValueError('Invalid volume-up attempt name')
        OUT = DEVICE / ('out/combo-probe-'+args.volume_up_attempt)
        VOLUME_UP = True
    if args.menu_attempt:
        if not args.menu_attempt.isalnum():
            raise ValueError('Invalid menu attempt name')
        OUT = DEVICE / ('out/combo-probe-'+args.menu_attempt)
        MENU = True
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Selector))
    record = dict(passed=result.wasSuccessful(), cases=Selector.results,
                  image_sha256=hashlib.sha256((OUT/'combo.Image').read_bytes()).hexdigest(),
                  device_operations=False, hardware_verified=False,
                  cache_maintenance_is_software_model=True)
    if VOLUME_UP:
        record['selector']='default Android; Sony PON RESIN bit6 volume-up -> UEFI'
        path=DEVICE/'evidence'/('volume-up-selector-emulation-'+args.volume_up_attempt+'.json')
    else:
        path = DEVICE/'evidence'/('menu-selector-emulation-'+args.menu_attempt+'.json' if MENU else 'combo-selector-emulation.json')
    if (MENU or VOLUME_UP) and path.exists():
        raise RuntimeError('Preserve previous menu emulation')
    path.write_text(json.dumps(record, indent=2))
    raise SystemExit(0 if result.wasSuccessful() else 1)
