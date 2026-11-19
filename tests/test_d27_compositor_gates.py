"""Check gate decoding boundaries without claiming guest rendering."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ci/qemu'))
from d27_compositor_gates import FUNCTIONS, decode_event


def event(name, state=b'\1\0\0\0\1\1\0\0', **values):
    address, prefix, _ = FUNCTIONS[name]
    memory = [dict(register=0, offset=816, indirect=True, bytes=state.hex())]
    spans = [(0, 696, 8), (0, 30032, 80), (1, 320, 32)] if name == 'ignore_update' else [
        (0, 696, 8), (0, 30000, 48), (0, 952, 4)]
    for register, offset, size in spans:
        data = bytearray(size)
        if offset == 696:
            data[0] = 1
        memory.append(dict(register=register, offset=offset, indirect=False, bytes=data.hex()))
    result = dict(name=name, pc=hex(address + 0x520000), entry_bytes=prefix, pstate='0x0',
                  arguments=['0x10000', '0x0'],
                  process=dict(name='backboardd', pid=60, shared_region_slide=0x520000), memory=memory)
    result.update(values)
    return result


def write(observation, offset, index, value):
    row = next(r for r in observation['memory'] if r['offset'] == offset)
    data = bytearray.fromhex(row['bytes'])
    data[index] = value
    row['bytes'] = data.hex()


class CompositorGateTests(unittest.TestCase):
    def test_original_function_identity_required(self):
        for field, value in [('entry_bytes', '00' * 16), ('pc', '0x18445c17c'), ('pstate', '0x4')]:
            observation = event('ignore_update')
            observation[field] = value
            with self.assertRaises(ValueError):
                decode_event(observation)

    def test_process_and_slide_required(self):
        for change in [dict(name='SpringBoard'), dict(shared_region_slide=0x520001), dict(shared_region_slide=None)]:
            observation = event('ignore_update')
            observation['process'].update(change)
            with self.assertRaises(ValueError):
                decode_event(observation)

    def test_ready_state_branches(self):
        for fourth, fifth, prediction in [(1, 1, 1), (0, 0, 0), (0, 2, 1), (0, 1, None)]:
            state = bytes([1, 0, 0, 0, fourth, fifth, 0, 0])
            result = decode_event(event('is_ready', state))
            self.assertTrue(result['decoded'])
            self.assertEqual(result['predicted_return'], prediction)
            self.assertFalse(result['captured_return'])

    def test_ignore_disabled_and_initial_update_flags(self):
        observation = event('ignore_update', b'\1\0\0\0\0\1\0\0')
        self.assertEqual(decode_event(observation)['predicted_return'], 0)
        write(observation, 696, 3, 0x10)
        self.assertTrue(decode_event(observation)['predicted_ignore_update'])
        for flags, ignored in [(2, False), (8, False), (1, True), (10, False)]:
            write(observation, 320, 0, flags)
            self.assertEqual(decode_event(observation)['predicted_ignore_update'], ignored)

    def test_special_and_accumulated_ignore_gate(self):
        observation = event('ignore_update')
        write(observation, 696, 3, 0x10)
        write(observation, 30032, 8, 1)
        self.assertFalse(decode_event(observation)['predicted_ignore_update'])
        write(observation, 30032, 69, 1)
        self.assertTrue(decode_event(observation)['predicted_ignore_update'])

    def test_can_update_rejections(self):
        rows = [(b'\0\0\0\0\1\1\0\0', 255),
                (b'\1\0\0\1\1\1\0\0', 255),
                (b'\1\0\0\0\1\0\0\0', 233),
                (b'\2\1\0\0\1\1\0\0', 252)]
        for state, expected in rows:
            self.assertEqual(decode_event(event('can_update', state))['predicted_return'], expected)
        observation = event('can_update')
        write(observation, 696, 0, 0)
        self.assertEqual(decode_event(observation)['predicted_return'], 254)
        write(observation, 696, 0, 1)
        write(observation, 30000, 37, 1)
        self.assertEqual(decode_event(observation)['predicted_return'], 253)
        write(observation, 30000, 37, 0)
        write(observation, 952, 1, 8)
        self.assertEqual(decode_event(observation)['predicted_return'], 251)

    def test_can_update_helper_remains_unknown(self):
        result = decode_event(event('can_update'))
        self.assertIsNone(result['predicted_return'])
        self.assertEqual(result['possible_returns'], [0, 250])

    def test_missing_capture_remains_unknown(self):
        observation = event('ignore_update')
        observation['memory'][0]['bytes'] = 'E14'
        result = decode_event(observation)
        self.assertFalse(result['decoded'])
        self.assertNotIn('predicted_return', result)


if __name__ == '__main__':
    unittest.main()
