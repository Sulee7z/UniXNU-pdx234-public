"""Decode only byte-qualified original D27 compositor gate observations.

Inputs are genuine user-trace events captured at original function entries.
This module does not alter guest state or substitute predictions for a captured
return. Results describe the observed entry values, which may race with other
threads after the breakpoint is resumed.
"""
FUNCTIONS = {
    'ignore_update': (0x18445c17c, '08ec4a39680020370800805219000014',
                      '973011edd8f016a75b52d30e36493f29ec24ec8ecd8d5b14af818be182c03e1e'),
    'can_update': (0x184435238, '7f2303d5f44fbea9fd7b01a9fd430091',
                   '8d748c5378ceb8808c10beac233d9092b9ef2e580ca4e45a9ee555948213a59f'),
    'is_ready': (0x18441fbac, '7f2303d5ffc300d1f44f01a9fd7b02a9',
                  'f65e256278f297ae9dd6acf7e1e87e0c5f1747d0a70b5240bfeef8aca8d35cf9'),
}


def number(value):
    return int(value, 0) if isinstance(value, str) else value


def decode_event(event):
    name = event['name']
    if name not in FUNCTIONS:
        raise ValueError('Unqualified original gate: ' + name)
    address, prefix, body_sha = FUNCTIONS[name]
    process = event.get('process', {})
    slide = number(process.get('shared_region_slide'))
    if (process.get('name') != 'backboardd' or slide is None or slide < 0 or slide & 4095 or
            number(event['pc']) != address + slide or event.get('entry_bytes') != prefix or
            number(event['pstate']) & 31):
        raise ValueError('Require the actual unchanged original backboardd EL0 entry')
    result = dict(name=name, pc=event['pc'], process=process, read_only=True,
                  original_function_sha256=body_sha,
                  captured_return=False, desktop_verified=False)

    def read(register, offset, size, indirect=False):
        matches = [r for r in event.get('memory', []) if r.get('register') == register
                   and r.get('offset') == offset and r.get('indirect', False) == indirect]
        if len(matches) != 1:
            raise ValueError('Required entry memory was not captured')
        raw = matches[0].get('bytes')
        if not isinstance(raw, str) or raw.startswith('E') or len(raw) < size * 2:
            raise ValueError('Original gate entry memory unavailable')
        return bytes.fromhex(raw)

    try:
        state = read(0, 816, 8, True)
        result['shared_state_bytes'] = state[:8].hex()
        if name == 'is_ready':
            if state[4]:
                result.update(entry_branch='existing-ready flag', predicted_return=1)
            elif state[5] != 1:
                result.update(entry_branch='state-five fallback', predicted_return=int(state[5] != 0))
            else:
                result.update(entry_branch='readiness initialization required', predicted_return=None,
                              reason='Original code calls its initialization and state-update paths')
        elif name == 'ignore_update':
            flags = read(0, 696, 8)
            extended = read(0, 30032, 80)
            update = read(1, 320, 8)
            update_bits = int.from_bytes(update[:8], 'little') & 0xa
            result['update_flags_mask_0a'] = update_bits
            if not flags[3] & 0x10:
                result.update(entry_branch='gate disabled', predicted_return=0)
            else:
                any_update = int(update_bits != 0)
                if extended[30101 - 30032] & 1:
                    use = any_update
                    branch = 'special update gate'
                else:
                    use = extended[30040 - 30032] | any_update
                    branch = 'accumulated update gate'
                    if not state[4] and state[5] == 1:
                        use = any_update
                        branch = 'initial display update gate'
                result.update(entry_branch=branch, predicted_return=(use ^ 1) & 1)
            result['predicted_ignore_update'] = bool(result['predicted_return'])
        else:
            flags = number(event['arguments'][1]) & 0xffffffff
            result['request_flags'] = hex(flags)
            if state[0] != 1 and state[1] != 1:
                result.update(entry_branch='primary state not usable', predicted_return=255)
            elif (flags & 4 and state[3] != 2) or (not flags & 4 and state[3] != 0):
                result.update(entry_branch='request and shared state mismatch', predicted_return=255)
            elif state[5] != 1:
                result.update(entry_branch='display state-five not ready', predicted_return=233)
            elif int.from_bytes(read(0, 696, 8)[:8], 'little') == 0:
                result.update(entry_branch='display context absent', predicted_return=254)
            elif read(0, 30000, 48)[37] & 1:
                result.update(entry_branch='display update inhibition bit', predicted_return=253)
            elif state[0] in (2, 3):
                result.update(entry_branch='shared state prevents update', predicted_return=252)
            elif read(0, 952, 4)[1] & 8:
                result.update(entry_branch='display flag prevents update', predicted_return=251)
            else:
                result.update(entry_branch='original update helper decides', predicted_return=None,
                              possible_returns=[0, 250],
                              reason='Original helper call at0x184435314 must actually execute')
        result['decoded'] = True
    except (ValueError, TypeError) as error:
        result.update(decoded=False, error=str(error))
    result['limits'] = ('Prediction from captured original entry values only; '
                        'requires actual return, swap completion and QMP UI for presentation evidence')
    return result
