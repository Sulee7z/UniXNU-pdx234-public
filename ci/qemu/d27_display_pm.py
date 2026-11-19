"""Bounded reads of the actual display PM object through the stopped TTBR1.

The debugger supplies only packet reads. This module neither calls a guest
function nor changes its state; the shared translation reader restores the
debugger's original memory mode after every read.
"""
from d27_user_memory import kernel_pointer_view, read_kernel_memory


def _decode(raw, layout):
    values = {}
    if len(raw) != layout['bytes'] or not 0 < len(raw) <= 4096:
        raise ValueError('Incomplete bounded PM class read')
    for name, field in layout['fields'].items():
        start, size = field['offset'], field['bytes']
        if not 0 <= start < start + size <= len(raw) or size not in (1, 4, 8):
            raise ValueError('Invalid PM field span: ' + name)
        value = int.from_bytes(raw[start:start + size], 'little')
        if 'bit' in field:
            if field.get('bit_size') != 1 or not 0 <= field['bit'] < 8 or size != 1:
                raise ValueError('Invalid PM bit field: ' + name)
            value = (value >> field['bit']) & 1
        values[name] = value
    return values


def capture_display_pm(packet, registers, object_symbol, plan):
    """Use the exact compiler-qualified plan with a selected kernel's symbol.

The caller must bind plan.native_sha256/plan.object_sha256 to its selected
native build before using it with a prelinked guest. A prelink changes the final
image hash but must retain the exact native IOServicePM object/layout.
    """
    if (plan.get('schema') != 'd27-qemu-display-pm-layout-v1' or
            plan.get('compiler_qualified') is not True or plan.get('read_only') is not True):
        raise ValueError('Require the compiler-qualified read-only PM plan')
    result = dict(read_only=True, source='Actual stopped guest display and IOServicePM',
                  layout_object_sha256=plan['object_sha256'], reads=[], complete=False)

    def read(address, size):
        observed = read_kernel_memory(packet, registers, address, size)
        result['reads'].append(observed)
        raw = bytes.fromhex(observed['bytes'])
        if len(raw) != size:
            raise ValueError('Guest PM memory unavailable at ' + hex(address))
        return raw

    raw = read(object_symbol, 8)
    pointer = int.from_bytes(raw, 'little')
    result['object_pointer_raw'] = hex(pointer)
    if pointer == 0:
        result['display_created'] = False
        return result
    result['display_created'] = True
    display = kernel_pointer_view(pointer, registers['TCR_EL1'])
    result['object'] = hex(display)
    service_layout = plan['layouts']['IOService']
    service = _decode(read(display, service_layout['bytes']), service_layout)
    result['service'] = {**service, 'pwrMgt': hex(service['pwrMgt'])}
    if service['pwrMgt'] == 0:
        result['pm_object_created'] = False
        return result
    result['pm_object_created'] = True
    pm = kernel_pointer_view(service['pwrMgt'], registers['TCR_EL1'])
    result['pm_object'] = hex(pm)
    pm_layout = plan['layouts']['IOServicePM']
    values = _decode(read(pm, pm_layout['bytes']), pm_layout)
    result['pm'] = values
    result['predicates'] = dict(
        initialized=bool(service['initialized']),
        controlling_driver_present=values['ControllingDriver'] != 0,
        parents_know_state=bool(values['ParentsKnowState']),
        initial_power_change_pending=bool(values['InitialPowerChange']),
        driver_call_busy=bool(values['DriverCallBusy']),
        desired_differs_from_current=values['DesiredPowerState'] != values['CurrentPowerState'],
        power_plane_membership_observed=False,
    )
    for name in ('PowerStates', 'ControllingDriver'):
        result['pm'][name] = hex(values[name])
    result['complete'] = True
    result['limits'] = ('One stopped snapshot: does not prove power-plane membership, '
                        'wait duration, successful callback or desktop presentation')
    return result
