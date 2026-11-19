"""Strengthen vendor dispatch prerequisites without changing their PE code."""
import uuid

DAL = 'ae37b942-457f-4c91-a196-d9669fd347a3'
CONSUMERS = ('NpaDxe', 'ULogDxe', 'RscDxe', 'UsbConfigDxe')
NPA = '79d6c870-725e-489e-a0a1-27e7a5d0cb35'
RPMH = 'e1d0b573-f29f-495d-9352-ca0dd42a0a74'
CLOCK = '241afae6-885f-4f6c-a7ea-c28eab79c3e5'
CMDDB = '1c34f691-d33d-4e14-b8f8-32c6c029e95b'
HWIO = '9e61de7c-9927-4f28-9f3d-320705d81801'
ULOG = '93a824b1-f77c-4880-ad95-e7bc634f9051'
ULOG_DEPENDENCIES = {'NpaDxe': (ULOG,)}
PMIC_VERSION = '4684800a-2755-4edc-b443-7f8ceb3239d3'
PMIC_GPIO = '4bc5c6d7-4ca4-8835-d1bc-d29cc2025d4a'
ICB = '5824f9de-17d2-4b1f-a5fe-5eb77fa53093'
# UsbConfigLibOpenProtocols consumes PMIC services and /icb/arbiter.
USB_RESOURCE_DEPENDENCIES = {'UsbConfigDxe': (PMIC_VERSION, PMIC_GPIO, ICB),
                             'UsbPwrCtrlDxe': (PMIC_VERSION,)}
# Sony BOOT.MXF.2.1.1 code calls these services during initialization.
# ClockVoltage registers callbacks for future VCS rails: do not add a
# Clock -> VCS edge that would deadlock VCS -> RPMh -> Clock.
POWER_DEPENDENCIES = {
    'ClockDxe': (NPA,),
    'RpmhDxe': (CLOCK, CMDDB),
    'PmicDxe': (NPA, CLOCK, RPMH, CMDDB),
    'VcsDxe': (NPA, RPMH, CMDDB),
    'ICBDxe': (NPA, CLOCK, RPMH, CMDDB),
    'RscDxe': (HWIO, CLOCK),
    'UsbConfigDxe': (NPA, CLOCK),
}


def evaluate(data, installed):
    stack = []; at = 0
    while at < len(data):
        op = data[at]; at += 1
        if op == 2:
            if at + 16 > len(data): raise ValueError('Truncated PUSH')
            guid = str(uuid.UUID(bytes_le=data[at:at+16])); at += 16
            stack.append(guid in installed)
        elif op in (3, 4):
            if len(stack) < 2: raise ValueError('Stack underflow')
            right, left = stack.pop(), stack.pop()
            stack.append(left and right if op == 3 else left or right)
        elif op == 5:
            if not stack: raise ValueError('Stack underflow')
            stack[-1] = not stack[-1]
        elif op in (6, 7): stack.append(op == 6)
        elif op == 8:
            if at != len(data) or len(stack) != 1: raise ValueError('Invalid END')
            return stack[0]
        else: raise ValueError('Unsupported DEPEX opcode')
    raise ValueError('Missing END')


def require_dal(data):
    return require_protocols(data, (DAL,))


def require_protocols(data, guids):
    evaluate(data, set())  # Validate the original expression before composing.
    for guid in guids:
        data = data[:-1] + b'\x02' + uuid.UUID(guid).bytes_le + b'\x03\x08'
    return data
