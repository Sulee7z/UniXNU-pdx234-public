"""Exact068 storage-source qualifiers for selected069 crash evidence/policy overlays."""
import hashlib
from pathlib import Path
from .source import preserve_crash_messages, launch_policy

BOOT_INPUT = '50efc2b0dc008e3b10a7ccc284f1f063f90d1c566d4087a19594e43d9cee566a'
BOOT_OUTPUT = 'd82b8a7799eee68246dfefb026bac4aaac8e660b86fd673a44262bdabab4b846'
POLICY_INPUT = '890acb06824ecb4e8f5b15b92d0b9cddbba10e6de87f5843af33f8361a4f38fd'
POLICY_OUTPUT = '097e0d085ec60e9357b20bd3088a7f96cab1c092dea46e65a519c10ae1c4f568'
OFFICIAL_POLICY = Path('/mnt/f/UniXNU-Port-artifacts/platform069-20261118/sheng/package/BootWatchdogPolicy.c')
OFFICIAL_POLICY_SHA = 'b8a8b3eb6fa3877df534dfacb1957d15efd9be689266a7bfd1fe321fe6b563d1'


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def adapt_boot_log(text):
    if digest(text) != BOOT_INPUT:
        raise ValueError('Crash logging requires the actual068 selected provider')
    result = preserve_crash_messages(text)
    if digest(result) != BOOT_OUTPUT:
        raise ValueError('Unqualified069 bounded crash selector')
    return result


def adapt_launch_policy(text):
    if digest(text) != POLICY_INPUT:
        raise ValueError('Launch policy requires selected Sony068 baseline')
    official = OFFICIAL_POLICY.read_text()
    if digest(official) != OFFICIAL_POLICY_SHA:
        raise ValueError('Official069 policy source changed')
    result = launch_policy(text, official)
    if digest(result) != POLICY_OUTPUT:
        raise ValueError('Official launch policy / Sony builtins composition changed')
    return result


ADAPTERS = {'crashes069-persistent-lines': adapt_boot_log,
            'crashes069-official-launch-policy': adapt_launch_policy}
