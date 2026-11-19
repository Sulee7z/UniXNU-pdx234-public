"""Composed069 diagnostics/policy overlays; never relax PAC, trust, guards or budgets."""
from pathlib import Path
import re


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Unqualified069 source anchor: ' + repr(old[:120]))
    return text.replace(old, new, 1)


def preserve_crash_messages(text):
    """Use the existing official bounded selector without enabling GPU diagnostic work.

    Actual068 has storage-probe1 but diag/gpu-trace0. Its writer consequently
    never saved unixnu-exit/EXC/memorystatus excerpts into periodic slots and the
    first580seconds were overwritten in the128KiB message tail. This changes
    only that selector gate. It does not enable screenshots/samplers/exports.
    """
    text = once(text, 'static uint64_t diag_msg_scan;   // stream offset of the first byte not scanned yet',
                'static int log_crash_evidence_on;   // storage-probe: retain exits/EXC/limits without GPU diagnostics\n'
                'static uint64_t diag_msg_scan;   // stream offset of the first byte not scanned yet')
    text = once(text, '    if (diag == 1) text = diag_msg_lines((char *)boot_log_buffer, text, LogSlotBlocks * LogBlock);',
                '    if (diag == 1 || log_crash_evidence_on) text = diag_msg_lines((char *)boot_log_buffer, text, LogSlotBlocks * LogBlock);')
    text = once(text, '  uint32_t checkpoint_mode = 0;\n'
                '  if (PE_parse_boot_argn("storage-probe", &checkpoint_mode, sizeof checkpoint_mode) && checkpoint_mode == 1) {',
                '  uint32_t checkpoint_mode = 0;\n'
                '  (void)PE_parse_boot_argn("storage-probe", &checkpoint_mode, sizeof checkpoint_mode);\n'
                '  log_crash_evidence_on = checkpoint_mode == 1;\n'
                '  if (checkpoint_mode == 1) {')
    return text


def launch_policy(text, fresh):
    """Take current official enable-jobs+POLICY_CALL logic, preserve Sony builtins.

    The current fresh builtins also enable uefi-watchdog. That firmware policy
    is not an app-crash fix, so the exact installed builtins remain unchanged.
    No job is automatically disabled/enabled by this adapter.
    """
    pattern = r'char PE_builtin_boot_args\[\]="[^"\n]+"'
    before = re.findall(pattern, text)
    after = re.findall(pattern, fresh)
    if len(before) != 1 or len(after) != 1:
        raise ValueError('Expected exact one initial builtin string in policy')
    return fresh.replace(after[0], before[0], 1)
