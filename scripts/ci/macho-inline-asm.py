#!/usr/bin/env python3
"""Preserve all instructions in C/C++ inline asm when targeting Mach-O ARM64."""
import re


def normalize(source):
    count = 0

    def replace(match):
        nonlocal count
        head, literals = match.groups()
        changed = literals.replace(';', r'\n\t')
        count += literals.count(';')
        return head + changed

    # Only the assembler template: operands/clobbers and ordinary C++ strings
    # are excluded. Quoted sequences may be concatenated across source lines.
    pattern = r'((?:__asm__|asm)\s*(?:volatile\s*)?\(\s*)((?:"(?:\\.|[^"\\])*"\s*)+)'
    result = re.sub(pattern, replace, source)
    return result, count
