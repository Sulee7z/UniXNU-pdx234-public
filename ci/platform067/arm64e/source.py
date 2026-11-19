"""Exact composed source qualifier for main's optional official addon-size integration.

Replaces the *qualification* of audit-d27-addon-reference only when this hunk
is actually selected. Existing native_source_overlays.py is not edited here.
"""
import hashlib
from pathlib import Path

ORIGINAL_SHA = 'b4289eb0381519fe151109c6c11fc9b340d319f020d1a2aff261e7e40c21b8eb'
STAGED_SHA = 'f53f9ae1393621368bbba4bdcea39c35d472f154994123a288119bc071e211f6'
PATCH_SHA = '1483202946d5e5b4e8d4e7e5f96f25a84ddf6ed5c385930a3792e4e50b3b21bf'
ANCHOR = ('\t\tVATTR_SET(&va, va_mode, mode);\n'
          '\t\terror = vnode_setattr(vp, &va, ctx);')
ADDITION = ('\t\t/* Kernel vnode_open does not finish O_TRUNC on the non-compound path. */\n'
            '\t\tVATTR_SET(&va, va_data_size, size);\n')


def adapt_source(text):
    """Preserve D27's proven lower G14 entry, add only the official two lines."""
    if hashlib.sha256(text.encode()).hexdigest() != ORIGINAL_SHA:
        raise ValueError('Unqualified066 original kern_exec source')
    old = '"/System/Library/Extensions/AGXMetalG17G.bundle"'
    if text.count(old) != 1 or text.count(ANCHOR) != 1:
        raise ValueError('Unexpected D27 addon anchors')
    text = text.replace(old, '"/System/Library/Extensions/AGXMetalG14.bundle"', 1)
    text = text.replace(ANCHOR, '\t\tVATTR_SET(&va, va_mode, mode);\n' + ADDITION +
                        '\t\terror = vnode_setattr(vp, &va, ctx);', 1)
    if hashlib.sha256(text.encode()).hexdigest() != STAGED_SHA:
        raise ValueError('Composed official addon-size source identity differs')
    return text
