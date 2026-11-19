"""Bounded source corrections identified by the sheng27 integration audit."""


def restore_dtrace(text):
    start=text.index('/* Sony interim build: keep the MAC checks')
    end=text.index('#define DTRACE_LABEL(provider, name) ""',start)
    end+=len('#define DTRACE_LABEL(provider, name) ""\n')
    return text[:start]+text[end:]


def addon_reference(text):
    old='"/System/Library/Extensions/AGXMetalG17G.bundle"'
    if text.count(old)!=1:raise ValueError('Unexpected GPU lower reference')
    # The D27 original cache index identifies AGXMetalG14; retain the mounted
    # lower-entry and owner-entry checks instead of ignoring their errors.
    return text.replace(old,'"/System/Library/Extensions/AGXMetalG14.bundle"')


def sdt_section(text):
    old='if ((sec_sdt = getsectbynamefromheader(mh, "__DATA_CONST", "__sdt")) == NULL) {'
    if text.count(old)!=1:raise ValueError('Unexpected SDT section consumer')
    return text.replace(old,'''/* Native SDT records may live in readonly TEXT to preserve D27's
         * retained constant prefix; original kext sections remain supported. */
        sec_sdt = getsectbynamefromheader(mh, "__DATA_CONST", "__sdt");
        if (sec_sdt == NULL) sec_sdt = getsectbynamefromheader(mh, "__TEXT", "__sdt");
        if (sec_sdt == NULL) {''')


ADAPTERS={'audit-restore-mac-dtrace':restore_dtrace,'audit-d27-addon-reference':addon_reference,
          'audit-readonly-sdt-location':sdt_section}
UNITS={'mac_vfs.c':'audit-restore-mac-dtrace','kern_exec.c':'audit-d27-addon-reference',
       'sdt.c':'audit-readonly-sdt-location'}
