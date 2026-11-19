"""Bridge retained D27 kmod entrypoint fixups to the native compiler's ABI.

This changes only kmod_info.start/stop authentication diversifiers. Targets,
keys, address diversity and all other chained pointers remain untouched. It
does not strip PAC or relax authentication. Native callers still authenticate.
"""
import struct

D27_KMOD_DIVERSITY = 0xE4FE
NATIVE_KMOD_DIVERSITY = 0
START_OFFSET, STOP_OFFSET = 180, 188  # kmod_info_t, #pragma pack(4)
# Names in the pinned D27 kmod records need not equal CFBundleIdentifier.
D27_KMOD_NAMES = {
    'com.apple.driver.AppleARMWatchdogTimer': 'com.apple.watchdog',
    'com.apple.kext.AppleMatch': 'com.apple.kext.Match',
    'com.apple.driver.ApplePMGR': 'com.apple.ApplePMGR',
    'com.apple.iokit.CoreAnalyticsFamily': 'com.apple.iokit.CoreAnalytics',
    'com.apple.kext.CoreTrust': 'com.company.driver.modulename',
    'com.apple.iokit.IOReportFamily': 'com.apple.iokit.IOReporting',
    'com.apple.iokit.IOStorageFamily': 'com.company.driver.modulename',
}


def converted_pointer(pointer):
    target, auth, key, diversity, address_diversity = pointer
    if (auth, key, diversity, address_diversity) != (1, 0, D27_KMOD_DIVERSITY, 0):
        raise ValueError(f'Unexpected retained kmod PAC schema: {pointer!r}')
    return target, auth, key, NATIVE_KMOD_DIVERSITY, address_diversity


def entrypoint_sites(cache, metadata, closure, native):
    """Use explicit prelink kmod records, never a global diversity substitution."""
    names = {name: address for address, symbols in native.symbols().items() for name in symbols}
    start_once = names.get('_source_corecrypto14_start_once')
    if start_once is None:
        raise ValueError('Need the audited native corecrypto caller')
    # Its observed ldur x8,[x19,#180] / blraaz x8 call proves zero-diversity IA.
    body = native.read(start_once, 0x100)
    expected = struct.pack('<4I', 0xF84B4268, 0xAA1303E0, 0xAA1403E1, 0xD63F091F)
    if body.count(expected) != 1:
        raise ValueError('Native kmod caller no longer has the audited zero-diversity ABI')
    fixups = cache.fixups()
    sites, records = {}, []
    for entry in metadata['_PrelinkInfoDictionary']:
        identifier = entry['CFBundleIdentifier']
        if closure is not None and identifier not in closure:
            continue
        kmod = entry.get('_PrelinkKmodInfo', 0) & ((1 << 64) - 1)
        if not kmod:
            continue
        if struct.unpack('<I', cache.read(kmod + 8, 4))[0] != 1:
            raise ValueError(f'Unexpected kmod version: {identifier}')
        name = cache.read(kmod + 16, 64).split(b'\0', 1)[0].decode()
        if name != D27_KMOD_NAMES.get(identifier, identifier):
            raise ValueError(f'Kmod identity mismatch: {identifier} / {name}')
        for field, offset in (('start', START_OFFSET), ('stop', STOP_OFFSET)):
            site = kmod + offset
            pointer = fixups.get(site)
            if pointer is None:
                if cache.read(site, 8) != bytes(8):
                    raise ValueError(f'Non-null unchained kmod field: {identifier}.{field}')
                continue
            converted_pointer(pointer)  # validate the original authenticated schema
            if site in sites:
                raise ValueError('Overlapping kmod entrypoint records')
            sites[site] = pointer
            records.append(dict(component=identifier, kmod_name=name, field=field, site=hex(site),
                                target=hex(pointer[0]), key='IA', authentication=True,
                                old_diversity=hex(pointer[3]), new_diversity='0x0',
                                address_diversity=False))
    if not any(e['component'] == 'com.apple.kec.corecrypto' and e['field'] == 'start' for e in records):
        raise ValueError('Retained original corecrypto start fixup is required')
    return sites, records
