"""Guarded fileset extension for native RW data beyond the retained-kext window."""
from pathlib import Path
import struct


def apply(kit: Path):
    path = kit / 'fileset_layout.py'
    text = path.read_text()
    old = '        self.place_data(code_end)\n'
    new = '''        # The original __DATA mapping remains at its original address for
        # retained kexts. Native data gets a separate RW mapping at the tail.
        # XNU maps the member's __DATA independently of the root's kext DATA.
        segment = self.segment('__DATA')
        address = self.allocate(segment['size'])
        self.reserve('__DATA', address)
        self.roots['__PDX_DATA'] = dict(segment, name='__PDX_DATA', va=address,
                                      fileoff=address-cache.base, filesize=segment['size'])
'''
    if text.count(old) != 1:raise ValueError('Unexpected data placement implementation')
    text = text.replace(old,new)
    old = "address = self.end('__DATA') if segment['name'] == '__PRELINK_DATA' else self.end('__KLD')"
    new = "address = self.roots['__DATA']['va'] if segment['name'] == '__PRELINK_DATA' else self.end('__KLD')"
    if text.count(old) != 1:raise ValueError('Unexpected prelink data marker')
    text = text.replace(old,new)
    path.write_text(text)
    path = kit / 'fileset_segmented.py'
    text = path.read_text()
    old = "            source = self.layout.segment(name)\n"
    new = "            source = self.layout.segment('__DATA' if name == '__PDX_DATA' else name)\n"
    if text.count(old) != 1:raise ValueError('Unexpected root mapping serialization')
    path.write_text(text.replace(old,new))


def validate(original, native, candidate, layout):
    from kc_image import Image
    member = Image(candidate.data, candidate.entries['com.apple.kernel'][1])
    root = next(s for s in candidate.segments if s['name'] == '__PDX_DATA')
    data = next(s for s in member.segments if s['name'] == '__DATA')
    marker = next(s for s in member.segments if s['name'] == '__PRELINK_DATA')
    old_data = next(s for s in original.segments if s['name'] == '__DATA')
    kept_data = next(s for s in candidate.segments if s['name'] == '__DATA')
    assert all(kept_data[k] == old_data[k] for k in ('va','size','fileoff','filesize'))
    assert root['va'] == data['va'] and root['size'] == data['size']
    assert root['filesize'] == root['size'] and root['fileoff'] == root['va']-candidate.base
    assert marker['size'] == 0 and marker['va'] == kept_data['va']
    assert struct.unpack_from('<II',candidate.data,root['command_offset']+56) == (3,3)
    retained = 0
    for name, (_, offset) in candidate.entries.items():
        if name == 'com.apple.kernel':continue
        before = Image(original.data, original.entries[name][1])
        after = Image(candidate.data, offset)
        for old,new in zip(before.segments,after.segments):
            assert all(old[k] == new[k] for k in ('name','va','size','fileoff','filesize'))
        retained += 1
    def translate(address):
        segments=[s for s in native.segments if s['va'] <= address < s['va']+s['size']]
        assert len(segments)==1
        s=segments[0]
        return int(layout[s['name']]['new'],16)+address-s['va']
    fixups=candidate.fixups()
    for site,pointer in native.fixups().items():
        assert fixups[translate(site)] == (translate(pointer[0]),*pointer[1:])
    zeros = candidate.read(data['va']+data['filesize'], data['size']-data['filesize'])
    assert not any(zeros), 'Native zero-fill data is not zero'
    return dict(native_data_bytes=data['size'],root_mapping='__PDX_DATA',
                native_data_address=hex(data['va']),prelink_data_marker=hex(marker['va']),
                retained_members=retained,all_native_fixups_verified=len(native.fixups()),
                zero_fill_verified=True,rw_nx=True,runtime_verified=False)
