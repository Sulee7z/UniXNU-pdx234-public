"""Sony resource sizing within the retained, allocator-checked entry bank."""
import copy
import struct

ENTRY_BASE = 0x880000000
ENTRY_BYTES = 0x39d00000
OWNED_BYTES = 0x38000000
MAXVNODES = OWNED_BYTES // 65536 + 1024


def apply(tree, high_memory=False):
    before = copy.deepcopy(tree)
    chosen = tree['children']['chosen']['properties']
    defaults = tree['children']['defaults']['properties']
    assert struct.unpack('<Q', chosen['dram-base'])[0] == ENTRY_BASE
    assert struct.unpack('<Q', chosen['dram-size'])[0] == ENTRY_BYTES
    assert struct.unpack('<Q', chosen['darwinboot-memory-size'])[0] == 0x30000000
    assert 'kern.maxvnodes' not in defaults
    # The image base retains a 16KiB offset within the loader's 2MiB alignment.
    # Leave the rest of this real bank for firmware allocations. AllocatePages
    # still decides whether a conventional run actually exists at boot.
    assert OWNED_BYTES + 0x4000 < ENTRY_BYTES
    owned = 0x130000000 if high_memory else OWNED_BYTES
    base = 0x980000000 if high_memory else ENTRY_BASE
    length = 0x180000000 if high_memory else ENTRY_BYTES
    chosen['darwinboot-memory-size'] = struct.pack('<Q', owned)
    defaults['kern.maxvnodes'] = struct.pack('<I', owned//65536+1024)
    if high_memory:
        chosen['dram-base'] = struct.pack('<Q',base)
        chosen['dram-size'] = struct.pack('<Q',length)
    restored = copy.deepcopy(tree)
    restored['children']['chosen']['properties']['darwinboot-memory-size'] = before['children']['chosen']['properties']['darwinboot-memory-size']
    del restored['children']['defaults']['properties']['kern.maxvnodes']
    if high_memory:
        for key in ('dram-base','dram-size'):
            restored['children']['chosen']['properties'][key]=before['children']['chosen']['properties'][key]
    assert restored == before
    return dict(owned_memory_before=0x30000000, owned_memory_bytes=owned,
                owned_memory_mib=owned//2**20, maxvnodes=owned//65536+1024,
                entry_base=hex(base), entry_bytes=length,
                other_adt_properties_unchanged=True, runtime_verified=False)
