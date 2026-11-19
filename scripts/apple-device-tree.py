#!/usr/bin/env python3
"""Bounded reader for the documented Apple device-tree wire format."""
import struct


def parse(blob):
    def node(at, depth):
        if depth > 64 or at + 8 > len(blob):
            raise ValueError('Truncated or overdeep ADT')
        count, children = struct.unpack_from('<II', blob, at)
        at += 8
        properties = {}
        for _ in range(count):
            if at + 36 > len(blob):
                raise ValueError('Truncated ADT property')
            key, size = struct.unpack_from('<32sI', blob, at)
            key = key.split(b'\0')[0].decode('ascii')
            at += 36
            if key in properties or at + ((size + 3) & ~3) > len(blob):
                raise ValueError('Duplicate or truncated ADT property')
            properties[key] = blob[at:at + size]
            at += (size + 3) & ~3
        if not properties.get('name', b'').endswith(b'\0'):
            raise ValueError('ADT node has no terminated name')
        kids = {}
        for _ in range(children):
            child, at = node(at, depth + 1)
            name = child['properties']['name'][:-1].decode('ascii')
            if name in kids:
                raise ValueError('Duplicate ADT child')
            kids[name] = child
        return {'properties': properties, 'children': kids}, at

    tree, end = node(0, 0)
    if end != len(blob):
        raise ValueError('Trailing ADT bytes')
    return tree


def u32(tree, path, key):
    for name in path.strip('/').split('/'):
        if name:
            tree = tree['children'][name]
    value = tree['properties'][key]
    if len(value) != 4:
        raise ValueError(f'{path}/{key} must be u32')
    return struct.unpack('<I', value)[0]
