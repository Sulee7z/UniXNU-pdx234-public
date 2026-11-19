"""Keep Recount's fixed CPU-kind indexes inside the allocated track span."""
OLD = '\t_recount_cpu_kind_count = __builtin_popcount(cpu_kind_bits);'
NEW = ('\t/* Tracks are indexed by the fixed RCT_CPU_* values.  A boot with only\n'
       '\t * E cores still uses index 1; popcount would allocate just index 0.\n'
       '\t * Reserve through the highest present index, leaving holes zeroed. */\n'
       '\t_recount_cpu_kind_count = cpu_kind_bits ?\n'
       '\t    (unsigned int)(sizeof(cpu_kind_bits) * 8 - __builtin_clz(cpu_kind_bits)) : 0;')


def adapt_source(text):
    if text.count(OLD) != 1:
        raise ValueError('Unexpected Recount startup source; do not alter allocator checks')
    return text.replace(OLD, NEW, 1)
