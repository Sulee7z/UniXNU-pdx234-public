"""Backport the selected upstream native-PAC default JOP policy C hunk."""
OLD = ('\treturn vmapple_default_jop_pid;\n'
       '#else\n'
       '\treturn 0;\n'
       '#endif /* HAS_PARAVIRTUALIZED_PAC */')
NEW = ('\treturn vmapple_default_jop_pid;\n'
       '#elif HAS_NATIVE_PAC\n'
       '\t/*\n'
       '\t * Every process signs with the one architectural key set, so this value\n'
       '\t * selects no key. It must not be 0: the shared region and dyld pagers\n'
       '\t * sign pointers only for a nonzero key and give arm64 processes key 0.\n'
       '\t */\n'
       '\treturn 1;\n'
       '#else\n'
       '\treturn 0;\n'
       '#endif /* HAS_PARAVIRTUALIZED_PAC */')
UPSTREAM = 'UniXNU/UniXNU@a11553a7a29a49777f2665008f4216fcd4ad1b40/patches/xnu-12377/native-pac-keys.patch'


def adapt_source(text):
    if text.count(OLD) != 1:
        raise ValueError('Unexpected native default JOP source; do not change PAC instructions or key setup')
    return text.replace(OLD, NEW, 1)
