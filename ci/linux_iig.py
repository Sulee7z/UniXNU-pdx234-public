"""Shared iig-port PAC fallback, matching the published Linux iPadOS27 patch."""
FALLBACK = ('#else\n#define SimpleMemberFunctionCast(cfnty, self, func) '
            '({ union { typeof(func) memfun; cfnty cfun; } pair; pair.memfun = func; pair.cfun; })\n#endif')
AUTHENTICATED = ('#elif __has_feature(ptrauth_calls)\n'
                 '/* Read the nonvirtual _Impl address with its member-pointer schema; the load then authenticates and resigns for cfnty. */\n'
                 '#define SimpleMemberFunctionCast(cfnty, self, func) '
                 '({ union { typeof(func) memfun; cfnty __ptrauth(0, 0, __builtin_ptrauth_type_discriminator(typeof(func))) cfun; } pair; pair.memfun = func; pair.cfun; })\n'
                 + FALLBACK)


def adapt_generated(text):
    if AUTHENTICATED in text:
        return text
    if text.count(FALLBACK) != 1:
        raise ValueError('Unexpected generated IIG fallback; do not guess or strip PAC')
    return text.replace(FALLBACK, AUTHENTICATED, 1)
