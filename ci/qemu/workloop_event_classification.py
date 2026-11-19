"""Resolve the actual authenticated virtual target for event classification."""
import hashlib

SOURCE_SHA256 = '10f6d04e18a5fb60fda7782b13c5b551d7e27bb191e798ad1011429c0ef66bc3'
OLD = '''		ptr1 = OSMemberFunctionCast(void*, inEventSource, &IOEventSource::checkForWork);
		ptr2 = OSMemberFunctionCast(void*, controlG, &IOEventSource::checkForWork);'''
NEW = '''#if __has_feature(ptrauth_member_function_pointer_type_discrimination) && !__has_builtin(__builtin_load_member_function_pointer)
		// This compiler represents virtual member pointers as dispatch thunks.
		// Comparing that thunk would classify every subclass as passive. Compare
		// the authenticated implementation in the qualified IOEventSource slot.
		// No table or entry is changed, and each original entry is authenticated
		// before its address is compared. Nothing is converted to a callable
		// pointer, so no unrelated C function-pointer signature is introduced.
		auto implementation = [](IOEventSource *event) -> void * {
			const void *const *table = reinterpret_cast<const void *const *>(
			    __builtin_get_vtable_pointer(event));
			const void *const *entry = table + 16;
			return const_cast<void *>(ptrauth_auth_data(*entry,
			    ptrauth_key_function_pointer, ptrauth_blend_discriminator(entry, 0x234e)));
		};
		ptr1 = implementation(inEventSource);
		ptr2 = implementation(controlG);
#else
''' + OLD + '''
#endif'''


def adapt_source(text):
    if hashlib.sha256(text.encode()).hexdigest() != SOURCE_SHA256 or text.count(OLD) != 1:
        raise ValueError('Require the exact current IOWorkLoop event classification source')
    return text.replace(OLD, NEW)
