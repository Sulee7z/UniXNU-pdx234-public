// Real compiler regression input; no weakened schema or emulated auth functions.
struct AuthSlot {
  void * __ptrauth(2, 1, 0x2345, "authenticates-null-values") value;
};
struct OrdinarySlot {
  void * __ptrauth(2, 1, 0x2345) value;
};

void auth_store_zero(struct AuthSlot *slot) { slot->value = (void *)0; }
void *auth_load(struct AuthSlot *slot) { return slot->value; }
void auth_store_pointer(struct AuthSlot *slot, void *value) { slot->value = value; }
void auth_copy(struct AuthSlot *dst, struct AuthSlot *src) { *dst = *src; }
void ordinary_copy(struct OrdinarySlot *dst, struct OrdinarySlot *src) { *dst = *src; }
void auth_to_ordinary(struct OrdinarySlot *dst, struct AuthSlot *src) { dst->value = src->value; }
void ordinary_to_auth(struct AuthSlot *dst, struct OrdinarySlot *src) { dst->value = src->value; }
void ordinary_store_zero(struct OrdinarySlot *slot) { slot->value = (void *)0; }
void *ordinary_load(struct OrdinarySlot *slot) { return slot->value; }

#ifndef QEMU_RUNTIME
struct AuthSlot explicit_global_zero = {(void *)0};
struct AuthSlot implicit_global_zero = {0};
#endif
