// SPDX-License-Identifier: BSD-2-Clause-Patent
// Sony GKI wrapper: preserve the original Android Image as a byte-identical payload.
// No stack/ABI or CPU-control changes on the default Android path.
#include "Pdx234ComboInputs.h"

.text
.global _Head
_Head:
  b _Start
  .long 0
  .quad 0                              // Linux text_offset is relative, not the FD destination.
  .quad (_ImageEnd - _Head)
  .quad ANDROID_IMAGE_FLAGS
  .quad 0
  .quad 0
  .quad 0
  .ascii "ARM\x64"
  .long 0

_Start:
  mov x24, x0
  mov x25, x1
  mov x26, x2
  mov x27, x3
  ldr x10, =SPMI_CORE_BASE
  ldr w11, [x10]
  mov w12, #0x70000000
  cmp w11, w12
   b.lo _Android
  mov w12, #0x80000000
  cmp w11, w12
   b.hs _Android
  ldr w11, [x10, #4]
  and w11, w11, #0x7ff
   cbz w11, _Android
  cmp w11, #1024
   b.hi _Android
  add x12, x10, #2, lsl #12
  mov x13, #0
_FindPon:
  ldr w14, [x12, x13, lsl #2]
  cbz w14, _NextPon
  ubfx w14, w14, #8, #12
   cmp w14, #0x013                     // Sony volume-up is PMK8550 PON RESIN.
  b.eq _ReadPon
_NextPon:
  add x13, x13, #1
  cmp w13, w11
  b.lo _FindPon
   b _Android
_ReadPon:
  ldr x15, =SPMI_OBSERVER_BASE
  add x15, x15, x13, lsl #5
  mov w16, #0x100
   movk w16, #0x800, lsl #16             // EXT_READL, PON_RT_STS +0x10
  str w16, [x15]
  dmb sy
  ldr w17, =100000
_PollPon:
  ldr w16, [x15, #8]
  tst w16, #1
  b.ne _PonReady
  subs w17, w17, #1
  b.ne _PollPon
   b _Android
_PonReady:
  tst w16, #0xe
   b.ne _Android
  ldr w16, [x15, #0x18]
   tst w16, #0x40                     // RESIN bit6: only held volume-up enters UEFI.
   b.eq _Android

_Uefi:
  adrp x4, _UefiSource
  add x4, x4, :lo12:_UefiSource
  ldr x5, =FD_BASE
  ldr x6, =FD_SIZE
_CopyFd:
  ldp x2, x3, [x4], #16
  stp x2, x3, [x5], #16
  subs x6, x6, #16
  b.ne _CopyFd
  ldr x5, =FD_BASE
  dsb sy
  mrs x9, ctr_el0
  ubfx x9, x9, #16, #4
  mov x10, #4
  lsl x9, x10, x9
  sub x10, x9, #1
  bic x8, x5, x10
  ldr x7, =FD_SIZE
  add x7, x5, x7
_CleanFd:
  dc cvac, x8
  add x8, x8, x9
  cmp x8, x7
  b.lo _CleanFd
  dsb sy
  ic iallu
  dsb sy
  isb
  adrp x1, _ComboInfo
  add x1, x1, :lo12:_ComboInfo
  adrp x2, _Head
  add x2, x2, :lo12:_Head
  adrp x9, _AndroidImage
  add x9, x9, :lo12:_AndroidImage
  str x9, [x1, #16]
  str x24, [x1, #32]
  str x2, [x1, #48]
  ldr x3, =(_ImageEnd - _Head)
  str x3, [x1, #56]
  mov x0, x24
  br x5

_Android:
  mov x0, x24
  mov x1, x25
  mov x2, x26
  mov x3, x27
  b _AndroidImage

.ltorg
.org ANDROID_PAYLOAD_OFFSET
.global _AndroidImage
_AndroidImage:
  .incbin ANDROID_INPUT_PATH
  // Reserve the original Image's stated in-memory extent before the FD source.
.org (ANDROID_PAYLOAD_OFFSET + ANDROID_MEMORY_BYTES)
.global _UefiSource
_UefiSource:
  .incbin UEFI_FD_INPUT_PATH
#ifdef XNU_BUNDLE_INPUT_PATH
  .balign 4096
_XnuBundle:
  .incbin XNU_BUNDLE_INPUT_PATH
_XnuBundleEnd:
  .balign 8
#endif
.global _ComboInfo
_ComboInfo:
  .ascii "PXCBHOF1"
#ifdef XNU_BUNDLE_INPUT_PATH
  .long 2
  .long 80
#else
  .long 1
  .long 64
#endif
  .quad 0
  .quad ANDROID_IMAGE_BYTES
  .quad 0
  .long ANDROID_IMAGE_CRC32
  .long 0
  .quad 0
  .quad 0
#ifdef XNU_BUNDLE_INPUT_PATH
  .quad (_XnuBundle - _Head)
  .quad (_XnuBundleEnd - _XnuBundle)
#endif
.global _ImageEnd
_ImageEnd:
