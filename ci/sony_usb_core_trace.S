// SPDX-License-Identifier: BSD-2-Clause-Patent
// Diagnostic wrappers for hash-qualified Sony USBFN call sites.
// Preserve all integer/SIMD argument and result registers across DebugPrint.
// x16/x17 are AAPCS64 intra-procedure-call scratch registers.
.text
.p2align 2
.macro WRAPPER name, number, target
.global \name
\name:
  mov w16, #\number
  adr x17, \target
  b CoreTrace
.endm
// Generated call-site wrappers precede CoreTrace in the assembly input.
// Step identifier is the original call-site RVA, so repeated FIFO accesses
// retain their actual MMIO address in the logged arguments.

// Same three original QSCRATCH RMW operations, routed through the existing
// vendor IoLib for per-access boundaries. No additional register is touched.
.global TraceConnectBody
TraceConnectBody:
  cbz w0, 1f
  ret
1:
  stp x19, x30, [sp, #-32]!
  str x0, [sp, #16]
  mov x19, #0x8810
  movk x19, #0xa6f, lsl #16
  mov x0, x19
  bl TraceQRead20
  orr w1, w0, #0x100000
  mov x0, x19
  bl TraceQWrite20
  mov x0, x19
  bl TraceQRead28
  orr w1, w0, #0x10000000
  mov x0, x19
  bl TraceQWrite28
  add x0, x19, #32
  bl TraceQRead24
  orr w1, w0, #0x1000000
  add x0, x19, #32
  bl TraceQWrite24
  ldr x0, [sp, #16]
  ldp x19, x30, [sp], #32
  ret
WRAPPER TraceQRead20, 0xec1c, VendorRead
WRAPPER TraceQWrite20, 0xec24, VendorWrite
WRAPPER TraceQRead28, 0xec28, VendorRead
WRAPPER TraceQWrite28, 0xec30, VendorWrite
WRAPPER TraceQRead24, 0xec34, VendorRead
WRAPPER TraceQWrite24, 0xec3c, VendorWrite

.macro SAVE_VALUES
  stp x0, x1, [sp, #0]
  stp x2, x3, [sp, #16]
  stp x4, x5, [sp, #32]
  stp x6, x7, [sp, #48]
  str x8, [sp, #64]
  stp q0, q1, [sp, #96]
  stp q2, q3, [sp, #128]
  stp q4, q5, [sp, #160]
  stp q6, q7, [sp, #192]
.endm
.macro RESTORE_VALUES
  ldp x0, x1, [sp, #0]
  ldp x2, x3, [sp, #16]
  ldp x4, x5, [sp, #32]
  ldp x6, x7, [sp, #48]
  ldr x8, [sp, #64]
  ldp q0, q1, [sp, #96]
  ldp q2, q3, [sp, #128]
  ldp q4, q5, [sp, #160]
  ldp q6, q7, [sp, #192]
.endm
CoreTrace:
  sub sp, sp, #240
  stp x16, x17, [sp, #72]
  str x30, [sp, #224]
  SAVE_VALUES
  mov x6, x3
  mov x5, x2
  mov x4, x1
  mov x3, x0
  mov x2, x16
  mov w0, #0x80000000
  adr x1, EnterFormat
  bl VendorDebugPrint
  ldr x2, [sp, #72]
  ldp x3, x4, [sp, #32]
  ldp x5, x6, [sp, #48]
  mov w0, #0x80000000
  adr x1, UpperFormat
  bl VendorDebugPrint
  RESTORE_VALUES
  ldr x17, [sp, #80]
  blr x17
  SAVE_VALUES
  mov x3, x0
  ldr x2, [sp, #72]
  mov w0, #0x80000000
  adr x1, ReturnFormat
  bl VendorDebugPrint
  RESTORE_VALUES
  ldr x30, [sp, #224]
  add sp, sp, #240
  ret
EnterFormat:
  .asciz "PDX core %x enter %lx %lx %lx %lx\n"
ReturnFormat:
  .asciz "PDX core %x return %lx\n"
UpperFormat:
  .asciz "PDX core %x args4-7 %lx %lx %lx %lx\n"
