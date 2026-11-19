// SPDX-License-Identifier: BSD-2-Clause-Patent
// First 64 preparation calls per loaded image. x0 is logged as a register,
// never interpreted as an error for void/unknown APIs. All sites have <=3 args.
.text
.p2align 2
.macro WRAPPER name, site, target
\name:
 mov w16, #\site
 adr x17, \target
 b PrepareTrace
.endm
// WRAPPERS
.macro SAVE
 stp x0, x1, [sp]
 stp x2, x3, [sp, #16]
 stp x4, x5, [sp, #32]
 stp x6, x7, [sp, #48]
 str x8, [sp, #64]
 stp q0, q1, [sp, #96]
 stp q2, q3, [sp, #128]
 stp q4, q5, [sp, #160]
 stp q6, q7, [sp, #192]
.endm
.macro RESTORE
 ldp x0, x1, [sp]
 ldp x2, x3, [sp, #16]
 ldp x4, x5, [sp, #32]
 ldp x6, x7, [sp, #48]
 ldr x8, [sp, #64]
 ldp q0, q1, [sp, #96]
 ldp q2, q3, [sp, #128]
 ldp q4, q5, [sp, #160]
 ldp q6, q7, [sp, #192]
.endm
.global PrepareTrace
PrepareTrace:
 sub sp, sp, #240
 stp x16, x17, [sp, #72]
 str x30, [sp, #224]
 SAVE
 adr x17, Counter
 ldr w8, [x17]
 cmp w8, #64
 cset w8, lo
 str w8, [sp, #88]
 cbz w8, 1f
 ldr w8, [x17]
 add w8, w8, #1
 str w8, [x17]
 mov x5, x2
 mov x4, x1
 mov x3, x0
 mov x2, x16
 mov w0, #0x80000000
 adr x1, EnterFormat
 bl DebugPrint
1:
 RESTORE
 ldr x17, [sp, #80]
 blr x17
 SAVE
 ldr w8, [sp, #88]
 cbz w8, 2f
 mov x3, x0
 ldr x2, [sp, #72]
 mov w0, #0x80000000
 adr x1, ReturnFormat
 bl DebugPrint
2:
 RESTORE
 ldr x30, [sp, #224]
 add sp, sp, #240
 ret
EnterFormat:
 .asciz "PDX prep %x enter x0-2 %lx %lx %lx\n"
ReturnFormat:
 .asciz "PDX prep %x return x0 %lx\n"
