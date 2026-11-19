// SPDX-License-Identifier: BSD-2-Clause-Patent
// Host-only QEMU fixture. Never embedded in a handset image.
.arch armv8.3-a
.text
.global _start
_start:
    mov x0, #0x42000000
    mov sp, x0
    mrs x0, CurrentEL
    cmp x0, #4
    b.ne fail
    adr x0, vectors
    msr VBAR_EL1, x0
    mov x0, #0x1234
    msr APIAKeyLo_EL1, x0
    mov x0, #0x5678
    msr APIAKeyHi_EL1, x0
    mrs x0, SCTLR_EL1
    mov x1, #0x80000000
    orr x0, x0, x1
    msr SCTLR_EL1, x0
    isb

    // Retained D27 storage: sign using the recorded kmod type diversifier.
    adr x20, target
    mov x17, #0xe4fe
    mov x8, x20
    pacia x8, x17
    cmp x8, x20
    b.eq fail
    // Native caller's zero-diversity authentication must reject that pointer.
    mov x9, x8
    mov x22, #0
    autiza x9
    cbnz x22, expected_rejection
    cmp x9, x20
    b.eq fail
expected_rejection:
    // Correct original schema still authenticates with the very same key.
    autia x8, x17
    cmp x8, x20
    b.ne fail

    // Adapter: only the storage diversifier changes; authentication stays on.
    mov x8, x20
    paciza x8
    blraaz x8
    cmp x0, #0x55
    b.ne fail
    adr x0, success_text
    bl puts
    mov x0, #0
    b exit
target:
    mov x0, #0x55
    ret
fail:
    adr x0, failure_text
    bl puts
    mov x0, #1
exit:
    adr x1, exit_block
    str x0, [x1, #8]
    mov x0, #0x20
    hlt #0xf000
    b .
puts:
    mov x2, #0x09000000
1:
    ldrb w1, [x0], #1
    cbz w1, 2f
    str w1, [x2]
    b 1b
2:
    ret

.balign 2048
vectors:
.rept 16
    b synchronous
    .space 124
.endr
synchronous:
    mrs x10, ESR_EL1
    lsr x11, x10, #26
    cmp x11, #0x1c
    b.ne fail
    mov x22, #1
    mrs x10, ELR_EL1
    add x10, x10, #4
    msr ELR_EL1, x10
    eret
.balign 8
exit_block:
    .quad 0x20026, 0
success_text:
    .asciz "D27-KMOD-PAC: PASS original-e4fe/reject-zero; adapted-zero/call-pass\n"
failure_text:
    .asciz "D27-KMOD-PAC: FAIL\n"
