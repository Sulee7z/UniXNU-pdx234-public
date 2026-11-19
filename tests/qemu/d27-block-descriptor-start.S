// SPDX-License-Identifier: BSD-2-Clause-Patent
// Bounded host-only PAC fixture, never linked into handset images.
.arch armv8.3-a
.text
.global _start
_start:
    mov x0, #0x42000000
    mov sp, x0
    adr x0, vectors
    msr VBAR_EL1, x0
    mov x0, #0x1234
    msr APIAKeyLo_EL1, x0
    msr APDAKeyLo_EL1, x0
    mov x0, #0x5678
    msr APIAKeyHi_EL1, x0
    msr APDAKeyHi_EL1, x0
    mov x0, #0x2345
    msr APIBKeyLo_EL1, x0
    mov x0, #0x6789
    msr APIBKeyHi_EL1, x0
    mrs x0, SCTLR_EL1
    mov x1, #0xc0000000
    orr x0, x0, x1
    mov x1, #0x08000000
    orr x0, x0, x1
    msr SCTLR_EL1, x0
    mov x0, #0x300000
    msr CPACR_EL1, x0
    isb
    bl block_test_main
    cbnz w0, failure
    adr x0, pass_text
    bl puts
    mov x0, #0
    b exit
.global block_test_fail
block_test_fail:
failure:
    mrs x0, ESR_EL1
    bl hex
    mrs x0, ELR_EL1
    bl hex
    mrs x0, FAR_EL1
    bl hex
    adr x0, fail_text
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
hex:
    mov x2,#0x09000000
    mov x3,#60
3:
    lsr x4,x0,x3
    and x4,x4,#15
    cmp x4,#10
    add x5,x4,#48
    add x6,x4,#87
    csel x5,x5,x6,lo
    str w5,[x2]
    subs x3,x3,#4
    b.ge 3b
    mov w5,#32
    str w5,[x2]
    ret
.balign 2048
vectors:
.rept 16
    b exception
    .space 124
.endr
exception:
    stp x0,x1,[sp,#-32]!
    stp x2,x3,[sp,#16]
    mrs x0,ESR_EL1
    lsr x0,x0,#26
    cmp x0,#0x1c
    b.ne failure
    adrp x1,block_test_expect_failure
    add x1,x1,:lo12:block_test_expect_failure
    ldr x0,[x1]
    cmp x0,#1
    b.ne failure
    str xzr,[x1]
    adrp x1,block_test_rejected
    add x1,x1,:lo12:block_test_rejected
    ldr x0,[x1]
    add x0,x0,#1
    str x0,[x1]
    mrs x0,ELR_EL1
    add x0,x0,#4
    msr ELR_EL1,x0
    ldp x2,x3,[sp,#16]
    ldp x0,x1,[sp],#32
    eret
.balign 8
exit_block: .quad 0x20026,0
pass_text: .asciz "D27-BLOCK-DESCRIPTOR: PASS copy/resign/retain/release/nested/global and tamper rejection\n"
fail_text: .asciz "D27-BLOCK-DESCRIPTOR: FAIL or unexpected PAC exception\n"
