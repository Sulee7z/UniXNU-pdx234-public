// Source mapping: UsbfnDwc3Ch9.c CoreCableStatus/CorePoll and
// UsbfnDwc3.c UsbfnEventHandler. Private VOID paths gain an EFI status;
// no public table, object layout, global latch, or relocation is added.
.text
.global CableFailure, PollReturn, PollSuccess, LogSuccess, LogFailure, Success
CableFailure:
    // Original 0x6380 failure tail has not restored the CableStatus frame.
    // Keep IsAttached set for explicit shutdown, but prohibit another poll.
    strb wzr, [x19, #0x180]       // Usbfn->Enabled = FALSE
    stp x0, x30, [sp, #-16]!
    mov x3, x0
    adr x1, FailureFormat
    adr x2, CableName
    mov w0, #0x80000000
    bl DebugPrint
    ldp x0, x30, [sp], #16
    ldp x20, x19, [sp, #0x30]
    ldp x22, x21, [sp, #0x20]
    ldr x23, [sp, #0x10]
    ldp x29, x30, [sp], #0x40
    ret
PollSuccess:
    mov x0, xzr
PollReturn:
    // Successful CableStatus's RUN_STOP tail returns a UINT32 MMIO value.
    // Only an actual EFI error (bit63) is propagated as an error.
    cmp x0, #0
    csel x0, x0, xzr, mi
    ldr x19, [sp, #0x10]
    ldp x29, x30, [sp], #0x20
    ret
LogSuccess:
    stp x29, x30, [sp, #-16]!
    bl DebugPrint
    ldp x29, x30, [sp], #16
Success:
    mov x0, xzr
    ret
LogFailure:
    // Original invalid/disabled poll path has already restored its frame.
    stp x29, x30, [sp, #-16]!
    bl DebugPrint
    ldp x29, x30, [sp], #16
    mov x0, #6                  // EFI_NOT_READY; no hardware access/retry
    movk x0, #0x8000, lsl #48
    ret
