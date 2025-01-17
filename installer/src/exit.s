.align 2
.arm

.global _dyld_quit

_dyld_quit:
    push    {r7, lr}
    mov     r7, sp
    sub     sp, #0x1c

    str     r0, [sp]
    movs    r0, #0x5
    str     r0, [sp, #0x4]

    mov     r12, #-28
    svc     #0x80

    movs    r1, #0x11
    add     r2, sp, #0x8
    add     r3, sp, #0x4
    blx     _task_info

    ldr     r0, [sp]
    ldr     r1, [sp, #0x8]

    str     r0, [r1, #0x20]
    movs    r0, #0
    str     r0, [r1, #0x24]

    trap
    add    sp, #0x8
    pop    {r7, pc}
