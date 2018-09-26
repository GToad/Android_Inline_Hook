.global _shellcode_start_s
.global _shellcode_end_s
.global _hookstub_function_addr_s
.global _old_function_addr_s

.data

_shellcode_start_s:

    sub     sp, sp, #0x20

    mrs     x0, NZCV
    str     x0, [sp, #0x10]
    str     x30, [sp]   
    add     x30, sp, #0x20
    str     x30, [sp, #0x8]    
    ldr     x0, [sp, #0x18]

    sub     sp, sp, #0xf0
    stp     X0, X1, [SP]
    stp     X2, X3, [SP,#0x10]
    stp     X4, X5, [SP,#0x20]
    stp     X6, X7, [SP,#0x30]
    stp     X8, X9, [SP,#0x40]
    stp     X10, X11, [SP,#0x50]
    stp     X12, X13, [SP,#0x60]
    stp     X14, X15, [SP,#0x70]
    stp     X16, X17, [SP,#0x80]
    stp     X18, X19, [SP,#0x90]
    stp     X20, X21, [SP,#0xa0]
    stp     X22, X23, [SP,#0xb0]
    stp     X24, X25, [SP,#0xc0]
    stp     X26, X27, [SP,#0xd0]
    stp     X28, X29, [SP,#0xe0]
          
    mov     x0, sp
    ldr     x3, 8
    b       12

_hookstub_function_addr_s:
.double 0xffffffffffffffff

    blr     x3
    ldr     x0, [sp, #0x100]
    msr     NZCV, x0

    ldp     X0, X1, [SP]
    ldp     X2, X3, [SP,#0x10]
    ldp     X4, X5, [SP,#0x20]
    ldp     X6, X7, [SP,#0x30]
    ldp     X8, X9, [SP,#0x40]
    ldp     X10, X11, [SP,#0x50]
    ldp     X12, X13, [SP,#0x60]
    ldp     X14, X15, [SP,#0x70]
    ldp     X16, X17, [SP,#0x80]
    ldp     X18, X19, [SP,#0x90]
    ldp     X20, X21, [SP,#0xa0]
    ldp     X22, X23, [SP,#0xb0]
    ldp     X24, X25, [SP,#0xc0]
    ldp     X26, X27, [SP,#0xd0]
    ldp     X28, X29, [SP,#0xe0]
    add     sp, sp, #0xf0
     
    ldr     x30, [sp]
    add     sp, sp, #0x20

    stp     X1, X0, [SP, #-0x10]
    ldr     x0, 8
    b       12

_old_function_addr_s:
.double 0xffffffffffffffff

    br      x0


    


_shellcode_end_s:

.end
