.syntax unified
.cpu cortex-r5
.thumb

.equ SPM_BASE, 0x18308000

@ void sccmd_write_status(u32 status, u32 a2, u32 a3, u32 a4, u32 a5)
.equ sccmd_write_status, 0x0B506|1
@ void sccmd_trigger_reply()
.equ sccmd_trigger_reply, 0x0B4E8|1
.equ memcpy, 0x07F4

.equ uart0_mute, 0x9086D8

.macro mov32, reg, val
    movw \reg, #:lower16:\val
    movt \reg, #:upper16:\val
.endm

.macro blxi, reg, target
    mov32   \reg, \target
    blx     \reg
.endm

.global _start
_start:
    push    {r3-r11,lr}

    @ enable uart
    mov32   r3, uart0_mute
    mov     r4, 0
    strb    r4, [r3]

    @ reply to emc sccmd
    blxi    r4, sccmd_write_status
    blxi    r4, sccmd_trigger_reply

    @ set a cookie
    mov32   r3, SPM_BASE
    mov     r0, 0x1337
    str     r0, [r3]

    ldr     r1, [r3, 4]
    cmp     r1, r0
    bne     use_fw_shell

    @ jump to our own uart shell
    cpsid   aif

    mrc     p15, 0, r0, c1, c0, 0
    @ disable caches
    @ TODO properly flush before this
    mov     r1, ((1 << 12) | (1 << 2))
    bic     r0, r1
    @ disable mpu
    bic     r0, 1
    dsb
    mcr     p15, 0, r0, c1, c0, 0
    dsb
    isb

    mov32   r0, 0x58800000
    mov     sp, r0
    blxi    r0, 0x58000000

use_fw_shell:

@    mrc     p15, 0, r3, c1, c0, 0
@    mov     r5, r3
@    @ disable caches
@    mov     r3, ((1 << 12) | (1 << 2))
@    @ disable mpu (will screw up crash handling)
@    @orr     r4, 1
@    bic     r3, 1
@    @ enable background mode
@    orr     r3, (1 << 17)
@    dsb
@    mcr     p15, 0, r3, c1, c0, 0
@    dsb
@    isb
@    
@    mov32   r3, SPM_BASE+0x10
@    mov32   r0, 0
@    mov32   r2, 0x1000
@1:
@    ldr     r1, [r0], 4
@    str     r1, [r3], 4
@    cmp     r0, r2
@    bne     1b
@
@    mov     r3, r5
@    dsb
@    mcr     p15, 0, r3, c1, c0, 0
@    dsb
@    isb

    @ when ATCM is disabled, sram(the 0x1e0000 sized one) appears at 0

    @ MIDR
    @ on efc core0: 41_1_F_C15_3 ARM Cortex-R5 r1p3
    @mrc     p15, 0, r0, c0, c0, 0
    @ TCMTR: 00010001 (1 DTCM, 1 ITCM)
    @mrc     p15, 0, r0, c0, c0, 2
    @ SCTLR: 00ED1C7D
    @mrc     p15, 0, r0, c1, c0, 0
    @ ATCM region: 00000031, 2MB
    @mrc     p15, 0, r0, c9, c1, 1
    @ BTCM region: 00800031, 2MB
    @mrc     p15, 0, r0, c9, c1, 0
    @ Build Options 1: 00800000,TCM_HI_INIT_ADDR=00800000, no bus-ecc
    @mrc     p15, 0, r0, c15, c2, 0
    @ Build Options 2: 0EFFC1D2, no fpu, 16mpu regions
    @mrc     p15, 0, r0, c15, c2, 1

    @ LLPP Normal AXI region: 14000045, size=0b10001
    @mrc     p15, 0, r0, c15, c0, 1
    @ LLPP Virtual AXI region: 00000000
    @mrc     p15, 0, r0, c15, c0, 2
    @ AHB peripheral interface region: 10000045
    @mrc     p15, 0, r0, c15, c0, 3

    @ DIDR: 77040013
    @mrc     p14, 0, r0, c0, c0, 0
    @ DRAR: 18180003
    @mrc     p14, 0, r0, c1, c0, 0
    @ DSAR: 00010003
    @mrc     p14, 0, r0, c2, c0, 0

    pop     {r3-r11,pc}
