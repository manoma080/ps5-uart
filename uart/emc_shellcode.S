@ arm-none-eabi-as -o emc_shellcode emc_shellcode.S
@ arm-none-eabi-objcopy -O binary emc_shellcode
@ TODO autogenerate at build time? 8)
.syntax unified
.arch armv7-m
.thumb

// E1E 0001 0000 0004 13d0
//.equ shellcode_addr, 0x1762E8 + 0xc * 2
//.equ auth_status_set, 0x120F94|1
//.equ ucmd_cmds_0, 0x157600
//.equ ucmd_iface_0_cmd_table, 0x173F68 + 0x78
//.equ hcmd_log_flag, 0x175724

// E1E 0001 0002 0003 1580
//.equ shellcode_addr, 0x17DE38 + 0xc * 2
//.equ auth_status_set, 0x122830|1
//.equ ucmd_cmds_0, 0x15A330
//.equ ucmd_iface_0_cmd_table, 0x17A674 + 0x78
//.equ hcmd_log_flag, 0x17D240

// E1E 0001 0004 0002 1752
.equ shellcode_addr, 0x184D9C + 0xc * 2
.equ auth_status_set, 0x124308|1
.equ ucmd_cmds_0, 0x15D37C
.equ ucmd_iface_0_cmd_table, 0x181148 + 0x78
.equ hcmd_log_flag, 0x183F14

@.org shellcode_addr

push    {lr}

@ restore cmd_table
movw    r0, #:lower16:ucmd_cmds_0
movt    r0, #:upper16:ucmd_cmds_0
movw    r1, #:lower16:ucmd_iface_0_cmd_table
movt    r1, #:upper16:ucmd_iface_0_cmd_table
str     r0, [r1]

movs    r0, #1
@ enable spew of hcmd packet data
@ this isn't really needed
movw    r1, #:lower16:hcmd_log_flag
movt    r1, #:upper16:hcmd_log_flag
str     r0, [r1]

@ set auth success
movw    r1, #:lower16:auth_status_set
movt    r1, #:upper16:auth_status_set
blx     r1

pop     {pc}
