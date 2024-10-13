ENTRY(dled_set)
SECTIONS {
    # need to provide memset if using -nostdlib
    # if just using -nostartfiles, we'll get toolchain's memset
    memset = 0x150872 | 1;
    hcmd_sys_make_head_param = 0x114DB2 | 1;
    
    .dled_set 0x121988 : {
        *(.text.dled_set)
        *(.text*)
        *(.*data*)
    }
}
