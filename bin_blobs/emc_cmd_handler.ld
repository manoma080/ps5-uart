ENTRY(ucmd_handler)
SECTIONS {
    ucmd_send_status = 0x12C044 | 1;
    parse_u32 = 0x14CB3A | 1;
    titania_spi_init = 0x12A424 | 1;
    # need to provide memset if using -nostdlib
    # if just using -nostartfiles, we'll get toolchain's memset
    memset = 0x150872 | 1;
    # for debug
    ucmd_printf = 0x12BF6A | 1;
    sflash_read_imm = 0x1121F2 | 1;
    msleep = 0x12F560 | 1;

    .code 0x141458 : {
        *(.text.ucmd_handler)
        *(.text*)
        *(.*data*)
    }
}
