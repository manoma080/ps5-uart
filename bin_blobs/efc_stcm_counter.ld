ENTRY(stcm_counter)
SECTIONS {
    SRAM_BASE = 0x01000000;
    .code SRAM_BASE : {
        *(.text.stcm_counter)
        *(.text*)
        *(.data*)
    }
}
