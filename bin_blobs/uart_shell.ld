ENTRY(entry)
SECTIONS {
    .code 0x58000000 : {
        *(.text.entry)
        *(.text*)
        *(.*data*)
    }
}
