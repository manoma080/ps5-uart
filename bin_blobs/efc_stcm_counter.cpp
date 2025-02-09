#include <cstdint>

using u32 = uint32_t;
using vu32 = volatile u32;

#define STCM_BASE 0x00900000

#pragma GCC diagnostic ignored "-Wvolatile"

static u32 mpidr_read() {
    u32 val;
    asm volatile("mrc p15, 0, %0, c0, c0, 5" : "=r"(val));
    return val;
}

static void delay(u32 amount) {
    for (vu32 i = 0; i < amount; i++) {}
}

void stcm_counter() {
    auto counters = (vu32 *)STCM_BASE;
    auto counter = &counters[mpidr_read()];
    *counter = 0;
    while (true) {
        delay(1000);
        *counter++;
    }
}