#include <arm_acle.h>
#include <array>
#include <cstdint>
#include <cstring>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef volatile u8 vu8;
typedef volatile u16 vu16;
typedef volatile u32 vu32;
typedef volatile u64 vu64;

// UART0: EFC firmware
// UART1: Titania bootrom, EAP firmware (+APU, ...)
#define UART0_BASE 0x11010000
#define UART1_BASE 0x11010100

void* memset(void* ptr, int value, size_t num) {
  auto p = (u8*)ptr;
  while (num--) {
    *p++ = (u8)value;
  }
  return ptr;
}

static inline u32 arm_cpsr_read() {
  u32 cpsr;
  asm volatile("mrs %0, cpsr" : "=r"(cpsr));
  return cpsr;
}

static inline u32 arm_dfsr_read() {
  u32 val;
  asm volatile("mrc p15, 0, %0, c5, c0, 0" : "=r"(val));
  return val;
}

static inline u32 arm_dfar_read() {
  u32 val;
  asm volatile("mrc p15, 0, %0, c6, c0, 0" : "=r"(val));
  return val;
}

struct DAbortRecord {
  u32 addr{UINT32_MAX};
  u32 status{UINT32_MAX};
};
static DAbortRecord g_abort_status;

struct Uart {
  static constexpr u8 UART_FCR_FIFOE{1 << 0};
  static constexpr u8 UART_FCR_FIFO64{1 << 5};
  static constexpr u8 UART_LSR_RX_READY{1 << 0};
  static constexpr u8 UART_LSR_TEMT{1 << 6};

  enum class Timeout : u32 {
    Infinite = 0xffffffff,
  };

  template <typename RegType>
  struct RegLayout {
    // XXX titania specific
    RegType reg0;
    RegType reg1;
    RegType reg2;
    RegType reg3;
    RegType reg4;
    RegType reg5;
    RegType reg6;
    RegType reg7;
    RegType reg8;
  };
  using Regs = RegLayout<vu32>;

  Uart() {
    // eap_kbl normally inits/uses uart1
    // On EAP, we can use uart0 (which hasn't really been setup) as-is,
    // but the baudrate seems to be ~700000
    regs_ = (Regs*)UART0_BASE;
  }
  u32 fifo_max_len() const {
    u32 len = 1;
    // u8 fcr = regs_->fcr;
    // if (fcr & UART_FCR_FIFOE) {
    //     len = (fcr & UART_FCR_FIFO64) ? 64 : 16;
    // }
    return len;
  }
  inline bool rx_ready() const {
    // regs_->lsr & UART_LSR_RX_READY
    return (regs_->reg3 >> 4) & 1;
  }
  inline bool tx_ready() const {
    // regs_->lsr & UART_LSR_TEMT
    return (regs_->reg3 >> 5) & 1;
  }
  void wait_tx_ready() const {
    while (!tx_ready()) {
    }
  }
  bool wait_rx_ready(Timeout timeout) const {
    u32 rem = (u32)timeout;
    while (!rx_ready()) {
      if (timeout == Timeout::Infinite) {
        continue;
      }
      if (rem == 0) {
        return false;
      }
      rem--;
    }
    return true;
  }
  void write(const u8* buf, u32 len) {
    const u32 fifo_len = fifo_max_len();
    const u8* p = buf;
    while (len) {
      wait_tx_ready();
      for (u32 i = 0; i < fifo_len && len; i++, len--) {
        regs_->reg1 = *p++;
      }
    }
  }
  void write(const char* buf) { write((const u8*)buf, strlen(buf)); }
  template <typename T>
  void write(const T& data) {
    write((const u8*)&data, sizeof(T));
  }
  bool read_byte(u8* data, Timeout timeout) {
    if (!wait_rx_ready(timeout)) {
      return false;
    }
    *data = regs_->reg0;
    return true;
  }
  bool read(u8* data, u32 len, Timeout timeout = (Timeout)1000000) {
    auto p = data;
    while (p != data + len) {
      if (!read_byte(p++, timeout)) {
        return false;
      }
    }
    return true;
  }
  template <typename T>
  bool read(T* data) {
    return read((u8*)data, sizeof(T));
  }

  Regs* regs_{};
};

struct UartServer {
  bool ping() {
    u32 val;
    if (!uart_.read(&val)) {
      return false;
    }
    uart_.write(val + 1);
    return true;
  }
  template <typename T>
  bool read_into_mem(u32 addr, u32 count) {
    while (count--) {
      T val;
      if (!uart_.read(&val)) {
        return false;
      }
      *(T*)addr = val;
      addr += sizeof(T);
    }
    return true;
  }
  template <typename T>
  void write_from_mem(u32 addr, u32 count) {
    while (count--) {
      T val = *(T*)addr;
      addr += sizeof(T);
      uart_.write(val);
    }
  }
  bool mem_access() {
    struct [[gnu::packed]] {
      u32 addr;
      u32 count;
      u8 stride;
      u8 is_write;
    } req{};
    if (!uart_.read(&req)) {
      return false;
    }
    bool ok = true;
    if (req.is_write) {
      switch (req.stride) {
      case 1:
        ok = read_into_mem<u8>(req.addr, req.count);
        break;
      // case 2: ok = read_into_mem<u16>(req.addr, req.count); break;
      case 4:
        ok = read_into_mem<u32>(req.addr, req.count);
        break;
      }
    } else {
      switch (req.stride) {
      case 1:
        write_from_mem<u8>(req.addr, req.count);
        break;
      // case 2: write_from_mem<u16>(req.addr, req.count); break;
      case 4:
        write_from_mem<u32>(req.addr, req.count);
        break;
      }
    }
    return ok;
  }
  enum CpReg : u8 {
    kMIDR,
    kDBGDRAR,
    kDBGDSAR,
    kVBAR,
    kDBGPRCR,
    kSCTLR,
    kCPSR,
  };
  bool reg_read() {
    u8 reg{};
    if (!uart_.read(&reg)) {
      return false;
    }
    u32 val{};
    switch (reg) {
    case kMIDR:
      val = __arm_mrc(15, 0, 0, 0, 0);
      break;
    case kVBAR:
      val = __arm_mrc(15, 0, 12, 0, 0);
      break;
    case kDBGDRAR:
      val = __arm_mrc(14, 0, 1, 0, 0);
      break;
    case kDBGDSAR:
      val = __arm_mrc(14, 0, 2, 0, 0);
      break;
    case kDBGPRCR:
      val = __arm_mrc(14, 0, 1, 4, 4);
      break;
    case kSCTLR:
      val = __arm_mrc(15, 0, 1, 0, 0);
      break;
    case kCPSR:
      val = arm_cpsr_read();
      break;
    default:
      val = 0xcacacaca;
      break;
    }
    uart_.write(val);
    return true;
  }
  bool reg_write() {
    u8 reg{};
    if (!uart_.read(&reg)) {
      return false;
    }
    // NOTE: At least EAP requires alignment (if reading as packed struct, the
    // load of |val| into a register to perform the MCR would die)
    u32 val{};
    if (!uart_.read(&val)) {
      return false;
    }
    switch (reg) {
    case kVBAR:
      __arm_mcr(15, 0, val, 12, 0, 0);
      break;
    case kDBGPRCR:
      __arm_mcr(14, 0, val, 1, 4, 4);
      break;
    case kSCTLR:
      __arm_mcr(15, 0, val, 1, 0, 0);
      break;
    default:
      return false;
    }
    return true;
  }
  bool int_disable() {
    asm volatile("cpsid aif" : : : "memory");
    return true;
  }
  bool int_enable() {
    asm volatile("cpsie aif" : : : "memory");
    return true;
  }
  bool dabort_status() {
    uart_.write(g_abort_status);
    g_abort_status = {};
    return true;
  }
  [[noreturn]] void run() {
    while (1) {
      u32 cmd;
      if (!uart_.read(&cmd)) {
        continue;
      }
      using handler_t = bool (UartServer::*)();
      handler_t handlers[] = {
          &UartServer::ping,          &UartServer::mem_access,
          &UartServer::reg_read,      &UartServer::reg_write,
          &UartServer::int_disable,   &UartServer::int_enable,
          &UartServer::dabort_status,
      };
      if (cmd >= std::size(handlers)) {
        continue;
      }
      (this->*handlers[cmd])();
    }
  }
  Uart uart_;
};

extern "C" {
[[noreturn]] void uart_server() {
  auto server = UartServer();
  server.run();
}

[[noreturn]] static void die(const char* reason) {
  auto uart = Uart();
  uart.write(reason);
  while (true) {
  }
}
void exception_reset() {}
[[gnu::interrupt("UNDEF")]] void exception_undef() {
  die("undef");
}
[[gnu::interrupt("SWI")]] void exception_swi() {
  die("swi");
}
[[gnu::interrupt("ABORT")]] void exception_pabort() {
  die("pabort");
}
[[gnu::interrupt("ABORT")]] void exception_dabort() {
  g_abort_status = {
      .addr = arm_dfar_read(),
      .status = arm_dfsr_read(),
  };
}
[[gnu::interrupt("IRQ")]] void exception_irq() {
  die("irq");
}
[[gnu::interrupt("FIQ")]] void exception_fiq() {
  die("fiq");
}

void install_exception_handlers_efc() {
  // overwrite the constant pool in a0tcm
  using handler_t = void (*)(void);
  const handler_t handlers[]{exception_reset,  exception_undef,  exception_swi,
                             exception_pabort, exception_dabort, exception_irq,
                             exception_fiq};
  auto ptrs = (handler_t*)0x20;
  for (size_t i = 0; i < std::size(handlers); i++) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
    ptrs[i] = handlers[i];
#pragma GCC diagnostic pop
  }
}

[[noreturn]] void entry() {
  // Reach here in SVC mode(on EAP, SYS on EFC?) with SP in dram.
  // MMU and caches are disabled.
  // IRQ/FIQ are masked.
  u32 tmp0, tmp1;
  asm volatile(
#if defined(CPU_EFC)
      ".cpu cortex-r5\n"
#elif defined(CPU_EAP)
      ".cpu cortex-a7\n"
#endif
      ".syntax unified\n"
      ".arm\n"

      ".equ     MASK_AIF, (1 << 8) | (1 << 7) | (1 << 6)\n"
      ".equ     MODE_ABORT, 0b10111\n"
      ".equ     MODE_SVC, 0b10011\n"

      "setup_stacks:\n"
      // save sp
      "mov      %1, sp\n"
      // abort
      "mov      %0, MASK_AIF | MODE_ABORT\n"
      "msr      cpsr_c, %0\n"
      //"mrs      %0, sp_svc\n"
      //"add      sp, %0, 0x100\n"
      "add      sp, %1, 0x1100\n"
      // svc
      "mov      %0, MASK_AIF | MODE_SVC\n"
      "msr      cpsr_c, %0\n"
      // move svc sp a bit so we can relaunch the exploit in same location after
      // reset (for EAP)
      "add      sp, %1, 0x1000\n"

#if defined(CPU_EFC)
      "bl       install_exception_handlers_efc\n"
#elif defined(CPU_EAP)
      // set vbar
      "ldr      %0, =vbar_dram\n"
      "mcr      p15, 0, %0, c12, c0, 0\n"
#endif
      "b        uart_server\n"

#if defined(CPU_EAP)
      ".align 5\n"
      "vbar_dram:\n"
      "b        exception_reset\n"
      "b        exception_undef\n"
      "b        exception_swi\n"
      "b        exception_pabort\n"
      "b        exception_dabort\n"
      "nop\n"
      "b        exception_irq\n"
      "b        exception_fiq\n"
#endif
      : "=r"(tmp0), "=r"(tmp1));
  __builtin_unreachable();
}
}