#pragma once

#include <cstdio>

#include <hardware/gpio.h>
#include <hardware/i2c.h>

#include "string_utils.h"
#include "types.h"

// This wound up not being useful, as while writing 0 to rt5126 reg 0x2c does
// turn off the rail for salina, there's no way to turn it back on - rt5126
// seems to be on same rail or something (haven't looked into it).

/*
i2c addr: 64 (rt5069/rt5126 salina pmic)
this matches init table in emc fw
82 24 24 66 66 68 21 64 03 00 00 00 a0 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 12 7f 7f b3 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
02 00 17 06 60 16 16 01 08 6b 02 13 09 1b 06 15
0a 19 04 1a 0a 0b 29 4c 50 42 b5 35 21 64 01 05
0b 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
i2c addr: 51 (rt5127 titania pmic)
82 8a ff 55 55 06 15 44 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 d5 70 00 10 56 19 00 08 b1 00 00 00 20
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 fa 01 1c 01 02 46 41 06 bd cd 37 08 1a 0c 1e
0b 1f 00 01 00 00 00 00 00 00 00 00 00 00 00 01
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
*/

struct I2cBus {
  I2cBus() {
    // i2c0 can be on gpio 4,5 (pico_w pins 6,7)
    constexpr uint sda_gpio = 4;
    constexpr uint scl_gpio = 5;
    gpio_set_function(sda_gpio, GPIO_FUNC_I2C);
    gpio_set_function(scl_gpio, GPIO_FUNC_I2C);
    gpio_pull_up(sda_gpio);
    gpio_pull_up(scl_gpio);

    inst_ = i2c_get_instance(0);
    i2c_init(inst_, 400'000);
  }
  bool convert_err(int err, size_t expected) const {
    if (static_cast<size_t>(err) == expected) {
      return true;
    }
    if (err == PICO_ERROR_GENERIC) {
      puts("addr nak");
    } else if (err == PICO_ERROR_TIMEOUT) {
      puts("timeout");
    }
    return false;
  }
  bool write(u8 addr, const u8* buf, size_t len, bool nostop = false) const {
    const auto rv = i2c_write_timeout_per_char_us(inst_, addr, buf, len, nostop,
                                                  timeout_per_char_us_);
    return convert_err(rv, len);
  }
  bool read(u8 addr, u8* buf, size_t len, bool nostop = false) const {
    const auto rv = i2c_read_timeout_per_char_us(inst_, addr, buf, len, nostop,
                                                 timeout_per_char_us_);
    return convert_err(rv, len);
  }
  template <typename RegType, typename ValType>
  bool reg_read(u8 addr, RegType reg, ValType* val) const {
    if (!write(addr, reinterpret_cast<const u8*>(&reg), sizeof(reg), true)) {
      return false;
    }
    return read(addr, val, sizeof(*val));
  }
  template <typename RegType, typename ValType>
  bool reg_write(u8 addr, RegType reg, ValType val) const {
    u8 buf[sizeof(reg) + sizeof(val)];
    std::memcpy(&buf[0], &reg, sizeof(reg));
    std::memcpy(&buf[sizeof(reg)], &val, sizeof(val));
    return write(addr, buf, sizeof(buf));
  }
  void dump_regs8(u8 addr) {
    u8 regs[0x100]{};
    for (size_t i = 0; i < 0x100; i++) {
      if (!reg_read<u8>(addr, i, &regs[i])) {
        printf("failed to read8 i2c %02x:%02x", addr, i);
      }
    }
    printf("i2c addr: %02x\n", addr);
    hexdump(regs, sizeof(regs));
  }
  static constexpr uint timeout_per_char_us_{200};
  i2c_inst_t* inst_{};
};
