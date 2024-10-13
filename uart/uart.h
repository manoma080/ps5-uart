#pragma once

#include <hardware/gpio.h>
#include <hardware/timer.h>
#include <hardware/uart.h>

#include "types.h"

class Uart {
 public:
  ~Uart() { deinit(); }

  bool init(uint instance, uint baudrate, irq_handler_t rx_handler) {
    // Only hw uarts
    if (instance >= NUM_UARTS) {
      return false;
    }
    // uart0 could be mapped to {0,1}, {12,13}, {16,17}
    // uart1 could be mapped to {4,5}, {8,9}
    // just choose some defaults here.
    struct {
      uint tx, rx;
    } const gpios[NUM_UARTS]{
        {0, 1},
        {8, 9},
    };
    // Must be done before uart_init
    gpio_set_function(gpios[instance].tx, GPIO_FUNC_UART);
    gpio_set_function(gpios[instance].rx, GPIO_FUNC_UART);

    uart_ = uart_get_instance(instance);
    // Reset the hw and configure as 8n1 with given baudrate
    // Note: default setup of crlf translation is:
    // PICO_UART_ENABLE_CRLF_SUPPORT=1,PICO_UART_DEFAULT_CRLF=0 (compiled in but
    // disabled)
    if (!uart_init(uart_, baudrate)) {
      return false;
    }
    baudrate_ = baudrate;

    const uint irq = (instance == 0) ? UART0_IRQ : UART1_IRQ;
    irq_set_exclusive_handler(irq, rx_handler);
    irq_set_enabled(irq, true);
    uart_set_irq_enables(uart_, true, false);

    return true;
  }

  void set_baudrate(uint baudrate) {
    if (baudrate_ != baudrate) {
      uart_set_baudrate(uart_, baudrate);
      baudrate_ = baudrate;
    }
  }

  void rx_irq_enable(bool enable) const {
    uart_set_irq_enables(uart_, enable, false);
  }

  template <typename T>
  void try_read(T callback) const {
    // pico_stdio_uart toggles irq enables here(on irq path)...is it really
    // required?
    rx_irq_enable(false);
    while (uart_is_readable(uart_)) {
      callback(read_dr());
    }
    rx_irq_enable(true);
  }

  void write_blocking(const u8* data, size_t len, bool wait_tx = true) const {
    // Note this waits until data is sent to uart - not until tx fifo is drained
    uart_write_blocking(uart_, data, len);
    if (wait_tx) {
      // Wait for data to be sent on wire
      uart_tx_wait_blocking(uart_);
    }
  }

 private:
  void deinit() {
    if (uart_) {
      uart_deinit(uart_);
      uart_ = {};
    }
  }

  u8 read_dr() const {
    const auto dr = uart_get_hw(uart_)->dr;
    /*
    constexpr u32 err_bits = UART_UARTDR_FE_BITS | UART_UARTDR_PE_BITS |
                             UART_UARTDR_BE_BITS | UART_UARTDR_OE_BITS;
    const auto dr_err = dr & err_bits;
    if (dr_err) {
      printf("read_dr err %lx\n", dr_err);
    }
    //*/
    return dr & UART_UARTDR_DATA_BITS;
  }

  uart_inst_t* uart_{};
  uint baudrate_{};
};
