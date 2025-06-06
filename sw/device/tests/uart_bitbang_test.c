// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/lib/arch/device.h"
#include "sw/device/lib/base/mmio.h"
#include "sw/device/lib/dif/dif_base.h"
#include "sw/device/lib/dif/dif_pinmux.h"
#include "sw/device/lib/dif/dif_uart.h"
#include "sw/device/lib/runtime/hart.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_console.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"
#include "sw/device/lib/testing/test_framework/ottf_utils.h"
#include "sw/device/lib/testing/test_framework/status.h"
#include "sw/device/lib/testing/uart_testutils.h"

#include "hw/top_earlgrey/sw/autogen/top_earlgrey.h"

#define UART_DATASET_SIZE 64

static dif_pinmux_t pinmux;
static dif_uart_t uart;

/**
 * UART test data transfer direction
 *
 * Enumeration indicating the direction of transfer of test data.
 */
typedef enum uart_direction {
  kUartSend = 0,
  kUartReceive,
} uart_direction_t;

/**
 * Indicates the UART device under test.
 */
static volatile uint8_t kUartIdx = 0xff;

// There are multiple uart instances in the chip. These variables will be
// updated according to the uart we select.
static volatile uart_cfg_params_t uart_cfg;

// A set of bytes to be send out of TX.
//
// The first byte must be FF so we can differentiate this blob from ASCII sent
// by the ROM when it starts. FF is not UTF-8 / ASCII.
static volatile const uint8_t kUartTxData[UART_DATASET_SIZE] = {
    0xff, 0x50, 0xc6, 0xb4, 0xbe, 0x16, 0xed, 0x55, 0x16, 0x1d, 0xe6,
    0x1c, 0xde, 0x9f, 0xfd, 0x24, 0x89, 0x81, 0x4d, 0x0d, 0x1a, 0x12,
    0x4f, 0x57, 0xea, 0xd6, 0x6f, 0xc0, 0x7d, 0x46, 0xe7, 0x37, 0x81,
    0xd3, 0x8e, 0x16, 0xad, 0x7b, 0xd0, 0xe2, 0x4f, 0xff, 0x39, 0xe6,
    0x71, 0x3c, 0x82, 0x04, 0xec, 0x3a, 0x27, 0xcc, 0x3d, 0x58, 0x0e,
    0x56, 0xd2, 0xd2, 0xb9, 0xa3, 0xb5, 0x3d, 0xc0, 0x40,
};

// The set of bytes expected to be received over RX.
static volatile const uint8_t kExpUartRxData[UART_DATASET_SIZE] = {
    0x1b, 0x95, 0xc5, 0xb5, 0x8a, 0xa4, 0xa8, 0x9f, 0x6a, 0x7d, 0x6b,
    0x0c, 0xcd, 0xd5, 0xa6, 0x8f, 0x07, 0x3a, 0x9e, 0x82, 0xe6, 0xa2,
    0x2b, 0xe0, 0x0c, 0x30, 0xe8, 0x5a, 0x05, 0x14, 0x79, 0x8a, 0xFf,
    0x88, 0x29, 0xda, 0xc8, 0xdd, 0x82, 0xd5, 0x68, 0xa5, 0x9d, 0x5a,
    0x48, 0x02, 0x7f, 0x24, 0x32, 0xaf, 0x9d, 0xca, 0xa7, 0x06, 0x0c,
    0x96, 0x65, 0x18, 0xe4, 0x7f, 0x26, 0x44, 0xf3, 0x14,
};

enum {
  kCommandTimeout = 5000000,  // microseconds
};

/**
 * Initializes UART.
 */
static void uart_init_with_irqs(mmio_region_t base_addr, dif_uart_t *uart,
                                uint32_t uartBaudrate, uint32_t uartFreqHz) {
  LOG_INFO("Initializing the UART.");

  CHECK_DIF_OK(dif_uart_init(base_addr, uart));
  CHECK_DIF_OK(dif_uart_configure(uart, (dif_uart_config_t){
                                            .baudrate = (uint32_t)uartBaudrate,
                                            .clk_freq_hz = (uint32_t)uartFreqHz,
                                            .parity_enable = kDifToggleDisabled,
                                            .parity = kDifUartParityEven,
                                            .tx_enable = kDifToggleEnabled,
                                            .rx_enable = kDifToggleEnabled,
                                        }));
}

/**
 * Continue ongoing transmission of bytes.
 *
 * This is a wrapper around `dif_uart_bytes_send|receive()` functions. It picks
 * up an ongoing transfer of data starting at `dataset_index` location until
 * the UART can no longer accept any more data to be sent / return any more
 * data received, depending on the direction of the data transfer indicated with
 * the `uart_direction` argument. It uses the `bytes_written` / `bytes_read`
 * value to advance the `dataset_index` for the next round. It updates the
 * `transfer_done` arg to indicate if the ongoing transfer has completed.
 */
static bool uart_transfer_ongoing_bytes(const dif_uart_t *uart,
                                        uart_direction_t uart_direction,
                                        uint8_t *data, size_t dataset_size,
                                        size_t *dataset_index,
                                        size_t max_xfer_size,
                                        bool *transfer_done) {
  size_t bytes_remaining = dataset_size - *dataset_index;
  size_t bytes_to_xfer =
      max_xfer_size < bytes_remaining ? max_xfer_size : bytes_remaining;
  size_t bytes_transferred = 0;
  bool result = false;
  switch (uart_direction) {
    case kUartSend:
      result = dif_uart_bytes_send(uart, &data[*dataset_index], bytes_to_xfer,
                                   &bytes_transferred) == kDifOk;
      break;
    case kUartReceive:
      result =
          dif_uart_bytes_receive(uart, bytes_to_xfer, &data[*dataset_index],
                                 &bytes_transferred) == kDifOk;
      break;
    default:
      LOG_FATAL("Invalid UART data transfer direction!");
  }
  *dataset_index += bytes_transferred;
  *transfer_done = *dataset_index == dataset_size;
  return result;
}

static void execute_test(const dif_uart_t *uart) {
  bool uart_tx_done = false;
  size_t uart_tx_bytes_written = 0;

  bool uart_rx_done = false;
  size_t uart_rx_bytes_read = 0;

  // A set of bytes actually received over RX.
  uint8_t uart_rx_data[UART_DATASET_SIZE];

  LOG_INFO("Executing the test.");
  while (!uart_tx_done || !uart_rx_done) {
    if (!uart_tx_done) {
      // Send the remaining kUartTxData as and when the TX watermark fires.
      // Intentionally limit the transfer size to 32 bytes at a time. This means
      // we see multiple TX watermark interrupts in the test.
      CHECK(uart_transfer_ongoing_bytes(
          uart, kUartSend, (uint8_t *)kUartTxData, UART_DATASET_SIZE,
          &uart_tx_bytes_written, UART_DATASET_SIZE, &uart_tx_done));
    }

    if (!uart_rx_done) {
      do {
        CHECK(uart_transfer_ongoing_bytes(
            uart, kUartReceive, uart_rx_data, UART_DATASET_SIZE,
            &uart_rx_bytes_read, UART_DATASET_SIZE, &uart_rx_done));
      } while (!uart_rx_done && (UART_DATASET_SIZE - uart_rx_bytes_read < 16));
    }
  }

  // Check data consistency.
  LOG_INFO("Checking the received UART RX data for consistency.");
  for (int i = 0; i < UART_DATASET_SIZE; ++i) {
    CHECK(uart_rx_data[i] == kExpUartRxData[i],
          "UART RX data[%d] mismatched: {act: %x, exp: %x}", i, uart_rx_data[i],
          kExpUartRxData[i]);
  }
}

OTTF_DEFINE_TEST_CONFIG(.enable_uart_flow_control = true);

bool test_main(void) {
  mmio_region_t base_addr;

  base_addr = mmio_region_from_addr(TOP_EARLGREY_PINMUX_AON_BASE_ADDR);
  CHECK_DIF_OK(dif_pinmux_init(base_addr, &pinmux));

  OTTF_WAIT_FOR(kUartIdx != 0xff, kCommandTimeout);

  // Use the default UART baud rate and clock frequency for the target device.
  uint64_t uartBaudrate = kUartBaudrate;
  uint64_t uartFreqHz = kClockFreqPeripheralHz;
  CHECK(uartBaudrate <= UINT32_MAX, "uartBaudrate must fit in uint32_t");
  CHECK(uartFreqHz <= UINT32_MAX, "uartFreqHz must fit in uint32_t");

  // If we're testing UART0 we need to move the console to UART1.
  if (kUartIdx == 0 && kDeviceType != kDeviceSimDV) {
    CHECK_STATUS_OK(
        uart_testutils_select_pinmux(&pinmux, 1, kUartPinmuxChannelConsole));
    ottf_console_configure_uart(TOP_EARLGREY_UART1_BASE_ADDR);
  }

  CHECK_STATUS_OK(
      uart_testutils_cfg_params(kUartIdx, (uart_cfg_params_t *)&uart_cfg));

  LOG_INFO("Test UART%d with base_addr: %08x", kUartIdx, uart_cfg.base_addr);

  // Attach the UART under test.
  CHECK_STATUS_OK(
      uart_testutils_select_pinmux(&pinmux, kUartIdx, kUartPinmuxChannelDut));

  // Initialize the UART.
  mmio_region_t chosen_uart_region = mmio_region_from_addr(uart_cfg.base_addr);
  uart_init_with_irqs(chosen_uart_region, &uart, (uint32_t)uartBaudrate,
                      (uint32_t)uartFreqHz);

  // Execute the test.
  execute_test(&uart);

  return true;
}
