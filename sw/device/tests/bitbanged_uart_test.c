// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/lib/arch/device.h"
#include "sw/device/lib/base/mmio.h"
#include "sw/device/lib/dif/dif_pinmux.h"
#include "sw/device/lib/dif/dif_uart.h"
#include "sw/device/lib/runtime/hart.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_console.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"
#include "sw/device/lib/testing/test_framework/ottf_utils.h"
#include "sw/device/lib/testing/uart_testutils.h"

#include "hw/top_earlgrey/sw/autogen/top_earlgrey.h"

/**
 * Send and receive a small amount of UART data by communicating with a UART
 * that is bitbanged on the host side. Used to test UART bitbanging works for
 * a given host transport backend. The UART is configured at a lower baud rate
 * (57600 Bd) to work around issues with Hyperdebug's clock accuracy making
 * bitbanging at 115200 Bd infeasible, and likewise performs minimal
 * Device<->Host communication using a SPI console to avoid a UART console
 * (which picks up the default Baud rate, which is too high).
 */

OTTF_DEFINE_TEST_CONFIG(.console.type = kOttfConsoleSpiDevice,
                        .console.base_addr = TOP_EARLGREY_SPI_DEVICE_BASE_ADDR,
                        .console.test_may_clobber = false);

static const uint8_t kSendData[] = "UART bitbang test";

enum {
  kTestTimeoutMillis = 500000,
  kTestBaud = 57600,
  kUartIdx = 1,
};

typedef enum test_phase {
  kTestPhaseInit,
  kTestPhaseCfg,
  kTestPhaseSend,
  kTestPhaseRecv,
  kTestPhaseDone,
} test_phase_t;

static volatile uint8_t test_phase = kTestPhaseInit;

static dif_uart_t uart;
static dif_pinmux_t pinmux;

// Send all bytes in `kSendData`, and check that they are received via the
// loopback mechanism.
static status_t test_uart_baud(void) {
  test_phase = kTestPhaseCfg;

  // Configure and reset the UART under test.
  TRY(dif_uart_configure(&uart,
                         (dif_uart_config_t){
                             .baudrate = (uint32_t)kTestBaud,
                             .clk_freq_hz = (uint32_t)kClockFreqPeripheralHz,
                             .parity_enable = kDifToggleDisabled,
                             .parity = kDifUartParityEven,
                             .tx_enable = kDifToggleEnabled,
                             .rx_enable = kDifToggleEnabled,
                         }));
  TRY(dif_uart_fifo_reset(&uart, kDifUartDatapathAll));
  LOG_INFO("Configured UART%d with Baud rate %d", kUartIdx, kTestBaud);

  // When the host is ready, send the test data to the host
  OTTF_WAIT_FOR(test_phase == kTestPhaseSend, kTestTimeoutMillis);
  LOG_INFO("Sending data...");
  TRY(dif_uart_bytes_send(&uart, kSendData, sizeof(kSendData), NULL));
  LOG_INFO("Data sent");

  // When the host is ready, receive data from the host
  OTTF_WAIT_FOR(test_phase == kTestPhaseRecv, kTestTimeoutMillis);
  LOG_INFO("Receiving data...");
  uint8_t data[sizeof(kSendData)] = {0};
  for (size_t i = 0; i < sizeof(data); ++i) {
    TRY(dif_uart_byte_receive_polled(&uart, &data[i]));
  }
  TRY_CHECK_ARRAYS_EQ(data, kSendData, sizeof(kSendData));

  // Complete the test
  test_phase = kTestPhaseDone;
  return OK_STATUS();
}

bool test_main(void) {
  mmio_region_t base_addr;
  base_addr = mmio_region_from_addr(TOP_EARLGREY_PINMUX_AON_BASE_ADDR);
  CHECK_DIF_OK(dif_pinmux_init(base_addr, &pinmux));
  base_addr = mmio_region_from_addr(TOP_EARLGREY_UART1_BASE_ADDR);
  CHECK_DIF_OK(dif_uart_init(base_addr, &uart));
  CHECK_STATUS_OK(
      uart_testutils_select_pinmux(&pinmux, kUartIdx, kUartPinmuxChannelDut));

  status_t result = OK_STATUS();
  EXECUTE_TEST(result, test_uart_baud);
  return status_ok(result);
}
