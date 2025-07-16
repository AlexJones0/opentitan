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
 * This test is based on the `uart_baud_rate_test`, but differs in that it:
 * 1. Uses bitbanged UARTs on the host side for both sending and receiving.
 * 2. Uses a SPI OTTF console to avoid issues with bitbanging the console
 *    UART at high default baud rates.
 * 3. Uses a selection of 5 lower rates that Hyperdebug can reliably bitbang.
 * 4. Uses much longer test data, to test the bitbanging implementation.
 */

OTTF_DEFINE_TEST_CONFIG(.console.type = kOttfConsoleSpiDevice,
                        .console.base_addr = TOP_EARLGREY_SPI_DEVICE_BASE_ADDR,
                        .console.test_may_clobber = false);

// TODO: maybe use smaller test data if this ends up breaking
// TODO: if I do so, update the comment at the top of the test
static const uint8_t kSendData[] =
    "2A2AFF29DE2892AEC5938694E773D801C1F354E9A94CCDF06CBCDED749EE1AA006CB04E3F3"
    "FFC441DBC0525C7968B5960C9740A1253E128886C9B4FE5AAD064F9D602B975CD48380B8D1"
    "C1873BC83D7141993F438609709240B3B36C248CA2EB342E05DDAE72F60F8ED2C938C266B5"
    "6AC1DC38F5EEFDD15D2334924FEC8FA87013C4715E9581C51B71159CA998A9F8E689E1B8D8"
    "2189914B6F0CA8C44AD3C5B6E306B4357E138DF6D76D802D62D9DF69F3351C97160C9A02AC"
    "00D114CD6E5A04A8EB41A244793D3A43E44FDF214E98BB64BC6F3E163E5CEA7E600577DA91"
    "40B6C03F827AD525F68781A1928995D1F23EAFC0CC8C72BD9F15A65E6D9294C54E2347BEF5"
    "3F0C727F3094D79E62B5C786FB8E380F6A3ABDB5165868ABA16E259E99234935F33CE1DFC3"
    "82B25A5B85CD946A99681D2FA95A4C7C9A33003ACD3F1B425AED858279FFECA1567C290E5B"
    "6474D5DCA7AC080F61D30D0DFC79D660AD51A499479F2CF16381AA012A892D97CD7AE56A7A"
    "3D4D5590E93B9496A718B31105D97B6B10F1742059693A99B88F0D59DAC2BDF12439D9E0F6"
    "3B2AFD642D4DBC17E2740D1E2C4195AC232FAAE7889695A24939C6D4D9A783F62E3A865A1C"
    "15233E06BD550B59D63603A880FE1A8BADD485F8A46E458A21671CD129C2B7565AC66EAF44"
    "DFBAED16FB4651C7C8AB4ADDAEB38346DA34E31B843FA087DC943A2DF353F9";
static const uint32_t kBaseAddrs[4] = {
    TOP_EARLGREY_UART0_BASE_ADDR,
    TOP_EARLGREY_UART1_BASE_ADDR,
    TOP_EARLGREY_UART2_BASE_ADDR,
    TOP_EARLGREY_UART3_BASE_ADDR,
};

static const uint32_t kBauds[5] = {
    4800, 9600, 19200, 38400, 57600,
};

enum {
  kTestTimeoutMillis = 500000,
};

typedef enum test_phase {
  kTestPhaseInit,
  kTestPhaseCfg,
  kTestPhaseSend,
  kTestPhaseRecv,
  kTestPhaseDone,
} test_phase_t;

static volatile uint8_t test_phase = kTestPhaseInit;
static volatile uint8_t uart_idx = UINT8_MAX;
static volatile uint32_t baud_rate = UINT32_MAX;

static dif_uart_t uart;
static dif_pinmux_t pinmux;

// Send all bytes in `kSendData`, and check that they are received via the
// loopback mechanism.
static status_t test_uart_baud(void) {
  test_phase = kTestPhaseCfg;

  // Configure and reset the UART under test.
  TRY(dif_uart_configure(&uart,
                         (dif_uart_config_t){
                             .baudrate = (uint32_t)baud_rate,
                             .clk_freq_hz = (uint32_t)kClockFreqPeripheralHz,
                             .parity_enable = kDifToggleDisabled,
                             .parity = kDifUartParityEven,
                             .tx_enable = kDifToggleEnabled,
                             .rx_enable = kDifToggleEnabled,
                         }));
  TRY(dif_uart_fifo_reset(&uart, kDifUartDatapathAll));
  LOG_INFO("Configured UART%d with Baud rate %d", uart_idx, baud_rate);

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
  // Wait to be told the UART under test, and then configure it via Pinmux
  OTTF_WAIT_FOR(uart_idx != 0xff, kTestTimeoutMillis);

  mmio_region_t base_addr;
  base_addr = mmio_region_from_addr(TOP_EARLGREY_PINMUX_AON_BASE_ADDR);
  CHECK_DIF_OK(dif_pinmux_init(base_addr, &pinmux));
  base_addr = mmio_region_from_addr(kBaseAddrs[uart_idx]);
  CHECK_DIF_OK(dif_uart_init(base_addr, &uart));

  CHECK_STATUS_OK(
      uart_testutils_select_pinmux(&pinmux, uart_idx, kUartPinmuxChannelDut));

  // Check UART data is sent and received with the bitbanged uart at different
  // (low) baud rates.
  status_t result = OK_STATUS();
  for (size_t baud_idx = 0; baud_idx < ARRAYSIZE(kBauds); ++baud_idx) {
    baud_rate = kBauds[baud_idx];
    EXECUTE_TEST(result, test_uart_baud);
  }
  return status_ok(result);
}
