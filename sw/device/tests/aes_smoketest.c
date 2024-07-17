// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "hw/ip/aes/model/aes_modes.h"
#include "sw/device/lib/base/memory.h"
#include "sw/device/lib/base/mmio.h"
#include "sw/device/lib/dif/dif_aes.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/aes_testutils.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"

#include "hw/top_earlgrey/sw/autogen/top_earlgrey.h"

#define TIMEOUT (1000 * 1000)

OTTF_DEFINE_TEST_CONFIG();

status_t execute_test(dif_aes_t *aes) {
  // Setup ECB encryption transaction.
  dif_aes_transaction_t transaction = {
      .operation = kDifAesOperationEncrypt,
      .mode = kDifAesModeEcb,
      .key_len = kDifAesKey256,
      .key_provider = kDifAesKeySoftwareProvided,
      .mask_reseeding = kDifAesReseedPerBlock,
      .manual_operation = kDifAesManualOperationAuto,
      .reseed_on_key_change = false,
      .ctrl_aux_lock = false,
  };

  CHECK_STATUS_OK(aes_testutils_setup_encryption(transaction, aes));

  AES_TESTUTILS_WAIT_FOR_STATUS(aes, kDifAesStatusOutputValid, true, TIMEOUT);

  return aes_testutils_decrypt_ciphertext(transaction, aes);
}

bool test_main(void) {
  dif_aes_t aes;
  LOG_INFO("%%"); // % Symbol
  LOG_INFO("%c", (int) '0'); // Character
  LOG_INFO("%s", "test_string_1"); // String
  LOG_INFO("%!s", 7, "test_string_2"); // String with length
  LOG_INFO("%d %d %d", -3, -3l, -3ll); // Signed int
  LOG_INFO("%i %i %i", -4, -4l, -4ll); // Signed int
  LOG_INFO("%o", 05); // (unsigned) octal
  LOG_INFO("%x", 0x6); // Lower hexadecimal
  uint32_t val = 0x7;
  LOG_INFO("%!x", 4, &val); // Lower hexadecimal with length
  LOG_INFO("%X", 0x8); // Upper hexadecimal
  val = 0x9;
  LOG_INFO("%!X", 4, &val); // Upper hexadecimal with length
  LOG_INFO("%u", 10); // Unsigned int
  LOG_INFO("%p", 11); // Pointer
  LOG_INFO("%b", 12); // Binary
  LOG_INFO("%!b", 13); // Boolean
  LOG_INFO("%h", 0xe); // Lower hexadecimal, but SystemVerilog?
  LOG_INFO("%H", 0xF); // Upper hexadecimal, but SystemVerilog?
  val = 0x0100;
  LOG_INFO("%!y", 4, &val); // Little endian hex string with length
  val = 0x1100;
  LOG_INFO("%!Y", 4, &val); // Upper little endian hex string with length
  LOG_INFO("%r", DEADLINE_EXCEEDED()); // status_t
  LOG_INFO("%!r", DEADLINE_EXCEEDED()); // status_t, as json
  LOG_INFO("%C", 20); // kFourCC
  //LOG_INFO("percent_r_status: %r %!r %i %b", DEADLINE_EXCEEDED(), DEADLINE_EXCEEDED(), (int) -29, (int) 29);
  // Initialise AES.
  CHECK_DIF_OK(
      dif_aes_init(mmio_region_from_addr(TOP_EARLGREY_AES_BASE_ADDR), &aes));
  CHECK_DIF_OK(dif_aes_reset(&aes));

  return status_ok(execute_test(&aes));
}
