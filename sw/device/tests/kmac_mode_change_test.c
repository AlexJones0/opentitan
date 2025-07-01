// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/lib/base/macros.h"
#include "sw/device/lib/base/mmio.h"
#include "sw/device/lib/dif/dif_kmac.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/entropy_testutils.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"

#include "hw/top_earlgrey/sw/autogen/top_earlgrey.h"
#include "kmac_regs.h"  // Generated.

/**
 * This test attempts to exercise a feature where, with the KMAC configured
 * in EDN entropy mode, we can switch to SW-backed entropy if the entropy
 * timeout occurs. We check to ensure that the mode the KMAC is using is
 * actually the latched internal mode that we expect, and not necessarily
 * the configured values.
 */

static dif_kmac_t kmac;

OTTF_DEFINE_TEST_CONFIG();

enum {
  // Maxiumum digest size in bytes
  kKmacDigestLenMax = 100,
};

/**
 * KMAC test description.
 */
typedef struct kmac_test {
  dif_kmac_mode_kmac_t mode;
  dif_kmac_key_t key;

  const char *message;
  size_t message_len;

  const char *customization_string;
  size_t customization_string_len;

  const uint32_t digest[kKmacDigestLenMax];
  size_t digest_len;
  bool digest_len_is_fixed;
} kmac_test_t;

/**
 * A single KMAC example:
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf
 */
const kmac_test_t kKmacTestVector = {
    .mode = kDifKmacModeKmacLen256,
    .key =
        (dif_kmac_key_t){
            .share0 = {0x43424140, 0x47464544, 0x4b4a4948, 0x4f4e4f4c,
                       0x53525150, 0x57565554, 0x5b5a5958, 0x5f5e5d5c},
            .share1 = {0},
            .length = kDifKmacKeyLen256,
        },
    .message =
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
        "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
        "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
        "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
        "\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
        "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"
        "\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
        "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
        "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
        "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
        "\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
        "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7",
    .message_len = 200,
    .customization_string = "My Tagged Application",
    .customization_string_len = 21,
    .digest = {0x1c73bed5, 0x73d74e95, 0x59bb4628, 0xe3a8e3db, 0x7ae7830f,
               0x5944ff4b, 0xb4c2f1f2, 0xceb8ebec, 0xc601ba67, 0x57b88a2e,
               0x9b492d8d, 0x6727bbd1, 0x90117868, 0x6a300a02, 0x1d28de97,
               0x5d3030cc},
    .digest_len = 16,
    .digest_len_is_fixed = false,
};

static bool is_kmac_state_idle(const dif_kmac_t *kmac) {
  uint32_t reg = mmio_region_read32(kmac->base_addr, KMAC_STATUS_REG_OFFSET);
  return bitfield_bit32_read(reg, KMAC_STATUS_SHA3_IDLE_BIT);
}

status_t test_kmac_mode_change(void) {
  LOG_INFO("Testing kmac_mode_change test");

  // Initialise the KMAC block.
  TRY(dif_kmac_init(mmio_region_from_addr(TOP_EARLGREY_KMAC_BASE_ADDR), &kmac));

  // Configure the KMAC in EDN entropy mode with a sufficiently large timeout.
  dif_kmac_config_t config = (dif_kmac_config_t){
      .entropy_mode = kDifKmacEntropyModeEdn,
      .entropy_wait_timer = 0xfff,
      .entropy_prescaler = 0x3ff,
      .entropy_fast_process = kDifToggleDisabled,
      .message_big_endian = kDifToggleDisabled,
      .output_big_endian = kDifToggleDisabled,
      .sideload = kDifToggleDisabled,
      .msg_mask = kDifToggleEnabled,
  };
  TRY(dif_kmac_configure(&kmac, config));

  // Perform a regular KMAC operation using EDN entropy.
  // This should complete normally.
  dif_kmac_operation_state_t kmac_operation_state;
  TRY(dif_kmac_mode_kmac_start(&kmac, &kmac_operation_state,
                               kKmacTestVector.mode, 0, &kKmacTestVector.key,
                               NULL));
  TRY(dif_kmac_absorb(&kmac, &kmac_operation_state, kKmacTestVector.message,
                      kKmacTestVector.message_len, NULL));
  uint32_t digest[kKmacTestVector.digest_len];
  TRY(dif_kmac_squeeze(&kmac, &kmac_operation_state, digest,
                       kKmacTestVector.digest_len,
                       /*processed=*/NULL, /*capacity=*/NULL));
  TRY(dif_kmac_end(&kmac, &kmac_operation_state));

  // Check the KMAC is idle
  CHECK(is_kmac_state_idle(&kmac));

  // Next, we configure the KMAC to remain in EDN entropy mode, but set it to a
  // very small timeout.
  config = (dif_kmac_config_t){
      .entropy_mode = kDifKmacEntropyModeEdn,
      .entropy_wait_timer = 0x001,
      .entropy_prescaler = 0x000,
      .entropy_fast_process = kDifToggleDisabled,
      .message_big_endian = kDifToggleDisabled,
      .output_big_endian = kDifToggleDisabled,
      .sideload = kDifToggleDisabled,
      .msg_mask = kDifToggleEnabled,
  };
  TRY(dif_kmac_configure(&kmac, config));

  // We issue a manual reseed request to ensure entropy reseeds and a timeout
  // will occur.
  uint32_t cmd_reg = bitfield_bit32_write(0, KMAC_CMD_ENTROPY_REQ_BIT, 1);
  mmio_region_write32(kmac.base_addr, KMAC_CMD_REG_OFFSET, cmd_reg);

  // Start a new KMAC operation, which should fail due to an entropy timeout.
  dif_kmac_operation_state_t kmac_operation_2_state;
  TRY(dif_kmac_mode_kmac_start(&kmac, &kmac_operation_2_state,
                               kKmacTestVector.mode, 0, &kKmacTestVector.key,
                               NULL));
  TRY(dif_kmac_absorb(&kmac, &kmac_operation_2_state, kKmacTestVector.message,
                      kKmacTestVector.message_len, NULL));

  // We manually handle the DIF result as we expect the squeeze step to fail.
  dif_result_t res = dif_kmac_squeeze(&kmac, &kmac_operation_2_state, digest,
                                      kKmacTestVector.digest_len,
                                      /*processed=*/NULL, /*capacity=*/NULL);
  TRY_CHECK(res == kDifOk || res == kDifError);

  // Check that there is an error because of the timeout
  bool irq_err_pending;
  TRY(dif_kmac_irq_is_pending(&kmac, kDifKmacIrqKmacErr, &irq_err_pending));
  if (irq_err_pending) {
    dif_kmac_error_t err_status;
    uint32_t err_info;
    TRY(dif_kmac_get_error(&kmac, &err_status, &err_info));
    TRY_CHECK(err_status == kDifErrorEntropyWaitTimerExpired,
              "Error other than EDN timeout occurred.");
    LOG_INFO("EDN timed out.");
  } else {
    LOG_INFO("EDN seed received before timeout.");
  }

  // Flush out the result and check correctness
  TRY(dif_kmac_end(&kmac, &kmac_operation_2_state));

  // If err interrupt is generated, we need clean-up
  if (irq_err_pending) {
    // Clean INTR_STATE
    TRY(dif_kmac_irq_acknowledge_all(&kmac));

    // Reset FSM by setting `err_processed` bit
    // This does not modify any other KMAC state.
    TRY(dif_kmac_reset(&kmac, &kmac_operation_2_state));

    // At this point, we expect that there are no remaining interrupts.
    dif_kmac_irq_state_snapshot_t intr_snapshot;
    TRY(dif_kmac_irq_get_state(&kmac, &intr_snapshot));
    TRY_CHECK(intr_snapshot == 0,
              "INTR_STATE is non-zero after timeout clean-up.");

    bool is_kmac_locked;
    TRY(dif_kmac_config_is_locked(&kmac, &is_kmac_locked));
    TRY_CHECK(!is_kmac_locked, "KMAC still locked after timeout clean-up.");
  }

  // Check the KMAC is idle
  CHECK(is_kmac_state_idle(&kmac));

  // Now that we've reset the KMAC Entropy module back to its `StRandReset`
  // state, we can configure the KMAC to use SW-seeded entropy.
  config = (dif_kmac_config_t){
      .entropy_mode = kDifKmacEntropyModeSoftware,
      .entropy_fast_process = kDifToggleDisabled,
      .entropy_seed = {0xaa25b4bf, 0x48ce8fff, 0x5a78282a, 0x48465647,
                       0x70410fef},
      .message_big_endian = kDifToggleDisabled,
      .output_big_endian = kDifToggleDisabled,
      .sideload = kDifToggleDisabled,
      .msg_mask = kDifToggleEnabled,
  };
  TRY(dif_kmac_configure(&kmac, config));

  // Perform a regular KMAC operation using SW-seeded entropy.
  dif_kmac_operation_state_t kmac_operation_3_state;
  TRY(dif_kmac_mode_kmac_start(&kmac, &kmac_operation_3_state,
                               kKmacTestVector.mode, 0, &kKmacTestVector.key,
                               NULL));
  TRY(dif_kmac_absorb(&kmac, &kmac_operation_3_state, kKmacTestVector.message,
                      kKmacTestVector.message_len, NULL));
  TRY(dif_kmac_squeeze(&kmac, &kmac_operation_3_state, digest,
                       kKmacTestVector.digest_len,
                       /*processed=*/NULL, /*capacity=*/NULL));
  TRY(dif_kmac_end(&kmac, &kmac_operation_3_state));

  // Check the KMAC is idle
  CHECK(is_kmac_state_idle(&kmac));

  // To verify we are actually running with SW-seeded entropy, try configuring
  // the KMAC to use EDN-entropy mode with a small timeout again.
  config = (dif_kmac_config_t){
      .entropy_mode = kDifKmacEntropyModeEdn,
      .entropy_wait_timer = 0x001,
      .entropy_prescaler = 0x000,
      .entropy_fast_process = kDifToggleDisabled,
      .message_big_endian = kDifToggleDisabled,
      .output_big_endian = kDifToggleDisabled,
      .sideload = kDifToggleDisabled,
      .msg_mask = kDifToggleEnabled,
  };
  TRY(dif_kmac_configure(&kmac, config));

  // Unlike the last time we used this configuration, we expect there to be
  // no error, because the new mode that is written should not be latched,
  // and SW-seeded entropy should be being used by the KMAC HW under the
  // hood. Hence, this performs a KMAC operation using SW-seeded entropy.
  dif_kmac_operation_state_t kmac_operation_4_state;
  TRY(dif_kmac_mode_kmac_start(&kmac, &kmac_operation_4_state,
                               kKmacTestVector.mode, 0, &kKmacTestVector.key,
                               NULL));
  TRY(dif_kmac_absorb(&kmac, &kmac_operation_4_state, kKmacTestVector.message,
                      kKmacTestVector.message_len, NULL));
  TRY(dif_kmac_squeeze(&kmac, &kmac_operation_4_state, digest,
                       kKmacTestVector.digest_len,
                       /*processed=*/NULL, /*capacity=*/NULL));
  TRY(dif_kmac_end(&kmac, &kmac_operation_4_state));

  // Check that there is not an error error because of the timeout
  irq_err_pending = false;
  TRY(dif_kmac_irq_is_pending(&kmac, kDifKmacIrqKmacErr, &irq_err_pending));
  if (irq_err_pending) {
    dif_kmac_error_t err_status;
    uint32_t err_info;
    TRY(dif_kmac_get_error(&kmac, &err_status, &err_info));
    TRY_CHECK(err_status == kDifErrorEntropyWaitTimerExpired,
              "Error other than EDN timeout occurred.");
    TRY_CHECK(err_status != kDifErrorEntropyWaitTimerExpired, "EDN timed out.");
  } else {
    LOG_INFO("EDN seed received before timeout.");
  }

  return OK_STATUS();
}

bool test_main(void) {
  static status_t result;

  EXECUTE_TEST(result, test_kmac_mode_change);

  return status_ok(result);
}
