// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/lib/base/macros.h"
#include "sw/device/lib/base/mmio.h"
#include "sw/device/lib/crypto/drivers/entropy.h"
#include "sw/device/lib/dif/dif_kmac.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/entropy_testutils.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"

#include "hw/top_earlgrey/sw/autogen/top_earlgrey.h"
#include "kmac_regs.h"  // Generated.

/**
 * Test the manual KMAC PRNG reseeding guidance is working as expected.
 */

static dif_kmac_t kmac;

#define DIGEST_LEN_CSHAKE_MAX 4

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

static uint32_t get_entropy_refresh_hash_threshold(const dif_kmac_t *kmac) {
  uint32_t reg = mmio_region_read32(
      kmac->base_addr, KMAC_ENTROPY_REFRESH_THRESHOLD_SHADOWED_REG_OFFSET);
  return bitfield_field32_read(
      reg, KMAC_ENTROPY_REFRESH_THRESHOLD_SHADOWED_THRESHOLD_FIELD);
}

static void kmac_trigger_manual_reseed(const dif_kmac_t *kmac) {
  uint32_t cmd_reg = bitfield_bit32_write(0, KMAC_CMD_ENTROPY_REQ_BIT, true);
  mmio_region_write32(kmac->base_addr, KMAC_CMD_REG_OFFSET, cmd_reg);
}

status_t do_kmac_operation(const dif_kmac_t *kmac, uint32_t *hash_ctr) {
  // Assumes that the KMAC is already appropriately configured.
  dif_kmac_operation_state_t kmac_operation_state;
  TRY(dif_kmac_mode_kmac_start(kmac, &kmac_operation_state,
                               kKmacTestVector.mode, 0, &kKmacTestVector.key,
                               NULL));
  TRY(dif_kmac_absorb(kmac, &kmac_operation_state, kKmacTestVector.message,
                      kKmacTestVector.message_len, NULL));
  uint32_t digest[kKmacTestVector.digest_len];
  TRY(dif_kmac_squeeze(kmac, &kmac_operation_state, digest,
                       kKmacTestVector.digest_len,
                       /*processed=*/NULL, /*capacity=*/NULL));
  TRY(dif_kmac_end(kmac, &kmac_operation_state));

  // Check the KMAC is idle
  CHECK(is_kmac_state_idle(kmac),
        "Expected KMAC to be idle after finishing operation");

  // Retrieve the new hash count
  CHECK_DIF_OK(dif_kmac_get_hash_counter(kmac, hash_ctr));

  return OK_STATUS();
}

status_t test_kmac_manual_prng_reseed(void) {
  LOG_INFO("Testing kmac_mode_change test");

  // Initialise the Entropy Complex
  TRY(entropy_complex_init());

  // Initialise the KMAC block.
  TRY(dif_kmac_init(mmio_region_from_addr(TOP_EARLGREY_KMAC_BASE_ADDR), &kmac));

  // Configure the KMAC in EDN entropy mode with a sufficiently large timeout.
  // Set it with a hash threshold of 32 hashes.
  dif_kmac_config_t config = (dif_kmac_config_t){
      .entropy_mode = kDifKmacEntropyModeEdn,
      .entropy_wait_timer = 0xfff,
      .entropy_prescaler = 0x3ff,
      .entropy_fast_process = kDifToggleDisabled,
      .entropy_hash_threshold = 32,
      .message_big_endian = kDifToggleDisabled,
      .output_big_endian = kDifToggleDisabled,
      .sideload = kDifToggleDisabled,
      .msg_mask = kDifToggleEnabled,
  };
  TRY(dif_kmac_configure(&kmac, config));

  // Check that the entropy hash threshold was appropriately written.
  uint32_t threshold = get_entropy_refresh_hash_threshold(&kmac);
  CHECK(threshold == config.entropy_hash_threshold,
        "Entropy hash threshold not configured as expected");

  // Check that we start with an initial hash count of 0
  uint32_t hash_cnt = 0xffffffff;
  CHECK_DIF_OK(dif_kmac_get_hash_counter(&kmac, &hash_cnt));
  CHECK(hash_cnt == 0, "Expected to start with a hash count of 0");

  // Do 31 KMAC operations, checking that the hash counter increments.
  for (int i = 1; i < config.entropy_hash_threshold; ++i) {
    TRY(do_kmac_operation(&kmac, &hash_cnt));
    CHECK(hash_cnt == i, "Hash count did not increment as expected");
  }
  // Check that on the final KMAC operation that the threshold is met
  // and so entropy is reseeded, meaning the counter resets.
  TRY(do_kmac_operation(&kmac, &hash_cnt));
  CHECK(hash_cnt == 0,
        "Hash count did not reset on entropy reseed as expected");

  // Do 30 KMAC operations so that the next message sent will not reseed,
  // but the message after that will.
  for (int i = 1; i < (config.entropy_hash_threshold - 1); ++i) {
    TRY(do_kmac_operation(&kmac, &hash_cnt));
    CHECK(hash_cnt == i, "Hash count did not increment as expected");
  }
  
  // Now follow manual reseeding guidance
  // 1. Check the entropy complex is running
  CHECK_STATUS_OK(entropy_complex_check(),
                  "Entropy complex is not running as expected");
  // 2. Check the KMAC is idle
  CHECK(is_kmac_state_idle(&kmac),
        "Expected KMAC to be idle after finishing operation");
  // 3. Trigger a manual reseed operation.
  // We expect the hash counter to reset to 0, rather than increment to 31.
  kmac_trigger_manual_reseed(&kmac);
  CHECK_DIF_OK(dif_kmac_get_hash_counter(&kmac, &hash_cnt));
  CHECK(hash_cnt == 0, "Hash count should have reset");
  // 4. Configure KMAC to process a message in cSHAKE mode without enabling KMAC
  // mode
  // 5. Set entropy_fast_process to 0 to block any hashing.
  uint32_t cfg_reg =
      mmio_region_read32(kmac.base_addr, KMAC_CFG_SHADOWED_REG_OFFSET);
  cfg_reg = bitfield_field32_write(cfg_reg, KMAC_CFG_SHADOWED_MODE_FIELD,
                                   KMAC_CFG_SHADOWED_MODE_VALUE_CSHAKE);
  cfg_reg = bitfield_bit32_write(cfg_reg, KMAC_CFG_SHADOWED_KMAC_EN_BIT, false);
  cfg_reg =
      bitfield_bit32_write(cfg_reg, KMAC_CFG_SHADOWED_MSG_MASK_BIT, false);
  cfg_reg = bitfield_bit32_write(
      cfg_reg, KMAC_CFG_SHADOWED_ENTROPY_FAST_PROCESS_BIT, false);
  mmio_region_write32_shadowed(kmac.base_addr, KMAC_CFG_SHADOWED_REG_OFFSET, cfg_reg);
  // 6. Send the `start` command to the CMD register.
  uint32_t cmd_reg =
      bitfield_field32_write(0, KMAC_CMD_CMD_FIELD, KMAC_CMD_CMD_VALUE_START);
  mmio_region_write32(kmac.base_addr, KMAC_CMD_REG_OFFSET, cmd_reg);
  CHECK_DIF_OK(dif_kmac_poll_status(&kmac, KMAC_STATUS_SHA3_ABSORB_BIT));
  // 7. Send the `process` command to the CMD register
  cmd_reg =
      bitfield_field32_write(0, KMAC_CMD_CMD_FIELD, KMAC_CMD_CMD_VALUE_PROCESS);
  mmio_region_write32(kmac.base_addr, KMAC_CMD_REG_OFFSET, cmd_reg);
  // 8. Wait for STATUS.sha3_squeeze to get set.
  TRY(dif_kmac_poll_status(&kmac, KMAC_STATUS_SHA3_SQUEEZE_BIT));
  // 9. Send the `done` command to the CMD register to finish processing.
  cmd_reg =
      bitfield_field32_write(0, KMAC_CMD_CMD_FIELD, KMAC_CMD_CMD_VALUE_DONE);
  mmio_region_write32(kmac.base_addr, KMAC_CMD_REG_OFFSET, cmd_reg);
  // Check the KMAC is now idle
  CHECK(is_kmac_state_idle(&kmac),
        "Expected KMAC to be idle after finishing operation");

  // Retrieve the new hash count
  CHECK_DIF_OK(dif_kmac_get_hash_counter(&kmac, &hash_cnt));
  CHECK(hash_cnt == 0, "Entropy hash threshold not reset to 0 as expected");

  return OK_STATUS();
}

bool test_main(void) {
  static status_t result;

  EXECUTE_TEST(result, test_kmac_manual_prng_reseed);

  return status_ok(result);
}
