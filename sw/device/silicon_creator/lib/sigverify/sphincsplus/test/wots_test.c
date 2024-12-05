// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/silicon_creator/lib/drivers/hmac.h"
#include "hmac_regs.h"  // Generated.
#include "hw/top_earlgrey/sw/autogen/top_earlgrey.h"
#include "sw/device/lib/base/abs_mmio.h"
//#include "sw/device/lib/base/bitfield.h"
//#include "sw/device/lib/base/macros.h"
//#include "sw/device/lib/base/memory.h"

#include <stdint.h>

#include "sw/device/lib/runtime/ibex.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"
#include "sw/device/silicon_creator/lib/sigverify/sphincsplus/hash.h"
#include "sw/device/silicon_creator/lib/sigverify/sphincsplus/params.h"
#include "sw/device/silicon_creator/lib/sigverify/sphincsplus/thash.h"

enum {
  /**
   * Number of bytes in the SHA256 block size (512 bits).
   */
  kSpxSha2BlockNumBytes = 512 / 8,
  /**
   * Number of words in the SHA256 block size.
   */
  kSpxSha2BlockNumWords = kSpxSha2BlockNumBytes / sizeof(uint32_t),
  /**
   * Total number of bytes in the SHA256 address representation.
   */
  kSpxSha256AddrBytes = 22,
};


/**
 * Wait for the `hmac_done` interrupt and then clear it.
 *
 * Should only be called after a `process` or `stop` command.
 */
static void wait_for_done(void) {
  uint32_t reg = 0;
  do {
    reg = abs_mmio_read32(TOP_EARLGREY_HMAC_BASE_ADDR +
                          HMAC_INTR_STATE_REG_OFFSET);
  } while (!bitfield_bit32_read(reg, HMAC_INTR_STATE_HMAC_DONE_BIT));
  abs_mmio_write32(TOP_EARLGREY_HMAC_BASE_ADDR + HMAC_INTR_STATE_REG_OFFSET,
                   reg);
}


void my_hmac_sha256_final_truncated(uint32_t *digest, size_t len) {
  wait_for_done();

  uint32_t result, incr;
  uint32_t reg =
      abs_mmio_read32(TOP_EARLGREY_HMAC_BASE_ADDR + HMAC_CFG_REG_OFFSET);
  if (bitfield_bit32_read(reg, HMAC_CFG_DIGEST_SWAP_BIT)) {
    // Big-endian output.
    result = HMAC_DIGEST_0_REG_OFFSET;
    incr = sizeof(uint32_t);
  } else {
    // Little-endian output.
    // Note: we rely on 32-bit integer wraparound to cause the result register
    // index to count down from 7 to 0.
    result = HMAC_DIGEST_7_REG_OFFSET;
    incr = (uint32_t) - sizeof(uint32_t);
  }

  // Ensure len is at most the digest length; this function should never be
  // called with a `len` that is too big, but this helps ensure it at runtime
  // just in case.
  len = len <= kHmacDigestNumWords ? len : kHmacDigestNumWords;
  for (uint32_t i = 0; i < len; ++i, result += incr) {
    digest[i] = abs_mmio_read32(TOP_EARLGREY_HMAC_BASE_ADDR + result);
  }
}

// Throughout this file, we need to assume that integers in base-w will fit
// into a single byte.
static_assert(sizeof(uint8_t) <= kSpxWotsLogW,
              "Base-w integers must fit in a `uint8_t`.");
/**
 * Computes the chaining function.
 *
 * Interprets `in` as the value of the chain at index `start`. `addr` must
 * contain the address of the chain.
 *
 * The chain `hash` value that is incremented at each step is stored in a
 * single byte, so the caller must ensure that `start + steps <= UINT8_MAX`.
 *
 * @param in Input buffer (`kSpxN` bytes).
 * @param start Start index.
 * @param steps Number of steps.
 * @param addr Hypertree address.
 * @param[out] Output buffer (`kSpxNWords` words).
 */
static void gen_chain(const uint32_t *in, uint8_t start, const spx_ctx_t *ctx,
                      spx_addr_t *addr, uint32_t *out) {
  // Initialize out with the value at position `start`.
  memcpy(out, in, kSpxN);
  // Iterate `kSpxWotsW - 1` calls to the hash function. This loop is
  // performance-critical.
  spx_addr_hash_set(addr, start);
  for (uint8_t i = start; i + 1 < kSpxWotsW; i++) {
    // This loop body is essentially just `thash`, inlined for performance.
    hmac_sha256_restore(&ctx->state_seeded);
    hmac_sha256_update((unsigned char *)addr->addr, kSpxSha256AddrBytes);
    hmac_sha256_update_words(out, kSpxNWords);
    hmac_sha256_process();
    // Update the address while HMAC is processing for performance reasons.
    spx_addr_hash_set(addr, i + 1);
    my_hmac_sha256_final_truncated(out, kSpxNWords);
    LOG_INFO("Digest at [%d]: 0x%02x0x%02x0x%02x0x%02x", (uint32_t)i, out[0], out[1], out[2], out[3]);
  }
  LOG_INFO("Finished `gen_chain`.");
}

/**
 * Interprets an array of bytes as integers in base w.
 *
 * The NIST submission describes this operation in detail (section 2.5):
 *   https://sphincs.org/data/sphincs+-r3.1-specification.pdf
 *
 * The caller is responsible for ensuring that `input` has at least
 * `kSpxWotsLogW * out_len` bits available.
 *
 * This implementation assumes log2(w) is a divisor of 8 (1, 2, 4, or 8).
 *
 * @param input Input buffer.
 * @param out_len Length of output buffer.
 * @param[out] output Resulting array of integers.
 */
static_assert(8 % kSpxWotsLogW == 0, "log2(w) must be a divisor of 8.");
static void base_w(const uint8_t *input, const size_t out_len,
                   uint8_t *output) {
  size_t bits = 0;
  size_t in_idx = 0;
  uint8_t total;
  for (size_t out_idx = 0; out_idx < out_len; out_idx++) {
    if (bits == 0) {
      total = input[in_idx];
      in_idx++;
      bits += 8;
    }
    bits -= kSpxWotsLogW;
    output[out_idx] = (total >> bits) & (kSpxWotsW - 1);
  }
}

/**
 * Computes the WOTS+ checksum over a message (in base-w).
 *
 * The length of the checksum is `kSpxWotsLen2` integers in base-w; the caller
 * must ensure that `csum_base_w` has at least this length.
 *
 * This implementation uses a 32-bit integer to store the checksum, which
 * assumes that the maximum checksum value (len1 * (w - 1)) fits in that range.
 *
 * See section 3.1 of the NIST submission for explanation about the WOTS
 * parameters here (e.g. `kSpxWotsLen2`):
 *   https://sphincs.org/data/sphincs+-r3.1-specification.pdf
 *
 * @param msg_base_w Message in base-w.
 * @param[out] csum_base_w Resulting checksum in base-w.
 */
static_assert(kSpxWotsLen1 * (kSpxWotsW - 1) <= UINT32_MAX,
              "WOTS checksum may not fit in a 32-bit integer.");
static void wots_checksum(const uint8_t *msg_base_w, uint8_t *csum_base_w) {
  // Compute checksum.
  uint32_t csum = 0;
  for (size_t i = 0; i < kSpxWotsLen1; i++) {
    csum += kSpxWotsW - 1 - msg_base_w[i];
  }

  // Make sure any expected empty zero bits are the least significant bits by
  // shifting csum left.
  size_t csum_nbits = kSpxWotsLen2 * kSpxWotsLogW;
  csum <<= ((32 - (csum_nbits % 32)) % 32);

  // Convert checksum to big-endian bytes and then to base-w.
  csum = __builtin_bswap32(csum);
  base_w((unsigned char *)&csum, kSpxWotsLen2, csum_base_w);
}

/**
 * Derive the matching chain lengths from a message.
 *
 * The `lengths` buffer should be at least `kSpxWotsLen` words long.
 *
 * @param msg Input message.
 * @param[out] lengths Resulting chain lengths.
 */
static void chain_lengths(const uint32_t *msg, uint8_t *lengths) {
  base_w((unsigned char *)msg, kSpxWotsLen1, lengths);
  wots_checksum(lengths, &lengths[kSpxWotsLen1]);
}

static_assert(kSpxWotsLen - 1 <= UINT8_MAX,
              "Maximum chain value must fit into a `uint8_t`");
void wots_pk_from_sig(const uint32_t *sig, const uint32_t *msg,
                      const spx_ctx_t *ctx, spx_addr_t *addr, uint32_t *pk) {
  uint8_t lengths[kSpxWotsLen];
  chain_lengths(msg, lengths);

  for (uint8_t i = 0; i < kSpxWotsLen; i++) {
    spx_addr_chain_set(addr, i);
    size_t word_offset = i * kSpxNWords;
    gen_chain(sig + word_offset, lengths[i], ctx, addr, pk + word_offset);
  }
}


OTTF_DEFINE_TEST_CONFIG();

enum {
  kSpxWotsMsgBytes = ((kSpxWotsLen1 * kSpxWotsLogW + 7) / 8),
  kSpxWotsMsgWords =
      (kSpxWotsMsgBytes + sizeof(uint32_t) - 1) / sizeof(uint32_t),
};

// Test signature, message, and address. Populate before running test.
static uint32_t kTestSig[kSpxWotsWords] = {0};
static uint32_t kTestMsg[kSpxWotsMsgWords] = {0};
static spx_addr_t kTestAddr = {.addr = {0}};

// Test context.
static spx_ctx_t kTestCtx = {
    .pub_seed =
        {
            0xf3f2f1f0,
            0xf7f6f5f4,
            0xfbfaf9f8,
            0xfffefdfc,
        },
};

void my_hmac_sha256_save(hmac_context_t *ctx) {
  // Issue the STOP command to halt the operation and compute the intermediate
  // digest.
  uint32_t cmd = bitfield_bit32_write(0, HMAC_CMD_HASH_STOP_BIT, true);
  abs_mmio_write32(TOP_EARLGREY_HMAC_BASE_ADDR + HMAC_CMD_REG_OFFSET, cmd);
  wait_for_done();
  
  // Read the digest registers. Note that endianness does not matter here,
  // because we will simply restore the registers in the same order as we saved
  // them.
  for (uint32_t i = 0; i < kHmacDigestNumWords; i++) {
    ctx->digest[i] =
        abs_mmio_read32(TOP_EARLGREY_HMAC_BASE_ADDR + HMAC_DIGEST_0_REG_OFFSET +
                        i * sizeof(uint32_t));
  }

  // Read the message length registers.
  ctx->msg_len_lower = abs_mmio_read32(TOP_EARLGREY_HMAC_BASE_ADDR +
                                       HMAC_MSG_LENGTH_LOWER_REG_OFFSET);
  ctx->msg_len_upper = abs_mmio_read32(TOP_EARLGREY_HMAC_BASE_ADDR +
                                       HMAC_MSG_LENGTH_UPPER_REG_OFFSET);
  
  // Momentarily clear the `sha_en` bit, which clears the digest.
  uint32_t cfg =
      abs_mmio_read32(TOP_EARLGREY_HMAC_BASE_ADDR + HMAC_CFG_REG_OFFSET);
  abs_mmio_write32(TOP_EARLGREY_HMAC_BASE_ADDR + HMAC_CFG_REG_OFFSET,
                   bitfield_bit32_write(cfg, HMAC_CFG_SHA_EN_BIT, false));
  
  // Restore the full original configuration.
  abs_mmio_write32(TOP_EARLGREY_HMAC_BASE_ADDR + HMAC_CFG_REG_OFFSET, cfg);
}

rom_error_t my_spx_hash_initialize(spx_ctx_t *ctx) {
  hmac_sha256_configure(/*big_endian_digest=*/true);
  
  // Save state for the first part of `thash`: public key seed + padding.
  hmac_sha256_start();
  hmac_sha256_update_words(ctx->pub_seed, kSpxNWords);
  uint32_t padding[kSpxSha2BlockNumWords - kSpxNWords];
  memset(padding, 0, sizeof(padding));
  hmac_sha256_update_words(padding, ARRAYSIZE(padding));
  my_hmac_sha256_save(&ctx->state_seeded);
  return kErrorOk;
}

// Test data generated with a third-party implementation of SPHINCS+.
static uint32_t kExpectedLeaf[kSpxNWords] = {0x14199738, 0x8d0ae722, 0x27ba271f,
                                             0x94194a62};

OT_WARN_UNUSED_RESULT
static rom_error_t pk_from_sig_test(void) {
  RETURN_IF_ERROR(my_spx_hash_initialize(&kTestCtx));
  
  // Extract the public key from the signature.
  uint32_t wots_pk[kSpxWotsPkWords];
  wots_pk_from_sig(kTestSig, kTestMsg, &kTestCtx, &kTestAddr, wots_pk);
  
  // Compute the leaf node using `thash`. This is the next step in the
  // verification procedure and FIPS 205 combines it into the same algorithm as
  // `wots_pk_from_sig`; mostly this lets us have a shorter value to check.
  spx_addr_t wots_pk_addr = {.addr = {0}};
  spx_addr_type_set(&wots_pk_addr, kSpxAddrTypeWotsPk);
  spx_addr_keypair_copy(&wots_pk_addr, &kTestAddr);
  uint32_t actual_leaf[kSpxNWords];
  thash(wots_pk, kSpxWotsLen, &kTestCtx, &wots_pk_addr, actual_leaf);
  
  // Check results.
  CHECK_ARRAYS_EQ(actual_leaf, kExpectedLeaf, ARRAYSIZE(kExpectedLeaf));

  LOG_INFO("8");

  return kErrorOk;
}

bool test_main(void) {
  status_t result = OK_STATUS();

  // Populate signature with {0, 1, 2, 3, ... }.
  unsigned char *test_sig_bytes = (unsigned char *)kTestSig;
  for (size_t i = 0; i < kSpxWotsBytes; i++) {
    test_sig_bytes[i] = i & 255;
  }

  // Populate message with { ..., 3, 2, 1, 0}.
  unsigned char *test_msg_bytes = (unsigned char *)kTestMsg;
  for (size_t i = 0; i < kSpxWotsMsgBytes; i++) {
    test_msg_bytes[i] = (kSpxWotsMsgBytes - i) & 255;
  }

  // Populate address.
  spx_addr_layer_set(&kTestAddr, 0xa3);
  spx_addr_tree_set(&kTestAddr, 0xafaeadacabaaa9a8);
  spx_addr_type_set(&kTestAddr, kSpxAddrTypeWots);
  spx_addr_keypair_set(&kTestAddr, 0xb4b5b6b7);

  EXECUTE_TEST(result, pk_from_sig_test);
  LOG_INFO("RETURNED");

  return status_ok(result);
}
