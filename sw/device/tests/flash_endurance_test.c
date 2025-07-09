// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/lib/base/macros.h"
#include "sw/device/lib/base/status.h"
#include "sw/device/lib/dif/dif_flash_ctrl.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/flash_ctrl_testutils.h"
#include "sw/device/lib/testing/rand_testutils.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"
#include "sw/device/lib/testing/test_framework/ottf_utils.h"
#include "sw/device/silicon_creator/lib/base/chip.h"

#include "flash_ctrl_regs.h"                          // Generated
#include "hw/top_earlgrey/sw/autogen/top_earlgrey.h"  // Generated

// WARNING: this test wears down flash, and so should only be run manually!
//
// Test that flash on PROD silicon endures a minimum number of program/erase
// cycles before it wears & faults are seen. Find the last working page(s) of
// flash and repeatedly erase & program the page, counting how many cycles
// before an error is seen.

OTTF_DEFINE_TEST_CONFIG();

enum {
  kTestTimeoutMillis = 500000,
  // The max number of program/erase cycles to try for any single test
  kMaxProgramEraseCycles = 10 * 1000 * 1000,
  // The granularity with which to log test progress. Will log the current
  // progress every X program/erase cycles.
  kLogCycleGranularity = 1000,
  // Default to testing bank 1, data partition 0, using protection region 2
  // (ROM-EXT uses protection regions 0&1)
  kFlashBank = 1,
  kPartitionId = 0,
  kDataRegionIndex = 2,
  // Number of bytes/words (u32, not flash words) per flash word / page
  kBytesPerFlashPage = FLASH_CTRL_PARAM_BYTES_PER_PAGE,
  kWordsPerFlashPage = kBytesPerFlashPage / sizeof(uint32_t),
  kBytesPerFlashWord = FLASH_CTRL_PARAM_BYTES_PER_WORD,
  kWordsPerFlashWord = kBytesPerFlashWord / sizeof(uint32_t),
  kFlashWordsPerPage = kBytesPerFlashPage / kBytesPerFlashWord,
  // Number of flash pages per bank
  kFlashPagesPerBank = FLASH_CTRL_PARAM_REG_PAGES_PER_BANK,
  // Number of pages allocated to the ROM_EXT. The same number of pages are
  // allocated at the begining of each data bank.
  kRomExtPageCount = CHIP_ROM_EXT_SIZE_MAX / kBytesPerFlashPage,
  // The last page of owner partition B (bank 1) - we search back from this
  // page until we find a valid page to write to.
  KBank1LastPageNum = 2 * kFlashPagesPerBank - 1,
  // The first page of owner partition B - the last possible page we might
  // use for this test when searching backwards.
  kBank1StartPageNum = kFlashPagesPerBank + kRomExtPageCount,
};

static_assert(kBank1StartPageNum <= KBank1LastPageNum,
              "there are no valid pages to test in bank 1.");

static dif_flash_ctrl_state_t flash_ctrl;

static uint32_t test_data[kWordsPerFlashPage];
static uint32_t inverted_test_data[kWordsPerFlashPage];

typedef struct flash_endurance_test {
  const char *description;
  // The number of program/erase cycles we expect to endure without faults
  uint32_t target_cycles;
  // The properties to use when testing
  dif_flash_ctrl_region_properties_t properties;
} flash_endurance_test_t;

static const flash_endurance_test_t kTestData[] = {
    {

        .description = "ECC, scrambling & high-endurance disabled",
        .target_cycles = 1 * 1000,
        .properties =
            {
                .rd_en = kMultiBitBool4True,
                .prog_en = kMultiBitBool4True,
                .erase_en = kMultiBitBool4True,
                .scramble_en = kMultiBitBool4False,
                .ecc_en = kMultiBitBool4False,
                .high_endurance_en = kMultiBitBool4False,
            },
    },
    {
        .description = "high-endurance enabled with ECC & scrambling disabled",
        .target_cycles = 2 * 1000,
        .properties =
            {
                .rd_en = kMultiBitBool4True,
                .prog_en = kMultiBitBool4True,
                .erase_en = kMultiBitBool4True,
                .scramble_en = kMultiBitBool4False,
                .ecc_en = kMultiBitBool4False,
                .high_endurance_en = kMultiBitBool4True,
            },
    },
};

/**
 * Initialise test data for writing each page on each cycle. Can either use
 * random data, or an alternating 0xA5A5A5A5 pattern.
 */
static void initialise_test_data(bool random_data) {
  for (int i = 0; i < ARRAYSIZE(test_data); ++i) {
    if (random_data) {
      test_data[i] = rand_testutils_gen32();
    } else {
      test_data[i] = 0xA5A5A5A5;
    }
    inverted_test_data[i] = ~test_data[i];
  }
}

/**
 * Perform a page erase operation and verify that the entire erase happened
 * without any faults by reading the data back.
 */
static void flash_ctrl_verify_erase(dif_flash_ctrl_state_t *flash_state,
                                    uint32_t address, bool *error) {
  // Erase the page and read it back
  *error = false;
  status_t status = flash_ctrl_testutils_erase_page(
      flash_state, address, kPartitionId, kDifFlashCtrlPartitionTypeData);
  if (status_err(status)) {
    *error = true;
    return;
  }
  uint32_t readback_data[kWordsPerFlashPage];
  status = flash_ctrl_testutils_read(
      flash_state, address, kPartitionId, readback_data,
      kDifFlashCtrlPartitionTypeData, ARRAYSIZE(readback_data), /*delay=*/1);
  if (status_err(status)) {
    *error = true;
    return;
  }

  // Check that we read back all 0xFFFFFFFF after erasure
  for (int i = 0; i < ARRAYSIZE(readback_data); ++i) {
    if (~readback_data[i] != 0) {
      *error = true;
      break;
    }
  }
}

/**
 * Perform a word program (write) operation and verify that the write occurred
 * without any faults by reading the data back.
 */
static void flash_ctrl_verify_word_write(dif_flash_ctrl_state_t *flash_state,
                                         uint32_t address, const uint32_t *data,
                                         bool *error) {
  // Program the given flash word and read it back
  *error = false;
  uint32_t readback_data[kWordsPerFlashWord];
  status_t status = flash_ctrl_testutils_write(
      flash_state, address, kPartitionId, data, kDifFlashCtrlPartitionTypeData,
      ARRAYSIZE(readback_data));
  if (status_err(status)) {
    *error = true;
    return;
  }
  status = flash_ctrl_testutils_read(
      flash_state, address, kPartitionId, readback_data,
      kDifFlashCtrlPartitionTypeData, ARRAYSIZE(readback_data), /*delay=*/1);
  if (status_err(status)) {
    *error = true;
    return;
  }

  // Check that the data we read back matches the test data we wrote
  for (int i = 0; i < ARRAYSIZE(readback_data); ++i) {
    if (readback_data[i] != data[i]) {
      *error = true;
      break;
    }
  }
}

/**
 * Perform program (write) operations for each flash word in a given page,
 * verifying that each write occurred without faults by reading the data back.
 */
static void flash_ctrl_verify_page_write(dif_flash_ctrl_state_t *flash_state,
                                         uint32_t address, const uint32_t *data,
                                         bool *error) {
  *error = false;
  for (int word = 0; word < kFlashWordsPerPage; ++word) {
    flash_ctrl_verify_word_write(flash_state, address, data, error);
    if (*error) {
      break;
    }
    address += kBytesPerFlashWord;
    data += kWordsPerFlashWord;
  }
}

/**
 * Erase a page in flash and then write to the entire page, verifying after
 * each operation that the erase/program occurred without faults by reading
 * the data back. Stops when any errors are detected.
 */
static void flash_ctrl_verify_erase_program(dif_flash_ctrl_state_t *flash_state,
                                            uint32_t address,
                                            const uint32_t *data, bool *error) {
  *error = false;
  flash_ctrl_verify_erase(flash_state, address, error);
  if (!*error) {
    flash_ctrl_verify_page_write(flash_state, address, data, error);
  }
}

/**
 * Find the last writable page within an input range of flash pages. This is
 * the last page which can be erased and written to without any errors
 * occurring. Performs 2 Program/Erase operations with an alternating
 * (inverted) bit pattern to check for errors on any bits.
 */
static status_t get_last_writable_page(dif_flash_ctrl_state_t *flash_state,
                                       int first_page, int last_page,
                                       int *last_writable) {
  dif_flash_ctrl_region_properties_t region_properties = {
      .erase_en = kMultiBitBool4True,
      .prog_en = kMultiBitBool4True,
      .rd_en = kMultiBitBool4True,
      .ecc_en = kMultiBitBool4False,
      .high_endurance_en = kMultiBitBool4False,
      .scramble_en = kMultiBitBool4False};

  // Iterate backwards through pages, configuring data region 0 for each page
  // and erasing/programming until we find a fully working page.
  CHECK(first_page >= 0, "Page range provided must be >= 0");
  for (int32_t page_num = last_page; page_num >= first_page; --page_num) {
    uint32_t page_address;
    CHECK_STATUS_OK(flash_ctrl_testutils_data_region_setup_properties(
        flash_state, (uint32_t)page_num, kDataRegionIndex, /*region_size=*/1,
        region_properties, &page_address));
    bool error = false;
    flash_ctrl_verify_erase_program(flash_state, page_address, test_data,
                                    &error);
    if (error) {
      continue;
    }
    flash_ctrl_verify_erase_program(flash_state, page_address,
                                    inverted_test_data, &error);
    if (!error) {
      *last_writable = page_num;
      return OK_STATUS();
    }
  }
  CHECK(false, "No writable pages remain.");
  OT_UNREACHABLE();
}

/**
 * Run a flash endurance test - this will wear down the provided page. Performs
 * erase & program operations with given flash protection settings until a
 * fault occurs, or a limiting maximum number of cycles is reached. Then checks
 * that this meets or exceeds the target cycles specified in the test.
 */
static status_t flash_endurance_test(dif_flash_ctrl_state_t *flash_state,
                                     uint32_t max_cycles,
                                     flash_endurance_test_t test,
                                     uint32_t page_index,
                                     uint32_t mp_region_index) {
  LOG_INFO("Starting flash endurance test...");

  // We only want to test flash on silicon. On all other targets, always clamp
  // the target to the max cycles so that the test can pass in limited cycles.
  uint32_t target_cycles = test.target_cycles;
  if (kDeviceType != kDeviceSilicon && target_cycles > max_cycles) {
    target_cycles = max_cycles;
  }
  CHECK(target_cycles <= max_cycles,
        "Target cycles should be less than the maximum");

  // Configure a memory protected region covering our page to implement
  // the configuration described in `test.properties`
  uint32_t page_address;
  CHECK_STATUS_OK(flash_ctrl_testutils_data_region_setup_properties(
      flash_state, page_index, mp_region_index, /*region_size=*/1,
      test.properties, &page_address));

  // We assume we already did 2 program/erase cycles to find this writable page
  uint32_t valid_cycles = 1;

  // Repeatedly erase & program until an error is detected
  bool error = false;
  while (!error && valid_cycles < max_cycles) {
    valid_cycles += 1;
    if (valid_cycles % kLogCycleGranularity == 0) {
      LOG_INFO("Succeeded %d program/erase cycles", valid_cycles);
    }
    const uint32_t *data = (valid_cycles % 2) ? inverted_test_data : test_data;
    flash_ctrl_verify_erase_program(flash_state, page_address, data, &error);
  }

  if (error) {
    LOG_INFO(
        "Flash failed after %d program/erase cycles (expected >= %d cycles)",
        valid_cycles, target_cycles);
  } else {
    LOG_INFO("Exceeded max program/erase cycles without failing (%d cycles)",
             max_cycles);
  }
  CHECK(valid_cycles >= target_cycles,
        "Flash did not endure for the target number of cycles");

  return OK_STATUS();
}

bool test_main(void) {
  CHECK_DIF_OK(dif_flash_ctrl_init_state(
      &flash_ctrl,
      mmio_region_from_addr(TOP_EARLGREY_FLASH_CTRL_CORE_BASE_ADDR)));
  CHECK_STATUS_OK(flash_ctrl_testutils_wait_for_init(&flash_ctrl));

  // Initialise data for programming flash in tests
  initialise_test_data(/*random_data=*/false);

  // We only want to test flash on silicon. On all other targets, clamp each
  // test to a few cycles so we don't wear down any hardware.
  uint32_t max_cycles = kMaxProgramEraseCycles;
  if (kDeviceType != kDeviceSilicon) {
    max_cycles = 5;
    LOG_INFO("Not running on silicon - limiting to %d program/erase cycles.",
             max_cycles);
  }

  // For each test, find the last working page and run the endurance test
  uint32_t num_tests = ARRAYSIZE(kTestData);
  int last_writable_page = 0;
  for (uint32_t i = 0; i < num_tests; ++i) {
    flash_endurance_test_t test = kTestData[i];
    LOG_INFO("Test %d/%d with %s", i + 1, num_tests, test.description);
    int end_page_num =
        (last_writable_page > 0) ? (last_writable_page - 1) : KBank1LastPageNum;
    CHECK_STATUS_OK(get_last_writable_page(&flash_ctrl, kBank1StartPageNum,
                                           end_page_num, &last_writable_page));
    LOG_INFO("Testing page with index %d", last_writable_page);
    CHECK_STATUS_OK(flash_endurance_test(&flash_ctrl, max_cycles, test,
                                         (uint32_t)last_writable_page,
                                         kDataRegionIndex));
  }

  return true;
}
