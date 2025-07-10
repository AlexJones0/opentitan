// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "dt/dt_api.h"  // Generated
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

#include "flash_ctrl_regs.h"  // Generated

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
  kLogCycleGranularity = 500,
  // Default to testing bank 1, data partition 0, using protection region 0
  kFlashBank = 1,
  kPartitionId = 0,
  kDataRegionIndex = 0,
  // Number of bytes / words (`uint32_t`, not flash page) per flash word / page.
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

static const dt_flash_ctrl_t kFlashCtrlDt = 0;
static_assert(kDtFlashCtrlCount >= 1, "this test expects a flash_ctrl");
static dif_flash_ctrl_state_t flash_ctrl;

static uint32_t test_data[kWordsPerFlashPage];
static uint32_t inverted_test_data[kWordsPerFlashPage];

typedef struct flash_endurance_test {
  const char *description;
  // The number of program/erase cycles we expect to endure without faults
  uint32_t target_cycles;
  // Whether single ECC errors corrected by flash_ctrl should be allowed (true)
  // or treated as errors (false). Only applies if ECC is enabled.
  bool allow_ecc_corrections;
  // The properties to use when testing
  dif_flash_ctrl_region_properties_t properties;
} flash_endurance_test_t;

static const flash_endurance_test_t kTestData[] = {
    {

        .description = "ECC, scrambling & high-endurance disabled",
        .target_cycles = 100 * 1000,
        .allow_ecc_corrections = false,
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
        .target_cycles = 200 * 1000,
        .allow_ecc_corrections = false,
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
    {
        .description =
            "ECC enabled, with scrambling and high-endurance disabled",
        .target_cycles = 150 * 1000,
        .allow_ecc_corrections = true,
        .properties =
            {
                .rd_en = kMultiBitBool4True,
                .prog_en = kMultiBitBool4True,
                .erase_en = kMultiBitBool4True,
                .scramble_en = kMultiBitBool4False,
                .ecc_en = kMultiBitBool4True,
                .high_endurance_en = kMultiBitBool4True,
            },
    },
};

/**
 * Initialise test data for writing each page on each cycle. Can either use
 * random data, or an alternating 0xA5A5A5A5 pattern
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
 * Retrieve the number of single ECC errors that have been counted so far.
 */
static status_t flash_ctrl_get_single_ecc_errors(
    dif_flash_ctrl_state_t *flash_state, uint32_t *errors) {
  dif_flash_ctrl_ecc_errors_t ecc_errors;
  CHECK_DIF_OK(
      dif_flash_ctrl_get_ecc_errors(flash_state, kFlashBank, &ecc_errors));
  *errors = ecc_errors.single_bit_error_count;
  return OK_STATUS();
}

/**
 * Perform a page erase operation and verify that the entire erase happened
 * without any faults by reading the data back. Reports errors on flash-word
 * granularity, only checking words that have not yet errored. Optionally check
 * for single ECC errors if `check_ecc=true`.
 */
static status_t flash_ctrl_verify_erase(dif_flash_ctrl_state_t *flash_state,
                                        uint32_t address, bool check_ecc,
                                        bool *errors) {
  // Check the original number of single ECC errors
  uint32_t ecc_errors = 0;
  if (check_ecc) {
    CHECK_STATUS_OK(flash_ctrl_get_single_ecc_errors(flash_state, &ecc_errors));
  }

  // Erase the page
  CHECK_STATUS_OK(flash_ctrl_testutils_erase_page(
      flash_state, address, kPartitionId, kDifFlashCtrlPartitionTypeData));

  // Read the page back, a word at a time, to find errors at word-level.
  uint32_t readback_data[kWordsPerFlashWord];
  for (uint32_t i = 0; i < kFlashWordsPerPage; ++i) {
    // Don't check flash words that have already errored
    if (errors[i]) {
      address += kBytesPerFlashWord;
      continue;
    }

    // Check that we read back all 0xFFFFFFFF after erasure
    CHECK_STATUS_OK(flash_ctrl_testutils_read(
        flash_state, address, kPartitionId, readback_data,
        kDifFlashCtrlPartitionTypeData, ARRAYSIZE(readback_data), /*delay=*/1));
    address += kBytesPerFlashWord;
    for (int j = 0; j < ARRAYSIZE(readback_data); ++j) {
      if (~readback_data[j] != 0) {
        errors[i] = true;
        break;
      }
    }

    // Check that no single ECC errors were reported, if applicable
    if (check_ecc) {
      uint32_t updated_errors = 0;
      CHECK_STATUS_OK(
          flash_ctrl_get_single_ecc_errors(flash_state, &updated_errors));
      if (updated_errors > ecc_errors) {
        errors[i] = true;
        ecc_errors = updated_errors;
      }
    }
  }
  return OK_STATUS();
}

/**
 * Perform a word program (write) operation and verify that the write occurred
 * without any faults by reading the data back. Optionally check for single
 * ECC errors if `check_ecc=true`.
 */
static status_t flash_ctrl_verify_word_write(
    dif_flash_ctrl_state_t *flash_state, uint32_t address, const uint32_t *data,
    bool check_ecc, bool *error) {
  // Check the original number of single ECC errors
  uint32_t ecc_errors = 0;
  if (check_ecc) {
    CHECK_STATUS_OK(flash_ctrl_get_single_ecc_errors(flash_state, &ecc_errors));
  }

  // Program the given flash word and read it back
  uint32_t readback_data[kWordsPerFlashWord];
  CHECK_STATUS_OK(flash_ctrl_testutils_write(
      flash_state, address, kPartitionId, data, kDifFlashCtrlPartitionTypeData,
      ARRAYSIZE(readback_data)));
  CHECK_STATUS_OK(flash_ctrl_testutils_read(
      flash_state, address, kPartitionId, readback_data,
      kDifFlashCtrlPartitionTypeData, ARRAYSIZE(readback_data), /*delay=*/1));

  // Check that no single ECC errors were reported, if applicable
  if (check_ecc) {
    uint32_t updated_errors = 0;
    CHECK_STATUS_OK(
        flash_ctrl_get_single_ecc_errors(flash_state, &updated_errors));
    if (updated_errors > ecc_errors) {
      *error = true;
      return OK_STATUS();
    }
  }

  // Check that the data we read back matches the test data we wrote
  for (int i = 0; i < ARRAYSIZE(readback_data); ++i) {
    if (readback_data[i] != data[i]) {
      *error = true;
      break;
    }
  }
  return OK_STATUS();
}

/**
 * Perform program (write) operations for each flash word in a given page,
 * verifying that each write occurred without faults by reading the data back.
 * Errors are reported at a flash-word granularity.
 * Optionally check for ECC errors if `check_ecc=true`.
 */
static status_t flash_ctrl_verify_page_write(
    dif_flash_ctrl_state_t *flash_state, uint32_t address, const uint32_t *data,
    bool check_ecc, bool *errors) {
  for (int word = 0; word < kFlashWordsPerPage; ++word) {
    if (!errors[word]) {
      CHECK_STATUS_OK(flash_ctrl_verify_word_write(flash_state, address, data,
                                                   check_ecc, &errors[word]));
    }
    address += kBytesPerFlashWord;
    data += kWordsPerFlashWord;
  }
  return OK_STATUS();
}

/**
 * Erase a page in flash and then write to the entire page, verifying after
 * each operation that the eerase/program occurred without faults by reading
 * the data back. Errors are reported at a flash-word granularity. Optionally
 * check for ECC errors if `check_ecc=true`.
 */
static status_t flash_ctrl_verify_erase_program(
    dif_flash_ctrl_state_t *flash_state, uint32_t address, const uint32_t *data,
    bool check_ecc, bool *errors) {
  CHECK_STATUS_OK(
      flash_ctrl_verify_erase(flash_state, address, check_ecc, errors));
  CHECK_STATUS_OK(flash_ctrl_verify_page_write(flash_state, address, test_data,
                                               check_ecc, errors));
  return OK_STATUS();
}

static uint32_t error_count(bool *errors, uint32_t words) {
  uint32_t error_count = 0;
  for (uint32_t i = 0; i < words; ++i) {
    error_count += (uint32_t)errors[i];
  }
  return error_count;
}

/**
 * Find the last writable page within an input range of flash pages. This is
 * the last page which can be erased and written to without any errors
 * occurring. Performs 2 Program/Erase operations with an alternating
 * (inverted) bit pattern to check for errors on any bits.
 */
static status_t get_last_writable_page(dif_flash_ctrl_state_t *flash_state,
                                       uint32_t first_page, uint32_t last_page,
                                       uint32_t *last_writable) {
  dif_flash_ctrl_region_properties_t region_properties = {
      .erase_en = kMultiBitBool4True,
      .prog_en = kMultiBitBool4True,
      .rd_en = kMultiBitBool4True,
      .ecc_en = kMultiBitBool4False,
      .high_endurance_en = kMultiBitBool4False,
      .scramble_en = kMultiBitBool4False};

  // Iterate backwards through pages, configuring data region 0 for each page
  // and erasing/programming until we find a fully working page.
  for (uint32_t page_num = last_page; page_num >= first_page; --page_num) {
    uint32_t page_address;
    CHECK_STATUS_OK(flash_ctrl_testutils_data_region_setup_properties(
        flash_state, page_num, kDataRegionIndex, /*region_size=*/1,
        region_properties, &page_address));

    bool errors[kFlashWordsPerPage] = {false};
    CHECK_STATUS_OK(flash_ctrl_verify_erase_program(
        flash_state, page_address, test_data, /*check_ecc=*/false, errors));
    if (error_count(errors, kFlashWordsPerPage) > 0) {
      continue;
    }
    CHECK_STATUS_OK(flash_ctrl_verify_erase_program(
        flash_state, page_address, inverted_test_data, /*check_ecc=*/false,
        errors));
    if (error_count(errors, kFlashWordsPerPage) == 0) {
      *last_writable = page_num;
      return OK_STATUS();
    }
  }
  CHECK(false, "No writable pages remain.");
  return OK_STATUS();  // Unreachable
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
  uint32_t cycles = 1;
  uint32_t word_cycles[kFlashWordsPerPage];
  for (int i = 0; i < kFlashWordsPerPage; ++i) {
    word_cycles[i] = cycles;
  }
  bool check_ecc = (test.properties.ecc_en == kMultiBitBool4True) &&
                   (!test.allow_ecc_corrections);

  // Repeatedly erase & program until an error is detected in 50% of flash words
  bool errors[kFlashWordsPerPage] = {false};
  uint32_t threshold = kFlashWordsPerPage / 2 + kFlashWordsPerPage % 2;
  while (error_count(errors, kFlashWordsPerPage) < threshold &&
         cycles < max_cycles) {
    // Increment cycle counters for all words that did not report errors.
    cycles += 1;
    for (uint32_t i = 0; i < kFlashWordsPerPage; ++i) {
      word_cycles[i] += errors[i] ? 0 : 1;
    }

    if (cycles % kLogCycleGranularity == 0) {
      LOG_INFO("Processed %d program/erase cycles (%d/%d word faults)", cycles,
               error_count(errors, kFlashWordsPerPage), kFlashWordsPerPage);
    }

    // Run a Program/Erase operation on the entire page
    const uint32_t *data = (cycles % 2) ? inverted_test_data : test_data;
    CHECK_STATUS_OK(flash_ctrl_verify_erase_program(flash_state, page_address,
                                                    data, check_ecc, errors));
  }

  // Calculate useful info/statistics
  uint32_t num_errors = error_count(errors, kFlashWordsPerPage);
  uint32_t minimum_cycles = word_cycles[0];
  uint32_t total_cycles = 0;
  for (uint32_t i = 0; i < kFlashWordsPerPage; ++i) {
    if (word_cycles[i] < minimum_cycles) {
      minimum_cycles = word_cycles[i];
    }
    if (errors[i]) {
      total_cycles += word_cycles[i];
    }
  }
  uint32_t mean_cycles = total_cycles / num_errors;

  uint32_t variance_cycles = 0;
  for (uint32_t i = 0; i < kFlashWordsPerPage; ++i) {
    if (!errors[i]) {
      continue;
    }
    uint32_t mean_diff = (mean_cycles >= word_cycles[i])
                             ? mean_cycles - word_cycles[i]
                             : word_cycles[i] - mean_cycles;
    variance_cycles += mean_diff * mean_diff / num_errors;
  }

  // Report useful info/stats and check the minimum failed cycles
  if (num_errors > 0) {
    LOG_INFO(
        "First flash word failure occured after %d cycles (expected >= %d)",
        minimum_cycles, target_cycles);
  } else {
    LOG_INFO("Exceeded max (%d) program/erase cycles without failing",
             max_cycles);
  }
  if (num_errors >= threshold) {
    LOG_INFO("Half (%d/%d) of flash words failed after %d cycles", num_errors,
             kFlashWordsPerPage, cycles);
  } else {
    LOG_INFO("After the max (%d) cycles, %d out of %d flash words failed",
             max_cycles, num_errors, kFlashWordsPerPage);
  }
  if (num_errors > 0) {
    LOG_INFO("For the failing words:");
    LOG_INFO("\t- It took an average of %d cycles for failure", mean_cycles);
    LOG_INFO("\t- With a variance of (approx) %d cycles", variance_cycles);
  }
  CHECK(minimum_cycles >= target_cycles,
        "Flash did not endure for the target number of cycles");

  return OK_STATUS();
}

bool test_main(void) {
  CHECK_DIF_OK(dif_flash_ctrl_init_state_from_dt(&flash_ctrl, kFlashCtrlDt));

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
  for (uint32_t i = 0; i < num_tests; ++i) {
    flash_endurance_test_t test = kTestData[i];
    LOG_INFO("Test %d/%d with %s", i + 1, num_tests, test.description);
    uint32_t last_writable_page;
    CHECK_STATUS_OK(get_last_writable_page(&flash_ctrl, kBank1StartPageNum,
                                           KBank1LastPageNum,
                                           &last_writable_page));
    LOG_INFO("Testing page with index %d", last_writable_page);
    CHECK_STATUS_OK(flash_endurance_test(&flash_ctrl, max_cycles, test,
                                         last_writable_page, kDataRegionIndex));
  }

  return true;
}
