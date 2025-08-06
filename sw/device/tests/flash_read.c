// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/lib/base/macros.h"
#include "sw/device/lib/base/status.h"
#include "sw/device/lib/dif/dif_alert_handler.h"
#include "sw/device/lib/dif/dif_flash_ctrl.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/flash_ctrl_testutils.h"
#include "sw/device/lib/testing/json/command.h"
#include "sw/device/lib/testing/json/flash.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"
#include "sw/device/lib/testing/test_framework/ujson_ottf.h"
#include "sw/device/lib/testing/test_framework/ujson_ottf_commands.h"
#include "sw/device/lib/ujson/ujson.h"
#include "sw/device/silicon_creator/lib/base/chip.h"
#include "sw/device/silicon_creator/lib/boot_data.h"
#include "sw/device/silicon_creator/lib/boot_log.h"
#include "sw/device/silicon_creator/lib/drivers/retention_sram.h"

#include "flash_ctrl_regs.h"                          // Generated
#include "hw/top_earlgrey/sw/autogen/top_earlgrey.h"  // Generated

// WARNING: this test can wear down flash, and so should only be run manually!
// See sw/host/tests/chip/flash_ctrl/endurance_tests/README.md for more info.

OTTF_DEFINE_TEST_CONFIG(.enable_uart_flow_control = true);

enum {
  // Default to testing data partion 0, using protection region 2 (ROM_EXT
  // uses protection regions 0 & 1)
  kPartitionId = 0,
  kDataRegionIndex = 2,
  // Flash size information, including the number of bytes & words (u32, not
  // flash words) per flash word & flash page.
  kFlashBanks = FLASH_CTRL_PARAM_REG_NUM_BANKS,
  kFlashPagesPerBank = FLASH_CTRL_PARAM_REG_PAGES_PER_BANK,
  kFlashDataRegions = FLASH_CTRL_PARAM_NUM_REGIONS,
  kBytesPerFlashPage = FLASH_CTRL_PARAM_BYTES_PER_PAGE,
  kWordsPerFlashPage = kBytesPerFlashPage / sizeof(uint32_t),
  kBytesPerFlashWord = FLASH_CTRL_PARAM_BYTES_PER_WORD,
  kWordsPerFlashWord = kBytesPerFlashWord / sizeof(uint32_t),
  kFlashWordsPerPage = FLASH_CTRL_PARAM_WORDS_PER_PAGE,
  // Number of pages allocated to the ROM_EXT. The same number of pages are
  // allocated at the beginning of each bank('s data partition).
  kRomExtPageCount = CHIP_ROM_EXT_SIZE_MAX / kBytesPerFlashPage,
  // The start and end bounds of owner partition A (bank 0) and B (bank 1)
  kBank0FirstPage = kRomExtPageCount,
  kBank0LastPage = kFlashPagesPerBank - 1,
  kBank1FirstPage = kFlashPagesPerBank + kRomExtPageCount,
  kBank1LastPage = 2 * kFlashPagesPerBank - 1,
};

static_assert(kDataRegionIndex >= 2,
              "Regions 0 & 1 are used by ROM_EXT and so cannot be used");
static_assert(kDataRegionIndex < kFlashDataRegions,
              "kDataRegionIndex does not refer to a valid protection region");
static_assert(kBank0FirstPage <= kBank0LastPage,
              "There are no valid pages to test in owner partition A (bank 0)");
static_assert(kBank1FirstPage <= kBank1LastPage,
              "There are no valid pages to test in owner partition B (bank 1)");

static dif_flash_ctrl_state_t flash_ctrl;

bool test_main(void) {
  CHECK_DIF_OK(dif_flash_ctrl_init_state(
      &flash_ctrl,
      mmio_region_from_addr(TOP_EARLGREY_FLASH_CTRL_CORE_BASE_ADDR)));
  CHECK_STATUS_OK(flash_ctrl_testutils_wait_for_init(&flash_ctrl));

  const uint32_t test_page = 450;
  uint32_t test_data[kWordsPerFlashPage];
  for (int i = 0; i < ARRAYSIZE(test_data); ++i) {
    test_data[i] = 0xA5A5A5A5;
  }

  dif_flash_ctrl_region_properties_t region_properties = {
      .erase_en = kMultiBitBool4True,
      .prog_en = kMultiBitBool4True,
      .rd_en = kMultiBitBool4True,
      .ecc_en = kMultiBitBool4False,
      .high_endurance_en = kMultiBitBool4False,
      .scramble_en = kMultiBitBool4False};

  uint32_t page_address;
  CHECK_STATUS_OK(flash_ctrl_testutils_data_region_setup_properties(
      &flash_ctrl, test_page, kDataRegionIndex, /*region_size=*/1,
      region_properties, &page_address));
      
  // Read the page back
  uint32_t readback_data[kWordsPerFlashPage];
  CHECK_STATUS_OK(flash_ctrl_testutils_read(
      &flash_ctrl, page_address, kPartitionId, readback_data,
      kDifFlashCtrlPartitionTypeData, ARRAYSIZE(readback_data), /*delay=*/1));

  // Check that the data we read back matches our expected data
  bool error = false;
  for (int i = 0; i < ARRAYSIZE(readback_data); ++i) {
    LOG_INFO("word %d: readback=0x%08x, expected=0x%08x", i+1, readback_data[i], test_data[i]);
    if (readback_data[i] != test_data[i]) {
     LOG_INFO("DATA MISMATCH");
     error = true;
     break;
    }
  }
  if (!error) {
     LOG_INFO("SUCCESS!");
     return true;
  }
  return false;
}
