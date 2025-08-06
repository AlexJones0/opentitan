// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
#ifndef OPENTITAN_SW_DEVICE_LIB_TESTING_JSON_FLASH_H_
#define OPENTITAN_SW_DEVICE_LIB_TESTING_JSON_FLASH_H_

#include "sw/device/lib/ujson/ujson_derive.h"
#ifdef __cplusplus
extern "C" {
#endif
// clang-format off

#define MODULE_ID MAKE_MODULE_ID('j', 'f', 'l')

#define STRUCT_FLASH_PROGRAM_ERASE_TEST(field, string) \
    field(num_cycles, uint32_t) \
    field(log_granularity, uint32_t) \
    field(readback_delay_us, uint64_t) \
    field(allow_ecc_errors, bool) \
    field(test_data, uint32_t, 512) \
    field(invert_each_cycle, bool)
UJSON_SERDE_STRUCT(FlashProgramEraseTest, flash_program_erase_test_t, STRUCT_FLASH_PROGRAM_ERASE_TEST);

#define STRUCT_FLASH_READ_AND_CHECK_PAGE(field, string) \
    field(expected_data, uint32_t, 512)
UJSON_SERDE_STRUCT(FlashReadAndCheckPage, flash_read_page_t, STRUCT_FLASH_READ_AND_CHECK_PAGE);

#define STRUCT_FLASH_WRITE_PAGE(field, string) \
    field(readback_delay_us, uint64_t) \
    field(data, uint32_t, 512)
UJSON_SERDE_STRUCT(FlashWritePage, flash_write_page_t, STRUCT_FLASH_WRITE_PAGE);

#define STRUCT_FLASH_TEST_CONFIG(field, string) \
    field(page_num, uint32_t) \
    field(high_endurance_en, bool) \
    field(scramble_en, bool) \
    field(ecc_en, bool)
UJSON_SERDE_STRUCT(FlashTestConfig, flash_test_config_t, STRUCT_FLASH_TEST_CONFIG);

#define STRUCT_FLASH_PROGRAM_ERASE_RESULT(field, string) \
    field(cycle, uint32_t) \
    field(success, bool) \
    field(ecc_errors, uint32_t) \
    field(erase_us, uint64_t) \
    field(program_us, uint64_t) \
    field(read_us, uint64_t)
UJSON_SERDE_STRUCT(FlashProgramEraseResult, flash_program_erase_result_t, STRUCT_FLASH_PROGRAM_ERASE_RESULT);

#undef MODULE_ID

// clang-format on
#ifdef __cplusplus
}
#endif
#endif  // OPENTITAN_SW_DEVICE_LIB_TESTING_JSON_FLASH_H_
