// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/lib/testing/keymgr_dpe_testutils.h"

#include "sw/device/lib/dif/dif_keymgr_dpe.h"
#include "sw/device/lib/dif/dif_otp_ctrl.h"
#include "sw/device/lib/dif/dif_rstmgr.h"
#include "sw/device/lib/runtime/ibex.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/otp_ctrl_testutils.h"
#include "sw/device/lib/testing/rstmgr_testutils.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/silicon_creator/lib/base/chip.h"

#include "hw/top_darjeeling/sw/autogen/top_darjeeling.h"

status_t keymgr_dpe_testutils_startup(dif_keymgr_dpe_t *keymgr_dpe,
                                      uint32_t slot_dst_sel) {
  dif_rstmgr_t rstmgr;
  dif_rstmgr_reset_info_bitfield_t info;

  TRY(dif_rstmgr_init(
      mmio_region_from_addr(TOP_DARJEELING_RSTMGR_AON_BASE_ADDR), &rstmgr));
  info = rstmgr_testutils_reason_get();

  // POR reset.
  if (info == kDifRstmgrResetInfoPor) {
    LOG_INFO(
        "Powered up for the first time, lock SECRET2 and SECRET3 partitions");
    dif_otp_ctrl_t otp;
    TRY(dif_otp_ctrl_init(
        mmio_region_from_addr(TOP_DARJEELING_OTP_CTRL_CORE_BASE_ADDR), &otp));
    TRY(otp_ctrl_testutils_lock_partition(&otp, kDifOtpCtrlPartitionSecret2,
                                          0));
    TRY(otp_ctrl_testutils_lock_partition(&otp, kDifOtpCtrlPartitionSecret3,
                                          0));

    // Reboot device.
    rstmgr_testutils_reason_clear();
    LOG_INFO("Triggering software reset");
    TRY(dif_rstmgr_software_device_reset(&rstmgr));

    // Wait here until device reset.
    wait_for_interrupt();

  } else {
    TRY_CHECK(info == kDifRstmgrResetInfoSw, "Unexpected reset reason: %08x",
              info);
    LOG_INFO(
        "Powered up for the second time, actuate keymgr_dpe and perform test.");

    // Initialize keymgr_dpe context.
    TRY(dif_keymgr_dpe_init(
        mmio_region_from_addr(TOP_DARJEELING_KEYMGR_DPE_BASE_ADDR),
        keymgr_dpe));

    // Advance to Initialized state.
    TRY(keymgr_dpe_testutils_check_state(keymgr_dpe, kDifKeymgrDpeStateReset));
    TRY(dif_keymgr_dpe_initialize(keymgr_dpe, slot_dst_sel));
    TRY(keymgr_dpe_testutils_wait_for_operation_done(keymgr_dpe));
    TRY(keymgr_dpe_testutils_check_state(keymgr_dpe,
                                         kDifKeymgrDpeStateAvailable));
    LOG_INFO("UDS is latched.");
  }
  return OK_STATUS();
}

status_t keymgr_dpe_testutils_advance_state(
    const dif_keymgr_dpe_t *keymgr_dpe,
    const dif_keymgr_dpe_advance_params_t *params) {
  TRY(dif_keymgr_dpe_advance_state(keymgr_dpe, params));
  return keymgr_dpe_testutils_wait_for_operation_done(keymgr_dpe);
}

status_t keymgr_dpe_testutils_erase_slot(
    const dif_keymgr_dpe_t *keymgr_dpe,
    const dif_keymgr_dpe_erase_params_t *params) {
  TRY(dif_keymgr_dpe_erase_slot(keymgr_dpe, params));
  return keymgr_dpe_testutils_wait_for_operation_done(keymgr_dpe);
}

status_t keymgr_dpe_testutils_generate(
    const dif_keymgr_dpe_t *keymgr_dpe,
    const dif_keymgr_dpe_generate_params_t *params,
    dif_keymgr_dpe_output_t *key) {
  TRY(dif_keymgr_dpe_generate(keymgr_dpe, params));
  TRY(keymgr_dpe_testutils_wait_for_operation_done(keymgr_dpe));
  TRY(dif_keymgr_dpe_read_output(keymgr_dpe, key));
  return OK_STATUS();
}

status_t keymgr_dpe_testutils_check_state(
    const dif_keymgr_dpe_t *keymgr_dpe,
    const dif_keymgr_dpe_state_t exp_state) {
  dif_keymgr_dpe_state_t act_state;
  TRY(dif_keymgr_dpe_get_state(keymgr_dpe, &act_state));
  TRY_CHECK(act_state == exp_state,
            "KeymgrDPE in unexpected state: %x, expected to be %x", act_state,
            exp_state);
  return OK_STATUS();
}

status_t keymgr_dpe_testutils_wait_for_operation_done(
    const dif_keymgr_dpe_t *keymgr_dpe) {
  dif_keymgr_dpe_status_codes_t status;
  do {
    TRY(dif_keymgr_dpe_get_status_codes(keymgr_dpe, &status));
  } while (status == 0);
  LOG_INFO("keymgr_dpe_status_code: 0x%x", status);
  TRY_CHECK(status == kDifKeymgrDpeStatusCodeIdle, "Unexpected status: %x",
            status);
  return OK_STATUS();
}
