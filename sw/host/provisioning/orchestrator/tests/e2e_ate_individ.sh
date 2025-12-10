#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

# Test Description:
#
# This tests fuly provisioning an OpenTitan chip by executing both CP and FT
# stages in a single execution of the orchestrator script, using the FT
# individualization binary compiled for the ATE environment (i.e., with no SPI
# console communication).

set -ex

source sw/host/provisioning/orchestrator/tests/common_e2e_setup.sh

# Run tool. The path to the --sku-config parameter is relative to the
# runfiles-dir. Note: "use-ext-clk" flag on FPGA does nothing, but this tests
# the flag can be piped through to the test harness.
$PYTHON ${ORCHESTRATOR_PATH} \
  --sku-config=sw/host/provisioning/orchestrator/configs/skus/emulation.hjson \
  --test-unlock-token="0x11111111_11111111_11111111_11111111" \
  --test-exit-token="0x22222222_22222222_22222222_22222222" \
  --exec-target=${EXEC_TARGET} \
  --use-ate-individ-bin \
  --log-ujson-payloads \
  --non-interactive \
  --db-path=$TEST_TMPDIR/registry.sqlite

source sw/host/provisioning/orchestrator/tests/common_e2e_cleanup.sh
