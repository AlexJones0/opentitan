#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

# Test Description:
#
# This tests running the CP stage first, then running CP + FT stages later to
# test the scenario where a chip is provisioned to TEST_LOCKED0 state in a
# secure site, and then transported to another secure site where it is further
# provisioned into a mission mode state (by runnning CP + FT stages, where this
# time the CP stage is skipped by the host test program and only the FT stage
# is effectively run).

set -ex

source sw/host/provisioning/orchestrator/tests/common_e2e_setup.sh

# Run tool in CP-only mode first. The path to the --sku-config parameter is
# relative to the runfiles-dir.
$PYTHON ${ORCHESTRATOR_PATH} \
  --sku-config=sw/host/provisioning/orchestrator/configs/skus/emulation.hjson \
  --test-unlock-token="0x11111111_11111111_11111111_11111111" \
  --test-exit-token="0x22222222_22222222_22222222_22222222" \
  --exec-target=${EXEC_TARGET} \
  --non-interactive \
  --cp-only \
  --db-path=$TEST_TMPDIR/registry.sqlite

# Run tool (CP + FT will both attempt to execute). We do not clear the bitstream
# when executing CP mode as we want to simulate a chip that has already had CP
# run, but just needs to run FT.
$PYTHON ${ORCHESTRATOR_PATH} \
  --sku-config=sw/host/provisioning/orchestrator/configs/skus/emulation.hjson \
  --test-unlock-token="0x11111111_11111111_11111111_11111111" \
  --test-exit-token="0x22222222_22222222_22222222_22222222" \
  --exec-target=${EXEC_TARGET} \
  --fpga-dont-clear-bitstream \
  --non-interactive \
  --db-path=$TEST_TMPDIR/registry.sqlite

source sw/host/provisioning/orchestrator/tests/common_e2e_cleanup.sh
