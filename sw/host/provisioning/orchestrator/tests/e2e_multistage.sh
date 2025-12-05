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

cp sw/host/provisioning/orchestrator/src/orchestrator.zip $TEST_TMPDIR

ORCHESTRATOR_PATH=$TEST_TMPDIR/orchestrator.zip

# This script is run by a Bazel sh_test rule, which sets RUNFILES_DIR to point
# at the test's runfiles. However, if RUNFILES_DIR is set, orchestrator.zip will
# inherit its value instead of setting it to the proper directory. This breaks
# runfile resolution, so we unset this variable here.
unset RUNFILES_DIR

if [ "$EXEC_TARGET" == "qemu" ]; then
  # TODO: can I get from runfiles (RUNFILES_DIR) directly instead of unzipping? see e.g. OPENOCD.
  # TODO ^ would play nice with moving all this logic to be in the orchestrator Python as well
  # Extract files to run QEMU from the orchestrator
  qemu_bin="runfiles/+qemu+qemu_opentitan/build/qemu-system-riscv32"
  qemu_rom="runfiles/_main/sw/device/silicon_creator/rom/mask_rom_sim_qemu_base.elf"
  qemu_cfg="runfiles/_main/sw/host/provisioning/orchestrator/src/qemu_base_cfg.ini"
  # TODO comment somewhere: non empty flash image needed to retain state across runs?
  qemu_flash="runfiles/_main/sw/host/provisioning/orchestrator/src/qemu_empty_flash.qemu_bin"
  qemu_otp="runfiles/_main/sw/host/provisioning/orchestrator/src/qemu_base_otp.raw"
  # TODO: change below to /hw/top_earlgrey/sw/util/qemu.sh" on rebase
  qemu_start="runfiles/_main/hw/top_earlgrey/util/qemu.sh"
  unzip -j -o "$ORCHESTRATOR_PATH" "$qemu_bin" "$qemu_rom" "$qemu_cfg" "$qemu_flash" "$qemu_otp" "$qemu_start" -d "$TEST_TMPDIR"

  # Start & daemonize QEMU
  # TODO: document why we need pushd/popd here (QEMU path limits)
  # and thus why we need configurable paths
  pushd "$TEST_TMPDIR"
  export QEMU_BIN="qemu-system-riscv32"
  export QEMU_ROM="mask_rom_sim_qemu_base.elf"
  export QEMU_CONFIG="qemu_base_cfg.ini"
  export QEMU_FLASH="qemu_empty_flash.qemu_bin"
  export QEMU_OTP="qemu_base_otp.raw"
  export QEMU_MONITOR="qemu-monitor"
  export QEMU_RV_DM_JTAG_SOCK="qemu-jtag.sock"
  export QEMU_LC_JTAG_SOCK="qemu-jtag-lc-ctrl.sock"
  # TODO: QEMU log or no?
  export QEMU_LOG="qemu.log"
  #export QEMU_PIDFILE="${TEST_TMPDIR}/qemu.pid"

  mkfifo "$QEMU_LOG" && cat "$QEMU_LOG" &

  # Make the OTP file mutable
  chmod +w "$QEMU_OTP" "$QEMU_FLASH"

  extra_qemu_args=(
    # We don't really care about emulating the OTP write/read delay in QEMU,
    # so shorten them to be almost instant to speed up testing.
    # TODO: even with this it's still really slow. Why?
    "--global" "ot-otp_ot_be.write_ns=10"
    "--global" "ot-otp_ot_be.read_ns=2"
    
    #"--trace" "ot_uart_io_write*" 
    #"--trace" "ot_hmac*"
    #"--trace" "ot_flash*"
    #"--trace" "ot_spi_device*"
    #"--trace" "ot_gpio*"
  )

  echo "Starting QEMU for the Orchestrator..."
  "./qemu.sh" "${extra_qemu_args[@]}"

  popd
  #"${TEST_TMPDIR}/qemu.sh" &
  # TODO: why does this delay logging until the end of the test?

  # Wait until QEMU is daemonized (PID file appears)
  #while [ ! -s "$QEMU_PIDFILE" ]; do sleep 0.05; done

  echo "Finished initializing QEMU"
fi

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

# Exit QEMU
# TODO: check if this actually works or not somehow (maybe exit then spawn again?)
echo "{ \"execute\": \"quit\", \"id\": 0 }" >> $QEMU_MONITOR