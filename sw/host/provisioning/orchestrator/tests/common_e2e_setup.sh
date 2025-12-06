# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash

# Common setup/initialization code for the provisioning orchestrator E2E tests
# Copies the orchestrator zip over to the temporary testing directory and
# configures the environment to allow the orchestrator to run.
#
# For environments that require additional environmental setup, this is done
# here (e.g. for QEMU, we must spawn QEMU before running the orchestrator).

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
  qemu_start="runfiles/_main/hw/top_earlgrey/sw/util/qemu.sh"
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
  export QEMU_PIDFILE="${TEST_TMPDIR}/qemu.pid"

  mkfifo "$QEMU_LOG" && cat "$QEMU_LOG" &

  # Make the OTP file and flash mutable
  chmod +w "$QEMU_OTP" "$QEMU_FLASH"

  #mkdir -p /dev/shm/qemu
  #cp "$QEMU_OTP" "/dev/shm/qemu/${QEMU_OTP}"
  #export QEMU_OTP="/dev/shm/qemu/${QEMU_OTP}"
  #cp "$QEMU_FLASH" "/dev/shm/qemu/${QEMU_FLASH}"
  #export QEMU_FLASH="/dev/shm/qemu/${QEMU_FLASH}"

  extra_qemu_args=(
    # Individualization executes a *lot* of instructions in SRAM before flash
    # execution is enabled. When it does so, it does not initialize the SRAM.
    # To emulate SRAM initialization & scrambling QEMU by default will start
    # by using a device IO memory region and dynamically swap it to a regular
    # guest RAM region upon SRAM initialization.
    #
    # Importantly, IO memory ops are *significantly* slower than writes/reads
    # to guest RAM. Essentially, every instruction QEMU executes must be slowly
    # fetched and translated, with no caching, slowing to a crawl. This can
    # generally add a good 3 minutes or so to each E2E orchestrator test.
    #
    # Since we don't care about completely accurate SRAM initialization /
    # scrambling semantics in these tests and we don't initialize SRAM during
    # the manufacturing flow, set an option to always use the faster guest RAM
    # memory region for a very substantial speedup.
    "--global" "ot-sram_ctrl.noinit=true"

    # We aren't too interested in accurately emulating an OTP write/read delay
    # in QEMU compared to benefit of faster testing by removing this delay, so
    # shorten OTP backend cell writes and reads to be near-instant. This helps
    # make test timing a bit more reliable.
    "--global" "ot-otp_ot_be.write_ns=10"
    "--global" "ot-otp_ot_be.read_ns=10"
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
