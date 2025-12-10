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

# These test scripts are run by a Bazel sh_test rule, which sets RUNFILES_DIR to
# point at the test's runfiles. However, with RUNFILES_DIR set, orchestrator.zip
# will inherit its value instead of setting it to the proper directory. This
# breaks runfile resolution, so we unset this variable here.
unset RUNFILES_DIR

if [ "$EXEC_TARGET" == "qemu" ]; then

  # Extract runfiles for starting QEMU from the orchestrator zip
  qemu_bin="runfiles/+qemu+qemu_opentitan/build/qemu-system-riscv32"
  qemu_rom="runfiles/_main/sw/device/silicon_creator/rom/mask_rom_sim_qemu_base.elf"
  qemu_cfg="runfiles/_main/sw/host/provisioning/orchestrator/src/qemu_base_cfg.ini"
  qemu_otp="runfiles/_main/sw/host/provisioning/orchestrator/src/qemu_base_otp.raw"
  qemu_start="runfiles/_main/hw/top_earlgrey/sw/util/qemu.sh"
  qemu_runfiles=( "$qemu_bin" "$qemu_rom" "$qemu_cfg" "$qemu_otp" "$qemu_start" )
  unzip -j -o "$ORCHESTRATOR_PATH" "${qemu_runfiles[@]}" -d "$TEST_TMPDIR"

  # Start and daemonize a QEMU instance to provision with the orchestrator.
  # We spawn all sockets / PTYs in the tmpdir to find later, changing directory
  # to ensure that the relative paths are all <= ~100 chars, below the max socket
  # path length supported for Unix sockets.
  pushd "$TEST_TMPDIR"
  export QEMU_BIN=$(basename "$qemu_bin")
  export QEMU_ROM=$(basename "$qemu_rom")
  export QEMU_CONFIG=$(basename "$qemu_cfg")
  export QEMU_OTP=$(basename "$qemu_otp")
  export QEMU_MONITOR="qemu-monitor.sock"
  export QEMU_GPIO_SOCK="qemu-gpio.sock"
  export QEMU_RV_DM_JTAG="qemu-jtag.sock"
  export QEMU_LC_JTAG="qemu-jtag-lc-ctrl.sock"

  # Setup QEMU log output for debugging the tests
  export QEMU_LOG="qemu.log"
  mkfifo "$QEMU_LOG" && cat "$QEMU_LOG" &

  # Ensure the backing OTP file is mutable
  chmod +w "$QEMU_OTP"

  # Add additional QEMU arguments for orchestrator E2E tests
  extra_qemu_args=(
    # Individualization executes a *lot* of instructions in SRAM before flash
    # execution is enabled, and it does so before initializing the SRAM to
    # avoid SRAM scrambling. To emulate SRAM initialization & scrambling, QEMU
    # will by default start emulating a device IO memory region and dynamically
    # swap this to a regular guest RAM region upon initialization via an alias.
    #
    # Importantly, device IO memory ops are *significantly* slower than writes
    # to / reads from guest RAM. Essentially, every instruction QEMU executes
    # must be naively fetched and translated, with no caching or translation
    # optimization. This often adds 3-5 minutes to each E2E orchestrator test.
    #
    # Since we don't care about having completely accurate SRAM initialization
    # and scrambling semantics in QEMU for these tests, and we don't initialize
    # SRAM until the very end of the provisioning flow, we configure QEMU to
    # always use the faster guest RAM memory region for a significant speedup.
    "--global" "ot-sram_ctrl.noinit=true"

    # We aren't too interested in accurately emulating an OTP write/read delay
    # in QEMU compared to benefit of faster testing by removing this delay, so
    # shorten OTP backend cell writes and reads to be near-instant. This helps
    # make test timing a bit more reliable.
    "--global" "ot-otp_ot_be.write_ns=10"
    "--global" "ot-otp_ot_be.read_ns=10"
  )

  echo "Starting QEMU for the Orchestrator..."
  $(basename "$qemu_start") "${extra_qemu_args[@]}"
  popd

  echo "Finished initializing QEMU"
fi
