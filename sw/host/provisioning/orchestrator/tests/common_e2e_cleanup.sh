# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash

# Common cleanup/finalization code for the provisioning orchestrator E2E tests

# Exit QEMU
# TODO: check if this actually works or not somehow (maybe exit then spawn again?)
if [ "$EXEC_TARGET" == "qemu" ]; then
    echo "{ \"execute\": \"quit\", \"id\": 0 }" >> $QEMU_MONITOR
    # Kill the QEMU DAEMON PID? DO this in a trap handler in the startup?
fi
