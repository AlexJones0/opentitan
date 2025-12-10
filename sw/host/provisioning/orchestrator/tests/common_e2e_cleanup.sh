# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash

# Common cleanup/finalization code for the provisioning orchestrator E2E tests

if [ "$EXEC_TARGET" == "qemu" ]; then
    # Send a "quit" command to QEMU now that we are finished testing.
    pushd "$TEST_TMPDIR"
    {
      echo '{ "execute": "qmp_capabilities" }'
      sleep 0.2  # Wait a short time for QEMU to process the command
      echo '{ "execute": "quit", "id": 0 }'
    } | nc -NU "$QEMU_MONITOR"
    popd
fi
