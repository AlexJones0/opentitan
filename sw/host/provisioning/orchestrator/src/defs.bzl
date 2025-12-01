# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
load("@bazel_skylib//lib:dicts.bzl", "dicts")

# Map provisioning execution targets to tags
# Provisioning FPGA targets
FPGA_TARGETS = [
    "hyper310",
    "cw340",
]

# Provisioning simulation/emulation targets
SIM_TARGETS = [
    "qemu",
]

# ALl provisioning targets (minus silicon)
ALL_TARGETS = FPGA_TARGETS + SIM_TARGETS
