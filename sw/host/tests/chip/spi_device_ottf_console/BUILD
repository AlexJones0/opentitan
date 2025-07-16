# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@rules_rust//rust:defs.bzl", "rust_binary")

package(default_visibility = ["//visibility:public"])

rust_binary(
    name = "bitbanged_spi",
    srcs = [
        "src/bitbanged_spi.rs",
        "src/common.rs",
    ],
    crate_root = "src/bitbanged_spi.rs",
    deps = [
        "//sw/host/opentitanlib",
        "@crate_index//:anyhow",
        "@crate_index//:clap",
        "@crate_index//:humantime",
        "@crate_index//:log",
        "@crate_index//:object",
        "@crate_index//:regex",
    ],
)

rust_binary(
    name = "spi_device_ottf_console",
    srcs = [
        "src/common.rs",
        "src/ottf_console.rs",
    ],
    crate_root = "src/ottf_console.rs",
    deps = [
        "//sw/host/opentitanlib",
        "@crate_index//:anyhow",
        "@crate_index//:clap",
        "@crate_index//:humantime",
        "@crate_index//:log",
        "@crate_index//:object",
        "@crate_index//:regex",
    ],
)
