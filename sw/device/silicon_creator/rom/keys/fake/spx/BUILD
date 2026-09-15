# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("//rules:signing.bzl", "keyset")

package(default_visibility = ["//visibility:public"])

keyset(
    name = "spx_keyset",
    build_setting_default = "",
    keys = {
        "test_key_0_spx.pem": "test_key_0:legacy=True",
        "dev_key_0_spx.pem": "dev_key_0:legacy=True",
        "prod_key_0_spx.pem": "prod_key_0:legacy=false",
        "prod_key_1_spx.pem": "prod_key_1:legacy=false",
    },
    profile = "local",
    tool = "//signing/tokens:local",
)
