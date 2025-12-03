# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@bazel_skylib//rules:common_settings.bzl", "bool_flag")
load("@ot_python_deps//:requirements.bzl", "requirement")
load("@rules_python//python:defs.bzl", "py_binary", "py_library")
load("//rules/opentitan:qemu.bzl", "qemu_cfg", "qemu_otp")

package(default_visibility = ["//visibility:public"])

py_library(
    name = "device_id",
    srcs = ["device_id.py"],
    data = [
        "//sw/host/provisioning/orchestrator/data:products.hjson",
        "//sw/host/provisioning/orchestrator/data/packages:earlgrey_a1.hjson",
        "//sw/host/provisioning/orchestrator/data/packages:earlgrey_a2.hjson",
    ],
    imports = ["."],
    deps = [
        ":sku_config",
        ":util",
        requirement("hjson"),
    ],
)

py_binary(
    name = "devid_header_gen",
    srcs = ["devid_header_gen.py"],
    data = ["//sw/device/silicon_creator/manuf/keys:ca_data_all"],
    imports = ["."],
    deps = [
        ":device_id",
        ":sku_config",
        requirement("hjson"),
        requirement("mako"),
    ],
)

py_library(
    name = "ca_config",
    srcs = ["ca_config.py"],
)

py_library(
    name = "db",
    srcs = ["db.py"],
    imports = ["."],
    deps = [
        ":ot_dut",
    ],
)

py_library(
    name = "sku_config",
    srcs = ["sku_config.py"],
    data = [
        "//sw/host/provisioning/orchestrator/data:products.hjson",
        "//sw/host/provisioning/orchestrator/data/packages:earlgrey_a1.hjson",
        "//sw/host/provisioning/orchestrator/data/packages:earlgrey_a2.hjson",
    ],
    deps = [
        ":ca_config",
        ":util",
        requirement("hjson"),
    ],
)

py_library(
    name = "util",
    srcs = ["util.py"],
    imports = ["."],
    deps = [
        requirement("hjson"),
        "@rules_python//python/runfiles",
    ],
)

py_library(
    name = "ot_dut",
    srcs = ["ot_dut.py"],
    imports = ["."],
    deps = [
        ":device_id",
        ":sku_config",
        ":util",
    ],
)

filegroup(
    name = "data_dependencies",
    testonly = True,
    srcs = [
        "//hw/bitstream/universal:splice",
        "//sw/device/silicon_creator/manuf/base:ft_personalize_all",
        "//sw/device/silicon_creator/manuf/base:sram_cp_provision",
        "//sw/device/silicon_creator/manuf/base:sram_ft_individualize_all",
        "//sw/device/silicon_creator/manuf/keys:ca_data_all",
        "//sw/host/provisioning/cp",
        "//sw/host/provisioning/ft:ft_all",
        "//sw/host/provisioning/orchestrator/configs/skus:all",
        "//third_party/openocd:jtag_cmsis_dap_adapter_cfg",
        "//third_party/openocd:jtag_olimex_cfg",
        "//third_party/openocd:openocd_bin",
        "@sc_hsm",
    ],
)

# Generated QEMU configurations and OTP files for the orchestrator zip to be able to run QEMU
qemu_cfg(
    name = "qemu_base_cfg",
    lc_sv = "//hw/ip/lc_ctrl:rtl/lc_ctrl_state_pkg.sv",
    otp_sv = "//hw/ip/otp_ctrl:rtl/otp_ctrl_part_pkg.sv",
    top_hjson = "//hw/top_earlgrey/data:autogen/top_earlgrey.gen.hjson",
    top_name = "earlgrey",
)

qemu_otp(
    name = "qemu_base_otp",
    vmem = "//hw/ip/otp_ctrl/data/earlgrey_skus/emulation:otp_img_test_unlocked0_manuf_empty",
)

filegroup(
    name = "qemu_data_dependencies",
    testonly = True,
    srcs = [
        ":data_dependencies",
        ":qemu_base_cfg",
        ":qemu_base_otp",
        "//hw/top_earlgrey/util:qemu_start",
        "//third_party/qemu:qemu-system-riscv32",
    ],
)

bool_flag(
    name = "include_qemu_dependencies",
    build_setting_default = False,
)

config_setting(
    name = "with_qemu_dependencies",
    flag_values = {
        ":include_qemu_dependencies": "True",
    },
)

py_binary(
    name = "orchestrator",
    testonly = True,
    srcs = ["orchestrator.py"],
    data = select({
        ":with_qemu_dependencies": [":qemu_data_dependencies"],
        "//conditions:default": [":data_dependencies"],
    }),
    imports = ["."],
    deps = [
        ":db",
        ":device_id",
        ":ot_dut",
        ":sku_config",
        ":util",
        requirement("hjson"),
    ],
)

filegroup(
    name = "orchestrator.zip",
    testonly = True,
    srcs = [":orchestrator"],
    output_group = "python_zip_file",
)
