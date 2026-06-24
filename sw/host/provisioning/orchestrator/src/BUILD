# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@ot_python_deps//:requirements.bzl", "requirement")
load("@rules_python//python:defs.bzl", "py_binary", "py_library")
load("//rules/opentitan:exec_env.bzl", select_bitstream = "bitstream_from_env", select_memory = "memory_from_env")

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

label_flag(
    name = "env",
    build_setting_default = "//hw/bitstream/universal:none",
)

select_bitstream(
    name = "test_bitstream",
    testonly = True,
    exec_env = ":env",
    tags = ["manual"],
)

# Memories to be loaded onto the FPGA after the bitstream is loaded
# to replicate the specified execution environment.
FPGA_LOADED_MEORIES = [
    "rom",
    "otp",
]

[
    label_flag(
        name = memory,
        build_setting_default = ":none",
    )
    for memory in FPGA_LOADED_MEORIES
]


[
    select_memory(
        name = "test_{}".format(memory),
        testonly = True,
        exec_env = ":env",
        src = ":{}".format(memory),
        memory = memory,
        tags = ["manual"],
    )
    for memory in FPGA_LOADED_MEORIES
]

filegroup(
    name = "data_dependencies",
    testonly = True,
    srcs = [
        ":test_bitstream",
        ":test_otp",
        ":test_rom",
        "//sw/device/silicon_creator/manuf/base:ft_personalize_all",
        "//sw/device/silicon_creator/manuf/base:sram_cp_provision",
        "//sw/device/silicon_creator/manuf/base:sram_ft_individualize_all",
        "//sw/device/silicon_creator/manuf/keys:ca_data_all",
        "//sw/host/provisioning/cp",
        "//sw/host/provisioning/ft:ft_all",
        "//sw/host/provisioning/orchestrator/configs/skus:all",
        "//third_party/openocd:jtag_cmsis_dap_adapter_cfg",
        "//third_party/openocd:jtag_ftdi_cfg",
        "//third_party/openocd:jtag_olimex_cfg",
        "//third_party/openocd:openocd_bin",
        "@sc_hsm",
    ],
)

py_binary(
    name = "orchestrator",
    testonly = True,
    srcs = ["orchestrator.py"],
    data = [":data_dependencies"],
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
