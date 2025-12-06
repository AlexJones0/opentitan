# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@rules_python//python:defs.bzl", "py_test")
load(
    "//sw/device/silicon_creator/manuf/base:provisioning_inputs.bzl",
    "EARLGREY_SKUS",
)
load(
    "//sw/host/provisioning/orchestrator/src:defs.bzl",
    "ALL_TARGETS",
    "FPGA_TARGETS",
    "SIM_TARGETS",
)
load(
    "//sw/host/provisioning/orchestrator/tests:transition.bzl",
    "orchestrator_cw340_test_settings_transition",
    "orchestrator_hyper310_test_settings_transition",
    "orchestrator_qemu_test_settings_transition",
)
load("@bazel_skylib//lib:dicts.bzl", "dicts")
load("@ot_python_deps//:requirements.bzl", "requirement")

package(default_visibility = ["//visibility:public"])

py_test(
    name = "db_test",
    srcs = ["db_test.py"],
    deps = [
        "//sw/host/provisioning/orchestrator/src:db",
    ],
)

py_test(
    name = "device_id_test",
    srcs = ["device_id_test.py"],
    data = [
        "//sw/device/silicon_creator/manuf/keys/fake:dice_ca.pem",
        "//sw/device/silicon_creator/manuf/keys/fake:ext_ca.pem",
        "//sw/device/silicon_creator/manuf/keys/fake:rma_unlock_enc_rsa3072.pub.der",
        "//sw/device/silicon_creator/manuf/keys/fake:sk.pkcs8.der",
        "//sw/host/provisioning/orchestrator/configs/skus:emulation.hjson",
    ],
    deps = [
        requirement("hjson"),
        "//sw/host/provisioning/orchestrator/src:device_id",
        "//sw/host/provisioning/orchestrator/src:sku_config",
        "//sw/host/provisioning/orchestrator/src:util",
    ],
)

py_test(
    name = "util_test",
    srcs = ["util_test.py"],
    data = [
        "//sw/device/silicon_creator/manuf/keys/fake:dice_ca.pem",
        "//third_party/openocd:jtag_cmsis_dap_adapter_cfg",
    ],
    deps = [
        "//sw/host/provisioning/orchestrator/src:util",
    ],
)

# These transitions have the same effect as supplying the following flags to bazel test:
#  --//hw/bitstream/universal:env=//hw/top_earlgrey:fpga_<fpga>_rom_with_fake_keys
#  --//hw/bitstream/universal:otp=//hw/ip/otp_ctrl/data/earlgrey_skus/emulation:otp_img_test_unlocked0_manuf_empty
orchestrator_hyper310_test_settings_transition(
    name = "orchestrator_hyper310_zip",
    testonly = True,
    target = "//sw/host/provisioning/orchestrator/src:orchestrator.zip",
)

orchestrator_cw340_test_settings_transition(
    name = "orchestrator_cw340_zip",
    testonly = True,
    target = "//sw/host/provisioning/orchestrator/src:orchestrator.zip",
)

# These transitions
# This transition has the same effect as supplying the following flags to bazel test:
#  --//sw/host/provisioning/orchestrator/src:include_qemu_dependencies=True
# which will include the dependencies for testing with QEMU in the orchestrator zip
orchestrator_qemu_test_settings_transition(
    name = "orchestrator_qemu_zip",
    testonly = True,
    target = "//sw/host/provisioning/orchestrator/src:orchestrator.zip",
)

sh_library(
    name = "e2e_test_lib",
    srcs = [
        "common_e2e_cleanup.sh",
        "common_e2e_setup.sh",
    ],
)

E2E_TEST_DATA = {
    exec_target: {
        # TODO: QEMU OTP is currently slow, making these take a very long time
        "timeout": "eternal" if exec_target == "qemu" else "moderate",
        "data": [
            ":orchestrator_{}_zip".format(exec_target),
            "@python3",
        ],
        "env": {
            "PYTHON": "$(location @python3//:python3)",
            "EXEC_TARGET": "{}".format(exec_target),
        },
        "tags": [
            exec_target,
            "manuf",
        ] + ([
            "changes_otp",
            "exclusive",
        ] if exec_target in FPGA_TARGETS else []),
        "deps": [":e2e_test_lib"],
    }
    for exec_target in ALL_TARGETS
}

[
    sh_test(
        name = "e2e_{}_option_flags_test".format(exec_target),
        timeout = test_data["timeout"],
        srcs = ["e2e_option_flags.sh"],
        data = test_data["data"] + [
            "@//sw/host/provisioning/orchestrator/configs/skus:emulation.hjson",
        ],
        env = dicts.add(
            test_data["env"],
            {"PACKAGE": "npcr12"},
        ),
        tags = test_data["tags"],
        deps = test_data["deps"],
    )
    for exec_target, test_data in E2E_TEST_DATA.items()
]

[
    sh_test(
        name = "e2e_{}_multistage_test".format(exec_target),
        timeout = test_data["timeout"],
        srcs = ["e2e_multistage.sh"],
        data = test_data["data"],
        env = test_data["env"],
        tags = test_data["tags"],
        deps = test_data["deps"],
    )
    for exec_target, test_data in E2E_TEST_DATA.items()
]

[
    sh_test(
        name = "e2e_{}_ate_individ_test".format(exec_target),
        timeout = test_data["timeout"],
        srcs = ["e2e_ate_individ.sh"],
        data = test_data["data"] + [
            "@//sw/host/provisioning/orchestrator/configs/skus:emulation.hjson",
        ],
        env = dicts.add(
            test_data["env"],
            {"PACKAGE": "npcr12"},
        ),
        tags = test_data["tags"],
        deps = test_data["deps"],
    )
    for exec_target, test_data in E2E_TEST_DATA.items()
]

[
    sh_test(
        name = "e2e_{}_{}_test".format(sku, exec_target),
        timeout = test_data["timeout"],
        srcs = ["e2e.sh"],
        data = test_data["data"] + [cfg["orchestrator_cfg"]],
        env = dicts.add(
            test_data["env"],
            {"SKU_CONFIG_PATH": "$(location {})".format(cfg["orchestrator_cfg"])},
        ),
        tags = test_data["tags"] + ([
            "manual",
        ] if cfg.get("offline", False) else []),
        deps = test_data["deps"],
    )
    for sku, cfg in EARLGREY_SKUS.items()
    for exec_target, test_data in E2E_TEST_DATA.items()
]

[
    test_suite(
        name = "e2e_{}".format(exec_target),
        tags = ["manual"],
        tests = [
            ":e2e_{}_{}_test".format(sku, exec_target)
            for sku, config in EARLGREY_SKUS.items()
            if not config.get("offline", False)
        ],
    )
    for exec_target in ALL_TARGETS
]

[
    test_suite(
        name = "e2e_including_offline_{}".format(exec_target),
        tags = ["manual"],
        tests = [
            ":e2e_{}_{}_test".format(sku, exec_target)
            for sku in EARLGREY_SKUS.keys()
        ],
    )
    for exec_target in ALL_TARGETS
]
