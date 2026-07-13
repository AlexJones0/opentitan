# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def _devbundle_repos(ctx):
    tarball_path = ctx.path(Label("//third_party/devbundle:devbundle.tar.xz"))

    http_archive(
        name = "devbundle",
        urls = ["file:///{}".format(tarball_path)],
        sha256 = "a453cce21a152d2499c3b6b031d52050cd08a16b5ee4acf1736498d6bef573fb",
        build_file = Label("//third_party/devbundle:BUILD.devbundle.bazel"),
    )

devbundle = module_extension(
    implementation = _devbundle_repos,
)
