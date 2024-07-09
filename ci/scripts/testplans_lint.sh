#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

# Use json schema to lint testplan hjson files for correct formatting.

set -e

testplan_lint_cmd="util/lint_testplan.py"
dirs_with_testplan_files=(
    "hw/top_earlgrey/data"
    "hw/top_earlgrey/data/ip"
)
testplan_schema="hw/lint/sival_testplan_schema.hjson"

for dir in "${dirs_with_testplan_files[@]}"; do
    $testplan_lint_cmd --dir "$dir" --schema "$testplan_schema" || {
        echo -n "##vso[task.logissue type=error]"
        echo "Failed testplan lint in ${dir}."
        exit 1
    }
done

exit 0
