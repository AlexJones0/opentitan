#!/usr/bin/env bash

# Make the gen-otp-img.py file dirty so Bazel reruns the script
echo " " >>util/design/gen-otp-img.py

# Find otp images for Earlgrey, build them ,and retrieve the cpuctrl value from the logs
./bazelisk.sh query "kind('.*otp_image rule', //...)" --//hw/top=earlgrey 2>/dev/null | grep -v "darjeeling" | xargs ./bazelisk.sh build 2>/dev/null | grep "cpuctrl value"
