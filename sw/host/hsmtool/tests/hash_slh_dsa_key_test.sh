#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -uo pipefail
source sw/host/hsmtool/tests/test_lib.sh

shopt -s nocasematch

# Each input key should be a PEM encoded SLH-DSA key, where the algorithm OID
# stored in the ASN.1 object (either a PKCS#8 OneAsymmetricKey or a RFC7468
# SubjectPublicKeyInfo) is a Hash-SLH-DSA variant. We test that such keys
# are supported by hsmtool.
index=0
for key in "$@"; do
    ((index++))

    if [ ! -f "$key" ]; then
        echo "Error: $key is not a valid key file."
        exit 1
    fi

    # Check that OpenSSL actually recognizes this key as an SLH-DSA key
    openssl_object_id=$(
        run ${OPENSSL} asn1parse -in "$key" --strictpem \
        | grep -m 1 "OBJECT" \
        | awk -F: '{print $NF}'
    )
    hash_slh_dsa_alg="SLH-DSA-SHA*-128s-WITH-SHA*"
    if [[ "$openssl_object_id" != $hash_slh_dsa_alg ]]; then
        echo "Error: $key is not recognized as a small 128-bit security HashSLH-DSA key."
        exit 1
    fi

    # Check that hsmtool also recognizes this key as an SLH-DSA key
    hsmtool_output=$(run ${HSMTOOL} slh-dsa import --label="hash-slh-dsa-$index" "$key" 2>&1)
    if [ "$?" -eq 1 ]; then
        invalid_key_err="*Invalid*Key*"
        if [[ "$hsmtool_output" == $invalid_key_err ]]; then
            echo "Error: $key is incorrectly recognized as invalid by hsmtool."
        else
            echo "Error: $key produces an unexpected error when given to hsmtool."
        fi
        exit 1
    fi

done

shopt -u nocasematch
