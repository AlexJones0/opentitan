#!/usr/bin/env bash

# Run from the root of your OpenTitan repo

export STAGING_DIR=$(mktemp -d)
echo "Carrying out signing ceremony at $STAGING_DIR"

echo "Building HSMtool..."
bazelisk build --stamp //sw/host/hsmtool
cp "$(bazelisk cquery --stamp //sw/host/hsmtool 2>/dev/null | grep 'hsmtool$')" ${STAGING_DIR}/hsmtool

echo "Building OpenSSL..."
bazelisk build --stamp @openssl
cp "$(bazelisk cquery --stamp @openssl 2>/dev/null | head -n 1)" ${STAGING_DIR}/openssl
export OPENSSL=${STAGING_DIR}/openssl

echo "Building SoftHSMv2..."
bazelisk build --stamp @softhsm2//:gen_dir
cp "$(bazelisk cquery --stamp @softhsm2//:gen_dir 2>/dev/null)/lib/softhsm/libsofthsm2.so" ${STAGING_DIR}/libsofthsm2.so
cp "$(bazelisk cquery --stamp @softhsm2//:gen_dir 2>/dev/null)/bin/softhsm2-util" ${STAGING_DIR}/softhsm2-util
export HSMTOOL_MODULE=${STAGING_DIR}/libsofthsm2.so
# We would need to have the below line if we were doing SPHINCS+ signing instead of SLH-DSA
# export HSMTOOL_SPX_MODULE=pkcs11-ef

# Make sure that all of the ECDSA and/or SLH-DSA keys that you want to use for signing are copied across here.
echo "Gathering fake signing keys for SoftHSMv2"
cp sw/device/silicon_creator/rom/keys/fake/ecdsa/prod_key_0_ecdsa_p256.der ${STAGING_DIR}/prod_key_0.der
cp sw/device/silicon_creator/rom/keys/fake/slh_dsa/prod_key_1_slh_dsa.pem ${STAGING_DIR}/prod_key_1.pem

echo "Setting up SoftHSMv2"
cp signing/softhsm/softhsm.conf ${STAGING_DIR}/softhsm.conf
export SOFTHSM2_CONF=${STAGING_DIR}/softhsm.conf
pushd ${STAGING_DIR} >/dev/null # Be careful; softHSMv2 token configuration uses a relative path.
mkdir -p signing/softhsm/tokens
./softhsm2-util --module="${STAGING_DIR}/libsofthsm2.so" --init-token --label fake_keys --so-pin officer_pin --pin 123456 --free
export HSMTOOL_TOKEN=fake_keys
export HSMTOOL_USER=user
export HSMTOOL_PIN=123456

# Make sure that all of the ECDSA and/or SLH-DSA keys that you want to use for signing are imported here, without any overlapping names.
./hsmtool ecdsa import --label prod_key_0 prod_key_0.der
./hsmtool slh-dsa import --label prod_key_1 prod_key_1.pem
popd >/dev/null

echo "Building ROM_EXT & Personalization digests"
bazelisk build --stamp \
    //sw/device/silicon_creator/rom_ext/sival:digests \
    //sw/device/silicon_creator/manuf/base:digests
cp "$(bazelisk cquery --stamp //sw/device/silicon_creator/rom_ext/sival:digests 2>/dev/null)" ${STAGING_DIR}/sival.tar
cp "$(bazelisk cquery --stamp //sw/device/silicon_creator/manuf/base:digests 2>/dev/null)" ${STAGING_DIR}/perso.tar

echo "Sha256sum of the generated digests:"
sha256sum \
    bazel-out/k8-fastbuild/bin/sw/device/silicon_creator/rom_ext/sival/digests.tar \
    bazel-out/k8-fastbuild/bin/sw/device/silicon_creator/manuf/base/digests.tar

echo "Signing the ROM_EXT artifacts..."
pushd ${STAGING_DIR} >/dev/null # Again; softHSMv2 token configuration uses a relative path.
mkdir sival
cd sival
tar xvf ../sival.tar
cp -r ../signing .
../hsmtool exec presigning.json
cd ..

echo "Signing the personalization artifacts..."
mkdir perso
cd perso
tar xvf ../perso.tar
cp -r ../signing .
../hsmtool exec provisioning_sival.json
cd ..

echo "Compiling a tarball of all generated signatures..."
tar cvf signatures.tar */*_sig
popd >/dev/null
cp ${STAGING_DIR}/signatures.tar signatures.tar

echo "Copying the signatures across into the OpenTitan tree..."
rm sw/device/silicon_creator/rom_ext/sival/signatures/*_sig
rm sw/device/silicon_creator/manuf/base/signatures/*_sig
cp ${STAGING_DIR}/sival/*_sig sw/device/silicon_creator/rom_ext/sival/signatures
cp ${STAGING_DIR}/perso/*_sig sw/device/silicon_creator/manuf/base/signatures

echo "Building the final signed binaries, and copying them into the OpenTitan tree..."
bazelisk build --stamp \
    //sw/device/silicon_creator/rom_ext/sival:signed \
    //sw/device/silicon_creator/manuf/base:signed
bazelisk build --stamp \
    //sw/device/silicon_creator/rom_ext/sival/binaries:copy_signed \
    //sw/device/silicon_creator/manuf/base/binaries:copy_signed

echo "Done. Cleaning up $STAGING_DIR..."
rm -rf $STAGING_DIR
echo "Signing ceremony finished."

