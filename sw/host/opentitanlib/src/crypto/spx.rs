// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Write};
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result, anyhow, bail, ensure};
use clap::ValueEnum;
use pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use serde::{Deserialize, Serialize};
use serde_annotate::Annotate;
use strum::{EnumIter, IntoEnumIterator};

use super::Error;
use sphincsplus::{DecodeKey, EncodeKey, SphincsPlus, SpxPublicKey, SpxSecretKey};

/// Formats that can be used to represent SPX (SPHINCS+ or SLH-DSA) keys.
#[derive(
    Default, Debug, Clone, Copy, PartialEq, Eq, ValueEnum, EnumIter, Serialize, Deserialize,
)]
pub enum SpxKeyFormat {
    /// A custom RAW PEM format used by OpenTitan pre-standardization of SLH-DSA.
    /// A legacy format which is used only for SPHINCS+ signing.
    #[default]
    #[serde(rename = "pre-standard")]
    PreStandardPem,
    /// PEM format: PKCS#8 for private keys, and `SubjectPublicKeyInfo` for public keys.
    /// A standard format used for SLH-DSA signing.
    #[serde(rename = "pkcs8-pem")]
    Pkcs8Pem,
    /// DER format: PKCS#8 for private keys, and `SubjectPublicKeyInfo` for public keys.
    /// A standard format used for SLH-DSA signing.
    #[serde(rename = "pkcs8-der")]
    Pkcs8Der,
}

impl std::fmt::Display for SpxKeyFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PreStandardPem => write!(f, "pre-standard"),
            Self::Pkcs8Pem => write!(f, "pkcs8-pem"),
            Self::Pkcs8Der => write!(f, "pkcs8-der"),
        }
    }
}

impl SpxKeyFormat {
    /// Standard file extension for a private key in this format.
    pub fn ext(&self) -> &'static str {
        match self {
            Self::PreStandardPem | Self::Pkcs8Pem => "pem",
            Self::Pkcs8Der => "der",
        }
    }
    /// Standard file extension for a public key in this format.
    pub fn pub_ext(&self) -> String {
        format!("pub.{}", self.ext())
    }

    /// Load a SPHINCS+/SLH-DSA secret key of a known format from its raw bytes.
    pub fn secret_key_from_bytes<'a>(&self, input: &'a [u8]) -> Result<SpxSecretKey> {
        match self {
            Self::PreStandardPem => {
                return SpxSecretKey::from_pem_bytes(input).map_err(|e| anyhow!(e));
            }
            // For standard PKCS8 forms, we first try SHAKE128, and then SHA128.
            // This is not the most efficient approach - a better way would be
            // to manually parse out the OID depending on the format and use
            // to determine the algorithm. This would be much more complicated,
            // however, so we keep things simple here unless deemed necessary.
            Self::Pkcs8Pem => {
                let pem =
                    std::str::from_utf8(input).context("Failed to read PEM contents as UTF-8")?;
                if let Ok(sk) = slh_dsa::SigningKey::<slh_dsa::Shake128s>::from_pkcs8_pem(pem) {
                    return SpxSecretKey::from_bytes(SphincsPlus::Shake128sSimple, &sk.to_bytes())
                        .map_err(|e| anyhow!(e));
                }
                if let Ok(sk) = slh_dsa::SigningKey::<slh_dsa::Sha2_128s>::from_pkcs8_pem(pem) {
                    return SpxSecretKey::from_bytes(SphincsPlus::Sha2128sSimple, &sk.to_bytes())
                        .map_err(|e| anyhow!(e));
                }
            }
            Self::Pkcs8Der => {
                if let Ok(sk) = slh_dsa::SigningKey::<slh_dsa::Shake128s>::from_pkcs8_der(input) {
                    return SpxSecretKey::from_bytes(SphincsPlus::Shake128sSimple, &sk.to_bytes())
                        .map_err(|e| anyhow!(e));
                }
                if let Ok(sk) = slh_dsa::SigningKey::<slh_dsa::Sha2_128s>::from_pkcs8_der(input) {
                    return SpxSecretKey::from_bytes(SphincsPlus::Sha2128sSimple, &sk.to_bytes())
                        .map_err(|e| anyhow!(e));
                }
            }
        };
        bail!("failed to parse SPHINCS+/SLH-DSA secret key in the {self:?} format")
    }

    /// Load a SPHINCS+/SLH-DSA public key of a known format from its raw bytes.
    pub fn public_key_from_bytes<'a>(&self, input: &'a [u8]) -> Result<SpxPublicKey> {
        match self {
            Self::PreStandardPem => {
                return SpxPublicKey::from_pem_bytes(input).map_err(|e| anyhow!(e));
            }
            // For standard PKCS8 forms, we first try SHAKE128, and then SHA128.
            // This is not the most efficient approach - a better way would be
            // to manually parse out the OID depending on the format and use
            // to determine the algorithm. This would be much more complicated,
            // however, so we keep things simple here unless deemed necessary.
            Self::Pkcs8Pem => {
                let pem =
                    std::str::from_utf8(input).context("Failed to read PEM contents as UTF-8")?;
                if let Ok(pk) =
                    slh_dsa::VerifyingKey::<slh_dsa::Shake128s>::from_public_key_pem(pem)
                {
                    return SpxPublicKey::from_bytes(SphincsPlus::Shake128sSimple, &pk.to_bytes())
                        .map_err(|e| anyhow!(e));
                }
                if let Ok(pk) =
                    slh_dsa::VerifyingKey::<slh_dsa::Sha2_128s>::from_public_key_pem(pem)
                {
                    return SpxPublicKey::from_bytes(SphincsPlus::Sha2128sSimple, &pk.to_bytes())
                        .map_err(|e| anyhow!(e));
                }
            }
            Self::Pkcs8Der => {
                if let Ok(pk) =
                    slh_dsa::VerifyingKey::<slh_dsa::Shake128s>::from_public_key_der(input)
                {
                    return SpxPublicKey::from_bytes(SphincsPlus::Shake128sSimple, &pk.to_bytes())
                        .map_err(|e| anyhow!(e));
                }
                if let Ok(pk) =
                    slh_dsa::VerifyingKey::<slh_dsa::Sha2_128s>::from_public_key_der(input)
                {
                    return SpxPublicKey::from_bytes(SphincsPlus::Sha2128sSimple, &pk.to_bytes())
                        .map_err(|e| anyhow!(e));
                }
            }
        };
        bail!("failed to parse SPHINCS+/SLH-DSA public key in the {self:?} format")
    }
}

/// Load a SPHINCS+/SLH-DSA secret key of an unknown format from its raw bytes.
pub fn load_spx_secret_key_from_bytes<'a>(input: &'a [u8]) -> Result<SpxSecretKey> {
    // Simply try the variants in the order: Pre-Standard -> Pem -> Der
    SpxKeyFormat::PreStandardPem
        .secret_key_from_bytes(input)
        .or_else(|_| SpxKeyFormat::Pkcs8Pem.secret_key_from_bytes(input))
        .or_else(|_| SpxKeyFormat::Pkcs8Der.secret_key_from_bytes(input))
        .map_err(|_| anyhow!("failed to parse SPHINCS+/SLH-DSA secret key in any known format"))
}

/// Load a SPHINCS+/SLH-DSA secret key of an unknown format from a file.
pub fn load_spx_secret_key(path: impl AsRef<Path>) -> Result<SpxSecretKey> {
    let path = path.as_ref();
    let data = std::fs::read(path).with_context(|| format!("Failed to read file: {path:?}"))?;
    load_spx_secret_key_from_bytes(&data)
}

// Write a SPHINCS+/SLH-DSA secret key to a given file in the specified format.
pub fn save_spx_secret_key(
    key: &SpxSecretKey,
    path: impl AsRef<Path>,
    format: SpxKeyFormat,
) -> Result<()> {
    let path = path.as_ref();
    match format {
        SpxKeyFormat::PreStandardPem => key.write_pem_file(path).with_context(|| {
            format!("Failed to write pre-standard OpenTitan RAW PEM to {path:?}")
        })?,
        SpxKeyFormat::Pkcs8Pem | SpxKeyFormat::Pkcs8Der => match key.algorithm() {
            SphincsPlus::Shake128sSimple => {
                let sk = slh_dsa::SigningKey::<slh_dsa::Shake128s>::try_from(key.as_bytes())
                    .map_err(|e| anyhow!("Failed to convert to slh_dsa SigningKey: {:?}", e))?;
                match format {
                    SpxKeyFormat::Pkcs8Pem => sk
                        .write_pkcs8_pem_file(path, LineEnding::default())
                        .with_context(|| format!("Failed to write PKCS#8 PEM to {path:?}"))?,
                    SpxKeyFormat::Pkcs8Der => sk
                        .write_pkcs8_der_file(path)
                        .with_context(|| format!("Failed to write PKCS#8 DER to {path:?}"))?,
                    _ => unreachable!(),
                }
            }
            SphincsPlus::Sha2128sSimple => {
                let sk = slh_dsa::SigningKey::<slh_dsa::Sha2_128s>::try_from(key.as_bytes())
                    .map_err(|e| anyhow!("Failed to convert to slh_dsa SigningKey: {:?}", e))?;
                match format {
                    SpxKeyFormat::Pkcs8Pem => sk
                        .write_pkcs8_pem_file(path, LineEnding::default())
                        .with_context(|| format!("Failed to write PKCS#8 PEM to {path:?}"))?,
                    SpxKeyFormat::Pkcs8Der => sk
                        .write_pkcs8_der_file(path)
                        .with_context(|| format!("Failed to write PKCS#8 DER to {path:?}"))?,
                    _ => unreachable!(),
                }
            }
        },
    }
    Ok(())
}

/// Load a SPHINCS+/SLH-DSA public key of an unknown format from its raw bytes.
/// If `fallback` is `true`, then this will attempt to load the file as a secret key
/// (as in [`load_spx_secret_key_from_bytes`]) upon failing to load it as a public key
/// in any known formats. If this is successful, the public key is extracted from the
/// secret key and returned.
pub fn load_spx_public_key_from_bytes<'a>(input: &'a [u8], fallback: bool) -> Result<SpxPublicKey> {
    // Simply try the variants in the order: Pre-Standard -> Pem -> Der
    let loaded_pk = SpxKeyFormat::PreStandardPem
        .public_key_from_bytes(input)
        .or_else(|_| SpxKeyFormat::Pkcs8Pem.public_key_from_bytes(input))
        .or_else(|_| SpxKeyFormat::Pkcs8Der.public_key_from_bytes(input))
        .map_err(|_| anyhow!("failed to parse SPHINCS+/SLH-DSA public key in any known format"));
    if loaded_pk.is_ok() || !fallback {
        return loaded_pk;
    }
    load_spx_secret_key_from_bytes(input)
        .map(|sk| SpxPublicKey::from(&sk))
        .map_err(|_| anyhow!("failed to parse SPHINCS+/SLH-DSA public key in any known format"))
}

/// Load a SPHINCS+/SLH-DSA public key of an unknown format from a file.
/// If `fallback` is `true`, then this will attempt to load the file as a secret key
/// (as in [`load_spx_secret_key`]) upon failing to load it as a public key
/// in any known formats. If this is successful, the public key is extracted from the
/// secret key and returned.
pub fn load_spx_public_key(path: impl AsRef<Path>, fallback: bool) -> Result<SpxPublicKey> {
    let path = path.as_ref();
    let data = std::fs::read(path).with_context(|| format!("Failed to read file: {path:?}"))?;
    load_spx_public_key_from_bytes(&data, fallback)
}

// Write a SPHINCS+/SLH-DSA public key to a given file in the specified format.
pub fn save_spx_public_key(
    key: &SpxPublicKey,
    path: impl AsRef<Path>,
    format: SpxKeyFormat,
) -> Result<()> {
    let path = path.as_ref();
    match format {
        SpxKeyFormat::PreStandardPem => key.write_pem_file(path).with_context(|| {
            format!("Failed to write pre-standard OpenTitan RAW PEM to {path:?}")
        })?,
        SpxKeyFormat::Pkcs8Pem | SpxKeyFormat::Pkcs8Der => match key.algorithm() {
            SphincsPlus::Shake128sSimple => {
                let pk = slh_dsa::VerifyingKey::<slh_dsa::Shake128s>::try_from(key.as_bytes())
                    .map_err(|e| anyhow!("Failed to convert to slh_dsa VerifyingKey: {:?}", e))?;
                match format {
                    SpxKeyFormat::Pkcs8Pem => pk
                        .write_public_key_pem_file(path, LineEnding::default())
                        .with_context(|| format!("Failed to write PKCS#8 PEM to {path:?}"))?,
                    SpxKeyFormat::Pkcs8Der => pk
                        .write_public_key_der_file(path)
                        .with_context(|| format!("Failed to write PKCS#8 DER to {path:?}"))?,
                    _ => unreachable!(),
                }
            }
            SphincsPlus::Sha2128sSimple => {
                let pk = slh_dsa::VerifyingKey::<slh_dsa::Sha2_128s>::try_from(key.as_bytes())
                    .map_err(|e| anyhow!("Failed to convert to slh_dsa VerifyingKey: {:?}", e))?;
                match format {
                    SpxKeyFormat::Pkcs8Pem => pk
                        .write_public_key_pem_file(path, LineEnding::default())
                        .with_context(|| format!("Failed to write PKCS#8 PEM to {path:?}"))?,
                    SpxKeyFormat::Pkcs8Der => pk
                        .write_public_key_der_file(path)
                        .with_context(|| format!("Failed to write PKCS#8 DER to {path:?}"))?,
                    _ => unreachable!(),
                }
            }
        },
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize, Annotate, PartialEq)]
pub struct SpxRawPublicKey {
    #[serde(with = "serde_bytes")]
    #[annotate(format = hexstr)]
    pub key: Vec<u8>,
}

impl Default for SpxRawPublicKey {
    fn default() -> Self {
        Self { key: vec![0; 32] }
    }
}

impl TryFrom<&sphincsplus::SpxPublicKey> for SpxRawPublicKey {
    type Error = Error;
    fn try_from(v: &SpxPublicKey) -> Result<Self, Self::Error> {
        Ok(Self {
            key: v.as_bytes().to_vec(),
        })
    }
}

impl TryFrom<sphincsplus::SpxPublicKey> for SpxRawPublicKey {
    type Error = Error;
    fn try_from(v: SpxPublicKey) -> Result<Self, Self::Error> {
        (&v).try_into()
    }
}

impl FromStr for SpxRawPublicKey {
    type Err = Error;

    // Note: this function is a bit unintuitive - it loads from the file path,
    // not the string contents.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let key = load_spx_public_key(s, true)
            .with_context(|| format!("Failed to load {s}"))
            .map_err(Error::Other)?;
        SpxRawPublicKey::try_from(&key)
    }
}

impl SpxRawPublicKey {
    pub const SIZE: usize = 32;
    pub fn read(src: &mut impl Read) -> Result<Self> {
        let mut key = Self::default();
        key.key.resize(32, 0);
        src.read_exact(&mut key.key)?;
        Ok(key)
    }
    pub fn write(&self, dest: &mut impl Write) -> Result<()> {
        ensure!(
            self.key.len() == Self::SIZE,
            Error::InvalidPublicKey(anyhow!("bad key length: {}", self.key.len()))
        );
        dest.write_all(&self.key)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::util::tmpfilename;
    use sphincsplus::SpxDomain;

    /// A SLH-DSA-SHA2-128s key pair in Opentitan's Pre-Standard RAW PEM format.
    const PRESTANDARD_SK_PEM: &str = "-----BEGIN RAW:SLH_DSA_SHA2_128s PRIVATE KEY-----\n\
        6bjY0UDbmzL4TnTVYwINqOCrxxyGNC8hJXMzKB9WDNfaSaVWNOfNyXSDc9opKeh2\n\
        dNVIlMTKhAWCYUnLhZ0gsw==\n\
        -----END RAW:SLH_DSA_SHA2_128s PRIVATE KEY-----\n";
    const PRESTANDARD_PK_PEM: &str = "-----BEGIN RAW:SLH_DSA_SHA2_128s PUBLIC KEY-----\n\
        2kmlVjTnzcl0g3PaKSnodnTVSJTEyoQFgmFJy4WdILM=\n\
        -----END RAW:SLH_DSA_SHA2_128s PUBLIC KEY-----\n";

    /// A public key with an AlgorithmIdentifier OID of HASHSLH-DSA-SHA2-128s
    /// (2.16.840.1.101.3.4.3.35) as often handed out by HSMs.
    const HSM_SPKI_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
        MDAwCwYJYIZIAWUDBAMjAyEA2kmlVjTnzcl0g3PaKSnodnTVSJTEyoQFgmFJy4Wd\n\
        ILM=\n\
        -----END PUBLIC KEY-----\n";
    const PK_HEX: &str = "da49a55634e7cdc9748373da2929e87674d54894c4ca8405826149cb859d20b3";

    #[test]
    fn test_pre_standard_pem_vectors() -> Result<()> {
        let pk = load_spx_public_key_from_bytes(PRESTANDARD_PK_PEM.as_bytes(), false)?;
        assert_eq!(pk.algorithm(), SphincsPlus::Sha2128sSimple);
        assert_eq!(hex::encode(pk.as_bytes()), PK_HEX);

        // The secret key should contain the public key.
        let sk = load_spx_secret_key_from_bytes(PRESTANDARD_SK_PEM.as_bytes())?;
        assert_eq!(SpxPublicKey::from(&sk), pk);

        // We shouldn't be able to load the public key from the secret key
        // unless the fallthrough option is enabled - in which case we should.
        assert!(load_spx_public_key_from_bytes(PRESTANDARD_SK_PEM.as_bytes(), false).is_err());
        assert_eq!(
            load_spx_public_key_from_bytes(PRESTANDARD_SK_PEM.as_bytes(), true)?,
            pk
        );

        // Test keys in the pre-standard OpenTitan RAW PEM format.
        let legacy =
            |pem: &str| pem.replace("RAW:SLH_DSA_SHA2_128s", "RAW:SPHINCS+_SHA2_128s_simple");
        assert_eq!(
            load_spx_public_key_from_bytes(legacy(PRESTANDARD_PK_PEM).as_bytes(), true)?,
            pk
        );
        assert_eq!(
            load_spx_secret_key_from_bytes(legacy(PRESTANDARD_SK_PEM).as_bytes())?,
            sk
        );

        // A public key must not satisfy a request for a secret key.
        assert!(load_spx_secret_key_from_bytes(PRESTANDARD_PK_PEM.as_bytes()).is_err());
        Ok(())
    }

    #[test]
    fn test_hsm_spki_vector() -> Result<()> {
        let pk = load_spx_public_key_from_bytes(HSM_SPKI_PEM.as_bytes(), false)?;
        assert_eq!(pk.algorithm(), SphincsPlus::Sha2128sSimple);
        assert_eq!(hex::encode(pk.as_bytes()), PK_HEX);

        // The pure SLH-DSA OIDs do not cover this key, so it is the sphincsplus
        // ASN.1 fallback rather than the slh_dsa decoder that accepts it.
        assert!(
            slh_dsa::VerifyingKey::<slh_dsa::Sha2_128s>::from_public_key_pem(HSM_SPKI_PEM).is_err()
        );
        Ok(())
    }

    #[test]
    fn test_spx_format_roundtrip() -> Result<()> {
        for algorithm in [SphincsPlus::Shake128sSimple, SphincsPlus::Sha2128sSimple] {
            let (sk, pk) = SpxSecretKey::new_keypair(algorithm)?;

            for format in SpxKeyFormat::iter() {
                let sk_path = tmpfilename(&format!("test_sk_{:?}.{}", algorithm, format.ext()));
                let pk_path = tmpfilename(&format!("test_pk_{:?}.{}", algorithm, format.pub_ext()));

                save_spx_secret_key(&sk, &sk_path, format)?;
                save_spx_public_key(&pk, &pk_path, format)?;

                let loaded_sk = load_spx_secret_key(&sk_path)?;
                let loaded_pk = load_spx_public_key(&pk_path, false)?;

                assert_eq!(loaded_sk, sk);
                assert_eq!(loaded_pk, pk);

                // Test extracting public key from secret key file, with and without the fallback.
                assert!(load_spx_public_key(&sk_path, false).is_err());
                let extracted_pk = load_spx_public_key(&sk_path, true)?;
                assert_eq!(extracted_pk, pk);
            }
        }
        Ok(())
    }

    #[test]
    fn test_pkcs8_sign_verify() -> Result<()> {
        let algorithm = SphincsPlus::Shake128sSimple;
        let (sk, pk) = SpxSecretKey::new_keypair(algorithm)?;

        let sk_path = tmpfilename("test_pkcs8_sk.der");
        let pk_path = tmpfilename("test_pkcs8_pk.der");

        save_spx_secret_key(&sk, &sk_path, SpxKeyFormat::Pkcs8Der)?;
        save_spx_public_key(&pk, &pk_path, SpxKeyFormat::Pkcs8Der)?;

        let loaded_sk = load_spx_secret_key(&sk_path)?;
        let loaded_pk = load_spx_public_key(&pk_path, false)?;

        let msg = b"OpenTitan SLH-DSA PKCS#8 test message";
        let sig = loaded_sk.sign(SpxDomain::Pure, msg)?;
        loaded_pk.verify(SpxDomain::Pure, &sig, msg)?;
        Ok(())
    }
}
