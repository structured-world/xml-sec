//! Signature verification helpers for XMLDSig.
//!
//! This module covers RSA PKCS#1 v1.5, DSA-SHA1, and ECDSA verification,
//! including donor P-521 interoperability under the XMLDSig `ecdsa-sha384` URI.
//!
//! Input public keys are accepted in SubjectPublicKeyInfo (SPKI) form because
//! that is how the vendored PEM fixtures are stored.
//! - RSA keys are parsed from full SPKI DER (`PUBLIC KEY`) and verified via
//!   RustCrypto `rsa::pkcs1v15`.
//! - ECDSA keys are validated as uncompressed SEC1 points from the SPKI bit
//!   string and verified with RustCrypto curve crates (`p256`/`p384`/`p521`).

use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use p384::ecdsa::{Signature as P384Signature, VerifyingKey as P384VerifyingKey};
use p521::ecdsa::{Signature as P521Signature, VerifyingKey as P521VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::hazmat::PrehashVerifier;
use rsa::{
    pkcs1v15::{Signature as RsaPkcs1v15Signature, VerifyingKey as RsaVerifyingKey},
    traits::PublicKeyParts,
};
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use signature::Verifier;
use x509_parser::prelude::FromDer;
use x509_parser::public_key::{ECPoint, PublicKey};
use x509_parser::x509::SubjectPublicKeyInfo;

use super::parse::SignatureAlgorithm;
use crate::policy::EcdsaSignatureValueEncoding;

pub(crate) fn signature_value_matches_algorithm(
    algorithm: SignatureAlgorithm,
    signature_value: &[u8],
) -> bool {
    signature_value_matches_algorithm_with_encoding(
        algorithm,
        signature_value,
        EcdsaSignatureValueEncoding::XmlDsig,
    )
}

pub(crate) fn signature_value_matches_algorithm_with_encoding(
    algorithm: SignatureAlgorithm,
    signature_value: &[u8],
    encoding: EcdsaSignatureValueEncoding,
) -> bool {
    match algorithm {
        SignatureAlgorithm::DsaSha1 => signature_value.len() == 40,
        SignatureAlgorithm::DsaSha256 => signature_value.len() == 64,
        SignatureAlgorithm::HmacSha1
        | SignatureAlgorithm::HmacSha224
        | SignatureAlgorithm::HmacSha256
        | SignatureAlgorithm::HmacSha384
        | SignatureAlgorithm::HmacSha512 => algorithm
            .hmac_output_bits()
            .is_some_and(|bits| (1..=bits / 8).contains(&signature_value.len())),
        // Opaque custom keys expose no modulus here, so the default can enforce
        // only non-empty framing under the absolute ceiling. Built-in keys
        // override this with the exact modulus width.
        SignatureAlgorithm::RsaSha1
        | SignatureAlgorithm::RsaSha224
        | SignatureAlgorithm::RsaSha256
        | SignatureAlgorithm::RsaSha384
        | SignatureAlgorithm::RsaSha512 => {
            (1..=crate::hard_limits::RSA_MODULUS_BIT_CEILING / 8).contains(&signature_value.len())
        }
        SignatureAlgorithm::EcdsaSha1
        | SignatureAlgorithm::EcdsaSha224
        | SignatureAlgorithm::EcdsaSha256
        | SignatureAlgorithm::EcdsaSha384
        | SignatureAlgorithm::EcdsaSha512 => {
            [32, 48, 66]
                .into_iter()
                .any(|component_len| match encoding {
                    EcdsaSignatureValueEncoding::XmlDsig => {
                        signature_value.len() == component_len * 2
                    }
                    EcdsaSignatureValueEncoding::XmlSecAsn1Der => {
                        inspect_der_encoded_ecdsa_signature(signature_value, component_len)
                            .is_ok_and(|value| value.is_some())
                    }
                })
        }
    }
}

pub(crate) fn signature_value_matches_spki(
    algorithm: SignatureAlgorithm,
    public_key_spki_der: &[u8],
    signature_value: &[u8],
) -> Result<bool, SignatureVerificationError> {
    signature_value_matches_spki_with_encoding(
        algorithm,
        public_key_spki_der,
        signature_value,
        EcdsaSignatureValueEncoding::XmlDsig,
    )
}

pub(crate) fn signature_value_matches_spki_with_encoding(
    algorithm: SignatureAlgorithm,
    public_key_spki_der: &[u8],
    signature_value: &[u8],
    encoding: EcdsaSignatureValueEncoding,
) -> Result<bool, SignatureVerificationError> {
    let (rest, spki) = SubjectPublicKeyInfo::from_der(public_key_spki_der)
        .map_err(|_| SignatureVerificationError::InvalidKeyDer)?;
    if !rest.is_empty() {
        return Err(SignatureVerificationError::InvalidKeyDer);
    }
    let public_key = spki
        .parsed()
        .map_err(|_| SignatureVerificationError::InvalidKeyDer)?;

    match (algorithm, public_key) {
        (SignatureAlgorithm::DsaSha1, PublicKey::DSA(_)) => Ok(signature_value.len() == 40),
        (SignatureAlgorithm::DsaSha256, PublicKey::DSA(_)) => Ok(signature_value.len() == 64),
        (
            SignatureAlgorithm::RsaSha1
            | SignatureAlgorithm::RsaSha224
            | SignatureAlgorithm::RsaSha256
            | SignatureAlgorithm::RsaSha384
            | SignatureAlgorithm::RsaSha512,
            PublicKey::RSA(_),
        ) => {
            let key = rsa::RsaPublicKey::from_public_key_der(public_key_spki_der)
                .map_err(|_| SignatureVerificationError::InvalidKeyDer)?;
            Ok(signature_value.len() == key.size())
        }
        (
            SignatureAlgorithm::EcdsaSha1
            | SignatureAlgorithm::EcdsaSha224
            | SignatureAlgorithm::EcdsaSha256
            | SignatureAlgorithm::EcdsaSha384
            | SignatureAlgorithm::EcdsaSha512,
            PublicKey::EC(ec),
        ) => {
            validate_ec_public_key_encoding(&ec, &spki.subject_public_key.data)?;
            let (_, component_len) = ecdsa_curve_and_component_len(&spki, &ec)?;
            match encoding {
                EcdsaSignatureValueEncoding::XmlDsig
                    if signature_value.len() == component_len * 2 => {}
                EcdsaSignatureValueEncoding::XmlSecAsn1Der
                    if inspect_der_encoded_ecdsa_signature(signature_value, component_len)?
                        .is_some() => {}
                _ => return Err(SignatureVerificationError::InvalidSignatureFormat),
            }
            Ok(true)
        }
        (
            SignatureAlgorithm::HmacSha1
            | SignatureAlgorithm::HmacSha224
            | SignatureAlgorithm::HmacSha256
            | SignatureAlgorithm::HmacSha384
            | SignatureAlgorithm::HmacSha512,
            _,
        ) => Err(SignatureVerificationError::KeyAlgorithmMismatch {
            uri: algorithm.uri().to_owned(),
        }),
        _ => Err(SignatureVerificationError::KeyAlgorithmMismatch {
            uri: algorithm.uri().to_owned(),
        }),
    }
}

/// Errors while preparing or running XMLDSig signature verification.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignatureVerificationError {
    /// The provided PEM block could not be parsed as PEM input.
    #[error("invalid PEM public key")]
    InvalidKeyPem,

    /// The signature method is not an RSA PKCS#1 v1.5 algorithm.
    #[error("unsupported signature algorithm: {uri}")]
    UnsupportedAlgorithm {
        /// XMLDSig algorithm URI used for diagnostics.
        uri: String,
    },

    /// The provided PEM block was not a public key.
    #[error("invalid key format: expected PUBLIC KEY PEM, got {label}")]
    InvalidKeyFormat {
        /// The PEM label that was actually supplied.
        label: String,
    },

    /// The provided DER bytes were not a valid SPKI-encoded public key.
    #[error("invalid SubjectPublicKeyInfo DER")]
    InvalidKeyDer,

    /// A structurally valid key violates the active key-strength policy.
    #[error("verification key rejected by policy: {0}")]
    KeyPolicy(#[from] crate::policy::PolicyViolation),

    /// The provided public key does not match the signature algorithm.
    #[error("public key does not match signature algorithm: {uri}")]
    KeyAlgorithmMismatch {
        /// XMLDSig algorithm URI used for diagnostics.
        uri: String,
    },

    /// The provided ECDSA signature bytes do not use the encoding selected by
    /// the active verification policy.
    #[error("invalid ECDSA signature encoding")]
    InvalidSignatureFormat,
}

/// Verify an RSA XMLDSig signature using a PEM-encoded SPKI public key.
///
/// The PEM must contain a `PUBLIC KEY` block. Returns `Ok(false)` for signature
/// mismatch and `Err` for algorithm/key preparation errors.
#[must_use = "discarding the verification result skips signature validation"]
pub fn verify_rsa_signature_pem(
    algorithm: SignatureAlgorithm,
    public_key_pem: &str,
    signed_data: &[u8],
    signature_value: &[u8],
) -> Result<bool, SignatureVerificationError> {
    let public_key_spki_der = parse_public_key_pem(public_key_pem)?;
    verify_rsa_signature_spki(
        algorithm,
        &public_key_spki_der,
        signed_data,
        signature_value,
    )
}

/// Verify an ECDSA XMLDSig signature using a PEM-encoded SPKI public key.
///
/// The PEM must contain a `PUBLIC KEY` block. The signature value is expected
/// to use the XMLDSig fixed-width `r || s` format required by RFC 6931 /
/// XMLDSig 1.1. Use [`verify_ecdsa_signature_pem_with_encoding`] to opt into
/// libxmlsec1's ASN.1 compatibility representation. Returns `Ok(false)` for a
/// signature mismatch and `Err` for key or signature-format errors.
#[must_use = "discarding the verification result skips signature validation"]
pub fn verify_ecdsa_signature_pem(
    algorithm: SignatureAlgorithm,
    public_key_pem: &str,
    signed_data: &[u8],
    signature_value: &[u8],
) -> Result<bool, SignatureVerificationError> {
    verify_ecdsa_signature_pem_with_encoding(
        algorithm,
        public_key_pem,
        signed_data,
        signature_value,
        EcdsaSignatureValueEncoding::XmlDsig,
    )
}

/// Verify an ECDSA signature using an explicit XMLDSig compatibility encoding.
#[must_use = "discarding the verification result skips signature validation"]
pub fn verify_ecdsa_signature_pem_with_encoding(
    algorithm: SignatureAlgorithm,
    public_key_pem: &str,
    signed_data: &[u8],
    signature_value: &[u8],
    encoding: EcdsaSignatureValueEncoding,
) -> Result<bool, SignatureVerificationError> {
    let public_key_spki_der = parse_public_key_pem(public_key_pem)?;
    verify_ecdsa_signature_spki_with_encoding(
        algorithm,
        &public_key_spki_der,
        signed_data,
        signature_value,
        encoding,
    )
}

fn parse_public_key_pem(public_key_pem: &str) -> Result<Vec<u8>, SignatureVerificationError> {
    let (rest, pem) = x509_parser::pem::parse_x509_pem(public_key_pem.as_bytes())
        .map_err(|_| SignatureVerificationError::InvalidKeyPem)?;
    if !rest.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Err(SignatureVerificationError::InvalidKeyPem);
    }
    if pem.label != "PUBLIC KEY" {
        return Err(SignatureVerificationError::InvalidKeyFormat { label: pem.label });
    }

    Ok(pem.contents)
}

/// Verify an RSA XMLDSig signature using DER-encoded SPKI public key bytes.
///
/// The input must be an X.509 `SubjectPublicKeyInfo` wrapping an RSA key.
/// Returns `Ok(false)` for signature mismatch and `Err` for algorithm/key
/// preparation errors.
#[must_use = "discarding the verification result skips signature validation"]
pub fn verify_rsa_signature_spki(
    algorithm: SignatureAlgorithm,
    public_key_spki_der: &[u8],
    signed_data: &[u8],
    signature_value: &[u8],
) -> Result<bool, SignatureVerificationError> {
    verify_rsa_signature_spki_with_minimum(
        algorithm,
        public_key_spki_der,
        signed_data,
        signature_value,
        2048,
    )
}

pub(crate) fn verify_rsa_signature_spki_with_minimum(
    algorithm: SignatureAlgorithm,
    public_key_spki_der: &[u8],
    signed_data: &[u8],
    signature_value: &[u8],
    minimum_modulus_bits: usize,
) -> Result<bool, SignatureVerificationError> {
    validate_rsa_signature_spki_with_minimum(algorithm, public_key_spki_der, minimum_modulus_bits)?;
    verify_rsa_signature_spki_primitive(
        algorithm,
        public_key_spki_der,
        signed_data,
        signature_value,
    )
}

pub(crate) fn validate_rsa_signature_spki_with_minimum(
    algorithm: SignatureAlgorithm,
    public_key_spki_der: &[u8],
    minimum_modulus_bits: usize,
) -> Result<(), SignatureVerificationError> {
    let (rest, spki) = SubjectPublicKeyInfo::from_der(public_key_spki_der)
        .map_err(|_| SignatureVerificationError::InvalidKeyDer)?;
    if !rest.is_empty() {
        return Err(SignatureVerificationError::InvalidKeyDer);
    }
    match spki
        .parsed()
        .map_err(|_| SignatureVerificationError::InvalidKeyDer)?
    {
        PublicKey::RSA(rsa) => validate_rsa_public_key(&rsa, algorithm, minimum_modulus_bits),
        _ => Err(SignatureVerificationError::KeyAlgorithmMismatch {
            uri: algorithm.uri().to_string(),
        }),
    }
}

pub(crate) fn verify_rsa_signature_spki_primitive(
    algorithm: SignatureAlgorithm,
    public_key_spki_der: &[u8],
    signed_data: &[u8],
    signature_value: &[u8],
) -> Result<bool, SignatureVerificationError> {
    ensure_rsa_signature_algorithm(algorithm)?;
    let key = rsa::RsaPublicKey::from_public_key_der(public_key_spki_der)
        .map_err(|_| SignatureVerificationError::InvalidKeyDer)?;
    let Ok(signature) = RsaPkcs1v15Signature::try_from(signature_value) else {
        return Ok(false);
    };
    let verified = match algorithm {
        SignatureAlgorithm::RsaSha1 => RsaVerifyingKey::<Sha1>::new(key)
            .verify(signed_data, &signature)
            .is_ok(),
        SignatureAlgorithm::RsaSha224 => RsaVerifyingKey::<Sha224>::new(key)
            .verify(signed_data, &signature)
            .is_ok(),
        SignatureAlgorithm::RsaSha256 => RsaVerifyingKey::<Sha256>::new(key)
            .verify(signed_data, &signature)
            .is_ok(),
        SignatureAlgorithm::RsaSha384 => RsaVerifyingKey::<Sha384>::new(key)
            .verify(signed_data, &signature)
            .is_ok(),
        SignatureAlgorithm::RsaSha512 => RsaVerifyingKey::<Sha512>::new(key)
            .verify(signed_data, &signature)
            .is_ok(),
        _ => unreachable!("RSA algorithm checked above"),
    };
    Ok(verified)
}

/// Verify an XMLDSig DSA-SHA1 signature using a DER SPKI public key.
///
/// XMLDSig 1.0 encodes the signature as the fixed-width 20-byte `r` followed
/// by the fixed-width 20-byte `s`, rather than ASN.1 DER.
#[must_use = "discarding the verification result skips signature validation"]
pub fn verify_dsa_signature_spki(
    algorithm: SignatureAlgorithm,
    public_key_spki_der: &[u8],
    signed_data: &[u8],
    signature_value: &[u8],
) -> Result<bool, SignatureVerificationError> {
    verify_dsa_signature_spki_with_minimum(
        algorithm,
        public_key_spki_der,
        signed_data,
        signature_value,
        crate::policy::DsaKeyPolicy::default().minimum_modulus_bits,
    )
}

pub(crate) fn verify_dsa_signature_spki_with_minimum(
    algorithm: SignatureAlgorithm,
    public_key_spki_der: &[u8],
    signed_data: &[u8],
    signature_value: &[u8],
    minimum_modulus_bits: usize,
) -> Result<bool, SignatureVerificationError> {
    validate_dsa_signature_spki_with_minimum(public_key_spki_der, minimum_modulus_bits)?;
    verify_dsa_signature_spki_primitive(
        algorithm,
        public_key_spki_der,
        signed_data,
        signature_value,
    )
}

pub(crate) fn validate_dsa_signature_spki_with_minimum(
    public_key_spki_der: &[u8],
    minimum_modulus_bits: usize,
) -> Result<(), SignatureVerificationError> {
    let key = dsa::VerifyingKey::from_public_key_der(public_key_spki_der)
        .map_err(|_| SignatureVerificationError::InvalidKeyDer)?;
    let modulus_bits = usize::try_from(key.components().p().bits_vartime())
        .map_err(|_| SignatureVerificationError::InvalidKeyDer)?;
    crate::policy::DsaKeyPolicy {
        minimum_modulus_bits,
    }
    .validate_modulus_bits(modulus_bits)
    .map_err(SignatureVerificationError::KeyPolicy)
}

pub(crate) fn verify_dsa_signature_spki_primitive(
    algorithm: SignatureAlgorithm,
    public_key_spki_der: &[u8],
    signed_data: &[u8],
    signature_value: &[u8],
) -> Result<bool, SignatureVerificationError> {
    if !matches!(
        algorithm,
        SignatureAlgorithm::DsaSha1 | SignatureAlgorithm::DsaSha256
    ) {
        return Err(SignatureVerificationError::UnsupportedAlgorithm {
            uri: algorithm.uri().to_string(),
        });
    }
    let key = dsa::VerifyingKey::from_public_key_der(public_key_spki_der)
        .map_err(|_| SignatureVerificationError::InvalidKeyDer)?;
    let component_len = usize::try_from(key.components().q().bits_vartime())
        .map_err(|_| SignatureVerificationError::InvalidKeyDer)?
        .div_ceil(8);
    if signature_value.len() != component_len.saturating_mul(2) {
        return Ok(false);
    }
    let Some(signature) = dsa::Signature::from_components(
        crypto_bigint::BoxedUint::from_be_slice_vartime(&signature_value[..component_len]),
        crypto_bigint::BoxedUint::from_be_slice_vartime(&signature_value[component_len..]),
    ) else {
        return Ok(false);
    };
    let verified = match algorithm {
        SignatureAlgorithm::DsaSha1 => key.verify_prehash(&Sha1::digest(signed_data), &signature),
        SignatureAlgorithm::DsaSha256 => {
            key.verify_prehash(&Sha256::digest(signed_data), &signature)
        }
        _ => unreachable!("DSA algorithm checked above"),
    };
    Ok(verified.is_ok())
}

/// Verify an ECDSA XMLDSig signature using DER-encoded SPKI public key bytes.
///
/// The input must be an X.509 `SubjectPublicKeyInfo` wrapping an EC key. The
/// signature value must use XMLDSig fixed-width `r || s` bytes. Use
/// [`verify_ecdsa_signature_spki_with_encoding`] to select libxmlsec1's ASN.1
/// compatibility representation explicitly.
#[must_use = "discarding the verification result skips signature validation"]
pub fn verify_ecdsa_signature_spki(
    algorithm: SignatureAlgorithm,
    public_key_spki_der: &[u8],
    signed_data: &[u8],
    signature_value: &[u8],
) -> Result<bool, SignatureVerificationError> {
    verify_ecdsa_signature_spki_with_encoding(
        algorithm,
        public_key_spki_der,
        signed_data,
        signature_value,
        EcdsaSignatureValueEncoding::XmlDsig,
    )
}

/// Verify an ECDSA signature using an explicit XMLDSig compatibility encoding.
#[must_use = "discarding the verification result skips signature validation"]
pub fn verify_ecdsa_signature_spki_with_encoding(
    algorithm: SignatureAlgorithm,
    public_key_spki_der: &[u8],
    signed_data: &[u8],
    signature_value: &[u8],
    encoding: EcdsaSignatureValueEncoding,
) -> Result<bool, SignatureVerificationError> {
    if !matches!(
        algorithm,
        SignatureAlgorithm::EcdsaSha1
            | SignatureAlgorithm::EcdsaSha224
            | SignatureAlgorithm::EcdsaSha256
            | SignatureAlgorithm::EcdsaSha384
            | SignatureAlgorithm::EcdsaSha512
    ) {
        return Err(SignatureVerificationError::UnsupportedAlgorithm {
            uri: algorithm.uri().to_string(),
        });
    }

    let (rest, spki) = SubjectPublicKeyInfo::from_der(public_key_spki_der)
        .map_err(|_| SignatureVerificationError::InvalidKeyDer)?;
    if !rest.is_empty() {
        return Err(SignatureVerificationError::InvalidKeyDer);
    }
    let public_key = spki
        .parsed()
        .map_err(|_| SignatureVerificationError::InvalidKeyDer)?;

    match public_key {
        PublicKey::EC(ec) => {
            validate_ec_public_key_encoding(&ec, &spki.subject_public_key.data)?;
            let (curve, component_len) = ecdsa_curve_and_component_len(&spki, &ec)?;
            let signature_encoding = match encoding {
                EcdsaSignatureValueEncoding::XmlDsig => {
                    if signature_value.len() != component_len * 2 {
                        return Err(SignatureVerificationError::InvalidSignatureFormat);
                    }
                    EcdsaSignatureEncoding::XmlDsigFixed
                }
                EcdsaSignatureValueEncoding::XmlSecAsn1Der => {
                    if inspect_der_encoded_ecdsa_signature(signature_value, component_len)?
                        .is_none()
                    {
                        return Err(SignatureVerificationError::InvalidSignatureFormat);
                    }
                    EcdsaSignatureEncoding::Asn1Der
                }
            };
            let prehash = match algorithm {
                SignatureAlgorithm::EcdsaSha1 => Sha1::digest(signed_data).to_vec(),
                SignatureAlgorithm::EcdsaSha224 => Sha224::digest(signed_data).to_vec(),
                SignatureAlgorithm::EcdsaSha256 => Sha256::digest(signed_data).to_vec(),
                SignatureAlgorithm::EcdsaSha384 => Sha384::digest(signed_data).to_vec(),
                SignatureAlgorithm::EcdsaSha512 => Sha512::digest(signed_data).to_vec(),
                _ => unreachable!("ECDSA algorithm was validated above"),
            };
            match curve {
                EcCurve::P256 => verify_ecdsa_p256(
                    &spki.subject_public_key.data,
                    &prehash,
                    signature_value,
                    signature_encoding,
                ),
                EcCurve::P384 => verify_ecdsa_p384(
                    &spki.subject_public_key.data,
                    &prehash,
                    signature_value,
                    signature_encoding,
                ),
                EcCurve::P521 => verify_ecdsa_p521(
                    &spki.subject_public_key.data,
                    &prehash,
                    signature_value,
                    signature_encoding,
                ),
            }
        }
        _ => Err(SignatureVerificationError::KeyAlgorithmMismatch {
            uri: algorithm.uri().to_string(),
        }),
    }
}

/// Verify the ASN.1 DER ECDSA representation required by X.509 signatures.
///
/// This is intentionally separate from the XMLDSig policy-aware entry point:
/// certificate signature framing is fixed by X.509 and must not inherit the
/// document's `SignatureValue` compatibility mode.
pub(crate) fn verify_ecdsa_signature_spki_asn1_der(
    algorithm: SignatureAlgorithm,
    public_key_spki_der: &[u8],
    signed_data: &[u8],
    signature_value: &[u8],
) -> Result<bool, SignatureVerificationError> {
    verify_ecdsa_signature_spki_with_encoding(
        algorithm,
        public_key_spki_der,
        signed_data,
        signature_value,
        EcdsaSignatureValueEncoding::XmlSecAsn1Der,
    )
}

fn validate_rsa_public_key(
    rsa: &x509_parser::public_key::RSAPublicKey<'_>,
    algorithm: SignatureAlgorithm,
    minimum_modulus_bits: usize,
) -> Result<(), SignatureVerificationError> {
    ensure_rsa_signature_algorithm(algorithm)?;
    validate_rsa_key_components(rsa.modulus, rsa.exponent, minimum_modulus_bits)
}

/// Apply the RSA key-strength invariant shared by XMLDSig and X.509 algorithms.
pub(crate) fn validate_rsa_key_components(
    modulus: &[u8],
    exponent: &[u8],
    minimum_modulus_bits: usize,
) -> Result<(), SignatureVerificationError> {
    crate::policy::RsaKeyPolicy {
        minimum_modulus_bits,
    }
    .validate_components("verification", modulus, exponent)
    .map(|_| ())
    .map_err(SignatureVerificationError::KeyPolicy)
}

fn ensure_rsa_signature_algorithm(
    algorithm: SignatureAlgorithm,
) -> Result<(), SignatureVerificationError> {
    match algorithm {
        SignatureAlgorithm::RsaSha1
        | SignatureAlgorithm::RsaSha224
        | SignatureAlgorithm::RsaSha256
        | SignatureAlgorithm::RsaSha384
        | SignatureAlgorithm::RsaSha512 => Ok(()),
        _ => Err(SignatureVerificationError::UnsupportedAlgorithm {
            uri: algorithm.uri().to_string(),
        }),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EcCurve {
    P256,
    P384,
    P521,
}

fn ecdsa_curve_and_component_len(
    spki: &SubjectPublicKeyInfo<'_>,
    ec: &ECPoint<'_>,
) -> Result<(EcCurve, usize), SignatureVerificationError> {
    let curve_oid = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|params| params.as_oid().ok())
        .ok_or(SignatureVerificationError::InvalidKeyDer)?;
    let point_len = ec.key_size();

    let curve_oid = curve_oid.to_id_string();
    match (curve_oid.as_str(), point_len) {
        ("1.2.840.10045.3.1.7", 256) => Ok((EcCurve::P256, 32)),
        ("1.3.132.0.34", 384) => Ok((EcCurve::P384, 48)),
        // x509-parser reports the byte-aligned SEC1 point size for P-521.
        ("1.3.132.0.35", 528) => Ok((EcCurve::P521, 66)),
        _ => Err(SignatureVerificationError::InvalidKeyDer),
    }
}

fn verify_ecdsa_p256(
    public_key: &[u8],
    prehash: &[u8],
    signature_value: &[u8],
    signature_encoding: EcdsaSignatureEncoding,
) -> Result<bool, SignatureVerificationError> {
    let key = P256VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|_| SignatureVerificationError::InvalidKeyDer)?;
    verify_p256_signature(&key, signature_value, signature_encoding, prehash)
}

fn verify_ecdsa_p384(
    public_key: &[u8],
    prehash: &[u8],
    signature_value: &[u8],
    signature_encoding: EcdsaSignatureEncoding,
) -> Result<bool, SignatureVerificationError> {
    let key = P384VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|_| SignatureVerificationError::InvalidKeyDer)?;
    verify_p384_signature(&key, signature_value, signature_encoding, prehash)
}

fn verify_ecdsa_p521(
    public_key: &[u8],
    prehash: &[u8],
    signature_value: &[u8],
    signature_encoding: EcdsaSignatureEncoding,
) -> Result<bool, SignatureVerificationError> {
    let key = P521VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|_| SignatureVerificationError::InvalidKeyDer)?;
    verify_p521_signature(&key, signature_value, signature_encoding, prehash)
}

fn verify_p256_signature(
    key: &P256VerifyingKey,
    signature_value: &[u8],
    signature_encoding: EcdsaSignatureEncoding,
    prehash: &[u8],
) -> Result<bool, SignatureVerificationError> {
    match signature_encoding {
        EcdsaSignatureEncoding::XmlDsigFixed => {
            let signature = P256Signature::from_slice(signature_value)
                .map_err(|_| SignatureVerificationError::InvalidSignatureFormat)?;
            Ok(key.verify_prehash(prehash, &signature).is_ok())
        }
        EcdsaSignatureEncoding::Asn1Der => {
            let signature = P256Signature::from_der(signature_value)
                .map_err(|_| SignatureVerificationError::InvalidSignatureFormat)?;
            Ok(key.verify_prehash(prehash, &signature).is_ok())
        }
    }
}

fn verify_p384_signature(
    key: &P384VerifyingKey,
    signature_value: &[u8],
    signature_encoding: EcdsaSignatureEncoding,
    prehash: &[u8],
) -> Result<bool, SignatureVerificationError> {
    match signature_encoding {
        EcdsaSignatureEncoding::XmlDsigFixed => {
            let signature = P384Signature::from_slice(signature_value)
                .map_err(|_| SignatureVerificationError::InvalidSignatureFormat)?;
            Ok(key.verify_prehash(prehash, &signature).is_ok())
        }
        EcdsaSignatureEncoding::Asn1Der => {
            let signature = P384Signature::from_der(signature_value)
                .map_err(|_| SignatureVerificationError::InvalidSignatureFormat)?;
            Ok(key.verify_prehash(prehash, &signature).is_ok())
        }
    }
}

fn verify_p521_signature(
    key: &P521VerifyingKey,
    signature_value: &[u8],
    signature_encoding: EcdsaSignatureEncoding,
    prehash: &[u8],
) -> Result<bool, SignatureVerificationError> {
    match signature_encoding {
        EcdsaSignatureEncoding::XmlDsigFixed => {
            let signature = P521Signature::from_slice(signature_value)
                .map_err(|_| SignatureVerificationError::InvalidSignatureFormat)?;
            Ok(key.verify_prehash(prehash, &signature).is_ok())
        }
        EcdsaSignatureEncoding::Asn1Der => {
            let signature = P521Signature::from_der(signature_value)
                .map_err(|_| SignatureVerificationError::InvalidSignatureFormat)?;
            Ok(key.verify_prehash(prehash, &signature).is_ok())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EcdsaSignatureEncoding {
    XmlDsigFixed,
    Asn1Der,
}

pub(crate) fn encode_ecdsa_signature_as_der(signature: &[u8]) -> Option<Vec<u8>> {
    if signature.is_empty() || !signature.len().is_multiple_of(2) {
        return None;
    }
    let component_len = signature.len() / 2;
    let mut content = Vec::with_capacity(signature.len() + 8);
    encode_der_integer(&signature[..component_len], &mut content);
    encode_der_integer(&signature[component_len..], &mut content);

    let mut encoded = Vec::with_capacity(content.len() + 3);
    encoded.push(0x30);
    encode_der_length(content.len(), &mut encoded);
    encoded.extend_from_slice(&content);
    Some(encoded)
}

pub(crate) fn maximum_ecdsa_der_signature_len(raw_signature_len: usize) -> Option<usize> {
    if raw_signature_len == 0 || !raw_signature_len.is_multiple_of(2) {
        return None;
    }
    let component_len = raw_signature_len / 2;
    let integer_content_len = component_len.checked_add(1)?;
    let integer_len = 1_usize
        .checked_add(der_length_octets(integer_content_len)?)?
        .checked_add(integer_content_len)?;
    let sequence_content_len = integer_len.checked_mul(2)?;
    1_usize
        .checked_add(der_length_octets(sequence_content_len)?)?
        .checked_add(sequence_content_len)
}

fn encode_der_integer(component: &[u8], output: &mut Vec<u8>) {
    let first_nonzero = component
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(component.len() - 1);
    let magnitude = &component[first_nonzero..];
    let needs_sign_octet = magnitude[0] & 0x80 != 0;
    output.push(0x02);
    encode_der_length(magnitude.len() + usize::from(needs_sign_octet), output);
    if needs_sign_octet {
        output.push(0);
    }
    output.extend_from_slice(magnitude);
}

fn encode_der_length(len: usize, output: &mut Vec<u8>) {
    if len < 128 {
        output.push(len as u8);
        return;
    }

    let bytes = len.to_be_bytes();
    let first_nonzero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .expect("non-short DER lengths are nonzero");
    let encoded = &bytes[first_nonzero..];
    output.push(0x80 | encoded.len() as u8);
    output.extend_from_slice(encoded);
}

fn der_length_octets(len: usize) -> Option<usize> {
    if len < 128 {
        return Some(1);
    }
    let significant_bytes = (usize::BITS - len.leading_zeros()).div_ceil(8) as usize;
    significant_bytes.checked_add(1)
}

fn inspect_der_encoded_ecdsa_signature(
    signature_value: &[u8],
    component_len: usize,
) -> Result<Option<()>, SignatureVerificationError> {
    let Some((&tag, rest)) = signature_value.split_first() else {
        return Ok(None);
    };
    if tag != 0x30 {
        return Ok(None);
    }

    let sequence = parse_der_length(rest)
        .ok_or(SignatureVerificationError::InvalidSignatureFormat)?
        .map_err(|_| SignatureVerificationError::InvalidSignatureFormat)?;
    let (sequence_len, sequence_rest) = sequence;
    let (sequence_content, trailing) = sequence_rest
        .split_at_checked(sequence_len)
        .ok_or(SignatureVerificationError::InvalidSignatureFormat)?;
    if !trailing.is_empty() {
        return Err(SignatureVerificationError::InvalidSignatureFormat);
    }

    let after_r = parse_der_integer(sequence_content, component_len)?;
    let after_s = parse_der_integer(after_r, component_len)?;
    if !after_s.is_empty() {
        return Err(SignatureVerificationError::InvalidSignatureFormat);
    }

    Ok(Some(()))
}

fn parse_der_integer(
    input: &[u8],
    component_len: usize,
) -> Result<&[u8], SignatureVerificationError> {
    let Some((&tag, rest)) = input.split_first() else {
        return Err(SignatureVerificationError::InvalidSignatureFormat);
    };
    if tag != 0x02 {
        return Err(SignatureVerificationError::InvalidSignatureFormat);
    }

    let (len, rest) = parse_der_length(rest)
        .ok_or(SignatureVerificationError::InvalidSignatureFormat)?
        .map_err(|_| SignatureVerificationError::InvalidSignatureFormat)?;
    let (integer_bytes, remainder) = rest
        .split_at_checked(len)
        .ok_or(SignatureVerificationError::InvalidSignatureFormat)?;

    if integer_bytes.is_empty() {
        return Err(SignatureVerificationError::InvalidSignatureFormat);
    }
    if integer_bytes.len() > component_len + 1 {
        return Err(SignatureVerificationError::InvalidSignatureFormat);
    }
    if integer_bytes.len() == component_len + 1 && integer_bytes[0] != 0 {
        return Err(SignatureVerificationError::InvalidSignatureFormat);
    }
    if integer_bytes[0] & 0x80 != 0 {
        return Err(SignatureVerificationError::InvalidSignatureFormat);
    }
    if integer_bytes.len() > 1 && integer_bytes[0] == 0 && integer_bytes[1] & 0x80 == 0 {
        return Err(SignatureVerificationError::InvalidSignatureFormat);
    }

    Ok(remainder)
}

fn parse_der_length(input: &[u8]) -> Option<Result<(usize, &[u8]), ()>> {
    let (&len_byte, rest) = input.split_first()?;

    if len_byte & 0x80 == 0 {
        return Some(Ok((usize::from(len_byte), rest)));
    }

    let len_len = usize::from(len_byte & 0x7f);
    if len_len == 0 || len_len > std::mem::size_of::<usize>() || rest.len() < len_len {
        return Some(Err(()));
    }

    let (len_bytes, remainder) = rest.split_at(len_len);
    if len_bytes[0] == 0 {
        return Some(Err(()));
    }

    let mut declared_len = 0_usize;
    for &byte in len_bytes {
        declared_len = match declared_len.checked_mul(256) {
            Some(len) => len,
            None => return Some(Err(())),
        };
        declared_len = match declared_len.checked_add(usize::from(byte)) {
            Some(len) => len,
            None => return Some(Err(())),
        };
    }

    if declared_len < 128 {
        return Some(Err(()));
    }

    Some(Ok((declared_len, remainder)))
}

fn validate_ec_public_key_encoding(
    ec: &ECPoint<'_>,
    public_key_bytes: &[u8],
) -> Result<(), SignatureVerificationError> {
    let coordinate_len = ec_coordinate_len_bytes(ec.key_size())?;
    let expected_len = coordinate_len
        .checked_mul(2)
        .and_then(|len| len.checked_add(1))
        .ok_or(SignatureVerificationError::InvalidKeyDer)?;

    let is_uncompressed_sec1 =
        public_key_bytes.len() == expected_len && public_key_bytes.first() == Some(&0x04);
    if !is_uncompressed_sec1 {
        return Err(SignatureVerificationError::InvalidKeyDer);
    }

    Ok(())
}

fn ec_coordinate_len_bytes(key_bits: usize) -> Result<usize, SignatureVerificationError> {
    key_bits
        .checked_add(7)
        .and_then(|bits| bits.checked_div(8))
        .ok_or(SignatureVerificationError::InvalidKeyDer)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "unit tests use fixed fixture data")]
mod tests {
    use super::*;

    #[test]
    fn ecdsa_algorithms_are_rejected_for_rsa_verification() {
        for algorithm in [
            SignatureAlgorithm::EcdsaSha256,
            SignatureAlgorithm::EcdsaSha384,
        ] {
            let err = ensure_rsa_signature_algorithm(algorithm).unwrap_err();
            assert!(matches!(
                err,
                SignatureVerificationError::UnsupportedAlgorithm { .. }
            ));
        }
    }

    #[test]
    fn malformed_dsa_components_are_verification_misses() {
        let public_key = include_bytes!(
            "../../tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/certs/lugh.der"
        );
        let signature = [0_u8; 40];

        assert!(matches!(
            verify_dsa_signature_spki_with_minimum(
                SignatureAlgorithm::DsaSha1,
                public_key,
                b"signed",
                &signature,
                1024,
            ),
            Ok(false)
        ));
    }

    #[test]
    fn spki_signature_framing_uses_the_resolved_key_width() {
        let rsa = parse_public_key_pem(include_str!(
            "../../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"
        ))
        .expect("RSA fixture must parse");
        assert!(
            signature_value_matches_spki(SignatureAlgorithm::RsaSha256, &rsa, &[0; 256]).unwrap()
        );
        assert!(
            !signature_value_matches_spki(SignatureAlgorithm::RsaSha256, &rsa, &[0; 255]).unwrap()
        );

        let p256 = parse_public_key_pem(include_str!(
            "../../tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem"
        ))
        .expect("P-256 fixture must parse");
        assert!(
            signature_value_matches_spki(SignatureAlgorithm::EcdsaSha256, &p256, &[0xAA; 64])
                .unwrap()
        );
        assert!(matches!(
            signature_value_matches_spki(SignatureAlgorithm::EcdsaSha256, &p256, &[0xAA; 96]),
            Err(SignatureVerificationError::InvalidSignatureFormat)
        ));
    }

    #[test]
    fn der_like_prefix_with_fixed_width_len_is_not_valid_der() {
        let mut signature = vec![0xAA_u8; 96];
        signature[0] = 0x30;
        signature[1] = 0x20;

        assert!(inspect_der_encoded_ecdsa_signature(&signature, 48).is_err());
    }

    #[test]
    fn overlong_der_length_below_128_is_rejected() {
        let bad = [0x81_u8, 0x7f];
        let parsed = parse_der_length(&bad).expect("length bytes should be present");
        assert!(
            matches!(parsed, Err(())),
            "DER must reject long-form lengths below 128"
        );
    }

    #[test]
    fn ec_coordinate_length_rounds_up_for_non_byte_aligned_curves() {
        assert_eq!(
            ec_coordinate_len_bytes(521).expect("521-bit curves require rounded byte length"),
            66
        );
    }

    #[test]
    fn same_width_valid_der_is_recognized_in_explicit_mode() {
        let mut signature = Vec::with_capacity(64);
        signature.extend_from_slice(&[0x30, 0x3e, 0x02, 0x1d]);
        signature.extend(std::iter::repeat_n(0x11_u8, 29));
        signature.extend_from_slice(&[0x02, 0x1d]);
        signature.extend(std::iter::repeat_n(0x22_u8, 29));

        assert_eq!(
            inspect_der_encoded_ecdsa_signature(&signature, 32).unwrap(),
            Some(())
        );
    }

    #[test]
    fn der_integer_longer_than_component_requires_sign_byte() {
        let mut signature = Vec::with_capacity(72);
        signature.extend_from_slice(&[0x30, 0x46, 0x02, 0x21, 0x01]);
        signature.extend(std::iter::repeat_n(0x11_u8, 32));
        signature.extend_from_slice(&[0x02, 0x21, 0x01]);
        signature.extend(std::iter::repeat_n(0x22_u8, 32));

        let encoding = inspect_der_encoded_ecdsa_signature(&signature, 32);
        assert!(matches!(
            encoding,
            Err(SignatureVerificationError::InvalidSignatureFormat)
        ));
    }

    #[test]
    fn fixed_width_ecdsa_is_encoded_as_canonical_der() {
        // Leading zeroes are stripped, while a high-bit magnitude receives the
        // sign-protecting zero octet required by DER INTEGER canonicalization.
        let mut raw = vec![0_u8; 64];
        raw[31] = 1;
        raw[32] = 0x80;

        let encoded = encode_ecdsa_signature_as_der(&raw).unwrap();
        assert_eq!(
            encoded,
            [
                &[0x30, 0x26, 0x02, 0x01, 0x01, 0x02, 0x21, 0x00][..],
                &[0x80],
                &[0; 31],
            ]
            .concat()
        );
        assert_eq!(
            inspect_der_encoded_ecdsa_signature(&encoded, 32).unwrap(),
            Some(())
        );
    }

    #[test]
    fn maximum_der_length_covers_supported_curve_widths() {
        // Signing preflight must reserve the worst-case canonical DER framing
        // for every supported curve and reject impossible raw widths.
        assert_eq!(maximum_ecdsa_der_signature_len(64), Some(72));
        assert_eq!(maximum_ecdsa_der_signature_len(96), Some(104));
        assert_eq!(maximum_ecdsa_der_signature_len(132), Some(141));
        assert_eq!(maximum_ecdsa_der_signature_len(0), None);
        assert_eq!(maximum_ecdsa_der_signature_len(65), None);
    }
}
