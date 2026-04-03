//! Signature verification helpers for XMLDSig.
//!
//! This module currently covers roadmap task P1-019 (RSA PKCS#1 v1.5) and
//! P1-020 (ECDSA P-256/P-384) verification, plus donor P-521 interop under
//! the XMLDSig `ecdsa-sha384` URI.
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
use rsa::pkcs1v15::{Signature as RsaPkcs1v15Signature, VerifyingKey as RsaVerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use signature::hazmat::PrehashVerifier;
use signature::{DigestVerifier, Verifier};
use x509_parser::prelude::FromDer;
use x509_parser::public_key::{ECPoint, PublicKey};
use x509_parser::x509::SubjectPublicKeyInfo;

use super::parse::SignatureAlgorithm;

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

    /// The provided public key does not match the signature algorithm.
    #[error("public key does not match signature algorithm: {uri}")]
    KeyAlgorithmMismatch {
        /// XMLDSig algorithm URI used for diagnostics.
        uri: String,
    },

    /// The provided ECDSA signature bytes were neither XMLDSig fixed-width
    /// nor ASN.1 DER encoded.
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
/// XMLDSig 1.1, but ASN.1 DER-encoded ECDSA signatures are also accepted as an
/// interop fallback. Returns `Ok(false)` for signature mismatch and `Err` for
/// algorithm/key/signature-format preparation errors (including
/// `InvalidSignatureFormat` when the bytes are neither valid fixed-width
/// `r || s` nor valid ASN.1 DER ECDSA).
#[must_use = "discarding the verification result skips signature validation"]
pub fn verify_ecdsa_signature_pem(
    algorithm: SignatureAlgorithm,
    public_key_pem: &str,
    signed_data: &[u8],
    signature_value: &[u8],
) -> Result<bool, SignatureVerificationError> {
    let public_key_spki_der = parse_public_key_pem(public_key_pem)?;
    verify_ecdsa_signature_spki(
        algorithm,
        &public_key_spki_der,
        signed_data,
        signature_value,
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
    let (rest, spki) = SubjectPublicKeyInfo::from_der(public_key_spki_der)
        .map_err(|_| SignatureVerificationError::InvalidKeyDer)?;
    if !rest.is_empty() {
        return Err(SignatureVerificationError::InvalidKeyDer);
    }
    let public_key = spki
        .parsed()
        .map_err(|_| SignatureVerificationError::InvalidKeyDer)?;

    match public_key {
        PublicKey::RSA(rsa) => {
            validate_rsa_public_key(&rsa, algorithm)?;
            let key = rsa::RsaPublicKey::from_public_key_der(public_key_spki_der)
                .map_err(|_| SignatureVerificationError::InvalidKeyDer)?;
            let Ok(signature) = RsaPkcs1v15Signature::try_from(signature_value) else {
                return Ok(false);
            };

            let verified = match algorithm {
                SignatureAlgorithm::RsaSha1 => {
                    let key = RsaVerifyingKey::<Sha1>::new(key);
                    key.verify(signed_data, &signature).is_ok()
                }
                SignatureAlgorithm::RsaSha256 => {
                    let key = RsaVerifyingKey::<Sha256>::new(key);
                    key.verify(signed_data, &signature).is_ok()
                }
                SignatureAlgorithm::RsaSha384 => {
                    let key = RsaVerifyingKey::<Sha384>::new(key);
                    key.verify(signed_data, &signature).is_ok()
                }
                SignatureAlgorithm::RsaSha512 => {
                    let key = RsaVerifyingKey::<Sha512>::new(key);
                    key.verify(signed_data, &signature).is_ok()
                }
                _ => {
                    return Err(SignatureVerificationError::UnsupportedAlgorithm {
                        uri: algorithm.uri().to_string(),
                    });
                }
            };

            Ok(verified)
        }
        _ => Err(SignatureVerificationError::KeyAlgorithmMismatch {
            uri: algorithm.uri().to_string(),
        }),
    }
}

/// Verify an ECDSA XMLDSig signature using DER-encoded SPKI public key bytes.
///
/// The input must be an X.509 `SubjectPublicKeyInfo` wrapping an EC key. The
/// signature value may be either XMLDSig fixed-width `r || s` bytes or ASN.1
/// DER-encoded ECDSA for interop compatibility. Returns `Ok(false)` for
/// signature mismatch and `Err` for algorithm/key/signature-format preparation
/// errors.
#[must_use = "discarding the verification result skips signature validation"]
pub fn verify_ecdsa_signature_spki(
    algorithm: SignatureAlgorithm,
    public_key_spki_der: &[u8],
    signed_data: &[u8],
    signature_value: &[u8],
) -> Result<bool, SignatureVerificationError> {
    if !matches!(
        algorithm,
        SignatureAlgorithm::EcdsaP256Sha256 | SignatureAlgorithm::EcdsaP384Sha384
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
            let (curve, component_len) = ecdsa_curve_and_component_len(&spki, &ec, algorithm)?;
            let signature_encoding =
                classify_ecdsa_signature_encoding(signature_value, component_len)?;
            match curve {
                EcCurve::P256 => verify_ecdsa_p256_sha256(
                    &spki.subject_public_key.data,
                    signed_data,
                    signature_value,
                    signature_encoding,
                ),
                EcCurve::P384 => verify_ecdsa_p384_sha384(
                    &spki.subject_public_key.data,
                    signed_data,
                    signature_value,
                    signature_encoding,
                ),
                EcCurve::P521 => verify_ecdsa_p521_sha384(
                    &spki.subject_public_key.data,
                    signed_data,
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

fn validate_rsa_public_key(
    rsa: &x509_parser::public_key::RSAPublicKey<'_>,
    algorithm: SignatureAlgorithm,
) -> Result<(), SignatureVerificationError> {
    let min_modulus_bits = minimum_rsa_modulus_bits(algorithm)?;
    let modulus_start = rsa
        .modulus
        .iter()
        .position(|byte| *byte != 0)
        .ok_or(SignatureVerificationError::InvalidKeyDer)?;
    let modulus = &rsa.modulus[modulus_start..];
    if modulus.is_empty() {
        return Err(SignatureVerificationError::InvalidKeyDer);
    }
    // Match ring's RSA parameter checks: modulus length is evaluated after
    // rounding up to the nearest whole byte, not by exact significant-bit
    // length of the highest non-zero byte.
    let modulus_bits = modulus
        .len()
        .checked_mul(8)
        .ok_or(SignatureVerificationError::InvalidKeyDer)?;
    if !(min_modulus_bits..=8192).contains(&modulus_bits) {
        return Err(SignatureVerificationError::InvalidKeyDer);
    }

    let exponent = rsa
        .try_exponent()
        .map_err(|_| SignatureVerificationError::InvalidKeyDer)?;
    if !(3..=((1_u64 << 33) - 1)).contains(&exponent) || exponent % 2 == 0 {
        return Err(SignatureVerificationError::InvalidKeyDer);
    }

    Ok(())
}

fn minimum_rsa_modulus_bits(
    algorithm: SignatureAlgorithm,
) -> Result<usize, SignatureVerificationError> {
    match algorithm {
        SignatureAlgorithm::RsaSha1
        | SignatureAlgorithm::RsaSha256
        | SignatureAlgorithm::RsaSha384
        | SignatureAlgorithm::RsaSha512 => Ok(2048),
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
    algorithm: SignatureAlgorithm,
) -> Result<(EcCurve, usize), SignatureVerificationError> {
    let curve_oid = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|params| params.as_oid().ok())
        .ok_or(SignatureVerificationError::InvalidKeyDer)?;
    let point_len = ec.key_size();

    let curve_oid = curve_oid.to_id_string();
    match algorithm {
        SignatureAlgorithm::EcdsaP256Sha256 => {
            if curve_oid == "1.2.840.10045.3.1.7" && point_len == 256 {
                Ok((EcCurve::P256, 32))
            } else {
                Err(SignatureVerificationError::KeyAlgorithmMismatch {
                    uri: algorithm.uri().to_string(),
                })
            }
        }
        SignatureAlgorithm::EcdsaP384Sha384 => {
            if curve_oid == "1.3.132.0.34" && point_len == 384 {
                Ok((EcCurve::P384, 48))
            // XMLDSig `ecdsa-sha384` identifies the digest/signature method URI,
            // not a single curve. For interop we accept secp521r1 donor vectors;
            // x509-parser reports ECPoint::key_size() as byte-aligned bits (528)
            // for P-521 uncompressed points, so allow both exact and aligned size.
            } else if curve_oid == "1.3.132.0.35" && matches!(point_len, 521 | 528) {
                Ok((EcCurve::P521, 66))
            } else {
                Err(SignatureVerificationError::KeyAlgorithmMismatch {
                    uri: algorithm.uri().to_string(),
                })
            }
        }
        _ => Err(SignatureVerificationError::UnsupportedAlgorithm {
            uri: algorithm.uri().to_string(),
        }),
    }
}

fn verify_ecdsa_p256_sha256(
    public_key: &[u8],
    signed_data: &[u8],
    signature_value: &[u8],
    signature_encoding: EcdsaSignatureEncoding,
) -> Result<bool, SignatureVerificationError> {
    let key = P256VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|_| SignatureVerificationError::InvalidKeyDer)?;
    let mut digest = Sha256::new();
    digest.update(signed_data);
    verify_p256_signature(&key, signature_value, signature_encoding, digest)
}

fn verify_ecdsa_p384_sha384(
    public_key: &[u8],
    signed_data: &[u8],
    signature_value: &[u8],
    signature_encoding: EcdsaSignatureEncoding,
) -> Result<bool, SignatureVerificationError> {
    let key = P384VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|_| SignatureVerificationError::InvalidKeyDer)?;
    let mut digest = Sha384::new();
    digest.update(signed_data);
    verify_p384_signature(&key, signature_value, signature_encoding, digest)
}

fn verify_ecdsa_p521_sha384(
    public_key: &[u8],
    signed_data: &[u8],
    signature_value: &[u8],
    signature_encoding: EcdsaSignatureEncoding,
) -> Result<bool, SignatureVerificationError> {
    let key = P521VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|_| SignatureVerificationError::InvalidKeyDer)?;
    let prehash = Sha384::digest(signed_data);
    verify_p521_signature(&key, signature_value, signature_encoding, &prehash)
}

fn verify_p256_signature(
    key: &P256VerifyingKey,
    signature_value: &[u8],
    signature_encoding: EcdsaSignatureEncoding,
    digest: Sha256,
) -> Result<bool, SignatureVerificationError> {
    match signature_encoding {
        EcdsaSignatureEncoding::XmlDsigFixed => {
            let signature = P256Signature::from_slice(signature_value)
                .map_err(|_| SignatureVerificationError::InvalidSignatureFormat)?;
            Ok(key.verify_digest(digest, &signature).is_ok())
        }
        EcdsaSignatureEncoding::Asn1Der => {
            let signature = P256Signature::from_der(signature_value)
                .map_err(|_| SignatureVerificationError::InvalidSignatureFormat)?;
            Ok(key.verify_digest(digest, &signature).is_ok())
        }
        EcdsaSignatureEncoding::Ambiguous => {
            if let Ok(signature) = P256Signature::from_der(signature_value)
                && key.verify_digest(digest.clone(), &signature).is_ok()
            {
                return Ok(true);
            }

            let signature = P256Signature::from_slice(signature_value)
                .map_err(|_| SignatureVerificationError::InvalidSignatureFormat)?;
            Ok(key.verify_digest(digest, &signature).is_ok())
        }
    }
}

fn verify_p384_signature(
    key: &P384VerifyingKey,
    signature_value: &[u8],
    signature_encoding: EcdsaSignatureEncoding,
    digest: Sha384,
) -> Result<bool, SignatureVerificationError> {
    match signature_encoding {
        EcdsaSignatureEncoding::XmlDsigFixed => {
            let signature = P384Signature::from_slice(signature_value)
                .map_err(|_| SignatureVerificationError::InvalidSignatureFormat)?;
            Ok(key.verify_digest(digest, &signature).is_ok())
        }
        EcdsaSignatureEncoding::Asn1Der => {
            let signature = P384Signature::from_der(signature_value)
                .map_err(|_| SignatureVerificationError::InvalidSignatureFormat)?;
            Ok(key.verify_digest(digest, &signature).is_ok())
        }
        EcdsaSignatureEncoding::Ambiguous => {
            if let Ok(signature) = P384Signature::from_der(signature_value)
                && key.verify_digest(digest.clone(), &signature).is_ok()
            {
                return Ok(true);
            }

            let signature = P384Signature::from_slice(signature_value)
                .map_err(|_| SignatureVerificationError::InvalidSignatureFormat)?;
            Ok(key.verify_digest(digest, &signature).is_ok())
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
        EcdsaSignatureEncoding::Ambiguous => {
            if let Ok(signature) = P521Signature::from_der(signature_value)
                && key.verify_prehash(prehash, &signature).is_ok()
            {
                return Ok(true);
            }

            let signature = P521Signature::from_slice(signature_value)
                .map_err(|_| SignatureVerificationError::InvalidSignatureFormat)?;
            Ok(key.verify_prehash(prehash, &signature).is_ok())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EcdsaSignatureEncoding {
    XmlDsigFixed,
    Asn1Der,
    Ambiguous,
}

fn classify_ecdsa_signature_encoding(
    signature_value: &[u8],
    component_len: usize,
) -> Result<EcdsaSignatureEncoding, SignatureVerificationError> {
    let expected_len = component_len
        .checked_mul(2)
        .ok_or(SignatureVerificationError::InvalidSignatureFormat)?;

    match inspect_der_encoded_ecdsa_signature(signature_value, component_len) {
        Ok(Some(())) if signature_value.len() == expected_len => {
            Ok(EcdsaSignatureEncoding::Ambiguous)
        }
        Ok(Some(())) => Ok(EcdsaSignatureEncoding::Asn1Der),
        Ok(None) | Err(_) if signature_value.len() == expected_len => {
            Ok(EcdsaSignatureEncoding::XmlDsigFixed)
        }
        Ok(None) | Err(_) => Err(SignatureVerificationError::InvalidSignatureFormat),
    }
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
            SignatureAlgorithm::EcdsaP256Sha256,
            SignatureAlgorithm::EcdsaP384Sha384,
        ] {
            let err = minimum_rsa_modulus_bits(algorithm).unwrap_err();
            assert!(matches!(
                err,
                SignatureVerificationError::UnsupportedAlgorithm { .. }
            ));
        }
    }

    #[test]
    fn der_like_prefix_with_fixed_width_len_is_classified_as_raw() {
        let mut signature = vec![0xAA_u8; 96];
        signature[0] = 0x30;
        signature[1] = 0x20;

        let encoding = classify_ecdsa_signature_encoding(&signature, 48)
            .expect("same-width signature with invalid DER must fall back to raw");
        assert_eq!(encoding, EcdsaSignatureEncoding::XmlDsigFixed);
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
    fn same_width_valid_der_is_marked_ambiguous() {
        let mut signature = Vec::with_capacity(64);
        signature.extend_from_slice(&[0x30, 0x3e, 0x02, 0x1d]);
        signature.extend(std::iter::repeat_n(0x11_u8, 29));
        signature.extend_from_slice(&[0x02, 0x1d]);
        signature.extend(std::iter::repeat_n(0x22_u8, 29));

        let encoding = classify_ecdsa_signature_encoding(&signature, 32)
            .expect("same-width structurally valid DER should classify as ambiguous");
        assert_eq!(encoding, EcdsaSignatureEncoding::Ambiguous);
    }

    #[test]
    fn der_integer_longer_than_component_requires_sign_byte() {
        let mut signature = Vec::with_capacity(72);
        signature.extend_from_slice(&[0x30, 0x46, 0x02, 0x21, 0x01]);
        signature.extend(std::iter::repeat_n(0x11_u8, 32));
        signature.extend_from_slice(&[0x02, 0x21, 0x01]);
        signature.extend(std::iter::repeat_n(0x22_u8, 32));

        let encoding = classify_ecdsa_signature_encoding(&signature, 32);
        assert!(matches!(
            encoding,
            Err(SignatureVerificationError::InvalidSignatureFormat)
        ));
    }
}
