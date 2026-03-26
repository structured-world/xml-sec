//! RSA signature verification helpers for XMLDSig.
//!
//! This module covers roadmap task P1-019: RSA PKCS#1 v1.5 verification for
//! `rsa-sha1`, `rsa-sha256`, `rsa-sha384`, and `rsa-sha512`.
//!
//! Input public keys are accepted in SubjectPublicKeyInfo (SPKI) form because
//! that is how the vendored PEM fixtures are stored. `ring` expects the inner
//! ASN.1 `RSAPublicKey` bytes, so we validate and unwrap SPKI first.

use ring::signature;
use x509_parser::prelude::FromDer;
use x509_parser::public_key::PublicKey;
use x509_parser::x509::SubjectPublicKeyInfo;

use super::parse::SignatureAlgorithm;

/// Errors while preparing or running RSA signature verification.
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

    /// The provided DER bytes were not a valid SPKI-encoded RSA public key.
    #[error("invalid RSA SubjectPublicKeyInfo DER")]
    InvalidKeyDer,
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
    let (rest, pem) = x509_parser::pem::parse_x509_pem(public_key_pem.as_bytes())
        .map_err(|_| SignatureVerificationError::InvalidKeyPem)?;
    if !rest.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Err(SignatureVerificationError::InvalidKeyPem);
    }
    if pem.label != "PUBLIC KEY" {
        return Err(SignatureVerificationError::InvalidKeyFormat { label: pem.label });
    }

    verify_rsa_signature_spki(algorithm, &pem.contents, signed_data, signature_value)
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
    let verification_algorithm = verification_algorithm(algorithm)?;
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
            let key = signature::UnparsedPublicKey::new(
                verification_algorithm,
                spki.subject_public_key.data,
            );
            Ok(key.verify(signed_data, signature_value).is_ok())
        }
        _ => Err(SignatureVerificationError::InvalidKeyDer),
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

fn verification_algorithm(
    algorithm: SignatureAlgorithm,
) -> Result<&'static dyn signature::VerificationAlgorithm, SignatureVerificationError> {
    match algorithm {
        SignatureAlgorithm::RsaSha1 => Ok(&signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY),
        SignatureAlgorithm::RsaSha256 => Ok(&signature::RSA_PKCS1_2048_8192_SHA256),
        SignatureAlgorithm::RsaSha384 => Ok(&signature::RSA_PKCS1_2048_8192_SHA384),
        SignatureAlgorithm::RsaSha512 => Ok(&signature::RSA_PKCS1_2048_8192_SHA512),
        _ => Err(SignatureVerificationError::UnsupportedAlgorithm {
            uri: algorithm.uri().to_string(),
        }),
    }
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
            let err = verification_algorithm(algorithm).unwrap_err();
            assert!(matches!(
                err,
                SignatureVerificationError::UnsupportedAlgorithm { .. }
            ));
        }
    }
}
