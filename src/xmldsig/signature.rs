//! Signature verification helpers for `XMLDSig`.
//!
//! Public-key admission and `SignatureValue` framing read the SPKI through
//! the shared PKIX reader and hold for every provider. With `rustcrypto`,
//! this module also carries the built-in RSA PKCS#1 v1.5, DSA and ECDSA
//! verification, including donor P-521 interoperability under the `XMLDSig`
//! `ecdsa-sha384` URI.
//!
//! Input public keys are accepted in `SubjectPublicKeyInfo` (SPKI) form because
//! that is how the vendored PEM fixtures are stored.
//! - RSA keys are parsed from full SPKI DER (`PUBLIC KEY`) and verified via
//!   `RustCrypto` `rsa::pkcs1v15`.
//! - ECDSA keys are validated as uncompressed SEC1 points from the SPKI bit
//!   string and verified with `RustCrypto` curve crates (`p256`/`p384`/`p521`).

#[cfg(feature = "rustcrypto")]
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
#[cfg(feature = "rustcrypto")]
use p384::ecdsa::{Signature as P384Signature, VerifyingKey as P384VerifyingKey};
#[cfg(feature = "rustcrypto")]
use p521::ecdsa::{Signature as P521Signature, VerifyingKey as P521VerifyingKey};
#[cfg(feature = "rustcrypto")]
use rsa::pkcs1v15::{Signature as RsaPkcs1v15Signature, VerifyingKey as RsaVerifyingKey};
#[cfg(feature = "rustcrypto")]
use rsa::signature::hazmat::PrehashVerifier;
#[cfg(feature = "rustcrypto")]
use sha1::Sha1;
#[cfg(feature = "rustcrypto")]
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
#[cfg(feature = "rustcrypto")]
use signature::Verifier;

#[cfg(any(feature = "rustcrypto", test))]
use alloc::vec::Vec;
use alloc::{
    borrow::ToOwned,
    string::{String, ToString},
};

use super::parse::SignatureAlgorithm;
use super::pkix::{CertificateSession, SpkiAlgorithm};
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
    if algorithm.rsa_pss_parameters().is_some() {
        return (1..=crate::hard_limits::RSA_MODULUS_BIT_CEILING / 8)
            .contains(&signature_value.len());
    }
    match algorithm {
        #[cfg(feature = "legacy-algorithms")]
        SignatureAlgorithm::RsaMd5 | SignatureAlgorithm::RsaRipemd160 => {
            (1..=crate::hard_limits::RSA_MODULUS_BIT_CEILING / 8).contains(&signature_value.len())
        }
        #[cfg(feature = "legacy-algorithms")]
        SignatureAlgorithm::HmacMd5 | SignatureAlgorithm::HmacRipemd160 => algorithm
            .hmac_output_bits()
            .is_some_and(|bits| (1..=bits / 8).contains(&signature_value.len())),
        #[cfg(feature = "legacy-algorithms")]
        SignatureAlgorithm::EcdsaRipemd160 => {
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
        SignatureAlgorithm::PostQuantum(algorithm) => {
            signature_value.len() == algorithm.signature_len()
        }
        SignatureAlgorithm::Ed25519
        | SignatureAlgorithm::Ed25519Ctx
        | SignatureAlgorithm::Ed25519Ph => signature_value.len() == 64,
        SignatureAlgorithm::Ed448 | SignatureAlgorithm::Ed448Ph => signature_value.len() == 114,
        // Two equal components of at most 64 octets; the key fixes their minimum.
        #[cfg(feature = "dstu4145")]
        SignatureAlgorithm::Dstu4145Gost34311 | SignatureAlgorithm::Dstu4145Dstu7564_256 => {
            (2..=128).contains(&signature_value.len()) && signature_value.len().is_multiple_of(2)
        }
        SignatureAlgorithm::DsaSha1 | SignatureAlgorithm::DsaSha256 => algorithm
            .dsa_component_len()
            .is_some_and(|component_len| signature_value.len() == component_len * 2),
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
        SignatureAlgorithm::RsaPssSha1
        | SignatureAlgorithm::RsaPssSha224
        | SignatureAlgorithm::RsaPssSha256
        | SignatureAlgorithm::RsaPssSha384
        | SignatureAlgorithm::RsaPssSha512
        | SignatureAlgorithm::RsaPssSha3_224
        | SignatureAlgorithm::RsaPssSha3_256
        | SignatureAlgorithm::RsaPssSha3_384
        | SignatureAlgorithm::RsaPssSha3_512
        | SignatureAlgorithm::RsaPss(_) => unreachable!("PSS handled before dispatch"),
        SignatureAlgorithm::EcdsaSha1
        | SignatureAlgorithm::EcdsaSha224
        | SignatureAlgorithm::EcdsaSha256
        | SignatureAlgorithm::EcdsaSha384
        | SignatureAlgorithm::EcdsaSha512
        | SignatureAlgorithm::EcdsaSha3_224
        | SignatureAlgorithm::EcdsaSha3_256
        | SignatureAlgorithm::EcdsaSha3_384
        | SignatureAlgorithm::EcdsaSha3_512 => {
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

/// A shared-reader refusal of key material read under `session`: resource
/// exhaustion is that account's typed policy violation, anything else a
/// malformed key.
pub(crate) fn key_read_error(
    session: &CertificateSession,
    error: &structured_pkix::Error,
) -> SignatureVerificationError {
    session.resource_violation(error).map_or(
        SignatureVerificationError::InvalidKeyDer,
        SignatureVerificationError::KeyPolicy,
    )
}

/// The RSA key of `spki` admitted for `pss`, read under `session`.
pub(crate) fn read_rsa_public_key<'a>(
    session: &'a CertificateSession,
    spki: &'a [u8],
    pss: Option<super::RsaPssParameters>,
) -> Result<structured_pkix::key::rsa::PublicKey<'a>, SignatureVerificationError> {
    session
        .rsa_public_key(spki, pss)
        .map_err(|error| key_read_error(session, &error))?
        .ok_or(SignatureVerificationError::InvalidKeyDer)
}

/// The `RSAPublicKey` DER inside `spki`, after its algorithm restrictions for
/// `pss` are checked (RFC 4055 section 3.3). Every provider shares this
/// preflight without allocating RSA integers.
#[cfg(feature = "rustcrypto")]
pub(crate) fn rsa_public_key_der<'a>(
    spki: &'a [u8],
    pss: super::RsaPssParameters,
    session: &CertificateSession,
) -> Result<&'a [u8], SignatureVerificationError> {
    // The shared PKIX reader owns SPKI and RSASSA-PSS-params syntax.
    // The SPKI is read at document offset zero, so its source span indexes it.
    let span = read_rsa_public_key(session, spki, Some(pss))?
        .element()
        .span();
    let range = usize::try_from(span.start).ok().and_then(|start| {
        usize::try_from(span.length)
            .ok()
            .and_then(|length| start.checked_add(length))
            .map(|end| start..end)
    });
    range
        .and_then(|range| spki.get(range))
        .ok_or(SignatureVerificationError::InvalidKeyDer)
}

/// The software RSA key of an SPKI, read under `session` with the bare
/// decoder's admission rules.
#[cfg(feature = "rustcrypto")]
fn software_rsa_public_key(
    session: &CertificateSession,
    spki: &[u8],
) -> Result<rsa::RsaPublicKey, SignatureVerificationError> {
    crate::rsa_encoding::read_spki_public_key(session, spki)
        .map_err(|error| key_read_error(session, &error))?
        .ok_or(SignatureVerificationError::InvalidKeyDer)
}

pub(crate) fn signature_value_matches_spki_with_encoding(
    algorithm: SignatureAlgorithm,
    public_key_spki_der: &[u8],
    signature_value: &[u8],
    encoding: EcdsaSignatureValueEncoding,
    session: &CertificateSession,
) -> Result<bool, SignatureVerificationError> {
    if let Some(length) = algorithm.eddsa_signature_len() {
        super::modern::validate_public_key(algorithm, public_key_spki_der, session)?;
        return Ok(signature_value.len() == length);
    }
    if let SignatureAlgorithm::PostQuantum(algorithm) = algorithm {
        #[cfg(feature = "experimental-pq")]
        {
            super::post_quantum::validate_public_key(algorithm, public_key_spki_der, session)?;
            return Ok(signature_value.len() == algorithm.signature_len());
        }
        #[cfg(not(feature = "experimental-pq"))]
        {
            return Err(SignatureVerificationError::UnsupportedAlgorithm {
                uri: algorithm.uri().to_owned(),
            });
        }
    }
    #[cfg(feature = "dstu4145")]
    if algorithm.dstu4145_digest().is_some() {
        super::dstu4145::validate_public_key(public_key_spki_der, session)?;
        return Ok(signature_value_matches_algorithm_with_encoding(
            algorithm,
            signature_value,
            encoding,
        ));
    }
    if let Some(parameters) = algorithm.rsa_pss_parameters() {
        let modulus =
            read_rsa_public_key(session, public_key_spki_der, Some(parameters))?.modulus();
        let bits = usize::try_from(modulus.bits())
            .map_err(|_| SignatureVerificationError::InvalidKeyDer)?;
        return Ok(
            parameters.fits_modulus_bits(bits) && signature_value.len() == modulus.as_bytes().len()
        );
    }
    let family = session
        .spki_algorithm(public_key_spki_der)
        .map_err(|error| key_read_error(session, &error))?;
    match (algorithm, family) {
        (
            algorithm @ (SignatureAlgorithm::DsaSha1 | SignatureAlgorithm::DsaSha256),
            SpkiAlgorithm::Dsa,
        ) => {
            let (_, subgroup_bits) = dsa_parameter_bits(public_key_spki_der, session)?;
            let component_len = subgroup_bits.div_ceil(8);
            Ok(algorithm.dsa_component_len() == Some(component_len)
                && signature_value.len() == component_len * 2)
        }
        // RFC 8017 section 8.2.2: the signature is exactly k octets, k the
        // modulus length in octets.
        (method, SpkiAlgorithm::RsaEncryption) if method.is_rsa() => {
            let key = read_rsa_public_key(session, public_key_spki_der, None)?;
            Ok(signature_value.len() == key.modulus().as_bytes().len())
        }
        (method, SpkiAlgorithm::Ec) if method.ecdsa_digest().is_some() => {
            let (curve, _) = ecdsa_public_key(session, public_key_spki_der)?;
            let component_len = curve.component_len();
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
        _ => Err(SignatureVerificationError::KeyAlgorithmMismatch {
            uri: algorithm.uri().to_owned(),
        }),
    }
}

/// Errors while preparing or running `XMLDSig` signature verification.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignatureVerificationError {
    /// The provided PEM block could not be parsed as PEM input.
    #[error("invalid PEM public key")]
    InvalidKeyPem,

    /// The signature method is not an RSA PKCS#1 v1.5 algorithm.
    #[error("unsupported signature algorithm: {uri}")]
    UnsupportedAlgorithm {
        /// `XMLDSig` algorithm URI used for diagnostics.
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
        /// `XMLDSig` algorithm URI used for diagnostics.
        uri: String,
    },

    /// The provided ECDSA signature bytes do not use the encoding selected by
    /// the active verification policy.
    #[error("invalid ECDSA signature encoding")]
    InvalidSignatureFormat,
}

/// Verify an RSA `XMLDSig` signature using a PEM-encoded SPKI public key.
///
/// The PEM must contain a `PUBLIC KEY` block. Returns `Ok(false)` for signature
/// mismatch and `Err` for algorithm/key preparation errors.
///
/// # Errors
/// Returns an error for invalid PEM or RSA key encoding, an unsupported method,
/// or a key that does not meet the direct helper's strength requirements.
#[cfg(feature = "rustcrypto")]
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

/// Verify an ECDSA `XMLDSig` signature using a PEM-encoded SPKI public key.
///
/// The PEM must contain a `PUBLIC KEY` block. The signature value is expected
/// to use the `XMLDSig` fixed-width `r || s` format required by
/// [RFC 9231 section 2.3.6](https://www.rfc-editor.org/rfc/rfc9231.html#section-2.3.6)
/// (which replaces RFC 6931) and `XMLDSig` 1.1. Use [`verify_ecdsa_signature_pem_with_encoding`] to opt into
/// libxmlsec1's ASN.1 compatibility representation. Returns `Ok(false)` for a
/// signature mismatch and `Err` for key or signature-format errors.
///
/// # Errors
/// Returns an error for invalid PEM, an unsupported algorithm or curve,
/// mismatched key metadata, or invalid signature framing.
#[cfg(feature = "rustcrypto")]
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

/// Verify an ECDSA signature using an explicit `XMLDSig` compatibility encoding.
///
/// # Errors
/// Returns an error for invalid PEM, an unsupported algorithm or curve,
/// mismatched key metadata, or framing inconsistent with `encoding`.
#[cfg(feature = "rustcrypto")]
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

#[cfg(any(feature = "rustcrypto", test))]
fn parse_public_key_pem(public_key_pem: &str) -> Result<Vec<u8>, SignatureVerificationError> {
    let mut block =
        PemBlock::decode(public_key_pem).ok_or(SignatureVerificationError::InvalidKeyPem)?;
    if block.label != "PUBLIC KEY" {
        return Err(SignatureVerificationError::InvalidKeyFormat { label: block.label });
    }
    // Public material needs no wiping; take the buffer instead of copying it.
    Ok(core::mem::take(&mut *block.contents))
}

/// One decoded PEM block of caller-supplied key or certificate text.
#[cfg(any(feature = "rustcrypto", test))]
pub(crate) struct PemBlock {
    /// Type label of the pre-encapsulation boundary.
    pub(crate) label: String,
    /// Decoded contents; private keys pass through here, so they are wiped on drop.
    pub(crate) contents: zeroize::Zeroizing<Vec<u8>>,
}

#[cfg(any(feature = "rustcrypto", test))]
impl PemBlock {
    /// Decodes exactly one block under RFC 7468 section 2: explanatory text may
    /// precede it, only whitespace may follow, and both boundaries carry the same label.
    pub(crate) fn decode(text: &str) -> Option<Self> {
        let mut decoder = der::pem::Decoder::new_detect_wrap(text.trim_end().as_bytes()).ok()?;
        let label = decoder.type_label().to_owned();
        let mut contents = zeroize::Zeroizing::new(Vec::with_capacity(decoder.remaining_len()));
        decoder.decode_to_end(&mut contents).ok()?;
        Some(Self { label, contents })
    }
}

/// Verify an RSA `XMLDSig` signature using DER-encoded SPKI public key bytes.
///
/// The input must be an X.509 `SubjectPublicKeyInfo` wrapping an RSA key.
/// Returns `Ok(false)` for signature mismatch and `Err` for algorithm/key
/// preparation errors.
///
/// # Errors
/// Returns an error for invalid or mismatched RSA key encoding, an unsupported
/// method, or a key that does not meet the direct helper's strength requirements.
#[cfg(feature = "rustcrypto")]
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

#[cfg(feature = "rustcrypto")]
pub(crate) fn verify_rsa_signature_spki_with_minimum(
    algorithm: SignatureAlgorithm,
    public_key_spki_der: &[u8],
    signed_data: &[u8],
    signature_value: &[u8],
    minimum_modulus_bits: usize,
) -> Result<bool, SignatureVerificationError> {
    let session = CertificateSession::standalone();
    validate_rsa_signature_spki_with_minimum(
        algorithm,
        public_key_spki_der,
        minimum_modulus_bits,
        &session,
    )?;
    verify_rsa_signature_spki_primitive(
        algorithm,
        public_key_spki_der,
        signed_data,
        signature_value,
        &session,
    )
}

pub(crate) fn validate_rsa_signature_spki_with_minimum(
    algorithm: SignatureAlgorithm,
    public_key_spki_der: &[u8],
    minimum_modulus_bits: usize,
    session: &CertificateSession,
) -> Result<(), SignatureVerificationError> {
    let pss = algorithm.rsa_pss_parameters();
    if pss.is_none()
        && session
            .spki_algorithm(public_key_spki_der)
            .map_err(|error| key_read_error(session, &error))?
            != SpkiAlgorithm::RsaEncryption
    {
        return Err(SignatureVerificationError::KeyAlgorithmMismatch {
            uri: algorithm.uri().to_string(),
        });
    }
    let key = read_rsa_public_key(session, public_key_spki_der, pss)?;
    validate_rsa_public_key(
        key.modulus(),
        key.exponent().as_bytes(),
        algorithm,
        minimum_modulus_bits,
    )
}

#[cfg(feature = "rustcrypto")]
pub(crate) fn verify_rsa_signature_spki_primitive(
    algorithm: SignatureAlgorithm,
    public_key_spki_der: &[u8],
    signed_data: &[u8],
    signature_value: &[u8],
    session: &CertificateSession,
) -> Result<bool, SignatureVerificationError> {
    ensure_rsa_signature_algorithm(algorithm)?;
    if let Some(parameters) = algorithm.rsa_pss_parameters() {
        let key = crate::provider::rsa_pss::public_key(public_key_spki_der, parameters, session)?;
        return Ok(crate::provider::rsa_pss::verify(
            &key,
            parameters,
            signed_data,
            signature_value,
        ));
    }
    let key = software_rsa_public_key(session, public_key_spki_der)?;
    let Ok(signature) = RsaPkcs1v15Signature::try_from(signature_value) else {
        return Ok(false);
    };
    let verified = match algorithm {
        #[cfg(feature = "legacy-algorithms")]
        SignatureAlgorithm::RsaMd5 => RsaVerifyingKey::<md5::Md5>::new(key)
            .verify(signed_data, &signature)
            .is_ok(),
        #[cfg(feature = "legacy-algorithms")]
        SignatureAlgorithm::RsaRipemd160 => RsaVerifyingKey::<ripemd::Ripemd160>::new(key)
            .verify(signed_data, &signature)
            .is_ok(),
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

/// Verify an `XMLDSig` DSA-SHA1 or DSA-SHA256 signature using a DER SPKI public key.
///
/// Signatures contain fixed-width `r || s`, rather than ASN.1 DER: 20-byte
/// components for SHA1 and 32-byte components for SHA256. The direct helper
/// enforces the default DSA key minimum; use a policy-aware verification
/// context for explicitly authorized historical 1024-bit keys.
///
/// # Errors
/// Returns an error for invalid DSA key encoding, an unsupported method,
/// or key parameters that violate the direct helper's strength requirements.
#[cfg(feature = "rustcrypto")]
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

#[cfg(feature = "rustcrypto")]
pub(crate) fn verify_dsa_signature_spki_with_minimum(
    algorithm: SignatureAlgorithm,
    public_key_spki_der: &[u8],
    signed_data: &[u8],
    signature_value: &[u8],
    minimum_modulus_bits: usize,
) -> Result<bool, SignatureVerificationError> {
    let session = CertificateSession::standalone();
    validate_dsa_signature_spki_with_minimum(public_key_spki_der, minimum_modulus_bits, &session)?;
    verify_dsa_signature_spki_primitive(
        algorithm,
        public_key_spki_der,
        signed_data,
        signature_value,
        &session,
    )
}

pub(crate) fn validate_dsa_signature_spki_with_minimum(
    public_key_spki_der: &[u8],
    minimum_modulus_bits: usize,
    session: &CertificateSession,
) -> Result<(), SignatureVerificationError> {
    // The built-in backend refuses an invalid group before the key is used,
    // and its decoded key already carries the width.
    #[cfg(feature = "rustcrypto")]
    let modulus_bits = usize::try_from(
        decode_dsa_verifying_key(public_key_spki_der, session)?
            .components()
            .p()
            .bit_width_vartime(),
    )
    .map_err(|_| SignatureVerificationError::InvalidKeyDer)?;
    #[cfg(not(feature = "rustcrypto"))]
    let (modulus_bits, _) = dsa_parameter_bits(public_key_spki_der, session)?;
    crate::policy::DsaKeyPolicy {
        minimum_modulus_bits,
    }
    .validate_modulus_bits(modulus_bits)
    .map_err(SignatureVerificationError::KeyPolicy)
}

/// Bit widths of the prime `p` and subgroup order `q` a standalone DSA SPKI
/// writes in its `Dss-Parms` (RFC 3279 section 2.3.2), read by the shared
/// PKIX reader. Whether they form a valid group is the verifying provider's
/// decision; zero and over-wide components are refused here.
fn dsa_parameter_bits(
    spki: &[u8],
    session: &CertificateSession,
) -> Result<(usize, usize), SignatureVerificationError> {
    let key = session
        .read_dsa_public_key(spki)
        .map_err(|error| key_read_error(session, &error))?;
    let parameters = key
        .parameters()
        .ok_or(SignatureVerificationError::InvalidKeyDer)?;
    // The reader strips the sign octet, and DER leaves no other leading zero.
    let bits = |magnitude: &[u8]| match magnitude {
        [] | [0] => Err(SignatureVerificationError::InvalidKeyDer),
        bytes if bytes.len() > crate::hard_limits::DSA_KEY_COMPONENT_BYTE_CEILING => {
            Err(SignatureVerificationError::InvalidKeyDer)
        }
        bytes => Ok((bytes.len() - 1) * 8 + (8 - bytes[0].leading_zeros() as usize)),
    };
    Ok((
        bits(parameters.p().as_bytes())?,
        bits(parameters.q().as_bytes())?,
    ))
}

#[cfg(feature = "xmldsig-sign")]
#[derive(der::Sequence)]
pub(crate) struct BorrowedDsaPublicParameters<'a> {
    pub(crate) p: der::asn1::UintRef<'a>,
    pub(crate) q: der::asn1::UintRef<'a>,
    pub(crate) g: der::asn1::UintRef<'a>,
}

#[cfg(feature = "rustcrypto")]
pub(crate) fn decode_dsa_verifying_key(
    bytes: &[u8],
    session: &CertificateSession,
) -> Result<dsa::VerifyingKey, SignatureVerificationError> {
    // The shared PKIX reader owns SPKI and Dss-Parms syntax (RFC 3279 2.3.2);
    // a standalone key must write its own parameters.
    let key = session
        .read_dsa_public_key(bytes)
        .map_err(|error| key_read_error(session, &error))?;
    let parameters = key
        .parameters()
        .ok_or(SignatureVerificationError::InvalidKeyDer)?;
    dsa_verifying_key(
        parameters.p().as_bytes(),
        parameters.q().as_bytes(),
        parameters.g().as_bytes(),
        key.y().as_bytes(),
    )
    .ok_or(SignatureVerificationError::InvalidKeyDer)
}

/// DSA key from unsigned big-endian components, group-validated by `dsa`.
///
/// Component size is a process-safety bound, not a DSA conformance rule; it is
/// checked on borrowed bytes before any allocating bigint conversion.
#[cfg(feature = "rustcrypto")]
pub(crate) fn dsa_verifying_key(
    p: &[u8],
    q: &[u8],
    g: &[u8],
    y: &[u8],
) -> Option<dsa::VerifyingKey> {
    fn trim(bytes: &[u8]) -> &[u8] {
        &bytes[bytes.iter().take_while(|byte| **byte == 0).count()..]
    }
    let [p, q, g, y] = [trim(p), trim(q), trim(g), trim(y)];
    if [p, q, g, y].iter().any(|value| {
        value.is_empty() || value.len() > crate::hard_limits::DSA_KEY_COMPONENT_BYTE_CEILING
    }) {
        return None;
    }
    let components = dsa::Components::from_components(
        crypto_bigint::BoxedUint::from_be_slice_vartime(p),
        crypto_bigint::BoxedUint::from_be_slice_vartime(q),
        crypto_bigint::BoxedUint::from_be_slice_vartime(g),
    )
    .ok()?;
    dsa::VerifyingKey::from_components(
        components,
        crypto_bigint::BoxedUint::from_be_slice_vartime(y),
    )
    .ok()
}

#[cfg(feature = "rustcrypto")]
pub(crate) fn verify_dsa_signature_spki_primitive(
    algorithm: SignatureAlgorithm,
    public_key_spki_der: &[u8],
    signed_data: &[u8],
    signature_value: &[u8],
    session: &CertificateSession,
) -> Result<bool, SignatureVerificationError> {
    if !matches!(
        algorithm,
        SignatureAlgorithm::DsaSha1 | SignatureAlgorithm::DsaSha256
    ) {
        return Err(SignatureVerificationError::UnsupportedAlgorithm {
            uri: algorithm.uri().to_string(),
        });
    }
    let key = decode_dsa_verifying_key(public_key_spki_der, session)?;
    let component_len = usize::try_from(key.components().q().bit_width_vartime())
        .map_err(|_| SignatureVerificationError::InvalidKeyDer)?
        .div_ceil(8);
    if algorithm.dsa_component_len() != Some(component_len) {
        return Ok(false);
    }
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

/// Verify an ECDSA `XMLDSig` signature using DER-encoded SPKI public key bytes.
///
/// The input must be an X.509 `SubjectPublicKeyInfo` wrapping an EC key. The
/// signature value must use `XMLDSig` fixed-width `r || s` bytes. Use
/// [`verify_ecdsa_signature_spki_with_encoding`] to select libxmlsec1's ASN.1
/// compatibility representation explicitly.
///
/// # Errors
/// Returns an error for invalid key encoding, an unsupported algorithm or curve,
/// mismatched key metadata, or malformed fixed-width signature bytes.
#[cfg(feature = "rustcrypto")]
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

/// Verify an ECDSA signature using an explicit `XMLDSig` compatibility encoding.
///
/// # Errors
/// Returns an error for invalid key encoding, an unsupported algorithm or curve,
/// mismatched key metadata, or framing inconsistent with `encoding`.
#[cfg(feature = "rustcrypto")]
#[must_use = "discarding the verification result skips signature validation"]
pub fn verify_ecdsa_signature_spki_with_encoding(
    algorithm: SignatureAlgorithm,
    public_key_spki_der: &[u8],
    signed_data: &[u8],
    signature_value: &[u8],
    encoding: EcdsaSignatureValueEncoding,
) -> Result<bool, SignatureVerificationError> {
    verify_ecdsa_signature_spki_in(
        algorithm,
        public_key_spki_der,
        signed_data,
        signature_value,
        encoding,
        &CertificateSession::standalone(),
    )
}

#[cfg(feature = "rustcrypto")]
pub(crate) fn verify_ecdsa_signature_spki_in(
    algorithm: SignatureAlgorithm,
    public_key_spki_der: &[u8],
    signed_data: &[u8],
    signature_value: &[u8],
    encoding: EcdsaSignatureValueEncoding,
    session: &CertificateSession,
) -> Result<bool, SignatureVerificationError> {
    let digest_algorithm = algorithm.ecdsa_digest().ok_or_else(|| {
        SignatureVerificationError::UnsupportedAlgorithm {
            uri: algorithm.uri().to_string(),
        }
    })?;

    match session
        .spki_algorithm(public_key_spki_der)
        .map_err(|error| key_read_error(session, &error))?
    {
        SpkiAlgorithm::Ec => {
            let (curve, public_key) = ecdsa_public_key(session, public_key_spki_der)?;
            let component_len = curve.component_len();
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
            let prehash = super::compute_digest(digest_algorithm, signed_data);
            match curve {
                EcCurve::P256 => {
                    verify_ecdsa_p256(public_key, &prehash, signature_value, signature_encoding)
                }
                EcCurve::P384 => {
                    verify_ecdsa_p384(public_key, &prehash, signature_value, signature_encoding)
                }
                EcCurve::P521 => {
                    verify_ecdsa_p521(public_key, &prehash, signature_value, signature_encoding)
                }
            }
        }
        _ => Err(SignatureVerificationError::KeyAlgorithmMismatch {
            uri: algorithm.uri().to_string(),
        }),
    }
}

fn validate_rsa_public_key(
    modulus: structured_pkix::key::rsa::Magnitude<'_>,
    exponent: &[u8],
    algorithm: SignatureAlgorithm,
    minimum_modulus_bits: usize,
) -> Result<(), SignatureVerificationError> {
    ensure_rsa_signature_algorithm(algorithm)?;
    validate_rsa_key_components(modulus.as_bytes(), exponent, minimum_modulus_bits)?;
    if let Some(parameters) = algorithm.rsa_pss_parameters() {
        let bits = usize::try_from(modulus.bits())
            .map_err(|_| SignatureVerificationError::InvalidKeyDer)?;
        if !parameters.fits_modulus_bits(bits) {
            return Err(SignatureVerificationError::KeyAlgorithmMismatch {
                uri: algorithm.uri().into(),
            });
        }
    }
    Ok(())
}

/// Apply the RSA key-strength invariant shared by `XMLDSig` and X.509 algorithms.
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
    if algorithm.is_rsa() {
        Ok(())
    } else {
        Err(SignatureVerificationError::UnsupportedAlgorithm {
            uri: algorithm.uri().to_string(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EcCurve {
    P256,
    P384,
    P521,
}

impl EcCurve {
    /// Curve named by the contents octets of an OBJECT IDENTIFIER:
    /// secp256r1 1.2.840.10045.3.1.7, secp384r1 1.3.132.0.34 and secp521r1
    /// 1.3.132.0.35 (RFC 5480 section 2.1.1.1).
    pub(crate) fn from_oid_bytes(oid: &[u8]) -> Option<Self> {
        match oid {
            [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] => Some(Self::P256),
            [0x2b, 0x81, 0x04, 0x00, 0x22] => Some(Self::P384),
            [0x2b, 0x81, 0x04, 0x00, 0x23] => Some(Self::P521),
            _ => None,
        }
    }

    fn component_len(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
            Self::P521 => 66,
        }
    }

    pub(crate) fn validate_point(self, point: &[u8]) -> Result<(), SignatureVerificationError> {
        // RFC 5480 2.2 permits but does not mandate compressed points. This
        // product's uncompressed profile is shared by import and verification.
        // https://www.rfc-editor.org/rfc/rfc5480.html#section-2.2
        if point.len() != self.component_len() * 2 + 1 || point.first() != Some(&4) {
            return Err(SignatureVerificationError::InvalidKeyDer);
        }
        Ok(())
    }
}

/// Supported named curve and validated uncompressed SEC1 point of an EC SPKI,
/// read by the shared PKIX reader; the point borrows `spki`.
fn ecdsa_public_key<'a>(
    session: &CertificateSession,
    spki: &'a [u8],
) -> Result<(EcCurve, &'a [u8]), SignatureVerificationError> {
    let (curve, range) = session
        .ec_named_point(spki)
        .map_err(|error| key_read_error(session, &error))?
        .ok_or(SignatureVerificationError::InvalidKeyDer)?;
    let point = spki
        .get(range)
        .ok_or(SignatureVerificationError::InvalidKeyDer)?;
    curve.validate_point(point)?;
    Ok((curve, point))
}

#[cfg(feature = "rustcrypto")]
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

#[cfg(feature = "rustcrypto")]
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

#[cfg(feature = "rustcrypto")]
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

#[cfg(feature = "rustcrypto")]
trait DecodeEcdsaSignature: Sized {
    fn decode_fixed_width(bytes: &[u8]) -> Result<Self, SignatureVerificationError>;
    fn decode_der(bytes: &[u8]) -> Result<Self, SignatureVerificationError>;
}

#[cfg(feature = "rustcrypto")]
macro_rules! impl_ecdsa_signature_decoder {
    ($signature:ty) => {
        impl DecodeEcdsaSignature for $signature {
            fn decode_fixed_width(bytes: &[u8]) -> Result<Self, SignatureVerificationError> {
                Self::from_slice(bytes)
                    .map_err(|_| SignatureVerificationError::InvalidSignatureFormat)
            }

            fn decode_der(bytes: &[u8]) -> Result<Self, SignatureVerificationError> {
                Self::from_der(bytes)
                    .map_err(|_| SignatureVerificationError::InvalidSignatureFormat)
            }
        }
    };
}

#[cfg(feature = "rustcrypto")]
impl_ecdsa_signature_decoder!(P256Signature);
#[cfg(feature = "rustcrypto")]
impl_ecdsa_signature_decoder!(P384Signature);
#[cfg(feature = "rustcrypto")]
impl_ecdsa_signature_decoder!(P521Signature);

#[cfg(feature = "rustcrypto")]
fn verify_ecdsa_signature<K, S>(
    key: &K,
    signature_value: &[u8],
    signature_encoding: EcdsaSignatureEncoding,
    prehash: &[u8],
) -> Result<bool, SignatureVerificationError>
where
    K: PrehashVerifier<S>,
    S: DecodeEcdsaSignature,
{
    let signature = match signature_encoding {
        EcdsaSignatureEncoding::XmlDsigFixed => S::decode_fixed_width(signature_value)?,
        EcdsaSignatureEncoding::Asn1Der => S::decode_der(signature_value)?,
    };
    Ok(key.verify_prehash(prehash, &signature).is_ok())
}

#[cfg(feature = "rustcrypto")]
fn verify_p256_signature(
    key: &P256VerifyingKey,
    signature_value: &[u8],
    signature_encoding: EcdsaSignatureEncoding,
    prehash: &[u8],
) -> Result<bool, SignatureVerificationError> {
    verify_ecdsa_signature::<_, P256Signature>(key, signature_value, signature_encoding, prehash)
}

#[cfg(feature = "rustcrypto")]
fn verify_p384_signature(
    key: &P384VerifyingKey,
    signature_value: &[u8],
    signature_encoding: EcdsaSignatureEncoding,
    prehash: &[u8],
) -> Result<bool, SignatureVerificationError> {
    verify_ecdsa_signature::<_, P384Signature>(key, signature_value, signature_encoding, prehash)
}

#[cfg(feature = "rustcrypto")]
fn verify_p521_signature(
    key: &P521VerifyingKey,
    signature_value: &[u8],
    signature_encoding: EcdsaSignatureEncoding,
    prehash: &[u8],
) -> Result<bool, SignatureVerificationError> {
    verify_ecdsa_signature::<_, P521Signature>(key, signature_value, signature_encoding, prehash)
}

#[cfg(feature = "rustcrypto")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EcdsaSignatureEncoding {
    XmlDsigFixed,
    Asn1Der,
}

#[cfg(feature = "xmldsig-sign")]
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

#[cfg(feature = "xmldsig-sign")]
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

#[cfg(feature = "xmldsig-sign")]
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

#[cfg(feature = "xmldsig-sign")]
fn encode_der_length(len: usize, output: &mut Vec<u8>) {
    if len < 128 {
        output.push(u8::try_from(len).expect("short DER lengths fit one octet"));
        return;
    }

    let bytes = len.to_be_bytes();
    let first_nonzero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .expect("non-short DER lengths are nonzero");
    let encoded = &bytes[first_nonzero..];
    output.push(
        0x80 | u8::try_from(encoded.len()).expect("a usize length uses at most eight octets"),
    );
    output.extend_from_slice(encoded);
}

#[cfg(feature = "xmldsig-sign")]
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
        .map_err(|()| SignatureVerificationError::InvalidSignatureFormat)?;
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
        .map_err(|()| SignatureVerificationError::InvalidSignatureFormat)?;
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
    if len_len == 0 || len_len > core::mem::size_of::<usize>() || rest.len() < len_len {
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

#[cfg(test)]
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
        let session = CertificateSession::standalone();
        let signature_value_matches_spki = |algorithm, spki: &[u8], value: &[u8]| {
            signature_value_matches_spki_with_encoding(
                algorithm,
                spki,
                value,
                EcdsaSignatureValueEncoding::XmlDsig,
                &session,
            )
        };
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

    #[cfg(feature = "xmldsig-sign")]
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

    #[cfg(feature = "xmldsig-sign")]
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
