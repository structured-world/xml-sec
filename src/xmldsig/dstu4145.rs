//! DSTU 4145 signature verification and the Ukrainian digests, over the
//! published `structured-dstu4145` arithmetic.

use super::{DigestAlgorithm, SignatureAlgorithm, SignatureVerificationError};
use crate::provider::{DigestState, ProviderError};
use alloc::{boxed::Box, vec::Vec};
use once_cell::race::OnceBox;
use structured_dstu4145::{
    accounted::DkeBinding,
    domain::{Domain, Explicit, PublicKey},
    gost::{DEFAULT_DKE, Dke},
    hash::{Hash, State},
};
use structured_pkix::algorithm::dstu4145::{Curve, ExplicitCurve, Parameters};

static TABLE: OnceBox<Dke> = OnceBox::new();

/// Substitution table number one: the digest URI has no parameter to name
/// another, so a key or Reference with a different table is not representable.
fn default_dke() -> &'static Dke {
    TABLE.get_or_init(|| Box::new(Dke::new(&DEFAULT_DKE).expect("the published table is valid")))
}

fn hash(algorithm: DigestAlgorithm) -> Option<Hash<'static>> {
    match algorithm {
        DigestAlgorithm::Gost34311 => Some(Hash::Gost34311(default_dke())),
        DigestAlgorithm::Dstu7564_256 => Some(Hash::Kupyna(32)),
        _ => None,
    }
}

struct UkrainianDigest(State<'static>);

impl DigestState for UkrainianDigest {
    fn update(&mut self, data: &[u8]) -> Result<(), ProviderError> {
        self.0.update(data).map_err(|_| digest_refusal())
    }

    fn finalize(self: Box<Self>) -> Result<Vec<u8>, ProviderError> {
        Ok(self.0.finalize().as_ref().to_vec())
    }
}

fn digest_refusal() -> ProviderError {
    ProviderError::Unsupported {
        operation: crate::provider::ProviderOperation::Digest,
        algorithm: None,
    }
}

/// One-shot digest of `parts`. Fixed outputs and an input bounded by the
/// addressable range leave no failure for the two known identities.
pub(crate) fn digest_parts(algorithm: DigestAlgorithm, parts: &[&[u8]]) -> Vec<u8> {
    let identity = hash(algorithm).expect("a Ukrainian digest");
    let mut state = State::new(identity).expect("a fixed output width");
    for part in parts {
        state.update(part).expect("input within u64");
    }
    state.finalize().as_ref().to_vec()
}

/// Whether `algorithm` is one of the digests this module executes.
pub(crate) const fn is_ukrainian_digest(algorithm: DigestAlgorithm) -> bool {
    matches!(
        algorithm,
        DigestAlgorithm::Gost34311 | DigestAlgorithm::Dstu7564_256
    )
}

/// Start the incremental digest of a Ukrainian `algorithm`.
pub(crate) fn begin_digest(
    algorithm: DigestAlgorithm,
) -> Result<Box<dyn DigestState>, ProviderError> {
    let identity = hash(algorithm).ok_or_else(digest_refusal)?;
    let state = State::new(identity).map_err(|_| digest_refusal())?;
    Ok(Box::new(UkrainianDigest(state)))
}

/// The numeric domain written in `curve`, for the crate's own validation.
fn explicit_input<'a>(
    curve: &ExplicitCurve<'a>,
    byte_order: structured_dstu4145::ByteOrder,
) -> Option<Explicit<'a>> {
    let a = match curve.a().value().as_u64() {
        Some(0) => false,
        Some(1) => true,
        _ => return None,
    };
    Some(Explicit {
        degree: curve.degree_value(),
        reduction: curve.reduction(),
        a,
        b: curve.b().as_bytes(),
        order: curve.order().value().as_bytes(),
        base_point: curve.base_point().as_bytes(),
        byte_order,
    })
}

/// The domain named or written in `parameters`. A custom domain needs primality
/// evidence that a certificate does not carry, so it stays unsupported.
fn domain(
    parameters: &Parameters<'_>,
    profile: structured_pkix::algorithm::dstu4145::Profile,
) -> Option<Domain> {
    match parameters.curve() {
        Curve::Named(named) => {
            let (basis, degree) = named.known()?;
            (basis == profile.basis())
                .then(|| Domain::named(basis, degree as usize).ok())
                .flatten()
        }
        Curve::Explicit(curve) => {
            Domain::explicit(explicit_input(&curve, profile.byte_order())?).ok()
        }
    }
}

/// A validated public key of `der` and its signature byte order.
fn public_key(
    der: &[u8],
    session: &super::pkix::CertificateSession,
) -> Result<(PublicKey, structured_dstu4145::ByteOrder), SignatureVerificationError> {
    session
        .with_public_key_info(der, |info, execution| {
            let key = structured_pkix::key::dstu4145::read(info, execution)?;
            Ok(prepared(&key, execution))
        })
        .map_err(|error| super::signature::key_read_error(session, &error))?
        .ok_or(SignatureVerificationError::InvalidKeyDer)
}

fn prepared(
    key: &structured_pkix::key::dstu4145::PublicKey<'_>,
    execution: &structured_asn1::memory::Execution<'_>,
) -> Option<(PublicKey, structured_dstu4145::ByteOrder)> {
    let profile = key.profile();
    let parameters = key.parameters()?;
    // A key under another table signs digests no supported URI can identify.
    DkeBinding::new(parameters, default_dke(), execution).ok()?;
    let byte_order = profile.byte_order();
    let public = domain(&parameters, profile)?
        .public_key(key.point().as_bytes(), byte_order)
        .ok()?;
    Some((public, byte_order))
}

/// Verify `signature`, the bare signature octets, for an ASN.1 carrier: there
/// the identifier, not the key, states the byte order.
pub(crate) fn verify_identified(
    digest: DigestAlgorithm,
    big_endian: bool,
    issuer_spki: &[u8],
    signed_data: &[u8],
    signature: &[u8],
    session: &super::pkix::CertificateSession,
) -> Result<bool, SignatureVerificationError> {
    let (key, _) = public_key(issuer_spki, session)?;
    let byte_order = if big_endian {
        structured_dstu4145::ByteOrder::BigEndian
    } else {
        structured_dstu4145::ByteOrder::LittleEndian
    };
    key.verify_prehash(&digest_parts(digest, &[signed_data]), signature, byte_order)
        .map_err(|_| SignatureVerificationError::InvalidSignatureFormat)
}

/// Check that `der` is a usable DSTU 4145 key.
pub(crate) fn validate_public_key(
    der: &[u8],
    session: &super::pkix::CertificateSession,
) -> Result<(), SignatureVerificationError> {
    public_key(der, session).map(|_| ())
}

/// Verify `signature` over `message`: hash it with the method's digest, then
/// hand the digest octets unchanged to the verifier.
pub(crate) fn verify(
    algorithm: SignatureAlgorithm,
    der: &[u8],
    message: &[u8],
    signature: &[u8],
    session: &super::pkix::CertificateSession,
) -> Result<bool, SignatureVerificationError> {
    let digest = algorithm.dstu4145_digest().and_then(hash).ok_or_else(|| {
        SignatureVerificationError::UnsupportedAlgorithm {
            uri: alloc::borrow::ToOwned::to_owned(algorithm.uri()),
        }
    })?;
    let (key, byte_order) = public_key(der, session)?;
    let mut state = State::new(digest).map_err(|_| SignatureVerificationError::InvalidKeyDer)?;
    state
        .update(message)
        .map_err(|_| SignatureVerificationError::InvalidSignatureFormat)?;
    key.verify_prehash(state.finalize().as_ref(), signature, byte_order)
        .map_err(|_| SignatureVerificationError::InvalidSignatureFormat)
}
