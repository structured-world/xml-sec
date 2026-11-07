//! What one operation's policy decided, returned with the operation's result.

use super::{Instant, ManifestProcessing, PolicyIdentity, PolicyValidity, PolicyViolation};
use crate::xmldsig::UriClass;
use alloc::{string::String, sync::Arc, vec::Vec};

/// The policy decisions one operation made, and the snapshot it enforced.
///
/// Records name algorithms by their public URI and URIs only by class: they
/// carry no document content, key material or resource bytes. A refusal that
/// ends the operation is its error, not a record here. Resource ceilings the
/// operation stayed within are identified by [`Self::identity`], whose digest
/// covers every effective limit. How a verifying key was authorized is the
/// verification result's own `key_trust` evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PolicyAudit {
    /// The published snapshot the operation enforced; `None` when the caller
    /// built or customized the policy itself.
    pub identity: Option<Arc<PolicyIdentity>>,
    /// Decisions in the order the operation made them.
    pub decisions: Vec<PolicyDecision>,
}

/// An operation's output, with the audit of the policy that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Audited<T> {
    /// What the operation produced.
    pub output: T,
    /// What its policy decided, and the snapshot it enforced.
    pub policy: PolicyAudit,
}

// Only producing operations (signing and XMLEnc) return an output.
#[cfg(feature = "xmldsig-sign")]
impl<T> Audited<T> {
    pub(crate) fn new(output: T, policy: PolicyAudit) -> Self {
        Self { output, policy }
    }
}

/// One decision of an operation's policy.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyDecision {
    /// The policy permitted this algorithm in this role.
    Algorithm {
        /// What the algorithm does in the operation.
        role: AlgorithmRole,
        /// The algorithm's identifying URI.
        uri: String,
    },
    /// The policy permitted a URI of this class in this role.
    Uri {
        /// What the URI selects.
        role: UriRole,
        /// The URI's structural class.
        class: UriClass,
    },
    /// The policy's Manifest processing applied to an authenticated signature.
    Manifests(ManifestProcessing),
    /// The operation ran under this caller-authorized exception.
    Exception {
        /// The application's audit record of the grant.
        authorization_id: String,
        /// The authenticated principal that granted it.
        authority: String,
        /// The grant's exclusive expiry.
        expires_at: Instant,
    },
    /// The policy refused one input and the operation went on without it,
    /// such as one Reference among several.
    Rejected(PolicyViolation),
}

/// What an algorithm does in an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AlgorithmRole {
    /// `SignatureMethod`.
    Signature,
    /// `CanonicalizationMethod` of `SignedInfo`.
    Canonicalization,
    /// A Reference's `DigestMethod`.
    Digest,
    /// A Reference's `Transform`.
    Transform,
    /// The content `EncryptionMethod`.
    DataEncryption,
    /// A key transport `EncryptionMethod`.
    KeyTransport,
    /// A key wrap `EncryptionMethod`.
    KeyWrap,
}

/// What a URI selects in an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UriRole {
    /// A `Reference` of `SignedInfo`.
    Reference,
    /// A `Reference` of an authenticated `Manifest`.
    ManifestReference,
    /// A `CipherReference` of encrypted data.
    CipherReference,
}

impl PolicyDecision {
    /// The record of operating under `validity`.
    pub(crate) fn exception(validity: &PolicyValidity) -> Self {
        Self::Exception {
            authorization_id: validity.authorization_id.clone(),
            authority: validity.authority.clone(),
            expires_at: validity.expires_at,
        }
    }

    pub(crate) fn algorithm(role: AlgorithmRole, uri: &str) -> Self {
        Self::Algorithm {
            role,
            uri: uri.into(),
        }
    }
}
