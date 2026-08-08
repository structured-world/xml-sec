//! Immutable security policy snapshots shared by XML Security operations.
//!
//! Policy contains trusted, reusable decisions. Caller-owned keys, selected
//! document targets, tenant identity, and external resource bytes remain in
//! operation request contexts and are deliberately not stored here.

#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
use std::collections::HashSet;
#[cfg(feature = "xmldsig")]
use std::time::SystemTime;

#[cfg(feature = "xmldsig")]
use crate::xmldsig::{DigestAlgorithm, SignatureAlgorithm, UriTypeSet, XPathHereSemantics};
#[cfg(feature = "xmlenc")]
use crate::xmlenc::{
    DataEncryptionAlgorithm, KeyTransportAlgorithm, KeyWrapAlgorithm, OaepDigestAlgorithm,
};

/// A typed rejection produced by an operation policy.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyViolation {
    /// An algorithm is outside the operation allowlist.
    #[error("{operation} policy rejects algorithm {algorithm}")]
    Algorithm {
        /// Operation evaluating the algorithm.
        operation: &'static str,
        /// Stable algorithm URI or diagnostic name.
        algorithm: String,
    },
    /// An input exceeds a configured resource ceiling.
    #[error("{resource} exceeds policy maximum {maximum}: got {actual}")]
    ResourceLimit {
        /// Resource whose consumption was rejected.
        resource: &'static str,
        /// Effective policy ceiling.
        maximum: usize,
        /// Observed consumption.
        actual: usize,
    },
    /// The selected key source or trust mode is disallowed.
    #[error("key/trust policy rejected the operation: {reason}")]
    KeyTrust {
        /// Non-secret reason suitable for diagnostics.
        reason: &'static str,
    },
    /// XML parser behavior is disallowed.
    #[error("XML input policy rejected the operation: {reason}")]
    XmlInput {
        /// Non-secret reason suitable for diagnostics.
        reason: &'static str,
    },
}

/// Resource ceilings shared by parsing, transforms, and cryptographic output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePolicy {
    /// Maximum XML nodes in one parsed document.
    pub max_xml_nodes: usize,
    /// Maximum references in one signature or manifest.
    pub max_references: usize,
    /// Maximum transforms in one reference.
    pub max_transforms_per_reference: usize,
    /// Maximum canonical bytes retained across one signature operation.
    pub max_canonicalized_bytes: usize,
    /// Maximum decoded external resource bytes.
    pub max_external_resource_bytes: usize,
    /// Maximum aggregate external resource bytes.
    pub max_external_resource_total_bytes: usize,
    /// Maximum XMLEnc plaintext bytes.
    pub max_encryption_plaintext_bytes: usize,
    /// Maximum caller-owned XML bytes accepted by XMLEnc document operations.
    pub max_encryption_document_bytes: usize,
    /// Maximum independently wrapped recipients.
    pub max_encryption_recipients: usize,
    /// Maximum caller-controlled XMLEnc metadata bytes per field.
    pub max_encryption_metadata_bytes: usize,
}

impl Default for ResourcePolicy {
    fn default() -> Self {
        Self {
            max_xml_nodes: crate::hard_limits::XML_DOCUMENT_NODE_CEILING as usize,
            max_references: 64,
            max_transforms_per_reference: 64,
            max_canonicalized_bytes: crate::hard_limits::CANONICALIZED_SIGNATURE_DATA_BYTE_CEILING,
            max_external_resource_bytes: crate::hard_limits::EXTERNAL_RESOURCE_BYTE_CEILING,
            max_external_resource_total_bytes:
                crate::hard_limits::EXTERNAL_RESOURCE_TOTAL_BYTE_CEILING,
            max_encryption_plaintext_bytes: crate::hard_limits::ENCRYPTION_PLAINTEXT_BYTE_CEILING,
            max_encryption_document_bytes: crate::hard_limits::ENCRYPTION_DOCUMENT_BYTE_CEILING,
            max_encryption_recipients: crate::hard_limits::ENCRYPTION_RECIPIENT_CEILING,
            max_encryption_metadata_bytes: crate::hard_limits::ENCRYPTION_METADATA_BYTE_CEILING,
        }
    }
}

impl ResourcePolicy {
    /// Validate policy values against non-configurable implementation ceilings.
    pub fn validate(&self) -> Result<(), PolicyViolation> {
        Self::within(
            "XML nodes",
            self.max_xml_nodes,
            crate::hard_limits::XML_DOCUMENT_NODE_CEILING as usize,
        )?;
        Self::within(
            "canonicalized bytes",
            self.max_canonicalized_bytes,
            crate::hard_limits::CANONICALIZED_SIGNATURE_DATA_BYTE_CEILING,
        )?;
        Self::within("signature references", self.max_references, 64)?;
        Self::within(
            "reference transforms",
            self.max_transforms_per_reference,
            64,
        )?;
        Self::within(
            "encryption document",
            self.max_encryption_document_bytes,
            crate::hard_limits::ENCRYPTION_DOCUMENT_BYTE_CEILING,
        )?;
        Self::within(
            "external resource bytes",
            self.max_external_resource_bytes,
            crate::hard_limits::EXTERNAL_RESOURCE_BYTE_CEILING,
        )?;
        Self::within(
            "aggregate external resource bytes",
            self.max_external_resource_total_bytes,
            crate::hard_limits::EXTERNAL_RESOURCE_TOTAL_BYTE_CEILING,
        )?;
        Self::within(
            "encryption plaintext bytes",
            self.max_encryption_plaintext_bytes,
            crate::hard_limits::ENCRYPTION_PLAINTEXT_BYTE_CEILING,
        )?;
        Self::within(
            "encryption recipients",
            self.max_encryption_recipients,
            crate::hard_limits::ENCRYPTION_RECIPIENT_CEILING,
        )?;
        Self::within(
            "encryption metadata bytes",
            self.max_encryption_metadata_bytes,
            crate::hard_limits::ENCRYPTION_METADATA_BYTE_CEILING,
        )
    }

    fn within(
        resource: &'static str,
        selected: usize,
        ceiling: usize,
    ) -> Result<(), PolicyViolation> {
        if selected == 0 || selected > ceiling {
            return Err(PolicyViolation::ResourceLimit {
                resource,
                maximum: ceiling,
                actual: selected,
            });
        }
        Ok(())
    }
}

/// XML parsing decisions shared by all operation policies.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct XmlInputPolicy {
    /// Permit bounded internal DTD declarations. External resolution stays off.
    pub allow_internal_dtd: bool,
}

/// X.509 and key-resolution decisions for verification.
#[cfg(feature = "xmldsig")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyTrustPolicy {
    /// Require embedded or selected certificates to chain to a configured anchor.
    pub verify_x509_chains: bool,
    /// Maximum validated path depth.
    pub max_x509_chain_depth: usize,
    /// Maximum complete or partial signature-valid path states generated.
    pub max_x509_candidate_paths: usize,
    /// Permit legacy RSA-SHA1 verification after key resolution.
    pub allow_legacy_rsa_sha1: bool,
    /// Authenticate and enforce embedded CRLs during path validation.
    pub check_crls: bool,
    /// Verification time override; `None` selects the system clock.
    pub verification_time: Option<SystemTime>,
}

#[cfg(feature = "xmldsig")]
impl Default for KeyTrustPolicy {
    fn default() -> Self {
        Self {
            verify_x509_chains: false,
            max_x509_chain_depth: 9,
            max_x509_candidate_paths: 64,
            allow_legacy_rsa_sha1: false,
            check_crls: false,
            verification_time: None,
        }
    }
}

#[cfg(feature = "xmldsig")]
impl KeyTrustPolicy {
    pub(crate) fn validate(&self) -> Result<(), PolicyViolation> {
        ResourcePolicy::within("X.509 chain depth", self.max_x509_chain_depth, 9)?;
        ResourcePolicy::within("X.509 candidate paths", self.max_x509_candidate_paths, 64)
    }
}

/// Immutable policy snapshot for XMLDSig verification.
#[cfg(feature = "xmldsig")]
#[derive(Debug, Clone, Default)]
pub struct VerificationPolicy {
    /// Allowed signature methods; `None` accepts every implemented method.
    pub signature_algorithms: Option<HashSet<SignatureAlgorithm>>,
    /// Allowed reference digest methods; `None` accepts every implemented method.
    pub digest_algorithms: Option<HashSet<DigestAlgorithm>>,
    /// Key and certificate trust rules.
    pub key_trust: KeyTrustPolicy,
    /// Allowed Reference URI classes.
    pub reference_uri_types: UriTypeSet,
    /// Allowed RetrievalMethod URI classes.
    pub retrieval_uri_types: UriTypeSet,
    /// Allowed transform and canonicalization URIs; `None` accepts every implemented algorithm.
    pub transforms: Option<HashSet<String>>,
    /// Whether authenticated Manifest references are processed.
    pub process_manifests: bool,
    /// XML parser rules.
    pub xml: XmlInputPolicy,
    /// Node selected for the XPath `here()` extension function.
    pub xpath_here_semantics: XPathHereSemantics,
    /// Resource ceilings.
    pub resources: ResourcePolicy,
}

#[cfg(feature = "xmldsig")]
impl VerificationPolicy {
    /// Validate the complete snapshot against implementation hard ceilings.
    pub fn validate(&self) -> Result<(), PolicyViolation> {
        self.resources.validate()?;
        self.key_trust.validate()
    }

    /// Enforce the signature algorithm after key resolution.
    pub fn check_signature_algorithm(
        &self,
        algorithm: SignatureAlgorithm,
    ) -> Result<(), PolicyViolation> {
        if algorithm == SignatureAlgorithm::RsaSha1 && !self.key_trust.allow_legacy_rsa_sha1 {
            return Err(PolicyViolation::Algorithm {
                operation: "verification",
                algorithm: algorithm.uri().to_string(),
            });
        }
        if self
            .signature_algorithms
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(&algorithm))
        {
            return Err(PolicyViolation::Algorithm {
                operation: "verification",
                algorithm: algorithm.uri().to_string(),
            });
        }
        Ok(())
    }
}

/// Immutable policy snapshot for XMLDSig signing.
#[cfg(feature = "xmldsig")]
#[derive(Debug, Clone, Default)]
pub struct SigningPolicy {
    /// Allowed signing methods; `None` uses the implemented secure defaults.
    pub signature_algorithms: Option<HashSet<SignatureAlgorithm>>,
    /// Allowed reference digest methods; `None` uses the implemented secure defaults.
    pub digest_algorithms: Option<HashSet<DigestAlgorithm>>,
    /// Allowed transform URIs; `None` accepts every implemented transform.
    pub transforms: Option<HashSet<String>>,
    /// XML parser rules.
    pub xml: XmlInputPolicy,
    /// Node selected for the XPath `here()` extension function.
    pub xpath_here_semantics: XPathHereSemantics,
    /// Resource ceilings.
    pub resources: ResourcePolicy,
}

/// Immutable policy snapshot for XMLEnc encryption.
#[cfg(feature = "xmlenc")]
#[derive(Debug, Clone, Default)]
pub struct EncryptionPolicy {
    /// Allowed content-encryption algorithms.
    pub data_algorithms: Option<HashSet<DataEncryptionAlgorithm>>,
    /// Allowed RSA key-transport algorithms.
    pub key_transport_algorithms: Option<HashSet<KeyTransportAlgorithm>>,
    /// Allowed symmetric key-wrap algorithms.
    pub key_wrap_algorithms: Option<HashSet<KeyWrapAlgorithm>>,
    /// Allowed OAEP digest algorithms.
    pub oaep_digests: Option<HashSet<OaepDigestAlgorithm>>,
    /// XML parser rules.
    pub xml: XmlInputPolicy,
    /// Resource ceilings.
    pub resources: ResourcePolicy,
}

/// Immutable policy snapshot for XMLEnc decryption.
#[cfg(feature = "xmlenc")]
pub type DecryptionPolicy = EncryptionPolicy;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_policy_cannot_exceed_implementation_ceiling() {
        let policy = ResourcePolicy {
            max_xml_nodes: 100_001,
            ..ResourcePolicy::default()
        };
        assert!(matches!(
            policy.validate(),
            Err(PolicyViolation::ResourceLimit {
                resource: "XML nodes",
                maximum: 100_000,
                actual: 100_001,
            })
        ));
    }

    #[test]
    fn every_resource_policy_field_obeys_its_hard_ceiling() {
        // Each public tuning knob is only a stricter operational limit; none
        // may raise the implementation's allocation ceiling.
        let mut policies = Vec::new();
        let mut external = ResourcePolicy::default();
        external.max_external_resource_bytes += 1;
        policies.push(external);
        let mut aggregate = ResourcePolicy::default();
        aggregate.max_external_resource_total_bytes += 1;
        policies.push(aggregate);
        let mut plaintext = ResourcePolicy::default();
        plaintext.max_encryption_plaintext_bytes += 1;
        policies.push(plaintext);
        let mut recipients = ResourcePolicy::default();
        recipients.max_encryption_recipients += 1;
        policies.push(recipients);
        let mut metadata = ResourcePolicy::default();
        metadata.max_encryption_metadata_bytes += 1;
        policies.push(metadata);

        for policy in policies {
            assert!(matches!(
                policy.validate(),
                Err(PolicyViolation::ResourceLimit { .. })
            ));
        }
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn rsa_sha1_requires_legacy_verification_policy() {
        let mut policy = VerificationPolicy::default();
        assert!(
            policy
                .check_signature_algorithm(SignatureAlgorithm::RsaSha1)
                .is_err()
        );
        policy.key_trust.allow_legacy_rsa_sha1 = true;
        assert!(
            policy
                .check_signature_algorithm(SignatureAlgorithm::RsaSha1)
                .is_ok()
        );
    }
}
