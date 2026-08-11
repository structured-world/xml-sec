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
    /// A configured resource limit violates a structural policy requirement.
    #[error("{resource} has invalid policy limit {actual}: {requirement}")]
    InvalidResourceLimit {
        /// Resource whose configured limit was rejected.
        resource: &'static str,
        /// Required property of the configured limit.
        requirement: &'static str,
        /// Rejected configured value.
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
    /// Maximum inherited `xml:base` components in one URI resolution.
    pub max_xml_base_components: usize,
    /// Maximum cumulative bytes processed while resolving `xml:base` URIs.
    pub max_xml_base_resolution_bytes: usize,
    /// Maximum canonical bytes retained across one signature operation.
    pub max_canonicalized_bytes: usize,
    /// Maximum decoded external resource bytes.
    pub max_external_resource_bytes: usize,
    /// Maximum bytes in the complete external map and cumulatively dereferenced.
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
            max_xml_base_components: crate::hard_limits::XML_BASE_COMPONENT_CEILING,
            max_xml_base_resolution_bytes: crate::hard_limits::XML_BASE_RESOLUTION_BYTE_CEILING,
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
            "XML Base components",
            self.max_xml_base_components,
            crate::hard_limits::XML_BASE_COMPONENT_CEILING,
        )?;
        Self::within(
            "XML Base resolution bytes",
            self.max_xml_base_resolution_bytes,
            crate::hard_limits::XML_BASE_RESOLUTION_BYTE_CEILING,
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
        if selected > ceiling {
            return Err(PolicyViolation::ResourceLimit {
                resource,
                maximum: ceiling,
                actual: selected,
            });
        }
        Ok(())
    }

    fn nonzero_within(
        resource: &'static str,
        selected: usize,
        ceiling: usize,
    ) -> Result<(), PolicyViolation> {
        if selected == 0 {
            return Err(PolicyViolation::InvalidResourceLimit {
                resource,
                requirement: "limit must be nonzero",
                actual: selected,
            });
        }
        Self::within(resource, selected, ceiling)
    }
}

/// XML parsing decisions shared by all operation policies.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct XmlInputPolicy {
    /// Permit bounded internal DTD declarations. External resolution stays off.
    pub allow_internal_dtd: bool,
}

/// An RFC 5280 extended-key-purpose identifier accepted for XML signing.
#[cfg(feature = "xmldsig")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ExtendedKeyPurpose {
    /// TLS server authentication (`id-kp-serverAuth`).
    ServerAuth,
    /// TLS client authentication (`id-kp-clientAuth`).
    ClientAuth,
    /// Executable code signing (`id-kp-codeSigning`).
    CodeSigning,
    /// Email protection (`id-kp-emailProtection`).
    EmailProtection,
    /// Trusted timestamping (`id-kp-timeStamping`).
    TimeStamping,
    /// OCSP response signing (`id-kp-OCSPSigning`).
    OcspSigning,
    /// Application-defined purpose represented as OID arcs.
    Other(Vec<u64>),
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
    /// Purposes accepted when any certificate in a path carries ExtendedKeyUsage.
    ///
    /// An empty set accepts only paths whose certificates omit ExtendedKeyUsage
    /// or use `anyExtendedKeyUsage`; it does not treat TLS/code-signing purposes
    /// as a generic authorization for XML signatures.
    pub allowed_extended_key_usages: HashSet<ExtendedKeyPurpose>,
    /// Authenticate and enforce embedded CRLs during path validation.
    /// Requires [`Self::verify_x509_chains`].
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
            allowed_extended_key_usages: HashSet::new(),
            check_crls: false,
            verification_time: None,
        }
    }
}

#[cfg(feature = "xmldsig")]
impl KeyTrustPolicy {
    pub(crate) fn validate(&self) -> Result<(), PolicyViolation> {
        if self.check_crls && !self.verify_x509_chains {
            return Err(PolicyViolation::KeyTrust {
                reason: "CRL checking requires X.509 chain validation",
            });
        }
        if self
            .allowed_extended_key_usages
            .iter()
            .any(|purpose| match purpose {
                ExtendedKeyPurpose::Other(arcs) => {
                    arcs.len() < 2 || arcs[0] > 2 || (arcs[0] < 2 && arcs[1] > 39)
                }
                _ => false,
            })
        {
            return Err(PolicyViolation::KeyTrust {
                reason: "custom extended key purposes must contain valid OID arcs",
            });
        }
        ResourcePolicy::nonzero_within("X.509 chain depth", self.max_x509_chain_depth, 9)?;
        ResourcePolicy::nonzero_within("X.509 candidate paths", self.max_x509_candidate_paths, 64)
    }
}

/// Immutable policy snapshot for XMLDSig verification.
#[cfg(feature = "xmldsig")]
#[derive(Debug, Clone, Default)]
pub struct VerificationPolicy {
    /// Allowed signature methods; `None` accepts every implemented method subject to
    /// independent gates such as [`KeyTrustPolicy::allow_legacy_rsa_sha1`].
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
        let mut xml_base_components = ResourcePolicy::default();
        xml_base_components.max_xml_base_components += 1;
        policies.push(xml_base_components);
        let mut xml_base_bytes = ResourcePolicy::default();
        xml_base_bytes.max_xml_base_resolution_bytes += 1;
        policies.push(xml_base_bytes);
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

    #[test]
    fn resource_policy_accepts_zero_as_a_deny_all_ceiling() {
        // Zero is a valid policy decision for resources that an operation can
        // avoid consuming; runtime checks must reject only actual non-zero use.
        let policy = ResourcePolicy {
            max_xml_nodes: 0,
            max_references: 0,
            max_transforms_per_reference: 0,
            max_xml_base_components: 0,
            max_xml_base_resolution_bytes: 0,
            max_canonicalized_bytes: 0,
            max_external_resource_bytes: 0,
            max_external_resource_total_bytes: 0,
            max_encryption_plaintext_bytes: 0,
            max_encryption_document_bytes: 0,
            max_encryption_recipients: 0,
            max_encryption_metadata_bytes: 0,
        };

        assert_eq!(policy.validate(), Ok(()));
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn mandatory_x509_limits_report_the_nonzero_requirement() {
        // A lower-bound violation must not be reported as exceeding the upper
        // ceiling: that diagnostic points callers toward the wrong correction.
        let policy = KeyTrustPolicy {
            max_x509_chain_depth: 0,
            ..KeyTrustPolicy::default()
        };

        let error = policy.validate().expect_err("zero depth must be rejected");
        assert!(
            error.to_string().contains("must be nonzero"),
            "unexpected lower-bound diagnostic: {error}"
        );
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn custom_extended_key_purposes_require_valid_oid_arcs() {
        // The typed policy rejects impossible OIDs when the immutable snapshot
        // is validated instead of silently making the purpose unmatchable.
        let mut policy = KeyTrustPolicy::default();
        policy
            .allowed_extended_key_usages
            .insert(ExtendedKeyPurpose::Other(vec![1, 40, 7]));

        assert!(matches!(
            policy.validate(),
            Err(PolicyViolation::KeyTrust {
                reason: "custom extended key purposes must contain valid OID arcs",
            })
        ));
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn crl_checking_requires_x509_chain_validation() {
        // CRLs authenticate through the validated issuer path. Accepting this
        // combination would advertise a security control the resolver skips.
        let policy = KeyTrustPolicy {
            check_crls: true,
            ..KeyTrustPolicy::default()
        };

        assert!(matches!(
            policy.validate(),
            Err(PolicyViolation::KeyTrust {
                reason: "CRL checking requires X.509 chain validation"
            })
        ));
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
