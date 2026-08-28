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

/// Canonical diagnostics for limits represented by [`ResourcePolicy`].
///
/// Validation and every enforcement point use the same names so callers can
/// match typed policy violations without operation-specific string drift.
pub(crate) mod resource_name {
    pub const XML_NODES: &str = "XML nodes";
    pub const XML_DEPTH: &str = "XML element depth";
    pub const SIGNATURE_REFERENCES: &str = "signature references";
    pub const REFERENCE_TRANSFORMS: &str = "reference transforms";
    pub const XML_BASE_COMPONENTS: &str = "XML Base components";
    pub const XML_BASE_RESOLUTION_BYTES: &str = "XML Base resolution bytes";
    pub const CANONICALIZED_BYTES: &str = "canonicalized bytes";
    pub const EXTERNAL_RESOURCE_BYTES: &str = "external resource bytes";
    pub const AGGREGATE_EXTERNAL_RESOURCE_BYTES: &str = "aggregate external resource bytes";
    pub const ENCRYPTION_PLAINTEXT_BYTES: &str = "encryption plaintext bytes";
    #[cfg(feature = "xmlenc")]
    pub const AGGREGATE_ENCRYPTION_CIPHER_VALUE_BYTES: &str =
        "aggregate encryption CipherValue bytes";
    pub const XML_DOCUMENT: &str = "XML document";
    pub const XML_PARSE_WORK_BYTES: &str = "cumulative XML parse-work bytes";
    pub const ENCRYPTION_RECIPIENTS: &str = "encryption recipients";
    pub const ENCRYPTION_METADATA_BYTES: &str = "encryption metadata bytes";
    pub const KEY_CANDIDATES: &str = "key candidates";
    pub const KEY_INFO_REFERENCE_DEPTH: &str = "KeyInfoReference depth";
    pub const BASE64_TRANSFORM_INPUT_BYTES: &str = "Base64 transform input bytes";
    pub const BASE64_TRANSFORM_OUTPUT_BYTES: &str = "Base64 transform output bytes";
    pub const XPATH_EXPRESSIONS: &str = "XPath expressions";
    pub const XPATH_EXPRESSION_BYTES: &str = "XPath expression bytes";
    pub const XPATH_EXPRESSION_COMPLEXITY: &str = "XPath expression complexity";
    pub const XPATH_CONTEXT_EVALUATIONS: &str = "XPath context evaluations";
    pub const XPATH_EVALUATION_WORK: &str = "XPath evaluation work";
    pub const XPATH_MIRROR_STRING_BYTES: &str = "XPath mirror string bytes";
    pub const XPATH_STRING_WORK_BYTES: &str = "XPath string-processing work bytes";
    pub const XPATH_NAMESPACE_BINDINGS: &str = "XPath namespace bindings";
    pub const XPATH_NAMESPACE_BYTES: &str = "XPath namespace bytes";
    pub const XPATH_FILTERS: &str = "XPath filters";
    pub const NODE_SET_FILTER_WORK: &str = "node-set filter work";
    pub const NODE_SET_ENTRIES: &str = "node-set entries";
    pub const NODE_SET_OWNED_STRING_BYTES: &str = "node-set owned string bytes";
    pub const NODE_SET_CUMULATIVE_OWNED_STRING_BYTES: &str =
        "cumulative node-set owned string bytes";
}

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
    /// An HMAC output length is outside the operation's configured bounds.
    #[cfg(feature = "xmldsig")]
    #[error("HMAC output length must be between {minimum} and {maximum} bits: got {actual}")]
    HmacOutputLength {
        /// Minimum output length selected by policy.
        minimum: usize,
        /// Full output width of the selected HMAC algorithm.
        maximum: usize,
        /// Parsed output length.
        actual: usize,
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
    /// A URI class is outside the operation policy.
    #[error("{operation} URI policy rejected the operation: {reason}")]
    Uri {
        /// Operation evaluating the URI.
        operation: &'static str,
        /// Non-sensitive reason suitable for diagnostics.
        reason: &'static str,
    },
    /// An RSA key falls outside the operation's configured strength range.
    #[error(
        "{operation} policy requires {key_type} keys between {minimum_bits} and {maximum_bits} bits: got {actual_bits}"
    )]
    KeySize {
        /// Operation evaluating the key.
        operation: &'static str,
        /// Stable key-family diagnostic.
        key_type: &'static str,
        /// Configured minimum modulus width.
        minimum_bits: usize,
        /// Non-configurable implementation ceiling.
        maximum_bits: usize,
        /// Observed normalized modulus width.
        actual_bits: usize,
    },
    /// RSA key material is structurally invalid.
    #[error("{operation} policy rejects invalid {key_type} key material: {reason}")]
    InvalidKeyMaterial {
        /// Operation evaluating the key.
        operation: &'static str,
        /// Stable key-family diagnostic.
        key_type: &'static str,
        /// Non-secret structural rejection reason.
        reason: &'static str,
    },
}

/// HMAC key-strength and truncation requirements shared by signing and verification.
#[cfg(feature = "xmldsig")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HmacPolicy {
    /// Minimum caller-owned secret length in bits.
    pub minimum_key_bits: usize,
    /// Minimum emitted or accepted MAC length in bits.
    pub minimum_output_bits: usize,
}

#[cfg(feature = "xmldsig")]
impl Default for HmacPolicy {
    fn default() -> Self {
        Self {
            minimum_key_bits: 128,
            minimum_output_bits: 128,
        }
    }
}

#[cfg(feature = "xmldsig")]
impl HmacPolicy {
    pub(crate) fn validate(self) -> Result<(), PolicyViolation> {
        if self.minimum_key_bits == 0 || self.minimum_output_bits == 0 {
            return Err(PolicyViolation::KeyTrust {
                reason: "HMAC minimum key and output lengths must be nonzero",
            });
        }
        Ok(())
    }

    pub(crate) fn validate_key_bytes(self, key_bytes: usize) -> Result<(), PolicyViolation> {
        self.validate_key_bits(key_bytes.saturating_mul(8))
    }

    pub(crate) fn validate_key_bits(self, key_bits: usize) -> Result<(), PolicyViolation> {
        if key_bits < self.minimum_key_bits {
            return Err(PolicyViolation::InvalidKeyMaterial {
                operation: "HMAC",
                key_type: "symmetric",
                reason: "secret is shorter than the configured minimum",
            });
        }
        Ok(())
    }

    pub(crate) fn validate_output(
        self,
        algorithm: SignatureAlgorithm,
        selected_bits: usize,
    ) -> Result<(), PolicyViolation> {
        let maximum = algorithm
            .hmac_output_bits()
            .ok_or_else(|| PolicyViolation::Algorithm {
                operation: "HMAC",
                algorithm: algorithm.uri().to_owned(),
            })?;
        // XMLDSig 1.1 section 6.3.1 makes this a protocol floor, not a
        // deployment preference: truncation is at least 80 bits and at least
        // half the underlying digest width. Caller policy may only tighten it.
        let minimum = self.minimum_output_bits.max(80).max(maximum / 2);
        if selected_bits < minimum || selected_bits > maximum {
            return Err(PolicyViolation::HmacOutputLength {
                minimum,
                maximum,
                actual: selected_bits,
            });
        }
        Ok(())
    }
}

/// RSA strength and structural requirements for outbound cryptographic operations.
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RsaKeyPolicy {
    /// Minimum mathematical RSA modulus bit length accepted for new output.
    pub minimum_modulus_bits: usize,
}

/// DSA strength requirements for legacy signature verification.
#[cfg(feature = "xmldsig")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DsaKeyPolicy {
    /// Minimum prime-modulus width accepted for DSA verification.
    pub minimum_modulus_bits: usize,
}

#[cfg(feature = "xmldsig")]
impl Default for DsaKeyPolicy {
    fn default() -> Self {
        Self {
            minimum_modulus_bits: 2048,
        }
    }
}

#[cfg(feature = "xmldsig")]
impl DsaKeyPolicy {
    /// Validate the configured minimum against the implementation ceiling.
    pub fn validate(&self) -> Result<(), PolicyViolation> {
        if self.minimum_modulus_bits == 0 || !self.minimum_modulus_bits.is_multiple_of(64) {
            return Err(PolicyViolation::InvalidResourceLimit {
                resource: "minimum DSA modulus bits",
                requirement: "minimum must be a nonzero multiple of 64 bits",
                actual: self.minimum_modulus_bits,
            });
        }
        ResourcePolicy::within(
            "minimum DSA modulus bits",
            self.minimum_modulus_bits,
            crate::hard_limits::DSA_MODULUS_BIT_CEILING,
        )
    }

    pub(crate) fn validate_modulus_bits(&self, actual_bits: usize) -> Result<(), PolicyViolation> {
        self.validate()?;
        if !(self.minimum_modulus_bits..=crate::hard_limits::DSA_MODULUS_BIT_CEILING)
            .contains(&actual_bits)
        {
            return Err(PolicyViolation::KeySize {
                operation: "verification",
                key_type: "DSA",
                minimum_bits: self.minimum_modulus_bits,
                maximum_bits: crate::hard_limits::DSA_MODULUS_BIT_CEILING,
                actual_bits,
            });
        }
        Ok(())
    }
}

#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
impl Default for RsaKeyPolicy {
    fn default() -> Self {
        Self {
            minimum_modulus_bits: 2048,
        }
    }
}

#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
impl RsaKeyPolicy {
    /// Validate the configured minimum against the implementation ceiling.
    pub fn validate(&self) -> Result<(), PolicyViolation> {
        if self.minimum_modulus_bits == 0 || !self.minimum_modulus_bits.is_multiple_of(8) {
            return Err(PolicyViolation::InvalidResourceLimit {
                resource: "minimum RSA modulus bits",
                requirement: "minimum must be a nonzero whole-byte width",
                actual: self.minimum_modulus_bits,
            });
        }
        ResourcePolicy::within(
            "minimum RSA modulus bits",
            self.minimum_modulus_bits,
            crate::hard_limits::RSA_MODULUS_BIT_CEILING,
        )
    }

    pub(crate) fn validate_components(
        &self,
        operation: &'static str,
        modulus: &[u8],
        exponent: &[u8],
    ) -> Result<usize, PolicyViolation> {
        self.validate()?;
        let modulus = modulus
            .iter()
            .position(|byte| *byte != 0)
            .map(|start| &modulus[start..])
            .ok_or(PolicyViolation::InvalidKeyMaterial {
                operation,
                key_type: "RSA",
                reason: "modulus is zero",
            })?;
        let modulus_bits = modulus
            .len()
            .checked_mul(8)
            .and_then(|width| width.checked_sub(modulus[0].leading_zeros() as usize))
            .ok_or(PolicyViolation::InvalidKeyMaterial {
                operation,
                key_type: "RSA",
                reason: "modulus width overflows",
            })?;
        if !(self.minimum_modulus_bits..=crate::hard_limits::RSA_MODULUS_BIT_CEILING)
            .contains(&modulus_bits)
        {
            return Err(PolicyViolation::KeySize {
                operation,
                key_type: "RSA",
                minimum_bits: self.minimum_modulus_bits,
                maximum_bits: crate::hard_limits::RSA_MODULUS_BIT_CEILING,
                actual_bits: modulus_bits,
            });
        }
        if exponent.is_empty() || exponent.len() > 8 {
            return Err(PolicyViolation::InvalidKeyMaterial {
                operation,
                key_type: "RSA",
                reason: "public exponent has invalid encoding",
            });
        }
        let mut exponent_bytes = [0_u8; 8];
        exponent_bytes[8 - exponent.len()..].copy_from_slice(exponent);
        let exponent = u64::from_be_bytes(exponent_bytes);
        if !(3..=((1_u64 << 33) - 1)).contains(&exponent) || exponent % 2 == 0 {
            return Err(PolicyViolation::InvalidKeyMaterial {
                operation,
                key_type: "RSA",
                reason: "public exponent is outside the supported odd range",
            });
        }
        Ok(modulus.len())
    }
}

/// Resource ceilings shared by parsing, transforms, and cryptographic output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePolicy {
    /// Maximum XML nodes in one parsed document.
    pub max_xml_nodes: usize,
    /// Maximum element nesting depth in one parsed document.
    pub max_xml_depth: usize,
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
    /// Maximum caller-owned XML bytes accepted by any document operation.
    pub max_xml_document_bytes: usize,
    /// Maximum cumulative XML bytes parsed by one operation.
    pub max_xml_parse_work_bytes: usize,
    /// Maximum independently wrapped recipients.
    pub max_encryption_recipients: usize,
    /// Maximum caller-controlled XMLEnc metadata bytes per field.
    pub max_encryption_metadata_bytes: usize,
    /// Maximum key-source expansion work and concrete key or certificate
    /// candidates inspected by one operation stage.
    pub max_key_candidates: usize,
    /// Maximum nested `KeyInfoReference` dereference depth.
    pub max_key_info_reference_depth: usize,
    /// Maximum bytes accepted by Base64 transforms before decoding.
    pub max_base64_transform_input_bytes: usize,
    /// Maximum cumulative bytes emitted by Base64 transforms in one operation.
    pub max_base64_transform_output_bytes: usize,
    /// Maximum XPath expressions evaluated by one signature operation.
    pub max_xpath_expressions: usize,
    /// Maximum UTF-8 bytes in one XPath expression.
    pub max_xpath_expression_bytes: usize,
    /// Maximum structural complexity accepted for one XPath expression.
    pub max_xpath_expression_complexity: usize,
    /// Maximum context-node evaluations for one ordinary XPath transform.
    pub max_xpath_context_evaluations: usize,
    /// Maximum conservative XPath node-evaluation work per operation.
    pub max_xpath_evaluation_work: usize,
    /// Maximum source strings copied into the XPath mirror.
    pub max_xpath_mirror_string_bytes: usize,
    /// Maximum conservative XPath string-processing work per operation.
    pub max_xpath_string_work_bytes: usize,
    /// Maximum namespace bindings captured by one XPath expression.
    pub max_xpath_namespace_bindings: usize,
    /// Maximum aggregate namespace prefix and URI bytes per XPath expression.
    pub max_xpath_namespace_bytes: usize,
    /// Maximum filters in one XPath Filter 2.0 transform.
    pub max_xpath_filters: usize,
    /// Maximum cumulative node-set entries visited by filtering transforms.
    pub max_node_set_filter_work: usize,
    /// Maximum entries materialized in one exact node set.
    pub max_node_set_entries: usize,
    /// Maximum owned string bytes in one materialized node set.
    pub max_node_set_owned_string_bytes: usize,
    /// Maximum cumulative owned node-set string bytes per operation.
    pub max_node_set_cumulative_owned_string_bytes: usize,
}

impl Default for ResourcePolicy {
    fn default() -> Self {
        Self {
            max_xml_nodes: crate::hard_limits::XML_DOCUMENT_NODE_CEILING as usize,
            max_xml_depth: crate::hard_limits::XML_DOCUMENT_DEPTH_CEILING,
            max_references: crate::hard_limits::SIGNATURE_REFERENCE_CEILING,
            max_transforms_per_reference: crate::hard_limits::REFERENCE_TRANSFORM_CEILING,
            max_xml_base_components: crate::hard_limits::XML_BASE_COMPONENT_CEILING,
            max_xml_base_resolution_bytes: crate::hard_limits::XML_BASE_RESOLUTION_BYTE_CEILING,
            max_canonicalized_bytes: crate::hard_limits::CANONICALIZED_SIGNATURE_DATA_BYTE_CEILING,
            max_external_resource_bytes: crate::hard_limits::EXTERNAL_RESOURCE_BYTE_CEILING,
            max_external_resource_total_bytes:
                crate::hard_limits::EXTERNAL_RESOURCE_TOTAL_BYTE_CEILING,
            max_encryption_plaintext_bytes: crate::hard_limits::ENCRYPTION_PLAINTEXT_BYTE_CEILING,
            max_xml_document_bytes: crate::hard_limits::XML_DOCUMENT_BYTE_CEILING,
            max_xml_parse_work_bytes: crate::hard_limits::XML_PARSE_WORK_BYTE_CEILING,
            max_encryption_recipients: crate::hard_limits::ENCRYPTION_RECIPIENT_CEILING,
            max_encryption_metadata_bytes: crate::hard_limits::ENCRYPTION_METADATA_BYTE_CEILING,
            max_key_candidates: crate::hard_limits::KEY_CANDIDATE_CEILING,
            max_key_info_reference_depth: crate::hard_limits::KEY_INFO_REFERENCE_DEPTH_CEILING,
            max_base64_transform_input_bytes:
                crate::hard_limits::BASE64_TRANSFORM_INPUT_BYTE_CEILING,
            max_base64_transform_output_bytes:
                crate::hard_limits::BASE64_TRANSFORM_OUTPUT_BYTE_CEILING,
            max_xpath_expressions: crate::hard_limits::XPATH_EXPRESSION_COUNT_CEILING,
            max_xpath_expression_bytes: crate::hard_limits::XPATH_EXPRESSION_BYTE_CEILING,
            max_xpath_expression_complexity:
                crate::hard_limits::XPATH_EXPRESSION_COMPLEXITY_CEILING,
            max_xpath_context_evaluations: crate::hard_limits::XPATH_CONTEXT_EVALUATION_CEILING,
            max_xpath_evaluation_work: crate::hard_limits::XPATH_EVALUATION_WORK_CEILING,
            max_xpath_mirror_string_bytes: crate::hard_limits::XPATH_MIRROR_STRING_BYTE_CEILING,
            max_xpath_string_work_bytes: crate::hard_limits::XPATH_STRING_WORK_BYTE_CEILING,
            max_xpath_namespace_bindings: crate::hard_limits::XPATH_NAMESPACE_BINDING_CEILING,
            max_xpath_namespace_bytes: crate::hard_limits::XPATH_NAMESPACE_BYTE_CEILING,
            max_xpath_filters: crate::hard_limits::XPATH_FILTER_COUNT_CEILING,
            max_node_set_filter_work: crate::hard_limits::NODE_SET_FILTER_WORK_CEILING,
            max_node_set_entries: crate::hard_limits::NODE_SET_ENTRY_CEILING,
            max_node_set_owned_string_bytes: crate::hard_limits::NODE_SET_OWNED_STRING_BYTE_CEILING,
            max_node_set_cumulative_owned_string_bytes:
                crate::hard_limits::NODE_SET_CUMULATIVE_OWNED_STRING_BYTE_CEILING,
        }
    }
}

impl ResourcePolicy {
    /// Validate policy values against non-configurable implementation ceilings.
    pub fn validate(&self) -> Result<(), PolicyViolation> {
        Self::within(
            resource_name::XML_NODES,
            self.max_xml_nodes,
            crate::hard_limits::XML_DOCUMENT_NODE_CEILING as usize,
        )?;
        Self::within(
            resource_name::XML_DEPTH,
            self.max_xml_depth,
            crate::hard_limits::XML_DOCUMENT_DEPTH_CEILING,
        )?;
        Self::within(
            resource_name::CANONICALIZED_BYTES,
            self.max_canonicalized_bytes,
            crate::hard_limits::CANONICALIZED_SIGNATURE_DATA_BYTE_CEILING,
        )?;
        Self::within(
            resource_name::SIGNATURE_REFERENCES,
            self.max_references,
            crate::hard_limits::SIGNATURE_REFERENCE_CEILING,
        )?;
        Self::within(
            resource_name::REFERENCE_TRANSFORMS,
            self.max_transforms_per_reference,
            crate::hard_limits::REFERENCE_TRANSFORM_CEILING,
        )?;
        Self::within(
            resource_name::XML_BASE_COMPONENTS,
            self.max_xml_base_components,
            crate::hard_limits::XML_BASE_COMPONENT_CEILING,
        )?;
        Self::within(
            resource_name::XML_BASE_RESOLUTION_BYTES,
            self.max_xml_base_resolution_bytes,
            crate::hard_limits::XML_BASE_RESOLUTION_BYTE_CEILING,
        )?;
        Self::within(
            resource_name::XML_DOCUMENT,
            self.max_xml_document_bytes,
            crate::hard_limits::XML_DOCUMENT_BYTE_CEILING,
        )?;
        Self::within(
            resource_name::XML_PARSE_WORK_BYTES,
            self.max_xml_parse_work_bytes,
            crate::hard_limits::XML_PARSE_WORK_BYTE_CEILING,
        )?;
        Self::within(
            resource_name::EXTERNAL_RESOURCE_BYTES,
            self.max_external_resource_bytes,
            crate::hard_limits::EXTERNAL_RESOURCE_BYTE_CEILING,
        )?;
        Self::within(
            resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
            self.max_external_resource_total_bytes,
            crate::hard_limits::EXTERNAL_RESOURCE_TOTAL_BYTE_CEILING,
        )?;
        Self::within(
            resource_name::ENCRYPTION_PLAINTEXT_BYTES,
            self.max_encryption_plaintext_bytes,
            crate::hard_limits::ENCRYPTION_PLAINTEXT_BYTE_CEILING,
        )?;
        Self::within(
            resource_name::ENCRYPTION_RECIPIENTS,
            self.max_encryption_recipients,
            crate::hard_limits::ENCRYPTION_RECIPIENT_CEILING,
        )?;
        Self::within(
            resource_name::ENCRYPTION_METADATA_BYTES,
            self.max_encryption_metadata_bytes,
            crate::hard_limits::ENCRYPTION_METADATA_BYTE_CEILING,
        )?;
        for (resource, selected, ceiling) in [
            (
                resource_name::KEY_CANDIDATES,
                self.max_key_candidates,
                crate::hard_limits::KEY_CANDIDATE_CEILING,
            ),
            (
                resource_name::KEY_INFO_REFERENCE_DEPTH,
                self.max_key_info_reference_depth,
                crate::hard_limits::KEY_INFO_REFERENCE_DEPTH_CEILING,
            ),
            (
                resource_name::BASE64_TRANSFORM_INPUT_BYTES,
                self.max_base64_transform_input_bytes,
                crate::hard_limits::BASE64_TRANSFORM_INPUT_BYTE_CEILING,
            ),
            (
                resource_name::BASE64_TRANSFORM_OUTPUT_BYTES,
                self.max_base64_transform_output_bytes,
                crate::hard_limits::BASE64_TRANSFORM_OUTPUT_BYTE_CEILING,
            ),
            (
                resource_name::XPATH_EXPRESSIONS,
                self.max_xpath_expressions,
                crate::hard_limits::XPATH_EXPRESSION_COUNT_CEILING,
            ),
            (
                resource_name::XPATH_EXPRESSION_BYTES,
                self.max_xpath_expression_bytes,
                crate::hard_limits::XPATH_EXPRESSION_BYTE_CEILING,
            ),
            (
                resource_name::XPATH_EXPRESSION_COMPLEXITY,
                self.max_xpath_expression_complexity,
                crate::hard_limits::XPATH_EXPRESSION_COMPLEXITY_CEILING,
            ),
            (
                resource_name::XPATH_CONTEXT_EVALUATIONS,
                self.max_xpath_context_evaluations,
                crate::hard_limits::XPATH_CONTEXT_EVALUATION_CEILING,
            ),
            (
                resource_name::XPATH_EVALUATION_WORK,
                self.max_xpath_evaluation_work,
                crate::hard_limits::XPATH_EVALUATION_WORK_CEILING,
            ),
            (
                resource_name::XPATH_MIRROR_STRING_BYTES,
                self.max_xpath_mirror_string_bytes,
                crate::hard_limits::XPATH_MIRROR_STRING_BYTE_CEILING,
            ),
            (
                resource_name::XPATH_STRING_WORK_BYTES,
                self.max_xpath_string_work_bytes,
                crate::hard_limits::XPATH_STRING_WORK_BYTE_CEILING,
            ),
            (
                resource_name::XPATH_NAMESPACE_BINDINGS,
                self.max_xpath_namespace_bindings,
                crate::hard_limits::XPATH_NAMESPACE_BINDING_CEILING,
            ),
            (
                resource_name::XPATH_NAMESPACE_BYTES,
                self.max_xpath_namespace_bytes,
                crate::hard_limits::XPATH_NAMESPACE_BYTE_CEILING,
            ),
            (
                resource_name::XPATH_FILTERS,
                self.max_xpath_filters,
                crate::hard_limits::XPATH_FILTER_COUNT_CEILING,
            ),
            (
                resource_name::NODE_SET_FILTER_WORK,
                self.max_node_set_filter_work,
                crate::hard_limits::NODE_SET_FILTER_WORK_CEILING,
            ),
            (
                resource_name::NODE_SET_ENTRIES,
                self.max_node_set_entries,
                crate::hard_limits::NODE_SET_ENTRY_CEILING,
            ),
            (
                resource_name::NODE_SET_OWNED_STRING_BYTES,
                self.max_node_set_owned_string_bytes,
                crate::hard_limits::NODE_SET_OWNED_STRING_BYTE_CEILING,
            ),
            (
                resource_name::NODE_SET_CUMULATIVE_OWNED_STRING_BYTES,
                self.max_node_set_cumulative_owned_string_bytes,
                crate::hard_limits::NODE_SET_CUMULATIVE_OWNED_STRING_BYTE_CEILING,
            ),
        ] {
            Self::within(resource, selected, ceiling)?;
        }
        Ok(())
    }

    pub(crate) fn validate_xml_document_len(&self, actual: usize) -> Result<(), PolicyViolation> {
        if actual > self.max_xml_document_bytes {
            return Err(PolicyViolation::ResourceLimit {
                resource: resource_name::XML_DOCUMENT,
                maximum: self.max_xml_document_bytes,
                actual,
            });
        }
        Ok(())
    }

    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    /// Reject aggregate key-candidate work beyond this policy snapshot.
    pub fn validate_key_candidates(&self, actual: usize) -> Result<(), PolicyViolation> {
        if actual > self.max_key_candidates {
            return Err(PolicyViolation::ResourceLimit {
                resource: resource_name::KEY_CANDIDATES,
                maximum: self.max_key_candidates,
                actual,
            });
        }
        Ok(())
    }

    /// Reject `KeyInfoReference` traversal beyond this policy snapshot.
    #[cfg(feature = "xmldsig")]
    pub fn validate_key_info_reference_depth(&self, actual: usize) -> Result<(), PolicyViolation> {
        if actual > self.max_key_info_reference_depth {
            return Err(PolicyViolation::ResourceLimit {
                resource: resource_name::KEY_INFO_REFERENCE_DEPTH,
                maximum: self.max_key_info_reference_depth,
                actual,
            });
        }
        Ok(())
    }

    pub(crate) fn effective_xml_nodes(&self) -> u32 {
        u32::try_from(self.max_xml_nodes)
            .unwrap_or(crate::hard_limits::XML_DOCUMENT_NODE_CEILING)
            .min(crate::hard_limits::XML_DOCUMENT_NODE_CEILING)
    }

    #[cfg(feature = "xmldsig")]
    pub(crate) fn effective_canonicalized_bytes(&self) -> usize {
        self.max_canonicalized_bytes
            .min(crate::hard_limits::CANONICALIZED_SIGNATURE_DATA_BYTE_CEILING)
    }

    #[cfg(feature = "xmldsig")]
    pub(crate) fn effective_xml_base_components(&self) -> usize {
        self.max_xml_base_components
            .min(crate::hard_limits::XML_BASE_COMPONENT_CEILING)
    }

    #[cfg(feature = "xmldsig")]
    pub(crate) fn effective_xml_base_resolution_bytes(&self) -> usize {
        self.max_xml_base_resolution_bytes
            .min(crate::hard_limits::XML_BASE_RESOLUTION_BYTE_CEILING)
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

    #[cfg(feature = "xmldsig")]
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

/// XMLDSig transform and canonicalization decisions shared by signing and verification.
#[cfg(feature = "xmldsig")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SameDocumentIdSemantics {
    /// Require bare fragment identifiers to satisfy the XML NCName grammar.
    #[default]
    Specification,
    /// Apply libxmlsec1's default barename compatibility grammar.
    ///
    /// Registered non-NCName values are accepted unless a single quote makes
    /// them unrepresentable in the donor's single-quoted XPointer expression.
    /// The resulting node set retains barename semantics and excludes comments.
    XmlSecBarename,
    /// Resolve the fragment text directly as an ID, including non-NCName values.
    ///
    /// This reproduces libxmlsec1's explicit Visa3D compatibility flag.
    XmlSecVisa3d,
}

/// Wire representation used for ECDSA `SignatureValue` bytes.
#[cfg(feature = "xmldsig")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EcdsaSignatureValueEncoding {
    /// XMLDSig fixed-width `r || s` representation.
    #[default]
    XmlDsig,
    /// ASN.1 DER `SEQUENCE(INTEGER(r), INTEGER(s))` compatibility representation.
    XmlSecAsn1Der,
}

/// XMLDSig transform and canonicalization decisions shared by signing and verification.
#[cfg(feature = "xmldsig")]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransformPolicy {
    /// Allowed transform and canonicalization URIs; `None` accepts every implemented algorithm.
    pub allowed_algorithms: Option<HashSet<String>>,
    /// Node selected for the XPath `here()` extension function.
    pub xpath_here_semantics: XPathHereSemantics,
    /// Interpretation of bare same-document ID fragments.
    pub same_document_id_semantics: SameDocumentIdSemantics,
}

/// URI-class decisions shared by XMLDSig reference and key retrieval processing.
#[cfg(feature = "xmldsig")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UriPolicy {
    /// URI classes accepted by SignedInfo and Manifest references.
    pub references: UriTypeSet,
    /// URI classes accepted by RetrievalMethod processing.
    pub retrieval_methods: UriTypeSet,
    /// URI classes accepted by XMLDSig 1.1 `KeyInfoReference` processing.
    pub key_info_references: UriTypeSet,
}

#[cfg(feature = "xmldsig")]
impl Default for UriPolicy {
    fn default() -> Self {
        Self {
            references: UriTypeSet::SAME_DOCUMENT,
            retrieval_methods: UriTypeSet::SAME_DOCUMENT,
            key_info_references: UriTypeSet::SAME_DOCUMENT,
        }
    }
}

/// KeyInfo sources an XMLDSig verification operation is permitted to trust.
#[cfg(feature = "xmldsig")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeySourcePolicy {
    /// Permit a caller-supplied pre-resolved key.
    pub preset_key: bool,
    /// Permit keys selected by document `KeyName`.
    pub key_name: bool,
    /// Permit public keys embedded in `KeyValue`.
    pub key_value: bool,
    /// Permit public keys embedded in `DEREncodedKeyValue`.
    pub der_encoded_key_value: bool,
    /// Permit certificates and selectors embedded in `X509Data`.
    pub x509_data: bool,
    /// Permit `KeyInfoReference` indirection to another bounded `KeyInfo`.
    pub key_info_reference: bool,
}

#[cfg(feature = "xmldsig")]
impl Default for KeySourcePolicy {
    fn default() -> Self {
        Self {
            preset_key: true,
            key_name: true,
            key_value: true,
            der_encoded_key_value: true,
            x509_data: true,
            key_info_reference: true,
        }
    }
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
    /// Legacy signature algorithms explicitly permitted for verification.
    pub allowed_legacy_signature_algorithms: HashSet<SignatureAlgorithm>,
    /// RSA requirements enforced for resolved verification keys and issuer keys.
    pub rsa_keys: RsaKeyPolicy,
    /// DSA requirements enforced for resolved verification keys.
    pub dsa_keys: DsaKeyPolicy,
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
            max_x509_chain_depth: crate::hard_limits::X509_CHAIN_DEPTH_CEILING,
            max_x509_candidate_paths: crate::hard_limits::X509_CANDIDATE_PATH_CEILING,
            allowed_legacy_signature_algorithms: HashSet::new(),
            rsa_keys: RsaKeyPolicy::default(),
            dsa_keys: DsaKeyPolicy::default(),
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
        self.rsa_keys.validate()?;
        self.dsa_keys.validate()?;
        ResourcePolicy::nonzero_within(
            "X.509 chain depth",
            self.max_x509_chain_depth,
            crate::hard_limits::X509_CHAIN_DEPTH_CEILING,
        )?;
        ResourcePolicy::nonzero_within(
            "X.509 candidate paths",
            self.max_x509_candidate_paths,
            crate::hard_limits::X509_CANDIDATE_PATH_CEILING,
        )
    }
}

/// Whether an XMLDSig operation evaluates direct `<Object>/<Manifest>` references.
#[cfg(feature = "xmldsig")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ManifestProcessing {
    /// Leave Manifest reference values untouched and perform no Manifest work.
    #[default]
    Ignore,
    /// Evaluate Manifest references under the operation's shared resource policy.
    Process,
}

/// Immutable policy snapshot for XMLDSig verification.
#[cfg(feature = "xmldsig")]
#[derive(Debug, Clone, Default)]
pub struct VerificationPolicy {
    /// Allowed signature methods; `None` accepts every implemented method subject to
    /// independent gates such as [`KeyTrustPolicy::allowed_legacy_signature_algorithms`].
    pub signature_algorithms: Option<HashSet<SignatureAlgorithm>>,
    /// Allowed reference digest methods; `None` accepts every implemented method.
    pub digest_algorithms: Option<HashSet<DigestAlgorithm>>,
    /// HMAC secret and output-length requirements.
    pub hmac: HmacPolicy,
    /// Required ECDSA `SignatureValue` wire representation.
    pub ecdsa_signature_value_encoding: EcdsaSignatureValueEncoding,
    /// Key and certificate trust rules.
    pub key_trust: KeyTrustPolicy,
    /// KeyInfo source permissions.
    pub key_sources: KeySourcePolicy,
    /// Reference and key-retrieval URI permissions.
    pub uris: UriPolicy,
    /// Transform and canonicalization permissions.
    pub transforms: TransformPolicy,
    /// Whether authenticated Manifest references are processed.
    pub manifest_processing: ManifestProcessing,
    /// XML parser rules.
    pub xml: XmlInputPolicy,
    /// Resource ceilings.
    pub resources: ResourcePolicy,
}

#[cfg(feature = "xmldsig")]
impl VerificationPolicy {
    /// Validate the complete snapshot against implementation hard ceilings.
    pub fn validate(&self) -> Result<(), PolicyViolation> {
        self.resources.validate()?;
        self.key_trust.validate()?;
        self.hmac.validate()
    }

    /// Enforce the signature algorithm after key resolution.
    pub fn check_signature_algorithm(
        &self,
        algorithm: SignatureAlgorithm,
    ) -> Result<(), PolicyViolation> {
        if matches!(
            algorithm,
            SignatureAlgorithm::RsaSha1
                | SignatureAlgorithm::DsaSha1
                | SignatureAlgorithm::HmacSha1
                | SignatureAlgorithm::EcdsaSha1
        ) && !self
            .key_trust
            .allowed_legacy_signature_algorithms
            .contains(&algorithm)
        {
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
    /// HMAC secret and output-length requirements.
    pub hmac: HmacPolicy,
    /// ECDSA `SignatureValue` wire representation emitted by signing.
    pub ecdsa_signature_value_encoding: EcdsaSignatureValueEncoding,
    /// RSA requirements enforced before producing a signature.
    pub rsa_keys: RsaKeyPolicy,
    /// DSA requirements enforced before producing a signature.
    pub dsa_keys: DsaKeyPolicy,
    /// Reference URI permissions. External URIs remain unsupported until the
    /// caller supplies request-scoped external bytes through the signing API.
    pub uris: UriPolicy,
    /// Transform and canonicalization permissions.
    pub transforms: TransformPolicy,
    /// Whether direct `<Object>/<Manifest>` reference digests are populated.
    pub manifest_processing: ManifestProcessing,
    /// XML parser rules.
    pub xml: XmlInputPolicy,
    /// Resource ceilings.
    pub resources: ResourcePolicy,
}

#[cfg(feature = "xmldsig")]
impl SigningPolicy {
    /// Validate the complete snapshot before signing work begins.
    pub fn validate(&self) -> Result<(), PolicyViolation> {
        self.resources.validate()?;
        self.rsa_keys.validate()?;
        self.dsa_keys.validate()?;
        self.hmac.validate()
    }

    pub(crate) fn check_signature_algorithm(
        &self,
        algorithm: SignatureAlgorithm,
    ) -> Result<(), PolicyViolation> {
        let explicitly_allowed = self
            .signature_algorithms
            .as_ref()
            .is_some_and(|allowed| allowed.contains(&algorithm));
        if (!algorithm.signing_allowed() && !explicitly_allowed)
            || self
                .signature_algorithms
                .as_ref()
                .is_some_and(|allowed| !allowed.contains(&algorithm))
        {
            return Err(PolicyViolation::Algorithm {
                operation: "signing",
                algorithm: algorithm.uri().to_owned(),
            });
        }
        Ok(())
    }

    pub(crate) fn check_digest_algorithm(
        &self,
        algorithm: DigestAlgorithm,
    ) -> Result<(), PolicyViolation> {
        let explicitly_allowed = self
            .digest_algorithms
            .as_ref()
            .is_some_and(|allowed| allowed.contains(&algorithm));
        if (!algorithm.signing_allowed() && !explicitly_allowed)
            || self
                .digest_algorithms
                .as_ref()
                .is_some_and(|allowed| !allowed.contains(&algorithm))
        {
            return Err(PolicyViolation::Algorithm {
                operation: "signing",
                algorithm: algorithm.uri().to_owned(),
            });
        }
        Ok(())
    }
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
    /// RSA requirements enforced when producing OAEP key transport.
    pub rsa_keys: RsaKeyPolicy,
    /// XML parser rules.
    pub xml: XmlInputPolicy,
    /// Resource ceilings.
    pub resources: ResourcePolicy,
}

#[cfg(feature = "xmlenc")]
impl EncryptionPolicy {
    /// Validate the complete snapshot before outbound encryption work begins.
    pub fn validate(&self) -> Result<(), PolicyViolation> {
        self.resources.validate()?;
        self.rsa_keys.validate()
    }
}

/// Immutable policy snapshot for XMLEnc decryption.
#[cfg(feature = "xmlenc")]
#[derive(Debug, Clone, Default)]
pub struct DecryptionPolicy {
    /// Allowed content-decryption algorithms.
    pub data_algorithms: Option<HashSet<DataEncryptionAlgorithm>>,
    /// Allowed RSA key-transport algorithms accepted on input.
    pub key_transport_algorithms: Option<HashSet<KeyTransportAlgorithm>>,
    /// Allowed symmetric key-wrap algorithms accepted on input.
    pub key_wrap_algorithms: Option<HashSet<KeyWrapAlgorithm>>,
    /// Allowed OAEP digest algorithms accepted on input.
    pub oaep_digests: Option<HashSet<OaepDigestAlgorithm>>,
    /// XML parser rules.
    pub xml: XmlInputPolicy,
    /// Resource ceilings.
    pub resources: ResourcePolicy,
}

#[cfg(feature = "xmlenc")]
impl DecryptionPolicy {
    /// Validate the complete snapshot before inbound decryption work begins.
    pub fn validate(&self) -> Result<(), PolicyViolation> {
        self.resources.validate()
    }
}

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
                resource: resource_name::XML_NODES,
                maximum: 100_000,
                actual: 100_001,
            })
        ));
    }

    #[test]
    fn xml_parse_work_policy_cannot_exceed_implementation_ceiling() {
        let policy = ResourcePolicy {
            max_xml_parse_work_bytes: crate::hard_limits::XML_PARSE_WORK_BYTE_CEILING
                .saturating_add(1),
            ..ResourcePolicy::default()
        };

        assert_eq!(
            policy.validate(),
            Err(PolicyViolation::ResourceLimit {
                resource: resource_name::XML_PARSE_WORK_BYTES,
                maximum: crate::hard_limits::XML_PARSE_WORK_BYTE_CEILING,
                actual: crate::hard_limits::XML_PARSE_WORK_BYTE_CEILING.saturating_add(1),
            })
        );
    }

    #[test]
    fn every_resource_policy_field_obeys_its_hard_ceiling() {
        // Each public tuning knob is only a stricter operational limit; none
        // may raise the implementation's allocation ceiling. Exact diagnostics
        // also catch a field accidentally paired with another field's ceiling.
        type Case = (&'static str, usize, fn(&mut ResourcePolicy) -> &mut usize);
        let cases: &[Case] = &[
            (
                resource_name::XML_NODES,
                crate::hard_limits::XML_DOCUMENT_NODE_CEILING as usize,
                |p| &mut p.max_xml_nodes,
            ),
            (
                resource_name::XML_DEPTH,
                crate::hard_limits::XML_DOCUMENT_DEPTH_CEILING,
                |p| &mut p.max_xml_depth,
            ),
            (
                resource_name::SIGNATURE_REFERENCES,
                crate::hard_limits::SIGNATURE_REFERENCE_CEILING,
                |p| &mut p.max_references,
            ),
            (
                resource_name::REFERENCE_TRANSFORMS,
                crate::hard_limits::REFERENCE_TRANSFORM_CEILING,
                |p| &mut p.max_transforms_per_reference,
            ),
            (
                resource_name::XML_BASE_COMPONENTS,
                crate::hard_limits::XML_BASE_COMPONENT_CEILING,
                |p| &mut p.max_xml_base_components,
            ),
            (
                resource_name::XML_BASE_RESOLUTION_BYTES,
                crate::hard_limits::XML_BASE_RESOLUTION_BYTE_CEILING,
                |p| &mut p.max_xml_base_resolution_bytes,
            ),
            (
                resource_name::CANONICALIZED_BYTES,
                crate::hard_limits::CANONICALIZED_SIGNATURE_DATA_BYTE_CEILING,
                |p| &mut p.max_canonicalized_bytes,
            ),
            (
                resource_name::EXTERNAL_RESOURCE_BYTES,
                crate::hard_limits::EXTERNAL_RESOURCE_BYTE_CEILING,
                |p| &mut p.max_external_resource_bytes,
            ),
            (
                resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                crate::hard_limits::EXTERNAL_RESOURCE_TOTAL_BYTE_CEILING,
                |p| &mut p.max_external_resource_total_bytes,
            ),
            (
                resource_name::ENCRYPTION_PLAINTEXT_BYTES,
                crate::hard_limits::ENCRYPTION_PLAINTEXT_BYTE_CEILING,
                |p| &mut p.max_encryption_plaintext_bytes,
            ),
            (
                resource_name::XML_DOCUMENT,
                crate::hard_limits::XML_DOCUMENT_BYTE_CEILING,
                |p| &mut p.max_xml_document_bytes,
            ),
            (
                resource_name::XML_PARSE_WORK_BYTES,
                crate::hard_limits::XML_PARSE_WORK_BYTE_CEILING,
                |p| &mut p.max_xml_parse_work_bytes,
            ),
            (
                resource_name::ENCRYPTION_RECIPIENTS,
                crate::hard_limits::ENCRYPTION_RECIPIENT_CEILING,
                |p| &mut p.max_encryption_recipients,
            ),
            (
                resource_name::ENCRYPTION_METADATA_BYTES,
                crate::hard_limits::ENCRYPTION_METADATA_BYTE_CEILING,
                |p| &mut p.max_encryption_metadata_bytes,
            ),
            (
                resource_name::KEY_CANDIDATES,
                crate::hard_limits::KEY_CANDIDATE_CEILING,
                |p| &mut p.max_key_candidates,
            ),
            (
                resource_name::KEY_INFO_REFERENCE_DEPTH,
                crate::hard_limits::KEY_INFO_REFERENCE_DEPTH_CEILING,
                |p| &mut p.max_key_info_reference_depth,
            ),
            (
                resource_name::BASE64_TRANSFORM_INPUT_BYTES,
                crate::hard_limits::BASE64_TRANSFORM_INPUT_BYTE_CEILING,
                |p| &mut p.max_base64_transform_input_bytes,
            ),
            (
                resource_name::BASE64_TRANSFORM_OUTPUT_BYTES,
                crate::hard_limits::BASE64_TRANSFORM_OUTPUT_BYTE_CEILING,
                |p| &mut p.max_base64_transform_output_bytes,
            ),
            (
                resource_name::XPATH_EXPRESSIONS,
                crate::hard_limits::XPATH_EXPRESSION_COUNT_CEILING,
                |p| &mut p.max_xpath_expressions,
            ),
            (
                resource_name::XPATH_EXPRESSION_BYTES,
                crate::hard_limits::XPATH_EXPRESSION_BYTE_CEILING,
                |p| &mut p.max_xpath_expression_bytes,
            ),
            (
                resource_name::XPATH_EXPRESSION_COMPLEXITY,
                crate::hard_limits::XPATH_EXPRESSION_COMPLEXITY_CEILING,
                |p| &mut p.max_xpath_expression_complexity,
            ),
            (
                resource_name::XPATH_CONTEXT_EVALUATIONS,
                crate::hard_limits::XPATH_CONTEXT_EVALUATION_CEILING,
                |p| &mut p.max_xpath_context_evaluations,
            ),
            (
                resource_name::XPATH_EVALUATION_WORK,
                crate::hard_limits::XPATH_EVALUATION_WORK_CEILING,
                |p| &mut p.max_xpath_evaluation_work,
            ),
            (
                resource_name::XPATH_MIRROR_STRING_BYTES,
                crate::hard_limits::XPATH_MIRROR_STRING_BYTE_CEILING,
                |p| &mut p.max_xpath_mirror_string_bytes,
            ),
            (
                resource_name::XPATH_STRING_WORK_BYTES,
                crate::hard_limits::XPATH_STRING_WORK_BYTE_CEILING,
                |p| &mut p.max_xpath_string_work_bytes,
            ),
            (
                resource_name::XPATH_NAMESPACE_BINDINGS,
                crate::hard_limits::XPATH_NAMESPACE_BINDING_CEILING,
                |p| &mut p.max_xpath_namespace_bindings,
            ),
            (
                resource_name::XPATH_NAMESPACE_BYTES,
                crate::hard_limits::XPATH_NAMESPACE_BYTE_CEILING,
                |p| &mut p.max_xpath_namespace_bytes,
            ),
            (
                resource_name::XPATH_FILTERS,
                crate::hard_limits::XPATH_FILTER_COUNT_CEILING,
                |p| &mut p.max_xpath_filters,
            ),
            (
                resource_name::NODE_SET_FILTER_WORK,
                crate::hard_limits::NODE_SET_FILTER_WORK_CEILING,
                |p| &mut p.max_node_set_filter_work,
            ),
            (
                resource_name::NODE_SET_ENTRIES,
                crate::hard_limits::NODE_SET_ENTRY_CEILING,
                |p| &mut p.max_node_set_entries,
            ),
            (
                resource_name::NODE_SET_OWNED_STRING_BYTES,
                crate::hard_limits::NODE_SET_OWNED_STRING_BYTE_CEILING,
                |p| &mut p.max_node_set_owned_string_bytes,
            ),
            (
                resource_name::NODE_SET_CUMULATIVE_OWNED_STRING_BYTES,
                crate::hard_limits::NODE_SET_CUMULATIVE_OWNED_STRING_BYTE_CEILING,
                |p| &mut p.max_node_set_cumulative_owned_string_bytes,
            ),
        ];

        for &(resource, ceiling, field) in cases {
            let mut policy = ResourcePolicy::default();
            let actual = ceiling.saturating_add(1);
            *field(&mut policy) = actual;
            assert_eq!(
                policy.validate(),
                Err(PolicyViolation::ResourceLimit {
                    resource,
                    maximum: ceiling,
                    actual,
                }),
                "wrong hard-ceiling validation for {resource}",
            );
        }
    }

    #[test]
    fn resource_policy_accepts_zero_as_a_deny_all_ceiling() {
        // Zero is a valid policy decision for resources that an operation can
        // avoid consuming; runtime checks must reject only actual non-zero use.
        let policy = ResourcePolicy {
            max_xml_nodes: 0,
            max_xml_depth: 0,
            max_references: 0,
            max_transforms_per_reference: 0,
            max_xml_base_components: 0,
            max_xml_base_resolution_bytes: 0,
            max_canonicalized_bytes: 0,
            max_external_resource_bytes: 0,
            max_external_resource_total_bytes: 0,
            max_encryption_plaintext_bytes: 0,
            max_xml_document_bytes: 0,
            max_xml_parse_work_bytes: 0,
            max_encryption_recipients: 0,
            max_encryption_metadata_bytes: 0,
            max_key_candidates: 0,
            max_key_info_reference_depth: 0,
            max_base64_transform_input_bytes: 0,
            max_base64_transform_output_bytes: 0,
            max_xpath_expressions: 0,
            max_xpath_expression_bytes: 0,
            max_xpath_expression_complexity: 0,
            max_xpath_context_evaluations: 0,
            max_xpath_evaluation_work: 0,
            max_xpath_mirror_string_bytes: 0,
            max_xpath_string_work_bytes: 0,
            max_xpath_namespace_bindings: 0,
            max_xpath_namespace_bytes: 0,
            max_xpath_filters: 0,
            max_node_set_filter_work: 0,
            max_node_set_entries: 0,
            max_node_set_owned_string_bytes: 0,
            max_node_set_cumulative_owned_string_bytes: 0,
        };

        assert_eq!(policy.validate(), Ok(()));
    }

    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    #[test]
    fn rsa_key_policy_enforces_structure_range_and_explicit_relaxation() {
        let secure = RsaKeyPolicy::default();
        assert!(matches!(
            secure.validate_components("test", &[0x80; 128], &[1, 0, 1]),
            Err(PolicyViolation::KeySize {
                minimum_bits: 2048,
                maximum_bits: 8192,
                actual_bits: 1024,
                ..
            })
        ));
        let mut short_2048_width = [0_u8; 256];
        short_2048_width[0] = 1;
        assert!(matches!(
            secure.validate_components("test", &short_2048_width, &[1, 0, 1]),
            Err(PolicyViolation::KeySize {
                minimum_bits: 2048,
                actual_bits: 2041,
                ..
            })
        ));
        assert!(matches!(
            secure.validate_components("test", &[1; 1025], &[1, 0, 1]),
            Err(PolicyViolation::KeySize {
                actual_bits: 8193,
                ..
            })
        ));
        assert!(matches!(
            secure.validate_components("test", &[0x80; 256], &[2]),
            Err(PolicyViolation::InvalidKeyMaterial { .. })
        ));
        assert_eq!(
            secure.validate_components("test", &[0x80; 256], &[0x80, 0, 0, 1]),
            Ok(256),
            "normalized RSA components encode the exponent as unsigned bytes"
        );

        let compatibility = RsaKeyPolicy {
            minimum_modulus_bits: 1024,
        };
        assert_eq!(
            compatibility.validate_components("test", &[0x80; 128], &[1, 0, 1]),
            Ok(128)
        );
        assert!(
            RsaKeyPolicy {
                minimum_modulus_bits: 2047,
            }
            .validate()
            .is_err()
        );
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
    fn legacy_signature_algorithms_require_independent_policy_opt_ins() {
        let legacy = [
            SignatureAlgorithm::RsaSha1,
            SignatureAlgorithm::DsaSha1,
            SignatureAlgorithm::HmacSha1,
            SignatureAlgorithm::EcdsaSha1,
        ];
        let mut policy = VerificationPolicy::default();

        for algorithm in legacy {
            assert!(matches!(
                policy.check_signature_algorithm(algorithm),
                Err(PolicyViolation::Algorithm { .. })
            ));
            policy
                .key_trust
                .allowed_legacy_signature_algorithms
                .insert(algorithm);
            assert_eq!(policy.check_signature_algorithm(algorithm), Ok(()));
            policy
                .key_trust
                .allowed_legacy_signature_algorithms
                .remove(&algorithm);
        }
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn dsa_key_policy_enforces_configured_minimum_and_hard_ceiling() {
        let policy = DsaKeyPolicy::default();

        assert!(matches!(
            policy.validate_modulus_bits(1024),
            Err(PolicyViolation::KeySize {
                key_type: "DSA",
                minimum_bits: 2048,
                maximum_bits: 3072,
                actual_bits: 1024,
                ..
            })
        ));
        assert_eq!(policy.validate_modulus_bits(2048), Ok(()));
        assert!(matches!(
            policy.validate_modulus_bits(4096),
            Err(PolicyViolation::KeySize {
                key_type: "DSA",
                minimum_bits: 2048,
                maximum_bits: 3072,
                actual_bits: 4096,
                ..
            })
        ));
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn hmac_output_policy_cannot_weaken_the_xmldsig_floor() {
        // Caller policy may tighten but cannot weaken XMLDSig section 6.3.1:
        // truncation is at least 80 bits and at least half the digest width.
        let compatibility = HmacPolicy {
            minimum_key_bits: 40,
            minimum_output_bits: 40,
        };

        assert_eq!(
            compatibility.validate_output(SignatureAlgorithm::HmacSha1, 80),
            Ok(())
        );
        assert!(matches!(
            compatibility.validate_output(SignatureAlgorithm::HmacSha1, 72),
            Err(PolicyViolation::HmacOutputLength { minimum: 80, .. })
        ));
        assert!(matches!(
            compatibility.validate_output(SignatureAlgorithm::HmacSha256, 120),
            Err(PolicyViolation::HmacOutputLength { minimum: 128, .. })
        ));
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn documented_xmldsig_limits_match_hard_limits() {
        // Public deployment guidance must change in the same commit as the
        // implementation ceilings from which these values are derived.
        let docs = include_str!("../docs/xmldsig.md");
        let mib = 1024 * 1024;
        assert!(docs.contains(&format!(
            "Individual resources are limited to {} MiB",
            crate::hard_limits::EXTERNAL_RESOURCE_BYTE_CEILING / mib
        )));
        assert!(docs.contains(&format!(
            "complete map to {} MiB",
            crate::hard_limits::EXTERNAL_RESOURCE_TOTAL_BYTE_CEILING / mib
        )));
        assert!(docs.contains(&format!(
            "ceilings are {} components and {} MiB per operation",
            crate::hard_limits::XML_BASE_COMPONENT_CEILING,
            crate::hard_limits::XML_BASE_RESOLUTION_BYTE_CEILING / mib
        )));
    }
}
