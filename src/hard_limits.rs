//! Non-configurable implementation safety ceilings.
//!
//! These caps bound allocations even when a future compiled deployment policy
//! permits larger inputs. Deployment policy may only select stricter values.

/// Maximum XML nodes allocated while parsing one verification or transform document.
pub(crate) const XML_DOCUMENT_NODE_CEILING: u32 = 100_000;
/// Maximum general-entity substitutions performed while parsing one document.
pub(crate) const XML_ENTITY_EXPANSION_CEILING: u32 = 10_000;
/// Maximum lexical source positions retained for backend-neutral ranges.
pub(crate) const XML_SOURCE_POSITION_CEILING: usize = 2 * XML_DOCUMENT_NODE_CEILING as usize;
/// Maximum replacement bytes traversed while expanding one XML document.
pub(crate) const XML_ENTITY_EXPANSION_WORK_BYTE_CEILING: usize = 16 * XML_DOCUMENT_BYTE_CEILING;
/// Maximum element nesting accepted by every XML parser backend.
pub(crate) const XML_DOCUMENT_DEPTH_CEILING: usize = 256;

/// Maximum inherited `xml:base` attributes considered for one URI resolution.
pub(crate) const XML_BASE_COMPONENT_CEILING: usize = 64;

/// Maximum cumulative bytes inspected or allocated while resolving XML Base.
pub(crate) const XML_BASE_RESOLUTION_BYTE_CEILING: usize = 1024 * 1024;

/// Maximum canonicalized SignedInfo plus retained diagnostics for one signature.
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const CANONICALIZED_SIGNATURE_DATA_BYTE_CEILING: usize = 32 * 1024 * 1024;

#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const EXTERNAL_RESOURCE_BYTE_CEILING: usize = 8 * 1024 * 1024;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const EXTERNAL_RESOURCE_TOTAL_BYTE_CEILING: usize = 32 * 1024 * 1024;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const ENCRYPTION_CIPHER_VALUE_BASE64_BYTE_CEILING: usize = XML_DOCUMENT_BYTE_CEILING;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const ENCRYPTION_PLAINTEXT_BYTE_CEILING: usize =
    (ENCRYPTION_CIPHER_VALUE_BASE64_BYTE_CEILING / 4 * 3) - 32;
pub(crate) const XML_DOCUMENT_BYTE_CEILING: usize = 16 * 1024 * 1024;
/// Maximum cumulative bytes handed to an XML parser by one operation.
///
/// Sixteen full-size passes cover the ordinary staged sign/encrypt/decrypt
/// pipelines while bounding adversarial dependency or key-candidate retries.
/// Differential builds receive four additional passes because every semantic
/// parse also runs the comparison backend; this preserves the same document
/// size envelope while still metering the diagnostic work.
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const XML_PARSE_WORK_PASS_CEILING: usize =
    16 + 4 * cfg!(feature = "xml-backend-differential") as usize;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const XML_PARSE_WORK_BYTE_CEILING: usize =
    XML_PARSE_WORK_PASS_CEILING * XML_DOCUMENT_BYTE_CEILING;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const ENCRYPTION_RECIPIENT_CEILING: usize = 64;
/// Maximum symmetric keys attempted by one prepared decryption operation.
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const KEY_CANDIDATE_CEILING: usize = 64;
/// Maximum nested `KeyInfoReference` dereference depth.
#[cfg(feature = "xmldsig")]
pub(crate) const KEY_INFO_REFERENCE_DEPTH_CEILING: usize = 8;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const ENCRYPTION_METADATA_BYTE_CEILING: usize = 4 * 1024;

/// Largest RSA modulus accepted by built-in operation paths.
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const RSA_MODULUS_BIT_CEILING: usize = 8192;
/// Largest DSA prime modulus accepted by built-in verification paths.
#[cfg(feature = "xmldsig")]
pub(crate) const DSA_MODULUS_BIT_CEILING: usize = 3072;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const SIGNATURE_REFERENCE_CEILING: usize = 64;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const REFERENCE_TRANSFORM_CEILING: usize = 64;
#[cfg(feature = "xmldsig")]
pub(crate) const X509_CHAIN_DEPTH_CEILING: usize = 9;
#[cfg(feature = "xmldsig")]
pub(crate) const X509_CANDIDATE_PATH_CEILING: usize = 64;

/// Absolute transform and XPath work ceilings. Operation policy may only tighten these.
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const BASE64_TRANSFORM_INPUT_BYTE_CEILING: usize = 16 * 1024 * 1024;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const BASE64_TRANSFORM_OUTPUT_BYTE_CEILING: usize = 8 * 1024 * 1024;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const XPATH_EXPRESSION_COUNT_CEILING: usize = 4_096;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const XPATH_EXPRESSION_BYTE_CEILING: usize = 16 * 1024;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const XPATH_EXPRESSION_COMPLEXITY_CEILING: usize = 256;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const XPATH_CONTEXT_EVALUATION_CEILING: usize = 4_096;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const XPATH_EVALUATION_WORK_CEILING: usize = 6_000_000;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const XPATH_MIRROR_STRING_BYTE_CEILING: usize = 8 * 1024 * 1024;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const XPATH_STRING_WORK_BYTE_CEILING: usize = 512 * 1024 * 1024;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const XPATH_NAMESPACE_BINDING_CEILING: usize = 1_024;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const XPATH_NAMESPACE_BYTE_CEILING: usize = 64 * 1024;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const XPATH_FILTER_COUNT_CEILING: usize = 64;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const NODE_SET_FILTER_WORK_CEILING: usize = 6_000_000;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const NODE_SET_ENTRY_CEILING: usize = 65_536;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const NODE_SET_OWNED_STRING_BYTE_CEILING: usize = 8 * 1024 * 1024;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const NODE_SET_CUMULATIVE_OWNED_STRING_BYTE_CEILING: usize = 64 * 1024 * 1024;
