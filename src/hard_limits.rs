//! Non-configurable implementation safety ceilings.
//!
//! These caps bound allocations even when a future compiled deployment policy
//! permits larger inputs. Deployment policy may only select stricter values.

/// Maximum XML nodes allocated while parsing one verification or transform document.
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const XML_DOCUMENT_NODE_CEILING: u32 = 100_000;

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
pub(crate) const ENCRYPTION_CIPHER_VALUE_BASE64_BYTE_CEILING: usize = 16 * 1024 * 1024;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const ENCRYPTION_PLAINTEXT_BYTE_CEILING: usize =
    (ENCRYPTION_CIPHER_VALUE_BASE64_BYTE_CEILING / 4 * 3) - 32;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const XML_DOCUMENT_BYTE_CEILING: usize = ENCRYPTION_CIPHER_VALUE_BASE64_BYTE_CEILING;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const ENCRYPTION_RECIPIENT_CEILING: usize = 64;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const ENCRYPTION_METADATA_BYTE_CEILING: usize = 4 * 1024;

/// Largest RSA modulus accepted by built-in operation paths.
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) const RSA_MODULUS_BIT_CEILING: usize = 8192;
/// Largest DSA prime modulus accepted by built-in verification paths.
#[cfg(feature = "xmldsig")]
pub(crate) const DSA_MODULUS_BIT_CEILING: usize = 3072;
#[cfg(feature = "xmldsig")]
pub(crate) const SIGNATURE_REFERENCE_CEILING: usize = 64;
#[cfg(feature = "xmldsig")]
pub(crate) const REFERENCE_TRANSFORM_CEILING: usize = 64;
#[cfg(feature = "xmldsig")]
pub(crate) const X509_CHAIN_DEPTH_CEILING: usize = 9;
#[cfg(feature = "xmldsig")]
pub(crate) const X509_CANDIDATE_PATH_CEILING: usize = 64;
