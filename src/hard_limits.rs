//! Non-configurable implementation safety ceilings.
//!
//! These caps bound allocations even when a future compiled deployment policy
//! permits larger inputs. Deployment policy may only select stricter values.

/// Maximum XML nodes allocated while parsing one verification or transform document.
pub(crate) const XML_DOCUMENT_NODE_CEILING: u32 = 100_000;

/// Maximum canonicalized SignedInfo plus retained diagnostics for one signature.
pub(crate) const CANONICALIZED_SIGNATURE_DATA_BYTE_CEILING: usize = 32 * 1024 * 1024;

pub(crate) const EXTERNAL_RESOURCE_BYTE_CEILING: usize = 8 * 1024 * 1024;
pub(crate) const EXTERNAL_RESOURCE_TOTAL_BYTE_CEILING: usize = 32 * 1024 * 1024;
pub(crate) const ENCRYPTION_CIPHER_VALUE_BASE64_BYTE_CEILING: usize = 16 * 1024 * 1024;
pub(crate) const ENCRYPTION_PLAINTEXT_BYTE_CEILING: usize =
    (ENCRYPTION_CIPHER_VALUE_BASE64_BYTE_CEILING / 4 * 3) - 32;
pub(crate) const ENCRYPTION_DOCUMENT_BYTE_CEILING: usize =
    ENCRYPTION_CIPHER_VALUE_BASE64_BYTE_CEILING;
pub(crate) const ENCRYPTION_RECIPIENT_CEILING: usize = 64;
pub(crate) const ENCRYPTION_METADATA_BYTE_CEILING: usize = 4 * 1024;
