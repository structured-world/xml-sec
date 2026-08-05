//! Non-configurable implementation safety ceilings.
//!
//! These caps bound allocations even when a future compiled deployment policy
//! permits larger inputs. Deployment policy may only select stricter values.

/// Maximum XML nodes allocated while parsing one verification or transform document.
pub(crate) const XML_DOCUMENT_NODE_CEILING: u32 = 100_000;

/// Maximum bytes retained across one verification result's diagnostic buffers.
pub(crate) const STORED_PRE_DIGEST_BYTE_CEILING: usize = 32 * 1024 * 1024;
