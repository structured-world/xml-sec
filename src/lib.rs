//! # xml-sec — Pure Rust XML Security
//!
//! Drop-in replacement for libxmlsec1. XMLDSig, XMLEnc, C14N — no C dependencies.
//!
//! ## Features
//!
//! - **C14N** — XML Canonicalization (inclusive + exclusive)
//! - **XMLDSig** — XML Digital Signatures (sign + verify)
//! - **XMLEnc** — XML Encryption (encrypt + decrypt)
//! - **X.509** — Certificate-based key extraction
//!
//! ## Quick Start
//!
//! ```rust
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use xml_sec::c14n::{C14nAlgorithm, C14nMode, canonicalize_xml};
//!
//! let xml = b"<root b=\"2\" a=\"1\"><empty/></root>";
//! let algo = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
//! let canonical = canonicalize_xml(xml, &algo)?;
//! assert_eq!(
//!     String::from_utf8(canonical)?,
//!     "<root a=\"1\" b=\"2\"><empty></empty></root>"
//! );
//! # Ok(())
//! # }
//! ```

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![warn(missing_docs)]

pub mod c14n;
pub mod document;
pub mod encoding;
pub mod error;
mod hard_limits;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub mod policy;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub mod provider;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
mod xml;

#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub use xml::IdAttributeRegistration;

#[cfg(feature = "xmldsig")]
pub mod xmldsig;

#[cfg(feature = "xmlenc")]
pub mod xmlenc;

pub use document::{
    AttributeIdentity, DocumentIdentity, DocumentView, NamespaceIdentity, NodeIdentity,
    SemanticOrder, XmlDocument, XmlDocumentError,
};
pub use error::XmlSecError;
