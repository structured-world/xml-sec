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

extern crate alloc;
#[cfg(feature = "xmldsig")]
#[macro_use]
extern crate peresil;

#[cfg(not(any(feature = "xml-backend-xmloxide", feature = "xml-backend-roxmltree")))]
compile_error!(
    "compile at least one XML backend: `xml-backend-xmloxide` or `xml-backend-roxmltree`"
);

pub mod c14n;
pub mod document;
pub mod encoding;
pub mod error;
mod hard_limits;
#[cfg(feature = "xmldsig")]
// The same sources also build as standalone crates for the XSLT workspace member.
// Only their XPath-facing surface is used by this package.
#[doc(hidden)]
#[allow(dead_code, unused_imports, missing_docs)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
#[path = "sxd_document/lib.rs"]
mod sxd_document;
#[cfg(feature = "xmldsig")]
#[doc(hidden)]
#[allow(dead_code, unused_imports, missing_docs)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
#[path = "sxd_xpath/lib.rs"]
mod sxd_xpath;
#[path = "xml_input/shared.rs"]
// The internal xml-input crate also compiles this source for XSLT's wider API.
#[allow(dead_code)]
mod xml_input_shared;
/// Bounded XML input decoding and lexical helpers.
///
/// [`decode_xml_bounded`] accepts trusted encoding metadata and a caller-supplied
/// decoded-byte limit. The unbounded internal helpers are not public.
///
/// ```compile_fail
/// use xml_sec::xml_input::decode_xml;
/// ```
pub mod xml_input {
    pub use crate::xml_input_shared::{Error, decode_xml_bounded, lexical};
}
#[cfg(all(test, feature = "xmldsig"))]
pub(crate) use sxd_document::{Package, QName, dom};
#[cfg(feature = "xmldsig")]
pub(crate) use sxd_document::{StorageRequirements, XML_NS_PREFIX, XML_NS_URI, str, string_pool};
#[cfg(all(test, feature = "xmldsig"))]
pub(crate) use sxd_xpath::{Context, Factory};
#[cfg(feature = "xmldsig")]
pub(crate) use sxd_xpath::{
    LiteralValue, OwnedPrefixedName, OwnedQName, ParseBudget, Value, axis, context, expression,
    function, node_test, node_to_num_with_context, nodeset, parser, str_to_num, token, tokenizer,
};
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
mod operation;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub mod policy;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub mod provider;
mod xml;

pub use xml::IdAttributeRegistration;
pub use xml::dom::{
    Ancestors, Attribute, Attributes, Children, Descendants, Document, Document as XmlDomDocument,
    ExpandedName, Namespace, Namespaces, Node, Node as XmlDomNode, NodeId, NodeId as XmlDomNodeId,
    NodeType, PI, ParseError, ParseError as XmlDomParseError, ParsingOptions,
    ParsingOptions as XmlDomParsingOptions, XmlBackend,
};

#[cfg(feature = "xmldsig")]
pub mod key_manager;
#[cfg(feature = "xmldsig")]
pub mod xmldsig;

#[cfg(feature = "xmlenc")]
pub mod xmlenc;

#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub use document::XmlDocumentPolicy;
pub use document::{
    AttributeIdentity, DocumentIdentity, DocumentView, NamespaceIdentity, NodeIdentity,
    SemanticOrder, XmlDocument, XmlDocumentError,
};
pub use error::XmlSecError;
