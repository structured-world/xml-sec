//! # xml-sec — Pure Rust XML Security
//!
//! `XMLDSig`, `XMLEnc` and C14N with explicit policy and cryptographic providers.
//! The default build is pure Rust. Optional native providers have their own
//! toolchain requirements. Wire/CLI interoperability does not imply libxmlsec1
//! C source or binary ABI compatibility.
//!
//! With `xmldsig`, start with `XmlSecurity` and its policy-bound operation
//! handles. Verification acceptance requires expected-target evidence, not just
//! a valid signature value. Low-level APIs remain in `xmldsig`; C14N-only
//! builds use [`c14n`] independently.
//!
//! ## Features
//!
//! - **C14N** — XML Canonicalization (inclusive + exclusive)
//! - **`XMLDSig`**: XML Digital Signatures (sign + verify)
//! - **`XMLEnc`**: XML Encryption (encrypt + decrypt)
//! - **X.509** — Certificate-based key extraction
//!
//! Without the default `std` feature, C14N and `XMLDSig` verification build on
//! `core` and `alloc` alone; the caller then supplies the verification time.
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

// The unit-test harness needs std; the library target stays `no_std` here.
#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![warn(missing_docs)]

extern crate alloc;
// The embedded XPath engine's XML parser only builds test documents.
#[cfg(all(test, feature = "xmldsig"))]
#[macro_use]
extern crate peresil;

#[cfg(not(any(feature = "xml-backend-xmloxide", feature = "xml-backend-roxmltree")))]
compile_error!(
    "compile at least one XML backend: `xml-backend-xmloxide` or `xml-backend-roxmltree`"
);

#[cfg(feature = "xmldsig")]
pub mod api;
#[cfg(feature = "benchmark-internals")]
#[doc(hidden)]
pub mod benchmark_support;
pub mod c14n;
mod collections;
pub mod document;
pub mod encoding;
pub mod error;
#[cfg(feature = "xmldsig")]
pub use api::XmlSecurity;
mod hard_limits;
// These XML parser kernels are checksum-pinned in scripts/import-xml-backends.sh.
// Embedding the maintained sources also preserves the patch for package users.
// Upstream navigation/construction APIs not used by this adapter stay private.
#[cfg(feature = "xml-backend-roxmltree")]
#[allow(dead_code, unused_imports, missing_docs)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
#[path = "parser_roxmltree/lib.rs"]
mod parser_roxmltree;
#[cfg(feature = "xml-backend-xmloxide")]
#[allow(dead_code, unused_imports, missing_docs)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
#[path = "parser_xmloxide/lib.rs"]
mod parser_xmloxide;
#[cfg(feature = "xmldsig")]
pub mod rsa_encoding;
#[cfg(feature = "xmldsig")]
#[path = "rustcrypto_sha3/lib.rs"]
mod rustcrypto_sha3;
// Checksum-pinned RustCrypto ML-DSA with checked expanded-key import. Keep it
// inside the published package: Cargo patches do not propagate to consumers.
#[cfg(feature = "experimental-pq")]
#[allow(dead_code, unused_imports, missing_docs)]
#[cfg_attr(test, allow(clippy::unwrap_used, deprecated))]
#[path = "rustcrypto_ml_dsa/lib.rs"]
mod rustcrypto_ml_dsa;
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
// The same sources build the standalone XSLT workspace crate and its conformance suite.
#[path = "xml_input/shared.rs"]
// The internal xml-input crate also compiles this source for XSLT's wider API.
#[allow(dead_code)]
mod xml_input_shared;
#[cfg(feature = "xslt")]
#[doc(hidden)]
#[allow(dead_code, unused_imports, missing_docs)]
#[path = "xslt/lib.rs"]
mod xslt;
/// Bounded XML input decoding and lexical helpers.
///
/// [`decode_xml_bounded`](xml_input::decode_xml_bounded) accepts trusted encoding metadata and a caller-supplied
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
    function, node_test, node_to_num_with_context, nodeset, parser, runtime, str_to_num, token,
    tokenizer,
};
#[cfg(feature = "xmldsig")]
pub mod key_establishment;
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
    ParsingOptions as XmlDomParsingOptions, XmlBackend, XmlIdError,
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
