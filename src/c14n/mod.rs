//! XML Canonicalization (C14N).
//!
//! Implements:
//! - [Canonical XML 1.0](https://www.w3.org/TR/xml-c14n/) (inclusive)
//! - [Canonical XML 1.1](https://www.w3.org/TR/xml-c14n11/) — URI parsing only;
//!   canonicalization returns `UnsupportedAlgorithm` (1.1-specific rules not yet implemented)
//! - [Exclusive XML Canonicalization 1.0](https://www.w3.org/TR/xml-exc-c14n/) (exclusive)
//!
//! # Example
//!
//! ```
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

mod escape;
mod ns_common;
pub(crate) mod ns_exclusive;
pub(crate) mod ns_inclusive;
mod prefix;
pub(crate) mod serialize;

use std::collections::HashSet;

use roxmltree::{Document, Node};

use ns_exclusive::ExclusiveNsRenderer;
use ns_inclusive::InclusiveNsRenderer;
use serialize::serialize_canonical;

/// C14N algorithm mode (without the comments flag).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum C14nMode {
    /// Inclusive C14N 1.0 — all in-scope namespaces rendered.
    Inclusive1_0,
    /// Inclusive C14N 1.1 — like 1.0 with xml:id propagation and xml:base fixup.
    Inclusive1_1,
    /// Exclusive C14N 1.0 — only visibly-utilized namespaces rendered.
    Exclusive1_0,
}

/// Full C14N algorithm identifier.
///
/// Constructed from algorithm URIs found in `<CanonicalizationMethod>` or
/// `<Transform>` elements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct C14nAlgorithm {
    mode: C14nMode,
    with_comments: bool,
    /// For Exclusive C14N: prefixes forced via InclusiveNamespaces PrefixList.
    /// `"#default"` is normalized to `""` (empty string) by `with_prefix_list()`.
    inclusive_prefixes: HashSet<String>,
}

impl C14nAlgorithm {
    /// The canonicalization mode.
    pub fn mode(&self) -> C14nMode {
        self.mode
    }

    /// Whether comment nodes are preserved.
    pub fn with_comments(&self) -> bool {
        self.with_comments
    }

    /// Prefixes forced via InclusiveNamespaces PrefixList (exclusive C14N).
    pub fn inclusive_prefixes(&self) -> &HashSet<String> {
        &self.inclusive_prefixes
    }

    /// Create a new algorithm with the given mode and comments flag.
    pub fn new(mode: C14nMode, with_comments: bool) -> Self {
        Self {
            mode,
            with_comments,
            inclusive_prefixes: HashSet::new(),
        }
    }

    /// Parse from an algorithm URI. Returns `None` for unrecognized URIs.
    pub fn from_uri(uri: &str) -> Option<Self> {
        let (mode, with_comments) = match uri {
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" => (C14nMode::Inclusive1_0, false),
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments" => {
                (C14nMode::Inclusive1_0, true)
            }
            "http://www.w3.org/2006/12/xml-c14n11" => (C14nMode::Inclusive1_1, false),
            "http://www.w3.org/2006/12/xml-c14n11#WithComments" => (C14nMode::Inclusive1_1, true),
            "http://www.w3.org/2001/10/xml-exc-c14n#" => (C14nMode::Exclusive1_0, false),
            "http://www.w3.org/2001/10/xml-exc-c14n#WithComments" => (C14nMode::Exclusive1_0, true),
            _ => return None,
        };
        Some(Self {
            mode,
            with_comments,
            inclusive_prefixes: HashSet::new(),
        })
    }

    /// Set the InclusiveNamespaces PrefixList (exclusive C14N only).
    /// `"#default"` is normalized to empty string `""`.
    ///
    /// Only meaningful for [`C14nMode::Exclusive1_0`]. For inclusive modes,
    /// the prefix list is ignored during canonicalization.
    pub fn with_prefix_list(mut self, prefix_list: &str) -> Self {
        self.inclusive_prefixes = prefix_list
            .split_whitespace()
            .map(|p| {
                if p == "#default" {
                    String::new()
                } else {
                    p.to_string()
                }
            })
            .collect();
        self
    }

    /// Get the algorithm URI for this configuration.
    pub fn uri(&self) -> &'static str {
        match (self.mode, self.with_comments) {
            (C14nMode::Inclusive1_0, false) => "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
            (C14nMode::Inclusive1_0, true) => {
                "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
            }
            (C14nMode::Inclusive1_1, false) => "http://www.w3.org/2006/12/xml-c14n11",
            (C14nMode::Inclusive1_1, true) => "http://www.w3.org/2006/12/xml-c14n11#WithComments",
            (C14nMode::Exclusive1_0, false) => "http://www.w3.org/2001/10/xml-exc-c14n#",
            (C14nMode::Exclusive1_0, true) => "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
        }
    }
}

/// Error type for C14N operations.
#[derive(Debug, thiserror::Error)]
pub enum C14nError {
    /// XML parsing error.
    #[error("XML parse error: {0}")]
    Parse(String),
    /// Invalid node reference.
    #[error("invalid node reference")]
    InvalidNode,
    /// Algorithm not yet implemented.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Canonicalize an XML document or document subset.
///
/// - `doc`: parsed roxmltree document (read-only DOM).
/// - `node_set`: optional predicate controlling which nodes appear in output.
///   `None` means the entire document.
/// - `algo`: algorithm parameters (mode, comments, prefix list).
/// - `output`: byte buffer receiving canonical XML.
pub fn canonicalize(
    doc: &Document,
    node_set: Option<&dyn Fn(Node) -> bool>,
    algo: &C14nAlgorithm,
    output: &mut Vec<u8>,
) -> Result<(), C14nError> {
    match algo.mode {
        C14nMode::Inclusive1_0 => {
            let renderer = InclusiveNsRenderer;
            serialize_canonical(doc, node_set, algo.with_comments, &renderer, output)
        }
        // C14N 1.1 has observable differences (xml:id propagation, xml:base fixup)
        // that are not yet implemented. Fail explicitly rather than silently
        // producing 1.0 output.
        C14nMode::Inclusive1_1 => Err(C14nError::UnsupportedAlgorithm(
            "C14N 1.1 is not yet implemented".to_string(),
        )),
        C14nMode::Exclusive1_0 => {
            let renderer = ExclusiveNsRenderer::new(&algo.inclusive_prefixes);
            serialize_canonical(doc, node_set, algo.with_comments, &renderer, output)
        }
    }
}

/// Convenience: parse XML bytes and canonicalize the whole document.
///
/// Input must be valid UTF-8 (XML 1.0 documents are UTF-8 or declare their
/// encoding; roxmltree only accepts UTF-8). Returns `C14nError::Parse` for
/// invalid UTF-8 or malformed XML.
pub fn canonicalize_xml(xml: &[u8], algo: &C14nAlgorithm) -> Result<Vec<u8>, C14nError> {
    let xml_str =
        std::str::from_utf8(xml).map_err(|e| C14nError::Parse(format!("invalid UTF-8: {e}")))?;
    let doc = Document::parse(xml_str).map_err(|e| C14nError::Parse(e.to_string()))?;
    let mut output = Vec::new();
    canonicalize(&doc, None, algo, &mut output)?;
    Ok(output)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn from_uri_roundtrip() {
        let uris = [
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
            "http://www.w3.org/2006/12/xml-c14n11",
            "http://www.w3.org/2006/12/xml-c14n11#WithComments",
            "http://www.w3.org/2001/10/xml-exc-c14n#",
            "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
        ];
        for uri in uris {
            let algo = C14nAlgorithm::from_uri(uri).expect(uri);
            assert_eq!(algo.uri(), uri);
        }
    }

    #[test]
    fn unknown_uri_returns_none() {
        assert!(C14nAlgorithm::from_uri("http://example.com/unknown").is_none());
    }

    #[test]
    fn prefix_list_parsing() {
        let algo = C14nAlgorithm::new(C14nMode::Exclusive1_0, false)
            .with_prefix_list("foo bar #default baz");
        assert!(algo.inclusive_prefixes.contains("foo"));
        assert!(algo.inclusive_prefixes.contains("bar"));
        assert!(algo.inclusive_prefixes.contains("baz"));
        assert!(algo.inclusive_prefixes.contains("")); // #default → ""
        assert_eq!(algo.inclusive_prefixes.len(), 4);
    }

    #[test]
    fn canonicalize_xml_basic() {
        let xml = b"<root b=\"2\" a=\"1\"><empty/></root>";
        let algo = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
        let result = canonicalize_xml(xml, &algo).expect("c14n");
        assert_eq!(
            String::from_utf8(result).expect("utf8"),
            r#"<root a="1" b="2"><empty></empty></root>"#
        );
    }

    #[test]
    fn c14n_1_1_returns_error() {
        let xml = b"<root/>";
        let algo = C14nAlgorithm::new(C14nMode::Inclusive1_1, false);
        let result = canonicalize_xml(xml, &algo);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, C14nError::UnsupportedAlgorithm(_)),
            "expected UnsupportedAlgorithm, got: {err:?}"
        );
    }
}
