//! Parsing never reaches outside the document.

use std::io::Write as _;

use super::{xmlSecParseMemory, xmlSecParseMemoryExt};
use crate::ffi::tree::nodes;

/// A document cannot read a local file through an external entity: the
/// core parser loads no external entity, so the document is refused or its
/// reference stays unexpanded.
#[test]
fn external_entities_are_not_loaded() {
    let mut secret = tempfile::NamedTempFile::new().expect("a temporary file");
    secret.write_all(b"SECRET").expect("write");
    let path = secret.path().display();
    let xml = format!("<!DOCTYPE r [<!ENTITY e SYSTEM \"file://{path}\">]><r>[&e;]</r>");
    // SAFETY: `xml` holds its length in bytes.
    let doc = unsafe { xmlSecParseMemory(xml.as_ptr(), xml.len(), 1) };
    if !doc.is_null() {
        let text = nodes::content(nodes::root_element(doc)).unwrap_or_default();
        xml_sec_libxml2::document::free(doc);
        assert!(!text.contains("SECRET"), "{text}");
    }
}

/// The three chunks of `xmlSecParseMemoryExt` form one document, in order.
#[test]
fn chunks_are_parsed_in_sequence() {
    let (prefix, body, postfix) = (b"<r>".as_slice(), b"text".as_slice(), b"</r>".as_slice());
    // SAFETY: each chunk holds its length in bytes.
    let doc = unsafe {
        xmlSecParseMemoryExt(
            prefix.as_ptr(),
            prefix.len(),
            body.as_ptr(),
            body.len(),
            postfix.as_ptr(),
            postfix.len(),
        )
    };
    assert!(!doc.is_null(), "the document parses");
    assert_eq!(
        nodes::content(nodes::root_element(doc)).as_deref(),
        Some("text")
    );
    xml_sec_libxml2::document::free(doc);
}
