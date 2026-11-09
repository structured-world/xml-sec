//! Parsing with the default options never reaches outside the document.

use std::io::Write as _;

use super::xmlSecParseMemory;
use crate::ffi::free;
use crate::ffi::tree::{xmlFreeDoc, xmlNodeGetContent};

/// A document cannot read a local file through an external entity: the
/// default options load no external entity or DTD with any libxml2, where
/// libxmlsec1's options do on libxml2 older than 2.13.
#[test]
fn external_entities_are_not_loaded() {
    let mut secret = tempfile::NamedTempFile::new().expect("a temporary file");
    secret.write_all(b"SECRET").expect("write");
    let path = secret.path().display();
    let xml = format!("<!DOCTYPE r [<!ENTITY e SYSTEM \"file://{path}\">]><r>[&e;]</r>");
    // SAFETY: the document is used while live and freed once.
    unsafe {
        let doc = xmlSecParseMemory(xml.as_ptr(), xml.len(), 1);
        assert!(!doc.is_null(), "the document parses");
        let content = xmlNodeGetContent((*doc).last.cast());
        let text = if content.is_null() {
            String::new()
        } else {
            let text = std::ffi::CStr::from_ptr(content.cast())
                .to_string_lossy()
                .into_owned();
            free(content.cast());
            text
        };
        xmlFreeDoc(doc);
        assert!(!text.contains("SECRET"), "{text}");
    }
}
