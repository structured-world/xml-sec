//! Parsing never reaches outside the document, and with the default options
//! the core's policy decides what a document may hold.

use std::ffi::{CStr, CString, c_int};
use std::io::Write as _;

use super::{
    xmlSecParseFile, xmlSecParseMemory, xmlSecParseMemoryExt, xmlSecParserSetDefaultOptions,
};
use crate::ffi::free;
use crate::ffi::tree::{xmlFreeDoc, xmlNodeGetContent};
use xml_sec_libxml2::ffi::{XmlDoc, XmlNode};

unsafe extern "C" {
    fn xmlNodeGetBase(doc: *mut XmlDoc, node: *mut XmlNode) -> *mut u8;
}

/// The text content of `node`, freed after reading.
///
/// # Safety
/// `node` is a live node.
unsafe fn content(node: *mut XmlNode) -> String {
    // SAFETY: by the caller's contract; libxml2 allocated the copy.
    unsafe {
        let text = xmlNodeGetContent(node);
        if text.is_null() {
            return String::new();
        }
        let owned = CStr::from_ptr(text.cast()).to_string_lossy().into_owned();
        free(text.cast());
        owned
    }
}

/// A document naming a local file through an external entity.
fn external_entity_document() -> (tempfile::NamedTempFile, String) {
    let mut secret = tempfile::NamedTempFile::new().expect("a temporary file");
    secret.write_all(b"SECRET").expect("write");
    let path = secret.path().display();
    let xml = format!("<!DOCTYPE r [<!ENTITY e SYSTEM \"file://{path}\">]><r>[&e;]</r>");
    (secret, xml)
}

/// With recovery libxml2 parses, and its default options load no external
/// entity or DTD with any libxml2, where libxmlsec1's options do on
/// libxml2 older than 2.13.
#[test]
fn external_entities_are_not_loaded() {
    let (_secret, xml) = external_entity_document();
    // SAFETY: the document is used while live and freed once.
    unsafe {
        let doc = xmlSecParseMemory(xml.as_ptr(), xml.len(), 1);
        assert!(!doc.is_null(), "the document parses");
        let text = content((*doc).last);
        xmlFreeDoc(doc);
        assert!(!text.contains("SECRET"), "{text}");
    }
}

/// With the default options the core parses under the library's policy,
/// which admits no document type declaration: the document is refused
/// whatever the linked libxml2 would load.
#[test]
fn the_policy_refuses_a_document_type_declaration() {
    let (_secret, xml) = external_entity_document();
    // SAFETY: the buffer holds its length.
    let doc = unsafe { xmlSecParseMemory(xml.as_ptr(), xml.len(), 0) };
    assert!(doc.is_null());
}

/// The core's tree becomes the libxml2 tree: the content, the three chunks
/// joined, and a malformed document refused.
#[test]
fn the_core_builds_the_document() {
    // SAFETY: every buffer holds its length; documents are freed once.
    unsafe {
        let good = b"<a x='1'><b>t&amp;u</b></a>";
        let doc = xmlSecParseMemory(good.as_ptr(), good.len(), 0);
        assert!(!doc.is_null());
        assert_eq!(content((*doc).children), "t&u");
        xmlFreeDoc(doc);
        let doc =
            xmlSecParseMemoryExt(b"<a>".as_ptr(), 3, b"<b/>".as_ptr(), 4, b"</a>".as_ptr(), 4);
        assert!(!doc.is_null());
        assert!(!(*(*doc).children).children.is_null());
        xmlFreeDoc(doc);
        let bad = b"<a><b></a>";
        assert!(xmlSecParseMemory(bad.as_ptr(), bad.len(), 0).is_null());
    }
}

/// A parsed file records its location as the document URL, as libxml2's
/// file parser does, so relative references resolve against it.
#[test]
fn a_file_document_knows_its_location() {
    let mut file = tempfile::NamedTempFile::new().expect("a temporary file");
    file.write_all(b"<r/>").expect("write");
    let path = CString::new(file.path().to_str().expect("a UTF-8 path")).expect("no NUL");
    // SAFETY: the path is NUL-terminated; the document and base are freed once.
    unsafe {
        let doc = xmlSecParseFile(path.as_ptr());
        assert!(!doc.is_null());
        let base = xmlNodeGetBase(doc, (*doc).children);
        assert!(!base.is_null());
        let base_text = CStr::from_ptr(base.cast()).to_string_lossy().into_owned();
        free(base.cast());
        xmlFreeDoc(doc);
        let name = file.path().file_name().expect("a name").to_string_lossy();
        assert!(base_text.ends_with(name.as_ref()), "{base_text}");
    }
}

/// Options a caller set are libxml2 parser options, so libxml2 parses with
/// them: a document type declaration the policy refuses then parses.
#[test]
fn caller_options_keep_the_libxml2_parser() {
    /// `XML_PARSE_NONET`.
    const NONET: c_int = 1 << 11;
    let xml = b"<!DOCTYPE r><r/>";
    // SAFETY: the buffer holds its length; the document is freed once. Each
    // test runs in its own process, so the option change stays here.
    unsafe {
        assert!(xmlSecParseMemory(xml.as_ptr(), xml.len(), 0).is_null());
        xmlSecParserSetDefaultOptions(NONET);
        let doc = xmlSecParseMemory(xml.as_ptr(), xml.len(), 0);
        assert!(!doc.is_null());
        xmlFreeDoc(doc);
    }
}
