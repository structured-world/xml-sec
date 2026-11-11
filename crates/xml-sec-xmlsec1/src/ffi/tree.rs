//! The document tree the library works on: `xml-sec-libxml2`'s documents,
//! read and changed through its validated handles, never dereferenced.

pub(crate) use xml_sec_libxml2::ffi::tree::xsStrEqual as xmlStrEqual;
pub(crate) use xml_sec_libxml2::nodes::{
    self, Doc as XmlDoc, Node as XmlNode, NodeSet as XmlNodeSet, XML_ATTRIBUTE_NODE,
    XML_CDATA_SECTION_NODE, XML_COMMENT_NODE, XML_DOCUMENT_NODE, XML_ELEMENT_NODE,
    XML_NAMESPACE_DECL, XML_TEXT_NODE,
};

/// The text of a NUL-terminated string; `None` for null or text that is
/// not UTF-8.
///
/// # Safety
/// `text` is null or NUL-terminated.
pub(crate) unsafe fn c_text<'a>(text: *const u8) -> Option<&'a str> {
    if text.is_null() {
        return None;
    }
    // SAFETY: NUL-terminated by the caller's contract.
    unsafe { std::ffi::CStr::from_ptr(text.cast()) }
        .to_str()
        .ok()
}

/// Whether `value` equals the NUL-terminated `expected`, as libxml2's
/// `xmlStrEqual` compares: two absent strings are equal.
///
/// # Safety
/// `expected` is null or NUL-terminated.
pub(crate) unsafe fn same_text(value: Option<&str>, expected: *const u8) -> bool {
    if expected.is_null() {
        return value.is_none();
    }
    // SAFETY: NUL-terminated by the caller's contract.
    let expected = unsafe { std::ffi::CStr::from_ptr(expected.cast()) }.to_bytes();
    value.is_some_and(|value| value.as_bytes() == expected)
}

/// The name of `node` as a C string for a report's object, empty for none.
pub(crate) fn name_for_report<T>(node: *const T) -> std::ffi::CString {
    nodes::name(node)
        .and_then(|name| std::ffi::CString::new(name).ok())
        .unwrap_or_default()
}

/// A copy of `value` on the library's heap, released with `xmlFree`; null
/// for none or an exhausted heap.
pub(crate) fn give(value: Option<&str>) -> *mut u8 {
    value.map_or(std::ptr::null_mut(), |value| {
        xml_sec_libxml2::ffi::memory::copy(value.as_bytes())
    })
}
