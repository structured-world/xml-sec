//! libxml2 declarations the library calls, beyond the tree structures
//! `xml-sec-libxml2` declares and verifies.

use std::ffi::{c_char, c_int, c_void};

use xml_sec_libxml2::ffi::{XmlAttr, XmlDoc, XmlNode, XmlNodeSet, XmlNs};

unsafe extern "C" {
    pub(crate) fn xmlXPathNodeSetCreate(node: *mut XmlNode) -> *mut XmlNodeSet;
    pub(crate) fn xmlXPathNodeSetAdd(set: *mut XmlNodeSet, node: *mut XmlNode) -> c_int;
    pub(crate) fn xmlXPathNodeSetContains(set: *mut XmlNodeSet, node: *mut XmlNode) -> c_int;
    pub(crate) fn xmlXPathFreeNodeSet(set: *mut XmlNodeSet);
    /// 1 when `first` precedes `second` in document order, -1 when it
    /// follows, 0 for the same node, -2 when they cannot be ordered.
    pub(crate) fn xmlXPathCmpNodes(first: *mut XmlNode, second: *mut XmlNode) -> c_int;
    pub(crate) fn xmlXPathNodeSetAddNs(
        set: *mut XmlNodeSet,
        node: *mut XmlNode,
        ns: *mut XmlNs,
    ) -> c_int;
    pub(crate) fn xmlGetProp(node: *mut XmlNode, name: *const u8) -> *mut u8;
    pub(crate) fn xmlNodeGetContent(node: *mut XmlNode) -> *mut u8;
    pub(crate) fn xmlNodeAddContent(node: *mut XmlNode, content: *const u8);
    pub(crate) fn xmlGetID(doc: *mut XmlDoc, id: *const u8) -> *mut XmlAttr;
    pub(crate) fn xmlSearchNs(
        doc: *mut XmlDoc,
        node: *mut XmlNode,
        prefix: *const u8,
    ) -> *mut XmlNs;
    pub(crate) fn xmlFreeDoc(doc: *mut XmlDoc);
    pub(crate) fn xmlOutputBufferWriteString(out: *mut c_void, text: *const c_char) -> c_int;
    pub(crate) fn xmlStrEqual(left: *const u8, right: *const u8) -> c_int;
}

/// Whether the linked libxml2 lays out its trees as declared; a function
/// that would read a tree fails otherwise.
pub(crate) fn readable() -> bool {
    xml_sec_libxml2::ffi::layout_matches()
}
