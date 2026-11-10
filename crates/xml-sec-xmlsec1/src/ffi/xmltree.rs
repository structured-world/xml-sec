//! `xmlsec/xmltree.h`: helpers over libxml2 trees.

use std::ffi::{c_int, c_void};

use xml_sec_libxml2::ffi::{XML_DOCUMENT_NODE, XML_ELEMENT_NODE, XmlNode};

use super::contain;
use super::errors::{self, check, here};
use super::tree::{readable, xmlNodeGetContent, xmlSearchNs, xmlStrEqual};

/// `xmlSecGetNodeContentAndTrim`: the text content of `cur` without leading
/// and trailing C-locale white space, which the caller frees with `xmlFree`.
///
/// # Safety
/// `cur` is null or a live node.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecGetNodeContentAndTrim(cur: *mut XmlNode) -> *mut u8 {
    contain(std::ptr::null_mut(), || {
        if cur.is_null() {
            return std::ptr::null_mut();
        }
        // SAFETY: a live node; the content is a NUL-terminated copy this
        // function owns until it returns it, trimmed in place.
        unsafe {
            let content = xmlNodeGetContent(cur);
            if content.is_null() {
                return content;
            }
            let len = std::ffi::CStr::from_ptr(content.cast()).to_bytes().len();
            let text = std::slice::from_raw_parts_mut(content, len + 1);
            // C `isspace` in the "C" locale.
            let space = |byte: &u8| matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r');
            let start = text[..len].iter().take_while(|byte| space(byte)).count();
            let end = len
                - text[start..len]
                    .iter()
                    .rev()
                    .take_while(|byte| space(byte))
                    .count();
            text.copy_within(start..end, 0);
            text[end - start] = 0;
            content
        }
    })
}

/// `xmlSecGetNodeNsHref`: the namespace of `cur`, or for an unqualified
/// node the default namespace in scope at it, as libxmlsec1 reads names.
///
/// # Safety
/// `cur` is null or a live node of a live document.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecGetNodeNsHref(cur: *mut XmlNode) -> *const u8 {
    contain(std::ptr::null(), || {
        check!(
            !cur.is_null(),
            "xmlSecGetNodeNsHref",
            c"cur != NULL",
            std::ptr::null()
        );
        if !readable() {
            errors::no_libxml2(here!("xmlSecGetNodeNsHref"));
            return std::ptr::null();
        }
        // SAFETY: `cur` is a live node; its namespace and document are live.
        unsafe {
            if let Some(ns) = (*cur).ns.as_ref() {
                return ns.href;
            }
            xmlSearchNs((*cur).doc, cur, std::ptr::null())
                .as_ref()
                .map_or(std::ptr::null(), |ns| ns.href)
        }
    })
}

/// `xmlSecCheckNodeName`: 1 when `cur` has local name `name` in namespace
/// `ns` (read as by [`xmlSecGetNodeNsHref`]), otherwise 0.
///
/// # Safety
/// `cur` is null or a live node; `name` and `ns` are null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecCheckNodeName(
    cur: *mut XmlNode,
    name: *const u8,
    ns: *const u8,
) -> c_int {
    contain(0, || {
        check!(!cur.is_null(), "xmlSecCheckNodeName", c"cur != NULL", 0);
        if !readable() {
            errors::no_libxml2(here!("xmlSecCheckNodeName"));
            return 0;
        }
        // SAFETY: `cur` is live; libxml2 compares possibly-null strings.
        unsafe {
            c_int::from(
                xmlStrEqual((*cur).name, name) != 0
                    && xmlStrEqual(xmlSecGetNodeNsHref(cur), ns) != 0,
            )
        }
    })
}

/// `xmlSecFindSibling`: `cur` or the first following sibling element with
/// the name and namespace.
///
/// # Safety
/// `cur` is null or a live node; `name` and `ns` as for
/// [`xmlSecCheckNodeName`].
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecFindSibling(
    cur: *mut XmlNode,
    name: *const u8,
    ns: *const u8,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !name.is_null(),
            "xmlSecFindSibling",
            c"name != NULL",
            std::ptr::null_mut()
        );
        if !readable() {
            errors::no_libxml2(here!("xmlSecFindSibling"));
            return std::ptr::null_mut();
        }
        let mut node = cur;
        while !node.is_null() {
            // SAFETY: `node` is `cur` or one of its live siblings.
            unsafe {
                if (*node).kind == XML_ELEMENT_NODE && xmlSecCheckNodeName(node, name, ns) != 0 {
                    return node;
                }
                node = (*node).next;
            }
        }
        std::ptr::null_mut()
    })
}

/// `xmlSecFindChild`: the first child element of `parent` with the name and
/// namespace.
///
/// # Safety
/// As for [`xmlSecFindSibling`], for `parent`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecFindChild(
    parent: *mut XmlNode,
    name: *const u8,
    ns: *const u8,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !parent.is_null(),
            "xmlSecFindChild",
            c"parent != NULL",
            std::ptr::null_mut()
        );
        check!(
            !name.is_null(),
            "xmlSecFindChild",
            c"name != NULL",
            std::ptr::null_mut()
        );
        // SAFETY: `parent` is live and its children are its nodes.
        unsafe { xmlSecFindSibling((*parent).children, name, ns) }
    })
}

/// `xmlSecFindParent`: `cur` or its nearest ancestor with the name and
/// namespace.
///
/// # Safety
/// As for [`xmlSecFindSibling`].
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecFindParent(
    cur: *mut XmlNode,
    name: *const u8,
    ns: *const u8,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !cur.is_null(),
            "xmlSecFindParent",
            c"cur != NULL",
            std::ptr::null_mut()
        );
        check!(
            !name.is_null(),
            "xmlSecFindParent",
            c"name != NULL",
            std::ptr::null_mut()
        );
        let mut node = cur;
        while !node.is_null() {
            // SAFETY: `node` is `cur` or one of its live ancestors.
            unsafe {
                if xmlSecCheckNodeName(node, name, ns) != 0 {
                    return node;
                }
                node = (*node).parent;
            }
        }
        std::ptr::null_mut()
    })
}

/// `xmlSecGetNextElementNode`: `cur` or its first following sibling that is
/// an element.
///
/// # Safety
/// `cur` is null or a live node.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecGetNextElementNode(cur: *mut XmlNode) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        if !readable() {
            return std::ptr::null_mut();
        }
        let mut node = cur;
        // SAFETY: `node` is `cur` or one of its live siblings.
        while !node.is_null() && unsafe { (*node).kind } != XML_ELEMENT_NODE {
            // SAFETY: as above.
            node = unsafe { (*node).next };
        }
        node
    })
}

/// What [`find_node`] looks for and found.
struct FindNode {
    name: *const u8,
    ns: *const u8,
    result: *mut XmlNode,
}

/// Stops the walk at the first element with the searched name.
unsafe extern "C" fn find_node(cur: *mut XmlNode, data: *mut c_void) -> c_int {
    // SAFETY: `data` is the search the caller set up; `cur` is a live node.
    unsafe {
        let search = &mut *data.cast::<FindNode>();
        if (*cur).kind == XML_ELEMENT_NODE && xmlSecCheckNodeName(cur, search.name, search.ns) != 0
        {
            search.result = cur;
            return 0;
        }
    }
    1
}

/// `xmlSecFindNode`: the first element with the name and namespace in the
/// subtrees of `parent` and of its following siblings, in document order.
///
/// # Safety
/// As for [`xmlSecFindSibling`], for `parent`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecFindNode(
    parent: *mut XmlNode,
    name: *const u8,
    ns: *const u8,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !name.is_null(),
            "xmlSecFindNode",
            c"name != NULL",
            std::ptr::null_mut()
        );
        let mut search = FindNode {
            name,
            ns,
            result: std::ptr::null_mut(),
        };
        let data = (&raw mut search).cast::<c_void>();
        let mut node = parent;
        while !node.is_null() {
            // SAFETY: `node` is `parent` or one of its live siblings.
            unsafe {
                if xmlSecDepthFirstTreeWalk(node, Some(find_node), data) < 0 {
                    errors::internal(
                        here!("xmlSecFindNode"),
                        std::ptr::null(),
                        c"xmlSecDepthFirstTreeWalk",
                    );
                    return std::ptr::null_mut();
                }
                if !search.result.is_null() {
                    break;
                }
                node = (*node).next;
            }
        }
        search.result
    })
}

/// `xmlSecTreeWalkCallback`: 1 continues, 0 stops, negative fails.
pub(crate) type TreeWalkCallback = Option<unsafe extern "C" fn(*mut XmlNode, *mut c_void) -> c_int>;

/// `xmlSecDepthFirstTreeWalk`: calls `callback` for `node` and every node of
/// its subtree in document order, attributes and namespaces excluded.
///
/// # Safety
/// `node` is null or a live node whose subtree stays live and unchanged
/// in shape while the walk runs; `callback` may change node contents.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecDepthFirstTreeWalk(
    node: *mut XmlNode,
    callback: TreeWalkCallback,
    data: *mut c_void,
) -> c_int {
    contain(-1, || {
        let Some(callback) = callback else {
            errors::assertion(here!("xmlSecDepthFirstTreeWalk"), c"callback != NULL");
            return -1;
        };
        if node.is_null() {
            return 0;
        }
        if !readable() {
            errors::no_libxml2(here!("xmlSecDepthFirstTreeWalk"));
            return -1;
        }
        // A stack of pending nodes, children pushed last first, as libxmlsec1
        // walks without recursion.
        let mut pending = vec![node];
        while let Some(current) = pending.pop() {
            // SAFETY: `current` is a live node of the walked subtree.
            let result = unsafe { callback(current, data) };
            if result < 0 {
                errors::internal(
                    here!("xmlSecDepthFirstTreeWalk"),
                    std::ptr::null(),
                    c"callback",
                );
                return -1;
            }
            if result == 0 {
                break;
            }
            // SAFETY: as above; an element's or document's children are live.
            unsafe {
                let kind = (*current).kind;
                if kind == XML_ELEMENT_NODE || kind == XML_DOCUMENT_NODE {
                    let mut child = (*current).last;
                    while !child.is_null() {
                        pending.push(child);
                        child = (*child).prev;
                    }
                }
            }
        }
        0
    })
}
