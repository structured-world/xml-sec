//! `xmlsec/xmltree.h`: helpers over the document tree.

use std::ffi::{c_int, c_void};

use super::contain;
use super::errors::{self, check, here};
use super::tree::{XML_DOCUMENT_NODE, XML_ELEMENT_NODE, XmlNode, give, nodes, same_text};

mod content;
mod edit;
mod qname;

pub(crate) use content::{
    xmlSecGetNodeContentAsSize, xmlSecIsEmptyNode, xmlSecNodeEncodeAndSetContent,
    xmlSecPrintXmlString,
};
pub(crate) use edit::{
    xmlSecAddChild, xmlSecAddNextSibling, xmlSecAddPrevSibling, xmlSecGetDefaultLineFeed,
    xmlSecReplaceContent,
};

/// C `isspace` in the "C" locale, which libxmlsec1 trims and tests with.
const fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// The text content of `cur` without leading and trailing C-locale white
/// space, as libxmlsec1 reads element values.
pub(crate) fn trimmed_content(cur: *const XmlNode) -> Option<String> {
    let content = nodes::content(cur)?;
    Some(
        content
            .trim_matches(|character: char| u8::try_from(character).is_ok_and(is_space))
            .to_owned(),
    )
}

/// `xmlSecGetNodeContentAndTrim`: the text content of `cur` without leading
/// and trailing C-locale white space, which the caller frees with `xmlFree`.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecGetNodeContentAndTrim(cur: *mut XmlNode) -> *mut u8 {
    contain(std::ptr::null_mut(), || {
        give(trimmed_content(cur).as_deref())
    })
}

/// The namespace of `cur`, or for an unqualified node the default namespace
/// in scope at it, as libxmlsec1 reads names.
pub(crate) fn namespace_of(cur: *const XmlNode) -> Option<String> {
    nodes::namespace(cur).or_else(|| nodes::in_scope(cur, None).filter(|uri| !uri.is_empty()))
}

/// `xmlSecGetNodeNsHref`: the namespace of `cur` as [`namespace_of`] reads
/// it; the string lives as long as the document.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecGetNodeNsHref(cur: *mut XmlNode) -> *const u8 {
    contain(std::ptr::null(), || {
        check!(
            !cur.is_null(),
            "xmlSecGetNodeNsHref",
            c"cur != NULL",
            std::ptr::null()
        );
        match (namespace_of(cur), nodes::document_of(cur)) {
            (Some(uri), Some(document)) => xml_sec_libxml2::handles::intern(document, &uri),
            _ => std::ptr::null(),
        }
    })
}

/// Whether `cur` has local name `name` in namespace `ns`, read as by
/// [`namespace_of`].
///
/// # Safety
/// `name` and `ns` are null or NUL-terminated.
pub(crate) unsafe fn has_name(cur: *const XmlNode, name: *const u8, ns: *const u8) -> bool {
    // SAFETY: by the caller's contract.
    unsafe {
        same_text(nodes::name(cur).as_deref(), name) && same_text(namespace_of(cur).as_deref(), ns)
    }
}

/// `xmlSecCheckNodeName`: 1 when `cur` has local name `name` in namespace
/// `ns` (read as by [`namespace_of`]), otherwise 0.
///
/// # Safety
/// `name` and `ns` are null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecCheckNodeName(
    cur: *mut XmlNode,
    name: *const u8,
    ns: *const u8,
) -> c_int {
    contain(0, || {
        check!(!cur.is_null(), "xmlSecCheckNodeName", c"cur != NULL", 0);
        // SAFETY: by the caller's contract.
        c_int::from(unsafe { has_name(cur, name, ns) })
    })
}

/// `xmlSecFindSibling`: `cur` or the first following sibling element with
/// the name and namespace.
///
/// # Safety
/// `name` and `ns` as for [`xmlSecCheckNodeName`].
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
        let mut node = cur;
        while !node.is_null() {
            // SAFETY: by the caller's contract.
            if nodes::is_element(node) && unsafe { has_name(node, name, ns) } {
                return node;
            }
            node = nodes::next(node);
        }
        std::ptr::null_mut()
    })
}

/// `xmlSecFindChild`: the first child element of `parent` with the name and
/// namespace.
///
/// # Safety
/// As for [`xmlSecFindSibling`].
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
        // SAFETY: by the caller's contract.
        unsafe { xmlSecFindSibling(nodes::first_child(parent), name, ns) }
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
            // SAFETY: by the caller's contract.
            if unsafe { has_name(node, name, ns) } {
                return node;
            }
            node = nodes::parent(node);
        }
        std::ptr::null_mut()
    })
}

/// `cur` or its first following sibling that is an element.
pub(crate) fn next_element(cur: *const XmlNode) -> *mut XmlNode {
    let mut node = cur.cast_mut();
    while !node.is_null() && !nodes::is_element(node) {
        node = nodes::next(node);
    }
    node
}

/// `xmlSecGetNextElementNode`: `cur` or its first following sibling that is
/// an element.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecGetNextElementNode(cur: *mut XmlNode) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || next_element(cur))
}

/// What [`find_node`] looks for and found.
struct FindNode {
    name: *const u8,
    ns: *const u8,
    result: *mut XmlNode,
}

/// Stops the walk at the first element with the searched name.
unsafe extern "C" fn find_node(cur: *mut XmlNode, data: *mut c_void) -> c_int {
    // SAFETY: `data` is the search the caller set up; its strings are the
    // caller's NUL-terminated ones.
    unsafe {
        let search = &mut *data.cast::<FindNode>();
        if nodes::is_element(cur) && has_name(cur, search.name, search.ns) {
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
/// As for [`xmlSecFindSibling`].
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
            // SAFETY: the search outlives the walk.
            if unsafe { xmlSecDepthFirstTreeWalk(node, Some(find_node), data) } < 0 {
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
            node = nodes::next(node);
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
/// `callback` is callable with `data`.
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
        // A stack of pending nodes, children pushed last first, as libxmlsec1
        // walks without recursion. A node the callback frees is refused by
        // every later lookup, so its children are not reached.
        let mut pending = vec![node];
        while let Some(current) = pending.pop() {
            // SAFETY: by the caller's contract.
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
            // An entity reference a tree kept holds its parsed replacement,
            // which is content (XML 1.0 section 4.4.2), so the walk enters it.
            let kind = nodes::kind(current);
            if matches!(
                kind,
                XML_ELEMENT_NODE | XML_DOCUMENT_NODE | nodes::XML_ENTITY_REF_NODE
            ) {
                let mut child = nodes::last_child(current);
                while !child.is_null() {
                    pending.push(child);
                    child = nodes::prev(child);
                }
            }
        }
        0
    })
}
