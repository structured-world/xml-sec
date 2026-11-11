//! Tree editing of `xmlsec/xmltree.h`: adding elements with the line feeds
//! libxmlsec1 writes around them, replacing nodes and content, registering
//! IDs and creating a document.

use std::ffi::{CStr, c_int, c_void};
use std::sync::atomic::{AtomicPtr, Ordering};

use xml_sec_libxml2::ffi::tree::{
    Ns, xsAddChild, xsAddID, xsAddNextSibling, xsAddPrevSibling, xsDocSetRootElement, xsFreeDoc,
    xsFreeNode, xsFreeNodeList, xsGetID, xsNewDoc, xsNewDocNode, xsNewDocText, xsNewNs,
    xsParseInNodeContext, xsReplaceNode, xsSearchNs, xsSearchNsByHref, xsSetNs, xsUnlinkNode,
};

use super::super::contain;
use super::super::errors::{self, check, here};
use super::super::parser::xmlSecParserGetDefaultOptions;
use super::super::strings::xmlSecStringCR;
use super::super::tree::{XML_ELEMENT_NODE, XmlDoc, XmlNode, c_text, nodes};
use super::content::xmlSecIsEmptyNode;
use super::{xmlSecDepthFirstTreeWalk, xmlSecFindNode, xmlSecFindSibling};

/// The line feed written around added elements; libxmlsec1 starts with
/// `xmlSecStringCR`, which is a line feed despite its name.
static LINE_FEED: AtomicPtr<u8> =
    AtomicPtr::new((&raw const xmlSecStringCR).cast::<u8>().cast_mut());

/// `xmlSecGetDefaultLineFeed`: the line feed added elements are surrounded
/// with.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn xmlSecGetDefaultLineFeed() -> *const u8 {
    LINE_FEED.load(Ordering::Acquire)
}

/// `xmlSecSetDefaultLineFeed`: replaces the line feed; the caller keeps the
/// string alive until it sets another.
///
/// # Safety
/// `linefeed` is NUL-terminated and outlives its use.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecSetDefaultLineFeed(linefeed: *const u8) {
    LINE_FEED.store(linefeed.cast_mut(), Ordering::Release);
}

/// A new text node of `node`'s document holding the default line feed; null
/// when it cannot be created, reported at `here`.
fn line_feed(node: *mut XmlNode, here: errors::Here) -> *mut XmlNode {
    // SAFETY: the line feed is NUL-terminated by the setter's contract.
    let text = unsafe { xsNewDocText(nodes::doc(node), xmlSecGetDefaultLineFeed()) };
    if text.is_null() {
        errors::xml_failed(here, std::ptr::null(), c"xmlNewText");
    }
    text
}

/// Appends a text node holding the default line feed to `parent`, as
/// libxmlsec1 does before and after an added child; false when it cannot be
/// created, reported at `here`.
fn add_line_feed(parent: *mut XmlNode, here: errors::Here) -> bool {
    let text = line_feed(parent, here);
    if text.is_null() {
        return false;
    }
    // SAFETY: both are handles, validated by the call.
    unsafe { xsAddChild(parent, text) };
    true
}

/// The namespace an added element `cur` uses for `ns`: one in scope whose
/// prefix is not redeclared below it, otherwise a new default declaration on
/// `cur`; null when none can be declared.
///
/// # Safety
/// `ns` is NUL-terminated.
unsafe fn namespace_for(cur: *mut XmlNode, ns: *const u8) -> *mut Ns {
    // SAFETY: handles are validated by each call; `ns` is NUL-terminated.
    unsafe {
        let doc = nodes::doc(cur);
        let found = xsSearchNsByHref(doc, cur, ns);
        let rebound = found.is_null() || {
            let prefix = nodes::binding(found).and_then(|(prefix, _)| prefix);
            let prefix = prefix.and_then(|prefix| std::ffi::CString::new(prefix).ok());
            let prefix = prefix
                .as_ref()
                .map_or(std::ptr::null(), |prefix| prefix.as_ptr());
            xsSearchNs(doc, cur, prefix.cast()) != found
        };
        if rebound {
            return xsNewNs(cur, ns, std::ptr::null());
        }
        found
    }
}

/// `xmlSecAddChild`: appends an element `name` in namespace `ns` to
/// `parent`, between line feeds.
///
/// # Safety
/// `name` and `ns` are null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecAddChild(
    parent: *mut XmlNode,
    name: *const u8,
    ns: *const u8,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        let here = here!("xmlSecAddChild");
        check!(
            !parent.is_null(),
            "xmlSecAddChild",
            c"parent != NULL",
            std::ptr::null_mut()
        );
        check!(
            !name.is_null(),
            "xmlSecAddChild",
            c"name != NULL",
            std::ptr::null_mut()
        );
        if nodes::first_child(parent).is_null() && !add_line_feed(parent, here) {
            return std::ptr::null_mut();
        }
        // SAFETY: handles are validated by each call; the names are
        // NUL-terminated by the caller's contract.
        unsafe {
            let created = xsNewDocNode(
                nodes::doc(parent),
                std::ptr::null_mut(),
                name,
                std::ptr::null(),
            );
            let cur = if created.is_null() {
                std::ptr::null_mut()
            } else {
                xsAddChild(parent, created)
            };
            if cur.is_null() {
                errors::xml_failed(here, std::ptr::null(), c"xmlNewChild");
                return std::ptr::null_mut();
            }
            if !ns.is_null() {
                let declared = namespace_for(cur, ns);
                if declared.is_null() {
                    errors::xml_failed(here, std::ptr::null(), c"xmlNewNs");
                    return std::ptr::null_mut();
                }
                xsSetNs(cur, declared);
            }
            if !add_line_feed(parent, here) {
                return std::ptr::null_mut();
            }
            cur
        }
    })
}

/// `xmlSecAddChildNode`: appends `child` to `parent`, between line feeds.
/// libxml2 merges a text child into the line feed before it and returns
/// the merged node; this tree keeps adjacent text nodes apart, so the child
/// itself is returned, linked.
///
/// # Safety
/// Callable with any pointers.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecAddChildNode(
    parent: *mut XmlNode,
    child: *mut XmlNode,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        let here = here!("xmlSecAddChildNode");
        check!(
            !parent.is_null(),
            "xmlSecAddChildNode",
            c"parent != NULL",
            std::ptr::null_mut()
        );
        check!(
            !child.is_null(),
            "xmlSecAddChildNode",
            c"child != NULL",
            std::ptr::null_mut()
        );
        if nodes::first_child(parent).is_null() && !add_line_feed(parent, here) {
            return std::ptr::null_mut();
        }
        // SAFETY: handles are validated by the call.
        let added = unsafe { xsAddChild(parent, child) };
        if added.is_null() {
            errors::xml_failed(here, std::ptr::null(), c"xmlAddChild");
            return std::ptr::null_mut();
        }
        if !add_line_feed(parent, here) {
            return std::ptr::null_mut();
        }
        added
    })
}

/// Which side of a node a sibling is added on.
#[derive(Clone, Copy)]
enum Side {
    Next,
    Prev,
}

/// `xmlSecAddNextSibling` and `xmlSecAddPrevSibling`: a new element beside
/// `node` with a line feed between them. A namespace declaration that
/// cannot be created leaves the element without one, as in libxmlsec1.
///
/// # Safety
/// `name` is NUL-terminated and `ns` null or NUL-terminated.
unsafe fn add_sibling(
    node: *mut XmlNode,
    name: *const u8,
    ns: *const u8,
    side: Side,
    here: errors::Here,
) -> *mut XmlNode {
    let add = match side {
        Side::Next => xsAddNextSibling,
        Side::Prev => xsAddPrevSibling,
    };
    // SAFETY: handles are validated by each call; the names are
    // NUL-terminated by the caller's contract.
    unsafe {
        let cur = xsNewDocNode(
            nodes::doc(node),
            std::ptr::null_mut(),
            name,
            std::ptr::null(),
        );
        if cur.is_null() {
            errors::xml_failed(here, std::ptr::null(), c"xmlNewNode");
            return std::ptr::null_mut();
        }
        add(node, cur);
        if !ns.is_null() {
            xsSetNs(cur, namespace_for(cur, ns));
        }
        let text = line_feed(node, here);
        if text.is_null() {
            return std::ptr::null_mut();
        }
        add(node, text);
        cur
    }
}

/// `xmlSecAddNextSibling`: a new element `name` in namespace `ns` after
/// `node`.
///
/// # Safety
/// `name` and `ns` are null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecAddNextSibling(
    node: *mut XmlNode,
    name: *const u8,
    ns: *const u8,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !node.is_null(),
            "xmlSecAddNextSibling",
            c"node != NULL",
            std::ptr::null_mut()
        );
        check!(
            !name.is_null(),
            "xmlSecAddNextSibling",
            c"name != NULL",
            std::ptr::null_mut()
        );
        // SAFETY: by the caller's contract.
        unsafe { add_sibling(node, name, ns, Side::Next, here!("xmlSecAddNextSibling")) }
    })
}

/// `xmlSecAddPrevSibling`: a new element `name` in namespace `ns` before
/// `node`.
///
/// # Safety
/// As for [`xmlSecAddNextSibling`].
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecAddPrevSibling(
    node: *mut XmlNode,
    name: *const u8,
    ns: *const u8,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !node.is_null(),
            "xmlSecAddPrevSibling",
            c"node != NULL",
            std::ptr::null_mut()
        );
        check!(
            !name.is_null(),
            "xmlSecAddPrevSibling",
            c"name != NULL",
            std::ptr::null_mut()
        );
        // SAFETY: by the caller's contract.
        unsafe { add_sibling(node, name, ns, Side::Prev, here!("xmlSecAddPrevSibling")) }
    })
}

/// `xmlSecEnsureEmptyChild`: the first empty element `name` in namespace
/// `ns` among the descendants of `parent` and their following siblings, or a
/// new one after the last such element (or at the end of `parent` when
/// there is none).
///
/// # Safety
/// `name` and `ns` are null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecEnsureEmptyChild(
    parent: *mut XmlNode,
    name: *const u8,
    ns: *const u8,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !parent.is_null(),
            "xmlSecEnsureEmptyChild",
            c"parent != NULL",
            std::ptr::null_mut()
        );
        check!(
            !name.is_null(),
            "xmlSecEnsureEmptyChild",
            c"name != NULL",
            std::ptr::null_mut()
        );
        // SAFETY: the names are NUL-terminated by the caller's contract.
        unsafe {
            let mut last = std::ptr::null_mut();
            let mut found = xmlSecFindNode(parent, name, ns);
            while !found.is_null() {
                last = found;
                if xmlSecIsEmptyNode(found) == 1 {
                    return found;
                }
                found = xmlSecFindSibling(nodes::next(found), name, ns);
            }
            let cur = if last.is_null() {
                xmlSecAddChild(parent, name, ns)
            } else {
                xmlSecAddNextSibling(last, name, ns)
            };
            if cur.is_null() {
                errors::internal_with(
                    here!("xmlSecEnsureEmptyChild"),
                    std::ptr::null(),
                    c"xmlSecAddChild or xmlSecAddNextSibling",
                    &format!("node={}", CStr::from_ptr(name.cast()).to_string_lossy()),
                );
            }
            cur
        }
    })
}

/// `xmlSecReplaceNode`: puts `new_node` in the place of `node`, which is
/// freed.
///
/// # Safety
/// Callable with any pointers.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecReplaceNode(
    node: *mut XmlNode,
    new_node: *mut XmlNode,
) -> c_int {
    // SAFETY: a null destination is never written.
    unsafe { xmlSecReplaceNodeAndReturn(node, new_node, std::ptr::null_mut()) }
}

/// `xmlSecReplaceNodeAndReturn`: puts `new_node` in the place of `node`;
/// the unlinked `node` goes to `replaced`, or is freed when it is null. A
/// replaced document element makes `new_node` the document element.
///
/// # Safety
/// `replaced` is null or writable.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecReplaceNodeAndReturn(
    node: *mut XmlNode,
    new_node: *mut XmlNode,
    replaced: *mut *mut XmlNode,
) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecReplaceNodeAndReturn");
        check!(
            !node.is_null(),
            "xmlSecReplaceNodeAndReturn",
            c"node != NULL",
            -1
        );
        check!(
            !new_node.is_null(),
            "xmlSecReplaceNodeAndReturn",
            c"newNode != NULL",
            -1
        );
        // The tree keeps its document element in its place, so a replaced
        // one needs none of the pointer repair libxmlsec1 does over libxml2.
        // SAFETY: handles are validated by each call; `replaced` is writable
        // by the caller's contract.
        unsafe {
            let old = xsReplaceNode(node, new_node);
            if old.is_null() {
                errors::xml_failed(here, std::ptr::null(), c"xmlReplaceNode");
                return -1;
            }
            if replaced.is_null() {
                xsFreeNode(old);
            } else {
                replaced.write(old);
            }
        }
        0
    })
}

/// `xmlSecReplaceContent`: makes `new_node` the content of `node`, whose
/// previous content is freed.
///
/// # Safety
/// Callable with any pointers.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecReplaceContent(
    node: *mut XmlNode,
    new_node: *mut XmlNode,
) -> c_int {
    // SAFETY: a null destination is never written.
    unsafe { xmlSecReplaceContentAndReturn(node, new_node, std::ptr::null_mut()) }
}

/// `xmlSecReplaceContentAndReturn`: makes `new_node` the content of `node`;
/// the previous children go to `replaced` as an unlinked sibling list, which
/// the caller frees with `xmlFreeNodeList`, or are freed when it is null.
///
/// # Safety
/// `replaced` is null or writable.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecReplaceContentAndReturn(
    node: *mut XmlNode,
    new_node: *mut XmlNode,
    replaced: *mut *mut XmlNode,
) -> c_int {
    contain(-1, || {
        check!(
            !node.is_null(),
            "xmlSecReplaceContentAndReturn",
            c"node != NULL",
            -1
        );
        check!(
            !new_node.is_null(),
            "xmlSecReplaceContentAndReturn",
            c"newNode != NULL",
            -1
        );
        let former = nodes::unlink_children(node);
        // SAFETY: handles are validated by each call; `replaced` is writable
        // by the caller's contract.
        unsafe {
            if replaced.is_null() {
                xsFreeNodeList(former);
            } else {
                replaced.write(former);
            }
            // libxmlsec1 links `new_node` alone, after unlinking it.
            xsUnlinkNode(new_node);
            xsAddChild(node, new_node);
        }
        0
    })
}

/// `xmlSecReplaceNodeBuffer`: replaces `node` with the nodes `buffer`
/// parses to in the context of its parent; `node` is freed.
///
/// # Safety
/// `buffer` is null or holds `size` bytes.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecReplaceNodeBuffer(
    node: *mut XmlNode,
    buffer: *const u8,
    size: usize,
) -> c_int {
    // SAFETY: by the caller's contract; a null destination is never written.
    unsafe { xmlSecReplaceNodeBufferAndReturn(node, buffer, size, std::ptr::null_mut()) }
}

/// `xmlSecReplaceNodeBufferAndReturn`: replaces `node` with the nodes
/// `buffer` parses to as UTF-8 in the context of its parent; the unlinked
/// `node` goes to `replaced`, or is freed when it is null.
///
/// # Safety
/// `buffer` is null or holds `size` bytes; `replaced` is null or writable.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecReplaceNodeBufferAndReturn(
    node: *mut XmlNode,
    buffer: *const u8,
    size: usize,
    replaced: *mut *mut XmlNode,
) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecReplaceNodeBufferAndReturn");
        check!(
            !node.is_null(),
            "xmlSecReplaceNodeBufferAndReturn",
            c"node != NULL",
            -1
        );
        let parent = nodes::parent(node);
        check!(
            !parent.is_null(),
            "xmlSecReplaceNodeBufferAndReturn",
            c"node->parent != NULL",
            -1
        );
        let Ok(len) = c_int::try_from(size) else {
            errors::size_to_int_impossible(here, size);
            return -1;
        };
        // SAFETY: handles are validated by each call; `buffer` holds `len`
        // bytes and `replaced` is writable by the caller's contract.
        unsafe {
            let mut results: *mut XmlNode = std::ptr::null_mut();
            let parsed = xsParseInNodeContext(
                parent,
                buffer.cast(),
                len,
                xmlSecParserGetDefaultOptions(),
                &raw mut results,
            );
            // XML_ERR_OK.
            if parsed != 0 {
                errors::xml_failed(here, std::ptr::null(), c"xmlParseInNodeContext");
                return -1;
            }
            while !results.is_null() {
                let next = nodes::next(results);
                xsAddPrevSibling(node, results);
                results = next;
            }
            xsUnlinkNode(node);
            if replaced.is_null() {
                xsFreeNode(node);
            } else {
                replaced.write(node);
            }
        }
        0
    })
}

/// The document and ID attribute names [`add_ids`] registers.
struct AddIds {
    doc: *mut XmlDoc,
    ids: *const *const u8,
}

/// Registers the ID attributes of the element `cur`; a value already bound
/// to another element is reported and left as it is.
unsafe extern "C" fn add_ids(cur: *mut XmlNode, data: *mut c_void) -> c_int {
    if nodes::kind(cur) != XML_ELEMENT_NODE {
        return 1;
    }
    // SAFETY: `data` is the walk's `AddIds`; its names list ends in null and
    // each name is NUL-terminated.
    unsafe {
        let walk = &*data.cast::<AddIds>();
        for attr in nodes::attributes(cur) {
            let name = nodes::name(attr);
            let mut id = walk.ids;
            while !(*id).is_null() {
                if c_text(*id).is_some_and(|wanted| name.as_deref() == Some(wanted))
                    && let Some(value) = nodes::content(attr)
                    && let Ok(value) = std::ffi::CString::new(value)
                {
                    let bound = xsGetID(walk.doc, value.as_ptr().cast());
                    if bound.is_null() {
                        // A refusal leaves the attribute unregistered, as
                        // libxml2's failed xmlAddID does.
                        xsAddID(walk.doc, value.as_ptr().cast(), attr);
                    } else if bound != cur {
                        errors::invalid_string_data(
                            here!("xmlSecAddIDsCallback"),
                            std::ptr::null(),
                            "id",
                            value.as_bytes(),
                            "unique id (id already defined)",
                        );
                    }
                }
                id = id.add(1);
            }
        }
    }
    1
}

/// `xmlSecAddIDs`: registers as IDs of `doc` the attributes named in `ids`
/// (a null-terminated list) on the elements of `node`'s subtree, or of every
/// top-level element when `node` is null.
///
/// # Safety
/// `ids` is null or a null-terminated list of NUL-terminated names.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecAddIDs(
    doc: *mut XmlDoc,
    node: *mut XmlNode,
    ids: *const *const u8,
) {
    contain((), || {
        check!(!doc.is_null(), "xmlSecAddIDs", c"doc != NULL");
        check!(!ids.is_null(), "xmlSecAddIDs", c"ids != NULL");
        let here = here!("xmlSecAddIDs");
        let mut walk = AddIds { doc, ids };
        let data = (&raw mut walk).cast::<c_void>();
        let roots: Vec<*mut XmlNode> = if node.is_null() {
            let mut roots = Vec::new();
            let mut cur = nodes::first_child(doc);
            while !cur.is_null() {
                if nodes::is_element(cur) {
                    roots.push(cur);
                }
                cur = nodes::next(cur);
            }
            roots
        } else if nodes::is_element(node) {
            vec![node]
        } else {
            Vec::new()
        };
        for root in roots {
            // SAFETY: `add_ids` takes the walk's `AddIds`, which outlives it.
            if unsafe { xmlSecDepthFirstTreeWalk(root, Some(add_ids), data) } < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecDepthFirstTreeWalk");
                return;
            }
        }
    });
}

/// `xmlSecCreateTree`: a new XML 1.0 document whose root element is
/// `root_node_name` in the default namespace `root_node_ns`.
///
/// # Safety
/// `root_node_name` and `root_node_ns` are null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecCreateTree(
    root_node_name: *const u8,
    root_node_ns: *const u8,
) -> *mut XmlDoc {
    contain(std::ptr::null_mut(), || {
        check!(
            !root_node_name.is_null(),
            "xmlSecCreateTree",
            c"rootNodeName != NULL",
            std::ptr::null_mut()
        );
        let here = here!("xmlSecCreateTree");
        let text = |value: *const u8| {
            if value.is_null() {
                "NULL".to_owned()
            } else {
                // SAFETY: a non-null argument is NUL-terminated.
                unsafe { CStr::from_ptr(value.cast()) }
                    .to_string_lossy()
                    .into_owned()
            }
        };
        // SAFETY: handles are validated by each call; the names are
        // NUL-terminated by the caller's contract; the document is freed on
        // failure.
        unsafe {
            let doc = xsNewDoc(c"1.0".as_ptr().cast());
            if doc.is_null() {
                errors::xml_failed(here, std::ptr::null(), c"xmlNewDoc");
                return std::ptr::null_mut();
            }
            let root = xsNewDocNode(doc, std::ptr::null_mut(), root_node_name, std::ptr::null());
            if root.is_null() {
                errors::xml_failed_with(
                    here,
                    std::ptr::null(),
                    c"xmlNewDocNode",
                    &format!("node={}", text(root_node_name)),
                );
                xsFreeDoc(doc);
                return std::ptr::null_mut();
            }
            xsDocSetRootElement(doc, root);
            // libxml2 declares a null URI as a namespace with no URI, which
            // it never writes and which puts the element in no namespace:
            // the element as it is.
            if root_node_ns.is_null() {
                return doc;
            }
            let ns = xsNewNs(root, root_node_ns, std::ptr::null());
            if ns.is_null() {
                errors::xml_failed_with(
                    here,
                    std::ptr::null(),
                    c"xmlNewNs",
                    &format!("ns={}", text(root_node_ns)),
                );
                xsFreeDoc(doc);
                return std::ptr::null_mut();
            }
            xsSetNs(root, ns);
            doc
        }
    })
}

#[cfg(test)]
mod tests;
