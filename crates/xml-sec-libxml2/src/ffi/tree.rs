//! The tree functions: our own functions shaped like libxml2's interfaces,
//! exported under the `xs` prefix where libxml2 has `xml`.
//!
//! Each function takes and returns the opaque handles of [`crate::nodes`] as
//! `xmlDocPtr`, `xmlNodePtr`, `xmlNsPtr`, `xmlAttrPtr` and `xmlNodeSetPtr`.
//! A handle is validated before use and refused (null, 0 or -1) when it
//! names nothing live; no handle is dereferenced. Strings a function returns
//! are copies on the library's heap, released with
//! [`xsFree`](super::memory::xsFree). The parameters, semantics and ownership
//! follow the libxml2 function of the same name except where a comment says
//! otherwise.

use std::ffi::{CStr, c_char, c_int};
use std::panic::AssertUnwindSafe;

use xml_sec::document::owned_tree::{OwnedTree, TreeError, TreeNode, TreeNodeKind};

use super::memory;
use crate::handles::{self, HandleError, Resolved, Target};
use crate::nodes::{self, document_of, handle_of, node_pointer, pointer_of, tree_node};
pub use crate::nodes::{Attr, Doc, Node, NodeSet, Ns, XmlChar};

/// Run `work`, turning a panic into `fallback` instead of unwinding into C.
fn contain<R>(fallback: R, work: impl FnOnce() -> R) -> R {
    std::panic::catch_unwind(AssertUnwindSafe(work)).unwrap_or(fallback)
}

/// The text of a NUL-terminated string; `None` for null or text that is
/// not UTF-8.
///
/// # Safety
/// `text` is null or NUL-terminated and readable.
unsafe fn text<'a>(text: *const XmlChar) -> Option<&'a str> {
    if text.is_null() {
        return None;
    }
    // SAFETY: a NUL-terminated string by the caller's contract.
    unsafe { CStr::from_ptr(text.cast::<c_char>()) }
        .to_str()
        .ok()
}

/// A string argument that is neither null nor UTF-8.
struct NotText;

/// The text of an optional NUL-terminated argument: `Ok(None)` for null,
/// which the call reads as absent, and [`NotText`] for text that is not
/// UTF-8, which names nothing the call can act on and refuses it.
///
/// # Safety
/// As for [`text`].
unsafe fn optional<'a>(value: *const XmlChar) -> Result<Option<&'a str>, NotText> {
    if value.is_null() {
        return Ok(None);
    }
    // SAFETY: the caller's contract.
    unsafe { text(value) }.map(Some).ok_or(NotText)
}

/// As [`text`], with null as the empty string, as libxml2 takes a null value.
///
/// # Safety
/// As for [`text`].
unsafe fn text_or_empty<'a>(value: *const XmlChar) -> Option<&'a str> {
    if value.is_null() {
        Some("")
    } else {
        // SAFETY: the caller's contract.
        unsafe { text(value) }
    }
}

/// A copy of `value` the caller releases with `xsFree`, or null for none.
fn give(value: Option<String>) -> *mut XmlChar {
    value.map_or(std::ptr::null_mut(), |value| memory::copy(value.as_bytes()))
}

fn status<T>(result: &Result<T, HandleError>) -> c_int {
    if result.is_ok() { 0 } else { -1 }
}

/// `xmlStrEqual`: whether two strings are equal; two nulls are.
///
/// # Safety
/// Each pointer is null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsStrEqual(left: *const XmlChar, right: *const XmlChar) -> c_int {
    contain(0, || {
        if left.is_null() || right.is_null() {
            return c_int::from(left.is_null() && right.is_null());
        }
        // SAFETY: both NUL-terminated by the caller's contract.
        let (left, right) = unsafe {
            (
                CStr::from_ptr(left.cast::<c_char>()),
                CStr::from_ptr(right.cast::<c_char>()),
            )
        };
        c_int::from(left == right)
    })
}

/// `xmlReadMemory`: the document in `size` bytes at `buffer`, parsed by the
/// core under the library policy; null when it is refused. The bytes are in
/// the encoding their byte-order mark or XML declaration selects, UTF-16
/// included; `url`, `encoding` and `options` are accepted for the shape of
/// the call and do not change the parse, which loads nothing external.
///
/// # Safety
/// `buffer` is null or holds `size` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsReadMemory(
    buffer: *const c_char,
    size: c_int,
    _url: *const c_char,
    _encoding: *const c_char,
    _options: c_int,
) -> *mut Doc {
    contain(std::ptr::null_mut(), || {
        let Ok(size) = usize::try_from(size) else {
            return std::ptr::null_mut();
        };
        if buffer.is_null() {
            return std::ptr::null_mut();
        }
        // SAFETY: `buffer` holds `size` bytes by the caller's contract.
        let bytes = unsafe { std::slice::from_raw_parts(buffer.cast::<u8>(), size) };
        crate::document::parse(bytes).map_or(std::ptr::null_mut(), pointer_of)
    })
}

/// `xmlNewDoc`: a new empty document; the version is accepted for the shape
/// of the call.
///
/// # Safety
/// `version` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsNewDoc(_version: *const XmlChar) -> *mut Doc {
    contain(std::ptr::null_mut(), || {
        handles::register(OwnedTree::new()).map_or(std::ptr::null_mut(), pointer_of)
    })
}

/// `xmlFreeDoc`: free the document and every node of it; a value that names
/// no live document is ignored.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsFreeDoc(doc: *mut Doc) {
    contain((), || crate::document::free(doc));
}

/// `xmlDocGetRootElement`: the document element of `doc`.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsDocGetRootElement(doc: *const Doc) -> *mut Node {
    contain(std::ptr::null_mut(), || nodes::root_element(doc))
}

/// `xmlDocSetRootElement`: make `root` the document element of `doc`,
/// unlinking it first; returns the former document element, unlinked, or
/// null.
///
/// # Safety
/// Callable with any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsDocSetRootElement(doc: *mut Doc, root: *mut Node) -> *mut Node {
    contain(std::ptr::null_mut(), || {
        let (Some(document), Some((owner, root))) = (document_of(doc), tree_node(root)) else {
            return std::ptr::null_mut();
        };
        if owner != document {
            return std::ptr::null_mut();
        }
        let old = handles::edit_document(document, |tree| {
            if tree.kind(root)? != TreeNodeKind::Element {
                return Ok(None);
            }
            tree.unlink(root)?;
            if let Some(old) = tree.root_element() {
                tree.insert_before(old, root)?;
                tree.unlink(old)?;
                Ok(Some(old))
            } else {
                let node = tree.document_node();
                tree.append_child(node, root)?;
                Ok(None)
            }
        });
        match old {
            Ok(Some(old)) => node_pointer(document, old),
            _ => std::ptr::null_mut(),
        }
    })
}

/// `xmlDocDumpMemory`: the document as XML text in `*mem`, its length in
/// `*size`; the caller frees `*mem` with `xsFree`. On failure `*mem` is null
/// and `*size` zero.
///
/// # Safety
/// `mem` and `size` are null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsDocDumpMemory(
    doc: *const Doc,
    mem: *mut *mut XmlChar,
    size: *mut c_int,
) {
    contain((), || {
        let text = document_of(doc)
            .and_then(|document| handles::read_document(document, OwnedTree::serialize).ok());
        let wants_text = !mem.is_null() && mem.is_aligned();
        let (pointer, length) = match text.map(|text| (c_int::try_from(text.len()), text)) {
            // A copy is made only for a destination that receives it; one no
            // one receives could never be freed.
            Some((Ok(length), text)) if wants_text => (memory::copy(text.as_bytes()), length),
            Some((Ok(length), _)) => (std::ptr::null_mut(), length),
            _ => (std::ptr::null_mut(), 0),
        };
        let failed = wants_text && pointer.is_null();
        if wants_text {
            // SAFETY: writable by the caller's contract.
            unsafe { mem.write(pointer) };
        }
        if !size.is_null() && size.is_aligned() {
            // SAFETY: as above.
            unsafe { size.write(if failed { 0 } else { length }) };
        }
    });
}

/// The document `node` belongs to, as `node->doc`.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsNodeGetDoc(node: *const Node) -> *mut Doc {
    contain(std::ptr::null_mut(), || nodes::doc(node))
}

/// The parent of `node`, as `node->parent`; an attribute's element.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsNodeGetParent(node: *const Node) -> *mut Node {
    contain(std::ptr::null_mut(), || nodes::parent(node))
}

/// The first child of `node`, as `node->children`.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsNodeGetChildren(node: *const Node) -> *mut Node {
    contain(std::ptr::null_mut(), || nodes::first_child(node))
}

/// The last child of `node`, as `node->last`.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsNodeGetLast(node: *const Node) -> *mut Node {
    contain(std::ptr::null_mut(), || nodes::last_child(node))
}

/// The next sibling of `node`, as `node->next`.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsNodeGetNext(node: *const Node) -> *mut Node {
    contain(std::ptr::null_mut(), || nodes::next(node))
}

/// The previous sibling of `node`, as `node->prev`.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsNodeGetPrev(node: *const Node) -> *mut Node {
    contain(std::ptr::null_mut(), || nodes::prev(node))
}

/// The libxml2 node type of `node`, as `node->type`: an attribute is
/// `XML_ATTRIBUTE_NODE`, a namespace declaration or node
/// `XML_NAMESPACE_DECL`; 0 for nothing live.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsNodeGetType(node: *const Node) -> c_int {
    contain(0, || nodes::kind(node))
}

/// The name of `node`, as `node->name` (see [`nodes::name`]); a copy the
/// caller frees with `xsFree`, or null.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsNodeGetName(node: *const Node) -> *mut XmlChar {
    contain(std::ptr::null_mut(), || give(nodes::name(node)))
}

/// The name of `node` as `node->name` reads it: a string the caller does
/// not own, valid until the document is freed; null for a node without a
/// name or a value naming nothing live. libxmlsec1's `xmlSecNodeGetName`
/// macro reads it.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsNodeName(node: *const Node) -> *const XmlChar {
    contain(std::ptr::null(), || {
        let (Ok(document), Some(name)) = (handles::document(handle_of(node)), nodes::name(node))
        else {
            return std::ptr::null();
        };
        handles::intern(document, &name)
    })
}

/// The namespace URI of an element or attribute, as `node->ns->href`; a
/// copy the caller frees with `xsFree`, or null for none.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsNodeGetNsHref(node: *const Node) -> *mut XmlChar {
    contain(std::ptr::null_mut(), || give(nodes::namespace(node)))
}

/// The prefix of an element or attribute, as `node->ns->prefix`; a copy the
/// caller frees with `xsFree`, or null for none.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsNodeGetNsPrefix(node: *const Node) -> *mut XmlChar {
    contain(std::ptr::null_mut(), || give(nodes::prefix(node)))
}

/// The URI of the declaration or namespace node `ns`, as `ns->href`; a copy
/// the caller frees with `xsFree`, or null.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsNsGetHref(ns: *const Ns) -> *mut XmlChar {
    contain(std::ptr::null_mut(), || {
        give(nodes::binding(ns).map(|(_, uri)| uri))
    })
}

/// The prefix of the declaration or namespace node `ns`, as `ns->prefix`; a
/// copy the caller frees with `xsFree`, or null for the default namespace.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsNsGetPrefix(ns: *const Ns) -> *mut XmlChar {
    contain(std::ptr::null_mut(), || {
        give(nodes::binding(ns).and_then(|(prefix, _)| prefix))
    })
}

/// The attributes of the element `node`, in document order, as the
/// `node->properties` list: the first, then [`xsAttrGetNext`].
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsNodeGetProperties(node: *const Node) -> *mut Attr {
    contain(std::ptr::null_mut(), || {
        nodes::attributes(node)
            .first()
            .copied()
            .unwrap_or(std::ptr::null_mut())
    })
}

/// The attribute after `attr` on its element, as `attr->next`, or null.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsAttrGetNext(attr: *const Attr) -> *mut Attr {
    contain(std::ptr::null_mut(), || {
        let siblings = nodes::attributes(nodes::parent(attr));
        siblings
            .iter()
            .position(|&sibling| std::ptr::eq(sibling, attr))
            .and_then(|position| siblings.get(position + 1).copied())
            .unwrap_or(std::ptr::null_mut())
    })
}

/// The first namespace declaration of the element `node`, as `node->nsDef`;
/// the next are [`xsNsGetNext`].
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsNodeGetNsDef(node: *const Node) -> *mut Ns {
    contain(std::ptr::null_mut(), || {
        nodes::declarations(node)
            .first()
            .copied()
            .unwrap_or(std::ptr::null_mut())
    })
}

/// The declaration after `ns` on its element, as `ns->next`, or null.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsNsGetNext(ns: *const Ns) -> *mut Ns {
    contain(std::ptr::null_mut(), || {
        let Ok(Resolved {
            document,
            target: Target::Namespace { element, .. },
        }) = handles::resolve(handle_of(ns))
        else {
            return std::ptr::null_mut();
        };
        let siblings = nodes::declarations(node_pointer(document, element));
        siblings
            .iter()
            .position(|&sibling| std::ptr::eq(sibling, ns))
            .and_then(|position| siblings.get(position + 1).copied())
            .unwrap_or(std::ptr::null_mut())
    })
}

/// `xmlNewDocNode`: a new unlinked element of `doc` named `name`, in the
/// namespace of `ns` if not null, with `content` as its text if not null.
///
/// # Safety
/// `name` and `content` are null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsNewDocNode(
    doc: *mut Doc,
    ns: *mut Ns,
    name: *const XmlChar,
    content: *const XmlChar,
) -> *mut Node {
    contain(std::ptr::null_mut(), || {
        // SAFETY: NUL-terminated or null by the caller's contract.
        let (Some(name), Ok(content)) = (unsafe { text(name) }, unsafe { optional(content) })
        else {
            return std::ptr::null_mut();
        };
        let Some(document) = document_of(doc) else {
            return std::ptr::null_mut();
        };
        let (prefix, namespace) = if ns.is_null() {
            (None, None)
        } else {
            match nodes::binding(ns) {
                Some((prefix, uri)) => (prefix, Some(uri)),
                None => return std::ptr::null_mut(),
            }
        };
        let created = handles::edit_document(document, |tree| {
            let element = tree.create_element(name, prefix.as_deref(), namespace.as_deref())?;
            if let Some(content) = content {
                tree.set_text(element, content)?;
            }
            Ok(element)
        });
        created.map_or(std::ptr::null_mut(), |element| {
            node_pointer(document, element)
        })
    })
}

/// A new unlinked leaf of `doc` that `create` builds from `content`.
fn new_leaf(
    doc: *mut Doc,
    content: Option<&str>,
    create: impl FnOnce(&mut OwnedTree, &str) -> Result<TreeNode, TreeError>,
) -> *mut Node {
    let (Some(content), Some(document)) = (content, document_of(doc)) else {
        return std::ptr::null_mut();
    };
    handles::edit_document(document, |tree| create(tree, content))
        .map_or(std::ptr::null_mut(), |node| node_pointer(document, node))
}

/// `xmlNewDocText`: a new unlinked text node of `doc`.
///
/// # Safety
/// `content` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsNewDocText(doc: *mut Doc, content: *const XmlChar) -> *mut Node {
    contain(std::ptr::null_mut(), || {
        // SAFETY: as documented.
        new_leaf(doc, unsafe { text(content) }, OwnedTree::create_text)
    })
}

/// `xmlNewDocComment`: a new unlinked comment of `doc`.
///
/// # Safety
/// `content` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsNewDocComment(doc: *mut Doc, content: *const XmlChar) -> *mut Node {
    contain(std::ptr::null_mut(), || {
        // SAFETY: as documented.
        new_leaf(doc, unsafe { text(content) }, OwnedTree::create_comment)
    })
}

/// The two nodes of one document `first` and `second` name.
fn pair(first: *const Node, second: *const Node) -> Option<(usize, TreeNode, TreeNode)> {
    let (document, first) = tree_node(first)?;
    let (other, second) = tree_node(second)?;
    (document == other).then_some((document, first, second))
}

/// Link `node` by `place` relative to `anchor`, unlinking it first as
/// libxml2 does; returns `node`, or null when refused. Adjacent text is not
/// merged, so the returned node is always the node passed.
fn link(
    anchor: *mut Node,
    node: *mut Node,
    place: fn(&mut OwnedTree, TreeNode, TreeNode) -> Result<(), TreeError>,
) -> *mut Node {
    let Some((document, anchor_node, linked)) = pair(anchor, node) else {
        return std::ptr::null_mut();
    };
    let done = handles::edit_document(document, |tree| {
        moved(tree, linked, |tree| place(tree, anchor_node, linked))
    });
    if done.is_ok() {
        node
    } else {
        std::ptr::null_mut()
    }
}

/// Unlink `node` and run `place`; when `place` refuses, `node` goes back
/// where it was, so a refused call leaves the document as it found it. The
/// tree alone decides what a link may do.
fn moved(
    tree: &mut OwnedTree,
    node: TreeNode,
    place: impl FnOnce(&mut OwnedTree) -> Result<(), TreeError>,
) -> Result<(), TreeError> {
    let origin = match tree.parent(node)? {
        Some(parent) => Some((parent, tree.next_sibling(node)?)),
        None => None,
    };
    if origin.is_some() {
        tree.unlink(node)?;
    }
    place(tree).inspect_err(|_| match origin {
        Some((_, Some(next))) => tree
            .insert_before(next, node)
            .expect("a node goes back before its former sibling"),
        Some((parent, None)) => tree
            .append_child(parent, node)
            .expect("a node goes back under its former parent"),
        None => {}
    })
}

/// `xmlAddChild`: link `child` as the last child of `parent`.
///
/// # Safety
/// Callable with any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsAddChild(parent: *mut Node, child: *mut Node) -> *mut Node {
    contain(std::ptr::null_mut(), || {
        link(parent, child, OwnedTree::append_child)
    })
}

/// `xmlAddNextSibling`: link `node` just after `current`.
///
/// # Safety
/// Callable with any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsAddNextSibling(current: *mut Node, node: *mut Node) -> *mut Node {
    contain(std::ptr::null_mut(), || {
        link(current, node, OwnedTree::insert_after)
    })
}

/// `xmlAddPrevSibling`: link `node` just before `current`.
///
/// # Safety
/// Callable with any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsAddPrevSibling(current: *mut Node, node: *mut Node) -> *mut Node {
    contain(std::ptr::null_mut(), || {
        link(current, node, OwnedTree::insert_before)
    })
}

/// `xmlUnlinkNode`: unlink `node`; it stays a live node of its document. A
/// value naming nothing live, or the document node, is ignored.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsUnlinkNode(node: *mut Node) {
    contain((), || {
        if handles::edit(handle_of(node), OwnedTree::unlink).is_err() {
            // libxml2's function returns nothing; there is no one to tell.
        }
    });
}

/// `xmlFreeNode`: unlink and free `node` with its subtree; every handle of
/// those nodes is refused afterwards. A value naming nothing live is
/// ignored.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsFreeNode(node: *mut Node) {
    contain((), || {
        if handles::edit(handle_of(node), OwnedTree::free).is_err() {
            // As for `xsUnlinkNode`.
        }
    });
}

/// `xmlDocCopyNode`: a copy of `node` and its subtree in `doc`, unlinked,
/// for `extended` 1, the recursive copy; null otherwise or when refused. An
/// element copy declares the namespace bindings it inherited.
///
/// # Safety
/// Callable with any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsDocCopyNode(
    node: *const Node,
    doc: *mut Doc,
    extended: c_int,
) -> *mut Node {
    contain(std::ptr::null_mut(), || {
        if extended == 1 {
            nodes::copy_node(node, doc)
        } else {
            std::ptr::null_mut()
        }
    })
}

/// `xmlFreeNodeList`: free `node` and every sibling after it, each with its
/// subtree; a node of a linked list is unlinked before it is freed.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsFreeNodeList(node: *mut Node) {
    contain((), || nodes::free_list(node));
}

/// libxml2's `XML_ERR_INTERNAL_ERROR`, returned for a refused context.
const XML_ERR_INTERNAL_ERROR: c_int = 1;
/// libxml2's `XML_ERR_NO_MEMORY`.
const XML_ERR_NO_MEMORY: c_int = 2;
/// libxml2's `XML_ERR_DOCUMENT_END`: markup after the content, as a fragment
/// that closes its context reports.
const XML_ERR_DOCUMENT_END: c_int = 5;

/// `xmlParseInNodeContext`: parse the `size` bytes at `data`, UTF-8, as
/// content of the element `node`, under the library policy; the parsed
/// nodes come back in `*list` as one run of unlinked siblings (null when
/// there are none), which the caller links or frees with
/// [`xsFreeNodeList`]. Returns 0, or a libxml2 error code: 1 for a refused
/// context or bytes that are not UTF-8, 5 for content that is not
/// well-formed or that the policy refuses. `options` is accepted for the
/// shape of the call; nothing external is loaded.
///
/// # Safety
/// `data` is null or holds `size` bytes; `list` is null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsParseInNodeContext(
    node: *mut Node,
    data: *const c_char,
    size: c_int,
    _options: c_int,
    list: *mut *mut Node,
) -> c_int {
    contain(XML_ERR_NO_MEMORY, || {
        let writable = !list.is_null() && list.is_aligned();
        if writable {
            // SAFETY: writable by the caller's contract.
            unsafe { list.write(std::ptr::null_mut()) };
        }
        let (Ok(size), false) = (usize::try_from(size), data.is_null()) else {
            return XML_ERR_INTERNAL_ERROR;
        };
        // SAFETY: `data` holds `size` bytes by the caller's contract.
        let bytes = unsafe { std::slice::from_raw_parts(data.cast::<u8>(), size) };
        match nodes::parse_in_context(node, bytes) {
            Ok(first) if writable => {
                // SAFETY: as above.
                unsafe { list.write(first) };
                0
            }
            // Nodes no one receives could never be freed.
            Ok(first) => {
                nodes::free_list(first);
                0
            }
            Err(nodes::FragmentError::Document(_)) => XML_ERR_DOCUMENT_END,
            Err(_) => XML_ERR_INTERNAL_ERROR,
        }
    })
}

/// `xmlReplaceNode`: put `current` in the place of `old`, unlinking both
/// first; returns `old`, unlinked, or null.
///
/// # Safety
/// Callable with any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsReplaceNode(old: *mut Node, current: *mut Node) -> *mut Node {
    contain(std::ptr::null_mut(), || {
        let Some((document, old_node, new_node)) = pair(old, current) else {
            return std::ptr::null_mut();
        };
        let done = handles::edit_document(document, |tree| {
            moved(tree, new_node, |tree| {
                tree.insert_before(old_node, new_node)
            })?;
            tree.unlink(old_node)
        });
        if done.is_ok() {
            old
        } else {
            std::ptr::null_mut()
        }
    })
}

/// `xmlNodeGetContent`: the character data of `node` (see
/// [`nodes::content`]); a copy the caller frees with `xsFree`, or null.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsNodeGetContent(node: *const Node) -> *mut XmlChar {
    contain(std::ptr::null_mut(), || give(nodes::content(node)))
}

/// `xmlNodeSetContent`: replace the content of `node` with `content`, as
/// character data; 0 on success, -1 when refused.
///
/// # Safety
/// `content` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsNodeSetContent(node: *mut Node, content: *const XmlChar) -> c_int {
    contain(-1, || {
        // SAFETY: null or NUL-terminated by the caller's contract.
        let Some(content) = (unsafe { text_or_empty(content) }) else {
            return -1;
        };
        status(&nodes::set_content(node, content))
    })
}

/// `xmlNodeAddContent`: append `content` to the content of `node`. Returns
/// 0 on success, -1 when refused, where libxml2 returns nothing.
///
/// # Safety
/// `content` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsNodeAddContent(node: *mut Node, content: *const XmlChar) -> c_int {
    contain(-1, || {
        // SAFETY: as documented.
        let Some(content) = (unsafe { text(content) }) else {
            return -1;
        };
        status(&nodes::add_content(node, content))
    })
}

/// `xmlGetProp`: the value of the attribute `name` of `node`; a copy the
/// caller frees with `xsFree`, or null.
///
/// # Safety
/// `name` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsGetProp(node: *const Node, name: *const XmlChar) -> *mut XmlChar {
    contain(std::ptr::null_mut(), || {
        // SAFETY: as documented.
        let Some(name) = (unsafe { text(name) }) else {
            return std::ptr::null_mut();
        };
        give(nodes::property(node, name))
    })
}

/// `xmlGetNsProp`: the value of the attribute `name` in `href` (null: no
/// namespace) of `node`; a copy the caller frees with `xsFree`, or null.
///
/// # Safety
/// `name` and `href` are null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsGetNsProp(
    node: *const Node,
    name: *const XmlChar,
    href: *const XmlChar,
) -> *mut XmlChar {
    contain(std::ptr::null_mut(), || {
        // SAFETY: as documented.
        let (Some(name), Ok(href)) = (unsafe { text(name) }, unsafe { optional(href) }) else {
            return std::ptr::null_mut();
        };
        give(nodes::namespaced_property(node, name, href))
    })
}

/// `xmlHasProp`: the attribute `name` of `node` in no namespace, or null.
///
/// # Safety
/// `name` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsHasProp(node: *const Node, name: *const XmlChar) -> *mut Attr {
    contain(std::ptr::null_mut(), || {
        // SAFETY: as documented.
        let Some(name) = (unsafe { text(name) }) else {
            return std::ptr::null_mut();
        };
        nodes::attribute(node, name, None)
    })
}

/// `xmlHasNsProp`: the attribute `name` in `href` (null: no namespace) of
/// `node`, or null.
///
/// # Safety
/// `name` and `href` are null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsHasNsProp(
    node: *const Node,
    name: *const XmlChar,
    href: *const XmlChar,
) -> *mut Attr {
    contain(std::ptr::null_mut(), || {
        // SAFETY: as documented.
        let (Some(name), Ok(href)) = (unsafe { text(name) }, unsafe { optional(href) }) else {
            return std::ptr::null_mut();
        };
        nodes::attribute(node, name, href)
    })
}

/// Set the attribute `name` in `namespace` with `prefix` of `node` and
/// return its handle.
fn set_property(
    node: *mut Node,
    name: &str,
    prefix: Option<&str>,
    namespace: Option<&str>,
    value: &str,
) -> *mut Attr {
    let Some((document, element)) = tree_node(node) else {
        return std::ptr::null_mut();
    };
    let set = handles::edit_document(document, |tree| {
        tree.set_attribute(element, name, prefix, namespace, value)
    });
    if set.is_err() {
        return std::ptr::null_mut();
    }
    nodes::attribute(node, name, namespace)
}

/// `xmlSetProp`: set the attribute `name` of `node` to `value`, adding it if
/// absent; a `prefix:local` name uses the declaration of `prefix` in scope.
///
/// # Safety
/// `name` and `value` are null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsSetProp(
    node: *mut Node,
    name: *const XmlChar,
    value: *const XmlChar,
) -> *mut Attr {
    contain(std::ptr::null_mut(), || {
        // SAFETY: null or NUL-terminated by the caller's contract.
        let name = unsafe { text(name) };
        // SAFETY: as above; null sets the empty value.
        let value = unsafe { text_or_empty(value) };
        let (Some(name), Some(value)) = (name, value) else {
            return std::ptr::null_mut();
        };
        match name.split_once(':') {
            Some((prefix, local)) => {
                let Some(uri) = nodes::in_scope(node, Some(prefix)) else {
                    return std::ptr::null_mut();
                };
                set_property(node, local, Some(prefix), Some(&uri), value)
            }
            None => set_property(node, name, None, None, value),
        }
    })
}

/// `xmlSetNsProp`: set the attribute `name` in the namespace of `ns` (null:
/// none) of `node` to `value`.
///
/// # Safety
/// `name` and `value` are null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsSetNsProp(
    node: *mut Node,
    ns: *mut Ns,
    name: *const XmlChar,
    value: *const XmlChar,
) -> *mut Attr {
    contain(std::ptr::null_mut(), || {
        // SAFETY: null or NUL-terminated by the caller's contract.
        let name = unsafe { text(name) };
        // SAFETY: as above; null sets the empty value.
        let value = unsafe { text_or_empty(value) };
        let (Some(name), Some(value)) = (name, value) else {
            return std::ptr::null_mut();
        };
        if ns.is_null() {
            return set_property(node, name, None, None, value);
        }
        match nodes::binding(ns) {
            Some((prefix, uri)) => set_property(node, name, prefix.as_deref(), Some(&uri), value),
            None => std::ptr::null_mut(),
        }
    })
}

/// `xmlUnsetProp`: remove the attribute `name` in no namespace of `node`;
/// 0 when removed, -1 otherwise.
///
/// # Safety
/// `name` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsUnsetProp(node: *mut Node, name: *const XmlChar) -> c_int {
    contain(-1, || {
        // SAFETY: as documented.
        let Some(name) = (unsafe { text(name) }) else {
            return -1;
        };
        match handles::edit(handle_of(node), |tree, node| {
            tree.remove_attribute(node, name, None)
        }) {
            Ok(true) => 0,
            _ => -1,
        }
    })
}

/// `xmlNewNs`: declare `prefix` (null: the default namespace) for `href` on
/// the element `node`; returns the declaration, or null when the element
/// already declares that prefix or `href` is null.
///
/// # Safety
/// `href` and `prefix` are null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsNewNs(
    node: *mut Node,
    href: *const XmlChar,
    prefix: *const XmlChar,
) -> *mut Ns {
    contain(std::ptr::null_mut(), || {
        // SAFETY: as documented.
        let (Some(href), Ok(prefix)) = (unsafe { text(href) }, unsafe { optional(prefix) }) else {
            return std::ptr::null_mut();
        };
        if prefix == Some("xml") {
            return std::ptr::null_mut();
        }
        let Some((document, element)) = tree_node(node) else {
            return std::ptr::null_mut();
        };
        let declared = handles::edit_document(document, |tree| {
            let exists = tree
                .namespace_declarations(element)?
                .any(|declaration| declaration.prefix == prefix);
            if exists {
                return Ok(false);
            }
            tree.declare_namespace(element, prefix, href)?;
            Ok(true)
        });
        match declared {
            Ok(true) => nodes::pointer(
                document,
                Target::Namespace {
                    element,
                    prefix: prefix.map(String::from),
                },
            ),
            _ => std::ptr::null_mut(),
        }
    })
}

/// `xmlSearchNs`: the declaration of `prefix` (null: the default namespace)
/// in scope at `node`; the document is accepted for the shape of the call.
///
/// # Safety
/// `prefix` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsSearchNs(
    _doc: *mut Doc,
    node: *mut Node,
    prefix: *const XmlChar,
) -> *mut Ns {
    contain(std::ptr::null_mut(), || {
        // SAFETY: as documented.
        match unsafe { optional(prefix) } {
            Ok(prefix) => nodes::search_namespace(node, prefix),
            Err(NotText) => std::ptr::null_mut(),
        }
    })
}

/// `xmlSearchNsByHref`: a declaration of `href` in scope at `node` whose
/// prefix is not redeclared below it.
///
/// # Safety
/// `href` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsSearchNsByHref(
    _doc: *mut Doc,
    node: *mut Node,
    href: *const XmlChar,
) -> *mut Ns {
    contain(std::ptr::null_mut(), || {
        // SAFETY: as documented.
        match unsafe { text(href) } {
            Some(href) => nodes::search_namespace_by_uri(node, href),
            None => std::ptr::null_mut(),
        }
    })
}

/// `xmlSetNs`: put the element `node` in the namespace of `ns`, or in none
/// for null; a value naming nothing live is ignored.
///
/// # Safety
/// Callable with any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsSetNs(node: *mut Node, ns: *mut Ns) {
    contain((), || {
        let (prefix, uri) = if ns.is_null() {
            (None, None)
        } else {
            match nodes::binding(ns) {
                Some((prefix, uri)) => (prefix, Some(uri)),
                None => return,
            }
        };
        if handles::edit(handle_of(node), |tree, node| {
            tree.set_element_namespace(node, prefix.as_deref(), uri.as_deref())
        })
        .is_err()
        {
            // As for `xsUnlinkNode`.
        }
    });
}

/// Register the attribute `attr` as carrying the ID `value` in `doc`; 0 on
/// success, -1 when refused, as for an ID another element holds. A later
/// change of the attribute moves or ends the registration. libxml2's
/// `xmlAddID` takes a validation context and returns the table entry; this
/// one needs neither.
///
/// # Safety
/// `value` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsAddID(doc: *mut Doc, value: *const XmlChar, attr: *mut Attr) -> c_int {
    contain(-1, || {
        // SAFETY: as documented.
        let Some(value) = (unsafe { text(value) }) else {
            return -1;
        };
        let Ok(Resolved {
            document,
            target:
                Target::Attribute {
                    element,
                    name,
                    namespace,
                },
        }) = handles::resolve(handle_of(attr))
        else {
            return -1;
        };
        if document_of(doc) != Some(document) {
            return -1;
        }
        status(&handles::edit_document(document, |tree| {
            tree.register_id(element, &name, namespace.as_deref(), value)
        }))
    })
}

/// The element registered for the ID `value` in `doc`, or null. libxml2's
/// `xmlGetID` returns the ID attribute; this one returns its element.
///
/// # Safety
/// `value` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsGetID(doc: *mut Doc, value: *const XmlChar) -> *mut Node {
    contain(std::ptr::null_mut(), || {
        // SAFETY: as documented.
        match unsafe { text(value) } {
            Some(value) => nodes::element_by_id(doc, value),
            None => std::ptr::null_mut(),
        }
    })
}

/// `xmlXPathNodeSetCreate`: a new node set holding `node`, or empty for
/// null; released with [`xsXPathFreeNodeSet`].
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsXPathNodeSetCreate(node: *mut Node) -> *mut NodeSet {
    contain(std::ptr::null_mut(), || nodes::node_set(node))
}

/// `xmlXPathNodeSetAdd`: add `node` to `set` unless it is listed; 0 on
/// success, -1 when refused.
///
/// # Safety
/// Callable with any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsXPathNodeSetAdd(set: *mut NodeSet, node: *mut Node) -> c_int {
    contain(-1, || status(&nodes::node_set_add(set, node)))
}

/// `xmlXPathNodeSetAddNs`: add the namespace node of `element` for the
/// binding `ns` declares to `set`; 0 on success, -1 when refused.
///
/// # Safety
/// Callable with any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsXPathNodeSetAddNs(
    set: *mut NodeSet,
    element: *mut Node,
    ns: *mut Ns,
) -> c_int {
    contain(-1, || {
        let Some((prefix, _)) = nodes::binding(ns) else {
            return -1;
        };
        status(&nodes::node_set_add(
            set,
            nodes::namespace_node(element, prefix.as_deref()),
        ))
    })
}

/// `xmlXPathNodeSetContains`: 1 when `set` lists `node`, else 0.
///
/// # Safety
/// Callable with any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsXPathNodeSetContains(set: *const NodeSet, node: *const Node) -> c_int {
    contain(0, || c_int::from(nodes::node_set_contains(set, node)))
}

/// `xmlXPathNodeSetGetLength`: the number of nodes `set` lists; 0 for null.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsXPathNodeSetGetLength(set: *const NodeSet) -> c_int {
    contain(0, || {
        handles::set_member(handle_of(set), 0)
            .ok()
            .and_then(|(length, _)| c_int::try_from(length).ok())
            .unwrap_or(0)
    })
}

/// `xmlXPathNodeSetItem`: the node at `index` of `set`, or null.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsXPathNodeSetItem(set: *const NodeSet, index: c_int) -> *mut Node {
    contain(std::ptr::null_mut(), || {
        usize::try_from(index)
            .ok()
            .and_then(|index| handles::set_member(handle_of(set), index).ok())
            .and_then(|(_, member)| member)
            .map_or(std::ptr::null_mut(), pointer_of)
    })
}

/// `xmlXPathFreeNodeSet`: free `set`; its nodes stay.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsXPathFreeNodeSet(set: *mut NodeSet) {
    contain((), || nodes::node_set_free(set));
}

/// `xmlXPathCmpNodes`: 1 when `left` precedes `right` in document order, -1
/// when it follows, 0 for the same node, -2 when they cannot be ordered.
///
/// # Safety
/// Callable with any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsXPathCmpNodes(left: *const Node, right: *const Node) -> c_int {
    contain(-2, || match nodes::compare_order(left, right) {
        Some(std::cmp::Ordering::Less) => 1,
        Some(std::cmp::Ordering::Greater) => -1,
        Some(std::cmp::Ordering::Equal) => 0,
        None => -2,
    })
}

#[cfg(test)]
mod tests;
