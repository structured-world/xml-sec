//! The document tree as the library's C surface sees it: our own operations
//! shaped like libxml2's tree interface, over the opaque handles of
//! [`crate::handles`].
//!
//! A tree pointer (`xmlDocPtr`, `xmlNodePtr`, `xmlNsPtr`, `xmlAttrPtr`,
//! `xmlNodeSetPtr`) is a handle value, never an address: every function here
//! validates it and answers null, zero or `None` for one that names nothing
//! live, so these functions are safe to call with any value. A document's
//! pointer is its document node's, and an attribute or a namespace node is
//! also a node pointer, as in libxml2's `XPath` node sets.

use std::cmp::Ordering;
use std::ffi::c_int;

use xml_sec::document::owned_tree::{OwnedTree, TreeError, TreeNode, TreeNodeKind};

use crate::handles::{self, HandleError, Resolved, Target, XML_NAMESPACE};

/// libxml2's `xmlChar`.
pub type XmlChar = u8;

/// An `xmlDoc`: never dereferenced, a handle only.
pub enum Doc {}
/// An `xmlNode`: never dereferenced, a handle only.
pub enum Node {}
/// An `xmlNs`: never dereferenced, a handle only.
pub enum Ns {}
/// An `xmlAttr`: never dereferenced, a handle only.
pub enum Attr {}
/// An `xmlNodeSet`: never dereferenced, a handle only.
pub enum NodeSet {}

// libxml2's `xmlElementType` values, part of its interface.
/// An element.
pub const XML_ELEMENT_NODE: c_int = 1;
/// An attribute.
pub const XML_ATTRIBUTE_NODE: c_int = 2;
/// A text node.
pub const XML_TEXT_NODE: c_int = 3;
/// A CDATA section.
pub const XML_CDATA_SECTION_NODE: c_int = 4;
/// An entity reference.
pub const XML_ENTITY_REF_NODE: c_int = 5;
/// A processing instruction.
pub const XML_PI_NODE: c_int = 7;
/// A comment.
pub const XML_COMMENT_NODE: c_int = 8;
/// The document.
pub const XML_DOCUMENT_NODE: c_int = 9;
/// A document type declaration.
pub const XML_DTD_NODE: c_int = 14;
/// A namespace declaration or namespace node.
pub const XML_NAMESPACE_DECL: c_int = 18;

/// The handle a pointer carries.
#[must_use]
pub fn handle_of<T>(pointer: *const T) -> usize {
    pointer.addr()
}

/// The pointer that carries `handle`; it has no provenance and is never
/// dereferenced.
#[must_use]
pub const fn pointer_of<T>(handle: usize) -> *mut T {
    std::ptr::without_provenance_mut(handle)
}

fn or_null<T>(handle: Result<usize, HandleError>) -> *mut T {
    handle.map_or(std::ptr::null_mut(), pointer_of)
}

/// The pointer of `target` in `document`, or null when it does not exist.
#[must_use]
pub fn pointer<T>(document: usize, target: Target) -> *mut T {
    or_null(handles::handle(document, target))
}

/// The pointer of the node `node` of `document`, or null.
#[must_use]
pub fn node_pointer(document: usize, node: TreeNode) -> *mut Node {
    pointer(document, Target::Node(node))
}

/// The document a pointer of any tree kind belongs to.
#[must_use]
pub fn document_of<T>(pointer: *const T) -> Option<usize> {
    handles::document(handle_of(pointer)).ok()
}

/// The document and tree node `node` names, if it names a node.
#[must_use]
pub fn tree_node(node: *const Node) -> Option<(usize, TreeNode)> {
    handles::node(handle_of(node)).ok()
}

fn kind_code(kind: TreeNodeKind) -> c_int {
    match kind {
        TreeNodeKind::Document => XML_DOCUMENT_NODE,
        TreeNodeKind::Element => XML_ELEMENT_NODE,
        TreeNodeKind::Text => XML_TEXT_NODE,
        TreeNodeKind::CData => XML_CDATA_SECTION_NODE,
        TreeNodeKind::Comment => XML_COMMENT_NODE,
        TreeNodeKind::ProcessingInstruction => XML_PI_NODE,
        TreeNodeKind::EntityReference => XML_ENTITY_REF_NODE,
        TreeNodeKind::DocumentType => XML_DTD_NODE,
    }
}

/// The libxml2 type of what `node` names, as `node->type`; 0 for nothing.
#[must_use]
pub fn kind<T>(node: *const T) -> c_int {
    match handles::resolve(handle_of(node)) {
        Ok(Resolved {
            document,
            target: Target::Node(node),
        }) => handles::read_document(document, |tree| tree.kind(node))
            .ok()
            .and_then(Result::ok)
            .map_or(0, kind_code),
        Ok(Resolved {
            target: Target::Attribute { .. },
            ..
        }) => XML_ATTRIBUTE_NODE,
        Ok(_) => XML_NAMESPACE_DECL,
        Err(_) => 0,
    }
}

/// Whether `node` names an element.
#[must_use]
pub fn is_element<T>(node: *const T) -> bool {
    kind(node) == XML_ELEMENT_NODE
}

/// The document `node` belongs to, as `node->doc`.
#[must_use]
pub fn doc<T>(node: *const T) -> *mut Doc {
    or_null(handles::document(handle_of(node)).and_then(handles::document_handle))
}

/// The document element of `doc`.
#[must_use]
pub fn root_element(doc: *const Doc) -> *mut Node {
    let Some(document) = document_of(doc) else {
        return std::ptr::null_mut();
    };
    match handles::read_document(document, OwnedTree::root_element) {
        Ok(Some(root)) => node_pointer(document, root),
        _ => std::ptr::null_mut(),
    }
}

/// The node `node` links to by `select`.
fn neighbour(
    node: *const Node,
    select: fn(&OwnedTree, TreeNode) -> Result<Option<TreeNode>, TreeError>,
) -> *mut Node {
    let Some((document, node)) = tree_node(node) else {
        return std::ptr::null_mut();
    };
    match handles::read_document(document, |tree| select(tree, node)) {
        Ok(Ok(Some(found))) => node_pointer(document, found),
        _ => std::ptr::null_mut(),
    }
}

/// The parent of `node`, as `node->parent`; an attribute's or namespace
/// node's element. A namespace declaration has none.
#[must_use]
pub fn parent<T>(node: *const T) -> *mut Node {
    match handles::resolve(handle_of(node)) {
        Ok(Resolved {
            document,
            target: Target::Node(node),
        }) => match handles::read_document(document, |tree| tree.parent(node)) {
            Ok(Ok(Some(parent))) => node_pointer(document, parent),
            _ => std::ptr::null_mut(),
        },
        Ok(Resolved {
            document,
            target: Target::Attribute { element, .. } | Target::NamespaceNode { element, .. },
        }) => node_pointer(document, element),
        _ => std::ptr::null_mut(),
    }
}

/// The first child of `node`, as `node->children`.
#[must_use]
pub fn first_child<T>(node: *const T) -> *mut Node {
    neighbour(node.cast(), OwnedTree::first_child)
}

/// The last child of `node`, as `node->last`.
#[must_use]
pub fn last_child<T>(node: *const T) -> *mut Node {
    neighbour(node.cast(), OwnedTree::last_child)
}

/// The next sibling of `node`, as `node->next`.
#[must_use]
pub fn next(node: *const Node) -> *mut Node {
    neighbour(node, OwnedTree::next_sibling)
}

/// The previous sibling of `node`, as `node->prev`.
#[must_use]
pub fn prev(node: *const Node) -> *mut Node {
    neighbour(node, OwnedTree::previous_sibling)
}

/// The name of `node`, as `node->name`: an element's or attribute's local
/// name, a processing instruction's target, and `text`, `cdata` or
/// `comment` as libxml2 names those nodes; a namespace's prefix.
#[must_use]
pub fn name<T>(node: *const T) -> Option<String> {
    match handles::resolve(handle_of(node)).ok()? {
        Resolved {
            document,
            target: Target::Node(node),
        } => handles::read_document(document, |tree| match tree.kind(node) {
            Ok(TreeNodeKind::Text) => Some(String::from("text")),
            Ok(TreeNodeKind::CData) => Some(String::from("cdata")),
            Ok(TreeNodeKind::Comment) => Some(String::from("comment")),
            _ => tree.name(node).ok().flatten().map(String::from),
        })
        .ok()
        .flatten(),
        Resolved {
            target: Target::Attribute { name, .. },
            ..
        } => Some(name),
        Resolved {
            target: Target::Namespace { prefix, .. } | Target::NamespaceNode { prefix, .. },
            ..
        } => prefix,
        Resolved {
            target: Target::XmlNamespace,
            ..
        } => Some(String::from("xml")),
    }
}

/// The namespace URI of an element or attribute, as `node->ns->href`.
#[must_use]
pub fn namespace<T>(node: *const T) -> Option<String> {
    match handles::resolve(handle_of(node)).ok()? {
        Resolved {
            document,
            target: Target::Node(node),
        } => handles::read_document(document, |tree| {
            tree.namespace(node).ok().flatten().map(String::from)
        })
        .ok()
        .flatten(),
        Resolved {
            target: Target::Attribute { namespace, .. },
            ..
        } => namespace,
        _ => None,
    }
}

/// The prefix of an element or attribute, as `node->ns->prefix`.
#[must_use]
pub fn prefix<T>(node: *const T) -> Option<String> {
    match handles::resolve(handle_of(node)).ok()? {
        Resolved {
            document,
            target: Target::Node(node),
        } => handles::read_document(document, |tree| {
            tree.prefix(node).ok().flatten().map(String::from)
        })
        .ok()
        .flatten(),
        Resolved {
            document,
            target:
                Target::Attribute {
                    element,
                    name,
                    namespace,
                },
        } => handles::read_document(document, |tree| {
            tree.attributes(element).ok().and_then(|mut attributes| {
                attributes
                    .find(|attribute| {
                        attribute.local_name == name && attribute.namespace == namespace.as_deref()
                    })
                    .and_then(|attribute| attribute.prefix.map(String::from))
            })
        })
        .ok()
        .flatten(),
        _ => None,
    }
}

/// A namespace URI of the element or attribute `node` that lives as long as
/// its document, for a function whose contract returns a pointer into the
/// tree (`node->ns->href`); null for none.
#[must_use]
pub fn namespace_in_tree<T>(node: *const T) -> *const XmlChar {
    match (namespace(node), document_of(node)) {
        (Some(uri), Some(document)) => handles::intern(document, &uri),
        _ => std::ptr::null(),
    }
}

/// The character data `node` holds as `node->content`: a text, CDATA or
/// comment node's text, a processing instruction's value.
#[must_use]
pub fn text<T>(node: *const T) -> Option<String> {
    let (document, node) = tree_node(node.cast())?;
    handles::read_document(document, |tree| {
        tree.text(node).ok().flatten().map(String::from)
    })
    .ok()
    .flatten()
}

/// `xmlNodeGetContent`: the character data of an element or document and
/// its descendants, a leaf's text, an attribute's value or a namespace's
/// URI.
#[must_use]
pub fn content<T>(node: *const T) -> Option<String> {
    match handles::resolve(handle_of(node)).ok()? {
        Resolved {
            document,
            target: Target::Node(node),
        } => handles::read_document(document, |tree| match tree.kind(node) {
            Ok(TreeNodeKind::Element | TreeNodeKind::Document) => tree.text_content(node).ok(),
            _ => tree.text(node).ok().flatten().map(String::from),
        })
        .ok()
        .flatten(),
        Resolved {
            document,
            target:
                Target::Attribute {
                    element,
                    name,
                    namespace,
                },
        } => handles::read_document(document, |tree| {
            tree.attribute(element, &name, namespace.as_deref())
                .ok()
                .flatten()
                .map(String::from)
        })
        .ok()
        .flatten(),
        Resolved { document, target } => binding_in(document, &target).map(|(_, uri)| uri),
    }
}

/// The attributes of the element `node`, in document order.
#[must_use]
pub fn attributes<T>(node: *const T) -> Vec<*mut Attr> {
    let Some((document, element)) = tree_node(node.cast()) else {
        return Vec::new();
    };
    let targets: Vec<Target> = handles::read_document(document, |tree| {
        tree.attributes(element)
            .map(|attributes| {
                attributes
                    .map(|attribute| Target::Attribute {
                        element,
                        name: String::from(attribute.local_name),
                        namespace: attribute.namespace.map(String::from),
                    })
                    .collect()
            })
            .unwrap_or_default()
    })
    .unwrap_or_default();
    targets
        .into_iter()
        .map(|target| pointer(document, target))
        .collect()
}

/// The namespace declarations of the element `node`, as `node->nsDef`.
#[must_use]
pub fn declarations<T>(node: *const T) -> Vec<*mut Ns> {
    let Some((document, element)) = tree_node(node.cast()) else {
        return Vec::new();
    };
    let prefixes: Vec<Option<String>> = handles::read_document(document, |tree| {
        tree.namespace_declarations(element)
            .map(|declarations| {
                declarations
                    .map(|declaration| declaration.prefix.map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    })
    .unwrap_or_default();
    prefixes
        .into_iter()
        .map(|prefix| pointer(document, Target::Namespace { element, prefix }))
        .collect()
}

/// The value of the attribute `name` of `node`: the one in no namespace,
/// else the first of that local name, as libxml2's `xmlGetProp` finds it.
#[must_use]
pub fn property<T>(node: *const T, name: &str) -> Option<String> {
    let (document, element) = tree_node(node.cast())?;
    handles::read_document(document, |tree| {
        let mut fallback = None;
        for attribute in tree.attributes(element).ok()? {
            if attribute.local_name == name {
                if attribute.namespace.is_none() {
                    return Some(String::from(attribute.value));
                }
                fallback.get_or_insert_with(|| String::from(attribute.value));
            }
        }
        fallback
    })
    .ok()
    .flatten()
}

/// `xmlGetNsProp`: the value of the attribute `name` in `namespace` (`None`:
/// no namespace) of `node`.
#[must_use]
pub fn namespaced_property<T>(
    node: *const T,
    name: &str,
    namespace: Option<&str>,
) -> Option<String> {
    let (document, element) = tree_node(node.cast())?;
    handles::read_document(document, |tree| {
        tree.attribute(element, name, namespace)
            .ok()
            .flatten()
            .map(String::from)
    })
    .ok()
    .flatten()
}

/// `xmlHasNsProp`: the attribute `name` in `namespace` of `node`, or null.
#[must_use]
pub fn attribute<T>(node: *const T, name: &str, namespace: Option<&str>) -> *mut Attr {
    let Some((document, element)) = tree_node(node.cast()) else {
        return std::ptr::null_mut();
    };
    pointer(
        document,
        Target::Attribute {
            element,
            name: String::from(name),
            namespace: namespace.map(String::from),
        },
    )
}

/// The prefix and URI a namespace target binds.
fn binding_in(document: usize, target: &Target) -> Option<(Option<String>, String)> {
    match target {
        Target::XmlNamespace => Some((Some(String::from("xml")), String::from(XML_NAMESPACE))),
        Target::Namespace { element, prefix } => handles::read_document(document, |tree| {
            tree.namespace_declarations(*element)
                .ok()?
                .find(|declaration| declaration.prefix == prefix.as_deref())
                .map(|declaration| (prefix.clone(), String::from(declaration.uri)))
        })
        .ok()
        .flatten(),
        Target::NamespaceNode { element, prefix } => handles::read_document(document, |tree| {
            handles::in_scope(tree, *element, prefix.as_deref())
                .map(|uri| (prefix.clone(), String::from(uri)))
        })
        .ok()
        .flatten(),
        _ => None,
    }
}

/// The prefix and URI of the namespace declaration or node `ns` names.
#[must_use]
pub fn binding<T>(ns: *const T) -> Option<(Option<String>, String)> {
    let Resolved { document, target } = handles::resolve(handle_of(ns)).ok()?;
    binding_in(document, &target)
}

/// The URI `prefix` (`None`: the default namespace) is bound to at `node`.
#[must_use]
pub fn in_scope<T>(node: *const T, prefix: Option<&str>) -> Option<String> {
    let (document, element) = tree_node(node.cast())?;
    handles::read_document(document, |tree| {
        handles::in_scope(tree, element, prefix).map(String::from)
    })
    .ok()
    .flatten()
}

/// The nearest element at or above `node` declaring a binding `wanted`
/// accepts: its document, the element and the declared prefix.
fn declaring(
    node: *const Node,
    wanted: impl Fn(Option<&str>, &str) -> bool,
) -> Option<(usize, TreeNode, Option<String>)> {
    let (document, start) = tree_node(node)?;
    handles::read_document(document, |tree| {
        let mut current = Some(start);
        while let Some(element) = current {
            if let Ok(mut declarations) = tree.namespace_declarations(element)
                && let Some(found) =
                    declarations.find(|declaration| wanted(declaration.prefix, declaration.uri))
            {
                return Some((document, element, found.prefix.map(String::from)));
            }
            current = tree.parent(element).ok().flatten();
        }
        None
    })
    .ok()
    .flatten()
}

fn declaration_pointer(found: Option<(usize, TreeNode, Option<String>)>) -> *mut Ns {
    match found {
        Some((document, element, prefix)) => {
            pointer(document, Target::Namespace { element, prefix })
        }
        None => std::ptr::null_mut(),
    }
}

/// `xmlSearchNs`: the declaration of `prefix` (`None`: the default
/// namespace) in scope at `node`.
#[must_use]
pub fn search_namespace<T>(node: *const T, prefix: Option<&str>) -> *mut Ns {
    if prefix == Some("xml") {
        return document_of(node).map_or(std::ptr::null_mut(), |document| {
            pointer(document, Target::XmlNamespace)
        });
    }
    declaration_pointer(declaring(node.cast(), |declared, _| declared == prefix))
}

/// `xmlSearchNsByHref`: a declaration of `href` in scope at `node` whose
/// prefix is not redeclared below it.
#[must_use]
pub fn search_namespace_by_uri<T>(node: *const T, href: &str) -> *mut Ns {
    if href == XML_NAMESPACE {
        return document_of(node).map_or(std::ptr::null_mut(), |document| {
            pointer(document, Target::XmlNamespace)
        });
    }
    let found = declaring(node.cast(), |_, uri| uri == href);
    match &found {
        Some((_, _, prefix)) if in_scope(node, prefix.as_deref()).as_deref() != Some(href) => {
            std::ptr::null_mut()
        }
        _ => declaration_pointer(found),
    }
}

/// The namespace node of the element `element` for `prefix`, as libxml2's
/// `XPath` represents the binding in scope there.
#[must_use]
pub fn namespace_node<T>(element: *const T, prefix: Option<&str>) -> *mut Node {
    let Some((document, element)) = tree_node(element.cast()) else {
        return std::ptr::null_mut();
    };
    pointer(
        document,
        Target::NamespaceNode {
            element,
            prefix: prefix.map(String::from),
        },
    )
}

/// The namespace nodes of the element `element`: one per binding in scope
/// there, the nearest declaration of each prefix, the `xml` binding last.
#[must_use]
pub fn namespace_nodes<T>(element: *const T) -> Vec<*mut Node> {
    let Some((document, start)) = tree_node(element.cast()) else {
        return Vec::new();
    };
    let prefixes: Vec<Option<String>> = handles::read_document(document, |tree| {
        let mut seen: Vec<Option<String>> = Vec::new();
        let mut current = Some(start);
        while let Some(element) = current {
            if let Ok(declarations) = tree.namespace_declarations(element) {
                for declaration in declarations {
                    let prefix = declaration.prefix.map(String::from);
                    if !seen.contains(&prefix) {
                        seen.push(prefix);
                    }
                }
            }
            current = tree.parent(element).ok().flatten();
        }
        seen.push(Some(String::from("xml")));
        seen
    })
    .unwrap_or_default();
    prefixes
        .into_iter()
        .map(|prefix| {
            pointer(
                document,
                Target::NamespaceNode {
                    element: start,
                    prefix,
                },
            )
        })
        .filter(|node: &*mut Node| !node.is_null())
        .collect()
}

/// The element registered for the ID `value` in `doc`, or null.
#[must_use]
pub fn element_by_id(doc: *const Doc, value: &str) -> *mut Node {
    let Some(document) = document_of(doc) else {
        return std::ptr::null_mut();
    };
    match handles::read_document(document, |tree| tree.element_by_id(value)) {
        Ok(Some(element)) => node_pointer(document, element),
        _ => std::ptr::null_mut(),
    }
}

/// Replace the content of `node` with `content` as character data.
///
/// # Errors
/// The handle's or the tree's refusal.
pub fn set_content(node: *mut Node, content: &str) -> Result<(), HandleError> {
    handles::edit(handle_of(node), |tree, node| tree.set_text(node, content))
}

/// `xmlNodeAddContent`: append `content` to a text node's data, or as a new
/// last text child of an element.
///
/// # Errors
/// The handle's or the tree's refusal.
pub fn add_content(node: *mut Node, content: &str) -> Result<(), HandleError> {
    handles::edit(handle_of(node), |tree, node| {
        if tree.kind(node)? == TreeNodeKind::Element {
            let added = tree.create_text(content)?;
            tree.append_child(node, added)
        } else {
            let joined = format!("{}{content}", tree.text(node)?.unwrap_or_default());
            tree.set_text(node, &joined)
        }
    })
}

/// The ancestors of `node` from the document node down to `node`.
fn path(tree: &OwnedTree, node: TreeNode) -> Vec<TreeNode> {
    let mut path = vec![node];
    let mut current = node;
    while let Ok(Some(parent)) = tree.parent(current) {
        path.push(parent);
        current = parent;
    }
    path.reverse();
    path
}

/// The document order of two nodes of one document; `None` for nodes of
/// different documents, attribute or namespace nodes, or nodes in unlinked
/// subtrees of different roots.
#[must_use]
pub fn compare_order(left: *const Node, right: *const Node) -> Option<Ordering> {
    let (document, left) = tree_node(left)?;
    let (other, right) = tree_node(right)?;
    if document != other {
        return None;
    }
    handles::read_document(document, |tree| {
        let (left_path, right_path) = (path(tree, left), path(tree, right));
        if left_path.first() != right_path.first() {
            return None;
        }
        let shared = left_path
            .iter()
            .zip(&right_path)
            .take_while(|(left, right)| left == right)
            .count();
        let (Some(&left_step), Some(&right_step)) = (left_path.get(shared), right_path.get(shared))
        else {
            // One node is an ancestor of the other, which precedes it.
            return Some(left_path.len().cmp(&right_path.len()));
        };
        let mut sibling = tree.next_sibling(left_step).ok().flatten();
        while let Some(current) = sibling {
            if current == right_step {
                return Some(Ordering::Less);
            }
            sibling = tree.next_sibling(current).ok().flatten();
        }
        Some(Ordering::Greater)
    })
    .ok()
    .flatten()
}

/// `xmlXPathNodeSetCreate`: a new node set holding `node`, or empty for
/// null; null when `node` names nothing live.
#[must_use]
pub fn node_set<T>(node: *const T) -> *mut NodeSet {
    let Ok(set) = handles::set_create() else {
        return std::ptr::null_mut();
    };
    if !node.is_null() && handles::set_add(set, handle_of(node)).is_err() {
        handles::set_free(set);
        return std::ptr::null_mut();
    }
    pointer_of(set)
}

/// `xmlXPathNodeSetAdd`: add `node` to `set`; a node already listed is not
/// added again.
///
/// # Errors
/// [`HandleError::Stale`] for a set or node that is not live.
pub fn node_set_add<T>(set: *mut NodeSet, node: *const T) -> Result<(), HandleError> {
    handles::set_add(handle_of(set), handle_of(node))
}

/// `xmlXPathNodeSetContains`: whether `set` lists `node`.
#[must_use]
pub fn node_set_contains<T>(set: *const NodeSet, node: *const T) -> bool {
    handles::set_contains(handle_of(set), handle_of(node))
}

/// The members of `set` in the order they were added; empty for a set that
/// is not live.
#[must_use]
pub fn node_set_members(set: *const NodeSet) -> Vec<*mut Node> {
    handles::set_members(handle_of(set))
        .unwrap_or_default()
        .into_iter()
        .map(pointer_of)
        .collect()
}

/// `xmlXPathFreeNodeSet`: free `set`; its nodes stay.
pub fn node_set_free(set: *mut NodeSet) {
    handles::set_free(handle_of(set));
}
