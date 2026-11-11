//! The handle table: the opaque `xmlDocPtr`, `xmlNodePtr`, `xmlNsPtr` and
//! `xmlAttrPtr` values the C surface hands out, and the documents they name.
//!
//! A document is a core [`OwnedTree`] kept in a slot of the table. A handle is
//! a number from a counter that never repeats, so a pointer value C code holds
//! names one thing of one document for as long as both exist, and nothing
//! afterwards: a freed node, a removed declaration or attribute, a freed
//! document or a forged value is refused on lookup. No handle is an address;
//! C code never reaches the tree's memory. One thing always yields the same
//! handle, so C code may compare pointers.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
use xml_sec::document::owned_tree::{OwnedTree, TreeError, TreeNode, TreeNodeKind};

/// What a handle names within its document.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Target {
    /// A node; the document node stands for the document.
    Node(TreeNode),
    /// The declaration of `prefix` (`None`: the default namespace) on
    /// `element`; the implicit `xml` binding is its own target.
    Namespace {
        /// The declaring element.
        element: TreeNode,
        /// The declared prefix.
        prefix: Option<String>,
    },
    /// The attribute of `element` named `name` in `namespace`.
    Attribute {
        /// The element.
        element: TreeNode,
        /// Its local name.
        name: String,
        /// Its namespace URI, if any.
        namespace: Option<String>,
    },
    /// The `xml` prefix every element binds (Namespaces in XML 1.0 section 3).
    XmlNamespace,
    /// The namespace node of `element` for `prefix` (`None`: the default
    /// namespace): one per binding in scope at the element (`XPath` 1.0
    /// section 5.4), whichever element declares it.
    NamespaceNode {
        /// The element the node belongs to.
        element: TreeNode,
        /// The bound prefix.
        prefix: Option<String>,
    },
}

/// A handle's document and target.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Resolved {
    /// The document's slot.
    pub document: usize,
    /// What the handle names in it.
    pub target: Target,
}

/// A refused lookup or document operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HandleError {
    /// The value names nothing live.
    #[error("the handle names nothing live")]
    Stale,
    /// The handle names something of another kind than the call needs.
    #[error("the handle names a different kind of object")]
    WrongKind,
    /// The document is lent to a running operation.
    #[error("the document is in use by an operation")]
    Busy,
    /// The tree refused the operation.
    #[error(transparent)]
    Tree(#[from] TreeError),
}

/// One document: its tree and the strings handed out of it. Each document
/// has its own lock, so reading or changing one does not hold up the others.
struct Slot {
    /// `None` while an operation holds the tree.
    tree: Option<OwnedTree>,
    /// Read-only copies of strings handed to C code that does not own them
    /// (libxmlsec1 functions returning `const xmlChar *`), kept until the
    /// document is freed. A `CString`'s bytes stay where they are when the
    /// map moves it, so a returned pointer stays valid.
    strings: HashMap<String, std::ffi::CString>,
}

/// A document shared between the table and the calls working on it: a call
/// takes its own reference, leaves the table's lock and then locks the
/// document, so the two locks are never held together.
type Shared = Arc<RwLock<Slot>>;

/// The handles issued into one document.
#[derive(Default)]
struct Issued {
    /// Every handle into the document.
    all: HashSet<usize>,
    /// The handles whose target is named by element and name (attributes,
    /// declarations, namespace nodes): an edit can remove such a target and
    /// add another under the same name, so an edit drops the handles of the
    /// removed ones at once. A node's number is never reused, so a node
    /// handle is refused once its node is freed without that.
    named: HashSet<usize>,
}

#[derive(Default)]
struct Table {
    /// Documents by a number from the handle counter, never reused: a slot
    /// number kept past its document's end never names a later document.
    slots: HashMap<usize, (Shared, Issued)>,
    handles: HashMap<usize, Resolved>,
    reverse: HashMap<Resolved, usize>,
    /// Node sets, under handles from the same counter.
    sets: HashMap<usize, Set>,
    /// The last handle issued; zero is never one.
    issued: usize,
}

static TABLE: Mutex<Option<Table>> = Mutex::new(None);

fn with_table<R>(work: impl FnOnce(&mut Table) -> R) -> R {
    let mut guard = TABLE.lock();
    work(guard.get_or_insert_with(Table::default))
}

/// The document numbered `document`, taken out of the table's lock.
fn slot(document: usize) -> Result<Shared, HandleError> {
    with_table(|table| {
        table
            .slots
            .get(&document)
            .map(|(slot, _)| Arc::clone(slot))
            .ok_or(HandleError::Stale)
    })
}

/// Whether `target` still exists in `tree`.
fn exists(tree: &OwnedTree, target: &Target) -> bool {
    match target {
        Target::Node(node) => tree.contains(*node),
        Target::XmlNamespace => true,
        Target::Namespace { element, prefix } => {
            tree.namespace_declarations(*element)
                .is_ok_and(|mut declarations| {
                    declarations.any(|declaration| declaration.prefix == prefix.as_deref())
                })
        }
        Target::Attribute {
            element,
            name,
            namespace,
        } => tree
            .attribute(*element, name, namespace.as_deref())
            .is_ok_and(|value| value.is_some()),
        Target::NamespaceNode { element, prefix } => {
            tree.kind(*element) == Ok(TreeNodeKind::Element)
                && in_scope(tree, *element, prefix.as_deref()).is_some_and(|uri| !uri.is_empty())
        }
    }
}

/// The namespace URI `prefix` (`None`: the default namespace) is bound to at
/// `node`, from the nearest declaration at or above it; the `xml` prefix is
/// always bound (Namespaces in XML 1.0 section 3). An empty URI undeclares
/// the default namespace.
#[must_use]
pub fn in_scope<'a>(tree: &'a OwnedTree, node: TreeNode, prefix: Option<&str>) -> Option<&'a str> {
    if prefix == Some("xml") {
        return Some(XML_NAMESPACE);
    }
    let mut current = Some(node);
    while let Some(element) = current {
        if let Ok(mut declarations) = tree.namespace_declarations(element)
            && let Some(found) = declarations.find(|declaration| declaration.prefix == prefix)
        {
            return Some(found.uri);
        }
        current = tree.parent(element).ok().flatten();
    }
    None
}

/// The namespace the `xml` prefix is bound to (Namespaces in XML 1.0
/// section 3).
pub const XML_NAMESPACE: &str = "http://www.w3.org/XML/1998/namespace";

/// A node set: distinct handles in insertion order, as libxml2's
/// `xmlNodeSet` keeps them.
#[derive(Default)]
struct Set {
    members: Vec<usize>,
    index: HashSet<usize>,
}

impl Table {
    /// A value never issued before.
    fn fresh(&mut self) -> Result<usize, HandleError> {
        // A counter that wraps would give an old value a new meaning; a
        // process issuing `usize::MAX` handles is refused instead.
        let handle = self.issued.checked_add(1).ok_or(HandleError::Stale)?;
        self.issued = handle;
        Ok(handle)
    }

    fn issue(&mut self, resolved: Resolved) -> Result<usize, HandleError> {
        if let Some(&handle) = self.reverse.get(&resolved) {
            return Ok(handle);
        }
        // A value the counter skips for a missing document is never issued.
        let handle = self.fresh()?;
        let (_, issued) = self
            .slots
            .get_mut(&resolved.document)
            .ok_or(HandleError::Stale)?;
        issued.all.insert(handle);
        if !matches!(resolved.target, Target::Node(_)) {
            issued.named.insert(handle);
        }
        self.handles.insert(handle, resolved.clone());
        self.reverse.insert(resolved, handle);
        Ok(handle)
    }

    fn forget(&mut self, handle: usize) {
        if let Some(resolved) = self.handles.remove(&handle) {
            if let Some((_, issued)) = self.slots.get_mut(&resolved.document) {
                issued.all.remove(&handle);
                issued.named.remove(&handle);
            }
            self.reverse.remove(&resolved);
        }
    }

    /// The name-keyed handles of `document` with their targets.
    fn named(&self, document: usize) -> Vec<(usize, Target)> {
        self.slots
            .get(&document)
            .map(|(_, issued)| {
                issued
                    .named
                    .iter()
                    .filter_map(|handle| {
                        self.handles
                            .get(handle)
                            .map(|resolved| (*handle, resolved.target.clone()))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Drop the handles of `document` named by element and name whose target no
/// longer exists; only that document's are visited.
fn prune(document: usize, slot: &Shared) {
    let named = with_table(|table| table.named(document));
    if named.is_empty() {
        return;
    }
    let dead: Vec<usize> = {
        let guard = slot.read();
        let Some(tree) = guard.tree.as_ref() else {
            return;
        };
        named
            .into_iter()
            .filter(|(_, target)| !exists(tree, target))
            .map(|(handle, _)| handle)
            .collect()
    };
    with_table(|table| {
        for handle in dead {
            table.forget(handle);
        }
    });
}

/// Run `work` on the tree of `document` for writing, then drop the handles
/// of what it removed.
fn write_document<R>(
    document: usize,
    work: impl FnOnce(&mut OwnedTree) -> R,
) -> Result<R, HandleError> {
    let slot = slot(document)?;
    let result = {
        let mut guard = slot.write();
        work(guard.tree.as_mut().ok_or(HandleError::Busy)?)
    };
    prune(document, &slot);
    Ok(result)
}

/// Register `tree` as a new document; its handle names the document node.
///
/// # Errors
/// [`HandleError::Stale`] when the handle counter is exhausted.
pub fn register(tree: OwnedTree) -> Result<usize, HandleError> {
    let node = tree.document_node();
    let slot = Arc::new(RwLock::new(Slot {
        tree: Some(tree),
        strings: HashMap::new(),
    }));
    with_table(|table| {
        let document = table.fresh()?;
        table.slots.insert(document, (slot, Issued::default()));
        table.issue(Resolved {
            document,
            target: Target::Node(node),
        })
    })
}

/// What `handle` names, if it names something live in a document no
/// operation holds.
///
/// # Errors
/// [`HandleError::Stale`] or [`HandleError::Busy`].
pub fn resolve(handle: usize) -> Result<Resolved, HandleError> {
    let resolved =
        with_table(|table| table.handles.get(&handle).cloned()).ok_or(HandleError::Stale)?;
    let alive = read_document(resolved.document, |tree| exists(tree, &resolved.target))?;
    if alive {
        Ok(resolved)
    } else {
        with_table(|table| table.forget(handle));
        Err(HandleError::Stale)
    }
}

/// The node `handle` names.
///
/// # Errors
/// [`HandleError::WrongKind`] for a handle of another kind, or as for
/// [`resolve`].
pub fn node(handle: usize) -> Result<(usize, TreeNode), HandleError> {
    match resolve(handle)? {
        Resolved {
            document,
            target: Target::Node(node),
        } => Ok((document, node)),
        _ => Err(HandleError::WrongKind),
    }
}

/// The document `handle` names: a document's own handle or any of its nodes'.
///
/// # Errors
/// As for [`resolve`].
pub fn document(handle: usize) -> Result<usize, HandleError> {
    resolve(handle).map(|resolved| resolved.document)
}

/// The handle of `target` in `document`, issued on first use.
///
/// # Errors
/// [`HandleError::Stale`] for a document or target that does not exist, or
/// an exhausted counter.
pub fn handle(document: usize, target: Target) -> Result<usize, HandleError> {
    // A target removed between the check and the issue gets a handle that
    // its first lookup refuses and forgets.
    if !read_document(document, |tree| exists(tree, &target))? {
        return Err(HandleError::Stale);
    }
    with_table(|table| table.issue(Resolved { document, target }))
}

/// The handle of the document node of `document`.
///
/// # Errors
/// As for [`handle`].
pub fn document_handle(document: usize) -> Result<usize, HandleError> {
    let node = read_document(document, OwnedTree::document_node)?;
    handle(document, Target::Node(node))
}

/// Read `document`.
///
/// # Errors
/// [`HandleError::Stale`] or [`HandleError::Busy`].
pub fn read_document<R>(
    document: usize,
    work: impl FnOnce(&OwnedTree) -> R,
) -> Result<R, HandleError> {
    let slot = slot(document)?;
    let guard = slot.read();
    Ok(work(guard.tree.as_ref().ok_or(HandleError::Busy)?))
}

/// Change `document`; handles of what the change removed are dropped.
///
/// # Errors
/// [`HandleError::Stale`], [`HandleError::Busy`], or the tree's refusal.
pub fn edit_document<R>(
    document: usize,
    work: impl FnOnce(&mut OwnedTree) -> Result<R, TreeError>,
) -> Result<R, HandleError> {
    Ok(write_document(document, work)??)
}

/// Run `work` on `document`'s tree; handles of what it removed are dropped.
/// Unlike [`edit_document`], `work` reports its own failures.
///
/// # Errors
/// [`HandleError::Stale`] or [`HandleError::Busy`].
pub fn update_document<R>(
    document: usize,
    work: impl FnOnce(&mut OwnedTree) -> R,
) -> Result<R, HandleError> {
    write_document(document, work)
}

/// Read the document `handle` belongs to, with the node it names.
///
/// # Errors
/// [`HandleError::WrongKind`], [`HandleError::Stale`] or [`HandleError::Busy`].
pub fn read<R>(
    handle: usize,
    work: impl FnOnce(&OwnedTree, TreeNode) -> R,
) -> Result<R, HandleError> {
    let (document, node) = node(handle)?;
    read_document(document, |tree| work(tree, node))
}

/// Change the document `handle` belongs to, at the node it names.
///
/// # Errors
/// As for [`read`], or the tree's refusal.
pub fn edit<R>(
    handle: usize,
    work: impl FnOnce(&mut OwnedTree, TreeNode) -> Result<R, TreeError>,
) -> Result<R, HandleError> {
    let (document, node) = node(handle)?;
    edit_document(document, |tree| work(tree, node))
}

/// Whether `handle` names an element.
#[must_use]
pub fn is_element(handle: usize) -> bool {
    read(handle, |tree, node| {
        tree.kind(node) == Ok(TreeNodeKind::Element)
    })
    .unwrap_or(false)
}

/// Take the tree of the document `handle` belongs to, for an operation;
/// lookups into it are refused as busy until [`give_back`].
///
/// # Errors
/// [`HandleError::Stale`] or [`HandleError::Busy`].
pub fn lend(handle: usize) -> Result<(usize, OwnedTree), HandleError> {
    let document = resolve(handle)?.document;
    let tree = slot(document)?
        .write()
        .tree
        .take()
        .ok_or(HandleError::Busy)?;
    Ok((document, tree))
}

/// Return the tree an operation held to its document.
///
/// # Errors
/// [`HandleError::Stale`] when the document was freed meanwhile, or
/// [`HandleError::Busy`] when it already holds a tree.
pub fn give_back(document: usize, tree: OwnedTree) -> Result<(), HandleError> {
    let slot = slot(document)?;
    {
        let mut guard = slot.write();
        if guard.tree.is_some() {
            return Err(HandleError::Busy);
        }
        guard.tree = Some(tree);
    }
    prune(document, &slot);
    Ok(())
}

/// A read-only, NUL-terminated copy of `value` that stays valid until
/// `document` is freed, for a function whose contract returns a string the
/// caller does not own; null for text holding NUL or a document that is not
/// live.
#[must_use]
pub fn intern(document: usize, value: &str) -> *const u8 {
    let Ok(slot) = slot(document) else {
        return std::ptr::null();
    };
    let mut guard = slot.write();
    if let Some(copy) = guard.strings.get(value) {
        return copy.as_ptr().cast();
    }
    let Ok(copy) = std::ffi::CString::new(value) else {
        return std::ptr::null();
    };
    let pointer = copy.as_ptr().cast();
    guard.strings.insert(String::from(value), copy);
    pointer
}

/// Free the document `handle` belongs to, with every handle into it.
///
/// # Errors
/// [`HandleError::Stale`] or [`HandleError::Busy`].
pub fn free_document(handle: usize) -> Result<(), HandleError> {
    let document = resolve(handle)?.document;
    // The tree goes first, under the document's own lock: a document an
    // operation holds is refused, and a call already holding a reference
    // to the slot finds no tree from then on.
    slot(document)?
        .write()
        .tree
        .take()
        .ok_or(HandleError::Busy)?;
    with_table(|table| {
        let (_, issued) = table.slots.remove(&document).ok_or(HandleError::Stale)?;
        for handle in issued.all {
            if let Some(resolved) = table.handles.remove(&handle) {
                table.reverse.remove(&resolved);
            }
        }
        Ok(())
    })
}

/// A handle value never issued before, for an object another table keeps.
///
/// # Errors
/// [`HandleError::Stale`] when the handle counter is exhausted.
pub fn fresh() -> Result<usize, HandleError> {
    with_table(Table::fresh)
}

/// A new empty node set.
///
/// # Errors
/// [`HandleError::Stale`] when the handle counter is exhausted.
pub fn set_create() -> Result<usize, HandleError> {
    with_table(|table| {
        let set = table.fresh()?;
        table.sets.insert(set, Set::default());
        Ok(set)
    })
}

/// Add the node `member` names to `set`; a member already listed is not
/// added again.
///
/// # Errors
/// [`HandleError::Stale`] when `set` or `member` names nothing issued.
pub fn set_add(set: usize, member: usize) -> Result<(), HandleError> {
    with_table(|table| {
        if !table.handles.contains_key(&member) {
            return Err(HandleError::Stale);
        }
        let set = table.sets.get_mut(&set).ok_or(HandleError::Stale)?;
        if set.index.insert(member) {
            set.members.push(member);
        }
        Ok(())
    })
}

/// Whether `set` lists `member`.
#[must_use]
pub fn set_contains(set: usize, member: usize) -> bool {
    with_table(|table| {
        table
            .sets
            .get(&set)
            .is_some_and(|set| set.index.contains(&member))
    })
}

/// The members of `set` in the order they were added.
///
/// # Errors
/// [`HandleError::Stale`] when `set` is not a live node set.
pub fn set_members(set: usize) -> Result<Vec<usize>, HandleError> {
    with_table(|table| {
        table
            .sets
            .get(&set)
            .map(|set| set.members.clone())
            .ok_or(HandleError::Stale)
    })
}

/// The number of members of `set` and the member at `index`, if any.
///
/// # Errors
/// [`HandleError::Stale`] when `set` is not a live node set.
pub fn set_member(set: usize, index: usize) -> Result<(usize, Option<usize>), HandleError> {
    with_table(|table| {
        table
            .sets
            .get(&set)
            .map(|set| (set.members.len(), set.members.get(index).copied()))
            .ok_or(HandleError::Stale)
    })
}

/// Free `set` if it is a live node set; its members are not affected.
pub fn set_free(set: usize) {
    with_table(|table| table.sets.remove(&set));
}

#[cfg(test)]
mod tests;
