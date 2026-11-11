//! Documents backed by an external tree instead of a serialization.
//!
//! An application that already holds its document as a tree (for example a
//! libxml2 `xmlDoc`) implements [`ExternalTree`] over it. The resulting
//! [`XmlDocument`](super::XmlDocument) is read by every operation exactly like
//! a parsed one: its semantic view is built by walking the tree into a
//! [`TreeSink`], under the operation's XML input policy and resource limits.
//! Operations that change the document hand the tree [`TreeEdit`]s, then walk
//! it again for the next generation.

use alloc::string::String;

pub use crate::xml::dom::external::{ExternalNode, TreeSink};

use crate::{Node, NodeType, ParseError};

/// A document tree owned outside this crate.
///
/// Implementations report the tree as it is when [`Self::project`] runs; the
/// tree must not change while a document built from it is in use, except
/// through that document.
pub trait ExternalTree: Send + Sync {
    /// The node that stands for the whole document.
    fn document(&self) -> ExternalNode;

    /// Report the whole tree to `sink` in document order: a document type
    /// declaration first if there is one, then the children of the document
    /// node with their descendants.
    ///
    /// # Errors
    /// Whatever `sink` refuses, returned unchanged, or a tree the
    /// implementation cannot read.
    fn project(&self, sink: &mut TreeSink<'_>) -> Result<(), ParseError>;

    /// Apply `edits` in order. Every target is a node of the tree's current
    /// state, reported by the last projection.
    ///
    /// The fragments are already validated in their insertion context. The
    /// tree records what it needs to undo the edits from the current
    /// [`Self::checkpoint`] on, and keeps removed nodes alive until
    /// [`Self::release`].
    ///
    /// # Errors
    /// A node the tree cannot create or link. The edits applied before the
    /// failure stay applied; the document rolls them back.
    fn apply(&mut self, edits: &[TreeEdit<'_>]) -> Result<(), TreeEditError>;

    /// A mark of the tree's current state that [`Self::rollback`] returns to.
    fn checkpoint(&mut self) -> usize;

    /// Undo every edit applied since `mark`, newest first, restoring removed
    /// nodes where they were and freeing the nodes the edits created.
    fn rollback(&mut self, mark: usize);

    /// Keep every edit applied since `mark`: free the nodes they removed and
    /// forget how to undo them.
    fn release(&mut self, mark: usize);

    /// This tree as the crate's own [`OwnedTree`](super::owned_tree::OwnedTree),
    /// if it is one, so a caller that lent it to a document gets it back.
    #[cfg(all(feature = "owned-tree", any(feature = "xmldsig", feature = "xmlenc")))]
    #[must_use]
    fn into_owned_tree(self: alloc::boxed::Box<Self>) -> Option<super::owned_tree::OwnedTree> {
        None
    }
}

/// A tree's failure to carry out an edit.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("external tree edit failed: {0}")]
pub struct TreeEditError(pub String);

/// One change of an external tree, addressed by a node of its current state.
#[derive(Clone, Copy, Debug)]
pub enum TreeEdit<'a> {
    /// The element's children become one text node with `text`.
    SetText {
        /// The element whose content changes.
        target: ExternalNode,
        /// The new character data, unescaped.
        text: &'a str,
    },
    /// The element's children become the fragment's nodes.
    ReplaceContent {
        /// The element whose content changes.
        target: ExternalNode,
        /// The new children.
        fragment: Fragment<'a>,
    },
    /// The node is replaced by the fragment's nodes, possibly none.
    ReplaceNode {
        /// The node that is replaced.
        target: ExternalNode,
        /// The nodes taking its place.
        fragment: Fragment<'a>,
    },
    /// The fragment's nodes are inserted just before the node.
    InsertBefore {
        /// The node the fragment precedes.
        target: ExternalNode,
        /// The inserted nodes.
        fragment: Fragment<'a>,
    },
    /// The fragment's nodes become the element's last children.
    AppendChild {
        /// The element that receives the fragment.
        target: ExternalNode,
        /// The appended nodes.
        fragment: Fragment<'a>,
    },
}

/// Validated content to insert into an external tree: a sequence of sibling
/// nodes, read through [`Self::walk`].
#[derive(Clone, Copy)]
pub struct Fragment<'a> {
    container: Node<'a, 'a>,
}

impl core::fmt::Debug for Fragment<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Fragment")
            .field("nodes", &self.container.children().count())
            .finish()
    }
}

/// One step of a [`Fragment`] walk, in document order.
///
/// An element is `StartElement`, its `Namespace` declarations, its
/// `Attribute`s, `OpenElement`, its content, then `EndElement`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FragmentEvent<'a> {
    /// An element starts.
    StartElement {
        /// Its local name.
        local_name: &'a str,
        /// Its prefix, `None` for none.
        prefix: Option<&'a str>,
        /// Its namespace URI, `None` for no namespace.
        namespace: Option<&'a str>,
    },
    /// The element declares `prefix` (`None` for the default namespace);
    /// an empty `uri` undeclares the default namespace. Only bindings the
    /// insertion context does not already have are declared.
    Namespace {
        /// The declared prefix.
        prefix: Option<&'a str>,
        /// The bound URI.
        uri: &'a str,
    },
    /// An attribute of the element.
    Attribute {
        /// Its local name.
        local_name: &'a str,
        /// Its prefix, `None` for none.
        prefix: Option<&'a str>,
        /// Its namespace URI, `None` for no namespace.
        namespace: Option<&'a str>,
        /// Its value, unescaped.
        value: &'a str,
    },
    /// The element's start tag ends; its content follows.
    OpenElement,
    /// The innermost element ends.
    EndElement,
    /// Character data, unescaped.
    Text(&'a str),
    /// A comment.
    Comment(&'a str),
    /// A processing instruction.
    ProcessingInstruction {
        /// Its target.
        target: &'a str,
        /// Its value, if any.
        value: Option<&'a str>,
    },
}

impl<'a> Fragment<'a> {
    /// The children of `container` as the fragment.
    pub(crate) const fn children_of(container: Node<'a, 'a>) -> Self {
        Self { container }
    }

    /// Report the fragment's nodes to `visit` in document order.
    ///
    /// # Errors
    /// The first error `visit` returns, unchanged.
    pub fn walk<E>(
        &self,
        visit: &mut impl FnMut(FragmentEvent<'a>) -> Result<(), E>,
    ) -> Result<(), E> {
        for child in self.container.children() {
            walk_node(child, visit)?;
        }
        Ok(())
    }
}

fn walk_node<'a, E>(
    node: Node<'a, 'a>,
    visit: &mut impl FnMut(FragmentEvent<'a>) -> Result<(), E>,
) -> Result<(), E> {
    match node.node_type() {
        NodeType::Element => {
            let name = node.tag_name();
            visit(FragmentEvent::StartElement {
                local_name: name.name(),
                prefix: node.prefix(),
                namespace: name.namespace(),
            })?;
            // The parent's scope already holds what is not declared here,
            // the insertion context included.
            let parent = node.parent_element();
            for namespace in node.namespaces() {
                let inherited = parent
                    .and_then(|parent| parent.lookup_namespace_uri(namespace.name()))
                    .unwrap_or_default();
                if inherited != namespace.uri() {
                    visit(FragmentEvent::Namespace {
                        prefix: namespace.name(),
                        uri: namespace.uri(),
                    })?;
                }
            }
            for attribute in node.attributes() {
                visit(FragmentEvent::Attribute {
                    local_name: attribute.name(),
                    prefix: attribute.prefix(),
                    namespace: attribute.namespace(),
                    value: attribute.value(),
                })?;
            }
            visit(FragmentEvent::OpenElement)?;
            for child in node.children() {
                walk_node(child, visit)?;
            }
            visit(FragmentEvent::EndElement)
        }
        NodeType::Text => visit(FragmentEvent::Text(node.text().unwrap_or_default())),
        NodeType::Comment => visit(FragmentEvent::Comment(node.text().unwrap_or_default())),
        NodeType::PI => {
            let pi = node.pi().unwrap_or(crate::PI {
                target: "",
                value: None,
            });
            visit(FragmentEvent::ProcessingInstruction {
                target: pi.target,
                value: pi.value,
            })
        }
        NodeType::Root => Ok(()),
    }
}

#[cfg(all(test, feature = "xmldsig"))]
mod tests;
