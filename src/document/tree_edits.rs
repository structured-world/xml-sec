//! Mutation of a tree-backed [`XmlDocument`]: every change is an edit of the
//! external tree, followed by a projection of the tree as the next generation.

use alloc::{string::String, vec::Vec};
use core::fmt::Write as _;

use super::external::{ExternalNode, ExternalTree, Fragment, TreeEdit};
use super::{
    DocumentCell, DocumentParseSettings, NodeIdentity, ReplacementShape, XmlDocument,
    XmlDocumentError, XmlParseWorkBudget, build_cell, charge_parse_work, project_external,
};
use crate::ParseError;
use crate::collections::{Set, Table as _};
use crate::xml::dom::Node;

/// The wrapper element's name. It is unprefixed and declares nothing of its
/// own, so every prefix the context binds is free for the application: only
/// the wrapper's children are ever applied, never its name or namespace.
const WRAPPER: &str = "wrapper";

/// What one tree edit does at its target.
#[derive(Clone, Copy)]
pub(crate) enum TreeChange<'a> {
    /// The element's content becomes this character data.
    SetText(&'a str),
    /// The element's content becomes this fragment.
    Content(&'a str),
    /// The node is replaced by this fragment of the given shape.
    Node(&'a str, ReplacementShape),
    /// This fragment is inserted before the node.
    Before(&'a str),
    /// This fragment becomes the element's last children.
    Append(&'a str),
}

/// Where a validated fragment goes.
#[derive(Clone, Copy)]
pub(super) enum Placement {
    Content,
    Node,
    Before,
    Append,
}

/// A change checked against the current generation, ready for the tree.
pub(super) enum ValidatedChange {
    Text {
        target: ExternalNode,
        text: String,
    },
    Fragment {
        target: ExternalNode,
        placement: Placement,
        /// The fragment parsed inside a wrapper declaring its context's scope.
        cell: DocumentCell,
    },
}

impl XmlDocument {
    /// Validate `changes` against the current generation without touching
    /// the tree: targets, shapes and fragments parsed in their context.
    pub(super) fn validate_tree_changes(
        &self,
        changes: &[(NodeIdentity, TreeChange<'_>)],
        settings: DocumentParseSettings,
        budget: Option<&XmlParseWorkBudget>,
    ) -> Result<Vec<ValidatedChange>, XmlDocumentError> {
        if changes.len() > 1 {
            self.with_view(|view| reject_nested_targets(view, changes))?;
        }
        let mut targets = Set::with_entry_capacity(changes.len());
        let mut validated = Vec::with_capacity(changes.len());
        for (target, change) in changes {
            if !targets.insert(*target) {
                return Err(XmlDocumentError::InvalidReplacement(
                    "replacement targets must be unique".into(),
                ));
            }
            let planned = self.with_view(|view| {
                let node = view.resolve_node(*target)?;
                let external = view
                    .parsed
                    .external
                    .get(node.id().get_usize())
                    .copied()
                    .flatten()
                    .ok_or(XmlDocumentError::EntityExpandedMutationTarget)?;
                let (placement, fragment, shape, context) = match *change {
                    TreeChange::SetText(text) => {
                        require_element(node)?;
                        return Ok(Planned::Text(external, String::from(text)));
                    }
                    TreeChange::Content(fragment) => {
                        require_element(node)?;
                        (Placement::Content, fragment, Shape::Fragment, Some(node))
                    }
                    TreeChange::Append(fragment) => {
                        require_element(node)?;
                        (Placement::Append, fragment, Shape::Fragment, Some(node))
                    }
                    TreeChange::Node(fragment, shape) => {
                        if shape == ReplacementShape::SingleElement {
                            require_element(node)?;
                        }
                        let parent = node.parent_element();
                        let shape = match parent {
                            Some(_) => shape.into(),
                            None => document_level(node)?,
                        };
                        (Placement::Node, fragment, shape, parent)
                    }
                    TreeChange::Before(fragment) => {
                        let parent = node.parent_element();
                        // A node at the document level is preceded by prolog
                        // or misc content: comments, processing instructions
                        // and whitespace (XML 1.0 productions 22 and 27).
                        let shape = if parent.is_some() {
                            Shape::Fragment
                        } else {
                            document_level(node)?;
                            Shape::Misc
                        };
                        (Placement::Before, fragment, shape, parent)
                    }
                };
                let wrapper = wrap_in_scope(fragment, context)?;
                // The wrapper is the fragment plus the markup around it.
                let overhead = wrapper.len() - fragment.len();
                Ok::<_, XmlDocumentError>(Planned::Fragment(
                    external, placement, wrapper, overhead, shape,
                ))
            })?;
            validated.push(match planned {
                Planned::Text(target, text) => ValidatedChange::Text { target, text },
                Planned::Fragment(target, placement, wrapper, overhead, shape) => {
                    let cell = parse_fragment(wrapper, overhead, settings, budget)?;
                    check_shape(&cell, shape)?;
                    ValidatedChange::Fragment {
                        target,
                        placement,
                        cell,
                    }
                }
            });
        }
        Ok(validated)
    }

    /// Apply validated changes to the tree and commit its projection as one
    /// new generation. On any failure the tree is rolled back and the
    /// document keeps its generation.
    pub(super) fn commit_tree_changes(
        &mut self,
        changes: &[ValidatedChange],
        settings: DocumentParseSettings,
        budget: Option<&XmlParseWorkBudget>,
    ) -> Result<(), XmlDocumentError> {
        let tree = self.tree.as_mut().ok_or(XmlDocumentError::NotTreeBacked)?;
        let mark = tree.checkpoint();
        let projected = apply_all(tree.as_mut(), changes).and_then(|()| {
            let (cell, _) = project_external(tree.as_ref(), settings).map_err(|error| {
                match (error, budget) {
                    (XmlDocumentError::Parse(ParseError::NodesLimitReached), Some(_)) => {
                        XmlDocumentError::ProjectedNodeLimit {
                            maximum: settings.nodes_limit as usize,
                        }
                    }
                    (error, _) => error,
                }
            })?;
            // Walking the edited tree is the parse a text document would run.
            charge_parse_work(budget, super::recorded_work(&cell))?;
            Ok(cell)
        });
        let next = match projected {
            Ok(next) => next,
            Err(error) => {
                tree.rollback(mark);
                return Err(error);
            }
        };
        if let Err(error) = self.commit_generation(next) {
            if let Some(tree) = self.tree.as_mut() {
                tree.rollback(mark);
            }
            return Err(error);
        }
        if !self.in_transaction()
            && let Some(tree) = self.tree.as_mut()
        {
            tree.release(mark);
        }
        Ok(())
    }

    /// Validate and commit `changes` as one generation.
    pub(crate) fn change_tree(
        &mut self,
        changes: &[(NodeIdentity, TreeChange<'_>)],
        settings: DocumentParseSettings,
        budget: Option<&XmlParseWorkBudget>,
    ) -> Result<(), XmlDocumentError> {
        let validated = self.validate_tree_changes(changes, settings, budget)?;
        self.commit_tree_changes(&validated, settings, budget)
    }
}

/// A change resolved inside the view, before its fragment is parsed.
enum Planned {
    Text(ExternalNode, String),
    /// The fragment in its wrapper, and the wrapper's own bytes.
    Fragment(ExternalNode, Placement, String, usize, Shape),
}

/// Refuse targets one of which lies inside another: an edit at the outer
/// one removes the inner node, so an edit at the inner one could only land
/// on a detached node, which a text document refuses as overlapping ranges.
fn reject_nested_targets(
    view: super::DocumentView<'_>,
    changes: &[(NodeIdentity, TreeChange<'_>)],
) -> Result<(), XmlDocumentError> {
    let mut nodes = Set::with_entry_capacity(changes.len());
    for (target, _) in changes {
        nodes.insert(view.resolve_node(*target)?.id());
    }
    for (target, _) in changes {
        let mut ancestor = view.resolve_node(*target)?.parent_element();
        while let Some(element) = ancestor {
            if nodes.contains(&element.id()) {
                return Err(XmlDocumentError::InvalidReplacement(
                    "replacement targets overlap".into(),
                ));
            }
            ancestor = element.parent_element();
        }
    }
    Ok(())
}

fn require_element(node: Node<'_, '_>) -> Result<(), XmlDocumentError> {
    if node.is_element() {
        Ok(())
    } else {
        Err(XmlDocumentError::TargetNotElement)
    }
}

fn apply_all(
    tree: &mut dyn ExternalTree,
    changes: &[ValidatedChange],
) -> Result<(), XmlDocumentError> {
    let edit_error = |error: super::external::TreeEditError| XmlDocumentError::TreeEdit(error.0);
    for change in changes {
        match change {
            ValidatedChange::Text { target, text } => tree
                .apply(&[TreeEdit::SetText {
                    target: *target,
                    text,
                }])
                .map_err(edit_error)?,
            ValidatedChange::Fragment {
                target,
                placement,
                cell,
            } => cell.with_dependent(|_, parsed| {
                let fragment = Fragment::children_of(parsed.document.root_element());
                let target = *target;
                let edit = match placement {
                    Placement::Content => TreeEdit::ReplaceContent { target, fragment },
                    Placement::Node => TreeEdit::ReplaceNode { target, fragment },
                    Placement::Before => TreeEdit::InsertBefore { target, fragment },
                    Placement::Append => TreeEdit::AppendChild { target, fragment },
                };
                tree.apply(&[edit]).map_err(edit_error)
            })?,
        }
    }
    Ok(())
}

/// `fragment` inside a wrapper element that declares every binding in scope
/// at `context`, so the fragment parses with exactly its insertion scope.
pub(crate) fn wrap_in_scope(
    fragment: &str,
    context: Option<Node<'_, '_>>,
) -> Result<String, XmlDocumentError> {
    let mut wrapper = String::new();
    wrapper
        .try_reserve(fragment.len() + 2 * WRAPPER.len() + 64)
        .map_err(|_| XmlDocumentError::Parse(ParseError::AllocationFailed))?;
    write!(wrapper, "<{WRAPPER}").expect("writing to a String cannot fail");
    if let Some(context) = context {
        for namespace in context.namespaces() {
            match namespace.name() {
                Some(prefix) => {
                    write!(wrapper, " xmlns:{prefix}=\"").expect("writing to a String cannot fail");
                }
                None => wrapper.push_str(" xmlns=\""),
            }
            escape_attribute_into(namespace.uri(), &mut wrapper);
            wrapper.push('"');
        }
    }
    wrapper.push('>');
    wrapper.push_str(fragment);
    write!(wrapper, "</{WRAPPER}>").expect("writing to a String cannot fail");
    Ok(wrapper)
}

fn escape_attribute_into(value: &str, output: &mut String) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '"' => output.push_str("&quot;"),
            character => output.push(character),
        }
    }
}

// What a wrapper adds to the content it wraps: a document node and the
// wrapper element, one level of depth, and the scope it declares. Content
// parsed inside a wrapper stays under the operation's limits, and the
// projection of the edited tree then applies them exactly. A limit already
// at its type's maximum stays there (hence `saturating_add`): these
// allowances only widen a temporary parse, never a committed generation.
const WRAPPER_NODES: u32 = 2;
const WRAPPER_DEPTH: usize = 1;
const WRAPPER_BINDINGS: usize = 1;

/// Widen `resources` by the room a wrapper of `overhead` bytes takes, for a
/// temporary parse of content written out inside [`wrap_in_scope`].
#[cfg(feature = "xmldsig-sign")]
pub(crate) fn admit_wrapper(resources: &mut crate::policy::ResourcePolicy, overhead: usize) {
    resources.max_xml_nodes = resources
        .max_xml_nodes
        .saturating_add(WRAPPER_NODES as usize);
    resources.max_xml_depth = resources.max_xml_depth.saturating_add(WRAPPER_DEPTH);
    resources.max_xml_namespace_bindings = resources
        .max_xml_namespace_bindings
        .saturating_add(WRAPPER_BINDINGS);
    resources.max_xml_document_bytes = resources.max_xml_document_bytes.saturating_add(overhead);
}

fn parse_fragment(
    wrapper: String,
    overhead: usize,
    settings: DocumentParseSettings,
    budget: Option<&XmlParseWorkBudget>,
) -> Result<DocumentCell, XmlDocumentError> {
    let fragment_settings = DocumentParseSettings {
        allow_dtd: false,
        nodes_limit: settings.nodes_limit.saturating_add(WRAPPER_NODES),
        depth_limit: settings.depth_limit.saturating_add(WRAPPER_DEPTH),
        namespace_bindings_limit: settings
            .namespace_bindings_limit
            .saturating_add(WRAPPER_BINDINGS),
        max_bytes: settings.max_bytes.saturating_add(overhead),
        ..settings
    };
    build_cell(wrapper, fragment_settings, budget)
}

/// The shape a replacement of `node`, a child of the document node, takes:
/// the document element stays exactly one element (XML 1.0 production 1),
/// and anything else there is `Misc` (production 27). The document node
/// itself is the parent of that level, not a node in it.
fn document_level(node: Node<'_, '_>) -> Result<Shape, XmlDocumentError> {
    if node.is_element() {
        Ok(Shape::SingleElement)
    } else if node.is_root() {
        Err(XmlDocumentError::InvalidReplacement(
            "the document node has no siblings to replace it or precede it".into(),
        ))
    } else {
        Ok(Shape::Misc)
    }
}

/// The node sequence a fragment must parse to at its placement.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Shape {
    /// Any content.
    Fragment,
    /// Exactly one element, with markup and whitespace around it.
    SingleElement,
    /// Document-level `Misc`: comments, processing instructions and
    /// whitespace, no element and no other character data (XML 1.0
    /// production 27).
    Misc,
}

impl From<ReplacementShape> for Shape {
    fn from(shape: ReplacementShape) -> Self {
        match shape {
            ReplacementShape::Fragment => Self::Fragment,
            ReplacementShape::SingleElement => Self::SingleElement,
        }
    }
}

fn check_shape(cell: &DocumentCell, shape: Shape) -> Result<(), XmlDocumentError> {
    if shape == Shape::Fragment {
        return Ok(());
    }
    cell.with_dependent(|_, parsed| {
        let wrapper = parsed.document.root_element();
        let elements = wrapper.children().filter(Node::is_element).count();
        // White space is S (XML 1.0 production 3), not every Unicode space.
        let markup = |node: Node<'_, '_>| {
            node.is_comment()
                || node.is_pi()
                || node.text().is_some_and(|text| {
                    text.chars()
                        .all(|character| matches!(character, ' ' | '\t' | '\r' | '\n'))
                })
        };
        let (expected, message) = match shape {
            Shape::SingleElement => (1, "element replacement must contain exactly one element"),
            _ => (
                0,
                "only comments, processing instructions and white space may stand outside the document element",
            ),
        };
        if elements == expected
            && wrapper
                .children()
                .all(|node| node.is_element() || markup(node))
        {
            Ok(())
        } else {
            Err(XmlDocumentError::InvalidReplacement(message.into()))
        }
    })
}
