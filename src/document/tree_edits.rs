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

const WRAPPER_PREFIX: &str = "xmlsec_owned_document";
const WRAPPER_NAMESPACE: &str = "urn:xml-sec:owned-document-validation";

/// What one tree edit does at its target.
#[derive(Clone, Copy)]
pub(super) enum TreeChange<'a> {
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
                        let shape = ReplacementShape::Fragment;
                        (Placement::Content, fragment, shape, Some(node))
                    }
                    TreeChange::Append(fragment) => {
                        require_element(node)?;
                        let shape = ReplacementShape::Fragment;
                        (Placement::Append, fragment, shape, Some(node))
                    }
                    TreeChange::Node(fragment, shape) => {
                        if shape == ReplacementShape::SingleElement {
                            require_element(node)?;
                        }
                        // The document element has no parent element, and its
                        // replacement must stay one element (XML 1.0 production 1).
                        let parent = node.parent_element();
                        let shape = if parent.is_none() {
                            ReplacementShape::SingleElement
                        } else {
                            shape
                        };
                        (Placement::Node, fragment, shape, parent)
                    }
                    TreeChange::Before(fragment) => {
                        let parent = node.parent_element().ok_or_else(|| {
                            XmlDocumentError::InvalidReplacement(
                                "nothing may precede the document element".into(),
                            )
                        })?;
                        let shape = ReplacementShape::Fragment;
                        (Placement::Before, fragment, shape, Some(parent))
                    }
                };
                let wrapper = wrap_in_scope(fragment, context)?;
                Ok::<_, XmlDocumentError>(Planned::Fragment(external, placement, wrapper, shape))
            })?;
            validated.push(match planned {
                Planned::Text(target, text) => ValidatedChange::Text { target, text },
                Planned::Fragment(target, placement, wrapper, shape) => {
                    let cell = parse_fragment(wrapper, settings, budget)?;
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
        let tree = self
            .tree
            .as_mut()
            .ok_or(XmlDocumentError::TreeBackedSerialization)?;
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
    pub(super) fn change_tree(
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
    Fragment(ExternalNode, Placement, String, ReplacementShape),
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
fn wrap_in_scope(
    fragment: &str,
    context: Option<Node<'_, '_>>,
) -> Result<String, XmlDocumentError> {
    let mut wrapper = String::new();
    wrapper
        .try_reserve(fragment.len() + 2 * WRAPPER_PREFIX.len() + WRAPPER_NAMESPACE.len() + 64)
        .map_err(|_| XmlDocumentError::Parse(ParseError::AllocationFailed))?;
    write!(
        wrapper,
        "<{WRAPPER_PREFIX}:wrapper xmlns:{WRAPPER_PREFIX}=\"{WRAPPER_NAMESPACE}\""
    )
    .expect("writing to a String cannot fail");
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
    write!(wrapper, "</{WRAPPER_PREFIX}:wrapper>").expect("writing to a String cannot fail");
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

fn parse_fragment(
    wrapper: String,
    settings: DocumentParseSettings,
    budget: Option<&XmlParseWorkBudget>,
) -> Result<DocumentCell, XmlDocumentError> {
    // The wrapper adds a root and one element above the fragment; the
    // projection of the edited tree then applies the caller's exact limits.
    // A limit already at its type's maximum stays there: these allowances
    // only widen the fragment's own parse, never the committed generation.
    let fragment_settings = DocumentParseSettings {
        allow_dtd: false,
        nodes_limit: settings.nodes_limit.saturating_add(2),
        depth_limit: settings.depth_limit.saturating_add(1),
        namespace_bindings_limit: settings.namespace_bindings_limit.saturating_add(1),
        max_bytes: wrapper.len().max(settings.max_bytes),
        ..settings
    };
    build_cell(wrapper, fragment_settings, budget)
}

fn check_shape(cell: &DocumentCell, shape: ReplacementShape) -> Result<(), XmlDocumentError> {
    if shape == ReplacementShape::Fragment {
        return Ok(());
    }
    cell.with_dependent(|_, parsed| {
        let wrapper = parsed.document.root_element();
        let elements = wrapper.children().filter(Node::is_element).count();
        let only_markup = wrapper.children().all(|node| {
            node.is_element()
                || node.is_comment()
                || node.is_pi()
                || node.text().is_some_and(|text| text.trim().is_empty())
        });
        if elements == 1 && only_markup {
            Ok(())
        } else {
            Err(XmlDocumentError::InvalidReplacement(
                "element replacement must contain exactly one element".into(),
            ))
        }
    })
}
