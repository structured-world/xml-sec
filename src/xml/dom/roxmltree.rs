//! `roxmltree` parser adapter: the parser builds the shared semantic arena.

use super::storage::{Native, Storage, Values};
use crate::parser_roxmltree as backend;
use alloc::string::ToString;

use super::{
    Document, LexicalPreflight, ParseError, ParsingOptions, XmlBackendImplementation,
    tree::{
        AttributeData, NamespaceData, NamespaceSet, NodeId, NodeKind, TreeBuilder, range_contains,
    },
};

pub(super) struct RoxmltreeBackend;

#[cfg(feature = "xmldsig")]
impl RoxmltreeBackend {
    pub(super) fn parse_in<'input, 'w, W: structured_asn1::memory::Work>(
        input: &'input str,
        options: ParsingOptions,
        preflight: &LexicalPreflight<'input, super::storage::Accounted<'w, W>>,
        storage: super::storage::Accounted<'w, W>,
    ) -> Result<Document<'input, super::storage::Accounted<'w, W>>, super::AccountedParseError>
    {
        parse_arena(input, options, preflight, storage).map_err(|refusal| match refusal {
            Refusal::Parser(error) => super::AccountedParseError::Roxmltree(
                error.map_text(structured_asn1::memory::OwnedText::into_owned),
            ),
            Refusal::Semantic(error) => error.into(),
        })
    }
}

impl XmlBackendImplementation for RoxmltreeBackend {
    fn parse<'input>(
        input: &'input str,
        options: ParsingOptions,
        preflight: &LexicalPreflight,
    ) -> Result<Document<'input>, ParseError> {
        parse_arena(input, options, preflight, Native).map_err(|refusal| match refusal {
            Refusal::Parser(error) => map_error(error),
            Refusal::Semantic(error) => error,
        })
    }
}

/// Why a parse into the semantic arena failed.
enum Refusal<T> {
    /// The parser refused the input.
    Parser(backend::Error<T>),
    /// Building the arena failed.
    Semantic(ParseError),
}

/// Parses `input` straight into the semantic arena, with no backend DOM.
fn parse_arena<'input, S: Storage, P: Storage>(
    input: &'input str,
    options: ParsingOptions,
    preflight: &LexicalPreflight<'_, P>,
    storage: S,
) -> Result<Document<'input, S>, Refusal<S::Text>> {
    let mut tree = Semantic::new(input, preflight, storage).map_err(Refusal::Semantic)?;
    let parsed = backend::parse_into(
        input,
        backend::ParsingOptions {
            allow_dtd: options.allow_dtd,
            nodes_limit: options.nodes_limit,
            entity_resolver: None,
        },
        storage,
        &mut tree,
    );
    if let Some(error) = tree.failure.take() {
        return Err(Refusal::Semantic(error));
    }
    parsed.map_err(Refusal::Parser)?;
    tree.finish().map_err(Refusal::Semantic)
}

/// The semantic arena as the tree the roxmltree parser builds, node by node,
/// in the form the lexical scan's positions give each node.
struct Semantic<'input, 'p, 'l, S: Storage, P: Storage> {
    tree: TreeBuilder<'input, S>,
    root: NodeId,
    preflight: &'p LexicalPreflight<'l, P>,
    /// Elements open, the one being appended included.
    depth: usize,
    /// The arena's own failure, which the parser reports as stopped.
    failure: Option<ParseError>,
}

impl<'input, 'p, 'l, S: Storage, P: Storage> Semantic<'input, 'p, 'l, S, P> {
    fn new(
        input: &'input str,
        preflight: &'p LexicalPreflight<'l, P>,
        storage: S,
    ) -> Result<Self, ParseError> {
        // The scan records a position per source node; the root has none. The
        // count is bounded by the input length, so adding one cannot overflow.
        let mut tree = TreeBuilder::new(input, preflight.node_count() + 1, storage)?;
        let range = 0..input.len();
        let actionable = !preflight
            .doctype_range()
            .is_some_and(|doctype| range_contains(doctype, &range));
        let root = tree.push_with_actionability(None, NodeKind::Root, range, actionable)?;
        Ok(Self {
            tree,
            root,
            preflight,
            depth: 0,
            failure: None,
        })
    }

    fn finish(mut self) -> Result<Document<'input, S>, ParseError> {
        self.tree.finish_subtree(self.root);
        self.tree.finish(self.preflight)
    }

    /// Keeps `result`'s failure for the caller and stops the parser.
    fn stop<T>(&mut self, result: Result<T, ParseError>) -> Result<T, backend::Error<S::Text>> {
        result.map_err(|error| {
            self.failure.get_or_insert(error);
            backend::Error::ProcessingStopped
        })
    }

    fn inside_doctype(&self, range: &core::ops::Range<usize>) -> bool {
        self.preflight
            .doctype_range()
            .is_some_and(|doctype| range_contains(doctype, range))
    }

    /// Whether a node at `range` under `parent` is a declaration inside the
    /// DOCTYPE rather than a document node.
    fn in_internal_subset(&self, parent: NodeId, range: &core::ops::Range<usize>) -> bool {
        parent == self.root && self.inside_doctype(range)
    }

    fn element(
        &mut self,
        parent: NodeId,
        mut element: backend::Element<'_, 'input, S>,
        range: core::ops::Range<usize>,
    ) -> Result<NodeId, ParseError> {
        self.depth += 1;
        if self.depth > crate::hard_limits::XML_DOCUMENT_DEPTH_CEILING {
            return Err(ParseError::DepthLimitReached {
                maximum: crate::hard_limits::XML_DOCUMENT_DEPTH_CEILING,
                actual: self.depth,
            });
        }
        let storage = self.tree.storage();
        let mut attributes = storage.values(element.attribute_count())?;
        for attribute in element.attributes()? {
            storage.charge(1)?;
            attributes.push(AttributeData {
                name: storage.text(attribute.local)?,
                namespace: storage.optional_text(attribute.namespace)?,
                prefix: storage.optional_text(attribute.prefix)?,
                value: owned_text(attribute.value, storage)?,
                is_id: false,
                xml_id_error: None,
            })?;
        }
        let namespaces = self.namespaces(parent, &element)?;
        let kind = NodeKind::Element {
            name: storage.text(element.local_name())?,
            namespace: storage.optional_text(element.namespace().filter(|uri| !uri.is_empty()))?,
            prefix: storage.optional_text(element.prefix())?,
            attributes,
            namespaces,
        };
        let actionable = !self.inside_doctype(&range);
        self.tree
            .push_with_actionability(Some(parent), kind, range, actionable)
    }

    /// The element's in-scope set, sharing its parent's when the bindings agree.
    fn namespaces(
        &mut self,
        parent: NodeId,
        element: &backend::Element<'_, 'input, S>,
    ) -> Result<NamespaceSet, ParseError> {
        let storage = self.tree.storage();
        let inherited = self.tree.namespace_set_of(Some(parent));
        let bindings = self.tree.namespace_bindings(inherited);
        let mut same = bindings.len() == element.namespaces().len();
        if same {
            for (binding, namespace) in bindings.iter().zip(element.namespaces()) {
                // A URI is a slice of the input, whose length is far below usize::MAX.
                storage.charge(binding.uri.len() + 1)?;
                if binding.prefix.as_deref() != namespace.name() || &*binding.uri != namespace.uri()
                {
                    same = false;
                    break;
                }
            }
        }
        if same {
            return Ok(inherited);
        }
        let mut namespaces = storage.values(element.namespaces().len())?;
        for namespace in element.namespaces() {
            storage.charge(1)?;
            namespaces.push(NamespaceData {
                prefix: storage.optional_text(namespace.name())?,
                uri: storage.text(namespace.uri())?,
            })?;
        }
        self.tree.add_namespace_set(namespaces)
    }

    fn text(
        &mut self,
        parent: NodeId,
        text: backend::StringStorage<'input, S>,
        mut range: core::ops::Range<usize>,
    ) -> Result<(), ParseError> {
        if self.in_internal_subset(parent, &range) {
            return Ok(());
        }
        let mut actionable = !self.inside_doctype(&range);
        if let Some((folded, folded_actionable)) =
            self.preflight.folded_character_data_range(range.start)?
        {
            range = folded;
            actionable &= folded_actionable;
        }
        let value = owned_text(text, self.tree.storage())?;
        self.tree.push_with_actionability(
            Some(parent),
            NodeKind::Text(value),
            range,
            actionable,
        )?;
        Ok(())
    }

    fn leaf(
        &mut self,
        parent: NodeId,
        kind: impl FnOnce(S) -> Result<NodeKind<S>, ParseError>,
        range: core::ops::Range<usize>,
    ) -> Result<(), ParseError> {
        if self.in_internal_subset(parent, &range) {
            return Ok(());
        }
        let kind = kind(self.tree.storage())?;
        let actionable = !self.inside_doctype(&range);
        self.tree
            .push_with_actionability(Some(parent), kind, range, actionable)?;
        Ok(())
    }
}

impl<'input, S: Storage, P: Storage> backend::Tree<'input, S> for Semantic<'input, '_, '_, S, P> {
    type Node = NodeId;

    fn root(&self) -> NodeId {
        self.root
    }

    fn element(
        &mut self,
        parent: NodeId,
        element: backend::Element<'_, 'input, S>,
        range: core::ops::Range<usize>,
    ) -> Result<NodeId, backend::Error<S::Text>> {
        let result = Semantic::element(self, parent, element, range);
        self.stop(result)
    }

    fn end_element(
        &mut self,
        element: NodeId,
        end: Option<usize>,
    ) -> Result<(), backend::Error<S::Text>> {
        if let Some(end) = end {
            self.tree.end_range(element, end);
        }
        self.tree.finish_subtree(element);
        self.depth -= 1;
        Ok(())
    }

    fn text(
        &mut self,
        parent: NodeId,
        text: backend::StringStorage<'input, S>,
        range: core::ops::Range<usize>,
    ) -> Result<(), backend::Error<S::Text>> {
        let result = Semantic::text(self, parent, text, range);
        self.stop(result)
    }

    fn comment(
        &mut self,
        parent: NodeId,
        text: &'input str,
        range: core::ops::Range<usize>,
    ) -> Result<(), backend::Error<S::Text>> {
        let result = self.leaf(
            parent,
            |storage| Ok(NodeKind::Comment(storage.text(text)?)),
            range,
        );
        self.stop(result)
    }

    fn processing_instruction(
        &mut self,
        parent: NodeId,
        pi: backend::PI<'input>,
        range: core::ops::Range<usize>,
    ) -> Result<(), backend::Error<S::Text>> {
        let result = self.leaf(
            parent,
            |storage| {
                Ok(NodeKind::PI {
                    target: storage.text(pi.target)?,
                    value: storage.optional_text(pi.value)?,
                })
            },
            range,
        );
        self.stop(result)
    }
}

/// A parsed value as arena text: a buffer the parser normalized moves in,
/// a slice of the input is copied.
fn owned_text<S: Storage>(
    value: backend::StringStorage<'_, S>,
    storage: S,
) -> Result<S::Text, ParseError> {
    match value {
        backend::StringStorage::Borrowed(text) => storage.text(text),
        backend::StringStorage::Owned(text) => Ok(text),
    }
}

fn map_error(error: backend::Error) -> ParseError {
    match error {
        backend::Error::DtdDetected => ParseError::DtdDetected,
        backend::Error::NodesLimitReached => ParseError::NodesLimitReached,
        other => ParseError::Backend {
            backend: "roxmltree",
            message: other.to_string(),
        },
    }
}
