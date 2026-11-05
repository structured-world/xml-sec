//! `xmloxide` parser adapter: the parser builds the shared semantic arena.

use alloc::string::ToString;
use core::ops::Range;

use super::storage::names::NameStorage;
use super::storage::{Native, Storage, Values};
use crate::parser_xmloxide as xmloxide;
use xmloxide::parser::{PushedElement, Span, Tree};
use xmloxide::tree::NodeKind as XmloxNodeKind;

use super::{
    Document, LexicalPreflight, ParseError, ParseLimits, ParsingOptions, Refused,
    XmlBackendImplementation,
    tree::{AttributeData, NamespaceData, NamespaceSet, NodeId, NodeKind, TreeBuilder},
};

pub(super) struct XmloxideBackend;

/// The parser's failure in storage `S`.
#[cfg(feature = "xmldsig")]
type XmloxideError<S> = xmloxide::error::ParseError<
    <S as Storage>::FrozenText,
    <S as Storage>::Values<xmloxide::error::ParseDiagnostic<<S as Storage>::FrozenText>>,
>;

#[cfg(feature = "xmldsig")]
fn accounted_failure<W: structured_asn1::memory::Work>(
    error: XmloxideError<super::storage::Accounted<'_, W>>,
) -> super::AccountedParseError {
    match error {
        xmloxide::error::ParseError::Resource(error) => super::AccountedParseError::Semantic(error),
        xmloxide::error::ParseError::Syntax {
            message,
            location,
            diagnostics,
        } => super::AccountedParseError::Xmloxide(xmloxide::error::ParseError::Syntax {
            message,
            location,
            diagnostics: diagnostics.into_owned(),
        }),
    }
}

fn native_failure(error: xmloxide::error::ParseError) -> ParseError {
    match error {
        xmloxide::error::ParseError::Resource(error) => error,
        error @ xmloxide::error::ParseError::Syntax { .. } => ParseError::Backend {
            backend: "xmloxide",
            message: error.to_string(),
        },
    }
}

#[cfg(feature = "xmldsig")]
impl XmloxideBackend {
    pub(super) fn parse_in<'input, 'w, W: structured_asn1::memory::Work>(
        input: &'input str,
        options: ParsingOptions,
        preflight: &LexicalPreflight<'input, super::storage::Accounted<'w, W>>,
        storage: super::storage::Accounted<'w, W>,
    ) -> Result<Document<'input, super::storage::Accounted<'w, W>>, super::AccountedParseError>
    {
        let tree = Semantic::new(input, options, storage)?;
        let tree = xmloxide::parser::XmlParser::with_tree(input, &backend_options(), storage, tree)
            .and_then(xmloxide::parser::XmlParser::parse)
            .map_err(accounted_failure)?;
        Ok(tree.finish(preflight)?)
    }

    /// [`parse_enforcing_limits`](Self::parse_enforcing_limits) in the
    /// current query's storage.
    pub(super) fn parse_enforcing_limits_in<'input, 'w, W: structured_asn1::memory::Work>(
        input: &'input str,
        options: ParsingOptions,
        limits: ParseLimits,
        storage: super::storage::Accounted<'w, W>,
    ) -> Result<
        Limited<'input, super::storage::Accounted<'w, W>>,
        Refused<super::AccountedParseError>,
    > {
        let tree =
            Semantic::new(input, options, storage).map_err(|error| Refused::Parse(error.into()))?;
        let (parsed, counter) =
            xmloxide::parser::XmlParser::with_tree(input, &backend_options(), storage, tree)
                .and_then(|parser| parser.parse_enforcing_limits(limits))
                .map_err(|error| Refused::Parse(accounted_failure(error)))?;
        let tree = parsed.map_err(|error| match counter.refusal() {
            Some(refusal) => Refused::Limit(refusal),
            None => Refused::Parse(accounted_failure(error)),
        })?;
        let preflight = LexicalPreflight::unscanned(storage);
        let document = tree
            .finish(&preflight)
            .map_err(|error| Refused::Parse(error.into()))?;
        Ok((document, counter.peak_namespace_bindings()))
    }
}

/// A document parsed under its limits, with the most namespace bindings it had
/// in scope at once.
pub(super) type Limited<'input, S> = (Document<'input, S>, usize);

impl XmloxideBackend {
    /// Parses a document without a DOCTYPE, refusing it at the first of
    /// `limits` it passes as the parser reads it, so no pass over the source
    /// precedes the parse.
    pub(super) fn parse_enforcing_limits(
        input: &str,
        options: ParsingOptions,
        limits: ParseLimits,
    ) -> Result<Limited<'_, Native>, Refused<ParseError>> {
        let tree = Semantic::new(input, options, Native).map_err(Refused::Parse)?;
        let (parsed, counter) =
            xmloxide::parser::parse_str_enforcing_limits(input, &backend_options(), limits, tree)
                .map_err(|error| Refused::Parse(native_failure(error)))?;
        let tree = parsed.map_err(|error| match counter.refusal() {
            Some(refusal) => Refused::Limit(refusal),
            None => Refused::Parse(native_failure(error)),
        })?;
        let preflight = LexicalPreflight::unscanned(Native);
        let document = tree.finish(&preflight).map_err(Refused::Parse)?;
        Ok((document, counter.peak_namespace_bindings()))
    }
}

impl XmlBackendImplementation for XmloxideBackend {
    fn parse<'input>(
        input: &'input str,
        options: ParsingOptions,
        preflight: &LexicalPreflight,
    ) -> Result<Document<'input>, ParseError> {
        let tree = Semantic::new(input, options, Native)?;
        xmloxide::parser::parse_str_into(input, &backend_options(), tree)
            .map_err(native_failure)?
            .finish(preflight)
    }
}

pub(super) fn backend_options() -> xmloxide::parser::ParseOptions {
    // The shared preflight owns the backend-neutral contract. These absolute
    // limits are defense in depth against a backend regression allocating
    // expanded entity data before returning control to the semantic tree.
    xmloxide::parser::ParseOptions::default()
        .max_depth(
            u32::try_from(crate::hard_limits::XML_DOCUMENT_DEPTH_CEILING)
                .expect("XML depth ceiling fits into u32"),
        )
        .max_attributes(u32::MAX)
        .max_attribute_length(usize::MAX)
        .max_text_length(crate::hard_limits::XML_ENTITY_EXPANSION_WORK_BYTE_CEILING)
        .max_name_length(usize::MAX)
        .max_entity_expansions(crate::hard_limits::XML_ENTITY_EXPANSION_CEILING)
}

/// The semantic arena as the tree the parser builds: each node the parser
/// reads lands in its final form, with no backend DOM between them.
struct Semantic<'input, S: Storage> {
    tree: TreeBuilder<'input, S>,
    root: NodeId,
    nodes_limit: u32,
}

impl<'input, S: NameStorage> Semantic<'input, S> {
    fn new(input: &'input str, options: ParsingOptions, storage: S) -> Result<Self, ParseError> {
        if options.nodes_limit == 0 {
            return Err(ParseError::NodesLimitReached);
        }
        // Never more than may be admitted.
        let capacity =
            xmloxide::parser::initial_node_capacity(input.len()).min(options.nodes_limit as usize);
        let mut tree = TreeBuilder::new(input, capacity, storage)?;
        let root = tree.push(None, NodeKind::Root, 0..input.len())?;
        Ok(Self {
            tree,
            root,
            nodes_limit: options.nodes_limit,
        })
    }

    fn finish<P: Storage>(
        mut self,
        preflight: &LexicalPreflight<'_, P>,
    ) -> Result<Document<'input, S>, ParseError> {
        self.tree.finish_subtree(self.root);
        self.tree.finish(preflight)
    }

    /// The element node, and the parser's attribute list emptied of the
    /// attributes it moved into the node.
    fn element(
        &mut self,
        parent: NodeId,
        kind: XmloxNodeKind<S>,
        range: Range<usize>,
        range_actionable: bool,
    ) -> Result<(NodeId, S::Values<xmloxide::tree::Attribute<S>>), ParseError> {
        let XmloxNodeKind::Element {
            name,
            prefix,
            namespace,
            mut attributes,
        } = kind
        else {
            unreachable!("element construction requires an element");
        };
        self.admit_node()?;
        let storage = self.tree.storage();
        let namespaces = self.namespaces(parent, &attributes)?;
        // Declarations are namespace nodes, not attributes: an element that
        // only declares allocates no attribute list.
        storage.charge(attributes.len())?;
        let declarations = attributes
            .iter()
            .filter(|attribute| namespace_declaration(attribute).is_some())
            .count();
        let mut semantic_attributes = storage.values(attributes.len() - declarations)?;
        for attribute in attributes.drain_all()? {
            storage.charge(1)?;
            if namespace_declaration(&attribute).is_none() {
                semantic_attributes.push(AttributeData {
                    name: attribute.name,
                    namespace: attribute.namespace,
                    prefix: attribute.prefix,
                    value: attribute.value,
                    is_id: false,
                    xml_id_error: None,
                })?;
            }
        }
        let element = self.tree.push_with_actionability(
            Some(parent),
            NodeKind::Element {
                name,
                namespace: namespace.filter(|uri| !uri.is_empty()),
                prefix,
                attributes: semantic_attributes,
                namespaces,
            },
            range,
            range_actionable,
        )?;
        Ok((element, attributes))
    }

    /// The element's in-scope set: its parent's, unless it declares bindings.
    fn namespaces(
        &mut self,
        parent: NodeId,
        attributes: &[xmloxide::tree::Attribute<S>],
    ) -> Result<NamespaceSet, ParseError> {
        let storage = self.tree.storage();
        let inherited = self.tree.namespace_set_of(Some(parent));
        storage.charge(attributes.len())?;
        if attributes
            .iter()
            .all(|attribute| namespace_declaration(attribute).is_none())
        {
            return Ok(inherited);
        }
        let inherited = self.tree.namespace_bindings(inherited);
        let mut namespaces = storage.values(inherited.len())?;
        for namespace in inherited {
            storage.charge(1)?;
            namespaces.push(NamespaceData {
                prefix: storage.optional_text(namespace.prefix.as_deref())?,
                uri: storage.text(namespace.uri.as_ref())?,
            })?;
        }
        for attribute in attributes {
            if let Some(declared) = namespace_declaration(attribute) {
                set_namespace(
                    &mut namespaces,
                    declared.prefix(),
                    &attribute.value,
                    storage,
                )?;
            }
        }
        self.tree.add_namespace_set(namespaces)
    }

    fn text(
        &mut self,
        parent: NodeId,
        content: S::Text,
        range: Range<usize>,
        range_actionable: bool,
    ) -> Result<NodeId, ParseError> {
        self.admit_text(parent)?;
        self.tree
            .append_text(parent, content, range, range_actionable)?;
        Ok(parent)
    }

    fn leaf(
        &mut self,
        parent: NodeId,
        kind: NodeKind<S>,
        range: Range<usize>,
        range_actionable: bool,
    ) -> Result<NodeId, ParseError> {
        self.admit_node()?;
        self.tree
            .push_with_actionability(Some(parent), kind, range, range_actionable)
    }

    fn admit_node(&self) -> Result<(), ParseError> {
        if self.tree.len() >= self.nodes_limit as usize {
            Err(ParseError::NodesLimitReached)
        } else {
            Ok(())
        }
    }

    fn admit_text(&self, parent: NodeId) -> Result<(), ParseError> {
        if self.tree.len() < self.nodes_limit as usize || self.tree.has_text_tail(parent) {
            return Ok(());
        }
        Err(ParseError::NodesLimitReached)
    }
}

impl<S: NameStorage> Tree<S> for Semantic<'_, S> {
    type Node = NodeId;
    type Base = Self;
    const DOCTYPE: bool = false;

    fn root(&self) -> NodeId {
        self.root
    }
    fn base(&mut self) -> &mut Self {
        self
    }
    fn expansion(&self) -> Option<Range<usize>> {
        None
    }
    fn declaration(&mut self, _: S::Text, _: Option<S::Text>, _: Option<bool>) {}
    fn push(
        &mut self,
        parent: NodeId,
        kind: XmloxNodeKind<S>,
        span: Span,
    ) -> Result<NodeId, ParseError> {
        let actionable = !span.expanded;
        match kind {
            kind @ XmloxNodeKind::Element { .. } => {
                Ok(self.element(parent, kind, span.range, actionable)?.0)
            }
            XmloxNodeKind::Text { content } => {
                // Whitespace outside the document element is not content.
                if parent == self.root {
                    self.tree.storage().charge(content.len())?;
                    if content.chars().all(char::is_whitespace) {
                        return Ok(parent);
                    }
                }
                self.text(parent, content, span.range, actionable)
            }
            XmloxNodeKind::CData { content } => self.text(parent, content, span.range, actionable),
            XmloxNodeKind::Comment { content } => {
                self.leaf(parent, NodeKind::Comment(content), span.range, actionable)
            }
            XmloxNodeKind::ProcessingInstruction { target, data } => self.leaf(
                parent,
                NodeKind::PI {
                    target,
                    value: data,
                },
                span.range,
                actionable,
            ),
            // A reference's content follows as its children, which belong to
            // the reference's parent here. Only an empty replacement has none;
            // it leaves an empty text no edit may split.
            XmloxNodeKind::EntityRef { value, .. } => match value {
                Some(value) if value.is_empty() => self.text(parent, value, span.range, false),
                _ => Ok(parent),
            },
            XmloxNodeKind::Document | XmloxNodeKind::DocumentType { .. } => Ok(parent),
        }
    }
    fn push_element(
        &mut self,
        parent: NodeId,
        element: XmloxNodeKind<S>,
        span: Span,
    ) -> Result<PushedElement<NodeId, S>, ParseError> {
        let (element, attributes) = self.element(parent, element, span.range, !span.expanded)?;
        Ok((element, Some(attributes)))
    }
    fn element_name(&self, element: NodeId) -> (Option<&str>, &str) {
        self.tree.element_name(element)
    }
    fn end_element(&mut self, element: NodeId, end: Option<usize>) {
        if let Some(end) = end {
            self.tree.end_range(element, end);
        }
        self.tree.finish_subtree(element);
    }
    fn finish(&mut self, _: S::Values<xmloxide::error::ParseDiagnostic<S::FrozenText>>) {}
}

/// What a namespace declaration attribute binds.
#[derive(Clone, Copy)]
enum Declared<'a> {
    Default,
    Prefix(&'a str),
}

impl<'a> Declared<'a> {
    fn prefix(self) -> Option<&'a str> {
        match self {
            Self::Default => None,
            Self::Prefix(prefix) => Some(prefix),
        }
    }
}

fn namespace_declaration<S: NameStorage>(
    attribute: &xmloxide::tree::Attribute<S>,
) -> Option<Declared<'_>> {
    if attribute.prefix.as_deref() == Some("xmlns") {
        Some(Declared::Prefix(&attribute.name))
    } else if attribute.prefix.is_none() && attribute.name.as_ref() == "xmlns" {
        Some(Declared::Default)
    } else {
        None
    }
}

fn set_namespace<S: Storage>(
    namespaces: &mut S::Values<NamespaceData<S>>,
    prefix: Option<&str>,
    uri: &str,
    storage: S,
) -> Result<(), ParseError> {
    for existing in namespaces.iter_mut() {
        storage.charge(1)?;
        storage.charge(prefix.map_or(0, str::len))?;
        if existing.prefix.as_deref() == prefix {
            existing.uri = storage.text(uri)?;
            return Ok(());
        }
    }
    namespaces.push(NamespaceData {
        prefix: storage.optional_text(prefix)?,
        uri: storage.text(uri)?,
    })?;
    Ok(())
}

#[cfg(test)]
mod tests;
