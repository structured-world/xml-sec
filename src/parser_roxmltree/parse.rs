use crate::xml::dom::storage::{Native, Storage, Values};
use alloc::borrow::Cow;
use alloc::string::{String, ToString};
use alloc::{vec, vec::Vec};
use core::fmt;
use core::mem::take;
use core::ops::Range;
use memchr::{memchr, memchr_iter, memchr2};

use crate::parser_roxmltree::{
    AttributeData, Document, ExpandedNameIndexed, NS_XML_PREFIX, NS_XML_URI, NS_XMLNS_URI,
    Namespace, NamespaceIdx, Namespaces, NodeData, NodeId, NodeKind, PI, ShortRange, StringStorage,
    TextPos, XMLNS,
};

use crate::parser_roxmltree::tokenizer::{self, Reference, StrSpan, Stream};

type Result<T, E = String> = core::result::Result<T, Error<E>>;
type ScopedResult<T, S> = Result<T, <S as Storage>::Text>;

/// A list of all possible errors.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Error<E = String> {
    AllocationFailed,
    #[cfg(feature = "xmldsig")]
    SharedExecution(structured_asn1::memory::MemoryError),
    /// The `xmlns:xml` attribute must have an <http://www.w3.org/XML/1998/namespace> URI.
    InvalidXmlPrefixUri(TextPos),

    /// Only the `xmlns:xml` attribute can have the <http://www.w3.org/XML/1998/namespace> URI.
    UnexpectedXmlUri(TextPos),

    /// The <http://www.w3.org/2000/xmlns/> URI must not be declared.
    UnexpectedXmlnsUri(TextPos),

    /// Namespaces in XML 1.0 forbids undeclaring a non-default prefix.
    EmptyPrefixedNamespace(TextPos),

    /// `xmlns` can't be used as an element prefix.
    InvalidElementNamePrefix(TextPos),

    /// A namespace was already defined on this element.
    DuplicatedNamespace(E, TextPos),

    /// An unknown namespace.
    ///
    /// Indicates that an element or an attribute has an unknown qualified name prefix.
    ///
    /// The first value is a prefix.
    UnknownNamespace(E, TextPos),

    /// Incorrect tree structure.
    ///
    /// expected, actual, position
    UnexpectedCloseTag(E, E, TextPos),

    /// Entity value starts with a close tag.
    ///
    /// Example:
    /// ```xml
    /// <!DOCTYPE test [ <!ENTITY p '</p>'> ]>
    /// <root>&p;</root>
    /// ```
    UnexpectedEntityCloseTag(TextPos),

    /// A reference to an entity that was not defined in the DTD.
    UnknownEntityReference(E, TextPos),

    /// A malformed entity reference.
    ///
    /// A `&` character inside an attribute value or text indicates an entity reference.
    /// Otherwise, the document is not well-formed.
    MalformedEntityReference(TextPos),

    /// A possible entity reference loop.
    ///
    /// The current depth limit is 10. The max number of references per reference is 255.
    EntityReferenceLoop(TextPos),

    /// Attribute value cannot have a `<` character.
    InvalidAttributeValue(TextPos),

    /// An element has a duplicated attributes.
    ///
    /// This also includes namespaces resolving.
    /// So an element like this will lead to an error.
    /// ```xml
    /// <e xmlns:n1='http://www.w3.org' xmlns:n2='http://www.w3.org' n1:a='b1' n2:a='b2'/>
    /// ```
    DuplicatedAttribute(E, TextPos),

    /// The XML document must have at least one element.
    NoRootNode,

    /// The root node was opened but never closed.
    UnclosedRootNode,

    /// An XML document can have only one XML declaration
    /// and it must be at the start of the document.
    UnexpectedDeclaration(TextPos),

    /// An XML with DTD detected.
    ///
    /// This error will be emitted only when `ParsingOptions::allow_dtd` is set to `false`.
    DtdDetected,

    /// Indicates that the [`ParsingOptions::nodes_limit`] was reached.
    NodesLimitReached,

    /// Indicates that too many attributes were parsed.
    AttributesLimitReached,

    /// Indicates that too many namespaces were parsed.
    NamespacesLimitReached,

    /// An invalid name.
    InvalidName(TextPos),

    /// A non-XML character has occurred.
    ///
    /// Valid characters are: <https://www.w3.org/TR/xml/#char32>
    NonXmlChar(char, TextPos),

    /// An invalid/unexpected character.
    ///
    /// expected, actual, position
    InvalidChar(u8, u8, TextPos),

    /// An invalid/unexpected character.
    ///
    /// expected, actual, position
    InvalidChar2(&'static str, u8, TextPos),

    /// An unexpected string.
    ///
    /// Contains what string was expected.
    InvalidString(&'static str, TextPos),

    /// An invalid `ExternalID` in the DTD.
    InvalidExternalID(TextPos),

    /// The given entity resolved yielded an errror.
    EntityResolver(TextPos, String),

    /// A comment cannot contain `--` or end with `-`.
    InvalidComment(TextPos),

    /// A Character Data node contains an invalid data.
    ///
    /// Currently, only `]]>` is not allowed.
    InvalidCharacterData(TextPos),

    /// An unknown token.
    UnknownToken(TextPos),

    /// The steam ended earlier than we expected.
    ///
    /// Should only appear on invalid input data.
    UnexpectedEndOfStream,
    /// A callback retained the original typed failure in its execution scope.
    ProcessingStopped,
}

impl<E> Error<E> {
    pub(crate) fn map_text<T>(self, mut map: impl FnMut(E) -> T) -> Error<T> {
        match self.try_map_text(|text| Ok::<_, core::convert::Infallible>(map(text))) {
            Ok(error) => error,
            Err(never) => match never {},
        }
    }

    pub(crate) fn try_map_text<T, F>(
        self,
        mut map: impl FnMut(E) -> core::result::Result<T, F>,
    ) -> core::result::Result<Error<T>, F> {
        Ok(match self {
            Self::AllocationFailed => Error::AllocationFailed,
            #[cfg(feature = "xmldsig")]
            Self::SharedExecution(error) => Error::SharedExecution(error),
            Self::InvalidXmlPrefixUri(pos) => Error::InvalidXmlPrefixUri(pos),
            Self::UnexpectedXmlUri(pos) => Error::UnexpectedXmlUri(pos),
            Self::UnexpectedXmlnsUri(pos) => Error::UnexpectedXmlnsUri(pos),
            Self::EmptyPrefixedNamespace(pos) => Error::EmptyPrefixedNamespace(pos),
            Self::InvalidElementNamePrefix(pos) => Error::InvalidElementNamePrefix(pos),
            Self::DuplicatedNamespace(name, pos) => Error::DuplicatedNamespace(map(name)?, pos),
            Self::UnknownNamespace(name, pos) => Error::UnknownNamespace(map(name)?, pos),
            Self::UnexpectedCloseTag(expected, actual, pos) => {
                Error::UnexpectedCloseTag(map(expected)?, map(actual)?, pos)
            }
            Self::UnexpectedEntityCloseTag(pos) => Error::UnexpectedEntityCloseTag(pos),
            Self::UnknownEntityReference(name, pos) => {
                Error::UnknownEntityReference(map(name)?, pos)
            }
            Self::MalformedEntityReference(pos) => Error::MalformedEntityReference(pos),
            Self::EntityReferenceLoop(pos) => Error::EntityReferenceLoop(pos),
            Self::InvalidAttributeValue(pos) => Error::InvalidAttributeValue(pos),
            Self::DuplicatedAttribute(name, pos) => Error::DuplicatedAttribute(map(name)?, pos),
            Self::NoRootNode => Error::NoRootNode,
            Self::UnclosedRootNode => Error::UnclosedRootNode,
            Self::UnexpectedDeclaration(pos) => Error::UnexpectedDeclaration(pos),
            Self::DtdDetected => Error::DtdDetected,
            Self::NodesLimitReached => Error::NodesLimitReached,
            Self::AttributesLimitReached => Error::AttributesLimitReached,
            Self::NamespacesLimitReached => Error::NamespacesLimitReached,
            Self::InvalidName(pos) => Error::InvalidName(pos),
            Self::NonXmlChar(character, pos) => Error::NonXmlChar(character, pos),
            Self::InvalidChar(expected, actual, pos) => Error::InvalidChar(expected, actual, pos),
            Self::InvalidChar2(expected, actual, pos) => Error::InvalidChar2(expected, actual, pos),
            Self::InvalidString(expected, pos) => Error::InvalidString(expected, pos),
            Self::InvalidExternalID(pos) => Error::InvalidExternalID(pos),
            Self::EntityResolver(pos, message) => Error::EntityResolver(pos, message),
            Self::InvalidComment(pos) => Error::InvalidComment(pos),
            Self::InvalidCharacterData(pos) => Error::InvalidCharacterData(pos),
            Self::UnknownToken(pos) => Error::UnknownToken(pos),
            Self::UnexpectedEndOfStream => Error::UnexpectedEndOfStream,
            Self::ProcessingStopped => Error::ProcessingStopped,
        })
    }
    /// Returns the error position.
    pub fn pos(&self) -> TextPos {
        match *self {
            Error::AllocationFailed => TextPos::new(1, 1),
            #[cfg(feature = "xmldsig")]
            Error::SharedExecution(_) => TextPos::new(1, 1),
            Error::InvalidXmlPrefixUri(pos) => pos,
            Error::UnexpectedXmlUri(pos) => pos,
            Error::UnexpectedXmlnsUri(pos) => pos,
            Error::EmptyPrefixedNamespace(pos) => pos,
            Error::InvalidElementNamePrefix(pos) => pos,
            Error::DuplicatedNamespace(_, pos) => pos,
            Error::UnknownNamespace(_, pos) => pos,
            Error::UnexpectedCloseTag(_, _, pos) => pos,
            Error::UnexpectedEntityCloseTag(pos) => pos,
            Error::UnknownEntityReference(_, pos) => pos,
            Error::MalformedEntityReference(pos) => pos,
            Error::EntityReferenceLoop(pos) => pos,
            Error::InvalidAttributeValue(pos) => pos,
            Error::DuplicatedAttribute(_, pos) => pos,
            Error::NoRootNode => TextPos::new(1, 1),
            Error::UnclosedRootNode => TextPos::new(1, 1),
            Error::UnexpectedDeclaration(pos) => pos,
            Error::DtdDetected => TextPos::new(1, 1),
            Error::NodesLimitReached => TextPos::new(1, 1),
            Error::AttributesLimitReached => TextPos::new(1, 1),
            Error::NamespacesLimitReached => TextPos::new(1, 1),
            Error::InvalidName(pos) => pos,
            Error::NonXmlChar(_, pos) => pos,
            Error::InvalidChar(_, _, pos) => pos,
            Error::InvalidChar2(_, _, pos) => pos,
            Error::InvalidString(_, pos) => pos,
            Error::InvalidExternalID(pos) => pos,
            Error::EntityResolver(pos, _) => pos,
            Error::InvalidComment(pos) => pos,
            Error::InvalidCharacterData(pos) => pos,
            Error::UnknownToken(pos) => pos,
            Error::UnexpectedEndOfStream => TextPos::new(1, 1),
            Error::ProcessingStopped => TextPos::new(1, 1),
        }
    }
}

impl<E: fmt::Display> core::fmt::Display for Error<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::AllocationFailed => f.write_str("XML parser allocation failed"),
            Error::ProcessingStopped => f.write_str("XML callback processing stopped"),
            #[cfg(feature = "xmldsig")]
            Error::SharedExecution(error) => write!(f, "XML parser execution: {error}"),
            Error::InvalidXmlPrefixUri(pos) => {
                write!(f, "'xml' namespace prefix mapped to wrong URI at {pos}")
            }
            Error::EmptyPrefixedNamespace(pos) => {
                write!(
                    f,
                    "a namespace prefix cannot be undeclared in XML 1.0 at {pos}"
                )
            }
            Error::UnexpectedXmlUri(pos) => {
                write!(
                    f,
                    "the 'xml' namespace URI is used for not 'xml' prefix at {pos}"
                )
            }
            Error::UnexpectedXmlnsUri(pos) => {
                write!(
                    f,
                    "the 'xmlns' URI is used at {pos}, but it must not be declared"
                )
            }
            Error::InvalidElementNamePrefix(pos) => {
                write!(f, "the 'xmlns' prefix is used at {pos}, but it must not be")
            }
            Error::DuplicatedNamespace(name, pos) => {
                write!(f, "namespace '{name}' at {pos} is already defined")
            }
            Error::UnknownNamespace(name, pos) => {
                write!(f, "an unknown namespace prefix '{name}' at {pos}")
            }
            Error::UnexpectedCloseTag(expected, actual, pos) => {
                write!(f, "expected '{expected}' tag, not '{actual}' at {pos}")
            }
            Error::UnexpectedEntityCloseTag(pos) => write!(f, "unexpected close tag at {pos}"),
            Error::MalformedEntityReference(pos) => {
                write!(f, "malformed entity reference at {pos}")
            }
            Error::UnknownEntityReference(name, pos) => {
                write!(f, "unknown entity reference '{name}' at {pos}")
            }
            Error::EntityReferenceLoop(pos) => {
                write!(f, "a possible entity reference loop is detected at {pos}")
            }
            Error::InvalidAttributeValue(pos) => write!(f, "unescaped '<' found at {pos}"),
            Error::DuplicatedAttribute(name, pos) => {
                write!(f, "attribute '{name}' at {pos} is already defined")
            }
            Error::NoRootNode => f.write_str("the document does not have a root node"),
            Error::UnclosedRootNode => f.write_str("the root node was opened but never closed"),
            Error::UnexpectedDeclaration(pos) => write!(f, "unexpected XML declaration at {pos}"),
            Error::DtdDetected => f.write_str("XML with DTD detected"),
            Error::NodesLimitReached => f.write_str("nodes limit reached"),
            Error::AttributesLimitReached => f.write_str("more than 2^32 attributes were parsed"),
            Error::NamespacesLimitReached => {
                f.write_str("more than 2^16 unique namespaces were parsed")
            }
            Error::InvalidName(pos) => write!(f, "invalid name token at {pos}"),
            Error::NonXmlChar(c, pos) => write!(f, "a non-XML character {c:?} found at {pos}"),
            Error::InvalidChar(expected, actual, pos) => {
                write!(
                    f,
                    "expected '{}' not '{}' at {pos}",
                    *expected as char, *actual as char
                )
            }
            Error::InvalidChar2(expected, actual, pos) => {
                write!(f, "expected {expected} not '{}' at {pos}", *actual as char)
            }
            Error::InvalidString(expected, pos) => write!(f, "expected '{expected}' at {pos}"),
            Error::InvalidExternalID(pos) => write!(f, "invalid ExternalID at {pos}"),
            Error::EntityResolver(pos, msg) => write!(f, "entity resolver failed at {pos}: {msg}"),
            Error::InvalidComment(pos) => write!(f, "comment at {pos} contains '--'"),
            Error::InvalidCharacterData(pos) => {
                write!(f, "']]>' at {pos} is not allowed inside a character data")
            }
            Error::UnknownToken(pos) => write!(f, "unknown token at {pos}"),
            Error::UnexpectedEndOfStream => f.write_str("unexpected end of stream"),
        }
    }
}

impl<E> From<crate::xml::dom::ParseError> for Error<E> {
    fn from(error: crate::xml::dom::ParseError) -> Self {
        match error {
            crate::xml::dom::ParseError::AllocationFailed => Self::AllocationFailed,
            #[cfg(feature = "xmldsig")]
            crate::xml::dom::ParseError::SharedExecution(error) => Self::SharedExecution(error),
            _ => unreachable!("XML storage strategy returns only allocation/execution failures"),
        }
    }
}

impl<E: fmt::Display + fmt::Debug> core::error::Error for Error<E> {}

/// Parsing options.
pub struct ParsingOptions<'input> {
    /// Allow DTD parsing.
    ///
    /// When set to `false`, XML with DTD will cause an error.
    /// Empty DTD block is not an error.
    ///
    /// Currently, there is no option to simply skip DTD.
    /// Mainly because you will get `UnknownEntityReference` error later anyway.
    ///
    /// This flag is set to `false` by default for security reasons,
    /// but `roxmltree` still has checks for billion laughs attack,
    /// so this is just an extra security measure.
    ///
    /// Default: false
    pub allow_dtd: bool,

    /// Sets the maximum number of nodes to parse.
    ///
    /// Useful when dealing with random input to limit memory usage.
    ///
    /// Default: `u32::MAX` (no limit)
    pub nodes_limit: u32,

    /// Function to resolve external entities
    ///
    /// See [`EntityResolver`] for the signature
    /// and the expected behaviour.
    pub entity_resolver: Option<&'input EntityResolver<'input>>,
}

/// Function to resolve external entities
///
/// This function is passed the optional public ID
/// and the mandatory URI of the external entity.
///
/// It is expected to yield the content defining
/// the URI, possibly preceeded by a text declaration.
///
/// If it yields [`None`], the entity is discarded
/// and will yield errors if referenced during parsing.
///
/// Errors must be stringified so they can be propagated
/// via [`Error::EntityResolver`].
pub type EntityResolver<'input> =
    dyn Fn(Option<&str>, &str) -> core::result::Result<Option<&'input str>, String> + 'input;

impl Default for ParsingOptions<'_> {
    fn default() -> Self {
        ParsingOptions {
            allow_dtd: false,
            nodes_limit: u32::MAX,
            entity_resolver: None,
        }
    }
}

impl fmt::Debug for ParsingOptions<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entity_resolver = if self.entity_resolver.is_some() {
            "Some(..)"
        } else {
            "None"
        };

        fmt.debug_struct("ParsingOptions")
            .field("allow_dtd", &self.allow_dtd)
            .field("nodes_limit", &self.nodes_limit)
            .field("entity_resolver", &entity_resolver)
            .finish()
    }
}

struct TempAttributeData<'input, S: Storage = Native> {
    prefix: &'input str,
    local: &'input str,
    value: StringStorage<'input, S>,
    range: Range<usize>,
    #[cfg(feature = "xml-backend-roxmltree")]
    qname_len: u16,
    #[cfg(feature = "xml-backend-roxmltree")]
    eq_len: u8,
}

/// An attribute resolved against the namespaces in scope, with its prefix.
struct ResolvedAttribute<'input, S: Storage = Native> {
    prefix: &'input str,
    data: AttributeData<'input, S>,
}

/// The tree a parse builds, node by node in document order.
pub(crate) trait Tree<'input, S: Storage> {
    /// A node that takes children.
    type Node: Copy;

    fn root(&self) -> Self::Node;
    /// Appends a start tag's element under `parent`; `range` covers the tag.
    fn element(
        &mut self,
        parent: Self::Node,
        element: Element<'_, 'input, S>,
        range: Range<usize>,
    ) -> ScopedResult<Self::Node, S>;
    /// Closes `element`. `end` is where its end tag ends, or `None` for an
    /// empty-element tag, whose range is already complete.
    fn end_element(&mut self, element: Self::Node, end: Option<usize>) -> ScopedResult<(), S>;
    /// Appends a text node, every adjacent fragment already joined in `text`.
    fn text(
        &mut self,
        parent: Self::Node,
        text: StringStorage<'input, S>,
        range: Range<usize>,
    ) -> ScopedResult<(), S>;
    fn comment(
        &mut self,
        parent: Self::Node,
        text: &'input str,
        range: Range<usize>,
    ) -> ScopedResult<(), S>;
    fn processing_instruction(
        &mut self,
        parent: Self::Node,
        pi: PI<'input>,
        range: Range<usize>,
    ) -> ScopedResult<(), S>;
}

/// A start tag as the parser resolved it, for its tree to take.
pub(crate) struct Element<'a, 'input, S: Storage = Native> {
    prefix: &'input str,
    tag_name: ExpandedNameIndexed<'input>,
    namespaces: ShortRange,
    attributes: &'a mut S::Values<ResolvedAttribute<'input, S>>,
    table: &'a Namespaces<'input, S>,
}

/// An attribute of an [`Element`], its value moved out of the parser.
pub(crate) struct ParsedAttribute<'a, 'input, S: Storage = Native> {
    pub(crate) prefix: Option<&'input str>,
    pub(crate) local: &'input str,
    pub(crate) namespace: Option<&'a str>,
    pub(crate) value: StringStorage<'input, S>,
}

impl<'a, 'input, S: Storage> Element<'a, 'input, S> {
    pub(crate) fn prefix(&self) -> Option<&'input str> {
        (!self.prefix.is_empty()).then_some(self.prefix)
    }

    pub(crate) fn local_name(&self) -> &'input str {
        self.tag_name.local_name
    }

    pub(crate) fn namespace(&self) -> Option<&'a str> {
        let table = self.table;
        self.tag_name.namespace_idx.map(|idx| table.get(idx).uri())
    }

    /// The namespaces in scope, the element's own declarations first.
    pub(crate) fn namespaces(
        &self,
    ) -> impl ExactSizeIterator<Item = &'a Namespace<'input, S>> + use<'a, 'input, S> {
        let table = self.table;
        table.tree_order[self.namespaces.to_urange()]
            .iter()
            .map(move |idx| table.get(*idx))
    }

    pub(crate) fn attribute_count(&self) -> usize {
        self.attributes.len()
    }

    /// Moves the attributes out in document order, leaving the parser's list
    /// empty for the next start tag.
    pub(crate) fn attributes(
        &mut self,
    ) -> core::result::Result<
        impl Iterator<Item = ParsedAttribute<'a, 'input, S>> + '_,
        crate::xml::dom::ParseError,
    > {
        let table = self.table;
        Ok(self
            .attributes
            .drain_all()?
            .map(move |attribute| ParsedAttribute {
                prefix: (!attribute.prefix.is_empty()).then_some(attribute.prefix),
                local: attribute.data.name.local_name,
                namespace: attribute
                    .data
                    .name
                    .namespace_idx
                    .map(|idx| table.get(idx).uri()),
                value: attribute.data.value,
            }))
    }
}

/// The parser's own read-only DOM as the tree it builds.
struct DocumentTree<'input, S: Storage = Native> {
    doc: Document<'input, S>,
    /// Nodes whose next subtree is the next node appended.
    awaiting_subtree: S::Values<NodeId>,
    storage: S,
}

impl<'input, S: Storage> DocumentTree<'input, S> {
    fn new(text: &'input str, storage: S) -> ScopedResult<Self, S> {
        // Trying to guess rough nodes and attributes amount.
        storage.charge(text.len())?;
        let nodes_capacity = memchr_iter(b'<', text.as_bytes()).count();
        storage.charge(text.len())?;
        let attributes_capacity = memchr_iter(b'=', text.as_bytes()).count();

        let mut doc = Document {
            text,
            nodes: storage.values(nodes_capacity)?,
            attributes: storage.values(attributes_capacity)?,
            namespaces: Namespaces::new(storage)?,
        };
        doc.nodes.push(NodeData {
            parent: None,
            prev_sibling: None,
            next_subtree: None,
            last_child: None,
            kind: NodeKind::Root,
            #[cfg(feature = "xml-backend-roxmltree")]
            range: 0..text.len(),
        })?;
        Ok(Self {
            doc,
            awaiting_subtree: storage.values(0)?,
            storage,
        })
    }

    fn append(
        &mut self,
        parent: NodeId,
        kind: NodeKind<'input, S>,
        range: Range<usize>,
    ) -> ScopedResult<NodeId, S> {
        #[cfg(not(feature = "xml-backend-roxmltree"))]
        let _ = range;

        let new_child_id = NodeId::from(self.doc.nodes.len());

        let appending_element = matches!(kind, NodeKind::Element { .. });
        self.doc.nodes.push(NodeData {
            parent: Some(parent),
            prev_sibling: None,
            next_subtree: None,
            last_child: None,
            kind,
            #[cfg(feature = "xml-backend-roxmltree")]
            range,
        })?;

        let last_child_id = self.doc.nodes[parent.get_usize()].last_child;
        self.doc.nodes[new_child_id.get_usize()].prev_sibling = last_child_id;
        self.doc.nodes[parent.get_usize()].last_child = Some(new_child_id);

        self.storage.charge(self.awaiting_subtree.len())?;
        for id in self.awaiting_subtree.iter() {
            self.doc.nodes[id.get_usize()].next_subtree = Some(new_child_id);
        }
        self.awaiting_subtree.clear();

        if !appending_element {
            self.awaiting_subtree.push(new_child_id)?;
        }

        Ok(new_child_id)
    }

    fn finish(mut self, namespaces: Namespaces<'input, S>) -> ScopedResult<Document<'input, S>, S> {
        self.doc.namespaces = namespaces;
        self.storage.finish_values(&mut self.doc.nodes);
        self.storage.finish_values(&mut self.doc.attributes);
        self.doc.namespaces.shrink_to_fit()?;
        Ok(self.doc)
    }
}

impl<'input, S: Storage> Tree<'input, S> for DocumentTree<'input, S> {
    type Node = NodeId;

    fn root(&self) -> NodeId {
        NodeId::new(0)
    }

    fn element(
        &mut self,
        parent: NodeId,
        element: Element<'_, 'input, S>,
        range: Range<usize>,
    ) -> ScopedResult<NodeId, S> {
        let start = self.doc.attributes.len();
        for attribute in element.attributes.drain_all()? {
            self.doc.attributes.push(attribute.data)?;
        }
        let attributes = if start == self.doc.attributes.len() {
            ShortRange::new(0, 0)
        } else {
            (start..self.doc.attributes.len()).into()
        };
        self.append(
            parent,
            NodeKind::Element {
                tag_name: element.tag_name,
                attributes,
                namespaces: element.namespaces,
            },
            range,
        )
    }

    fn end_element(&mut self, element: NodeId, end: Option<usize>) -> ScopedResult<(), S> {
        if let Some(end) = end {
            #[cfg(feature = "xml-backend-roxmltree")]
            {
                self.doc.nodes[element.get_usize()].range.end = end;
            }
            #[cfg(not(feature = "xml-backend-roxmltree"))]
            let _ = end;
        }
        // An empty element has no children to wait for; a closed one has
        // pushed all of them, so its next subtree is the next node either way.
        self.awaiting_subtree.push(element)?;
        Ok(())
    }

    fn text(
        &mut self,
        parent: NodeId,
        text: StringStorage<'input, S>,
        range: Range<usize>,
    ) -> ScopedResult<(), S> {
        self.append(parent, NodeKind::Text(text), range)?;
        Ok(())
    }

    fn comment(
        &mut self,
        parent: NodeId,
        text: &'input str,
        range: Range<usize>,
    ) -> ScopedResult<(), S> {
        self.append(
            parent,
            NodeKind::Comment(StringStorage::Borrowed(text)),
            range,
        )?;
        Ok(())
    }

    fn processing_instruction(
        &mut self,
        parent: NodeId,
        pi: PI<'input>,
        range: Range<usize>,
    ) -> ScopedResult<(), S> {
        self.append(parent, NodeKind::PI(pi), range)?;
        Ok(())
    }
}

impl<'input> Document<'input> {
    /// Parses the input XML string.
    ///
    /// We do not support `&[u8]` or `Reader` because the input must be an already allocated
    /// UTF-8 string.
    ///
    /// This is a shorthand for `Document::parse_with_options(data, ParsingOptions::default())`.
    ///
    /// # Examples
    ///
    /// ```text,xml-sec-example
    /// let doc = roxmltree::Document::parse("<e/>").unwrap();
    /// assert_eq!(doc.descendants().count(), 2); // root node + `e` element node
    /// ```
    #[inline]
    pub fn parse(text: &'input str) -> Result<Self> {
        Self::parse_with_options(text, ParsingOptions::default())
    }

    /// Parses the input XML string using to selected options.
    ///
    /// We do not support `&[u8]` or `Reader` because the input must be an already allocated
    /// UTF-8 string.
    ///
    /// # Examples
    ///
    /// ```text,xml-sec-example
    /// let opt = roxmltree::ParsingOptions::default();
    /// let doc = roxmltree::Document::parse_with_options("<e/>", opt).unwrap();
    /// assert_eq!(doc.descendants().count(), 2); // root node + `e` element node
    /// ```
    #[inline]
    pub fn parse_with_options(text: &'input str, opt: ParsingOptions<'input>) -> Result<Self> {
        parse_document(text, opt, Native)
    }
}

impl<'input, S: Storage> Document<'input, S> {
    pub(crate) fn parse_with_storage(
        text: &'input str,
        opt: ParsingOptions<'input>,
        storage: S,
    ) -> ScopedResult<Self, S> {
        parse_document(text, opt, storage)
    }
}

fn parse_document<'input, S: Storage>(
    text: &'input str,
    opt: ParsingOptions<'input>,
    storage: S,
) -> ScopedResult<Document<'input, S>, S> {
    let mut tree = DocumentTree::new(text, storage)?;
    let namespaces = parse_into(text, opt, storage, &mut tree)?;
    tree.finish(namespaces)
}

struct Entity<'input> {
    name: &'input str,
    value: StrSpan<'input>,
}

#[derive(Clone, Copy)]
struct TagNameSpan<'input> {
    prefix: &'input str,
    name: &'input str,
    pos: usize,
    prefix_pos: usize,
}

impl TagNameSpan<'_> {
    #[inline]
    fn new_null() -> Self {
        Self {
            prefix: "",
            name: "",
            pos: 0,
            prefix_pos: 0,
        }
    }
}

/// An entity loop detector.
///
/// Limits:
/// - Entities depth is 10.
/// - Maximum number of entity references per entity reference is 255.
///
/// Basically, if a text or an attribute has an entity reference and this reference
/// has more than 10 nested references - this is an error.
///
/// This is useful for simple loops like:
///
/// ```text
/// <!ENTITY a '&b;'>
/// <!ENTITY b '&a;'>
/// ```
///
/// And, if a text or an attribute has an entity reference and it references more
/// than 255 references - this is an error.
///
/// This is useful for cases like billion laughs attack, where depth can be pretty small,
/// but the number of references is exponentially increasing:
///
/// ```text
/// <!ENTITY lol "lol">
/// <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
/// <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
/// <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
/// <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
/// ```
#[derive(Default)]
struct LoopDetector {
    /// References depth.
    depth: u8,
    /// Number of references resolved by the root reference.
    references: u8,
}

impl LoopDetector {
    #[inline]
    fn inc_depth<E>(&mut self, stream: &Stream) -> Result<(), E> {
        if self.depth < 10 {
            self.depth += 1;
            Ok(())
        } else {
            Err(Error::EntityReferenceLoop(stream.gen_text_pos()))
        }
    }

    #[inline]
    fn dec_depth(&mut self) {
        if self.depth > 0 {
            self.depth -= 1;
        }

        // Reset references count after reaching zero depth.
        if self.depth == 0 {
            self.references = 0;
        }
    }

    #[inline]
    fn inc_references<E>(&mut self, stream: &Stream) -> Result<(), E> {
        if self.depth == 0 {
            // Allow infinite amount of references at zero depth.
            Ok(())
        } else {
            if self.references == u8::MAX {
                return Err(Error::EntityReferenceLoop(stream.gen_text_pos()));
            }

            self.references += 1;
            Ok(())
        }
    }
}

/// An element whose end tag the parser has not read yet.
struct Open<'input, N> {
    node: N,
    prefix: &'input str,
    local: &'input str,
    /// The namespaces in scope; the document root has none of its own.
    namespaces: Option<ShortRange>,
}

struct Context<'input, 't, S: Storage, T: Tree<'input, S>> {
    opt: ParsingOptions<'input>,
    text: &'input str,
    tree: &'t mut T,
    namespaces: Namespaces<'input, S>,
    namespace_start_idx: usize,
    current_attributes: S::Values<TempAttributeData<'input, S>>,
    /// The current start tag's attributes, resolved, until its tree takes them.
    attributes: S::Values<ResolvedAttribute<'input, S>>,
    /// Attributes of every element so far.
    attribute_count: usize,
    /// The document root, then each element still open.
    open: S::Values<Open<'input, T::Node>>,
    entities: S::Values<Entity<'input>>,
    /// The first fragment of a text node not appended yet, and its range.
    pending_text: Option<(StringStorage<'input, S>, Range<usize>)>,
    text_fragments: S::Values<StringStorage<'input, S>>,
    tag_name: TagNameSpan<'input>,
    loop_detector: LoopDetector,
    /// Nodes admitted so far, the root included.
    nodes: usize,
    has_root_element: bool,
    storage: S,
    failure: Option<Error<S::Text>>,
}

impl<'input, S: Storage, T: Tree<'input, S>> Context<'input, '_, S, T> {
    fn text_pos_at(&self, pos: usize) -> TextPos {
        tokenizer::Stream::new(self.text).gen_text_pos_from(pos)
    }

    fn parent(&self) -> T::Node {
        self.open
            .last()
            .expect("the document root is never closed")
            .node
    }

    /// Counts one more node, refusing it past the node limit.
    fn admit_node(&mut self) -> ScopedResult<(), S> {
        if self.nodes >= self.opt.nodes_limit as usize {
            return Err(Error::NodesLimitReached);
        }
        self.nodes += 1;
        Ok(())
    }

    fn append_text(
        &mut self,
        text: StringStorage<'input, S>,
        range: Range<usize>,
    ) -> ScopedResult<(), S> {
        if self.pending_text.is_some() {
            self.text_fragments.push(text)?;
        } else {
            // The text node is admitted at its first fragment and appended once
            // its last one is read; no other node comes between.
            self.admit_node()?;
            self.pending_text = Some((text, range));
        }
        Ok(())
    }

    #[cold]
    #[inline(never)]
    fn merge_text(
        &mut self,
        first: StringStorage<'input, S>,
    ) -> ScopedResult<StringStorage<'input, S>, S> {
        self.storage.charge(self.text_fragments.len())?;
        let additional = self
            .text_fragments
            .iter()
            .try_fold(0usize, |length, part| length.checked_add(part.len()))
            .expect("coalesced text length fits the bounded source layout");
        let mut value = match first {
            StringStorage::Owned(value) => {
                let mut value = value;
                self.storage.reserve_text(&mut value, additional)?;
                value
            }
            StringStorage::Borrowed(first) => {
                let capacity = first
                    .len()
                    .checked_add(additional)
                    .expect("coalesced text length fits the bounded source layout");
                let mut value = self.storage.text("")?;
                self.storage.reserve_text(&mut value, capacity)?;
                self.storage.append(&mut value, first)?;
                value
            }
        };
        for fragment in self.text_fragments.drain_all()? {
            self.storage.append(&mut value, fragment.as_str())?;
        }
        Ok(StringStorage::from_owned(value))
    }

    /// Appends the pending text node, its fragments joined.
    #[inline]
    fn reset_after_text(&mut self) -> ScopedResult<(), S> {
        let Some((text, range)) = self.pending_text.take() else {
            return Ok(());
        };
        let text = if self.text_fragments.is_empty() {
            text
        } else {
            self.merge_text(text)?
        };
        let parent = self.parent();
        self.tree.text(parent, text, range)
    }
}

/// Parses `text` into `tree`, returning the namespace table its elements
/// index.
pub(crate) fn parse_into<'input, S: Storage, T: Tree<'input, S>>(
    text: &'input str,
    opt: ParsingOptions<'input>,
    storage: S,
    tree: &mut T,
) -> ScopedResult<Namespaces<'input, S>, S> {
    let mut namespaces = Namespaces::new(storage)?;
    namespaces.push_ns(Some(NS_XML_PREFIX), StringStorage::Borrowed(NS_XML_URI))?;

    let allow_dtd = opt.allow_dtd;

    let mut open = storage.values(1)?;
    open.push(Open {
        node: tree.root(),
        prefix: "",
        local: "",
        namespaces: None,
    })?;
    let mut ctx = Context {
        opt,
        text,
        tree,
        namespaces,
        namespace_start_idx: 1,
        current_attributes: storage.values(0)?,
        attributes: storage.values(0)?,
        attribute_count: 0,
        open,
        entities: storage.values(0)?,
        pending_text: None,
        text_fragments: storage.values(0)?,
        tag_name: TagNameSpan::new_null(),
        loop_detector: LoopDetector::default(),
        nodes: 1,
        has_root_element: false,
        storage,
        failure: None,
    };

    // One lexical walk and the first fatal diagnostic's row/column walks are
    // bounded by this actual input. Internal entity walks are admitted below.
    storage.charge(text.len())?;
    storage.charge(text.len())?;
    storage.charge(text.len())?;
    let parsed = tokenizer::parse(text, allow_dtd, &mut ctx);
    if let Some(error) = ctx.failure.take() {
        return Err(error);
    }
    parsed.map_err(|error| adopt_error(error, storage))?;

    ctx.reset_after_text()?;
    storage.charge(ctx.nodes)?;
    if !ctx.has_root_element {
        return Err(Error::NoRootNode);
    }

    if ctx.open.len() > 1 {
        return Err(Error::UnclosedRootNode);
    }

    Ok(ctx.namespaces)
}

impl<'input, S: Storage, T: Tree<'input, S>> tokenizer::XmlEvents<'input>
    for Context<'input, '_, S, T>
{
    #[inline]
    fn token(&mut self, token: tokenizer::Token<'input>) -> Result<()> {
        if self.failure.is_some() {
            return Err(Error::ProcessingStopped);
        }
        match self.process_token(token) {
            Ok(()) => Ok(()),
            Err(error) => {
                if self.failure.is_none() {
                    self.failure = Some(error);
                }
                Err(Error::ProcessingStopped)
            }
        }
    }

    fn resolve_entity(
        &mut self,
        pub_id: Option<&str>,
        uri: &str,
    ) -> core::result::Result<Option<&'input str>, String> {
        match &mut self.opt.entity_resolver {
            Some(entity_resolver) => entity_resolver(pub_id, uri),
            None => Ok(None),
        }
    }
}

fn adopt_error<S: Storage>(error: Error, storage: S) -> Error<S::Text> {
    match error.try_map_text(|text| storage.text(&text)) {
        Ok(error) => error,
        Err(error) => error.into(),
    }
}

impl<'input, S: Storage, T: Tree<'input, S>> Context<'input, '_, S, T> {
    fn process_token(&mut self, token: tokenizer::Token<'input>) -> ScopedResult<(), S> {
        match token {
            tokenizer::Token::ProcessingInstruction(target, value, range) => {
                self.reset_after_text()?;
                self.admit_node()?;
                let parent = self.parent();
                self.tree
                    .processing_instruction(parent, PI { target, value }, range)?;
            }
            tokenizer::Token::Comment(text, range) => {
                self.reset_after_text()?;
                self.admit_node()?;
                let parent = self.parent();
                self.tree.comment(parent, text, range)?;
            }
            tokenizer::Token::EntityDeclaration(name, definition) => {
                self.entities.push(Entity {
                    name,
                    value: definition,
                })?;
            }
            tokenizer::Token::ElementStart(prefix, local, start) => {
                self.reset_after_text()?;

                if prefix == XMLNS {
                    let pos = self.text_pos_at(start + 1);
                    return Err(Error::InvalidElementNamePrefix(pos));
                }

                self.tag_name = TagNameSpan {
                    prefix,
                    name: local,
                    pos: start,
                    prefix_pos: start + 1,
                };
            }
            tokenizer::Token::Attribute(range, qname_len, eq_len, prefix, local, value) => {
                process_attribute(range, qname_len, eq_len, prefix, local, value, self)?;
            }
            tokenizer::Token::ElementEnd(end, range) => {
                self.reset_after_text()?;
                process_element(end, range, self)?;
            }
            tokenizer::Token::Text(text, range) => {
                process_text(text, range, self)?;
            }
            tokenizer::Token::Cdata(text, range) => {
                process_cdata(text, range, self)?;
            }
        }

        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn process_attribute<'input, S: Storage, T: Tree<'input, S>>(
    range: Range<usize>,
    qname_len: u16,
    eq_len: u8,
    prefix: &'input str,
    local: &'input str,
    value: StrSpan<'input>,
    ctx: &mut Context<'input, '_, S, T>,
) -> ScopedResult<(), S> {
    let value = normalize_attribute(value, ctx)?;

    if prefix == XMLNS {
        // Namespaces in XML 1.0 Third Edition §5, No Prefix Undeclaring:
        // a prefixed namespace declaration's attribute value MUST NOT be empty.
        // Default xmlns="" remains permitted by §6.2.
        // https://www.w3.org/TR/2009/REC-xml-names-20091208/#nsc-NoPrefixUndecl
        if value.as_str().is_empty() {
            return Err(Error::EmptyPrefixedNamespace(ctx.text_pos_at(range.start)));
        }
        // The xmlns namespace MUST NOT be declared as the default namespace.
        if value.as_str() == NS_XMLNS_URI {
            let pos = ctx.text_pos_at(range.start);
            return Err(Error::UnexpectedXmlnsUri(pos));
        }

        let is_xml_ns_uri = value.as_str() == NS_XML_URI;

        // The prefix 'xml' is by definition bound to the namespace name
        // http://www.w3.org/XML/1998/namespace.
        // It MUST NOT be bound to any other namespace name.
        if local == NS_XML_PREFIX {
            if !is_xml_ns_uri {
                let pos = ctx.text_pos_at(range.start);
                return Err(Error::InvalidXmlPrefixUri(pos));
            }
        } else {
            // The xml namespace MUST NOT be bound to a non-xml prefix.
            if is_xml_ns_uri {
                let pos = ctx.text_pos_at(range.start);
                return Err(Error::UnexpectedXmlUri(pos));
            }
        }

        // Check for duplicated namespaces.
        if ctx
            .namespaces
            .exists(ctx.namespace_start_idx, Some(local))?
        {
            let pos = ctx.text_pos_at(range.start);
            return Err(Error::DuplicatedNamespace(ctx.storage.text(local)?, pos));
        }

        // Xml namespace should not be added to the namespaces.
        if !is_xml_ns_uri {
            ctx.namespaces.push_ns(Some(local), value)?;
        }
    } else if local == XMLNS {
        // The xml namespace MUST NOT be declared as the default namespace.
        if value.as_str() == NS_XML_URI {
            let pos = ctx.text_pos_at(range.start);
            return Err(Error::UnexpectedXmlUri(pos));
        }

        // The xmlns namespace MUST NOT be declared as the default namespace.
        if value.as_str() == NS_XMLNS_URI {
            let pos = ctx.text_pos_at(range.start);
            return Err(Error::UnexpectedXmlnsUri(pos));
        }

        ctx.namespaces.push_ns(None, value)?;
    } else {
        #[cfg(not(feature = "xml-backend-roxmltree"))]
        let _ = (qname_len, eq_len);

        ctx.current_attributes.push(TempAttributeData {
            prefix,
            local,
            value,
            range,
            #[cfg(feature = "xml-backend-roxmltree")]
            qname_len,
            #[cfg(feature = "xml-backend-roxmltree")]
            eq_len,
        })?;
    }

    Ok(())
}

fn process_element<'input, S: Storage, T: Tree<'input, S>>(
    end_token: tokenizer::ElementEnd<'input>,
    token_range: Range<usize>,
    ctx: &mut Context<'input, '_, S, T>,
) -> ScopedResult<(), S> {
    if ctx.tag_name.name.is_empty() {
        // May occur in XML like this:
        // <!DOCTYPE test [ <!ENTITY p '</p>'> ]>
        // <root>&p;</root>

        if let tokenizer::ElementEnd::Close(..) = end_token {
            return Err(Error::UnexpectedEntityCloseTag(
                ctx.text_pos_at(token_range.start),
            ));
        }
        unreachable!("should be already checked by the tokenizer");
    }

    let namespaces = ctx.resolve_namespaces()?;
    ctx.namespace_start_idx = ctx.namespaces.tree_order.len();

    resolve_attributes(namespaces, ctx)?;

    match end_token {
        tokenizer::ElementEnd::Empty => {
            let element = ctx.push_element(namespaces, token_range.end)?;
            ctx.tree.end_element(element, None)?;
        }
        tokenizer::ElementEnd::Close(prefix, local) => {
            if ctx.open.len() == 1 {
                // May occur in XML like this:
                // <!DOCTYPE test [ <!ENTITY p '<p></p></p>'> ]>
                // <p>&p;&p;

                return Err(Error::UnexpectedEntityCloseTag(
                    ctx.text_pos_at(token_range.start),
                ));
            }
            let open = ctx
                .open
                .last()
                .expect("an element is open above the document root");
            if prefix != open.prefix || local != open.local {
                return Err(Error::UnexpectedCloseTag(
                    gen_qname_string(open.prefix, open.local, ctx.storage)?,
                    gen_qname_string(prefix, local, ctx.storage)?,
                    ctx.text_pos_at(token_range.start),
                ));
            }
            let element = open.node;
            ctx.tree.end_element(element, Some(token_range.end))?;
            ctx.open.pop();
        }
        tokenizer::ElementEnd::Open => {
            let element = ctx.push_element(namespaces, token_range.end)?;
            ctx.open.push(Open {
                node: element,
                prefix: ctx.tag_name.prefix,
                local: ctx.tag_name.name,
                namespaces: Some(namespaces),
            })?;
        }
    }

    Ok(())
}

impl<'input, S: Storage, T: Tree<'input, S>> Context<'input, '_, S, T> {
    fn resolve_namespaces(&mut self) -> ScopedResult<ShortRange, S> {
        let parent = self
            .open
            .last()
            .expect("the document root is never closed")
            .namespaces;
        if let Some(parent_ns) = parent {
            if self.namespace_start_idx == self.namespaces.tree_order.len() {
                return Ok(parent_ns);
            }

            for i in parent_ns.to_urange() {
                if !self.namespaces.exists(
                    self.namespace_start_idx,
                    self.namespaces.get(self.namespaces.tree_order[i]).name,
                )? {
                    self.namespaces.push_ref(i)?;
                }
            }
        }

        Ok((self.namespace_start_idx..self.namespaces.tree_order.len()).into())
    }

    /// Hands the current start tag, which ends at `end`, to the tree.
    fn push_element(&mut self, namespaces: ShortRange, end: usize) -> ScopedResult<T::Node, S> {
        let tag_ns_idx = get_ns_idx_by_prefix(
            namespaces,
            self.tag_name.prefix_pos,
            self.tag_name.prefix,
            &self.namespaces,
            self.text,
        )?;
        self.admit_node()?;
        let parent = self.parent();
        self.has_root_element |= self.open.len() == 1;
        self.tree.element(
            parent,
            Element {
                prefix: self.tag_name.prefix,
                tag_name: ExpandedNameIndexed {
                    namespace_idx: tag_ns_idx,
                    local_name: self.tag_name.name,
                },
                namespaces,
                attributes: &mut self.attributes,
                table: &self.namespaces,
            },
            self.tag_name.pos..end,
        )
    }
}

fn resolve_attributes<'input, S: Storage, T: Tree<'input, S>>(
    namespaces: ShortRange,
    ctx: &mut Context<'input, '_, S, T>,
) -> ScopedResult<(), S> {
    debug_assert!(ctx.attributes.is_empty());
    if ctx.current_attributes.is_empty() {
        return Ok(());
    }

    if ctx.attribute_count + ctx.current_attributes.len() >= u32::MAX as usize {
        return Err(Error::AttributesLimitReached);
    }
    ctx.attribute_count += ctx.current_attributes.len();

    for attr in ctx.current_attributes.drain_all()? {
        let namespace_idx = if attr.prefix == NS_XML_PREFIX {
            // The prefix 'xml' is by definition bound to the namespace name
            // http://www.w3.org/XML/1998/namespace. This namespace is added
            // to the document on creation and is always element 0.
            Some(NamespaceIdx(0))
        } else if attr.prefix.is_empty() {
            // 'The namespace name for an unprefixed attribute name
            // always has no value.'
            None
        } else {
            get_ns_idx_by_prefix(
                namespaces,
                attr.range.start,
                attr.prefix,
                &ctx.namespaces,
                ctx.text,
            )?
        };

        let attr_name = ExpandedNameIndexed {
            namespace_idx,
            local_name: attr.local,
        };

        // Check for duplicated attributes.
        let current_uri = attr_name.namespace_uri(&ctx.namespaces);
        for previous in ctx.attributes.iter() {
            let previous_uri = previous.data.name.namespace_uri(&ctx.namespaces);
            if equal_text(previous.data.name.local_name, attr.local, ctx.storage)?
                && previous_uri.is_some() == current_uri.is_some()
                && equal_text(
                    previous_uri.unwrap_or(""),
                    current_uri.unwrap_or(""),
                    ctx.storage,
                )?
            {
                let pos = tokenizer::Stream::new(ctx.text).gen_text_pos_from(attr.range.start);
                return Err(Error::DuplicatedAttribute(
                    ctx.storage.text(attr.local)?,
                    pos,
                ));
            }
        }

        ctx.attributes.push(ResolvedAttribute {
            prefix: attr.prefix,
            data: AttributeData {
                name: attr_name,
                value: attr.value,
                #[cfg(feature = "xml-backend-roxmltree")]
                range: attr.range,
                #[cfg(feature = "xml-backend-roxmltree")]
                qname_len: attr.qname_len,
                #[cfg(feature = "xml-backend-roxmltree")]
                eq_len: attr.eq_len,
            },
        })?;
    }

    Ok(())
}

fn process_text<'input, S: Storage, T: Tree<'input, S>>(
    text: &'input str,
    range: Range<usize>,
    ctx: &mut Context<'input, '_, S, T>,
) -> ScopedResult<(), S> {
    // Add text as is if it has only valid characters.
    ctx.storage.charge(text.len())?;
    if memchr2(b'&', b'\r', text.as_bytes()).is_none() {
        ctx.append_text(StringStorage::Borrowed(text), range)?;
        return Ok(());
    }

    let mut text_buffer = TextBuffer::new(ctx.storage)?;
    ctx.storage.charge(text.len())?;
    let mut is_as_is = false; // TODO: explain
    let mut stream = Stream::from_substr(ctx.text, range.clone());
    while !stream.at_end() {
        match parse_next_chunk(&mut stream, &ctx.entities, ctx.storage)? {
            NextChunk::Byte(c) => {
                if is_as_is {
                    text_buffer.push_raw(c)?;
                    is_as_is = false;
                } else {
                    text_buffer.push_from_text(c, stream.at_end())?;
                }
            }
            NextChunk::Char(c) => {
                for b in CharToBytes::new(c) {
                    if ctx.loop_detector.depth > 0 {
                        text_buffer.push_from_text(b, stream.at_end())?;
                    } else {
                        // Characters not from entity should be added as is.
                        // Not sure why... At least `lxml` produces the same result.
                        text_buffer.push_raw(b)?;
                        is_as_is = true;
                    }
                }
            }
            NextChunk::Text(fragment) => {
                is_as_is = false;

                if !text_buffer.is_empty() {
                    ctx.append_text(StringStorage::Owned(text_buffer.finish()?), range.clone())?;
                }

                ctx.loop_detector.inc_references(&stream)?;
                ctx.loop_detector.inc_depth(&stream)?;

                let text = if fragment.range().start == 0 {
                    fragment.as_str()
                } else {
                    ctx.text
                };

                let mut stream = Stream::from_substr(text, fragment.range());
                let prev_tag_name = ctx.tag_name;
                ctx.tag_name = TagNameSpan::new_null();
                ctx.storage.charge(fragment.range().len())?;
                tokenizer::parse_content(&mut stream, ctx)
                    .map_err(|error| adopt_error(error, ctx.storage))?;
                ctx.tag_name = prev_tag_name;
                text_buffer.clear();

                ctx.loop_detector.dec_depth();
            }
        }
    }

    if !text_buffer.is_empty() {
        ctx.append_text(StringStorage::Owned(text_buffer.finish()?), range)?;
    }

    Ok(())
}

// While the whole purpose of CDATA is to indicate to an XML library that this text
// has to be stored as is, carriage return (`\r`) is still has to be replaced with `\n`.
fn process_cdata<'input, S: Storage, T: Tree<'input, S>>(
    mut text: &'input str,
    range: Range<usize>,
    ctx: &mut Context<'input, '_, S, T>,
) -> ScopedResult<(), S> {
    ctx.storage.charge(text.len())?;
    let mut pos = memchr(b'\r', text.as_bytes());

    // Add text as is if it has only valid characters.
    if pos.is_none() {
        ctx.append_text(StringStorage::Borrowed(text), range)?;
        return Ok(());
    }

    let mut buf = ctx.storage.values(text.len())?;

    while let Some(pos1) = pos {
        let (line, rest) = text.split_at(pos1);

        buf.extend_copy(line.as_bytes())?;
        buf.push(b'\n')?;

        text = if rest.as_bytes().get(1) == Some(&b'\n') {
            &rest[2..]
        } else {
            &rest[1..]
        };

        pos = memchr(b'\r', text.as_bytes());
    }

    buf.extend_copy(text.as_bytes())?;

    ctx.append_text(StringStorage::Owned(ctx.storage.finish_bytes(buf)?), range)?;
    Ok(())
}

enum NextChunk<'a> {
    Byte(u8),
    Char(char),
    Text(StrSpan<'a>),
}

fn equal_text<S: Storage>(left: &str, right: &str, storage: S) -> ScopedResult<bool, S> {
    storage.charge(1)?;
    if left.len() != right.len() {
        return Ok(false);
    }
    storage.charge(left.len())?;
    Ok(left == right)
}

fn find_entity<'input, S: Storage>(
    entities: &[Entity<'input>],
    name: &str,
    storage: S,
) -> ScopedResult<Option<StrSpan<'input>>, S> {
    for entity in entities {
        if equal_text(entity.name, name, storage)? {
            return Ok(Some(entity.value));
        }
    }
    Ok(None)
}

fn parse_next_chunk<'a, S: Storage>(
    stream: &mut Stream<'a>,
    entities: &[Entity<'a>],
    storage: S,
) -> ScopedResult<NextChunk<'a>, S> {
    debug_assert!(!stream.at_end());

    // Safe, because we already checked that stream is not at the end.
    // But we have an additional `debug_assert` above just in case.
    let c = stream.curr_byte_unchecked();

    // Check for character/entity references.
    if c == b'&' {
        let start = stream.pos();
        match stream.consume_reference() {
            Some(Reference::Char(ch)) => Ok(NextChunk::Char(ch)),
            Some(Reference::Entity(name)) => find_entity(entities, name, storage)?
                .map(NextChunk::Text)
                .ok_or_else(|| {
                    let pos = stream.gen_text_pos_from(start);
                    match storage.text(name) {
                        Ok(name) => Error::UnknownEntityReference(name, pos),
                        Err(error) => error.into(),
                    }
                }),
            None => {
                let pos = stream.gen_text_pos_from(start);
                Err(Error::MalformedEntityReference(pos))
            }
        }
    } else {
        stream.advance(1);
        Ok(NextChunk::Byte(c))
    }
}

// https://www.w3.org/TR/REC-xml/#AVNormalize
fn normalize_attribute<'input, S: Storage, T: Tree<'input, S>>(
    text: StrSpan<'input>,
    ctx: &mut Context<'input, '_, S, T>,
) -> ScopedResult<StringStorage<'input, S>, S> {
    // We assume that `&` indicates an entity or a character reference.
    // But in rare cases it can be just an another character.
    ctx.storage.charge(text.as_str().len())?;
    ctx.storage.charge(text.as_str().len())?;
    if memchr2(b'&', b'\t', text.as_str().as_bytes()).is_some()
        || memchr2(b'\n', b'\r', text.as_str().as_bytes()).is_some()
    {
        let mut text_buffer = TextBuffer::new(ctx.storage)?;
        normalize_attribute_into(text, &mut text_buffer, ctx)?;
        Ok(StringStorage::from_owned(text_buffer.finish()?))
    } else {
        Ok(StringStorage::Borrowed(text.as_str()))
    }
}

fn normalize_attribute_into<'input, S: Storage, T: Tree<'input, S>>(
    text: StrSpan,
    buffer: &mut TextBuffer<S>,
    ctx: &mut Context<'input, '_, S, T>,
) -> ScopedResult<(), S> {
    ctx.storage.charge(text.as_str().len())?;
    let mut stream = Stream::from_substr(ctx.text, text.range());
    while !stream.at_end() {
        // Safe, because we already checked that the stream is not at the end.
        let c = stream.curr_byte_unchecked();

        if c != b'&' {
            stream.advance(1);
            buffer.push_from_attr(c, stream.curr_byte().ok())?;
            continue;
        }

        // Check for character/entity references.
        let start = stream.pos();
        match stream.consume_reference() {
            Some(Reference::Char(ch)) => {
                for b in CharToBytes::new(ch) {
                    if ctx.loop_detector.depth > 0 {
                        // Escaped `<` inside an ENTITY is an error.
                        // Escaped `<` outside an ENTITY is ok.
                        if b == b'<' {
                            return Err(Error::InvalidAttributeValue(
                                stream.gen_text_pos_from(start),
                            ));
                        }

                        buffer.push_from_attr(b, None)?;
                    } else {
                        // XML 1.0 §3.3.3 appends a character reference's character
                        // directly; whitespace replacement applies to literal text.
                        // https://www.w3.org/TR/2008/REC-xml-20081126/#AVNormalize
                        buffer.push_raw(b)?;
                    }
                }
            }
            Some(Reference::Entity(name)) => {
                if let Some(value) = find_entity(&ctx.entities, name, ctx.storage)? {
                    ctx.loop_detector.inc_references(&stream)?;
                    ctx.loop_detector.inc_depth(&stream)?;
                    normalize_attribute_into(value, buffer, ctx)?;
                    ctx.loop_detector.dec_depth();
                } else {
                    let pos = stream.gen_text_pos_from(start);
                    return Err(Error::UnknownEntityReference(ctx.storage.text(name)?, pos));
                }
            }
            None => {
                let pos = stream.gen_text_pos_from(start);
                return Err(Error::MalformedEntityReference(pos));
            }
        }
    }

    Ok(())
}

fn get_ns_idx_by_prefix<S: Storage>(
    namespaces: ShortRange,
    prefix_pos: usize,
    prefix: &str,
    table: &Namespaces<'_, S>,
    text: &str,
) -> ScopedResult<Option<NamespaceIdx>, S> {
    // Prefix CAN be empty when the default namespace was defined.
    //
    // Example:
    // <e xmlns='http://www.w3.org'/>
    let prefix_opt = if prefix.is_empty() {
        None
    } else {
        Some(prefix)
    };

    let mut idx = None;
    for candidate in &table.tree_order[namespaces.to_urange()] {
        let name = table.get(*candidate).name;
        table.storage.charge(1)?;
        if name.is_some() == prefix_opt.is_some()
            && equal_text(name.unwrap_or(""), prefix, table.storage)?
        {
            idx = Some(*candidate);
            break;
        }
    }

    match idx {
        Some(idx) => Ok(Some(idx)),
        None => {
            if prefix.is_empty() {
                // Without a default declaration, an unprefixed name has no namespace.
                Ok(None)
            } else {
                // If an URI was not found and prefix IS NOT empty than
                // we have an unknown namespace.
                //
                // Example:
                // <e random:a='b'/>
                let pos = tokenizer::Stream::new(text).gen_text_pos_from(prefix_pos);
                Err(Error::UnknownNamespace(table.storage.text(prefix)?, pos))
            }
        }
    }
}

fn gen_qname_string<S: Storage>(prefix: &str, local: &str, storage: S) -> ScopedResult<S::Text, S> {
    if prefix.is_empty() {
        Ok(storage.text(local)?)
    } else {
        let mut name = storage.text(prefix)?;
        storage.append(&mut name, ":")?;
        storage.append(&mut name, local)?;
        Ok(name)
    }
}

/// Iterate over `char` by `u8`.
struct CharToBytes {
    buf: [u8; 4],
    idx: u8,
}

impl CharToBytes {
    #[inline]
    fn new(c: char) -> Self {
        let mut buf = [0xFF; 4];
        c.encode_utf8(&mut buf);

        CharToBytes { buf, idx: 0 }
    }
}

impl Iterator for CharToBytes {
    type Item = u8;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.idx < 4 {
            let b = self.buf[self.idx as usize];

            if b == 0xFF {
                self.idx = 4;
            } else {
                self.idx += 1;
                return Some(b);
            }
        }

        None
    }
}

struct TextBuffer<S: Storage = Native> {
    buffer: S::Values<u8>,
    storage: S,
}

impl<S: Storage> TextBuffer<S> {
    #[inline]
    fn new(storage: S) -> ScopedResult<Self, S> {
        Ok(TextBuffer {
            buffer: storage.values(32)?,
            storage,
        })
    }

    #[inline]
    fn push_raw(&mut self, c: u8) -> ScopedResult<(), S> {
        Ok(self.buffer.push(c)?)
    }

    fn push_from_attr(&mut self, mut current: u8, next: Option<u8>) -> ScopedResult<(), S> {
        // \r in \r\n should be ignored.
        if current == b'\r' && next == Some(b'\n') {
            return Ok(());
        }

        // \n, \r and \t should be converted into spaces.
        current = match current {
            b'\n' | b'\r' | b'\t' => b' ',
            _ => current,
        };

        Ok(self.buffer.push(current)?)
    }

    // Translate \r\n and any \r that is not followed by \n into a single \n character.
    //
    // https://www.w3.org/TR/xml/#sec-line-ends
    fn push_from_text(&mut self, c: u8, at_end: bool) -> ScopedResult<(), S> {
        if self.buffer.last() == Some(&b'\r') {
            let idx = self.buffer.len() - 1;
            self.buffer[idx] = b'\n';

            if at_end && c == b'\r' {
                self.buffer.push(b'\n')?;
            } else if c != b'\n' {
                self.buffer.push(c)?;
            }
        } else if at_end && c == b'\r' {
            self.buffer.push(b'\n')?;
        } else {
            self.buffer.push(c)?;
        }
        Ok(())
    }

    #[inline]
    fn clear(&mut self) {
        self.buffer.clear();
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    #[inline]
    fn finish(&mut self) -> ScopedResult<S::Text, S> {
        let bytes = core::mem::replace(&mut self.buffer, self.storage.values(0)?);
        Ok(self.storage.finish_bytes(bytes)?)
    }
}
