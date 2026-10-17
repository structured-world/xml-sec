/*!
Represent an [XML](https://www.w3.org/TR/xml/) document as a read-only tree.

The root point of the documentations is [`Document::parse`].

You can find more details in the [README] and the [parsing doc].

The tree structure itself is a heavily modified <https://github.com/causal-agent/ego-tree>
License: ISC.

[`Document::parse`]: struct.Document.html#method.parse
[README]: https://github.com/RazrFalcon/roxmltree/blob/master/README.md
[parsing doc]: https://github.com/RazrFalcon/roxmltree/blob/master/docs/parsing.md
*/

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(missing_copy_implementations)]
#![warn(missing_debug_implementations)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use core::cmp::Ordering;
use core::fmt;
use core::hash::{Hash, Hasher};
use core::num::NonZeroU32;
use core::ops::Range;

use crate::xml::dom::storage::{Native, Storage, Values};
use alloc::vec::Vec;

mod parse;
mod tokenizer;

#[cfg(test)]
mod tokenizer_tests;

#[cfg(test)]
mod documentation_tests;

pub use crate::parser_roxmltree::parse::*;

/// The <http://www.w3.org/XML/1998/namespace> URI.
pub const NS_XML_URI: &str = "http://www.w3.org/XML/1998/namespace";
/// The prefix 'xml', which is by definition bound to NS_XML_URI
const NS_XML_PREFIX: &str = "xml";

/// The <http://www.w3.org/2000/xmlns/> URI.
pub const NS_XMLNS_URI: &str = "http://www.w3.org/2000/xmlns/";
/// The string 'xmlns', which is used to declare new namespaces
const XMLNS: &str = "xmlns";

/// Position in text.
///
/// Position indicates a row/line and a column in the original text. Starting from 1:1.
#[allow(missing_docs)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct TextPos {
    pub row: u32,
    pub col: u32,
}

impl TextPos {
    /// Constructs a new `TextPos`.
    pub fn new(row: u32, col: u32) -> TextPos {
        TextPos { row, col }
    }
}

impl fmt::Display for TextPos {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.row, self.col)
    }
}

/// An XML tree container.
///
/// A tree consists of [`Nodes`].
/// There are no separate structs for each node type.
/// So you should check the current node type yourself via [`Node::node_type()`].
/// There are only [5 types](enum.NodeType.html):
/// Root, Element, PI, Comment and Text.
///
/// As you can see there are no XML declaration and CDATA types.
/// The XML declaration is basically skipped, since it doesn't contain any
/// valuable information (we support only UTF-8 anyway).
/// And CDATA will be converted into a Text node as is, without
/// any preprocessing (you can read more about it
/// [here](https://github.com/RazrFalcon/roxmltree/blob/master/docs/parsing.md)).
///
/// Also, the Text node data can be accessed from the text node itself or from
/// the parent element via [`Node::text()`] or [`Node::tail()`].
///
/// [`Nodes`]: struct.Node.html
/// [`Node::node_type()`]: struct.Node.html#method.node_type
/// [`Node::text()`]: struct.Node.html#method.text
/// [`Node::tail()`]: struct.Node.html#method.tail
pub struct Document<'input, S: crate::xml::dom::storage::Storage = crate::xml::dom::storage::Native>
{
    /// An original data.
    ///
    /// Required for `text_pos_at` methods.
    text: &'input str,
    nodes: S::Values<NodeData<'input, S>>,
    attributes: S::Values<AttributeData<'input, S>>,
    namespaces: Namespaces<'input, S>,
}

impl<'input, S: crate::xml::dom::storage::Storage> Document<'input, S> {
    /// Returns the root node.
    ///
    /// # Examples
    ///
    /// ```text,xml-sec-example
    /// let doc = roxmltree::Document::parse("<e/>").unwrap();
    /// assert!(doc.root().is_root());
    /// assert!(doc.root().first_child().unwrap().has_tag_name("e"));
    /// ```
    #[inline]
    pub fn root<'a>(&'a self) -> Node<'a, 'input, S> {
        Node {
            id: NodeId::new(0),
            d: &self.nodes[0],
            doc: self,
        }
    }

    /// Returns the node of the tree with the given NodeId.
    ///
    /// Note: NodeId::new(0) represents the root node
    ///
    /// # Examples
    ///
    /// ```text,xml-sec-example
    /// let doc = roxmltree::Document::parse("\
    /// <p>
    ///     text
    /// </p>
    /// ").unwrap();
    ///
    /// use roxmltree::NodeId;
    /// assert_eq!(doc.get_node(NodeId::new(0)).unwrap(), doc.root());
    /// assert_eq!(doc.get_node(NodeId::new(1)), doc.descendants().find(|n| n.has_tag_name("p")));
    /// assert_eq!(doc.get_node(NodeId::new(2)), doc.descendants().find(|n| n.is_text()));
    /// assert_eq!(doc.get_node(NodeId::new(3)), None);
    /// ```
    #[inline]
    pub fn get_node<'a>(&'a self, id: NodeId) -> Option<Node<'a, 'input, S>> {
        self.nodes.get(id.get_usize()).map(|data| Node {
            id,
            d: data,
            doc: self,
        })
    }

    /// Returns the root element of the document.
    ///
    /// Unlike `root`, will return a first element node.
    ///
    /// The root element always exists.
    ///
    /// # Examples
    ///
    /// ```text,xml-sec-example
    /// let doc = roxmltree::Document::parse("<!-- comment --><e/>").unwrap();
    /// assert!(doc.root_element().has_tag_name("e"));
    /// ```
    #[inline]
    pub fn root_element<'a>(&'a self) -> Node<'a, 'input, S> {
        // `expect` is safe, because the `Document` is guarantee to have at least one element.
        self.root()
            .first_element_child()
            .expect("XML documents must contain a root element")
    }

    /// Returns an iterator over document's descendant nodes.
    ///
    /// Shorthand for `doc.root().descendants()`.
    #[inline]
    pub fn descendants(&self) -> Descendants<'_, 'input, S> {
        self.root().descendants()
    }

    /// Calculates `TextPos` in the original document from position in bytes.
    ///
    /// **Note:** this operation is expensive.
    ///
    /// # Examples
    ///
    /// ```text,xml-sec-example
    /// use roxmltree::*;
    ///
    /// let doc = Document::parse("\
    /// <!-- comment -->
    /// <e/>"
    /// ).unwrap();
    ///
    /// assert_eq!(doc.text_pos_at(10), TextPos::new(1, 11));
    /// assert_eq!(doc.text_pos_at(9999), TextPos::new(2, 5));
    /// ```
    #[inline]
    pub fn text_pos_at(&self, pos: usize) -> TextPos {
        tokenizer::Stream::new(self.text).gen_text_pos_from(pos)
    }

    /// Returns the input text of the original document.
    ///
    /// # Examples
    ///
    /// ```text,xml-sec-example
    /// use roxmltree::*;
    ///
    /// let doc = Document::parse("<e/>").unwrap();
    ///
    /// assert_eq!(doc.input_text(), "<e/>");
    /// ```
    #[inline]
    pub fn input_text(&self) -> &'input str {
        self.text
    }
}

impl<'input, S: crate::xml::dom::storage::Storage> fmt::Debug for Document<'input, S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        if !self.root().has_children() {
            return write!(f, "Document []");
        }

        macro_rules! writeln_indented {
            ($depth:expr, $f:expr, $fmt:expr) => {
                for _ in 0..$depth { write!($f, "    ")?; }
                writeln!($f, $fmt)?;
            };
            ($depth:expr, $f:expr, $fmt:expr, $($arg:tt)*) => {
                for _ in 0..$depth { write!($f, "    ")?; }
                writeln!($f, $fmt, $($arg)*)?;
            };
        }

        fn print_into_iter<
            T: fmt::Debug,
            E: ExactSizeIterator<Item = T>,
            I: IntoIterator<Item = T, IntoIter = E>,
        >(
            prefix: &str,
            data: I,
            depth: usize,
            f: &mut fmt::Formatter,
        ) -> Result<(), fmt::Error> {
            let data = data.into_iter();
            if data.len() == 0 {
                return Ok(());
            }

            writeln_indented!(depth, f, "{}: [", prefix);
            for v in data {
                writeln_indented!(depth + 1, f, "{:?}", v);
            }
            writeln_indented!(depth, f, "]");

            Ok(())
        }

        fn print_children<S: crate::xml::dom::storage::Storage>(
            parent: Node<'_, '_, S>,
            depth: usize,
            f: &mut fmt::Formatter,
        ) -> Result<(), fmt::Error> {
            for child in parent.children() {
                if child.is_element() {
                    writeln_indented!(depth, f, "Element {{");
                    writeln_indented!(depth, f, "    tag_name: {:?}", child.tag_name());
                    print_into_iter("attributes", child.attributes(), depth + 1, f)?;
                    print_into_iter("namespaces", child.namespaces(), depth + 1, f)?;

                    if child.has_children() {
                        writeln_indented!(depth, f, "    children: [");
                        print_children(child, depth + 2, f)?;
                        writeln_indented!(depth, f, "    ]");
                    }

                    writeln_indented!(depth, f, "}}");
                } else {
                    writeln_indented!(depth, f, "{:?}", child);
                }
            }

            Ok(())
        }

        writeln!(f, "Document [")?;
        print_children(self.root(), 1, f)?;
        writeln!(f, "]")?;

        Ok(())
    }
}

/// A list of supported node types.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NodeType {
    /// The root node of the `Document`.
    Root,
    /// An element node.
    ///
    /// Only an element can have a tag name and attributes.
    Element,
    /// A processing instruction.
    PI,
    /// A comment node.
    Comment,
    /// A text node.
    Text,
}

/// A processing instruction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[allow(missing_docs)]
pub struct PI<'input> {
    pub target: &'input str,
    pub value: Option<&'input str>,
}

/// A short range.
///
/// Just like Range, but only for `u32` and copyable.
#[derive(Clone, Copy, Debug)]
struct ShortRange {
    start: u32,
    end: u32,
}

impl From<Range<usize>> for ShortRange {
    #[inline]
    fn from(range: Range<usize>) -> Self {
        debug_assert!(range.start <= u32::MAX as usize);
        debug_assert!(range.end <= u32::MAX as usize);
        ShortRange::new(range.start as u32, range.end as u32)
    }
}

impl ShortRange {
    #[inline]
    fn new(start: u32, end: u32) -> Self {
        ShortRange { start, end }
    }

    #[inline]
    fn to_urange(self) -> Range<usize> {
        self.start as usize..self.end as usize
    }
}

/// A node ID stored as `u32`.
///
/// An index into a `Tree`-internal `Vec`.
///
/// Note that this value should be used with care since `roxmltree` doesn't
/// check that `NodeId` actually belongs to a selected `Document`.
/// So you can end up in a situation, when `NodeId` produced by one `Document`
/// is used to select a node in another `Document`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct NodeId(NonZeroU32);

impl NodeId {
    /// Construct a new `NodeId` from a `u32`.
    #[inline]
    pub fn new(id: u32) -> Self {
        debug_assert!(id < u32::MAX);

        // We are using `NonZeroU32` to reduce overhead of `Option<NodeId>`.
        NodeId(NonZeroU32::new(id + 1).expect("node IDs are below the u32 arena limit"))
    }

    /// Returns the `u32` representation of the `NodeId`.
    #[inline]
    pub fn get(self) -> u32 {
        self.0.get() - 1
    }

    /// Returns the `usize` representation of the `NodeId`.
    #[inline]
    pub fn get_usize(self) -> usize {
        self.get() as usize
    }
}

impl From<u32> for NodeId {
    #[inline]
    fn from(id: u32) -> Self {
        NodeId::new(id)
    }
}

impl From<usize> for NodeId {
    #[inline]
    fn from(id: usize) -> Self {
        // We already checked that `id` is limited by u32::MAX.
        debug_assert!(id <= u32::MAX as usize);
        NodeId::new(id as u32)
    }
}

#[derive(Debug)]
enum NodeKind<'input, S: crate::xml::dom::storage::Storage = crate::xml::dom::storage::Native> {
    Root,
    Element {
        tag_name: ExpandedNameIndexed<'input>,
        attributes: ShortRange,
        namespaces: ShortRange,
    },
    PI(PI<'input>),
    Comment(StringStorage<'input, S>),
    Text(StringStorage<'input, S>),
}

#[derive(Debug)]
struct NodeData<'input, S: crate::xml::dom::storage::Storage = crate::xml::dom::storage::Native> {
    parent: Option<NodeId>,
    prev_sibling: Option<NodeId>,
    next_subtree: Option<NodeId>,
    last_child: Option<NodeId>,
    kind: NodeKind<'input, S>,
    #[cfg(feature = "xml-backend-roxmltree")]
    range: Range<usize>,
}

/// A string storage.
///
/// Used by text nodes and attributes values.
///
/// We try our best not to allocate strings, referencing the input string as much as possible.
/// But in some cases post-processing is necessary and we have to allocate them.
///
/// Completed normalization buffers have one owner in this read-only tree.
/// No parser or adapter clones this storage or needs a reference-count block.
#[derive(Debug)]
pub enum StringStorage<
    'input,
    S: crate::xml::dom::storage::Storage = crate::xml::dom::storage::Native,
> {
    /// A raw slice of the input string.
    Borrowed(&'input str),

    /// An owned normalization buffer.
    Owned(S::Text),
}

impl<S: crate::xml::dom::storage::Storage> StringStorage<'_, S> {
    /// Takes the completed normalization buffer.
    fn from_owned(s: S::Text) -> Self {
        Self::Owned(s)
    }

    /// Returns a string slice.
    pub fn as_str(&self) -> &str {
        match self {
            StringStorage::Borrowed(s) => s,
            StringStorage::Owned(s) => s,
        }
    }
}

impl<S: crate::xml::dom::storage::Storage> PartialEq for StringStorage<'_, S> {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl<S: crate::xml::dom::storage::Storage> Eq for StringStorage<'_, S> {}
impl<S: crate::xml::dom::storage::Storage> core::fmt::Display for StringStorage<'_, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl<S: crate::xml::dom::storage::Storage> core::ops::Deref for StringStorage<'_, S> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

#[cfg(test)]
mod owned_text_tests {
    use super::*;

    #[cfg(feature = "xmldsig")]
    #[test]
    fn scoped_parser_retains_real_tree_storage_and_releases_failures() {
        // Raw parser storage, not a surrogate input reservation, must remain
        // charged until the tree is dropped. Partial failures release it all.
        use crate::xml::dom::storage::Accounted;
        use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
        let source = "<r xmlns:p='urn:p' p:a='one&#x20;two'>left<![CDATA[middle]]>right</r>";
        for capacity in [0, 1, 127, 1024, 1 << 20] {
            let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(capacity, 1 << 20)));
            let parsed =
                Document::parse_with_storage(source, ParsingOptions::default(), Accounted(&memory));
            match parsed {
                Ok(document) => {
                    assert_eq!(document.root_element().text(), Some("leftmiddleright"));
                    assert_eq!(
                        document.root_element().attribute(("urn:p", "a")),
                        Some("one two")
                    );
                    assert!(memory.used() > 0);
                    drop(document);
                }
                Err(Error::SharedExecution(MemoryError::LimitExceeded)) => {
                    assert!(capacity < 1 << 20);
                }
                Err(error) => panic!("unexpected parser error: {error}"),
            }
            assert_eq!(memory.used(), 0);
        }
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn scoped_parser_keeps_dynamic_error_labels_in_the_current_account() {
        // A fatal diagnostic must move its already-funded label out of the
        // callback bridge without formatting a native String or losing cause.
        use crate::xml::dom::storage::Accounted;
        use structured_asn1::memory::{Memory, MemoryAccount};
        let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(1 << 20, 1 << 20)));
        let error = Document::parse_with_storage(
            "<unbound:root/>",
            ParsingOptions::default(),
            Accounted(&memory),
        )
        .unwrap_err();
        assert!(matches!(&error, Error::UnknownNamespace(name, _) if &**name == "unbound"));
        assert!(memory.used() > 0);
        drop(error);
        assert_eq!(memory.used(), 0);
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn scoped_parser_cannot_erase_the_current_query_work_ceiling() {
        // Aggregate capacity/work cannot authorize construction on a query
        // whose own work allowance is zero, even for malformed input.
        use crate::xml::dom::storage::Accounted;
        use structured_asn1::{
            Encoding, Limits, Parser,
            memory::{Memory, MemoryAccount, MemoryError},
        };
        let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(1 << 20, 1 << 20)));
        let parser = Parser::new(
            Encoding::Der,
            Limits {
                max_work: 0,
                ..Default::default()
            },
            memory.clone(),
        );
        let reader = parser.read(&[], 0).unwrap();
        for source in ["<r/>", "<unbound:root/>"] {
            assert!(matches!(
                Document::parse_with_storage(
                    source,
                    ParsingOptions::default(),
                    Accounted(&reader.execution())
                ),
                Err(Error::SharedExecution(MemoryError::WorkExceeded))
            ));
        }
        assert_eq!(memory.used(), 0);
        assert_eq!(memory.work_used(), 0);
    }

    #[test]
    fn normalization_buffer_is_adopted_without_another_allocation() {
        // A completed normalization buffer already owns valid UTF-8. Moving
        // it into the tree must not allocate a second copy or a refcount block.
        let source = alloc::string::String::from("normalized text");
        let pointer = source.as_ptr();
        let stored: StringStorage<'_> = StringStorage::from_owned(source);
        assert_eq!(stored.as_str(), "normalized text");
        assert_eq!(stored.as_str().as_ptr(), pointer);
    }

    #[test]
    fn moving_text_buffers_preserves_normalization_and_coalescing() {
        // Ownership changes must preserve one text node across literal,
        // character-reference, CDATA and included internal-entity fragments.
        for (xml, expected) in [
            (
                "<root>left<![CDATA[middle]]>right</root>",
                "leftmiddleright",
            ),
            ("<root>left&#x20;right</root>", "left right"),
            ("<root>line\r\nnext</root>", "line\nnext"),
            ("<root><![CDATA[]]>after</root>", "after"),
            (
                "<!DOCTYPE root [<!ENTITY e 'entity'>]><root>before&e;after</root>",
                "beforeentityafter",
            ),
        ] {
            let document = Document::parse_with_options(
                xml,
                ParsingOptions {
                    allow_dtd: true,
                    ..ParsingOptions::default()
                },
            )
            .expect("fixed normalization fixture");
            assert_eq!(document.root_element().text(), Some(expected));
            assert_eq!(document.root_element().children().count(), 1);
        }
        let document = Document::parse("<root a='line\r\nnext&#xA;end'/>")
            .expect("fixed attribute normalization fixture");
        assert_eq!(
            document.root_element().attribute("a"),
            Some("line next\nend")
        );
    }
}

#[derive(Debug)]
struct AttributeData<
    'input,
    S: crate::xml::dom::storage::Storage = crate::xml::dom::storage::Native,
> {
    name: ExpandedNameIndexed<'input>,
    value: StringStorage<'input, S>,
    #[cfg(feature = "xml-backend-roxmltree")]
    range: Range<usize>,
    #[cfg(feature = "xml-backend-roxmltree")]
    qname_len: u16,
    #[cfg(feature = "xml-backend-roxmltree")]
    eq_len: u8, // includes any surrounding spaces
}

/// An attribute.
pub struct Attribute<
    'a,
    'input: 'a,
    S: crate::xml::dom::storage::Storage = crate::xml::dom::storage::Native,
> {
    doc: &'a Document<'input, S>,
    data: &'a AttributeData<'input, S>,
}

impl<S: crate::xml::dom::storage::Storage> Copy for Attribute<'_, '_, S> {}
impl<S: crate::xml::dom::storage::Storage> Clone for Attribute<'_, '_, S> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<'a, 'input, S: crate::xml::dom::storage::Storage> Attribute<'a, 'input, S> {
    /// Returns attribute's namespace URI.
    ///
    /// # Examples
    ///
    /// ```text,xml-sec-example
    /// let doc = roxmltree::Document::parse(
    ///     "<e xmlns:n='http://www.w3.org' a='b' n:a='c'/>"
    /// ).unwrap();
    ///
    /// assert_eq!(doc.root_element().attributes().next().unwrap().namespace(), None);
    /// assert_eq!(doc.root_element().attributes().nth(1).unwrap().namespace(), Some("http://www.w3.org"));
    /// ```
    #[inline]
    pub fn namespace(&self) -> Option<&'a str> {
        self.data.name.namespace(self.doc).map(Namespace::uri)
    }

    /// Returns attribute's name.
    ///
    /// # Examples
    ///
    /// ```text,xml-sec-example
    /// let doc = roxmltree::Document::parse(
    ///     "<e xmlns:n='http://www.w3.org' a='b' n:a='c'/>"
    /// ).unwrap();
    ///
    /// assert_eq!(doc.root_element().attributes().next().unwrap().name(), "a");
    /// assert_eq!(doc.root_element().attributes().nth(1).unwrap().name(), "a");
    /// ```
    #[inline]
    pub fn name(&self) -> &'input str {
        self.data.name.local_name
    }

    /// Returns attribute's value.
    ///
    /// # Examples
    ///
    /// ```text,xml-sec-example
    /// let doc = roxmltree::Document::parse(
    ///     "<e xmlns:n='http://www.w3.org' a='b' n:a='c'/>"
    /// ).unwrap();
    ///
    /// assert_eq!(doc.root_element().attributes().next().unwrap().value(), "b");
    /// assert_eq!(doc.root_element().attributes().nth(1).unwrap().value(), "c");
    /// ```
    #[inline]
    pub fn value(&self) -> &'a str {
        &self.data.value
    }

    /// Returns attribute's value storage.
    ///
    /// Useful when you need a more low-level access to an allocated string.
    #[inline]
    pub fn value_storage(&self) -> &StringStorage<'input, S> {
        &self.data.value
    }

    /// Returns attribute's position in bytes in the original document.
    ///
    /// You can calculate a human-readable text position via [Document::text_pos_at].
    ///
    /// ```text
    /// <e attr='value'/>
    ///    ^
    /// ```
    ///
    /// [Document::text_pos_at]: struct.Document.html#method.text_pos_at
    #[deprecated(note = "replaced by `range`")]
    #[cfg(feature = "xml-backend-roxmltree")]
    #[inline]
    pub fn position(&self) -> usize {
        self.data.range.start
    }

    /// Returns attribute's range in bytes in the original document.
    ///
    /// ```text
    /// <e n:attr='value'/>
    ///    ^^^^^^^^^^^^^^
    /// ```
    #[cfg(feature = "xml-backend-roxmltree")]
    #[inline]
    pub fn range(&self) -> Range<usize> {
        self.data.range.clone()
    }

    /// Returns attribute's qname's range in bytes in the original document.
    ///
    /// ```text
    /// <e n:attr='value'/>
    ///    ^^^^^^
    /// ```
    ///
    /// To reduce memory usage the qname length is limited by u16::MAX.
    /// If the attribute exceeds that limit then the end of the returned range will be incorrect.
    #[cfg(feature = "xml-backend-roxmltree")]
    #[inline]
    pub fn range_qname(&self) -> Range<usize> {
        let end = self.data.range.start + usize::from(self.data.qname_len);
        self.data.range.start..end
    }

    /// Returns attribute's value's range in bytes in the original document, excluding the surrounding quotes.
    ///
    /// If the attribute's value is an empty string then the `start` and `end` of this `Range` are equal, and indicate the closing quote.
    ///
    /// ```text
    /// <e n:attr='value'/>
    ///            ^^^^^
    /// ```
    ///
    /// To reduce memory usage the qname length is limited by u16::MAX,
    /// and the number of spaces around the equal sign is limited by u8::MAX.
    /// If the attribute exceeds those limits then the start of the returned range will be incorrect.
    #[cfg(feature = "xml-backend-roxmltree")]
    #[inline]
    pub fn range_value(&self) -> Range<usize> {
        // +1 on start and -1 on end are to exclude the quotes around the value (all valid quotes are 1 byte)
        let start = self.data.range.start
            + usize::from(self.data.qname_len)
            + usize::from(self.data.eq_len)
            + 1;
        let end = self.data.range.end - 1;
        start..end
    }
}

impl<S: crate::xml::dom::storage::Storage> PartialEq for Attribute<'_, '_, S> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.data.name.as_expanded_name(self.doc) == other.data.name.as_expanded_name(other.doc)
            && self.data.value == other.data.value
    }
}

impl<S: crate::xml::dom::storage::Storage> fmt::Debug for Attribute<'_, '_, S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "Attribute {{ name: {:?}, value: {:?} }}",
            self.data.name.as_expanded_name(self.doc),
            self.data.value
        )
    }
}

/// A namespace.
///
/// Contains URI and *prefix* pair.
#[derive(PartialEq, Eq, Debug)]
pub struct Namespace<
    'input,
    S: crate::xml::dom::storage::Storage = crate::xml::dom::storage::Native,
> {
    name: Option<&'input str>,
    uri: StringStorage<'input, S>,
}

impl<'input, S: crate::xml::dom::storage::Storage> Namespace<'input, S> {
    /// Returns namespace name/prefix.
    ///
    /// # Examples
    ///
    /// ```text,xml-sec-example
    /// let doc = roxmltree::Document::parse(
    ///     "<e xmlns:n='http://www.w3.org'/>"
    /// ).unwrap();
    ///
    /// assert_eq!(doc.root_element().namespaces().next().unwrap().name(), Some("n"));
    /// ```
    ///
    /// ```text,xml-sec-example
    /// let doc = roxmltree::Document::parse(
    ///     "<e xmlns='http://www.w3.org'/>"
    /// ).unwrap();
    ///
    /// assert_eq!(doc.root_element().namespaces().next().unwrap().name(), None);
    /// ```
    #[inline]
    pub fn name(&self) -> Option<&'input str> {
        self.name
    }

    /// Returns namespace URI.
    ///
    /// # Examples
    ///
    /// ```text,xml-sec-example
    /// let doc = roxmltree::Document::parse(
    ///     "<e xmlns:n='http://www.w3.org'/>"
    /// ).unwrap();
    ///
    /// assert_eq!(doc.root_element().namespaces().next().unwrap().uri(), "http://www.w3.org");
    /// ```
    #[inline]
    pub fn uri(&self) -> &str {
        self.uri.as_ref()
    }
}

struct Namespaces<'input, S: crate::xml::dom::storage::Storage = crate::xml::dom::storage::Native> {
    // Deduplicated namespace values used throughout the document
    values: S::Values<Namespace<'input, S>>,
    // Indices into the above in tree order as the document is parsed
    tree_order: S::Values<NamespaceIdx>,
    // Indices into the above sorted by value used for deduplication
    sorted_order: S::Values<NamespaceIdx>,
    storage: S,
}

impl<'input, S: crate::xml::dom::storage::Storage> Namespaces<'input, S> {
    fn new(storage: S) -> Result<Self, Error<S::Text>> {
        Ok(Self {
            values: storage.values(0)?,
            tree_order: storage.values(0)?,
            sorted_order: storage.values(0)?,
            storage,
        })
    }
    fn push_ns(
        &mut self,
        name: Option<&'input str>,
        uri: StringStorage<'input, S>,
    ) -> Result<(), Error<S::Text>> {
        debug_assert_ne!(name, Some(""));

        let mut failure = None;
        let search = self.sorted_order.binary_search_by(|idx| {
            if failure.is_some() {
                return Ordering::Equal;
            }
            if let Err(error) = self
                .storage
                .charge(1 + name.map_or(0, str::len) + uri.len())
            {
                failure = Some(error);
                return Ordering::Equal;
            }
            let value = &self.values[idx.0 as usize];

            (value.name, value.uri.as_ref()).cmp(&(name, uri.as_str()))
        });
        if let Some(error) = failure {
            return Err(error.into());
        }
        let idx = match search {
            Ok(sorted_idx) => self.sorted_order[sorted_idx],
            Err(sorted_idx) => {
                if self.values.len() > u16::MAX as usize {
                    return Err(Error::NamespacesLimitReached);
                }
                let idx = NamespaceIdx(self.values.len() as u16);
                self.values.push(Namespace { name, uri })?;
                self.storage.charge(
                    (self.sorted_order.len() - sorted_idx) * core::mem::size_of::<NamespaceIdx>(),
                )?;
                self.sorted_order.insert_copy(sorted_idx, idx)?;
                idx
            }
        };

        self.tree_order.push(idx)?;

        Ok(())
    }

    #[inline]
    fn push_ref(&mut self, tree_idx: usize) -> Result<(), Error<S::Text>> {
        let idx = self.tree_order[tree_idx];
        self.tree_order.push(idx)?;
        Ok(())
    }

    #[inline]
    fn exists(&self, start: usize, prefix: Option<&str>) -> Result<bool, Error<S::Text>> {
        for idx in &self.tree_order[start..] {
            self.storage.charge(1 + prefix.map_or(0, str::len))?;
            if self.values[idx.0 as usize].name == prefix {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn shrink_to_fit(&mut self) -> Result<(), Error<S::Text>> {
        self.storage.finish_values(&mut self.values);
        self.storage.finish_values(&mut self.tree_order);
        // Only needed to deduplicate namespaces during parsing.
        self.sorted_order = self.storage.values(0)?;
        Ok(())
    }

    #[inline]
    fn get(&self, idx: NamespaceIdx) -> &Namespace<'input, S> {
        &self.values[idx.0 as usize]
    }
}

impl Default for Namespaces<'_> {
    fn default() -> Self {
        Self::new(Native).expect("empty native namespace storage cannot allocate")
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
struct NamespaceIdx(u16);

#[derive(Clone, Copy, Debug)]
struct ExpandedNameIndexed<'input> {
    namespace_idx: Option<NamespaceIdx>,
    local_name: &'input str,
}

impl<'input> ExpandedNameIndexed<'input> {
    #[inline]
    fn namespace<'a, S: crate::xml::dom::storage::Storage>(
        &self,
        doc: &'a Document<'input, S>,
    ) -> Option<&'a Namespace<'input, S>> {
        self.namespace_idx.map(|idx| doc.namespaces.get(idx))
    }

    #[inline]
    fn as_expanded_name<'a, S: crate::xml::dom::storage::Storage>(
        &self,
        doc: &'a Document<'input, S>,
    ) -> ExpandedName<'a, 'input> {
        ExpandedName {
            uri: self.namespace(doc).map(Namespace::uri),
            name: self.local_name,
        }
    }
}

/// An expanded name.
///
/// Contains an namespace URI and name pair.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ExpandedName<'a, 'b> {
    uri: Option<&'a str>,
    name: &'b str,
}

impl<'a, 'b> ExpandedName<'a, 'b> {
    /// Returns a namespace URI.
    ///
    /// # Examples
    ///
    /// ```text,xml-sec-example
    /// let doc = roxmltree::Document::parse("<e xmlns='http://www.w3.org'/>").unwrap();
    ///
    /// assert_eq!(doc.root_element().tag_name().namespace(), Some("http://www.w3.org"));
    /// ```
    #[inline]
    pub fn namespace(&self) -> Option<&'a str> {
        self.uri
    }

    /// Returns a local name.
    ///
    /// # Examples
    ///
    /// ```text,xml-sec-example
    /// let doc = roxmltree::Document::parse("<e/>").unwrap();
    ///
    /// assert_eq!(doc.root_element().tag_name().name(), "e");
    /// ```
    #[inline]
    pub fn name(&self) -> &'b str {
        self.name
    }
}

impl ExpandedName<'static, 'static> {
    /// Create a new instance from static data.
    ///
    /// # Example
    ///
    /// ```text,xml-sec-example
    /// use roxmltree::ExpandedName;
    /// const DAV_HREF: ExpandedName =
    ///     ExpandedName::from_static("urn:ietf:params:xml:ns:caldav:", "calendar-data");
    /// ```
    pub const fn from_static(uri: &'static str, name: &'static str) -> Self {
        Self {
            uri: Some(uri),
            name,
        }
    }
}

impl fmt::Debug for ExpandedName<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self.namespace() {
            Some(ns) => write!(f, "{{{}}}{}", ns, self.name),
            None => write!(f, "{}", self.name),
        }
    }
}

impl<'a, 'b> From<&'b str> for ExpandedName<'a, 'b> {
    #[inline]
    fn from(v: &'b str) -> Self {
        ExpandedName { uri: None, name: v }
    }
}

impl<'a, 'b> From<(&'a str, &'b str)> for ExpandedName<'a, 'b> {
    #[inline]
    fn from(v: (&'a str, &'b str)) -> Self {
        ExpandedName {
            uri: Some(v.0),
            name: v.1,
        }
    }
}

/// A node in a document.
///
/// # Document Order
///
/// The implementation of the `Ord` traits for `Node` is based on the concept of *document-order*.
/// In layman's terms, document-order is the order in which one would see each element if
/// one opened a document in a text editor or web browser and scrolled down.
/// Document-order convention is followed in XPath, CSS Counters, and DOM selectors API
/// to ensure consistent results from selection.
/// One difference in `roxmltree` is that there is the notion of more than one document
/// in existence at a time. While Nodes within the same document are in document-order,
/// Nodes in different documents will be grouped together, but not in any particular
/// order.
///
/// As an example, if we have a Document `a` with Nodes `[a0, a1, a2]` and a
/// Document `b` with Nodes `[b0, b1]`, these Nodes in order could be either
/// `[a0, a1, a2, b0, b1]` or `[b0, b1, a0, a1, a2]` and roxmltree makes no
/// guarantee which it will be.
///
/// Document-order is defined here in the
/// [W3C XPath Recommendation](https://www.w3.org/TR/xpath-3/#id-document-order)
/// The use of document-order in DOM Selectors is described here in the
/// [W3C Selectors API Level 1](https://www.w3.org/TR/selectors-api/#the-apis)
#[derive(Clone, Copy)]
pub struct Node<'a, 'input: 'a, S: Storage = Native> {
    /// Node's ID.
    id: NodeId,

    /// The tree containing the node.
    doc: &'a Document<'input, S>,

    /// Node's data.
    d: &'a NodeData<'input, S>,
}

impl<S: Storage> Eq for Node<'_, '_, S> {}

impl<S: Storage> PartialEq for Node<'_, '_, S> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        (self.id, self.doc as *const _) == (other.id, other.doc as *const _)
    }
}

impl<S: Storage> PartialOrd for Node<'_, '_, S> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<S: Storage> Ord for Node<'_, '_, S> {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.id.0, self.doc as *const _).cmp(&(other.id.0, other.doc as *const _))
    }
}

impl<S: Storage> Hash for Node<'_, '_, S> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.0.hash(state);
        core::ptr::from_ref(self.doc).hash(state);
        core::ptr::from_ref(self.d).hash(state);
    }
}

impl<'a, 'input: 'a, S: Storage> Node<'a, 'input, S> {
    /// Returns node's type.
    #[inline]
    pub fn node_type(&self) -> NodeType {
        match self.d.kind {
            NodeKind::Root => NodeType::Root,
            NodeKind::Element { .. } => NodeType::Element,
            NodeKind::PI { .. } => NodeType::PI,
            NodeKind::Comment(_) => NodeType::Comment,
            NodeKind::Text(_) => NodeType::Text,
        }
    }

    /// Checks that node is a root node.
    #[inline]
    pub fn is_root(&self) -> bool {
        self.node_type() == NodeType::Root
    }

    /// Checks that node is an element node.
    #[inline]
    pub fn is_element(&self) -> bool {
        self.node_type() == NodeType::Element
    }

    /// Checks that node is a processing instruction node.
    #[inline]
    pub fn is_pi(&self) -> bool {
        self.node_type() == NodeType::PI
    }

    /// Checks that node is a comment node.
    #[inline]
    pub fn is_comment(&self) -> bool {
        self.node_type() == NodeType::Comment
    }

    /// Checks that node is a text node.
    #[inline]
    pub fn is_text(&self) -> bool {
        self.node_type() == NodeType::Text
    }

    /// Returns node's document.
    #[inline]
    pub fn document(&self) -> &'a Document<'input, S> {
        self.doc
    }

    /// Returns node's tag name.
    ///
    /// Returns an empty name with no namespace if the current node is not an element.
    ///
    /// # Examples
    ///
    /// ```text,xml-sec-example
    /// let doc = roxmltree::Document::parse("<e xmlns='http://www.w3.org'/>").unwrap();
    ///
    /// assert_eq!(doc.root_element().tag_name().namespace(), Some("http://www.w3.org"));
    /// assert_eq!(doc.root_element().tag_name().name(), "e");
    /// ```
    #[inline]
    pub fn tag_name(&self) -> ExpandedName<'a, 'input> {
        match self.d.kind {
            NodeKind::Element { ref tag_name, .. } => tag_name.as_expanded_name(self.doc),
            _ => "".into(),
        }
    }

    /// Checks that node has a specified tag name.
    ///
    /// # Examples
    ///
    /// ```text,xml-sec-example
    /// let doc = roxmltree::Document::parse("<e xmlns='http://www.w3.org'/>").unwrap();
    ///
    /// assert!(doc.root_element().has_tag_name("e"));
    /// assert!(doc.root_element().has_tag_name(("http://www.w3.org", "e")));
    ///
    /// assert!(!doc.root_element().has_tag_name("b"));
    /// assert!(!doc.root_element().has_tag_name(("http://www.w4.org", "e")));
    /// ```
    pub fn has_tag_name<'n, 'm, N>(&self, name: N) -> bool
    where
        N: Into<ExpandedName<'n, 'm>>,
    {
        let name = name.into();

        match self.d.kind {
            NodeKind::Element { ref tag_name, .. } => match name.namespace() {
                Some(_) => tag_name.as_expanded_name(self.doc) == name,
                None => tag_name.local_name == name.name,
            },
            _ => false,
        }
    }

    /// Returns node's default namespace URI.
    ///
    /// # Examples
    ///
    /// ```text,xml-sec-example
    /// let doc = roxmltree::Document::parse("<e xmlns='http://www.w3.org'/>").unwrap();
    ///
    /// assert_eq!(doc.root_element().default_namespace(), Some("http://www.w3.org"));
    /// ```
    ///
    /// ```text,xml-sec-example
    /// let doc = roxmltree::Document::parse("<e xmlns:n='http://www.w3.org'/>").unwrap();
    ///
    /// assert_eq!(doc.root_element().default_namespace(), None);
    /// ```
    pub fn default_namespace(&self) -> Option<&'a str> {
        self.namespaces()
            .find(|ns| ns.name.is_none())
            .map(|v| v.uri.as_ref())
    }

    /// Returns a prefix for a given namespace URI.
    ///
    /// # Examples
    ///
    /// ```text,xml-sec-example
    /// let doc = roxmltree::Document::parse("<e xmlns:n='http://www.w3.org'/>").unwrap();
    ///
    /// assert_eq!(doc.root_element().lookup_prefix("http://www.w3.org"), Some("n"));
    /// ```
    ///
    /// ```text,xml-sec-example
    /// // Namespaces in XML 1.0 §5 forbids undeclaring a non-default prefix.
    /// // https://www.w3.org/TR/2009/REC-xml-names-20091208/#nsc-NoPrefixUndecl
    /// assert!(roxmltree::Document::parse("<e xmlns:n=''/>").is_err());
    /// // Default namespace undeclaration is permitted by §6.2.
    /// let doc = roxmltree::Document::parse("<e xmlns=''/>").unwrap();
    ///
    /// assert_eq!(doc.root_element().lookup_prefix(""), None);
    /// ```
    pub fn lookup_prefix(&self, uri: &str) -> Option<&'input str> {
        if uri == NS_XML_URI {
            return Some(NS_XML_PREFIX);
        }

        self.namespaces()
            .find(|ns| &*ns.uri == uri)
            .map(|v| v.name)
            .unwrap_or(None)
    }

    /// Returns an URI for a given prefix.
    ///
    /// # Examples
    ///
    /// ```text,xml-sec-example
    /// let doc = roxmltree::Document::parse("<e xmlns:n='http://www.w3.org'/>").unwrap();
    ///
    /// assert_eq!(doc.root_element().lookup_namespace_uri(Some("n")), Some("http://www.w3.org"));
    /// ```
    ///
    /// ```text,xml-sec-example
    /// let doc = roxmltree::Document::parse("<e xmlns='http://www.w3.org'/>").unwrap();
    ///
    /// assert_eq!(doc.root_element().lookup_namespace_uri(None), Some("http://www.w3.org"));
    /// ```
    pub fn lookup_namespace_uri(&self, prefix: Option<&str>) -> Option<&'a str> {
        self.namespaces()
            .find(|ns| ns.name == prefix)
            .map(|v| v.uri.as_ref())
    }

    /// Returns element's attribute value.
    ///
    /// # Examples
    ///
    /// ```text,xml-sec-example
    /// let doc = roxmltree::Document::parse("<e a='b'/>").unwrap();
    ///
    /// assert_eq!(doc.root_element().attribute("a"), Some("b"));
    /// ```
    ///
    /// ```text,xml-sec-example
    /// let doc = roxmltree::Document::parse(
    ///     "<e xmlns:n='http://www.w3.org' a='b' n:a='c'/>"
    /// ).unwrap();
    ///
    /// assert_eq!(doc.root_element().attribute("a"), Some("b"));
    /// assert_eq!(doc.root_element().attribute(("http://www.w3.org", "a")), Some("c"));
    /// ```
    pub fn attribute<'n, 'm, N>(&self, name: N) -> Option<&'a str>
    where
        N: Into<ExpandedName<'n, 'm>>,
    {
        self.attribute_node(name).map(|a| a.value())
    }

    /// Returns element's attribute object.
    ///
    /// The same as [`attribute()`], but returns the `Attribute` itself instead of a value string.
    ///
    /// [`attribute()`]: struct.Node.html#method.attribute
    pub fn attribute_node<'n, 'm, N>(&self, name: N) -> Option<Attribute<'a, 'input, S>>
    where
        N: Into<ExpandedName<'n, 'm>>,
    {
        let name = name.into();

        match name.namespace() {
            Some(_) => self
                .attributes()
                .find(|a| a.data.name.as_expanded_name(self.doc) == name),
            None => self
                .attributes()
                .find(|a| a.data.name.local_name == name.name),
        }
    }

    /// Checks that element has a specified attribute.
    ///
    /// # Examples
    ///
    /// ```text,xml-sec-example
    /// let doc = roxmltree::Document::parse(
    ///     "<e xmlns:n='http://www.w3.org' a='b' n:a='c'/>"
    /// ).unwrap();
    ///
    /// assert!(doc.root_element().has_attribute("a"));
    /// assert!(doc.root_element().has_attribute(("http://www.w3.org", "a")));
    ///
    /// assert!(!doc.root_element().has_attribute("b"));
    /// assert!(!doc.root_element().has_attribute(("http://www.w4.org", "a")));
    /// ```
    pub fn has_attribute<'n, 'm, N>(&self, name: N) -> bool
    where
        N: Into<ExpandedName<'n, 'm>>,
    {
        self.attribute_node(name).is_some()
    }

    /// Returns element's attributes.
    ///
    /// # Examples
    ///
    /// ```text,xml-sec-example
    /// let doc = roxmltree::Document::parse(
    ///     "<e xmlns:n='http://www.w3.org' a='b' n:a='c'/>"
    /// ).unwrap();
    ///
    /// assert_eq!(doc.root_element().attributes().len(), 2);
    /// ```
    #[inline]
    pub fn attributes(&self) -> Attributes<'a, 'input, S> {
        Attributes::new(self)
    }

    /// Returns element's namespaces.
    ///
    /// # Examples
    ///
    /// ```text,xml-sec-example
    /// let doc = roxmltree::Document::parse(
    ///     "<e xmlns:n='http://www.w3.org'/>"
    /// ).unwrap();
    ///
    /// assert_eq!(doc.root_element().namespaces().len(), 1);
    /// ```
    #[inline]
    pub fn namespaces(&self) -> NamespaceIter<'a, 'input, S> {
        let namespaces = match self.d.kind {
            NodeKind::Element { ref namespaces, .. } => {
                &self.doc.namespaces.tree_order[namespaces.to_urange()]
            }
            _ => &[],
        };

        NamespaceIter {
            doc: self.doc,
            namespaces: namespaces.iter(),
        }
    }

    /// Returns node's text.
    ///
    /// - for an element will return a first text child
    /// - for a comment will return a self text
    /// - for a text node will return a self text
    ///
    /// # Examples
    ///
    /// ```text,xml-sec-example
    /// let doc = roxmltree::Document::parse("\
    /// <p>
    ///     text
    /// </p>
    /// ").unwrap();
    ///
    /// assert_eq!(doc.root_element().text(),
    ///            Some("\n    text\n"));
    /// assert_eq!(doc.root_element().first_child().unwrap().text(),
    ///            Some("\n    text\n"));
    /// ```
    ///
    /// ```text,xml-sec-example
    /// let doc = roxmltree::Document::parse("<!-- comment --><e/>").unwrap();
    ///
    /// assert_eq!(doc.root().first_child().unwrap().text(), Some(" comment "));
    /// ```
    #[inline]
    pub fn text(&self) -> Option<&'a str> {
        self.text_storage().map(|s| s.as_str())
    }

    /// Returns node's text storage.
    ///
    /// Useful when you need a more low-level access to an allocated string.
    pub fn text_storage(&self) -> Option<&'a StringStorage<'input, S>> {
        match self.d.kind {
            NodeKind::Element { .. } => match self.first_child() {
                Some(child) if child.is_text() => match self.doc.nodes[child.id.get_usize()].kind {
                    NodeKind::Text(ref text) => Some(text),
                    _ => None,
                },
                _ => None,
            },
            NodeKind::Comment(ref text) => Some(text),
            NodeKind::Text(ref text) => Some(text),
            _ => None,
        }
    }

    /// Returns element's tail text.
    ///
    /// # Examples
    ///
    /// ```text,xml-sec-example
    /// let doc = roxmltree::Document::parse("\
    /// <root>
    ///     text1
    ///     <p/>
    ///     text2
    /// </root>
    /// ").unwrap();
    ///
    /// let p = doc.descendants().find(|n| n.has_tag_name("p")).unwrap();
    /// assert_eq!(p.tail(), Some("\n    text2\n"));
    /// ```
    #[inline]
    pub fn tail(&self) -> Option<&'a str> {
        self.tail_storage().map(|s| s.as_str())
    }

    /// Returns element's tail text storage.
    ///
    /// Useful when you need a more low-level access to an allocated string.
    pub fn tail_storage(&self) -> Option<&'a StringStorage<'input, S>> {
        if !self.is_element() {
            return None;
        }

        match self.next_sibling().map(|n| n.id) {
            Some(id) => match self.doc.nodes[id.get_usize()].kind {
                NodeKind::Text(ref text) => Some(text),
                _ => None,
            },
            None => None,
        }
    }

    /// Returns node as Processing Instruction.
    #[inline]
    pub fn pi(&self) -> Option<PI<'input>> {
        match self.d.kind {
            NodeKind::PI(pi) => Some(pi),
            _ => None,
        }
    }

    /// Returns the parent of this node.
    #[inline]
    pub fn parent(&self) -> Option<Self> {
        self.d
            .parent
            .map(|id| self.doc.get_node(id).expect("parent belongs to this arena"))
    }

    /// Returns the parent element of this node.
    pub fn parent_element(&self) -> Option<Self> {
        self.ancestors().skip(1).find(|n| n.is_element())
    }

    /// Returns the previous sibling of this node.
    #[inline]
    pub fn prev_sibling(&self) -> Option<Self> {
        self.d.prev_sibling.map(|id| {
            self.doc
                .get_node(id)
                .expect("previous sibling belongs to this arena")
        })
    }

    /// Returns the previous sibling element of this node.
    pub fn prev_sibling_element(&self) -> Option<Self> {
        self.prev_siblings().skip(1).find(|n| n.is_element())
    }

    /// Returns the next sibling of this node.
    #[inline]
    pub fn next_sibling(&self) -> Option<Self> {
        self.d
            .next_subtree
            .map(|id| {
                self.doc
                    .get_node(id)
                    .expect("next subtree belongs to this arena")
            })
            .and_then(|node| {
                let possibly_self = node
                    .d
                    .prev_sibling
                    .expect("next_subtree will always have a previous sibling");
                if possibly_self == self.id {
                    Some(node)
                } else {
                    None
                }
            })
    }

    /// Returns the next sibling element of this node.
    pub fn next_sibling_element(&self) -> Option<Self> {
        self.next_siblings().skip(1).find(|n| n.is_element())
    }

    /// Returns the first child of this node.
    #[inline]
    pub fn first_child(&self) -> Option<Self> {
        self.d.last_child.map(|_| {
            self.doc
                .get_node(NodeId::new(self.id.get() + 1))
                .expect("a nonempty subtree starts at the next arena entry")
        })
    }

    /// Returns the first element child of this node.
    pub fn first_element_child(&self) -> Option<Self> {
        self.children().find(|n| n.is_element())
    }

    /// Returns the last child of this node.
    #[inline]
    pub fn last_child(&self) -> Option<Self> {
        self.d.last_child.map(|id| {
            self.doc
                .get_node(id)
                .expect("last child belongs to this arena")
        })
    }

    /// Returns the last element child of this node.
    pub fn last_element_child(&self) -> Option<Self> {
        self.children().rfind(|child| child.is_element())
    }

    /// Returns true if this node has siblings.
    #[inline]
    pub fn has_siblings(&self) -> bool {
        self.d.prev_sibling.is_some() || self.next_sibling().is_some()
    }

    /// Returns true if this node has children.
    #[inline]
    pub fn has_children(&self) -> bool {
        self.d.last_child.is_some()
    }

    /// Returns an iterator over ancestor nodes starting at this node.
    #[inline]
    pub fn ancestors(&self) -> AxisIter<'a, 'input, S> {
        AxisIter {
            node: Some(*self),
            next: Node::parent,
        }
    }

    /// Returns an iterator over previous sibling nodes starting at this node.
    #[inline]
    pub fn prev_siblings(&self) -> AxisIter<'a, 'input, S> {
        AxisIter {
            node: Some(*self),
            next: Node::prev_sibling,
        }
    }

    /// Returns an iterator over next sibling nodes starting at this node.
    #[inline]
    pub fn next_siblings(&self) -> AxisIter<'a, 'input, S> {
        AxisIter {
            node: Some(*self),
            next: Node::next_sibling,
        }
    }

    /// Returns an iterator over first children nodes starting at this node.
    #[inline]
    pub fn first_children(&self) -> AxisIter<'a, 'input, S> {
        AxisIter {
            node: Some(*self),
            next: Node::first_child,
        }
    }

    /// Returns an iterator over last children nodes starting at this node.
    #[inline]
    pub fn last_children(&self) -> AxisIter<'a, 'input, S> {
        AxisIter {
            node: Some(*self),
            next: Node::last_child,
        }
    }

    /// Returns an iterator over children nodes.
    #[inline]
    pub fn children(&self) -> Children<'a, 'input, S> {
        Children {
            front: self.first_child(),
            back: self.last_child(),
        }
    }

    /// Returns an iterator over this node and its descendants.
    #[inline]
    pub fn descendants(&self) -> Descendants<'a, 'input, S> {
        Descendants::new(*self)
    }

    /// Returns node's range in bytes in the original document.
    #[cfg(feature = "xml-backend-roxmltree")]
    #[inline]
    pub fn range(&self) -> Range<usize> {
        self.d.range.clone()
    }

    /// Returns node's NodeId
    #[inline]
    pub fn id(&self) -> NodeId {
        self.id
    }
}

impl<'a, 'input: 'a, S: Storage> fmt::Debug for Node<'a, 'input, S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self.d.kind {
            NodeKind::Root => write!(f, "Root"),
            NodeKind::Element { .. } => {
                write!(
                    f,
                    "Element {{ tag_name: {:?}, attributes: {:?}, namespaces: {:?} }}",
                    self.tag_name(),
                    self.attributes(),
                    self.namespaces()
                )
            }
            NodeKind::PI(pi) => {
                write!(f, "PI {{ target: {:?}, value: {:?} }}", pi.target, pi.value)
            }
            NodeKind::Comment(ref text) => write!(f, "Comment({:?})", text.as_str()),
            NodeKind::Text(ref text) => write!(f, "Text({:?})", text.as_str()),
        }
    }
}

/// Iterator over a node's attributes
#[derive(Clone)]
pub struct Attributes<'a, 'input, S: Storage = Native> {
    doc: &'a Document<'input, S>,
    attrs: core::slice::Iter<'a, AttributeData<'input, S>>,
}

impl<'a, 'input, S: Storage> Attributes<'a, 'input, S> {
    #[inline]
    fn new(node: &Node<'a, 'input, S>) -> Attributes<'a, 'input, S> {
        let attrs = match node.d.kind {
            NodeKind::Element { ref attributes, .. } => {
                &node.doc.attributes[attributes.to_urange()]
            }
            _ => &[],
        };
        Attributes {
            doc: node.doc,
            attrs: attrs.iter(),
        }
    }
}

impl<'a, 'input, S: Storage> Iterator for Attributes<'a, 'input, S> {
    type Item = Attribute<'a, 'input, S>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.attrs.next().map(|attr| Attribute {
            doc: self.doc,
            data: attr,
        })
    }

    #[inline]
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.attrs.nth(n).map(|attr| Attribute {
            doc: self.doc,
            data: attr,
        })
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.attrs.size_hint()
    }
}

impl<'a, 'input, S: Storage> DoubleEndedIterator for Attributes<'a, 'input, S> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        self.attrs.next_back().map(|attr| Attribute {
            doc: self.doc,
            data: attr,
        })
    }
}

impl<S: Storage> ExactSizeIterator for Attributes<'_, '_, S> {}

impl<S: Storage> fmt::Debug for Attributes<'_, '_, S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("Attributes")
            .field("attrs", &self.attrs)
            .finish()
    }
}

/// Iterator over specified axis.
#[derive(Clone)]
pub struct AxisIter<'a, 'input: 'a, S: Storage = Native> {
    node: Option<Node<'a, 'input, S>>,
    next: fn(&Node<'a, 'input, S>) -> Option<Node<'a, 'input, S>>,
}

impl<'a, 'input: 'a, S: Storage> Iterator for AxisIter<'a, 'input, S> {
    type Item = Node<'a, 'input, S>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let node = self.node.take();
        self.node = node.as_ref().and_then(self.next);
        node
    }
}

impl<S: Storage> fmt::Debug for AxisIter<'_, '_, S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("AxisIter")
            .field("node", &self.node)
            .field("next", &"fn()")
            .finish()
    }
}

/// Iterator over children.
#[derive(Clone, Debug)]
pub struct Children<'a, 'input: 'a, S: Storage = Native> {
    front: Option<Node<'a, 'input, S>>,
    back: Option<Node<'a, 'input, S>>,
}

impl<'a, 'input: 'a, S: Storage> Iterator for Children<'a, 'input, S> {
    type Item = Node<'a, 'input, S>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.front == self.back {
            let node = self.front.take();
            self.back = None;
            node
        } else {
            let node = self.front.take();
            self.front = node.as_ref().and_then(Node::next_sibling);
            node
        }
    }
}

impl<'a, 'input: 'a, S: Storage> DoubleEndedIterator for Children<'a, 'input, S> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.back == self.front {
            let node = self.back.take();
            self.front = None;
            node
        } else {
            let node = self.back.take();
            self.back = node.as_ref().and_then(Node::prev_sibling);
            node
        }
    }
}

/// Iterator over a node and its descendants.
#[derive(Clone)]
pub struct Descendants<'a, 'input, S: Storage = Native> {
    doc: &'a Document<'input, S>,
    nodes: core::iter::Enumerate<core::slice::Iter<'a, NodeData<'input, S>>>,
    from: usize,
}

impl<'a, 'input, S: Storage> Descendants<'a, 'input, S> {
    #[inline]
    fn new(start: Node<'a, 'input, S>) -> Self {
        let from = start.id.get_usize();

        let until = start
            .d
            .next_subtree
            .map(NodeId::get_usize)
            .unwrap_or(start.doc.nodes.len());

        let nodes = start.doc.nodes[from..until].iter().enumerate();

        Self {
            doc: start.doc,
            nodes,
            from,
        }
    }
}

impl<'a, 'input, S: Storage> Iterator for Descendants<'a, 'input, S> {
    type Item = Node<'a, 'input, S>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.nodes.next().map(|(idx, data)| Node {
            id: NodeId::from(self.from + idx),
            d: data,
            doc: self.doc,
        })
    }

    #[inline]
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.nodes.nth(n).map(|(idx, data)| Node {
            id: NodeId::from(self.from + idx),
            d: data,
            doc: self.doc,
        })
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.nodes.size_hint()
    }
}

impl<'a, 'input, S: Storage> DoubleEndedIterator for Descendants<'a, 'input, S> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        self.nodes.next_back().map(|(idx, data)| Node {
            id: NodeId::from(self.from + idx),
            d: data,
            doc: self.doc,
        })
    }
}

impl<S: Storage> ExactSizeIterator for Descendants<'_, '_, S> {}

impl<S: Storage> fmt::Debug for Descendants<'_, '_, S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("Descendants")
            .field("nodes", &self.nodes)
            .field("from", &self.from)
            .finish()
    }
}

/// Iterator over the namespaces attached to a node.
#[derive(Clone)]
pub struct NamespaceIter<'a, 'input, S: Storage = Native> {
    doc: &'a Document<'input, S>,
    namespaces: core::slice::Iter<'a, NamespaceIdx>,
}

impl<'a, 'input, S: Storage> Iterator for NamespaceIter<'a, 'input, S> {
    type Item = &'a Namespace<'input, S>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.namespaces
            .next()
            .map(|idx| self.doc.namespaces.get(*idx))
    }

    #[inline]
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.namespaces
            .nth(n)
            .map(|idx| self.doc.namespaces.get(*idx))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.namespaces.size_hint()
    }
}

impl<'a, 'input, S: Storage> DoubleEndedIterator for NamespaceIter<'a, 'input, S> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        self.namespaces
            .next()
            .map(|idx| self.doc.namespaces.get(*idx))
    }
}

impl<S: Storage> ExactSizeIterator for NamespaceIter<'_, '_, S> {}

impl<S: Storage> fmt::Debug for NamespaceIter<'_, '_, S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("NamespaceIter")
            .field("namespaces", &self.namespaces)
            .finish()
    }
}
