//! XSLT transform adapter (XMLDSig 1.1 section 6.6.5).
//!
//! <https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-XSLT>

use std::cell::Cell;
use std::sync::Arc;

use super::{ExecutionData, TransformError, TransformExecutionBudget, TransformScratch};
use crate::c14n::scratch::Bytes as _;
use crate::c14n::scratch::List as _;
use crate::document::{DocumentParseSettings, XmlDocumentError, XmlParseWorkBudget};
use crate::policy::{PolicyViolation, ResourcePolicy, XsltStylesheetSemantics, resource_name};
use crate::xml::dom::storage::Storage as DomStorage;
use crate::xslt::{
    BudgetKind, CompileBudget, Compiler, Document, Error, ExecutionBudget, ExecutionEnvironment,
    ExecutionOptions, ExecutionUsage, NoResolver, Parameters, ParseBudget, ParseUsage, Reported,
    UnboundPrefixLists,
};

#[cfg(test)]
mod tests;

/// Work kinds that `ResourcePolicy::max_xslt_work` bounds independently.
const WORK_KINDS: [BudgetKind; 9] = [
    BudgetKind::XPathEvaluations,
    BudgetKind::XPathOperations,
    BudgetKind::ExtensionOperations,
    BudgetKind::PatternEvaluations,
    BudgetKind::TemplateApplications,
    BudgetKind::SortComparisons,
    BudgetKind::KeyEntries,
    BudgetKind::ResultNodes,
    BudgetKind::Messages,
];

fn admitted(usage: &ExecutionUsage, kind: BudgetKind) -> usize {
    match kind {
        BudgetKind::XPathEvaluations => usage.xpath_evaluations,
        BudgetKind::XPathOperations => usage.xpath_operations,
        BudgetKind::ExtensionOperations => usage.extension_operations,
        BudgetKind::PatternEvaluations => usage.pattern_evaluations,
        BudgetKind::TemplateApplications => usage.template_applications,
        BudgetKind::SortComparisons => usage.sort_comparisons,
        BudgetKind::KeyEntries => usage.key_entries,
        BudgetKind::ResultNodes => usage.result_nodes,
        BudgetKind::Messages => usage.messages,
        _ => 0,
    }
}

/// The `xsl:stylesheet` parameter of an XSLT transform, kept as the markup the
/// `<Transform>` element contains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XsltStylesheet {
    source: String,
    parsed: Option<ParsedStylesheet>,
}

/// The stylesheet element of a parsed `<Transform>`, serialized from the tree.
///
/// Entity references and character references are already replaced, so the
/// stylesheet compiles without the document's DTD (XML 1.0 section 4.4).
/// <https://www.w3.org/TR/2008/REC-xml-20081126/#entproc>
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ParsedStylesheet {
    /// The stylesheet with the namespace declarations written on its elements.
    document: String,
    /// Declarations in scope at the `<Transform>` that the stylesheet element does
    /// not make itself, serialized as attributes.
    inherited: String,
    /// Offset in `document` just after the stylesheet element's name.
    at: usize,
}

impl ParsedStylesheet {
    /// The stylesheet document `semantics` compiles.
    ///
    /// The stylesheet is an element of the signed document: every namespace in
    /// scope at it, including those declared on its ancestors (Namespaces in XML
    /// 1.0 section 6.1), is a namespace node of its elements that literal result
    /// elements copy (XSLT 1.0 section 7.1.1), and an ancestor's `xml:space`
    /// applies to its whitespace (XSLT 1.0 section 3.4). libxmlsec1 compiles the
    /// element with only what is written inside it.
    /// <https://www.w3.org/TR/1999/REC-xslt-19991116#literal-result-element>
    fn text(&self, semantics: XsltStylesheetSemantics) -> std::borrow::Cow<'_, str> {
        match semantics {
            XsltStylesheetSemantics::Specification if !self.inherited.is_empty() => {
                let (head, tail) = self.document.split_at(self.at);
                std::borrow::Cow::Owned([head, &self.inherited, tail].concat())
            }
            _ => std::borrow::Cow::Borrowed(&self.document),
        }
    }
}

/// Why a parameter yields no stylesheet document.
#[derive(Debug)]
enum Unavailable {
    /// The `<Transform>` holds no stylesheet element.
    Missing,
    /// Serializing it needs this many bytes, more than the workspace grants.
    Exceeds(usize),
    /// The query refused the work of serializing it.
    Refused(TransformError),
}

impl From<usize> for Unavailable {
    /// A [`Bounded`] refusal, which carries the length that would exceed its limit.
    fn from(needed: usize) -> Self {
        Self::Exceeds(needed)
    }
}

impl From<TransformError> for Unavailable {
    fn from(error: TransformError) -> Self {
        Self::Refused(error)
    }
}

/// An XSLT transform parameter as the executor reads it.
#[derive(Clone, Copy)]
pub(crate) enum XsltParameter<'a> {
    /// A stylesheet held by an owned transform.
    Stylesheet(&'a XsltStylesheet),
    /// The `<Transform>` element of a parsed document.
    Transform(crate::xml::dom::Node<'a, 'a>),
}

impl<'a> XsltParameter<'a> {
    /// Bytes a stylesheet parsed from a signature keeps for the whole operation.
    /// Markup given to `XsltStylesheet::new` belongs to
    /// the caller; a `<Transform>` read in place keeps nothing.
    fn carried_bytes(self) -> usize {
        match self {
            Self::Stylesheet(XsltStylesheet {
                source,
                parsed: Some(parsed),
            }) => source.capacity() + parsed.document.capacity() + parsed.inherited.capacity(),
            _ => 0,
        }
    }
}

impl XsltStylesheet {
    /// Accept stylesheet markup for a signature template.
    ///
    /// The markup is written into the `<Transform>` element unchanged and is
    /// compiled as its own document, so it must be valid element content holding
    /// exactly one `xsl:stylesheet` or `xsl:transform` element.
    ///
    /// # Errors
    ///
    /// [`TransformError::XmlParse`] for markup that is not well-formed element
    /// content, and [`TransformError::UnsupportedTransform`] when it does not
    /// hold exactly that element outside comments, processing instructions and
    /// whitespace.
    ///
    /// # Examples
    ///
    /// ```
    /// use xml_sec::xmldsig::{Transform, XsltStylesheet};
    ///
    /// let stylesheet = XsltStylesheet::new(
    ///     r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"/>"#,
    /// )?;
    /// let transform = Transform::Xslt(stylesheet);
    /// # let _ = transform;
    /// # Ok::<(), xml_sec::xmldsig::TransformError>(())
    /// ```
    pub fn new(source: impl Into<String>) -> Result<Self, TransformError> {
        let source = source.into();
        let wrapped = format!("<transform>{source}</transform>");
        let document = crate::xml::dom::Document::parse(&wrapped)
            .map_err(|error| TransformError::XmlParse(XmlDocumentError::Parse(error)))?;
        let mut elements = 0usize;
        for child in document.root_element().children() {
            if child.is_element() {
                elements += if is_stylesheet_element(child) { 1 } else { 2 };
            } else if child.is_text()
                && !child
                    .text()
                    .is_some_and(super::super::whitespace::is_xml_whitespace_only)
            {
                elements = usize::MAX;
                break;
            }
        }
        if elements != 1 {
            return Err(TransformError::UnsupportedTransform(
                "XSLT stylesheet must be one element".into(),
            ));
        }
        Ok(Self {
            source,
            parsed: None,
        })
    }

    /// The stylesheet of a parsed `<Transform>`, whose markup is already element content.
    pub(super) fn from_parsed(
        transform: crate::xml::dom::Node<'_, '_>,
        allowance: &Allowance,
    ) -> Result<Self, TransformError> {
        let limit = allowance.max_workspace;
        let parsed = ParsedStylesheet::from_transform(
            transform,
            limit,
            Inheritance::Separate,
            &mut |units| allowance.serialize(units),
        )
        .map_err(|error| match error {
            Unavailable::Exceeds(needed) => allowance.workspace_error(needed),
            Unavailable::Refused(error) => error,
            Unavailable::Missing => {
                TransformError::UnsupportedTransform("XSLT transform requires a stylesheet".into())
            }
        })?;
        Ok(Self {
            source: String::new(),
            parsed: Some(parsed),
        })
    }

    /// Self-contained stylesheet markup under specification semantics.
    ///
    /// Caller-provided markup is borrowed unchanged. Parsed parameters include
    /// inherited namespace declarations and `xml:space`, so the returned markup
    /// can be passed to [`Self::new`] outside its original signature document.
    #[must_use]
    pub fn source(&self) -> std::borrow::Cow<'_, str> {
        self.markup()
    }

    /// Markup that means the same stylesheet in any `<Transform>`.
    ///
    /// A parsed stylesheet may use namespaces declared on its original ancestors and
    /// entities of its original DTD; its serialization carries them, with references
    /// replaced, so it needs neither.
    pub(crate) fn markup(&self) -> std::borrow::Cow<'_, str> {
        match &self.parsed {
            Some(parsed) => parsed.text(XsltStylesheetSemantics::Specification),
            None => std::borrow::Cow::Borrowed(&self.source),
        }
    }

    /// The length of [`Self::markup`], without materializing it.
    pub(crate) fn markup_len(&self) -> usize {
        match &self.parsed {
            Some(parsed) => parsed.document.len() + parsed.inherited.len(),
            None => self.source.len(),
        }
    }
}

/// Text whose allocation stays within `limit` bytes, refused before it would exceed it.
struct Bounded {
    text: String,
    limit: usize,
}

impl Bounded {
    const fn new(limit: usize) -> Self {
        Self {
            text: String::new(),
            limit,
        }
    }

    /// Append `piece`; a refusal carries the length that would exceed the limit.
    fn push_str(&mut self, piece: &str) -> Result<(), usize> {
        let needed = self.text.len().checked_add(piece.len()).ok_or(usize::MAX)?;
        if needed > self.limit {
            return Err(needed);
        }
        if needed > self.text.capacity() {
            let available = self.limit - self.text.capacity();
            if needed > available {
                return Err(self.text.capacity().saturating_add(needed));
            }
            // A capacity never exceeds `isize::MAX`, so doubling it cannot overflow.
            let grown = (self.text.capacity() * 2).clamp(needed, available);
            self.text
                .try_reserve_exact(grown - self.text.len())
                .map_err(|_| needed)?;
            // An allocator may grant more than requested; what it granted is what is held.
            if self.text.capacity() > self.limit {
                return Err(self.text.capacity());
            }
        }
        self.text.push_str(piece);
        Ok(())
    }
}

/// The same serializer targets either captured native markup or query-owned bytes.
trait Markup {
    fn len(&self) -> usize;
    fn push_str(&mut self, text: &str) -> Result<(), Unavailable>;
    fn push(&mut self, character: char) -> Result<(), Unavailable> {
        self.push_str(character.encode_utf8(&mut [0; 4]))
    }
}

impl Markup for Bounded {
    fn len(&self) -> usize {
        self.text.len()
    }
    fn push_str(&mut self, text: &str) -> Result<(), Unavailable> {
        Bounded::push_str(self, text).map_err(Unavailable::Exceeds)
    }
}

struct QueryMarkup<B: crate::c14n::scratch::Bytes> {
    bytes: B,
    limit: usize,
}

impl<B: crate::c14n::scratch::Bytes> QueryMarkup<B> {
    fn text(&self) -> &str {
        // Only UTF-8 string fragments are appended by Markup.
        std::str::from_utf8(&self.bytes).expect("serialized markup is UTF-8")
    }
    fn append(&mut self, text: &[u8]) -> Result<(), Unavailable> {
        let needed = self.bytes.len().checked_add(text.len()).ok_or(usize::MAX)?;
        if needed > self.limit {
            return Err(Unavailable::Exceeds(needed));
        }
        if needed > self.bytes.capacity() {
            let old = self.bytes.capacity();
            let available = self.limit - old;
            if needed > available {
                return Err(Unavailable::Exceeds(old.saturating_add(needed)));
            }
            // Vec's native minimum growth is eight bytes; the accounted storage
            // reserves exactly this target, before calling its allocator.
            let target = (old * 2).max(needed).max(8);
            if target > available {
                return Err(Unavailable::Exceeds(old.saturating_add(target)));
            }
            self.bytes
                .reserve(target - self.bytes.len())
                .map_err(TransformError::from)?;
            if self.bytes.capacity() > available {
                return Err(Unavailable::Exceeds(
                    old.saturating_add(self.bytes.capacity()),
                ));
            }
        }
        self.bytes.append(text).map_err(TransformError::from)?;
        Ok(())
    }
}

impl<B: crate::c14n::scratch::Bytes> Markup for QueryMarkup<B> {
    fn len(&self) -> usize {
        self.bytes.len()
    }
    fn push_str(&mut self, text: &str) -> Result<(), Unavailable> {
        self.append(text.as_bytes())
    }
}

/// The implicit conversion belongs to this XSLT step, including replacement
/// blocks during growth. Keep its capacity live through engine execution.
pub(super) fn canonicalize_input<S: TransformScratch, D: DomStorage>(
    parameter: XsltParameter<'_>,
    document: &crate::xml::dom::Document<'_, D>,
    visibility: &dyn crate::c14n::NodeVisibility<D>,
    budget: &TransformExecutionBudget,
    scratch: &S,
) -> Result<S::Bytes, TransformError> {
    struct Output<B: crate::c14n::scratch::Bytes> {
        buffer: QueryMarkup<B>,
        failure: Option<Unavailable>,
    }
    impl<B: crate::c14n::scratch::Bytes> std::io::Write for Output<B> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.failure.is_none() {
                if let Err(error) = self.buffer.append(bytes) {
                    self.failure = Some(error);
                } else {
                    return Ok(bytes.len());
                }
            }
            Err(std::io::ErrorKind::OutOfMemory.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let carried = parameter.carried_bytes();
    let limit = budget
        .xslt
        .max_workspace
        .checked_sub(carried)
        .ok_or_else(|| budget.xslt.workspace_error(carried))?;
    let mut output = Output {
        buffer: QueryMarkup {
            bytes: scratch.bytes(),
            limit,
        },
        failure: None,
    };
    let algorithm = crate::c14n::C14nAlgorithm::from_uri(super::DEFAULT_IMPLICIT_C14N_URI)
        .expect("constant C14N URI");
    let result = crate::c14n::canonicalize_visible_to_writer_in(
        document,
        visibility,
        (&algorithm, None),
        budget.c14n.remaining(),
        budget.xml_base_resolution(),
        &mut output,
        scratch,
    );
    if let Some(error) = output.failure {
        return Err(match error {
            Unavailable::Exceeds(needed) => {
                budget.xslt.workspace_error(carried.saturating_add(needed))
            }
            Unavailable::Refused(error) => error,
            Unavailable::Missing => unreachable!("byte append cannot lack a stylesheet"),
        });
    }
    result.map_err(|error| super::map_c14n_limit_error(error, &budget.c14n))?;
    budget.c14n.charge(output.buffer.bytes.len())?;
    Ok(output.buffer.bytes)
}

enum QueryStylesheet<'a, B: crate::c14n::scratch::Bytes> {
    Borrowed(&'a str),
    Owned(QueryMarkup<B>),
}

impl<B: crate::c14n::scratch::Bytes> QueryStylesheet<'_, B> {
    fn len(&self) -> usize {
        match self {
            Self::Borrowed(text) => text.len(),
            Self::Owned(text) => text.len(),
        }
    }
    fn text(&self) -> &str {
        match self {
            Self::Borrowed(text) => text,
            Self::Owned(text) => text.text(),
        }
    }
    fn capacity(&self) -> usize {
        match self {
            Self::Borrowed(_) => 0,
            Self::Owned(text) => text.bytes.capacity(),
        }
    }
}

enum DecodeFailure {
    Encoding(crate::encoding::XmlEncodingError),
    Refused(TransformError),
}

impl From<crate::encoding::XmlEncodingError> for DecodeFailure {
    fn from(error: crate::encoding::XmlEncodingError) -> Self {
        Self::Encoding(error)
    }
}

/// The existing decoder grammar, with the same query storage and a bounded
/// growth peak. Native and accounted execution use one allocation strategy.
struct WorkspaceDecoder<'s, S> {
    scratch: &'s S,
    limit: usize,
    held: usize,
}

impl<S: TransformScratch> WorkspaceDecoder<'_, S> {
    fn refused(&self, error: Unavailable) -> DecodeFailure {
        DecodeFailure::Refused(match error {
            Unavailable::Exceeds(actual) => PolicyViolation::ResourceLimit {
                resource: resource_name::XSLT_WORKSPACE_BYTES,
                maximum: self.limit + self.held,
                actual: self.held.saturating_add(actual),
            }
            .into(),
            Unavailable::Refused(error) => error,
            Unavailable::Missing => unreachable!("decoding has no stylesheet lookup"),
        })
    }
}

impl<S: TransformScratch> crate::xml_input_shared::DecodeStorage for WorkspaceDecoder<'_, S> {
    type Text = <S::Decoder as crate::xml_input_shared::DecodeStorage>::Text;
    type Buffer = QueryMarkup<S::Bytes>;
    type Error = DecodeFailure;
    fn label_error(&self, kind: crate::xml_input_shared::LabelError, label: &str) -> DecodeFailure {
        DecodeFailure::Refused(S::decode_error(
            self.scratch.decoder().label_error(kind, label),
        ))
    }
    fn charge(&self, bytes: usize) -> Result<(), DecodeFailure> {
        self.scratch
            .charge(bytes)
            .map_err(|error| DecodeFailure::Refused(error.into()))
    }
    fn buffer(&self) -> Self::Buffer {
        QueryMarkup {
            bytes: self.scratch.bytes(),
            limit: self.limit,
        }
    }
    fn len(&self, buffer: &Self::Buffer) -> usize {
        buffer.len()
    }
    fn append(&self, buffer: &mut Self::Buffer, text: &str) -> Result<(), DecodeFailure> {
        buffer.push_str(text).map_err(|error| self.refused(error))
    }
    fn finish(&self, buffer: Self::Buffer) -> Result<Self::Text, DecodeFailure> {
        S::decoded_text(buffer.bytes).map_err(DecodeFailure::Refused)
    }
    fn replace(
        &self,
        text: Self::Text,
        range: std::ops::Range<usize>,
        replacement: &str,
    ) -> Result<Self::Text, DecodeFailure> {
        let mut buffer = self.buffer();
        let held = S::decoded_capacity(&text);
        buffer.limit = self
            .limit
            .checked_sub(held)
            .ok_or_else(|| self.refused(Unavailable::Exceeds(held)))?;
        for part in [
            &text.as_ref()[..range.start],
            replacement,
            &text.as_ref()[range.end..],
        ] {
            buffer.push_str(part).map_err(|error| {
                self.refused(match error {
                    Unavailable::Exceeds(actual) => {
                        Unavailable::Exceeds(held.saturating_add(actual))
                    }
                    error => error,
                })
            })?;
        }
        self.finish(buffer)
    }
}

/// Whether `element` is an `xsl:stylesheet` or `xsl:transform` element.
///
/// XMLDSig 1.1 section 6.6.5 requires "the mandatory XSLT namespace-qualified
/// stylesheet element" as the parameter, so a literal result element used as a
/// simplified stylesheet (XSLT 1.0 section 2.3) is not accepted.
/// <https://www.w3.org/TR/xmldsig-core1/#sec-XSLT>
pub(super) fn is_stylesheet_element(element: crate::xml::dom::Node<'_, '_>) -> bool {
    const XSLT_NS: &str = "http://www.w3.org/1999/XSL/Transform";
    let name = element.tag_name();
    name.namespace() == Some(XSLT_NS) && matches!(name.name(), "stylesheet" | "transform")
}

/// Append `value`, writing each byte `escape` maps as its reference and the runs
/// between them as they are.
fn push_escaped(
    out: &mut impl Markup,
    value: &str,
    escape: impl Fn(u8) -> Option<&'static str>,
) -> Result<(), Unavailable> {
    let mut run = 0;
    for (index, byte) in value.bytes().enumerate() {
        // Every escaped character is ASCII, so `index` is a character boundary.
        if let Some(reference) = escape(byte) {
            out.push_str(&value[run..index])?;
            out.push_str(reference)?;
            run = index + 1;
        }
    }
    out.push_str(&value[run..])
}

/// Append `value` as the content of a double-quoted attribute.
fn push_attribute_value(out: &mut impl Markup, value: &str) -> Result<(), Unavailable> {
    push_escaped(out, value, |byte| match byte {
        b'&' => Some("&amp;"),
        b'<' => Some("&lt;"),
        b'"' => Some("&quot;"),
        // Attribute-value normalization would turn these into spaces.
        b'\t' => Some("&#9;"),
        b'\n' => Some("&#10;"),
        b'\r' => Some("&#13;"),
        _ => None,
    })
}

/// Append `value` as character data.
fn push_text(out: &mut impl Markup, value: &str) -> Result<(), Unavailable> {
    push_escaped(out, value, |byte| match byte {
        b'&' => Some("&amp;"),
        b'<' => Some("&lt;"),
        b'>' => Some("&gt;"),
        // Line-end normalization would turn a literal carriage return into a line feed.
        b'\r' => Some("&#13;"),
        _ => None,
    })
}

/// Append `prefix:local`, or `local` without a prefix.
fn push_name(out: &mut impl Markup, prefix: Option<&str>, local: &str) -> Result<(), Unavailable> {
    if let Some(prefix) = prefix {
        out.push_str(prefix)?;
        out.push(':')?;
    }
    out.push_str(local)
}

/// Append ` prefix:local="value"`.
fn push_attribute(
    out: &mut impl Markup,
    prefix: Option<&str>,
    local: &str,
    value: &str,
) -> Result<(), Unavailable> {
    out.push(' ')?;
    push_name(out, prefix, local)?;
    out.push_str("=\"")?;
    push_attribute_value(out, value)?;
    out.push('"')
}

/// Append ` xmlns[:prefix]="uri"`.
fn push_declaration(
    out: &mut impl Markup,
    prefix: Option<&str>,
    uri: &str,
) -> Result<(), Unavailable> {
    match prefix {
        Some(prefix) => push_attribute(out, Some("xmlns"), prefix, uri),
        None => push_attribute(out, None, "xmlns", uri),
    }
}

/// The `xml:space` value `element` carries itself.
fn own_xml_space<'a>(element: crate::xml::dom::Node<'a, 'a>) -> Option<&'a str> {
    const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
    element
        .attributes()
        .find(|attribute| attribute.namespace() == Some(XML_NS) && attribute.name() == "space")
        .map(|attribute| attribute.value())
}

/// Work done outside any query: an owned transform is serialized once, when it is built.
#[cfg(test)]
fn unmetered(_: usize) -> Result<(), TransformError> {
    Ok(())
}

/// Prefixes declared on `element` itself, `None` for the default namespace; `work`
/// pays for each step before it runs.
///
/// The tree keeps only in-scope bindings. The declarations written in the
/// element's start tag are read from it, including those that repeat a binding
/// of the parent; bindings that differ from the parent's are added, which covers
/// declarations an internal DTD defaults (XML 1.0 section 3.3.2) and elements
/// produced by entity replacement, which have no start tag of their own.
fn declared_prefixes<'a, W: FnMut(usize) -> Result<(), TransformError>, S: TransformScratch>(
    element: crate::xml::dom::Node<'a, 'a>,
    work: &mut W,
    scratch: &S,
) -> Result<S::Values<Option<&'a str>>, TransformError> {
    let range = element.range();
    // XML 1.0 sections 3.1 and 4.4.2: an included entity's children can
    // originate in the DTD, so their source ranges cannot delimit this tag.
    // https://www.w3.org/TR/2008/REC-xml-20081126/#sec-starttags
    let source = element
        .document()
        .input_text()
        .get(range.clone())
        .filter(|markup| markup.starts_with('<'))
        .unwrap_or("");
    let mut quote = None;
    let mut end = 0;
    for (index, byte) in source.bytes().enumerate() {
        work(1)?;
        match (quote, byte) {
            (Some(delimiter), byte) if delimiter == byte => quote = None,
            (None, b'\'' | b'"') => quote = Some(byte),
            (None, b'>') => {
                end = index + 1;
                break;
            }
            _ => {}
        }
    }
    let markup = &source[..end];
    let scope = element.namespaces().len();
    work(markup.len())?;
    let tag = match crate::xml_input_shared::lexical::Scanner::with_storage(
        markup,
        scratch.dom_storage(),
    )
    .next_event()
    {
        Ok(Some(
            crate::xml_input_shared::lexical::Event::Start(tag)
            | crate::xml_input_shared::lexical::Event::Empty(tag),
        )) => Some(tag),
        Err(error @ crate::xml_input_shared::lexical::Error::Resource(_)) => {
            return Err(S::lexical_error(error));
        }
        _ => None,
    };
    let mut declared = scratch.values();
    if let Some(tag) = tag {
        work(tag.attributes.len() * (scope + 1))?;
        for prefix in tag.attributes.iter().filter_map(|attribute| {
            let name = attribute.name;
            if name.prefix().is_none() && name.local() == "xmlns" {
                Some(None)
            } else if name.prefix() == Some("xmlns") {
                element
                    .namespaces()
                    .find(|namespace| namespace.name() == Some(name.local()))
                    .map(|namespace| namespace.name())
            } else {
                None
            }
        }) {
            declared.push(prefix)?;
        }
    }
    let parent = element.parent();
    let parent_scope = parent.map_or(0, |parent| parent.namespaces().len());
    let inherited =
        |prefix: Option<&str>| parent.and_then(|parent| parent.lookup_namespace_uri(prefix));
    for namespace in element.namespaces() {
        work(parent_scope + declared.len() + 1)?;
        let prefix = namespace.name();
        if inherited(prefix) != Some(namespace.uri()) && !declared.contains(&prefix) {
            declared.push(prefix)?;
        }
    }
    work(scope + parent_scope + declared.len() + 1)?;
    if element.lookup_namespace_uri(None).is_none()
        && inherited(None).is_some()
        && !declared.contains(&None)
    {
        declared.push(None)?;
    }
    Ok(declared)
}

/// What a serialized stylesheet does with what its element inherits.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Inheritance {
    /// Written on the stylesheet element: the text compiled under the specification.
    Inline,
    /// Kept apart, for either semantics to use later.
    Separate,
    /// Neither written nor kept: the text compiled under libxmlsec1 semantics.
    Omit,
}

impl ParsedStylesheet {
    /// Serialize the stylesheet element of `transform` from the parsed tree, refusing
    /// before the text would take more than `limit` bytes; `work` pays for each step
    /// before it runs.
    fn from_transform<W: FnMut(usize) -> Result<(), TransformError>>(
        transform: crate::xml::dom::Node<'_, '_>,
        limit: usize,
        inheritance: Inheritance,
        work: &mut W,
    ) -> Result<Self, Unavailable> {
        let root = transform
            .children()
            .find(|child| child.is_element())
            .ok_or(Unavailable::Missing)?;
        let mut inherited = Bounded::new(limit);
        if inheritance != Inheritance::Omit {
            serialize_inherited(
                transform,
                root,
                &mut inherited,
                work,
                &crate::c14n::scratch::Native,
            )?;
        }
        // `Bounded` keeps its capacity within its limit.
        let mut document = Bounded::new(limit - inherited.text.capacity());
        let inline = (inheritance == Inheritance::Inline).then_some(inherited.text.as_str());
        let at = serialize_stylesheet_children(
            transform,
            root,
            &mut document,
            inline,
            work,
            &crate::c14n::scratch::Native,
        )?;
        Ok(Self {
            document: document.text,
            inherited: inherited.text,
            at,
        })
    }
}

fn serialize_inherited<W: FnMut(usize) -> Result<(), TransformError>, S: TransformScratch>(
    transform: crate::xml::dom::Node<'_, '_>,
    root: crate::xml::dom::Node<'_, '_>,
    out: &mut impl Markup,
    work: &mut W,
    scratch: &S,
) -> Result<(), Unavailable> {
    let root_declarations = declared_prefixes(root, work, scratch)?;
    for namespace in transform.namespaces() {
        work(root_declarations.len() + namespace.uri().len() + 1)?;
        let prefix = namespace.name();
        if prefix != Some("xml") && !root_declarations.contains(&prefix) {
            push_declaration(out, prefix, namespace.uri())?;
        }
    }
    // XSLT 1.0 section 3.4: the nearest inherited xml:space applies to
    // stylesheet text, not to source-document stripping.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#strip
    let mut space = None;
    let mut ancestor = Some(root);
    while space.is_none()
        && let Some(node) = ancestor
    {
        work(node.attributes().len() + 1)?;
        space = node
            .is_element()
            .then(|| own_xml_space(node))
            .flatten()
            .map(|value| (node == root, value));
        ancestor = node.parent();
    }
    if space == Some((false, "preserve")) {
        push_attribute(out, Some("xml"), "space", "preserve")?;
    }
    Ok(())
}

impl<'a> XsltParameter<'a> {
    /// Serialize directly into current-query storage before the native engine
    /// lease is admitted. No intermediate native document or ownership copy.
    fn document_in<S: TransformScratch>(
        self,
        semantics: XsltStylesheetSemantics,
        limit: usize,
        scratch: &S,
        work: &mut impl FnMut(usize) -> Result<(), TransformError>,
    ) -> Result<QueryStylesheet<'a, S::Bytes>, Unavailable> {
        let mut out = QueryMarkup {
            bytes: scratch.bytes(),
            limit,
        };
        match self {
            Self::Stylesheet(stylesheet) => match &stylesheet.parsed {
                Some(parsed)
                    if semantics == XsltStylesheetSemantics::Specification
                        && !parsed.inherited.is_empty() =>
                {
                    let size = parsed
                        .document
                        .len()
                        .checked_add(parsed.inherited.len())
                        .ok_or(usize::MAX)?;
                    if size > limit {
                        return Err(Unavailable::Exceeds(size));
                    }
                    work(size)?;
                    // All three fragments are known: reserve the final shape once.
                    out.bytes.reserve(size).map_err(TransformError::from)?;
                    if out.bytes.capacity() > limit {
                        return Err(Unavailable::Exceeds(out.bytes.capacity()));
                    }
                    let (head, tail) = parsed.document.split_at(parsed.at);
                    for part in [head, &parsed.inherited, tail] {
                        out.push_str(part)?;
                    }
                }
                Some(parsed) => return Ok(QueryStylesheet::Borrowed(&parsed.document)),
                None => return Ok(QueryStylesheet::Borrowed(&stylesheet.source)),
            },
            Self::Transform(transform) => {
                let root = transform
                    .children()
                    .find(|child| child.is_element())
                    .ok_or(Unavailable::Missing)?;
                let mut inherited = QueryMarkup {
                    bytes: scratch.bytes(),
                    limit,
                };
                if semantics == XsltStylesheetSemantics::Specification {
                    serialize_inherited(transform, root, &mut inherited, work, scratch)?;
                }
                out.limit -= inherited.bytes.capacity();
                work(inherited.len())?;
                serialize_stylesheet_children(
                    transform,
                    root,
                    &mut out,
                    Some(inherited.text()),
                    work,
                    scratch,
                )?;
            }
        }
        Ok(QueryStylesheet::Owned(out))
    }
}

fn serialize_stylesheet_children<
    W: FnMut(usize) -> Result<(), TransformError>,
    S: TransformScratch,
>(
    transform: crate::xml::dom::Node<'_, '_>,
    root: crate::xml::dom::Node<'_, '_>,
    out: &mut impl Markup,
    inherited: Option<&str>,
    work: &mut W,
    scratch: &S,
) -> Result<usize, Unavailable> {
    // XSLT 1.0 section 12.1: document('') exposes the stylesheet document,
    // including comments and processing instructions beside its root element.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#document
    let mut at = 0;
    for child in transform.children() {
        if child.is_text() {
            let text = child.text().unwrap_or("");
            work(text.len() + 1)?;
            // XPath 1.0 section 5.1 excludes text children of the root node.
            // XML 1.0 section 2.8 permits literal Misc whitespace here, not
            // character references such as the escaped carriage return.
            // https://www.w3.org/TR/1999/REC-xpath-19991116/#root-node
            // https://www.w3.org/TR/2008/REC-xml-20081126/#sec-prolog-dtd
            if super::super::whitespace::is_xml_whitespace_only(text) {
                continue;
            }
        }
        let offset = serialize_element(
            child,
            out,
            if child == root { inherited } else { None },
            work,
            scratch,
        )?;
        if child == root {
            at = offset;
        }
    }
    Ok(at)
}

/// Write `root` and its content to `out`; returns the offset just after its name,
/// where `inherited` is written when given.
///
/// The walk follows sibling and parent links, so neither native recursion nor a
/// stack grows with the stylesheet. `work` pays for each node before it is written:
/// its names and values, and the namespace lookups of its declarations.
fn serialize_element<W: FnMut(usize) -> Result<(), TransformError>, S: TransformScratch>(
    root: crate::xml::dom::Node<'_, '_>,
    out: &mut impl Markup,
    inherited: Option<&str>,
    work: &mut W,
    scratch: &S,
) -> Result<usize, Unavailable> {
    let mut at = 0;
    let mut node = root;
    loop {
        let mut descended = false;
        if node.is_element() {
            let name = node.prefix().map_or(0, str::len) + node.tag_name().name().len();
            // Opened and closed, with the markup around both.
            work(2 * name + 5)?;
            out.push('<')?;
            push_name(out, node.prefix(), node.tag_name().name())?;
            if node == root {
                at = out.len();
                if let Some(inherited) = inherited {
                    out.push_str(inherited)?;
                }
            }
            let scope = node.namespaces().len();
            for prefix in declared_prefixes(node, work, scratch)?.iter().copied() {
                work(scope + 1)?;
                push_declaration(out, prefix, node.lookup_namespace_uri(prefix).unwrap_or(""))?;
            }
            for attribute in node.attributes() {
                work(
                    attribute.prefix().map_or(0, str::len)
                        + attribute.name().len()
                        + attribute.value().len()
                        + 4,
                )?;
                push_attribute(out, attribute.prefix(), attribute.name(), attribute.value())?;
            }
            if let Some(child) = node.first_child() {
                out.push('>')?;
                node = child;
                descended = true;
            } else {
                out.push_str("/>")?;
            }
        } else if node.is_comment() {
            work(node.text().map_or(0, str::len) + 7)?;
            out.push_str("<!--")?;
            out.push_str(node.text().unwrap_or(""))?;
            out.push_str("-->")?;
        } else if node.is_pi() {
            if let Some(pi) = node.pi() {
                work(pi.target.len() + pi.value.map_or(0, str::len) + 5)?;
                out.push_str("<?")?;
                out.push_str(pi.target)?;
                if let Some(value) = pi.value {
                    out.push(' ')?;
                    out.push_str(value)?;
                }
                out.push_str("?>")?;
            }
        } else {
            work(node.text().map_or(0, str::len) + 1)?;
            push_text(out, node.text().unwrap_or(""))?;
        }
        if descended {
            continue;
        }
        // Move to the next node, closing every element whose content is complete.
        loop {
            if node == root {
                return Ok(at);
            }
            if let Some(next) = node.next_sibling() {
                node = next;
                break;
            }
            node = node
                .parent()
                .expect("a node below the stylesheet has a parent");
            out.push_str("</")?;
            push_name(out, node.prefix(), node.tag_name().name())?;
            out.push('>')?;
        }
    }
}

/// One XSLT allowance shared by every execution in an operation.
pub(crate) struct Allowance {
    work_used: [Cell<usize>; WORK_KINDS.len()],
    serialization_used: Cell<usize>,
    output_used: Cell<usize>,
    max_work: usize,
    max_output: usize,
    max_workspace: usize,
    max_recursion: usize,
    max_document_bytes: usize,
    max_nodes: usize,
    max_depth: usize,
}

impl Default for Allowance {
    fn default() -> Self {
        Self::new(&ResourcePolicy::default())
    }
}

impl Allowance {
    pub(crate) fn new(resources: &ResourcePolicy) -> Self {
        Self {
            work_used: Default::default(),
            serialization_used: Cell::new(0),
            output_used: Cell::new(0),
            max_work: resources.max_xslt_work,
            max_output: resources.max_xslt_output_bytes,
            max_workspace: resources.max_xslt_workspace_bytes,
            max_recursion: resources.max_xslt_recursion_depth,
            max_document_bytes: resources.max_xml_document_bytes,
            max_nodes: resources.max_xml_nodes,
            max_depth: resources.max_xml_depth,
        }
    }

    fn workspace_error(&self, actual: usize) -> TransformError {
        PolicyViolation::ResourceLimit {
            resource: resource_name::XSLT_WORKSPACE_BYTES,
            maximum: self.max_workspace,
            actual,
        }
        .into()
    }

    fn serialize(&self, units: usize) -> Result<(), TransformError> {
        let used = self.serialization_used.get();
        if units > self.max_work - used {
            return Err(PolicyViolation::ResourceLimit {
                resource: resource_name::XSLT_WORK,
                maximum: self.max_work,
                actual: used.saturating_add(units),
            }
            .into());
        }
        self.serialization_used.set(used + units);
        Ok(())
    }

    fn work_used(&self, kind: BudgetKind) -> usize {
        WORK_KINDS
            .iter()
            .position(|candidate| *candidate == kind)
            .map_or(0, |index| self.work_used[index].get())
    }

    fn execution_budget(&self, workspace: usize) -> ExecutionBudget {
        // Each admitted amount was at most the remainder offered, so `used <= max` holds.
        let remaining = |kind| self.max_work - self.work_used(kind);
        ExecutionBudget {
            source_bytes: self.max_document_bytes,
            // Stylesheets cannot resolve resources: `document()` has no capability to use.
            external_documents: 0,
            recursion_depth: self.max_recursion,
            xpath_evaluations: remaining(BudgetKind::XPathEvaluations),
            xpath_operations: remaining(BudgetKind::XPathOperations),
            extension_operations: remaining(BudgetKind::ExtensionOperations),
            pattern_evaluations: remaining(BudgetKind::PatternEvaluations),
            template_applications: remaining(BudgetKind::TemplateApplications),
            sort_comparisons: remaining(BudgetKind::SortComparisons),
            key_entries: remaining(BudgetKind::KeyEntries),
            result_nodes: remaining(BudgetKind::ResultNodes),
            serialized_bytes: self.max_output - self.output_used.get(),
            messages: remaining(BudgetKind::Messages),
            owned_bytes: workspace,
        }
    }

    fn admit(&self, usage: &ExecutionUsage) {
        for (index, kind) in WORK_KINDS.into_iter().enumerate() {
            let used = &self.work_used[index];
            used.set(used.get() + admitted(usage, kind));
        }
        self.output_used
            .set(self.output_used.get() + usage.serialized_bytes);
    }
}

#[derive(Clone, Copy)]
enum Phase {
    Stylesheet,
    Input,
    Execution,
}

fn uri_refusal() -> TransformError {
    // XMLDSig gives the transform no base URI or resolver; libxmlsec1 forbids
    // file and network access through xsltSetSecurityPrefs as well.
    PolicyViolation::Uri {
        operation: "XSLT transform",
        reason: "stylesheets cannot resolve external resources",
    }
    .into()
}

fn map_error<S: TransformScratch>(
    error: Error,
    phase: Phase,
    held: usize,
    allowance: &Allowance,
    workspace: usize,
    scratch: &S,
) -> TransformError {
    let limit = |resource, maximum, actual| -> TransformError {
        PolicyViolation::ResourceLimit {
            resource,
            maximum,
            actual,
        }
        .into()
    };
    match error {
        Error::Budget { kind, actual, .. } => match kind {
            BudgetKind::OwnedBytes | BudgetKind::NamespaceScopeBytes
                if workspace < allowance.max_workspace =>
            {
                // The operation's memory account, not the policy, granted less.
                structured_asn1::memory::MemoryError::LimitExceeded.into()
            }
            BudgetKind::OwnedBytes | BudgetKind::NamespaceScopeBytes => limit(
                resource_name::XSLT_WORKSPACE_BYTES,
                allowance.max_workspace,
                // The engine reports `usize::MAX` for a total it cannot represent;
                // adding what earlier stages hold keeps that meaning.
                held.saturating_add(actual),
            ),
            BudgetKind::StylesheetBytes | BudgetKind::SourceBytes => limit(
                resource_name::XML_DOCUMENT,
                allowance.max_document_bytes,
                actual,
            ),
            BudgetKind::SourceNodes => limit(resource_name::XML_NODES, allowance.max_nodes, actual),
            BudgetKind::RecursionDepth => match phase {
                Phase::Input => limit(resource_name::XML_DEPTH, allowance.max_depth, actual),
                Phase::Stylesheet | Phase::Execution => limit(
                    resource_name::XSLT_RECURSION_DEPTH,
                    allowance.max_recursion,
                    actual,
                ),
            },
            BudgetKind::SerializedBytes => limit(
                resource_name::XSLT_OUTPUT_BYTES,
                allowance.max_output,
                allowance.output_used.get() + actual,
            ),
            BudgetKind::ImportedModules | BudgetKind::ExternalDocuments => uri_refusal(),
            kind if WORK_KINDS.contains(&kind) => limit(
                resource_name::XSLT_WORK,
                allowance.max_work,
                allowance.work_used(kind) + actual,
            ),
            _ => scratch.xslt_error(&Error::Budget {
                kind,
                limit: 0,
                actual,
            }),
        },
        Error::StaleResource { .. }
        | Error::ResourceNotFound { .. }
        | Error::Resolver { .. }
        | Error::ResourceAccessDenied { .. } => uri_refusal(),
        error => scratch.xslt_error(&error),
    }
}

/// Refuse a document type declaration before the engine applies it.
///
/// The engine expands internal entities and applies attribute defaults, which
/// changes the signed data, so this follows the operation's XML input policy. The
/// query pays for the scan before it runs.
fn reject_document_type<S: TransformScratch>(
    xml: &str,
    settings: DocumentParseSettings,
    scratch: &S,
) -> Result<(), TransformError> {
    if settings.allow_dtd {
        return Ok(());
    }
    scratch.charge(xml.len())?;
    let mut scanner = crate::xml_input_shared::lexical::Scanner::new(xml);
    // A lexical error is reported by the engine's own parse of the same text.
    while let Ok(Some(event)) = scanner.next_event() {
        match event {
            crate::xml_input_shared::lexical::Event::DocType { .. } => {
                return Err(super::map_transform_xml_parse_error(
                    XmlDocumentError::Parse(crate::xml::dom::ParseError::DtdDetected),
                    settings,
                ));
            }
            crate::xml_input_shared::lexical::Event::Start(_)
            | crate::xml_input_shared::lexical::Event::Empty(_) => return Ok(()),
            _ => {}
        }
    }
    Ok(())
}

/// The parser work an engine pass may do: what both the operation and the query admit.
fn parse_work_limit<S: TransformScratch>(xml_parse: &XmlParseWorkBudget, scratch: &S) -> usize {
    xml_parse.remaining().min(scratch.work_remaining())
}

/// Debit the parser work an engine pass admitted from the operation and the query; a
/// pass refused at the offered limit is refused by whichever of the two set it.
fn charge_parse_work<T, S: TransformScratch>(
    reported: Reported<T, ParseUsage>,
    xml_parse: &XmlParseWorkBudget,
    scratch: &S,
) -> Result<Result<T, Error>, TransformError> {
    // The engine was offered the smaller remainder, so what it admitted fits both.
    let used = reported.usage.parse_work_bytes;
    xml_parse.charge_policy(used)?;
    scratch.charge(used)?;
    match reported.outcome {
        Err(Error::Budget {
            kind: BudgetKind::ParseWorkBytes,
            actual,
            ..
        }) => {
            let excess = actual - used;
            let refused = if excess > xml_parse.remaining() {
                xml_parse
                    .charge_policy(excess)
                    .err()
                    .map(TransformError::from)
            } else {
                scratch.charge(excess).err().map(TransformError::from)
            };
            Err(refused.unwrap_or_else(|| {
                TransformError::Xslt("XSLT parser work exceeded its allowance".into())
            }))
        }
        outcome => Ok(outcome),
    }
}

/// Apply the stylesheet of `parameter` to the octets `input` and return the serialized result.
///
/// The input is decoded first, into the query's own account; compilation, the
/// parsed input and execution then share one workspace from what remains: each
/// stage receives what the earlier ones still hold subtracted from it.
#[allow(clippy::too_many_arguments)]
pub(super) fn execute<'d, S: TransformScratch, D: DomStorage>(
    parameter: XsltParameter<'_>,
    input: &[u8],
    input_storage: usize,
    semantics: XsltStylesheetSemantics,
    allow_dtd: bool,
    budget: &TransformExecutionBudget,
    xml_parse: &XmlParseWorkBudget,
    scratch: &S,
) -> Result<ExecutionData<'d, S, D>, TransformError> {
    let allowance = &budget.xslt;
    let carried = parameter
        .carried_bytes()
        .checked_add(input_storage)
        .ok_or_else(|| allowance.workspace_error(usize::MAX))?;
    let available = allowance
        .max_workspace
        .checked_sub(carried)
        .ok_or_else(|| allowance.workspace_error(carried))?;
    let settings = DocumentParseSettings {
        allow_dtd,
        ..budget.xml_parse_settings
    };
    super::check_xml_octets(input, settings)?;
    xml_parse.charge_policy(input.len())?;
    let xml = crate::xml_input_shared::decode_xml_in(
        input,
        settings.max_bytes,
        |_, _| Ok(()),
        &WorkspaceDecoder {
            scratch,
            limit: available,
            held: carried,
        },
    )
    .map_err(|error| match error {
        DecodeFailure::Encoding(error) => super::map_transform_xml_decode_error(error),
        DecodeFailure::Refused(error) => error,
    })?;
    let decoded = match &xml {
        crate::xml_input_shared::Decoded::Borrowed(_) => 0,
        crate::xml_input_shared::Decoded::Owned(text) => S::decoded_capacity(text),
    };
    // The query pays for each of the adapter's lexical passes before it runs.
    reject_document_type(xml.as_ref(), settings, scratch)?;
    // The engine's parser does not count namespace bindings or apply the rest of
    // the operation's XML input policy itself.
    scratch.charge(xml.as_ref().len())?;
    crate::document::preflight_xml_limits(xml.as_ref(), settings, xml_parse, scratch.dom_storage())
        .map_err(|error| super::map_transform_xml_parse_error(error, settings))?;

    // Copies a parsed stylesheet carries stay in the workspace until the transform ends.
    let available = allowance
        .max_workspace
        .checked_sub(carried + decoded)
        .ok_or_else(|| allowance.workspace_error(carried.saturating_add(decoded)))?;
    // Query-owned text and lexical preflight precede the opaque native lease:
    // both allocate and charge through the same current Work, never a new account.
    let stylesheet = parameter
        .document_in(semantics, available, scratch, &mut |units| {
            allowance.serialize(units)?;
            scratch.charge(units).map_err(TransformError::from)
        })
        .map_err(|unavailable| match unavailable {
            Unavailable::Missing => {
                TransformError::UnsupportedTransform("XSLT transform requires a stylesheet".into())
            }
            Unavailable::Exceeds(needed) => {
                allowance.workspace_error(carried.saturating_add(needed))
            }
            Unavailable::Refused(error) => error,
        })?;

    // The stylesheet is element content, which cannot hold a document type declaration.
    let stylesheet_settings = DocumentParseSettings {
        allow_dtd: false,
        ..budget.xml_parse_settings
    };
    // Validate constructed UTF-8 once, after admission, and borrow that view
    // throughout preflight and compilation rather than rescanning on access.
    scratch.charge(stylesheet.len())?;
    let stylesheet_text = stylesheet.text();
    crate::document::preflight_xml_limits(
        stylesheet_text,
        stylesheet_settings,
        xml_parse,
        scratch.dom_storage(),
    )
    .map_err(|error| super::map_transform_xml_parse_error(error, stylesheet_settings))?;
    // Text assembled with inherited declarations lives in the workspace until compiled.
    let assembled = stylesheet.capacity();
    let maximum = allowance
        .max_workspace
        .checked_sub(assembled + decoded)
        .and_then(|remaining| remaining.checked_sub(input_storage))
        .ok_or_else(|| {
            allowance.workspace_error(carried.saturating_add(assembled).saturating_add(decoded))
        })?;
    let (reservation, reserved) = scratch.reserve_workspace(maximum)?;
    // Accounted input already owns its allocation in the current query. The
    // opaque engine lease excludes it, while every peak calculation includes it.
    let reserved = reserved + input_storage;
    let workspace = reserved + assembled + decoded;
    let fail = |error, phase, held| map_error(error, phase, held, allowance, workspace, scratch);
    let exhausted = |needed: usize| Error::Budget {
        kind: BudgetKind::OwnedBytes,
        limit: workspace,
        actual: needed,
    };
    let compile_workspace = reserved
        .checked_sub(carried)
        .ok_or_else(|| fail(exhausted(carried), Phase::Stylesheet, 0))?;
    let compiled = charge_parse_work(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(
                allowance.max_document_bytes,
                0,
                allowance.max_recursion,
                compile_workspace,
            )
            .with_parse_work_bytes(parse_work_limit(xml_parse, scratch)),
        )
        .unbound_prefix_lists(match semantics {
            XsltStylesheetSemantics::Specification => UnboundPrefixLists::Reject,
            XsltStylesheetSemantics::Libxmlsec1 => UnboundPrefixLists::Ignore,
        })
        .compile_reported(stylesheet_text, None),
        xml_parse,
        scratch,
    )?
    .map_err(|error| fail(error, Phase::Stylesheet, carried + assembled + decoded))?;
    // Compilation no longer borrows the text. Release its actual allocation,
    // then admit that capacity for later engine stages while the first lease
    // continues to cover the compiled tree. A competing query may get it first.
    drop(stylesheet);
    let (execution_reservation, reclaimed) = scratch.reserve_workspace(assembled)?;
    let workspace = reserved + reclaimed + decoded;
    let fail = |error, phase, held| map_error(error, phase, held, allowance, workspace, scratch);
    // Both fit the workspace, so their sum cannot overflow.
    let held = carried + compiled.retained_bytes() + decoded;

    let (entity_references, entity_expansion_bytes) = if allow_dtd {
        (
            crate::hard_limits::XML_ENTITY_EXPANSION_CEILING as usize,
            crate::hard_limits::XML_ENTITY_EXPANSION_WORK_BYTE_CEILING,
        )
    } else {
        (0, 0)
    };
    let source_workspace = workspace
        .checked_sub(held)
        .ok_or_else(|| fail(exhausted(held), Phase::Input, 0))?;
    let source = charge_parse_work(
        Document::parse_with_budget_reported(
            xml.as_ref(),
            None,
            ParseBudget::new(
                allowance.max_document_bytes,
                allowance.max_nodes,
                allowance.max_depth,
                entity_references,
                entity_expansion_bytes.min(source_workspace),
                source_workspace,
            )
            .with_owned_bytes(source_workspace)
            .with_parse_work_bytes(parse_work_limit(xml_parse, scratch)),
        ),
        xml_parse,
        scratch,
    )?
    .map_err(|error| fail(error, Phase::Input, held))?;
    drop(xml);
    let (input_reservation, reclaimed_input) = if decoded == 0 {
        (None, 0)
    } else {
        let (reservation, reclaimed) = scratch.reserve_workspace(decoded)?;
        (Some(reservation), reclaimed)
    };
    let workspace = workspace - decoded + reclaimed_input;
    let fail = |error, phase, held| map_error(error, phase, held, allowance, workspace, scratch);
    let held = (held - decoded)
        .checked_add(source.retained_bytes())
        .ok_or_else(|| fail(exhausted(usize::MAX), Phase::Input, 0))?;

    // The engine opens its owned-byte count with the source's text length, which the
    // tree held above already covers; that opening charge is granted on top.
    let opening = source.source_bytes();
    let execution_workspace = workspace
        .checked_sub(held)
        .and_then(|free| free.checked_add(opening))
        .ok_or_else(|| fail(exhausted(held), Phase::Execution, 0))?;
    let reported = compiled.execute_reported(
        &source,
        &Parameters::new(),
        // The query's remainder bounds the work of every kind together, so the engine
        // stops where the query would refuse it rather than after the policy allows.
        ExecutionEnvironment::new(Arc::new(NoResolver)).with_work_ceiling(scratch.work_remaining()),
        ExecutionOptions {
            budget: allowance.execution_budget(execution_workspace),
            initial_mode: None,
            initial_template: None,
        },
    );
    drop(source);
    drop(compiled);
    // A failed execution spends its work too, and later references and signatures
    // of the operation draw on the same allowance. The error reports the totals
    // before this execution's work is admitted.
    let usage = reported.usage;
    let work = WORK_KINDS
        .into_iter()
        .try_fold(usage.serialized_bytes, |total, kind| {
            total.checked_add(admitted(&usage, kind))
        })
        .expect("each kind is bounded by the policy work ceiling");
    let outcome = match reported.outcome {
        Err(Error::Budget {
            kind: BudgetKind::AggregateWork,
            actual,
            ..
        }) => Err(scratch.charge(actual).err().map_or_else(
            // The query's remainder was the ceiling, so charging the total the
            // engine asked for is refused like any other step of the query.
            || TransformError::Xslt("XSLT work exceeded the query's remainder".into()),
            TransformError::from,
        )),
        // The engine's owned-byte total includes the opening charge `held` already counts.
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            limit,
            actual,
        }) if actual != usize::MAX => Err(fail(
            Error::Budget {
                kind: BudgetKind::OwnedBytes,
                limit,
                actual: actual - opening,
            },
            Phase::Execution,
            held,
        )),
        outcome => outcome.map_err(|error| fail(error, Phase::Execution, held)),
    };
    allowance.admit(&usage);
    // The ceiling admitted at most the remainder, so this fits.
    scratch.charge(work)?;
    let output = outcome?.serialized.bytes;
    if S::ACCOUNTED {
        // The empty accounted buffer reserves exactly output.len() on append.
        // Both copies and carried stylesheet storage must fit the XSLT peak,
        // independently of the query account's remaining memory. Refuse before
        // allocating the copy; dropping engine leases must not reset this limit.
        let peak = output
            .capacity()
            .checked_add(output.len())
            .and_then(|bytes| bytes.checked_add(carried))
            .ok_or_else(|| allowance.workspace_error(usize::MAX))?;
        if peak > allowance.max_workspace {
            return Err(allowance.workspace_error(peak));
        }
        // The native output sits inside the workspace reservation. Move its charge to
        // a reservation of its own, so the account sees both copies while it is copied.
        drop(input_reservation);
        drop(execution_reservation);
        drop(reservation);
        let (output_reservation, granted) = scratch.reserve_workspace(output.capacity())?;
        if granted < output.capacity() {
            return Err(structured_asn1::memory::MemoryError::LimitExceeded.into());
        }
        let mut accounted = scratch.bytes();
        accounted.append(&output)?;
        drop(output);
        drop(output_reservation);
        Ok(ExecutionData::Accounted(accounted))
    } else {
        drop(input_reservation);
        drop(execution_reservation);
        drop(reservation);
        Ok(ExecutionData::NativeBinary(output))
    }
}
