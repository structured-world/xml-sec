//! Zero-copy lexical XML events and deterministic XML serialization.
//!
//! This module is the parser-neutral boundary used before semantic DOM
//! construction. The public event model intentionally does not expose the
//! implementation tokenizer, so consumers can share source ranges, escaping,
//! and serialization without inheriting a parser's tree semantics.

use alloc::{
    borrow::{Cow, ToOwned},
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::ops::Range;

#[cfg(feature = "std")]
use std::{
    collections::HashSet,
    io::{Error as IoError, ErrorKind, Write},
};

/// A lexical XML failure with a source position.
#[derive(Debug, thiserror::Error)]
#[error("XML lexical error: {message}")]
pub struct Error {
    message: String,
}

impl Error {
    fn tokenizer(error: xmlparser::Error) -> Self {
        Self {
            message: error.to_string(),
        }
    }

    fn malformed(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// A borrowed qualified XML name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Name<'a> {
    prefix: &'a str,
    local: &'a str,
}

impl<'a> Name<'a> {
    /// Namespace prefix, or `None` for an unprefixed name.
    #[must_use]
    pub fn prefix(self) -> Option<&'a str> {
        (!self.prefix.is_empty()).then_some(self.prefix)
    }

    /// Local component of the name.
    #[must_use]
    pub const fn local(self) -> &'a str {
        self.local
    }

    /// Compare the lexical qualified name without allocating.
    #[must_use]
    pub fn is_qualified(self, value: &str) -> bool {
        match self.prefix() {
            Some(prefix) => {
                value
                    .strip_prefix(prefix)
                    .and_then(|suffix| suffix.strip_prefix(':'))
                    == Some(self.local)
            }
            None => value == self.local,
        }
    }

    /// Materialize the lexical qualified name.
    #[must_use]
    pub fn qualified(self) -> Cow<'a, str> {
        self.prefix().map_or_else(
            || Cow::Borrowed(self.local),
            |prefix| Cow::Owned(format!("{prefix}:{}", self.local)),
        )
    }
}

/// A borrowed attribute from one start tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attribute<'a> {
    /// Lexical attribute name.
    pub name: Name<'a>,
    /// Raw value before entity/reference expansion.
    pub value: &'a str,
    /// Complete source range of the attribute.
    pub range: Range<usize>,
}

/// A complete start or empty-element tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartTag<'a> {
    /// Lexical element name.
    pub name: Name<'a>,
    /// Attributes in source order.
    pub attributes: Vec<Attribute<'a>>,
    /// Complete source range including `<` and `>`.
    pub range: Range<usize>,
}

/// One lexical XML event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event<'a> {
    /// XML declaration.
    Declaration {
        /// Declared XML version.
        version: &'a str,
        /// Complete declaration range.
        range: Range<usize>,
    },
    /// Processing instruction.
    ProcessingInstruction {
        /// PI target.
        target: &'a str,
        /// Optional PI value without separator whitespace.
        content: Option<&'a str>,
        /// Complete source range.
        range: Range<usize>,
    },
    /// XML comment.
    Comment {
        /// Comment content.
        text: &'a str,
        /// Complete source range.
        range: Range<usize>,
    },
    /// Complete document type declaration.
    DocType {
        /// Declared document element lexical qualified name.
        name: &'a str,
        /// Complete source range.
        range: Range<usize>,
    },
    /// Opening element tag.
    Start(StartTag<'a>),
    /// Empty-element tag.
    Empty(StartTag<'a>),
    /// Closing element tag.
    End {
        /// Lexical closing name.
        name: Name<'a>,
        /// Complete source range.
        range: Range<usize>,
    },
    /// Character data without general references.
    Text {
        /// Raw text.
        text: &'a str,
        /// Source range equal to the text.
        range: Range<usize>,
    },
    /// CDATA content.
    CData {
        /// Unwrapped CDATA content.
        text: &'a str,
        /// Complete source range including delimiters.
        range: Range<usize>,
    },
    /// A character or entity reference from character data.
    Reference {
        /// Reference body without `&` and `;`.
        name: &'a str,
        /// Complete reference range.
        range: Range<usize>,
    },
}

/// Pull-based, zero-copy lexical scanner.
pub struct Scanner<'a> {
    input: &'a str,
    tokenizer: xmlparser::Tokenizer<'a>,
    pending_text: Option<PendingText<'a>>,
    pending_start: Option<PendingStart<'a>>,
    dtd_start: Option<(usize, &'a str)>,
}

struct PendingStart<'a> {
    name: Name<'a>,
    attributes: Vec<Attribute<'a>>,
    start: usize,
}

struct PendingText<'a> {
    text: &'a str,
    range: Range<usize>,
    offset: usize,
}

fn validate_unique_attributes(attributes: &mut [Attribute<'_>]) -> Result<(), Error> {
    const SMALL_TAG_ATTRIBUTES: usize = 8;

    if attributes.len() <= SMALL_TAG_ATTRIBUTES {
        for index in 1..attributes.len() {
            let name = attributes[index].name;
            if attributes[..index]
                .iter()
                .any(|attribute| attribute.name == name)
            {
                return Err(Error::malformed(format!(
                    "duplicate attribute `{}`",
                    name.qualified()
                )));
            }
        }
        return Ok(());
    }

    attributes.sort_unstable_by_key(|attribute| attribute.name);
    if let Some(name) = attributes
        .windows(2)
        .find_map(|pair| (pair[0].name == pair[1].name).then_some(pair[0].name))
    {
        return Err(Error::malformed(format!(
            "duplicate attribute `{}`",
            name.qualified()
        )));
    }
    attributes.sort_unstable_by_key(|attribute| attribute.range.start);
    Ok(())
}

impl<'a> Scanner<'a> {
    /// Scan a complete XML document.
    #[must_use]
    pub fn new(input: &'a str) -> Self {
        Self {
            input,
            tokenizer: xmlparser::Tokenizer::from(input),
            pending_text: None,
            pending_start: None,
            dtd_start: None,
        }
    }

    /// Return the next event, or `None` at end of input.
    pub fn next_event(&mut self) -> Result<Option<Event<'a>>, Error> {
        if let Some(event) = self.next_text_event()? {
            return Ok(Some(event));
        }
        loop {
            let Some(token) = self.tokenizer.next() else {
                if self.pending_start.is_some() {
                    return Err(Error::malformed("unterminated element start tag"));
                }
                return Ok(None);
            };
            let token = token.map_err(Error::tokenizer)?;
            use xmlparser::{ElementEnd, Token};
            match &token {
                Token::DtdStart { name, span, .. } => {
                    self.dtd_start = Some((span.range().start, name.as_str()));
                    continue;
                }
                Token::DtdEnd { span } if self.dtd_start.is_some() => {
                    let (start, name) = self.dtd_start.take().expect("DTD start is present");
                    return Ok(Some(Event::DocType {
                        name,
                        range: start..span.range().end,
                    }));
                }
                _ if self.dtd_start.is_some() => {
                    // Internal-subset tokens belong to the DocType event and
                    // must never be projected as document-tree nodes.
                    continue;
                }
                _ => {}
            }
            match token {
                Token::Declaration { version, span, .. } => {
                    return Ok(Some(Event::Declaration {
                        version: version.as_str(),
                        range: span.range(),
                    }));
                }
                Token::ProcessingInstruction {
                    target,
                    content,
                    span,
                } => {
                    return Ok(Some(Event::ProcessingInstruction {
                        target: target.as_str(),
                        content: content.map(|value| value.as_str()),
                        range: span.range(),
                    }));
                }
                Token::Comment { text, span } => {
                    return Ok(Some(Event::Comment {
                        text: text.as_str(),
                        range: span.range(),
                    }));
                }
                Token::DtdStart { .. } => unreachable!("DTD start is handled above"),
                Token::EmptyDtd { name, span, .. } => {
                    return Ok(Some(Event::DocType {
                        name: name.as_str(),
                        range: span.range(),
                    }));
                }
                Token::DtdEnd { .. } => {
                    return Err(Error::malformed("DOCTYPE end without a start"));
                }
                Token::EntityDeclaration { .. } => {}
                Token::ElementStart {
                    prefix,
                    local,
                    span,
                } => {
                    validate_qualified_lexeme(&self.input[span.range()])?;
                    if self.pending_start.is_some() {
                        return Err(Error::malformed("nested element start tokens"));
                    }
                    self.pending_start = Some(PendingStart {
                        name: Name {
                            prefix: prefix.as_str(),
                            local: local.as_str(),
                        },
                        attributes: Vec::new(),
                        start: span.range().start,
                    });
                }
                Token::Attribute {
                    prefix,
                    local,
                    value,
                    span,
                } => {
                    validate_qualified_lexeme(&self.input[span.range()])?;
                    let start = self
                        .pending_start
                        .as_mut()
                        .ok_or_else(|| Error::malformed("attribute outside a start tag"))?;
                    let name = Name {
                        prefix: prefix.as_str(),
                        local: local.as_str(),
                    };
                    start.attributes.push(Attribute {
                        name,
                        value: value.as_str(),
                        range: span.range(),
                    });
                }
                Token::ElementEnd { end, span } => match end {
                    ElementEnd::Open | ElementEnd::Empty => {
                        let mut start = self
                            .pending_start
                            .take()
                            .ok_or_else(|| Error::malformed("element end without a start"))?;
                        validate_unique_attributes(&mut start.attributes)?;
                        let tag = StartTag {
                            name: start.name,
                            attributes: start.attributes,
                            range: start.start..span.range().end,
                        };
                        return Ok(Some(if end == ElementEnd::Open {
                            Event::Start(tag)
                        } else {
                            Event::Empty(tag)
                        }));
                    }
                    ElementEnd::Close(prefix, local) => {
                        validate_qualified_lexeme(&self.input[span.range()])?;
                        return Ok(Some(Event::End {
                            name: Name {
                                prefix: prefix.as_str(),
                                local: local.as_str(),
                            },
                            range: span.range(),
                        }));
                    }
                },
                Token::Text { text } => {
                    self.pending_text = Some(PendingText {
                        text: text.as_str(),
                        range: text.range(),
                        offset: 0,
                    });
                    if let Some(event) = self.next_text_event()? {
                        return Ok(Some(event));
                    }
                }
                Token::Cdata { text, span } => {
                    return Ok(Some(Event::CData {
                        text: text.as_str(),
                        range: span.range(),
                    }));
                }
            }
        }
    }

    fn next_text_event(&mut self) -> Result<Option<Event<'a>>, Error> {
        let Some(mut pending) = self.pending_text.take() else {
            return Ok(None);
        };
        let tail = &pending.text[pending.offset..];
        let Some(relative) = tail.find('&') else {
            return Ok((!tail.is_empty()).then_some(Event::Text {
                text: tail,
                range: pending.range.start + pending.offset..pending.range.end,
            }));
        };
        let start = pending.offset + relative;
        if start > pending.offset {
            let event = Event::Text {
                text: &pending.text[pending.offset..start],
                range: pending.range.start + pending.offset..pending.range.start + start,
            };
            pending.offset = start;
            self.pending_text = Some(pending);
            return Ok(Some(event));
        }
        let Some(relative_end) = pending.text[start + 1..].find(';') else {
            return Err(Error::malformed(
                "unterminated XML reference in character data",
            ));
        };
        let end = start + 1 + relative_end;
        let event = Event::Reference {
            name: &pending.text[start + 1..end],
            range: pending.range.start + start..pending.range.start + end + 1,
        };
        pending.offset = end + 1;
        if pending.offset < pending.text.len() {
            self.pending_text = Some(pending);
        }
        Ok(Some(event))
    }

    /// Original scanner input.
    #[must_use]
    pub const fn input(&self) -> &'a str {
        self.input
    }
}

fn validate_qualified_lexeme(source: &str) -> Result<(), Error> {
    let source = source.trim_start_matches(['<', '/']).trim_start();
    let name = source
        .split(|character: char| {
            character.is_ascii_whitespace() || matches!(character, '=' | '/' | '>')
        })
        .next()
        .unwrap_or_default();
    let mut parts = name.split(':');
    let first = parts.next().unwrap_or_default();
    let second = parts.next();
    if first.is_empty() || second.is_some_and(str::is_empty) || parts.next().is_some() {
        return Err(Error::malformed("invalid qualified XML name"));
    }
    Ok(())
}

/// Return whether `value` is an XML Namespaces 1.0 `QName`.
#[must_use]
pub fn is_qname(value: &str) -> bool {
    let mut parts = value.split(':');
    let first = parts.next().unwrap_or_default();
    !first.is_empty()
        && is_ncname(first)
        && parts.next().is_none_or(is_ncname)
        && parts.next().is_none()
}

fn is_ncname(value: &str) -> bool {
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    is_ncname_start(first) && characters.all(is_ncname_char)
}

fn is_ncname_start(character: char) -> bool {
    matches!(
        character,
        'A'..='Z'
            | '_'
            | 'a'..='z'
            | '\u{C0}'..='\u{D6}'
            | '\u{D8}'..='\u{F6}'
            | '\u{F8}'..='\u{2FF}'
            | '\u{370}'..='\u{37D}'
            | '\u{37F}'..='\u{1FFF}'
            | '\u{200C}'..='\u{200D}'
            | '\u{2070}'..='\u{218F}'
            | '\u{2C00}'..='\u{2FEF}'
            | '\u{3001}'..='\u{D7FF}'
            | '\u{F900}'..='\u{FDCF}'
            | '\u{FDF0}'..='\u{FFFD}'
            | '\u{10000}'..='\u{EFFFF}'
    )
}

fn is_ncname_char(character: char) -> bool {
    is_ncname_start(character)
        || matches!(
            character,
            '-' | '.' | '0'..='9' | '\u{B7}' | '\u{0300}'..='\u{036F}' | '\u{203F}'..='\u{2040}'
        )
}

/// Namespace prefixes declared directly by one lexical opening tag.
///
/// The default namespace is represented by an empty string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredNamespacePrefixes(Vec<String>);

impl DeclaredNamespacePrefixes {
    /// Return whether the opening tag declares `prefix` directly.
    #[must_use]
    pub fn contains(&self, prefix: &str) -> bool {
        self.0.iter().any(|candidate| candidate == prefix)
    }
}

/// Parse the namespace prefixes declared directly by one lexical opening tag.
pub fn declared_namespace_prefixes(opening: &str) -> Result<DeclaredNamespacePrefixes, Error> {
    let standalone = format!("{} />", opening.trim_end_matches('/'));
    let mut scanner = Scanner::new(&standalone);
    let Some(Event::Start(tag) | Event::Empty(tag)) = scanner.next_event()? else {
        return Err(Error::malformed("expected one opening element tag"));
    };
    Ok(DeclaredNamespacePrefixes(
        tag.attributes
            .iter()
            .filter_map(
                |attribute| match (attribute.name.prefix(), attribute.name.local()) {
                    (None, "xmlns") => Some(String::new()),
                    (Some("xmlns"), prefix) => Some(prefix.to_owned()),
                    _ => None,
                },
            )
            .collect(),
    ))
}

/// Expand the five predefined entities and XML character references.
pub fn decode_references(value: &str) -> Result<Cow<'_, str>, Error> {
    if !value.contains('&') {
        return Ok(Cow::Borrowed(value));
    }
    let mut output = String::with_capacity(value.len());
    let mut offset = 0;
    while let Some(relative) = value[offset..].find('&') {
        let start = offset + relative;
        output.push_str(&value[offset..start]);
        let end = value[start + 1..]
            .find(';')
            .map(|relative| start + 1 + relative)
            .ok_or_else(|| Error::malformed("unterminated XML reference"))?;
        let name = &value[start + 1..end];
        let character = match name {
            "amp" => '&',
            "apos" => '\'',
            "gt" => '>',
            "lt" => '<',
            "quot" => '"',
            value if value.starts_with("#x") => decode_character(&value[2..], 16)?,
            value if value.starts_with('#') => decode_character(&value[1..], 10)?,
            _ => {
                return Err(Error::malformed(format!(
                    "unresolved entity reference &{name};"
                )));
            }
        };
        output.push(character);
        offset = end + 1;
    }
    output.push_str(&value[offset..]);
    Ok(Cow::Owned(output))
}

fn decode_character(digits: &str, radix: u32) -> Result<char, Error> {
    u32::from_str_radix(digits, radix)
        .ok()
        .and_then(char::from_u32)
        .filter(|character| is_xml_1_0_character(*character))
        .ok_or_else(|| Error::malformed("invalid XML character reference"))
}

fn is_xml_1_0_character(character: char) -> bool {
    matches!(character, '\u{9}' | '\u{A}' | '\u{D}' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}')
}

/// Escape XML character data.
#[must_use]
pub fn escape_text(value: &str) -> Cow<'_, str> {
    escape(value, false)
}

/// Escape a double-quoted XML attribute value.
#[must_use]
pub fn escape_attribute(value: &str) -> Cow<'_, str> {
    escape(value, true)
}

fn escape(value: &str, attribute: bool) -> Cow<'_, str> {
    if !value.bytes().any(|byte| {
        matches!(byte, b'&' | b'<' | b'>' | b'\r')
            || (attribute && matches!(byte, b'"' | b'\n' | b'\t'))
    }) {
        return Cow::Borrowed(value);
    }
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' if attribute => output.push_str("&quot;"),
            '\t' if attribute => output.push_str("&#9;"),
            '\n' if attribute => output.push_str("&#10;"),
            '\r' => output.push_str("&#13;"),
            _ => output.push(character),
        }
    }
    Cow::Owned(output)
}

/// Deterministic UTF-8 XML writer for generated markup.
#[cfg(feature = "std")]
pub struct Writer<W> {
    output: W,
    namespace_frames: Vec<Vec<(String, String)>>,
}

#[cfg(feature = "std")]
impl<W: Write> Writer<W> {
    /// Wrap an output sink.
    #[must_use]
    pub const fn new(output: W) -> Self {
        Self {
            output,
            namespace_frames: Vec::new(),
        }
    }

    /// Write an opening tag and escaped attributes.
    pub fn start<'a>(
        &mut self,
        name: &str,
        attributes: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> std::io::Result<()> {
        self.tag(name, attributes, false)
    }

    /// Write an empty-element tag and escaped attributes.
    pub fn empty<'a>(
        &mut self,
        name: &str,
        attributes: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> std::io::Result<()> {
        self.tag(name, attributes, true)
    }

    fn tag<'a>(
        &mut self,
        name: &str,
        attributes: impl IntoIterator<Item = (&'a str, &'a str)>,
        empty: bool,
    ) -> std::io::Result<()> {
        validate_writer_qname(name)?;
        let attributes = attributes.into_iter().collect::<Vec<_>>();
        validate_writer_element_namespace(name, &attributes, &self.namespace_frames)?;
        validate_writer_attributes(&attributes, &self.namespace_frames)?;
        write!(self.output, "<{name}")?;
        for (attribute, value) in &attributes {
            write!(self.output, " {attribute}=\"{}\"", escape_attribute(value))?;
        }
        self.output.write_all(if empty { b"/>" } else { b">" })?;
        if !empty {
            self.namespace_frames.push(
                attributes
                    .iter()
                    .filter_map(|(name, uri)| namespace_declaration(name).map(|name| (name, *uri)))
                    .map(|(name, uri)| (name.to_owned(), uri.to_owned()))
                    .collect(),
            );
        }
        Ok(())
    }

    /// Write a closing tag.
    pub fn end(&mut self, name: &str) -> std::io::Result<()> {
        validate_writer_qname(name)?;
        write!(self.output, "</{name}>")?;
        self.namespace_frames.pop();
        Ok(())
    }

    /// Write escaped character data.
    pub fn text(&mut self, value: &str) -> std::io::Result<()> {
        validate_writer_characters(value)?;
        write!(self.output, "{}", escape_text(value))
    }

    /// Write caller-validated XML markup unchanged.
    pub fn raw(&mut self, value: &str) -> std::io::Result<()> {
        self.output.write_all(value.as_bytes())
    }

    /// Return the wrapped sink.
    #[must_use]
    pub fn into_inner(self) -> W {
        self.output
    }
}

#[cfg(feature = "std")]
fn validate_writer_attributes(
    attributes: &[(&str, &str)],
    namespace_frames: &[Vec<(String, String)>],
) -> std::io::Result<()> {
    const SMALL_TAG_ATTRIBUTES: usize = 8;

    for (name, value) in attributes {
        validate_writer_qname(name)?;
        validate_writer_characters(value)?;
        validate_writer_namespace_declaration(name, value)?;
    }
    if attributes.len() <= SMALL_TAG_ATTRIBUTES {
        for index in 1..attributes.len() {
            if attributes[..index]
                .iter()
                .any(|(name, _)| *name == attributes[index].0)
            {
                return Err(IoError::new(
                    ErrorKind::InvalidInput,
                    format!("duplicate XML attribute `{}`", attributes[index].0),
                ));
            }
        }
    } else {
        let mut names = HashSet::with_capacity(attributes.len());
        if let Some((duplicate, _)) = attributes.iter().find(|(name, _)| !names.insert(*name)) {
            return Err(IoError::new(
                ErrorKind::InvalidInput,
                format!("duplicate XML attribute `{duplicate}`"),
            ));
        }
    }

    let mut expanded = HashSet::with_capacity(attributes.len());
    for (name, _) in attributes {
        let Some((prefix, local)) = name.split_once(':') else {
            if name != &"xmlns" && !expanded.insert((None, *name)) {
                return duplicate_expanded_attribute(name);
            }
            continue;
        };
        if prefix == "xmlns" {
            continue;
        }
        let namespace =
            resolve_writer_prefix(prefix, attributes, namespace_frames).ok_or_else(|| {
                IoError::new(
                    ErrorKind::InvalidInput,
                    format!("unbound XML namespace prefix `{prefix}`"),
                )
            })?;
        if namespace.is_empty() {
            return Err(IoError::new(
                ErrorKind::InvalidInput,
                format!("unbound XML namespace prefix `{prefix}`"),
            ));
        }
        if !expanded.insert((Some(namespace), local)) {
            return duplicate_expanded_attribute(name);
        }
    }
    Ok(())
}

#[cfg(feature = "std")]
fn validate_writer_element_namespace(
    name: &str,
    attributes: &[(&str, &str)],
    namespace_frames: &[Vec<(String, String)>],
) -> std::io::Result<()> {
    let Some((prefix, _)) = name.split_once(':') else {
        return Ok(());
    };
    // Namespaces in XML 1.0 sections 2.2 and 5 require a non-empty namespace binding for every
    // prefixed element name.
    // https://www.w3.org/TR/xml-names/#iri-use https://www.w3.org/TR/xml-names/#ns-using
    if prefix == "xmlns"
        || resolve_writer_prefix(prefix, attributes, namespace_frames).is_none_or(str::is_empty)
    {
        return Err(IoError::new(
            ErrorKind::InvalidInput,
            format!("unbound XML namespace prefix `{prefix}`"),
        ));
    }
    Ok(())
}

#[cfg(feature = "std")]
fn validate_writer_namespace_declaration(name: &str, uri: &str) -> std::io::Result<()> {
    const XML_NAMESPACE: &str = "http://www.w3.org/XML/1998/namespace";
    const XMLNS_NAMESPACE: &str = "http://www.w3.org/2000/xmlns/";

    let Some(prefix) = namespace_declaration(name) else {
        return Ok(());
    };
    // Namespaces in XML 1.0 section 3 reserves both namespace names and their prefixes. Only the
    // fixed xml -> XML namespace binding is legal; xmlns itself cannot be declared.
    // https://www.w3.org/TR/xml-names/#ns-decl
    let valid = if prefix == "xml" {
        uri == XML_NAMESPACE
    } else if prefix == "xmlns" {
        false
    } else {
        uri != XML_NAMESPACE && uri != XMLNS_NAMESPACE && (prefix.is_empty() || !uri.is_empty())
    };
    if valid {
        Ok(())
    } else {
        Err(IoError::new(
            ErrorKind::InvalidInput,
            format!("invalid XML namespace declaration `{name}={uri}`"),
        ))
    }
}

#[cfg(feature = "std")]
fn namespace_declaration(name: &str) -> Option<&str> {
    if name == "xmlns" {
        Some("")
    } else {
        name.strip_prefix("xmlns:")
    }
}

#[cfg(feature = "std")]
fn resolve_writer_prefix<'a>(
    prefix: &str,
    attributes: &'a [(&str, &str)],
    namespace_frames: &'a [Vec<(String, String)>],
) -> Option<&'a str> {
    if prefix == "xml" {
        return Some("http://www.w3.org/XML/1998/namespace");
    }
    attributes
        .iter()
        .find_map(|(name, uri)| (namespace_declaration(name) == Some(prefix)).then_some(*uri))
        .or_else(|| {
            namespace_frames.iter().rev().find_map(|frame| {
                frame
                    .iter()
                    .rev()
                    .find_map(|(name, uri)| (name == prefix).then_some(uri.as_str()))
            })
        })
}

#[cfg(feature = "std")]
fn duplicate_expanded_attribute(name: &str) -> std::io::Result<()> {
    Err(IoError::new(
        ErrorKind::InvalidInput,
        format!("duplicate expanded XML attribute `{name}`"),
    ))
}

#[cfg(feature = "std")]
fn validate_writer_qname(name: &str) -> std::io::Result<()> {
    // Namespaces in XML 1.0 section 3 production [6] permits exactly one optional prefix.
    // https://www.w3.org/TR/xml-names/#NT-QName
    if is_qname(name) {
        Ok(())
    } else {
        Err(IoError::new(ErrorKind::InvalidInput, "invalid XML QName"))
    }
}

#[cfg(feature = "std")]
fn validate_writer_characters(value: &str) -> std::io::Result<()> {
    // XML 1.0 section 2.2 production [2] is the character repertoire for parsed entities;
    // escaping markup delimiters cannot make a forbidden control character legal.
    // https://www.w3.org/TR/xml/#charsets
    if let Some(character) = value
        .chars()
        .find(|character| !is_xml_1_0_character(*character))
    {
        Err(IoError::new(
            ErrorKind::InvalidInput,
            format!(
                "character U+{:04X} is forbidden by XML 1.0",
                u32::from(character)
            ),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scanner_groups_start_tags_and_splits_references() {
        let xml = "<p xmlns='urn:test' a='x&amp;y'>a&amp;&#x62;<![CDATA[c]]></p>";
        let mut scanner = Scanner::new(xml);
        let events = std::iter::from_fn(|| scanner.next_event().transpose())
            .collect::<Result<Vec<_>, _>>()
            .expect("fixture must scan");
        assert!(matches!(&events[0], Event::Start(tag) if tag.attributes.len() == 2));
        assert!(matches!(&events[1], Event::Text { text: "a", .. }));
        assert!(matches!(&events[2], Event::Reference { name: "amp", .. }));
        assert!(matches!(&events[3], Event::Reference { name: "#x62", .. }));
        assert!(matches!(&events[4], Event::CData { text: "c", .. }));
        assert!(matches!(&events[5], Event::End { .. }));
    }

    #[test]
    fn scanner_streams_dense_reference_runs_without_buffering_events() {
        // One borrowed lexical event must be produced per pull. A source-sized reference run
        // cannot amplify into an event queue before the consumer sees its first reference.
        let xml = format!("<root>{}</root>", "&amp;".repeat(4096));
        let mut scanner = Scanner::new(&xml);
        assert!(matches!(
            scanner.next_event().expect("scan root start"),
            Some(Event::Start(_))
        ));
        assert!(matches!(
            scanner.next_event().expect("scan first reference"),
            Some(Event::Reference { name: "amp", .. })
        ));
        assert_eq!(
            scanner.pending_text.as_ref().map(|pending| pending.offset),
            Some("&amp;".len()),
            "the scanner retains only a cursor into the source token"
        );
        assert_eq!(
            std::iter::from_fn(|| scanner.next_event().transpose())
                .collect::<Result<Vec<_>, _>>()
                .expect("remaining references scan")
                .len(),
            4096
        );
    }

    #[test]
    fn scanner_rejects_unterminated_references_in_character_data() {
        // XML 1.0 productions [66]-[68] require every reference opened by `&` to end with `;`.
        // https://www.w3.org/TR/xml/#NT-Reference
        for xml in ["<root>AT&T</root>", "<root>&bad</root>"] {
            let mut scanner = Scanner::new(xml);
            let result = std::iter::from_fn(|| scanner.next_event().transpose())
                .collect::<Result<Vec<_>, _>>();
            assert!(result.is_err(), "accepted {xml}");
        }
    }

    #[test]
    fn scanner_keeps_the_internal_subset_as_one_doctype_event() {
        // DTD comments and declarations are not document-tree nodes. Keeping
        // them inside one event prevents semantic sidecars from diverging.
        let xml = r#"<!DOCTYPE root [<!-- <fake/> --><!ENTITY value "ok">]><root/>"#;
        let mut scanner = Scanner::new(xml);
        assert!(matches!(
            scanner.next_event().expect("scan DTD"),
            Some(Event::DocType { .. })
        ));
        assert!(matches!(
            scanner.next_event().expect("scan root"),
            Some(Event::Empty(_))
        ));
        assert!(scanner.next_event().expect("scan EOF").is_none());
    }

    #[test]
    fn scanner_rejects_empty_and_repeated_prefix_components() {
        // The tokenizer exposes split names but accepts these malformed QName
        // spellings, so the shared lexical contract must reject them itself.
        for xml in ["<:root/>", "<root: />", "<a:b:c/>"] {
            assert!(Scanner::new(xml).next_event().is_err(), "accepted {xml}");
        }
    }

    #[test]
    fn scanner_rejects_duplicate_lexical_attributes() {
        // Namespace declarations are attributes under XML Namespaces 1.0 and
        // may not be repeated even though they do not enter the XPath axis.
        for xml in [
            "<root xmlns='urn:first' xmlns='urn:second'/>",
            "<root xmlns:p='urn:first' xmlns:p='urn:second'/>",
            "<root value='first' value='second'/>",
        ] {
            assert!(Scanner::new(xml).next_event().is_err(), "accepted {xml}");
        }
    }

    #[test]
    fn scanner_validates_wide_attributes_without_changing_source_order() {
        // Wide tags use the allocation-free sorted duplicate check. Restoring source order is part
        // of the public lexical event contract and keeps downstream namespace processing stable.
        let attributes = (0..4096)
            .rev()
            .map(|index| format!(" a{index}='{index}'"))
            .collect::<String>();
        let xml = format!("<root{attributes}/>");
        let Some(Event::Empty(tag)) = Scanner::new(&xml)
            .next_event()
            .expect("wide start tag scans")
        else {
            panic!("wide empty element must produce one empty-tag event");
        };
        assert_eq!(tag.attributes.len(), 4096);
        assert_eq!(tag.attributes[0].name.local(), "a4095");
        assert_eq!(tag.attributes[4095].name.local(), "a0");

        let unique = (0..4096)
            .map(|index| format!(" a{index}='x'"))
            .collect::<String>();
        let duplicate = format!("<root{unique} a0='duplicate'/>");
        assert!(Scanner::new(&duplicate).next_event().is_err());
    }

    #[test]
    fn writer_escapes_text_and_attributes_by_context() {
        let mut writer = Writer::new(Vec::new());
        writer
            .start("p", [("a", "<&\"")])
            .expect("start tag must serialize");
        writer.text("<&\"").expect("text must serialize");
        writer.end("p").expect("end tag must serialize");
        assert_eq!(
            String::from_utf8(writer.into_inner()).expect("writer emits UTF-8"),
            "<p a=\"&lt;&amp;&quot;\">&lt;&amp;\"</p>"
        );
    }

    #[test]
    fn writer_preserves_normalized_whitespace_across_reparse() {
        // Literal XML whitespace is normalized differently in character data
        // and attributes, so numeric references preserve the semantic value.
        let mut writer = Writer::new(Vec::new());
        writer
            .empty("root", [("value", "tab\tline\nreturn\r")])
            .expect("empty tag must serialize");
        assert_eq!(
            String::from_utf8(writer.into_inner()).expect("writer emits UTF-8"),
            "<root value=\"tab&#9;line&#10;return&#13;\"/>"
        );

        let mut writer = Writer::new(Vec::new());
        writer.text("line\rbreak\n").expect("text must serialize");
        assert_eq!(
            String::from_utf8(writer.into_inner()).expect("writer emits UTF-8"),
            "line&#13;break\n"
        );
    }

    #[test]
    fn writer_rejects_invalid_element_and_attribute_qnames() {
        for name in ["", ":root", "root:", "a:b:c", "root><injected"] {
            let mut writer = Writer::new(Vec::new());
            assert!(
                writer.empty(name, []).is_err(),
                "accepted element name {name:?}"
            );
        }

        let mut writer = Writer::new(Vec::new());
        assert!(writer.empty("root", [("a:b:c", "value")]).is_err());
        let mut writer = Writer::new(Vec::new());
        assert!(writer.end("root><injected").is_err());
    }

    #[test]
    fn writer_rejects_duplicate_attributes_before_emitting_markup() {
        // XML 1.0 section 3.1 forbids an attribute name from appearing more than once in the
        // same start-tag: https://www.w3.org/TR/xml/#sec-starttags
        let mut writer = Writer::new(Vec::new());
        assert!(
            writer
                .empty("root", [("id", "one"), ("id", "two")])
                .is_err()
        );
        assert!(writer.into_inner().is_empty());
    }

    #[test]
    fn writer_rejects_duplicate_expanded_attribute_names() {
        // Namespaces in XML 1.0 section 6.3 makes expanded names, not lexical prefixes, unique.
        // https://www.w3.org/TR/xml-names/#uniqAttrs
        let mut writer = Writer::new(Vec::new());
        assert!(
            writer
                .empty(
                    "root",
                    [
                        ("xmlns:a", "urn:shared"),
                        ("xmlns:b", "urn:shared"),
                        ("a:id", "one"),
                        ("b:id", "two"),
                    ],
                )
                .is_err()
        );
        assert!(writer.into_inner().is_empty());

        let mut writer = Writer::new(Vec::new());
        writer
            .empty(
                "root",
                [
                    ("xmlns:a", "urn:first"),
                    ("xmlns:b", "urn:second"),
                    ("a:id", "one"),
                    ("b:id", "two"),
                ],
            )
            .expect("different expanded names remain legal");
    }

    #[test]
    fn writer_rejects_invalid_element_namespace_bindings_before_output() {
        // Namespaces in XML 1.0 sections 3 and 5 reserve xml/xmlns and require every other
        // element prefix to be declared: https://www.w3.org/TR/xml-names/#ns-decl and
        // https://www.w3.org/TR/xml-names/#ns-using
        for (name, attributes) in [
            ("p:root", Vec::new()),
            ("root", vec![("xmlns:xml", "urn:wrong")]),
            ("root", vec![("xmlns:xmlns", "urn:wrong")]),
        ] {
            let mut writer = Writer::new(Vec::new());
            assert!(writer.empty(name, attributes).is_err(), "accepted {name}");
            assert!(writer.into_inner().is_empty());
        }

        let mut writer = Writer::new(Vec::new());
        writer
            .empty("p:root", [("xmlns:p", "urn:bound")])
            .expect("a same-tag namespace declaration binds the element prefix");

        let mut writer = Writer::new(Vec::new());
        writer
            .start("root", [("xmlns:p", "urn:bound")])
            .expect("parent namespace declaration is valid");
        writer
            .empty("p:child", [])
            .expect("an inherited namespace declaration binds the child prefix");
    }

    #[test]
    fn writer_rejects_characters_forbidden_by_xml_1_0() {
        let mut writer = Writer::new(Vec::new());
        assert!(writer.text("before\0after").is_err());
        assert!(writer.into_inner().is_empty());

        let mut writer = Writer::new(Vec::new());
        assert!(
            writer
                .empty("root", [("value", "before\u{1}after")])
                .is_err()
        );
    }
}
