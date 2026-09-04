//! Zero-copy lexical XML events and deterministic XML serialization.
//!
//! This module is the parser-neutral boundary used before semantic DOM
//! construction. The public event model intentionally does not expose the
//! implementation tokenizer, so consumers can share source ranges, escaping,
//! and serialization without inheriting a parser's tree semantics.

use alloc::{
    borrow::{Cow, ToOwned},
    collections::VecDeque,
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::ops::Range;

#[cfg(feature = "std")]
use std::io::{Error as IoError, ErrorKind, Write};

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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    pending: VecDeque<Event<'a>>,
    pending_start: Option<PendingStart<'a>>,
    dtd_start: Option<(usize, &'a str)>,
}

struct PendingStart<'a> {
    name: Name<'a>,
    attributes: Vec<Attribute<'a>>,
    start: usize,
}

impl<'a> Scanner<'a> {
    /// Scan a complete XML document.
    #[must_use]
    pub fn new(input: &'a str) -> Self {
        Self {
            input,
            tokenizer: xmlparser::Tokenizer::from(input),
            pending: VecDeque::new(),
            pending_start: None,
            dtd_start: None,
        }
    }

    /// Return the next event, or `None` at end of input.
    pub fn next_event(&mut self) -> Result<Option<Event<'a>>, Error> {
        if let Some(event) = self.pending.pop_front() {
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
                    if start
                        .attributes
                        .iter()
                        .any(|attribute| attribute.name == name)
                    {
                        return Err(Error::malformed(format!(
                            "duplicate attribute `{}`",
                            name.qualified()
                        )));
                    }
                    start.attributes.push(Attribute {
                        name,
                        value: value.as_str(),
                        range: span.range(),
                    });
                }
                Token::ElementEnd { end, span } => match end {
                    ElementEnd::Open | ElementEnd::Empty => {
                        let start = self
                            .pending_start
                            .take()
                            .ok_or_else(|| Error::malformed("element end without a start"))?;
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
                    self.split_text(text.as_str(), text.range())?;
                    if let Some(event) = self.pending.pop_front() {
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

    fn split_text(&mut self, text: &'a str, range: Range<usize>) -> Result<(), Error> {
        let mut offset = 0;
        while let Some(relative) = text[offset..].find('&') {
            let start = offset + relative;
            if start > offset {
                self.pending.push_back(Event::Text {
                    text: &text[offset..start],
                    range: range.start + offset..range.start + start,
                });
            }
            let Some(relative_end) = text[start + 1..].find(';') else {
                self.pending.clear();
                return Err(Error::malformed(
                    "unterminated XML reference in character data",
                ));
            };
            let end = start + 1 + relative_end;
            self.pending.push_back(Event::Reference {
                name: &text[start + 1..end],
                range: range.start + start..range.start + end + 1,
            });
            offset = end + 1;
        }
        if offset < text.len() {
            self.pending.push_back(Event::Text {
                text: &text[offset..],
                range: range.start + offset..range.end,
            });
        }
        Ok(())
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
}

#[cfg(feature = "std")]
impl<W: Write> Writer<W> {
    /// Wrap an output sink.
    #[must_use]
    pub const fn new(output: W) -> Self {
        Self { output }
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
        write!(self.output, "<{name}")?;
        for (attribute, value) in attributes {
            validate_writer_qname(attribute)?;
            write!(self.output, " {attribute}=\"{}\"", escape_attribute(value))?;
        }
        self.output.write_all(if empty { b"/>" } else { b">" })
    }

    /// Write a closing tag.
    pub fn end(&mut self, name: &str) -> std::io::Result<()> {
        validate_writer_qname(name)?;
        write!(self.output, "</{name}>")
    }

    /// Write escaped character data.
    pub fn text(&mut self, value: &str) -> std::io::Result<()> {
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
fn validate_writer_qname(name: &str) -> std::io::Result<()> {
    // Namespaces in XML 1.0 section 3 production [6] permits exactly one optional prefix.
    // https://www.w3.org/TR/xml-names/#NT-QName
    if is_qname(name) {
        Ok(())
    } else {
        Err(IoError::new(ErrorKind::InvalidInput, "invalid XML QName"))
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
}
