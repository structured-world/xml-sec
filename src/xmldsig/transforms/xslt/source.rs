//! The engine's source document for a node-set input, built from the
//! structure of its implicit inclusive C14N 1.0 form as that form is
//! produced, instead of from parsing its octets.
//!
//! The tree and the refusals are those of parsing the octets: the
//! canonical serializer reports each construct in document order while its
//! octets are only counted, the XML input policy limits of the parse are
//! applied to the same counts, and character data reaches the engine in the
//! runs and references a parse of the canonical escaping reports. Refusals
//! keep the parse's precedence: canonicalization, then the document size,
//! then the first structural limit, then the engine.

use std::cell::Cell;

use super::super::{TransformError, TransformExecutionBudget, TransformScratch};
use crate::c14n::serialize::CanonicalObserver;
use crate::c14n::sink::ByteSink;
use crate::c14n::{C14nError, NodeVisibility};
use crate::collections::{Set, Table as _};
use crate::document::{DocumentParseSettings, XmlDocumentError, XmlParseWorkBudget};
use crate::xml::dom::ParseError;
use crate::xml::dom::storage::Storage as DomStorage;
use crate::xslt::{Document, DocumentBuilder, Error, ParseBudget};

#[cfg(test)]
mod tests;

/// Build the engine's source document for the node-set `visibility` selects
/// in `document` within `workspace` owned bytes, applying the XML input
/// policy `settings` as a parse of its canonical octets would.
pub(super) fn build<S: TransformScratch, D: DomStorage>(
    (document, visibility): (&crate::xml::dom::Document<'_, D>, &dyn NodeVisibility<D>),
    settings: DocumentParseSettings,
    workspace: usize,
    budget: &TransformExecutionBudget,
    xml_parse: &XmlParseWorkBudget,
    scratch: &S,
) -> Result<Result<Document, Error>, TransformError> {
    let allowance = &budget.xslt;
    let mut builder = DocumentBuilder::new(
        None,
        // Canonical form has no document type declaration, so it can neither
        // reference nor expand an entity.
        ParseBudget::new(
            allowance.max_document_bytes,
            allowance.max_nodes,
            allowance.max_depth,
            0,
            0,
            workspace,
        )
        .with_owned_bytes(workspace)
        .with_parse_work_bytes(super::parse_work_limit(xml_parse, scratch)),
    );
    let counters = (Cell::new(0), Cell::new(0));
    let algorithm = crate::c14n::C14nAlgorithm::from_uri(super::super::DEFAULT_IMPLICIT_C14N_URI)
        .expect("constant C14N URI");
    let mut reader = SourceReader::new(&mut builder, &counters, settings);
    let walked = crate::c14n::canonicalize_visible_observed_in(
        document,
        visibility,
        &algorithm,
        budget.c14n.remaining(),
        budget.xml_base_resolution(),
        &mut CanonicalCount(&counters),
        scratch,
        &mut reader,
    );
    reader.flush();
    let refusal = reader.refusal;
    walked.map_err(|error| super::super::map_c14n_limit_error(error, &budget.c14n))?;
    let written = counters.0.get();
    budget.c14n.charge(written)?;
    // The policy bounds the octets a parse would read, so a canonical form
    // above it is refused as that document would be.
    if written > settings.max_bytes {
        return Err(super::super::map_transform_xml_parse_error(
            XmlDocumentError::DocumentTooLarge {
                maximum: settings.max_bytes,
                actual: written,
            },
            settings,
        ));
    }
    if let Some(error) = refusal {
        return Err(error);
    }
    super::charge_parse_work(builder.finish(written), xml_parse, scratch)
}

/// The canonical octets' length and line breaks, counted as they are
/// written and never stored.
struct CanonicalCount<'c>(&'c (Cell<usize>, Cell<usize>));

impl ByteSink for CanonicalCount<'_> {
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), C14nError> {
        let (written, line_breaks) = self.0;
        // Canonical output is bounded by the operation's C14N allowance, far
        // below the address space, so neither count can overflow.
        written.set(written.get() + bytes.len());
        line_breaks.set(line_breaks.get() + memchr::memchr_iter(b'\n', bytes).count());
        Ok(())
    }
}

/// Feeds the canonical structure to the engine and applies the XML input
/// policy's structural limits the way the parse's preflight counts them.
///
/// Neither a refusal nor an engine failure stops the canonical walk, which
/// must reach its end for the document's size and for a later
/// canonicalization failure, both of which take precedence.
struct SourceReader<'b, 'c> {
    builder: &'b mut DocumentBuilder,
    written: &'c Cell<usize>,
    line_breaks: &'c Cell<usize>,
    settings: DocumentParseSettings,
    /// The first structural limit the canonical form exceeds; once set,
    /// nothing more is observed.
    refusal: Option<TransformError>,
    /// Unescaped character data not yet passed on: a parse reports each
    /// maximal run between references and markup as one text event, and the
    /// engine's text storage grows by the runs it receives.
    pending: String,
    /// The line `pending` starts on.
    pending_line: usize,
    /// Semantic nodes so far, the document root included.
    nodes: u32,
    depth: usize,
    in_character_data: bool,
    /// Prefixes bound at the current element; the default prefix is empty.
    bindings: Set<String>,
    /// Each open element's binding changes: a prefix and whether it was
    /// already bound before the element.
    scopes: Vec<Vec<(String, bool)>>,
}

impl<'b, 'c> SourceReader<'b, 'c> {
    fn new(
        builder: &'b mut DocumentBuilder,
        (written, line_breaks): &'c (Cell<usize>, Cell<usize>),
        settings: DocumentParseSettings,
    ) -> Self {
        Self {
            builder,
            written,
            line_breaks,
            settings,
            refusal: None,
            pending: String::new(),
            pending_line: 1,
            nodes: 1,
            depth: 0,
            in_character_data: false,
            bindings: Set::with_entry_capacity(0),
            scopes: Vec::new(),
        }
    }

    /// Whether a construct still matters: nothing does after a refusal, of a
    /// document already larger than a parse would read, or for the engine
    /// once it refused.
    fn observing(&self) -> bool {
        self.refusal.is_none() && self.written.get() <= self.settings.max_bytes
    }

    fn line(&self) -> usize {
        self.line_breaks.get() + 1
    }

    /// Pass on the pending run of character data.
    fn flush(&mut self) {
        if !self.pending.is_empty() {
            self.builder.text(&self.pending, self.pending_line);
            self.pending.clear();
        }
    }

    /// Unescaped character data starting on `line`.
    fn literal(&mut self, text: &str, line: usize) {
        if self.pending.is_empty() {
            self.pending_line = line;
        }
        self.pending.push_str(text);
    }

    fn refuse(&mut self, error: XmlDocumentError) {
        self.refusal = Some(super::super::map_transform_xml_parse_error(
            error,
            self.settings,
        ));
    }

    /// Count one semantic node against the policy's node limit.
    fn node(&mut self) {
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > self.settings.nodes_limit {
            self.refuse(XmlDocumentError::Parse(ParseError::NodesLimitReached));
        }
    }

    /// Character data starts a node unless it continues a run; whitespace
    /// outside the document element is no node.
    fn character_data(&mut self, whitespace: bool) {
        if self.depth == 0 && whitespace {
            self.in_character_data = false;
        } else if !self.in_character_data {
            self.in_character_data = true;
            self.node();
        }
    }

    /// Pass `text` on as a parse of its escaping reports it: runs of
    /// unescaped characters and one reference per escaped character.
    fn escaped_text(&mut self, text: &str, escaped: fn(char) -> bool) {
        let line = self.line();
        let mut run = 0;
        for (index, character) in text.char_indices() {
            if escaped(character) {
                self.literal(&text[run..index], line);
                self.flush();
                self.builder.character_reference(character, line);
                run = index + character.len_utf8();
            }
        }
        self.literal(&text[run..], line);
    }

    /// Markup ends the pending run of character data.
    fn markup(&mut self) {
        self.flush();
        self.in_character_data = false;
    }

    fn bind(&mut self, prefix: &str, uri: &str, changes: &mut Vec<(String, bool)>) {
        // An empty default namespace name undeclares the default namespace.
        let was_bound = if prefix.is_empty() && uri.is_empty() {
            self.bindings.remove(prefix)
        } else if self.bindings.contains(prefix) {
            true
        } else {
            self.bindings.insert(prefix.to_owned());
            false
        };
        changes.push((prefix.to_owned(), was_bound));
    }

    fn unbind(&mut self, changes: Vec<(String, bool)>) {
        for (prefix, was_bound) in changes.into_iter().rev() {
            if was_bound {
                self.bindings.insert(prefix);
            } else {
                self.bindings.remove(&prefix);
            }
        }
    }

    /// An omitted element's selected axis written as character data:
    /// ` name="value"`, its value escaped.
    fn axis_text(&mut self, name: std::fmt::Arguments<'_>, value: &str) {
        let line = self.line();
        let start = self.pending.len();
        std::fmt::Write::write_fmt(&mut self.pending, name).expect("writing to a String");
        if start == 0 {
            self.pending_line = line;
        }
        self.escaped_text(value, attribute_escape);
        self.literal("\"", line);
    }
}

/// Characters canonical text escapes (C14N 1.0 section 2.3).
fn text_escape(character: char) -> bool {
    matches!(character, '&' | '<' | '>' | '\r')
}

/// Characters a canonical attribute value escapes (C14N 1.0 section 2.3).
fn attribute_escape(character: char) -> bool {
    matches!(character, '&' | '<' | '"' | '\t' | '\n' | '\r')
}

/// A comment or instruction value as a parse reads it: canonical form
/// writes a carriage return as `&#xD;`, which those constructs keep literal.
fn literal_carriage_returns(value: &str) -> std::borrow::Cow<'_, str> {
    if value.contains('\r') {
        std::borrow::Cow::Owned(value.replace('\r', "&#xD;"))
    } else {
        std::borrow::Cow::Borrowed(value)
    }
}

impl CanonicalObserver for SourceReader<'_, '_> {
    fn start_tag<'v>(
        &mut self,
        prefix: &str,
        local: &str,
        namespaces: &[(&'v str, &'v str)],
        attributes: impl Iterator<Item = Result<(&'v str, &'v str, &'v str), C14nError>>,
    ) -> Result<(), C14nError> {
        if !self.observing() {
            return Ok(());
        }
        self.markup();
        let mut changes = Vec::with_capacity(namespaces.len());
        for &(bound, uri) in namespaces {
            self.bind(bound, uri, &mut changes);
        }
        self.scopes.push(changes);
        let bound = self.bindings.len();
        if bound > self.settings.namespace_bindings_limit {
            self.refuse(XmlDocumentError::Parse(
                ParseError::NamespaceBindingLimitReached {
                    maximum: self.settings.namespace_bindings_limit,
                    actual: bound,
                },
            ));
            return Ok(());
        }
        self.node();
        self.depth += 1;
        if self.depth > self.settings.depth_limit {
            self.refuse(XmlDocumentError::DocumentTooDeep {
                maximum: self.settings.depth_limit,
                actual: self.depth,
            });
        }
        if self.builder.is_refused() {
            return Ok(());
        }
        let attributes = attributes.collect::<Result<Vec<_>, _>>()?;
        self.builder.start_element(
            ((!prefix.is_empty()).then_some(prefix), local),
            namespaces
                .iter()
                .map(|&(bound, uri)| ((!bound.is_empty()).then_some(bound), uri)),
            attributes
                .iter()
                .map(|&(bound, name, value)| ((!bound.is_empty()).then_some(bound), name, value)),
            self.line(),
        );
        Ok(())
    }

    fn end_tag(&mut self) -> Result<(), C14nError> {
        if !self.observing() {
            return Ok(());
        }
        self.markup();
        self.depth -= 1;
        let changes = self
            .scopes
            .pop()
            .expect("an end tag closes an open element");
        self.unbind(changes);
        self.builder.end_element();
        Ok(())
    }

    fn text(&mut self, text: &str) -> Result<(), C14nError> {
        if text.is_empty() || !self.observing() {
            return Ok(());
        }
        // Escaped characters reach a parse as references, which are not
        // whitespace; only an unescaped whitespace run is.
        let whitespace = text
            .chars()
            .all(|character| matches!(character, ' ' | '\t' | '\n'));
        self.character_data(whitespace);
        self.escaped_text(text, text_escape);
        Ok(())
    }

    fn comment(&mut self, text: &str) -> Result<(), C14nError> {
        if !self.observing() {
            return Ok(());
        }
        self.markup();
        self.node();
        let line = self.line();
        self.builder.comment(&literal_carriage_returns(text), line);
        Ok(())
    }

    fn processing_instruction(
        &mut self,
        target: &str,
        value: Option<&str>,
    ) -> Result<(), C14nError> {
        if !self.observing() {
            return Ok(());
        }
        self.markup();
        self.node();
        let line = self.line();
        let value = value.map(literal_carriage_returns);
        self.builder
            .processing_instruction(target, value.as_deref(), line);
        Ok(())
    }

    fn omitted_axes<'v>(
        &mut self,
        namespaces: &[(&'v str, &'v str)],
        attributes: impl Iterator<Item = (&'v str, &'v str, &'v str)>,
    ) -> Result<(), C14nError> {
        if !self.observing() {
            return Ok(());
        }
        // The axes' octets are character data of the enclosing content.
        let mut attributes = attributes.peekable();
        if !namespaces.is_empty() || attributes.peek().is_some() {
            self.character_data(false);
        }
        for &(prefix, uri) in namespaces {
            if prefix.is_empty() {
                self.axis_text(format_args!(" xmlns=\""), uri);
            } else {
                self.axis_text(format_args!(" xmlns:{prefix}=\""), uri);
            }
        }
        for (prefix, local, value) in attributes {
            if prefix.is_empty() {
                self.axis_text(format_args!(" {local}=\""), value);
            } else {
                self.axis_text(format_args!(" {prefix}:{local}=\""), value);
            }
        }
        Ok(())
    }
}
