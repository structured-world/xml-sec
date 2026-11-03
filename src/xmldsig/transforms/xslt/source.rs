//! The engine's source document for a node-set input, built from the
//! structure of its implicit inclusive C14N 1.0 form instead of from parsing
//! its octets.
//!
//! The canonical walk runs where octet input is decoded, before the engine's
//! workspace lease, and records the constructs a parse of its octets would
//! read on a tape in the query's storage; names, values and text stay
//! borrowed from the document. The octets are only counted, and the XML input
//! policy limits of that parse apply to the same counts. After the stylesheet
//! is compiled the tape is replayed into the engine's builder, which applies
//! the parse's own budgets. Refusals keep the precedence of octet input:
//! canonicalization, the document size, the tape's workspace (where decoding
//! would stand), the first structural limit, the stylesheet, then the engine.

use core::ops::Range;
use std::cell::Cell;

use super::super::{TransformError, TransformExecutionBudget, TransformScratch};
use crate::c14n::scratch::{List as _, Scratch};
use crate::c14n::serialize::{CanonicalObserver, ObservedAttribute, ObservedValue};
use crate::c14n::sink::ByteSink;
use crate::c14n::{C14nError, NodeVisibility};
use crate::document::{DocumentParseSettings, XmlDocumentError, XmlParseWorkBudget};
use crate::xml::dom::ParseError;
use crate::xml::dom::storage::Storage as DomStorage;
use crate::xslt::{Document, DocumentBuilder, Error, ParseBudget};

#[cfg(test)]
mod tests;

/// One construct of the canonical form as a parse of its octets reads it.
enum Event<'n> {
    Start {
        prefix: &'n str,
        local: &'n str,
        namespaces: Range<usize>,
        attributes: Range<usize>,
        line: usize,
    },
    End,
    /// A maximal run of character data between references.
    Text {
        pieces: Range<usize>,
        line: usize,
    },
    Reference {
        character: char,
        line: usize,
    },
    Comment {
        pieces: Range<usize>,
        line: usize,
    },
    Instruction {
        target: &'n str,
        value: Option<Range<usize>>,
        line: usize,
    },
}

/// An attribute value: the document's, or one canonicalization computed.
enum Value<'n> {
    Document(&'n str),
    Computed(usize),
}

/// The constructs of a node-set's canonical form, held in query storage.
pub(super) struct Tape<'n, S: Scratch> {
    events: S::Values<Event<'n>>,
    pieces: S::Values<&'n str>,
    namespaces: S::Values<(&'n str, &'n str)>,
    attributes: S::Values<(&'n str, &'n str, Value<'n>)>,
    computed: S::Values<S::Text>,
    computed_bytes: usize,
    /// The length of the canonical octets.
    source_bytes: usize,
}

impl<'n, S: Scratch> Tape<'n, S> {
    fn new(scratch: &S) -> Self {
        Self {
            events: scratch.values(),
            pieces: scratch.values(),
            namespaces: scratch.values(),
            attributes: scratch.values(),
            computed: scratch.values(),
            computed_bytes: 0,
            source_bytes: 0,
        }
    }

    /// Bytes the tape holds.
    pub(super) fn held_bytes(&self) -> usize {
        fn bytes<T>(capacity: usize) -> usize {
            capacity * core::mem::size_of::<T>()
        }
        // Each list's storage was allocated, so the sum fits the address space.
        bytes::<Event<'n>>(self.events.capacity())
            + bytes::<&str>(self.pieces.capacity())
            + bytes::<(&str, &str)>(self.namespaces.capacity())
            + bytes::<(&str, &str, Value<'n>)>(self.attributes.capacity())
            + bytes::<S::Text>(self.computed.capacity())
            + self.computed_bytes
    }

    fn value(&self, value: &Value<'n>) -> &str {
        match value {
            Value::Document(text) => text,
            Value::Computed(index) => &self.computed[*index],
        }
    }

    /// Describe the recorded constructs to `builder`.
    fn replay(&self, builder: &mut DocumentBuilder<'_, '_>) -> Result<(), Error> {
        let name = |prefix: &'n str| (!prefix.is_empty()).then_some(prefix);
        for event in self.events.iter() {
            match event {
                Event::Start {
                    prefix,
                    local,
                    namespaces,
                    attributes,
                    line,
                } => builder.start_element(
                    (name(prefix), local),
                    self.namespaces[namespaces.clone()]
                        .iter()
                        .map(|&(prefix, uri)| (name(prefix), uri)),
                    self.attributes[attributes.clone()]
                        .iter()
                        .map(|(prefix, local, value)| (name(prefix), *local, self.value(value))),
                    *line,
                )?,
                Event::End => builder.end_element()?,
                Event::Text { pieces, line } => {
                    builder.text(&self.pieces[pieces.clone()], *line)?;
                }
                Event::Reference { character, line } => {
                    builder.character_reference(*character, *line)?;
                }
                Event::Comment { pieces, line } => {
                    builder.comment(&self.pieces[pieces.clone()], *line)?;
                }
                Event::Instruction {
                    target,
                    value,
                    line,
                } => builder.processing_instruction(
                    target,
                    value.clone().map(|value| &self.pieces[value]),
                    *line,
                )?,
            }
        }
        Ok(())
    }
}

/// Canonicalize the node-set `visibility` selects in `document` onto a tape,
/// applying the XML input policy `settings` as a parse of its canonical
/// octets would; the tape may hold at most `limit` bytes beside `held` ones.
pub(super) fn record<'n, S: TransformScratch, D: DomStorage>(
    (document, visibility): (&'n crate::xml::dom::Document<'_, D>, &dyn NodeVisibility<D>),
    settings: DocumentParseSettings,
    budget: &TransformExecutionBudget,
    scratch: &S,
    (limit, held): (usize, usize),
) -> Result<Tape<'n, S>, TransformError> {
    let counters = (Cell::new(0), Cell::new(0));
    let algorithm = crate::c14n::C14nAlgorithm::from_uri(super::super::DEFAULT_IMPLICIT_C14N_URI)
        .expect("constant C14N URI");
    let mut recorder = Recorder::new(scratch, &counters, settings, limit);
    let walked = crate::c14n::canonicalize_visible_observed_in(
        document,
        visibility,
        &algorithm,
        budget.c14n.remaining(),
        budget.xml_base_resolution(),
        &mut CanonicalCount(&counters),
        scratch,
        &mut Settled(&mut recorder),
    );
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
    // A tape over the workspace is refused after the size, as decoding octets
    // into the workspace follows their size check.
    if let Some(needed) = recorder.exceeded {
        return Err(budget.xslt.workspace_error(held.saturating_add(needed)));
    }
    if let Some(error) = recorder.refusal {
        return Err(error);
    }
    recorder.tape.source_bytes = written;
    Ok(recorder.tape)
}

/// Build the engine's source document from `tape` within `workspace` owned
/// bytes.
pub(super) fn build<S: TransformScratch>(
    tape: &Tape<'_, S>,
    workspace: usize,
    budget: &TransformExecutionBudget,
    xml_parse: &XmlParseWorkBudget,
    scratch: &S,
) -> Result<Result<Document, Error>, TransformError> {
    let allowance = &budget.xslt;
    super::charge_parse_work(
        Document::build_with_budget_reported(
            None,
            // Canonical form has no document type declaration, so it can
            // neither reference nor expand an entity.
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
            tape.source_bytes,
            |builder| tape.replay(builder),
        ),
        xml_parse,
        scratch,
    )
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

/// Records the canonical structure and applies the XML input policy's
/// structural limits the way the parse's preflight counts them.
///
/// A refusal does not stop the canonical walk, which must reach its end for
/// the document's size and for a later canonicalization failure, both of
/// which take precedence.
struct Recorder<'n, 'c, S: Scratch> {
    tape: Tape<'n, S>,
    scratch: &'c S,
    written: &'c Cell<usize>,
    line_breaks: &'c Cell<usize>,
    settings: DocumentParseSettings,
    /// The first structural limit the canonical form exceeds; once set,
    /// nothing more is recorded.
    refusal: Option<TransformError>,
    /// Semantic nodes so far, the document root included.
    nodes: u32,
    depth: usize,
    in_character_data: bool,
    scopes: Scopes<'n, S>,
    /// The bytes the tape and the scopes may hold.
    limit: usize,
    /// The tape size a refused growth needed; it stops the walk.
    exceeded: Option<usize>,
}

/// The namespace bindings in scope at the walk's position, held beside the
/// tape in the same storage while the walk runs.
struct Scopes<'n, S: Scratch> {
    /// Bound prefixes in order, the default prefix as empty. A policy bounds
    /// their number, so a sorted list keeps lookups logarithmic and every
    /// byte countable.
    bound: S::Values<&'n str>,
    /// Each open element's binding changes, as a prefix and whether it was
    /// bound before the element, and where each element's changes start.
    changes: S::Values<(&'n str, bool)>,
    starts: S::Values<usize>,
}

impl<S: Scratch> Scopes<'_, S> {
    fn new(scratch: &S) -> Self {
        Self {
            bound: scratch.values(),
            changes: scratch.values(),
            starts: scratch.values(),
        }
    }

    fn held_bytes(&self) -> usize {
        // Each list's storage was allocated, so the sum fits the address space.
        self.bound.capacity() * core::mem::size_of::<&str>()
            + self.changes.capacity() * core::mem::size_of::<(&str, bool)>()
            + self.starts.capacity() * core::mem::size_of::<usize>()
    }

    fn unbind_at(&mut self, index: usize) {
        self.bound[index..].rotate_left(1);
        self.bound.pop();
    }
}

/// A list a [`Recorder`] grows.
type Grown<'n, 'c, S, T> =
    for<'r> fn(&'r mut Recorder<'n, 'c, S>) -> &'r mut <S as Scratch>::Values<T>;

impl<'n, 'c, S: Scratch> Recorder<'n, 'c, S> {
    fn new(
        scratch: &'c S,
        (written, line_breaks): &'c (Cell<usize>, Cell<usize>),
        settings: DocumentParseSettings,
        limit: usize,
    ) -> Self {
        Self {
            tape: Tape::new(scratch),
            scratch,
            written,
            line_breaks,
            settings,
            limit,
            exceeded: None,
            refusal: None,
            nodes: 1,
            depth: 0,
            in_character_data: false,
            scopes: Scopes::new(scratch),
        }
    }

    /// Whether a construct still matters: nothing does after a refusal, once
    /// the tape is full, or of a document already larger than a parse would
    /// read.
    fn observing(&self) -> bool {
        self.refusal.is_none()
            && self.exceeded.is_none()
            && self.written.get() <= self.settings.max_bytes
    }

    fn line(&self) -> usize {
        self.line_breaks.get() + 1
    }

    /// Admit `bytes` more storage beside the tape and the scopes, or end the
    /// recording.
    fn admit(&mut self, bytes: usize) -> Result<(), C14nError> {
        // Each term is the size of live or requested storage, far below the
        // address space.
        let needed = self.tape.held_bytes() + self.scopes.held_bytes() + bytes;
        if needed > self.limit {
            self.exceeded = Some(needed);
            // Unwinds the construct being recorded; `Settled` ends it there
            // and the walk goes on, measuring the document unrecorded.
            return Err(C14nError::OutputRefused);
        }
        Ok(())
    }

    /// Append `value` to the list `list` selects, admitting the list's growth
    /// before it allocates.
    fn push<T>(&mut self, list: Grown<'n, 'c, S, T>, value: T) -> Result<(), C14nError> {
        let (length, capacity) = {
            let values = list(self);
            (values.len(), values.capacity())
        };
        if length == capacity {
            let additional = capacity.max(4);
            // Growth moves the list: the old allocation, which the tape
            // already holds, lives until the whole replacement has its copy.
            self.admit((capacity + additional) * core::mem::size_of::<T>())?;
            list(self).reserve_exact(additional)?;
            // An allocator may grant more than requested; what it granted is held.
            self.admit(0)?;
        }
        list(self).push(value)
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

    /// Unescaped character data: it extends the run the last event records,
    /// or starts one.
    fn literal(&mut self, piece: &'n str, line: usize) -> Result<(), C14nError> {
        if piece.is_empty() {
            return Ok(());
        }
        let end = self.tape.pieces.len();
        match self.tape.events.last_mut() {
            Some(Event::Text { pieces, .. }) if pieces.end == end => pieces.end += 1,
            _ => self.push(
                |recorder| &mut recorder.tape.events,
                Event::Text {
                    pieces: end..end + 1,
                    line,
                },
            )?,
        }
        self.push(|recorder| &mut recorder.tape.pieces, piece)
    }

    /// `text` as a parse of its escaping reads it: runs of unescaped
    /// characters and one reference per escaped character.
    fn escaped_text(&mut self, text: &'n str, escaped: fn(char) -> bool) -> Result<(), C14nError> {
        let line = self.line();
        let mut run = 0;
        for (index, character) in text.char_indices() {
            if escaped(character) {
                self.literal(&text[run..index], line)?;
                self.push(
                    |recorder| &mut recorder.tape.events,
                    Event::Reference { character, line },
                )?;
                run = index + character.len_utf8();
            }
        }
        self.literal(&text[run..], line)
    }

    /// A comment or instruction value as pieces a parse reads: canonical form
    /// writes a carriage return as `&#xD;`, which those constructs keep.
    fn value_pieces(&mut self, value: &'n str) -> Result<Range<usize>, C14nError> {
        let start = self.tape.pieces.len();
        let mut rest = value;
        while let Some(index) = rest.find('\r') {
            self.push(|recorder| &mut recorder.tape.pieces, &rest[..index])?;
            self.push(|recorder| &mut recorder.tape.pieces, "&#xD;")?;
            rest = &rest[index + 1..];
        }
        self.push(|recorder| &mut recorder.tape.pieces, rest)?;
        Ok(start..self.tape.pieces.len())
    }

    /// Apply an element's namespace declarations to the bound prefixes.
    fn bind(&mut self, namespaces: &[(&'n str, &'n str)]) -> Result<(), C14nError> {
        let start = self.scopes.changes.len();
        self.push(|recorder| &mut recorder.scopes.starts, start)?;
        for &(prefix, uri) in namespaces {
            let position = self.scopes.bound.binary_search(&prefix);
            // An empty default namespace name undeclares the default namespace.
            let undeclares = prefix.is_empty() && uri.is_empty();
            match position {
                Ok(index) if undeclares => self.scopes.unbind_at(index),
                Err(index) if !undeclares => {
                    self.push(|recorder| &mut recorder.scopes.bound, prefix)?;
                    self.scopes.bound[index..].rotate_right(1);
                }
                _ => {}
            }
            self.push(
                |recorder| &mut recorder.scopes.changes,
                (prefix, position.is_ok()),
            )?;
        }
        Ok(())
    }

    /// Restore the bound prefixes the innermost element changed.
    fn unbind(&mut self) -> Result<(), C14nError> {
        let scopes = &mut self.scopes;
        let start = scopes
            .starts
            .pop()
            .expect("an end tag closes an open element");
        while scopes.changes.len() > start {
            let (prefix, was_bound) = scopes.changes.pop().expect("changes above the scope start");
            match (was_bound, scopes.bound.binary_search(&prefix)) {
                // The prefix was in the list before this element removed it,
                // so its capacity holds it again without growing.
                (true, Err(index)) => {
                    scopes.bound.push(prefix)?;
                    scopes.bound[index..].rotate_right(1);
                }
                (false, Ok(index)) => scopes.unbind_at(index),
                _ => {}
            }
        }
        Ok(())
    }

    /// An omitted element's selected axis written as character data:
    /// ` name="value"`, its value escaped.
    fn axis(&mut self, name: &[&'n str], value: &'n str) -> Result<(), C14nError> {
        let line = self.line();
        for piece in name {
            self.literal(piece, line)?;
        }
        self.escaped_text(value, attribute_escape)?;
        self.literal("\"", line)
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

impl<'n, S: Scratch> CanonicalObserver<'n> for Recorder<'n, '_, S> {
    fn start_tag<'v>(
        &mut self,
        prefix: &'n str,
        local: &'n str,
        namespaces: &[(&'n str, &'n str)],
        attributes: impl Iterator<Item = Result<ObservedAttribute<'n, 'v>, C14nError>>,
    ) -> Result<(), C14nError> {
        if !self.observing() {
            return Ok(());
        }
        self.in_character_data = false;
        self.bind(namespaces)?;
        let bound = self.scopes.bound.len();
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
        // The preflight reports the node limit first when one element
        // passes both.
        if self.refusal.is_some() {
            return Ok(());
        }
        self.depth += 1;
        if self.depth > self.settings.depth_limit {
            self.refuse(XmlDocumentError::DocumentTooDeep {
                maximum: self.settings.depth_limit,
                actual: self.depth,
            });
            return Ok(());
        }
        let first_namespace = self.tape.namespaces.len();
        for &declaration in namespaces {
            self.push(|recorder| &mut recorder.tape.namespaces, declaration)?;
        }
        let first_attribute = self.tape.attributes.len();
        for attribute in attributes {
            let (prefix, local, value) = attribute?;
            let value = match value {
                ObservedValue::Document(text) => Value::Document(text),
                ObservedValue::Computed(text) => {
                    self.admit(text.len())?;
                    let copy = self.scratch.text(&[text])?;
                    self.tape.computed_bytes += copy.len();
                    self.push(|recorder| &mut recorder.tape.computed, copy)?;
                    Value::Computed(self.tape.computed.len() - 1)
                }
            };
            self.push(
                |recorder| &mut recorder.tape.attributes,
                (prefix, local, value),
            )?;
        }
        let line = self.line();
        let start = Event::Start {
            prefix,
            local,
            namespaces: first_namespace..self.tape.namespaces.len(),
            attributes: first_attribute..self.tape.attributes.len(),
            line,
        };
        self.push(|recorder| &mut recorder.tape.events, start)
    }

    fn end_tag(&mut self) -> Result<(), C14nError> {
        if !self.observing() {
            return Ok(());
        }
        self.in_character_data = false;
        self.depth -= 1;
        self.unbind()?;
        self.push(|recorder| &mut recorder.tape.events, Event::End)
    }

    fn text(&mut self, text: &'n str) -> Result<(), C14nError> {
        if text.is_empty() || !self.observing() {
            return Ok(());
        }
        // Escaped characters reach a parse as references, which are not
        // whitespace; only an unescaped whitespace run is.
        let whitespace = text
            .chars()
            .all(|character| matches!(character, ' ' | '\t' | '\n'));
        self.character_data(whitespace);
        self.escaped_text(text, text_escape)
    }

    fn comment(&mut self, text: &'n str) -> Result<(), C14nError> {
        if !self.observing() {
            return Ok(());
        }
        self.in_character_data = false;
        self.node();
        let line = self.line();
        let pieces = self.value_pieces(text)?;
        self.push(
            |recorder| &mut recorder.tape.events,
            Event::Comment { pieces, line },
        )
    }

    fn processing_instruction(
        &mut self,
        target: &'n str,
        value: Option<&'n str>,
    ) -> Result<(), C14nError> {
        if !self.observing() {
            return Ok(());
        }
        self.in_character_data = false;
        self.node();
        let line = self.line();
        let value = value.map(|value| self.value_pieces(value)).transpose()?;
        self.push(
            |recorder| &mut recorder.tape.events,
            Event::Instruction {
                target,
                value,
                line,
            },
        )
    }

    fn omitted_axes(
        &mut self,
        namespaces: &[(&'n str, &'n str)],
        attributes: impl Iterator<Item = (&'n str, &'n str, &'n str)>,
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
                self.axis(&[" xmlns=\""], uri)?;
            } else {
                self.axis(&[" xmlns:", prefix, "=\""], uri)?;
            }
        }
        for (prefix, local, value) in attributes {
            if prefix.is_empty() {
                self.axis(&[" ", local, "=\""], value)?;
            } else {
                self.axis(&[" ", prefix, ":", local, "=\""], value)?;
            }
        }
        Ok(())
    }
}

/// A [`Recorder`] whose full tape ends the recording but not the canonical
/// walk, which still measures the document and may still fail.
struct Settled<'r, 'n, 'c, S: Scratch>(&'r mut Recorder<'n, 'c, S>);

impl<S: Scratch> Settled<'_, '_, '_, S> {
    fn settle(&self, recorded: Result<(), C14nError>) -> Result<(), C14nError> {
        match recorded {
            Err(C14nError::OutputRefused) if self.0.exceeded.is_some() => Ok(()),
            recorded => recorded,
        }
    }
}

impl<'n, S: Scratch> CanonicalObserver<'n> for Settled<'_, 'n, '_, S> {
    fn start_tag<'v>(
        &mut self,
        prefix: &'n str,
        local: &'n str,
        namespaces: &[(&'n str, &'n str)],
        attributes: impl Iterator<Item = Result<ObservedAttribute<'n, 'v>, C14nError>>,
    ) -> Result<(), C14nError> {
        let recorded = self.0.start_tag(prefix, local, namespaces, attributes);
        self.settle(recorded)
    }

    fn end_tag(&mut self) -> Result<(), C14nError> {
        let recorded = self.0.end_tag();
        self.settle(recorded)
    }

    fn text(&mut self, text: &'n str) -> Result<(), C14nError> {
        let recorded = self.0.text(text);
        self.settle(recorded)
    }

    fn comment(&mut self, text: &'n str) -> Result<(), C14nError> {
        let recorded = self.0.comment(text);
        self.settle(recorded)
    }

    fn processing_instruction(
        &mut self,
        target: &'n str,
        value: Option<&'n str>,
    ) -> Result<(), C14nError> {
        let recorded = self.0.processing_instruction(target, value);
        self.settle(recorded)
    }

    fn omitted_axes(
        &mut self,
        namespaces: &[(&'n str, &'n str)],
        attributes: impl Iterator<Item = (&'n str, &'n str, &'n str)>,
    ) -> Result<(), C14nError> {
        let recorded = self.0.omitted_axes(namespaces, attributes);
        self.settle(recorded)
    }
}
