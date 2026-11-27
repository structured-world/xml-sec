//! The unpublished XML draft behind the shared construction events.
//!
//! [`Draft`] turns the expanded-name events of `structured_xades::produce`
//! into one element: it selects prefixes, escapes text and attributes,
//! encodes binary values and checks every value with the same XML Schema
//! kernels that read it back. The serialization is held in storage of the
//! caller's account and admitted through its work before it grows.

use alloc::{format, string::String, vec::Vec};
use structured_asn1::memory::{Memory, MemoryError, OwnedVec, Work};
use structured_xades::produce::{Datatype, Event, Value, Writer};
use structured_xades::xml::Name;
use xml_sec::xml_input::lexical::{escape_attribute, escape_text, is_qname, is_xml_1_0_character};
use xml_sec::xmldsig::extension::{
    InspectionError, ScalarError, ScalarFact, ScalarType, ScalarValue, with_lexical_scalar,
};

#[cfg(test)]
mod tests;

/// Prefixes for the namespaces the shared rules emit, so the draft reads
/// like the documents other implementations produce.
const KNOWN_PREFIXES: [(&str, &str); 3] = [
    ("http://www.w3.org/2000/09/xmldsig#", "ds"),
    ("http://uri.etsi.org/01903/v1.3.2#", "xades"),
    ("http://uri.etsi.org/01903/v1.4.1#", "xades141"),
];

/// A construction event the draft refused; nothing of it was written.
#[derive(Debug, thiserror::Error)]
pub enum DraftError {
    /// The account refused work or storage.
    #[error("draft resource refusal: {0}")]
    Resource(MemoryError),
    /// An element or attribute name is not an XML name.
    #[error("invalid XML name {0:?}")]
    Name(&'static str),
    /// A value is not valid for the datatype the shared rules selected.
    #[error("{datatype:?} value is not valid: {value:?}")]
    Value {
        /// Datatype the value had to satisfy.
        datatype: Datatype,
        /// Rejected value.
        value: String,
    },
    /// The draft already holds this ID.
    #[error("duplicate ID {0:?}")]
    DuplicateId(String),
    /// The element already has this attribute.
    #[error("duplicate attribute {0:?}")]
    DuplicateAttribute(&'static str),
    /// The event does not fit the elements written so far.
    #[error("construction event out of order: {0}")]
    Order(&'static str),
}

impl From<MemoryError> for DraftError {
    fn from(error: MemoryError) -> Self {
        Self::Resource(error)
    }
}

/// One open element.
struct Frame {
    /// Qualified name, for the end tag.
    name: String,
    /// Prefix bindings this element declares, as (namespace, prefix).
    bindings: Vec<(&'static str, String)>,
    /// Expanded names of its attributes, for the uniqueness check.
    attributes: Vec<Name<'static>>,
    /// The start tag is still open and accepts attributes.
    open: bool,
}

/// An XML element under construction.
///
/// Feed it through [`Writer`] and take the result with [`Draft::finish`]. A
/// refused event leaves the draft unusable, and a caller discards it whole.
#[derive(Default)]
pub struct Draft {
    output: Option<OwnedVec<u8, Memory>>,
    frames: Vec<Frame>,
    ids: Vec<String>,
    generated: usize,
    complete: bool,
    /// Prefixes the caller chose, as (namespace, prefix), ahead of the known
    /// ones; an empty prefix writes the namespace as the default one.
    chosen: Vec<(&'static str, String)>,
}

/// The namespace the `xml` prefix is bound to (Namespaces in XML 1.0 §3).
const XML_NAMESPACE: &str = "http://www.w3.org/XML/1998/namespace";

impl Draft {
    /// An empty draft; it allocates nothing until the first event.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty draft writing each namespace of `chosen` with its prefix, an
    /// empty one as the default namespace.
    ///
    /// # Errors
    /// Returns [`DraftError::Name`] for a prefix that is neither empty nor an
    /// XML name without a colon, for one chosen for two namespaces, and for
    /// `xmlns`, or `xml` for any namespace but the XML namespace.
    pub fn with_prefixes(chosen: &[(&'static str, &str)]) -> Result<Self, DraftError> {
        let mut draft = Self::default();
        for (index, (namespace, prefix)) in chosen.iter().enumerate() {
            // The default namespace is declared again wherever it changes, so
            // several namespaces may take it; a prefix stays with one.
            let reused = !prefix.is_empty()
                && chosen[..index]
                    .iter()
                    .any(|(other, earlier)| earlier == prefix && other != namespace);
            // Namespaces in XML 1.0 §3: `xmlns` is never declared, and `xml`
            // may only be bound to the XML namespace.
            let reserved = match *prefix {
                "xmlns" => true,
                "xml" => *namespace != XML_NAMESPACE,
                _ => false,
            };
            if (!prefix.is_empty() && (!is_ncname(prefix) || reserved)) || reused {
                return Err(DraftError::Name("a chosen namespace prefix"));
            }
            draft.chosen.push((namespace, (*prefix).into()));
        }
        Ok(draft)
    }

    /// The prefix bound to `namespace` in scope: the innermost declaration of
    /// it whose prefix no inner element rebinds to another namespace.
    fn in_scope(&self, namespace: &str) -> Option<String> {
        let mut rebound: Vec<&str> = Vec::new();
        for frame in self.frames.iter().rev() {
            for (bound, prefix) in &frame.bindings {
                if prefix.is_empty() || rebound.contains(&prefix.as_str()) {
                    continue;
                }
                if *bound == namespace {
                    return Some(prefix.clone());
                }
            }
            rebound.extend(
                frame
                    .bindings
                    .iter()
                    .filter(|(bound, _)| *bound != namespace)
                    .map(|(_, prefix)| prefix.as_str()),
            );
        }
        None
    }

    /// The default namespace in scope, if one is declared.
    fn default_namespace(&self) -> Option<&'static str> {
        self.frames.iter().rev().find_map(|frame| {
            frame
                .bindings
                .iter()
                .find_map(|(bound, prefix)| prefix.is_empty().then_some(*bound))
        })
    }

    /// The finished element and every ID it declares.
    ///
    /// # Errors
    /// Returns [`DraftError::Order`] unless exactly one element was completed.
    pub fn finish(self) -> Result<(String, Vec<String>), DraftError> {
        if !self.complete {
            return Err(DraftError::Order("the element is not complete"));
        }
        let output = self
            .output
            .ok_or(DraftError::Order("no element was written"))?;
        let markup = core::str::from_utf8(&output)
            .map_err(|_| DraftError::Order("the draft is not UTF-8"))?;
        Ok((markup.into(), self.ids))
    }

    fn push(&mut self, bytes: &[u8], work: &impl Work) -> Result<(), DraftError> {
        work.charge_work(bytes.len() as u64)?;
        let output = self
            .output
            .get_or_insert_with(|| work.memory().clone().vector());
        output.try_extend_from_slice(bytes)?;
        Ok(())
    }

    /// Close an open start tag before content follows it.
    fn content(&mut self, work: &impl Work) -> Result<(), DraftError> {
        let Some(frame) = self.frames.last_mut() else {
            return Err(DraftError::Order("content outside the element"));
        };
        if frame.open {
            frame.open = false;
            self.push(b">", work)?;
        }
        Ok(())
    }

    /// The prefix bound to `namespace` in scope, and whether it is a new
    /// binding of the innermost element that its start tag must declare.
    fn bind(
        &mut self,
        namespace: &'static str,
        work: &impl Work,
    ) -> Result<(String, bool), DraftError> {
        work.charge_work(self.frames.len() as u64 + 1)?;
        let chosen = self
            .chosen
            .iter()
            .find_map(|(bound, prefix)| (*bound == namespace).then(|| prefix.clone()));
        // The default namespace is in scope only until an inner element
        // declares another, so it is declared again whenever it changes.
        if chosen.as_deref() == Some("") {
            if self.default_namespace() == Some(namespace) {
                return Ok((String::new(), false));
            }
            let frame = self
                .frames
                .last_mut()
                .ok_or(DraftError::Order("namespace outside a start tag"))?;
            frame.bindings.push((namespace, String::new()));
            return Ok((String::new(), true));
        }
        if let Some(prefix) = self.in_scope(namespace) {
            return Ok((prefix, false));
        }
        // A fallback prefix the caller chose for another namespace, or one in
        // scope for another namespace, would rebind it for this subtree
        // (Namespaces in XML 1.0 §6.1): such a prefix is skipped.
        let taken = |draft: &Self, prefix: &str| {
            draft
                .chosen
                .iter()
                .any(|(bound, chosen)| chosen == prefix && *bound != namespace)
                || draft
                    .frames
                    .iter()
                    .flat_map(|frame| frame.bindings.iter())
                    .any(|(bound, bound_prefix)| bound_prefix == prefix && *bound != namespace)
        };
        let known = KNOWN_PREFIXES
            .iter()
            .find(|(known, _)| *known == namespace)
            .map(|(_, prefix)| String::from(*prefix));
        let prefix: String = match (chosen, known) {
            (Some(prefix), _) => prefix,
            (None, Some(prefix)) if !taken(self, &prefix) => prefix,
            _ => loop {
                work.charge_work(1)?;
                self.generated += 1;
                let prefix = format!("ns{}", self.generated);
                if !taken(self, &prefix) {
                    break prefix;
                }
            },
        };
        let frame = self
            .frames
            .last_mut()
            .ok_or(DraftError::Order("namespace outside a start tag"))?;
        frame.bindings.push((namespace, prefix.clone()));
        Ok((prefix, true))
    }

    /// Declare `prefix` for `namespace` on the open start tag.
    fn declare(
        &mut self,
        prefix: &str,
        namespace: &str,
        work: &impl Work,
    ) -> Result<(), DraftError> {
        work.charge_work(namespace.len() as u64)?;
        let escaped = escape_attribute(namespace);
        if prefix.is_empty() {
            self.push(b" xmlns", work)?;
        } else {
            self.push(b" xmlns:", work)?;
            self.push(prefix.as_bytes(), work)?;
        }
        self.push(b"=\"", work)?;
        self.push(escaped.as_bytes(), work)?;
        self.push(b"\"", work)
    }

    fn begin(&mut self, name: Name<'static>, work: &impl Work) -> Result<(), DraftError> {
        if self.complete {
            return Err(DraftError::Order("a second element"));
        }
        if !self.frames.is_empty() {
            self.content(work)?;
        }
        if !is_ncname(name.local) {
            return Err(DraftError::Name(name.local));
        }
        work.charge_work(1)?;
        self.frames.push(Frame {
            name: String::new(),
            bindings: Vec::new(),
            attributes: Vec::new(),
            open: true,
        });
        // An element in no namespace stays unprefixed; the Object content
        // check undeclares any default namespace around it. Under a default
        // namespace of this draft it would change namespace, so it is refused.
        let (qualified, declaration) = if name.namespace.is_empty() {
            if self.default_namespace().is_some() {
                return Err(DraftError::Name(name.local));
            }
            (String::from(name.local), None)
        } else {
            let (prefix, new) = self.bind(name.namespace, work)?;
            let qualified = if prefix.is_empty() {
                String::from(name.local)
            } else {
                format!("{prefix}:{}", name.local)
            };
            (qualified, new.then_some(prefix))
        };
        self.push(b"<", work)?;
        self.push(qualified.as_bytes(), work)?;
        if let Some(prefix) = declaration {
            self.declare(&prefix, name.namespace, work)?;
        }
        let frame = self
            .frames
            .last_mut()
            .ok_or(DraftError::Order("no open element"))?;
        frame.name = qualified;
        Ok(())
    }

    fn attribute(
        &mut self,
        name: Name<'static>,
        value: Value<'_>,
        work: &impl Work,
    ) -> Result<(), DraftError> {
        let frame = self
            .frames
            .last_mut()
            .ok_or(DraftError::Order("attribute outside an element"))?;
        if !frame.open {
            return Err(DraftError::Order("attribute after content"));
        }
        if !is_ncname(name.local) {
            return Err(DraftError::Name(name.local));
        }
        work.charge_work(frame.attributes.len() as u64 + 1)?;
        if frame.attributes.contains(&name) {
            return Err(DraftError::DuplicateAttribute(name.local));
        }
        frame.attributes.push(name);
        let lexical = checked(value, work)?;
        if let Datatype::Id = value.datatype {
            work.charge_work(self.ids.len() as u64 + 1)?;
            if self.ids.iter().any(|id| id == lexical) {
                return Err(DraftError::DuplicateId(lexical.into()));
            }
            self.ids.push(lexical.into());
        }
        // Namespaces in XML 1.0 §6.2: an unprefixed attribute is in no
        // namespace, whatever default namespace is in scope.
        let qualified = if name.namespace.is_empty() {
            String::from(name.local)
        } else {
            // Namespaces in XML 1.0 §6.2: a default namespace never applies to
            // an attribute, so a namespaced one needs a prefix.
            if self
                .chosen
                .iter()
                .any(|(bound, prefix)| *bound == name.namespace && prefix.is_empty())
            {
                return Err(DraftError::Name(name.local));
            }
            let (prefix, new) = self.bind(name.namespace, work)?;
            if new {
                self.declare(&prefix, name.namespace, work)?;
            }
            format!("{prefix}:{}", name.local)
        };
        work.charge_work(lexical.len() as u64)?;
        let escaped = escape_attribute(lexical);
        self.push(b" ", work)?;
        self.push(qualified.as_bytes(), work)?;
        self.push(b"=\"", work)?;
        self.push(escaped.as_bytes(), work)?;
        self.push(b"\"", work)
    }

    fn text(&mut self, value: Value<'_>, work: &impl Work) -> Result<(), DraftError> {
        self.content(work)?;
        let lexical = checked(value, work)?;
        work.charge_work(lexical.len() as u64)?;
        let escaped = escape_text(lexical);
        self.push(escaped.as_bytes(), work)
    }

    fn binary(&mut self, bytes: &[u8], work: &impl Work) -> Result<(), DraftError> {
        self.content(work)?;
        // RFC 4648 §4 without line breaks: every complete input group of
        // three bytes becomes four characters, the last group padded.
        let mut encoded = [0_u8; 1024];
        for chunk in bytes.chunks(768) {
            work.charge_work(chunk.len() as u64)?;
            let length = structured_base64::STANDARD
                .encode_slice(chunk, &mut encoded)
                .map_err(|_| DraftError::Order("base64 output does not fit its chunk"))?;
            self.push(&encoded[..length], work)?;
        }
        Ok(())
    }

    /// Append part of one complete element serialized by its XML owner, such
    /// as a canonical copy of an existing element, as content of the open one.
    pub(crate) fn copied(&mut self, bytes: &[u8], work: &impl Work) -> Result<(), DraftError> {
        self.content(work)?;
        self.push(bytes, work)
    }

    fn end(&mut self, work: &impl Work) -> Result<(), DraftError> {
        let frame = self
            .frames
            .pop()
            .ok_or(DraftError::Order("end without an element"))?;
        if frame.open {
            self.push(b"/>", work)?;
        } else {
            self.push(b"</", work)?;
            self.push(frame.name.as_bytes(), work)?;
            self.push(b">", work)?;
        }
        if self.frames.is_empty() {
            self.complete = true;
        }
        Ok(())
    }
}

impl Writer for Draft {
    type Error = DraftError;

    fn write<W: Work>(&mut self, event: Event<'_>, work: &W) -> Result<(), DraftError> {
        match event {
            Event::Begin(name) => self.begin(name, work),
            Event::Attribute(name, value) => self.attribute(name, value, work),
            Event::Text(value) => self.text(value, work),
            Event::Binary(bytes) => self.binary(bytes, work),
            Event::End => self.end(work),
        }
    }
}

fn is_ncname(value: &str) -> bool {
    is_qname(value) && !value.contains(':')
}

/// The value exactly as supplied, after the check its datatype requires.
fn checked<'a>(value: Value<'a>, work: &impl Work) -> Result<&'a str, DraftError> {
    let lexical = value.lexical;
    let invalid = || DraftError::Value {
        datatype: value.datatype,
        value: lexical.into(),
    };
    work.charge_work(lexical.len() as u64)?;
    if !lexical.chars().all(is_xml_1_0_character) {
        return Err(invalid());
    }
    let datatype = match value.datatype {
        Datatype::String => return Ok(lexical),
        Datatype::Id => ScalarType::Id,
        Datatype::AnyUri => ScalarType::AnyUri,
        Datatype::ZonedDateTime => ScalarType::DateTime,
    };
    let valid = with_lexical_scalar(lexical, datatype, work, |fact| {
        Ok::<_, core::convert::Infallible>(match fact {
            // A reference names the ID exactly, so it must need no collapsing.
            ScalarFact::Value(ScalarValue::Id(id)) => id == lexical,
            ScalarFact::Value(ScalarValue::AnyUri(_)) => true,
            // EN 319 132-1 §5.2.1 SigningTime is an instant: an absent timezone
            // is not UTC (XSD 1.0 §3.2.7), so it cannot be claimed as one.
            ScalarFact::Value(ScalarValue::DateTime(time)) => time.timezone_minutes.is_some(),
            _ => false,
        })
    })
    .map_err(|error| match error {
        InspectionError::Processing(ScalarError::Resource(error)) => DraftError::Resource(error),
        InspectionError::Processing(_) => invalid(),
        InspectionError::Visitor(never) => match never {},
    })?;
    if valid { Ok(lexical) } else { Err(invalid()) }
}
