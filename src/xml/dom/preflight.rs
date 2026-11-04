//! Shared lexical preflight and source-position sidecar for every DOM backend.

use crate::collections::{Map, Table};
use crate::xml_input as xml_sec_xml_input;
use core::ops::Range;

use xml_sec_xml_input::lexical::{Event, Scanner};

use super::ParseError;
use super::storage::{Native, Storage, Values};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SourceKind {
    Element,
    Text,
    CData,
    EntityRef,
    Comment,
    Pi,
}

pub(crate) struct SourceNode {
    kind: SourceKind,
    range: Range<usize>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DtdAttributeName<'a>(Option<&'a str>, &'a str, Option<&'a str>, &'a str);

#[cfg(feature = "xmldsig")]
impl structured_asn1::memory::HashWork for DtdAttributeName<'_> {
    fn hash_work(&self) -> Result<u64, structured_asn1::memory::MemoryError> {
        let mut work = 4_u64;
        for part in [self.0.unwrap_or(""), self.1, self.2.unwrap_or(""), self.3] {
            work = work
                .checked_add(part.len() as u64)
                .ok_or(structured_asn1::memory::MemoryError::WorkExceeded)?;
        }
        Ok(work)
    }
}

#[derive(Clone, Copy)]
pub struct DtdAttributeInfo {
    pub(super) kind: crate::document::DtdAttributeType,
    pub(super) has_non_id_declaration: bool,
}

/// XML declaration lookup with a short borrowed `QName` query.
#[doc(hidden)]
pub trait Declarations<'input, S: Storage> {
    fn lookup(
        &self,
        key: &DtdAttributeName<'_>,
        storage: S,
    ) -> Result<Option<DtdAttributeInfo>, ParseError>;
    fn get_mut(
        &mut self,
        key: &DtdAttributeName<'input>,
        storage: S,
    ) -> Result<Option<&mut DtdAttributeInfo>, ParseError>;
    fn insert(
        &mut self,
        key: DtdAttributeName<'input>,
        value: DtdAttributeInfo,
    ) -> Result<(), ParseError>;
}

impl<'input> Declarations<'input, Native> for Map<DtdAttributeName<'input>, DtdAttributeInfo> {
    fn lookup(
        &self,
        key: &DtdAttributeName<'_>,
        _: Native,
    ) -> Result<Option<DtdAttributeInfo>, ParseError> {
        Ok(self.get(key).copied())
    }
    fn get_mut(
        &mut self,
        key: &DtdAttributeName<'input>,
        _: Native,
    ) -> Result<Option<&mut DtdAttributeInfo>, ParseError> {
        Ok(Map::get_mut(self, key))
    }
    fn insert(
        &mut self,
        key: DtdAttributeName<'input>,
        value: DtdAttributeInfo,
    ) -> Result<(), ParseError> {
        self.try_reserve_entries(1)
            .map_err(|_| ParseError::AllocationFailed)?;
        Map::insert(self, key, value);
        Ok(())
    }
}

#[cfg(feature = "xmldsig")]
impl<'input, 'w, W: structured_asn1::memory::Work>
    Declarations<'input, super::storage::Accounted<'w, W>>
    for structured_asn1::memory::OwnedMap<DtdAttributeName<'input>, DtdAttributeInfo, W>
{
    fn lookup(
        &self,
        key: &DtdAttributeName<'_>,
        storage: super::storage::Accounted<'w, W>,
    ) -> Result<Option<DtdAttributeInfo>, ParseError> {
        Ok(self.get(key, storage.0)?.copied())
    }
    fn get_mut(
        &mut self,
        key: &DtdAttributeName<'input>,
        storage: super::storage::Accounted<'w, W>,
    ) -> Result<Option<&mut DtdAttributeInfo>, ParseError> {
        Ok(structured_asn1::memory::OwnedMap::get_mut(
            self, key, storage.0,
        )?)
    }
    fn insert(
        &mut self,
        key: DtdAttributeName<'input>,
        value: DtdAttributeInfo,
    ) -> Result<(), ParseError> {
        self.try_insert(key, value)?;
        Ok(())
    }
}

/// The checks the pass before the parser makes on what it reads, beside
/// recording source positions, so that one lexical pass serves both.
pub(crate) trait ScanObserver<'input> {
    /// A document type declaration, read only where DTDs are allowed; every
    /// attribute declaration of its internal subset goes to `attribute`.
    ///
    /// # Errors
    /// The check's refusal, or `attribute`'s.
    fn doctype<F>(&mut self, doctype: &'input str, attribute: F) -> Result<(), ParseError>
    where
        F: FnMut(
            &'input str,
            &'input str,
            crate::document::DtdAttributeType,
        ) -> Result<(), ParseError>;

    /// A start tag or, with `empty`, an empty-element tag: `tag` is its
    /// source, which starts at `tag_start` in the document.
    ///
    /// # Errors
    /// The check's refusal.
    fn start_element(
        &mut self,
        tag: &'input str,
        tag_start: usize,
        attributes: &[xml_sec_xml_input::lexical::Attribute<'input>],
        empty: bool,
    ) -> Result<(), ParseError>;

    /// An end tag.
    ///
    /// # Errors
    /// The check's refusal.
    fn end_element(&mut self) -> Result<(), ParseError>;

    /// Character data inside the document element: text, CDATA, or a
    /// predefined or character reference.
    ///
    /// # Errors
    /// The check's refusal.
    fn character_data(&mut self) -> Result<(), ParseError>;

    /// A reference to the general entity `name` in content.
    ///
    /// # Errors
    /// The check's refusal.
    fn entity_reference(&mut self, name: &'input str) -> Result<(), ParseError>;

    /// A comment or processing instruction.
    ///
    /// # Errors
    /// The check's refusal.
    fn node(&mut self) -> Result<(), ParseError>;

    /// Markup that is no node: the XML declaration, a document type
    /// declaration, or whitespace outside the document element.
    fn markup(&mut self);
}

/// The scan of a parse that checks nothing beyond the parser's own ceilings.
#[cfg(any(feature = "benchmark-internals", test))]
pub(crate) struct Unchecked;

#[cfg(any(feature = "benchmark-internals", test))]
impl<'input> ScanObserver<'input> for Unchecked {
    fn doctype<F>(&mut self, doctype: &'input str, mut attribute: F) -> Result<(), ParseError>
    where
        F: FnMut(
            &'input str,
            &'input str,
            crate::document::DtdAttributeType,
        ) -> Result<(), ParseError>,
    {
        let mut failure = None;
        crate::document::visit_dtd_attributes(doctype, |element, name, kind| {
            if failure.is_none()
                && let Err(error) = attribute(element, name, kind)
            {
                failure = Some(error);
            }
        });
        failure.map_or(Ok(()), Err)
    }

    fn start_element(
        &mut self,
        _: &'input str,
        _: usize,
        _: &[xml_sec_xml_input::lexical::Attribute<'input>],
        _: bool,
    ) -> Result<(), ParseError> {
        Ok(())
    }

    fn end_element(&mut self) -> Result<(), ParseError> {
        Ok(())
    }

    fn character_data(&mut self) -> Result<(), ParseError> {
        Ok(())
    }

    fn entity_reference(&mut self, _: &'input str) -> Result<(), ParseError> {
        Ok(())
    }

    fn node(&mut self) -> Result<(), ParseError> {
        Ok(())
    }

    fn markup(&mut self) {}
}

pub(super) struct LexicalPreflight<'input, S: Storage = Native> {
    /// The source positions the roxmltree projection reads; none when the
    /// preflight serves a backend that records its own.
    #[cfg(feature = "xml-backend-roxmltree")]
    nodes: Option<S::Values<SourceNode>>,
    attributes: S::Declarations<'input>,
    storage: S,
    #[cfg(feature = "xml-backend-roxmltree")]
    doctype: Option<Range<usize>>,
}

impl<'input> LexicalPreflight<'input> {
    #[cfg(any(feature = "benchmark-internals", test))]
    pub(super) fn scan(input: &'input str, allow_dtd: bool) -> Result<Self, ParseError> {
        Self::scan_in(input, allow_dtd, Native)
    }

    pub(super) fn scan_observed<O: ScanObserver<'input>>(
        input: &'input str,
        allow_dtd: bool,
        backend: super::XmlBackend,
        observer: &mut O,
    ) -> Result<Self, ParseError> {
        Self::scan_observed_in(input, allow_dtd, backend, Native, observer)
    }
}

impl<'input, S: Storage> LexicalPreflight<'input, S> {
    /// The preflight of a document that declares nothing: no attribute
    /// declarations exist, and the parser supplies the positions.
    #[cfg(feature = "xml-backend-xmloxide")]
    pub(super) fn unscanned(storage: S) -> Self {
        Self {
            #[cfg(feature = "xml-backend-roxmltree")]
            nodes: None,
            attributes: storage.declarations(),
            storage,
            #[cfg(feature = "xml-backend-roxmltree")]
            doctype: None,
        }
    }

    /// A scan recording the positions any backend of the build may read.
    #[cfg(any(feature = "benchmark-internals", test))]
    pub(super) fn scan_in(
        input: &'input str,
        allow_dtd: bool,
        storage: S,
    ) -> Result<Self, S::ParseFailure> {
        Self::scan_observed_in(
            input,
            allow_dtd,
            super::XmlBackend::Differential,
            storage,
            &mut Unchecked,
        )
    }

    /// The scan, with `observer` checking each event before its position is
    /// recorded, so the observer's refusal precedes the position ceilings.
    /// Positions are recorded only for a `backend` that reads them.
    pub(super) fn scan_observed_in<O: ScanObserver<'input>>(
        input: &'input str,
        allow_dtd: bool,
        backend: super::XmlBackend,
        storage: S,
        observer: &mut O,
    ) -> Result<Self, S::ParseFailure> {
        let mut reader = Scanner::with_storage(input, storage);
        let mut positions = Positions::new(storage, backend)?;
        let mut attributes = storage.declarations();
        #[cfg(feature = "xml-backend-roxmltree")]
        let mut doctype = None;
        while let Some(event) = reader.next_event().map_err(S::lexical_error)? {
            storage.charge(1)?;
            match event {
                Event::Start(element) => {
                    observer.start_element(
                        &input[element.range.clone()],
                        element.range.start,
                        &element.attributes,
                        false,
                    )?;
                    positions.start_element(element.range, false)?;
                    reader.recycle(element.attributes);
                }
                Event::Empty(element) => {
                    observer.start_element(
                        &input[element.range.clone()],
                        element.range.start,
                        &element.attributes,
                        true,
                    )?;
                    positions.start_element(element.range, true)?;
                    reader.recycle(element.attributes);
                }
                Event::End { range, .. } => {
                    observer.end_element()?;
                    positions.end_element(range.end);
                }
                // Both supported DOMs omit whitespace outside the document
                // element, so it must not shift the semantic sidecar.
                Event::Text { range, .. } if positions.in_element() => {
                    observer.character_data()?;
                    positions.text(range)?;
                }
                Event::Text { .. } | Event::Declaration { .. } => observer.markup(),
                Event::CData { range, .. } => {
                    observer.character_data()?;
                    positions.leaf(SourceKind::CData, range)?;
                }
                Event::Reference { name, range } if is_builtin_or_character_reference(name) => {
                    observer.character_data()?;
                    positions.text(range)?;
                }
                Event::Reference { name, range } => {
                    observer.entity_reference(name)?;
                    positions.leaf(SourceKind::EntityRef, range)?;
                }
                Event::Comment { range, .. } => {
                    observer.node()?;
                    positions.leaf(SourceKind::Comment, range)?;
                }
                Event::ProcessingInstruction { range, .. } => {
                    observer.node()?;
                    positions.leaf(SourceKind::Pi, range)?;
                }
                Event::DocType { .. } if !allow_dtd => return Err(ParseError::DtdDetected.into()),
                Event::DocType { range, .. } => {
                    // Internal declaration scanning is bounded by the actual
                    // DOCTYPE; repeated QName/hash probes are admitted below.
                    storage.charge(range.len())?;
                    storage.charge(range.len())?;
                    storage.charge(range.len())?;
                    observer.markup();
                    observer.doctype(&input[range.clone()], |element, attribute, kind| {
                        declare_attribute(&mut attributes, storage, element, attribute, kind)
                    })?;
                    #[cfg(feature = "xml-backend-roxmltree")]
                    {
                        doctype = Some(range);
                    }
                }
            }
        }
        Ok(Self {
            #[cfg(feature = "xml-backend-roxmltree")]
            nodes: positions.into_nodes(),
            attributes,
            storage,
            #[cfg(feature = "xml-backend-roxmltree")]
            doctype,
        })
    }

    pub(super) fn attribute_declaration(
        &self,
        element_prefix: Option<&str>,
        element_local: &str,
        attribute_prefix: Option<&str>,
        attribute_local: &str,
    ) -> Result<Option<DtdAttributeInfo>, ParseError> {
        self.attributes.lookup(
            &DtdAttributeName(
                element_prefix,
                element_local,
                attribute_prefix,
                attribute_local,
            ),
            self.storage,
        )
    }

    #[cfg(feature = "xml-backend-roxmltree")]
    pub(super) fn doctype_range(&self) -> Option<&Range<usize>> {
        self.doctype.as_ref()
    }

    #[cfg(feature = "xml-backend-roxmltree")]
    fn positions(&self) -> &[SourceNode] {
        self.nodes.as_deref().unwrap_or_default()
    }

    #[cfg(feature = "xml-backend-roxmltree")]
    pub(super) fn node_count(&self) -> usize {
        self.positions().len()
    }

    #[cfg(feature = "xml-backend-roxmltree")]
    pub(super) fn folded_character_data_range(
        &self,
        start: usize,
    ) -> Result<Option<(Range<usize>, bool)>, ParseError> {
        let nodes = self.positions();
        self.storage.charge(if nodes.is_empty() {
            0
        } else {
            nodes.len().ilog2() as usize + 1
        })?;
        let first = nodes.partition_point(|node| node.range.start < start);
        let Some(node) = nodes.get(first) else {
            return Ok(None);
        };
        if node.range.start != start || !node.kind.is_character_data() {
            return Ok(None);
        }

        let mut range = node.range.clone();
        let mut actionable = node.kind != SourceKind::EntityRef;
        for node in &nodes[first + 1..] {
            self.storage.charge(1)?;
            if !node.kind.is_character_data() || node.range.start != range.end {
                break;
            }
            range.end = range.end.max(node.range.end);
            actionable &= node.kind != SourceKind::EntityRef;
        }
        Ok(Some((range, actionable)))
    }
}

/// Record the internal-subset declaration of `attribute` on `element`.
fn declare_attribute<'input, S: Storage>(
    attributes: &mut S::Declarations<'input>,
    storage: S,
    element: &'input str,
    attribute: &'input str,
    kind: crate::document::DtdAttributeType,
) -> Result<(), ParseError> {
    storage.charge(element.len())?;
    storage.charge(attribute.len())?;
    let (element_prefix, element_local) = split_name(element);
    let (attribute_prefix, attribute_local) = split_name(attribute);
    // XML 1.0 3.3: the first declaration is binding.
    // https://www.w3.org/TR/2008/REC-xml-20081126/#attdecls
    let key = DtdAttributeName(
        element_prefix,
        element_local,
        attribute_prefix,
        attribute_local,
    );
    if let Some(info) = attributes.get_mut(&key, storage)? {
        // xml:id 4 constrains all declarations, even shadowed ones.
        // https://www.w3.org/TR/2005/REC-xml-id-20050909/#processing
        info.has_non_id_declaration |= kind != crate::document::DtdAttributeType::Id;
    } else {
        attributes.insert(
            key,
            DtdAttributeInfo {
                kind,
                has_non_id_declaration: kind != crate::document::DtdAttributeType::Id,
            },
        )?;
    }
    Ok(())
}

fn split_name(name: &str) -> (Option<&str>, &str) {
    match name.split_once(':') {
        Some((prefix, local)) => (Some(prefix), local),
        None => (None, name),
    }
}

#[cfg(feature = "xml-backend-roxmltree")]
impl SourceKind {
    fn is_character_data(self) -> bool {
        matches!(self, Self::Text | Self::CData | Self::EntityRef)
    }
}

fn enforce_depth(actual: usize) -> Result<(), ParseError> {
    let maximum = crate::hard_limits::XML_DOCUMENT_DEPTH_CEILING;
    if actual > maximum {
        Err(ParseError::DepthLimitReached { maximum, actual })
    } else {
        Ok(())
    }
}

/// The element depth a scan tracks, with the source positions it records
/// for the roxmltree projection when the scan serves a backend that reads
/// them.
struct Positions<S: Storage> {
    depth: usize,
    sidecar: Option<Sidecar<S>>,
}

struct Sidecar<S: Storage> {
    nodes: S::Values<SourceNode>,
    /// The position of each open element, whose end is still unread.
    open: S::Values<usize>,
}

impl<S: Storage> Positions<S> {
    fn new(storage: S, backend: super::XmlBackend) -> Result<Self, ParseError> {
        // Only the roxmltree projection reads source positions from the
        // scan; xmloxide records the positions of its own tree as it parses.
        let sidecar =
            if cfg!(feature = "xml-backend-roxmltree") && backend != super::XmlBackend::Xmloxide {
                Some(Sidecar {
                    nodes: storage.values(0)?,
                    open: storage.values(0)?,
                })
            } else {
                None
            };
        Ok(Self { depth: 0, sidecar })
    }

    fn in_element(&self) -> bool {
        self.depth > 0
    }

    fn start_element(&mut self, range: Range<usize>, empty: bool) -> Result<(), ParseError> {
        enforce_depth(self.depth + 1)?;
        if let Some(sidecar) = &mut self.sidecar {
            if !empty {
                sidecar.open.push(sidecar.nodes.len())?;
            }
            push_leaf(&mut sidecar.nodes, SourceKind::Element, range)?;
        }
        if !empty {
            self.depth += 1;
        }
        Ok(())
    }

    fn end_element(&mut self, end: usize) {
        if let Some(depth) = self.depth.checked_sub(1) {
            self.depth = depth;
        }
        if let Some(sidecar) = &mut self.sidecar
            && let Some(index) = sidecar.open.pop()
        {
            sidecar.nodes[index].range.end = end;
        }
    }

    fn text(&mut self, range: Range<usize>) -> Result<(), ParseError> {
        match &mut self.sidecar {
            Some(sidecar) => push_text_position(&mut sidecar.nodes, range),
            None => Ok(()),
        }
    }

    fn leaf(&mut self, kind: SourceKind, range: Range<usize>) -> Result<(), ParseError> {
        match &mut self.sidecar {
            Some(sidecar) => push_leaf(&mut sidecar.nodes, kind, range),
            None => Ok(()),
        }
    }

    #[cfg(feature = "xml-backend-roxmltree")]
    fn into_nodes(self) -> Option<S::Values<SourceNode>> {
        self.sidecar.map(|sidecar| sidecar.nodes)
    }
}

fn push_text_position<V: Values<SourceNode>>(
    nodes: &mut V,
    range: Range<usize>,
) -> Result<(), ParseError> {
    if let Some(previous) = nodes.last_mut()
        && previous.kind == SourceKind::Text
        && previous.range.end == range.start
    {
        previous.range.end = range.end;
    } else {
        push_source_position(
            nodes,
            SourceNode {
                kind: SourceKind::Text,
                range,
            },
        )?;
    }
    Ok(())
}

fn push_leaf<V: Values<SourceNode>>(
    nodes: &mut V,
    kind: SourceKind,
    range: Range<usize>,
) -> Result<(), ParseError> {
    push_source_position(nodes, SourceNode { kind, range })
}

fn push_source_position<V: Values<SourceNode>>(
    nodes: &mut V,
    node: SourceNode,
) -> Result<(), ParseError> {
    let maximum = crate::hard_limits::XML_SOURCE_POSITION_CEILING;
    if nodes.len() >= maximum {
        return Err(ParseError::SourcePositionLimitReached {
            maximum,
            actual: nodes.len() + 1,
        });
    }
    nodes.push(node)
}

fn is_builtin_or_character_reference(reference: &str) -> bool {
    reference.starts_with('#') || matches!(reference, "amp" | "lt" | "gt" | "apos" | "quot")
}

#[cfg(all(test, feature = "xmldsig"))]
mod accounted_tests {
    use super::super::storage::Accounted;
    use super::*;
    use structured_asn1::{
        Encoding, Limits, Parser,
        memory::{Memory, MemoryAccount, MemoryError},
    };

    #[test]
    fn scanner_retains_actual_attribute_storage_without_copying_borrowed_values() {
        use std::fmt::Write as _;
        // Wide tags exercise both in-place sort passes. Attribute order and
        // source borrows must remain identical to the standalone scanner.
        let mut source = String::from("<r");
        for index in (0..64).rev() {
            write!(source, " a{index}='v{index}'").expect("scanner attribute");
        }
        source.push_str("/>");
        let Some(Event::Empty(expected)) = Scanner::new(&source)
            .next_event()
            .expect("native empty tag")
        else {
            panic!("one empty tag");
        };
        let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
        let mut scanner = Scanner::with_storage(&source, Accounted(&memory));
        let Some(Event::Empty(actual)) = scanner.next_event().expect("funded empty tag") else {
            panic!("one empty tag");
        };
        assert_eq!(actual.name, expected.name);
        assert_eq!(actual.range, expected.range);
        assert_eq!(&*actual.attributes, &expected.attributes);
        for (actual, expected) in actual.attributes.iter().zip(&expected.attributes) {
            assert_eq!(actual.value.as_ptr(), expected.value.as_ptr());
        }
        assert!(memory.used() > 0);
        drop(actual);
        assert_eq!(memory.used(), 0);
    }

    #[test]
    fn recycling_a_tag_releases_its_accounted_capacity() {
        use std::fmt::Write as _;
        // A finished wide tag must not stay charged while later source
        // positions allocate: a document at its limit would be refused.
        let mut source = String::from("<r");
        for index in 0..64 {
            write!(source, " a{index}='v'").expect("scanner attribute");
        }
        source.push_str("/>");
        let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
        let mut scanner = Scanner::with_storage(&source, Accounted(&memory));
        let Some(Event::Empty(tag)) = scanner.next_event().expect("funded empty tag") else {
            panic!("one empty tag");
        };
        assert!(memory.used() > 0);
        scanner.recycle(tag.attributes);
        assert_eq!(memory.used(), 0);
    }

    #[test]
    fn scanner_refusal_precedes_lexing_and_releases_partial_attribute_buffers() {
        // A current query's work ceiling is not replaced by its account;
        // capacity failure must also release a partially constructed tag.
        let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
        let parser = Parser::new(
            Encoding::Der,
            Limits {
                max_work: 0,
                ..Default::default()
            },
            memory.clone(),
        );
        let reader = parser.read(&[], 0).expect("empty execution cursor");
        let work = reader.execution();
        let mut scanner = Scanner::with_storage("<r a='v'/>", Accounted(&work));
        assert!(matches!(
            scanner.next_event(),
            Err(crate::xml_input::lexical::Error::Resource(
                MemoryError::WorkExceeded
            ))
        ));
        assert_eq!(memory.used(), 0);
        assert_eq!(memory.work_used(), 0);
        for capacity in [0, 1, 128] {
            let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(capacity, 1 << 24)));
            let mut scanner =
                Scanner::with_storage("<r a='v' b='w' c='x' d='y' e='z'/>", Accounted(&memory));
            assert!(matches!(
                scanner.next_event(),
                Err(crate::xml_input::lexical::Error::Resource(
                    MemoryError::LimitExceeded
                ))
            ));
            drop(scanner);
            assert_eq!(memory.used(), 0);
        }
    }

    #[test]
    fn duplicate_attribute_diagnostic_retains_its_paid_name_and_original_kind() {
        // A duplicate QName is a grammar error only if its diagnostic fits;
        // a construction refusal must never be formatted as malformed XML.
        let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
        let mut scanner =
            Scanner::with_storage("<r p:repeated='a' p:repeated='b'/>", Accounted(&memory));
        let error = scanner
            .next_event()
            .expect_err("duplicate attribute must be rejected");
        assert!(
            matches!(&error, crate::xml_input::lexical::Error::DuplicateAttribute(name) if &**name == "p:repeated")
        );
        drop(scanner);
        assert!(memory.used() > 0);
        drop(error);
        assert_eq!(memory.used(), 0);
    }

    #[test]
    fn preflight_indexes_paid_dtd_names_and_retains_first_declaration() {
        // DTD metadata uses the same first-binding/xml:id constraints with
        // borrowed short-lived queries, without collecting native maps.
        let source =
            "<!DOCTYPE r [<!ATTLIST r id ID #IMPLIED><!ATTLIST r id CDATA #IMPLIED>]><r id='a'/>";
        let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
        let preflight = LexicalPreflight::scan_in(source, true, Accounted(&memory))
            .expect("fixed DTD preflight");
        let query = String::from("id");
        let declaration = preflight
            .attribute_declaration(None, "r", None, &query)
            .expect("borrowed declaration query")
            .expect("first declaration retained");
        assert_eq!(declaration.kind, crate::document::DtdAttributeType::Id);
        assert!(declaration.has_non_id_declaration);
        assert!(memory.used() > 0);
        drop(preflight);
        assert_eq!(memory.used(), 0);
    }
}
