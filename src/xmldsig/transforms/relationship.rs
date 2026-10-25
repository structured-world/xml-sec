//! ECMA-376 Part 2 relationship normalization, with one MCE semantic path.

use std::{
    cell::Cell,
    io::{self, Write},
    mem::size_of,
};

#[cfg(test)]
use super::Transform;
use super::parameters::{Instruction, Selector, View};
use super::{TransformError, TransformExecutionBudget, transform_resource_limit};
#[cfg(test)]
use crate::c14n::scratch::Native;
use crate::c14n::scratch::{List, Scratch};
use crate::{
    c14n::C14nMode,
    policy::OpcRelationshipEdition,
    xml::dom::{Document, Node},
};

/// OPC Relationship Transform algorithm URI (both supported editions).
pub const RELATIONSHIP_TRANSFORM_URI: &str =
    "http://schemas.openxmlformats.org/package/2006/RelationshipTransform";
const REL: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
const PARAM: &str = "http://schemas.openxmlformats.org/package/2006/digital-signature";
const MC: &str = "http://schemas.openxmlformats.org/markup-compatibility/2006";
const XML: &str = "http://www.w3.org/XML/1998/namespace";

/// An OPC selector. Repeated selectors form a union, never duplicate output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelationshipSelector {
    /// Select relationships by their Id attribute.
    SourceId(String),
    /// Select every relationship of the given Type.
    SourceType(String),
}

impl RelationshipSelector {
    pub(crate) fn parameter(&self) -> (&'static str, &'static str, &str) {
        match self {
            Self::SourceId(value) => ("RelationshipReference", "SourceId", value),
            Self::SourceType(value) => ("RelationshipsGroupReference", "SourceType", value),
        }
    }
}

pub(super) fn validate_owned_selectors(
    selectors: &[RelationshipSelector],
    budget: &WorkspaceBudget,
) -> Result<(), TransformError> {
    budget.charge(
        selectors
            .len()
            .checked_mul(size_of::<RelationshipSelector>())
            .ok_or_else(|| invalid("parameter size overflow"))?,
    )?;
    for selector in selectors {
        let (_, _, value) = selector.parameter();
        budget.charge(value.len())?;
    }
    Ok(())
}

pub(super) struct WorkspaceBudget {
    remaining: Cell<usize>,
    maximum: usize,
    resource: &'static str,
}

impl Default for WorkspaceBudget {
    fn default() -> Self {
        Self::new(crate::hard_limits::OPC_WORKSPACE_BYTE_CEILING)
    }
}

impl WorkspaceBudget {
    pub(super) fn new(maximum: usize) -> Self {
        Self {
            remaining: Cell::new(maximum),
            maximum,
            resource: crate::policy::resource_name::OPC_WORKSPACE_BYTES,
        }
    }

    pub(super) fn parameters(maximum: usize) -> Self {
        Self {
            resource: crate::policy::resource_name::OPC_PARAMETER_BYTES,
            ..Self::new(maximum)
        }
    }

    fn charge(&self, bytes: usize) -> Result<(), TransformError> {
        let remaining = self.remaining.get();
        if bytes > remaining {
            self.remaining.set(0);
            return Err(transform_resource_limit(
                self.resource,
                self.maximum,
                (self.maximum - remaining).saturating_add(bytes),
            ));
        }
        self.remaining.set(remaining - bytes);
        Ok(())
    }

    fn push<T>(&self, vector: &mut impl List<T>, value: T) -> Result<(), TransformError> {
        self.reserve_slot(vector)?;
        vector.push(value)?;
        Ok(())
    }

    fn reserve_slot<T>(&self, vector: &mut impl List<T>) -> Result<(), TransformError> {
        if vector.len() == vector.capacity() {
            let capacity = vector
                .capacity()
                .max(4)
                .checked_mul(2)
                .ok_or_else(|| invalid("workspace overflow"))?;
            // Charge the complete new allocation before reserve; old capacity
            // remains live during realloc and counts toward the cumulative limit.
            self.charge(
                capacity
                    .checked_mul(size_of::<T>())
                    .ok_or_else(|| invalid("workspace overflow"))?,
            )?;
            vector.reserve_exact(capacity - vector.len())?;
        }
        Ok(())
    }
}

fn invalid(message: &'static str) -> TransformError {
    TransformError::Relationship(message)
}

/// Validate one algorithm chain, not an OPC package signature.
/// ECMA-376 Part 2 (2021) §10.5.8.2 also constrains package Manifest
/// placement and per-part uniqueness; those require a package-level validator,
/// not restrictions on this reusable XMLDSig/XMLEnc transform mechanism.
/// <https://ecma-international.org/publications-and-standards/standards/ecma-376/>
pub(crate) fn validate_chain<I: Instruction>(chain: &[I]) -> Result<(), TransformError> {
    let mut seen = false;
    for (index, transform) in chain.iter().enumerate() {
        if let View::Relationship(selectors) = transform.view() {
            // ECMA-376 Part 2 (2021) §§10.5.8.2, 10.6; 2012 §13.2.4.24:
            // https://ecma-international.org/publications-and-standards/standards/ecma-376/
            // The normalized XML must immediately be followed by C14N.
            if seen
                || selectors.is_empty()
                || !matches!(
                    chain.get(index + 1).map(Instruction::view),
                    Some(View::C14n(..))
                )
            {
                return Err(invalid(
                    "each chain permits one relationship transform with selectors, immediately followed by canonicalization",
                ));
            }
            seen = true;
        }
    }
    Ok(())
}

pub(crate) fn validate_edition<I: Instruction>(
    chain: &[I],
    edition: OpcRelationshipEdition,
) -> Result<(), TransformError> {
    validate_chain(chain)?;
    // 2021 §§10.5.5, 10.5.8.2 and 2012 §13.2.4.4 restrict OPC
    // canonicalization to inclusive C14N 1.0 with/without comments. In 2012,
    // consumers "shall fail the validation" for other methods (M6.34).
    // https://ecma-international.org/publications-and-standards/standards/ecma-376/
    for pair in chain.windows(2) {
        if matches!(pair[0].view(), View::Relationship(_))
            && let View::C14n(algorithm, _) = pair[1].view()
            && algorithm.mode() != C14nMode::Inclusive1_0
        {
            return Err(invalid(match edition {
                OpcRelationshipEdition::Ecma2012 => {
                    "OPC Ecma2012 requires C14N 1.0 after relationship normalization"
                }
                OpcRelationshipEdition::Ecma2021 => {
                    "OPC Ecma2021 requires C14N 1.0 after relationship normalization"
                }
            }));
        }
    }
    Ok(())
}

#[cfg(test)]
fn parse_selectors(
    node: Node<'_, '_>,
    budget: &WorkspaceBudget,
) -> Result<Vec<RelationshipSelector>, TransformError> {
    parse_selectors_in(node, budget, &Native)
}

pub(super) fn parse_selectors_in<'a, S: super::ParseStorage<'a>>(
    node: Node<'a, 'a>,
    budget: &WorkspaceBudget,
    scratch: &S,
) -> Result<S::Values<S::Selector>, TransformError> {
    let mut selectors = scratch.values();
    scratch.charge(node.children().len())?;
    for child in node.children() {
        if child.is_text()
            && let Some(text) = child.text()
        {
            scratch.charge(text.len())?;
        }
        if child.is_comment()
            || child.is_pi()
            || (child.is_text() && child.text().is_some_and(super::is_xml_whitespace_only))
        {
            continue;
        }
        let tag = child.tag_name();
        scratch.charge(tag.name().len() + tag.namespace().map_or(0, str::len))?;
        let attribute = match (tag.namespace(), tag.name()) {
            (Some(PARAM), "RelationshipReference") => "SourceId",
            (Some(PARAM), "RelationshipsGroupReference") => "SourceType",
            _ => return Err(invalid("unexpected relationship selector")),
        };
        // ECMA-376 Part 2: 2021 C.2 / 2012 D.3 extend xsd:string.
        // Character content is permitted but does not participate in selection.
        // https://ecma-international.org/publications-and-standards/standards/ecma-376/
        scratch.charge(child.children().len())?;
        if child.attributes().len() != 1 || child.children().any(|n| n.is_element()) {
            return Err(invalid(
                "relationship selector requires exactly its named attribute and no child elements",
            ));
        }
        for attribute in child.attributes() {
            scratch.charge(attribute.name().len() + attribute.namespace().map_or(0, str::len))?;
        }
        let value = child
            .attribute(attribute)
            .ok_or_else(|| invalid("missing relationship selector attribute"))?;
        budget.charge(value.len())?;
        budget.reserve_slot(&mut selectors)?;
        selectors.push(scratch.selector(attribute == "SourceId", value))?;
    }
    if selectors.is_empty() {
        return Err(invalid("relationship transform requires selectors"));
    }
    Ok(selectors)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Parent {
    Document,
    Relationships,
    Relationship(usize),
}

struct Frame<'a, D: crate::xml::dom::storage::Storage> {
    next: Option<Node<'a, 'a, D>>,
    parent: Parent,
}

struct Relationship<'a, S: Scratch, D: crate::xml::dom::storage::Storage> {
    id: &'a str,
    kind: &'a str,
    target: &'a str,
    mode: &'a str,
    instructions: S::Values<Node<'a, 'a, D>>,
    selected: bool,
}

enum Event<'a, D: crate::xml::dom::storage::Storage> {
    Instruction(Node<'a, 'a, D>),
    Relationship,
}

struct CurrentFilter<'a, S: Scratch> {
    original: &'a super::NodeFilterWorkBudget,
    scratch: &'a S,
}
impl<S: Scratch> CurrentFilter<'_, S> {
    fn charge(&self, units: usize) -> Result<(), TransformError> {
        self.original.charge(units)?;
        self.scratch.charge(units)?;
        Ok(())
    }
}
struct CurrentBudget<'a, S: Scratch> {
    original: &'a TransformExecutionBudget,
    node_filter: CurrentFilter<'a, S>,
}
impl<S: Scratch> CurrentBudget<'_, S> {
    fn attribute<'a, D: crate::xml::dom::storage::Storage>(
        &self,
        node: Node<'a, 'a, D>,
        namespace: Option<&str>,
        local: &str,
    ) -> Result<Option<&'a str>, TransformError> {
        for attribute in node.attributes() {
            let work = attribute
                .name()
                .len()
                .checked_add(attribute.namespace().map_or(0, str::len))
                .and_then(|size| size.checked_add(local.len()))
                .and_then(|size| size.checked_add(namespace.map_or(0, str::len)))
                .and_then(|size| size.checked_add(1))
                .ok_or(structured_asn1::memory::MemoryError::WorkExceeded)
                .map_err(crate::c14n::C14nError::from)?;
            self.node_filter.scratch.charge(work)?;
            if attribute.name() == local && attribute.namespace() == namespace {
                return Ok(Some(attribute.value()));
            }
        }
        Ok(None)
    }
}
impl<S: Scratch> std::ops::Deref for CurrentBudget<'_, S> {
    type Target = TransformExecutionBudget;
    fn deref(&self) -> &Self::Target {
        self.original
    }
}

/// No intermediate DOM or copied attribute strings: retained records borrow
/// the input arena; only the bounded traversal stack and sorted records allocate.
#[cfg(test)]
pub(super) fn normalize<'a>(
    document: &'a Document<'a>,
    selectors: &[RelationshipSelector],
    edition: OpcRelationshipEdition,
    budget: &TransformExecutionBudget,
) -> Result<Vec<u8>, TransformError> {
    normalize_in(document, selectors, edition, budget, &Native)
}

pub(super) fn normalize_in<'a, S: Scratch, D: crate::xml::dom::storage::Storage>(
    document: &'a Document<'a, D>,
    selectors: &[impl Selector],
    edition: OpcRelationshipEdition,
    budget: &TransformExecutionBudget,
    scratch: &S,
) -> Result<S::Bytes, TransformError> {
    let current = CurrentBudget {
        original: budget,
        node_filter: CurrentFilter {
            original: &budget.node_filter,
            scratch,
        },
    };
    let budget = &current;
    let mut scan = scan_relationships(document, edition, budget, scratch)?;
    sort_records(&mut scan.records, scan.padded_ids, budget, scratch)?;
    let selected = select_records(&mut scan.records, selectors, edition, budget)?;
    write_normalized(&scan, selected, edition, budget, scratch)
}

/// Relationships part content in document order, borrowing the input arena.
struct Scan<'a, S: Scratch, D: crate::xml::dom::storage::Storage> {
    records: S::Values<Relationship<'a, S, D>>,
    /// Processing instructions before the root element.
    before: S::Values<Node<'a, 'a, D>>,
    /// Processing instructions after the root element.
    after: S::Values<Node<'a, 'a, D>>,
    /// Relationship slots and root-level instructions in document order.
    events: S::Values<Event<'a, D>>,
    /// Whether any Id carries collapsible whitespace.
    padded_ids: bool,
}

/// Markup Compatibility handling of one element before vocabulary checks.
enum Compatibility<'a, D: crate::xml::dom::storage::Storage> {
    /// Process the element as Relationships vocabulary.
    Understood,
    /// Replace the element by this node's children, or by nothing.
    Replace(Option<Node<'a, 'a, D>>),
}

fn compatibility<'a, S: Scratch, D: crate::xml::dom::storage::Storage>(
    node: Node<'a, 'a, D>,
    edition: OpcRelationshipEdition,
    budget: &CurrentBudget<'_, S>,
) -> Result<Compatibility<'a, D>, TransformError> {
    let tag = node.tag_name();
    validate_mce_entry(node, edition, budget)?;
    if tag.namespace() != Some(REL)
        && tag.namespace() != Some(MC)
        && ignorable(node, tag.namespace(), budget)?
    {
        if !process_content(node, edition, budget)? {
            return Ok(Compatibility::Replace(None));
        }
        check_unwrapped(node)?;
        if edition == OpcRelationshipEdition::Ecma2021 {
            must_understand(node, budget)?;
        }
        return Ok(Compatibility::Replace(Some(node)));
    }
    if edition == OpcRelationshipEdition::Ecma2021 {
        must_understand(node, budget)?;
    }
    if tag.namespace() != Some(MC) {
        return Ok(Compatibility::Understood);
    }
    if tag.name() != "AlternateContent" {
        return Err(invalid("MCE Choice/Fallback outside AlternateContent"));
    }
    check_unwrapped(node)?;
    let branch = alternate_content(node, edition, budget)?;
    if let Some(branch) = branch
        && edition == OpcRelationshipEdition::Ecma2021
    {
        must_understand(branch, budget)?;
    }
    Ok(Compatibility::Replace(branch))
}

/// Validate one `Relationship` element; also reports whether its Id is padded.
fn read_relationship<'a, S: Scratch, D: crate::xml::dom::storage::Storage>(
    node: Node<'a, 'a, D>,
    edition: OpcRelationshipEdition,
    budget: &CurrentBudget<'_, S>,
    scratch: &S,
) -> Result<(Relationship<'a, S, D>, bool), TransformError> {
    validate_attributes(node, &["Id", "Type", "Target", "TargetMode"], budget)?;
    let id = budget
        .attribute(node, None, "Id")?
        .ok_or_else(|| invalid("missing relationship Id"))?;
    budget.node_filter.charge(id.len())?;
    // XSD 1.0 §§3.3.8, 4.3.6: ID's whiteSpace facet is collapse.
    // Schema validation does not replace lexical attribute content
    // in the transform's input XML infoset.
    // https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#ID
    if !ncname(id.trim_matches(xml_whitespace)) {
        return Err(invalid("relationship Id must be an xsd:ID"));
    }
    let padded = id != id.trim_matches(xml_whitespace);
    let kind = budget
        .attribute(node, None, "Type")?
        .ok_or_else(|| invalid("missing relationship Type"))?;
    budget.node_filter.charge(kind.len())?;
    validate_relationship_type_iri(kind)?;
    let target = budget
        .attribute(node, None, "Target")?
        .ok_or_else(|| invalid("missing relationship Target"))?;
    let mode = budget
        .attribute(node, None, "TargetMode")?
        .unwrap_or("Internal");
    if mode != "Internal" && mode != "External" {
        return Err(invalid("invalid relationship TargetMode"));
    }
    budget.node_filter.charge(target.len())?;
    if mode == "Internal" {
        validate_internal_target_reference_syntax(target)?;
    } else {
        validate_external_target_reference_syntax(target, edition)?;
    }
    Ok((
        Relationship {
            id,
            kind,
            target,
            mode,
            instructions: scratch.values(),
            selected: false,
        },
        padded,
    ))
}

/// Text outside a `Relationship` element must be whitespace.
fn check_text<S: Scratch, D: crate::xml::dom::storage::Storage>(
    node: Node<'_, '_, D>,
    parent: Parent,
    budget: &CurrentBudget<'_, S>,
) -> Result<(), TransformError> {
    budget
        .node_filter
        .scratch
        .charge(node.text().map_or(0, str::len))?;
    // CT_Relationship extends xsd:string (2012 D.4 / 2021 C.5).
    // 2012 §13.2.4.24 step 3(2) removes its contents; 2021 §10.6
    // step 3(a) removes text. CT_Relationships remains element-only.
    // https://ecma-international.org/publications-and-standards/standards/ecma-376/
    if matches!(parent, Parent::Relationship(_))
        || node.text().is_some_and(super::is_xml_whitespace_only)
    {
        return Ok(());
    }
    Err(invalid("Relationships part has character data"))
}

fn scan_relationships<'a, S: Scratch, D: crate::xml::dom::storage::Storage>(
    document: &'a Document<'a, D>,
    edition: OpcRelationshipEdition,
    budget: &CurrentBudget<'_, S>,
    scratch: &S,
) -> Result<Scan<'a, S, D>, TransformError> {
    let mut frames = scratch.values();
    let mut scan: Scan<'a, S, D> = Scan {
        records: scratch.values(),
        before: scratch.values(),
        after: scratch.values(),
        events: scratch.values(),
        padded_ids: false,
    };
    let mut root_seen = false;
    budget.opc_workspace.push(
        &mut frames,
        Frame {
            next: document.root().first_child(),
            parent: Parent::Document,
        },
    )?;
    while let Some(frame) = frames.last_mut() {
        let Some(node) = frame.next else {
            frames.pop();
            continue;
        };
        frame.next = node.next_sibling();
        let parent = frame.parent;
        budget.node_filter.charge(1)?;
        if node.is_comment() {
            continue;
        }
        if node.is_text() {
            check_text(node, parent, budget)?;
            continue;
        }
        if node.is_pi() {
            match parent {
                Parent::Document if !root_seen => {
                    budget.opc_workspace.push(&mut scan.before, node)?;
                }
                Parent::Document => budget.opc_workspace.push(&mut scan.after, node)?,
                Parent::Relationships => budget
                    .opc_workspace
                    .push(&mut scan.events, Event::Instruction(node))?,
                Parent::Relationship(_) if edition == OpcRelationshipEdition::Ecma2012 => {}
                Parent::Relationship(index) => {
                    budget
                        .opc_workspace
                        .push(&mut scan.records[index].instructions, node)?;
                }
            }
            continue;
        }
        if let Compatibility::Replace(content) = compatibility(node, edition, budget)? {
            if let Some(content) = content {
                budget.opc_workspace.push(
                    &mut frames,
                    Frame {
                        next: content.first_child(),
                        parent,
                    },
                )?;
            }
            continue;
        }
        let tag = node.tag_name();
        let next_parent = match (parent, tag.namespace(), tag.name()) {
            (Parent::Document, Some(REL), "Relationships") if !root_seen => {
                root_seen = true;
                validate_attributes(node, &[], budget)?;
                Parent::Relationships
            }
            (Parent::Relationships, Some(REL), "Relationship") => {
                let (record, padded) = read_relationship(node, edition, budget, scratch)?;
                scan.padded_ids |= padded;
                let index = scan.records.len();
                budget.opc_workspace.push(&mut scan.records, record)?;
                budget
                    .opc_workspace
                    .push(&mut scan.events, Event::Relationship)?;
                Parent::Relationship(index)
            }
            _ => return Err(invalid("invalid Relationships part element")),
        };
        budget.opc_workspace.push(
            &mut frames,
            Frame {
                next: node.first_child(),
                parent: next_parent,
            },
        )?;
    }
    if !root_seen {
        return Err(invalid("missing Relationships root"));
    }
    Ok(scan)
}

/// Sort records by Id and refuse duplicates under `xsd:ID` whitespace collapse.
fn sort_records<S: Scratch, D: crate::xml::dom::storage::Storage>(
    records: &mut S::Values<Relationship<'_, S, D>>,
    padded_ids: bool,
    budget: &CurrentBudget<'_, S>,
    scratch: &S,
) -> Result<(), TransformError> {
    // String comparison visits are conservatively charged before sorting.
    let max_id = records
        .iter()
        .map(|record| record.id.len())
        .max()
        .unwrap_or(0);
    let work = records
        .len()
        .checked_mul(4 * (records.len().max(1).ilog2() as usize + 1) * max_id.max(1))
        .ok_or_else(|| invalid("sort work overflow"))?;
    budget.node_filter.charge(work)?;
    if padded_ids {
        records.sort(|left, right| {
            scratch.charge(left.id.len().max(right.id.len()))?;
            Ok(left
                .id
                .trim_matches(xml_whitespace)
                .cmp(right.id.trim_matches(xml_whitespace)))
        })?;
    } else {
        records.sort(|left, right| {
            scratch.charge(left.id.len().max(right.id.len()))?;
            Ok(left.id.cmp(right.id))
        })?;
    }
    if records.windows(2).any(|pair| {
        pair[0].id.trim_matches(xml_whitespace) == pair[1].id.trim_matches(xml_whitespace)
    }) {
        return Err(invalid("duplicate relationship Id"));
    }
    if padded_ids {
        budget.node_filter.charge(work)?;
        records.sort(|left, right| {
            scratch.charge(left.id.len().max(right.id.len()))?;
            Ok(left.id.cmp(right.id))
        })?;
    }
    Ok(())
}

/// Mark records matched by any selector; returns the first and last selected
/// sorted positions.
fn select_records<S: Scratch, D: crate::xml::dom::storage::Storage>(
    records: &mut S::Values<Relationship<'_, S, D>>,
    selectors: &[impl Selector],
    edition: OpcRelationshipEdition,
    budget: &CurrentBudget<'_, S>,
) -> Result<Option<(usize, usize)>, TransformError> {
    let mut first_selected = None;
    let mut last_selected = 0;
    for (index, record) in records.iter_mut().enumerate() {
        for selector in selectors {
            let (_, attribute, expected) = selector.parameter();
            let actual = if attribute == "SourceId" {
                record.id
            } else {
                record.kind
            };
            budget
                .node_filter
                .charge(expected.len().max(actual.len()))?;
            // ECMA-376 Part 2 (2021) §10.6 step 2 changes selector
            // comparison only; sorting still compares case-sensitive Ids.
            let matches = match edition {
                OpcRelationshipEdition::Ecma2012 => actual == expected,
                OpcRelationshipEdition::Ecma2021 => actual.eq_ignore_ascii_case(expected),
            };
            if matches {
                record.selected = true;
                break;
            }
        }
        if record.selected {
            first_selected.get_or_insert(index);
            last_selected = index;
        }
    }
    Ok(first_selected.map(|first| (first, last_selected)))
}

/// Serialize the selected records in the normalized form.
fn write_normalized<S: Scratch, D: crate::xml::dom::storage::Storage>(
    scan: &Scan<'_, S, D>,
    selected: Option<(usize, usize)>,
    edition: OpcRelationshipEdition,
    budget: &CurrentBudget<'_, S>,
    scratch: &S,
) -> Result<S::Bytes, TransformError> {
    let mut output = Output {
        bytes: scratch.bytes(),
        budget,
        failure: None,
    };
    let result: Result<(), TransformError> = (|| {
        for node in scan.before.iter() {
            write_instruction(*node, &mut output)?;
        }
        output
            .write_all(b"<Relationships xmlns=\"")
            .map_err(output_error)?;
        output.write_all(REL.as_bytes()).map_err(output_error)?;
        output.write_all(b"\">").map_err(output_error)?;
        let mut records = scan.records.iter();
        let mut slots_seen = 0;
        for event in scan.events.iter() {
            let record = match event {
                Event::Instruction(node) => {
                    // 2012 §13.2.4.24 step 3 removes all edge characters,
                    // whereas 2021 §10.6 step 3 removes text/comments only:
                    // https://ecma-international.org/publications-and-standards/standards/ecma-376/
                    if edition == OpcRelationshipEdition::Ecma2021
                        || selected
                            .is_some_and(|(first, last)| slots_seen > first && slots_seen <= last)
                    {
                        write_instruction(*node, &mut output)?;
                    }
                    continue;
                }
                Event::Relationship => records
                    .next()
                    .ok_or_else(|| invalid("relationship slot mismatch"))?,
            };
            slots_seen += 1;
            if !record.selected {
                continue;
            }
            output.write_all(b"<Relationship").map_err(output_error)?;
            for (name, value) in [
                ("Id", record.id),
                ("Target", record.target),
                ("TargetMode", record.mode),
                ("Type", record.kind),
            ] {
                write!(output, " {name}=\"").map_err(output_error)?;
                crate::c14n::escape_attr(value, &mut output).map_err(output_error)?;
                output.write_all(b"\"").map_err(output_error)?;
            }
            output.write_all(b">").map_err(output_error)?;
            if edition == OpcRelationshipEdition::Ecma2021 {
                for instruction in record.instructions.iter() {
                    write_instruction(*instruction, &mut output)?;
                }
            }
            output.write_all(b"</Relationship>").map_err(output_error)?;
        }
        output
            .write_all(b"</Relationships>")
            .map_err(output_error)?;
        for node in scan.after.iter() {
            write_instruction(*node, &mut output)?;
        }
        Ok(())
    })();
    if let Some(error) = output.failure {
        return Err(error);
    }
    result?;
    Ok(output.bytes)
}

fn write_instruction<B: crate::c14n::scratch::Bytes, D: crate::xml::dom::storage::Storage>(
    node: Node<'_, '_, D>,
    output: &mut Output<'_, B>,
) -> Result<(), TransformError> {
    let instruction = node
        .pi()
        .ok_or_else(|| invalid("expected processing instruction"))?;
    write!(output, "<?{}", instruction.target).map_err(output_error)?;
    if let Some(value) = instruction.value {
        write!(output, " {value}").map_err(output_error)?;
    }
    output.write_all(b"?>").map_err(output_error)
}

fn output_error(_: io::Error) -> TransformError {
    // Output retains the original typed failure, checked before returning from
    // normalize_in. The io::Write boundary needs no boxed diagnostic allocation.
    invalid("relationship output failed")
}

struct Output<'a, B: crate::c14n::scratch::Bytes> {
    bytes: B,
    budget: &'a TransformExecutionBudget,
    failure: Option<TransformError>,
}

impl<B: crate::c14n::scratch::Bytes> Write for Output<'_, B> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.failure.is_some() {
            return Err(io::ErrorKind::Other.into());
        }
        let result = (|| {
            self.budget.charge_c14n_output_policy(bytes.len())?;
            if bytes.len() > self.bytes.capacity() - self.bytes.len() {
                let capacity = self
                    .bytes
                    .len()
                    .checked_add(bytes.len())
                    .and_then(usize::checked_next_power_of_two)
                    .ok_or_else(|| invalid("output overflow"))?;
                self.budget.opc_workspace.charge(capacity)?;
                self.bytes.reserve(capacity - self.bytes.len())?;
            }
            self.bytes.append(bytes)?;
            Ok::<_, TransformError>(bytes.len())
        })();
        result.map_err(|error| {
            self.failure = Some(error);
            io::ErrorKind::Other.into()
        })
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn tokens(value: &str) -> impl Iterator<Item = &str> {
    value
        .split([' ', '\t', '\r', '\n'])
        .filter(|token| !token.is_empty())
}

fn namespace<'a, S: Scratch, D: crate::xml::dom::storage::Storage>(
    node: Node<'a, 'a, D>,
    prefix: &str,
    budget: &CurrentBudget<'_, S>,
) -> Result<&'a str, TransformError> {
    budget
        .node_filter
        .charge(prefix.len().saturating_add(node.namespaces().len()))?;
    if !ncname(prefix) {
        return Err(invalid("invalid MCE prefix"));
    }
    let mut binding = None;
    for namespace in node.namespaces() {
        budget.node_filter.scratch.charge(
            namespace
                .name()
                .map_or(0, str::len)
                .checked_add(prefix.len())
                .and_then(|size| size.checked_add(1))
                .ok_or(structured_asn1::memory::MemoryError::WorkExceeded)
                .map_err(crate::c14n::C14nError::from)?,
        )?;
        if namespace.name() == Some(prefix) {
            binding = Some(namespace.uri());
            break;
        }
    }
    // Namespaces in XML 1.0 §3 reserves xml's implicit binding, even when it
    // is not declared: https://www.w3.org/TR/2009/REC-xml-names-20091208/#ns-decl
    if prefix == "xml" {
        binding = Some(XML);
    }
    match binding {
        Some(uri) if !uri.is_empty() && uri != MC => Ok(uri),
        _ => Err(invalid("MCE prefix must bind a non-MCE namespace")),
    }
}

fn ignorable<S: Scratch, D: crate::xml::dom::storage::Storage>(
    node: Node<'_, '_, D>,
    uri: Option<&str>,
    budget: &CurrentBudget<'_, S>,
) -> Result<bool, TransformError> {
    let Some(uri) = uri else {
        return Ok(false);
    };
    for ancestor in node.ancestors() {
        budget.node_filter.charge(1)?;
        if declares_ignorable(ancestor, uri, budget)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn declares_ignorable<S: Scratch, D: crate::xml::dom::storage::Storage>(
    node: Node<'_, '_, D>,
    uri: &str,
    budget: &CurrentBudget<'_, S>,
) -> Result<bool, TransformError> {
    if let Some(value) = budget.attribute(node, Some(MC), "Ignorable")? {
        budget.node_filter.charge(value.len())?;
        for prefix in tokens(value) {
            budget.node_filter.charge(uri.len())?;
            if namespace(node, prefix, budget)? == uri {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn process_content<S: Scratch, D: crate::xml::dom::storage::Storage>(
    node: Node<'_, '_, D>,
    edition: OpcRelationshipEdition,
    budget: &CurrentBudget<'_, S>,
) -> Result<bool, TransformError> {
    let tag = node.tag_name();
    for ancestor in node.ancestors() {
        budget.node_filter.charge(1)?;
        if let Some(value) = budget.attribute(ancestor, Some(MC), "ProcessContent")? {
            budget.node_filter.charge(value.len())?;
            for token in tokens(value) {
                let (prefix, local) = token
                    .split_once(':')
                    .ok_or_else(|| invalid("MCE name requires a prefix"))?;
                if tag.namespace() == Some(namespace(ancestor, prefix, budget)?)
                    && (local == "*" || local == tag.name())
                {
                    return Ok(true);
                }
            }
        }
        // Part 3:2012 §10.1.1 resets this namespace's inherited rules, after
        // applying local ProcessContent. Part 3:2015 §9.2 instead matches any
        // ancestor's name pair; do not carry the older reset into that edition.
        // https://ecma-international.org/publications-and-standards/standards/ecma-376/
        if edition == OpcRelationshipEdition::Ecma2012
            && let Some(uri) = tag.namespace()
            && declares_ignorable(ancestor, uri, budget)?
        {
            return Ok(false);
        }
    }
    Ok(false)
}

fn validate_mce_entry<S: Scratch, D: crate::xml::dom::storage::Storage>(
    node: Node<'_, '_, D>,
    edition: OpcRelationshipEdition,
    budget: &CurrentBudget<'_, S>,
) -> Result<(), TransformError> {
    // Part 3:2012 §§10.1, 10.1.3, 10.2.1 checks MCE attributes and
    // MustUnderstand before ignoring an encountered element, including all
    // Choice/Fallback attributes. Part 3:2015 §9.4 checks MustUnderstand only
    // after ignore/selection; descendants of unselected branches are not visited.
    // https://ecma-international.org/publications-and-standards/standards/ecma-376/
    validate_mc_attributes(node, edition, budget)?;
    if edition == OpcRelationshipEdition::Ecma2012 {
        must_understand(node, budget)?;
    }
    Ok(())
}

fn validate_mc_attributes<S: Scratch, D: crate::xml::dom::storage::Storage>(
    node: Node<'_, '_, D>,
    edition: OpcRelationshipEdition,
    budget: &CurrentBudget<'_, S>,
) -> Result<(), TransformError> {
    // ECMA-376 Part 3 (2015) §§7, 9: namespace lists bind at their
    // declaration element, not at a descendant that might rebind a prefix.
    // https://ecma-international.org/publications-and-standards/standards/ecma-376/
    for attribute in node.attributes() {
        budget
            .node_filter
            .charge(attribute.value().len().saturating_add(1))?;
        if attribute.namespace() != Some(MC) {
            continue;
        }
        match attribute.name() {
            "Ignorable" | "MustUnderstand" => {
                for prefix in tokens(attribute.value()) {
                    namespace(node, prefix, budget)?;
                }
            }
            "ProcessContent" => {
                // Part 3:2012 §10 and Part 3:2015 §7 both exclude the
                // preservation attributes of the original 2006 vocabulary.
                // https://ecma-international.org/publications-and-standards/standards/ecma-376/
                for token in tokens(attribute.value()) {
                    let (prefix, local) = token
                        .split_once(':')
                        .ok_or_else(|| invalid("MCE name requires a prefix"))?;
                    let uri = namespace(node, prefix, budget)?;
                    // Part 3:2012 §10.1.2 requires Ignorable on the same
                    // element; Part 3:2015 §7.3 permits ancestor declarations.
                    // Prefix aliases are compared by their expanded namespace.
                    // https://ecma-international.org/publications-and-standards/standards/ecma-376/
                    let declared = match edition {
                        OpcRelationshipEdition::Ecma2012 => declares_ignorable(node, uri, budget)?,
                        OpcRelationshipEdition::Ecma2021 => ignorable(node, Some(uri), budget)?,
                    };
                    if (local != "*" && !ncname(local)) || !declared {
                        return Err(invalid(
                            "MCE qualified name must belong to an ignorable namespace",
                        ));
                    }
                }
            }
            _ => return Err(invalid("unknown MCE attribute")),
        }
    }
    Ok(())
}

fn must_understand<S: Scratch, D: crate::xml::dom::storage::Storage>(
    node: Node<'_, '_, D>,
    budget: &CurrentBudget<'_, S>,
) -> Result<(), TransformError> {
    if let Some(value) = budget.attribute(node, Some(MC), "MustUnderstand")? {
        budget.node_filter.charge(value.len())?;
        for prefix in tokens(value) {
            if namespace(node, prefix, budget)? != REL {
                return Err(invalid("unsupported MCE MustUnderstand namespace"));
            }
        }
    }
    Ok(())
}

fn check_unwrapped<D: crate::xml::dom::storage::Storage>(
    node: Node<'_, '_, D>,
) -> Result<(), TransformError> {
    if node.attributes().any(|a| {
        a.namespace() == Some(XML)
            && (node.tag_name().namespace() == Some(MC)
                || matches!(a.name(), "base" | "lang" | "space"))
    }) {
        return Err(invalid("unwrapped MCE element has forbidden xml attribute"));
    }
    Ok(())
}

fn validate_attributes<S: Scratch, D: crate::xml::dom::storage::Storage>(
    node: Node<'_, '_, D>,
    allowed: &[&str],
    budget: &CurrentBudget<'_, S>,
) -> Result<(), TransformError> {
    for attribute in node.attributes() {
        budget.node_filter.charge(1)?;
        match attribute.namespace() {
            Some(MC) => {}
            Some(uri) if uri != REL && ignorable(node, Some(uri), budget)? => {}
            None if allowed.contains(&attribute.name()) => {}
            _ => return Err(invalid("unexpected Relationships part attribute")),
        }
    }
    Ok(())
}

fn alternate_content<'a, S: Scratch, D: crate::xml::dom::storage::Storage>(
    node: Node<'a, 'a, D>,
    edition: OpcRelationshipEdition,
    budget: &CurrentBudget<'_, S>,
) -> Result<Option<Node<'a, 'a, D>>, TransformError> {
    validate_attributes(node, &[], budget)?;
    let mut chosen = None;
    let mut fallback = None;
    let mut choices = 0;
    for child in node.children() {
        budget.node_filter.charge(1)?;
        if child.is_comment()
            || child.is_pi()
            || (child.is_text() && child.text().is_some_and(super::is_xml_whitespace_only))
        {
            continue;
        }
        let tag = child.tag_name();
        validate_mce_entry(child, edition, budget)?;
        // Part 3 (2015) §9.2 marks ProcessContent matches as unwrapped,
        // not ignored. §9.4(3a) permits only ignored extension children here.
        // https://ecma-international.org/publications-and-standards/standards/ecma-376/
        if tag.namespace() != Some(MC)
            && ignorable(child, tag.namespace(), budget)?
            && !process_content(child, edition, budget)?
        {
            continue;
        }
        check_unwrapped(child)?;
        match (tag.namespace(), tag.name()) {
            (Some(MC), "Choice") if fallback.is_none() => {
                choices += 1;
                validate_attributes(child, &["Requires"], budget)?;
                let requires = budget
                    .attribute(child, None, "Requires")?
                    .ok_or_else(|| invalid("MCE Choice requires Requires"))?;
                budget.node_filter.charge(requires.len())?;
                let mut all_known = true;
                let mut any = false;
                for prefix in tokens(requires) {
                    any = true;
                    all_known &= namespace(child, prefix, budget)? == REL;
                }
                if !any {
                    return Err(invalid("MCE Requires must not be empty"));
                }
                if chosen.is_none() && all_known {
                    chosen = Some(child);
                }
            }
            (Some(MC), "Fallback") if fallback.is_none() && choices != 0 => {
                validate_attributes(child, &[], budget)?;
                fallback = Some(child);
            }
            _ => return Err(invalid("invalid MCE AlternateContent child order")),
        }
    }
    if choices == 0 {
        return Err(invalid("MCE AlternateContent requires a Choice"));
    }
    Ok(chosen.or(fallback))
}

fn validate_relationship_type_iri(kind: &str) -> Result<(), TransformError> {
    // ECMA-376 Part 2:2021 §§3.2.8, 6.5.3.4 (2012 §§3, 9.3.2)
    // requires an absolute IRI, including on unselected relationships.
    // RFC 3987 §2.2 requires an ASCII scheme, allows Unicode in components,
    // and excludes fragments from the absolute-IRI production.
    // https://ecma-international.org/publications-and-standards/standards/ecma-376/
    // https://www.rfc-editor.org/rfc/rfc3987#section-2.2
    // Check the collapsed anyURI value without changing its lexical infoset.
    let value = kind.trim_matches(xml_whitespace);
    if let Some(remainder) = iri_scheme_remainder(value)
        && !remainder.contains('#')
        && valid_iri_reference(remainder, false)
    {
        return Ok(());
    }
    Err(invalid("relationship Type must be an absolute IRI"))
}

fn iri_scheme_remainder(value: &str) -> Option<&str> {
    let (scheme, remainder) = value.split_once(':')?;
    if !scheme
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphabetic)
    {
        return None;
    }
    for byte in scheme.bytes() {
        if !byte.is_ascii_alphanumeric() && !matches!(byte, b'+' | b'-' | b'.') {
            return None;
        }
    }
    Some(remainder)
}

fn validate_external_target_reference_syntax(
    target: &str,
    edition: OpcRelationshipEdition,
) -> Result<(), TransformError> {
    // Part 2:2012 §9.3.2.2 permits a URI or relative reference, including
    // format-defined fragments (O1.6); 2021 §6.5.3.4 instead specifies a
    // relative reference or absolute-IRI. RFC 3987 §2.2 excludes fragments
    // from absolute-IRI, but permits them in relative references.
    // https://ecma-international.org/publications-and-standards/standards/ecma-376/
    // https://www.rfc-editor.org/rfc/rfc3987#section-2.2
    let value = target.trim_matches(xml_whitespace);
    if let Some(remainder) = iri_scheme_remainder(value) {
        if edition == OpcRelationshipEdition::Ecma2021 && remainder.contains('#') {
            return Err(invalid(
                "External relationship Target must be a relative reference or absolute IRI",
            ));
        }
        if valid_iri_reference(remainder, false) {
            return Ok(());
        }
    } else if valid_iri_reference(value, true) {
        return Ok(());
    }
    Err(invalid("invalid External relationship Target reference"))
}

fn validate_internal_target_reference_syntax(target: &str) -> Result<(), TransformError> {
    // ECMA-376 Part 2 (2021) §6.5.3.4 / 2012 §9.3.2.2 requires a
    // relative reference. RFC 3986 §4.2 includes network-path references;
    // §5.2.2 can resolve one to the SAME pack authority. Without the base
    // pack IRI (2021 §§6.5.2.2-3), this transform cannot check membership.
    // Do not equate relative-reference syntax with package target resolution.
    // https://www.rfc-editor.org/rfc/rfc3986#section-4.2
    // xsd:anyURI collapses edge whitespace before lexical validation.
    if !valid_iri_reference(target.trim_matches(xml_whitespace), true) {
        return Err(invalid(
            "Internal relationship Target must be a relative reference",
        ));
    }
    Ok(())
}

// RFC 3987 §2.2: validate components on borrowed slices, preserving the lexical
// infoset. Relative references differ only by forbidding ':' in the first
// non-slash path segment. No resolution, decoding, or scheme-specific rewriting.
// https://www.rfc-editor.org/rfc/rfc3987#section-2.2
fn valid_iri_reference(value: &str, relative: bool) -> bool {
    let (value, fragment) = value
        .split_once('#')
        .map_or((value, None), |(v, f)| (v, Some(f)));
    if let Some(fragment) = fragment
        && !iri_component(fragment, |c| iri_pchar(c) || matches!(c, '/' | '?'))
    {
        return false;
    }
    let (path, query) = value
        .split_once('?')
        .map_or((value, None), |(v, q)| (v, Some(q)));
    if let Some(query) = query
        && !iri_component(query, |c| {
            iri_pchar(c)
                || matches!(c, '/' | '?')
                || matches!(c as u32, 0xe000..=0xf8ff | 0xf0000..=0xffffd | 0x10_0000..=0x10_fffd)
        })
    {
        return false;
    }
    if let Some(authority_path) = path.strip_prefix("//") {
        let (authority, path) = authority_path
            .split_once('/')
            .map_or((authority_path, ""), |(a, p)| (a, p));
        return valid_iri_authority(authority) && iri_component(path, |c| iri_pchar(c) || c == '/');
    }
    if relative
        && !path.starts_with('/')
        && path
            .split('/')
            .next()
            .is_some_and(|segment| segment.contains(':'))
    {
        return false;
    }
    iri_component(path, |c| iri_pchar(c) || c == '/')
}

fn valid_iri_authority(authority: &str) -> bool {
    let host_port = if let Some((userinfo, host_port)) = authority.split_once('@') {
        if !iri_component(userinfo, |c| {
            iri_unreserved(c) || iri_sub_delim(c) || c == ':'
        }) {
            return false;
        }
        host_port
    } else {
        authority
    };
    if let Some(literal) = host_port.strip_prefix('[') {
        let Some((address, suffix)) = literal.split_once(']') else {
            return false;
        };
        if !suffix.is_empty()
            && !suffix
                .strip_prefix(':')
                .is_some_and(|port| port.bytes().all(|b| b.is_ascii_digit()))
        {
            return false;
        }
        if address.parse::<std::net::Ipv6Addr>().is_ok() {
            return true;
        }
        if let Some(future) = address.strip_prefix(['v', 'V'])
            && let Some((version, address)) = future.split_once('.')
        {
            return !version.is_empty()
                && version.bytes().all(|b| b.is_ascii_hexdigit())
                && !address.is_empty()
                && address
                    .chars()
                    .all(|c| c.is_ascii() && (iri_unreserved(c) || iri_sub_delim(c) || c == ':'));
        }
        return false;
    }
    let host = if let Some((host, port)) = host_port.split_once(':') {
        if !port.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        host
    } else {
        host_port
    };
    iri_component(host, |c| iri_unreserved(c) || iri_sub_delim(c))
}

fn iri_component(value: &str, allowed: impl Fn(char) -> bool) -> bool {
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            if !chars.next().is_some_and(|c| c.is_ascii_hexdigit())
                || !chars.next().is_some_and(|c| c.is_ascii_hexdigit())
            {
                return false;
            }
        } else if !allowed(c) {
            return false;
        }
    }
    true
}

fn iri_unreserved(c: char) -> bool {
    let code = c as u32;
    c.is_ascii_alphanumeric()
        || matches!(c, '-' | '.' | '_' | '~')
        || matches!(code, 0xa0..=0xd7ff | 0xf900..=0xfdcf | 0xfdf0..=0xffef)
        || ((0x10000..=0xdfffd).contains(&code) && code & 0xffff <= 0xfffd)
        || (0xe1000..=0xefffd).contains(&code)
}

fn iri_sub_delim(c: char) -> bool {
    matches!(
        c,
        '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | '='
    )
}

fn iri_pchar(c: char) -> bool {
    iri_unreserved(c) || iri_sub_delim(c) || matches!(c, ':' | '@')
}

fn ncname(value: &str) -> bool {
    !value.contains(':') && crate::xml_input::lexical::is_qname(value)
}

fn xml_whitespace(value: char) -> bool {
    matches!(value, ' ' | '\t' | '\r' | '\n')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_normalization_preserves_bytes_and_current_execution_boundaries() {
        // Every OPC stack, record, PI list, sort and output buffer shares the
        // current execution. Refusal must preserve its typed cause and release
        // already admitted storage, without borrowing the producer's ceiling.
        use structured_asn1::{
            Encoding, Limits, Parser,
            memory::{Memory, MemoryAccount, MemoryError},
        };
        let document = Document::parse(
            r#"<?before a?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="b" Type="urn:type" Target="b"/><?between x?><Relationship Id="a" Type="urn:type" Target="a"/></Relationships><?after b?>"#,
        ).expect("fixed Relationships XML");
        let selectors = [RelationshipSelector::SourceType("urn:type".into())];
        for edition in [
            OpcRelationshipEdition::Ecma2012,
            OpcRelationshipEdition::Ecma2021,
        ] {
            let expected = normalize(
                &document,
                &selectors,
                edition,
                &TransformExecutionBudget::default(),
            )
            .expect("native normalization");
            let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
            // Relationship records contain their actual storage strategy. Measure
            // the Execution-backed layout, not a differently sized Memory layout.
            let baseline = Parser::new(Encoding::Der, Limits::default(), memory.clone());
            let baseline_reader = baseline.read(&[], 0).expect("empty baseline input");
            let baseline_work = baseline_reader.execution();
            let before = memory.work_used();
            let output = normalize_in(
                &document,
                &selectors,
                edition,
                &TransformExecutionBudget::default(),
                &crate::c14n::scratch::Accounted(&baseline_work),
            )
            .expect("paid normalization");
            assert_eq!(&*output, expected);
            assert!(memory.used() >= output.len());
            let cost = memory.work_used() - before;
            drop(output);
            assert_eq!(memory.used(), 0);
            for limit in [cost, cost - 1, 0] {
                let parser = Parser::new(
                    Encoding::Der,
                    Limits {
                        max_work: limit as u64,
                        ..Default::default()
                    },
                    memory.clone(),
                );
                let reader = parser.read(&[], 0).expect("empty query input");
                let work = reader.execution();
                let before = memory.work_used();
                let result = normalize_in(
                    &document,
                    &selectors,
                    edition,
                    &TransformExecutionBudget::default(),
                    &crate::c14n::scratch::Accounted(&work),
                );
                if limit == cost {
                    assert_eq!(&*result.expect("exact work admits normalization"), expected);
                    assert_eq!(memory.work_used() - before, cost);
                } else {
                    assert!(matches!(
                        result,
                        Err(TransformError::C14n(
                            crate::c14n::C14nError::SharedExecution(MemoryError::WorkExceeded)
                        ))
                    ));
                }
                assert_eq!(memory.used(), 0);
            }
            let small = Memory::new(std::sync::Arc::new(MemoryAccount::new(0, 1 << 24)));
            let result = normalize_in(
                &document,
                &selectors,
                edition,
                &TransformExecutionBudget::default(),
                &crate::c14n::scratch::Accounted(&small),
            );
            assert!(matches!(
                result,
                Err(TransformError::C14n(
                    crate::c14n::C14nError::SharedExecution(MemoryError::LimitExceeded)
                ))
            ));
            assert_eq!(small.used(), 0);
        }
    }

    #[test]
    fn complete_relationship_iri_syntax() {
        // A scheme alone is insufficient: every component must satisfy RFC 3987.
        for value in [
            "urn:%ZZ",
            "urn:a b",
            "urn:x#fragment",
            "http://[broken]/x",
            "http://host:port/x",
            "urn:\u{e000}",
            "urn:\u{fdd0}",
            "urn:\u{1fffe}",
            "http://user@@host/x",
            "http://[::1%25zone]/x",
            "http://[v1.]/x",
            "http://[vG.a]/x",
            "http://[::1]suffix/x",
        ] {
            assert!(validate_relationship_type_iri(value).is_err(), "{value}");
        }
        for value in [
            "urn:%20",
            "https://例え.example/役割",
            "http://[::1]:80/x",
            "urn:x?\u{e000}",
            "http://user:pass@host:/x",
            "http://[v1.a:b]/x",
            "urn:\u{10000}\u{e1000}",
        ] {
            assert!(validate_relationship_type_iri(value).is_ok(), "{value}");
        }
    }

    #[test]
    fn complete_internal_target_syntax() {
        // Relative references include network paths, but not malformed escapes/authorities.
        for value in [
            "part%GG.xml",
            "a%",
            "a%2",
            "a b",
            "//[broken]/x",
            "//host:port/x",
            "a\\b",
            "//user@@host/path",
            "a#b#c",
            "a#\u{e000}",
        ] {
            assert!(
                validate_internal_target_reference_syntax(value).is_err(),
                "{value}"
            );
        }
        for value in [
            "part%20.xml",
            "//host/path",
            "//[::1]/x",
            "a?b#c",
            "../役割.xml",
            "//user:pass@host:80/path",
            "//[V1.a:b]/path",
            "/a:b",
            "a?\u{f0000}",
        ] {
            assert!(
                validate_internal_target_reference_syntax(value).is_ok(),
                "{value}"
            );
        }
    }

    #[test]
    fn mce_preservation_attributes_follow_selected_edition() {
        // Neither selected MCE vocabulary includes the original preservation attributes.
        for attribute in ["PreserveElements", "PreserveAttributes"] {
            let xml = format!(
                "<Relationships xmlns=\"{REL}\" xmlns:mc=\"{MC}\" xmlns:e=\"urn:extension\" mc:Ignorable=\"e\" mc:{attribute}=\"e:*\"><Relationship Id=\"x\" Type=\"urn:t\" Target=\"a\"/></Relationships>"
            );
            let document = Document::parse(&xml).expect("well-formed MCE document");
            for edition in [
                OpcRelationshipEdition::Ecma2012,
                OpcRelationshipEdition::Ecma2021,
            ] {
                let result = normalize(
                    &document,
                    &[RelationshipSelector::SourceId("x".into())],
                    edition,
                    &TransformExecutionBudget::default(),
                );
                assert!(result.is_err(), "{edition:?}: {attribute}");
            }
        }
    }

    #[test]
    fn relationship_type_requires_an_absolute_iri_scheme_before_selection() {
        // Type defines a role by absolute IRI in both editions. The scheme
        // uses ASCII grammar, but its remainder can contain Unicode.
        for kind in [
            "",
            "relative/type",
            "//example.com/type",
            ":type",
            "1urn:type",
            "x_y:type",
            "x/y:type",
            "?x:type",
            "#x:type",
            "urn:%ZZ",
            "http://[broken]/type",
            "urn:a b",
        ] {
            let xml = format!(
                "<Relationships xmlns=\"{REL}\"><Relationship Id=\"x\" Type=\"{kind}\" Target=\"a\"/></Relationships>"
            );
            let document = Document::parse(&xml).expect("well-formed relationship XML");
            for edition in [
                OpcRelationshipEdition::Ecma2012,
                OpcRelationshipEdition::Ecma2021,
            ] {
                for id in ["x", "absent"] {
                    assert!(
                        normalize(
                            &document,
                            &[RelationshipSelector::SourceId(id.into())],
                            edition,
                            &TransformExecutionBudget::default()
                        )
                        .is_err(),
                        "{edition:?}, {id}, {kind}"
                    );
                }
            }
        }
        for kind in [
            "urn:t",
            "https://example.com/type",
            "https://例え.example/役割",
            "urn:роль",
            "x+y.z-1:type",
            " urn:t ",
        ] {
            let xml = format!(
                "<Relationships xmlns=\"{REL}\"><Relationship Id=\"x\" Type=\"{kind}\" Target=\"a\"/></Relationships>"
            );
            let document = Document::parse(&xml).expect("well-formed relationship XML");
            for edition in [
                OpcRelationshipEdition::Ecma2012,
                OpcRelationshipEdition::Ecma2021,
            ] {
                let output = normalize(
                    &document,
                    &[RelationshipSelector::SourceId("x".into())],
                    edition,
                    &TransformExecutionBudget::default(),
                )
                .expect("absolute IRI is accepted");
                let expected = format!(
                    "<Relationships xmlns=\"{REL}\"><Relationship Id=\"x\" Target=\"a\" TargetMode=\"Internal\" Type=\"{kind}\"></Relationship></Relationships>"
                );
                assert_eq!(output, expected.as_bytes());
            }
        }
    }

    #[test]
    fn selector_simple_content_does_not_change_selection() {
        // Both selector schemas extend xsd:string; only their attribute
        // participates in selection, and nested elements remain invalid.
        for (name, attribute, value) in [
            ("RelationshipReference", "SourceId", "x"),
            ("RelationshipsGroupReference", "SourceType", "urn:t"),
        ] {
            for content in ["", "metadata &amp; <![CDATA[value]]>", "<child/>"] {
                let parameters = format!(
                    "<Transform><{name} xmlns=\"{PARAM}\" {attribute}=\"{value}\">{content}</{name}></Transform>"
                );
                let parameters = Document::parse(&parameters).expect("well-formed selector XML");
                let parsed =
                    parse_selectors(parameters.root_element(), &WorkspaceBudget::default());
                if content == "<child/>" {
                    assert!(parsed.is_err());
                    continue;
                }
                let parsed = parsed.expect("selector simple content is valid");
                let xml = format!(
                    "<Relationships xmlns=\"{REL}\"><Relationship Id=\"x\" Type=\"urn:t\" Target=\"a\"/></Relationships>"
                );
                let document = Document::parse(&xml).expect("well-formed relationship XML");
                for edition in [
                    OpcRelationshipEdition::Ecma2012,
                    OpcRelationshipEdition::Ecma2021,
                ] {
                    let output = normalize(
                        &document,
                        &parsed,
                        edition,
                        &TransformExecutionBudget::default(),
                    )
                    .expect("selector simple content is ignored");
                    let expected = format!(
                        "<Relationships xmlns=\"{REL}\"><Relationship Id=\"x\" Target=\"a\" TargetMode=\"Internal\" Type=\"urn:t\"></Relationship></Relationships>"
                    );
                    assert_eq!(output, expected.as_bytes());
                }
            }
        }
    }

    #[test]
    fn alternate_content_distinguishes_ignored_and_unwrapped_extensions() {
        // Part 3 §9.4(3a) allows ignored extension children, not unwrapped
        // ones. ProcessContent may be inherited or local and use a wildcard.
        for declaration in [
            "",
            "mc:ProcessContent=\"u:extension\"",
            "mc:ProcessContent=\"u:*\"",
        ] {
            for local in [false, true] {
                let (root_attributes, child_attributes) = if local {
                    ("", declaration)
                } else {
                    (declaration, "")
                };
                let xml = format!(
                    "<Relationships xmlns=\"{REL}\" xmlns:mc=\"{MC}\" xmlns:r=\"{REL}\" xmlns:u=\"urn:unknown\" mc:Ignorable=\"u\" {root_attributes}><mc:AlternateContent><u:extension {child_attributes}/><mc:Choice Requires=\"r\"><Relationship Id=\"x\" Type=\"urn:t\" Target=\"a\"/></mc:Choice></mc:AlternateContent></Relationships>"
                );
                let document = Document::parse(&xml).expect("well-formed MCE input");
                for edition in [
                    OpcRelationshipEdition::Ecma2012,
                    OpcRelationshipEdition::Ecma2021,
                ] {
                    let result = normalize(
                        &document,
                        &[RelationshipSelector::SourceId("x".into())],
                        edition,
                        &TransformExecutionBudget::default(),
                    );
                    assert_eq!(
                        result.is_ok(),
                        declaration.is_empty(),
                        "{edition:?}: {declaration}, local={local}"
                    );
                }
            }
        }
    }

    #[test]
    fn relationship_simple_content_is_removed_but_invalid_structure_is_rejected() {
        // CT_Relationship is xsd:string simple content in both editions.
        // Stripping it must not permit container text or child elements.
        for edition in [
            OpcRelationshipEdition::Ecma2012,
            OpcRelationshipEdition::Ecma2021,
        ] {
            for (content, accepted) in [
                (
                    "<Relationship Id=\"x\" Type=\"urn:t\" Target=\"a\">metadata &amp; <![CDATA[value]]></Relationship>",
                    true,
                ),
                (
                    "metadata<Relationship Id=\"x\" Type=\"urn:t\" Target=\"a\"/>",
                    false,
                ),
                (
                    "<Relationship Id=\"x\" Type=\"urn:t\" Target=\"a\"><child/></Relationship>",
                    false,
                ),
            ] {
                let xml = format!("<Relationships xmlns=\"{REL}\">{content}</Relationships>");
                let document = Document::parse(&xml).expect("well-formed XML");
                let result = normalize(
                    &document,
                    &[RelationshipSelector::SourceId("x".into())],
                    edition,
                    &TransformExecutionBudget::default(),
                );
                assert_eq!(result.is_ok(), accepted, "{edition:?}: {content}");
                if accepted {
                    let expected = format!(
                        "<Relationships xmlns=\"{REL}\"><Relationship Id=\"x\" Target=\"a\" TargetMode=\"Internal\" Type=\"urn:t\"></Relationship></Relationships>"
                    );
                    assert_eq!(
                        result.expect("simple content is valid"),
                        expected.as_bytes()
                    );
                }
            }
        }
    }

    #[test]
    fn selection_union_survives_nonmatching_selectors_on_either_side() {
        // A later nonmatch must never undo membership in the selector union.
        let xml = format!(
            "<Relationships xmlns=\"{REL}\"><Relationship Id=\"x\" Type=\"urn:t\" Target=\"a\"/></Relationships>"
        );
        let document = Document::parse(&xml).expect("valid relationship document");
        for edition in [
            OpcRelationshipEdition::Ecma2012,
            OpcRelationshipEdition::Ecma2021,
        ] {
            let output = normalize(
                &document,
                &[
                    RelationshipSelector::SourceId("absent".into()),
                    RelationshipSelector::SourceType("urn:t".into()),
                    RelationshipSelector::SourceId("other".into()),
                ],
                edition,
                &TransformExecutionBudget::default(),
            )
            .expect("selector union normalization succeeds");
            assert!(
                std::str::from_utf8(&output)
                    .expect("normalized relationships are UTF-8")
                    .contains("Id=\"x\"")
            );
        }
    }

    #[test]
    fn both_editions_require_inclusive_c14n_1_0() {
        // Both editions reject other canonicalization methods after OPC.
        for edition in [
            OpcRelationshipEdition::Ecma2012,
            OpcRelationshipEdition::Ecma2021,
        ] {
            for mode in [
                C14nMode::Inclusive1_0,
                C14nMode::Inclusive1_1,
                C14nMode::Exclusive1_0,
            ] {
                for comments in [false, true] {
                    let chain = [
                        Transform::Relationship(vec![RelationshipSelector::SourceId("x".into())]),
                        Transform::C14n(crate::c14n::C14nAlgorithm::new(mode, comments)),
                    ];
                    assert!(validate_chain(&chain).is_ok());
                    assert_eq!(
                        validate_edition(&chain, edition).is_ok(),
                        mode == C14nMode::Inclusive1_0
                    );
                }
            }
        }
    }

    #[test]
    fn schema_id_validation_collapses_whitespace_without_rewriting_xml() {
        // XSD ID has a collapse whitespace facet; validation is not a request
        // to rewrite the attribute in the transform's XML input infoset.
        let xml = format!(
            "<Relationships xmlns=\"{REL}\"><Relationship Id=\" x \" Type=\"urn:t\" Target=\"a\"/></Relationships>"
        );
        let document = Document::parse(&xml).expect("valid XML");
        let output = normalize(
            &document,
            &[RelationshipSelector::SourceId(" x ".into())],
            OpcRelationshipEdition::Ecma2021,
            &TransformExecutionBudget::default(),
        )
        .expect("schema-valid ID");
        assert!(
            std::str::from_utf8(&output)
                .expect("UTF-8")
                .contains("Id=\" x \"")
        );
        let duplicate = xml.replace(
            "</Relationships>",
            "<Relationship Id=\"x\" Type=\"urn:t\" Target=\"b\"/></Relationships>",
        );
        let document = Document::parse(&duplicate).expect("valid XML");
        assert!(
            normalize(
                &document,
                &[RelationshipSelector::SourceId("none".into())],
                OpcRelationshipEdition::Ecma2021,
                &TransformExecutionBudget::default()
            )
            .is_err()
        );
    }

    #[test]
    fn legacy_preparation_removes_edge_and_relationship_contents() {
        // 2012 step 3 removes container-edge data and all Relationship content,
        // but does not remove PIs between two retained relationships.
        let xml = format!(
            "<Relationships xmlns=\"{REL}\"><?edge a?><Relationship Id=\"a\" Type=\"urn:t\" Target=\"a\"><?child a?></Relationship><?middle a?><Relationship Id=\"b\" Type=\"urn:t\" Target=\"b\"/><?edge b?></Relationships>"
        );
        let document = Document::parse(&xml).expect("valid Relationships XML");
        let output = normalize(
            &document,
            &[RelationshipSelector::SourceType("urn:t".into())],
            OpcRelationshipEdition::Ecma2012,
            &TransformExecutionBudget::default(),
        )
        .expect("valid legacy normalization");
        let expected = format!(
            "<Relationships xmlns=\"{REL}\"><Relationship Id=\"a\" Target=\"a\" TargetMode=\"Internal\" Type=\"urn:t\"></Relationship><?middle a?><Relationship Id=\"b\" Target=\"b\" TargetMode=\"Internal\" Type=\"urn:t\"></Relationship></Relationships>"
        );
        assert_eq!(output, expected.as_bytes());
    }
}
