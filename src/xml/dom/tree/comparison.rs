//! One semantic comparator for native and current-query DOM construction.

use alloc::string::String;
use core::ops::Range;

use super::{
    AttributeData, Document, NamespaceData, NodeData, NodeKind, XML_NAMESPACE_URI,
    source_ranges_equivalent,
};
use crate::collections::{Map, Table};
use crate::xml::dom::{
    ParseError,
    storage::{Native, Storage},
};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct NamespaceKey<'a>(Option<&'a str>, &'a str);

pub(crate) trait ComparisonStorage: Storage {
    type Counts<'a>: Counts<'a, Self>;
    fn counts<'a>(&self, capacity: usize) -> Result<Self::Counts<'a>, ParseError>;
    fn divergence(reason: Self::Text) -> Self::ParseFailure;
}

pub(crate) trait Counts<'a, S: Storage> {
    fn increment(&mut self, key: NamespaceKey<'a>, storage: S) -> Result<(), ParseError>;
    fn take(&mut self, key: NamespaceKey<'a>, storage: S) -> Result<bool, ParseError>;
}

impl ComparisonStorage for Native {
    type Counts<'a> = Map<NamespaceKey<'a>, usize>;
    fn counts<'a>(&self, capacity: usize) -> Result<Self::Counts<'a>, ParseError> {
        let mut counts = Map::new();
        counts
            .try_reserve_entries(capacity)
            .map_err(|_| ParseError::AllocationFailed)?;
        Ok(counts)
    }
    fn divergence(reason: String) -> ParseError {
        ParseError::BackendDivergence { reason }
    }
}

impl<'a> Counts<'a, Native> for Map<NamespaceKey<'a>, usize> {
    fn increment(&mut self, key: NamespaceKey<'a>, _: Native) -> Result<(), ParseError> {
        // The complete input axis length was reserved at construction.
        *self.entry(key).or_insert(0) += 1;
        Ok(())
    }
    fn take(&mut self, key: NamespaceKey<'a>, _: Native) -> Result<bool, ParseError> {
        let Some(count) = self.get_mut(&key) else {
            return Ok(false);
        };
        if *count == 0 {
            return Ok(false);
        }
        *count -= 1;
        Ok(true)
    }
}

#[cfg(feature = "xmldsig")]
impl structured_asn1::memory::HashWork for NamespaceKey<'_> {
    fn hash_work(&self) -> Result<u64, structured_asn1::memory::MemoryError> {
        (self.0.map_or(0, str::len) as u64)
            .checked_add(self.1.len() as u64)
            .and_then(|bytes| bytes.checked_add(1))
            .ok_or(structured_asn1::memory::MemoryError::WorkExceeded)
    }
}

#[cfg(feature = "xmldsig")]
impl<W: structured_asn1::memory::Work> ComparisonStorage
    for crate::xml::dom::storage::Accounted<'_, W>
{
    type Counts<'a> = structured_asn1::memory::OwnedMap<NamespaceKey<'a>, usize, W>;
    fn counts<'a>(&self, _: usize) -> Result<Self::Counts<'a>, ParseError> {
        Ok(self.0.map())
    }
    fn divergence(reason: Self::Text) -> Self::ParseFailure {
        crate::xml::dom::AccountedParseError::Divergence(reason.into_owned())
    }
}

#[cfg(feature = "xmldsig")]
impl<'a, W: structured_asn1::memory::Work> Counts<'a, crate::xml::dom::storage::Accounted<'_, W>>
    for structured_asn1::memory::OwnedMap<NamespaceKey<'a>, usize, W>
{
    fn increment(
        &mut self,
        key: NamespaceKey<'a>,
        storage: crate::xml::dom::storage::Accounted<'_, W>,
    ) -> Result<(), ParseError> {
        if let Some(count) = self.get_mut(&key, storage.0)? {
            *count += 1;
        } else {
            self.try_insert(key, 1)?;
        }
        Ok(())
    }
    fn take(
        &mut self,
        key: NamespaceKey<'a>,
        storage: crate::xml::dom::storage::Accounted<'_, W>,
    ) -> Result<bool, ParseError> {
        let Some(count) = self.get_mut(&key, storage.0)? else {
            return Ok(false);
        };
        if *count == 0 {
            return Ok(false);
        }
        *count -= 1;
        Ok(true)
    }
}

impl<L: Storage> Document<'_, L> {
    pub(in crate::xml::dom) fn ensure_semantically_equivalent_in<
        R: Storage,
        S: ComparisonStorage,
    >(
        &self,
        other: &Document<'_, R>,
        doctype: Option<&Range<usize>>,
        storage: S,
    ) -> Result<(), S::ParseFailure> {
        if self.nodes.len() != other.nodes.len() {
            for (index, (left, right)) in self.nodes.iter().zip(other.nodes.iter()).enumerate() {
                storage.charge(1)?;
                if label(&left.kind) != label(&right.kind) {
                    let reason = storage.formatted(format_args!(
                        "retained semantic node counts differ ({} versus {}): node {index} is {} versus {}",
                        self.nodes.len(), other.nodes.len(), label(&left.kind), label(&right.kind)
                    ))?;
                    return Err(S::divergence(reason));
                }
            }
            return Err(S::divergence(storage.formatted(format_args!(
                "retained semantic node counts differ ({} versus {}): one adapter retained trailing nodes",
                self.nodes.len(), other.nodes.len()
            ))?));
        }
        for (index, (left, right)) in self.nodes.iter().zip(other.nodes.iter()).enumerate() {
            if let Some(field) = difference(left, right, doctype, storage)? {
                let reason = if field == "source range" {
                    storage.formatted(format_args!(
                        "retained semantic node {index} differs in source range ({}..{} versus {}..{})",
                        left.range.start, left.range.end, right.range.start, right.range.end
                    ))?
                } else {
                    storage.formatted(format_args!(
                        "retained semantic node {index} differs in {field}"
                    ))?
                };
                return Err(S::divergence(reason));
            }
        }
        Ok(())
    }
}

fn text_equal<S: Storage>(left: &str, right: &str, storage: S) -> Result<bool, ParseError> {
    if left.len() != right.len() {
        return Ok(false);
    }
    storage.charge(left.len())?;
    Ok(left == right)
}

fn optional_equal<S: Storage>(
    left: Option<&str>,
    right: Option<&str>,
    storage: S,
) -> Result<bool, ParseError> {
    match (left, right) {
        (Some(left), Some(right)) => text_equal(left, right, storage),
        (None, None) => Ok(true),
        _ => Ok(false),
    }
}

fn difference<L: Storage, R: Storage, S: ComparisonStorage>(
    left: &NodeData<L>,
    right: &NodeData<R>,
    doctype: Option<&Range<usize>>,
    storage: S,
) -> Result<Option<&'static str>, ParseError> {
    storage.charge(1)?;
    if left.parent != right.parent {
        return Ok(Some("parent identity"));
    }
    if left.children.len() != right.children.len() {
        return Ok(Some("child identities"));
    }
    storage.charge(left.children.len())?;
    if left.children[..] != right.children[..] {
        return Ok(Some("child identities"));
    }
    if let Some(field) = kind_difference(&left.kind, &right.kind, storage)? {
        return Ok(Some(field));
    }
    if !source_ranges_equivalent(&left.range, &right.range, doctype) {
        return Ok(Some("source range"));
    }
    // Unique source-span actionability participates in mutation security even
    // when every retained semantic value and identity otherwise agrees.
    if left.range_actionable != right.range_actionable {
        return Ok(Some("source-range actionability"));
    }
    if left.subtree_end != right.subtree_end {
        return Ok(Some("subtree boundary"));
    }
    Ok(None)
}

fn kind_difference<L: Storage, R: Storage, S: ComparisonStorage>(
    left: &NodeKind<L>,
    right: &NodeKind<R>,
    storage: S,
) -> Result<Option<&'static str>, ParseError> {
    match (left, right) {
        (NodeKind::Root, NodeKind::Root) => Ok(None),
        (NodeKind::Text(left), NodeKind::Text(right)) => Ok(if text_equal(left, right, storage)? {
            None
        } else {
            Some("character data")
        }),
        (NodeKind::Comment(left), NodeKind::Comment(right)) => {
            Ok(if text_equal(left, right, storage)? {
                None
            } else {
                Some("comment data")
            })
        }
        (
            NodeKind::PI {
                target: lt,
                value: lv,
            },
            NodeKind::PI {
                target: rt,
                value: rv,
            },
        ) => Ok(
            if text_equal(lt, rt, storage)?
                && optional_equal(lv.as_deref(), rv.as_deref(), storage)?
            {
                None
            } else {
                Some("processing instruction data")
            },
        ),
        (
            NodeKind::Element {
                name: ln,
                namespace: lns,
                prefix: lp,
                attributes: la,
                namespaces: lx,
            },
            NodeKind::Element {
                name: rn,
                namespace: rns,
                prefix: rp,
                attributes: ra,
                namespaces: rx,
            },
        ) => {
            if !text_equal(ln, rn, storage)? {
                return Ok(Some("element local name"));
            }
            if !optional_equal(lns.as_deref(), rns.as_deref(), storage)? {
                return Ok(Some(match (lns.as_deref(), rns.as_deref()) {
                    (None, Some("")) => "element namespace URI (absent versus empty)",
                    (Some(""), None) => "element namespace URI (empty versus absent)",
                    (None, Some(_)) => "element namespace URI (absent versus non-empty)",
                    (Some(_), None) => "element namespace URI (non-empty versus absent)",
                    _ => "element namespace URI (different non-empty values)",
                }));
            }
            if !optional_equal(lp.as_deref(), rp.as_deref(), storage)? {
                return Ok(Some("element prefix"));
            }
            if !attributes_equal(la, ra, storage)? {
                return Ok(Some("attribute axis"));
            }
            if !namespaces_equal(lx, rx, storage)? {
                return Ok(Some("namespace axis"));
            }
            Ok(None)
        }
        _ => Ok(Some("node kind")),
    }
}

fn attributes_equal<L: Storage, R: Storage, S: Storage>(
    left: &[AttributeData<L>],
    right: &[AttributeData<R>],
    storage: S,
) -> Result<bool, ParseError> {
    if left.len() != right.len() {
        return Ok(false);
    }
    for (left, right) in left.iter().zip(right) {
        storage.charge(1)?;
        if left.is_id != right.is_id
            || left.xml_id_error != right.xml_id_error
            || !text_equal(&left.name, &right.name, storage)?
            || !optional_equal(
                left.namespace.as_deref(),
                right.namespace.as_deref(),
                storage,
            )?
            || !optional_equal(left.prefix.as_deref(), right.prefix.as_deref(), storage)?
            || !text_equal(&left.value, &right.value, storage)?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) fn namespaces_equal<'a, L: Storage, R: Storage, S: ComparisonStorage>(
    left: &'a [NamespaceData<L>],
    right: &'a [NamespaceData<R>],
    storage: S,
) -> Result<bool, ParseError> {
    // Namespaces in XML 1.0 §3 predefines xml independently of an explicit
    // declaration; omit that redundant binding, but preserve all multiplicities.
    // https://www.w3.org/TR/2009/REC-xml-names-20091208/#ns-decl
    let mut counts = None;
    let mut remaining = 0;
    for item in left {
        storage.charge(1)?;
        if predefined_xml_binding(item, storage)? {
            continue;
        }
        let counts = match counts {
            Some(ref mut counts) => counts,
            None => counts.insert(storage.counts(left.len())?),
        };
        counts.increment(NamespaceKey(item.prefix.as_deref(), &item.uri), storage)?;
        remaining += 1;
    }
    for item in right {
        storage.charge(1)?;
        if predefined_xml_binding(item, storage)? {
            continue;
        }
        let Some(counts) = &mut counts else {
            return Ok(false);
        };
        if !counts.take(NamespaceKey(item.prefix.as_deref(), &item.uri), storage)? {
            return Ok(false);
        }
        debug_assert!(
            remaining != 0,
            "each taken entry was inserted on the left axis"
        );
        remaining -= 1;
    }
    Ok(remaining == 0)
}

fn predefined_xml_binding<D: Storage, S: Storage>(
    item: &NamespaceData<D>,
    storage: S,
) -> Result<bool, ParseError> {
    // Namespaces in XML 1.0 §3 fixes both prefix and namespace name. Ignoring
    // an xml prefix with another URI would hide a backend semantic divergence.
    // https://www.w3.org/TR/2009/REC-xml-names-20091208/#ns-decl
    if !optional_equal(item.prefix.as_deref(), Some("xml"), storage)? {
        return Ok(false);
    }
    text_equal(&item.uri, XML_NAMESPACE_URI, storage)
}

fn label<S: Storage>(kind: &NodeKind<S>) -> &'static str {
    match kind {
        NodeKind::Root => "root",
        NodeKind::Element { .. } => "element",
        NodeKind::Text(_) => "text",
        NodeKind::Comment(_) => "comment",
        NodeKind::PI { .. } => "processing instruction",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "xmldsig")]
    use crate::xml::dom::XmlBackend;

    #[test]
    fn namespace_axis_comparison_preserves_multiplicity_and_optional_prefixes() {
        // Axis order and redundant xml declarations may vary, but duplication
        // and absent-versus-empty prefixes must not be silently erased.
        let namespace = |prefix: Option<&str>, uri: &str| NamespaceData::<Native> {
            prefix: prefix.map(str::to_owned),
            uri: uri.to_owned(),
        };
        let left = [namespace(None, "default"), namespace(Some("p"), "named")];
        let reordered = [
            namespace(Some("xml"), "http://www.w3.org/XML/1998/namespace"),
            namespace(Some("p"), "named"),
            namespace(None, "default"),
        ];
        assert!(namespaces_equal(&left, &reordered, Native).expect("native axis comparison"));
        let duplicated = [
            namespace(None, "default"),
            namespace(Some("p"), "named"),
            namespace(Some("p"), "named"),
        ];
        assert!(!namespaces_equal(&left, &duplicated, Native).expect("duplicate on right"));
        assert!(!namespaces_equal(&duplicated, &left, Native).expect("duplicate on left"));
        let empty_prefix = [
            namespace(Some(""), "default"),
            namespace(Some("p"), "named"),
        ];
        assert!(
            !namespaces_equal(&left, &empty_prefix, Native).expect("optional prefix comparison")
        );

        // Only the predefined URI is redundant. A backend supplying another
        // URI for xml must not disappear from fail-closed comparison.
        let no_bindings: [NamespaceData<Native>; 0] = [];
        let wrong_xml = [namespace(Some("xml"), "urn:not-the-xml-namespace")];
        assert!(
            !namespaces_equal(&no_bindings, &wrong_xml, Native)
                .expect("wrong xml binding on right")
        );
        assert!(
            !namespaces_equal(&wrong_xml, &no_bindings, Native).expect("wrong xml binding on left")
        );
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn comparator_uses_current_work_and_retains_only_completed_error_storage() {
        use crate::xml::dom::{AccountedParseError, storage::Accounted};
        use structured_asn1::{
            Encoding, Limits, Parser,
            memory::{Memory, MemoryAccount, MemoryError},
        };

        // Neither retained native DOM storage nor aggregate room pays a new
        // query's comparison, namespace probes, or diagnostic construction.
        let source = "<r xmlns:p='urn:p' p:a='value'>aa</r>";
        let left = Document::parse_with_backend(source, XmlBackend::Roxmltree)
            .expect("roxmltree baseline");
        let right =
            Document::parse_with_backend(source, XmlBackend::Xmloxide).expect("xmloxide baseline");
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
        assert!(matches!(
            left.ensure_semantically_equivalent_in(&right, None, Accounted(&work)),
            Err(AccountedParseError::Semantic(ParseError::SharedExecution(
                MemoryError::WorkExceeded
            )))
        ));
        assert_eq!(memory.used(), 0);
        assert_eq!(memory.work_used(), 0);
        left.ensure_semantically_equivalent_in(&right, None, Accounted(&memory))
            .expect("ample comparison budget");
        assert_eq!(
            memory.used(),
            0,
            "comparison scratch is released on success"
        );

        let denied = Memory::new(std::sync::Arc::new(MemoryAccount::new(0, 1 << 24)));
        assert!(matches!(
            left.ensure_semantically_equivalent_in(&right, None, Accounted(&denied)),
            Err(AccountedParseError::Semantic(ParseError::SharedExecution(
                MemoryError::LimitExceeded
            )))
        ));
        assert_eq!(denied.used(), 0);

        let different = Document::parse_with_backend(
            "<r xmlns:p='urn:p' p:a='value'>bb</r>",
            XmlBackend::Xmloxide,
        )
        .expect("different fixed XML parses");
        let error = left
            .ensure_semantically_equivalent_in(&different, None, Accounted(&memory))
            .expect_err("character-data divergence");
        assert!(
            matches!(&error, AccountedParseError::Divergence(reason) if reason.contains("character data"))
        );
        assert!(
            memory.used() > 0,
            "the surviving diagnostic retains its real allocation"
        );
        drop(error);
        assert_eq!(memory.used(), 0);
        assert!(matches!(
            left.ensure_semantically_equivalent_in(&different, None, Accounted(&denied)),
            Err(AccountedParseError::Semantic(ParseError::SharedExecution(
                MemoryError::LimitExceeded
            )))
        ));
        assert_eq!(denied.used(), 0);
    }
}
