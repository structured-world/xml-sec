//! Storage-specialized projection of the original XML `XPath` node identities.
//!
//! A whole document or rooted subtree, minus any excluded subtrees, remains a
//! range of the contiguous preorder arena and stores no per-node entries.
//! Arbitrary selections are explicit sets over the document-order `XPath` index:
//! a sorted index vector while sparse, a bitset once dense.

use super::{NodeSetMaterializationBudget, TransformError, charge_resource_bytes};
use crate::c14n::scratch::{List as _, Scratch as _};
use crate::c14n::{C14nError, NodeVisibility};
use crate::collections::Key;
use crate::xml::dom::storage::{Native as NativeDom, Storage as DomStorage};
use crate::xml::dom::{Document, Node, NodeId};
use core::ops::Range;
use structured_asn1::memory::{HashWork, MemoryError, Work};

/// Sets with at least `1 / DENSE_DIVISOR` of the document's `XPath` nodes use the
/// bitset. Measured with the `node_set_*` benchmarks (16K elements, inclusive
/// C14N, medians of three runs): at 1/37 density the vector matches the bitset's
/// peak memory but costs 48% more time; at 1/149 it costs 5% more with half the
/// memory.
const DENSE_DIVISOR: usize = 128;
/// Out-of-order inserts below this length shift the sparse tail in place.
const SPARSE_SHIFT_LIMIT: usize = 64;

fn name_work(parts: &[&str]) -> Result<usize, MemoryError> {
    let mut work = 1_usize;
    for part in parts {
        work = work
            .checked_add(part.len())
            .ok_or(MemoryError::WorkExceeded)?;
    }
    Ok(work)
}

/// Comparisons of one binary search over `len` ordered values, plus the probe.
fn search_work(len: usize) -> usize {
    (usize::BITS - len.leading_zeros()) as usize + 1
}

fn prefers_dense(entries: usize, universe: u32) -> bool {
    entries >= (universe as usize).div_ceil(DENSE_DIVISOR)
}

pub(super) struct Materialization {
    pub(super) entries: usize,
    pub(super) owned_string_bytes: usize,
}

pub(super) fn measure<D: DomStorage>(
    root: Node<'_, '_, D>,
    with_comments: bool,
    max_entries: usize,
    max_string_bytes: usize,
    keys: &impl Keys,
) -> Result<Materialization, TransformError> {
    let descendants = root.descendants().len();
    keys.charge(descendants).map_err(C14nError::from)?;
    let mut measured = Materialization {
        entries: 0,
        owned_string_bytes: 0,
    };
    for node in root.descendants() {
        if node.is_comment() && !with_comments {
            continue;
        }
        let axes = node
            .attributes()
            .len()
            .checked_add(node.namespaces().len())
            .ok_or(MemoryError::WorkExceeded)
            .map_err(C14nError::from)?;
        keys.charge(axes).map_err(C14nError::from)?;
        for attribute in node.attributes() {
            measured.owned_string_bytes = charge_resource_bytes(
                measured.owned_string_bytes,
                attribute.namespace().map_or(0, str::len),
                max_string_bytes,
                crate::policy::resource_name::NODE_SET_OWNED_STRING_BYTES,
            )?;
            measured.owned_string_bytes = charge_resource_bytes(
                measured.owned_string_bytes,
                attribute.name().len(),
                max_string_bytes,
                crate::policy::resource_name::NODE_SET_OWNED_STRING_BYTES,
            )?;
        }
        for namespace in node.namespaces() {
            measured.owned_string_bytes = charge_resource_bytes(
                measured.owned_string_bytes,
                namespace.name().map_or(0, str::len),
                max_string_bytes,
                crate::policy::resource_name::NODE_SET_OWNED_STRING_BYTES,
            )?;
            measured.owned_string_bytes = charge_resource_bytes(
                measured.owned_string_bytes,
                namespace.uri().len(),
                max_string_bytes,
                crate::policy::resource_name::NODE_SET_OWNED_STRING_BYTES,
            )?;
        }
        measured.entries = charge_resource_bytes(
            measured.entries,
            axes.checked_add(1)
                .ok_or(MemoryError::WorkExceeded)
                .map_err(C14nError::from)?,
            max_entries,
            crate::policy::resource_name::NODE_SET_ENTRIES,
        )?;
    }
    Ok(measured)
}

/// Name bytes a materialized key for this `XPath` node would have owned.
fn node_bytes<D: DomStorage>(owner: Node<'_, '_, D>, offset: u32) -> Result<usize, MemoryError> {
    let Some(axis) = (offset as usize).checked_sub(1) else {
        return Ok(0);
    };
    let attributes = owner.attributes().len();
    let bytes = match owner.attributes().nth(axis) {
        Some(attribute) => attribute
            .name()
            .len()
            .checked_add(attribute.namespace().map_or(0, str::len)),
        None => owner
            .namespaces()
            .nth(axis - attributes)
            .and_then(|namespace| {
                namespace
                    .uri()
                    .len()
                    .checked_add(namespace.name().map_or(0, str::len))
            }),
    };
    bytes.ok_or(MemoryError::WorkExceeded)
}

/// Name bytes of every `XPath` node owned by `node`.
fn owned_bytes<D: DomStorage>(node: Node<'_, '_, D>) -> Result<usize, MemoryError> {
    let mut bytes = 0_usize;
    for attribute in node.attributes() {
        bytes = bytes
            .checked_add(attribute.name().len())
            .and_then(|bytes| bytes.checked_add(attribute.namespace().map_or(0, str::len)))
            .ok_or(MemoryError::WorkExceeded)?;
    }
    for namespace in node.namespaces() {
        bytes = bytes
            .checked_add(namespace.uri().len())
            .and_then(|bytes| bytes.checked_add(namespace.name().map_or(0, str::len)))
            .ok_or(MemoryError::WorkExceeded)?;
    }
    Ok(bytes)
}

/// Narrow a count or offset inside the document arena, which admits every
/// node, attribute and namespace into one bounded `u32` index space.
fn arena_index(value: usize) -> u32 {
    u32::try_from(value).expect("the document arena indexes within u32")
}

/// Every `XPath` node owned by `node`: itself, then its attributes and namespaces.
fn owned_indexes<D: DomStorage>(node: Node<'_, '_, D>) -> Range<u32> {
    let start = node.xpath_index();
    let axes = arena_index(node.attributes().len() + node.namespaces().len());
    start..start + 1 + axes
}

fn subtree_ids<D: DomStorage>(node: Node<'_, '_, D>) -> Range<u32> {
    node.id().get()..node.id().get() + arena_index(node.descendants().len())
}

pub(crate) trait Keys {
    type Execution: Copy;
    type Scratch: crate::c14n::scratch::Scratch + crate::xmldsig::xpath::XPathStorage;
    type Bindings<'source>: super::super::xpath::storage::Bindings<'source, Self::Execution>;
    fn bindings<'source>(execution: Self::Execution) -> Self::Bindings<'source>;
    fn scratch(execution: Self::Execution) -> Self::Scratch;
    type Index<T: HashWork + Key, V>: super::super::xpath::storage::Index<T, V, Self::Execution>;
    fn index<T: HashWork + Key, V>(execution: Self::Execution) -> Self::Index<T, V>;
    type NamespaceIndex<'source>: super::super::xpath::storage::NamespaceIndex<'source, Self::Execution>;
    fn namespace_index<'source>(execution: Self::Execution) -> Self::NamespaceIndex<'source>;
    fn execution(&self) -> Self::Execution;
    fn empty_like(&self) -> Self;
    fn admit(execution: Self::Execution, units: usize) -> Result<(), MemoryError>;
    fn charge(&self, units: usize) -> Result<(), MemoryError> {
        Self::admit(self.execution(), units)
    }
}

type Values<K, T> = <<K as Keys>::Scratch as crate::c14n::scratch::Scratch>::Values<T>;

#[derive(Default)]
pub(crate) struct NativeKeys;
impl Keys for NativeKeys {
    type Execution = ();
    type Scratch = crate::c14n::scratch::Native;
    type Bindings<'source> = super::super::xpath::storage::NativeIndex<
        super::super::xpath::storage::Prefix<'source>,
        &'source str,
    >;
    fn bindings<'source>((): ()) -> Self::Bindings<'source> {
        super::super::xpath::storage::NativeIndex::new()
    }
    fn scratch((): ()) -> Self::Scratch {
        crate::c14n::scratch::Native
    }
    type NamespaceIndex<'source> = super::super::xpath::storage::NativeIndex<
        super::super::xpath::storage::NamespaceKey<'source>,
        usize,
    >;
    fn namespace_index<'source>((): ()) -> Self::NamespaceIndex<'source> {
        super::super::xpath::storage::NativeIndex::new()
    }
    type Index<T: HashWork + Key, V> = super::super::xpath::storage::NativeIndex<T, V>;
    fn index<T: HashWork + Key, V>((): ()) -> Self::Index<T, V> {
        super::super::xpath::storage::NativeIndex::new()
    }
    fn execution(&self) {}
    fn empty_like(&self) -> Self {
        Self
    }
    fn admit((): (), _: usize) -> Result<(), MemoryError> {
        Ok(())
    }
}

pub(crate) struct PaidKeys<'w, W: Work> {
    work: &'w W,
}
impl<'w, W: Work> PaidKeys<'w, W> {
    pub(crate) fn new(work: &'w W) -> Self {
        Self { work }
    }
}
impl<'w, W: Work> Keys for PaidKeys<'w, W> {
    type Execution = &'w W;
    type Scratch = crate::c14n::scratch::Accounted<'w, W>;
    type Bindings<'source> = structured_asn1::memory::OwnedMap<
        super::super::xpath::storage::Prefix<'source>,
        &'source str,
        W,
    >;
    fn bindings<'source>(execution: &'w W) -> Self::Bindings<'source> {
        execution.map()
    }
    fn scratch(execution: &'w W) -> Self::Scratch {
        crate::c14n::scratch::Accounted(execution)
    }
    type NamespaceIndex<'source> = structured_asn1::memory::OwnedMap<
        super::super::xpath::storage::NamespaceKey<'source>,
        usize,
        W,
    >;
    fn namespace_index<'source>(execution: &'w W) -> Self::NamespaceIndex<'source> {
        execution.map()
    }
    type Index<T: HashWork + Key, V> = structured_asn1::memory::OwnedMap<T, V, W>;
    fn index<T: HashWork + Key, V>(execution: &'w W) -> Self::Index<T, V> {
        execution.map()
    }
    fn execution(&self) -> &'w W {
        self.work
    }
    fn empty_like(&self) -> Self {
        Self { work: self.work }
    }
    fn admit(work: &'w W, units: usize) -> Result<(), MemoryError> {
        work.charge_work(u64::try_from(units).map_err(|_| MemoryError::WorkExceeded)?)
    }
}

/// `XPath` axis of one node owned by a tree node.
#[derive(Clone, Copy)]
enum Axis {
    Tree,
    Attribute(usize),
    Namespace(usize),
}

enum Members<K: Keys> {
    /// Every `XPath` node owned by an arena node in `nodes`, except the owners in
    /// `excluded` (sorted, disjoint whole subtrees) and, without `comments`,
    /// comment nodes.
    Subtree {
        nodes: Range<u32>,
        excluded: Values<K, Range<u32>>,
        comments: bool,
    },
    Sparse(SparseIndexes<K>),
    /// One bit per document-order `XPath` index.
    Dense(Values<K, u64>),
}

/// Sorted document-order `XPath` indexes with one summary bit per 64-index
/// block. C14N queries every document node, so a miss in an unoccupied block
/// must not cost a binary search.
struct SparseIndexes<K: Keys> {
    indexes: Values<K, u32>,
    /// Allocated with the first member.
    blocks: Values<K, u64>,
}

impl<K: Keys> SparseIndexes<K> {
    fn new(scratch: &K::Scratch) -> Self {
        Self {
            indexes: scratch.values(),
            blocks: scratch.values(),
        }
    }
    fn contains(&self, index: u32, execution: K::Execution) -> Result<bool, MemoryError> {
        K::admit(execution, 1)?;
        if !bit(&self.blocks, index / 64) {
            return Ok(false);
        }
        K::admit(execution, search_work(self.indexes.len()))?;
        Ok(self.indexes.binary_search(&index).is_ok())
    }
    /// Record an index added to `indexes` in a document of `universe` indexes.
    fn mark(
        &mut self,
        index: u32,
        universe: u32,
        execution: K::Execution,
    ) -> Result<(), TransformError> {
        if self.blocks.is_empty() {
            let words = (universe as usize).div_ceil(64 * 64);
            K::admit(execution, words).map_err(C14nError::from)?;
            self.blocks.reserve_exact(words)?;
            for _ in 0..words {
                self.blocks.push(0)?;
            }
        }
        set_bit(&mut self.blocks, index / 64);
        Ok(())
    }
    /// Recompute the summary after members were removed.
    fn summarize(&mut self, execution: K::Execution) -> Result<(), MemoryError> {
        K::admit(execution, self.blocks.len() + self.indexes.len())?;
        self.blocks.fill(0);
        for &index in self.indexes.iter() {
            set_bit(&mut self.blocks, index / 64);
        }
        Ok(())
    }
}

pub(crate) struct Projection<'a, K: Keys, D: DomStorage = NativeDom> {
    document: &'a Document<'a, D>,
    keys: K,
    members: Members<K>,
    entries: usize,
    projected_string_bytes: usize,
    with_comments: bool,
    failure: Option<MemoryError>,
    /// Ordered growth keeps the representation chosen by `pin_representation`.
    #[cfg(feature = "benchmark-internals")]
    pinned: bool,
}

#[cfg(test)]
impl<'a, 'w, W: Work, D: DomStorage> Projection<'a, PaidKeys<'w, W>, D> {
    pub(crate) fn accounted_subtree(
        root: Node<'a, 'a, D>,
        with_comments: bool,
        budget: &NodeSetMaterializationBudget,
        work: &'w W,
    ) -> Result<Self, TransformError> {
        Self::subtree(root, with_comments, budget, PaidKeys::new(work))
    }
}

impl<'a, K: Keys, D: DomStorage> Projection<'a, K, D> {
    pub(crate) fn subtree(
        root: Node<'a, 'a, D>,
        with_comments: bool,
        budget: &NodeSetMaterializationBudget,
        keys: K,
    ) -> Result<Self, TransformError> {
        let measured = measure(
            root,
            with_comments,
            budget.max_entries,
            budget.max_owned_string_bytes,
            &keys,
        )?;
        budget.charge(measured.owned_string_bytes)?;
        let excluded = K::scratch(keys.execution()).values();
        Ok(Self {
            document: root.document(),
            keys,
            members: Members::Subtree {
                nodes: subtree_ids(root),
                excluded,
                comments: with_comments,
            },
            entries: measured.entries,
            projected_string_bytes: measured.owned_string_bytes,
            with_comments,
            failure: None,
            #[cfg(feature = "benchmark-internals")]
            pinned: false,
        })
    }

    pub(crate) fn empty(document: &'a Document<'a, D>, keys: K) -> Self {
        let members = Members::Sparse(SparseIndexes::new(&K::scratch(keys.execution())));
        Self {
            document,
            keys,
            members,
            entries: 0,
            projected_string_bytes: 0,
            with_comments: false,
            failure: None,
            #[cfg(feature = "benchmark-internals")]
            pinned: false,
        }
    }

    fn owns(&self, node: Node<'_, '_, D>) -> bool {
        core::ptr::eq(self.document, node.document())
    }
    fn available(&self) -> Result<(), C14nError> {
        match self.failure {
            Some(error) => Err(error.into()),
            None => Ok(()),
        }
    }
    /// A mutation refused part-way leaves no successful subset observable.
    fn sticky<T>(&mut self, result: Result<T, TransformError>) -> Result<T, TransformError> {
        if let Err(TransformError::C14n(C14nError::SharedExecution(error))) = &result {
            self.failure = Some(*error);
        }
        result
    }
    fn values<T>(&self) -> Values<K, T> {
        K::scratch(self.keys.execution()).values()
    }
    fn no_members(&self) -> Members<K> {
        Members::Sparse(SparseIndexes::new(&K::scratch(self.keys.execution())))
    }
    fn universe(&self) -> u32 {
        self.document.xpath_node_count()
    }

    pub(crate) fn len(&self) -> usize {
        self.entries
    }
    /// Grow this empty set as a bitset or a sorted vector regardless of density,
    /// so both representations are measured without conversions.
    #[cfg(feature = "benchmark-internals")]
    pub(crate) fn pin_representation(&mut self, dense: bool) -> Result<(), TransformError> {
        assert_eq!(self.entries, 0, "only an empty set is pinned");
        if dense {
            self.members = Members::Dense(self.dense_words()?);
        }
        self.pinned = true;
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn representation(&self) -> &'static str {
        match self.members {
            Members::Subtree { .. } => "subtree",
            Members::Sparse(_) => "sparse",
            Members::Dense(_) => "dense",
        }
    }
    pub(crate) fn admit_walk(&self, nodes: usize) -> Result<(), C14nError> {
        self.available()?;
        self.keys.charge(nodes).map_err(C14nError::from)
    }
    pub(crate) fn execution(&self) -> K::Execution {
        self.keys.execution()
    }
    pub(crate) fn document(&self) -> &'a Document<'a, D> {
        self.document
    }
    pub(crate) fn with_comments(&self) -> bool {
        self.with_comments
    }
    pub(crate) fn empty_like(&self) -> Self {
        Self::empty(self.document, self.keys.empty_like())
    }
    pub(crate) fn entire_document_like(
        &self,
        budget: &NodeSetMaterializationBudget,
    ) -> Result<Self, TransformError> {
        Self::subtree(self.document.root(), true, budget, self.keys.empty_like())
    }
    pub(crate) fn measure_document(
        &self,
        budget: &NodeSetMaterializationBudget,
    ) -> Result<usize, TransformError> {
        measure(
            self.document.root(),
            true,
            budget.max_entries,
            budget.max_owned_string_bytes,
            &self.keys,
        )
        .map(|measured| measured.entries)
    }

    fn index(node: Node<'_, '_, D>, axis: Axis) -> Option<u32> {
        let start = node.xpath_index();
        // Ordinals are bounded by the owner's axes, which share the u32 index space.
        let offset = match axis {
            Axis::Tree => return Some(start),
            Axis::Attribute(ordinal) if ordinal < node.attributes().len() => ordinal,
            Axis::Namespace(ordinal) if ordinal < node.namespaces().len() => {
                node.attributes().len() + ordinal
            }
            Axis::Attribute(_) | Axis::Namespace(_) => return None,
        };
        Some(start + 1 + arena_index(offset))
    }

    /// Owner arena node and name bytes of one document-order `XPath` index.
    fn resolve(
        &self,
        index: u32,
        execution: K::Execution,
    ) -> Result<(Node<'a, 'a, D>, usize), MemoryError> {
        K::admit(execution, search_work(self.document.node_count()))?;
        let owner = self
            .document
            .xpath_owner(index)
            .expect("projected indexes belong to their document");
        Ok((owner, node_bytes(owner, index - owner.xpath_index())?))
    }

    fn semantic_contains(
        nodes: &Range<u32>,
        excluded: &[Range<u32>],
        comments: bool,
        node: Node<'_, '_, D>,
        tree: bool,
    ) -> bool {
        let id = node.id().get();
        if !nodes.contains(&id) || (tree && !comments && node.is_comment()) {
            return false;
        }
        let after = excluded.partition_point(|range| range.start <= id);
        after == 0 || !excluded[after - 1].contains(&id)
    }

    fn contains(&self, node: Node<'_, '_, D>, axis: Axis) -> Result<bool, C14nError> {
        self.available()?;
        if !self.owns(node) {
            return Ok(false);
        }
        let Some(index) = Self::index(node, axis) else {
            return Ok(false);
        };
        match &self.members {
            Members::Subtree {
                nodes,
                excluded,
                comments,
            } => {
                self.keys.charge(search_work(excluded.len()))?;
                Ok(Self::semantic_contains(
                    nodes,
                    excluded,
                    *comments,
                    node,
                    matches!(axis, Axis::Tree),
                ))
            }
            Members::Sparse(indexes) => Ok(indexes.contains(index, self.keys.execution())?),
            Members::Dense(words) => {
                self.keys.charge(1)?;
                Ok(bit(words, index))
            }
        }
    }

    /// Membership of a document index, paid by the querying `execution`.
    fn contains_index(&self, index: u32, execution: K::Execution) -> Result<bool, MemoryError> {
        match &self.members {
            Members::Subtree {
                nodes,
                excluded,
                comments,
            } => {
                let (owner, _) = self.resolve(index, execution)?;
                K::admit(execution, search_work(excluded.len()))?;
                Ok(Self::semantic_contains(
                    nodes,
                    excluded,
                    *comments,
                    owner,
                    index == owner.xpath_index(),
                ))
            }
            Members::Sparse(indexes) => indexes.contains(index, execution),
            Members::Dense(words) => {
                K::admit(execution, 1)?;
                Ok(bit(words, index))
            }
        }
    }

    /// Visit member indexes in increasing order, paid by the querying `execution`
    /// per emitted index and per stored unit scanned.
    fn for_each_index(
        &self,
        execution: K::Execution,
        mut visit: impl FnMut(u32) -> Result<(), TransformError>,
    ) -> Result<(), TransformError> {
        match &self.members {
            Members::Subtree {
                nodes,
                excluded,
                comments,
            } => {
                let mut id = nodes.start;
                let mut next_excluded = 0;
                while id < nodes.end {
                    if let Some(range) = excluded.get(next_excluded)
                        && range.start == id
                    {
                        K::admit(execution, 1).map_err(C14nError::from)?;
                        id = range.end;
                        next_excluded += 1;
                        continue;
                    }
                    let node = self
                        .document
                        .get_node(NodeId::from(id))
                        .expect("subtree IDs belong to their document");
                    id += 1;
                    if node.is_comment() && !comments {
                        K::admit(execution, 1).map_err(C14nError::from)?;
                        continue;
                    }
                    let indexes = owned_indexes(node);
                    // One unit for the visit and one per emitted index.
                    K::admit(execution, 1 + indexes.len()).map_err(C14nError::from)?;
                    for index in indexes {
                        visit(index)?;
                    }
                }
                Ok(())
            }
            Members::Sparse(sparse) => {
                K::admit(execution, sparse.indexes.len()).map_err(C14nError::from)?;
                for &index in sparse.indexes.iter() {
                    visit(index)?;
                }
                Ok(())
            }
            Members::Dense(words) => {
                for (position, &word) in words.iter().enumerate() {
                    K::admit(execution, 1 + word.count_ones() as usize).map_err(C14nError::from)?;
                    // The bitset covers the u32 document index space.
                    let base = arena_index(position * 64);
                    let mut bits = word;
                    while bits != 0 {
                        visit(base + bits.trailing_zeros())?;
                        bits &= bits - 1;
                    }
                }
                Ok(())
            }
        }
    }

    fn dense_words(&self) -> Result<Values<K, u64>, TransformError> {
        let length = (self.universe() as usize).div_ceil(64);
        self.keys.charge(length).map_err(C14nError::from)?;
        let mut words = self.values();
        words.reserve_exact(length)?;
        for _ in 0..length {
            words.push(0)?;
        }
        Ok(words)
    }

    /// Store the current members explicitly, choosing the representation by density.
    fn materialize(&mut self) -> Result<(), TransformError> {
        let dense = prefers_dense(self.entries, self.universe());
        let execution = self.keys.execution();
        let members = match (&self.members, dense) {
            (Members::Subtree { .. } | Members::Sparse(_), true) => {
                let mut words = self.dense_words()?;
                self.for_each_index(execution, |index| {
                    set_bit(&mut words, index);
                    Ok(())
                })?;
                Members::Dense(words)
            }
            (Members::Subtree { .. } | Members::Dense(_), false) => {
                Members::Sparse(self.sparse_copy()?)
            }
            (Members::Sparse(_), false) | (Members::Dense(_), true) => return Ok(()),
        };
        self.members = members;
        Ok(())
    }

    fn sparse_copy(&self) -> Result<SparseIndexes<K>, TransformError> {
        let execution = self.keys.execution();
        let universe = self.universe();
        let mut sparse = SparseIndexes::<K>::new(&K::scratch(execution));
        sparse.indexes.reserve_exact(self.entries)?;
        self.for_each_index(execution, |index| {
            K::admit(execution, 1).map_err(C14nError::from)?;
            sparse.indexes.push(index)?;
            sparse.mark(index, universe, execution)
        })?;
        Ok(sparse)
    }

    /// Explicit members in the representation their density selects.
    fn compact(&mut self) -> Result<(), TransformError> {
        let result = match &self.members {
            Members::Subtree { .. } => Ok(()),
            _ => self.materialize(),
        };
        self.sticky(result)
    }

    fn insert(
        &mut self,
        index: u32,
        bytes: usize,
        budget: Option<&NodeSetMaterializationBudget>,
    ) -> Result<(), TransformError> {
        self.available()?;
        if self
            .contains_index(index, self.keys.execution())
            .map_err(C14nError::from)?
        {
            return Ok(());
        }
        if matches!(self.members, Members::Subtree { .. }) {
            let result = self.materialize();
            self.sticky(result)?;
        }
        let strings = match budget {
            Some(budget) => {
                charge_resource_bytes(
                    self.entries,
                    1,
                    budget.max_entries,
                    crate::policy::resource_name::NODE_SET_ENTRIES,
                )?;
                let strings = charge_resource_bytes(
                    self.projected_string_bytes,
                    bytes,
                    budget.max_owned_string_bytes,
                    crate::policy::resource_name::NODE_SET_OWNED_STRING_BYTES,
                )?;
                // Preserve the original compiled projection allowance. Source names
                // remain borrowed; actual index capacity is separately allocator-paid.
                budget.charge(bytes)?;
                strings
            }
            None => self
                .projected_string_bytes
                .checked_add(bytes)
                .ok_or(MemoryError::WorkExceeded)
                .map_err(C14nError::from)?,
        };
        let result = self.add_absent(index);
        self.sticky(result)?;
        self.projected_string_bytes = strings;
        Ok(())
    }

    fn add_absent(&mut self, index: u32) -> Result<(), TransformError> {
        let entries = self.entries + 1;
        let universe = self.universe();
        let execution = self.keys.execution();
        let promote = match &mut self.members {
            Members::Sparse(sparse) => {
                let indexes = &mut sparse.indexes;
                if indexes.last().is_none_or(|last| *last < index) {
                    indexes.push(index)?;
                    sparse.mark(index, universe, execution)?;
                    #[cfg(feature = "benchmark-internals")]
                    if self.pinned {
                        self.entries = entries;
                        return Ok(());
                    }
                    prefers_dense(entries, universe)
                } else if indexes.len() < SPARSE_SHIFT_LIMIT {
                    let position = indexes.partition_point(|value| *value < index);
                    K::admit(execution, indexes.len() - position).map_err(C14nError::from)?;
                    indexes.push(index)?;
                    indexes[position..].rotate_right(1);
                    sparse.mark(index, universe, execution)?;
                    false
                } else {
                    // Unordered growth would shift the tail per insert.
                    true
                }
            }
            Members::Dense(words) => {
                set_bit(words, index);
                false
            }
            Members::Subtree { .. } => unreachable!("insertion materializes semantic members"),
        };
        if promote {
            let mut words = self.dense_words()?;
            self.for_each_index(self.keys.execution(), |index| {
                set_bit(&mut words, index);
                Ok(())
            })?;
            set_bit(&mut words, index);
            self.members = Members::Dense(words);
        }
        self.entries = entries;
        Ok(())
    }

    /// Keep only members accepted by `keep`, releasing their name bytes.
    fn filter(
        &mut self,
        mut keep: impl FnMut(u32) -> Result<bool, MemoryError>,
    ) -> Result<(), TransformError> {
        let document = self.document;
        let keys = &self.keys;
        let mut entries = self.entries;
        let mut bytes = self.projected_string_bytes;
        let mut drop_index = |index: u32| -> Result<(), MemoryError> {
            keys.charge(search_work(document.node_count()))?;
            let owner = document
                .xpath_owner(index)
                .expect("projected indexes belong to their document");
            entries -= 1;
            bytes -= node_bytes(owner, index - owner.xpath_index())?;
            Ok(())
        };
        match &mut self.members {
            Members::Sparse(sparse) => {
                let indexes = &mut sparse.indexes;
                // One unit per examined member; removals pay their lookup too.
                keys.charge(indexes.len())?;
                let mut kept = 0;
                for position in 0..indexes.len() {
                    let index = indexes[position];
                    if keep(index)? {
                        indexes[kept] = index;
                        kept += 1;
                    } else {
                        drop_index(index)?;
                    }
                }
                if indexes.len() > kept {
                    while indexes.len() > kept {
                        indexes.pop();
                    }
                    sparse.summarize(keys.execution())?;
                }
            }
            Members::Dense(words) => {
                for position in 0..words.len() {
                    // The word scan and each member it holds.
                    keys.charge(1 + words[position].count_ones() as usize)?;
                    let base = arena_index(position * 64);
                    let mut bits = words[position];
                    while bits != 0 {
                        let offset = bits.trailing_zeros();
                        bits &= bits - 1;
                        let index = base + offset;
                        if !keep(index)? {
                            words[position] &= !(1 << offset);
                            drop_index(index)?;
                        }
                    }
                }
            }
            Members::Subtree { .. } => unreachable!("filtering materializes semantic members"),
        }
        self.entries = entries;
        self.projected_string_bytes = bytes;
        Ok(())
    }

    pub(crate) fn insert_tree(
        &mut self,
        node: Node<'_, '_, D>,
        budget: Option<&NodeSetMaterializationBudget>,
    ) -> Result<(), TransformError> {
        self.available()?;
        if !self.owns(node) {
            return Ok(());
        }
        self.insert(node.xpath_index(), 0, budget)?;
        self.with_comments |= node.is_comment();
        Ok(())
    }

    pub(crate) fn insert_attribute_at(
        &mut self,
        owner: Node<'_, '_, D>,
        ordinal: usize,
        budget: &NodeSetMaterializationBudget,
    ) -> Result<(), TransformError> {
        self.available()?;
        if !self.owns(owner) {
            return Ok(());
        }
        self.keys.charge(1).map_err(C14nError::from)?;
        let Some(index) = Self::index(owner, Axis::Attribute(ordinal)) else {
            return Ok(());
        };
        let bytes = node_bytes(owner, index - owner.xpath_index()).map_err(C14nError::from)?;
        self.insert(index, bytes, Some(budget))
    }
    pub(crate) fn insert_namespace_at(
        &mut self,
        owner: Node<'_, '_, D>,
        ordinal: usize,
        budget: &NodeSetMaterializationBudget,
    ) -> Result<(), TransformError> {
        self.available()?;
        if !self.owns(owner) {
            return Ok(());
        }
        self.keys.charge(1).map_err(C14nError::from)?;
        let Some(index) = Self::index(owner, Axis::Namespace(ordinal)) else {
            return Ok(());
        };
        let bytes = node_bytes(owner, index - owner.xpath_index()).map_err(C14nError::from)?;
        self.insert(index, bytes, Some(budget))
    }

    #[cfg(test)]
    pub(crate) fn insert_attribute(
        &mut self,
        owner: Node<'_, '_, D>,
        namespace: Option<&str>,
        local: &str,
        budget: Option<&NodeSetMaterializationBudget>,
    ) -> Result<(), TransformError> {
        self.available()?;
        if !self.owns(owner) {
            return Ok(());
        }
        for (ordinal, attribute) in owner.attributes().enumerate() {
            self.keys
                .charge(
                    name_work(&[
                        attribute.name(),
                        local,
                        attribute.namespace().unwrap_or(""),
                        namespace.unwrap_or(""),
                    ])
                    .map_err(C14nError::from)?,
                )
                .map_err(C14nError::from)?;
            if attribute.name() == local && attribute.namespace() == namespace {
                let index = Self::index(owner, Axis::Attribute(ordinal))
                    .expect("enumerated attribute ordinal");
                let bytes =
                    node_bytes(owner, index - owner.xpath_index()).map_err(C14nError::from)?;
                return self.insert(index, bytes, budget);
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn insert_namespace(
        &mut self,
        owner: Node<'_, '_, D>,
        prefix: &str,
        uri: &str,
        budget: Option<&NodeSetMaterializationBudget>,
    ) -> Result<(), TransformError> {
        self.available()?;
        if !self.owns(owner) {
            return Ok(());
        }
        for (ordinal, namespace) in owner.namespaces().enumerate() {
            self.keys
                .charge(
                    name_work(&[namespace.name().unwrap_or(""), prefix, namespace.uri(), uri])
                        .map_err(C14nError::from)?,
                )
                .map_err(C14nError::from)?;
            if namespace.name().unwrap_or("") == prefix && namespace.uri() == uri {
                let index = Self::index(owner, Axis::Namespace(ordinal))
                    .expect("enumerated namespace ordinal");
                let bytes =
                    node_bytes(owner, index - owner.xpath_index()).map_err(C14nError::from)?;
                return self.insert(index, bytes, budget);
            }
        }
        Ok(())
    }

    pub(crate) fn union(
        &mut self,
        other: &Self,
        budget: &NodeSetMaterializationBudget,
    ) -> Result<(), TransformError> {
        self.available()?;
        other.available()?;
        if !core::ptr::eq(self.document, other.document) {
            return Ok(());
        }
        let execution = self.keys.execution();
        other.for_each_index(execution, |index| {
            let (_, bytes) = self.resolve(index, execution).map_err(C14nError::from)?;
            self.insert(index, bytes, Some(budget))
        })?;
        self.with_comments |= other.with_comments;
        self.compact()
    }

    pub(crate) fn contains_tree(&self, node: Node<'_, '_, D>) -> Result<bool, C14nError> {
        self.contains(node, Axis::Tree)
    }
    pub(crate) fn contains_attribute_at(
        &self,
        owner: Node<'_, '_, D>,
        ordinal: usize,
    ) -> Result<bool, C14nError> {
        self.contains(owner, Axis::Attribute(ordinal))
    }
    pub(crate) fn contains_namespace_at(
        &self,
        owner: Node<'_, '_, D>,
        ordinal: usize,
    ) -> Result<bool, C14nError> {
        self.contains(owner, Axis::Namespace(ordinal))
    }

    pub(crate) fn exclude_subtree(&mut self, node: Node<'_, '_, D>) -> Result<(), C14nError> {
        self.available()?;
        if !self.owns(node) {
            return Ok(());
        }
        let result = self.exclude(node);
        self.sticky(result).map_err(|error| match error {
            TransformError::C14n(error) => error,
            other => unreachable!("subtree exclusion only fails on execution: {other}"),
        })
    }

    fn exclude(&mut self, node: Node<'_, '_, D>) -> Result<(), TransformError> {
        let removed = subtree_ids(node);
        if let Members::Subtree {
            nodes,
            excluded,
            comments,
        } = &self.members
        {
            if removed.end <= nodes.start || nodes.end <= removed.start {
                return Ok(());
            }
            if removed.start <= nodes.start {
                // Arena subtrees nest: this one contains the whole projection.
                self.members = self.no_members();
                self.entries = 0;
                self.projected_string_bytes = 0;
                return Ok(());
            }
            self.keys
                .charge(search_work(excluded.len()))
                .map_err(C14nError::from)?;
            let after = excluded.partition_point(|range| range.start <= removed.start);
            if after > 0 && excluded[after - 1].end >= removed.end {
                return Ok(());
            }
            // Remove the members not already excluded by a nested subtree.
            let mut entries = 0_usize;
            let mut bytes = 0_usize;
            let mut nested = after;
            let mut id = removed.start;
            while id < removed.end {
                if let Some(range) = excluded.get(nested)
                    && range.start == id
                {
                    self.keys.charge(1).map_err(C14nError::from)?;
                    id = range.end;
                    nested += 1;
                    continue;
                }
                let member = self
                    .document
                    .get_node(NodeId::from(id))
                    .expect("subtree IDs belong to their document");
                id += 1;
                if member.is_comment() && !comments {
                    self.keys.charge(1).map_err(C14nError::from)?;
                    continue;
                }
                let owned = owned_indexes(member).len();
                // The visit and each axis whose name bytes are released.
                self.keys.charge(1 + owned).map_err(C14nError::from)?;
                entries += owned;
                bytes += owned_bytes(member).map_err(C14nError::from)?;
            }
            let (retained, nested_end) = (after, nested);
            let Members::Subtree { excluded, .. } = &mut self.members else {
                unreachable!("checked semantic members");
            };
            // Replace the nested exclusions by their enclosing subtree; the
            // rotations move every exclusion after the insertion point.
            self.keys
                .charge(excluded.len() + 1 - retained)
                .map_err(C14nError::from)?;
            let tail = excluded.len() - nested_end;
            excluded.push(removed.clone())?;
            excluded[retained..].rotate_right(1);
            let keep = retained + 1 + tail;
            excluded[retained + 1..].rotate_left(nested_end - retained);
            while excluded.len() > keep {
                excluded.pop();
            }
            self.entries -= entries;
            self.projected_string_bytes -= bytes;
            return Ok(());
        }
        let indexes = node.xpath_index()..node.xpath_subtree_end();
        self.filter(|index| Ok(!indexes.contains(&index)))?;
        self.compact()
    }

    pub(crate) fn intersect(&mut self, other: &Self) -> Result<(), C14nError> {
        self.available()?;
        other.available()?;
        let result = self.intersect_with(other);
        self.sticky(result).map_err(transform_c14n)
    }

    fn intersect_with(&mut self, other: &Self) -> Result<(), TransformError> {
        if !core::ptr::eq(self.document, other.document) {
            self.members = self.no_members();
            self.entries = 0;
            self.projected_string_bytes = 0;
            self.with_comments = false;
            return Ok(());
        }
        if !matches!(other.members, Members::Subtree { .. })
            && (matches!(self.members, Members::Subtree { .. }) || other.entries < self.entries)
        {
            // The result is a subset of the smaller explicit operand; scan only it.
            let execution = self.keys.execution();
            let mut result = Self::empty(self.document, self.keys.empty_like());
            other.for_each_index(execution, |index| {
                if self
                    .contains_index(index, execution)
                    .map_err(C14nError::from)?
                {
                    let (_, bytes) = self.resolve(index, execution).map_err(C14nError::from)?;
                    result.insert(index, bytes, None)?;
                }
                Ok(())
            })?;
            result.with_comments = self.with_comments & other.with_comments;
            result.compact()?;
            *self = result;
            return Ok(());
        }
        self.materialize()?;
        let execution = self.keys.execution();
        self.filter(|index| other.contains_index(index, execution))?;
        self.with_comments &= other.with_comments;
        self.compact()
    }

    pub(crate) fn subtract(&mut self, other: &Self) -> Result<(), C14nError> {
        self.available()?;
        other.available()?;
        if !core::ptr::eq(self.document, other.document) {
            return Ok(());
        }
        let execution = self.keys.execution();
        let result = self.materialize().and_then(|()| {
            if matches!(self.members, Members::Dense(_))
                && !matches!(other.members, Members::Subtree { .. })
            {
                // Clear the explicit operand's bits instead of testing every member.
                other.for_each_index(execution, |index| self.remove_dense(index))?;
            } else {
                self.filter(|index| {
                    other
                        .contains_index(index, execution)
                        .map(|present| !present)
                })?;
            }
            self.compact()
        });
        self.sticky(result).map_err(transform_c14n)
    }

    fn remove_dense(&mut self, index: u32) -> Result<(), TransformError> {
        let execution = self.keys.execution();
        K::admit(execution, 1).map_err(C14nError::from)?;
        let Members::Dense(words) = &mut self.members else {
            unreachable!("caller checked dense members");
        };
        if !bit(words, index) {
            return Ok(());
        }
        words[index as usize / 64] &= !(1 << (index % 64));
        let (_, bytes) = self.resolve(index, execution).map_err(C14nError::from)?;
        self.entries -= 1;
        self.projected_string_bytes -= bytes;
        Ok(())
    }
}

fn transform_c14n(error: TransformError) -> C14nError {
    match error {
        TransformError::C14n(error) => error,
        other => unreachable!("node-set algebra only fails on execution: {other}"),
    }
}

fn bit(words: &[u64], index: u32) -> bool {
    words
        .get(index as usize / 64)
        .is_some_and(|word| word & (1 << (index % 64)) != 0)
}

fn set_bit(words: &mut [u64], index: u32) {
    words[index as usize / 64] |= 1 << (index % 64);
}

impl<K: Keys, D: DomStorage> NodeVisibility<D> for Projection<'_, K, D> {
    fn contains_node(&self, node: Node<'_, '_, D>) -> Result<bool, C14nError> {
        self.contains_tree(node)
    }
    fn contains_attribute(
        &self,
        owner: Node<'_, '_, D>,
        namespace: Option<&str>,
        local: &str,
    ) -> Result<bool, C14nError> {
        self.available()?;
        if !self.owns(owner) {
            return Ok(false);
        }
        for (ordinal, attribute) in owner.attributes().enumerate() {
            self.keys.charge(name_work(&[
                attribute.name(),
                local,
                attribute.namespace().unwrap_or(""),
                namespace.unwrap_or(""),
            ])?)?;
            if attribute.name() == local && attribute.namespace() == namespace {
                return self.contains_attribute_at(owner, ordinal);
            }
        }
        Ok(false)
    }
    fn contains_namespace(
        &self,
        owner: Node<'_, '_, D>,
        prefix: &str,
        uri: &str,
    ) -> Result<bool, C14nError> {
        self.available()?;
        if !self.owns(owner) {
            return Ok(false);
        }
        for (ordinal, namespace) in owner.namespaces().enumerate() {
            self.keys.charge(name_work(&[
                namespace.name().unwrap_or(""),
                prefix,
                namespace.uri(),
                uri,
            ])?)?;
            if namespace.name().unwrap_or("") == prefix && namespace.uri() == uri {
                return self.contains_namespace_at(owner, ordinal);
            }
        }
        Ok(false)
    }
    fn contains_attribute_at(
        &self,
        owner: Node<'_, '_, D>,
        ordinal: usize,
        _: crate::xml::dom::Attribute<'_, D>,
    ) -> Result<bool, C14nError> {
        Projection::contains_attribute_at(self, owner, ordinal)
    }
    fn contains_namespace_at(
        &self,
        owner: Node<'_, '_, D>,
        ordinal: usize,
        _: crate::xml::dom::Namespace<'_, D>,
    ) -> Result<bool, C14nError> {
        Projection::contains_namespace_at(self, owner, ordinal)
    }
}

#[cfg(test)]
mod tests;
