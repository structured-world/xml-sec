//! Storage-specialized projection of the original XML XPath node identities.

use super::{NodeSetMaterializationBudget, TransformError, charge_resource_bytes};
use crate::c14n::{C14nError, NodeVisibility};
use crate::xml::dom::storage::{Native as NativeDom, Storage as DomStorage};
use crate::xml::dom::{Document, Node};
use std::collections::HashMap;
use structured_asn1::memory::{HashWork, MemoryError, OwnedMap, Work};

// Arena ordinals are private to this projection's one original document.
// Tree, attribute and namespace axes cannot collide, including inherited axes.
pub(crate) type Key = (usize, usize, usize);
const TREE: usize = 0;
const ATTRIBUTE: usize = 1;
const NAMESPACE: usize = 2;

fn name_work(parts: &[&str]) -> Result<usize, MemoryError> {
    let mut work = 1_usize;
    for part in parts {
        work = work
            .checked_add(part.len())
            .ok_or(MemoryError::WorkExceeded)?;
    }
    Ok(work)
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

pub(crate) trait Keys {
    type Execution: Copy;
    type Scratch: crate::c14n::scratch::Scratch + crate::xmldsig::xpath::XPathStorage;
    type Bindings<'source>: super::super::xpath::storage::Bindings<'source, Self::Execution>;
    fn bindings<'source>(execution: Self::Execution) -> Self::Bindings<'source>;
    fn scratch(execution: Self::Execution) -> Self::Scratch;
    type Index<T: HashWork, V>: super::super::xpath::storage::Index<T, V, Self::Execution>;
    fn index<T: HashWork, V>(execution: Self::Execution) -> Self::Index<T, V>;
    type NamespaceIndex<'source>: super::super::xpath::storage::NamespaceIndex<'source, Self::Execution>;
    fn namespace_index<'source>(execution: Self::Execution) -> Self::NamespaceIndex<'source>;
    fn execution(&self) -> Self::Execution;
    fn empty_like(&self) -> Self;
    fn admit(execution: Self::Execution, units: usize) -> Result<(), MemoryError>;
    fn charge(&self, units: usize) -> Result<(), MemoryError> {
        Self::admit(self.execution(), units)
    }
    fn len(&self) -> usize;
    fn contains_in(&self, key: Key, execution: Self::Execution) -> Result<bool, MemoryError>;
    fn contains(&self, key: Key) -> Result<bool, MemoryError> {
        self.contains_in(key, self.execution())
    }
    fn insert(&mut self, key: Key, bytes: usize) -> Result<(), MemoryError>;
    fn entries_in(
        &self,
        execution: Self::Execution,
    ) -> Result<impl Iterator<Item = (Key, usize)> + '_, MemoryError>;
}

pub(crate) trait RetainKeys: Keys {
    fn retain(
        &mut self,
        predicate: impl FnMut(Key, usize) -> Result<bool, MemoryError>,
    ) -> Result<(), MemoryError>;
}

#[derive(Default)]
pub(crate) struct NativeKeys(HashMap<Key, usize>);
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
    type Index<T: HashWork, V> = super::super::xpath::storage::NativeIndex<T, V>;
    fn index<T: HashWork, V>((): ()) -> Self::Index<T, V> {
        super::super::xpath::storage::NativeIndex::new()
    }
    fn execution(&self) {}
    fn empty_like(&self) -> Self {
        Self::default()
    }
    fn admit(_: (), _: usize) -> Result<(), MemoryError> {
        Ok(())
    }
    fn len(&self) -> usize {
        self.0.len()
    }
    fn contains_in(&self, key: Key, _: ()) -> Result<bool, MemoryError> {
        Ok(self.0.contains_key(&key))
    }
    fn insert(&mut self, key: Key, bytes: usize) -> Result<(), MemoryError> {
        self.0.insert(key, bytes);
        Ok(())
    }
    fn entries_in(&self, _: ()) -> Result<impl Iterator<Item = (Key, usize)> + '_, MemoryError> {
        Ok(self.0.iter().map(|(key, bytes)| (*key, *bytes)))
    }
}
impl RetainKeys for NativeKeys {
    fn retain(
        &mut self,
        mut predicate: impl FnMut(Key, usize) -> Result<bool, MemoryError>,
    ) -> Result<(), MemoryError> {
        let mut failure = None;
        self.0.retain(|key, bytes| {
            if failure.is_some() {
                return true;
            }
            match predicate(*key, *bytes) {
                Ok(keep) => keep,
                Err(error) => {
                    failure = Some(error);
                    true
                }
            }
        });
        failure.map_or(Ok(()), Err)
    }
}

pub(crate) struct PaidKeys<'w, W: Work> {
    values: OwnedMap<Key, usize, W>,
    work: &'w W,
}
impl<'w, W: Work> PaidKeys<'w, W> {
    pub(crate) fn new(work: &'w W) -> Self {
        Self {
            values: work.map(),
            work,
        }
    }
}
impl<W: Work> RetainKeys for PaidKeys<'_, W> {
    fn retain(
        &mut self,
        mut predicate: impl FnMut(Key, usize) -> Result<bool, MemoryError>,
    ) -> Result<(), MemoryError> {
        self.values
            .try_retain(self.work, |key, bytes| predicate(*key, *bytes))
            .map_err(MemoryError::from)
    }
}
impl<'w, W: Work> Keys for PaidKeys<'w, W> {
    type Execution = &'w W;
    type Scratch = crate::c14n::scratch::Accounted<'w, W>;
    type Bindings<'source> =
        OwnedMap<super::super::xpath::storage::Prefix<'source>, &'source str, W>;
    fn bindings<'source>(execution: &'w W) -> Self::Bindings<'source> {
        execution.map()
    }
    fn scratch(execution: &'w W) -> Self::Scratch {
        crate::c14n::scratch::Accounted(execution)
    }
    type NamespaceIndex<'source> =
        OwnedMap<super::super::xpath::storage::NamespaceKey<'source>, usize, W>;
    fn namespace_index<'source>(execution: &'w W) -> Self::NamespaceIndex<'source> {
        execution.map()
    }
    type Index<T: HashWork, V> = OwnedMap<T, V, W>;
    fn index<T: HashWork, V>(execution: &'w W) -> Self::Index<T, V> {
        execution.map()
    }
    fn execution(&self) -> &'w W {
        self.work
    }
    fn empty_like(&self) -> Self {
        Self {
            values: self.work.map(),
            work: self.work,
        }
    }
    fn admit(work: &'w W, units: usize) -> Result<(), MemoryError> {
        work.charge_work(u64::try_from(units).map_err(|_| MemoryError::WorkExceeded)?)
    }
    fn len(&self) -> usize {
        self.values.len()
    }
    fn contains_in(&self, key: Key, work: &'w W) -> Result<bool, MemoryError> {
        Ok(self.values.get(&key, work)?.is_some())
    }
    fn insert(&mut self, key: Key, bytes: usize) -> Result<(), MemoryError> {
        self.values.try_insert(key, bytes)?;
        Ok(())
    }
    fn entries_in(
        &self,
        work: &'w W,
    ) -> Result<impl Iterator<Item = (Key, usize)> + '_, MemoryError> {
        Ok(self
            .values
            .try_iter(work)?
            .map(|(key, bytes)| (*key, *bytes)))
    }
}

pub(crate) struct Projection<'a, K: Keys, D: DomStorage = NativeDom> {
    document: &'a Document<'a, D>,
    keys: K,
    projected_string_bytes: usize,
    with_comments: bool,
    failure: Option<MemoryError>,
}

fn walk<K: Keys, D: DomStorage>(
    root: Node<'_, '_, D>,
    comments: bool,
    execution: K::Execution,
    mut visit: impl FnMut(Key, usize, bool) -> Result<(), TransformError>,
) -> Result<(), TransformError> {
    K::admit(execution, root.descendants().len()).map_err(C14nError::from)?;
    for node in root.descendants() {
        if node.is_comment() && !comments {
            continue;
        }
        visit((TREE, node.id().get() as usize, 0), 0, node.is_comment())?;
        let axes = node
            .attributes()
            .len()
            .checked_add(node.namespaces().len())
            .ok_or(MemoryError::WorkExceeded)
            .map_err(C14nError::from)?;
        K::admit(execution, axes).map_err(C14nError::from)?;
        for (ordinal, attribute) in node.attributes().enumerate() {
            let bytes = attribute
                .name()
                .len()
                .checked_add(attribute.namespace().map_or(0, str::len))
                .ok_or(MemoryError::WorkExceeded)
                .map_err(C14nError::from)?;
            visit((ATTRIBUTE, node.id().get() as usize, ordinal), bytes, false)?;
        }
        for (ordinal, namespace) in node.namespaces().enumerate() {
            let bytes = namespace
                .uri()
                .len()
                .checked_add(namespace.name().map_or(0, str::len))
                .ok_or(MemoryError::WorkExceeded)
                .map_err(C14nError::from)?;
            visit((NAMESPACE, node.id().get() as usize, ordinal), bytes, false)?;
        }
    }
    Ok(())
}

#[cfg(test)]
impl<'a, 'w, W: Work, D: DomStorage> Projection<'a, PaidKeys<'w, W>, D> {
    pub(crate) fn accounted_subtree(
        root: Node<'a, 'a, D>,
        with_comments: bool,
        budget: &NodeSetMaterializationBudget,
        work: &'w W,
    ) -> Result<Self, TransformError> {
        Self::subtree(
            root,
            with_comments,
            budget,
            PaidKeys {
                values: work.map(),
                work,
            },
        )
    }
}

impl<'a, K: Keys, D: DomStorage> Projection<'a, K, D> {
    pub(crate) fn subtree(
        root: Node<'a, 'a, D>,
        with_comments: bool,
        budget: &NodeSetMaterializationBudget,
        keys: K,
    ) -> Result<Self, TransformError> {
        let mut projection = Self::empty(root.document(), keys);
        projection.with_comments = with_comments;
        let measured = measure(
            root,
            with_comments,
            budget.max_entries,
            budget.max_owned_string_bytes,
            &projection.keys,
        )?;
        budget.charge(measured.owned_string_bytes)?;
        walk::<K, D>(
            root,
            with_comments,
            projection.keys.execution(),
            |key, bytes, _| {
                projection
                    .keys
                    .insert(key, bytes)
                    .map_err(C14nError::from)?;
                Ok(())
            },
        )?;
        projection.projected_string_bytes = measured.owned_string_bytes;
        debug_assert_eq!(projection.keys.len(), measured.entries);
        Ok(projection)
    }

    fn insert_new(
        &mut self,
        key: Key,
        bytes: usize,
        budget: &NodeSetMaterializationBudget,
    ) -> Result<(), TransformError> {
        let next = charge_resource_bytes(
            self.keys.len(),
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
        // remain borrowed; actual table capacity is separately allocator-paid.
        budget.charge(bytes)?;
        self.keys.insert(key, bytes).map_err(C14nError::from)?;
        debug_assert_eq!(self.keys.len(), next);
        self.projected_string_bytes = strings;
        Ok(())
    }

    fn owns(&self, node: Node<'_, '_, D>) -> bool {
        std::ptr::eq(self.document, node.document())
    }
    pub(crate) fn empty(document: &'a Document<'a, D>, keys: K) -> Self {
        Self {
            document,
            keys,
            projected_string_bytes: 0,
            with_comments: false,
            failure: None,
        }
    }
    fn available(&self) -> Result<(), C14nError> {
        match self.failure {
            Some(error) => Err(error.into()),
            None => Ok(()),
        }
    }
    pub(crate) fn len(&self) -> usize {
        self.keys.len()
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

    fn insert(
        &mut self,
        key: Key,
        bytes: usize,
        budget: Option<&NodeSetMaterializationBudget>,
    ) -> Result<(), TransformError> {
        self.available()?;
        if self.keys.contains(key).map_err(C14nError::from)? {
            return Ok(());
        }
        match budget {
            Some(budget) => self.insert_new(key, bytes, budget),
            None => {
                let next = self
                    .projected_string_bytes
                    .checked_add(bytes)
                    .ok_or(MemoryError::WorkExceeded)
                    .map_err(C14nError::from)?;
                self.keys.insert(key, bytes).map_err(C14nError::from)?;
                self.projected_string_bytes = next;
                Ok(())
            }
        }
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
        self.insert((TREE, node.id().get() as usize, 0), 0, budget)?;
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
        let Some(attribute) = owner.attributes().nth(ordinal) else {
            return Ok(());
        };
        let bytes = attribute
            .name()
            .len()
            .checked_add(attribute.namespace().map_or(0, str::len))
            .ok_or(MemoryError::WorkExceeded)
            .map_err(C14nError::from)?;
        self.insert(
            (ATTRIBUTE, owner.id().get() as usize, ordinal),
            bytes,
            Some(budget),
        )
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
        let Some(namespace) = owner.namespaces().nth(ordinal) else {
            return Ok(());
        };
        let bytes = namespace
            .uri()
            .len()
            .checked_add(namespace.name().map_or(0, str::len))
            .ok_or(MemoryError::WorkExceeded)
            .map_err(C14nError::from)?;
        self.insert(
            (NAMESPACE, owner.id().get() as usize, ordinal),
            bytes,
            Some(budget),
        )
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
                return self.insert(
                    (ATTRIBUTE, owner.id().get() as usize, ordinal),
                    attribute
                        .name()
                        .len()
                        .saturating_add(attribute.namespace().map_or(0, str::len)),
                    budget,
                );
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
                return self.insert(
                    (NAMESPACE, owner.id().get() as usize, ordinal),
                    prefix.len().saturating_add(uri.len()),
                    budget,
                );
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
        if !std::ptr::eq(self.document, other.document) {
            return Ok(());
        }
        for (key, bytes) in other
            .keys
            .entries_in(self.keys.execution())
            .map_err(C14nError::from)?
        {
            self.insert(key, bytes, Some(budget))?;
        }
        self.with_comments |= other.with_comments;
        Ok(())
    }
    pub(crate) fn contains_tree(&self, node: Node<'_, '_, D>) -> Result<bool, C14nError> {
        self.available()?;
        if !self.owns(node) {
            return Ok(false);
        }
        self.keys
            .contains((TREE, node.id().get() as usize, 0))
            .map_err(Into::into)
    }
    pub(crate) fn contains_attribute_at(
        &self,
        owner: Node<'_, '_, D>,
        ordinal: usize,
    ) -> Result<bool, C14nError> {
        self.available()?;
        if !self.owns(owner) {
            return Ok(false);
        }
        self.keys
            .contains((ATTRIBUTE, owner.id().get() as usize, ordinal))
            .map_err(Into::into)
    }
    pub(crate) fn contains_namespace_at(
        &self,
        owner: Node<'_, '_, D>,
        ordinal: usize,
    ) -> Result<bool, C14nError> {
        self.available()?;
        if !self.owns(owner) {
            return Ok(false);
        }
        self.keys
            .contains((NAMESPACE, owner.id().get() as usize, ordinal))
            .map_err(Into::into)
    }
}

impl<K: RetainKeys, D: DomStorage> Projection<'_, K, D> {
    fn retain(
        &mut self,
        mut predicate: impl FnMut(Key) -> Result<bool, MemoryError>,
    ) -> Result<(), C14nError> {
        self.available()?;
        let bytes = &mut self.projected_string_bytes;
        let result = self.keys.retain(|key, weight| {
            let keep = predicate(key)?;
            if !keep {
                *bytes -= weight;
            }
            Ok(keep)
        });
        if let Err(error) = result {
            self.failure = Some(error);
        }
        result.map_err(Into::into)
    }
    pub(crate) fn exclude_subtree(&mut self, node: Node<'_, '_, D>) -> Result<(), C14nError> {
        self.available()?;
        if !self.owns(node) {
            return Ok(());
        }
        let range = super::subtree_node_id_range(node);
        self.retain(|key| Ok(!range.contains(&(key.1 as u32))))
    }
    pub(crate) fn intersect(&mut self, other: &Self) -> Result<(), C14nError> {
        other.available()?;
        if !std::ptr::eq(self.document, other.document) {
            self.retain(|_| Ok(false))?;
            self.with_comments = false;
            return Ok(());
        }
        let execution = self.keys.execution();
        self.retain(|key| other.keys.contains_in(key, execution))?;
        self.with_comments &= other.with_comments;
        Ok(())
    }
    pub(crate) fn subtract(&mut self, other: &Self) -> Result<(), C14nError> {
        self.available()?;
        other.available()?;
        if !std::ptr::eq(self.document, other.document) {
            return Ok(());
        }
        let execution = self.keys.execution();
        self.retain(|key| {
            other
                .keys
                .contains_in(key, execution)
                .map(|present| !present)
        })
    }
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
mod tests {
    use super::*;
    use std::sync::Arc;
    use structured_asn1::memory::{Memory, MemoryAccount};

    #[test]
    fn set_algebra_reads_retained_keys_only_with_current_execution() {
        // The right-hand set may outlive an exhausted producer. Its storage
        // remains retained there; filtering, membership and insertion use the
        // left-hand current query, including attributes and namespace axes.
        use structured_asn1::{Encoding, Limits, Parser};
        let document = Document::parse("<root xmlns:p='urn:p'><left p:a='v'/><right/></root>")
            .expect("fixed XML");
        let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
        let producer = Parser::new(
            Encoding::Der,
            Limits {
                max_work: 4096,
                ..Default::default()
            },
            memory.clone(),
        );
        let producer_reader = producer.read(&[], 0).expect("empty producer input");
        let producer_work = producer_reader.execution();
        let query = Parser::new(Encoding::Der, Limits::default(), memory.clone());
        let reader = query.read(&[], 0).expect("empty query input");
        let work = reader.execution();
        let budget = NodeSetMaterializationBudget::default();
        let child = document
            .root_element()
            .first_element_child()
            .expect("left child");
        let retained = Projection::accounted_subtree(child, true, &budget, &producer_work)
            .expect("producer projection fits");
        for shift in (0..=12).rev() {
            while producer_work.charge_work(1 << shift).is_ok() {}
        }
        let mut selected = Projection::accounted_subtree(document.root(), true, &budget, &work)
            .expect("current projection fits");
        selected.intersect(&retained).expect("current intersection");
        assert!(selected.contains_tree(child).expect("current lookup"));
        assert!(
            selected
                .contains_attribute_at(child, 0)
                .expect("current attribute lookup")
        );
        assert!(
            !selected
                .contains_tree(document.root_element())
                .expect("excluded root lookup")
        );
        selected.subtract(&retained).expect("current subtraction");
        assert_eq!(selected.len(), 0);
        selected.union(&retained, &budget).expect("current union");
        assert_eq!(selected.len(), retained.len());
        selected.exclude_subtree(child).expect("current exclusion");
        assert_eq!(selected.len(), 0);
        assert!(producer_work.charge_work(1).is_err());
        drop(selected);
        drop(retained);
        assert_eq!(memory.used(), 0);
    }

    #[test]
    fn failed_filter_is_sticky_and_cannot_be_observed_as_successful_subset() {
        // Even when a sparse-table scan refuses before its first predicate,
        // subsequent membership and serialization must retain that refusal.
        let document = Document::parse("<root><child/></root>").expect("fixed source XML");
        let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 4096)));
        let mut nodes = Projection::accounted_subtree(
            document.root(),
            true,
            &NodeSetMaterializationBudget::default(),
            &memory,
        )
        .expect("initial projection fits");
        memory
            .charge_work(memory.work_remaining() as u64)
            .expect("spend exactly remaining work");
        assert!(matches!(
            nodes.exclude_subtree(document.root_element()),
            Err(C14nError::SharedExecution(MemoryError::WorkExceeded))
        ));
        assert!(matches!(
            nodes.contains_tree(document.root()),
            Err(C14nError::SharedExecution(MemoryError::WorkExceeded))
        ));
        let mut output = Vec::new();
        let algorithm = crate::c14n::C14nAlgorithm::new(crate::c14n::C14nMode::Inclusive1_0, false);
        assert!(
            crate::c14n::canonicalize_with_visibility(
                &document,
                Some(&nodes),
                &algorithm,
                &mut output
            )
            .is_err()
        );
        assert!(output.is_empty());
        drop(nodes);
        assert_eq!(memory.used(), 0);
    }

    #[test]
    fn compact_projection_matches_original_axes_and_canonical_bytes() {
        // Private axis ordinals must preserve owner-specific namespace identity
        // and subset inheritance on both storage strategies and every C14N mode.
        let document = crate::xml::dom::Document::parse(
            r#"<outer xmlns="urn:default" xmlns:p="urn:a" xml:lang="en"><child p:a="v"><!--kept--><p:leaf xmlns:p="urn:b"/></child></outer>"#,
        ).expect("fixed namespace source XML");
        let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
        for root in [
            document.root(),
            document
                .root_element()
                .first_element_child()
                .expect("fixed child subtree"),
        ] {
            let budget = super::super::NodeSetMaterializationBudget::default();
            let original = super::super::NodeSet::subtree(root).expect("collecting projection");
            let native = Projection::subtree(root, true, &budget, NativeKeys::default())
                .expect("native projection");
            let paid = Projection::accounted_subtree(root, true, &budget, &memory)
                .expect("paid projection");
            assert!(paid.with_comments());
            assert!(std::ptr::eq(paid.document(), &document));
            for mode in [
                crate::c14n::C14nMode::Inclusive1_0,
                crate::c14n::C14nMode::Inclusive1_1,
                crate::c14n::C14nMode::Exclusive1_0,
            ] {
                for comments in [false, true] {
                    let algorithm = crate::c14n::C14nAlgorithm::new(mode, comments);
                    let mut expected = Vec::new();
                    crate::c14n::canonicalize_with_visibility(
                        &document,
                        Some(&original),
                        &algorithm,
                        &mut expected,
                    )
                    .expect("collecting canonical output");
                    for visibility in [&native as &dyn NodeVisibility, &paid] {
                        let mut actual = Vec::new();
                        crate::c14n::canonicalize_with_visibility(
                            &document,
                            Some(visibility),
                            &algorithm,
                            &mut actual,
                        )
                        .expect("storage-specialized canonical output");
                        assert_eq!(actual, expected);
                    }
                }
            }
        }
        assert_eq!(memory.used(), 0);
    }

    #[test]
    fn paid_projection_refuses_capacity_and_releases_storage() {
        // A wide source cannot materialize its XPath axes in an unaccounted
        // table. Projection failure and normal drop both release capacity.
        let xml = format!("<root>{}</root>", "<a p='v'/>".repeat(1024));
        let document = crate::xml::dom::Document::parse(&xml).expect("fixed wide source XML");
        let small = Memory::new(Arc::new(MemoryAccount::new(1024, 1 << 24)));
        let budget = super::super::NodeSetMaterializationBudget::default();
        assert!(Projection::accounted_subtree(document.root(), true, &budget, &small).is_err());
        assert_eq!(small.used(), 0);
        let large = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
        let nodes = Projection::accounted_subtree(document.root(), true, &budget, &large)
            .expect("larger account admits projection");
        assert!(large.used() > 1024);
        assert!(
            nodes
                .contains_tree(document.root_element())
                .expect("admitted membership lookup")
        );
        drop(nodes);
        assert_eq!(large.used(), 0);
    }
}
