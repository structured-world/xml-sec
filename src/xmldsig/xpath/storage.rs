//! Storage adapters for `XPath`'s original-to-mirror identity indexes.

use std::collections::HashMap;
use structured_asn1::memory::{HashWork, MemoryError, OwnedMap, Work};

pub(crate) trait Index<K: HashWork, V, E: Copy> {
    fn lookup(&self, key: &K, execution: E) -> Result<Option<&V>, MemoryError>;
    fn insert(&mut self, key: K, value: V) -> Result<(), MemoryError>;
}

pub(crate) struct NativeIndex<K, V>(HashMap<K, V>);

pub(crate) trait Bindings<'source, E: Copy> {
    fn resolve(&self, prefix: &str, execution: E) -> Result<Option<&'source str>, MemoryError>;
    fn bind(&mut self, prefix: &'source str, uri: &'source str) -> Result<(), MemoryError>;
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Prefix<'source>(&'source str);

impl std::borrow::Borrow<str> for Prefix<'_> {
    fn borrow(&self) -> &str {
        self.0
    }
}

impl HashWork for Prefix<'_> {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        self.0.hash_work()
    }
}

impl<'source> Bindings<'source, ()> for NativeIndex<Prefix<'source>, &'source str> {
    fn resolve(&self, prefix: &str, (): ()) -> Result<Option<&'source str>, MemoryError> {
        Ok(self.0.get(prefix).copied())
    }
    fn bind(&mut self, prefix: &'source str, uri: &'source str) -> Result<(), MemoryError> {
        self.0.insert(Prefix(prefix), uri);
        Ok(())
    }
}

impl<'source, 'w, W: Work> Bindings<'source, &'w W> for OwnedMap<Prefix<'source>, &'source str, W> {
    fn resolve(&self, prefix: &str, execution: &'w W) -> Result<Option<&'source str>, MemoryError> {
        self.get_key_value_borrowed(prefix, execution)
            .map(|entry| entry.map(|(_, uri)| *uri))
    }
    fn bind(&mut self, prefix: &'source str, uri: &'source str) -> Result<(), MemoryError> {
        self.try_insert(Prefix(prefix), uri).map(|_| ())
    }
}

impl<K, V> NativeIndex<K, V> {
    pub(crate) fn new() -> Self {
        Self(HashMap::new())
    }
}

impl<K: HashWork, V> Index<K, V, ()> for NativeIndex<K, V> {
    fn lookup(&self, key: &K, (): ()) -> Result<Option<&V>, MemoryError> {
        Ok(self.0.get(key))
    }
    fn insert(&mut self, key: K, value: V) -> Result<(), MemoryError> {
        self.0.insert(key, value);
        Ok(())
    }
}

impl<'w, K: HashWork, V, W: Work> Index<K, V, &'w W> for OwnedMap<K, V, W> {
    fn lookup(&self, key: &K, execution: &'w W) -> Result<Option<&V>, MemoryError> {
        self.get(key, execution)
    }
    fn insert(&mut self, key: K, value: V) -> Result<(), MemoryError> {
        self.try_insert(key, value).map(|_| ())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct NamespaceKey<'source> {
    pub(super) owner: (usize, usize, usize),
    pub(super) prefix: &'source str,
    pub(super) uri: &'source str,
}

impl HashWork for NamespaceKey<'_> {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        // Three scalar identity fields plus each string's data and length.
        5_u64
            .checked_add(self.prefix.len() as u64)
            .and_then(|work| work.checked_add(self.uri.len() as u64))
            .ok_or(MemoryError::WorkExceeded)
    }
}

pub(crate) trait NamespaceIndex<'source, E: Copy> {
    fn lookup_namespace(
        &self,
        key: &NamespaceKey<'_>,
        execution: E,
    ) -> Result<Option<usize>, MemoryError>;
    fn insert_namespace(
        &mut self,
        key: NamespaceKey<'source>,
        ordinal: usize,
    ) -> Result<(), MemoryError>;
}

impl<'source> NamespaceIndex<'source, ()> for NativeIndex<NamespaceKey<'source>, usize> {
    fn lookup_namespace(
        &self,
        key: &NamespaceKey<'_>,
        (): (),
    ) -> Result<Option<usize>, MemoryError> {
        Ok(self.0.get(key).copied())
    }
    fn insert_namespace(
        &mut self,
        key: NamespaceKey<'source>,
        ordinal: usize,
    ) -> Result<(), MemoryError> {
        self.0.insert(key, ordinal);
        Ok(())
    }
}

impl<'source, 'w, W: Work> NamespaceIndex<'source, &'w W>
    for OwnedMap<NamespaceKey<'source>, usize, W>
{
    fn lookup_namespace(
        &self,
        key: &NamespaceKey<'_>,
        execution: &'w W,
    ) -> Result<Option<usize>, MemoryError> {
        self.get(key, execution).map(Option::<&usize>::copied)
    }
    fn insert_namespace(
        &mut self,
        key: NamespaceKey<'source>,
        ordinal: usize,
    ) -> Result<(), MemoryError> {
        self.try_insert(key, ordinal).map(|_| ())
    }
}
