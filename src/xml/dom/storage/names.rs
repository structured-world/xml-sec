//! XML name-keyed indexes with allocation-free borrowed queries.

use super::{Native, Storage};
use crate::collections::{Map, Table};
use crate::xml::dom::ParseError;

pub(crate) trait NameStorage: Storage {
    type Names<K: AsRef<str>, V>: Names<K, V, Self>;
    fn names<K: AsRef<str>, V>(&self) -> Self::Names<K, V>;
}

pub(crate) trait Names<K, V, S: Storage> {
    fn len(&self) -> usize;
    fn get(&self, name: &str, storage: S) -> Result<Option<&V>, ParseError>;
    fn get_mut(&mut self, name: &str, storage: S) -> Result<Option<&mut V>, ParseError>;
    fn insert(&mut self, name: K, value: V) -> Result<Option<V>, ParseError>;
    fn remove(&mut self, name: &str, storage: S) -> Result<Option<V>, ParseError>;
    #[cfg(feature = "xml-backend-xmloxide")]
    fn entries<'a>(
        &'a self,
        storage: S,
    ) -> Result<impl Iterator<Item = (&'a K, &'a V)> + 'a, ParseError>
    where
        K: 'a,
        V: 'a;
    #[cfg(feature = "xml-backend-xmloxide")]
    fn key_value(&self, name: &str, storage: S) -> Result<Option<(&K, &V)>, ParseError>;
}

#[derive(Clone, Debug)]
pub(crate) struct Name<T>(T);
impl<T: AsRef<str>> core::fmt::Display for Name<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.as_ref().fmt(f)
    }
}
// Equality, ordering and hashing all follow the borrowed `str`, as the
// `Borrow` lookups of both table kinds require.
impl<T: AsRef<str>> core::borrow::Borrow<str> for Name<T> {
    fn borrow(&self) -> &str {
        self.0.as_ref()
    }
}
impl<T: AsRef<str>> core::hash::Hash for Name<T> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.as_ref().hash(state);
    }
}
impl<T: AsRef<str>> PartialEq for Name<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ref() == other.0.as_ref()
    }
}
impl<T: AsRef<str>> Eq for Name<T> {}
impl<T: AsRef<str>> PartialOrd for Name<T> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<T: AsRef<str>> Ord for Name<T> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.as_ref().cmp(other.0.as_ref())
    }
}

#[cfg(feature = "xmldsig")]
impl<T: AsRef<str>> structured_asn1::memory::HashWork for Name<T> {
    fn hash_work(&self) -> Result<u64, structured_asn1::memory::MemoryError> {
        (self.0.as_ref().len() as u64)
            .checked_add(1)
            .ok_or(structured_asn1::memory::MemoryError::WorkExceeded)
    }
}

impl NameStorage for Native {
    type Names<K: AsRef<str>, V> = Map<Name<K>, V>;
    fn names<K: AsRef<str>, V>(&self) -> Self::Names<K, V> {
        Map::new()
    }
}

impl<K: AsRef<str>, V> Names<K, V, Native> for Map<Name<K>, V> {
    fn len(&self) -> usize {
        Map::len(self)
    }
    fn get(&self, name: &str, _: Native) -> Result<Option<&V>, ParseError> {
        Ok(Map::get(self, name))
    }
    fn get_mut(&mut self, name: &str, _: Native) -> Result<Option<&mut V>, ParseError> {
        Ok(Map::get_mut(self, name))
    }
    fn insert(&mut self, name: K, value: V) -> Result<Option<V>, ParseError> {
        self.try_reserve_entries(1)
            .map_err(|_| ParseError::AllocationFailed)?;
        Ok(Map::insert(self, Name(name), value))
    }
    fn remove(&mut self, name: &str, _: Native) -> Result<Option<V>, ParseError> {
        Ok(Map::remove(self, name))
    }
    #[cfg(feature = "xml-backend-xmloxide")]
    fn entries<'a>(
        &'a self,
        _: Native,
    ) -> Result<impl Iterator<Item = (&'a K, &'a V)> + 'a, ParseError>
    where
        K: 'a,
        V: 'a,
    {
        Ok(self.iter().map(|(key, value)| (&key.0, value)))
    }
    #[cfg(feature = "xml-backend-xmloxide")]
    fn key_value(&self, name: &str, _: Native) -> Result<Option<(&K, &V)>, ParseError> {
        Ok(self.get_key_value(name).map(|(key, value)| (&key.0, value)))
    }
}

#[cfg(feature = "xmldsig")]
impl<W: structured_asn1::memory::Work> NameStorage for super::Accounted<'_, W> {
    type Names<K: AsRef<str>, V> = structured_asn1::memory::OwnedMap<Name<K>, V, W>;
    fn names<K: AsRef<str>, V>(&self) -> Self::Names<K, V> {
        self.0.map()
    }
}

#[cfg(feature = "xmldsig")]
impl<K: AsRef<str>, V, W: structured_asn1::memory::Work> Names<K, V, super::Accounted<'_, W>>
    for structured_asn1::memory::OwnedMap<Name<K>, V, W>
{
    fn len(&self) -> usize {
        structured_asn1::memory::OwnedMap::len(self)
    }
    fn get(&self, name: &str, storage: super::Accounted<'_, W>) -> Result<Option<&V>, ParseError> {
        Ok(self
            .get_key_value_borrowed(name, storage.0)?
            .map(|(_, value)| value))
    }
    fn get_mut(
        &mut self,
        name: &str,
        storage: super::Accounted<'_, W>,
    ) -> Result<Option<&mut V>, ParseError> {
        Ok(self.get_mut_borrowed(name, storage.0)?)
    }
    fn insert(&mut self, name: K, value: V) -> Result<Option<V>, ParseError> {
        Ok(self.try_insert(Name(name), value)?)
    }
    fn remove(
        &mut self,
        name: &str,
        storage: super::Accounted<'_, W>,
    ) -> Result<Option<V>, ParseError> {
        Ok(self.remove_borrowed(name, storage.0)?)
    }
    #[cfg(feature = "xml-backend-xmloxide")]
    fn entries<'a>(
        &'a self,
        storage: super::Accounted<'_, W>,
    ) -> Result<impl Iterator<Item = (&'a K, &'a V)> + 'a, ParseError>
    where
        K: 'a,
        V: 'a,
    {
        Ok(self
            .try_iter(storage.0)?
            .map(|(key, value)| (&key.0, value)))
    }
    #[cfg(feature = "xml-backend-xmloxide")]
    fn key_value(
        &self,
        name: &str,
        storage: super::Accounted<'_, W>,
    ) -> Result<Option<(&K, &V)>, ParseError> {
        Ok(self
            .get_key_value_borrowed(name, storage.0)?
            .map(|(key, value)| (&key.0, value)))
    }
}
