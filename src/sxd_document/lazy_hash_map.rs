use core::borrow::Borrow;

use crate::collections::{Key, Map, map};

pub struct LazyHashMap<K, V> {
    map: Option<Map<K, V>>,
}

impl<K, V> LazyHashMap<K, V>
where
    K: Key,
{
    pub fn new() -> LazyHashMap<K, V> {
        LazyHashMap { map: None }
    }

    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Key + ?Sized,
    {
        self.map.as_ref().is_some_and(|m| m.contains_key(key))
    }

    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Key + ?Sized,
    {
        self.map.as_ref().and_then(|m| m.get(key))
    }

    pub fn insert(&mut self, key: K, val: V) -> Option<V> {
        self.map = match self.map.take() {
            Some(m) => Some(m),
            None => Some(Map::new()),
        };

        self.map.as_mut().and_then(|m| m.insert(key, val))
    }

    pub fn iter(&self) -> Iter<'_, K, V> {
        Iter(self.map.as_ref().map(|m| m.iter()))
    }

    #[cfg(feature = "embedded")]
    pub fn capacity(&self) -> usize {
        self.map
            .as_ref()
            .map_or(0, crate::collections::Table::entry_capacity)
    }
}

pub struct Iter<'a, K, V>(Option<map::Iter<'a, K, V>>);

impl<'a, K: 'a, V: 'a> Iterator for Iter<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        self.0.as_mut().and_then(Iterator::next)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.as_ref().map_or((0, Some(0)), Iterator::size_hint)
    }
}
