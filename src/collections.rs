//! Lookup tables keyed by document content.
//!
//! With `std` these are randomly seeded hash tables. Without `std` there is no
//! seed source, and an unseeded hash table lets a document force collisions,
//! so ordered trees take their place.

use alloc::collections::TryReserveError;
#[cfg(not(feature = "std"))]
pub(crate) use alloc::collections::{BTreeMap as Map, BTreeSet as Set, btree_map::Entry};
#[cfg(all(not(feature = "std"), feature = "xmldsig"))]
pub(crate) use alloc::collections::{btree_map as map, btree_set as set};
#[cfg(feature = "std")]
pub(crate) use std::collections::{HashMap as Map, HashSet as Set, hash_map::Entry};
#[cfg(all(feature = "std", feature = "xmldsig"))]
pub(crate) use std::collections::{hash_map as map, hash_set as set};

/// What [`Map`] and [`Set`] require of their keys in this build.
#[cfg(feature = "std")]
pub(crate) trait Key: core::hash::Hash + Eq {}
#[cfg(feature = "std")]
impl<T: core::hash::Hash + Eq + ?Sized> Key for T {}
/// What [`Map`] and [`Set`] require of their keys in this build.
#[cfg(not(feature = "std"))]
pub(crate) trait Key: Ord {}
#[cfg(not(feature = "std"))]
impl<T: Ord + ?Sized> Key for T {}

/// Capacity management that both table kinds accept.
pub(crate) trait Table: Sized {
    /// An empty table with room for `capacity` entries where the kind supports it.
    fn with_entry_capacity(capacity: usize) -> Self;

    /// Reserves room for `additional` entries where the kind supports it. Tree
    /// nodes are allocated per insertion, so trees have nothing to reserve.
    fn try_reserve_entries(&mut self, additional: usize) -> Result<(), TryReserveError>;

    /// Entries the table holds storage for: allocated slots of a hash table,
    /// stored entries of a tree.
    #[cfg(feature = "xmldsig")]
    fn entry_capacity(&self) -> usize;
}

#[cfg(feature = "std")]
impl<K: Key, V> Table for Map<K, V> {
    fn with_entry_capacity(capacity: usize) -> Self {
        Self::with_capacity(capacity)
    }

    fn try_reserve_entries(&mut self, additional: usize) -> Result<(), TryReserveError> {
        self.try_reserve(additional)
    }

    #[cfg(feature = "xmldsig")]
    fn entry_capacity(&self) -> usize {
        self.capacity()
    }
}

#[cfg(feature = "std")]
impl<T: Key> Table for Set<T> {
    fn with_entry_capacity(capacity: usize) -> Self {
        Self::with_capacity(capacity)
    }

    fn try_reserve_entries(&mut self, additional: usize) -> Result<(), TryReserveError> {
        self.try_reserve(additional)
    }

    #[cfg(feature = "xmldsig")]
    fn entry_capacity(&self) -> usize {
        self.capacity()
    }
}

#[cfg(not(feature = "std"))]
impl<K: Key, V> Table for Map<K, V> {
    fn with_entry_capacity(_capacity: usize) -> Self {
        Self::new()
    }

    fn try_reserve_entries(&mut self, _additional: usize) -> Result<(), TryReserveError> {
        Ok(())
    }

    #[cfg(feature = "xmldsig")]
    fn entry_capacity(&self) -> usize {
        self.len()
    }
}

#[cfg(not(feature = "std"))]
impl<T: Key> Table for Set<T> {
    fn with_entry_capacity(_capacity: usize) -> Self {
        Self::new()
    }

    fn try_reserve_entries(&mut self, _additional: usize) -> Result<(), TryReserveError> {
        Ok(())
    }

    #[cfg(feature = "xmldsig")]
    fn entry_capacity(&self) -> usize {
        self.len()
    }
}
