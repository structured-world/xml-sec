//! Lookup tables keyed by document content.
//!
//! With `std` these are randomly seeded hash tables. Without `std` there is no
//! seed source, and an unseeded hash table lets a document force collisions,
//! so ordered trees take their place.

use alloc::collections::TryReserveError;
#[cfg(all(not(feature = "std"), any(feature = "xmldsig", test)))]
pub(crate) use alloc::collections::btree_map::Entry;
#[cfg(not(feature = "std"))]
pub(crate) use alloc::collections::{BTreeMap as Map, BTreeSet as Set};
#[cfg(all(not(feature = "std"), feature = "xmldsig"))]
pub(crate) use alloc::collections::{btree_map as map, btree_set as set};
#[cfg(all(feature = "std", any(feature = "xmldsig", test)))]
pub(crate) use std::collections::hash_map::Entry;
#[cfg(all(feature = "std", feature = "xmldsig"))]
pub(crate) use std::collections::{hash_map as map, hash_set as set};

/// Builds the hasher of one content-keyed table.
///
/// A document controls the strings these tables hash and chooses which arena
/// identities they hold. Each table gets its own random seed: integer words,
/// which most keys are (a document identity and a slot), take a seeded integer
/// mix, and strings and every word after one take the keyed `SipHash`, so a
/// document can predict where neither lands.
#[cfg(feature = "std")]
pub(crate) type SeededState = structured_asn1::hash::RandomState;

/// A hash table keyed by document content.
#[cfg(feature = "std")]
pub(crate) type Map<K, V> = std::collections::HashMap<K, V, SeededState>;
/// A hash set keyed by document content.
#[cfg(feature = "std")]
pub(crate) type Set<T> = std::collections::HashSet<T, SeededState>;

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
        Self::with_capacity_and_hasher(capacity, SeededState::default())
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
        Self::with_capacity_and_hasher(capacity, SeededState::default())
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

#[cfg(all(test, feature = "std"))]
mod tests;
