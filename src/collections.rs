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
#[cfg(feature = "std")]
use core::hash::{BuildHasher, Hasher};
#[cfg(all(feature = "std", any(feature = "xmldsig", test)))]
pub(crate) use std::collections::hash_map::Entry;
#[cfg(all(feature = "std", feature = "xmldsig"))]
pub(crate) use std::collections::{hash_map as map, hash_set as set};

/// A hash table keyed by document content.
#[cfg(feature = "std")]
pub(crate) type Map<K, V> = std::collections::HashMap<K, V, SeededState>;
/// A hash set keyed by document content.
#[cfg(feature = "std")]
pub(crate) type Set<T> = std::collections::HashSet<T, SeededState>;

/// Builds the hasher of one content-keyed table.
///
/// A document controls the strings these tables hash and chooses which arena
/// identities they hold. Strings go through the standard randomly keyed
/// `SipHash`; integer words, which most keys are (a document identity and a
/// slot), are mixed by a folded multiply under a random odd seed. Neither lets
/// a document predict where its keys land, and an identity costs a few
/// multiplications instead of a `SipHash`.
///
/// `pub` only because public storage traits name these tables in associated
/// types; this module is private, so nothing outside the crate can name it.
#[cfg(feature = "std")]
#[derive(Clone)]
pub struct SeededState {
    strings: std::hash::RandomState,
    seed: u64,
}

#[cfg(feature = "std")]
impl Default for SeededState {
    fn default() -> Self {
        let strings = std::hash::RandomState::new();
        // The keyed SipHash of a constant is as unpredictable as its keys.
        let seed = strings.hash_one(0x5eed_u64) | 1;
        Self { strings, seed }
    }
}

#[cfg(feature = "std")]
impl BuildHasher for SeededState {
    type Hasher = SeededHasher;

    #[inline]
    fn build_hasher(&self) -> SeededHasher {
        SeededHasher {
            state: self.seed,
            seed: self.seed,
            keys: self.strings.clone(),
            strings: None,
        }
    }
}

/// The hasher of [`SeededState`].
#[cfg(feature = "std")]
pub struct SeededHasher {
    state: u64,
    seed: u64,
    keys: std::hash::RandomState,
    /// Started at the first byte string written, with the words before it.
    /// Every later word goes into it in order: a string's length or end mark
    /// mixed apart from its bytes would let `("a", "bc")` equal `("ab", "c")`.
    strings: Option<std::hash::DefaultHasher>,
}

/// The 128-bit product folded to 64 bits: every input bit reaches the low
/// bits that select a bucket.
#[cfg(feature = "std")]
#[inline]
fn folded_multiply(x: u64, y: u64) -> u64 {
    let (low, high) = halves(u128::from(x) * u128::from(y));
    low ^ high
}

/// The low and high 64 bits of `word`.
#[cfg(feature = "std")]
#[inline]
fn halves(word: u128) -> (u64, u64) {
    // Both halves fit by construction; the checks fold away.
    let low = u64::try_from(word & u128::from(u64::MAX)).expect("masked to 64 bits");
    let high = u64::try_from(word >> 64).expect("shifted to 64 bits");
    (low, high)
}

#[cfg(feature = "std")]
impl Hasher for SeededHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let (keys, state) = (&self.keys, self.state);
        self.strings
            .get_or_insert_with(|| {
                let mut strings = keys.build_hasher();
                strings.write_u64(state);
                strings
            })
            .write(bytes);
    }

    #[inline]
    fn write_u8(&mut self, word: u8) {
        self.write_u64(u64::from(word));
    }

    #[inline]
    fn write_u16(&mut self, word: u16) {
        self.write_u64(u64::from(word));
    }

    #[inline]
    fn write_u32(&mut self, word: u32) {
        self.write_u64(u64::from(word));
    }

    #[inline]
    fn write_u64(&mut self, word: u64) {
        match &mut self.strings {
            None => self.state = folded_multiply(self.state ^ word, self.seed),
            Some(strings) => strings.write_u64(word),
        }
    }

    #[inline]
    fn write_u128(&mut self, word: u128) {
        let (low, high) = halves(word);
        self.write_u64(low);
        self.write_u64(high);
    }

    #[inline]
    fn write_usize(&mut self, word: usize) {
        self.write_u64(word as u64);
    }

    #[inline]
    fn write_i8(&mut self, word: i8) {
        self.write_u8(word.cast_unsigned());
    }

    #[inline]
    fn write_i16(&mut self, word: i16) {
        self.write_u16(word.cast_unsigned());
    }

    #[inline]
    fn write_i32(&mut self, word: i32) {
        self.write_u32(word.cast_unsigned());
    }

    #[inline]
    fn write_i64(&mut self, word: i64) {
        self.write_u64(word.cast_unsigned());
    }

    #[inline]
    fn write_i128(&mut self, word: i128) {
        self.write_u128(word.cast_unsigned());
    }

    #[inline]
    fn write_isize(&mut self, word: isize) {
        self.write_usize(word.cast_unsigned());
    }

    #[inline]
    fn finish(&self) -> u64 {
        let state = match &self.strings {
            Some(strings) => strings.finish(),
            None => self.state,
        };
        folded_multiply(state, self.seed.rotate_left(32) | 1)
    }
}

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
