use super::SeededState;
use core::hash::BuildHasher;

/// Distinct values among `bits` low bits of the hashes of `keys`.
fn distinct_low_bits(state: &SeededState, keys: impl Iterator<Item = u64>, bits: u32) -> usize {
    let mask = (1_u64 << bits) - 1;
    keys.map(|key| state.hash_one(key) & mask)
        .collect::<std::collections::BTreeSet<_>>()
        .len()
}

#[test]
fn equal_keys_hash_equally_within_a_table() {
    // A table finds a key only if every hash of it agrees, for integer words,
    // strings and the node-shaped tuples the XPath engine stores.
    let state = SeededState::default();
    assert_eq!(state.hash_one(42_u64), state.hash_one(42_u64));
    assert_eq!(state.hash_one("prefix"), state.hash_one("prefix"));
    assert_eq!(
        state.hash_one((7_usize, 3_u8, 1024_usize)),
        state.hash_one((7_usize, 3_u8, 1024_usize))
    );
    assert_ne!(state.hash_one("ab"), state.hash_one("ba"));
    assert_ne!(state.hash_one(("a", "bc")), state.hash_one(("ab", "c")));
}

#[test]
fn strided_identities_spread_across_buckets() {
    // A stylesheet can select every 2^k-th node, so slot indices sharing low
    // zero bits must still reach distinct buckets. 4096 keys over 4096
    // buckets fill about 63% when hashing is uniform.
    let state = SeededState::default();
    for stride in [1_u64, 1 << 8, 1 << 16, 1 << 32] {
        let distinct = distinct_low_bits(&state, (0..4096).map(|key| key * stride), 12);
        assert!(distinct > 2400, "stride {stride}: {distinct} buckets");
    }
    // hashbrown reads the top seven bits as the control byte.
    let control = (0..4096_u64)
        .map(|key| state.hash_one(key << 20) >> 57)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(control.len(), 128);
}

#[test]
fn tables_are_seeded_independently() {
    // A document cannot carry collisions computed for one table to another.
    let first = SeededState::default();
    let second = SeededState::default();
    assert_ne!(first.hash_one(1_u64), second.hash_one(1_u64));
    assert_ne!(first.hash_one("namespace"), second.hash_one("namespace"));
}
