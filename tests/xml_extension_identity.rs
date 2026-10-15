#![cfg(feature = "xmldsig")]

use std::{
    hash::{Hash, Hasher},
    sync::Arc,
};
use structured_asn1::memory::{HashWork, Memory, MemoryAccount, MemoryError};
use xml_sec::document::XmlDocument;

#[derive(Default)]
struct HashCost {
    bytes: u64,
    calls: u64,
}

impl Hasher for HashCost {
    fn finish(&self) -> u64 {
        0
    }
    fn write(&mut self, bytes: &[u8]) {
        self.bytes += bytes.len() as u64;
        self.calls += 1;
    }
}

#[test]
fn original_node_identity_hash_bound_covers_derived_field_traversal() {
    // Field widths, not struct padding or a phase-local ordinal, determine the
    // scan bound. This catches added fields and changes to derived Hash.
    let document = XmlDocument::parse("<root Id=\"root\"/>").unwrap();
    let identity = document.with_view(|view| view.node_for_id("root", &[]).unwrap());
    let mut actual = HashCost::default();
    identity.hash(&mut actual);
    assert_eq!(identity.hash_work().unwrap(), actual.bytes + actual.calls);
    assert_eq!(actual.bytes, 20);
    assert_eq!(actual.calls, 3);
}

#[test]
fn accounted_identity_map_preserves_document_provenance() {
    // Equal semantic ordinals in different documents cannot collapse into one
    // authenticated-reference entry; storage growth remains fallible.
    let first = XmlDocument::parse("<root Id=\"root\"/>").unwrap();
    let second = XmlDocument::parse("<root Id=\"root\"/>").unwrap();
    let a = first.with_view(|view| view.node_for_id("root", &[]).unwrap());
    let b = second.with_view(|view| view.node_for_id("root", &[]).unwrap());
    let work = Memory::new(Arc::new(MemoryAccount::new(4096, 10000)));
    let mut map = work.map();
    assert_eq!(map.try_insert(a, 0).unwrap(), None);
    assert_eq!(map.get(&a, &work).unwrap(), Some(&0));
    assert_eq!(map.get(&b, &work).unwrap(), None);
    assert_eq!(map.try_insert(b, 1).unwrap(), None);
    assert_eq!(map.get(&b, &work).unwrap(), Some(&1));
    let denied = Memory::new(Arc::new(MemoryAccount::new(0, 10000)));
    let mut map = denied.map();
    assert!(matches!(
        map.try_insert(a, 0),
        Err(MemoryError::LimitExceeded)
    ));
}
