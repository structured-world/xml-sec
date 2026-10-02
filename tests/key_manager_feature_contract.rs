#![cfg(feature = "xmlenc")]

use xml_sec::key_manager::KeyInventory;

#[test]
fn xmlenc_feature_exposes_key_inventory() {
    // A consumer selecting the XML Encryption feature can compile the shared
    // inventory API without separately naming the XMLDSig feature.
    let inventory = KeyInventory::default();
    assert_eq!(inventory.entry_count(), 0);
}
