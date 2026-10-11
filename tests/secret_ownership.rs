//! Owned encryption secrets must be wiped; borrowed material remains caller-owned.

#![cfg(feature = "xmlenc")]

use xml_sec::xmlenc::{EncryptionRecipient, KekDecryptor, KeyWrapAlgorithm, SymmetricKeyDecryptor};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[test]
fn secret_owners_have_a_drop_wipe_contract() {
    // Compile-time assurance avoids observing freed memory (which would be UB).
    fn require_drop_wipe<T: ZeroizeOnDrop>() {}
    require_drop_wipe::<EncryptionRecipient>();
    require_drop_wipe::<SymmetricKeyDecryptor>();
    require_drop_wipe::<KekDecryptor<'static>>();
}

#[test]
fn recipient_wipes_owned_material_without_wiping_its_clone() {
    // Each explicit clone owns an independent secret and must wipe independently.
    let mut recipient =
        EncryptionRecipient::aes_key_wrap(vec![0x73; 32], KeyWrapAlgorithm::AesKw256);
    let clone = recipient.clone();
    recipient.zeroize();
    let EncryptionRecipient::AesKeyWrap { kek, .. } = &recipient else {
        panic!("expected a KEK recipient");
    };
    assert!(kek.is_empty());
    let EncryptionRecipient::AesKeyWrap { kek, .. } = &clone else {
        panic!("expected a KEK recipient");
    };
    assert_eq!(kek, &[0x73; 32]);
    assert!(format!("{clone:?}").contains("[REDACTED]"));
}

#[test]
fn borrowed_kek_wipe_does_not_modify_caller_material() {
    // A resolver must not clear a shared slice or allocate a secret copy to clear.
    let bytes = [0x81; 32];
    let mut resolver = KekDecryptor::borrowed(&bytes);
    resolver.zeroize();
    assert_eq!(bytes, [0x81; 32]);
    assert!(format!("{resolver:?}").contains("[REDACTED]"));
}
