//! The public key of an imported private key, as a key-data reader that
//! holds only the private key needs it.

use pkcs8::DecodePublicKey as _;

use super::{KeyInventory, KeyUsages};
use crate::policy::ResourcePolicy;

#[test]
fn a_private_key_yields_the_spki_of_its_public_key() {
    // A loaded private key must verify what it signs and write the same
    // KeyValue as its public key file; each family's derived SPKI is the
    // fixture public key's DER.
    for (private, public) in [
        (
            include_str!("../../tests/fixtures/keys/rsa/rsa-2048-key.pem"),
            include_str!("../../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"),
        ),
        (
            include_str!("../../tests/fixtures/keys/ec/ec-prime256v1-key.pem"),
            include_str!("../../tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem"),
        ),
        (
            include_str!("../../tests/fixtures/keys/ec/ec-prime384v1-key.pem"),
            include_str!("../../tests/fixtures/keys/ec/ec-prime384v1-pubkey.pem"),
        ),
    ] {
        let mut inventory = KeyInventory::default();
        inventory
            .add_private_pem(
                "key",
                private.as_bytes(),
                None,
                KeyUsages::SIGN,
                &ResourcePolicy::default(),
            )
            .expect("private key fixture");
        let expected = pkcs8::Document::from_public_key_pem(public).expect("public key fixture");
        assert_eq!(
            inventory.private_keys()[0]
                .public_key_spki_der()
                .expect("derivable public key"),
            expected.as_bytes()
        );
    }
}
