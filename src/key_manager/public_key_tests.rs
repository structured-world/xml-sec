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

#[test]
fn dsa_and_eddsa_private_keys_yield_the_spki_of_their_public_keys() {
    // DSA derives its SPKI through its own encoder and EdDSA reuses the
    // PKCS#8 algorithm identifier: each must give the fixture public key.
    let cases: [(&[u8], bool, &str); 3] = [
        (
            include_bytes!("../../tests/fixtures/xmldsig/keys/dsa/dsa-1024-key.p8-der"),
            false,
            include_str!("../../tests/fixtures/xmldsig/keys/dsa/dsa-1024-pubkey.pem"),
        ),
        (
            include_bytes!("../../tests/fixtures/xmldsig/keys/eddsa/eddsa-ed25519-key.pem"),
            true,
            include_str!("../../tests/fixtures/xmldsig/keys/eddsa/eddsa-ed25519-pubkey.pem"),
        ),
        (
            include_bytes!("../../tests/fixtures/xmldsig/keys/eddsa/eddsa-ed448-key.pem"),
            true,
            include_str!("../../tests/fixtures/xmldsig/keys/eddsa/eddsa-ed448-pubkey.pem"),
        ),
    ];
    for (private, pem, public) in cases {
        let mut inventory = KeyInventory::default();
        let resources = ResourcePolicy::default();
        let added = if pem {
            inventory.add_private_pem("key", private, None, KeyUsages::SIGN, &resources)
        } else {
            // The donor's PKCS#8 DER fixture is encrypted under "secret123".
            inventory.add_private_der(
                "key".into(),
                private,
                Some(b"secret123"),
                KeyUsages::SIGN,
                &resources,
            )
        };
        added.expect("private key fixture");
        let expected = pkcs8::Document::from_public_key_pem(public).expect("public key fixture");
        assert_eq!(
            inventory.private_keys()[0]
                .public_key_spki_der()
                .expect("derivable public key"),
            expected.as_bytes()
        );
    }
}
