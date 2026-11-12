//! `KeyValueInfo` conversions to and from `SubjectPublicKeyInfo`, the
//! integration surface key-data readers outside the core build on.

use pkcs8::DecodePublicKey as _;

use super::{KeyResolutionError, KeyValueInfo};
use crate::policy::ResourcePolicy;

/// The DER of a PEM `PUBLIC KEY` fixture.
fn spki(pem: &str) -> Vec<u8> {
    pkcs8::Document::from_public_key_pem(pem)
        .expect("public key fixture")
        .as_bytes()
        .to_vec()
}

#[test]
fn every_supported_spki_round_trips_through_its_key_value() {
    // A reader writes RSAKeyValue, ECKeyValue or DSAKeyValue from a stored
    // SPKI and reads it back: the components must reproduce the same SPKI,
    // or a key written to XML would not be the key that was stored.
    for pem in [
        include_str!("../../../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"),
        include_str!("../../../tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem"),
        include_str!("../../../tests/fixtures/keys/ec/ec-prime384v1-pubkey.pem"),
        include_str!("../../../tests/fixtures/keys/ec/ec-prime521v1-pubkey.pem"),
        include_str!("../../../tests/fixtures/keys/dsa/dsa-2048-public.pem"),
    ] {
        let original = spki(pem);
        let value = KeyValueInfo::from_spki_der(&original, &ResourcePolicy::default())
            .expect("supported SPKI");
        assert_eq!(value.to_spki_der().expect("valid components"), original);
    }
}

#[test]
fn key_value_families_without_an_spki_are_refused() {
    // DSA without its domain parameters, DH and unsupported elements carry
    // no complete public key; reporting one would invent key material.
    let refused = [
        KeyValueInfo::Dsa {
            p: None,
            q: None,
            g: None,
            y: vec![5],
        },
        KeyValueInfo::Dh {
            p: None,
            q: None,
            generator: None,
            public: vec![5],
            seed: None,
            pgen_counter: None,
        },
        KeyValueInfo::InvalidEcKeyValue,
        KeyValueInfo::Unsupported {
            namespace: None,
            local_name: "Other".into(),
        },
        // An even modulus is no RSA key (RFC 8017 section 3.1).
        KeyValueInfo::Rsa {
            modulus: vec![0xc4],
            exponent: vec![3],
        },
    ];
    for value in refused {
        assert!(matches!(
            value.to_spki_der(),
            Err(KeyResolutionError::InvalidPublicKey)
        ));
    }
}

#[test]
fn a_pss_restricted_rsa_key_has_no_key_value() {
    // An id-RSASSA-PSS key admits only PSS (RFC 4055 section 1.2), which
    // RSAKeyValue cannot express: converting it would yield an unrestricted
    // rsaEncryption key.
    use der::{Decode as _, Encode as _};
    let rsa = spki(include_str!(
        "../../../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"
    ));
    let info = pkcs8::spki::SubjectPublicKeyInfoRef::from_der(&rsa).expect("an RSA SPKI");
    let pss = pkcs8::spki::SubjectPublicKeyInfoRef {
        algorithm: pkcs8::spki::AlgorithmIdentifierRef {
            oid: der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10"),
            parameters: None,
        },
        subject_public_key: info.subject_public_key,
    }
    .to_der()
    .expect("a PSS SPKI");
    assert!(matches!(
        KeyValueInfo::from_spki_der(&pss, &ResourcePolicy::default()),
        Err(KeyResolutionError::AlgorithmMismatch)
    ));
}

#[test]
fn an_spki_of_another_family_or_malformed_is_no_key_value() {
    // Ed25519 has no XMLDSig KeyValue form; garbage is no SPKI at all.
    let ed25519 = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0x19, 0xbf, 0x44,
        0x09, 0x69, 0x84, 0xcd, 0xfe, 0x85, 0x41, 0xba, 0xc1, 0x67, 0xdc, 0x3b, 0x96, 0xc8, 0x50,
        0x86, 0xaa, 0x30, 0xb6, 0xb6, 0xcb, 0x0c, 0x5c, 0x38, 0xad, 0x70, 0x31, 0x66, 0xe1,
    ];
    for bytes in [&ed25519[..], &[0x30, 0x00][..], &[][..]] {
        assert!(matches!(
            KeyValueInfo::from_spki_der(bytes, &ResourcePolicy::default()),
            Err(KeyResolutionError::InvalidPublicKey)
        ));
    }
}
