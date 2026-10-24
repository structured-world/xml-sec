use super::*;
use aes::cipher::BlockModeEncrypt as _;

fn encoded(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if value.len() < 128 {
        out.push(u8::try_from(value.len()).expect("short test encoding"));
    } else {
        out.push(0x82);
        out.extend_from_slice(
            &u16::try_from(value.len())
                .expect("test payload fits two length octets")
                .to_be_bytes(),
        );
    }
    out.extend_from_slice(value);
    out
}
fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    encoded(0x30, &parts.concat())
}
fn oid(value: Oid) -> Vec<u8> {
    encoded(6, value.as_bytes())
}
fn integer(value: u16) -> Vec<u8> {
    let mut bytes = value.to_be_bytes().to_vec();
    if bytes[0] == 0 && bytes[1] < 128 {
        bytes.remove(0);
    } else if bytes[0] & 128 != 0 {
        bytes.insert(0, 0);
    }
    encoded(2, &bytes)
}
fn bag(kind: Oid, value: &[u8]) -> Vec<u8> {
    sequence(&[oid(kind), encoded(0xa0, value)])
}
fn data(safe: &[u8]) -> Vec<u8> {
    sequence(&[oid(DATA), encoded(0xa0, &encoded(4, safe))])
}
fn pfx(infos: &[Vec<u8>]) -> Vec<u8> {
    sequence(&[integer(3), data(&sequence(infos))])
}
fn limits(candidates: usize) -> Limits {
    Limits {
        resources: ResourcePolicy::default(),
        candidates,
        memory_available: ResourcePolicy::default().max_external_resource_total_bytes,
    }
}

#[test]
fn legacy_password_format_is_bmp_not_utf16() {
    // RFC 7292 B.1 is shared by legacy MAC and encryption derivation;
    // surrogate-pair interoperability must not silently replace BMPString.
    let limits = limits(64);
    let mut budget = Budget::new(&limits);
    let mut password = Password {
        utf8: "p\u{ffff}",
        bmp: None,
    };
    assert_eq!(
        password.bmp(&mut budget).expect("BMP password"),
        &[0, b'p', 255, 255, 0, 0]
    );
    let mut password = Password {
        utf8: "secret\u{1f512}",
        bmp: None,
    };
    let before = budget.memory;
    assert!(matches!(
        password.bmp(&mut budget),
        Err(KeyStoreError::ProtectedContainer)
    ));
    assert_eq!(budget.memory, before, "reject before allocating conversion");
    assert!(password.bmp.is_none());
}

#[test]
fn ciphertext_capacity_is_checked_before_password_derivation() {
    // An already-live callback buffer must stop both PBES2 and legacy KDF
    // paths before any password preprocessing or BMP conversion.
    for hash in [Some(Hash::Sha1), None] {
        let mut limits = limits(64);
        limits.memory_available = 31;
        let mut budget = Budget::new(&limits);
        budget.allocate(16).expect("live password capacity");
        let mut password = Password {
            utf8: "password",
            bmp: None,
        };
        let encryption = Encryption {
            cipher: if hash.is_some() {
                Cipher::Aes128
            } else {
                Cipher::TripleDes
            },
            salt: Bytes::Borrowed(b"salt"),
            rounds: 2,
            hash,
            iv: [0; 16],
        };
        assert!(matches!(
            encryption.decrypt(&[0; 16], &mut password, &mut budget),
            Err(KeyStoreError::Policy(_))
        ));
        assert_eq!(budget.work, 0, "no password hashing before memory denial");
        assert!(
            password.bmp.is_none(),
            "no lazy BMP allocation before denial"
        );
    }
}

#[test]
fn ber_private_key_info_is_normalized_before_storage() {
    // KeyBag inherits the PFX BER contract; an indefinite SEQUENCE and
    // constructed OCTET STRING must reach the DER-only key decoder intact.
    let der = sequence(&[
        integer(0),
        sequence(&[
            oid(pkcs8::spki::ObjectIdentifier::new_unwrap(
                "1.2.840.113549.1.1.1",
            )),
            encoded(5, &[]),
        ]),
        encoded(4, b"private"),
    ]);
    let mut ber = vec![0x30, 0x80];
    ber.extend(integer(0));
    ber.extend(sequence(&[
        oid(Oid::new_unwrap("1.2.840.113549.1.1.1")),
        encoded(5, &[]),
    ]));
    ber.extend([
        0x24, 0x80, 4, 3, b'p', b'r', b'i', 4, 4, b'v', b'a', b't', b'e', 0, 0, 0, 0,
    ]);
    let bytes = pfx(&[data(&sequence(&[bag(pkcs12::PKCS_12_KEY_BAG_OID, &ber)]))]);
    let limits = limits(64);
    let imported = prepare(&bytes, &limits)
        .expect("BER preflight")
        .decrypt("secret")
        .expect("BER key import");
    assert_eq!(&*imported.private_keys[0], &der);
    let mut tight = limits;
    tight.memory_available = der.len() - 1;
    let mut budget = Budget::new(&tight);
    assert!(matches!(
        normalize_private_key(&ber, &mut budget),
        Err(KeyStoreError::Policy(_))
    ));
    assert_eq!(budget.memory, 0, "denial precedes output allocation");
}

#[cfg(feature = "experimental-pq")]
#[test]
fn kem_key_bag_reaches_public_inventory() {
    // The full PFX entry point must infer decapsulation-only usage, not
    // reject a valid ML-KEM bag because it inherited signing usage.
    let key = crate::provider::RustCryptoMlKemPrivateKey::from_seed(
        crate::provider::KeyEncapsulationAlgorithm::MlKem512,
        &[3; 64],
    )
    .expect("valid ML-KEM seed");
    let private = key
        .to_pkcs8_der(crate::provider::MlKemPrivateKeyEncoding::Seed)
        .expect("seed PKCS#8 export");
    let bytes = pfx(&[data(&sequence(&[bag(
        pkcs12::PKCS_12_KEY_BAG_OID,
        private.as_bytes(),
    )]))]);
    let mut inventory = crate::key_manager::KeyInventory::default();
    inventory
        .add_pkcs12(
            "recipient".into(),
            &bytes,
            "secret",
            &ResourcePolicy::default(),
        )
        .expect("ML-KEM PKCS#12 import");
    assert_eq!(
        inventory.private_keys()[0].usages,
        crate::key_manager::KeyUsages::DECRYPT
    );
}

#[test]
fn ber_key_bag_reaches_public_inventory() {
    // Public import must normalize the actual key, not merely accept BER
    // framing in preflight and fail in the later PKCS#8 decoder.
    let private = pem::parse(include_bytes!(
        "../../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
    ))
    .expect("PKCS#8 fixture")
    .into_contents();
    let sequence_value = tlv(&private, 0).expect("PrivateKeyInfo sequence").0;
    let mut ber = vec![0x30, 0x80];
    ber.extend_from_slice(sequence_value.value);
    ber.extend_from_slice(&[0, 0]);
    let bytes = pfx(&[data(&sequence(&[bag(pkcs12::PKCS_12_KEY_BAG_OID, &ber)]))]);
    let mut inventory = crate::key_manager::KeyInventory::default();
    inventory
        .add_pkcs12(
            "signer".into(),
            &bytes,
            "secret",
            &ResourcePolicy::default(),
        )
        .expect("public BER import");
    assert_eq!(inventory.private_keys().len(), 1);
}

#[test]
fn encrypted_data_version_tracks_unprotected_attributes() {
    // CMS version 2 is required exactly when [1] attributes are present.
    // Validate them before password processing, including malformed tails.
    let algorithm = sequence(&[
        oid(pkcs12::PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC),
        sequence(&[encoded(4, b"12345678"), integer(2)]),
    ]);
    let info = sequence(&[oid(DATA), algorithm, encoded(0x80, &[0; 8])]);
    let attribute = sequence(&[
        oid(Oid::new_unwrap("1.2.3.4")),
        encoded(0x31, &encoded(4, b"value")),
    ]);
    // RFC 5652 5.3 constrains the outer attribute collection, not the
    // generic Attribute.attrValues SET OF. Empty unknown values are valid.
    let empty_values = sequence(&[oid(Oid::new_unwrap("1.2.3.4")), encoded(0x31, &[])]);
    for (version, attrs, accepted) in [
        (0, None, true),
        (2, Some(attribute.clone()), true),
        (2, Some(empty_values), true),
        (0, Some(attribute), false),
        (2, None, false),
        (2, Some(Vec::new()), false),
        (2, Some(vec![0xff]), false),
    ] {
        let mut parts = vec![integer(version), info.clone()];
        if let Some(attrs) = attrs {
            parts.push(encoded(0xa1, &attrs));
        }
        let limits = limits(64);
        let mut budget = Budget::new(&limits);
        let bytes = sequence(&parts);
        assert_eq!(
            encrypted_content(
                tlv(&bytes, 0).expect("EncryptedData sequence").0,
                &mut budget
            )
            .is_ok(),
            accepted,
            "version {version}"
        );
    }
}

#[test]
fn unsupported_algorithms_are_distinct_from_bad_passwords() {
    // Unsupported capabilities must fail during preflight, rather than
    // suggesting that a password was tried and could not decode the key.
    let unsupported = Oid::new_unwrap("1.2.840.113549.1.12.1.6");
    for hmac in [false, true] {
        assert!(matches!(
            Hash::from_oid(unsupported, hmac),
            Err(KeyStoreError::Selection(_))
        ));
    }
    let derivation = sequence(&[encoded(4, b"salt"), integer(2)]);
    for algorithm in [
        sequence(&[oid(unsupported), derivation.clone()]),
        sequence(&[
            oid(PBES2),
            sequence(&[
                sequence(&[oid(PBKDF2), derivation.clone()]),
                sequence(&[oid(unsupported), encoded(4, &[0; 16])]),
            ]),
        ]),
        sequence(&[
            oid(PBES2),
            sequence(&[
                sequence(&[oid(unsupported), derivation]),
                sequence(&[
                    oid(pkcs8::pkcs5::pbes2::AES_128_CBC_OID),
                    encoded(4, &[0; 16]),
                ]),
            ]),
        ]),
    ] {
        let bytes = pfx(&[data(&sequence(&[bag(
            pkcs12::PKCS_12_PKCS8_KEY_BAG_OID,
            &sequence(&[algorithm, encoded(4, &[0; 16])]),
        )]))]);
        assert!(matches!(
            prepare(&bytes, &limits(64)),
            Err(KeyStoreError::Selection(_))
        ));
    }
}

#[test]
fn high_tag_attributes_are_valid_ber() {
    // Unknown attributes are ignorable, but their high-number identifiers
    // must remain well framed for primitive, constructed and indefinite BER.
    for value in [
        vec![0x9f, 31, 1, 7],
        vec![0xbf, 0x81, 0, 2, 4, 0],
        vec![0xbf, 31, 0x80, 4, 0, 0, 0],
        vec![
            0x9f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0,
        ],
    ] {
        let key = sequence(&[
            oid(pkcs12::PKCS_12_KEY_BAG_OID),
            encoded(0xa0, &[0x30, 0]),
            encoded(
                0x31,
                &sequence(&[oid(Oid::new_unwrap("1.2.3.4")), encoded(0x31, &value)]),
            ),
        ]);
        assert!(prepare(&pfx(&[data(&sequence(&[key]))]), &limits(64)).is_ok());
    }
    for value in [
        &[0x9f, 0, 0][..],
        &[0x9f, 0x80, 31, 0],
        &[0x9f, 30, 0],
        &[0x9f, 0x81],
        &[0x9f, 31],
        &[0x9f, 31, 0x80, 0, 0],
    ] {
        assert!(
            tlv(value, 0).is_err(),
            "malformed identifier/length {value:?}"
        );
    }
}

#[test]
fn malformed_bag_attributes_are_rejected_before_password() {
    // Optional attributes are still ASN.1 Attribute records, not an
    // unchecked opaque tail that can hide malformed BER.
    let key = sequence(&[
        oid(pkcs12::PKCS_12_KEY_BAG_OID),
        encoded(0xa0, &[0x30, 0]),
        encoded(0x31, &[0xff]),
    ]);
    assert!(prepare(&pfx(&[data(&sequence(&[key]))]), &limits(64)).is_err());
}

#[test]
fn redundant_integer_octets_are_not_ber() {
    // X.690 8.3.2 disallows a redundant leading zero even for BER.
    assert!(Reader(&[2, 2, 0, 3]).integer().is_err());
}

#[test]
fn content_infos_and_bags_share_candidate_count() {
    // Empty ContentInfos still inspect a source; bags cannot start a new allowance.
    let key = bag(pkcs12::PKCS_12_KEY_BAG_OID, &[0x30, 0]);
    let bytes = pfx(&[data(&sequence(&[])), data(&sequence(&[key]))]);
    assert!(matches!(
        prepare(&bytes, &limits(2)),
        Err(KeyStoreError::Policy(
            PolicyViolation::ResourceLimitExceeded {
                resource: resource_name::KEY_CANDIDATES,
                maximum: 2
            }
        ))
    ));
    assert!(prepare(&bytes, &limits(3)).is_ok());
}

#[test]
fn nested_bags_share_candidate_count() {
    // A nested SafeContentsBag is not a reset of the outer bag budget.
    let key = bag(pkcs12::PKCS_12_KEY_BAG_OID, &[0x30, 0]);
    let nested = bag(pkcs12::PKCS_12_SAFE_CONTENTS_BAG_OID, &sequence(&[key]));
    assert!(matches!(
        prepare(&pfx(&[data(&sequence(&[nested]))]), &limits(1)),
        Err(KeyStoreError::Policy(
            PolicyViolation::ResourceLimitExceeded {
                resource: resource_name::KEY_CANDIDATES,
                maximum: 1
            }
        ))
    ));
}

#[test]
fn constructed_octets_preserve_mac_input_and_ownership() {
    // Constructed OCTET STRING concatenates primitive contents; its
    // allocation must be charged once and released by retained capacity.
    let value = [0x24, 0x80, 4, 2, b'a', b'b', 0x24, 3, 4, 1, b'c', 0, 0];
    let limits = limits(64);
    let mut budget = Budget::new(&limits);
    let bytes = octets(tlv(&value, 0).expect("BER").0, 4, &mut budget).expect("flatten");
    assert_eq!(&*bytes, b"abc");
    assert_eq!(budget.memory, 3);
    bytes.release(&mut budget);
    assert_eq!(budget.memory, 0);
    assert!(tlv(&[4, 0x80, 0, 0], 0).is_err());
    assert!(tlv(&[0x30, 0x80, 4, 1, 7], 0).is_err());
}

#[test]
fn legacy_shrouded_key_and_hidden_limits() {
    // Exercise RustCrypto's PKCS#12 KDF with legacy SHA-1/3DES, then
    // prove an encrypted SafeContents cannot reset the inner KDF budget.
    let password = "secret";
    let bmp: Vec<u8> = password
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_be_bytes)
        .collect();
    let salt = b"12345678";
    let key = derive_key::<sha1::Sha1>(&bmp, salt, Pkcs12KeyType::EncryptionKey, 2, 24);
    let iv = derive_key::<sha1::Sha1>(&bmp, salt, Pkcs12KeyType::Iv, 2, 8);
    let algorithm = sequence(&[
        oid(pkcs12::PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC),
        sequence(&[encoded(4, salt), integer(2)]),
    ]);
    let private = pem::parse(include_bytes!(
        "../../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
    ))
    .expect("key")
    .into_contents();
    let encrypt = |bytes: &[u8]| {
        let mut output = vec![0; bytes.len() + 8];
        cbc::Encryptor::<des::TdesEde3>::new_from_slices(&key, &iv)
            .expect("cipher")
            .encrypt_padded_b2b::<Pkcs7>(bytes, &mut output)
            .expect("padding")
            .to_vec()
    };
    let shrouded = bag(
        pkcs12::PKCS_12_PKCS8_KEY_BAG_OID,
        &sequence(&[algorithm.clone(), encoded(4, &encrypt(&private))]),
    );
    let bytes = pfx(&[data(&sequence(std::slice::from_ref(&shrouded)))]);
    let limits = limits(64);
    let contents = prepare(&bytes, &limits)
        .expect("preflight")
        .decrypt(password)
        .expect("legacy import");
    assert_eq!(&*contents.private_keys[0], &private);
    assert!(
        prepare(&bytes, &limits)
            .expect("preflight")
            .decrypt("wrong")
            .is_err()
    );
    let encrypted_safe = sequence(&[
        oid(ENCRYPTED_DATA),
        encoded(
            0xa0,
            &sequence(&[
                integer(0),
                sequence(&[
                    oid(DATA),
                    algorithm,
                    encoded(0x80, &encrypt(&sequence(&[shrouded]))),
                ]),
            ]),
        ),
    ]);
    let bytes = pfx(&[encrypted_safe]);
    let tight = Limits {
        resources: ResourcePolicy {
            max_key_import_kdf_work: 6,
            ..ResourcePolicy::default()
        },
        candidates: 64,
        memory_available: ResourcePolicy::default().max_external_resource_total_bytes,
    };
    let prepared = prepare(&bytes, &tight).expect("outer KDF fits");
    assert!(matches!(
        prepared.decrypt(password),
        Err(KeyStoreError::Policy(
            PolicyViolation::ResourceLimitExceeded {
                resource: resource_name::KEY_IMPORT_KDF_WORK,
                maximum: 6
            }
        ))
    ));
}

#[test]
fn pbes2_ber_iv_forms_preserve_decryption() {
    // RFC 7292 section 4 accepts BER; X.690 8.7 permits nested,
    // definite or indefinite OCTET STRING segmentation for the IV.
    let private = pem::parse(include_bytes!(
        "../../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
    ))
    .expect("key")
    .into_contents();
    let iv = [7; 16];
    let mut key = [0; 16];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(b"secret", b"12345678", 2, &mut key);
    let mut output = vec![0; private.len() + 16];
    let ciphertext = cbc::Encryptor::<aes::Aes128Enc>::new_from_slices(&key, &iv)
        .expect("cipher")
        .encrypt_padded_b2b::<Pkcs7>(&private, &mut output)
        .expect("padding")
        .to_vec();
    let segments = [encoded(4, &iv[..5]), encoded(4, &iv[5..])].concat();
    for encoded_iv in [
        encoded(4, &iv),
        encoded(0x24, &segments),
        [vec![0x24, 0x80], segments.clone(), vec![0, 0]].concat(),
        encoded(0x24, &encoded(0x24, &segments)),
    ] {
        let algorithm = sequence(&[
            oid(PBES2),
            sequence(&[
                sequence(&[
                    oid(PBKDF2),
                    sequence(&[encoded(4, b"12345678"), integer(2)]),
                ]),
                sequence(&[oid(pkcs8::pkcs5::pbes2::AES_128_CBC_OID), encoded_iv]),
            ]),
        ]);
        let bytes = pfx(&[data(&sequence(&[bag(
            pkcs12::PKCS_12_PKCS8_KEY_BAG_OID,
            &sequence(&[algorithm, encoded(4, &ciphertext)]),
        )]))]);
        let mut inventory = super::super::KeyInventory::default();
        inventory
            .add_pkcs12("key".into(), &bytes, "secret", &ResourcePolicy::default())
            .expect("all BER IV forms import");
        assert_eq!(inventory.private_keys()[0].pkcs8_der.as_slice(), private);
    }
}

#[test]
fn pbes2_ber_iv_rejects_invalid_segments_and_lengths() {
    // Segmentation changes framing, never AES's required IV length or
    // the universal OCTET STRING type of each component.
    for iv in [
        encoded(4, &[0; 15]),
        encoded(4, &[0; 17]),
        encoded(0x24, &encoded(4, &[0; 17])),
        encoded(0x24, &encoded(2, &[0; 16])),
        [vec![0x24, 0x80], encoded(4, &[0; 16])].concat(),
    ] {
        let algorithm = sequence(&[
            oid(PBES2),
            sequence(&[
                sequence(&[oid(PBKDF2), sequence(&[encoded(4, b"salt"), integer(2)])]),
                sequence(&[oid(pkcs8::pkcs5::pbes2::AES_128_CBC_OID), iv]),
            ]),
        ]);
        let limits = limits(64);
        let mut budget = Budget::new(&limits);
        let result =
            tlv(&algorithm, 0).and_then(|(value, _)| Encryption::parse(value, &mut budget));
        assert!(matches!(result, Err(KeyStoreError::ProtectedContainer)));
        assert_eq!(budget.memory, 0, "IV framing requires no heap allocation");
    }
}

#[test]
fn kdf_integer_classification_preserves_ber_errors() {
    // Machine-width-independent policy denial must not hide malformed
    // negative/redundant/empty INTEGER encodings (X.690 8.3.2).
    let limits = Limits {
        resources: ResourcePolicy {
            max_key_import_kdf_work: 128,
            ..ResourcePolicy::default()
        },
        ..limits(64)
    };
    let budget = Budget::new(&limits);
    for value in [&[][..], &[0x80][..], &[0, 1][..]] {
        let encoded = encoded(2, value);
        assert!(matches!(
            Reader(&encoded).kdf_iterations(&budget),
            Err(KeyStoreError::ProtectedContainer)
        ));
    }
    let exact = encoded(2, &[0, 128]);
    assert_eq!(
        Reader(&exact).kdf_iterations(&budget).expect("exact limit"),
        128
    );
    let exceeded = encoded(2, &[0, 129]);
    assert!(matches!(
        Reader(&exceeded).kdf_iterations(&budget),
        Err(KeyStoreError::Policy(
            PolicyViolation::KdfIterationsOutsideLimit { maximum: 128 }
        ))
    ));
}

#[test]
fn oversized_kdf_integers_are_policy_failures() {
    // Positive BER INTEGERs do not become malformed merely because
    // they exceed a machine integer; reject work before any password.
    for value in [&[1, 0, 0, 0, 0][..], &[1, 0, 0, 0, 0, 0, 0, 0, 0][..]] {
        let rounds = encoded(2, value);
        let pbes2 = sequence(&[
            oid(PBES2),
            sequence(&[
                sequence(&[
                    oid(PBKDF2),
                    sequence(&[encoded(4, b"salt"), rounds.clone()]),
                ]),
                sequence(&[
                    oid(pkcs8::pkcs5::pbes2::AES_128_CBC_OID),
                    encoded(4, &[0; 16]),
                ]),
            ]),
        ]);
        let legacy = sequence(&[
            oid(pkcs12::PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC),
            sequence(&[encoded(4, b"salt"), rounds.clone()]),
        ]);
        for algorithm in [pbes2, legacy] {
            let bytes = pfx(&[data(&sequence(&[bag(
                pkcs12::PKCS_12_PKCS8_KEY_BAG_OID,
                &sequence(&[algorithm, encoded(4, &[0; 16])]),
            )]))]);
            let limits = limits(64);
            assert!(matches!(
                prepare(&bytes, &limits),
                Err(KeyStoreError::Policy(
                    PolicyViolation::KdfIterationsOutsideLimit { .. }
                ))
            ));
            let calls = std::cell::Cell::new(0);
            let result = super::super::KeyInventory::default().add_pkcs12_with_password_callback(
                "key".into(),
                &bytes,
                || {
                    calls.set(calls.get() + 1);
                    None
                },
                super::super::KeyUsages::SIGN,
                &limits.resources,
            );
            assert!(matches!(
                result,
                Err(KeyStoreError::Policy(
                    PolicyViolation::KdfIterationsOutsideLimit { .. }
                ))
            ));
            assert_eq!(
                calls.get(),
                0,
                "oversized work is rejected before password delivery"
            );
        }
        let mac = sequence(&[
            sequence(&[
                sequence(&[oid(Oid::new_unwrap("1.3.14.3.2.26")), encoded(5, &[])]),
                encoded(4, &[0; 20]),
            ]),
            encoded(4, b"salt"),
            rounds,
        ]);
        let bytes = sequence(&[integer(3), data(&sequence(&[])), mac]);
        assert!(matches!(
            prepare(&bytes, &limits(64)),
            Err(KeyStoreError::Policy(
                PolicyViolation::KdfIterationsOutsideLimit { .. }
            ))
        ));
    }
}

#[test]
fn pbes2_password_shares_work_and_live_memory_budget() {
    // A no-MAC PFX still hashes its UTF-8 password before PBKDF2. Policy
    // denial must precede derivation, and callback spare capacity is live.
    let password = "p".repeat(256);
    let private = pem::parse(include_bytes!(
        "../../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
    ))
    .expect("key")
    .into_contents();
    let mut key = [0; 16];
    let iv = [7; 16];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password.as_bytes(), b"salt", 2, &mut key);
    let mut output = vec![0; private.len() + 16];
    let ciphertext = cbc::Encryptor::<aes::Aes128Enc>::new_from_slices(&key, &iv)
        .expect("cipher")
        .encrypt_padded_b2b::<Pkcs7>(&private, &mut output)
        .expect("padding")
        .to_vec();
    let algorithm = sequence(&[
        oid(PBES2),
        sequence(&[
            sequence(&[oid(PBKDF2), sequence(&[encoded(4, b"salt"), integer(2)])]),
            sequence(&[oid(pkcs8::pkcs5::pbes2::AES_128_CBC_OID), encoded(4, &iv)]),
        ]),
    ]);
    let bytes = pfx(&[data(&sequence(&[bag(
        pkcs12::PKCS_12_PKCS8_KEY_BAG_OID,
        &sequence(&[algorithm, encoded(4, &ciphertext)]),
    )]))]);
    let peak = password.len() + ciphertext.len() + core::mem::size_of::<Zeroizing<Vec<u8>>>();
    for (work, memory, per_resource) in [(5, peak, 256), (6, peak - 1, 256), (6, peak, 255)] {
        let mut limits = limits(64);
        limits.resources.max_key_import_kdf_work = work;
        limits.resources.max_external_resource_bytes = per_resource;
        limits.memory_available = memory;
        assert!(matches!(
            prepare(&bytes, &limits)
                .expect("visible KDF fits")
                .decrypt(&password),
            Err(KeyStoreError::Policy(_))
        ));
    }
    let mut exact = limits(64);
    exact.resources.max_key_import_kdf_work = 6;
    exact.memory_available = peak;
    assert_eq!(
        &*prepare(&bytes, &exact)
            .expect("preflight")
            .decrypt(&password)
            .expect("exact password allowances")
            .private_keys[0],
        &private
    );
    let mut secret = String::with_capacity(4096);
    secret.push_str(&password);
    let resources = ResourcePolicy {
        max_external_resource_total_bytes: bytes.len() + peak + 3,
        ..ResourcePolicy::default()
    };
    let mut inventory = super::super::KeyInventory::default();
    assert!(matches!(
        inventory.add_pkcs12_with_password_callback(
            "new".into(),
            &bytes,
            || Some(Zeroizing::new(secret)),
            super::super::KeyUsages::SIGN,
            &resources
        ),
        Err(KeyStoreError::Policy(_))
    ));
    assert!(inventory.private_keys().is_empty());
}

#[test]
fn pbes2_cipher_prf_matrix_accepts_utf8_passwords_without_legacy_kdf() {
    // RFC 8018 PBES2 does not impose RFC 7292's legacy BMP password
    // conversion. Test every supported AES width and HMAC PRF with a
    // non-BMP UTF-8 password, including the default SHA-1 PRF.
    let password = "secret\u{1f512}";
    let private = pem::parse(include_bytes!(
        "../../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
    ))
    .expect("private key")
    .into_contents();
    let salt = b"salt beyond the old fixed thirty-two byte representation";
    let iv = [7_u8; 16];
    let prfs = [
        (Hash::Sha1, "1.2.840.113549.2.7"),
        (Hash::Sha224, "1.2.840.113549.2.8"),
        (Hash::Sha256, "1.2.840.113549.2.9"),
        (Hash::Sha384, "1.2.840.113549.2.10"),
        (Hash::Sha512, "1.2.840.113549.2.11"),
    ];
    for (cipher, cipher_oid) in [
        (Cipher::Aes128, pkcs8::pkcs5::pbes2::AES_128_CBC_OID),
        (Cipher::Aes192, pkcs8::pkcs5::pbes2::AES_192_CBC_OID),
        (Cipher::Aes256, pkcs8::pkcs5::pbes2::AES_256_CBC_OID),
    ] {
        for (hash, prf_oid) in prfs {
            let mut key = Zeroizing::new([0_u8; 32]);
            with_hash!(
                hash,
                D,
                pbkdf2::pbkdf2_hmac::<D>(
                    password.as_bytes(),
                    salt,
                    2,
                    &mut key[..cipher.key_len()]
                )
            );
            let mut output = vec![0; private.len() + 16];
            macro_rules! encrypt {
                ($cipher:ty) => {
                    cbc::Encryptor::<$cipher>::new_from_slices(&key[..cipher.key_len()], &iv)
                        .expect("cipher")
                        .encrypt_padded_b2b::<Pkcs7>(&private, &mut output)
                        .expect("padding")
                        .to_vec()
                };
            }
            let ciphertext = match cipher {
                Cipher::Aes128 => encrypt!(aes::Aes128Enc),
                Cipher::Aes192 => encrypt!(aes::Aes192Enc),
                Cipher::Aes256 => encrypt!(aes::Aes256Enc),
                _ => unreachable!(),
            };
            let mut params = vec![
                encoded(4, salt),
                integer(2),
                integer(u16::try_from(cipher.key_len()).expect("fixed cipher key width")),
            ];
            if !matches!(hash, Hash::Sha1) {
                params.push(sequence(&[oid(Oid::new_unwrap(prf_oid)), encoded(5, &[])]));
            }
            let algorithm = sequence(&[
                oid(PBES2),
                sequence(&[
                    sequence(&[oid(PBKDF2), sequence(&params)]),
                    sequence(&[oid(cipher_oid), encoded(4, &iv)]),
                ]),
            ]);
            let shrouded = bag(
                pkcs12::PKCS_12_PKCS8_KEY_BAG_OID,
                &sequence(&[algorithm, encoded(4, &ciphertext)]),
            );
            let bytes = pfx(&[data(&sequence(&[shrouded]))]);
            let limits = limits(64);
            let contents = prepare(&bytes, &limits)
                .expect("PBES2 preflight")
                .decrypt(password)
                .expect("UTF-8 PBES2 import");
            assert_eq!(&*contents.private_keys[0], &private);
        }
    }
}
