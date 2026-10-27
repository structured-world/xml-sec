use super::*;
use aes::cipher::BlockModeEncrypt as _;
use std::cell::Cell;

const DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.1");
const ENCRYPTED_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.6");
const SIGNED_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.2");
const ENVELOPED_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.3");
const PBES2: Oid = Oid::new_unwrap("1.2.840.113549.1.5.13");
const PBKDF2: Oid = Oid::new_unwrap("1.2.840.113549.1.5.12");
const SHA1: Oid = Oid::new_unwrap("1.3.14.3.2.26");

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
fn private_key() -> Vec<u8> {
    pem::parse(include_bytes!(
        "../../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
    ))
    .expect("PKCS#8 fixture")
    .into_contents()
}
fn bmp(password: &str) -> Vec<u8> {
    password
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_be_bytes)
        .collect()
}

/// Import with `password`, counting how often the password was requested.
fn import_counting(
    bytes: &[u8],
    limits: &Limits,
    work: &mut usize,
    password: &str,
) -> (Result<Contents>, usize) {
    let calls = Cell::new(0);
    let result = import(bytes, limits, work, || {
        calls.set(calls.get() + 1);
        Some(password)
    });
    (result, calls.get())
}

fn run(bytes: &[u8], limits: &Limits, password: &str) -> Result<Contents> {
    import(bytes, limits, &mut 0, || Some(password))
}

fn imported_key(contents: &Contents) -> &[u8] {
    contents.private_key.as_deref().expect("one private key")
}

/// A PFX whose only safe holds an encrypted `SafeContents`. The password is
/// never correct; inspection either refuses the PFX or reaches the password.
fn requests_password(bytes: &[u8]) -> bool {
    let (result, calls) = import_counting(bytes, &limits(64), &mut 0, "wrong");
    assert!(result.is_err() || calls == 1);
    calls == 1
}

fn legacy_mac(safe: &[u8], password: &str, hash: Oid, salt: &[u8], rounds: u16) -> Vec<u8> {
    let key = derive_key::<sha1::Sha1>(&bmp(password), salt, Pkcs12KeyType::Mac, rounds.into(), 20);
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(&key).expect("HMAC key");
    mac.update(safe);
    let digest = mac.finalize().into_bytes();
    sequence(&[
        sequence(&[sequence(&[oid(hash), encoded(5, &[])]), encoded(4, &digest)]),
        encoded(4, salt),
        integer(rounds),
    ])
}

fn pbes2_aes128(salt: &[u8], rounds: Vec<u8>, iv: Vec<u8>) -> Vec<u8> {
    sequence(&[
        oid(PBES2),
        sequence(&[
            sequence(&[oid(PBKDF2), sequence(&[encoded(4, salt), rounds])]),
            sequence(&[oid(pkcs8::pkcs5::pbes2::AES_128_CBC_OID), iv]),
        ]),
    ])
}

fn aes128_pbes2_ciphertext(password: &[u8], salt: &[u8], iv: [u8; 16], plain: &[u8]) -> Vec<u8> {
    let mut key = [0; 16];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, salt, 2, &mut key);
    let mut output = vec![0; plain.len() + 16];
    cbc::Encryptor::<aes::Aes128Enc>::new_from_slices(&key, &iv)
        .expect("cipher")
        .encrypt_padded_b2b::<Pkcs7>(plain, &mut output)
        .expect("padding")
        .to_vec()
}

#[test]
fn legacy_mac_authenticates_the_bmp_password() {
    // RFC 7292 B.1: the MAC derives from BMPString characters; a BMP-only
    // non-ASCII password verifies, a wrong one and a non-BMP one cannot.
    let key = bag(pkcs12::PKCS_12_KEY_BAG_OID, &private_key());
    let safe = sequence(&[data(&sequence(&[key]))]);
    let password = "p\u{ffff}";
    let bytes = sequence(&[
        integer(3),
        data(&safe),
        legacy_mac(&safe, password, SHA1, b"saltsalt", 2),
    ]);
    let contents = run(&bytes, &limits(64), password).expect("authenticated import");
    assert_eq!(imported_key(&contents), private_key());
    for wrong in ["p", "secret\u{1f512}"] {
        assert!(matches!(
            run(&bytes, &limits(64), wrong),
            Err(KeyStoreError::ProtectedContainer)
        ));
    }
}

#[test]
fn mac_covers_the_logical_safe_of_constructed_octets() {
    // X.690 8.7.3: a constructed OCTET STRING carries the concatenated
    // contents. The MAC input is that logical safe, not its BER framing.
    let key = bag(pkcs12::PKCS_12_KEY_BAG_OID, &private_key());
    let safe = sequence(&[data(&sequence(&[key]))]);
    let (first, second) = safe.split_at(7);
    let carried = encoded(0x24, &[encoded(4, first), encoded(4, second)].concat());
    let content = sequence(&[oid(DATA), encoded(0xa0, &carried)]);
    let mac = legacy_mac(&safe, "secret", SHA1, b"saltsalt", 2);
    let bytes = sequence(&[integer(3), content.clone(), mac]);
    run(&bytes, &limits(64), "secret").expect("segmented safe authenticates");
    let tampered = legacy_mac(&safe[1..], "secret", SHA1, b"saltsalt", 2);
    let bytes = sequence(&[integer(3), content, tampered]);
    assert!(matches!(
        run(&bytes, &limits(64), "secret"),
        Err(KeyStoreError::ProtectedContainer)
    ));
}

#[test]
fn ciphertext_capacity_is_checked_before_password_derivation() {
    // The plaintext copy is refused before any KDF or password conversion
    // runs, for both PBES2 and the legacy PKCS#12 KDF.
    let private = private_key();
    let iv = [7; 16];
    let pbes2 = bag(
        pkcs12::PKCS_12_PKCS8_KEY_BAG_OID,
        &sequence(&[
            pbes2_aes128(b"salt", integer(2), encoded(4, &iv)),
            encoded(
                4,
                &aes128_pbes2_ciphertext(b"password", b"salt", iv, &private),
            ),
        ]),
    );
    let legacy = bag(
        pkcs12::PKCS_12_PKCS8_KEY_BAG_OID,
        &sequence(&[
            sequence(&[
                oid(pkcs12::PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC),
                sequence(&[encoded(4, b"12345678"), integer(2)]),
            ]),
            encoded(4, &[0; 1024]),
        ]),
    );
    for shrouded in [pbes2, legacy] {
        let bytes = pfx(&[data(&sequence(&[shrouded]))]);
        // The borrowed PFX is accounted by the caller; this is working memory,
        // enough for the reader and password but not the ciphertext copy.
        let mut tight = limits(64);
        tight.memory_available = 600;
        let mut work = 0;
        let result = import(&bytes, &tight, &mut work, || Some("password"));
        assert!(matches!(
            result,
            Err(KeyStoreError::Policy(
                PolicyViolation::ResourceLimitExceeded {
                    resource: resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                    ..
                }
            ))
        ));
    }
}

#[test]
fn ber_private_key_info_is_normalized_before_storage() {
    // KeyBag inherits the PFX BER contract; an indefinite SEQUENCE and
    // constructed OCTET STRING must reach the DER-only key decoder intact.
    let algorithm = sequence(&[
        oid(Oid::new_unwrap("1.2.840.113549.1.1.1")),
        encoded(5, &[]),
    ]);
    let der = sequence(&[integer(0), algorithm.clone(), encoded(4, b"private")]);
    let mut ber = vec![0x30, 0x80];
    ber.extend(integer(0));
    ber.extend(&algorithm);
    ber.extend([
        0x24, 0x80, 4, 3, b'p', b'r', b'i', 4, 4, b'v', b'a', b't', b'e', 0, 0, 0, 0,
    ]);
    let bytes = pfx(&[data(&sequence(&[bag(pkcs12::PKCS_12_KEY_BAG_OID, &ber)]))]);
    let imported = run(&bytes, &limits(64), "secret").expect("BER key import");
    assert_eq!(imported_key(&imported), der);
}

#[test]
fn ber_algorithm_parameters_are_refused_not_rewritten() {
    // Only framing is synthesized. A non-DER parameter value (an indefinite
    // NULL) would change the key's identity if rewritten, so it is refused.
    let mut ber = vec![0x30, 0x80];
    ber.extend(integer(0));
    ber.extend(sequence(&[
        oid(Oid::new_unwrap("1.2.840.113549.1.1.1")),
        vec![0x25, 0x80, 0, 0],
    ]));
    ber.extend(encoded(4, b"private"));
    ber.extend([0, 0]);
    let bytes = pfx(&[data(&sequence(&[bag(pkcs12::PKCS_12_KEY_BAG_OID, &ber)]))]);
    assert!(matches!(
        run(&bytes, &limits(64), "secret"),
        Err(KeyStoreError::ProtectedContainer)
    ));
}

#[test]
fn key_output_is_charged_before_it_is_written() {
    // The normalized key is funded from the import's memory before copying.
    let bytes = pfx(&[data(&sequence(&[bag(
        pkcs12::PKCS_12_KEY_BAG_OID,
        &private_key(),
    )]))]);
    let mut tight = limits(64);
    tight.memory_available = private_key().len() - 1;
    assert!(matches!(
        run(&bytes, &tight, "secret"),
        Err(KeyStoreError::Policy(
            PolicyViolation::ResourceLimitExceeded {
                resource: resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                ..
            }
        ))
    ));
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
    // framing in inspection and fail in the later PKCS#8 decoder.
    let private = private_key();
    assert_eq!(&private[..2], &[0x30, 0x82], "two-octet DER length");
    let mut ber = vec![0x30, 0x80];
    ber.extend_from_slice(&private[4..]);
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
    assert_eq!(inventory.private_keys()[0].pkcs8_der(), private);
}

#[test]
fn encrypted_data_version_tracks_unprotected_attributes() {
    // RFC 5652 8: version 2 exactly when [1] attributes are present. The
    // shape is checked before the password is requested.
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
        let safe = sequence(&[oid(ENCRYPTED_DATA), encoded(0xa0, &sequence(&parts))]);
        assert_eq!(
            requests_password(&pfx(&[safe])),
            accepted,
            "version {version}"
        );
    }
}

#[test]
fn unsupported_algorithms_are_refused_before_the_password() {
    // An unsupported capability fails before the password is requested,
    // rather than suggesting that a password was tried and failed.
    let unsupported = Oid::new_unwrap("1.2.840.113549.1.12.1.6");
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
                sequence(&[oid(unsupported), derivation.clone()]),
                sequence(&[
                    oid(pkcs8::pkcs5::pbes2::AES_128_CBC_OID),
                    encoded(4, &[0; 16]),
                ]),
            ]),
        ]),
        sequence(&[
            oid(PBES2),
            sequence(&[
                sequence(&[
                    oid(PBKDF2),
                    sequence(&[
                        encoded(4, b"salt"),
                        integer(2),
                        sequence(&[oid(unsupported), encoded(5, &[])]),
                    ]),
                ]),
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
        let (result, calls) = import_counting(&bytes, &limits(64), &mut 0, "secret");
        assert!(matches!(result, Err(KeyStoreError::Selection(_))));
        assert_eq!(calls, 0);
    }
    let mac = sequence(&[
        sequence(&[
            sequence(&[oid(unsupported), encoded(5, &[])]),
            encoded(4, &[0; 20]),
        ]),
        encoded(4, b"salt"),
    ]);
    let bytes = sequence(&[integer(3), data(&sequence(&[])), mac]);
    let (result, calls) = import_counting(&bytes, &limits(64), &mut 0, "secret");
    assert!(matches!(result, Err(KeyStoreError::Selection(_))));
    assert_eq!(calls, 0);
}

#[test]
fn unsupported_integrity_privacy_and_bag_types_are_selection_errors() {
    // Public-key integrity, enveloped privacy, an unknown safe type and a
    // CRL bag are capabilities this import lacks, not malformed input.
    // RFC 5652 5.1: a degenerate SignedData with attached data content.
    let signed_data = sequence(&[
        integer(1),
        encoded(0x31, &[]),
        sequence(&[oid(DATA), encoded(0xa0, &encoded(4, &sequence(&[])))]),
        encoded(0x31, &[]),
    ]);
    let signed = sequence(&[
        integer(3),
        sequence(&[oid(SIGNED_DATA), encoded(0xa0, &signed_data)]),
    ]);
    // RFC 5652 6.1/6.2.3: version 2 EnvelopedData with one KEK recipient.
    let enveloped_data = sequence(&[
        integer(2),
        encoded(
            0x31,
            &encoded(
                0xa2,
                &[
                    integer(4),
                    sequence(&[encoded(4, b"kek")]),
                    sequence(&[oid(Oid::new_unwrap("2.16.840.1.101.3.4.1.5"))]),
                    encoded(4, &[0; 24]),
                ]
                .concat(),
            ),
        ),
        sequence(&[
            oid(DATA),
            sequence(&[
                oid(pkcs8::pkcs5::pbes2::AES_128_CBC_OID),
                encoded(4, &[0; 16]),
            ]),
            encoded(0x80, &[0; 16]),
        ]),
    ]);
    let enveloped = pfx(&[sequence(&[
        oid(ENVELOPED_DATA),
        encoded(0xa0, &enveloped_data),
    ])]);
    let unknown = pfx(&[sequence(&[
        oid(Oid::new_unwrap("1.2.3.4")),
        encoded(0xa0, &encoded(4, b"x")),
    ])]);
    let crl = pfx(&[data(&sequence(&[bag(
        Oid::new_unwrap("1.2.840.113549.1.12.10.1.4"),
        &sequence(&[
            oid(Oid::new_unwrap("1.2.840.113549.1.9.23.1")),
            encoded(0xa0, &encoded(4, b"crl")),
        ]),
    )]))]);
    for (name, bytes) in [
        ("signed", signed),
        ("enveloped", enveloped),
        ("unknown", unknown),
        ("crl", crl),
    ] {
        let (result, calls) = import_counting(&bytes, &limits(64), &mut 0, "secret");
        assert!(
            matches!(result, Err(KeyStoreError::Selection(_))),
            "{name} refused as unsupported: {:?}",
            result.err()
        );
        assert_eq!(calls, 0, "refused before the password");
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
    ] {
        let key = sequence(&[
            oid(pkcs12::PKCS_12_KEY_BAG_OID),
            encoded(0xa0, &private_key()),
            encoded(
                0x31,
                &sequence(&[oid(Oid::new_unwrap("1.2.3.4")), encoded(0x31, &value)]),
            ),
        ]);
        run(&pfx(&[data(&sequence(&[key]))]), &limits(64), "secret").expect("valid attribute");
    }
    for value in [
        &[0x9f, 0, 0][..],
        &[0x9f, 0x80, 31, 0],
        &[0x9f, 30, 0],
        &[0x9f, 0x81],
        &[0x9f, 31, 0x80, 0, 0],
    ] {
        let key = sequence(&[
            oid(pkcs12::PKCS_12_KEY_BAG_OID),
            encoded(0xa0, &private_key()),
            encoded(
                0x31,
                &sequence(&[oid(Oid::new_unwrap("1.2.3.4")), encoded(0x31, value)]),
            ),
        ]);
        let (result, calls) = import_counting(
            &pfx(&[data(&sequence(&[key]))]),
            &limits(64),
            &mut 0,
            "secret",
        );
        assert!(result.is_err(), "malformed identifier/length {value:?}");
        assert_eq!(calls, 0);
    }
}

#[test]
fn malformed_bag_attributes_are_rejected_before_password() {
    // Optional attributes are still ASN.1 Attribute records, not an
    // unchecked opaque tail that can hide malformed BER.
    let key = sequence(&[
        oid(pkcs12::PKCS_12_KEY_BAG_OID),
        encoded(0xa0, &private_key()),
        encoded(0x31, &[0xff]),
    ]);
    let (result, calls) = import_counting(
        &pfx(&[data(&sequence(&[key]))]),
        &limits(64),
        &mut 0,
        "secret",
    );
    assert!(matches!(result, Err(KeyStoreError::ProtectedContainer)));
    assert_eq!(calls, 0);
}

#[test]
fn redundant_integer_octets_are_not_ber() {
    // X.690 8.3.2 disallows a redundant leading zero even for BER.
    let mut bytes = pfx(&[]);
    let at = bytes
        .windows(3)
        .position(|w| w == [2, 1, 3])
        .expect("PFX version");
    bytes.splice(at..at + 3, [2, 2, 0, 3]);
    bytes[1] += 1;
    assert!(matches!(
        run(&bytes, &limits(64), "secret"),
        Err(KeyStoreError::ProtectedContainer)
    ));
}

#[test]
fn bags_share_one_candidate_count() {
    // Bags in separate safes cannot each start a new allowance. An unencrypted
    // safe is not expansion work; its bags are its candidates.
    let key = bag(pkcs12::PKCS_12_KEY_BAG_OID, &private_key());
    let certificate = bag(
        pkcs12::PKCS_12_CERT_BAG_OID,
        &sequence(&[
            oid(pkcs12::PKCS_12_X509_CERT_OID),
            encoded(0xa0, &encoded(4, b"certificate")),
        ]),
    );
    let bytes = pfx(&[data(&sequence(&[certificate])), data(&sequence(&[key]))]);
    let (result, calls) = import_counting(&bytes, &limits(1), &mut 0, "secret");
    assert!(matches!(
        result,
        Err(KeyStoreError::Policy(
            PolicyViolation::ResourceLimitExceeded {
                resource: resource_name::KEY_CANDIDATES,
                maximum: 1
            }
        ))
    ));
    assert_eq!(calls, 0, "an unprotected container needs no password");
    let contents = run(&bytes, &limits(2), "secret").expect("two bags fit");
    assert_eq!(contents.certificates, [b"certificate".to_vec()]);
}

#[test]
fn nested_bags_share_candidate_count() {
    // A nested SafeContentsBag is not a reset of the outer bag budget.
    let key = bag(pkcs12::PKCS_12_KEY_BAG_OID, &private_key());
    let nested = bag(pkcs12::PKCS_12_SAFE_CONTENTS_BAG_OID, &sequence(&[key]));
    let bytes = pfx(&[data(&sequence(&[nested]))]);
    assert!(matches!(
        run(&bytes, &limits(1), "secret"),
        Err(KeyStoreError::Policy(
            PolicyViolation::ResourceLimitExceeded {
                resource: resource_name::KEY_CANDIDATES,
                maximum: 1
            }
        ))
    ));
    let contents = run(&bytes, &limits(2), "secret").expect("nested key");
    assert_eq!(imported_key(&contents), private_key());
}

#[test]
fn a_second_private_key_is_refused() {
    // Names cannot be assigned from iteration order; two keys are ambiguous.
    let key = bag(pkcs12::PKCS_12_KEY_BAG_OID, &private_key());
    let bytes = pfx(&[data(&sequence(&[key.clone(), key]))]);
    assert!(matches!(
        run(&bytes, &limits(64), "secret"),
        Err(KeyStoreError::Selection(_))
    ));
}

#[test]
fn legacy_shrouded_key_and_hidden_limits() {
    // Exercise RustCrypto's PKCS#12 KDF with legacy SHA-1/3DES, then
    // prove an encrypted SafeContents cannot reset the inner KDF budget.
    let password = "secret";
    let salt = b"12345678";
    let key = derive_key::<sha1::Sha1>(&bmp(password), salt, Pkcs12KeyType::EncryptionKey, 2, 24);
    let iv = derive_key::<sha1::Sha1>(&bmp(password), salt, Pkcs12KeyType::Iv, 2, 8);
    let algorithm = sequence(&[
        oid(pkcs12::PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC),
        sequence(&[encoded(4, salt), integer(2)]),
    ]);
    let private = private_key();
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
    let contents = run(&bytes, &limits(64), password).expect("legacy import");
    assert_eq!(imported_key(&contents), private);
    assert!(run(&bytes, &limits(64), "wrong").is_err());
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
    let contents = run(&bytes, &limits(64), password).expect("nested legacy import");
    assert_eq!(imported_key(&contents), private);
    // The hidden bag continues the safe count taken before the password.
    let (result, calls) = import_counting(&bytes, &limits(1), &mut 0, password);
    assert_eq!(calls, 1, "the visible safe fits");
    assert!(matches!(
        result,
        Err(KeyStoreError::Policy(
            PolicyViolation::ResourceLimitExceeded {
                resource: resource_name::KEY_CANDIDATES,
                maximum: 1
            }
        ))
    ));
    // The outer safe needs 2 rounds x 3 blocks; the hidden key needs as much.
    let tight = Limits {
        resources: ResourcePolicy {
            max_key_import_kdf_work: 6,
            ..ResourcePolicy::default()
        },
        ..limits(64)
    };
    let mut work = 0;
    let (result, calls) = import_counting(&bytes, &tight, &mut work, password);
    assert_eq!(calls, 1, "the visible outer KDF fits");
    assert!(matches!(
        result,
        Err(KeyStoreError::Policy(
            PolicyViolation::ResourceLimitExceeded {
                resource: resource_name::KEY_IMPORT_KDF_WORK,
                maximum: 6
            }
        ))
    ));
    assert_eq!(work, 6, "work spent after the password is not refunded");
}

#[test]
fn pbes2_ber_iv_forms_preserve_decryption() {
    // RFC 7292 section 4 accepts BER; X.690 8.7 permits nested,
    // definite or indefinite OCTET STRING segmentation for the IV.
    let private = private_key();
    let iv = [7; 16];
    let ciphertext = aes128_pbes2_ciphertext(b"secret", b"12345678", iv, &private);
    let segments = [encoded(4, &iv[..5]), encoded(4, &iv[5..])].concat();
    for encoded_iv in [
        encoded(4, &iv),
        encoded(0x24, &segments),
        [vec![0x24, 0x80], segments.clone(), vec![0, 0]].concat(),
        encoded(0x24, &encoded(0x24, &segments)),
    ] {
        let bytes = pfx(&[data(&sequence(&[bag(
            pkcs12::PKCS_12_PKCS8_KEY_BAG_OID,
            &sequence(&[
                pbes2_aes128(b"12345678", integer(2), encoded_iv),
                encoded(4, &ciphertext),
            ]),
        )]))]);
        let mut inventory = super::super::KeyInventory::default();
        inventory
            .add_pkcs12("key".into(), &bytes, "secret", &ResourcePolicy::default())
            .expect("all BER IV forms import");
        assert_eq!(inventory.private_keys()[0].pkcs8_der(), private);
    }
}

#[test]
fn a_decrypted_der_key_is_kept_and_a_ber_key_rewritten() {
    // A DER PrivateKeyInfo is stored in its decrypted buffer, without a second
    // copy; RFC 7292 4.2.1 BER framing is still rewritten to DER.
    let private = private_key();
    let mut ber = vec![0x30, 0x80];
    ber.extend_from_slice(&private[4..]);
    ber.extend_from_slice(&[0, 0]);
    let iv = [7; 16];
    for (plain, kept) in [(&private, true), (&ber, false)] {
        let ciphertext = aes128_pbes2_ciphertext(b"secret", b"12345678", iv, plain);
        let bytes = pfx(&[data(&sequence(&[bag(
            pkcs12::PKCS_12_PKCS8_KEY_BAG_OID,
            &sequence(&[
                pbes2_aes128(b"12345678", integer(2), encoded(4, &iv)),
                encoded(4, &ciphertext),
            ]),
        )]))]);
        let contents = run(&bytes, &limits(64), "secret").expect("shrouded import");
        assert_eq!(imported_key(&contents), private);
        assert_eq!(
            matches!(contents.private_key, Some(PrivateKeyDer::Retained(_))),
            kept
        );
    }
}

#[test]
fn reader_work_limit_reaches_container_and_decrypted_content() {
    // max_x509_work bounds the shared reader through the public import, both
    // before the password and while reading what decryption produced. The
    // bundle holds one key and no certificate, so no X.509 parse is charged.
    let (password, salt, iv) = (b"secret", b"12345678", [7; 16]);
    let private = private_key();
    let shrouded = bag(
        pkcs12::PKCS_12_PKCS8_KEY_BAG_OID,
        &sequence(&[
            pbes2_aes128(salt, integer(2), encoded(4, &iv)),
            encoded(4, &aes128_pbes2_ciphertext(password, salt, iv, &private)),
        ]),
    );
    let safe = aes128_pbes2_ciphertext(password, salt, iv, &sequence(&[shrouded]));
    let bytes = pfx(&[sequence(&[
        oid(ENCRYPTED_DATA),
        encoded(
            0xa0,
            &sequence(&[
                integer(0),
                sequence(&[
                    oid(DATA),
                    pbes2_aes128(salt, integer(2), encoded(4, &iv)),
                    encoded(0x80, &safe),
                ]),
            ]),
        ),
    ])]);
    let import = |max_x509_work: usize| {
        let calls = Cell::new(0);
        let mut inventory = super::super::KeyInventory::default();
        let result = inventory.add_pkcs12_with_password_callback(
            "key".into(),
            &bytes,
            || {
                calls.set(calls.get() + 1);
                Some(Zeroizing::new("secret".to_owned()))
            },
            super::super::KeyUsages::SIGN,
            &ResourcePolicy {
                max_x509_work,
                ..ResourcePolicy::default()
            },
        );
        if result.is_ok() {
            assert_eq!(inventory.private_keys()[0].pkcs8_der(), private);
        }
        (result, calls.get())
    };
    let denied = |result: core::result::Result<(), KeyStoreError>, limit: usize| {
        matches!(
            result,
            Err(KeyStoreError::Policy(PolicyViolation::ResourceLimitExceeded {
                resource: resource_name::X509_WORK,
                maximum,
            })) if maximum == limit
        )
    };
    let (mut refused, mut admitted) = (0_usize, ResourcePolicy::default().max_x509_work);
    assert!(import(admitted).0.is_ok(), "the default admits the bundle");
    while admitted - refused > 1 {
        let middle = refused + (admitted - refused) / 2;
        if import(middle).0.is_ok() {
            admitted = middle;
        } else {
            refused = middle;
        }
    }
    // The last unit of reader work is spent inside the decrypted key.
    let (result, calls) = import(refused);
    assert!(denied(result, refused), "one unit short of the bundle");
    assert_eq!(calls, 1, "refused after decryption");
    // The outer container alone exceeds a single unit, before any password.
    let (result, calls) = import(1);
    assert!(denied(result, 1));
    assert_eq!(calls, 0, "refused before the password");
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
        let bytes = pfx(&[data(&sequence(&[bag(
            pkcs12::PKCS_12_PKCS8_KEY_BAG_OID,
            &sequence(&[pbes2_aes128(b"salt", integer(2), iv), encoded(4, &[0; 16])]),
        )]))]);
        let (result, calls) = import_counting(&bytes, &limits(64), &mut 0, "secret");
        assert!(matches!(result, Err(KeyStoreError::ProtectedContainer)));
        assert_eq!(calls, 0);
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
    let shrouded = |rounds: Vec<u8>| {
        pfx(&[data(&sequence(&[bag(
            pkcs12::PKCS_12_PKCS8_KEY_BAG_OID,
            &sequence(&[
                sequence(&[
                    oid(pkcs12::PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC),
                    sequence(&[encoded(4, b"salt"), rounds]),
                ]),
                encoded(4, &[0; 8]),
            ]),
        )]))])
    };
    for value in [&[][..], &[0x80][..], &[0, 1][..], &[0][..]] {
        let (result, calls) = import_counting(&shrouded(encoded(2, value)), &limits, &mut 0, "x");
        assert!(
            matches!(result, Err(KeyStoreError::ProtectedContainer)),
            "{value:?}"
        );
        assert_eq!(calls, 0);
    }
    // 128 rounds pass the iteration check; 3DES's three blocks exceed 128.
    let (result, calls) = import_counting(&shrouded(encoded(2, &[0, 128])), &limits, &mut 0, "x");
    assert!(matches!(
        result,
        Err(KeyStoreError::Policy(
            PolicyViolation::ResourceLimitExceeded {
                resource: resource_name::KEY_IMPORT_KDF_WORK,
                ..
            }
        ))
    ));
    assert_eq!(calls, 0);
    let (result, calls) = import_counting(&shrouded(encoded(2, &[0, 129])), &limits, &mut 0, "x");
    assert!(matches!(
        result,
        Err(KeyStoreError::Policy(
            PolicyViolation::KdfIterationsOutsideLimit { maximum: 128 }
        ))
    ));
    assert_eq!(calls, 0);
}

#[test]
fn oversized_kdf_integers_are_policy_failures() {
    // Positive BER INTEGERs do not become malformed merely because
    // they exceed a machine integer; reject work before any password.
    for value in [&[1, 0, 0, 0, 0][..], &[1, 0, 0, 0, 0, 0, 0, 0, 0][..]] {
        let rounds = encoded(2, value);
        let pbes2 = pbes2_aes128(b"salt", rounds.clone(), encoded(4, &[0; 16]));
        let legacy = sequence(&[
            oid(pkcs12::PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC),
            sequence(&[encoded(4, b"salt"), rounds.clone()]),
        ]);
        for algorithm in [pbes2, legacy] {
            let bytes = pfx(&[data(&sequence(&[bag(
                pkcs12::PKCS_12_PKCS8_KEY_BAG_OID,
                &sequence(&[algorithm, encoded(4, &[0; 16])]),
            )]))]);
            let calls = Cell::new(0);
            let result = super::super::KeyInventory::default().add_pkcs12_with_password_callback(
                "key".into(),
                &bytes,
                || {
                    calls.set(calls.get() + 1);
                    None
                },
                super::super::KeyUsages::SIGN,
                &ResourcePolicy::default(),
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
                sequence(&[oid(SHA1), encoded(5, &[])]),
                encoded(4, &[0; 20]),
            ]),
            encoded(4, b"salt"),
            rounds,
        ]);
        let bytes = sequence(&[integer(3), data(&sequence(&[])), mac]);
        let (result, calls) = import_counting(&bytes, &limits(64), &mut 0, "secret");
        assert!(matches!(
            result,
            Err(KeyStoreError::Policy(
                PolicyViolation::KdfIterationsOutsideLimit { .. }
            ))
        ));
        assert_eq!(calls, 0);
    }
}

#[test]
fn pbes2_password_shares_work_and_live_memory_budget() {
    // A no-MAC PFX still hashes its UTF-8 password before PBKDF2: 2 rounds
    // of one block plus 256 / 64 password blocks is 6 units of work.
    let password = "p".repeat(256);
    let private = private_key();
    let iv = [7; 16];
    let ciphertext = aes128_pbes2_ciphertext(password.as_bytes(), b"salt", iv, &private);
    let bytes = pfx(&[data(&sequence(&[bag(
        pkcs12::PKCS_12_PKCS8_KEY_BAG_OID,
        &sequence(&[
            pbes2_aes128(b"salt", integer(2), encoded(4, &iv)),
            encoded(4, &ciphertext),
        ]),
    )]))]);
    let mut short = limits(64);
    short.resources.max_key_import_kdf_work = 5;
    assert!(matches!(
        run(&bytes, &short, &password),
        Err(KeyStoreError::Policy(
            PolicyViolation::ResourceLimitExceeded {
                resource: resource_name::KEY_IMPORT_KDF_WORK,
                maximum: 5
            }
        ))
    ));
    let mut narrow = limits(64);
    narrow.resources.max_external_resource_bytes = 255;
    assert!(matches!(
        run(&bytes, &narrow, &password),
        Err(KeyStoreError::Policy(
            PolicyViolation::ResourceLimitExceeded {
                resource: resource_name::EXTERNAL_RESOURCE_BYTES,
                maximum: 255
            }
        ))
    ));
    let mut exact = limits(64);
    exact.resources.max_key_import_kdf_work = 6;
    let contents = run(&bytes, &exact, &password).expect("exact work");
    assert_eq!(imported_key(&contents), private);
    // A callback's spare capacity is live memory for the whole import.
    let mut secret = String::with_capacity(1 << 20);
    secret.push_str(&password);
    let resources = ResourcePolicy {
        max_external_resource_total_bytes: bytes.len() + (1 << 19),
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
        Err(KeyStoreError::Policy(
            PolicyViolation::ResourceLimitExceeded {
                resource: resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                ..
            }
        ))
    ));
    assert!(inventory.private_keys().is_empty());
}

#[test]
fn pbes2_cipher_prf_matrix_accepts_utf8_passwords_without_legacy_kdf() {
    // RFC 8018 PBES2 does not impose RFC 7292's legacy BMP password
    // conversion. Test every supported AES width and HMAC PRF with a
    // non-BMP UTF-8 password, including the default SHA-1 PRF.
    let password = "secret\u{1f512}";
    let private = private_key();
    let salt = b"salt beyond the old fixed thirty-two byte representation";
    let iv = [7_u8; 16];
    for (cipher, cipher_oid) in [
        (Cipher::Aes128, pkcs8::pkcs5::pbes2::AES_128_CBC_OID),
        (Cipher::Aes192, pkcs8::pkcs5::pbes2::AES_192_CBC_OID),
        (Cipher::Aes256, pkcs8::pkcs5::pbes2::AES_256_CBC_OID),
    ] {
        for (hash, prf_oid) in Hash::ALL.into_iter().zip(Hash::HMACS) {
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
                params.push(sequence(&[oid(prf_oid), encoded(5, &[])]));
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
            let contents = run(&bytes, &limits(64), password).expect("UTF-8 PBES2 import");
            assert_eq!(imported_key(&contents), private);
        }
    }
}

#[test]
fn the_password_is_requested_only_when_a_step_needs_it() {
    // One pass: an unprotected container never asks; a declined password
    // stops at the first step that needs it and leaves it unopened.
    let plain = pfx(&[data(&sequence(&[bag(
        pkcs12::PKCS_12_KEY_BAG_OID,
        &private_key(),
    )]))]);
    let contents = import::<&str, _>(&plain, &limits(64), &mut 0, || {
        panic!("no step of an unprotected container needs a password")
    })
    .expect("unprotected import");
    assert_eq!(imported_key(&contents), private_key());
    let iv = [7; 16];
    let shrouded = pfx(&[data(&sequence(&[bag(
        pkcs12::PKCS_12_PKCS8_KEY_BAG_OID,
        &sequence(&[
            pbes2_aes128(b"salt", integer(2), encoded(4, &iv)),
            encoded(
                4,
                &aes128_pbes2_ciphertext(b"secret", b"salt", iv, &private_key()),
            ),
        ]),
    )]))]);
    assert!(matches!(
        import::<&str, _>(&shrouded, &limits(64), &mut 0, || None),
        Err(KeyStoreError::ProtectedContainer)
    ));
    let (result, calls) = import_counting(&shrouded, &limits(64), &mut 0, "secret");
    assert_eq!(
        imported_key(&result.expect("shrouded import")),
        private_key()
    );
    assert_eq!(calls, 1, "requested once");
}
