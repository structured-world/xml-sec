#![cfg(feature = "xmlenc")]

use xml_sec::policy::{KeyAgreementAlgorithm, KeyEstablishmentPolicy};
use xml_sec::provider::{
    CryptoProvider, KeyAgreementParameters, RUST_CRYPTO_PROVIDER, RustCryptoDhKey,
};
use xml_sec::xmlenc::KeyEstablishmentBudget;

fn hex(input: &str) -> Vec<u8> {
    let (pairs, remainder) = input.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| {
            let digit = |b: u8| match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                _ => panic!("invalid test hex"),
            };
            digit(pair[0]) * 16 + digit(pair[1])
        })
        .collect()
}

fn domain() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    // RFC 5114 §2.1 is an informational test domain, not a secure default or
    // a mandate to use 1024-bit groups. DH is explicitly granted below.
    // https://www.rfc-editor.org/rfc/rfc5114.html#section-2.1
    (
        hex(concat!(
            "b10b8f96a080e01dde92de5eae5d54ec52c99fbcfb06a3c6",
            "9a6a9dca52d23b616073e28675a23d189838ef1e2ee652c0",
            "13ecb4aea906112324975c3cd49b83bfaccbdd7d90c4bd70",
            "98488e9c219a73724effd6fae5644738faa31a4ff55bccc0",
            "a151af5f0dc8b4bd45bf37df365c1a65e68cfda76d4da708",
            "df1fb2bc2e4a4371"
        )),
        hex("f518aa8781a8df278aba4e7d64b7cb9d49462353"),
        hex(concat!(
            "a4d1cbd5c3fd34126765a442efb99905f8104dd258ac507f",
            "d6406cff14266d31266fea1e5c41564b777e690f5504f213",
            "160217b4b01b886a5e91547f9e2749f4d7fbd7d3b9a92ee1",
            "909d0d2263f80a76a6a24c087a091f531dbf0a0169b6a28a",
            "d662a4d18e73afa32d779d5918d08bc8858f4dcef97c2a24",
            "855e6eeb22b3b2e5"
        )),
    )
}

fn policy() -> KeyEstablishmentPolicy {
    KeyEstablishmentPolicy {
        agreement_algorithms: Some(
            [KeyAgreementAlgorithm::DhEs, KeyAgreementAlgorithm::LegacyDh].into(),
        ),
        minimum_dh_modulus_bits: 1024,
        minimum_dh_subgroup_bits: 160,
        ..Default::default()
    }
}

#[test]
fn finite_field_agreement_matches_independent_rfc_vector() {
    // RFC 5114 Appendix A.1 fixes xA, yB and Z independently of this engine.
    // Check both XML algorithm identifiers and public-key export against yA.
    let (p, q, g) = domain();
    let policy = policy();
    let mut budget = KeyEstablishmentBudget::new(&policy).unwrap();
    let key = RustCryptoDhKey::from_components(
        &RUST_CRYPTO_PROVIDER,
        &mut budget,
        &p,
        &q,
        &g,
        &hex("b9a3b3ae8fefc1a2930496507086f8455d48943e"),
    )
    .unwrap();
    let public = hex(concat!(
        "2a853b3d92197501",
        "b9015b2deb3ed84f5e021dcc3e52f109d3273d2b7521281c",
        "babe0e76ff5727fa8acce26956ba9a1fca26f20228d8693f",
        "eb10841d84a7360054ece5a7f5b7a61ad3dfb3c60d2e4310",
        "6d8727da37df9cce95b478755d06bcea8f9d45965f75a5f3",
        "d1df3701165fc9e50c4279ceb07f989540ae96d5d88ed776"
    ));
    assert_eq!(key.public_key(), public);
    let peer = hex(concat!(
        "717a6cb053371ff4",
        "a3b932941c1e5663f861a1d6ad34ae66576dfb98f6c6cbf9",
        "ddd5a56c7833f6bcfdff095582ad868e440e8d09fd769e3c",
        "eccdc3d3b1e4cfa057776caaf9739b6a9fee8e7411f8d6da",
        "c09d6a4edb46cc2b5d5203090eae6126311e53fd2c14b574",
        "e6a3109a3da1be41bdceaa186f5ce06716a2b6a07b3c33fe"
    ));
    let expected = hex(concat!(
        "5c804f454d30d9c4",
        "df85271f93528c91df6b48ab5f80b3b59caac1b28f8acba9",
        "cd3e39f3cb614525d9521d2e644c53b807b810f340062f25",
        "7d7d6fbfe8d5e8f072e9b6e9afda9413eafb2e8b0699b1fb",
        "5a0caceddeaead7e9cfbb36ae2b420835bd83a19fb0b5e96",
        "bf8fa4d09e345525167ecd9155416f46f408ed31b63c6e6d"
    ));
    for algorithm in [KeyAgreementAlgorithm::DhEs, KeyAgreementAlgorithm::LegacyDh] {
        assert_eq!(
            RUST_CRYPTO_PROVIDER
                .agree_key(
                    &key,
                    &KeyAgreementParameters {
                        algorithm: algorithm.uri(),
                        peer_public_key: &peer
                    }
                )
                .unwrap(),
            expected
        );
        for invalid in [&[0][..], &[1][..], &p[..], &g[..1]] {
            assert!(
                RUST_CRYPTO_PROVIDER
                    .agree_key(
                        &key,
                        &KeyAgreementParameters {
                            algorithm: algorithm.uri(),
                            peer_public_key: invalid
                        }
                    )
                    .is_err()
            );
        }
    }
    assert!(budget.modular_work() > 0);
    assert!(budget.owned_bytes() > 0);
}

#[test]
fn finite_field_shared_secret_retains_leading_zero_octets() {
    // Independent integer modular exponentiation of the §2.1 test domain with
    // xA=24, xB=2 gives the following g^48 mod p. Its leading zero is required
    // by XMLEnc 1.1 §5.6.2; trimming changes every subsequent KDF output.
    let (p, q, g) = domain();
    let policy = policy();
    let mut budget = KeyEstablishmentBudget::new(&policy).unwrap();
    let key =
        RustCryptoDhKey::from_components(&RUST_CRYPTO_PROVIDER, &mut budget, &p, &q, &g, &[24])
            .unwrap();
    let peer = hex(concat!(
        "2acf5a75670b313325bee906c0be479fa35b5fb0acb7d3b69460268c10bc8ebe",
        "aa9573612e7ff47b9fe86db093a9768e2a2d287d09169de88540793ffbca3f6b",
        "2c99ca6e5ca0e55ccf16a6c22ad8ee3e80f758c8ce9502ec7f198786fa9d683",
        "15bd9996f34b4ecc3ae8f2dc56b13083089bcade0834943629a97540756bfaf21"
    ));
    let expected = hex(concat!(
        "002a89f6af2e9f74bdf4fd2dbc17af03ec1794aada13cbb947bccd8dbd1ae59f",
        "e461543b7deed7b1cdbe7d3d57b8a11c18b91740ba6f10cb3cfddf135621201d",
        "b72893f901c8a72c74c2a2ef8e5111b3e3cfb882ec867d6e348e0a111c333ff0",
        "e6907c47bf0ed846b3067dc7f30d594204f81b41bbba33a49e2c931c7220b604"
    ));
    assert_eq!(
        RUST_CRYPTO_PROVIDER
            .agree_key(
                &key,
                &KeyAgreementParameters {
                    algorithm: KeyAgreementAlgorithm::DhEs.uri(),
                    peer_public_key: &peer
                }
            )
            .unwrap(),
        expected
    );
}

#[test]
fn dh_permission_and_resource_gates_precede_validation() {
    // Neither mechanism availability nor a syntactically valid domain grants
    // deployment permission. A denied reservation is atomic and consumes none.
    let (p, q, g) = domain();
    let denied = KeyEstablishmentPolicy::default();
    let mut budget = KeyEstablishmentBudget::new(&denied).unwrap();
    assert!(
        RustCryptoDhKey::from_components(&RUST_CRYPTO_PROVIDER, &mut budget, &p, &q, &g, &[2])
            .is_err()
    );
    assert_eq!(budget.modular_work(), 0);
    let policy = KeyEstablishmentPolicy {
        max_modular_work: 0,
        ..policy()
    };
    let mut budget = KeyEstablishmentBudget::new(&policy).unwrap();
    assert!(
        RustCryptoDhKey::from_components(&RUST_CRYPTO_PROVIDER, &mut budget, &p, &q, &g, &[2])
            .is_err()
    );
    assert_eq!(budget.owned_bytes(), 0);
    assert_eq!(budget.modular_work(), 0);
}

#[test]
fn granting_dh_does_not_disable_default_key_strength_requirements() {
    // The wire format permits legacy domains, but enabling DH must not silently
    // disable the product's modern key-strength baseline.
    let (p, q, g) = domain();
    let permission = KeyEstablishmentPolicy {
        agreement_algorithms: policy().agreement_algorithms,
        ..Default::default()
    };
    let mut budget = KeyEstablishmentBudget::new(&permission).unwrap();
    assert!(matches!(
        RustCryptoDhKey::from_components(&RUST_CRYPTO_PROVIDER, &mut budget, &p, &q, &g, &[2]),
        Err(xml_sec::xmlenc::XmlEncError::Policy(
            xml_sec::policy::PolicyViolation::KeySize { .. }
        ))
    ));
    assert_eq!(budget.modular_work(), 0);
}

#[test]
fn malformed_dh_domains_and_private_scalars_are_rejected() {
    // Every accepted handle must have prime p/q, q | (p-1), a generator of
    // order q, and x in [2,q-2]. Never reduce invalid input modulo the domain.
    let (p, q, g) = domain();
    let policy = policy();
    for private in [&[0][..], &[1][..], q.as_slice(), p.as_slice()] {
        let mut budget = KeyEstablishmentBudget::new(&policy).unwrap();
        assert!(
            RustCryptoDhKey::from_components(
                &RUST_CRYPTO_PROVIDER,
                &mut budget,
                &p,
                &q,
                &g,
                private
            )
            .is_err()
        );
    }
    let mut composite = p.clone();
    composite[127] = 0x73;
    let mut budget = KeyEstablishmentBudget::new(&policy).unwrap();
    assert!(
        RustCryptoDhKey::from_components(
            &RUST_CRYPTO_PROVIDER,
            &mut budget,
            &composite,
            &q,
            &g,
            &[2]
        )
        .is_err()
    );
    let mut wrong_generator = g.clone();
    wrong_generator[127] ^= 1;
    let mut budget = KeyEstablishmentBudget::new(&policy).unwrap();
    assert!(
        RustCryptoDhKey::from_components(
            &RUST_CRYPTO_PROVIDER,
            &mut budget,
            &p,
            &q,
            &wrong_generator,
            &[2]
        )
        .is_err()
    );
    let mut wrong_order = q.clone();
    wrong_order[19] = 0x55;
    let mut budget = KeyEstablishmentBudget::new(&policy).unwrap();
    assert!(
        RustCryptoDhKey::from_components(
            &RUST_CRYPTO_PROVIDER,
            &mut budget,
            &p,
            &wrong_order,
            &g,
            &[2]
        )
        .is_err()
    );
}

#[test]
fn finite_field_key_agreement_reaches_public_encryption_pipeline() {
    // Opposite opaque DH handles derive the AES key inside each operation.
    // Modular allowance must be carried into encrypt/decrypt, not reset by KDF.
    use std::sync::Arc;
    use xml_sec::policy::{DecryptionPolicy, EncryptionPolicy};
    use xml_sec::xmlenc::{
        DataEncryptionAlgorithm, DecryptContext, DecryptedContent, DerivedKeyDecryptor,
        DerivedKeyInput, EncryptedDataBuilder, parse_key_derivation_method,
    };
    let (p, q, g) = domain();
    let permission = policy();
    let mut budget = KeyEstablishmentBudget::new(&permission).unwrap();
    let sender = Arc::new(
        RustCryptoDhKey::from_components(&RUST_CRYPTO_PROVIDER, &mut budget, &p, &q, &g, &[2])
            .unwrap(),
    );
    let recipient =
        RustCryptoDhKey::from_components(&RUST_CRYPTO_PROVIDER, &mut budget, &p, &q, &g, &[3])
            .unwrap();
    let decryption = DecryptionPolicy {
        key_establishment: permission.clone(),
        ..Default::default()
    };
    let method = parse_key_derivation_method(
        "<KeyDerivationMethod xmlns='http://www.w3.org/2009/xmlenc11#' Algorithm='http://www.w3.org/2009/xmlenc11#ConcatKDF'><ConcatKDFParams AlgorithmID='00616573313238'><DigestMethod xmlns='http://www.w3.org/2000/09/xmldsig#' Algorithm='http://www.w3.org/2001/04/xmlenc#sha256'/></ConcatKDFParams></KeyDerivationMethod>",
        &decryption).unwrap();
    let sender_public = sender.public_key();
    let mut legacy_budget = KeyEstablishmentBudget::new(&permission).unwrap();
    assert!(matches!(
        legacy_budget.agree_and_derive(
            &RUST_CRYPTO_PROVIDER,
            &recipient,
            &KeyAgreementParameters {
                algorithm: KeyAgreementAlgorithm::LegacyDh.uri(),
                peer_public_key: &sender_public
            },
            &method.parameters(16).unwrap()
        ),
        Err(xml_sec::xmlenc::XmlEncError::Provider(
            xml_sec::provider::ProviderError::InvalidInput(
                xml_sec::provider::ProviderInputError::LegacyDhKdfParameters
            )
        ))
    ));
    for (minimum_modulus, minimum_subgroup) in [(2048, 160), (1024, 224)] {
        let strict = KeyEstablishmentPolicy {
            minimum_dh_modulus_bits: minimum_modulus,
            minimum_dh_subgroup_bits: minimum_subgroup,
            ..permission.clone()
        };
        let mut strict_budget = KeyEstablishmentBudget::new(&strict).unwrap();
        assert!(matches!(
            strict_budget.agree_and_derive(
                &RUST_CRYPTO_PROVIDER,
                &recipient,
                &KeyAgreementParameters {
                    algorithm: KeyAgreementAlgorithm::DhEs.uri(),
                    peer_public_key: &sender_public
                },
                &method.parameters(16).unwrap()
            ),
            Err(xml_sec::xmlenc::XmlEncError::Policy(
                xml_sec::policy::PolicyViolation::KeySize { .. }
            ))
        ));
        assert_eq!(strict_budget.modular_work(), 0);
        assert_eq!(strict_budget.owned_bytes(), 0);
    }
    let builder = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm).agreement_key(
        method.clone(),
        sender,
        KeyAgreementAlgorithm::DhEs,
        recipient.public_key(),
    );
    assert!(builder.encrypt_binary(b"DH payload").is_err());
    let encrypted = builder
        .policy(EncryptionPolicy {
            key_establishment: permission,
            ..Default::default()
        })
        .encrypt_binary(b"DH payload")
        .unwrap();
    let resolver = DerivedKeyDecryptor::content(
        &method,
        DerivedKeyInput::Agreement {
            key: &recipient,
            parameters: KeyAgreementParameters {
                algorithm: KeyAgreementAlgorithm::DhEs.uri(),
                peer_public_key: &sender_public,
            },
        },
        DataEncryptionAlgorithm::Aes128Gcm,
    );
    assert_eq!(
        DecryptContext::new(&resolver)
            .policy(decryption.clone())
            .decrypt(&encrypted.encrypted_data_xml)
            .unwrap(),
        DecryptedContent::Bytes(b"DH payload".to_vec())
    );
    let denied = DecryptionPolicy {
        key_establishment: KeyEstablishmentPolicy {
            max_modular_work: 0,
            ..decryption.key_establishment
        },
        ..Default::default()
    };
    assert!(
        DecryptContext::new(&resolver)
            .policy(denied)
            .decrypt(&encrypted.encrypted_data_xml)
            .is_err()
    );
}
