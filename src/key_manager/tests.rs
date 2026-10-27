use crate::rsa_encoding::RsaPublicKeyEncoding as _;
use pkcs8::EncodePublicKey as _;
use rand_chacha::{ChaCha8Rng, rand_core::SeedableRng as _};
use rsa::RsaPublicKey;

use super::*;
use std::fmt::Write as _;

fn xml_policy(resources: ResourcePolicy) -> crate::policy::VerificationPolicy {
    crate::policy::VerificationPolicy {
        resources,
        ..crate::policy::VerificationPolicy::default()
    }
}

#[test]
fn inventory_merge_preserves_import_work() {
    // Moving inventories must not discard work spent before the merge.
    let resources = ResourcePolicy {
        max_key_import_kdf_work: 5,
        ..Default::default()
    };
    let mut inventory = KeyInventory {
        kdf_work: 2,
        ..Default::default()
    };
    inventory
        .extend(
            KeyInventory {
                kdf_work: 3,
                ..Default::default()
            },
            &resources,
        )
        .expect("exact work allowance");
    assert_eq!(inventory.key_import_kdf_work(), 5);
    assert!(matches!(
        inventory.extend(
            KeyInventory {
                kdf_work: 1,
                ..Default::default()
            },
            &resources
        ),
        Err(KeyStoreError::Policy(_))
    ));
    assert_eq!(inventory.key_import_kdf_work(), 5, "failed merge is atomic");
}

#[test]
fn repeated_pkcs12_imports_share_kdf_work() {
    // Each bundle fits by itself, but a session may not reset password work.
    let bytes = include_bytes!("../../tests/fixtures/xmlenc/01-phaos-xmlenc-3/rsa-priv-key.p12");
    let resources = ResourcePolicy {
        max_key_import_kdf_work: 10_000,
        ..ResourcePolicy::default()
    };
    let mut single = KeyInventory::default();
    single
        .add_pkcs12("first".into(), bytes, "secret", &resources)
        .expect("first bundle fits");
    let work = single.key_import_kdf_work();
    assert!(matches!(
        single.add_pkcs12("second".into(), bytes, "secret", &resources),
        Err(KeyStoreError::Policy(_))
    ));
    // Work already spent by the refused import is not refunded.
    assert!(single.key_import_kdf_work() > work);
    let exact = ResourcePolicy {
        max_key_import_kdf_work: work * 2,
        ..resources
    };
    let mut inventory = KeyInventory::default();
    inventory
        .add_pkcs12("first".into(), bytes, "secret", &exact)
        .expect("first exact-boundary bundle");
    inventory
        .add_pkcs12("second".into(), bytes, "secret", &exact)
        .expect("second exact-boundary bundle");
    assert_eq!(inventory.key_import_kdf_work(), work * 2);
}

#[test]
fn imports_donor_pkcs12_and_rejects_wrong_password() {
    // A real upstream PHAOS bundle exercises MAC, password decoding, key
    // association, and certificate import rather than a synthetic ASN.1 stub.
    let bytes = include_bytes!("../../tests/fixtures/xmlenc/01-phaos-xmlenc-3/rsa-priv-key.p12");
    let resources = ResourcePolicy::default();
    let mut inventory = KeyInventory::default();
    inventory
        .add_pkcs12("phaos".into(), bytes, "secret", &resources)
        .expect("donor PKCS#12 should import");
    assert_eq!(inventory.private_keys.len(), 1);
    assert_ne!(
        inventory.private_keys[0].certificate_chain,
        [] as [Vec<u8>; 0]
    );
    assert!(inventory.private_keys[0].usages.allows(KeyUsage::Sign));

    let mut wrong = KeyInventory::default();
    assert!(matches!(
        wrong.add_pkcs12("phaos".into(), bytes, "wrong", &resources),
        Err(KeyStoreError::ProtectedContainer)
    ));
    assert!(wrong.private_keys.is_empty());

    let oversized = ResourcePolicy {
        max_external_resource_bytes: bytes.len() - 1,
        ..ResourcePolicy::default()
    };
    assert!(matches!(
        KeyInventory::default().add_pkcs12("phaos".into(), bytes, "secret", &oversized),
        Err(KeyStoreError::Policy(
            crate::policy::PolicyViolation::ResourceLimitExceeded {
                resource: crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
                maximum,
            }
        )) if maximum == bytes.len() - 1
    ));
}

#[test]
fn pkcs12_kdf_limit_is_a_typed_policy_denial() {
    // A valid protected bundle that exceeds import work is not a bad password.
    let bytes = include_bytes!("../../tests/fixtures/xmlenc/01-phaos-xmlenc-3/rsa-priv-key.p12");
    let resources = ResourcePolicy {
        max_key_import_kdf_work: 1,
        ..ResourcePolicy::default()
    };
    assert!(matches!(
        KeyInventory::default().add_pkcs12("phaos".into(), bytes, "secret", &resources),
        Err(KeyStoreError::Policy(
            crate::policy::PolicyViolation::KdfIterationsOutsideLimit { maximum: 1 }
        ))
    ));
    assert!(matches!(
        KeyInventory::default().add_pkcs12(
            "phaos".into(),
            bytes,
            "wrong",
            &ResourcePolicy::default(),
        ),
        Err(KeyStoreError::ProtectedContainer)
    ));
}

#[test]
fn pkcs12_mac_rejects_altered_safe_before_decryption() {
    // The MAC covers the whole AuthenticatedSafe and is checked first:
    // altering a protection parameter inside it is caught as an
    // unauthenticated container before that parameter is used.
    let mut bytes =
        include_bytes!("../../tests/fixtures/xmlenc/01-phaos-xmlenc-3/rsa-priv-key.p12").to_vec();
    let offset = bytes
        .windows(4)
        .position(|v| v == [2, 2, 8, 0])
        .expect("PBKDF2 iterations");
    bytes[offset + 3] = 1;
    let resources = ResourcePolicy {
        max_key_import_kdf_work: 2048,
        ..ResourcePolicy::default()
    };
    let result = KeyInventory::default().add_pkcs12_with_password_callback(
        "limited".into(),
        &bytes,
        || Some(Zeroizing::new("secret".to_owned())),
        KeyUsages::SIGN,
        &resources,
    );
    assert!(matches!(result, Err(KeyStoreError::ProtectedContainer)));
}

#[test]
fn pkcs12_content_count_denial_is_not_a_password_error() {
    // An encrypted safe and the bags it carries exceed one candidate; with
    // the right password the refusal is the candidate policy, not a password
    // or container error.
    let bytes = include_bytes!("../../tests/fixtures/xmlenc/01-phaos-xmlenc-3/rsa-priv-key.p12");
    let resources = ResourcePolicy {
        max_key_candidates: 1,
        ..ResourcePolicy::default()
    };
    let result = KeyInventory::default().add_pkcs12_with_password_callback(
        "limited".into(),
        bytes,
        || Some(Zeroizing::new("secret".to_owned())),
        KeyUsages::SIGN,
        &resources,
    );
    assert!(matches!(
        result,
        Err(KeyStoreError::Policy(
            crate::policy::PolicyViolation::ResourceLimitExceeded {
                resource: crate::policy::resource_name::KEY_CANDIDATES,
                maximum: 1,
            }
        ))
    ));
}

#[test]
fn pkcs12_aggregate_kdf_work_preserves_policy_error() {
    // Individual counts fit, but MAC plus PBES2 exceeds one shared budget.
    let resources = ResourcePolicy {
        max_key_import_kdf_work: 3000,
        ..ResourcePolicy::default()
    };
    let bytes = include_bytes!("../../tests/fixtures/xmlenc/01-phaos-xmlenc-3/rsa-priv-key.p12");
    assert!(matches!(
        KeyInventory::default().add_pkcs12("limited".into(), bytes, "secret", &resources),
        Err(KeyStoreError::Policy(
            crate::policy::PolicyViolation::ResourceLimitExceeded {
                resource: crate::policy::resource_name::KEY_IMPORT_KDF_WORK,
                maximum: 3000,
            }
        ))
    ));
}

#[test]
fn pkcs12_workspace_denial_preserves_policy_error() {
    // KDF workspace denial must not look like a wrong password.
    let resources = ResourcePolicy {
        max_key_import_kdf_memory_bytes: 1,
        ..ResourcePolicy::default()
    };
    let bytes = include_bytes!("../../tests/fixtures/xmlenc/01-phaos-xmlenc-3/rsa-priv-key.p12");
    assert!(matches!(
        KeyInventory::default().add_pkcs12("limited".into(), bytes, "secret", &resources),
        Err(KeyStoreError::Policy(
            crate::policy::PolicyViolation::ResourceLimitExceeded {
                resource: crate::policy::resource_name::KEY_IMPORT_KDF_MEMORY,
                maximum: 1,
            }
        ))
    ));
}

#[test]
fn pkcs12_temporary_memory_shares_existing_inventory_budget() {
    // Encoded input fits, but decrypted buffers and retained vector slots
    // must not receive a fresh aggregate allowance beside existing keys.
    let resources = ResourcePolicy {
        max_external_resource_bytes: 3000,
        max_external_resource_total_bytes: 5000,
        ..ResourcePolicy::default()
    };
    let mut inventory = KeyInventory::default();
    inventory
        .add_symmetric(
            "hmac".into(),
            SymmetricKeyKind::Hmac,
            vec![1; 2000],
            KeyUsages::SIGN,
            &resources,
        )
        .expect("existing key fits");
    let bytes = include_bytes!("../../tests/fixtures/xmlenc/01-phaos-xmlenc-3/rsa-priv-key.p12");
    assert!(matches!(
        inventory.add_pkcs12("bundle".into(), bytes, "secret", &resources),
        Err(KeyStoreError::Policy(
            crate::policy::PolicyViolation::ResourceLimitExceeded {
                resource: crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                maximum: 5000
            }
        ))
    ));
    assert_eq!(inventory.symmetric_keys().len(), 1);
    assert!(inventory.private_keys().is_empty());
}

#[test]
fn private_bundle_certificates_do_not_authorize_verification() {
    // A SIGN/DECRYPT-only PKCS#12 bundle must not implicitly make its
    // associated leaf available as a verification lookup candidate.
    let bytes = include_bytes!("../../tests/fixtures/xmlenc/01-phaos-xmlenc-3/rsa-priv-key.p12");
    let resources = ResourcePolicy::default();
    let mut inventory = KeyInventory::default();
    inventory
        .add_pkcs12("private".into(), bytes, "secret", &resources)
        .expect("bundle imports");
    let leaf = inventory.private_keys()[0].certificate_chain[0].clone();
    let subject = crate::xmldsig::parse::parse_x509_certificate(&leaf)
        .expect("bundle leaf parses")
        .subject_dn;
    let key_info = KeyInfo {
        sources: vec![KeyInfoSource::X509Data(X509DataInfo {
            subject_names: vec![subject],
            ..X509DataInfo::default()
        })],
    };
    let resolver = inventory.verification_resolver();
    assert!(
        resolver
            .resolve(Some(&key_info), SignatureAlgorithm::RsaSha256)
            .expect("lookup completes")
            .is_none()
    );

    inventory
        .add_certificate_der(leaf, false, &resources)
        .expect("explicit lookup certificate imports");
    assert!(
        inventory
            .verification_resolver()
            .resolve(Some(&key_info), SignatureAlgorithm::RsaSha256)
            .expect("explicit lookup completes")
            .is_some()
    );
}

#[test]
fn stored_signing_keys_obey_operation_material_limits() {
    // An import-time resource policy must not override stricter limits
    // selected for a later signing operation.
    let resources = ResourcePolicy::default();
    let mut inventory = KeyInventory::default();
    inventory
        .add_symmetric(
            "hmac".into(),
            SymmetricKeyKind::Hmac,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            KeyUsages::SIGN,
            &resources,
        )
        .expect("HMAC imports");
    inventory
        .add_private_pem(
            "rsa".into(),
            include_bytes!("../../tests/fixtures/keys/rsa/rsa-2048-key.pem"),
            None,
            KeyUsages::SIGN,
            &resources,
        )
        .expect("RSA imports");

    for (name, algorithm, length) in [
        (
            "hmac",
            SignatureAlgorithm::HmacSha256,
            inventory.symmetric_keys[0].bytes.len(),
        ),
        (
            "rsa",
            SignatureAlgorithm::RsaSha256,
            inventory.private_keys[0].pkcs8_der.len(),
        ),
    ] {
        let mut policy = crate::policy::SigningPolicy::default();
        policy.resources.max_external_resource_bytes = length - 1;
        assert!(matches!(
            inventory.signing_key(name, algorithm, &policy),
            Err(KeyStoreError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
                    maximum,
                    actual,
                }
            )) if maximum == length - 1 && actual == length
        ));

        policy.resources.max_external_resource_bytes = length;
        policy.resources.max_external_resource_total_bytes = length - 1;
        assert!(matches!(
            inventory.signing_key(name, algorithm, &policy),
            Err(KeyStoreError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                    maximum,
                    actual,
                }
            )) if maximum == length - 1 && actual == length
        ));
    }
}

#[test]
fn named_signing_lookup_obeys_active_candidate_budget() {
    // Import limits do not authorize a later operation to scan the full inventory.
    let resources = ResourcePolicy::default();
    let mut inventory = KeyInventory::default();
    for name in ["first", "second"] {
        inventory
            .add_symmetric(
                name.into(),
                SymmetricKeyKind::Hmac,
                vec![0x42; 32],
                KeyUsages::SIGN,
                &resources,
            )
            .expect("HMAC imports");
    }
    let mut policy = crate::policy::SigningPolicy::default();
    policy.resources.max_key_candidates = 1;
    assert!(
        inventory
            .signing_key("first", SignatureAlgorithm::HmacSha256, &policy)
            .is_ok()
    );
    assert!(matches!(
        inventory.signing_key("second", SignatureAlgorithm::HmacSha256, &policy),
        Err(KeyStoreError::Policy(
            crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::KEY_CANDIDATES,
                ..
            }
        ))
    ));
}

#[cfg(feature = "xmlenc")]
#[test]
fn named_decryption_lookup_shares_candidate_budget_across_key_kinds() {
    // Scanning a symmetric miss must consume the same operation budget as
    // the subsequent private-key lookup.
    let resources = ResourcePolicy::default();
    let mut inventory = KeyInventory::default();
    inventory
        .add_symmetric(
            "aes".into(),
            SymmetricKeyKind::Aes,
            vec![0x42; 32],
            KeyUsages::DECRYPT,
            &resources,
        )
        .expect("AES imports");
    inventory
        .add_private_pem(
            "rsa".into(),
            include_bytes!("../../tests/fixtures/keys/rsa/rsa-2048-key.pem"),
            None,
            KeyUsages::DECRYPT,
            &resources,
        )
        .expect("RSA imports");
    let mut policy = crate::policy::DecryptionPolicy::default();
    policy.resources.max_key_candidates = 1;
    assert!(inventory.decryption_resolver("aes", &policy).is_ok());
    assert!(matches!(
        inventory.decryption_resolver("rsa", &policy),
        Err(KeyStoreError::Policy(
            crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::KEY_CANDIDATES,
                ..
            }
        ))
    ));
}

#[test]
fn pkcs12_imports_share_candidate_budget() {
    // Two ContentInfos and two SafeBags cost four inspections. The retained
    // key/certificate use two inventory slots, leaving too little work for
    // another bundle even though two more retained slots would fit.
    let bundle = include_bytes!("../../tests/fixtures/xmlenc/01-phaos-xmlenc-3/rsa-priv-key.p12");
    let resources = ResourcePolicy {
        max_key_candidates: 4,
        ..ResourcePolicy::default()
    };
    let mut inventory = KeyInventory::default();
    inventory
        .add_pkcs12("first".into(), bundle, "secret", &resources)
        .expect("first bundle fits");
    assert_eq!(inventory.entry_count(), 2);
    assert!(
        inventory.private_keys()[0]
            .matching_certificate_chain()
            .is_some()
    );
    assert!(
        inventory
            .add_pkcs12("second".into(), bundle, "secret", &resources)
            .is_err()
    );
}

#[test]
fn pkcs12_temporary_budget_excludes_live_input() {
    // The borrowed PFX remains live during both prepare and decrypt;
    // plaintext and KDF allocations must not reuse its allowance.
    let resources = ResourcePolicy::default();
    let mut inventory = KeyInventory::default();
    inventory
        .add_symmetric(
            "old".into(),
            SymmetricKeyKind::Hmac,
            vec![7; 32],
            KeyUsages::SIGN,
            &resources,
        )
        .expect("retained key");
    let input = [0; 128];
    let limits = inventory
        .pkcs12_import_limits("new", &input, KeyUsages::SIGN, &resources)
        .expect("import allowance");
    assert_eq!(
        limits.memory_available,
        resources.max_external_resource_total_bytes - inventory.material_bytes - 3 - input.len()
    );
}

#[test]
fn pkcs12_input_consumes_aggregate_import_budget() {
    // Repeated containers must charge encoded bytes, even when decoded material is small.
    let bundle = include_bytes!("../../tests/fixtures/xmlenc/01-phaos-xmlenc-3/rsa-priv-key.p12");
    let resources = ResourcePolicy::default();
    let mut inventory = KeyInventory::default();
    inventory
        .add_pkcs12("first".into(), bundle, "secret", &resources)
        .expect("first bundle imports");
    assert!(inventory.material_bytes >= bundle.len());
    let limited = ResourcePolicy {
        max_external_resource_total_bytes: bundle.len() * 2 - 1,
        ..resources
    };
    assert!(
        inventory
            .add_pkcs12("second".into(), bundle, "secret", &limited)
            .is_err()
    );
}

#[test]
fn pkcs12_unrelated_ca_does_not_block_private_key() {
    // Generated with OpenSSL from the tracked RSA key and unrelated CA;
    // the CA is lookup material, not a fabricated leaf certificate.
    let bundle = base64::engine::general_purpose::STANDARD
        .decode(
            include_str!("../../tests/fixtures/keys/pkcs12/rsa-key-unrelated-ca.p12.b64").trim(),
        )
        .expect("fixture base64 decodes");
    let mut inventory = KeyInventory::default();
    inventory
        .add_pkcs12(
            "ca-only".into(),
            &bundle,
            "secret",
            &ResourcePolicy::default(),
        )
        .expect("unrelated CA must not invalidate the private key");
    assert_eq!(inventory.private_keys.len(), 1);
    assert_eq!(inventory.private_keys[0].certificate_chain.len(), 1);
    assert!(!inventory.private_keys[0].has_matching_leaf);
    assert!(
        inventory
            .signing_key(
                "ca-only",
                SignatureAlgorithm::RsaSha256,
                &crate::policy::SigningPolicy::default(),
            )
            .is_ok()
    );
}

#[test]
fn pkcs12_identical_leaf_bags_are_one_candidate() {
    // OpenSSL exported the same certificate as both the leaf and an extra
    // cert bag; the inventory retains one copy for the matching key.
    let bundle = base64::engine::general_purpose::STANDARD
        .decode(include_str!("../../tests/fixtures/keys/pkcs12/rsa-duplicate-leaf.p12.b64").trim())
        .expect("fixture base64 decodes");
    let mut inventory = KeyInventory::default();
    inventory
        .add_pkcs12(
            "duplicate-leaf".into(),
            &bundle,
            "secret",
            &ResourcePolicy::default(),
        )
        .expect("identical leaf bags are not ambiguous");
    assert_eq!(inventory.private_keys[0].certificate_chain.len(), 1);
    assert!(inventory.private_keys[0].has_matching_leaf);
}

#[cfg(feature = "experimental-pq")]
#[test]
fn kem_pkcs12_auto_usage_is_decrypt_only() {
    // Convenience PKCS#12 import derives usages from the decoded key,
    // while an explicitly requested signing usage must remain forbidden.
    let key = crate::provider::RustCryptoMlKemPrivateKey::from_seed(
        crate::provider::KeyEncapsulationAlgorithm::MlKem512,
        &[3; 64],
    )
    .expect("valid ML-KEM seed");
    let der = key
        .to_pkcs8_der(crate::provider::MlKemPrivateKeyEncoding::Seed)
        .expect("seed PKCS#8 export");
    let contents = || pkcs12_import::Contents {
        private_key: Some(Zeroizing::new(der.as_bytes().to_vec())),
        certificates: Vec::new(),
    };
    let resources = ResourcePolicy::default();
    let mut inventory = KeyInventory::default();
    inventory
        .add_pkcs12_contents(
            "kem".into(),
            der.as_bytes().len(),
            contents(),
            KeyUsages::SIGN.union(KeyUsages::DECRYPT),
            &resources,
            true,
        )
        .expect("automatic recipient usages");
    assert_eq!(inventory.private_keys()[0].usages, KeyUsages::DECRYPT);
    // Explicit imports must never advertise unsupported recipient operations,
    // including mixed usages that happen to contain DECRYPT.
    for usages in [
        KeyUsages::VERIFY,
        KeyUsages::ENCRYPT,
        KeyUsages::DECRYPT.union(KeyUsages::VERIFY),
        KeyUsages::DECRYPT.union(KeyUsages::ENCRYPT),
        KeyUsages::DECRYPT.union(KeyUsages::SIGN),
    ] {
        let mut rejected = KeyInventory::default();
        assert!(
            rejected
                .add_pkcs12_contents(
                    "kem".into(),
                    der.as_bytes().len(),
                    contents(),
                    usages,
                    &resources,
                    false,
                )
                .is_err()
        );
        assert!(rejected.private_keys().is_empty());
    }
    assert!(
        KeyInventory::default()
            .add_pkcs12_contents(
                "kem".into(),
                der.as_bytes().len(),
                contents(),
                KeyUsages::SIGN,
                &resources,
                false
            )
            .is_err()
    );
}

#[test]
fn ec_pkcs12_import_is_sign_only() {
    // The convenience importer must not advertise RSA transport for EC.
    let bundle = base64::engine::general_purpose::STANDARD
        .decode(include_str!("../../tests/fixtures/keys/pkcs12/ec-key.p12.b64").trim())
        .expect("fixture base64 decodes");
    let resources = ResourcePolicy::default();
    let mut inventory = KeyInventory::default();
    inventory
        .add_pkcs12("ec".into(), &bundle, "secret", &resources)
        .expect("EC signing bundle imports");
    assert!(inventory.private_keys()[0].usages.allows(KeyUsage::Sign));
    assert!(!inventory.private_keys()[0].usages.allows(KeyUsage::Decrypt));
    assert!(
        KeyInventory::default()
            .add_pkcs12_with_usages(
                "ec".into(),
                &bundle,
                "secret",
                KeyUsages::DECRYPT,
                &resources,
            )
            .is_err()
    );
}

#[test]
fn password_callback_runs_for_protected_container() {
    // Password delivery is caller-owned and failures must not leak the
    // callback's diagnostic or retry a plaintext decoder.
    let bundle = include_bytes!("../../tests/fixtures/xmlenc/01-phaos-xmlenc-3/rsa-priv-key.p12");
    let mut inventory = KeyInventory::default();
    inventory
        .add_pkcs12_with_password_callback(
            "bundle".into(),
            bundle,
            || Some(Zeroizing::new("secret".to_owned())),
            KeyUsages::SIGN,
            &ResourcePolicy::default(),
        )
        .expect("callback password decrypts donor bundle");
    assert!(inventory.private_keys[0].usages.allows(KeyUsage::Sign));
    assert!(matches!(
        KeyInventory::default().add_pkcs12_with_password_callback(
            "bundle".into(),
            bundle,
            || None,
            KeyUsages::SIGN,
            &ResourcePolicy::default(),
        ),
        Err(KeyStoreError::ProtectedContainer)
    ));
    let limited = ResourcePolicy {
        max_external_resource_total_bytes: bundle.len() - 1,
        ..ResourcePolicy::default()
    };
    assert!(matches!(
        KeyInventory::default().add_pkcs12_with_password_callback(
            "bundle".into(),
            bundle,
            || panic!("budget must be checked before password delivery"),
            KeyUsages::SIGN,
            &limited,
        ),
        Err(KeyStoreError::Policy(
            crate::policy::PolicyViolation::ResourceLimitExceeded {
                resource: crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                ..
            }
        ))
    ));
    let limited_kdf = ResourcePolicy {
        max_key_import_kdf_work: 1,
        ..ResourcePolicy::default()
    };
    assert!(matches!(
        KeyInventory::default().add_pkcs12_with_password_callback(
            "bundle".into(),
            bundle,
            || panic!("KDF denial must precede password delivery"),
            KeyUsages::SIGN,
            &limited_kdf,
        ),
        Err(KeyStoreError::Policy(
            crate::policy::PolicyViolation::KdfIterationsOutsideLimit { maximum: 1 }
        ))
    ));
    let oversized_bundle = ResourcePolicy {
        max_external_resource_bytes: bundle.len() - 1,
        ..ResourcePolicy::default()
    };
    assert!(matches!(
        KeyInventory::default().add_pkcs12_with_password_callback(
            "bundle".into(),
            bundle,
            || panic!("size denial must precede password delivery"),
            KeyUsages::SIGN,
            &oversized_bundle,
        ),
        Err(KeyStoreError::Policy(
            crate::policy::PolicyViolation::ResourceLimitExceeded {
                resource: crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
                maximum,
            }
        )) if maximum == bundle.len() - 1
    ));
}

#[test]
fn pkcs12_callback_preflights_indefinite_outer_ber() {
    // The outer PFX may use BER indefinite length without changing MAC parameters.
    let bundle = include_bytes!("../../tests/fixtures/xmlenc/01-phaos-xmlenc-3/rsa-priv-key.p12");
    assert_eq!(bundle[0], 0x30);
    let length_octets = usize::from(bundle[1] & 0x7f);
    assert!(bundle[1] & 0x80 != 0 && length_octets > 0);
    let mut ber = vec![0x30, 0x80];
    ber.extend_from_slice(&bundle[2 + length_octets..]);
    ber.extend_from_slice(&[0, 0]);
    let resources = ResourcePolicy {
        max_key_import_kdf_work: 1,
        ..ResourcePolicy::default()
    };
    assert!(matches!(
        KeyInventory::default().add_pkcs12_with_password_callback(
            "bundle".into(),
            &ber,
            || panic!("BER MAC KDF denial must precede password delivery"),
            KeyUsages::SIGN,
            &resources,
        ),
        Err(KeyStoreError::Policy(
            crate::policy::PolicyViolation::KdfIterationsOutsideLimit { maximum: 1 }
        ))
    ));
}

#[test]
fn donor_xml_store_preserves_private_dsa_material() {
    // xmlsec's non-standard DSA X must be checked against Y, not silently
    // dropped while presenting the named key as usable for signing.
    let bytes = include_bytes!("../../tests/fixtures/keys/xmlsec/mixed-keys.xml");
    let inventory = KeyInventory::from_xml_bytes(
        bytes,
        &xml_policy(ResourcePolicy::default()),
        XmlBackend::default(),
    )
    .expect("donor key store should parse");
    let dsa = inventory
        .private_keys
        .iter()
        .find(|entry| entry.name == "test-dsa")
        .expect("DSA private X should be imported");
    assert!(dsa.usages.allows(KeyUsage::Sign));
    assert!(!dsa.usages.allows(KeyUsage::Decrypt));
    assert!(DsaSigningKey::from_pkcs8_der(&dsa.pkcs8_der).is_ok());
    let dsa_public = inventory
        .public_keys()
        .iter()
        .find(|entry| entry.name == "test-dsa")
        .expect("DSA public entry is retained");
    assert_eq!(dsa_public.usages, KeyUsages::VERIFY);
}

#[test]
fn xml_store_charges_retained_decoded_material() {
    // DSA retains public components, private PKCS#8 and three name copies.
    // A long valid name makes retained bytes exceed the encoded source.
    let source = include_str!("../../tests/fixtures/keys/xmlsec/mixed-keys.xml");
    let marker = source.find("<KeyName>test-dsa</KeyName>").expect("DSA key");
    let start = source[..marker].rfind("<KeyInfo").expect("DSA KeyInfo");
    let end = marker + source[marker..].find("</KeyInfo>").expect("DSA end") + "</KeyInfo>".len();
    let xml = format!(
        "<Keys xmlns=\"{XMLSEC_NS}\">{}</Keys>",
        source[start..end]
            .replace('\n', "")
            .replace("test-dsa", &"name".repeat(512))
    );
    let inventory = KeyInventory::from_xml_bytes(
        xml.as_bytes(),
        &xml_policy(ResourcePolicy::default()),
        XmlBackend::default(),
    )
    .expect("compact DSA store imports");
    let retained = inventory.retained_material_bytes().expect("bounded tally");
    assert_eq!(inventory.material_bytes, xml.len() + retained);
    assert!(retained >= inventory.private_keys[0].pkcs8_der.len());
    assert!(
        retained > xml.len(),
        "fixture must distinguish retained bytes from source bytes"
    );
    let resources = ResourcePolicy {
        max_external_resource_total_bytes: retained - 1,
        ..ResourcePolicy::default()
    };
    assert!(matches!(
        KeyInventory::from_xml_bytes(
            xml.as_bytes(),
            &xml_policy(resources),
            XmlBackend::default()
        ),
        Err(KeyStoreError::Policy(
            crate::policy::PolicyViolation::ResourceLimitExceeded {
                resource: crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                ..
            }
        ))
    ));
}

#[test]
fn xml_import_session_keeps_failed_work_and_preflights_live_material() {
    // Retrying malformed input cannot refund candidate inspections; a
    // full live inventory rejects the next source before XML parsing.
    let xml = |value: &str| {
        format!(
            "<Keys xmlns=\"{XMLSEC_NS}\" xmlns:ds=\"{XMLDSIG_NS}\"><ds:KeyInfo><ds:KeyName>a</ds:KeyName><ds:KeyValue><HMACKeyValue>{value}</HMACKeyValue></ds:KeyValue></ds:KeyInfo></Keys>"
        )
    };
    let policy = xml_policy(ResourcePolicy {
        max_key_candidates: 1,
        ..ResourcePolicy::default()
    });
    let mut importer = XmlKeyStoreImporter::new(&policy, XmlBackend::default()).expect("session");
    assert!(matches!(
        importer.import(xml("!").as_bytes()),
        Err(KeyStoreError::Invalid(_))
    ));
    assert!(matches!(
        importer.import(xml("AA==").as_bytes()),
        Err(KeyStoreError::Policy(
            crate::policy::PolicyViolation::ResourceLimitExceeded {
                resource: crate::policy::resource_name::KEY_CANDIDATES,
                maximum: 1
            }
        ))
    ));
    assert_eq!(importer.finish().entry_count(), 0);
    let valid = xml("AA==");
    let policy = xml_policy(ResourcePolicy {
        // Source, decoded byte, inventory name, and duplicate-name copy.
        max_external_resource_total_bytes: valid.len() + 3,
        ..ResourcePolicy::default()
    });
    let mut importer = XmlKeyStoreImporter::new(&policy, XmlBackend::default()).expect("session");
    importer
        .import(valid.as_bytes())
        .expect("first source fits exactly");
    let consumed = importer.parse_work.consumed();
    assert!(matches!(
        importer.import(b"!!"),
        Err(KeyStoreError::Policy(
            crate::policy::PolicyViolation::ResourceLimitExceeded {
                resource: crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                ..
            }
        ))
    ));
    assert_eq!(
        importer.parse_work.consumed(),
        consumed,
        "no parser work after byte denial"
    );
    assert_eq!(importer.finish().entry_count(), 1);
}

#[test]
fn xml_store_rejects_empty_symmetric_material() {
    // Empty decoded secrets are invalid at the same boundary as direct imports.
    for kind in ["HMACKeyValue", "AESKeyValue", "DESKeyValue"] {
        let xml = format!(
            "<Keys xmlns=\"{XMLSEC_NS}\"><KeyInfo xmlns=\"{XMLDSIG_NS}\"><KeyName>empty</KeyName><KeyValue><{kind} xmlns=\"{XMLSEC_NS}\"/></KeyValue></KeyInfo></Keys>"
        );
        assert!(
            KeyInventory::from_xml_bytes(
                xml.as_bytes(),
                &xml_policy(ResourcePolicy::default()),
                XmlBackend::default(),
            )
            .is_err()
        );
    }
}

#[test]
fn aes_imports_require_supported_key_widths() {
    // Both direct and XML key stores must reject widths unusable by AES-CBC/GCM.
    let resources = ResourcePolicy::default();
    for length in [1, 15, 17, 23, 25, 31, 33] {
        let mut inventory = KeyInventory::default();
        assert!(
            inventory
                .add_symmetric(
                    "aes".into(),
                    SymmetricKeyKind::Aes,
                    vec![0; length],
                    KeyUsages::ENCRYPT,
                    &resources,
                )
                .is_err()
        );
        let xml = format!(
            "<Keys xmlns=\"{XMLSEC_NS}\"><KeyInfo xmlns=\"{XMLDSIG_NS}\"><KeyName>aes</KeyName><KeyValue><AESKeyValue xmlns=\"{XMLSEC_NS}\">{}</AESKeyValue></KeyValue></KeyInfo></Keys>",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, vec![0; length])
        );
        assert!(
            KeyInventory::from_xml_bytes(
                xml.as_bytes(),
                &xml_policy(resources.clone()),
                XmlBackend::default(),
            )
            .is_err()
        );
    }
    for length in [16, 24, 32] {
        let mut inventory = KeyInventory::default();
        inventory
            .add_symmetric(
                "aes".into(),
                SymmetricKeyKind::Aes,
                vec![0; length],
                KeyUsages::ENCRYPT,
                &resources,
            )
            .expect("AES-128/192/256 key imports");
    }
}

#[test]
fn unsupported_des_material_is_not_authorized() {
    // A parsed legacy DES value must not advertise an operation that the
    // encryption pipeline cannot execute.
    let resources = ResourcePolicy::default();
    let mut inventory = KeyInventory::default();
    assert!(
        inventory
            .add_symmetric(
                "des".into(),
                SymmetricKeyKind::Des,
                vec![0x42; 8],
                KeyUsages::ENCRYPT,
                &resources,
            )
            .is_err()
    );
    let xml = format!(
        "<Keys xmlns=\"{XMLSEC_NS}\"><KeyInfo xmlns=\"{XMLDSIG_NS}\"><KeyName>des</KeyName><KeyValue><DESKeyValue xmlns=\"{XMLSEC_NS}\">QkJCQkJCQkI=</DESKeyValue></KeyValue></KeyInfo></Keys>"
    );
    assert!(
        KeyInventory::from_xml_bytes(
            xml.as_bytes(),
            &xml_policy(resources.clone()),
            XmlBackend::default(),
        )
        .is_err()
    );
}

#[test]
fn xml_store_accepts_xmlsig11_ec_key_value() {
    // XMLDSig 1.1 ECKeyValue must be recognized as public material.
    let pem = pem::parse(include_bytes!(
        "../../tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem"
    ))
    .expect("EC public PEM decodes");
    let (_, spki) =
        x509_parser::x509::SubjectPublicKeyInfo::from_der(pem.contents()).expect("EC SPKI parses");
    let point =
        base64::engine::general_purpose::STANDARD.encode(spki.subject_public_key.data.as_ref());
    let xml = format!(
        "<Keys xmlns=\"{XMLSEC_NS}\"><KeyInfo xmlns=\"{XMLDSIG_NS}\"><KeyName>ec</KeyName><KeyValue><ECKeyValue xmlns=\"{XMLDSIG11_NS}\"><NamedCurve URI=\"urn:oid:1.2.840.10045.3.1.7\"/><PublicKey>{point}</PublicKey></ECKeyValue></KeyValue></KeyInfo></Keys>"
    );
    let store = KeyInventory::from_xml_bytes(
        xml.as_bytes(),
        &xml_policy(ResourcePolicy::default()),
        XmlBackend::default(),
    )
    .expect("ECKeyValue namespace is supported");
    assert_eq!(store.public_keys().len(), 1);
    assert_eq!(store.public_keys()[0].usages, KeyUsages::VERIFY);
    assert!(
        store.public_keys()[0]
            .key_info
            .sources
            .iter()
            .any(|source| matches!(source, KeyInfoSource::KeyValue(KeyValueInfo::Ec { .. })))
    );
}

#[test]
fn xml_store_der_keys_share_one_x509_work_budget() {
    // Every key read while loading one store is paid by the same X.509
    // work account: the allowance that admits one DEREncodedKeyValue must
    // not admit two, as it already does not for two KeyValue entries.
    let encoded = base64::engine::general_purpose::STANDARD.encode(include_bytes!(
        "../../tests/fixtures/xmlenc/keys/ec/ec-prime256v1-pubkey.der"
    ));
    let store = |keys: usize| {
        let mut xml = format!("<Keys xmlns=\"{XMLSEC_NS}\">");
        for index in 0..keys {
            write!(xml,
                    "<KeyInfo xmlns=\"{XMLDSIG_NS}\"><KeyName>ec{index}</KeyName><DEREncodedKeyValue xmlns=\"{XMLDSIG11_NS}\">{encoded}</DEREncodedKeyValue></KeyInfo>"
                ).expect("writing into String is infallible");
        }
        xml.push_str("</Keys>");
        xml
    };
    let import = |xml: &str, max_x509_work: usize| {
        KeyInventory::from_xml_bytes(
            xml.as_bytes(),
            &xml_policy(ResourcePolicy {
                max_x509_work,
                ..ResourcePolicy::default()
            }),
            XmlBackend::default(),
        )
    };
    let (one, two) = (store(1), store(2));
    let (mut refused, mut admitted) = (0_usize, ResourcePolicy::default().max_x509_work);
    assert!(import(&one, admitted).is_ok(), "the default admits one key");
    while admitted - refused > 1 {
        let middle = refused + (admitted - refused) / 2;
        if import(&one, middle).is_ok() {
            admitted = middle;
        } else {
            refused = middle;
        }
    }
    assert!(matches!(
        import(&two, admitted),
        Err(KeyStoreError::Policy(
            crate::policy::PolicyViolation::ResourceLimitExceeded {
                resource: crate::policy::resource_name::X509_WORK,
                ..
            }
        ))
    ));
}

#[cfg(feature = "legacy-algorithms")]
#[test]
fn xml_store_imports_triple_des_without_granting_operation_permission() {
    // A supported key encoding grants usage, not algorithm policy permission;
    // an eight-byte DES key must never be mistaken for a three-key TDEA key.
    let encoded = base64::engine::general_purpose::STANDARD.encode([0x31; 24]);
    let xml = format!(
        "<Keys xmlns=\"{XMLSEC_NS}\"><KeyInfo xmlns=\"{XMLDSIG_NS}\"><KeyName>des</KeyName><KeyValue><DESKeyValue xmlns=\"{XMLSEC_NS}\">{encoded}</DESKeyValue></KeyValue></KeyInfo></Keys>"
    );
    let store = KeyInventory::from_xml_bytes(
        xml.as_bytes(),
        &xml_policy(ResourcePolicy::default()),
        XmlBackend::default(),
    )
    .expect("a three-key TDEA inventory entry is supported");
    assert_eq!(store.symmetric_keys()[0].kind, SymmetricKeyKind::Des);
    assert_eq!(store.symmetric_keys()[0].bytes.as_slice(), &[0x31; 24]);
    assert!(store.symmetric_keys()[0].usages.allows(KeyUsage::Decrypt));
}

#[test]
fn xml_store_rejects_unusable_public_key_values() {
    // Malformed supported public-key material must fail at import, not at verification.
    let cases = [
        "<RSAKeyValue><Modulus></Modulus><Exponent>AQAB</Exponent></RSAKeyValue>",
        "<ECKeyValue xmlns=\"http://www.w3.org/2009/xmldsig11#\"><NamedCurve URI=\"urn:oid:1.2.840.10045.3.1.7\"/><PublicKey>AQ==</PublicKey></ECKeyValue>",
    ];
    for key in cases {
        let xml = format!(
            "<Keys xmlns=\"{XMLSEC_NS}\"><KeyInfo xmlns=\"{XMLDSIG_NS}\"><KeyName>invalid</KeyName><KeyValue>{key}</KeyValue></KeyInfo></Keys>"
        );
        assert!(
            KeyInventory::from_xml_bytes(
                xml.as_bytes(),
                &xml_policy(ResourcePolicy::default()),
                XmlBackend::default(),
            )
            .is_err()
        );
    }
}

#[test]
fn xml_store_import_limits_preserve_policy_errors() {
    // Limit denials must not look like malformed stores or candidate misses.
    let xml = format!(
        "<Keys xmlns=\"{XMLSEC_NS}\"><KeyInfo xmlns=\"{XMLDSIG_NS}\"><KeyName>key</KeyName><KeyValue><HMACKeyValue xmlns=\"{XMLSEC_NS}\">c2VjcmV0</HMACKeyValue></KeyValue></KeyInfo></Keys>"
    );
    let two = xml.replace(
        "</Keys>",
        &format!(
            "{} </Keys>",
            xml[xml.find("<KeyInfo").expect("fixture has KeyInfo")
                ..xml.find("</Keys>").expect("fixture has Keys end tag")]
                .replace(">key<", ">other<")
        ),
    );
    for (bytes, resources, expected) in [
        (
            xml.as_bytes(),
            ResourcePolicy {
                max_external_resource_bytes: xml.len() - 1,
                ..ResourcePolicy::default()
            },
            crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
        ),
        (
            xml.as_bytes(),
            ResourcePolicy {
                max_external_resource_total_bytes: xml.len() - 1,
                ..ResourcePolicy::default()
            },
            crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
        ),
        (
            two.as_bytes(),
            ResourcePolicy {
                max_key_candidates: 1,
                ..ResourcePolicy::default()
            },
            crate::policy::resource_name::KEY_CANDIDATES,
        ),
    ] {
        assert!(
            matches!(KeyInventory::from_xml_bytes(bytes, &xml_policy(resources), XmlBackend::default()),
                Err(KeyStoreError::Policy(crate::policy::PolicyViolation::ResourceLimitExceeded { resource, .. })) if resource == expected)
        );
    }
    let mut inventory = KeyInventory::default();
    let resources = ResourcePolicy {
        max_external_resource_total_bytes: 3,
        ..ResourcePolicy::default()
    };
    assert!(matches!(
        inventory.add_symmetric(
            "key".into(),
            SymmetricKeyKind::Hmac,
            vec![7; 32],
            KeyUsages::SIGN,
            &resources
        ),
        Err(KeyStoreError::Policy(
            crate::policy::PolicyViolation::ResourceLimitExceeded {
                resource: crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                ..
            }
        ))
    ));
}

#[test]
fn xml_store_enforces_all_parser_resource_limits() {
    // Import must not skip the depth, namespace or cumulative work limits.
    let xml = format!(
        "<Keys xmlns=\"{XMLSEC_NS}\" xmlns:a=\"urn:a\" xmlns:b=\"urn:b\"><KeyInfo xmlns=\"{XMLDSIG_NS}\"><KeyName>key</KeyName><KeyValue><HMACKeyValue xmlns=\"{XMLSEC_NS}\">c2VjcmV0</HMACKeyValue></KeyValue></KeyInfo></Keys>"
    );
    for resources in [
        ResourcePolicy {
            max_xml_depth: 2,
            ..ResourcePolicy::default()
        },
        ResourcePolicy {
            max_xml_namespace_bindings: 1,
            ..ResourcePolicy::default()
        },
        ResourcePolicy {
            max_xml_parse_work_bytes: 1,
            ..ResourcePolicy::default()
        },
    ] {
        assert!(
            KeyInventory::from_xml_bytes(
                xml.as_bytes(),
                &xml_policy(resources),
                XmlBackend::default()
            )
            .is_err_and(|error| matches!(error, KeyStoreError::Policy(_))),
            "parser policy denial must retain its type in key stores"
        );
    }
}

#[test]
fn xml_store_bounds_source_before_utf16_decode() {
    // The source-byte ceiling must be checked before UTF-16 expansion or parsing.
    let xml = format!("<Keys xmlns=\"{XMLSEC_NS}\"/>");
    let mut bytes = vec![0xff, 0xfe];
    for unit in xml.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    let resources = ResourcePolicy {
        max_xml_document_bytes: xml.len() + 1,
        ..ResourcePolicy::default()
    };
    assert!(bytes.len() > resources.max_xml_document_bytes);
    assert!(
        KeyInventory::from_xml_bytes(&bytes, &xml_policy(resources), XmlBackend::default())
            .is_err()
    );
}

#[test]
fn xml_store_uses_operation_xml_policy() {
    // Internal DTD permission must come from the operation snapshot, not
    // an importer-local default that rejects a caller-authorized store.
    let xml = format!(
        "<!DOCTYPE Keys [<!ENTITY key 'named'>]><Keys xmlns=\"{XMLSEC_NS}\"><KeyInfo xmlns=\"{XMLDSIG_NS}\"><KeyName>&key;</KeyName><KeyValue><HMACKeyValue xmlns=\"{XMLSEC_NS}\">c2VjcmV0</HMACKeyValue></KeyValue></KeyInfo></Keys>"
    );
    let denied = crate::policy::VerificationPolicy::default();
    assert!(KeyInventory::from_xml_bytes(xml.as_bytes(), &denied, XmlBackend::default()).is_err());
    let mut allowed = denied;
    allowed.xml.allow_internal_dtd = true;
    assert!(KeyInventory::from_xml_bytes(xml.as_bytes(), &allowed, XmlBackend::default()).is_ok());
}

#[test]
fn ec_public_key_cannot_authorize_encryption() {
    // EC material can verify signatures but cannot serve as an RSA recipient.
    let resources = ResourcePolicy::default();
    let ec = include_bytes!("../../tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem");
    let cert = include_bytes!("../../tests/fixtures/keys/ec/ec-prime256v1-cert.pem");
    let mut store = KeyInventory::default();
    store
        .add_public_pem("ec".into(), ec, &resources)
        .expect("EC public key imports");
    assert_eq!(store.public_keys()[0].usages, KeyUsages::VERIFY);
    assert!(
        store
            .add_public_pem_with_usages("ec-encrypt".into(), ec, KeyUsages::ENCRYPT, &resources)
            .is_err()
    );
    let cert_der = pem::parse(cert)
        .expect("EC certificate PEM decodes")
        .into_contents();
    store
        .add_public_der("ec-cert".into(), cert_der.clone(), &resources)
        .expect("EC certificate imports");
    assert_eq!(store.public_keys()[1].usages, KeyUsages::VERIFY);
    assert!(
        store
            .add_public_der_with_usages(
                "ec-cert-encrypt".into(),
                cert_der,
                KeyUsages::ENCRYPT,
                &resources
            )
            .is_err()
    );
}

#[test]
fn xml_store_rejects_policy_above_absolute_ceiling() {
    // Public imports cannot bypass hard ceilings with an unvalidated policy.
    let resources = ResourcePolicy {
        max_xml_nodes: crate::hard_limits::XML_DOCUMENT_NODE_CEILING as usize + 1,
        ..ResourcePolicy::default()
    };
    let xml = format!("<Keys xmlns=\"{XMLSEC_NS}\"/>");
    assert!(
        KeyInventory::from_xml_bytes(
            xml.as_bytes(),
            &xml_policy(resources.clone()),
            XmlBackend::default(),
        )
        .is_err()
    );
    assert!(
        KeyInventory::default()
            .add_symmetric(
                "key".into(),
                SymmetricKeyKind::Hmac,
                b"secret".to_vec(),
                KeyUsages::SIGN,
                &resources,
            )
            .is_err()
    );
}

#[test]
fn ec_private_key_cannot_advertise_rsa_decryption() {
    // Only RSA private material can satisfy the inventory's decrypt API.
    let pem = include_bytes!("../../tests/fixtures/keys/ec/ec-prime256v1-key.pem");
    assert!(
        KeyInventory::default()
            .add_private_pem(
                "ec".into(),
                pem,
                None,
                KeyUsages::DECRYPT,
                &ResourcePolicy::default(),
            )
            .is_err()
    );
}

#[test]
fn imports_rsa_pkcs1_pem_and_resolves_named_spki() {
    // Traditional RSA import and named public lookup share one inventory,
    // while the resolver still applies the operation's verification policy.
    let private_pem = include_str!("../../tests/fixtures/keys/rsa/rsa-2048-key.pem");
    let rsa = RsaPrivateKey::from_pkcs8_pem(private_pem).expect("RSA fixture parses");
    let pkcs1 = rsa.to_pkcs1_der().expect("RSA fixture encodes as PKCS#1");
    let public = rsa
        .to_public_key()
        .to_public_key_der()
        .expect("RSA fixture has SPKI");
    let resources = ResourcePolicy::default();
    let mut inventory = KeyInventory::default();
    inventory
        .add_private_der(
            "key".into(),
            pkcs1.as_bytes(),
            None,
            KeyUsages::SIGN.union(KeyUsages::DECRYPT),
            &resources,
        )
        .expect("PKCS#1 private key imports");
    inventory
        .add_public_der("verify-key".into(), public.as_bytes().to_vec(), &resources)
        .expect("public SPKI imports");
    assert!(inventory.private_keys[0].usages.allows(KeyUsage::Sign));
    let mut info = KeyInfo::default();
    info.sources
        .push(KeyInfoSource::KeyName("verify-key".into()));
    let resolver = inventory.verification_resolver();
    let candidate = resolver
        .resolve(Some(&info), SignatureAlgorithm::RsaSha256)
        .expect("named public key resolves");
    assert!(candidate.is_some());
}

#[test]
fn rejects_unknown_pem_text_and_duplicate_names() {
    // PEM is a single armor block; unrelated trailing data must not be
    // silently skipped by the general-purpose PEM parser.
    let public = include_bytes!("../../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    let mut inventory = KeyInventory::default();
    let resources = ResourcePolicy::default();
    inventory
        .add_public_pem("first".into(), public, &resources)
        .expect("public PEM imports");
    assert!(matches!(
        inventory.add_public_pem("first".into(), public, &resources),
        Err(KeyStoreError::Selection("duplicate key name"))
    ));
    let mut trailing = public.to_vec();
    trailing.extend_from_slice(b"\nnot a key");
    assert!(
        inventory
            .add_public_pem("other".into(), &trailing, &resources)
            .is_err()
    );
}

#[test]
fn public_pem_label_rejects_certificate_payload() {
    // Strict label dispatch must not inherit generic DER's certificate fallback.
    let certificate = pem::parse(include_bytes!(
        "../../tests/fixtures/keys/rsa/rsa-2048-cert.pem"
    ))
    .expect("certificate")
    .into_contents();
    let mislabeled = pem::encode(&pem::Pem::new("PUBLIC KEY", certificate.clone()));
    let resources = ResourcePolicy::default();
    for usages in [None, Some(KeyUsages::VERIFY)] {
        let mut inventory = KeyInventory::default();
        assert!(matches!(
            inventory.add_public_pem_inner("key".into(), mislabeled.as_bytes(), usages, &resources),
            Err(KeyStoreError::Selection("invalid PUBLIC KEY payload"))
        ));
        assert!(inventory.public_keys().is_empty());
    }
    KeyInventory::default()
        .add_public_der("cert".into(), certificate, &resources)
        .expect("generic DER intentionally accepts certificates");
    KeyInventory::default()
        .add_public_pem(
            "spki".into(),
            include_bytes!("../../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"),
            &resources,
        )
        .expect("correct SPKI label");
}

#[test]
fn rsa_spki_import_rejects_even_public_exponent() {
    // ASN.1 shape alone must not grant verify/encrypt usages to an unusable RSA key.
    let mut der = single_pem_block(
        include_bytes!("../../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"),
        ResourcePolicy::default().max_external_resource_bytes,
    )
    .expect("public key fixture")
    .into_contents();
    let exponent = der
        .windows(5)
        .position(|bytes| bytes == [0x02, 0x03, 0x01, 0x00, 0x01])
        .expect("RSA exponent in SPKI");
    der[exponent + 4] = 0;
    assert!(
        KeyInventory::default()
            .add_public_der("invalid".into(), der, &ResourcePolicy::default())
            .is_err()
    );
}

#[test]
fn rsa_public_pkcs1_pem_is_bounded_before_bigint_decode() {
    // The borrowed ASN.1 modulus is checked before RSA allocates integers.
    let modulus = vec![1_u8; crate::hard_limits::RSA_MODULUS_BIT_CEILING.div_ceil(8) + 1];
    let exponent = [1_u8, 0, 1];
    let public = pkcs1::RsaPublicKeyRef {
        modulus: der::asn1::UintRef::new(&modulus).expect("valid modulus"),
        public_exponent: der::asn1::UintRef::new(&exponent).expect("valid exponent"),
    };
    let pem = pem::encode(&pem::Pem::new(
        "RSA PUBLIC KEY",
        der::Encode::to_der(&public).expect("encodable RSA public key"),
    ));
    assert!(matches!(
        KeyInventory::default().add_public_pem(
            "oversized".into(),
            pem.as_bytes(),
            &ResourcePolicy::default(),
        ),
        Err(KeyStoreError::Selection(
            "RSA public key exceeds safety limit"
        ))
    ));
}

#[test]
fn direct_inventory_names_consume_resource_budget() {
    // Caller-owned names must not bypass per-resource or retained aggregate bounds.
    let resources = ResourcePolicy {
        max_external_resource_bytes: 64,
        max_external_resource_total_bytes: 100,
        ..ResourcePolicy::default()
    };
    let mut inventory = KeyInventory::default();
    assert!(
        inventory
            .add_symmetric(
                "x".repeat(65),
                SymmetricKeyKind::Hmac,
                vec![7; 32],
                KeyUsages::SIGN,
                &resources,
            )
            .is_err()
    );
    inventory
        .add_symmetric(
            "a".repeat(40),
            SymmetricKeyKind::Hmac,
            vec![7; 32],
            KeyUsages::SIGN,
            &resources,
        )
        .expect("first named key fits");
    assert!(
        inventory
            .add_symmetric(
                "b".repeat(40),
                SymmetricKeyKind::Hmac,
                vec![8; 32],
                KeyUsages::SIGN,
                &resources,
            )
            .is_err()
    );
}

#[test]
fn private_pem_label_cannot_enable_der_fallback() {
    // A protected label must never import plaintext, even with a password.
    let plain = pem::parse(include_bytes!(
        "../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
    ))
    .expect("fixture")
    .into_contents();
    let mislabeled = pem::encode(&pem::Pem::new("ENCRYPTED PRIVATE KEY", plain));
    for password in [None, Some(b"ignored".as_slice())] {
        let mut inventory = KeyInventory::default();
        assert!(matches!(
            inventory.add_private_pem(
                "key".into(),
                mislabeled.as_bytes(),
                password,
                KeyUsages::SIGN,
                &ResourcePolicy::default()
            ),
            Err(KeyStoreError::ProtectedContainer)
        ));
        assert!(inventory.private_keys.is_empty());
        assert_eq!(inventory.material_bytes, 0);
    }
}

#[test]
fn encrypted_pkcs8_callback_checks_remaining_work() {
    use der::Encode as _;
    use pkcs8::pkcs5::{EncryptionScheme, pbes2};
    // Failed decryption consumes work. A later container must not request
    // another secret when its visible derivation exceeds the remainder.
    let envelope = EncryptedPrivateKeyInfoRef {
        encryption_algorithm: EncryptionScheme::Pbes2(pbes2::Parameters {
            kdf: pbes2::Kdf::Pbkdf2(pbes2::Pbkdf2Params {
                salt: pbes2::Salt::new(b"12345678").expect("salt"),
                iteration_count: 2,
                key_length: None,
                prf: pbes2::Pbkdf2Prf::HmacWithSha256,
            }),
            encryption: pbes2::EncryptionScheme::Aes256Cbc { iv: [0; 16] },
        }),
        encrypted_data: der::asn1::OctetStringRef::new(&[0; 64]).expect("ciphertext"),
    }
    .to_der()
    .expect("envelope");
    let resources = ResourcePolicy {
        max_key_import_kdf_work: 4,
        ..ResourcePolicy::default()
    };
    let mut inventory = KeyInventory::default();
    assert!(matches!(
        inventory.add_private_der(
            "first".into(),
            &envelope,
            Some(b"wrong"),
            KeyUsages::SIGN,
            &resources,
        ),
        Err(KeyStoreError::ProtectedContainer)
    ));
    assert_eq!(inventory.key_import_kdf_work(), 3);
    let calls = std::cell::Cell::new(0);
    let result = inventory.add_private_der_with_password_callback(
        "second".into(),
        &envelope,
        || {
            calls.set(calls.get() + 1);
            Some(Zeroizing::new(b"wrong".to_vec()))
        },
        KeyUsages::SIGN,
        &resources,
    );
    assert_eq!(calls.get(), 0, "preflight precedes secret acquisition");
    assert!(matches!(result, Err(KeyStoreError::Policy(_))));
    assert_eq!(inventory.key_import_kdf_work(), 3);
    // An exact remaining derivation is allowed to request the password.
    let exact = ResourcePolicy {
        max_key_import_kdf_work: 6,
        ..resources
    };
    assert!(matches!(
        inventory.add_private_der_with_password_callback(
            "third".into(),
            &envelope,
            || {
                calls.set(calls.get() + 1);
                Some(Zeroizing::new(b"wrong".to_vec()))
            },
            KeyUsages::SIGN,
            &exact,
        ),
        Err(KeyStoreError::ProtectedContainer)
    ));
    assert_eq!(calls.get(), 1);
    assert_eq!(inventory.key_import_kdf_work(), 6);
}

#[test]
fn encrypted_pkcs8_requires_correct_password_without_plaintext_fallback() {
    // Wrong passwords must not retry another format or leave a partial
    // registration in the caller-owned inventory.
    let private_pem = include_str!("../../tests/fixtures/keys/rsa/rsa-2048-key.pem");
    let rsa = RsaPrivateKey::from_pkcs8_pem(private_pem).expect("RSA fixture parses");
    let plain = rsa.to_pkcs8_der().expect("RSA fixture encodes as PKCS#8");
    let mut rng = ChaCha8Rng::seed_from_u64(0xA11C_E501);
    let encrypted = PrivateKeyInfoRef::try_from(plain.as_bytes())
        .expect("PKCS#8 reference parses")
        .encrypt_with_rng(&mut rng, b"correct")
        .expect("PKCS#8 fixture encrypts");
    let resources = ResourcePolicy::default();
    let mut inventory = KeyInventory::default();
    let restricted = ResourcePolicy {
        max_key_import_kdf_work: 1,
        ..ResourcePolicy::default()
    };
    assert!(matches!(
        inventory.add_private_der(
            "restricted".into(),
            encrypted.as_bytes(),
            Some(b"correct"),
            KeyUsages::SIGN,
            &restricted,
        ),
        Err(KeyStoreError::Policy(
            crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::KEY_IMPORT_KDF_WORK,
                maximum: 1,
                ..
            }
        ))
    ));
    let callback_calls = std::cell::Cell::new(0);
    assert!(matches!(
        inventory.add_private_der_with_password_callback(
            "restricted-callback".into(),
            encrypted.as_bytes(),
            || {
                callback_calls.set(callback_calls.get() + 1);
                Some(Zeroizing::new(b"correct".to_vec()))
            },
            KeyUsages::SIGN,
            &restricted,
        ),
        Err(KeyStoreError::Policy(
            crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::KEY_IMPORT_KDF_WORK,
                maximum: 1,
                ..
            }
        ))
    ));
    assert_eq!(callback_calls.get(), 0);
    assert!(matches!(
        inventory.add_private_der(
            "protected".into(),
            encrypted.as_bytes(),
            Some(b"wrong"),
            KeyUsages::SIGN,
            &resources,
        ),
        Err(KeyStoreError::ProtectedContainer)
    ));
    assert!(inventory.private_keys.is_empty());
    inventory
        .add_private_der(
            "protected".into(),
            encrypted.as_bytes(),
            Some(b"correct"),
            KeyUsages::SIGN,
            &resources,
        )
        .expect("correct password imports encrypted PKCS#8");
    assert_eq!(inventory.private_keys.len(), 1);
    assert!(inventory.material_bytes >= encrypted.as_bytes().len());
    let mut callback_inventory = KeyInventory::default();
    callback_inventory
        .add_private_der_with_password_callback(
            "callback".into(),
            encrypted.as_bytes(),
            || Some(Zeroizing::new(b"correct".to_vec())),
            KeyUsages::SIGN,
            &resources,
        )
        .expect("callback decrypts encrypted PKCS#8");
    callback_inventory
        .add_private_der_with_password_callback(
            "plain".into(),
            plain.as_bytes(),
            || panic!("plaintext PKCS#8 must not request a password"),
            KeyUsages::SIGN,
            &resources,
        )
        .expect("plaintext import ignores password callback");
}

#[test]
fn invalid_private_usages_do_not_request_password() {
    // Caller-visible rejection must precede prompting or retrieving secrets.
    let private = pem::parse(include_bytes!(
        "../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
    ))
    .expect("key")
    .into_contents();
    let encrypted = PrivateKeyInfoRef::try_from(private.as_slice())
        .expect("PKCS8")
        .encrypt_with_rng(&mut ChaCha8Rng::seed_from_u64(42), b"correct")
        .expect("encrypted PKCS8");
    for usages in [
        KeyUsages::VERIFY,
        KeyUsages(0),
        KeyUsages::SIGN.union(KeyUsages::VERIFY),
    ] {
        let calls = std::cell::Cell::new(0);
        let mut inventory = KeyInventory::default();
        assert!(matches!(
            inventory.add_private_der_with_password_callback(
                "invalid".into(),
                encrypted.as_bytes(),
                || {
                    calls.set(calls.get() + 1);
                    Some(Zeroizing::new(b"correct".to_vec()))
                },
                usages,
                &ResourcePolicy::default()
            ),
            Err(KeyStoreError::Selection(
                "private key usage is incompatible"
            ))
        ));
        assert_eq!(calls.get(), 0);
        assert_eq!(inventory.entry_count(), 0);
    }
}

#[test]
fn certificate_and_crl_capacity_precedes_der_parsing() {
    // Exhausted inventory limits are terminal policy errors even for
    // malformed DER. Failed imports must not change retained accounting.
    for candidates in [true, false] {
        for certificate in [true, false] {
            let mut inventory = KeyInventory::default();
            let resources = ResourcePolicy {
                max_key_candidates: if candidates { 1 } else { 64 },
                max_external_resource_total_bytes: 2,
                ..ResourcePolicy::default()
            };
            inventory
                .add_symmetric(
                    "a".into(),
                    SymmetricKeyKind::Hmac,
                    vec![0],
                    KeyUsages::SIGN,
                    &resources,
                )
                .expect("fill inventory");
            let result = if certificate {
                inventory.add_certificate_der(vec![0], false, &resources)
            } else {
                inventory.add_crl_der(vec![0], &resources)
            };
            let resource = if candidates {
                crate::policy::resource_name::KEY_CANDIDATES
            } else {
                crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES
            };
            assert!(matches!(result, Err(KeyStoreError::Policy(
                    crate::policy::PolicyViolation::ResourceLimitExceeded { resource: actual, .. }
                )) if actual == resource));
            assert_eq!(inventory.entry_count(), 1);
            assert_eq!(inventory.material_bytes, 2);
            assert_eq!(inventory.lookup_certificates, [] as [Vec<u8>; 0]);
            assert_eq!(inventory.crls, [] as [Vec<u8>; 0]);
        }
    }
    assert!(matches!(
        KeyInventory::default().add_crl_der(vec![0], &ResourcePolicy::default()),
        Err(KeyStoreError::Selection("invalid X.509 CRL"))
    ));
}

#[test]
fn pkcs8_pbkdf2_output_blocks_are_checked_before_password() {
    use der::Encode as _;
    // AES-256/SHA-1 needs two PBKDF2 blocks; three rounds cost six PRFs,
    // not three. Denial must precede the public password callback.
    use pkcs8::pkcs5::{EncryptionScheme, pbes2};
    let encrypted = EncryptedPrivateKeyInfoRef {
        encryption_algorithm: EncryptionScheme::Pbes2(pbes2::Parameters {
            kdf: pbes2::Kdf::Pbkdf2(pbes2::Pbkdf2Params {
                salt: pbes2::Salt::new(b"12345678").expect("salt"),
                iteration_count: 3,
                key_length: None,
                prf: pbes2::Pbkdf2Prf::HmacWithSha1,
            }),
            encryption: pbes2::EncryptionScheme::Aes256Cbc { iv: [0; 16] },
        }),
        encrypted_data: der::asn1::OctetStringRef::new(&[0; 16]).expect("ciphertext"),
    };
    let bytes = encrypted.to_der().expect("encrypted envelope");
    let resources = ResourcePolicy {
        max_key_import_kdf_work: 5,
        ..ResourcePolicy::default()
    };
    let calls = std::cell::Cell::new(0);
    let result = KeyInventory::default().add_private_der_with_password_callback(
        "key".into(),
        &bytes,
        || {
            calls.set(calls.get() + 1);
            None
        },
        KeyUsages::SIGN,
        &resources,
    );
    assert_eq!(calls.get(), 0);
    assert!(matches!(
        result,
        Err(KeyStoreError::Policy(
            crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::KEY_IMPORT_KDF_WORK,
                maximum: 5,
                actual: 6,
            }
        ))
    ));
    let exact = ResourcePolicy {
        max_key_import_kdf_work: 6,
        ..resources
    };
    assert!(enforce_pkcs8_kdf_policy(&encrypted, &exact, 0).is_ok());
    // Cover each PRF width and CBC key width, including single-block
    // cases so the fix cannot unconditionally double iteration charges.
    for (prf, hash_len) in [
        (pbes2::Pbkdf2Prf::HmacWithSha1, 20),
        (pbes2::Pbkdf2Prf::HmacWithSha224, 28),
        (pbes2::Pbkdf2Prf::HmacWithSha256, 32),
        (pbes2::Pbkdf2Prf::HmacWithSha384, 48),
        (pbes2::Pbkdf2Prf::HmacWithSha512, 64),
    ] {
        for cipher in [
            pbes2::EncryptionScheme::Aes128Cbc { iv: [0; 16] },
            pbes2::EncryptionScheme::Aes192Cbc { iv: [0; 16] },
            pbes2::EncryptionScheme::Aes256Cbc { iv: [0; 16] },
        ] {
            let mut envelope = encrypted.clone();
            let EncryptionScheme::Pbes2(params) = &mut envelope.encryption_algorithm else {
                panic!("PBES2 fixture");
            };
            let pbes2::Kdf::Pbkdf2(kdf) = &mut params.kdf else {
                panic!("PBKDF2 fixture");
            };
            kdf.prf = prf;
            params.encryption = cipher;
            let work = 3 * cipher.key_size().div_ceil(hash_len);
            let exact = ResourcePolicy {
                max_key_import_kdf_work: work,
                ..ResourcePolicy::default()
            };
            assert!(enforce_pkcs8_kdf_policy(&envelope, &exact, 0).is_ok());
            let tight = ResourcePolicy {
                max_key_import_kdf_work: work - 1,
                ..exact
            };
            assert!(matches!(enforce_pkcs8_kdf_policy(&envelope, &tight, 0),
                    Err(KeyStoreError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                        resource: crate::policy::resource_name::KEY_IMPORT_KDF_WORK,
                        actual, ..
                    })) if actual == work));
        }
    }
}

#[test]
fn protected_password_consumes_live_byte_and_work_budgets() {
    use der::Encode as _;
    use pkcs8::pkcs5::{EncryptionScheme, pbes2};
    // Password hashing and retained callback capacity must be denied before
    // failed padding can hide the resource-policy failure.
    let envelope = EncryptedPrivateKeyInfoRef {
        encryption_algorithm: EncryptionScheme::Pbes2(pbes2::Parameters {
            kdf: pbes2::Kdf::Pbkdf2(pbes2::Pbkdf2Params {
                salt: pbes2::Salt::new(b"12345678").expect("salt"),
                iteration_count: 2,
                key_length: None,
                prf: pbes2::Pbkdf2Prf::HmacWithSha256,
            }),
            encryption: pbes2::EncryptionScheme::Aes256Cbc { iv: [0; 16] },
        }),
        encrypted_data: der::asn1::OctetStringRef::new(&[0; 64]).expect("ciphertext"),
    }
    .to_der()
    .expect("envelope");
    let peak = 3 + envelope.len() + 64;
    for resources in [
        ResourcePolicy {
            max_external_resource_bytes: 255,
            ..ResourcePolicy::default()
        },
        ResourcePolicy {
            max_external_resource_total_bytes: peak + 255,
            ..ResourcePolicy::default()
        },
        ResourcePolicy {
            max_key_import_kdf_work: 5,
            ..ResourcePolicy::default()
        },
    ] {
        let mut inventory = KeyInventory::default();
        assert!(matches!(
            inventory.add_private_der(
                "new".into(),
                &envelope,
                Some(&[0; 256]),
                KeyUsages::SIGN,
                &resources
            ),
            Err(KeyStoreError::Policy(_))
        ));
        assert!(inventory.private_keys().is_empty());
    }
    let resources = ResourcePolicy {
        max_external_resource_total_bytes: peak + 255,
        ..ResourcePolicy::default()
    };
    let mut secret = Vec::with_capacity(256);
    secret.push(0);
    assert!(matches!(
        KeyInventory::default().add_private_der_with_password_callback(
            "new".into(),
            &envelope,
            || Some(Zeroizing::new(secret)),
            KeyUsages::SIGN,
            &resources
        ),
        Err(KeyStoreError::Policy(_))
    ));
    let exact = ResourcePolicy {
        max_external_resource_total_bytes: peak + 256,
        max_key_import_kdf_work: 6,
        ..ResourcePolicy::default()
    };
    assert!(matches!(
        KeyInventory::default().add_private_der(
            "new".into(),
            &envelope,
            Some(&[0; 256]),
            KeyUsages::SIGN,
            &exact
        ),
        Err(KeyStoreError::ProtectedContainer)
    ));
}

#[test]
fn private_identity_matches_without_owned_public_encoding() {
    // Compare every supported family against its canonical encoder, and
    // reject changed public material. Import itself retains no SPKI copy.
    let rsa_der = pem::parse(include_bytes!(
        "../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
    ))
    .expect("RSA PEM fixture")
    .into_contents();
    let rsa = RsaPrivateKey::from_pkcs8_der(&rsa_der).expect("RSA private key");
    let public = rsa
        .to_public_key()
        .to_public_key_der()
        .expect("RSA public encoding");
    let identity = PrivateKeyIdentity::decode(&rsa_der).expect("RSA identity");
    assert!(identity.matches_spki(public.as_bytes()));
    let mut changed = public.as_bytes().to_vec();
    *changed.last_mut().expect("nonempty RSA SPKI") ^= 2;
    assert!(!identity.matches_spki(&changed));
    assert!(!identity.matches_spki(b"invalid DER"));

    macro_rules! check_ec {
        ($key:ty, $length:expr) => {{
            let mut scalar = [0; $length];
            scalar[$length - 1] = 1;
            let key = <$key>::from_slice(&scalar).expect("valid EC scalar");
            let private = key.to_pkcs8_der().expect("EC private encoding");
            let public = key
                .public_key()
                .to_public_key_der()
                .expect("EC public encoding");
            let identity = PrivateKeyIdentity::decode(private.as_bytes()).expect("EC identity");
            assert!(identity.matches_spki(public.as_bytes()));
            let mut changed = public.as_bytes().to_vec();
            *changed.last_mut().expect("nonempty EC SPKI") ^= 1;
            assert!(!identity.matches_spki(&changed));
        }};
    }
    check_ec!(p256::SecretKey, 32);
    check_ec!(p384::SecretKey, 48);
    check_ec!(p521::SecretKey, 66);

    let inventory = KeyInventory::from_xml_bytes(
        include_bytes!("../../tests/fixtures/keys/xmlsec/mixed-keys.xml"),
        &xml_policy(ResourcePolicy::default()),
        XmlBackend::default(),
    )
    .expect("mixed store fixture");
    let private = inventory
        .private_keys()
        .iter()
        .find(|entry| entry.name == "test-dsa")
        .expect("stored DSA private key");
    let key = NativeDsaSigningKey::from_pkcs8_der(&private.pkcs8_der).expect("DSA private key");
    let public = key
        .verifying_key()
        .to_public_key_der()
        .expect("DSA public encoding");
    let identity = PrivateKeyIdentity::decode(&private.pkcs8_der).expect("DSA identity");
    assert!(identity.matches_spki(public.as_bytes()));
    let mut changed = public.as_bytes().to_vec();
    *changed.last_mut().expect("nonempty DSA SPKI") ^= 1;
    assert!(!identity.matches_spki(&changed));
}

#[test]
fn xml_import_counts_source_and_decoded_material_together() {
    // The caller still owns the Base64 XML while the decoded HMAC is live.
    let xml = format!(
        "<Keys xmlns='{XMLSEC_NS}' xmlns:ds='{XMLDSIG_NS}'><ds:KeyInfo><ds:KeyName>hmac</ds:KeyName><ds:KeyValue><HMACKeyValue>{}</HMACKeyValue></ds:KeyValue></ds:KeyInfo></Keys>",
        base64::engine::general_purpose::STANDARD.encode(vec![1; 1024])
    );
    let resources = ResourcePolicy {
        max_external_resource_total_bytes: xml.len(),
        ..Default::default()
    };
    assert!(matches!(
        KeyInventory::from_xml_bytes(
            xml.as_bytes(),
            &xml_policy(resources),
            XmlBackend::default()
        ),
        Err(KeyStoreError::Policy(_))
    ));
    // Exact peak includes both live name copies, not just retained bytes.
    let peak = xml.len() + 1024 + 2 * "hmac".len();
    for maximum in [peak - 1, peak] {
        let policy = xml_policy(ResourcePolicy {
            max_external_resource_total_bytes: maximum,
            ..Default::default()
        });
        let result = KeyInventory::from_xml_bytes(xml.as_bytes(), &policy, XmlBackend::default());
        if maximum == peak {
            let store = result.expect("exact live peak fits");
            assert_eq!(store.symmetric_keys[0].bytes.as_slice(), &[1; 1024]);
            assert_eq!(store.material_bytes, xml.len() + 1024 + "hmac".len());
        } else {
            assert!(matches!(result, Err(KeyStoreError::Policy(_))));
        }
    }
}

#[test]
fn private_pem_preflight_precedes_payload_parsing() {
    // Structurally invalid DER must never be reached when its allocation
    // already exceeds the allowance, for plain and encrypted labels alike.
    for label in ["PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "RSA PRIVATE KEY"] {
        let pem = pem::encode(&pem::Pem::new(label, vec![1, 2, 3]));
        let resources = ResourcePolicy {
            max_external_resource_total_bytes: pem.len() + "key".len() + 2,
            ..Default::default()
        };
        let mut store = KeyInventory::default();
        assert!(matches!(
            store.add_private_pem(
                "key".into(),
                pem.as_bytes(),
                None,
                KeyUsages::SIGN,
                &resources
            ),
            Err(KeyStoreError::Policy(_))
        ));
        assert_eq!(store.entry_count(), 0);
    }
}

#[test]
fn xml_public_key_import_preserves_key_info_metadata_validation() {
    // Importing KeyValue directly must not bypass the original KeyInfo
    // mixed-content and name-length validation performed by shared parsing.
    let source = include_str!("../../tests/fixtures/keys/xmlsec/mixed-keys.xml");
    let marker = source.find("<RSAKeyValue").expect("RSA entry");
    let start = source[..marker].rfind("<KeyInfo").expect("RSA KeyInfo");
    let end = marker + source[marker..].find("</KeyInfo>").expect("RSA end") + "</KeyInfo>".len();
    let entry = &source[start..end];
    let name_start = entry.find("<KeyName>").expect("name") + "<KeyName>".len();
    let name_end = name_start + entry[name_start..].find("</KeyName>").expect("name end");
    for changed in [
        format!(
            "{}{}{}",
            &entry[..name_start],
            "a".repeat(4097),
            &entry[name_end..]
        ),
        entry.replacen("<KeyName>", "unexpected<KeyName>", 1),
    ] {
        let xml = format!("<Keys xmlns='{XMLSEC_NS}'>{changed}</Keys>");
        assert!(
            KeyInventory::from_xml_bytes(
                xml.as_bytes(),
                &xml_policy(ResourcePolicy::default()),
                XmlBackend::default()
            )
            .is_err()
        );
    }
}

#[test]
fn public_pem_decoder_preserves_framing_and_whitespace_contract() {
    // Decode borrowed input without tightening the existing whitespace/header
    // contract; malformed framing, alphabet and padding remain rejected.
    for data in [
        "AQID",
        "A Q\tI\r\nD",
        "A\u{2003}QID",
        "Header: value\n\nAQID",
        "Header: value\r\n\r\nAQID",
    ] {
        let text = format!("-----BEGIN PUBLIC KEY-----\n{data}\n-----END PUBLIC KEY-----");
        let expected = single_pem_block(text.as_bytes(), 4096).expect("existing PEM contract");
        let frame = BorrowedPem::parse(text.as_bytes(), 4096).expect("borrowed frame");
        assert_eq!(
            frame.decode().expect("borrowed decode"),
            expected.contents()
        );
    }
    for data in ["AQI=", "AQ==", "AQID"] {
        let text = format!("-----BEGIN RSA PUBLIC KEY-----\n{data}\n-----END RSA PUBLIC KEY-----");
        let frame = BorrowedPem::parse(text.as_bytes(), 4096).expect("borrowed frame");
        assert_eq!(frame.decode().expect("decode").len(), frame.decoded_len);
    }
    // Exercise padding and the decoder's fixed-size staging boundaries;
    // whitespace-separated input must not truncate a multi-read payload.
    for length in [0, 1, 2, 3, 1023, 1024, 1025, 4096] {
        let bytes = vec![0xa5; length];
        let encoded = pem::encode(&pem::Pem::new("PUBLIC KEY", bytes.clone()));
        let frame = BorrowedPem::parse(encoded.as_bytes(), 8192).expect("frame");
        assert_eq!(frame.decoded_len, length);
        assert_eq!(frame.decode().expect("streamed decoding"), bytes);
    }
    for text in [
        "-----BEGIN PUBLIC KEY-----\nAQID\n-----END RSA PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\nAQID\n-----END PUBLIC KEY-----junk",
        "-----BEGIN PUBLIC KEY-----\nAQID\n-----END PUBLIC KEY-----\n-----BEGIN PUBLIC KEY-----\nAQID\n-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\nAQI\n-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\nAQ$=\n-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\nAR==\n-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\nA===\n-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\nAQ=I\n-----END PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\nnot a header\n\nAQID\n-----END PUBLIC KEY-----",
    ] {
        assert!(
            BorrowedPem::parse(text.as_bytes(), 4096)
                .and_then(|frame| frame.decode())
                .is_err(),
            "accepted {text}"
        );
    }
}

#[test]
fn public_pem_import_accounts_for_simultaneous_buffers() {
    // Caller PEM, decoded bytes and a normalized SPKI coexist; neither
    // prior inventory material nor any intermediate may reuse that budget.
    let pem = include_bytes!("../../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    let spki = pem::parse(pem).expect("public PEM fixture").into_contents();
    let key = RsaPublicKey::from_public_key_der(&spki).expect("RSA key");
    let pkcs1 = key.to_pkcs1_der().expect("PKCS1 encoding");
    for (label, decoded, extra) in [
        ("PUBLIC KEY", spki.as_slice(), 0),
        ("RSA PUBLIC KEY", pkcs1.as_bytes(), spki.len()),
    ] {
        let encoded = pem::encode(&pem::Pem::new(label, decoded.to_vec()));
        for exact in [false, true] {
            let mut inventory = KeyInventory::default();
            inventory
                .add_symmetric(
                    "existing".into(),
                    SymmetricKeyKind::Hmac,
                    vec![1; 16],
                    KeyUsages::SIGN,
                    &ResourcePolicy::default(),
                )
                .expect("existing key");
            let retained = inventory.material_bytes;
            let resources = ResourcePolicy {
                max_external_resource_total_bytes: retained
                    + 2 * "new".len()
                    + encoded.len()
                    + decoded.len()
                    + extra
                    - usize::from(!exact),
                ..ResourcePolicy::default()
            };
            let result = inventory.add_public_pem("new".into(), encoded.as_bytes(), &resources);
            if exact {
                result.expect("exact peak allowance");
                assert_eq!(inventory.entry_count(), 2);
            } else {
                assert!(matches!(result, Err(KeyStoreError::Policy(_))));
                assert_eq!(inventory.entry_count(), 1);
                assert_eq!(inventory.material_bytes, retained);
            }
        }
    }
}

#[test]
fn plaintext_private_import_checks_all_live_copies() {
    // Borrowed input, decoded PEM and retained DER coexist. Reject one
    // byte below that peak without retaining a key, and accept exactly it.
    let der = pem::parse(include_bytes!(
        "../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
    ))
    .expect("private key")
    .into_contents();
    let pkcs1 = RsaPrivateKey::from_pkcs8_der(&der)
        .expect("RSA")
        .to_pkcs1_der()
        .expect("PKCS1");
    for (label, input) in [
        ("PRIVATE KEY", der.as_slice()),
        ("RSA PRIVATE KEY", pkcs1.as_bytes()),
    ] {
        let pem = pem::encode(&pem::Pem::new(label, input.to_vec()));
        for encoded in [false, true] {
            let peak = 3 + input.len() + der.len() + if encoded { pem.len() } else { 0 };
            for exact in [false, true] {
                let resources = ResourcePolicy {
                    max_external_resource_total_bytes: peak - usize::from(!exact),
                    ..ResourcePolicy::default()
                };
                let mut inventory = KeyInventory::default();
                let result = if encoded {
                    inventory.add_private_pem(
                        "new".into(),
                        pem.as_bytes(),
                        None,
                        KeyUsages::SIGN,
                        &resources,
                    )
                } else {
                    inventory.add_private_der(
                        "new".into(),
                        input,
                        None,
                        KeyUsages::SIGN,
                        &resources,
                    )
                };
                if exact {
                    result.expect("exact live-byte allowance");
                    assert_eq!(inventory.entry_count(), 1);
                } else {
                    assert!(matches!(result, Err(KeyStoreError::Policy(_))));
                    assert_eq!(inventory.entry_count(), 0);
                    assert_eq!(inventory.material_bytes, 0);
                }
            }
        }
    }
}

#[test]
fn encrypted_pkcs8_plaintext_is_reserved_before_password() {
    use der::Encode as _;
    use pkcs8::pkcs5::{EncryptionScheme, pbes2};
    // PBKDF2 has no large workspace, but decrypt still allocates a full
    // ciphertext-sized buffer, even for a wrong password/malformed key.
    let encrypted = EncryptedPrivateKeyInfoRef {
        encryption_algorithm: EncryptionScheme::Pbes2(pbes2::Parameters {
            kdf: pbes2::Kdf::Pbkdf2(pbes2::Pbkdf2Params {
                salt: pbes2::Salt::new(b"12345678").expect("salt"),
                iteration_count: 2,
                key_length: None,
                prf: pbes2::Pbkdf2Prf::HmacWithSha256,
            }),
            encryption: pbes2::EncryptionScheme::Aes256Cbc { iv: [0; 16] },
        }),
        encrypted_data: der::asn1::OctetStringRef::new(&[0; 64]).expect("ciphertext"),
    };
    let bytes = encrypted.to_der().expect("envelope");
    let peak = 3 + bytes.len() + 64;
    let tight = ResourcePolicy {
        max_external_resource_total_bytes: peak - 1,
        ..ResourcePolicy::default()
    };
    let calls = std::cell::Cell::new(0);
    let mut inventory = KeyInventory::default();
    let result = inventory.add_private_der_with_password_callback(
        "new".into(),
        &bytes,
        || {
            calls.set(calls.get() + 1);
            None
        },
        KeyUsages::SIGN,
        &tight,
    );
    assert_eq!(calls.get(), 0);
    assert!(
        matches!(result, Err(KeyStoreError::Policy(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES, actual, ..
        })) if actual == peak)
    );
    assert!(matches!(
        inventory.add_private_der(
            "new".into(),
            &bytes,
            Some(b"wrong"),
            KeyUsages::SIGN,
            &tight
        ),
        Err(KeyStoreError::Policy(_))
    ));
    let exact = ResourcePolicy {
        max_external_resource_total_bytes: peak,
        ..tight
    };
    assert!(matches!(
        inventory.add_private_der_with_password_callback(
            "new".into(),
            &bytes,
            || {
                calls.set(calls.get() + 1);
                None
            },
            KeyUsages::SIGN,
            &exact
        ),
        Err(KeyStoreError::ProtectedContainer)
    ));
    assert_eq!(calls.get(), 1);
    assert!(inventory.private_keys().is_empty());
    assert_eq!(inventory.material_bytes, 0);
}

#[test]
fn encrypted_pem_workspace_accounts_for_live_encoded_input() {
    use der::Encode as _;
    use pkcs8::pkcs5::{EncryptionScheme, pbes2};
    // PEM and its decoded DER coexist during derivation. A DER-only
    // allowance must not authorize that larger peak or mutate inventory.
    let encrypted = EncryptedPrivateKeyInfoRef {
        encryption_algorithm: EncryptionScheme::Pbes2(pbes2::Parameters {
            kdf: pbes2::Kdf::Scrypt(pbes2::ScryptParams {
                salt: pbes2::Salt::new(b"12345678").expect("salt"),
                cost_parameter: 16,
                block_size: 1,
                parallelization: 1,
                key_length: None,
            }),
            encryption: pbes2::EncryptionScheme::Aes256Cbc { iv: [0; 16] },
        }),
        encrypted_data: der::asn1::OctetStringRef::new(&[0; 16]).expect("ciphertext"),
    };
    let der = encrypted.to_der().expect("envelope");
    let pem = pem::encode(&pem::Pem::new("ENCRYPTED PRIVATE KEY", der.clone()));
    let peak = 3 + pem.len() + der.len() + 16 + 2304;
    let mut inventory = KeyInventory::default();
    let tight = ResourcePolicy {
        max_external_resource_total_bytes: peak - 1,
        ..ResourcePolicy::default()
    };
    assert!(matches!(
        inventory.add_private_pem("new".into(), pem.as_bytes(), None, KeyUsages::SIGN, &tight),
        Err(KeyStoreError::Policy(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
            actual, ..
        })) if actual == peak
    ));
    let exact = ResourcePolicy {
        max_external_resource_total_bytes: peak,
        ..tight
    };
    assert!(matches!(
        inventory.add_private_pem("new".into(), pem.as_bytes(), None, KeyUsages::SIGN, &exact),
        Err(KeyStoreError::ProtectedContainer)
    ));
    assert!(matches!(
        inventory.add_private_der("new".into(), &der, None, KeyUsages::SIGN, &tight),
        Err(KeyStoreError::ProtectedContainer)
    ));
    assert!(inventory.private_keys().is_empty());
    assert_eq!(inventory.material_bytes, 0);
    // Exercise actual derivation/import as well as preflight: an exactly
    // fitting PEM peak succeeds with the correct password, not just framing.
    let plain = pem::parse(include_bytes!(
        "../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
    ))
    .expect("private key")
    .into_contents();
    let EncryptionScheme::Pbes2(params) = &encrypted.encryption_algorithm else {
        panic!("PBES2 envelope");
    };
    let ciphertext = params.encrypt(b"correct", &plain).expect("encrypt");
    let real = EncryptedPrivateKeyInfoRef {
        encryption_algorithm: encrypted.encryption_algorithm.clone(),
        encrypted_data: der::asn1::OctetStringRef::new(&ciphertext).expect("ciphertext"),
    }
    .to_der()
    .expect("envelope");
    let pem = pem::encode(&pem::Pem::new("ENCRYPTED PRIVATE KEY", real.clone()));
    let resources = ResourcePolicy {
        max_external_resource_total_bytes: 3
            + pem.len()
            + real.len()
            + ciphertext.len()
            + 2304
            + b"correct".len(),
        ..ResourcePolicy::default()
    };
    inventory
        .add_private_pem(
            "new".into(),
            pem.as_bytes(),
            Some(b"correct"),
            KeyUsages::SIGN,
            &resources,
        )
        .expect("exact PEM peak imports");
    assert_eq!(inventory.private_keys().len(), 1);
}

#[test]
fn pkcs8_scrypt_workspace_shares_retained_inventory_budget() {
    use der::Encode as _;
    // A workspace below its own ceiling must still fit alongside existing
    // inventory material; rejection must precede password delivery.
    use pkcs8::pkcs5::{EncryptionScheme, pbes2};
    let encrypted = EncryptedPrivateKeyInfoRef {
        encryption_algorithm: EncryptionScheme::Pbes2(pbes2::Parameters {
            kdf: pbes2::Kdf::Scrypt(pbes2::ScryptParams {
                salt: pbes2::Salt::new(b"12345678").expect("salt"),
                cost_parameter: 16,
                block_size: 1,
                parallelization: 1,
                key_length: None,
            }),
            encryption: pbes2::EncryptionScheme::Aes256Cbc { iv: [0; 16] },
        }),
        encrypted_data: der::asn1::OctetStringRef::new(&[0; 16]).expect("ciphertext"),
    };
    let bytes = encrypted.to_der().expect("envelope");
    let mut inventory = KeyInventory::default();
    inventory
        .add_symmetric(
            "old".into(),
            SymmetricKeyKind::Hmac,
            vec![7; 1024],
            KeyUsages::SIGN,
            &ResourcePolicy::default(),
        )
        .expect("retained key");
    let resources = ResourcePolicy {
        max_external_resource_total_bytes: inventory.material_bytes + 2304,
        max_key_import_kdf_memory_bytes: 4096,
        ..ResourcePolicy::default()
    };
    let calls = std::cell::Cell::new(0);
    let result = inventory.add_private_der_with_password_callback(
        "new".into(),
        &bytes,
        || {
            calls.set(calls.get() + 1);
            None
        },
        KeyUsages::SIGN,
        &resources,
    );
    assert_eq!(calls.get(), 0);
    assert!(matches!(
        result,
        Err(KeyStoreError::Policy(
            crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                ..
            }
        ))
    ));
    assert!(inventory.private_keys().is_empty());
    assert_eq!(inventory.symmetric_keys().len(), 1);
    let exact = ResourcePolicy {
        max_external_resource_total_bytes: inventory.material_bytes + bytes.len() + 3 + 16 + 2304,
        ..resources
    };
    assert!(matches!(
        inventory.add_private_der_with_password_callback(
            "new".into(),
            &bytes,
            || {
                calls.set(calls.get() + 1);
                None
            },
            KeyUsages::SIGN,
            &exact,
        ),
        Err(KeyStoreError::ProtectedContainer)
    ));
    assert_eq!(
        calls.get(),
        1,
        "an exactly fitting workspace reaches password delivery"
    );
}

#[test]
fn configured_x509_continuation_retains_first_deferred_error() {
    // Splitting at configured X509 must preserve the unsplit diagnostic
    // order, while a later terminal failure still stops immediately.
    let mut inventory = KeyInventory::default();
    inventory
        .add_certificate_der(
            single_pem_block(
                include_bytes!("../../tests/fixtures/keys/rsa/rsa-2048-cert.pem"),
                ResourcePolicy::default().max_external_resource_bytes,
            )
            .expect("certificate")
            .into_contents(),
            false,
            &ResourcePolicy::default(),
        )
        .expect("lookup");
    let mut info = KeyInfo {
        sources: vec![
            KeyInfoSource::KeyValue(KeyValueInfo::Dsa {
                p: None,
                q: None,
                g: None,
                y: vec![1],
            }),
            KeyInfoSource::X509Data(X509DataInfo {
                subject_names: vec!["CN=absent".into()],
                ..X509DataInfo::default()
            }),
            KeyInfoSource::KeyValue(KeyValueInfo::InvalidEcKeyValue),
        ],
    };
    let unsplit = DefaultKeyResolver::new(KeyResolverConfig::default())
        .resolve(Some(&info), SignatureAlgorithm::RsaSha256)
        .err()
        .expect("mismatch");
    let split = inventory
        .verification_resolver()
        .resolve(Some(&info), SignatureAlgorithm::RsaSha256)
        .err()
        .expect("mismatch");
    assert_eq!(format!("{split:?}"), format!("{unsplit:?}"));
    info.sources[2] = KeyInfoSource::DerEncodedKeyValue(vec![0]);
    let unsplit = DefaultKeyResolver::new(KeyResolverConfig::default())
        .resolve(Some(&info), SignatureAlgorithm::RsaSha256)
        .err()
        .expect("terminal");
    let split = inventory
        .verification_resolver()
        .resolve(Some(&info), SignatureAlgorithm::RsaSha256)
        .err()
        .expect("terminal");
    assert_eq!(format!("{split:?}"), format!("{unsplit:?}"));
}

#[test]
fn configured_x509_fallback_preserves_terminal_prefix_errors() {
    // Attaching configured certificates must not turn malformed earlier
    // DER key material into a successful certificate fallback.
    let resources = ResourcePolicy::default();
    let mut inventory = KeyInventory::default();
    let certificate = single_pem_block(
        include_bytes!("../../tests/fixtures/keys/rsa/rsa-2048-cert.pem"),
        resources.max_external_resource_bytes,
    )
    .expect("certificate")
    .into_contents();
    let subject = crate::xmldsig::parse::parse_x509_certificate(&certificate)
        .expect("leaf")
        .subject_dn;
    inventory
        .add_certificate_der(certificate, false, &resources)
        .expect("lookup");
    let mut info = KeyInfo {
        sources: vec![
            KeyInfoSource::DerEncodedKeyValue(vec![0]),
            KeyInfoSource::X509Data(X509DataInfo {
                subject_names: vec![subject],
                ..X509DataInfo::default()
            }),
        ],
    };
    assert!(
        inventory
            .verification_resolver()
            .resolve(Some(&info), SignatureAlgorithm::RsaSha256,)
            .is_err(),
        "a terminal prefix error must stop resolution"
    );
    // Unsupported EC material for an RSA method is explicitly deferrable;
    // a certificate can satisfy it, but a complete miss retains the error.
    info.sources[0] = KeyInfoSource::KeyValue(KeyValueInfo::InvalidEcKeyValue);
    assert!(
        inventory
            .verification_resolver()
            .resolve(Some(&info), SignatureAlgorithm::RsaSha256,)
            .expect("deferred prefix permits certificate fallback")
            .is_some()
    );
    let KeyInfoSource::X509Data(data) = &mut info.sources[1] else {
        panic!("X509 selector");
    };
    data.subject_names = vec!["CN=absent".into()];
    assert!(
        inventory
            .verification_resolver()
            .resolve(Some(&info), SignatureAlgorithm::RsaSha256,)
            .is_err(),
        "a complete miss retains its deferred error"
    );
}

#[test]
fn configured_x509_fallback_does_not_reinspect_prefix() {
    // One absent name, its document source, and the certificate inspection
    // fit exactly. Replaying the source prefix incorrectly exhausts it.
    let resources = ResourcePolicy::default();
    let mut inventory = KeyInventory::default();
    let certificate = single_pem_block(
        include_bytes!("../../tests/fixtures/keys/rsa/rsa-2048-cert.pem"),
        resources.max_external_resource_bytes,
    )
    .expect("certificate")
    .into_contents();
    let subject = crate::xmldsig::parse::parse_x509_certificate(&certificate)
        .expect("leaf")
        .subject_dn;
    inventory
        .add_certificate_der(certificate, false, &resources)
        .expect("lookup");
    let info = KeyInfo {
        sources: vec![
            KeyInfoSource::KeyName("absent".into()),
            KeyInfoSource::X509Data(X509DataInfo {
                subject_names: vec![subject],
                ..X509DataInfo::default()
            }),
        ],
    };
    let mut policy = crate::policy::VerificationPolicy::default();
    policy.resources.max_key_candidates = 3;
    assert!(
        inventory
            .verification_resolver()
            .resolve_with_policy_and_provider(
                Some(&info),
                SignatureAlgorithm::RsaSha256,
                &policy,
                crate::provider::default_provider(),
            )
            .expect("each source inspected once")
            .is_some()
    );
    policy.resources.max_key_candidates = 2;
    assert!(matches!(
        inventory
            .verification_resolver()
            .resolve_with_policy_and_provider(
                Some(&info),
                SignatureAlgorithm::RsaSha256,
                &policy,
                crate::provider::default_provider(),
            ),
        Err(DsigError::Policy(_))
    ));
}

#[test]
fn scrypt_parallel_buffers_are_checked_before_derivation() {
    // N*r fits a tiny limit, but p independent B/V/T workspaces do not.
    let mut resources = ResourcePolicy {
        max_key_import_kdf_work: 10_000,
        max_key_import_kdf_memory_bytes: 4_096,
        ..ResourcePolicy::default()
    };
    assert!(matches!(
        enforce_scrypt_kdf_limits(2, 1, 1_000, &resources, 0),
        Err(KeyStoreError::Policy(
            crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::KEY_IMPORT_KDF_MEMORY,
                maximum: 4_096,
                actual: 512_000,
            }
        ))
    ));
    resources.max_key_import_kdf_memory_bytes = 512_000;
    assert!(enforce_scrypt_kdf_limits(2, 1, 1_000, &resources, 0).is_ok());
}

#[test]
fn named_hmac_resolution_enforces_usage_and_method() {
    // A named secret may verify only when both its usage and the XMLDSig
    // method permit HMAC; the resolver must not fall back to another key.
    let resources = ResourcePolicy::default();
    let mut inventory = KeyInventory::default();
    inventory
        .add_symmetric(
            "verify".into(),
            SymmetricKeyKind::Hmac,
            b"sufficiently-long-hmac-secret".to_vec(),
            KeyUsages::VERIFY,
            &resources,
        )
        .expect("verification HMAC imports");
    inventory
        .add_symmetric(
            "sign-only".into(),
            SymmetricKeyKind::Hmac,
            b"another-hmac-secret".to_vec(),
            KeyUsages::SIGN,
            &resources,
        )
        .expect("sign-only HMAC imports");
    let resolver = inventory.verification_resolver();
    let named = |name: &str| KeyInfo {
        sources: vec![KeyInfoSource::KeyName(name.into())],
        ..KeyInfo::default()
    };
    assert!(
        resolver
            .resolve(Some(&named("verify")), SignatureAlgorithm::HmacSha256)
            .expect("named HMAC resolves")
            .is_some()
    );
    assert!(
        resolver
            .resolve(Some(&named("verify")), SignatureAlgorithm::RsaSha256)
            .is_err()
    );
    assert!(
        resolver
            .resolve(Some(&named("sign-only")), SignatureAlgorithm::HmacSha256)
            .is_err()
    );
}

#[test]
fn named_hmac_resolution_rejects_invalid_policy_snapshot() {
    // Early HMAC resolution must validate the entire snapshot even when
    // the selected key is small and otherwise permitted.
    let mut inventory = KeyInventory::default();
    inventory
        .add_symmetric(
            "verify".into(),
            SymmetricKeyKind::Hmac,
            b"sufficiently-long-hmac-secret".to_vec(),
            KeyUsages::VERIFY,
            &ResourcePolicy::default(),
        )
        .expect("verification HMAC imports");
    let info = KeyInfo {
        sources: vec![KeyInfoSource::KeyName("verify".into())],
        ..KeyInfo::default()
    };
    let mut policy = crate::policy::VerificationPolicy::default();
    policy.resources.max_external_resource_bytes = usize::MAX;
    assert!(matches!(
        inventory.verification_resolver().resolve_with_policy(
            Some(&info),
            SignatureAlgorithm::HmacSha256,
            &policy
        ),
        Err(DsigError::Policy(_))
    ));
}

#[test]
fn named_hmac_resolution_uses_active_resource_limits() {
    // A store imported under a broad policy must not bypass a later,
    // stricter verification snapshot when resolving a named secret.
    let resources = ResourcePolicy::default();
    let secret = b"sufficiently-long-hmac-secret";
    let mut inventory = KeyInventory::default();
    inventory
        .add_symmetric(
            "verify".into(),
            SymmetricKeyKind::Hmac,
            secret.to_vec(),
            KeyUsages::VERIFY,
            &resources,
        )
        .expect("verification HMAC imports");
    let key_info = KeyInfo {
        sources: vec![KeyInfoSource::KeyName("verify".into())],
        ..KeyInfo::default()
    };
    let resolver = inventory.verification_resolver();
    for (resource, aggregate) in [
        (crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES, false),
        (
            crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
            true,
        ),
    ] {
        let mut policy = crate::policy::VerificationPolicy::default();
        if aggregate {
            policy.resources.max_external_resource_total_bytes = secret.len() - 1;
        } else {
            policy.resources.max_external_resource_bytes = secret.len() - 1;
        }
        let error = resolver
            .resolve_with_policy(Some(&key_info), SignatureAlgorithm::HmacSha256, &policy)
            .err()
            .expect("active limit must reject stored HMAC material");
        assert!(
            matches!(
                error,
                DsigError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                    resource: actual,
                    maximum,
                    actual: size,
                }) if actual == resource && maximum == secret.len() - 1 && size == secret.len()
            ),
            "{error:?}"
        );
    }
}

#[test]
fn one_named_verification_entry_fits_one_candidate() {
    // A name and the single entry it selects are one lookup, not two.
    let mut inventory = KeyInventory::default();
    let mut policy = crate::policy::VerificationPolicy::default();
    inventory
        .add_symmetric(
            "only".into(),
            SymmetricKeyKind::Hmac,
            b"sufficiently-long-hmac-secret".to_vec(),
            KeyUsages::VERIFY,
            &policy.resources,
        )
        .expect("HMAC imports");
    policy.resources.max_key_candidates = 1;
    let info = KeyInfo {
        sources: vec![KeyInfoSource::KeyName("only".into())],
    };
    assert!(
        inventory
            .verification_resolver()
            .resolve_with_policy(Some(&info), SignatureAlgorithm::HmacSha256, &policy)
            .expect("one lookup fits")
            .is_some()
    );
}

#[test]
fn pem_imports_charge_encoded_input_to_aggregate_budget() {
    // Repeated padded PEM inputs must consume the aggregate work budget
    // even when their decoded DER keys are much smaller.
    let public = include_str!("../../tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
    let private = include_str!("../../tests/fixtures/keys/rsa/rsa-4096-key.pem");
    for (pem, is_private) in [(public, false), (private, true)] {
        let padded = format!("{pem}{}", " ".repeat(16 * 1024));
        // Public imports need one live DER; private imports need two,
        // in addition to encoded input. Retaining the first input charge
        // still makes the second padded import exceed this exact peak.
        let workspace =
            pem::parse(pem).expect("PEM payload").contents().len() * if is_private { 2 } else { 1 };
        let resources = ResourcePolicy {
            max_external_resource_bytes: padded.len(),
            max_external_resource_total_bytes: padded.len()
                + if is_private { 5 } else { 10 }
                + workspace
                + 1,
            ..ResourcePolicy::default()
        };
        let mut inventory = KeyInventory::default();
        let import = |inventory: &mut KeyInventory, name: &str| {
            if is_private {
                inventory.add_private_pem(
                    name.into(),
                    padded.as_bytes(),
                    None,
                    KeyUsages::SIGN,
                    &resources,
                )
            } else {
                inventory.add_public_pem(name.into(), padded.as_bytes(), &resources)
            }
        };
        import(&mut inventory, "first").expect("first PEM import fits");
        assert!(
            matches!(
                import(&mut inventory, "second"),
                Err(KeyStoreError::Policy(
                    crate::policy::PolicyViolation::ResourceLimitExceeded {
                        resource: crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                        ..
                    }
                ))
            ),
            "second PEM input must exceed aggregate budget"
        );
    }
}

#[test]
fn repeated_key_name_selects_one_inventory_entry() {
    // XMLDSig 1.1 section 4.5 permits repeated KeyInfo choices; duplicate
    // references to one entry are not two distinct verification keys.
    let resources = ResourcePolicy::default();
    let mut inventory = KeyInventory::default();
    inventory
        .add_symmetric(
            "secret".into(),
            SymmetricKeyKind::Hmac,
            b"sufficiently-long-hmac-secret".to_vec(),
            KeyUsages::VERIFY,
            &resources,
        )
        .expect("HMAC key imports");
    inventory
        .add_symmetric(
            "other-secret".into(),
            SymmetricKeyKind::Hmac,
            b"another-long-hmac-secret".to_vec(),
            KeyUsages::VERIFY,
            &resources,
        )
        .expect("second HMAC key imports");
    inventory
        .add_public_pem(
            "public".into(),
            include_bytes!("../../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"),
            &resources,
        )
        .expect("public key imports");
    let resolver = inventory.verification_resolver();
    for (name, algorithm) in [
        ("secret", SignatureAlgorithm::HmacSha256),
        ("public", SignatureAlgorithm::RsaSha256),
    ] {
        let info = KeyInfo {
            sources: vec![
                KeyInfoSource::KeyName(name.into()),
                KeyInfoSource::KeyName(name.into()),
            ],
        };
        assert!(resolver.resolve(Some(&info), algorithm).is_ok(), "{name}");
    }
    let distinct = KeyInfo {
        sources: vec![
            KeyInfoSource::KeyName("secret".into()),
            KeyInfoSource::KeyName("other-secret".into()),
        ],
    };
    assert!(
        resolver
            .resolve(Some(&distinct), SignatureAlgorithm::HmacSha256)
            .is_err()
    );
}

#[test]
fn named_lookup_charges_inspected_inventory_entries() {
    // A late KeyName must not bypass a stricter operation candidate limit.
    let mut inventory = KeyInventory::default();
    let resources = ResourcePolicy::default();
    for name in ["first", "second"] {
        inventory
            .add_symmetric(
                name.into(),
                SymmetricKeyKind::Hmac,
                b"sufficiently-long-hmac-secret".to_vec(),
                KeyUsages::VERIFY,
                &resources,
            )
            .expect("key imports");
    }
    let key_info = KeyInfo {
        sources: vec![KeyInfoSource::KeyName("second".into())],
        ..KeyInfo::default()
    };
    let policy = crate::policy::VerificationPolicy {
        resources: ResourcePolicy {
            max_key_candidates: 1,
            ..ResourcePolicy::default()
        },
        ..crate::policy::VerificationPolicy::default()
    };
    let resolver = inventory.verification_resolver();
    assert!(
        resolver
            .resolve_with_policy_and_provider(
                Some(&key_info),
                SignatureAlgorithm::HmacSha256,
                &policy,
                crate::provider::default_provider(),
            )
            .is_err()
    );
}

#[test]
fn private_import_rejects_public_only_usage() {
    // Usage is part of the inventory contract: nonsensical permissions
    // must not survive import and later be interpreted by a resolver.
    let private = include_bytes!("../../tests/fixtures/keys/rsa/rsa-2048-key.pem");
    let mut inventory = KeyInventory::default();
    assert!(
        inventory
            .add_private_pem(
                "wrong-use".into(),
                private,
                None,
                KeyUsages::SIGN.union(KeyUsages::VERIFY),
                &ResourcePolicy::default(),
            )
            .is_err()
    );
    assert!(inventory.private_keys.is_empty());
}

#[test]
fn normalized_private_key_must_fit_resource_limit() {
    // PKCS#8 wrapping may cross the per-resource ceiling even when PKCS#1 fits.
    let rsa = RsaPrivateKey::from_pkcs8_pem(include_str!(
        "../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
    ))
    .expect("RSA fixture parses");
    let pkcs1 = rsa.to_pkcs1_der().expect("PKCS#1 encodes");
    let pkcs8 = rsa.to_pkcs8_der().expect("PKCS#8 encodes");
    assert!(pkcs8.as_bytes().len() > pkcs1.as_bytes().len());
    let resources = ResourcePolicy {
        max_external_resource_bytes: pkcs1.as_bytes().len(),
        ..ResourcePolicy::default()
    };
    let mut inventory = KeyInventory::default();
    assert!(
        inventory
            .add_private_der(
                "rsa".into(),
                pkcs1.as_bytes(),
                None,
                KeyUsages::SIGN,
                &resources,
            )
            .is_err()
    );
    assert!(inventory.private_keys.is_empty());
}

#[test]
fn oversized_rsa_components_are_rejected_before_private_key_decode() {
    // PKCS#8 wraps PKCS#1 integers; every component must be checked
    // before RustCrypto allocates big integers or validates CRT arithmetic.
    let pem = include_bytes!("../../tests/fixtures/keys/rsa/rsa-2048-key.pem");
    let block = single_pem_block(pem, ResourcePolicy::default().max_external_resource_bytes)
        .expect("fixture PEM");
    let info = PrivateKeyInfoRef::try_from(block.contents()).expect("fixture PKCS#8");
    let original =
        pkcs1::RsaPrivateKeyRef::from_der(info.private_key.as_bytes()).expect("fixture PKCS#1");
    let oversized_modulus = vec![1_u8; 1025];
    let oversized = pkcs1::RsaPrivateKeyRef {
        modulus: der::asn1::UintRef::new(&oversized_modulus).expect("positive modulus"),
        public_exponent: original.public_exponent,
        private_exponent: original.private_exponent,
        prime1: original.prime1,
        prime2: original.prime2,
        exponent1: original.exponent1,
        exponent2: original.exponent2,
        coefficient: original.coefficient,
        other_prime_infos: None,
    };
    let pkcs1 = der::Encode::to_der(&oversized).expect("PKCS#1 encodes");
    let octets = der::asn1::OctetStringRef::new(&pkcs1).expect("PKCS#8 octets");
    let pkcs8 = der::Encode::to_der(&PrivateKeyInfoRef::new(pkcs1::ALGORITHM_ID, octets))
        .expect("PKCS#8 encodes");
    let mut inventory = KeyInventory::default();
    let error = inventory
        .add_private_der(
            "oversized".into(),
            &pkcs8,
            None,
            KeyUsages::SIGN,
            &ResourcePolicy::default(),
        )
        .expect_err("oversized RSA modulus must fail at preflight");
    assert!(error.to_string().contains("safety limit"), "{error}");

    let oversized_exponent = vec![1_u8; 1025];
    let oversized = pkcs1::RsaPrivateKeyRef {
        modulus: original.modulus,
        public_exponent: original.public_exponent,
        private_exponent: der::asn1::UintRef::new(&oversized_exponent).expect("positive exponent"),
        prime1: original.prime1,
        prime2: original.prime2,
        exponent1: original.exponent1,
        exponent2: original.exponent2,
        coefficient: original.coefficient,
        other_prime_infos: None,
    };
    let pkcs1 = der::Encode::to_der(&oversized).expect("PKCS#1 encodes");
    let error = preflight_rsa_pkcs1_components(&pkcs1)
        .expect_err("oversized private exponent must fail before bigint decoding");
    assert!(error.to_string().contains("safety limit"), "{error}");
}

#[test]
fn named_certificate_import_is_not_a_trust_anchor() {
    // A certificate is usable as a named public-key source but importing
    // it must never grant certificate-chain trust implicitly.
    let pem = include_bytes!("../../tests/fixtures/keys/rsa/rsa-4096-cert.pem");
    let certificate = single_pem_block(pem, ResourcePolicy::default().max_external_resource_bytes)
        .expect("certificate fixture is one PEM block");
    let mut inventory = KeyInventory::default();
    inventory
        .add_public_der(
            "recipient-cert".into(),
            certificate.contents().to_vec(),
            &ResourcePolicy::default(),
        )
        .expect("named X.509 certificate imports");
    #[cfg(feature = "xmlenc")]
    {
        assert!(
            inventory
                .rsa_encryption_key(
                    "recipient-cert",
                    &crate::policy::EncryptionPolicy::default()
                )
                .is_ok()
        );
        let restricted = crate::policy::EncryptionPolicy {
            resources: ResourcePolicy {
                max_external_resource_bytes: 64,
                max_external_resource_total_bytes: 64,
                ..ResourcePolicy::default()
            },
            ..crate::policy::EncryptionPolicy::default()
        };
        assert!(
            inventory
                .rsa_encryption_key("recipient-cert", &restricted)
                .is_err()
        );
    }
    assert_eq!(inventory.trusted_certificates, [] as [Vec<u8>; 0]);
}

#[test]
fn eddsa_private_identity_matches_only_its_corresponding_spki() {
    use pkcs8::{EncodePrivateKey, EncodePublicKey};
    // PKCS#12 leaf selection must bind exact algorithm and public bytes,
    // without retaining or allocating a second serialized public key.
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    let der = key.to_pkcs8_der().expect("Ed25519 private encoding");
    let public = key
        .verifying_key()
        .to_public_key_der()
        .expect("Ed25519 public encoding");
    let identity = PrivateKeyIdentity::decode(der.as_bytes()).expect("Ed25519 identity");
    assert!(identity.matches_spki(public.as_bytes()));
    let wrong = ed25519_dalek::SigningKey::from_bytes(&[0x43; 32])
        .verifying_key()
        .to_public_key_der()
        .expect("different Ed25519 public encoding");
    assert!(!identity.matches_spki(wrong.as_bytes()));
    let key = ed448_goldilocks::SigningKey::try_from(&[0x42; 57][..]).expect("Ed448 seed");
    let der = key.to_pkcs8_der().expect("Ed448 private encoding");
    let public = key
        .verifying_key()
        .to_public_key_der()
        .expect("Ed448 public encoding");
    let identity = PrivateKeyIdentity::decode(der.as_bytes()).expect("Ed448 identity");
    assert!(identity.matches_spki(public.as_bytes()));
    assert!(!identity.matches_spki(wrong.as_bytes()));
}

#[test]
fn unsupported_spki_is_rejected_at_import() {
    // A syntactically valid X25519 agreement key is not an Ed25519
    // signing key and must not acquire VERIFY usage (RFC 8410 section 5).
    let mut agreement_spki = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
    ];
    agreement_spki.extend_from_slice(&[1; 32]);
    let mut inventory = KeyInventory::default();
    assert!(
        inventory
            .add_public_der(
                "unsupported".into(),
                agreement_spki,
                &ResourcePolicy::default()
            )
            .is_err()
    );
    assert!(inventory.public_keys.is_empty());
}

fn revoking_test_crl(root: &rcgen::Issuer<'_, rcgen::KeyPair>) -> rcgen::CertificateRevocationList {
    use rcgen::SerialNumber;

    let now = time::OffsetDateTime::now_utc();
    rcgen::CertificateRevocationListParams {
        this_update: now - time::Duration::days(1),
        next_update: now + time::Duration::days(1),
        crl_number: SerialNumber::from(1_u64),
        issuing_distribution_point: None,
        revoked_certs: vec![rcgen::RevokedCertParams {
            serial_number: SerialNumber::from(42_u64),
            revocation_time: now - time::Duration::hours(1),
            reason_code: None,
            invalidity_date: None,
        }],
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    }
    .signed_by(root)
    .expect("signed CRL")
}

#[test]
fn named_certificate_resolution_preserves_document_crl() {
    // Named inventory selection must preserve document revocation evidence;
    // without it the same chain is valid and resolves successfully.
    use rcgen::{CertificateParams, KeyPair, KeyUsagePurpose, SerialNumber};
    let mut root_params = CertificateParams::new(Vec::new()).expect("root params");
    root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let root =
        rcgen::CertifiedIssuer::self_signed(root_params, KeyPair::generate().expect("root key"))
            .expect("root certificate");
    let mut leaf_params = CertificateParams::new(Vec::new()).expect("leaf params");
    leaf_params.serial_number = Some(SerialNumber::from(42_u64));
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let leaf = leaf_params
        .signed_by(&KeyPair::generate().expect("leaf key"), &root)
        .expect("leaf certificate");
    let crl = revoking_test_crl(&root);
    let resources = ResourcePolicy::default();
    let mut inventory = KeyInventory::default();
    inventory
        .add_public_der("leaf".into(), leaf.der().to_vec(), &resources)
        .expect("leaf imports");
    inventory
        .add_certificate_der(root.der().to_vec(), true, &resources)
        .expect("root imports");
    let policy = crate::policy::VerificationPolicy {
        key_trust: crate::policy::KeyTrustPolicy {
            verify_x509_chains: true,
            check_crls: true,
            verification_time: Some(std::time::SystemTime::now()),
            ..crate::policy::KeyTrustPolicy::default()
        },
        ..crate::policy::VerificationPolicy::default()
    };
    let mut info = KeyInfo {
        sources: vec![KeyInfoSource::KeyName("leaf".into())],
    };
    let resolver = inventory.verification_resolver();
    assert!(
        resolver
            .resolve_with_policy_and_provider(
                Some(&info),
                SignatureAlgorithm::EcdsaSha256,
                &policy,
                crate::provider::default_provider()
            )
            .expect("unrevoked chain resolves")
            .is_some()
    );
    info.sources.push(KeyInfoSource::X509Data(X509DataInfo {
        crls: vec![crl.der().to_vec()],
        ..X509DataInfo::default()
    }));
    let mut candidate_budget = InspectedKeyCandidateBudget::new_with_utc_facts(
        &policy,
        crate::xmldsig::pkix::test_utc_facts(),
    );
    let error = resolver
        .resolve_for_verification_with_budget(
            Some(&info),
            SignatureAlgorithm::EcdsaSha256,
            &policy,
            crate::provider::default_provider(),
            &mut candidate_budget,
        )
        .err()
        .expect("document CRL revokes leaf");
    assert!(
        error
            .to_string()
            .contains("certificate at chain position 0 is revoked"),
        "{error}"
    );
    let mut bounded = policy.clone();
    // The owned fallback coexists with the root and enabled document CRL.
    // Deny one byte below that peak; disabling CRLs releases both charges.
    bounded.resources.max_external_resource_total_bytes =
        leaf.der().len() + 2 * (root.der().len() + crl.der().len()) - 1;
    assert!(matches!(
        resolver.resolve_with_policy_and_provider(
            Some(&info),
            SignatureAlgorithm::EcdsaSha256,
            &bounded,
            crate::provider::default_provider()
        ),
        Err(DsigError::Policy(
            crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                ..
            }
        ))
    ));
    bounded.key_trust.check_crls = false;
    assert!(
        resolver
            .resolve_with_policy_and_provider(
                Some(&info),
                SignatureAlgorithm::EcdsaSha256,
                &bounded,
                crate::provider::default_provider()
            )
            .expect("disabled CRL checks do not load CRLs")
            .is_some()
    );
}

#[test]
fn named_certificate_resolution_enforces_inventory_crl() {
    // A KeyName must not drop caller-supplied revocation evidence.
    fn cert(pem: &[u8]) -> Vec<u8> {
        let text = std::str::from_utf8(pem).expect("fixture is UTF-8");
        let start = text.find("-----BEGIN ").expect("fixture has PEM armor");
        single_pem_block(
            &text.as_bytes()[start..],
            ResourcePolicy::default().max_external_resource_bytes,
        )
        .expect("certificate PEM parses")
        .into_contents()
    }
    let resources = ResourcePolicy::default();
    let mut inventory = KeyInventory::default();
    inventory
        .add_public_der(
            "leaf".into(),
            cert(include_bytes!(
                "../../tests/fixtures/keys/rsa/rsa-2048-cert.pem"
            )),
            &resources,
        )
        .expect("leaf imports");
    for anchor in [
        include_bytes!("../../tests/fixtures/keys/ca2cert.pem").as_slice(),
        include_bytes!("../../tests/fixtures/keys/cacert.pem").as_slice(),
    ] {
        inventory
            .add_certificate_der(cert(anchor), true, &resources)
            .expect("anchor imports");
    }
    inventory
        .add_crl_der(
            cert(include_bytes!(
                "../../tests/fixtures/keys/rsa/rsa-2048-cert-revoked-crl.pem"
            )),
            &resources,
        )
        .expect("CRL imports");
    let policy = crate::policy::VerificationPolicy {
        key_trust: crate::policy::KeyTrustPolicy {
            verify_x509_chains: true,
            check_crls: true,
            max_x509_chain_depth: 3,
            verification_time: Some(
                std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_hours(492_768),
            ),
            ..crate::policy::KeyTrustPolicy::default()
        },
        ..crate::policy::VerificationPolicy::default()
    };
    let key_info = KeyInfo {
        sources: vec![KeyInfoSource::KeyName("leaf".into())],
        ..KeyInfo::default()
    };
    let error = inventory
        .verification_resolver()
        .resolve_with_policy_and_provider(
            Some(&key_info),
            SignatureAlgorithm::RsaSha256,
            &policy,
            crate::provider::default_provider(),
        )
        .err()
        .expect("revocation evidence must reject this chain");
    assert!(error.to_string().contains("cRLSign"), "{error}");
}

#[test]
fn hmac_resolution_does_not_load_unrelated_certificate_material() {
    // The active snapshot bounds selected material, not unrelated X.509
    // bytes that an HMAC resolver never needs to copy or inspect.
    let mut inventory = KeyInventory::default();
    inventory
        .add_symmetric(
            "hmac".into(),
            SymmetricKeyKind::Hmac,
            b"secret".to_vec(),
            KeyUsages::VERIFY,
            &ResourcePolicy::default(),
        )
        .expect("HMAC imports");
    let pem = include_bytes!("../../tests/fixtures/keys/rsa/rsa-2048-cert.pem");
    let certificate = single_pem_block(pem, ResourcePolicy::default().max_external_resource_bytes)
        .expect("certificate fixture");
    inventory
        .add_certificate_der(
            certificate.contents().to_vec(),
            true,
            &ResourcePolicy::default(),
        )
        .expect("anchor imports");
    let policy = crate::policy::VerificationPolicy {
        resources: ResourcePolicy {
            max_external_resource_bytes: 64,
            max_external_resource_total_bytes: 64,
            ..ResourcePolicy::default()
        },
        ..crate::policy::VerificationPolicy::default()
    };
    let info = KeyInfo {
        sources: vec![KeyInfoSource::KeyName("hmac".into())],
        ..KeyInfo::default()
    };
    assert!(
        inventory
            .verification_resolver()
            .resolve_with_policy_and_provider(
                Some(&info),
                SignatureAlgorithm::HmacSha256,
                &policy,
                crate::provider::default_provider(),
            )
            .expect("unrelated certificates cannot consume HMAC budget")
            .is_some()
    );
}

#[test]
fn named_key_resolution_obeys_source_policy() {
    // Inventory lookup is not permission to use a KeyName source that the
    // operation's immutable verification policy has disabled.
    let resources = ResourcePolicy::default();
    let mut inventory = KeyInventory::default();
    inventory
        .add_symmetric(
            "blocked-name".into(),
            SymmetricKeyKind::Hmac,
            b"policy-guarded-hmac-secret".to_vec(),
            KeyUsages::VERIFY,
            &resources,
        )
        .expect("HMAC fixture imports");
    let info = KeyInfo {
        sources: vec![KeyInfoSource::KeyName("blocked-name".into())],
        ..KeyInfo::default()
    };
    let mut policy = crate::policy::VerificationPolicy::default();
    policy
        .key_sources
        .remove(crate::policy::KeySourceKind::KeyName);
    assert!(
        inventory
            .verification_resolver()
            .resolve_with_policy_and_provider(
                Some(&info),
                SignatureAlgorithm::HmacSha256,
                &policy,
                crate::provider::default_provider(),
            )
            .is_err()
    );
}

#[test]
fn named_lookup_and_fallback_share_one_candidate_budget() {
    // Finding a named inventory entry and resolving its embedded KeyValue
    // are one verification operation, not two independently budgeted scans.
    let mut inventory = KeyInventory::default();
    inventory.public_keys.push(StoredPublicKey {
        name: "named".into(),
        key_info: KeyInfo {
            sources: vec![
                KeyInfoSource::KeyName("named".into()),
                KeyInfoSource::KeyValue(KeyValueInfo::Rsa {
                    modulus: vec![3],
                    exponent: vec![3],
                }),
            ],
        },
        usages: KeyUsages::VERIFY,
    });
    let info = KeyInfo {
        sources: vec![KeyInfoSource::KeyName("named".into())],
    };
    let mut policy = crate::policy::VerificationPolicy::default();
    policy.resources.max_key_candidates = 1;
    let error = inventory
        .verification_resolver()
        .resolve_with_policy_and_provider(
            Some(&info),
            SignatureAlgorithm::RsaSha256,
            &policy,
            crate::provider::default_provider(),
        )
        .err()
        .expect("delegation must not reset the candidate budget");
    assert!(matches!(
        error,
        DsigError::Policy(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::KEY_CANDIDATES,
            maximum: 1,
            actual: 2,
        })
    ));
}

#[test]
fn prefix_retry_spends_the_same_candidate_budget() {
    // Unresolved sources preceding X.509 lookup are visited twice, so both
    // passes must charge the same operation budget.
    let mut sources = vec![KeyInfoSource::KeyName("missing".into()); 3];
    sources.push(KeyInfoSource::X509Data(X509DataInfo {
        subject_names: vec!["missing subject".into()],
        ..X509DataInfo::default()
    }));
    let info = KeyInfo { sources };
    let mut policy = crate::policy::VerificationPolicy::default();
    policy.resources.max_key_candidates = 5;
    let error = KeyInventory::default()
        .verification_resolver()
        .resolve_with_policy_and_provider(
            Some(&info),
            SignatureAlgorithm::RsaSha256,
            &policy,
            crate::provider::default_provider(),
        )
        .err()
        .expect("the repeated prefix must exhaust the candidate limit");
    assert!(matches!(
        error,
        DsigError::Policy(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::KEY_CANDIDATES,
            maximum: 5,
            actual: 6,
        })
    ));
}

#[test]
fn selected_key_value_is_one_resource() {
    // Representation must not split one key into separately bounded
    // components; exact boundaries remain accepted for all KeyValue kinds.
    for value in [
        KeyValueInfo::Rsa {
            modulus: vec![1; 256],
            exponent: vec![1; 3],
        },
        KeyValueInfo::Dsa {
            p: Some(vec![1; 64]),
            q: Some(vec![1; 16]),
            g: Some(vec![1; 64]),
            y: vec![1; 64],
        },
        KeyValueInfo::Ec {
            curve_oid: "1.2.840.10045.3.1.7".into(),
            public_key: vec![1; 65],
        },
    ] {
        let info = KeyInfo {
            sources: vec![KeyInfoSource::KeyValue(value)],
        };
        let size = check_selected_public_material(&info, &ResourcePolicy::default()).expect("size");
        let resources = ResourcePolicy {
            max_external_resource_bytes: size,
            ..ResourcePolicy::default()
        };
        assert_eq!(
            check_selected_public_material(&info, &resources).expect("exact limit"),
            size
        );
        let resources = ResourcePolicy {
            max_external_resource_bytes: size - 1,
            ..resources
        };
        assert!(matches!(check_selected_public_material(&info, &resources),
                Err(DsigError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES, actual, ..
                })) if actual == size));
    }
}

#[test]
fn named_verification_bounds_complete_key_value() {
    // A broadly imported XML key must obey the tighter operation snapshot
    // before the resolver constructs an SPKI from its components.
    use rsa::traits::PublicKeyParts as _;
    let public = RsaPublicKey::from_public_key_pem(include_str!(
        "../../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"
    ))
    .expect("RSA fixture");
    let modulus = public.n().to_be_bytes_trimmed_vartime();
    let exponent = public.e().to_be_bytes_trimmed_vartime();
    let size = modulus.len() + exponent.len();
    let base64 = base64::engine::general_purpose::STANDARD;
    let xml = format!(
        "<Keys xmlns=\"{XMLSEC_NS}\"><KeyInfo xmlns=\"{XMLDSIG_NS}\"><KeyName>named</KeyName><KeyValue><RSAKeyValue><Modulus>{}</Modulus><Exponent>{}</Exponent></RSAKeyValue></KeyValue></KeyInfo></Keys>",
        base64.encode(modulus),
        base64.encode(exponent)
    );
    let inventory = KeyInventory::from_xml_bytes(
        xml.as_bytes(),
        &xml_policy(ResourcePolicy::default()),
        XmlBackend::default(),
    )
    .expect("broad import");
    let info = KeyInfo {
        sources: vec![KeyInfoSource::KeyName("named".into())],
    };
    let mut policy = crate::policy::VerificationPolicy::default();
    policy.resources.max_external_resource_bytes = size;
    assert!(
        inventory
            .verification_resolver()
            .resolve_with_policy_and_provider(
                Some(&info),
                SignatureAlgorithm::RsaSha256,
                &policy,
                crate::provider::default_provider()
            )
            .expect("exact complete-key limit")
            .is_some()
    );
    policy.resources.max_external_resource_bytes = size - 1;
    assert!(
        matches!(inventory.verification_resolver().resolve_with_policy_and_provider(Some(&info), SignatureAlgorithm::RsaSha256,
            &policy, crate::provider::default_provider()),
            Err(DsigError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES, actual, ..
            })) if actual == size)
    );
}

#[test]
fn configured_x509_fallback_budgets_live_copies() {
    // Inventory bytes remain live while the owned fallback is assembled.
    // Deny before cloning even malformed CRLs; admit the exact live peak.
    let resources = ResourcePolicy::default();
    let certificate = single_pem_block(
        include_bytes!("../../tests/fixtures/keys/rsa/rsa-2048-cert.pem"),
        resources.max_external_resource_bytes,
    )
    .expect("certificate")
    .into_contents();
    for trusted in [false, true] {
        for with_crl in [false, true] {
            let mut inventory = KeyInventory::default();
            inventory
                .add_certificate_der(certificate.clone(), trusted, &resources)
                .expect("certificate imports");
            let document_crl = vec![0; 16];
            if with_crl {
                inventory.crls.push(vec![0; 32]);
            }
            let info = KeyInfo {
                sources: vec![KeyInfoSource::X509Data(X509DataInfo {
                    subject_names: vec!["CN=absent".into()],
                    crls: if with_crl {
                        vec![document_crl]
                    } else {
                        Vec::new()
                    },
                    ..X509DataInfo::default()
                })],
            };
            let mut policy = crate::policy::VerificationPolicy::default();
            policy.key_trust.verify_x509_chains = true;
            policy.key_trust.check_crls = with_crl;
            let configured = certificate.len() + if with_crl { 32 } else { 0 };
            // Document evidence is not copied into fallback for an unnamed
            // source; the default resolver checks it with configured bytes.
            let peak = 2 * configured;
            policy.resources.max_external_resource_total_bytes = peak - 1;
            assert!(
                matches!(
                    inventory
                        .verification_resolver()
                        .resolve_with_policy_and_provider(
                            Some(&info),
                            SignatureAlgorithm::RsaSha256,
                            &policy,
                            crate::provider::default_provider(),
                        ),
                    Err(DsigError::Policy(
                        crate::policy::PolicyViolation::ResourceLimit {
                            resource:
                                crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                            ..
                        }
                    ))
                ),
                "each owned fallback copy must fit before allocation"
            );
            policy.resources.max_external_resource_total_bytes = peak;
            let resolver = inventory.verification_resolver();
            let outcome = resolver.resolve_with_policy_and_provider(
                Some(&info),
                SignatureAlgorithm::RsaSha256,
                &policy,
                crate::provider::default_provider(),
            );
            assert!(
                !matches!(outcome, Err(DsigError::Policy(_))),
                "exact copy budget passes preflight"
            );
        }
    }
}

#[test]
fn named_x509_fallback_budgets_document_crl_copies() {
    // A named certificate substitutes document keys, not revocation
    // evidence. Both retained document CRLs and fallback copies coexist.
    let resources = ResourcePolicy::default();
    let certificate = single_pem_block(
        include_bytes!("../../tests/fixtures/keys/rsa/rsa-2048-cert.pem"),
        resources.max_external_resource_bytes,
    )
    .expect("certificate")
    .into_contents();
    let mut inventory = KeyInventory::default();
    inventory
        .add_public_der("leaf".into(), certificate.clone(), &resources)
        .expect("named certificate");
    let info = KeyInfo {
        sources: vec![
            KeyInfoSource::KeyName("leaf".into()),
            KeyInfoSource::X509Data(X509DataInfo {
                crls: vec![vec![0; 32]],
                ..X509DataInfo::default()
            }),
        ],
    };
    let mut policy = crate::policy::VerificationPolicy::default();
    policy.key_trust.verify_x509_chains = true;
    policy.key_trust.check_crls = true;
    policy.resources.max_external_resource_total_bytes = certificate.len() + 64 - 1;
    assert!(matches!(
        inventory
            .verification_resolver()
            .resolve_with_policy_and_provider(
                Some(&info),
                SignatureAlgorithm::RsaSha256,
                &policy,
                crate::provider::default_provider(),
            ),
        Err(DsigError::Policy(
            crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                ..
            }
        ))
    ));
}

#[test]
fn selected_certificate_and_anchors_share_aggregate_budget() {
    // Selected named material and configured trust material are one
    // operation, even though they enter the resolver through separate paths.
    let certificate = single_pem_block(
        include_bytes!("../../tests/fixtures/keys/rsa/rsa-2048-cert.pem"),
        ResourcePolicy::default().max_external_resource_bytes,
    )
    .expect("leaf PEM")
    .into_contents();
    let anchor = single_pem_block(
        include_bytes!("../../tests/fixtures/keys/rsa/rsa-4096-cert.pem"),
        ResourcePolicy::default().max_external_resource_bytes,
    )
    .expect("anchor PEM")
    .into_contents();
    let mut inventory = KeyInventory::default();
    inventory
        .add_public_der(
            "leaf".into(),
            certificate.clone(),
            &ResourcePolicy::default(),
        )
        .expect("leaf imports");
    inventory
        .add_certificate_der(anchor.clone(), true, &ResourcePolicy::default())
        .expect("anchor imports");
    let mut policy = crate::policy::VerificationPolicy::default();
    policy.key_trust.verify_x509_chains = true;
    policy.resources.max_external_resource_total_bytes = certificate.len() + anchor.len() - 1;
    let info = KeyInfo {
        sources: vec![KeyInfoSource::KeyName("leaf".into())],
    };
    let error = inventory
        .verification_resolver()
        .resolve_with_policy_and_provider(
            Some(&info),
            SignatureAlgorithm::RsaSha256,
            &policy,
            crate::provider::default_provider(),
        )
        .err()
        .expect("combined selected and configured material exceeds the budget");
    assert!(matches!(
        error,
        DsigError::Policy(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
            ..
        })
    ));
}

#[test]
fn named_key_does_not_bypass_other_source_permissions() {
    // Every source in a document KeyInfo is subject to the policy, even
    // when the inventory can resolve its KeyName without the other source.
    let resources = ResourcePolicy::default();
    let mut inventory = KeyInventory::default();
    inventory
        .add_symmetric(
            "named".into(),
            SymmetricKeyKind::Hmac,
            b"verification-secret".to_vec(),
            KeyUsages::VERIFY,
            &resources,
        )
        .expect("HMAC fixture imports");
    let info = KeyInfo {
        sources: vec![
            KeyInfoSource::KeyName("named".into()),
            KeyInfoSource::KeyValue(KeyValueInfo::Rsa {
                modulus: vec![3],
                exponent: vec![3],
            }),
        ],
        ..KeyInfo::default()
    };
    let mut policy = crate::policy::VerificationPolicy::default();
    policy
        .key_sources
        .remove(crate::policy::KeySourceKind::KeyValue);
    assert!(
        inventory
            .verification_resolver()
            .resolve_with_policy_and_provider(
                Some(&info),
                SignatureAlgorithm::HmacSha256,
                &policy,
                crate::provider::default_provider(),
            )
            .is_err()
    );
}

#[test]
fn named_public_key_is_trusted_inventory_material() {
    // A document KeyName must not inherit the source restrictions of the
    // caller-owned public key's internal representation.
    let mut inventory = KeyInventory::default();
    inventory
        .add_public_pem(
            "named".into(),
            include_bytes!("../../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"),
            &ResourcePolicy::default(),
        )
        .expect("public key imports");
    let info = KeyInfo {
        sources: vec![KeyInfoSource::KeyName("named".into())],
        ..KeyInfo::default()
    };
    let mut policy = crate::policy::VerificationPolicy::default();
    policy
        .key_sources
        .remove(crate::policy::KeySourceKind::KeyValue);
    policy
        .key_sources
        .remove(crate::policy::KeySourceKind::DerEncodedKeyValue);
    policy
        .key_sources
        .remove(crate::policy::KeySourceKind::X509Data);
    assert!(
        inventory
            .verification_resolver()
            .resolve_with_policy_and_provider(
                Some(&info),
                SignatureAlgorithm::RsaSha256,
                &policy,
                crate::provider::default_provider(),
            )
            .expect("trusted inventory material resolves")
            .is_some()
    );
}

#[test]
fn named_public_key_obeys_current_verification_limits() {
    // A permissive import policy cannot replace a later stricter operation snapshot.
    let mut inventory = KeyInventory::default();
    inventory
        .add_public_pem(
            "named".into(),
            include_bytes!("../../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"),
            &ResourcePolicy::default(),
        )
        .expect("public key imports");
    let info = KeyInfo {
        sources: vec![KeyInfoSource::KeyName("named".into())],
    };
    let mut policy = crate::policy::VerificationPolicy::default();
    policy.resources.max_external_resource_bytes = 1;
    assert!(
        inventory
            .verification_resolver()
            .resolve_with_policy(Some(&info), SignatureAlgorithm::RsaSha256, &policy)
            .is_err()
    );
    let certificate = pem::parse(include_bytes!(
        "../../tests/fixtures/keys/rsa/rsa-2048-cert.pem"
    ))
    .expect("certificate PEM")
    .into_contents();
    let mut certificate_inventory = KeyInventory::default();
    certificate_inventory
        .add_public_der("named".into(), certificate, &ResourcePolicy::default())
        .expect("certificate imports as a named public key");
    assert!(
        certificate_inventory
            .verification_resolver()
            .resolve_with_policy(Some(&info), SignatureAlgorithm::RsaSha256, &policy)
            .is_err()
    );
}

#[test]
fn unused_certificates_do_not_block_earlier_public_keys() {
    // X.509 lookup bytes are irrelevant when a preceding DER key resolves.
    let mut inventory = KeyInventory::default();
    let certificate = pem::parse(include_bytes!(
        "../../tests/fixtures/keys/rsa/rsa-2048-cert.pem"
    ))
    .expect("certificate PEM")
    .into_contents();
    inventory
        .add_certificate_der(certificate, false, &ResourcePolicy::default())
        .expect("certificate imports");
    let public = pem::parse(include_bytes!(
        "../../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"
    ))
    .expect("public PEM")
    .into_contents();
    let info = KeyInfo {
        sources: vec![
            KeyInfoSource::DerEncodedKeyValue(public.clone()),
            KeyInfoSource::X509Data(X509DataInfo {
                subject_names: vec!["unused".into()],
                ..X509DataInfo::default()
            }),
        ],
    };
    let mut policy = crate::policy::VerificationPolicy::default();
    policy.resources.max_external_resource_bytes = public.len();
    assert!(
        inventory
            .verification_resolver()
            .resolve_with_policy(Some(&info), SignatureAlgorithm::RsaSha256, &policy)
            .expect("earlier public key resolves")
            .is_some()
    );
}

#[test]
fn public_import_rejects_incompatible_usage() {
    // Public material may verify or encrypt, but cannot authorize signing.
    let resources = ResourcePolicy::default();
    let public = include_bytes!("../../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    let mut inventory = KeyInventory::default();
    assert!(
        inventory
            .add_public_pem_with_usages("invalid".into(), public, KeyUsages::SIGN, &resources,)
            .is_err()
    );
    assert_eq!(inventory.entry_count(), 0);
}

#[test]
fn public_certificate_import_accepts_supported_ed25519_key() {
    // Ed25519 can now acquire verification usage, but importing a
    // certificate still does not promote it into the trusted anchor set.
    let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("Ed25519 key generation");
    let params =
        rcgen::CertificateParams::new(vec!["example.test".into()]).expect("certificate parameters");
    let certificate = params.self_signed(&pair).expect("certificate generation");
    let mut inventory = KeyInventory::default();
    assert!(
        inventory
            .add_public_der(
                "ed25519".into(),
                certificate.der().to_vec(),
                &ResourcePolicy::default()
            )
            .is_ok()
    );
    assert_eq!(inventory.trusted_certificates, [] as [Vec<u8>; 0]);
}

#[cfg(feature = "xmlenc")]
#[test]
fn imported_usage_restricts_operation_selection() {
    // Explicit restrictions survive import and are enforced when selecting
    // material for the opposite operation.
    let resources = ResourcePolicy::default();
    let public = include_bytes!("../../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    let bundle = include_bytes!("../../tests/fixtures/xmlenc/01-phaos-xmlenc-3/rsa-priv-key.p12");
    let mut inventory = KeyInventory::default();
    inventory
        .add_public_pem_with_usages("verify".into(), public, KeyUsages::VERIFY, &resources)
        .expect("verification-only public key imports");
    assert!(
        inventory
            .rsa_encryption_key("verify", &crate::policy::EncryptionPolicy::default())
            .is_err()
    );
    inventory
        .add_pkcs12_with_usages(
            "decrypt".into(),
            bundle,
            "secret",
            KeyUsages::DECRYPT,
            &resources,
        )
        .expect("decryption-only private key imports");
    assert!(
        inventory
            .signing_key(
                "decrypt",
                SignatureAlgorithm::RsaSha256,
                &crate::policy::SigningPolicy::default(),
            )
            .is_err()
    );
    assert!(
        inventory
            .decryption_resolver("decrypt", &crate::policy::DecryptionPolicy::default())
            .is_ok()
    );
}

#[cfg(feature = "xmlenc")]
#[test]
fn selected_weak_rsa_decryptor_obeys_default_policy() {
    // Importing a legacy key grants no exemption from operation minima.
    let mut inventory = KeyInventory::default();
    let weak = RsaPrivateKey::new(&mut ChaCha8Rng::seed_from_u64(0xA11C_E502), 1024)
        .expect("legacy key generation")
        .to_pkcs8_der()
        .expect("legacy key encoding");
    inventory
        .add_private_der(
            "weak".into(),
            weak.as_bytes(),
            None,
            KeyUsages::DECRYPT,
            &ResourcePolicy::default(),
        )
        .expect("legacy import");
    let error = inventory
        .decryption_resolver("weak", &crate::policy::DecryptionPolicy::default())
        .err()
        .expect("weak key is rejected");
    assert!(
        matches!(
            error,
            KeyStoreError::Policy(crate::policy::PolicyViolation::KeySize {
                operation: "decryption",
                ..
            })
        ),
        "{error:?}"
    );
    // A caller can deliberately authorize legacy input, but the snapshot
    // must survive inventory selection and the complete recovery pipeline.
    let key = RsaPrivateKey::from_pkcs8_der(weak.as_bytes()).expect("legacy decode");
    let mut encryption = crate::policy::EncryptionPolicy::default();
    encryption.rsa_keys.minimum_modulus_bits = 1024;
    let encrypted =
        crate::xmlenc::EncryptedDataBuilder::new(crate::xmlenc::DataEncryptionAlgorithm::Aes128Gcm)
            .policy(encryption)
            .recipient_rsa_oaep(key.to_public_key())
            .encrypt_binary(b"legacy consent")
            .expect("explicit legacy encryption");
    let mut decryption = crate::policy::DecryptionPolicy::default();
    decryption.rsa_keys.minimum_modulus_bits = 1024;
    let resolver = inventory
        .decryption_resolver("weak", &decryption)
        .expect("explicit legacy selection");
    assert_eq!(
        crate::xmlenc::DecryptContext::new(resolver.as_ref())
            .policy(decryption)
            .decrypt(&encrypted.encrypted_data_xml)
            .expect("explicit legacy recovery"),
        crate::xmlenc::DecryptedContent::Bytes(b"legacy consent".to_vec())
    );
    assert!(matches!(
        crate::xmlenc::DecryptContext::new(resolver.as_ref())
            .decrypt(&encrypted.encrypted_data_xml),
        Err(crate::xmlenc::XmlEncError::Policy(
            crate::policy::PolicyViolation::KeySize {
                actual_bits: 1024,
                ..
            }
        ))
    ));
}

#[cfg(feature = "xmlenc")]
#[test]
fn selected_rsa_recipient_obeys_operation_modulus_policy() {
    // Import permission does not override a stricter encryption snapshot.
    let mut inventory = KeyInventory::default();
    inventory
        .add_public_pem(
            "rsa".into(),
            include_bytes!("../../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"),
            &ResourcePolicy::default(),
        )
        .expect("RSA fixture imports");
    let mut policy = crate::policy::EncryptionPolicy::default();
    policy.rsa_keys.minimum_modulus_bits = 4096;
    assert!(matches!(
        inventory.rsa_encryption_key("rsa", &policy),
        Err(KeyStoreError::Policy(
            crate::policy::PolicyViolation::KeySize { .. }
        ))
    ));
    assert!(matches!(
        inventory.public_keys()[0].rsa_encryption_key(&policy),
        Err(KeyStoreError::Policy(
            crate::policy::PolicyViolation::KeySize { .. }
        ))
    ));
}

#[test]
fn inventory_merge_checks_names_and_budget_atomically() {
    // Combining independently parsed stores cannot bypass name or
    // aggregate-material limits, and a rejected merge is atomic.
    let resources = ResourcePolicy::default();
    let mut first = KeyInventory::default();
    first
        .add_symmetric(
            "one".into(),
            SymmetricKeyKind::Hmac,
            b"first-secret".to_vec(),
            KeyUsages::SIGN,
            &resources,
        )
        .expect("first key imports");
    let mut duplicate = KeyInventory::default();
    duplicate
        .add_symmetric(
            "one".into(),
            SymmetricKeyKind::Hmac,
            b"second-secret".to_vec(),
            KeyUsages::VERIFY,
            &resources,
        )
        .expect("independent duplicate imports");
    assert!(matches!(
        first.extend(duplicate, &resources),
        Err(KeyStoreError::Selection("duplicate key name"))
    ));
    assert_eq!(first.entry_count(), 1);
    let mut second = KeyInventory::default();
    second
        .add_symmetric(
            "two".into(),
            SymmetricKeyKind::Hmac,
            b"second-secret".to_vec(),
            KeyUsages::VERIFY,
            &resources,
        )
        .expect("second key imports");
    let constrained = ResourcePolicy {
        max_external_resource_total_bytes: b"first-secret".len(),
        ..ResourcePolicy::default()
    };
    assert!(matches!(
        first.extend(second, &constrained),
        Err(KeyStoreError::Policy(
            crate::policy::PolicyViolation::ResourceLimitExceeded {
                resource: crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                ..
            }
        ))
    ));
    assert_eq!(first.entry_count(), 1);
}

#[test]
fn public_dsa_store_entries_require_usable_parameters() {
    // The inventory has no implicit parameter inheritance. Do not grant
    // VERIFY to material that its own resolver cannot construct as a key.
    for fields in [
        "<Y>AQ==</Y>",
        "<P/><Q/><G/><Y>AQ==</Y>",
        "<P>AQ==</P><Q>AQ==</Q><G>AQ==</G><Y>AQ==</Y>",
    ] {
        let xml = format!(
            "<Keys xmlns=\"{XMLSEC_NS}\"><KeyInfo xmlns=\"{XMLDSIG_NS}\"><KeyName>dsa</KeyName><KeyValue><DSAKeyValue>{fields}</DSAKeyValue></KeyValue></KeyInfo></Keys>"
        );
        assert!(
            KeyInventory::from_xml_bytes(
                xml.as_bytes(),
                &xml_policy(ResourcePolicy::default()),
                XmlBackend::default()
            )
            .is_err(),
            "accepted unusable DSA: {fields}"
        );
    }
}

#[test]
fn oversized_private_dsa_component_stops_before_big_integer_work() {
    // A bounded XML file can still contain an outsized exponent; reject
    // it before constructing a large modular exponentiation.
    let oversized = base64::engine::general_purpose::STANDARD.encode(vec![1_u8; 513]);
    let xml = format!(
        "<Keys xmlns=\"{XMLSEC_NS}\"><KeyInfo xmlns=\"{XMLDSIG_NS}\"><KeyName>dsa</KeyName><KeyValue><DSAKeyValue><P>{oversized}</P><Q>AQ==</Q><G>AQ==</G><X xmlns=\"{XMLSEC_NS}\">AQ==</X><Y>AQ==</Y></DSAKeyValue></KeyValue></KeyInfo></Keys>"
    );
    assert!(matches!(
        KeyInventory::from_xml_bytes(
            xml.as_bytes(),
            &xml_policy(ResourcePolicy::default()),
            XmlBackend::default(),
        ),
        Err(KeyStoreError::Invalid(message)) if message.contains("safety limit")
    ));
}

#[test]
fn oversized_pkcs8_dsa_parameters_stop_before_key_derivation() {
    // PKCS#8 uses the same component ceiling as xmlsec's DSAKeyValue.
    #[derive(der::Sequence)]
    struct DsaParameters<'a> {
        p: der::asn1::UintRef<'a>,
        q: der::asn1::UintRef<'a>,
        g: der::asn1::UintRef<'a>,
    }
    let oversized = vec![1_u8; crate::hard_limits::DSA_KEY_COMPONENT_BYTE_CEILING + 1];
    let one = [1_u8];
    let parameters = der::Encode::to_der(&DsaParameters {
        p: der::asn1::UintRef::new(&oversized).expect("positive P"),
        q: der::asn1::UintRef::new(&one).expect("positive Q"),
        g: der::asn1::UintRef::new(&one).expect("positive G"),
    })
    .expect("DSA parameters encode");
    let x = der::Encode::to_der(&der::asn1::UintRef::new(&one).expect("positive X"))
        .expect("DSA X encodes");
    let algorithm = pkcs8::AlgorithmIdentifierRef {
        oid: dsa::OID,
        parameters: Some(der::asn1::AnyRef::from_der(&parameters).expect("parameters")),
    };
    let private = der::asn1::OctetStringRef::new(&x).expect("private octets");
    let pkcs8 =
        der::Encode::to_der(&PrivateKeyInfoRef::new(algorithm, private)).expect("PKCS#8 encodes");
    let mut inventory = KeyInventory::default();
    let error = inventory
        .add_private_der(
            "oversized-dsa".into(),
            &pkcs8,
            None,
            KeyUsages::SIGN,
            &ResourcePolicy::default(),
        )
        .expect_err("oversized DSA parameter must fail preflight");
    assert!(
        matches!(
            error,
            KeyStoreError::Selection("invalid or oversized DSA private key")
        ),
        "{error}"
    );
}

#[test]
fn compressed_ec_spki_cannot_acquire_verify_usage() {
    struct CompressedPoint<'a>(&'a [u8], &'static rcgen::SignatureAlgorithm);
    impl rcgen::PublicKeyData for CompressedPoint<'_> {
        fn der_bytes(&self) -> &[u8] {
            self.0
        }
        fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
            self.1
        }
    }

    // Import must enforce the same SEC1 profile as signature verification,
    // for every supported curve, rather than grant unusable VERIFY usage.
    for pem in [
        include_bytes!("../../tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem").as_slice(),
        include_bytes!("../../tests/fixtures/keys/ec/ec-prime384v1-pubkey.pem").as_slice(),
        include_bytes!("../../tests/fixtures/keys/ec/ec-prime521v1-pubkey.pem").as_slice(),
    ] {
        let original = single_pem_block(pem, ResourcePolicy::default().max_external_resource_bytes)
            .expect("EC fixture")
            .into_contents();
        let spki = pkcs8::SubjectPublicKeyInfoRef::from_der(&original).expect("SPKI");
        let point = spki
            .subject_public_key
            .as_bytes()
            .expect("octet-aligned point");
        let coordinate_len = (point.len() - 1) / 2;
        let mut compressed = vec![2 | (point.last().expect("Y coordinate") & 1)];
        compressed.extend_from_slice(&point[1..=coordinate_len]);
        let encoded = der::Encode::to_der(&pkcs8::SubjectPublicKeyInfoRef {
            algorithm: spki.algorithm,
            subject_public_key: der::asn1::BitStringRef::from_bytes(&compressed).expect("point"),
        })
        .expect("compressed SPKI");
        let mut inventory = KeyInventory::default();
        assert!(
            inventory
                .add_public_der("compressed".into(), encoded, &ResourcePolicy::default())
                .is_err()
        );
        assert!(inventory.public_keys().is_empty());
        inventory
            .add_public_der("uncompressed".into(), original, &ResourcePolicy::default())
            .expect("supported uncompressed encoding remains usable");
    }
    // A genuinely signed certificate wrapper must not bypass this profile.
    let mut root_params = rcgen::CertificateParams::new(Vec::new()).expect("root params");
    root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let root = rcgen::CertifiedIssuer::self_signed(
        root_params,
        rcgen::KeyPair::generate().expect("root key"),
    )
    .expect("root certificate");
    for (pem, algorithm) in [
        (
            include_bytes!("../../tests/fixtures/keys/ec/ec-prime256v1-cert.pem").as_slice(),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        ),
        (
            include_bytes!("../../tests/fixtures/keys/ec/ec-prime384v1-cert.pem").as_slice(),
            &rcgen::PKCS_ECDSA_P384_SHA384,
        ),
    ] {
        let original = single_pem_block(pem, ResourcePolicy::default().max_external_resource_bytes)
            .expect("certificate fixture")
            .into_contents();
        let (_, certificate) = X509Certificate::from_der(&original).expect("certificate");
        let point = certificate.public_key().subject_public_key.data.as_ref();
        let coordinate_len = (point.len() - 1) / 2;
        let mut compressed = vec![2 | (point.last().expect("Y coordinate") & 1)];
        compressed.extend_from_slice(&point[1..=coordinate_len]);
        let leaf = rcgen::CertificateParams::new(Vec::new())
            .expect("leaf params")
            .signed_by(&CompressedPoint(&compressed, algorithm), &root)
            .expect("signed compressed certificate");
        let encoded = leaf.der().to_vec();
        let mut inventory = KeyInventory::default();
        assert!(
            inventory
                .add_public_der(
                    "compressed-cert".into(),
                    encoded,
                    &ResourcePolicy::default()
                )
                .is_err()
        );
        assert!(inventory.public_keys().is_empty());
        inventory
            .add_public_der(
                "uncompressed-cert".into(),
                original,
                &ResourcePolicy::default(),
            )
            .expect("uncompressed certificate imports");
    }
}

#[test]
fn malformed_ec_point_cannot_acquire_verify_usage() {
    // A supported curve OID does not make an off-curve point usable.
    let block = single_pem_block(
        include_bytes!("../../tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem"),
        ResourcePolicy::default().max_external_resource_bytes,
    )
    .expect("EC SPKI fixture");
    let mut der = block.into_contents();
    let last = der.last_mut().expect("point bytes");
    *last ^= 1;
    let mut inventory = KeyInventory::default();
    assert!(
        inventory
            .add_public_der("off-curve".into(), der, &ResourcePolicy::default())
            .is_err()
    );
    assert!(inventory.public_keys().is_empty());
}

#[cfg(feature = "xmlenc")]
#[test]
fn decryption_policy_rejection_retains_its_type() {
    // An invalid operation snapshot is not a candidate-local key miss.
    let mut policy = crate::policy::DecryptionPolicy::default();
    policy.resources.max_external_resource_bytes = usize::MAX;
    assert!(matches!(
        KeyInventory::default().decryption_resolver("missing", &policy),
        Err(KeyStoreError::Policy(_))
    ));
}

#[cfg(feature = "xmlenc")]
#[test]
fn inventory_decryption_resolver_enforces_aes_usage_end_to_end() {
    // Inventory authorization is checked before the normal XMLEnc
    // decryptor receives an otherwise valid direct AES content key.
    use crate::xmlenc::{
        DataEncryptionAlgorithm, DecryptContext, DecryptedContent, EncryptedDataBuilder,
    };

    let key = b"0123456789abcdef";
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .direct_key(*key)
        .encrypt_binary(b"inventory decrypt payload")
        .expect("AES fixture encrypts");
    let resources = ResourcePolicy::default();
    let mut keys = KeyInventory::default();
    keys.add_symmetric(
        "decrypt".into(),
        SymmetricKeyKind::Aes,
        key.to_vec(),
        KeyUsages::DECRYPT,
        &resources,
    )
    .expect("decrypt key imports");
    let resolver = keys
        .decryption_resolver("decrypt", &crate::policy::DecryptionPolicy::default())
        .expect("decrypt use is allowed");
    let content = DecryptContext::new(resolver.as_ref())
        .decrypt(&encrypted.encrypted_data_xml)
        .expect("inventory key decrypts");
    assert!(
        matches!(content, DecryptedContent::Bytes(bytes) if bytes == b"inventory decrypt payload")
    );

    let mut restricted = KeyInventory::default();
    restricted
        .add_symmetric(
            "encrypt-only".into(),
            SymmetricKeyKind::Aes,
            key.to_vec(),
            KeyUsages::ENCRYPT,
            &resources,
        )
        .expect("encrypt-only key imports");
    assert!(
        restricted
            .decryption_resolver("encrypt-only", &crate::policy::DecryptionPolicy::default())
            .is_err()
    );
}

#[cfg(feature = "xmlenc")]
#[test]
fn inventory_direct_aes_rechecks_execution_policy() {
    // Selection does not freeze resource permission: reject a tighter
    // execution snapshot before copying bytes or consuming a candidate.
    use crate::xmlenc::{DataEncryptionAlgorithm, KeyCandidateBudget, XmlEncError};
    let mut inventory = KeyInventory::default();
    inventory
        .add_symmetric(
            "aes".into(),
            SymmetricKeyKind::Aes,
            vec![1; 16],
            KeyUsages::DECRYPT,
            &ResourcePolicy::default(),
        )
        .expect("AES imports");
    let resolver = inventory
        .decryption_resolver("aes", &crate::policy::DecryptionPolicy::default())
        .expect("AES resolver");
    let mut policy = crate::policy::DecryptionPolicy::default();
    policy.resources.max_external_resource_bytes = 15;
    let mut budget = KeyCandidateBudget::with_limit(1);
    assert!(matches!(
        resolver.resolve_key_candidates_with_policy(
            &crate::provider::RustCryptoProvider,
            DataEncryptionAlgorithm::Aes128Gcm,
            None,
            &policy,
            &mut budget
        ),
        Err(XmlEncError::Policy(_))
    ));
    assert_eq!(budget.remaining(), 1);
    policy.resources.max_external_resource_bytes = 16;
    assert_eq!(
        resolver
            .resolve_key_candidates_with_policy(
                &crate::provider::RustCryptoProvider,
                DataEncryptionAlgorithm::Aes128Gcm,
                None,
                &policy,
                &mut budget
            )
            .expect("exact execution allowance"),
        vec![vec![1; 16]]
    );
    assert_eq!(budget.remaining(), 0);
}

#[cfg(feature = "xmlenc")]
#[test]
fn inventory_direct_aes_does_not_consume_recipient_candidates() {
    // A direct AES key is not a wrapping key. Recipient traversal must
    // leave its sole candidate available for the later direct-key path.
    use crate::xmlenc::{
        CipherData, DataEncryptionAlgorithm, EncryptedKey, EncryptionMethod, KeyCandidateBudget,
        KeyTransportAlgorithm, XmlEncError,
    };
    let mut keys = KeyInventory::default();
    keys.add_symmetric(
        "direct".into(),
        SymmetricKeyKind::Aes,
        vec![1; 16],
        KeyUsages::DECRYPT,
        &ResourcePolicy::default(),
    )
    .expect("AES imports");
    let resolver = keys
        .decryption_resolver("direct", &crate::policy::DecryptionPolicy::default())
        .expect("AES resolver");
    let recipient = EncryptedKey {
        sources: crate::xmlenc::EncryptionKeySources::default(),
        id: None,
        recipient: None,
        key_name: None,
        encryption_method: EncryptionMethod {
            chacha: None,
            algorithm: KeyTransportAlgorithm::RsaOaep11.uri().into(),
            key_size_bits: None,
            oaep_digest: None,
            mgf_algorithm: None,
            oaep_params: None,
        },
        cipher_data: CipherData::Value {
            value: String::new(),
        },
        reference_list: None,
        carried_key_name: None,
    };
    let mut budget = KeyCandidateBudget::with_limit(1);
    let provider = crate::provider::RustCryptoProvider;
    for _ in 0..64 {
        assert!(matches!(
            resolver.resolve_key_candidates(
                &provider,
                DataEncryptionAlgorithm::Aes128Gcm,
                Some(&recipient),
                &mut budget
            ),
            Err(XmlEncError::KeyNotFound)
        ));
        assert_eq!(budget.remaining(), 1);
    }
    assert_eq!(
        resolver
            .resolve_key_candidates(
                &provider,
                DataEncryptionAlgorithm::Aes128Gcm,
                None,
                &mut budget
            )
            .expect("one direct candidate"),
        vec![vec![1; 16]]
    );
    assert_eq!(budget.remaining(), 0);
}

#[cfg(feature = "xmlenc")]
#[test]
fn decryption_selection_checks_operation_limits_before_material_use() {
    // Reusing a broadly imported inventory with a tighter operation
    // snapshot must reject both AES and RSA material before copy/decode.
    let resources = ResourcePolicy::default();
    let mut keys = KeyInventory::default();
    keys.add_symmetric(
        "aes".into(),
        SymmetricKeyKind::Aes,
        vec![0x31; 16],
        KeyUsages::DECRYPT,
        &resources,
    )
    .expect("AES key imports");
    keys.add_private_pem(
        "rsa".into(),
        include_bytes!("../../tests/fixtures/keys/rsa/rsa-2048-key.pem"),
        None,
        KeyUsages::DECRYPT,
        &resources,
    )
    .expect("RSA key imports");
    let mut policy = crate::policy::DecryptionPolicy::default();
    policy.resources.max_external_resource_bytes = 8;
    policy.resources.max_external_resource_total_bytes = 8;
    assert!(keys.decryption_resolver("aes", &policy).is_err());
    assert!(keys.decryption_resolver("rsa", &policy).is_err());
}
