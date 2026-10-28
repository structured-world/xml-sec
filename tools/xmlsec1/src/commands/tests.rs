use std::{cell::Cell, ffi::OsString, rc::Rc};

use base64::Engine as _;

use super::*;

fn project_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
}

#[test]
fn signing_certificate_failure_has_signature_category() {
    // A malformed embedded certificate is a signing-input failure, not encryption.
    let key = xml_sec::xmldsig::RsaSigningKey::from_pkcs8_pem(include_str!(
        "../../../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
    ))
    .unwrap();
    let candidate = SigningKeyCandidate {
        key: Box::new(key),
        certificate_writer: None,
        leaf_certificate_der: None,
    };
    let mut info = KeyInfo::default();
    let mut data = xml_sec::xmldsig::X509DataInfo::default();
    data.certificates.push(vec![0]);
    info.sources.push(KeyInfoSource::X509Data(data));
    let resources = ResourcePolicy::default();
    let mut parsing = xml_sec::xmldsig::parse::KeyInfoParsingSession::new(&resources).unwrap();
    let error =
        validate_signing_key_info(Some(&info), &candidate, default_provider(), &mut parsing)
            .unwrap_err();
    assert!(matches!(error, CommandError::Signature(_)));
}

#[test]
fn certificate_work_refusal_is_terminal_for_lax_search() {
    // A certificate account failure must not be downgraded to candidate mismatch.
    let der = pem::parse(include_bytes!(
        "../../../../tests/fixtures/keys/rsa/rsa-2048-cert.pem"
    ))
    .unwrap()
    .into_contents();
    let resources = ResourcePolicy {
        max_x509_work: 1,
        ..Default::default()
    };
    let mut parsing = xml_sec::xmldsig::parse::KeyInfoParsingSession::new(&resources).unwrap();
    let error = certificate_public_key(&der, &mut parsing, |_| ())
        .map_err(certificate_command_error)
        .unwrap_err();
    assert!(matches!(error, CommandError::Policy(_)));
    assert!(!lax_candidate_error_is_recoverable(&error));
}

#[test]
fn certificate_candidate_matching_retains_spent_work() {
    // Hash-table equality work can vary across independent accounts.
    // Test one retained account until its exact work resource refuses admission.
    let der = pem::parse(include_bytes!(
        "../../../../tests/fixtures/keys/rsa/rsa-2048-cert.pem"
    ))
    .unwrap()
    .into_contents();
    let resources = ResourcePolicy {
        max_x509_work: 50_000,
        max_key_candidates: 32,
        ..Default::default()
    };
    let mut parsing = xml_sec::xmldsig::parse::KeyInfoParsingSession::new(&resources).unwrap();
    let mut successful = 0;
    for _ in 0..resources.max_key_candidates {
        match certificate_public_key(&der, &mut parsing, |_| ()).map_err(certificate_command_error)
        {
            Ok(()) => successful += 1,
            Err(error) => {
                assert!(successful > 0);
                assert!(matches!(
                    error,
                    CommandError::Policy(xml_sec::policy::PolicyViolation::ResourceLimitExceeded {
                        resource: "X.509 work",
                        maximum: 50_000
                    })
                ));
                assert!(!lax_candidate_error_is_recoverable(&error));
                return;
            }
        }
    }
    panic!("certificate work was reset between candidates");
}

fn invocation(arguments: &[&str]) -> Invocation {
    Invocation::parse(arguments.iter().map(OsString::from)).unwrap()
}

#[test]
fn signing_material_and_mappings_share_one_budget() {
    // Reference acquisition must not reset the allowance consumed by signing keys.
    let directory = tempfile::tempdir().unwrap();
    let key = directory.path().join("key");
    let part = directory.path().join("part");
    let template = directory.path().join("template.xml");
    fs::write(&key, [7; 32]).unwrap();
    fs::write(&part, b"abc").unwrap();
    fs::write(&template, br#"<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"/><Reference URI="urn:part"><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue/></Reference></SignedInfo><SignatureValue/></Signature>"#).unwrap();
    let request = invocation(&[
        "xmlsec1",
        "sign",
        "--hmac-key",
        key.to_str().unwrap(),
        "--url-map:urn:part",
        part.to_str().unwrap(),
        template.to_str().unwrap(),
    ]);
    let mut policy = xmlsec_compatibility_signing_policy(&request);
    policy.resources.max_external_resource_total_bytes = 34;
    let result = sign_with_policy(&request, &mut Vec::new(), policy);
    assert!(
        matches!(result, Err(CommandError::ExternalMaterialTooLarge { .. })),
        "{result:?}"
    );
    let mut policy = xmlsec_compatibility_signing_policy(&request);
    policy.resources.max_external_resource_total_bytes = 35;
    sign_with_policy(&request, &mut Vec::new(), policy).expect("exact combined allowance");
    let store = directory.path().join("keys.xml");
    fs::write(&store, br#"<Keys xmlns="http://www.aleksey.com/xmlsec/2002"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><KeyName>only-key</KeyName><KeyValue><HMACKeyValue xmlns="http://www.aleksey.com/xmlsec/2002">c2VjcmV0</HMACKeyValue></KeyValue></KeyInfo></Keys>"#).unwrap();
    let request = invocation(&[
        "xmlsec1",
        "sign",
        "--keys-file",
        store.to_str().unwrap(),
        "--lax-key-search",
        "--url-map:urn:part",
        part.to_str().unwrap(),
        template.to_str().unwrap(),
    ]);
    let mut policy = xmlsec_compatibility_signing_policy(&request);
    let store_bytes = usize::try_from(fs::metadata(&store).unwrap().len()).unwrap();
    // Leave headroom for the importer's decoded material, but make the map
    // exceed the bytes remaining after acquisition of the store itself.
    policy.resources.max_external_resource_total_bytes = store_bytes * 4;
    fs::write(&part, vec![0; store_bytes * 3 + 1]).unwrap();
    let result = sign_with_policy(&request, &mut Vec::new(), policy);
    assert!(
        matches!(result, Err(CommandError::ExternalMaterialTooLarge { .. })),
        "{result:?}"
    );
}

#[test]
fn mapped_references_enforce_individual_and_aggregate_limits() {
    // Limits apply before file-sized allocations, including existing
    // invocation material. An exact-boundary file remains usable.
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("part");
    fs::write(&file, b"abc").unwrap();
    let file = file.to_str().unwrap();
    let request = invocation(&["xmlsec1", "verify", "--url-map:urn:a", file]);
    let mut resources = ResourcePolicy {
        max_external_resource_bytes: 3,
        ..ResourcePolicy::default()
    };
    let mut budget = ExternalMaterialBudget::new(3);
    let map = load_mapped_reference_resources(&request, &resources, &mut budget).unwrap();
    assert_eq!(map["urn:a"], b"abc");
    assert_eq!(budget.remaining(), 0);
    resources.max_external_resource_bytes = 2;
    assert!(matches!(
        load_mapped_reference_resources(&request, &resources, &mut ExternalMaterialBudget::new(10)),
        Err(CommandError::ExternalMaterialTooLarge { .. })
    ));
    resources.max_external_resource_bytes = 3;
    let mut budget = ExternalMaterialBudget::new(4);
    budget.charge(2).unwrap();
    assert!(matches!(
        load_mapped_reference_resources(&request, &resources, &mut budget),
        Err(CommandError::ExternalMaterialTooLarge { .. })
    ));
    let request = invocation(&[
        "xmlsec1",
        "verify",
        "--url-map:urn:a",
        file,
        "--url-map:urn:b",
        file,
    ]);
    assert!(matches!(
        load_mapped_reference_resources(&request, &resources, &mut ExternalMaterialBudget::new(5)),
        Err(CommandError::ExternalMaterialTooLarge { .. })
    ));
}

#[test]
fn mapped_references_reject_ambiguous_or_missing_uri() {
    // A duplicate cannot replace bytes already loaded under a trusted URI;
    // malformed parameters fail before opening their file.
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("part");
    fs::write(&file, []).unwrap();
    let file = file.to_str().unwrap();
    let resources = ResourcePolicy::default();
    for request in [
        invocation(&["xmlsec1", "verify", "--url-map", "/missing"]),
        invocation(&["xmlsec1", "verify", "--url-map:", "/missing"]),
        invocation(&[
            "xmlsec1",
            "verify",
            "--url-map:urn:a",
            file,
            "--url-map:urn:a",
            "/missing",
        ]),
    ] {
        assert!(matches!(
            load_mapped_reference_resources(
                &request,
                &resources,
                &mut ExternalMaterialBudget::new(10)
            ),
            Err(CommandError::Usage(_))
        ));
    }
}

#[test]
fn recipient_metadata_shares_operation_candidate_preflight() {
    // Nested recipients must not each receive a fresh policy allowance;
    // the third candidate is denied before its malformed payload is decoded.
    let recipient = |value: &str| {
        format!(
            "<EncryptedKey><ds:KeyInfo><ds:KeyValue>{value}</ds:KeyValue></ds:KeyInfo></EncryptedKey>"
        )
    };
    let template = |last: &str| {
        format!(
            "<EncryptedData xmlns=\"http://www.w3.org/2001/04/xmlenc#\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:KeyInfo>{}{}{}</ds:KeyInfo></EncryptedData>",
            recipient("<Unknown/>"),
            recipient("<Unknown/>"),
            recipient(last),
        )
    };
    let mut policy = EncryptionPolicy::default();
    policy.resources.max_key_candidates = 2;
    let mut parsing =
        xml_sec::xmldsig::parse::KeyInfoParsingSession::new(&policy.resources).unwrap();
    let error = recipient_key_metadata(
        &template(""),
        None,
        &[],
        &policy,
        3,
        CommandBackends {
            xml: XmlBackend::default(),
            crypto: default_provider(),
        },
        &mut parsing,
    )
    .err()
    .expect("aggregate candidate limit");
    assert!(matches!(
        error,
        CommandError::Policy(xml_sec::policy::PolicyViolation::ResourceLimit {
            maximum: 2,
            actual: 3,
            ..
        })
    ));
    drop(parsing);
    policy.resources.max_key_candidates = 3;
    let mut parsing =
        xml_sec::xmldsig::parse::KeyInfoParsingSession::new(&policy.resources).unwrap();
    assert!(
        recipient_key_metadata(
            &template("<Unknown/>"),
            None,
            &[],
            &policy,
            3,
            CommandBackends {
                xml: XmlBackend::default(),
                crypto: default_provider()
            },
            &mut parsing,
        )
        .is_ok()
    );
}

#[test]
fn temporary_private_imports_keep_kdf_work_after_failure() {
    use der::Encode as _;
    use pkcs8::{
        EncryptedPrivateKeyInfoRef,
        pkcs5::{EncryptionScheme, pbes2},
    };
    // A failed decrypt spent work even though its temporary inventory held
    // no key. A second PEM/DER candidate must see only the remainder.
    let envelope = EncryptedPrivateKeyInfoRef {
        encryption_algorithm: EncryptionScheme::Pbes2(pbes2::Parameters {
            kdf: pbes2::Kdf::Pbkdf2(pbes2::Pbkdf2Params {
                salt: pbes2::Salt::new(b"12345678").unwrap(),
                iteration_count: 2,
                key_length: None,
                prf: pbes2::Pbkdf2Prf::HmacWithSha256,
            }),
            encryption: pbes2::EncryptionScheme::Aes256Cbc { iv: [0; 16] },
        }),
        encrypted_data: der::asn1::OctetStringRef::new(&[0; 64]).unwrap(),
    };
    let der = envelope.to_der().unwrap();
    let pem = pem::encode(&pem::Pem::new("ENCRYPTED PRIVATE KEY", der.clone()));
    let resources = xml_sec::policy::ResourcePolicy {
        max_key_import_kdf_work: 5,
        ..Default::default()
    };
    for (bytes, format) in [
        (der.as_slice(), key_material::PrivateKeyFormat::Pkcs8Der),
        (pem.as_bytes(), key_material::PrivateKeyFormat::Pkcs8Pem),
    ] {
        let mut budget = ExternalMaterialBudget::new(resources.max_external_resource_total_bytes);
        let import = |_: &mut ExternalMaterialBudget,
                      inventory: &mut KeyInventory,
                      remaining: &xml_sec::policy::ResourcePolicy| {
            key_material::decode_rsa_private_with_inventory(
                Path::new("key"),
                bytes,
                format,
                Some(b"wrong"),
                remaining,
                inventory,
            )
            .map_err(CommandError::from)
        };
        assert!(matches!(
            budget.with_key_import(&resources, import),
            Err(CommandError::Key(
                key_material::KeyMaterialError::ProtectedContainer
            ))
        ));
        assert_eq!(budget.kdf_work, 3);
        assert!(matches!(
            budget.with_key_import(&resources, import),
            Err(CommandError::Key(key_material::KeyMaterialError::Policy(_)))
        ));
        assert_eq!(budget.kdf_work, 3, "denial must precede the second KDF");
    }
}

#[test]
fn temporary_pkcs12_imports_keep_aggregate_work() {
    // Lax candidates use temporary inventories without resetting operation work.
    let bytes =
        include_bytes!("../../../../tests/fixtures/xmlenc/01-phaos-xmlenc-3/rsa-priv-key.p12");
    let resources = xml_sec::policy::ResourcePolicy {
        max_key_import_kdf_work: 10_000,
        ..Default::default()
    };
    let mut budget = ExternalMaterialBudget::new(resources.max_external_resource_total_bytes);
    let import = |_: &mut ExternalMaterialBudget,
                  inventory: &mut KeyInventory,
                  remaining: &xml_sec::policy::ResourcePolicy| {
        inventory
            .add_pkcs12("key".into(), bytes, "secret", remaining)
            .map_err(CommandError::from)
    };
    budget.with_key_import(&resources, import).unwrap();
    assert!(budget.kdf_work > 0);
    assert!(matches!(
        budget.with_key_import(&resources, import),
        Err(CommandError::KeyStore(key_manager::KeyStoreError::Policy(
            _
        )))
    ));
}

#[test]
fn key_store_import_includes_prior_external_material() {
    // Certificate buffers stay live while keys.xml and its decoded key coexist.
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("keys.xml");
    let xml = "<Keys xmlns=\"http://www.aleksey.com/xmlsec/2002\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:KeyInfo><ds:KeyName>a</ds:KeyName><ds:KeyValue><HMACKeyValue>AA==</HMACKeyValue></ds:KeyValue></ds:KeyInfo></Keys>";
    fs::write(&path, xml).unwrap();
    let invocation = invocation(&[
        "xmlsec1",
        "verify",
        "--keys-file",
        path.to_str().unwrap(),
        "input.xml",
    ]);
    let mut policy = xml_sec::policy::VerificationPolicy::default();
    policy.resources.max_external_resource_total_bytes = xml.len() + 100;
    let mut budget =
        ExternalMaterialBudget::new(policy.resources.max_external_resource_total_bytes);
    budget.charge(99).unwrap();
    assert!(matches!(
        load_xml_key_stores(&invocation, &policy, XmlBackend::default(), &mut budget),
        Err(CommandError::KeyStore(key_manager::KeyStoreError::Policy(
            _
        )))
    ));
    let mut exact = ExternalMaterialBudget::new(policy.resources.max_external_resource_total_bytes);
    exact.charge(97).unwrap();
    assert_eq!(
        load_xml_key_stores(&invocation, &policy, XmlBackend::default(), &mut exact)
            .unwrap()
            .entry_count(),
        1
    );
}

#[test]
fn repeated_key_files_share_candidate_and_parser_budgets() {
    // The third entry must fail the operation budget before its malformed
    // key is decoded; XML parser work must not reset between files either.
    let temp = tempfile::tempdir().expect("test directory");
    let first = temp.path().join("first.xml");
    let second = temp.path().join("second.xml");
    let entry = |name: &str, value: &str| {
        format!(
            "<ds:KeyInfo><ds:KeyName>{name}</ds:KeyName><ds:KeyValue><HMACKeyValue>{value}</HMACKeyValue></ds:KeyValue></ds:KeyInfo>"
        )
    };
    let store = |entries: String| {
        format!(
            "<Keys xmlns=\"http://www.aleksey.com/xmlsec/2002\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">{entries}</Keys>"
        )
    };
    let a = store(entry("a", "AA=="));
    fs::write(&first, &a).expect("first store");
    fs::write(&second, store(entry("b", "AA==") + &entry("c", "!"))).expect("second store");
    let invocation = invocation(&[
        "xmlsec1",
        "sign",
        "--keys-file",
        first.to_str().unwrap(),
        "--keys-file",
        second.to_str().unwrap(),
        "template.xml",
    ]);
    let mut policy = xml_sec::policy::VerificationPolicy::default();
    policy.resources.max_key_candidates = 2;
    let mut budget =
        ExternalMaterialBudget::new(policy.resources.max_external_resource_total_bytes);
    assert!(matches!(
        load_xml_key_stores(&invocation, &policy, XmlBackend::default(), &mut budget),
        Err(CommandError::KeyStore(key_manager::KeyStoreError::Policy(
            xml_sec::policy::PolicyViolation::ResourceLimitExceeded {
                resource: "key candidates",
                maximum: 2
            }
        )))
    ));
    fs::write(&second, store(entry("b", "AA=="))).expect("valid second store");
    let mut budget =
        ExternalMaterialBudget::new(policy.resources.max_external_resource_total_bytes);
    assert_eq!(
        load_xml_key_stores(&invocation, &policy, XmlBackend::default(), &mut budget)
            .expect("exact candidate boundary")
            .entry_count(),
        2
    );
    // Enough for either document individually, not both decoding/parsing passes.
    policy.resources.max_xml_parse_work_bytes = a.len() * 3;
    let mut budget =
        ExternalMaterialBudget::new(policy.resources.max_external_resource_total_bytes);
    assert!(matches!(
        load_xml_key_stores(&invocation, &policy, XmlBackend::default(), &mut budget),
        Err(CommandError::KeyStore(key_manager::KeyStoreError::Policy(
            xml_sec::policy::PolicyViolation::ResourceLimit {
                resource: "cumulative XML parse-work bytes",
                ..
            }
        )))
    ));
}

#[test]
fn explicit_pkcs8_signing_enforces_import_kdf_limits() {
    // Explicit PEM/DER options, including generic private-key aliases, must
    // reject KDF policy violations before password-dependent decryption.
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng as _};
    use xml_sec::rsa_encoding::RsaPrivateKeyEncoding as _;
    let rsa = rsa::RsaPrivateKey::from_pkcs8_pem(include_str!(
        "../../../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
    ))
    .unwrap();
    let plain = rsa.to_pkcs8_der().unwrap();
    let encrypted = pkcs8::PrivateKeyInfoRef::try_from(plain.as_bytes())
        .unwrap()
        .encrypt_with_rng(&mut ChaCha20Rng::seed_from_u64(42), b"correct")
        .unwrap();
    let pem = encrypted
        .to_pem("ENCRYPTED PRIVATE KEY", der::pem::LineEnding::LF)
        .unwrap();
    let temp = tempfile::tempdir().unwrap();
    for option_name in ["pkcs8-pem", "pkcs8-der", "privkey-pem", "privkey-der"] {
        let path = temp.path().join(option_name);
        fs::write(
            &path,
            if option_name.ends_with("pem") {
                pem.as_bytes()
            } else {
                encrypted.as_bytes()
            },
        )
        .unwrap();
        let parsed = Invocation::parse([
            OsString::from("xmlsec1"),
            OsString::from("sign"),
            OsString::from(format!("--{option_name}")),
            path.into_os_string(),
            OsString::from("template.xml"),
        ])
        .unwrap();
        for memory_limit in [false, true] {
            let mut policy = SigningPolicy::default();
            if memory_limit {
                policy.resources.max_key_import_kdf_memory_bytes = 1;
            } else {
                policy.resources.max_key_import_kdf_work = 1;
            }
            let mut budget =
                ExternalMaterialBudget::new(policy.resources.max_external_resource_total_bytes);
            let result = prepare_signing_key_candidate(
                parsed.values(option_name).next().unwrap(),
                SignatureAlgorithm::RsaSha256,
                &policy,
                Some(b"wrong"),
                &mut budget,
                default_provider(),
            );
            assert!(
                matches!(
                    result,
                    Err(CommandError::KeyStore(key_manager::KeyStoreError::Policy(
                        _
                    )))
                ),
                "{option_name}, memory limit {memory_limit}"
            );
        }
    }
}

#[test]
fn lax_key_search_stops_on_password_and_policy_failures() {
    // Candidate search may skip incompatible keys, never terminal
    // authentication or operation-wide policy failures.
    assert!(!lax_candidate_error_is_recoverable(&CommandError::Key(
        key_material::KeyMaterialError::ProtectedContainer,
    )));
    assert!(!lax_candidate_error_is_recoverable(&CommandError::Key(
        key_material::KeyMaterialError::PrivateKeyComponents(
            key_manager::KeyStoreError::Selection("RSA modulus exceeds safety limit"),
        ),
    )));
    assert!(!lax_candidate_error_is_recoverable(
        &CommandError::KeyStore(key_manager::KeyStoreError::Policy(
            xml_sec::policy::PolicyViolation::ResourceLimit {
                resource: "external resource bytes",
                maximum: 1,
                actual: 2,
            },
        ),)
    ));
    assert!(!lax_candidate_error_is_recoverable(&CommandError::Key(
        key_material::KeyMaterialError::Policy(xml_sec::policy::PolicyViolation::ResourceLimit {
            resource: "external resource bytes",
            maximum: 1,
            actual: 2,
        },),
    )));
}

#[test]
fn compatibility_signing_policy_includes_every_implemented_algorithm() {
    // An explicit allowlist replaces, rather than extends, secure defaults.
    // Keep the CLI compatibility boundary complete when algorithms evolve.
    let policy = xmlsec_compatibility_signing_policy(&invocation(&["xmlsec1", "sign"]));
    assert_eq!(
        policy.transforms.opc_relationship_edition,
        xml_sec::policy::OpcRelationshipEdition::Ecma2012
    );
    assert_eq!(
        policy.parameterized_rsa_pss,
        xml_sec::policy::RsaPssPermission::AllSupported
    );
    assert_eq!(
        policy.signature_algorithms,
        Some(HashSet::from([
            #[cfg(feature = "legacy-algorithms")]
            SignatureAlgorithm::RsaMd5,
            #[cfg(feature = "legacy-algorithms")]
            SignatureAlgorithm::RsaRipemd160,
            #[cfg(feature = "legacy-algorithms")]
            SignatureAlgorithm::HmacMd5,
            #[cfg(feature = "legacy-algorithms")]
            SignatureAlgorithm::HmacRipemd160,
            #[cfg(feature = "legacy-algorithms")]
            SignatureAlgorithm::EcdsaRipemd160,
            SignatureAlgorithm::DsaSha1,
            SignatureAlgorithm::DsaSha256,
            SignatureAlgorithm::HmacSha1,
            SignatureAlgorithm::HmacSha224,
            SignatureAlgorithm::HmacSha256,
            SignatureAlgorithm::HmacSha384,
            SignatureAlgorithm::HmacSha512,
            SignatureAlgorithm::RsaSha1,
            SignatureAlgorithm::RsaSha224,
            SignatureAlgorithm::RsaSha256,
            SignatureAlgorithm::RsaSha384,
            SignatureAlgorithm::RsaSha512,
            SignatureAlgorithm::RsaPssSha1,
            SignatureAlgorithm::RsaPssSha224,
            SignatureAlgorithm::RsaPssSha256,
            SignatureAlgorithm::RsaPssSha384,
            SignatureAlgorithm::RsaPssSha512,
            SignatureAlgorithm::RsaPssSha3_224,
            SignatureAlgorithm::RsaPssSha3_256,
            SignatureAlgorithm::RsaPssSha3_384,
            SignatureAlgorithm::RsaPssSha3_512,
            SignatureAlgorithm::RsaPss(xml_sec::xmldsig::RsaPssParameters::DEFAULT),
            SignatureAlgorithm::EcdsaSha1,
            SignatureAlgorithm::EcdsaSha224,
            SignatureAlgorithm::EcdsaSha256,
            SignatureAlgorithm::EcdsaSha384,
            SignatureAlgorithm::EcdsaSha512,
            SignatureAlgorithm::EcdsaSha3_224,
            SignatureAlgorithm::EcdsaSha3_256,
            SignatureAlgorithm::EcdsaSha3_384,
            SignatureAlgorithm::EcdsaSha3_512,
            SignatureAlgorithm::Ed25519,
            SignatureAlgorithm::Ed25519Ctx,
            SignatureAlgorithm::Ed25519Ph,
            SignatureAlgorithm::Ed448,
            SignatureAlgorithm::Ed448Ph,
            SignatureAlgorithm::PostQuantum(xml_sec::xmldsig::PqAlgorithm::MlDsa44),
            SignatureAlgorithm::PostQuantum(xml_sec::xmldsig::PqAlgorithm::MlDsa65),
            SignatureAlgorithm::PostQuantum(xml_sec::xmldsig::PqAlgorithm::MlDsa87),
            SignatureAlgorithm::PostQuantum(xml_sec::xmldsig::PqAlgorithm::SlhDsaSha2_128s),
            SignatureAlgorithm::PostQuantum(xml_sec::xmldsig::PqAlgorithm::SlhDsaSha2_128f),
            SignatureAlgorithm::PostQuantum(xml_sec::xmldsig::PqAlgorithm::SlhDsaSha2_192s),
            SignatureAlgorithm::PostQuantum(xml_sec::xmldsig::PqAlgorithm::SlhDsaSha2_192f),
            SignatureAlgorithm::PostQuantum(xml_sec::xmldsig::PqAlgorithm::SlhDsaSha2_256s),
            SignatureAlgorithm::PostQuantum(xml_sec::xmldsig::PqAlgorithm::SlhDsaSha2_256f),
        ]))
    );
    assert_eq!(
        policy.digest_algorithms,
        Some(HashSet::from([
            #[cfg(feature = "legacy-algorithms")]
            DigestAlgorithm::Md5,
            #[cfg(feature = "legacy-algorithms")]
            DigestAlgorithm::Ripemd160,
            DigestAlgorithm::Sha1,
            DigestAlgorithm::Sha224,
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
            DigestAlgorithm::Sha3_224,
            DigestAlgorithm::Sha3_256,
            DigestAlgorithm::Sha3_384,
            DigestAlgorithm::Sha3_512,
        ]))
    );
    assert_eq!(policy.dsa_keys.minimum_modulus_bits, 1024);
}

fn testdata(name: &str) -> PathBuf {
    project_root().join("tools/xmlsec1/testdata").join(name)
}

#[test]
fn named_store_encryption_falls_back_only_when_lax() {
    // An absent named key may fall back in lax mode, but an exact match wins.
    let names = ["fallback", "exact"];
    let requested = vec!["exact".to_string()];
    assert_eq!(
        select_store_candidates(names.iter(), &requested, true, 2, |name| name).unwrap()[0],
        &"exact"
    );
    let absent = vec!["absent".to_string()];
    assert!(select_store_candidates(names.iter(), &absent, false, 2, |name| name).is_err());
    assert_eq!(
        select_store_candidates(names.iter(), &absent, true, 2, |name| name).unwrap()[0],
        &"fallback"
    );
}

#[cfg(feature = "legacy-algorithms")]
#[test]
fn direct_candidates_do_not_cross_aes_and_triple_des_families() {
    // Equal 24-byte lengths must not turn an AES key into a TDEA key.
    let resolver = CandidateSymmetricKeyDecryptor {
        keys: vec![SymmetricCandidate {
            kind: key_manager::SymmetricKeyKind::Aes,
            bytes: Cow::Borrowed(&[1; 24]),
            name: None,
        }],
        lax_key_search: false,
        content_key_name: None,
        wrapping_only: false,
    };
    assert!(matches!(
        resolver.resolve_key(
            &xml_sec::provider::RustCryptoProvider,
            DataEncryptionAlgorithm::TripleDesCbc,
            None
        ),
        Err(XmlEncError::KeyNotFound)
    ));
    assert!(
        resolver
            .resolve_key(
                &xml_sec::provider::RustCryptoProvider,
                DataEncryptionAlgorithm::Aes192Cbc,
                None
            )
            .is_ok()
    );
}

#[cfg(feature = "legacy-algorithms")]
#[test]
fn cli_optional_content_round_trips_and_rejects_wrong_key_type() {
    // Exercise the actual command boundary, including named key selection
    // and explicit compatibility policy; equal AES/TDEA widths cannot alias.
    let directory = tempfile::tempdir().expect("temporary CLI files");
    let template = directory.path().join("template.xml");
    let input = directory.path().join("input.bin");
    let key = directory.path().join("key.bin");
    let encrypted = directory.path().join("encrypted.xml");
    fs::write(&input, b"legacy CLI plaintext").expect("plaintext file");
    fs::write(&key, [0x31; 24]).expect("key file");
    for algorithm in [
        DataEncryptionAlgorithm::TripleDesCbc,
        DataEncryptionAlgorithm::Aes192Cbc,
        DataEncryptionAlgorithm::Aes192Gcm,
    ] {
        fs::write(&template, format!("<EncryptedData xmlns=\"http://www.w3.org/2001/04/xmlenc#\"><EncryptionMethod Algorithm=\"{}\"/><CipherData><CipherValue/></CipherData></EncryptedData>", algorithm.uri())).expect("template file");
        let option = if algorithm == DataEncryptionAlgorithm::TripleDesCbc {
            "--deskey"
        } else {
            "--aeskey"
        };
        let args = [
            "xmlsec1",
            "encrypt",
            option,
            key.to_str().unwrap(),
            "--binary-data",
            input.to_str().unwrap(),
            template.to_str().unwrap(),
        ];
        let mut output = Vec::new();
        execute(&invocation(&args), &mut output, &mut Vec::new()).expect("CLI encryption");
        fs::write(&encrypted, output).expect("encrypted file");
        let args = [
            "xmlsec1",
            "decrypt",
            option,
            key.to_str().unwrap(),
            encrypted.to_str().unwrap(),
        ];
        let mut plaintext = Vec::new();
        execute(&invocation(&args), &mut plaintext, &mut Vec::new()).expect("CLI decryption");
        assert_eq!(plaintext, b"legacy CLI plaintext");
        let wrong_option = if option == "--deskey" {
            "--aeskey"
        } else {
            "--deskey"
        };
        let args = [
            "xmlsec1",
            "decrypt",
            wrong_option,
            key.to_str().unwrap(),
            encrypted.to_str().unwrap(),
        ];
        assert!(execute(&invocation(&args), &mut Vec::new(), &mut Vec::new()).is_err());
    }
}

#[cfg(feature = "legacy-algorithms")]
#[test]
fn cli_rsa15_template_selects_parameterless_transport() {
    // Test command wiring, not just the library builder: a template's
    // RSA-1.5 method must survive staging without acquiring OAEP children.
    let directory = tempfile::tempdir().expect("CLI files");
    let template = directory.path().join("template.xml");
    let input = directory.path().join("input.bin");
    let encrypted = directory.path().join("encrypted.xml");
    fs::write(&input, b"RSA15 CLI plaintext").expect("plaintext");
    fs::write(&template, "<EncryptedData xmlns=\"http://www.w3.org/2001/04/xmlenc#\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"/><ds:KeyInfo><EncryptedKey><EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-1_5\"/><CipherData><CipherValue/></CipherData></EncryptedKey></ds:KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>").expect("template");
    let root = project_root();
    let public = root.join("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    let private = root.join("tests/fixtures/keys/rsa/rsa-2048-key.pem");
    let args = [
        "xmlsec1",
        "encrypt",
        "--pubkey-pem",
        public.to_str().unwrap(),
        "--binary-data",
        input.to_str().unwrap(),
        template.to_str().unwrap(),
    ];
    let mut output = Vec::new();
    execute(&invocation(&args), &mut output, &mut Vec::new()).expect("CLI RSA-1.5 encrypt");
    assert!(!String::from_utf8_lossy(&output).contains("OAEPparams"));
    assert!(!String::from_utf8_lossy(&output).contains("DigestMethod"));
    fs::write(&encrypted, output).expect("ciphertext");
    let args = [
        "xmlsec1",
        "decrypt",
        "--privkey-pem",
        private.to_str().unwrap(),
        encrypted.to_str().unwrap(),
    ];
    let mut output = Vec::new();
    execute(&invocation(&args), &mut output, &mut Vec::new()).expect("CLI RSA-1.5 decrypt");
    assert_eq!(output, b"RSA15 CLI plaintext");
}

#[test]
fn store_selection_bounds_inspected_candidates() {
    // A name filter cannot make scanning an oversized candidate pool free.
    let names = ["first", "second"];
    let requested = vec!["second".to_owned()];
    assert!(matches!(
        select_store_candidates(names.iter(), &requested, false, 1, |name| name),
        Err(CommandError::KeyStore(key_manager::KeyStoreError::Policy(
            xml_sec::policy::PolicyViolation::ResourceLimit {
                resource: "key candidates",
                maximum: 1,
                actual: 2,
            }
        )))
    ));
    assert_eq!(
        select_store_candidates(names.iter(), &requested, false, 2, |name| name).unwrap(),
        vec![&"second"]
    );
}

#[test]
fn cli_lax_store_encryption_accepts_missing_template_key_name() {
    // Exercise the command boundary: a present but unknown KeyName must
    // fall back only when --lax-key-search was explicitly requested.
    let temp = tempfile::tempdir().expect("temporary test directory");
    let template_path = temp.path().join("template.xml");
    let input_path = temp.path().join("input.bin");
    let fixture =
        project_root().join("tests/fixtures/xmlenc/aleksey-xmlenc-01/enc-aes128gcm-keyname.tmpl");
    let template = fs::read_to_string(fixture)
        .expect("encryption template fixture")
        .replace("test-aes128", "absent");
    fs::write(&template_path, template).expect("write encryption template");
    fs::write(&input_path, b"lax fallback payload").expect("write plaintext");
    let store = project_root().join("tests/fixtures/keys/xmlsec/mixed-keys.xml");
    let args = [
        "xmlsec1",
        "encrypt",
        "--keys-file",
        store.to_str().expect("fixture path is UTF-8"),
        "--binary-data",
        input_path.to_str().expect("input path is UTF-8"),
        template_path.to_str().expect("template path is UTF-8"),
    ];
    assert!(execute(&invocation(&args), &mut Vec::new(), &mut Vec::new()).is_err());
    let mut lax_args = vec!["xmlsec1", "encrypt", "--lax-key-search"];
    lax_args.extend_from_slice(&args[2..]);
    let mut output = Vec::new();
    execute(&invocation(&lax_args), &mut output, &mut Vec::new())
        .expect("lax store encryption finds alternate AES key");
    assert!(String::from_utf8_lossy(&output).contains("CipherValue"));
}

#[test]
fn cli_lax_store_encryption_skips_ineligible_aes_key() {
    // A fallback candidate with the wrong AES length must not hide a later usable key.
    let temp = tempfile::tempdir().expect("temporary test directory");
    let template_path = temp.path().join("template.xml");
    let input_path = temp.path().join("input.bin");
    let store_path = temp.path().join("keys.xml");
    let fixture =
        project_root().join("tests/fixtures/xmlenc/aleksey-xmlenc-01/enc-aes128gcm-keyname.tmpl");
    let template = fs::read_to_string(fixture)
        .expect("encryption template fixture")
        .replace("test-aes128", "absent");
    fs::write(&template_path, template).expect("write encryption template");
    fs::write(&input_path, b"lax fallback payload").expect("write plaintext");
    let source =
        fs::read_to_string(project_root().join("tests/fixtures/keys/xmlsec/mixed-keys.xml"))
            .expect("key store fixture");
    let extra = "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><KeyName>wrong-aes192</KeyName><KeyValue><AESKeyValue xmlns=\"http://www.aleksey.com/xmlsec/2002\">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</AESKeyValue></KeyValue></KeyInfo>";
    fs::write(
        &store_path,
        source.replacen("<KeyInfo", &format!("{extra}<KeyInfo"), 1),
    )
    .expect("write key store");
    let args = [
        "xmlsec1",
        "encrypt",
        "--lax-key-search",
        "--keys-file",
        store_path.to_str().expect("store path is UTF-8"),
        "--binary-data",
        input_path.to_str().expect("input path is UTF-8"),
        template_path.to_str().expect("template path is UTF-8"),
    ];
    let mut output = Vec::new();
    execute(&invocation(&args), &mut output, &mut Vec::new())
        .expect("lax search skips AES-192 before AES-128");
    assert!(String::from_utf8_lossy(&output).contains("CipherValue"));
}

#[test]
fn cli_lax_store_encryption_preserves_policy_denial() {
    // Policy denials are terminal even when a later key is eligible.
    // A compliant-only inventory must still complete the round-trip.
    let temp = tempfile::tempdir().expect("temporary test directory");
    let template_path = temp.path().join("template.xml");
    let input_path = temp.path().join("input.bin");
    let store_path = temp.path().join("keys.xml");
    let fixture = project_root().join(
        "tests/fixtures/xmlenc/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha1_mgf1_sha512.tmpl",
    );
    let template = fs::read_to_string(fixture)
        .expect("encryption template fixture")
        .replace("TestKeyName-rsa-4096", "absent");
    fs::write(&template_path, template).expect("write encryption template");
    fs::write(&input_path, b"<root>lax RSA fallback payload</root>").expect("write plaintext");
    let pem =
        fs::read_to_string(project_root().join("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"))
            .expect("public key fixture");
    let public_key = RsaPublicKey::from_public_key_pem(&pem).expect("RSA public key");
    let encode = |bytes: Vec<u8>| base64::engine::general_purpose::STANDARD.encode(bytes);
    let extra = format!(
        "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><KeyName>valid-rsa</KeyName><KeyValue><RSAKeyValue><Modulus>{}</Modulus><Exponent>{}</Exponent></RSAKeyValue></KeyValue></KeyInfo>",
        encode(public_key.n().to_be_bytes_trimmed_vartime().into_vec()),
        encode(public_key.e().to_be_bytes_trimmed_vartime().into_vec())
    );
    let source =
        fs::read_to_string(project_root().join("tests/fixtures/keys/xmlsec/mixed-keys.xml"))
            .expect("key store fixture");
    fs::write(
        &store_path,
        source.replacen("</Keys>", &format!("{extra}</Keys>"), 1),
    )
    .expect("write key store");
    let args = [
        "xmlsec1",
        "encrypt",
        "--lax-key-search",
        "--keys-file",
        store_path.to_str().expect("store path is UTF-8"),
        "--xml-data",
        input_path.to_str().expect("input path is UTF-8"),
        template_path.to_str().expect("template path is UTF-8"),
    ];
    let mut output = Vec::new();
    assert!(matches!(
        execute(&invocation(&args), &mut output, &mut Vec::new()),
        Err(CommandError::KeyStore(key_manager::KeyStoreError::Policy(
            xml_sec::policy::PolicyViolation::KeySize {
                operation: "encryption",
                key_type: "RSA",
                minimum_bits: 2048,
                maximum_bits: 8192,
                actual_bits: 1024,
            }
        )))
    ));
    assert_eq!(output, b"");
    fs::write(
        &store_path,
        format!("<Keys xmlns=\"http://www.aleksey.com/xmlsec/2002\">{extra}</Keys>"),
    )
    .expect("compliant-only store");
    execute(&invocation(&args), &mut output, &mut Vec::new())
        .expect("lax search selects the compliant RSA key");
    assert!(String::from_utf8_lossy(&output).contains("CipherValue"));
    let encrypted = temp.path().join("encrypted.xml");
    fs::write(&encrypted, &output).expect("write encrypted output");
    let private = project_root().join("tests/fixtures/keys/rsa/rsa-2048-key.pem");
    let decrypt_args = [
        "xmlsec1",
        "decrypt",
        "--privkey-pem:valid-rsa",
        private.to_str().expect("key path is UTF-8"),
        encrypted.to_str().expect("encrypted path is UTF-8"),
    ];
    let mut decrypted = Vec::new();
    execute(&invocation(&decrypt_args), &mut decrypted, &mut Vec::new())
        .expect("strict decryption uses the fallback recipient name");
    // Content encryption keeps the data root, so decryption restores the data document.
    assert_eq!(decrypted, b"<root>lax RSA fallback payload</root>");
}

#[test]
fn store_signing_retries_key_info_mismatch_in_lax_mode() {
    // An algorithm-compatible key is not a valid match for embedded KeyInfo.
    let mut inventory = KeyInventory::default();
    let policy = SigningPolicy::default();
    let wrong =
        std::fs::read(project_root().join("tests/fixtures/keys/rsa/rsa-2048-key.pem")).unwrap();
    let right =
        std::fs::read(project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem")).unwrap();
    for (name, pem) in [("wrong", wrong), ("right", right)] {
        inventory
            .add_private_pem(
                name.into(),
                &pem,
                None,
                key_manager::KeyUsages::SIGN,
                &policy.resources,
            )
            .unwrap();
    }
    let right_spki = inventory
        .signing_key("right", SignatureAlgorithm::RsaSha256, &policy)
        .unwrap()
        .public_key_info()
        .unwrap()
        .spki_der()
        .unwrap()
        .to_vec();
    let mut info = KeyInfo::default();
    info.sources
        .push(KeyInfoSource::DerEncodedKeyValue(right_spki));
    assert!(
        select_store_signing_key(
            &inventory,
            ["wrong"],
            SignatureAlgorithm::RsaSha256,
            Some(&info),
            &policy,
            false,
            default_provider(),
        )
        .is_err()
    );
    assert!(
        select_store_signing_key(
            &inventory,
            ["wrong", "right"],
            SignatureAlgorithm::RsaSha256,
            Some(&info),
            &policy,
            true,
            default_provider(),
        )
        .is_ok()
    );
}

#[test]
fn lax_store_signing_shares_lookup_budget_across_retries() {
    // Three independent scans cost 1 + 2 + 3 inspections, not three.
    let mut inventory = KeyInventory::default();
    let mut policy = SigningPolicy::default();
    let wrong = fs::read(project_root().join("tests/fixtures/keys/rsa/rsa-2048-key.pem")).unwrap();
    let right = fs::read(project_root().join("tests/fixtures/keys/rsa/rsa-4096-key.pem")).unwrap();
    for (name, pem) in [("wrong-a", &wrong), ("wrong-b", &wrong), ("right", &right)] {
        inventory
            .add_private_pem(
                name.into(),
                pem,
                None,
                key_manager::KeyUsages::SIGN,
                &policy.resources,
            )
            .unwrap();
    }
    let right_spki = inventory
        .signing_key("right", SignatureAlgorithm::RsaSha256, &policy)
        .unwrap()
        .public_key_info()
        .unwrap()
        .spki_der()
        .unwrap()
        .to_vec();
    let mut info = KeyInfo::default();
    info.sources
        .push(KeyInfoSource::DerEncodedKeyValue(right_spki));
    policy.resources.max_key_candidates = 3;
    assert!(
        select_store_signing_key(
            &inventory,
            ["wrong-a", "wrong-b", "right"],
            SignatureAlgorithm::RsaSha256,
            Some(&info),
            &policy,
            true,
            default_provider(),
        )
        .is_err()
    );
}

#[test]
fn strict_store_signing_requires_template_key_name() {
    // A singleton store must not silently authorize an unnamed template.
    let temp = tempfile::tempdir().expect("temporary signing template");
    let template = temp.path().join("unsigned.xml");
    fs::write(
        &template,
        br#"<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"/><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue/></Reference></SignedInfo><SignatureValue/></Signature>"#,
    )
    .expect("write template");
    let template = template.to_str().expect("UTF-8 path");
    let store = temp.path().join("keys.xml");
    fs::write(
        &store,
        br#"<Keys xmlns="http://www.aleksey.com/xmlsec/2002"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><KeyName>only-key</KeyName><KeyValue><HMACKeyValue xmlns="http://www.aleksey.com/xmlsec/2002">c2VjcmV0</HMACKeyValue></KeyValue></KeyInfo></Keys>"#,
    )
    .expect("write singleton store");
    let store = store.to_str().expect("UTF-8 path");
    let strict = invocation(&["xmlsec1", "sign", "--keys-file", store, template]);
    let error = sign(&strict, &mut Vec::new()).expect_err("strict mode requires KeyName");
    assert!(
        error.to_string().contains("requires a template KeyName"),
        "{error}"
    );
    let lax = invocation(&[
        "xmlsec1",
        "sign",
        "--lax-key-search",
        "--keys-file",
        store,
        template,
    ]);
    let mut signed = Vec::new();
    sign(&lax, &mut signed).expect("lax mode may select the unnamed singleton");
    assert!(String::from_utf8_lossy(&signed).contains("DigestValue"));
}

#[test]
fn pkcs12_signing_ignores_unrelated_ca_certificate() {
    // A CA-only bundle still provides its private signing key, without a leaf writer.
    let bundle = base64::engine::general_purpose::STANDARD
        .decode(
            include_str!("../../../../tests/fixtures/keys/pkcs12/rsa-key-unrelated-ca.p12.b64")
                .trim(),
        )
        .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("key.p12");
    fs::write(&path, bundle).unwrap();
    let parsed = Invocation::parse([
        OsString::from("xmlsec1"),
        OsString::from("sign"),
        OsString::from("--pkcs12"),
        path.into_os_string(),
        OsString::from("template.xml"),
    ])
    .unwrap();
    let option = parsed.values("pkcs12").next().unwrap();
    let mut budget = ExternalMaterialBudget::new(usize::MAX);
    let candidate = prepare_signing_key_candidate(
        option,
        SignatureAlgorithm::RsaSha256,
        &SigningPolicy::default(),
        Some(b"secret"),
        &mut budget,
        default_provider(),
    )
    .unwrap();
    assert!(candidate.certificate_writer.is_none());
    assert!(candidate.leaf_certificate_der.is_none());
}

struct CountingVerificationKey {
    accepts: bool,
    calls: Rc<Cell<usize>>,
}

impl VerifyingKey for CountingVerificationKey {
    fn verify(
        &self,
        _algorithm: SignatureAlgorithm,
        _signed_data: &[u8],
        _signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        self.calls.set(self.calls.get() + 1);
        Ok(self.accepts)
    }
}

struct FailingVerificationKey {
    reason: &'static str,
}

impl VerifyingKey for FailingVerificationKey {
    fn verify(
        &self,
        _algorithm: SignatureAlgorithm,
        _signed_data: &[u8],
        _signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        Err(DsigError::InvalidStructure {
            reason: self.reason,
        })
    }
}

#[test]
fn candidate_verifier_preserves_mismatch_and_error_precedence() {
    // A definitive cryptographic mismatch outranks provider errors, while
    // an all-error candidate set reports the final attempted provider.
    let mismatch_then_error = CandidateVerifyingKey {
        candidates: vec![
            Box::new(CountingVerificationKey {
                accepts: false,
                calls: Rc::new(Cell::new(0)),
            }),
            Box::new(FailingVerificationKey { reason: "last" }),
        ],
    };
    assert!(matches!(
        mismatch_then_error.verify(SignatureAlgorithm::RsaSha256, b"data", b"signature"),
        Ok(false)
    ));

    let errors = CandidateVerifyingKey {
        candidates: vec![
            Box::new(FailingVerificationKey { reason: "first" }),
            Box::new(FailingVerificationKey { reason: "last" }),
        ],
    };
    assert!(matches!(
        errors.verify(SignatureAlgorithm::RsaSha256, b"data", b"signature"),
        Err(DsigError::InvalidStructure { reason: "last" })
    ));
}

#[test]
fn candidate_verifier_retries_only_the_signature_primitive() {
    // The outer VerifyContext sees one verifier, so XML parsing, Reference
    // transforms and SignedInfo C14N are not repeated per candidate.
    let first_calls = Rc::new(Cell::new(0));
    let second_calls = Rc::new(Cell::new(0));
    let candidates = CandidateVerifyingKey {
        candidates: vec![
            Box::new(CountingVerificationKey {
                accepts: false,
                calls: Rc::clone(&first_calls),
            }),
            Box::new(CountingVerificationKey {
                accepts: true,
                calls: Rc::clone(&second_calls),
            }),
        ],
    };
    let xml = fs::read_to_string(testdata("enveloping-sha256-rsa-sha256.xml")).unwrap();

    let result = VerifyContext::new()
        .key(&candidates)
        .first_document_signature()
        .verify(&xml)
        .unwrap();
    assert_eq!(result.status, DsigStatus::Valid);
    assert_eq!(first_calls.get(), 1);
    assert_eq!(second_calls.get(), 1);
}

#[test]
fn stored_verification_sources_share_candidate_budget() {
    // Lax search must not reset source-inspection work per imported entry,
    // or swallow the denial because an earlier candidate resolved.
    let mut info = KeyInfo::default();
    info.sources = vec![
        KeyInfoSource::KeyName("first".into()),
        KeyInfoSource::KeyValue(KeyValueInfo::Unsupported {
            namespace: None,
            local_name: "unsupported".into(),
        }),
    ];
    let mut inventory = KeyInventory::default();
    inventory
        .add_public_pem(
            "valid".into(),
            include_bytes!("../../../../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"),
            &ResourcePolicy::default(),
        )
        .unwrap();
    let valid = inventory.public_keys()[0].key_info.clone();
    for info in [info, valid] {
        let resolver = CandidateVerificationResolver::new(
            vec![
                ExplicitVerificationCandidate::Certificate(info.clone()),
                ExplicitVerificationCandidate::Certificate(info),
            ],
            ConfiguredCertificates::default(),
            true,
            false,
        );
        let mut policy = VerificationPolicy::default();
        policy.resources.max_key_candidates = 3;
        assert!(matches!(resolver.resolve_with_policy_and_provider(None,
        SignatureAlgorithm::RsaSha256, &policy, default_provider()),
        Err(DsigError::Policy(xml_sec::policy::PolicyViolation::ResourceLimit {
            resource, maximum: 3, ..
        })) if resource == "key candidates"));
        policy.resources.max_key_candidates = 4;
        assert!(
            resolver
                .resolve_with_policy_and_provider(
                    None,
                    SignatureAlgorithm::RsaSha256,
                    &policy,
                    default_provider()
                )
                .is_ok()
        );
    }
}

#[test]
fn verification_candidate_collection_obeys_trust_budget() {
    // Lax lookup must not turn caller-provided key files into unbounded
    // public-key verification attempts.
    let candidate = VerificationKey {
        algorithm: SignatureAlgorithm::RsaSha256,
        public_key_bytes: Vec::new(),
        certificate_der: None,
        name: None,
    };
    let mut policy = VerificationPolicy::default();
    policy.key_trust.max_x509_candidate_paths = 1;
    let resolver = CandidateVerificationResolver::new(
        vec![
            ExplicitVerificationCandidate::Direct(candidate.clone()),
            ExplicitVerificationCandidate::Direct(candidate),
        ],
        ConfiguredCertificates::default(),
        true,
        false,
    );

    let Err(error) = resolver.resolve_with_policy_and_provider(
        None,
        SignatureAlgorithm::RsaSha256,
        &policy,
        default_provider(),
    ) else {
        panic!("candidate count above policy must fail closed");
    };
    assert!(matches!(
        error,
        DsigError::Policy(xml_sec::policy::PolicyViolation::ResourceLimit {
            resource: "verification key candidates",
            maximum: 1,
            actual: 2,
        })
    ));
}

#[test]
fn raw_recipient_key_is_charged_before_decode() {
    // Raw keys and certificates share one invocation budget; bytes must be
    // charged before an asymmetric format decoder receives them.
    let path = testdata("rsa-2048-cert.pem");
    let mut budget = ExternalMaterialBudget::new(1);
    let error = load_rsa_recipient_candidate(
        path.as_os_str(),
        RecipientPublicKeySource::Public(key_material::PublicKeyEncoding::Pem),
        &EncryptionPolicy::default(),
        &mut budget,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        CommandError::ExternalMaterialTooLarge { maximum: 1 }
    ));
}

#[test]
fn certificate_recipient_key_is_charged_before_decode() {
    // Aggregate source accounting must reject certificate bytes before PEM
    // or X.509 parsing, just as it does for raw public-key candidates.
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("malformed.pem");
    fs::write(&path, b"xx").unwrap();
    let mut budget = ExternalMaterialBudget::new(1);

    let error = load_rsa_recipient_candidate(
        path.as_os_str(),
        RecipientPublicKeySource::Certificate(key_material::CertificateEncoding::Pem),
        &EncryptionPolicy::default(),
        &mut budget,
    )
    .unwrap_err();

    assert!(matches!(
        error,
        CommandError::ExternalMaterialTooLarge { maximum: 1 }
    ));
}

#[test]
fn capability_checks_reject_unknown_names() {
    let mut output = Vec::new();
    assert!(
        execute(
            &invocation(&["xmlsec1", "check-transforms", "c14n", "rsa-sha256"]),
            &mut output,
            &mut Vec::new()
        )
        .is_ok()
    );
    assert!(matches!(
        execute(
            &invocation(&["xmlsec1", "check-transforms", "unknown-transform"]),
            &mut output,
            &mut Vec::new()
        ),
        Err(CommandError::CapabilityUnavailable)
    ));
    assert_eq!(
        execute(
            &invocation(&["xmlsec1", "check-transforms", "xslt"]),
            &mut output,
            &mut Vec::new()
        )
        .is_ok(),
        cfg!(feature = "xslt")
    );
}

#[test]
fn unsupported_provider_never_falls_back() {
    let error = execute(
        &invocation(&["xmlsec1", "version", "--crypto", "openssl"]),
        &mut Vec::new(),
        &mut Vec::new(),
    )
    .unwrap_err();
    assert!(matches!(error, CommandError::UnsupportedProvider(_)));
}

#[test]
fn xml_backend_selector_is_strict_and_build_aware() {
    // Runtime selection must neither accept unknown names nor fall back
    // when a thin binary does not contain the requested implementation.
    let invalid = invocation(&["xmlsec1", "verify", "--xml-backend", "libxml2", "input.xml"]);
    assert!(matches!(
        selected_xml_backend(&invalid),
        Err(CommandError::UnsupportedXmlBackend(name)) if name == "libxml2"
    ));

    for (name, backend) in [
        ("xmloxide", XmlBackend::Xmloxide),
        ("roxmltree", XmlBackend::Roxmltree),
        ("differential", XmlBackend::Differential),
    ] {
        let invocation = invocation(&["xmlsec1", "verify", "--xml-backend", name, "input.xml"]);
        let selected = selected_xml_backend(&invocation);
        if backend.is_available() {
            assert_eq!(selected.unwrap(), backend);
        } else {
            assert!(matches!(
                selected,
                Err(CommandError::UnavailableXmlBackend(rejected)) if rejected == name
            ));
        }
    }
}

#[test]
fn command_help_is_an_action_and_semantic_no_ops_fail_closed() {
    let mut output = Vec::new();
    execute(
        &invocation(&["xmlsec1", "verify", "--help"]),
        &mut output,
        &mut Vec::new(),
    )
    .unwrap();
    let help = String::from_utf8(output).unwrap();
    assert!(help.starts_with("Usage: xmlsec1 verify"));
    assert!(help.contains("--pubkey-cert-pem"));
    assert!(!help.contains("--binary-data"));

    let mut command = Vec::new();
    execute(
        &invocation(&["xmlsec1", "help-encrypt"]),
        &mut command,
        &mut Vec::new(),
    )
    .unwrap();
    let command = String::from_utf8(command).unwrap();
    assert!(command.contains("Usage: xmlsec1 encrypt"));
    assert!(command.contains("--binary-data"));
    assert!(!command.contains("Usage: xmlsec1 decrypt"));

    let error = execute(
        &invocation(&["xmlsec1", "verify", "--lax-key-search", "input.xml"]),
        &mut Vec::new(),
        &mut Vec::new(),
    )
    .unwrap_err();
    assert!(matches!(error, CommandError::UnsupportedOption(_)));
}

#[test]
fn compatibility_verification_uses_libxmlsec_here_semantics() {
    // The CLI compatibility boundary must verify the same node set as the
    // donor when an XPath transform uses its non-standard here() binding.
    let policy =
        xmlsec_compatibility_verification_policy(&invocation(&["xmlsec1", "verify", "input.xml"]));
    // Every tuple is authorized by the profile before any XML is parsed.
    for salt_len in [0, 17, 32, 64] {
        let method = SignatureAlgorithm::RsaPss(xml_sec::xmldsig::RsaPssParameters {
            digest: DigestAlgorithm::Sha256,
            mgf_digest: DigestAlgorithm::Sha1,
            salt_len,
        });
        assert!(policy.check_signature_algorithm(method).is_ok());
        assert!(
            !policy
                .key_trust
                .allowed_legacy_signature_algorithms
                .contains(&method)
        );
    }
    assert_eq!(
        policy.transforms.xpath_here_semantics,
        xml_sec::xmldsig::XPathHereSemantics::XmlSecLegacy
    );
    assert_eq!(
        policy.transforms.opc_relationship_edition,
        xml_sec::policy::OpcRelationshipEdition::Ecma2012
    );
    assert_eq!(policy.key_trust.dsa_keys.minimum_modulus_bits, 1024);
    assert_eq!(policy.hmac.minimum_key_bits, 40);
    assert_eq!(policy.uris.key_info_references, UriTypeSet::SAME_DOCUMENT);
}

#[test]
fn openssl_compatibility_strict_check_flag_does_not_weaken_trust_policy() {
    // The pinned donor uses OpenSSL, where this backend-specific flag is a
    // no-op; accepting it must not disable Rust certificate/path checks.
    let baseline =
        xmlsec_compatibility_verification_policy(&invocation(&["xmlsec1", "verify", "input.xml"]));
    let skipped = xmlsec_compatibility_verification_policy(&invocation(&[
        "xmlsec1",
        "verify",
        "--X509-skip-strict-checks",
        "input.xml",
    ]));

    assert_eq!(skipped.key_trust, baseline.key_trust);
    assert_eq!(skipped.signature_algorithms, baseline.signature_algorithms);
    assert_eq!(skipped.digest_algorithms, baseline.digest_algorithms);
    assert_eq!(skipped.transforms, baseline.transforms);
}

#[test]
fn help_all_enumerates_the_registered_surface() {
    let mut output = Vec::new();
    execute(
        &invocation(&["xmlsec1", "help-all"]),
        &mut output,
        &mut Vec::new(),
    )
    .unwrap();
    let help = String::from_utf8(output).unwrap();
    for command in Command::ALL {
        assert!(
            help.contains(command.canonical_name()),
            "missing command {}",
            command.canonical_name()
        );
        if command_contract(*command).is_some() {
            let mut command_output = Vec::new();
            command_help(*command, &mut command_output).unwrap();
            assert!(
                String::from_utf8(command_output)
                    .unwrap()
                    .starts_with(&format!("Usage: xmlsec1 {}", command.canonical_name()))
            );
        }
    }
    assert!(!help.contains("sign-tmpl"));
    for option in OPTION_SPECS {
        assert!(
            help.contains(&format!("--{}", option.canonical)),
            "missing option --{}",
            option.canonical
        );
    }
    assert!(help.contains("--gen-key[:name] <value>"));
    assert!(help.contains("--insecure\n"));
}

#[test]
fn injected_key_info_carries_alternate_prefix_bindings() {
    // Extracting a subtree must preserve namespace bindings inherited from
    // the generated EncryptedData root, regardless of the chosen prefixes.
    let template = format!(
        "<e:EncryptedData xmlns:e=\"{XMLENC_NS}\"><e:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"/><e:CipherData><e:CipherValue/></e:CipherData></e:EncryptedData>"
    );
    let generated = format!(
        "<e:EncryptedData xmlns:e=\"{XMLENC_NS}\" xmlns:s=\"{XMLDSIG_NS}\" xmlns:n=\"http://www.w3.org/2009/xmlenc11#\"><e:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"/><s:KeyInfo><e:EncryptedKey><e:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#rsa-oaep\"><n:MGF Algorithm=\"http://www.w3.org/2009/xmlenc11#mgf1sha256\"/></e:EncryptionMethod><e:CipherData><e:CipherValue>a2V5</e:CipherValue></e:CipherData></e:EncryptedKey></s:KeyInfo><e:CipherData><e:CipherValue>ZGF0YQ==</e:CipherValue></e:CipherData></e:EncryptedData>"
    );

    let rendered = apply_encryption_template(
        &template,
        &generated,
        None,
        &[],
        &EncryptionPolicy::default(),
        XmlBackend::default(),
    )
    .unwrap();
    let document =
        Document::parse(&rendered).expect("injected KeyInfo prefixes must remain namespace-bound");
    assert!(
        document
            .descendants()
            .any(|node| node.has_tag_name((XMLDSIG_NS, "KeyInfo")))
    );
    assert!(
        document
            .descendants()
            .any(|node| node.has_tag_name(("http://www.w3.org/2009/xmlenc11#", "MGF")))
    );
}

#[cfg(feature = "experimental-pq")]
fn kem_template(mechanism_info: &str, outer_info: &str, sibling: &str) -> String {
    format!(
        "<root xmlns:x=\"{XMLENC_NS}\" xmlns:d=\"{XMLDSIG_NS}\" xmlns:i=\"http://www.w3.org/2009/xmldsig11#\" xmlns:k=\"{}\"><x:EncryptedData Id=\"data\"><x:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"/><d:KeyInfo>{outer_info}</d:KeyInfo><x:CipherData><x:CipherValue/></x:CipherData></x:EncryptedData><d:KeyInfo Id=\"mechanism\"><k:EncapsulationMechanism Algorithm=\"{}\"><d:KeyInfo>{mechanism_info}</d:KeyInfo><x:CipherData><x:CipherValue/></x:CipherData></k:EncapsulationMechanism></d:KeyInfo>{sibling}</root>",
        xml_sec::key_establishment::ENCAPSULATION_NS,
        xml_sec::provider::KeyEncapsulationAlgorithm::MlKem512.uri(),
    )
}

#[test]
#[cfg(feature = "experimental-pq")]
fn kem_recipient_options_fail_before_key_io() {
    // Missing or unsupported sources are usage errors, not KeyName ambiguity.
    for (command, option, expected) in [
        ("encrypt", None, "requires a recipient"),
        (
            "encrypt",
            Some("pubkey-cert-pem"),
            "--pubkey-cert-pem is inapplicable",
        ),
        ("decrypt", None, "requires a recipient"),
        ("decrypt", Some("pkcs12"), "--pkcs12 is inapplicable"),
    ] {
        let mut args = vec![OsString::from("xmlsec1"), OsString::from(command)];
        if let Some(option) = option {
            args.push(OsString::from(format!("--{option}")));
            args.push(OsString::from("missing-recipient-file"));
        }
        let invocation = Invocation::parse(args).unwrap();
        let policy = xmlsec_compatibility_encryption_policy();
        let mut budget =
            ExternalMaterialBudget::new(policy.resources.max_external_resource_total_bytes);
        let names = ["recipient"];
        let algorithm = xml_sec::provider::KeyEncapsulationAlgorithm::MlKem512;
        let error = if command == "encrypt" {
            select_encapsulation_key(
                &invocation,
                &names,
                algorithm,
                &policy.key_establishment,
                &policy,
                XmlBackend::default(),
                &mut budget,
            )
            .err()
            .unwrap()
        } else {
            select_decapsulation_key(
                &invocation,
                &names,
                algorithm,
                &policy.key_establishment,
                &policy,
                &mut budget,
            )
            .err()
            .unwrap()
        };
        assert!(matches!(error, CommandError::Usage(_)), "{error}");
        assert!(error.to_string().contains(expected), "{error}");
        assert!(error.to_string().contains(command), "{error}");
    }
}

#[test]
#[cfg(feature = "experimental-pq")]
fn kem_template_rejects_unexecuted_nested_recipient() {
    // Ordinary AES wrapping cannot preserve an unexecuted KEM instruction.
    let template = kem_template("<d:KeyName>wanted</d:KeyName>", "", "");
    let document = Document::parse(&template).unwrap();
    let mechanism = document
        .descendants()
        .find(|node| {
            node.has_tag_name((
                xml_sec::key_establishment::ENCAPSULATION_NS,
                "EncapsulationMechanism",
            ))
        })
        .unwrap();
    let nested = format!(
        "<x:EncryptedKey><x:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#kw-aes256\"/><d:KeyInfo>{}</d:KeyInfo><x:CipherData><x:CipherValue/></x:CipherData></x:EncryptedKey>",
        &template[mechanism.range()]
    );
    for recipient in [
        &nested,
        &format!(
            "<x:EncryptedKey><x:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#kw-aes256\"/><d:KeyInfo>{nested}</d:KeyInfo><x:CipherData><x:CipherValue/></x:CipherData></x:EncryptedKey>"
        ),
    ] {
        let input = template.replacen(
            "<d:KeyInfo></d:KeyInfo>",
            &format!("<d:KeyInfo>{recipient}</d:KeyInfo>"),
            1,
        );
        let error = encryption_template(
            &input,
            Some("data"),
            &[],
            &xmlsec_compatibility_encryption_policy(),
            XmlBackend::default(),
        )
        .err()
        .expect("unexecuted mechanism must be rejected");
        assert!(
            error.to_string().contains("nested EncapsulationMechanism"),
            "{error}"
        );
    }
}

#[test]
#[cfg(feature = "experimental-pq")]
fn kem_template_resolves_inner_recipient_references() {
    // A recipient name referenced inside the mechanism must reach selection.
    let template = kem_template(
        "<i:KeyInfoReference URI=\"#recipient\"/>",
        "<i:KeyInfoReference URI=\"#mechanism\"/>",
        "<d:KeyInfo Id=\"recipient\"><d:KeyName>wanted</d:KeyName></d:KeyInfo>",
    );
    let metadata = encryption_template(
        &template,
        Some("data"),
        &[],
        &xmlsec_compatibility_encryption_policy(),
        XmlBackend::default(),
    )
    .unwrap();
    assert_eq!(metadata.encapsulation.unwrap().1, ["wanted"]);
    for invalid in [
        template.replace("URI=\"#recipient\"", "URI=\"#absent\""),
        template.replace(
            "<d:KeyName>wanted</d:KeyName>",
            "<i:KeyInfoReference URI=\"#mechanism\"/>",
        ),
    ] {
        assert!(
            encryption_template(
                &invalid,
                Some("data"),
                &[],
                &xmlsec_compatibility_encryption_policy(),
                XmlBackend::default()
            )
            .is_err()
        );
    }
    let custom = template.replace("Id=\"recipient\"", "custom=\"recipient\"");
    assert!(
        encryption_template(
            &custom,
            Some("data"),
            &[],
            &xmlsec_compatibility_encryption_policy(),
            XmlBackend::default()
        )
        .is_err()
    );
    let metadata = encryption_template(
        &custom,
        Some("data"),
        &[IdAttributeRegistration::global("custom")],
        &xmlsec_compatibility_encryption_policy(),
        XmlBackend::default(),
    )
    .unwrap();
    assert_eq!(metadata.encapsulation.unwrap().1, ["wanted"]);
}

#[test]
#[cfg(feature = "experimental-pq")]
fn kem_template_updates_referenced_cipher_value() {
    // Mutate the original referenced mechanism, not a new inline duplicate.
    let template = kem_template(
        "<d:KeyName>wanted</d:KeyName>",
        "<i:KeyInfoReference URI=\"#mechanism\"/>",
        "",
    );
    let ciphertext = base64::engine::general_purpose::STANDARD.encode([7; 768]);
    let generated = format!(
        "<x:EncryptedData xmlns:x=\"{XMLENC_NS}\" xmlns:d=\"{XMLDSIG_NS}\" xmlns:k=\"{}\"><x:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"/><d:KeyInfo><k:EncapsulationMechanism Algorithm=\"{}\"><d:KeyInfo><d:KeyName>wanted</d:KeyName></d:KeyInfo><x:CipherData><x:CipherValue>{ciphertext}</x:CipherValue></x:CipherData></k:EncapsulationMechanism></d:KeyInfo><x:CipherData><x:CipherValue>AA==</x:CipherValue></x:CipherData></x:EncryptedData>",
        xml_sec::key_establishment::ENCAPSULATION_NS,
        xml_sec::provider::KeyEncapsulationAlgorithm::MlKem512.uri(),
    );
    let rendered = apply_encryption_template(
        &template,
        &generated,
        Some("data"),
        &[],
        &xmlsec_compatibility_encryption_policy(),
        XmlBackend::default(),
    )
    .unwrap();
    let document = Document::parse(&rendered).unwrap();
    let mechanisms: Vec<_> = document
        .descendants()
        .filter(|node| {
            node.has_tag_name((
                xml_sec::key_establishment::ENCAPSULATION_NS,
                "EncapsulationMechanism",
            ))
        })
        .collect();
    assert_eq!(mechanisms.len(), 1);
    assert_eq!(
        required_cipher_value(mechanisms[0], "mechanism")
            .unwrap()
            .text(),
        Some(ciphertext.as_str())
    );
}

#[test]
fn generated_recipient_expands_an_empty_key_info_placeholder() {
    // An empty KeyInfo reserves the schema position but not an EncryptedKey
    // skeleton; generated recipient metadata must expand it in place.
    let template = format!(
        "<e:EncryptedData xmlns:e=\"{XMLENC_NS}\" xmlns:s=\"{XMLDSIG_NS}\"><e:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"/><s:KeyInfo/><e:CipherData><e:CipherValue/></e:CipherData></e:EncryptedData>"
    );
    let generated = format!(
        "<e:EncryptedData xmlns:e=\"{XMLENC_NS}\" xmlns:s=\"{XMLDSIG_NS}\"><s:KeyInfo><e:EncryptedKey><e:CipherData><e:CipherValue>a2V5</e:CipherValue></e:CipherData></e:EncryptedKey></s:KeyInfo><e:CipherData><e:CipherValue>ZGF0YQ==</e:CipherValue></e:CipherData></e:EncryptedData>"
    );

    let rendered = apply_encryption_template(
        &template,
        &generated,
        None,
        &[],
        &EncryptionPolicy::default(),
        XmlBackend::default(),
    )
    .expect("empty KeyInfo must accept a generated recipient");
    let document = Document::parse(&rendered).expect("merged output must parse");

    assert_eq!(
        document
            .descendants()
            .filter(|node| node.has_tag_name((XMLENC_NS, "EncryptedKey")))
            .count(),
        1
    );
}

#[test]
fn generated_recipient_replaces_a_split_stale_key_name() {
    // A comment may split direct KeyName text without changing its value.
    // Comparing only the first text child would retain the stale name.
    let template = format!(
        "<e:EncryptedKey xmlns:e=\"{XMLENC_NS}\" xmlns:s=\"{XMLDSIG_NS}\"><s:KeyInfo><s:KeyName>valid<!-- split -->-old</s:KeyName></s:KeyInfo><e:CipherData><e:CipherValue/></e:CipherData></e:EncryptedKey>"
    );
    let generated = format!(
        "<e:EncryptedKey xmlns:e=\"{XMLENC_NS}\" xmlns:s=\"{XMLDSIG_NS}\"><s:KeyInfo><s:KeyName>valid</s:KeyName></s:KeyInfo><e:CipherData><e:CipherValue>a2V5</e:CipherValue></e:CipherData></e:EncryptedKey>"
    );
    let template_doc = Document::parse(&template).expect("template parses");
    let generated_doc = Document::parse(&generated).expect("generated key parses");
    let replacement = merge_generated_recipient_key_name(
        &template,
        template_doc.root_element(),
        &generated,
        generated_doc.root_element(),
    )
    .expect("recipient name merge succeeds")
    .expect("the stale full name must be replaced");
    let rendered = format!(
        "{}{}{}",
        &template[..replacement.0.start],
        replacement.1,
        &template[replacement.0.end..]
    );
    let document = Document::parse(&rendered).expect("replacement parses");
    let key_name = document
        .descendants()
        .find(|node| node.has_tag_name((XMLDSIG_NS, "KeyName")))
        .expect("recipient name remains present");
    assert_eq!(direct_simple_text(key_name, "KeyName").unwrap(), "valid");
}

#[test]
fn recipient_merge_keeps_parent_and_nested_insertions_disjoint() {
    // Outer key metadata, nested recipient identity, and ciphertext can all
    // be generated in one pass; their edits must not replace overlapping XML.
    let template = format!(
        "<e:EncryptedData xmlns:e=\"{XMLENC_NS}\" xmlns:s=\"{XMLDSIG_NS}\"><e:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"/><s:KeyInfo><e:EncryptedKey><s:KeyInfo/><e:CipherData><e:CipherValue/></e:CipherData></e:EncryptedKey></s:KeyInfo><e:CipherData><e:CipherValue/></e:CipherData></e:EncryptedData>"
    );
    let generated = format!(
        "<e:EncryptedData xmlns:e=\"{XMLENC_NS}\" xmlns:s=\"{XMLDSIG_NS}\"><s:KeyInfo><s:KeyName>outer</s:KeyName><e:EncryptedKey><s:KeyInfo><s:KeyName>recipient</s:KeyName></s:KeyInfo><e:CipherData><e:CipherValue>a2V5</e:CipherValue></e:CipherData></e:EncryptedKey></s:KeyInfo><e:CipherData><e:CipherValue>ZGF0YQ==</e:CipherValue></e:CipherData></e:EncryptedData>"
    );

    let rendered = apply_encryption_template(
        &template,
        &generated,
        None,
        &[],
        &EncryptionPolicy::default(),
        XmlBackend::default(),
    )
    .expect("all generated key metadata must merge without overlapping edits");
    let document = Document::parse(&rendered).expect("merged output must remain XML");
    let outer_key_info = document
        .descendants()
        .find(|node| {
            node.has_tag_name((XMLDSIG_NS, "KeyInfo"))
                && node
                    .parent()
                    .is_some_and(|parent| parent.has_tag_name((XMLENC_NS, "EncryptedData")))
        })
        .expect("outer KeyInfo");
    assert_eq!(
        direct_child_element(outer_key_info, XMLDSIG_NS, "KeyName").and_then(Node::text),
        Some("outer")
    );
    let encrypted_key = direct_child_element(outer_key_info, XMLENC_NS, "EncryptedKey")
        .expect("generated recipient");
    let recipient_key_info =
        direct_child_element(encrypted_key, XMLDSIG_NS, "KeyInfo").expect("recipient KeyInfo");
    assert_eq!(
        direct_child_element(recipient_key_info, XMLDSIG_NS, "KeyName").and_then(Node::text),
        Some("recipient")
    );
    let values = document
        .descendants()
        .filter(|node| node.has_tag_name((XMLENC_NS, "CipherValue")))
        .filter_map(Node::text)
        .collect::<Vec<_>>();
    assert_eq!(values, ["a2V5", "ZGF0YQ=="]);
}

#[test]
fn encryption_template_preserves_cipher_value_metadata() {
    // CipherValue is caller-owned: replacing ciphertext must preserve its
    // prefixes, namespace declarations, and extension attributes.
    let template = format!(
        "<e:EncryptedData xmlns:e=\"{XMLENC_NS}\" xmlns:s=\"{XMLDSIG_NS}\" xmlns:x=\"urn:ext\"><s:KeyInfo><e:EncryptedKey><e:CipherData><e:CipherValue x:kind=\"wrapped\">old</e:CipherValue></e:CipherData></e:EncryptedKey></s:KeyInfo><e:CipherData><e:CipherValue x:kind=\"content\"/></e:CipherData></e:EncryptedData>"
    );
    let generated = format!(
        "<e:EncryptedData xmlns:e=\"{XMLENC_NS}\" xmlns:s=\"{XMLDSIG_NS}\"><s:KeyInfo><e:EncryptedKey><e:CipherData><e:CipherValue>a2V5</e:CipherValue></e:CipherData></e:EncryptedKey></s:KeyInfo><e:CipherData><e:CipherValue>ZGF0YQ==</e:CipherValue></e:CipherData></e:EncryptedData>"
    );

    let rendered = apply_encryption_template(
        &template,
        &generated,
        None,
        &[],
        &EncryptionPolicy::default(),
        XmlBackend::default(),
    )
    .expect("CipherValue payload replacement must preserve template metadata");
    let document = Document::parse(&rendered).unwrap();
    let values = document
        .descendants()
        .filter(|node| node.has_tag_name((XMLENC_NS, "CipherValue")))
        .map(|node| (node.attribute(("urn:ext", "kind")), node.text()))
        .collect::<Vec<_>>();
    assert_eq!(
        values,
        vec![
            (Some("wrapped"), Some("a2V5")),
            (Some("content"), Some("ZGF0YQ=="))
        ]
    );
}

#[test]
fn encrypted_data_selection_uses_the_first_descendant() {
    // libxmlsec1 starts a depth-first search at the operation root and
    // does not impose global EncryptedData cardinality on that subtree.
    let xml = format!(
        "<root><group Id=\"selected\"><xenc:EncryptedData xmlns:xenc=\"{XMLENC_NS}\" Id=\"first\"/><xenc:EncryptedData xmlns:xenc=\"{XMLENC_NS}\" Id=\"second\"/></group></root>"
    );
    let document = Document::parse(&xml).unwrap();

    let selected = select_encrypted_data(&document, None, &[])
        .expect("the first document descendant must be selected");
    assert_eq!(selected.attribute("Id"), Some("first"));

    let selected = select_encrypted_data(&document, Some("selected"), &[])
        .expect("the first operation-subtree descendant must be selected");
    assert_eq!(selected.attribute("Id"), Some("first"));
}

#[test]
fn merged_encryption_template_obeys_the_aggregate_node_ceiling() {
    // Template and generated output cross the trust boundary separately,
    // but the returned document must also fit the same operation policy.
    let extras = "<extra/>".repeat(24);
    let template = format!(
        "<e:EncryptedData xmlns:e=\"{XMLENC_NS}\">{extras}<e:CipherData><e:CipherValue/></e:CipherData></e:EncryptedData>"
    );
    let generated = format!(
        "<e:EncryptedData xmlns:e=\"{XMLENC_NS}\" xmlns:s=\"{XMLDSIG_NS}\"><s:KeyInfo><e:EncryptedKey><e:CipherData><e:CipherValue>a2V5</e:CipherValue></e:CipherData></e:EncryptedKey></s:KeyInfo><e:CipherData><e:CipherValue>ZGF0YQ==</e:CipherValue></e:CipherData></e:EncryptedData>"
    );
    let individual_node_ceiling = [template.as_str(), generated.as_str()]
        .into_iter()
        .map(|xml| Document::parse(xml).unwrap().descendants().count())
        .max()
        .unwrap();
    let policy = EncryptionPolicy {
        resources: xml_sec::policy::ResourcePolicy {
            max_xml_nodes: individual_node_ceiling,
            ..xml_sec::policy::ResourcePolicy::default()
        },
        ..EncryptionPolicy::default()
    };

    let error = apply_encryption_template(
        &template,
        &generated,
        None,
        &[],
        &policy,
        XmlBackend::default(),
    )
    .expect_err("the aggregate merged document must be reparsed under policy");
    assert!(error.to_string().contains("nodes limit"), "{error}");
}

#[test]
fn merged_encryption_template_checks_bytes_before_reparsing() {
    // Both inputs fit independently, but adding generated recipient data to
    // the padded template crosses the document ceiling before a merged DOM
    // may be allocated.
    let padding = "x".repeat(256);
    let template = format!(
        "<e:EncryptedData xmlns:e=\"{XMLENC_NS}\" padding=\"{padding}\"><e:CipherData><e:CipherValue/></e:CipherData></e:EncryptedData>"
    );
    let generated = format!(
        "<e:EncryptedData xmlns:e=\"{XMLENC_NS}\" xmlns:s=\"{XMLDSIG_NS}\"><s:KeyInfo><e:EncryptedKey><e:CipherData><e:CipherValue>a2V5</e:CipherValue></e:CipherData></e:EncryptedKey></s:KeyInfo><e:CipherData><e:CipherValue>ZGF0YQ==</e:CipherValue></e:CipherData></e:EncryptedData>"
    );
    let maximum = template.len().max(generated.len());
    let policy = EncryptionPolicy {
        resources: xml_sec::policy::ResourcePolicy {
            max_xml_document_bytes: maximum,
            ..xml_sec::policy::ResourcePolicy::default()
        },
        ..EncryptionPolicy::default()
    };

    let error = apply_encryption_template(
        &template,
        &generated,
        None,
        &[],
        &policy,
        XmlBackend::default(),
    )
    .expect_err("merged output must be bounded before reparsing");
    assert!(
        matches!(&error, CommandError::Encryption(message) if message.contains("encrypted template output exceeds XML document policy")),
        "{error}"
    );
}

#[test]
fn input_reader_enforces_the_compiled_policy_limit_before_parsing() {
    // The reader must stop at maximum + 1 rather than allocating an entire
    // attacker-controlled XML file before the operation policy sees it.
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("oversized.xml");
    fs::write(&path, b"<root/>").unwrap();
    let invocation = Invocation::parse([
        OsString::from("xmlsec1"),
        OsString::from("verify"),
        path.into_os_string(),
    ])
    .unwrap();
    assert!(matches!(
        read_input(&invocation, 4),
        Err(CommandError::InputTooLarge { maximum: 4 })
    ));
}

#[test]
fn xml_readers_classify_decoded_expansion_as_input_too_large() {
    // A declared single-byte document may fit the raw-byte gate but expand after decoding.
    // Both CLI XML readers must preserve that second boundary as InputTooLarge.
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("expanded.xml");
    let bytes = b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><root>\xe9\xe9</root>";
    fs::write(&path, bytes).unwrap();
    let invocation = Invocation::parse([
        OsString::from("xmlsec1"),
        OsString::from("verify"),
        path.clone().into_os_string(),
    ])
    .unwrap();

    assert!(matches!(
        read_input(&invocation, bytes.len()),
        Err(CommandError::InputTooLarge { maximum }) if maximum == bytes.len()
    ));
    assert!(matches!(
        read_xml_data(path.as_os_str(), bytes.len()),
        Err(CommandError::InputTooLarge { maximum }) if maximum == bytes.len()
    ));
}

#[test]
fn encryption_template_inspection_enforces_the_xml_node_ceiling() {
    // CLI metadata discovery runs before the core builder, so it must reject
    // over-budget templates instead of constructing an unrestricted DOM.
    let mut xml = format!(
        "<EncryptedData xmlns=\"{XMLENC_NS}\"><EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"/><CipherData><CipherValue/></CipherData>"
    );
    for _ in 0..100_000 {
        xml.push_str("<Extension/>");
    }
    xml.push_str("</EncryptedData>");

    let Err(error) = encryption_template(
        &xml,
        None,
        &[],
        &EncryptionPolicy::default(),
        XmlBackend::default(),
    ) else {
        panic!("over-budget template must fail");
    };
    assert!(
        matches!(&error, CommandError::Encryption(message) if message.contains("nodes limit")),
        "expected the parser node ceiling, got: {error}"
    );
}

#[test]
fn plaintext_reader_enforces_the_compiled_policy_limit_before_encryption() {
    // Payload limits must be enforced by the reader, before the encryption
    // builder receives an attacker-controlled allocation.
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("oversized.bin");
    fs::write(&path, b"12345").unwrap();
    assert!(matches!(
        read_plaintext(path.as_os_str(), 4),
        Err(CommandError::PlaintextTooLarge { maximum: 4 })
    ));
}

#[test]
fn configured_certificates_are_deduplicated_and_aggregate_bounded() {
    // Repeated CLI options must not multiply retained DER, while distinct
    // trust material must be rejected before crossing the compiled total.
    let mut certificates = Vec::new();
    let mut budget = ExternalMaterialBudget::new(5);
    budget.charge(2).unwrap();
    push_configured_certificate(&mut certificates, vec![1, 2]);
    budget.charge(2).unwrap();
    push_configured_certificate(&mut certificates, vec![1, 2]);
    assert_eq!(certificates, [vec![1, 2]]);
    assert_eq!(budget.total_bytes, 4);

    assert!(matches!(
        budget.charge(2),
        Err(CommandError::ExternalMaterialTooLarge { maximum: 5 })
    ));
    assert_eq!(certificates, [vec![1, 2]]);
    assert_eq!(budget.total_bytes, 4);

    assert!(matches!(
        budget.charge(2),
        Err(CommandError::ExternalMaterialTooLarge { maximum: 5 })
    ));
    assert_eq!(budget.total_bytes, 4);
}

#[test]
fn signing_key_source_is_charged_before_private_key_decoding() {
    // Aggregate source limits must stop a candidate before malformed key
    // bytes reach the comparatively expensive private-key decoders.
    let temp = tempfile::tempdir().unwrap();
    let key_path = temp.path().join("malformed.pem");
    fs::write(&key_path, b"xx").unwrap();
    let parsed = Invocation::parse([
        OsString::from("xmlsec1"),
        OsString::from("sign"),
        OsString::from("--privkey-pem"),
        key_path.into_os_string(),
        OsString::from("template.xml"),
    ])
    .unwrap();
    let option = parsed.values("privkey-pem").next().unwrap();
    let mut budget = ExternalMaterialBudget::new(1);

    assert!(matches!(
        prepare_signing_key_candidate(
            option,
            SignatureAlgorithm::RsaSha256,
            &SigningPolicy::default(),
            None,
            &mut budget,
            default_provider(),
        ),
        Err(CommandError::ExternalMaterialTooLarge { maximum: 1 })
    ));
}

#[test]
fn lax_signing_propagates_aggregate_material_exhaustion() {
    // A malformed candidate is recoverable in lax mode, but a later source
    // that exhausts the shared budget must stop search before a valid key.
    let temp = tempfile::tempdir().unwrap();
    let malformed = temp.path().join("malformed.pem");
    let oversized = temp.path().join("oversized.pem");
    let valid = testdata("rsa-2048-key.pem");
    fs::write(&malformed, b"x").unwrap();
    let valid_len = fs::metadata(&valid).unwrap().len();
    fs::File::create(&oversized)
        .unwrap()
        .set_len(valid_len + 1)
        .unwrap();
    let parsed = Invocation::parse([
        OsString::from("xmlsec1"),
        OsString::from("sign"),
        OsString::from("--lax-key-search"),
        OsString::from("--privkey-pem:malformed"),
        malformed.into_os_string(),
        OsString::from("--privkey-pem:oversized"),
        oversized.into_os_string(),
        OsString::from("--privkey-pem:valid"),
        valid.into_os_string(),
        OsString::from("template.xml"),
    ])
    .unwrap();
    let total = usize::try_from(valid_len).unwrap() + 1;
    let mut policy = SigningPolicy::default();
    policy.resources.max_external_resource_total_bytes = total;

    assert!(matches!(
        select_signing_key(
            &parsed,
            &[],
            SignatureAlgorithm::RsaSha256,
            None,
            &policy,
            None,
            &mut ExternalMaterialBudget::new(policy.resources.max_external_resource_total_bytes),
        ),
        Err(CommandError::ExternalMaterialTooLarge { maximum }) if maximum == total
    ));
}

#[test]
fn duplicate_configured_certificate_sources_consume_aggregate_budget() {
    // Deduplicating retained DER must not make repeated external file reads
    // free: every explicitly supplied source consumes invocation work.
    let certificate = testdata("rsa-2048-cert.pem");
    let source_len = fs::read(&certificate).unwrap().len();
    let invocation = Invocation::parse([
        OsString::from("xmlsec1"),
        OsString::from("verify"),
        OsString::from("--trusted-pem"),
        certificate.as_os_str().to_owned(),
        OsString::from("--trusted-pem"),
        certificate.as_os_str().to_owned(),
        OsString::from("signed.xml"),
    ])
    .unwrap();
    let mut budget = ExternalMaterialBudget::new(source_len);

    assert!(matches!(
        load_configured_certificates(&invocation, false, &mut budget),
        Err(CommandError::ExternalMaterialTooLarge { maximum }) if maximum == source_len
    ));
}

#[test]
fn certificate_companions_charge_source_bytes_before_retention() {
    // PEM whitespace is still processed input even though it disappears
    // from decoded DER, so the source size must drive aggregate charging.
    let fixture = testdata("rsa-2048-cert.pem");
    let temp = tempfile::tempdir().unwrap();
    let padded = temp.path().join("padded-cert.pem");
    let mut source = fs::read(&fixture).unwrap();
    source.extend(std::iter::repeat_n(b' ', 4096));
    fs::write(&padded, &source).unwrap();
    let der_len = key_material::load_certificate_with_source_len(
        &padded,
        key_material::CertificateEncoding::Pem,
    )
    .unwrap()
    .0
    .len();
    let mut budget = ExternalMaterialBudget::new(der_len);

    assert!(matches!(
        load_certificate_companions(
            &[padded.as_os_str()],
            key_material::CertificateEncoding::Pem,
            &mut budget,
        ),
        Err(CommandError::ExternalMaterialTooLarge { maximum }) if maximum == der_len
    ));
}

#[test]
fn explicit_verification_certificate_charges_source_bytes() {
    // Explicit leaf certificates share the invocation budget with trust
    // inputs, including PEM bytes discarded while decoding the DER value.
    let fixture = testdata("rsa-2048-cert.pem");
    let temp = tempfile::tempdir().unwrap();
    let padded = temp.path().join("padded-explicit-cert.pem");
    let mut source = fs::read(&fixture).unwrap();
    source.extend(std::iter::repeat_n(b' ', 4096));
    fs::write(&padded, &source).unwrap();
    let der_len = key_material::load_certificate_with_source_len(
        &padded,
        key_material::CertificateEncoding::Pem,
    )
    .unwrap()
    .0
    .len();
    let option = crate::OptionValue {
        name: "pubkey-cert-pem".into(),
        parameter: None,
        value: Some(padded.into_os_string()),
    };
    let mut budget = ExternalMaterialBudget::new(der_len);

    assert!(matches!(
        load_explicit_certificate_key_info(&option, &mut budget),
        Err(CommandError::ExternalMaterialTooLarge { maximum }) if maximum == der_len
    ));
}

#[test]
fn recipient_resolver_bounds_applicable_private_keys_before_unwrap() {
    // Lax lookup must not hide an unbounded RSA-OAEP loop behind the single
    // content key eventually returned to the core decryption context.
    let path = testdata("rsa-2048-key.pem");
    let private_key =
        key_material::load_rsa_private(&path, key_material::PrivateKeyFormat::Pem).unwrap();
    let resolver = NamedRecipientDecryptor {
        keys: vec![
            RecipientPrivateKey {
                inner: PrivateKeyDecryptor::new(private_key.clone()),
                key_name: None,
            },
            RecipientPrivateKey {
                inner: PrivateKeyDecryptor::new(private_key),
                key_name: None,
            },
        ],
        lax_key_search: true,
        unnamed_single_key_fallback: false,
    };
    let encrypted_key = EncryptedKey {
        sources: xml_sec::xmlenc::EncryptionKeySources::default(),
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
        cipher_data: xml_sec::xmlenc::CipherData::Value {
            value: base64::engine::general_purpose::STANDARD.encode([0_u8; 256]),
        },
        reference_list: None,
        carried_key_name: None,
    };

    let mut candidate_budget = KeyCandidateBudget::for_operation();
    let maximum = candidate_budget.remaining();
    let reserved = maximum - 1;
    candidate_budget.consume(reserved).unwrap();
    let error = resolver
        .resolve_key_candidates(
            default_provider(),
            DataEncryptionAlgorithm::Aes128Gcm,
            Some(&encrypted_key),
            &mut candidate_budget,
        )
        .expect_err("oversized applicable RSA key sets must fail before unwrap");

    assert!(matches!(
        error,
        XmlEncError::Policy(xml_sec::policy::PolicyViolation::ResourceLimit {
            resource: "key candidates",
            maximum: observed_maximum,
            actual,
        }) if observed_maximum == maximum && actual == maximum + 1
    ));
}

#[test]
fn recipient_certificate_loader_charges_the_invocation_budget() {
    // Recipient certificates are external inputs even when used only to
    // extract an RSA wrapping key, so they share the operation-wide budget.
    let certificate = testdata("rsa-2048-cert.pem");
    let mut budget = ExternalMaterialBudget::new(1);

    let error = load_rsa_recipient_candidate(
        certificate.as_os_str(),
        RecipientPublicKeySource::Certificate(key_material::CertificateEncoding::Pem),
        &EncryptionPolicy::default(),
        &mut budget,
    )
    .expect_err("certificate DER must exceed the one-byte aggregate budget");

    assert!(matches!(
        error,
        CommandError::ExternalMaterialTooLarge { maximum: 1 }
    ));
}

#[test]
fn recipient_certificate_loader_charges_pem_source_bytes() {
    // PEM whitespace is processed external input even though decoding drops
    // it, so recipient certificate accounting must use the source length.
    let fixture = testdata("rsa-2048-cert.pem");
    let temp = tempfile::tempdir().unwrap();
    let padded = temp.path().join("padded-recipient-cert.pem");
    let mut source = fs::read(&fixture).unwrap();
    source.extend(std::iter::repeat_n(b' ', 4096));
    fs::write(&padded, source).unwrap();
    let der_len = key_material::load_certificate_with_source_len(
        &padded,
        key_material::CertificateEncoding::Pem,
    )
    .unwrap()
    .0
    .len();
    let mut budget = ExternalMaterialBudget::new(der_len);

    assert!(matches!(
        load_rsa_recipient_candidate(
            padded.as_os_str(),
            RecipientPublicKeySource::Certificate(key_material::CertificateEncoding::Pem,),
            &EncryptionPolicy::default(),
            &mut budget,
        ),
        Err(CommandError::ExternalMaterialTooLarge { maximum }) if maximum == der_len
    ));
}

#[test]
fn recipient_certificate_cache_reuses_one_budget_charge() {
    // Repeated recipient selection may reuse one CLI option, but external
    // certificate bytes belong to the invocation and are charged once.
    let certificate = testdata("rsa-2048-cert.pem");
    let (_, source_len) = key_material::load_certificate_with_source_len(
        certificate.as_os_str(),
        key_material::CertificateEncoding::Pem,
    )
    .unwrap();
    let invocation = Invocation::parse([
        OsString::from("xmlsec1"),
        OsString::from("encrypt"),
        OsString::from("--pubkey-cert-pem"),
        certificate.as_os_str().to_owned(),
        OsString::from("--binary-data"),
        OsString::from("payload.bin"),
        OsString::from("template.xml"),
    ])
    .unwrap();
    let option = invocation.values("pubkey-cert-pem").next().unwrap();
    let mut cache = HashMap::new();
    let mut budget = ExternalMaterialBudget::new(source_len);

    cached_rsa_recipient_candidate(
        &mut cache,
        option,
        true,
        &EncryptionPolicy::default(),
        &mut budget,
    )
    .unwrap();
    cached_rsa_recipient_candidate(
        &mut cache,
        option,
        true,
        &EncryptionPolicy::default(),
        &mut budget,
    )
    .expect("cached selection must not charge the certificate twice");
}

#[test]
fn xml_content_serialization_enforces_the_plaintext_limit_while_rendering() {
    // Inherited namespaces can expand every serialized child. The Content
    // path must stop at the operation budget rather than constructing the
    // complete expanded plaintext before the builder checks its length.
    let xml = r#"<root xmlns:a="urn:one" xmlns:b="urn:two"><a:item/><b:item/></root>"#;
    let policy = EncryptionPolicy {
        resources: xml_sec::policy::ResourcePolicy {
            max_encryption_plaintext_bytes: 32,
            ..xml_sec::policy::ResourcePolicy::default()
        },
        ..EncryptionPolicy::default()
    };

    let document =
        parse_encryption_document(xml, policy.xml, &policy.resources, XmlBackend::default())
            .unwrap();

    assert!(matches!(
        xml_data_plaintext(
            xml,
            document.root_element(),
            &EncryptedDataType::Content,
            &policy,
        ),
        Err(CommandError::PlaintextTooLarge { maximum: 32 })
    ));
}

const XML_DATA_TEMPLATE: &str = r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element"><EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><CipherData><CipherValue>AAAA</CipherValue></CipherData></EncryptedData>"#;

fn xml_data_command<'a>(
    invocation: &'a Invocation,
    policy: &'a EncryptionPolicy,
) -> EncryptCommand<'a> {
    EncryptCommand {
        invocation,
        template: XML_DATA_TEMPLATE,
        start_node_id: None,
        id_attributes: &[],
        policy,
        xml_backend: XmlBackend::default(),
        provider: &xml_sec::provider::RustCryptoProvider,
    }
}

#[test]
fn xml_data_output_obeys_the_document_limit() {
    // The data document fits the policy, but replacing a small node with the
    // filled EncryptedData grows it past the limit; the CLI must refuse
    // rather than write output it cannot read back.
    let data = format!("<root><t/>{}</root>", "x".repeat(400));
    let policy = EncryptionPolicy {
        resources: xml_sec::policy::ResourcePolicy {
            max_xml_document_bytes: data.len() + 16,
            ..xml_sec::policy::ResourcePolicy::default()
        },
        ..EncryptionPolicy::default()
    };
    let invocation = invocation(&["xmlsec1", "encrypt"]);
    let command = xml_data_command(&invocation, &policy);
    let document =
        parse_encryption_document(&data, policy.xml, &policy.resources, XmlBackend::default())
            .unwrap();
    let target = document
        .root_element()
        .first_element_child()
        .expect("the data has a target element");

    let result = place_encrypted_data(
        &command,
        &data,
        target,
        &EncryptedDataType::Element,
        XML_DATA_TEMPLATE,
    );
    assert!(result.is_err(), "oversized output was produced: {result:?}");
}

#[test]
fn xml_data_output_obeys_the_structural_limits() {
    // Replacing a leaf at the depth limit with EncryptedData nests its children
    // deeper than the policy allows; the assembled document must be refused.
    let data = "<a><b><c/></b></a>";
    let policy = EncryptionPolicy {
        resources: xml_sec::policy::ResourcePolicy {
            max_xml_depth: 3,
            ..xml_sec::policy::ResourcePolicy::default()
        },
        ..EncryptionPolicy::default()
    };
    let invocation = invocation(&["xmlsec1", "encrypt"]);
    let command = xml_data_command(&invocation, &policy);
    let document =
        parse_encryption_document(data, policy.xml, &policy.resources, XmlBackend::default())
            .unwrap();
    let leaf = document
        .descendants()
        .find(|node| node.has_tag_name("c"))
        .expect("the data has a leaf");
    let template = r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#"><CipherData><CipherValue>AAAA</CipherValue></CipherData></EncryptedData>"#;

    let result = place_encrypted_data(&command, data, leaf, &EncryptedDataType::Element, template);
    assert!(result.is_err(), "too deep output was produced: {result:?}");
}

#[test]
fn xml_data_moved_template_keeps_its_absent_default_namespace() {
    // Namespaces in XML 1.0 section 6.2: an unprefixed name takes the default
    // namespace in scope. A template without one, moved under a data element
    // that declares one, must keep its unprefixed names out of that namespace.
    let data = r#"<Order xmlns="urn:order"><Payment>secret</Payment></Order>"#;
    let template = r#"<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"><xenc:CipherData><xenc:CipherValue>AAAA</xenc:CipherValue></xenc:CipherData><xenc:EncryptionProperties><xenc:EncryptionProperty><Audit/></xenc:EncryptionProperty></xenc:EncryptionProperties></xenc:EncryptedData>"#;
    let policy = xmlsec_compatibility_encryption_policy();
    let invocation = invocation(&["xmlsec1", "encrypt"]);
    let command = xml_data_command(&invocation, &policy);
    let document =
        parse_encryption_document(data, policy.xml, &policy.resources, XmlBackend::default())
            .unwrap();
    let payment = document
        .descendants()
        .find(|node| node.has_tag_name("Payment"))
        .expect("the data has a payment");

    let output = place_encrypted_data(
        &command,
        data,
        payment,
        &EncryptedDataType::Element,
        template,
    )
    .expect("the template moves into the data document");
    let placed = parse_encryption_document(
        &output,
        policy.xml,
        &policy.resources,
        XmlBackend::default(),
    )
    .unwrap();
    let audit = placed
        .descendants()
        .find(|node| node.tag_name().name() == "Audit")
        .expect("the template metadata is preserved");
    assert_eq!(audit.tag_name().namespace(), None, "{output}");
    assert!(placed.root_element().has_tag_name(("urn:order", "Order")));
}

#[test]
fn xml_data_moved_template_keeps_its_own_default_undeclaration() {
    // A template that already undeclares the default namespace must not get a
    // second `xmlns=""`: Namespaces in XML 1.0 section 6.3 forbids duplicates.
    let data = r#"<Order xmlns="urn:order"><Payment>secret</Payment></Order>"#;
    let template = r#"<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns=""><xenc:CipherData><xenc:CipherValue>AAAA</xenc:CipherValue></xenc:CipherData><xenc:EncryptionProperties><xenc:EncryptionProperty><Audit/></xenc:EncryptionProperty></xenc:EncryptionProperties></xenc:EncryptedData>"#;
    let policy = xmlsec_compatibility_encryption_policy();
    let invocation = invocation(&["xmlsec1", "encrypt"]);
    let command = xml_data_command(&invocation, &policy);
    let document =
        parse_encryption_document(data, policy.xml, &policy.resources, XmlBackend::default())
            .unwrap();
    let payment = document
        .descendants()
        .find(|node| node.has_tag_name("Payment"))
        .expect("the data has a payment");

    let output = place_encrypted_data(
        &command,
        data,
        payment,
        &EncryptedDataType::Element,
        template,
    )
    .expect("an existing undeclaration is kept as is");
    assert_eq!(output.matches("xmlns=\"\"").count(), 1, "{output}");
}

#[test]
fn xml_data_references_stay_unambiguous_in_the_data_document() {
    // A reference that resolves inside the template can become ambiguous once the
    // EncryptedData joins a data document holding the same ID; decryption resolves
    // it there, so the assembled document must be checked.
    let data = r#"<Order><Payment>secret</Payment><Info Id="recipient-info"/></Order>"#;
    let template = r##"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#" Id="recipient-info"><KeyInfoReference xmlns="http://www.w3.org/2009/xmldsig11#" URI="#recipient-info"/></KeyInfo><CipherData><CipherValue>AAAA</CipherValue></CipherData></EncryptedData>"##;
    let policy = xmlsec_compatibility_encryption_policy();
    let invocation = invocation(&["xmlsec1", "encrypt"]);
    let command = xml_data_command(&invocation, &policy);
    let document =
        parse_encryption_document(data, policy.xml, &policy.resources, XmlBackend::default())
            .unwrap();
    let payment = document
        .descendants()
        .find(|node| node.has_tag_name("Payment"))
        .expect("the data has a payment");

    let result = place_encrypted_data(
        &command,
        data,
        payment,
        &EncryptedDataType::Element,
        template,
    );
    assert!(
        result.is_err(),
        "ambiguous reference was written: {result:?}"
    );
}

#[test]
fn xml_data_ignores_uri_attributes_of_extension_metadata() {
    // XMLEnc 1.1 section 3.7 allows foreign content in EncryptionProperty without
    // giving its URI attributes reference semantics; decryption never resolves
    // them, so they must not make the template look dangling.
    let data = "<Order><Payment>secret</Payment></Order>";
    let template = r##"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#"><CipherData><CipherValue>AAAA</CipherValue></CipherData><EncryptionProperties><EncryptionProperty><audit:Event xmlns:audit="urn:audit" URI="#event"/></EncryptionProperty></EncryptionProperties></EncryptedData>"##;
    let policy = xmlsec_compatibility_encryption_policy();
    let invocation = invocation(&["xmlsec1", "encrypt"]);
    let command = xml_data_command(&invocation, &policy);
    let document =
        parse_encryption_document(data, policy.xml, &policy.resources, XmlBackend::default())
            .unwrap();
    let payment = document
        .descendants()
        .find(|node| node.has_tag_name("Payment"))
        .expect("the data has a payment");

    place_encrypted_data(
        &command,
        data,
        payment,
        &EncryptedDataType::Element,
        template,
    )
    .expect("application metadata is preserved, not resolved");
}

#[test]
fn xml_data_template_references_resolve_xpointer_forms() {
    // Only EncryptedData moves into the data document, so an XPointer
    // reference to a node outside it would dangle exactly like a bare ID.
    let policy = xmlsec_compatibility_encryption_policy();
    let invocation = invocation(&["xmlsec1", "encrypt"]);
    let command = xml_data_command(&invocation, &policy);
    let filled = |uri: &str| {
        format!(
            r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Id="data"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><KeyInfoReference xmlns="http://www.w3.org/2009/xmldsig11#" URI="{uri}"/></KeyInfo><CipherData><CipherValue>AAAA</CipherValue></CipherData></EncryptedData>"#
        )
    };
    let check = |uri: &str| {
        let xml = filled(uri);
        ensure_self_contained(&xml, 0..xml.len(), &command)
    };
    assert!(check("#xpointer(id('mechanism'))").is_err());
    assert!(check("#mechanism").is_err());
    // After the move, the whole template document is no longer what `/` selects.
    assert!(check("#xpointer(/)").is_err());
    check("#xpointer(id('data'))").expect("a reference inside EncryptedData stays resolvable");
}

#[test]
fn xml_data_reader_decodes_utf16_before_template_use() {
    // --xml-data has its own file reader and must share the same XML 1.0
    // encoding contract as the primary command input.
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("payload.xml");
    let mut bytes = vec![0xfe, 0xff];
    bytes.extend(
        "<payload>value</payload>"
            .encode_utf16()
            .flat_map(u16::to_be_bytes),
    );
    fs::write(&path, &bytes).unwrap();

    assert_eq!(
        read_xml_data(path.as_os_str(), bytes.len()).unwrap(),
        "<payload>value</payload>"
    );
}

#[test]
fn verification_diagnostics_aggregate_manifest_failures() {
    // libxmlsec1 reports the operation as failed when a processed Manifest
    // reference fails, even though the core SignatureValue remains valid.
    let aggregate = aggregate_statuses(
        DsigStatus::Valid,
        [DsigStatus::Invalid(
            FailureReason::ReferenceDigestMismatch { ref_index: 0 },
        )],
    );

    assert_eq!(donor_dsig_status(aggregate), ("FAILED", "REFERENCE"));
}

#[test]
fn verification_diagnostics_name_unavailable_and_unprocessed_references() {
    // An unsupplied detached payload is a Reference failure; a Reference left
    // unprocessed behind an invalid signature keeps the donor's unknown status.
    assert_eq!(
        donor_dsig_status(DsigStatus::Invalid(FailureReason::ReferenceUnavailable {
            ref_index: 0
        })),
        ("FAILED", "REFERENCE")
    );
    assert_eq!(
        donor_dsig_status(DsigStatus::NotProcessed),
        ("ERROR", "UNKNOWN")
    );
}
