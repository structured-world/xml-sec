//! Donor full verification suite for ROADMAP task P1-025.
//!
//! This suite tracks pass/fail/skip accounting across donor vectors and
//! enforces that all supported donor vectors verify end-to-end.

use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use xml_sec::xmldsig::{
    DefaultKeyResolver, DsigError, DsigStatus, KeyResolverConfig, ParseError, SignatureAlgorithm,
    VerificationKey, VerifyContext,
};

#[derive(Clone, Copy)]
enum SkipProbe {
    WeakRsaKey,
    UnsupportedSignatureAlgorithm,
}

#[derive(Clone, Copy)]
enum Expectation {
    ValidEmbedded,
    ValidNamed {
        key_name: &'static str,
        key_path: &'static str,
        algorithm: SignatureAlgorithm,
    },
    ValidSelected {
        certificate_path: &'static str,
    },
    ValidChain {
        trust_anchor_path: &'static str,
    },
    Skip {
        reason: &'static str,
        probe: SkipProbe,
    },
}

struct VectorCase {
    name: &'static str,
    xml_path: &'static str,
    expectation: Expectation,
}

fn read_fixture(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read fixture {}: {err}", path.display()))
}

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_pem_der(path: &Path, expected_label: &str) -> Vec<u8> {
    let pem_text = read_fixture(path);
    let (rest, pem) = x509_parser::pem::parse_x509_pem(pem_text.as_bytes())
        .unwrap_or_else(|err| panic!("failed to parse PEM fixture {}: {err}", path.display()));
    assert!(rest.iter().all(|byte| byte.is_ascii_whitespace()));
    assert_eq!(pem.label, expected_label);
    pem.contents
}

fn cases() -> Vec<VectorCase> {
    vec![
        // Aleksey donor vectors: supported algorithms must pass end-to-end.
        VectorCase {
            name: "aleksey-rsa-sha1",
            xml_path: "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloped-sha1-rsa-sha1.xml",
            expectation: Expectation::ValidNamed {
                key_name: "TestKeyName-rsa-4096",
                key_path: "tests/fixtures/keys/rsa/rsa-4096-pubkey.pem",
                algorithm: SignatureAlgorithm::RsaSha1,
            },
        },
        VectorCase {
            name: "aleksey-rsa-sha256",
            xml_path: "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.xml",
            expectation: Expectation::ValidEmbedded,
        },
        VectorCase {
            name: "aleksey-rsa-sha384",
            xml_path: "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha384-rsa-sha384.xml",
            expectation: Expectation::ValidEmbedded,
        },
        VectorCase {
            name: "aleksey-rsa-sha512",
            xml_path: "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha512-rsa-sha512.xml",
            expectation: Expectation::ValidEmbedded,
        },
        VectorCase {
            name: "aleksey-ecdsa-p256-sha256",
            xml_path: "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloped-sha256-ecdsa-sha256.xml",
            expectation: Expectation::ValidNamed {
                key_name: "TestKeyName-ec-prime256v1",
                key_path: "tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem",
                algorithm: SignatureAlgorithm::EcdsaP256Sha256,
            },
        },
        VectorCase {
            name: "aleksey-ecdsa-p521-sha384",
            xml_path: "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloped-sha384-ecdsa-sha384.xml",
            expectation: Expectation::ValidNamed {
                key_name: "TestKeyName-ec-prime521v1",
                key_path: "tests/fixtures/keys/ec/ec-prime521v1-pubkey.pem",
                algorithm: SignatureAlgorithm::EcdsaP384Sha384,
            },
        },
        VectorCase {
            name: "aleksey-rsa-sha512-x509-digest",
            xml_path: "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloped-x509-digest-sha512.xml",
            expectation: Expectation::ValidSelected {
                certificate_path: "tests/fixtures/keys/rsa/rsa-4096-cert.pem",
            },
        },
        VectorCase {
            name: "aleksey-rsa-sha1-x509-chain-tofu",
            xml_path: "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-rsa-x509chain.xml",
            expectation: Expectation::ValidEmbedded,
        },
        VectorCase {
            name: "aleksey-rsa-sha1-x509-chain-anchored",
            xml_path: "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-rsa-x509chain.xml",
            expectation: Expectation::ValidChain {
                trust_anchor_path: "tests/fixtures/keys/cacert.pem",
            },
        },
        // Merlin "basic signatures" required by P1-025.
        // These are tracked explicitly as skips until P2/P4 capabilities exist.
        VectorCase {
            name: "merlin-enveloped-dsa",
            xml_path: "tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/signature-enveloped-dsa.xml",
            expectation: Expectation::Skip {
                reason: "DSA signature method is not implemented yet (planned P4-009)",
                probe: SkipProbe::UnsupportedSignatureAlgorithm,
            },
        },
        VectorCase {
            name: "merlin-enveloping-rsa-keyvalue",
            xml_path: "tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/signature-enveloping-rsa.xml",
            expectation: Expectation::Skip {
                reason: "RSAKeyValue resolves but its legacy 1024-bit modulus is below policy",
                probe: SkipProbe::WeakRsaKey,
            },
        },
        VectorCase {
            name: "merlin-x509-crt",
            xml_path: "tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/signature-x509-crt.xml",
            expectation: Expectation::Skip {
                reason: "DSA signature method is not implemented yet (planned P4-009); X509 KeyInfo resolution is not implemented yet (planned P2-009)",
                probe: SkipProbe::UnsupportedSignatureAlgorithm,
            },
        },
        VectorCase {
            name: "merlin-x509-crt-crl",
            xml_path: "tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/signature-x509-crt-crl.xml",
            expectation: Expectation::Skip {
                reason: "DSA signature method is not implemented yet (planned P4-009); X509/CRL KeyInfo resolution is not implemented yet (planned P2-009/P2-005)",
                probe: SkipProbe::UnsupportedSignatureAlgorithm,
            },
        },
        VectorCase {
            name: "merlin-x509-is",
            xml_path: "tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/signature-x509-is.xml",
            expectation: Expectation::Skip {
                reason: "DSA signature method is not implemented yet (planned P4-009); X509IssuerSerial resolution is not implemented yet (planned P2-009)",
                probe: SkipProbe::UnsupportedSignatureAlgorithm,
            },
        },
        VectorCase {
            name: "merlin-x509-ski",
            xml_path: "tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/signature-x509-ski.xml",
            expectation: Expectation::Skip {
                reason: "DSA signature method is not implemented yet (planned P4-009); X509SKI resolution is not implemented yet (planned P2-009)",
                probe: SkipProbe::UnsupportedSignatureAlgorithm,
            },
        },
        VectorCase {
            name: "merlin-x509-sn",
            xml_path: "tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/signature-x509-sn.xml",
            expectation: Expectation::Skip {
                reason: "DSA signature method is not implemented yet (planned P4-009); X509SubjectName resolution is not implemented yet (planned P2-009)",
                probe: SkipProbe::UnsupportedSignatureAlgorithm,
            },
        },
    ]
}

#[test]
fn donor_full_verification_suite_tracks_pass_fail_skip_counts() {
    let root = project_root();
    let mut passed = 0usize;
    let mut failed = Vec::<String>::new();
    let mut skipped = Vec::<String>::new();

    for case in cases() {
        match case.expectation {
            Expectation::ValidEmbedded => {
                let xml = read_fixture(&root.join(case.xml_path));
                let resolver = DefaultKeyResolver::default();
                match VerifyContext::new().key_resolver(&resolver).verify(&xml) {
                    Ok(result) if matches!(result.status, DsigStatus::Valid) => {
                        passed += 1;
                    }
                    Ok(result) => {
                        failed.push(format!(
                            "{}: expected Valid, got {:?}",
                            case.name, result.status
                        ));
                    }
                    Err(err) => {
                        failed.push(format!("{}: verification error {err}", case.name));
                    }
                }
            }
            Expectation::ValidNamed {
                key_name,
                key_path,
                algorithm,
            } => {
                let xml = read_fixture(&root.join(case.xml_path));
                let mut config = KeyResolverConfig::default();
                config.named_keys.insert(
                    key_name.into(),
                    VerificationKey {
                        algorithm,
                        public_key_bytes: read_pem_der(&root.join(key_path), "PUBLIC KEY"),
                        certificate_der: None,
                        name: Some(key_name.into()),
                    },
                );
                let resolver = DefaultKeyResolver::new(config);
                match VerifyContext::new().key_resolver(&resolver).verify(&xml) {
                    Ok(result) if matches!(result.status, DsigStatus::Valid) => passed += 1,
                    Ok(result) => failed.push(format!(
                        "{}: expected Valid, got {:?}",
                        case.name, result.status
                    )),
                    Err(err) => {
                        failed.push(format!("{}: verification error {err}", case.name));
                    }
                }
            }
            Expectation::ValidSelected { certificate_path } => {
                let xml = read_fixture(&root.join(case.xml_path));
                let resolver = DefaultKeyResolver::new(KeyResolverConfig {
                    trusted_certs: vec![read_pem_der(&root.join(certificate_path), "CERTIFICATE")],
                    ..KeyResolverConfig::default()
                });
                match VerifyContext::new().key_resolver(&resolver).verify(&xml) {
                    Ok(result) if matches!(result.status, DsigStatus::Valid) => passed += 1,
                    Ok(result) => failed.push(format!(
                        "{}: expected Valid, got {:?}",
                        case.name, result.status
                    )),
                    Err(err) => {
                        failed.push(format!("{}: verification error {err}", case.name));
                    }
                }
            }
            Expectation::ValidChain { trust_anchor_path } => {
                let xml = read_fixture(&root.join(case.xml_path));
                let resolver = DefaultKeyResolver::new(KeyResolverConfig {
                    trusted_certs: vec![read_pem_der(&root.join(trust_anchor_path), "CERTIFICATE")],
                    verify_chains: true,
                    // 2027-01-15 UTC, inside the donor chain's 2026-2126 validity window.
                    verification_time: Some(
                        SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000),
                    ),
                    ..KeyResolverConfig::default()
                });
                match VerifyContext::new().key_resolver(&resolver).verify(&xml) {
                    Ok(result) if matches!(result.status, DsigStatus::Valid) => passed += 1,
                    Ok(result) => failed.push(format!(
                        "{}: expected Valid, got {:?}",
                        case.name, result.status
                    )),
                    Err(err) => {
                        failed.push(format!("{}: verification error {err}", case.name));
                    }
                }
            }
            Expectation::Skip { reason, probe } => {
                let xml = read_fixture(&root.join(case.xml_path));
                roxmltree::Document::parse(&xml)
                    .unwrap_or_else(|err| panic!("{}: fixture XML must parse: {err}", case.name));
                match probe {
                    SkipProbe::WeakRsaKey => match VerifyContext::new()
                        .key_resolver(&DefaultKeyResolver::default())
                        .verify(&xml)
                    {
                        Err(DsigError::Crypto(
                            xml_sec::xmldsig::SignatureVerificationError::InvalidKeyDer,
                        )) => {}
                        Ok(result) => failed.push(format!(
                            "{}: expected weak RSA key error for skipped vector, got {:?}",
                            case.name, result.status
                        )),
                        Err(err) => failed.push(format!(
                            "{}: expected weak RSA key error for skipped vector, got {err}",
                            case.name
                        )),
                    },
                    SkipProbe::UnsupportedSignatureAlgorithm => match VerifyContext::new().verify(&xml)
                    {
                        Err(DsigError::ParseSignedInfo(ParseError::UnsupportedAlgorithm {
                            ..
                        })) => {}
                        Ok(result) => failed.push(format!(
                            "{}: expected unsupported signature algorithm error for skipped vector, got {:?}",
                            case.name, result.status
                        )),
                        Err(err) => failed.push(format!(
                            "{}: expected unsupported signature algorithm error for skipped vector, got {err}",
                            case.name
                        )),
                    },
                }
                skipped.push(format!("{}: {}", case.name, reason));
            }
        }
    }

    assert_eq!(
        failed.len(),
        0,
        "donor full verification suite had failures:\n{}",
        failed.join("\n")
    );

    let expected_skipped = vec![
        "merlin-enveloped-dsa: DSA signature method is not implemented yet (planned P4-009)",
        "merlin-enveloping-rsa-keyvalue: RSAKeyValue resolves but its legacy 1024-bit modulus is below policy",
        "merlin-x509-crt: DSA signature method is not implemented yet (planned P4-009); X509 KeyInfo resolution is not implemented yet (planned P2-009)",
        "merlin-x509-crt-crl: DSA signature method is not implemented yet (planned P4-009); X509/CRL KeyInfo resolution is not implemented yet (planned P2-009/P2-005)",
        "merlin-x509-is: DSA signature method is not implemented yet (planned P4-009); X509IssuerSerial resolution is not implemented yet (planned P2-009)",
        "merlin-x509-ski: DSA signature method is not implemented yet (planned P4-009); X509SKI resolution is not implemented yet (planned P2-009)",
        "merlin-x509-sn: DSA signature method is not implemented yet (planned P4-009); X509SubjectName resolution is not implemented yet (planned P2-009)",
    ];

    // P1-025 minimum expected accounting:
    // - all supported aleksey RSA/ECDSA vectors pass
    // - unsupported/deferred merlin vectors are tracked as skips with explicit reasons
    assert_eq!(passed, 9, "unexpected pass count");
    assert_eq!(skipped, expected_skipped, "unexpected skip inventory");
}
