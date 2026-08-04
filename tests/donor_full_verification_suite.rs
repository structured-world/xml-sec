//! End-to-end verification for the supported Aleksey donor vectors.

use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use xml_sec::xmldsig::{
    DefaultKeyResolver, DsigStatus, KeyResolverConfig, SignatureAlgorithm, VerificationKey,
    VerifyContext,
};

#[derive(Clone, Copy)]
enum Expectation {
    Embedded,
    Named {
        key_name: &'static str,
        key_path: &'static str,
        algorithm: SignatureAlgorithm,
    },
    Selected {
        certificate_paths: &'static [&'static str],
    },
    Chain {
        trust_anchor_path: &'static str,
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
            expectation: Expectation::Named {
                key_name: "TestKeyName-rsa-4096",
                key_path: "tests/fixtures/keys/rsa/rsa-4096-pubkey.pem",
                algorithm: SignatureAlgorithm::RsaSha1,
            },
        },
        VectorCase {
            name: "aleksey-rsa-sha256",
            xml_path: "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.xml",
            expectation: Expectation::Embedded,
        },
        VectorCase {
            name: "aleksey-rsa-sha384",
            xml_path: "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha384-rsa-sha384.xml",
            expectation: Expectation::Embedded,
        },
        VectorCase {
            name: "aleksey-rsa-sha512",
            xml_path: "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha512-rsa-sha512.xml",
            expectation: Expectation::Embedded,
        },
        VectorCase {
            name: "aleksey-ecdsa-p256-sha256",
            xml_path: "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloped-sha256-ecdsa-sha256.xml",
            expectation: Expectation::Named {
                key_name: "TestKeyName-ec-prime256v1",
                key_path: "tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem",
                algorithm: SignatureAlgorithm::EcdsaP256Sha256,
            },
        },
        VectorCase {
            name: "aleksey-ecdsa-p521-sha384",
            xml_path: "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloped-sha384-ecdsa-sha384.xml",
            expectation: Expectation::Named {
                key_name: "TestKeyName-ec-prime521v1",
                key_path: "tests/fixtures/keys/ec/ec-prime521v1-pubkey.pem",
                algorithm: SignatureAlgorithm::EcdsaP384Sha384,
            },
        },
        VectorCase {
            name: "aleksey-rsa-sha512-x509-digest",
            xml_path: "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloped-x509-digest-sha512.xml",
            expectation: Expectation::Selected {
                certificate_paths: &[
                    "tests/fixtures/keys/rsa/rsa-4096-cert.pem",
                    "tests/fixtures/keys/ca2cert.pem",
                    "tests/fixtures/keys/cacert.pem",
                ],
            },
        },
        VectorCase {
            name: "aleksey-rsa-sha1-x509-chain-tofu",
            xml_path: "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-rsa-x509chain.xml",
            expectation: Expectation::Embedded,
        },
        VectorCase {
            name: "aleksey-rsa-sha1-x509-chain-anchored",
            xml_path: "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-rsa-x509chain.xml",
            expectation: Expectation::Chain {
                trust_anchor_path: "tests/fixtures/keys/cacert.pem",
            },
        },
    ]
}

#[test]
fn donor_full_verification_suite_accepts_every_supported_case() {
    let root = project_root();
    let mut passed = 0usize;
    let mut failed = Vec::<String>::new();

    for case in cases() {
        match case.expectation {
            Expectation::Embedded => {
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
            Expectation::Named {
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
            Expectation::Selected { certificate_paths } => {
                let xml = read_fixture(&root.join(case.xml_path));
                let resolver = DefaultKeyResolver::new(KeyResolverConfig {
                    trusted_certs: certificate_paths
                        .iter()
                        .map(|path| read_pem_der(&root.join(path), "CERTIFICATE"))
                        .collect(),
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
            Expectation::Chain { trust_anchor_path } => {
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
        }
    }

    assert_eq!(
        failed.len(),
        0,
        "donor full verification suite had failures:\n{}",
        failed.join("\n")
    );

    assert_eq!(passed, 9, "unexpected pass count");
}
