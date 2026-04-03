//! Donor full verification suite for ROADMAP task P1-025.
//!
//! This suite tracks pass/fail/skip accounting across donor vectors and
//! enforces that all supported donor vectors verify end-to-end.

use std::path::{Path, PathBuf};

use xml_sec::xmldsig::{DsigStatus, verify_signature_with_pem_key};

#[derive(Clone, Copy)]
enum Expectation {
    ValidWithKey { key_path: &'static str },
    Skip { reason: &'static str },
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

fn cases() -> Vec<VectorCase> {
    vec![
        // Aleksey donor vectors: supported algorithms must pass end-to-end.
        VectorCase {
            name: "aleksey-rsa-sha1",
            xml_path: "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloped-sha1-rsa-sha1.xml",
            expectation: Expectation::ValidWithKey {
                key_path: "tests/fixtures/keys/rsa/rsa-4096-pubkey.pem",
            },
        },
        VectorCase {
            name: "aleksey-rsa-sha256",
            xml_path: "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.xml",
            expectation: Expectation::ValidWithKey {
                key_path: "tests/fixtures/keys/rsa/rsa-2048-pubkey.pem",
            },
        },
        VectorCase {
            name: "aleksey-rsa-sha384",
            xml_path: "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha384-rsa-sha384.xml",
            expectation: Expectation::ValidWithKey {
                key_path: "tests/fixtures/keys/rsa/rsa-4096-pubkey.pem",
            },
        },
        VectorCase {
            name: "aleksey-rsa-sha512",
            xml_path: "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha512-rsa-sha512.xml",
            expectation: Expectation::ValidWithKey {
                key_path: "tests/fixtures/keys/rsa/rsa-4096-pubkey.pem",
            },
        },
        VectorCase {
            name: "aleksey-ecdsa-p256-sha256",
            xml_path: "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloped-sha256-ecdsa-sha256.xml",
            expectation: Expectation::ValidWithKey {
                key_path: "tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem",
            },
        },
        VectorCase {
            name: "aleksey-ecdsa-p521-sha384",
            xml_path: "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloped-sha384-ecdsa-sha384.xml",
            expectation: Expectation::Skip {
                reason: "vector uses KeyName ec-prime521v1 (P-521), which is not supported yet",
            },
        },
        VectorCase {
            name: "aleksey-rsa-sha512-x509-digest",
            xml_path: "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloped-x509-digest-sha512.xml",
            expectation: Expectation::Skip {
                reason: "X509Digest key resolution is not implemented yet (planned P2-009)",
            },
        },
        // Merlin "basic signatures" required by P1-025.
        // These are tracked explicitly as skips until P2/P4 capabilities exist.
        VectorCase {
            name: "merlin-enveloped-dsa",
            xml_path: "tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/signature-enveloped-dsa.xml",
            expectation: Expectation::Skip {
                reason: "DSA signature method is not implemented yet (planned P4-009)",
            },
        },
        VectorCase {
            name: "merlin-enveloping-rsa-keyvalue",
            xml_path: "tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/signature-enveloping-rsa.xml",
            expectation: Expectation::Skip {
                reason: "KeyValue auto-resolution is not implemented yet (planned P2-009)",
            },
        },
        VectorCase {
            name: "merlin-x509-crt",
            xml_path: "tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/signature-x509-crt.xml",
            expectation: Expectation::Skip {
                reason: "X509 KeyInfo resolution is not implemented yet (planned P2-009)",
            },
        },
        VectorCase {
            name: "merlin-x509-crt-crl",
            xml_path: "tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/signature-x509-crt-crl.xml",
            expectation: Expectation::Skip {
                reason: "X509/CRL KeyInfo resolution is not implemented yet (planned P2-009/P2-005)",
            },
        },
        VectorCase {
            name: "merlin-x509-is",
            xml_path: "tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/signature-x509-is.xml",
            expectation: Expectation::Skip {
                reason: "X509IssuerSerial resolution is not implemented yet (planned P2-009)",
            },
        },
        VectorCase {
            name: "merlin-x509-ski",
            xml_path: "tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/signature-x509-ski.xml",
            expectation: Expectation::Skip {
                reason: "X509SKI resolution is not implemented yet (planned P2-009)",
            },
        },
        VectorCase {
            name: "merlin-x509-sn",
            xml_path: "tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/signature-x509-sn.xml",
            expectation: Expectation::Skip {
                reason: "X509SubjectName resolution is not implemented yet (planned P2-009)",
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
            Expectation::ValidWithKey { key_path } => {
                let xml = read_fixture(&root.join(case.xml_path));
                let key = read_fixture(&root.join(key_path));
                match verify_signature_with_pem_key(&xml, &key, false) {
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
            Expectation::Skip { reason } => {
                let _ = read_fixture(&root.join(case.xml_path));
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

    // P1-025 minimum expected accounting:
    // - all supported aleksey RSA/ECDSA vectors pass
    // - unsupported/deferred merlin vectors are tracked as skips with explicit reasons
    assert_eq!(passed, 5, "unexpected pass count");
    assert_eq!(skipped.len(), 9, "unexpected skip count");
}
