//! XMLDSig 1.1 and Second Edition donor interoperability inventory.
//!
//! Every vendored XML vector is classified. Vectors using the implemented
//! P-256/P-384 ECKeyValue path must verify; vectors requiring algorithms or
//! transforms outside the public contract must fail closed rather than being
//! accidentally accepted.

use std::path::{Path, PathBuf};

use xml_sec::xmldsig::{DefaultKeyResolver, DsigStatus, VerifyContext};

const XMLDSIG11_DIR: &str = "tests/fixtures/xmldsig/xmldsig11-interop-2012";
const XMLDSIG2ED_DIR: &str = "tests/fixtures/xmldsig/xmldsig2ed-tests";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedOutcome {
    Valid,
    Unsupported(&'static str),
}

struct VectorCase {
    path: PathBuf,
    expected: ExpectedOutcome,
}

fn xml_files(directory: &str) -> Vec<PathBuf> {
    let mut paths = std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("failed to list {directory}: {error}"))
        .map(|entry| entry.expect("directory entry must be readable").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "xml"))
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

fn xmlsec11_expected(path: &Path) -> ExpectedOutcome {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    match name {
        "signature-enveloping-p256_sha256.xml"
        | "signature-enveloping-p384_sha384.xml"
        | "signature-enveloping-derencoded-ec.xml" => ExpectedOutcome::Valid,
        name if name.contains("hmac") => ExpectedOutcome::Unsupported("HMAC signature method"),
        name if name.contains("sha224") => ExpectedOutcome::Unsupported("SHA-224 algorithm"),
        name if name.contains("p521") => ExpectedOutcome::Unsupported("P-521 KeyValue resolution"),
        name if name.contains("keyinforeference") => {
            ExpectedOutcome::Unsupported("KeyInfoReference dereference")
        }
        name if name.contains("x509digest") => {
            ExpectedOutcome::Unsupported("X509Digest configured-certificate lookup")
        }
        name if name.contains("rsa") => ExpectedOutcome::Unsupported("RSA fixture key material"),
        _ => ExpectedOutcome::Unsupported("unsupported XMLDSig 1.1 vector"),
    }
}

fn cases() -> Vec<VectorCase> {
    let mut cases = xml_files(XMLDSIG11_DIR)
        .into_iter()
        .map(|path| VectorCase {
            expected: xmlsec11_expected(&path),
            path,
        })
        .collect::<Vec<_>>();
    cases.extend(
        xml_files(XMLDSIG2ED_DIR)
            .into_iter()
            .map(|path| VectorCase {
                path,
                // Every 2nd Edition signature vector uses HMAC-SHA1 plus an external
                // reference and XPath transform, none of which is currently enabled.
                expected: ExpectedOutcome::Unsupported("HMAC/external-URI/XPath vector"),
            }),
    );
    cases
}

#[test]
fn donor_interop_vectors_have_explicit_pass_or_fail_closed_accounting() {
    let cases = cases();
    assert_eq!(
        cases.len(),
        54,
        "fixture import must retain the complete corpus"
    );

    let mut valid = 0;
    let mut unsupported = Vec::new();
    for case in cases {
        let xml = std::fs::read_to_string(&case.path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", case.path.display()));
        roxmltree::Document::parse(&xml)
            .unwrap_or_else(|error| panic!("{} must be well-formed: {error}", case.path.display()));

        let resolver = DefaultKeyResolver::default();
        let result = VerifyContext::new().key_resolver(&resolver).verify(&xml);
        match case.expected {
            ExpectedOutcome::Valid => {
                let result = result
                    .unwrap_or_else(|error| panic!("{} must verify: {error}", case.path.display()));
                assert!(
                    matches!(result.status, DsigStatus::Valid),
                    "{} must verify, got {:?}",
                    case.path.display(),
                    result.status
                );
                valid += 1;
            }
            ExpectedOutcome::Unsupported(reason) => {
                assert!(
                    !matches!(result, Ok(ref result) if matches!(result.status, DsigStatus::Valid)),
                    "{} unexpectedly verified despite requiring {reason}",
                    case.path.display()
                );
                unsupported.push(format!("{}: {reason}", case.path.display()));
            }
        }
    }

    assert_eq!(valid, 3, "all supported ECKeyValue vectors must verify");
    assert_eq!(
        unsupported.len(),
        51,
        "all remaining vectors must be accounted for"
    );
}
