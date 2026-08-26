//! Exhaustive public-pipeline coverage for the Phaos XMLDSig 3 corpus.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use x509_parser::prelude::{FromDer, X509Certificate};
use xml_sec::policy::VerificationPolicy;
use xml_sec::xmldsig::{
    DefaultKeyResolver, DsigError, DsigStatus, FailureReason, HmacSha1VerificationKey,
    KeyResolverConfig, ParseError, ReferenceProcessingError, SignatureAlgorithm, TransformError,
    UriTypeSet, VerificationKey, VerifyContext, X509ChainError,
};

const PHAOS: &str = "tests/fixtures/xmldsig/phaos-xmldsig-three";
const RFC3161: &str = "tests/fixtures/xmldsig/external-data/rfc3161.txt";
const VERIFY_2009: u64 = 1_230_804_000;
const XSLT_URI: &str = "http://www.w3.org/TR/1999/REC-xslt-19991116";
const MD5_URI: &str = "http://www.w3.org/2001/04/xmldsig-more#md5";
const HMAC_MD5_URI: &str = "http://www.w3.org/2001/04/xmldsig-more#hmac-md5";

#[derive(Clone, Copy, Debug)]
enum Setup {
    Rsa,
    Dsa,
    Hmac,
    Hmac80,
    X509Rsa,
}

#[derive(Clone, Copy, Debug)]
enum Expected {
    Valid,
    ValidWithManifestFailure,
    BadDigest,
    UnsupportedSignature(&'static str),
    UnsupportedTransform(&'static str),
    UnsupportedCertificateSignature(&'static str),
    UntrustedCertificateRoot,
}

#[derive(Clone, Copy, Debug)]
struct Case {
    name: &'static str,
    setup: Setup,
    expected: Expected,
}

const CASES: &[Case] = &[
    Case {
        name: "signature-big.xml",
        setup: Setup::Rsa,
        expected: Expected::UnsupportedTransform(XSLT_URI),
    },
    Case {
        name: "signature-dsa-detached.xml",
        setup: Setup::Dsa,
        expected: Expected::Valid,
    },
    Case {
        name: "signature-dsa-enveloped.xml",
        setup: Setup::Dsa,
        expected: Expected::Valid,
    },
    Case {
        name: "signature-dsa-enveloping.xml",
        setup: Setup::Dsa,
        expected: Expected::Valid,
    },
    Case {
        name: "signature-dsa-manifest.xml",
        setup: Setup::Dsa,
        expected: Expected::Valid,
    },
    Case {
        name: "signature-hmac-md5-c14n-enveloping.xml",
        setup: Setup::Hmac,
        expected: Expected::UnsupportedSignature(HMAC_MD5_URI),
    },
    Case {
        name: "signature-hmac-sha1-40-c14n-comments-detached.xml",
        setup: Setup::Hmac80,
        expected: Expected::Valid,
    },
    Case {
        name: "signature-hmac-sha1-40-exclusive-c14n-comments-detached.xml",
        setup: Setup::Hmac80,
        expected: Expected::Valid,
    },
    Case {
        name: "signature-hmac-sha1-exclusive-c14n-comments-detached.xml",
        setup: Setup::Hmac,
        expected: Expected::Valid,
    },
    Case {
        name: "signature-hmac-sha1-exclusive-c14n-enveloped.xml",
        setup: Setup::Hmac,
        expected: Expected::Valid,
    },
    Case {
        name: "signature-rsa-detached-b64-transform.xml",
        setup: Setup::Rsa,
        expected: Expected::Valid,
    },
    Case {
        name: "signature-rsa-detached-xpath-transform.xml",
        setup: Setup::Rsa,
        expected: Expected::Valid,
    },
    Case {
        name: "signature-rsa-detached-xslt-transform-bad-retrieval-method.xml",
        setup: Setup::X509Rsa,
        expected: Expected::UntrustedCertificateRoot,
    },
    Case {
        name: "signature-rsa-detached-xslt-transform-retrieval-method.xml",
        setup: Setup::X509Rsa,
        expected: Expected::UnsupportedCertificateSignature("1.2.840.113549.1.1.4"),
    },
    Case {
        name: "signature-rsa-detached-xslt-transform.xml",
        setup: Setup::Rsa,
        expected: Expected::ValidWithManifestFailure,
    },
    Case {
        name: "signature-rsa-detached.xml",
        setup: Setup::Rsa,
        expected: Expected::Valid,
    },
    Case {
        name: "signature-rsa-enveloped-bad-digest-val.xml",
        setup: Setup::Rsa,
        expected: Expected::BadDigest,
    },
    Case {
        name: "signature-rsa-enveloped-bad-sig.xml",
        setup: Setup::Rsa,
        expected: Expected::UnsupportedSignature(MD5_URI),
    },
    Case {
        name: "signature-rsa-enveloped.xml",
        setup: Setup::Rsa,
        expected: Expected::Valid,
    },
    Case {
        name: "signature-rsa-enveloping.xml",
        setup: Setup::Rsa,
        expected: Expected::Valid,
    },
    Case {
        name: "signature-rsa-manifest-x509-data-cert-chain.xml",
        setup: Setup::X509Rsa,
        expected: Expected::UnsupportedCertificateSignature("1.2.840.113549.1.1.4"),
    },
    Case {
        name: "signature-rsa-manifest-x509-data-cert.xml",
        setup: Setup::X509Rsa,
        expected: Expected::UnsupportedCertificateSignature("1.2.840.113549.1.1.4"),
    },
    Case {
        name: "signature-rsa-manifest-x509-data-issuer-serial.xml",
        setup: Setup::X509Rsa,
        expected: Expected::UnsupportedCertificateSignature("1.2.840.113549.1.1.4"),
    },
    Case {
        name: "signature-rsa-manifest-x509-data-ski.xml",
        setup: Setup::X509Rsa,
        expected: Expected::UnsupportedCertificateSignature("1.2.840.113549.1.1.4"),
    },
    Case {
        name: "signature-rsa-manifest-x509-data-subject-name.xml",
        setup: Setup::X509Rsa,
        expected: Expected::UnsupportedCertificateSignature("1.2.840.113549.1.1.4"),
    },
    Case {
        name: "signature-rsa-manifest.xml",
        setup: Setup::Rsa,
        expected: Expected::Valid,
    },
    Case {
        name: "signature-rsa-xpath-transform-enveloped.xml",
        setup: Setup::Rsa,
        expected: Expected::Valid,
    },
    Case {
        name: "signature-rsa-~x509-data-crl.xml",
        setup: Setup::X509Rsa,
        expected: Expected::UnsupportedCertificateSignature("1.2.840.113549.1.1.4"),
    },
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn bytes(path: impl AsRef<Path>) -> Vec<u8> {
    let path = root().join(path);
    std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn document(name: &str) -> String {
    String::from_utf8(bytes(Path::new(PHAOS).join(name))).expect("Phaos XML must be UTF-8")
}

fn certificate(name: &str) -> Vec<u8> {
    bytes(Path::new(PHAOS).join("certs").join(name))
}

fn verification_key() -> VerificationKey {
    let der = certificate("rsa-cert.der");
    let (rest, certificate) = X509Certificate::from_der(&der).expect("Phaos RSA certificate");
    assert!(rest.is_empty());
    VerificationKey {
        algorithm: SignatureAlgorithm::RsaSha1,
        public_key_bytes: certificate.public_key().raw.to_vec(),
        certificate_der: Some(der),
        name: None,
    }
}

fn policy(algorithm: SignatureAlgorithm, verify_x509_chains: bool) -> VerificationPolicy {
    let mut policy = VerificationPolicy::default();
    policy
        .key_trust
        .allowed_legacy_signature_algorithms
        .insert(algorithm);
    policy.key_trust.rsa_keys.minimum_modulus_bits = 1024;
    policy.key_trust.dsa_keys.minimum_modulus_bits = 1024;
    policy.key_trust.verify_x509_chains = verify_x509_chains;
    policy.key_trust.verification_time =
        Some(SystemTime::UNIX_EPOCH + Duration::from_secs(VERIFY_2009));
    policy.uris.retrieval_methods = UriTypeSet::ALL;
    policy
}

fn resources() -> HashMap<String, Vec<u8>> {
    HashMap::from([
        (
            "document.xml".into(),
            bytes(Path::new(PHAOS).join("document.xml")),
        ),
        (
            "document.b64".into(),
            bytes(Path::new(PHAOS).join("document.b64")),
        ),
        (
            "document-stylesheet.xml".into(),
            bytes(Path::new(PHAOS).join("document-stylesheet.xml")),
        ),
        (
            "document.xsl".into(),
            bytes(Path::new(PHAOS).join("document.xsl")),
        ),
        ("http://www.ietf.org/rfc/rfc3161.txt".into(), bytes(RFC3161)),
        ("certs/rsa-cert.der".into(), certificate("rsa-cert.der")),
        (
            "certs/dsa-ca-cert.der".into(),
            certificate("dsa-ca-cert.der"),
        ),
    ])
}

fn execute(case: Case) -> Result<xml_sec::xmldsig::VerifyResult, DsigError> {
    let xml = document(case.name);
    let resources = resources();
    match case.setup {
        Setup::Rsa => {
            let key = verification_key();
            VerifyContext::new()
                .policy(policy(SignatureAlgorithm::RsaSha1, false))
                .key(&key)
                .process_manifests(true)
                .allowed_uri_types(UriTypeSet::ALL)
                .external_resources(&resources)
                .verify(&xml)
        }
        Setup::Dsa => {
            let resolver = DefaultKeyResolver::new(KeyResolverConfig {
                lookup_certs: vec![certificate("dsa-cert.der")],
                trusted_certs: vec![certificate("dsa-ca-cert.der")],
                ..KeyResolverConfig::default()
            });
            VerifyContext::new()
                .policy(policy(SignatureAlgorithm::DsaSha1, true))
                .key_resolver(&resolver)
                .process_manifests(true)
                .allowed_uri_types(UriTypeSet::ALL)
                .external_resources(&resources)
                .verify(&xml)
        }
        Setup::Hmac => {
            let key = HmacSha1VerificationKey::new(certificate("hmackey.bin"))
                .expect("Phaos HMAC key is valid");
            VerifyContext::new()
                .policy(policy(SignatureAlgorithm::HmacSha1, false))
                .key(&key)
                .allowed_uri_types(UriTypeSet::ALL)
                .external_resources(&resources)
                .verify(&xml)
        }
        Setup::Hmac80 => {
            let key = HmacSha1VerificationKey::new(certificate("hmackey.bin"))
                .expect("Phaos HMAC key is valid")
                .with_output_length_bits(80)
                .expect("Phaos HMAC truncation is valid");
            VerifyContext::new()
                .policy(policy(SignatureAlgorithm::HmacSha1, false))
                .key(&key)
                .allowed_uri_types(UriTypeSet::ALL)
                .external_resources(&resources)
                .verify(&xml)
        }
        Setup::X509Rsa => {
            let resolver = DefaultKeyResolver::new(KeyResolverConfig {
                lookup_certs: vec![certificate("rsa-cert.der")],
                trusted_certs: vec![certificate("rsa-ca-cert.der")],
                ..KeyResolverConfig::default()
            });
            VerifyContext::new()
                .policy(policy(SignatureAlgorithm::RsaSha1, true))
                .key_resolver(&resolver)
                .process_manifests(true)
                .allowed_uri_types(UriTypeSet::ALL)
                .external_resources(&resources)
                .verify(&xml)
        }
    }
}

fn check_expected(
    case: Case,
    result: Result<xml_sec::xmldsig::VerifyResult, DsigError>,
) -> Result<(), String> {
    let matches = match (case.expected, &result) {
        (Expected::Valid, Ok(result)) => result.status == DsigStatus::Valid,
        (Expected::ValidWithManifestFailure, Ok(result)) => {
            result.status == DsigStatus::Valid
                && result.manifest_references.len() == 1
                && result.manifest_references[0].status
                    == DsigStatus::Invalid(FailureReason::ReferenceProcessingFailure {
                        ref_index: 0,
                    })
        }
        (Expected::BadDigest, Ok(result)) => {
            result.status
                == DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
        }
        (
            Expected::UnsupportedSignature(uri),
            Err(DsigError::ParseSignedInfo(ParseError::UnsupportedAlgorithm { uri: actual })),
        ) => actual == uri,
        (
            Expected::UnsupportedTransform(uri),
            Err(DsigError::ParseSignedInfo(ParseError::Transform(
                TransformError::UnsupportedTransform(actual),
            ))),
        ) => actual == uri,
        (
            Expected::UnsupportedCertificateSignature(oid),
            Err(DsigError::KeyResolution(xml_sec::xmldsig::KeyResolutionError::Chain(
                X509ChainError::UnsupportedSignatureAlgorithm { oid: actual },
            ))),
        ) => actual == oid,
        (
            Expected::UntrustedCertificateRoot,
            Err(DsigError::KeyResolution(xml_sec::xmldsig::KeyResolutionError::Chain(
                X509ChainError::UntrustedRoot,
            ))),
        ) => true,
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(format!(
            "{}: expected {:?}, got {result:?}",
            case.name, case.expected
        ))
    }
}

#[test]
fn every_phaos_signature_is_classified_once() {
    // Exact set equality turns donor additions, removals, and duplicate table rows into reviewable failures.
    let actual: BTreeSet<_> = std::fs::read_dir(root().join(PHAOS))
        .expect("Phaos fixture directory")
        .map(|entry| entry.expect("Phaos directory entry").file_name())
        .filter_map(|name| name.into_string().ok())
        .filter(|name| name.starts_with("signature-") && name.ends_with(".xml"))
        .collect();
    let classified: BTreeSet<_> = CASES.iter().map(|case| case.name.to_owned()).collect();
    assert_eq!(
        classified.len(),
        CASES.len(),
        "duplicate Phaos case classification"
    );
    assert_eq!(classified, actual, "Phaos corpus classification drift");
}

#[test]
fn executes_every_phaos_signature_through_the_public_pipeline() {
    // Unsupported future capabilities are executed and fail closed at an exact typed boundary; none are skipped.
    let failures: Vec<_> = CASES
        .iter()
        .copied()
        .filter_map(|case| check_expected(case, execute(case)).err())
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn detached_resources_are_caller_owned_and_required() {
    // The public API never performs implicit I/O for a donor URI.
    let xml = document("signature-rsa-detached.xml");
    let key = verification_key();
    let error = VerifyContext::new()
        .policy(policy(SignatureAlgorithm::RsaSha1, false))
        .key(&key)
        .process_manifests(true)
        .allowed_uri_types(UriTypeSet::ALL)
        .external_resources(&HashMap::new())
        .verify(&xml)
        .expect_err("missing caller resource must fail closed");
    assert!(
        matches!(
        error,
        DsigError::Reference(ReferenceProcessingError::UriDereference(
            TransformError::UnsupportedUri(ref uri)
        )) if uri == "http://www.ietf.org/rfc/rfc3161.txt"
        ),
        "unexpected missing-resource error: {error:?}"
    );
}
