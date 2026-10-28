//! Exhaustive public-pipeline coverage for the Phaos `XMLDSig` 3 corpus.

#![cfg(feature = "xmldsig")]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use x509_parser::prelude::{FromDer, X509Certificate};
use xml_sec::policy::VerificationPolicy;
use xml_sec::xmldsig::{
    DefaultKeyResolver, DsigError, DsigStatus, FailureReason, HmacSha1VerificationKey,
    KeyResolverConfig, ParseError, SignatureAlgorithm, UriTypeSet, VerificationKey, VerifyContext,
    X509ChainError,
};

const PHAOS: &str = "tests/fixtures/xmldsig/phaos-xmldsig-three";
const RFC3161: &str = "tests/fixtures/xmldsig/external-data/rfc3161.txt";
const VERIFY_2009: i64 = 1_230_804_000;
#[cfg(not(feature = "xslt"))]
const XSLT_URI: &str = "http://www.w3.org/TR/1999/REC-xslt-19991116";
#[cfg(not(feature = "legacy-algorithms"))]
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
    Valid {
        manifest_references: usize,
    },
    #[cfg(not(feature = "xslt"))]
    ValidWithManifestFailure,
    /// `SignedInfo` changed after signing: the signature is checked before any
    /// Reference, so it fails first and no Reference is dereferenced.
    TamperedSignedInfo,
    #[cfg(feature = "legacy-algorithms")]
    MissingDigestValue,
    UnsupportedSignature(&'static str),
    #[cfg(not(feature = "xslt"))]
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
        #[cfg(not(feature = "xslt"))]
        expected: Expected::UnsupportedTransform(XSLT_URI),
        #[cfg(feature = "xslt")]
        expected: Expected::Valid {
            manifest_references: 2,
        },
    },
    Case {
        name: "signature-dsa-detached.xml",
        setup: Setup::Dsa,
        expected: Expected::Valid {
            manifest_references: 0,
        },
    },
    Case {
        name: "signature-dsa-enveloped.xml",
        setup: Setup::Dsa,
        expected: Expected::Valid {
            manifest_references: 0,
        },
    },
    Case {
        name: "signature-dsa-enveloping.xml",
        setup: Setup::Dsa,
        expected: Expected::Valid {
            manifest_references: 0,
        },
    },
    Case {
        name: "signature-dsa-manifest.xml",
        setup: Setup::Dsa,
        expected: Expected::Valid {
            manifest_references: 2,
        },
    },
    Case {
        name: "signature-hmac-md5-c14n-enveloping.xml",
        setup: Setup::Hmac,
        expected: Expected::UnsupportedSignature(HMAC_MD5_URI),
    },
    Case {
        name: "signature-hmac-sha1-40-c14n-comments-detached.xml",
        setup: Setup::Hmac80,
        expected: Expected::Valid {
            manifest_references: 0,
        },
    },
    Case {
        name: "signature-hmac-sha1-40-exclusive-c14n-comments-detached.xml",
        setup: Setup::Hmac80,
        expected: Expected::Valid {
            manifest_references: 0,
        },
    },
    Case {
        name: "signature-hmac-sha1-exclusive-c14n-comments-detached.xml",
        setup: Setup::Hmac,
        expected: Expected::Valid {
            manifest_references: 0,
        },
    },
    Case {
        name: "signature-hmac-sha1-exclusive-c14n-enveloped.xml",
        setup: Setup::Hmac,
        expected: Expected::Valid {
            manifest_references: 0,
        },
    },
    Case {
        name: "signature-rsa-detached-b64-transform.xml",
        setup: Setup::Rsa,
        expected: Expected::Valid {
            manifest_references: 1,
        },
    },
    Case {
        name: "signature-rsa-detached-xpath-transform.xml",
        setup: Setup::Rsa,
        expected: Expected::Valid {
            manifest_references: 1,
        },
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
        #[cfg(not(feature = "xslt"))]
        expected: Expected::ValidWithManifestFailure,
        #[cfg(feature = "xslt")]
        expected: Expected::Valid {
            manifest_references: 1,
        },
    },
    Case {
        name: "signature-rsa-detached.xml",
        setup: Setup::Rsa,
        expected: Expected::Valid {
            manifest_references: 0,
        },
    },
    Case {
        name: "signature-rsa-enveloped-bad-digest-val.xml",
        setup: Setup::Rsa,
        expected: Expected::TamperedSignedInfo,
    },
    Case {
        name: "signature-rsa-enveloped-bad-sig.xml",
        setup: Setup::Rsa,
        #[cfg(not(feature = "legacy-algorithms"))]
        expected: Expected::UnsupportedSignature(MD5_URI),
        #[cfg(feature = "legacy-algorithms")]
        expected: Expected::MissingDigestValue,
    },
    Case {
        name: "signature-rsa-enveloped.xml",
        setup: Setup::Rsa,
        expected: Expected::Valid {
            manifest_references: 0,
        },
    },
    Case {
        name: "signature-rsa-enveloping.xml",
        setup: Setup::Rsa,
        expected: Expected::Valid {
            manifest_references: 0,
        },
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
        expected: Expected::Valid {
            manifest_references: 2,
        },
    },
    Case {
        name: "signature-rsa-xpath-transform-enveloped.xml",
        setup: Setup::Rsa,
        expected: Expected::Valid {
            manifest_references: 0,
        },
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
    assert_eq!(rest, []);
    VerificationKey {
        algorithm: SignatureAlgorithm::RsaSha1,
        public_key_bytes: certificate.public_key().raw.to_vec(),
        certificate_der: Some(der),
        name: None,
    }
}

fn policy(algorithm: SignatureAlgorithm, verify_x509_chains: bool) -> VerificationPolicy {
    let mut policy = VerificationPolicy::default();
    policy.key_trust.mode = if verify_x509_chains {
        xml_sec::policy::VerificationTrustMode::RequireTrustedKey
    } else {
        xml_sec::policy::VerificationTrustMode::CryptographicOnly
    };
    policy
        .key_trust
        .allowed_legacy_signature_algorithms
        .insert(algorithm);
    policy.key_trust.rsa_keys.minimum_modulus_bits = 1024;
    policy.key_trust.dsa_keys.minimum_modulus_bits = 1024;
    if algorithm == SignatureAlgorithm::HmacSha1 {
        // The published Phaos corpus intentionally uses a four-byte secret.
        policy.hmac.minimum_key_bits = 32;
        policy.hmac.minimum_output_bits = 40;
    }
    policy.key_trust.verify_x509_chains = verify_x509_chains;
    policy.key_trust.verification_time = xml_sec::policy::Instant::new(VERIFY_2009, 0);
    policy.uris.retrieval_methods = UriTypeSet::ALL;
    // The corpus signer compiled each stylesheet from the `<Transform>` content
    // alone, as libxmlsec1 does; read as an element of the signed document, its
    // literal results would also carry the inherited `dsig` namespace.
    #[cfg(feature = "xslt")]
    {
        policy.transforms.xslt_stylesheet_semantics =
            xml_sec::policy::XsltStylesheetSemantics::Libxmlsec1;
    }
    policy
}

fn resources() -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([
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
            // These DSA cases may select KeyValue before X509Data: the corpus
            // tests cryptographic interoperability, not authorization of that key.
            // This is a cryptographic corpus, not a certificate qualification
            // corpus: Phaos encodes KeyUsage as 03 03 07 D8 00, retaining
            // trailing zero bits forbidden for a DER named bit list by
            // X.690 (2021) 11.2.2. The negative corpus separately proves the
            // certificate path rejects it; do not relax the shared reader.
            // https://www.itu.int/rec/T-REC-X.690-202102-I/en
            let mut dsa_policy = policy(SignatureAlgorithm::DsaSha1, false);
            dsa_policy.key_trust.mode = xml_sec::policy::VerificationTrustMode::CryptographicOnly;
            let resolver = DefaultKeyResolver::new(KeyResolverConfig {
                lookup_certs: vec![certificate("dsa-cert.der")],
                trusted_certs: vec![certificate("dsa-ca-cert.der")],
                ..KeyResolverConfig::default()
            });
            VerifyContext::new()
                .policy(dsa_policy)
                .key_resolver(&resolver)
                .process_manifests(true)
                .allowed_uri_types(UriTypeSet::ALL)
                .external_resources(&resources)
                .verify(&xml)
        }
        Setup::Hmac | Setup::Hmac80 => {
            let key = HmacSha1VerificationKey::new(certificate("hmackey.bin"))
                .expect("Phaos HMAC key is valid");
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
    result: &Result<xml_sec::xmldsig::VerifyResult, DsigError>,
) -> Result<(), String> {
    let matches = match (case.expected, result) {
        (
            Expected::Valid {
                manifest_references,
            },
            Ok(result),
        ) => {
            result.status == DsigStatus::Valid
                && result.manifest_references.len() == manifest_references
                && result
                    .manifest_references
                    .iter()
                    .all(|reference| reference.status == DsigStatus::Valid)
        }
        #[cfg(not(feature = "xslt"))]
        (Expected::ValidWithManifestFailure, Ok(result)) => {
            result.status == DsigStatus::Valid
                && result.manifest_references.len() == 1
                && result.manifest_references[0].status
                    == DsigStatus::Invalid(FailureReason::ReferenceProcessingFailure {
                        ref_index: 0,
                    })
        }
        (Expected::TamperedSignedInfo, Ok(result)) => {
            result.status == DsigStatus::Invalid(FailureReason::SignatureMismatch)
                && result
                    .signed_info_references
                    .iter()
                    .all(|reference| reference.status == DsigStatus::NotProcessed)
        }
        #[cfg(feature = "legacy-algorithms")]
        (
            Expected::MissingDigestValue,
            Err(DsigError::ParseSignedInfo(ParseError::MissingElement {
                element: "DigestValue",
            })),
        ) => true,
        (
            Expected::UnsupportedSignature(uri),
            Err(DsigError::ParseSignedInfo(ParseError::UnsupportedAlgorithm { uri: actual })),
        ) => actual == uri,
        #[cfg(feature = "legacy-algorithms")]
        (
            Expected::UnsupportedSignature(uri),
            Err(DsigError::Policy(xml_sec::policy::PolicyViolation::Algorithm {
                operation: "verification",
                algorithm,
            })),
        ) => {
            algorithm == uri
                && SignatureAlgorithm::from_uri(uri)
                    .is_some_and(xml_sec::xmldsig::SignatureAlgorithm::requires_explicit_permission)
        }
        #[cfg(not(feature = "xslt"))]
        (
            Expected::UnsupportedTransform(uri),
            Err(DsigError::ParseSignedInfo(ParseError::Transform(
                xml_sec::xmldsig::TransformError::UnsupportedTransform(actual),
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
        .filter(|name| {
            name.starts_with("signature-")
                && std::path::Path::new(name)
                    .extension()
                    .is_some_and(|extension| extension == "xml")
        })
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
        .filter_map(|case| check_expected(case, &execute(case)).err())
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[cfg(feature = "xslt")]
#[test]
fn every_phaos_xslt_reference_chain_executes_with_a_caller_key() {
    // Certificate-policy refusals must not hide unexecuted XSLT reference
    // chains. Supplying a known key tests cryptography only; the exhaustive
    // suite above still tests certificate trust and bad RetrievalMethod input.
    let key = verification_key();
    let resources = resources();
    for backend in xml_sec::XmlBackend::available() {
        for (name, manifests) in [
            ("signature-big.xml", 2),
            ("signature-rsa-detached-xslt-transform.xml", 1),
            (
                "signature-rsa-detached-xslt-transform-retrieval-method.xml",
                1,
            ),
        ] {
            let result = VerifyContext::new()
                .policy(policy(SignatureAlgorithm::RsaSha1, false))
                .key(&key)
                .xml_backend(backend)
                .process_manifests(true)
                .store_pre_digest(true)
                .allowed_uri_types(UriTypeSet::ALL)
                .external_resources(&resources)
                .verify(&document(name))
                .unwrap_or_else(|error| panic!("{backend:?} {name}: {error}"));
            assert_eq!(result.status, DsigStatus::Valid, "{backend:?} {name}");
            assert_eq!(result.manifest_references.len(), manifests);
            for reference in result
                .signed_info_references
                .iter()
                .chain(&result.manifest_references)
            {
                assert_eq!(reference.status, DsigStatus::Valid, "{backend:?} {name}");
                assert!(
                    reference.pre_digest_data.is_some(),
                    "digest input was requested"
                );
            }
        }
    }
}

#[cfg(feature = "xslt")]
#[test]
fn specification_stylesheets_keep_the_inherited_namespace() {
    // Read as an element of the signed document, the stylesheet's literal results
    // copy the `dsig` binding of its `<Signature>` ancestor (XSLT 1.0 section 7.1.1),
    // which the corpus signer did not include in the digested output.
    let mut policy = policy(SignatureAlgorithm::RsaSha1, false);
    policy.transforms.xslt_stylesheet_semantics =
        xml_sec::policy::XsltStylesheetSemantics::Specification;
    let key = verification_key();
    let result = VerifyContext::new()
        .policy(policy)
        .key(&key)
        .process_manifests(true)
        .allowed_uri_types(UriTypeSet::ALL)
        .external_resources(&resources())
        .verify(&document("signature-rsa-detached-xslt-transform.xml"))
        .expect("verification runs");
    assert_eq!(result.status, DsigStatus::Valid);
    assert!(matches!(
        result.manifest_references[0].status,
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
    ));
}

#[test]
fn detached_resources_are_caller_owned_and_required() {
    // The public API never performs implicit I/O for a donor URI.
    let xml = document("signature-rsa-detached.xml");
    let key = verification_key();
    let result = VerifyContext::new()
        .policy(policy(SignatureAlgorithm::RsaSha1, false))
        .key(&key)
        .process_manifests(true)
        .allowed_uri_types(UriTypeSet::ALL)
        .external_resources(&BTreeMap::new())
        .verify(&xml)
        .expect("a missing caller resource is a verification status");
    // Fails closed as this Reference's Unavailable outcome, never a fetch.
    assert_eq!(
        result.status,
        DsigStatus::Invalid(FailureReason::ReferenceUnavailable { ref_index: 0 })
    );
    assert_eq!(
        result.signed_info_references[0].uri,
        "http://www.ietf.org/rfc/rfc3161.txt"
    );
}
