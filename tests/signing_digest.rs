use std::collections::HashSet;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::policy::SigningPolicy;
use xml_sec::xmldsig::mutation::append_signature_to_root;
use xml_sec::xmldsig::parse::{find_signature_node, parse_signed_info};
use xml_sec::xmldsig::uri::UriReferenceResolver;
use xml_sec::xmldsig::verify::process_all_references;
use xml_sec::xmldsig::{
    DEFAULT_IMPLICIT_C14N_URI, DefaultKeyResolver, DigestAlgorithm, DsigStatus,
    EcdsaP256SigningKey, EcdsaP384SigningKey, KeyInfoWriter, ReferenceBuilder, RsaSigningKey,
    SignContext, SignatureAlgorithm, SignatureBuilder, SigningDigestError, SigningError,
    SigningKey, SigningKeyError, SigningPublicKeyInfo, Transform, X509CertificateKeyInfoWriter,
    compute_reference_digest_values, fill_reference_digest_values, parse_key_info,
    validate_signing_key, verify_signature_with_pem_key,
};

fn exclusive_c14n() -> C14nAlgorithm {
    C14nAlgorithm::new(C14nMode::Exclusive1_0, false)
}

fn template_with_reference(reference: ReferenceBuilder) -> String {
    SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(reference)
        .build_template()
        .expect("valid signature template")
}

fn assert_reference_digests_verify(xml: &str) {
    let document = roxmltree::Document::parse(xml).expect("filled XML must parse");
    let signature = find_signature_node(&document).expect("Signature element");
    let signed_info_node = signature
        .children()
        .find(|node| {
            node.is_element()
                && node.tag_name().name() == "SignedInfo"
                && node.tag_name().namespace() == Some("http://www.w3.org/2000/09/xmldsig#")
        })
        .expect("SignedInfo element");
    let signed_info = parse_signed_info(signed_info_node).expect("filled SignedInfo must parse");
    let resolver = UriReferenceResolver::new(&document);
    let result = process_all_references(&signed_info.references, &resolver, signature, true)
        .expect("reference verification must run");
    assert!(result.all_valid(), "filled digest values must verify");
}

fn read_fixture(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|err| panic!("failed to read {path}: {err}"))
}

fn assert_signed_template_verifies(signed: &str, public_key_path: &str) {
    let public_key_pem = read_fixture(public_key_path);
    let verify_result = verify_signature_with_pem_key(signed, &public_key_pem, true)
        .expect("signed donor template must verify without pipeline errors");

    assert_eq!(verify_result.status, DsigStatus::Valid);
    assert!(signed.contains("<SignatureValue>"));
    assert!(!signed.contains("<DigestValue></DigestValue>"));
}

#[test]
fn rsa_signing_key_exposes_structured_public_key_info() {
    // Public-key metadata must be available without reparsing the private key in
    // each KeyInfo writer. RSA exposes SPKI plus normalized KeyValue fields.
    let private_key =
        RsaSigningKey::from_pkcs8_pem(&read_fixture("tests/fixtures/keys/rsa/rsa-2048-key.pem"))
            .expect("RSA private key fixture must parse");
    let public_key_info = private_key
        .public_key_info()
        .expect("RSA public-key info must encode");

    match public_key_info {
        SigningPublicKeyInfo::Rsa {
            spki_der,
            modulus,
            exponent,
        } => {
            assert!(!spki_der.is_empty());
            assert_eq!(modulus.len(), 256);
            assert_eq!(exponent, [1, 0, 1]);
        }
        SigningPublicKeyInfo::Ec { .. } => panic!("RSA key must expose RSA public-key info"),
        _ => panic!("RSA key must expose known public-key info"),
    }
}

#[test]
fn signing_key_preflight_rejects_verify_only_algorithms() {
    // Candidate search must not classify RSA-SHA1 as usable and then fail only
    // after choosing that key; the shared preflight owns signing capability.
    let key =
        RsaSigningKey::from_pkcs8_pem(&read_fixture("tests/fixtures/keys/rsa/rsa-2048-key.pem"))
            .expect("RSA private key fixture must parse");
    let policy = SigningPolicy::default();

    assert!(matches!(
        validate_signing_key(&key, SignatureAlgorithm::RsaSha1, &policy),
        Err(SigningError::Key(
            SigningKeyError::UnsupportedAlgorithm { .. }
        ))
    ));
    validate_signing_key(&key, SignatureAlgorithm::RsaSha256, &policy)
        .expect("secure signing algorithm must remain usable");
}

#[test]
fn ecdsa_signing_keys_expose_curve_public_key_info() {
    // ECDSA metadata includes the named curve and uncompressed SEC1 point needed
    // by XMLDSig 1.1 ECKeyValue writers.
    let p256_key = EcdsaP256SigningKey::from_pkcs8_pem(&read_fixture(
        "tests/fixtures/keys/ec/ec-prime256v1-key.pem",
    ))
    .expect("P-256 private key fixture must parse");
    let p384_key = EcdsaP384SigningKey::from_pkcs8_pem(&read_fixture(
        "tests/fixtures/keys/ec/ec-prime384v1-key.pem",
    ))
    .expect("P-384 private key fixture must parse");

    for (public_key_info, expected_oid, expected_len) in [
        (
            p256_key
                .public_key_info()
                .expect("P-256 public-key info must encode"),
            "1.2.840.10045.3.1.7",
            65,
        ),
        (
            p384_key
                .public_key_info()
                .expect("P-384 public-key info must encode"),
            "1.3.132.0.34",
            97,
        ),
    ] {
        match public_key_info {
            SigningPublicKeyInfo::Ec {
                spki_der,
                curve_oid,
                public_key,
            } => {
                assert!(!spki_der.is_empty());
                assert_eq!(curve_oid, expected_oid);
                assert_eq!(public_key.len(), expected_len);
                assert_eq!(public_key[0], 0x04);
            }
            SigningPublicKeyInfo::Rsa { .. } => panic!("EC key must expose EC public-key info"),
            _ => panic!("EC key must expose known public-key info"),
        }
    }
}

#[test]
fn signing_keys_reject_unsupported_signature_algorithms() {
    // The trait abstraction must fail closed when the caller asks a key to
    // produce an incompatible XMLDSig SignatureMethod.
    let rsa_key =
        RsaSigningKey::from_pkcs8_pem(&read_fixture("tests/fixtures/keys/rsa/rsa-2048-key.pem"))
            .expect("RSA private key fixture must parse");
    let p256_key = EcdsaP256SigningKey::from_pkcs8_pem(&read_fixture(
        "tests/fixtures/keys/ec/ec-prime256v1-key.pem",
    ))
    .expect("P-256 private key fixture must parse");
    for (result, expected_uri) in [
        (
            rsa_key.sign(SignatureAlgorithm::EcdsaSha256, b"signed-info"),
            SignatureAlgorithm::EcdsaSha256.uri(),
        ),
        (
            p256_key.sign(SignatureAlgorithm::RsaSha256, b"signed-info"),
            SignatureAlgorithm::RsaSha256.uri(),
        ),
    ] {
        assert!(matches!(
            result,
            Err(SigningKeyError::UnsupportedAlgorithm { uri }) if uri == expected_uri
        ));
    }
}

#[test]
fn signing_facade_rejects_malformed_key_specific_signature_output() {
    // Custom signing keys cannot bypass fixed-width RSA and XMLDSig ECDSA
    // output framing before SignatureValue serialization.
    struct FixedOutputSigningKey {
        output: Vec<u8>,
        public_key: SigningPublicKeyInfo,
    }

    impl SigningKey for FixedOutputSigningKey {
        fn sign(
            &self,
            _algorithm: SignatureAlgorithm,
            _canonical_signed_info: &[u8],
        ) -> Result<Vec<u8>, SigningKeyError> {
            Ok(self.output.clone())
        }

        fn public_key_info(&self) -> Result<SigningPublicKeyInfo, SigningKeyError> {
            Ok(self.public_key.clone())
        }
    }

    let xml = "<root><payload ID=\"payload\">hello</payload></root>";
    let cases = [
        (
            SignatureAlgorithm::RsaSha256,
            SigningPublicKeyInfo::Rsa {
                spki_der: Vec::new(),
                modulus: vec![0x80_u8; 256],
                exponent: vec![1, 0, 1],
            },
            255,
            256,
        ),
        (
            SignatureAlgorithm::EcdsaSha256,
            SigningPublicKeyInfo::Ec {
                spki_der: Vec::new(),
                curve_oid: "1.2.840.10045.3.1.7",
                public_key: [vec![4], vec![1_u8; 64]].concat(),
            },
            63,
            64,
        ),
    ];

    for (algorithm, public_key, actual, expected) in cases {
        let key = FixedOutputSigningKey {
            output: vec![1_u8; actual],
            public_key,
        };
        let builder = SignatureBuilder::new(exclusive_c14n(), algorithm).add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#payload")
                .transform(Transform::C14n(exclusive_c14n())),
        );

        assert!(matches!(
            SignContext::new(&key).sign_with_builder(xml, &builder),
            Err(SigningError::InvalidSignatureOutputLength {
                expected: expected_len,
                actual: actual_len,
            }) if expected_len == expected && actual_len == actual
        ));
    }
}

#[test]
fn signing_policy_rejects_weak_rsa_key_before_provider_dispatch() {
    struct CountingSigningKey {
        calls: Arc<AtomicUsize>,
        modulus: Vec<u8>,
        exponent: Vec<u8>,
    }

    impl SigningKey for CountingSigningKey {
        fn sign(
            &self,
            _algorithm: SignatureAlgorithm,
            _canonical_signed_info: &[u8],
        ) -> Result<Vec<u8>, SigningKeyError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(vec![1_u8; self.modulus.len()])
        }

        fn public_key_info(&self) -> Result<SigningPublicKeyInfo, SigningKeyError> {
            Ok(SigningPublicKeyInfo::Rsa {
                spki_der: Vec::new(),
                modulus: self.modulus.clone(),
                exponent: self.exponent.clone(),
            })
        }
    }

    let builder = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#payload")
                .transform(Transform::C14n(exclusive_c14n())),
        );

    for (modulus_bytes, actual_bits) in [(128, 1024), (1025, 8200)] {
        let calls = Arc::new(AtomicUsize::new(0));
        let key = CountingSigningKey {
            calls: Arc::clone(&calls),
            modulus: vec![0x80_u8; modulus_bytes],
            exponent: vec![1, 0, 1],
        };
        assert!(matches!(
            SignContext::new(&key).sign_with_builder(
                "<root><payload ID=\"payload\">hello</payload></root>",
                &builder
            ),
            Err(SigningError::Policy(
                xml_sec::policy::PolicyViolation::KeySize {
                    operation: "signing",
                    minimum_bits: 2048,
                    maximum_bits: 8192,
                    actual_bits: observed_bits,
                    ..
                }
            )) if observed_bits == actual_bits
        ));
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    let calls = Arc::new(AtomicUsize::new(0));
    let key = CountingSigningKey {
        calls: Arc::clone(&calls),
        modulus: vec![0x80_u8; 256],
        exponent: vec![2],
    };
    assert!(matches!(
        SignContext::new(&key).sign_with_builder(
            "<root><payload ID=\"payload\">hello</payload></root>",
            &builder
        ),
        Err(SigningError::Policy(
            xml_sec::policy::PolicyViolation::InvalidKeyMaterial {
                operation: "signing",
                ..
            }
        ))
    ));
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

#[test]
fn x509_key_info_writer_uses_structured_public_key_info() {
    struct PublicInfoFailingKey;

    impl SigningKey for PublicInfoFailingKey {
        fn sign(
            &self,
            _algorithm: SignatureAlgorithm,
            _canonical_signed_info: &[u8],
        ) -> Result<Vec<u8>, SigningKeyError> {
            unreachable!("KeyInfo writer must not sign while serializing metadata");
        }

        fn public_key_info(&self) -> Result<SigningPublicKeyInfo, SigningKeyError> {
            Err(SigningKeyError::PublicKeyEncodingFailed)
        }
    }

    let certificate = X509CertificateKeyInfoWriter::from_pem(&read_fixture(
        "tests/fixtures/keys/rsa/rsa-2048-cert.pem",
    ))
    .expect("RSA certificate fixture must parse");
    let err = certificate
        .write_key_info(&PublicInfoFailingKey)
        .expect_err("writer must surface public-key info extraction failures");

    assert!(matches!(
        err,
        xml_sec::xmldsig::KeyInfoWriteError::SigningKey(SigningKeyError::PublicKeyEncodingFailed)
    ));
}

#[test]
fn fills_single_same_document_reference_digest() {
    // Signing templates start with an empty DigestValue; the digest pass must
    // compute bytes from the referenced node and make the template parseable by
    // the stricter verification parser.
    let template = template_with_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("#payload")
            .transform(Transform::C14n(exclusive_c14n())),
    );
    let xml = append_signature_to_root(
        "<root><payload ID=\"payload\">hello</payload></root>",
        &template,
    )
    .expect("append signature");

    let digests = compute_reference_digest_values(&xml).expect("compute digest");
    assert_eq!(digests.len(), 1);
    assert_eq!(digests[0].index, 0);
    assert_eq!(digests[0].uri, "#payload");
    assert_eq!(digests[0].digest_method, DigestAlgorithm::Sha256);
    assert!(!digests[0].digest_value.is_empty());

    let filled = fill_reference_digest_values(&xml).expect("fill digest values");
    assert_reference_digests_verify(&filled);
}

#[test]
fn preserves_multiple_reference_digest_order() {
    // DigestValue replacement is positional; this prevents accidentally sorting
    // or otherwise normalizing Reference order before the SignedInfo pass.
    let template = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256).uri("#first"))
        .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha384).uri("#second"))
        .build_template()
        .expect("valid signature template");
    let xml = append_signature_to_root(
        "<root><first ID=\"first\">one</first><second ID=\"second\">two</second></root>",
        &template,
    )
    .expect("append signature");

    let digests = compute_reference_digest_values(&xml).expect("compute digests");
    assert_eq!(digests.len(), 2);
    assert_eq!(digests[0].index, 0);
    assert_eq!(digests[0].uri, "#first");
    assert_eq!(digests[0].digest_method, DigestAlgorithm::Sha256);
    assert_eq!(digests[1].index, 1);
    assert_eq!(digests[1].uri, "#second");
    assert_eq!(digests[1].digest_method, DigestAlgorithm::Sha384);
    assert_ne!(digests[0].digest_value, digests[1].digest_value);

    let filled = fill_reference_digest_values(&xml).expect("fill digest values");
    assert_reference_digests_verify(&filled);
}

#[test]
fn public_digest_helpers_target_the_last_signature() {
    // These public helpers predate indexed signing and intentionally operate on
    // the last template, matching append-then-fill callers with existing signatures.
    let first = template_with_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("#first")
            .transform(Transform::C14n(exclusive_c14n())),
    );
    let second = template_with_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("#second")
            .transform(Transform::C14n(exclusive_c14n())),
    );
    let with_first = append_signature_to_root(
        "<root><payload ID=\"first\">one</payload><payload ID=\"second\">two</payload></root>",
        &first,
    )
    .expect("first signature template must append");
    let xml = append_signature_to_root(&with_first, &second)
        .expect("second signature template must append");

    let digests = compute_reference_digest_values(&xml).expect("last digest must compute");
    let filled = fill_reference_digest_values(&xml).expect("last digest must fill");
    let document = roxmltree::Document::parse(&filled).expect("filled XML must parse");
    let signatures = document
        .descendants()
        .filter(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "Signature")))
        .collect::<Vec<_>>();
    assert_eq!(signatures.len(), 2);
    assert_eq!(digests.len(), 1);
    assert_eq!(digests[0].uri, "#second");
    assert_eq!(
        signatures[0]
            .descendants()
            .find(|node| {
                node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "DigestValue"))
            })
            .and_then(|node| node.text()),
        None
    );
    assert_eq!(
        signatures[1]
            .descendants()
            .find(|node| {
                node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "DigestValue"))
            })
            .and_then(|node| node.text()),
        Some(digests[0].digest_value.as_str())
    );
}

#[test]
fn sign_context_targets_the_last_signature_template_by_default() {
    // Core callers commonly append a new template to a document that already
    // contains signatures. The default must sign that newly appended template.
    let private_key =
        RsaSigningKey::from_pkcs8_pem(&read_fixture("tests/fixtures/keys/rsa/rsa-2048-key.pem"))
            .expect("RSA private key fixture must parse");
    let first = template_with_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("#first")
            .transform(Transform::C14n(exclusive_c14n())),
    );
    let second = template_with_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("#second")
            .transform(Transform::C14n(exclusive_c14n())),
    );
    let with_first = append_signature_to_root(
        "<root><payload ID=\"first\">one</payload><payload ID=\"second\">two</payload></root>",
        &first,
    )
    .expect("first signature template must append");
    let xml = append_signature_to_root(&with_first, &second)
        .expect("second signature template must append");

    let signed = SignContext::new(&private_key)
        .sign_template(&xml)
        .expect("last signature template must sign");
    let document = roxmltree::Document::parse(&signed).expect("signed XML must parse");
    let values = document
        .descendants()
        .filter(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "SignatureValue")))
        .map(|node| node.text().unwrap_or_default().trim().to_owned())
        .collect::<Vec<_>>();

    assert!(values[0].is_empty());
    assert!(!values[1].is_empty());
}

#[test]
fn computes_enveloped_signature_digest_for_whole_document() {
    // URI="" signs the full document; the enveloped transform must exclude the
    // generated Signature subtree before digesting, matching verification.
    let template = template_with_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha512)
            .uri("")
            .transform(Transform::Enveloped)
            .transform(Transform::C14n(exclusive_c14n())),
    );
    let xml = append_signature_to_root("<root><payload>hello</payload></root>", &template)
        .expect("append signature");

    let filled = fill_reference_digest_values(&xml).expect("fill digest values");
    assert_reference_digests_verify(&filled);
}

#[test]
fn signing_policy_rejects_disallowed_reference_transform() {
    // A signing policy is an execution boundary, not advisory metadata: every
    // template transform must be accepted before any digest work runs.
    let private_key =
        RsaSigningKey::from_pkcs8_pem(&read_fixture("tests/fixtures/keys/rsa/rsa-2048-key.pem"))
            .expect("RSA private key fixture must parse");
    let template = template_with_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("")
            .transform(Transform::Enveloped),
    );
    let xml =
        append_signature_to_root("<root><payload/></root>", &template).expect("append signature");
    let policy = SigningPolicy {
        transforms: Some(HashSet::from([exclusive_c14n().uri().to_owned()])),
        ..SigningPolicy::default()
    };

    assert!(matches!(
        SignContext::new(&private_key)
            .policy(policy)
            .sign_template(&xml),
        Err(SigningError::Digest(SigningDigestError::Policy(_)))
    ));
}

#[test]
fn signing_policy_bounds_document_bytes_before_parsing() {
    // Signing must reject a large low-node document at the same policy
    // boundary as verification rather than parsing it before work limits run.
    let private_key =
        RsaSigningKey::from_pkcs8_pem(&read_fixture("tests/fixtures/keys/rsa/rsa-2048-key.pem"))
            .expect("RSA private key fixture must parse");
    let xml = format!("<root>{}</root>", "x".repeat(1_024));
    let policy = SigningPolicy {
        resources: xml_sec::policy::ResourcePolicy {
            max_xml_document_bytes: xml.len() - 1,
            ..xml_sec::policy::ResourcePolicy::default()
        },
        ..SigningPolicy::default()
    };

    assert!(matches!(
        SignContext::new(&private_key)
            .policy(policy)
            .sign_template(&xml),
        Err(SigningError::Policy(
            xml_sec::policy::PolicyViolation::ResourceLimit {
                resource: "XML document",
                maximum,
                actual,
            }
        )) if maximum == xml.len() - 1 && actual == xml.len()
    ));
}

#[test]
fn signing_policy_rechecks_document_bytes_after_mutation() {
    // Filling DigestValue and SignatureValue grows the caller's document, so
    // the same byte ceiling must cover intermediate and returned XML.
    let private_key =
        RsaSigningKey::from_pkcs8_pem(&read_fixture("tests/fixtures/keys/rsa/rsa-2048-key.pem"))
            .expect("RSA private key fixture must parse");
    let template = template_with_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("#payload")
            .transform(Transform::C14n(exclusive_c14n())),
    );
    let xml = append_signature_to_root("<root><payload ID=\"payload\"/></root>", &template)
        .expect("append signature");
    let policy = SigningPolicy {
        resources: xml_sec::policy::ResourcePolicy {
            max_xml_document_bytes: xml.len(),
            ..xml_sec::policy::ResourcePolicy::default()
        },
        ..SigningPolicy::default()
    };

    assert!(matches!(
        SignContext::new(&private_key)
            .policy(policy)
            .sign_template(&xml),
        Err(SigningError::Policy(
            xml_sec::policy::PolicyViolation::ResourceLimit {
                resource: "XML document",
                maximum,
                actual,
            }
        )) if maximum == xml.len() && actual > maximum
    ));
}

#[test]
fn signing_policy_bounds_key_info_writer_bytes_before_parsing() {
    // Writer output is untrusted XML input. Its byte ceiling must win before
    // parsing, even when an oversized fragment is also malformed at its tail.
    struct OversizedWriter(String);

    impl KeyInfoWriter for OversizedWriter {
        fn write_key_info(
            &self,
            _signing_key: &dyn SigningKey,
        ) -> Result<String, xml_sec::xmldsig::KeyInfoWriteError> {
            Ok(self.0.clone())
        }
    }

    let private_key =
        RsaSigningKey::from_pkcs8_pem(&read_fixture("tests/fixtures/keys/rsa/rsa-2048-key.pem"))
            .expect("RSA private key fixture must parse");
    let template = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .key_info(true)
        .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256).uri(""))
        .build_template()
        .expect("valid signature template");
    let xml = append_signature_to_root("<root/>", &template).expect("append signature");
    let maximum = xml.len() + 64;
    let writer = OversizedWriter(format!("<KeyName>{}", "x".repeat(maximum)));
    let writer_len = writer.0.len();
    let policy = SigningPolicy {
        resources: xml_sec::policy::ResourcePolicy {
            max_xml_document_bytes: maximum,
            ..xml_sec::policy::ResourcePolicy::default()
        },
        ..SigningPolicy::default()
    };

    assert!(matches!(
        SignContext::new(&private_key)
            .policy(policy)
            .key_info_writer(&writer)
            .sign_template(&xml),
        Err(SigningError::Policy(
            xml_sec::policy::PolicyViolation::ResourceLimit {
                resource: "XML document",
                maximum: observed_maximum,
                actual,
            }
        )) if observed_maximum == maximum && actual == writer_len
    ));
}

#[test]
fn signing_policy_shares_canonicalization_budget_with_signed_info() {
    // Reference transforms and SignedInfo consume one operation-wide C14N
    // allowance, preventing a template from multiplying the configured cap.
    let private_key =
        RsaSigningKey::from_pkcs8_pem(&read_fixture("tests/fixtures/keys/rsa/rsa-2048-key.pem"))
            .expect("RSA private key fixture must parse");
    let template = template_with_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("#payload")
            .transform(Transform::C14n(exclusive_c14n())),
    );
    let xml = append_signature_to_root(
        "<root><payload ID=\"payload\">x</payload></root>",
        &template,
    )
    .expect("append signature");
    let constrained = SigningPolicy {
        resources: xml_sec::policy::ResourcePolicy {
            // The reference serializes below this bound; SignedInfo pushes the
            // operation-wide total over it.
            max_canonicalized_bytes: 64,
            ..xml_sec::policy::ResourcePolicy::default()
        },
        ..SigningPolicy::default()
    };

    assert!(matches!(
        SignContext::new(&private_key)
            .policy(constrained)
            .sign_template(&xml),
        Err(SigningError::Digest(SigningDigestError::Transform(_)))
    ));

    let sufficient = SigningPolicy {
        resources: xml_sec::policy::ResourcePolicy {
            max_canonicalized_bytes: 4_096,
            ..xml_sec::policy::ResourcePolicy::default()
        },
        ..SigningPolicy::default()
    };
    SignContext::new(&private_key)
        .policy(sufficient)
        .sign_template(&xml)
        .expect("the same reference must sign when the combined budget fits");
}

#[test]
fn signing_policy_applies_xml_base_budget_to_signed_info_c14n() {
    // SignedInfo canonicalization is part of the same operation as Reference
    // transforms and must not replace the compiled XML Base policy with hard
    // defaults when inherited context is reconstructed.
    let private_key =
        RsaSigningKey::from_pkcs8_pem(&read_fixture("tests/fixtures/keys/rsa/rsa-2048-key.pem"))
            .expect("RSA private key fixture must parse");
    let template =
        template_with_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256).uri("#payload"));
    let xml = append_signature_to_root(
        "<root><payload ID=\"payload\">x</payload></root>",
        &template,
    )
    .expect("append signature")
    .replacen(
        "http://www.w3.org/2001/10/xml-exc-c14n#",
        "http://www.w3.org/2006/12/xml-c14n11",
        1,
    )
    .replace(
        "<Signature xmlns=",
        "<outer xml:base=\"one/\"><inner xml:base=\"two/\"><Signature xmlns=",
    )
    .replace("</Signature>", "</Signature></inner></outer>");
    let policy = SigningPolicy {
        resources: xml_sec::policy::ResourcePolicy {
            max_xml_base_components: 1,
            ..xml_sec::policy::ResourcePolicy::default()
        },
        ..SigningPolicy::default()
    };

    let result = SignContext::new(&private_key)
        .policy(policy)
        .sign_template(&xml);
    assert!(
        matches!(
            result,
            Err(SigningError::Canonicalization(
                xml_sec::c14n::C14nError::XmlBaseComponentsTooLarge { max: 1, actual: 2 }
            ))
        ),
        "unexpected signing result: {result:?}"
    );
}

#[test]
fn signing_policy_covers_implicit_and_signed_info_canonicalization() {
    // The transform allowlist covers algorithms executed implicitly by the
    // pipeline, not only explicit Reference/Transforms children.
    let private_key =
        RsaSigningKey::from_pkcs8_pem(&read_fixture("tests/fixtures/keys/rsa/rsa-2048-key.pem"))
            .expect("RSA private key fixture must parse");
    let template =
        template_with_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256).uri("#payload"));
    let xml = append_signature_to_root(
        "<root><payload ID=\"payload\">x</payload></root>",
        &template,
    )
    .expect("append signature");

    let implicit_disallowed = SigningPolicy {
        transforms: Some(HashSet::from([exclusive_c14n().uri().to_owned()])),
        ..SigningPolicy::default()
    };
    assert!(matches!(
        SignContext::new(&private_key)
            .policy(implicit_disallowed)
            .sign_template(&xml),
        Err(SigningError::Digest(SigningDigestError::Policy(_)))
    ));

    let signed_info_disallowed = SigningPolicy {
        transforms: Some(HashSet::from([DEFAULT_IMPLICIT_C14N_URI.to_owned()])),
        ..SigningPolicy::default()
    };
    assert!(matches!(
        SignContext::new(&private_key)
            .policy(signed_info_disallowed)
            .sign_template(&xml),
        Err(SigningError::Policy(xml_sec::policy::PolicyViolation::Algorithm {
            operation: "SignedInfo canonicalization",
            algorithm,
        })) if algorithm == exclusive_c14n().uri()
    ));
}

#[test]
fn signing_internal_dtd_policy_reaches_builder_and_mutation_reparses() {
    // The parser opt-in is operation-wide: source validation, digest mutation,
    // SignedInfo canonicalization, and final mutation must agree on DTD policy.
    let private_key =
        RsaSigningKey::from_pkcs8_pem(&read_fixture("tests/fixtures/keys/rsa/rsa-2048-key.pem"))
            .expect("RSA private key fixture must parse");
    let builder = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#payload")
                .transform(Transform::C14n(exclusive_c14n())),
        );
    let xml = "<!DOCTYPE root [<!ENTITY value 'signed'>]><root><payload ID=\"payload\">&value;</payload></root>";

    assert!(matches!(
        SignContext::new(&private_key).sign_with_builder(xml, &builder),
        Err(SigningError::XmlMutation(
            xml_sec::xmldsig::mutation::XmlMutationError::XmlParse(roxmltree::Error::DtdDetected)
        ))
    ));

    let mut policy = SigningPolicy::default();
    policy.xml.allow_internal_dtd = true;
    let signed = SignContext::new(&private_key)
        .policy(policy)
        .sign_with_builder(xml, &builder)
        .expect("internal-DTD opt-in must reach every signing parse and reparse");
    assert!(!signed.contains("<DigestValue></DigestValue>"));
    assert!(!signed.contains("<SignatureValue></SignatureValue>"));
}

#[test]
fn fills_only_signed_info_reference_digest_values() {
    // Manifests can contain their own DigestValue elements inside the same
    // Signature. Signing the outer SignedInfo must not treat those as template
    // reference slots or overwrite their existing values.
    let template = template_with_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("#payload")
            .transform(Transform::C14n(exclusive_c14n())),
    );
    let template = template.replace(
        "</Signature>",
        "<Object><Manifest><Reference URI=\"#manifest-payload\"><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>keep-manifest-digest</DigestValue></Reference></Manifest></Object></Signature>",
    );
    let xml = append_signature_to_root(
        "<root><payload ID=\"payload\">hello</payload><manifest-payload ID=\"manifest-payload\">manifest</manifest-payload></root>",
        &template,
    )
    .expect("append signature");

    let filled = fill_reference_digest_values(&xml).expect("fill only SignedInfo digest values");

    assert!(filled.contains("<DigestValue>keep-manifest-digest</DigestValue>"));
    assert_reference_digests_verify(&filled);
}

#[test]
fn rejects_reference_without_uri() {
    // External/object reference support is not implicit: signing must know what
    // bytes are being digested, so an omitted URI fails before mutation.
    let template = template_with_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256));
    let xml = append_signature_to_root("<root><payload>hello</payload></root>", &template)
        .expect("append signature");

    let err = compute_reference_digest_values(&xml).expect_err("missing URI must fail");
    assert!(
        matches!(err, SigningDigestError::InvalidStructure(message) if message.contains("URI"))
    );
}

#[test]
fn validates_reference_elements_before_reporting_the_cardinality_limit() {
    // A foreign child after 64 valid References is a structural violation, not
    // a 65th Reference, and must retain the precise fail-closed error contract.
    let references = (0..64)
        .map(|_| {
            r#"<Reference URI=""><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue/></Reference>"#
        })
        .collect::<String>();
    let xml = format!(
        r#"<root><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>{references}<NotAReference/></SignedInfo><SignatureValue/></Signature></root>"#
    );

    let error = compute_reference_digest_values(&xml)
        .expect_err("foreign SignedInfo child must fail structural validation");

    assert!(
        matches!(error, SigningDigestError::InvalidStructure(ref message) if message.contains("Reference"))
    );
    assert!(!error.to_string().contains("more than 64"));
}

#[test]
fn signing_template_bounds_xpath_expressions_across_references() {
    // Signing has a dedicated template parser because DigestValue may be empty.
    // It must share the verifier/parser aggregate XPath contract rather than
    // resetting the budget for each Reference.
    let filters = r#"<XPath xmlns="http://www.w3.org/2002/06/xmldsig-filter2" Filter="intersect">true()</XPath>"#
        .repeat(64);
    let filter_transform = format!(
        r#"<Transform Algorithm="http://www.w3.org/2002/06/xmldsig-filter2">{filters}</Transform>"#
    );
    let max_transforms = filter_transform.repeat(64);
    let references = format!(
        r##"<Reference URI="#item-0"><Transforms>{max_transforms}</Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue/></Reference><Reference URI="#item-1"><Transforms><Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><XPath>true()</XPath></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue/></Reference>"##
    );
    let xml = format!(
        r#"<root><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>{references}</SignedInfo><SignatureValue/></Signature></root>"#
    );

    let error = compute_reference_digest_values(&xml)
        .expect_err("signing parser must enforce the signature-wide XPath budget");

    assert!(
        error
            .to_string()
            .contains("signature-wide XPath expression budget")
    );
}

#[test]
fn rejects_sha1_digest_for_signing_template() {
    // SHA-1 remains verify-only. This manually crafted template bypasses the
    // builder, so the digest pass must enforce the same policy before signing.
    let xml = r##"<root><payload ID="payload">hello</payload><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#payload"><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue/></Reference></SignedInfo><SignatureValue/></Signature></root>"##;

    let err = compute_reference_digest_values(xml).expect_err("SHA-1 signing digest must fail");
    assert!(matches!(
        err,
        SigningDigestError::SigningAlgorithmDisabled {
            uri: "http://www.w3.org/2000/09/xmldsig#sha1"
        }
    ));
}

#[test]
fn signs_rsa_sha256_template_and_verifies_round_trip() {
    // Full signing pipeline: append template, compute Reference digest,
    // canonicalize SignedInfo, RSA-sign it, fill SignatureValue, then verify
    // the final XML through the existing end-to-end verifier.
    let private_key =
        RsaSigningKey::from_pkcs8_pem(&read_fixture("tests/fixtures/keys/rsa/rsa-2048-key.pem"))
            .expect("RSA private key fixture must parse");
    let public_key_pem = read_fixture("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    let builder = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("")
                .transform(Transform::Enveloped)
                .transform(Transform::C14n(exclusive_c14n())),
        );

    let signed = SignContext::new(&private_key)
        .sign_with_builder("<root><payload>hello</payload></root>", &builder)
        .expect("RSA signing pipeline must succeed");
    let verify_result = verify_signature_with_pem_key(&signed, &public_key_pem, true)
        .expect("signed RSA XML must verify without pipeline errors");

    assert_eq!(verify_result.status, DsigStatus::Valid);
    assert!(signed.contains("<SignatureValue>"));
    assert!(!signed.contains("<DigestValue></DigestValue>"));
}

#[test]
fn x509_key_info_writer_serializes_certificate_data() {
    // The writer emits XMLDSig X509Data child content, not escaped text, so the
    // existing KeyInfo parser must be able to consume it directly.
    let certificate = X509CertificateKeyInfoWriter::from_pem(&read_fixture(
        "tests/fixtures/keys/rsa/rsa-2048-cert.pem",
    ))
    .expect("RSA certificate fixture must parse");
    let key_info_xml = format!(
        "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">{}</KeyInfo>",
        certificate
            .write_key_info(
                &RsaSigningKey::from_pkcs8_pem(&read_fixture(
                    "tests/fixtures/keys/rsa/rsa-2048-key.pem",
                ))
                .expect("RSA private key fixture must parse"),
            )
            .expect("write KeyInfo")
    );
    let doc = roxmltree::Document::parse(&key_info_xml).expect("writer output must parse");
    let key_info = parse_key_info(doc.root_element()).expect("writer output must parse as KeyInfo");

    assert_eq!(key_info.sources.len(), 1);
}

#[test]
fn signs_rsa_template_with_embedded_x509_key_info() {
    // KeyInfo is outside SignedInfo, but SAML verifiers commonly need the
    // embedded signing certificate to resolve the public key. This verifies the
    // writer path through the existing DefaultKeyResolver.
    let private_key =
        RsaSigningKey::from_pkcs8_pem(&read_fixture("tests/fixtures/keys/rsa/rsa-2048-key.pem"))
            .expect("RSA private key fixture must parse");
    let key_info_writer = X509CertificateKeyInfoWriter::from_pem(&read_fixture(
        "tests/fixtures/keys/rsa/rsa-2048-cert.pem",
    ))
    .expect("RSA certificate fixture must parse");
    let builder = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .key_info(true)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#payload")
                .transform(Transform::C14n(exclusive_c14n())),
        );

    let signed = SignContext::new(&private_key)
        .key_info_writer(&key_info_writer)
        .sign_with_builder(
            "<root><payload ID=\"payload\">hello</payload></root>",
            &builder,
        )
        .expect("RSA signing with KeyInfo must succeed");
    let resolver = DefaultKeyResolver::default();
    let verify_result = xml_sec::xmldsig::VerifyContext::new()
        .key_resolver(&resolver)
        .verify(&signed)
        .expect("embedded certificate KeyInfo must resolve");

    assert_eq!(verify_result.status, DsigStatus::Valid);
    assert!(signed.contains("<X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"));
    assert!(signed.contains("<X509Certificate>"));
}

#[test]
fn key_info_writer_populates_signed_key_info_before_reference_digests() {
    // KeyInfo may itself be a signed reference. Populate its template source
    // before digesting so the final embedded certificate is what was signed.
    let private_key =
        RsaSigningKey::from_pkcs8_pem(&read_fixture("tests/fixtures/keys/rsa/rsa-2048-key.pem"))
            .expect("RSA private key fixture must parse");
    let key_info_writer = X509CertificateKeyInfoWriter::from_pem(&read_fixture(
        "tests/fixtures/keys/rsa/rsa-2048-cert.pem",
    ))
    .expect("RSA certificate fixture must parse");
    let template = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .key_info(true)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#payload")
                .transform(Transform::C14n(exclusive_c14n())),
        )
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#key-info")
                .transform(Transform::C14n(exclusive_c14n())),
        )
        .build_template()
        .expect("valid signature template")
        .replace(
            "<KeyInfo/>",
            "<KeyInfo Id=\"key-info\"><X509Data/></KeyInfo>",
        );
    let xml = append_signature_to_root(
        "<root><payload ID=\"payload\">hello</payload></root>",
        &template,
    )
    .expect("append signature");

    let signed = SignContext::new(&private_key)
        .key_info_writer(&key_info_writer)
        .sign_template(&xml)
        .expect("signed KeyInfo template must succeed");
    let result = xml_sec::xmldsig::VerifyContext::new()
        .key_resolver(&DefaultKeyResolver::default())
        .verify(&signed)
        .expect("signed KeyInfo reference must verify without pipeline errors");

    assert_eq!(result.status, DsigStatus::Valid);
    let document = roxmltree::Document::parse(&signed).expect("signed XML must parse");
    let certificates = document
        .descendants()
        .filter(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "X509Certificate")))
        .collect::<Vec<_>>();
    assert_eq!(certificates.len(), 1);
    assert!(certificates[0].text().is_some_and(|text| !text.is_empty()));
}

#[test]
fn key_info_writer_accepts_multiple_direct_child_fragments() {
    // KeyInfoWriter returns child content, so sibling sources are valid output
    // and must be merged without requiring a synthetic single root from callers.
    struct MultiSourceWriter(X509CertificateKeyInfoWriter);

    impl KeyInfoWriter for MultiSourceWriter {
        fn write_key_info(
            &self,
            signing_key: &dyn SigningKey,
        ) -> Result<String, xml_sec::xmldsig::KeyInfoWriteError> {
            Ok(format!(
                "<KeyName xmlns=\"{}\">selected</KeyName>{}",
                "http://www.w3.org/2000/09/xmldsig#",
                self.0.write_key_info(signing_key)?
            ))
        }
    }

    let private_key =
        RsaSigningKey::from_pkcs8_pem(&read_fixture("tests/fixtures/keys/rsa/rsa-2048-key.pem"))
            .expect("RSA private key fixture must parse");
    let writer = MultiSourceWriter(
        X509CertificateKeyInfoWriter::from_pem(&read_fixture(
            "tests/fixtures/keys/rsa/rsa-2048-cert.pem",
        ))
        .expect("RSA certificate fixture must parse"),
    );
    let builder = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .key_info(true)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#payload")
                .transform(Transform::C14n(exclusive_c14n())),
        );

    let signed = SignContext::new(&private_key)
        .key_info_writer(&writer)
        .sign_with_builder(
            "<root><payload ID=\"payload\">hello</payload></root>",
            &builder,
        )
        .expect("multiple KeyInfo child fragments must be accepted");
    let result = xml_sec::xmldsig::VerifyContext::new()
        .key_resolver(&DefaultKeyResolver::default())
        .verify(&signed)
        .expect("writer certificate must resolve");

    assert_eq!(result.status, DsigStatus::Valid);
    assert!(signed.contains(">selected</KeyName>"));
}

#[test]
fn key_info_writer_replaces_stale_cryptographic_sources() {
    // Writer-provided key material is authoritative. Keeping an older source
    // first would make the default resolver verify with the wrong public key.
    let stale_key =
        RsaSigningKey::from_pkcs8_pem(&read_fixture("tests/fixtures/keys/rsa/rsa-4096-key.pem"))
            .expect("stale RSA private key fixture must parse");
    let stale_writer = X509CertificateKeyInfoWriter::from_pem(&read_fixture(
        "tests/fixtures/keys/rsa/rsa-4096-cert.pem",
    ))
    .expect("stale RSA certificate fixture must parse");
    let stale_source = stale_writer
        .write_key_info(&stale_key)
        .expect("stale KeyInfo source must render");
    let private_key =
        RsaSigningKey::from_pkcs8_pem(&read_fixture("tests/fixtures/keys/rsa/rsa-2048-key.pem"))
            .expect("RSA private key fixture must parse");
    let writer = X509CertificateKeyInfoWriter::from_pem(&read_fixture(
        "tests/fixtures/keys/rsa/rsa-2048-cert.pem",
    ))
    .expect("RSA certificate fixture must parse");
    let template = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .key_info(true)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#payload")
                .transform(Transform::C14n(exclusive_c14n())),
        )
        .build_template()
        .expect("valid signature template")
        .replace(
            "<KeyInfo/>",
            &format!("<KeyInfo><KeyName>selected</KeyName>{stale_source}</KeyInfo>"),
        );
    let xml = append_signature_to_root(
        "<root><payload ID=\"payload\">hello</payload></root>",
        &template,
    )
    .expect("append signature");

    let signed = SignContext::new(&private_key)
        .key_info_writer(&writer)
        .sign_template(&xml)
        .expect("authoritative KeyInfo source must replace stale material");
    let result = xml_sec::xmldsig::VerifyContext::new()
        .key_resolver(&DefaultKeyResolver::default())
        .verify(&signed)
        .expect("replacement certificate must resolve");

    assert_eq!(result.status, DsigStatus::Valid);
    assert!(signed.contains(">selected</KeyName>"));
    assert_eq!(signed.matches("<X509Data").count(), 1);
}

#[test]
fn key_info_writer_generated_id_can_be_signed() {
    // A writer-generated ID on a reused placeholder must exist before the
    // digest pass so SignedInfo can authenticate the resulting key metadata.
    struct IdentifiedWriter(X509CertificateKeyInfoWriter);

    impl KeyInfoWriter for IdentifiedWriter {
        fn write_key_info(
            &self,
            signing_key: &dyn SigningKey,
        ) -> Result<String, xml_sec::xmldsig::KeyInfoWriteError> {
            Ok(self.0.write_key_info(signing_key)?.replacen(
                "<X509Data ",
                "<X509Data Id=\"generated\" ",
                1,
            ))
        }
    }

    let private_key =
        RsaSigningKey::from_pkcs8_pem(&read_fixture("tests/fixtures/keys/rsa/rsa-2048-key.pem"))
            .expect("RSA private key fixture must parse");
    let writer = IdentifiedWriter(
        X509CertificateKeyInfoWriter::from_pem(&read_fixture(
            "tests/fixtures/keys/rsa/rsa-2048-cert.pem",
        ))
        .expect("RSA certificate fixture must parse"),
    );
    let template = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .key_info(true)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#payload")
                .transform(Transform::C14n(exclusive_c14n())),
        )
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#generated")
                .transform(Transform::C14n(exclusive_c14n())),
        )
        .build_template()
        .expect("valid signature template")
        .replace("<KeyInfo/>", "<KeyInfo><X509Data/></KeyInfo>");
    let xml = append_signature_to_root(
        "<root><payload ID=\"payload\">hello</payload></root>",
        &template,
    )
    .expect("append signature");

    let signed = SignContext::new(&private_key)
        .key_info_writer(&writer)
        .sign_template(&xml)
        .expect("writer-generated ID must resolve during digesting");
    let result = xml_sec::xmldsig::VerifyContext::new()
        .key_resolver(&DefaultKeyResolver::default())
        .verify(&signed)
        .expect("signed generated KeyInfo source must verify");

    assert_eq!(result.status, DsigStatus::Valid);
    assert!(signed.contains("Id=\"generated\""));
}

#[test]
fn key_info_writer_requires_direct_template_placeholder() {
    // The writer is intentionally opt-in and template-scoped. Without a direct
    // KeyInfo slot, signing fails instead of inventing insertion policy.
    let private_key =
        RsaSigningKey::from_pkcs8_pem(&read_fixture("tests/fixtures/keys/rsa/rsa-2048-key.pem"))
            .expect("RSA private key fixture must parse");
    let key_info_writer = X509CertificateKeyInfoWriter::from_pem(&read_fixture(
        "tests/fixtures/keys/rsa/rsa-2048-cert.pem",
    ))
    .expect("RSA certificate fixture must parse");
    let builder = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#payload")
                .transform(Transform::C14n(exclusive_c14n())),
        );

    let err = SignContext::new(&private_key)
        .key_info_writer(&key_info_writer)
        .sign_with_builder(
            "<root><payload ID=\"payload\">hello</payload></root>",
            &builder,
        )
        .expect_err("writer without KeyInfo placeholder must fail");

    assert!(matches!(
        err,
        SigningError::XmlMutation(
            xml_sec::xmldsig::mutation::XmlMutationError::ValueCountMismatch {
                element: "KeyInfo",
                expected: 1,
                actual: 0,
            }
        )
    ));
}

#[test]
fn key_info_writer_rejects_duplicate_direct_template_placeholders() {
    // Duplicate direct KeyInfo slots are ambiguous: signing must fail instead of
    // choosing one and silently leaving another template placeholder behind.
    let private_key =
        RsaSigningKey::from_pkcs8_pem(&read_fixture("tests/fixtures/keys/rsa/rsa-2048-key.pem"))
            .expect("RSA private key fixture must parse");
    let key_info_writer = X509CertificateKeyInfoWriter::from_pem(&read_fixture(
        "tests/fixtures/keys/rsa/rsa-2048-cert.pem",
    ))
    .expect("RSA certificate fixture must parse");
    let template = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .key_info(true)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#payload")
                .transform(Transform::C14n(exclusive_c14n())),
        )
        .build_template()
        .expect("valid signature template")
        .replace("</Signature>", "<KeyInfo/></Signature>");
    let xml = append_signature_to_root(
        "<root><payload ID=\"payload\">hello</payload></root>",
        &template,
    )
    .expect("append signature");

    let err = SignContext::new(&private_key)
        .key_info_writer(&key_info_writer)
        .sign_template(&xml)
        .expect_err("duplicate direct KeyInfo placeholders must fail");

    assert!(matches!(
        err,
        SigningError::Digest(SigningDigestError::InvalidStructure(message))
            if message.contains("KeyInfo must appear at most once")
    ));
}

#[test]
fn signing_without_key_info_writer_rejects_malformed_signature_children() {
    // Structural validation is independent of KeyInfo population: signing must
    // never emit a document that the verification parser necessarily rejects.
    let private_key =
        RsaSigningKey::from_pkcs8_pem(&read_fixture("tests/fixtures/keys/rsa/rsa-2048-key.pem"))
            .expect("RSA private key fixture must parse");
    let builder = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .key_info(true)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#payload")
                .transform(Transform::C14n(exclusive_c14n())),
        );
    let template = builder.build_template().expect("valid signature template");

    let malformed_templates = [
        template.replace("</Signature>", "<KeyInfo/></Signature>"),
        template.replace("<SignatureValue/>", "<KeyInfo/><SignatureValue/>"),
    ];
    for malformed in malformed_templates {
        let xml = append_signature_to_root(
            "<root><payload ID=\"payload\">hello</payload></root>",
            &malformed,
        )
        .expect("append malformed signature template");
        let error = SignContext::new(&private_key)
            .sign_template(&xml)
            .expect_err("malformed Signature children must fail without a writer");
        assert!(
            matches!(
                error,
                SigningError::Digest(SigningDigestError::InvalidStructure(_))
            ),
            "{error:?}"
        );
    }
}

#[test]
fn x509_key_info_writer_rejects_certificate_for_different_key() {
    // A successful signing call must not produce a document that embeds an
    // unrelated certificate which the default resolver will later reject.
    let private_key =
        RsaSigningKey::from_pkcs8_pem(&read_fixture("tests/fixtures/keys/rsa/rsa-2048-key.pem"))
            .expect("RSA private key fixture must parse");
    let key_info_writer = X509CertificateKeyInfoWriter::from_pem(&read_fixture(
        "tests/fixtures/keys/ec/ec-prime256v1-cert.pem",
    ))
    .expect("EC certificate fixture must parse");
    let builder = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .key_info(true)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#payload")
                .transform(Transform::C14n(exclusive_c14n())),
        );

    let err = SignContext::new(&private_key)
        .key_info_writer(&key_info_writer)
        .sign_with_builder(
            "<root><payload ID=\"payload\">hello</payload></root>",
            &builder,
        )
        .expect_err("mismatched certificate must fail before output");

    assert!(matches!(
        err,
        SigningError::KeyInfo(xml_sec::xmldsig::KeyInfoWriteError::CertificateKeyMismatch)
    ));
}

#[test]
fn sign_with_builder_targets_appended_signature_when_existing_key_info_is_present() {
    // Signing an already-signed document should fill only the newly appended
    // template. Existing Signature/KeyInfo blocks are immutable historical data.
    let private_key =
        RsaSigningKey::from_pkcs8_pem(&read_fixture("tests/fixtures/keys/rsa/rsa-2048-key.pem"))
            .expect("RSA private key fixture must parse");
    let key_info_writer = X509CertificateKeyInfoWriter::from_pem(&read_fixture(
        "tests/fixtures/keys/rsa/rsa-2048-cert.pem",
    ))
    .expect("RSA certificate fixture must parse");
    let first_builder = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .key_info(true)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#first")
                .transform(Transform::C14n(exclusive_c14n())),
        );
    let first_signed = SignContext::new(&private_key)
        .key_info_writer(&key_info_writer)
        .sign_with_builder(
            "<root><payload ID=\"first\">one</payload><payload ID=\"second\">two</payload></root>",
            &first_builder,
        )
        .expect("initial signing with KeyInfo must succeed");
    let second_builder = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .key_info(true)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#second")
                .transform(Transform::C14n(exclusive_c14n())),
        );

    let second_signed = SignContext::new(&private_key)
        .key_info_writer(&key_info_writer)
        .sign_with_builder(&first_signed, &second_builder)
        .expect("existing Signature/KeyInfo must not block appended template signing");
    let document = roxmltree::Document::parse(&second_signed).expect("signed XML must parse");
    let signature_count = document
        .descendants()
        .filter(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some("http://www.w3.org/2000/09/xmldsig#")
                && node.tag_name().name() == "Signature"
        })
        .count();

    assert_eq!(signature_count, 2);
    assert_eq!(second_signed.matches("<X509Certificate>").count(), 2);
    assert!(!second_signed.contains("<DigestValue></DigestValue>"));
    assert!(!second_signed.contains("<SignatureValue></SignatureValue>"));
}

#[test]
fn sign_with_builder_appends_and_targets_within_the_selected_start_node() {
    // A start-node selector scopes both template placement and target choice;
    // an older template in that subtree must remain untouched.
    let private_key =
        RsaSigningKey::from_pkcs8_pem(&read_fixture("tests/fixtures/keys/rsa/rsa-2048-key.pem"))
            .expect("RSA private key fixture must parse");
    let old_builder = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#old")
                .transform(Transform::C14n(exclusive_c14n())),
        );
    let old_template = old_builder
        .build_template()
        .expect("old template must build");
    let xml = format!(
        "<root><scope Id=\"selected\"><payload Id=\"old\">old</payload><payload Id=\"new\">new</payload>{old_template}</scope></root>"
    );
    let new_builder = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#new")
                .transform(Transform::C14n(exclusive_c14n())),
        );

    let signed = SignContext::new(&private_key)
        .start_node_id("selected")
        .sign_with_builder(&xml, &new_builder)
        .expect("builder signing must target its appended selected-node template");
    let document = roxmltree::Document::parse(&signed).expect("signed XML must parse");
    let scope = document
        .descendants()
        .find(|node| node.attribute("Id") == Some("selected"))
        .expect("selected scope must remain");
    let signatures = scope
        .children()
        .filter(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "Signature")))
        .collect::<Vec<_>>();
    assert_eq!(signatures.len(), 2);
    assert_eq!(
        signatures[0]
            .descendants()
            .find(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "DigestValue")))
            .and_then(|node| node.text()),
        None
    );
    assert_eq!(
        signatures[1]
            .descendants()
            .find(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "Reference")))
            .and_then(|node| node.attribute("URI")),
        Some("#new")
    );
    assert!(
        signatures[1]
            .descendants()
            .find(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "DigestValue")))
            .and_then(|node| node.text())
            .is_some()
    );
    assert!(
        signatures[1]
            .children()
            .find(|node| {
                node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "SignatureValue"))
            })
            .and_then(|node| node.text())
            .is_some()
    );
}

#[test]
fn signing_fills_only_top_level_signature_value() {
    // Object payloads may contain SignatureValue-named XMLDSig elements. The
    // signing pass must fill only the direct child of the selected Signature.
    let private_key =
        RsaSigningKey::from_pkcs8_pem(&read_fixture("tests/fixtures/keys/rsa/rsa-2048-key.pem"))
            .expect("RSA private key fixture must parse");
    let public_key_pem = read_fixture("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    let template = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#payload")
                .transform(Transform::C14n(exclusive_c14n())),
        )
        .build_template()
        .expect("valid signature template")
        .replace(
            "</Signature>",
            "<Object><SignatureValue>keep-object-signature</SignatureValue></Object></Signature>",
        );
    let xml = append_signature_to_root(
        "<root><payload ID=\"payload\">hello</payload></root>",
        &template,
    )
    .expect("append signature");

    let signed = SignContext::new(&private_key)
        .sign_template(&xml)
        .expect("signing must ignore object SignatureValue");
    let verify_result = verify_signature_with_pem_key(&signed, &public_key_pem, true)
        .expect("signed RSA XML must verify without pipeline errors");

    assert_eq!(verify_result.status, DsigStatus::Valid);
    assert!(signed.contains("<SignatureValue>keep-object-signature</SignatureValue>"));
}

#[test]
fn signs_ecdsa_p256_template_and_verifies_round_trip() {
    // ECDSA XMLDSig SignatureValue must be fixed-width r||s bytes, not ASN.1
    // DER. The verifier accepts the generated value as a final interop check.
    let private_key = EcdsaP256SigningKey::from_pkcs8_pem(&read_fixture(
        "tests/fixtures/keys/ec/ec-prime256v1-key.pem",
    ))
    .expect("P-256 private key fixture must parse");
    let public_key_pem = read_fixture("tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem");
    let builder = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::EcdsaSha256)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#payload")
                .transform(Transform::C14n(exclusive_c14n())),
        );

    let signed = SignContext::new(&private_key)
        .sign_with_builder(
            "<root><payload ID=\"payload\">hello</payload></root>",
            &builder,
        )
        .expect("ECDSA signing pipeline must succeed");
    let verify_result = verify_signature_with_pem_key(&signed, &public_key_pem, true)
        .expect("signed ECDSA XML must verify without pipeline errors");

    assert_eq!(verify_result.status, DsigStatus::Valid);
    assert!(signed.contains("<SignatureValue>"));
    assert!(!signed.contains("<DigestValue></DigestValue>"));
}

#[test]
fn signs_ecdsa_p384_template_and_verifies_round_trip() {
    // P-384 uses the XMLDSig ecdsa-sha384 URI and the same fixed-width r||s
    // SignatureValue encoding as P-256, with a wider component size.
    let private_key = EcdsaP384SigningKey::from_pkcs8_pem(&read_fixture(
        "tests/fixtures/keys/ec/ec-prime384v1-key.pem",
    ))
    .expect("P-384 private key fixture must parse");
    let public_key_pem = read_fixture("tests/fixtures/keys/ec/ec-prime384v1-pubkey.pem");
    let builder = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::EcdsaSha384)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha384)
                .uri("#payload")
                .transform(Transform::C14n(exclusive_c14n())),
        );

    let signed = SignContext::new(&private_key)
        .sign_with_builder(
            "<root><payload ID=\"payload\">hello</payload></root>",
            &builder,
        )
        .expect("P-384 signing pipeline must succeed");
    let verify_result = verify_signature_with_pem_key(&signed, &public_key_pem, true)
        .expect("signed P-384 XML must verify without pipeline errors");

    assert_eq!(verify_result.status, DsigStatus::Valid);
    assert!(signed.contains("<SignatureValue>"));
    assert!(!signed.contains("<DigestValue></DigestValue>"));
}

#[test]
fn signs_ecdsa_with_digest_independent_of_curve() {
    // XMLDSig SignatureMethod selects the hash; the signing key selects the
    // curve and SignatureValue width. Exercise both non-default pairings
    // through the complete template, signing, and verification pipeline.
    let p256_key = EcdsaP256SigningKey::from_pkcs8_pem(&read_fixture(
        "tests/fixtures/keys/ec/ec-prime256v1-key.pem",
    ))
    .expect("P-256 private key fixture must parse");
    let p384_key = EcdsaP384SigningKey::from_pkcs8_pem(&read_fixture(
        "tests/fixtures/keys/ec/ec-prime384v1-key.pem",
    ))
    .expect("P-384 private key fixture must parse");
    let cases: [(&dyn SigningKey, SignatureAlgorithm, &str); 2] = [
        (
            &p384_key,
            SignatureAlgorithm::EcdsaSha256,
            "tests/fixtures/keys/ec/ec-prime384v1-pubkey.pem",
        ),
        (
            &p256_key,
            SignatureAlgorithm::EcdsaSha384,
            "tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem",
        ),
    ];

    for (key, algorithm, public_key_path) in cases {
        let builder = SignatureBuilder::new(exclusive_c14n(), algorithm).add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#payload")
                .transform(Transform::C14n(exclusive_c14n())),
        );
        let signed = SignContext::new(key)
            .sign_with_builder(
                "<root><payload ID=\"payload\">hello</payload></root>",
                &builder,
            )
            .expect("curve-independent ECDSA signing must succeed");
        let public_key_pem = read_fixture(public_key_path);
        let result = verify_signature_with_pem_key(&signed, &public_key_pem, true)
            .expect("curve-independent ECDSA verification must run");

        assert_eq!(result.status, DsigStatus::Valid, "{}", algorithm.uri());
    }
}

#[test]
fn signs_rsa_donor_templates_and_verifies_round_trip() {
    // These are xmlsec1's supported enveloping signing templates. They exercise
    // template parsing, object dereference, digest fill, SignedInfo c14n, and
    // RSA PKCS#1 v1.5 signing without relying on our SignatureBuilder output.
    for (template_path, private_key_path, public_key_path) in [
        (
            "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.tmpl",
            "tests/fixtures/keys/rsa/rsa-2048-key.pem",
            "tests/fixtures/keys/rsa/rsa-2048-pubkey.pem",
        ),
        (
            "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha384-rsa-sha384.tmpl",
            "tests/fixtures/keys/rsa/rsa-4096-key.pem",
            "tests/fixtures/keys/rsa/rsa-4096-pubkey.pem",
        ),
        (
            "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha512-rsa-sha512.tmpl",
            "tests/fixtures/keys/rsa/rsa-4096-key.pem",
            "tests/fixtures/keys/rsa/rsa-4096-pubkey.pem",
        ),
    ] {
        let private_key = RsaSigningKey::from_pkcs8_pem(&read_fixture(private_key_path))
            .expect("RSA private key fixture must parse");

        let signed = SignContext::new(&private_key)
            .sign_template(&read_fixture(template_path))
            .expect("RSA donor template must sign");

        assert_signed_template_verifies(&signed, public_key_path);
    }
}

#[test]
fn signs_ecdsa_donor_templates_and_verifies_round_trip() {
    // The donor enveloped ECDSA templates include an XPath transform, which is
    // intentionally blocked until XPath support lands. The enveloping templates
    // cover the same ECDSA SignatureValue format without that blocked transform.
    let p256_key = EcdsaP256SigningKey::from_pkcs8_pem(&read_fixture(
        "tests/fixtures/keys/ec/ec-prime256v1-key.pem",
    ))
    .expect("P-256 private key fixture must parse");
    let p256_signed = SignContext::new(&p256_key)
        .sign_template(&read_fixture(
            "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-ecdsa-sha256.tmpl",
        ))
        .expect("P-256 donor template must sign");
    assert_signed_template_verifies(
        &p256_signed,
        "tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem",
    );

    let p384_key = EcdsaP384SigningKey::from_pkcs8_pem(&read_fixture(
        "tests/fixtures/keys/ec/ec-prime384v1-key.pem",
    ))
    .expect("P-384 private key fixture must parse");
    let p384_signed = SignContext::new(&p384_key)
        .sign_template(&read_fixture(
            "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha384-ecdsa-sha384.tmpl",
        ))
        .expect("P-384 donor template must sign");
    assert_signed_template_verifies(
        &p384_signed,
        "tests/fixtures/keys/ec/ec-prime384v1-pubkey.pem",
    );
}
