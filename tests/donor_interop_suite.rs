//! XMLDSig 1.1 and Second Edition donor interoperability coverage.

use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
};

use xml_sec::policy::{
    HmacPolicy, PolicyViolation, RsaKeyPolicy, SigningPolicy, VerificationPolicy,
};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DerEncodedKeyValueInfoWriter, DigestAlgorithm, DsaSigningKey, DsigError,
    DsigStatus, EcdsaP256SigningKey, EcdsaP384SigningKey, EcdsaP521SigningKey, FailureReason,
    HmacSigningKey, HmacVerificationKey, KeyResolverConfig, KeyValueInfoWriter, RsaSigningKey,
    SignContext, SignatureAlgorithm, SigningKey, SigningKeyError, SigningPublicKeyInfo, UriTypeSet,
    VerificationKey, VerifyContext, X509DigestKeyInfoWriter, validate_signing_key,
};

const XMLDSIG11_DIR: &str = "tests/fixtures/xmldsig/xmldsig11-interop-2012";
const XMLDSIG2ED_DIR: &str = "tests/fixtures/xmldsig/xmldsig2ed-tests";

fn sorted_files(directory: &str, extension: &str) -> Vec<std::path::PathBuf> {
    let mut paths = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("failed to list {directory}: {error}"))
        .map(|entry| entry.expect("directory entry must be readable").path())
        .filter(|path| path.extension().is_some_and(|value| value == extension))
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

fn compatibility_verification_policy() -> VerificationPolicy {
    let mut policy = VerificationPolicy {
        hmac: HmacPolicy {
            minimum_key_bits: 40,
            minimum_output_bits: 40,
        },
        ..VerificationPolicy::default()
    };
    policy.key_trust.allowed_legacy_signature_algorithms = HashSet::from([
        SignatureAlgorithm::DsaSha1,
        SignatureAlgorithm::EcdsaSha1,
        SignatureAlgorithm::HmacSha1,
        SignatureAlgorithm::RsaSha1,
    ]);
    policy.key_trust.rsa_keys = RsaKeyPolicy {
        minimum_modulus_bits: 1024,
    };
    policy
}

fn compatibility_signing_policy() -> SigningPolicy {
    SigningPolicy {
        signature_algorithms: Some(HashSet::from([
            SignatureAlgorithm::EcdsaSha1,
            SignatureAlgorithm::EcdsaSha224,
            SignatureAlgorithm::EcdsaSha256,
            SignatureAlgorithm::EcdsaSha384,
            SignatureAlgorithm::EcdsaSha512,
            SignatureAlgorithm::RsaSha256,
        ])),
        digest_algorithms: Some(HashSet::from([
            DigestAlgorithm::Sha1,
            DigestAlgorithm::Sha224,
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
        ])),
        rsa_keys: RsaKeyPolicy {
            minimum_modulus_bits: 1024,
        },
        ..SigningPolicy::default()
    }
}

fn x509_digest_resolver() -> DefaultKeyResolver {
    DefaultKeyResolver::new(KeyResolverConfig {
        lookup_certs: vec![
            fs::read(format!("{XMLDSIG11_DIR}/keys/rsa-key.crt"))
                .expect("RSA certificate fixture must be readable"),
        ],
        ..KeyResolverConfig::default()
    })
}

fn assert_valid(status: DsigStatus, path: &Path) {
    assert!(
        matches!(status, DsigStatus::Valid),
        "{} must verify, got {status:?}",
        path.display()
    );
}

fn clear_element_contents(xml: &str, qualified_name: &str) -> String {
    let opening = format!("<{qualified_name}");
    let opening_start = xml.find(&opening).expect("fixture element must exist");
    let content_start = xml[opening_start..]
        .find('>')
        .map(|offset| opening_start + offset + 1)
        .expect("fixture opening tag must terminate");
    let closing = format!("</{qualified_name}>");
    let content_end = xml[content_start..]
        .find(&closing)
        .map(|offset| content_start + offset)
        .expect("fixture closing tag must exist");
    let mut output = xml.to_owned();
    output.replace_range(content_start..content_end, "");
    output
}

fn replace_referenced_key_info_contents(xml: &str, replacement: &str) -> String {
    let marker = "Id=\"KeyInfoID\"";
    let marker_offset = xml.find(marker).expect("referenced KeyInfo must exist");
    let opening_start = xml[..marker_offset]
        .rfind("<dsig:KeyInfo")
        .expect("referenced KeyInfo opening tag must exist");
    let content_start = xml[opening_start..]
        .find('>')
        .map(|offset| opening_start + offset + 1)
        .expect("referenced KeyInfo opening tag must terminate");
    let content_end = xml[content_start..]
        .find("</dsig:KeyInfo>")
        .map(|offset| content_start + offset)
        .expect("referenced KeyInfo closing tag must exist");
    let mut output = xml.to_owned();
    output.replace_range(content_start..content_end, replacement);
    output
}

#[test]
fn complete_xmldsig11_verification_corpus_is_classified_and_executed() {
    // RFC 4050's coordinate-form ECDSAKeyValue is not part of XMLDSig 1.1;
    // every other upstream vector must execute through the public pipeline.
    let paths = sorted_files(XMLDSIG11_DIR, "xml");
    assert_eq!(
        paths.len(),
        45,
        "fixture import must retain the full corpus"
    );

    let hmac_key = HmacVerificationKey::new(
        fs::read(format!("{XMLDSIG11_DIR}/keys/hmackey.bin"))
            .expect("HMAC key fixture must be readable"),
    )
    .expect("donor HMAC key must parse");
    let embedded_resolver = DefaultKeyResolver::default();
    let x509_resolver = x509_digest_resolver();
    let policy = compatibility_verification_policy();
    let mut verified = 0;
    let mut rejected_rfc4050 = 0;

    for path in paths {
        let xml = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let name = path.file_name().and_then(|value| value.to_str()).unwrap();
        let result = if name.contains("hmac") {
            VerifyContext::new()
                .key(&hmac_key)
                .policy(policy.clone())
                .verify(&xml)
        } else if name.contains("x509digest") {
            VerifyContext::new()
                .key_resolver(&x509_resolver)
                .policy(policy.clone())
                .verify(&xml)
        } else {
            VerifyContext::new()
                .key_resolver(&embedded_resolver)
                .policy(policy.clone())
                .verify(&xml)
        };

        if name.contains("_4050") {
            assert!(
                matches!(
                    result,
                    Ok(ref value) if matches!(value.status, DsigStatus::Invalid(FailureReason::KeyNotFound))
                ),
                "{} must reject RFC 4050 KeyValue as unresolved",
                path.display()
            );
            rejected_rfc4050 += 1;
        } else {
            let result =
                result.unwrap_or_else(|error| panic!("{} must verify: {error}", path.display()));
            assert_valid(result.status, &path);
            verified += 1;
        }
    }

    assert_eq!(verified, 33);
    assert_eq!(rejected_rfc4050, 12);
}

#[test]
fn key_info_reference_policy_and_structure_fail_closed() {
    // Every indirection decision must be made before resolver fallback so a
    // malformed or forbidden reference cannot silently degrade to KeyNotFound.
    let xml = fs::read_to_string(format!(
        "{XMLDSIG11_DIR}/signature-enveloping-keyinforeference-rsa.xml"
    ))
    .expect("KeyInfoReference fixture must be readable");
    let resolver = DefaultKeyResolver::default();

    let missing = xml.replacen("URI=\"#KeyInfoID\"", "URI=\"#Missing\"", 1);
    assert!(matches!(
        VerifyContext::new()
            .key_resolver(&resolver)
            .verify(&missing),
        Err(DsigError::InvalidStructure {
            reason: "KeyInfoReference target is missing or ambiguous"
        })
    ));

    let non_key_info = xml.replacen(
        "URI=\"#KeyInfoID\"",
        "URI=\"#DSig.Object_W1u9Me3FAhWb4c7uH1IEmA22\"",
        1,
    );
    assert!(matches!(
        VerifyContext::new()
            .key_resolver(&resolver)
            .verify(&non_key_info),
        Err(DsigError::InvalidStructure {
            reason: "KeyInfoReference target must be KeyInfo"
        })
    ));

    let cycle = replace_referenced_key_info_contents(
        &xml,
        r##"<dsig11:KeyInfoReference xmlns:dsig11="http://www.w3.org/2009/xmldsig11#" URI="#KeyInfoID"/>"##,
    );
    assert!(matches!(
        VerifyContext::new().key_resolver(&resolver).verify(&cycle),
        Err(DsigError::InvalidStructure {
            reason: "KeyInfoReference cycle detected"
        })
    ));

    let mut depth_policy = compatibility_verification_policy();
    depth_policy.resources.max_key_info_reference_depth = 0;
    assert!(matches!(
        VerifyContext::new()
            .key_resolver(&resolver)
            .policy(depth_policy)
            .verify(&xml),
        Err(DsigError::Policy(PolicyViolation::ResourceLimit {
            resource: "KeyInfoReference depth",
            maximum: 0,
            actual: 1,
        }))
    ));

    let mut source_policy = compatibility_verification_policy();
    source_policy.key_sources.key_info_reference = false;
    assert!(matches!(
        VerifyContext::new()
            .key_resolver(&resolver)
            .policy(source_policy)
            .verify(&xml),
        Err(DsigError::Policy(PolicyViolation::KeyTrust {
            reason: "KeyInfoReference key sources are disabled"
        }))
    ));

    let mut uri_policy = compatibility_verification_policy();
    uri_policy.uris.key_info_references = UriTypeSet::new(false, false, false);
    assert!(matches!(
        VerifyContext::new()
            .key_resolver(&resolver)
            .policy(uri_policy)
            .verify(&xml),
        Err(DsigError::Policy(PolicyViolation::Uri {
            operation: "KeyInfoReference",
            reason: "URI class is disabled"
        }))
    ));
}

#[test]
fn key_info_reference_dag_is_bounded_by_candidate_work() {
    // Depth and active-path cycle checks do not bound a DAG whose siblings all
    // reference the same next level. Candidate discovery must reject that
    // repeated expansion before it can allocate an exponential source list.
    let xml = fs::read_to_string(format!(
        "{XMLDSIG11_DIR}/signature-enveloping-keyinforeference-rsa.xml"
    ))
    .expect("KeyInfoReference fixture must be readable");

    let mut nested = "<dsig:KeyInfo xmlns:dsig11=\"http://www.w3.org/2009/xmldsig11#\" Id=\"level-5\"><dsig:KeyName>terminal</dsig:KeyName></dsig:KeyInfo>".to_owned();
    for level in (1..5).rev() {
        let next = level + 1;
        nested = format!(
            "<dsig:KeyInfo xmlns:dsig11=\"http://www.w3.org/2009/xmldsig11#\" Id=\"level-{level}\"><dsig11:KeyInfoReference URI=\"#level-{next}\"/><dsig11:KeyInfoReference URI=\"#level-{next}\"/>{nested}</dsig:KeyInfo>"
        );
    }
    let replacement = format!(
        "<dsig11:KeyInfoReference xmlns:dsig11=\"http://www.w3.org/2009/xmldsig11#\" URI=\"#level-1\"/><dsig11:KeyInfoReference xmlns:dsig11=\"http://www.w3.org/2009/xmldsig11#\" URI=\"#level-1\"/>{nested}"
    );
    let dag = replace_referenced_key_info_contents(&xml, &replacement);
    let mut policy = compatibility_verification_policy();
    policy.resources.max_key_candidates = 8;

    let result = VerifyContext::new()
        .key_resolver(&DefaultKeyResolver::default())
        .policy(policy)
        .verify(&dag);
    assert!(
        matches!(
            result,
            Err(DsigError::Policy(PolicyViolation::ResourceLimit {
                resource: "key candidates",
                maximum: 8,
                actual: 9,
            }))
        ),
        "unexpected DAG budget result: {result:?}"
    );
}

#[test]
fn external_key_info_reference_uses_only_caller_owned_bytes() {
    // Enabling external key references never enables I/O; the complete XML
    // document is supplied by the caller and parsed under the operation budget.
    let xml = fs::read_to_string(format!(
        "{XMLDSIG11_DIR}/signature-enveloping-keyinforeference-rsa.xml"
    ))
    .expect("KeyInfoReference fixture must be readable");
    let marker = "Id=\"KeyInfoID\"";
    let marker_offset = xml.find(marker).expect("referenced KeyInfo must exist");
    let start = xml[..marker_offset].rfind("<dsig:KeyInfo").unwrap();
    let end = xml[marker_offset..]
        .find("</dsig:KeyInfo>")
        .map(|offset| marker_offset + offset + "</dsig:KeyInfo>".len())
        .unwrap();
    let external_key_info = xml.as_bytes()[start..end].to_vec();
    let external_xml = xml.replacen("URI=\"#KeyInfoID\"", "URI=\"key-info.xml\"", 1);
    let resources = HashMap::from([("key-info.xml".to_owned(), external_key_info)]);
    let resolver = DefaultKeyResolver::default();
    let mut policy = compatibility_verification_policy();
    policy.uris.key_info_references = UriTypeSet::ALL;

    let result = VerifyContext::new()
        .key_resolver(&resolver)
        .external_resources(&resources)
        .policy(policy)
        .verify(&external_xml)
        .expect("caller-owned external KeyInfo must materialize");
    assert_valid(result.status, Path::new("external KeyInfoReference"));
}

#[test]
fn external_key_info_reference_rebinds_fragments_and_shares_resource_budget() {
    // An external KeyInfo document owns its fragment namespace. Nested external
    // dereferences remain caller-owned and consume the same aggregate budget.
    let xml = fs::read_to_string(format!(
        "{XMLDSIG11_DIR}/signature-enveloping-keyinforeference-rsa.xml"
    ))
    .expect("KeyInfoReference fixture must be readable");
    let marker = "Id=\"KeyInfoID\"";
    let marker_offset = xml.find(marker).expect("referenced KeyInfo must exist");
    let start = xml[..marker_offset].rfind("<dsig:KeyInfo").unwrap();
    let end = xml[marker_offset..]
        .find("</dsig:KeyInfo>")
        .map(|offset| marker_offset + offset + "</dsig:KeyInfo>".len())
        .unwrap();
    let key_info = &xml[start..end];
    let inner_key_info = key_info.replacen("Id=\"KeyInfoID\"", "Id=\"inner\"", 1);
    let fragment_document = format!(
        r##"<keys xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" xmlns:dsig11="http://www.w3.org/2009/xmldsig11#"><dsig:KeyInfo Id="outer"><dsig11:KeyInfoReference URI="#inner"/></dsig:KeyInfo>{inner_key_info}</keys>"##
    );
    let fragment_signature = xml.replacen("URI=\"#KeyInfoID\"", "URI=\"key-info.xml#outer\"", 1);
    let fragment_resources =
        HashMap::from([("key-info.xml".to_owned(), fragment_document.into_bytes())]);
    let resolver = DefaultKeyResolver::default();
    let mut policy = compatibility_verification_policy();
    policy.uris.key_info_references = UriTypeSet::ALL;
    let result = VerifyContext::new()
        .key_resolver(&resolver)
        .external_resources(&fragment_resources)
        .policy(policy.clone())
        .verify(&fragment_signature)
        .expect("external fragments and their local KeyInfoReference must resolve");
    assert_valid(
        result.status,
        Path::new("external KeyInfoReference fragment"),
    );

    let outer = br#"<keys xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" xmlns:dsig11="http://www.w3.org/2009/xmldsig11#"><dsig:KeyInfo Id="outer"><dsig11:KeyInfoReference URI="inner.xml"/></dsig:KeyInfo></keys>"#.to_vec();
    let inner = key_info.as_bytes().to_vec();
    let external_signature = xml.replacen("URI=\"#KeyInfoID\"", "URI=\"keys/outer.xml#outer\"", 1);
    let external_resources = HashMap::from([
        ("keys/outer.xml".to_owned(), outer.clone()),
        ("keys/inner.xml".to_owned(), inner.clone()),
    ]);
    policy.resources.max_external_resource_bytes = outer.len().max(inner.len());
    policy.resources.max_external_resource_total_bytes = outer.len() + inner.len();
    let result = VerifyContext::new()
        .key_resolver(&resolver)
        .external_resources(&external_resources)
        .policy(policy.clone())
        .verify(&external_signature)
        .expect("nested external KeyInfoReference must share caller-owned resources");
    assert_valid(result.status, Path::new("nested external KeyInfoReference"));

    policy.resources.max_external_resource_total_bytes -= 1;
    let error = VerifyContext::new()
        .key_resolver(&resolver)
        .external_resources(&external_resources)
        .policy(policy)
        .verify(&external_signature)
        .expect_err("nested external resources must share the aggregate byte budget");
    assert!(
        matches!(
            error,
            DsigError::Policy(PolicyViolation::ResourceLimit {
                resource: "aggregate external resource bytes",
                ..
            })
        ),
        "unexpected aggregate budget error: {error:?}"
    );
}

#[test]
fn hmac_donor_vectors_sign_and_verify_with_declared_output_lengths() {
    // Re-sign every HMAC vector after clearing both generated values. This
    // covers SHA-1 truncation and full-width SHA-224/256/384/512 output.
    let secret = fs::read(format!("{XMLDSIG11_DIR}/keys/hmackey.bin"))
        .expect("HMAC key fixture must be readable");
    let signing_key = HmacSigningKey::new(secret.clone()).expect("HMAC signing key must parse");
    let verification_key = HmacVerificationKey::new(secret).expect("HMAC key must parse");
    let signing_policy = SigningPolicy {
        signature_algorithms: Some(HashSet::from([
            SignatureAlgorithm::HmacSha1,
            SignatureAlgorithm::HmacSha224,
            SignatureAlgorithm::HmacSha256,
            SignatureAlgorithm::HmacSha384,
            SignatureAlgorithm::HmacSha512,
        ])),
        digest_algorithms: Some(HashSet::from([
            DigestAlgorithm::Sha1,
            DigestAlgorithm::Sha224,
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
        ])),
        hmac: HmacPolicy {
            minimum_key_bits: 40,
            minimum_output_bits: 40,
        },
        ..SigningPolicy::default()
    };

    for path in sorted_files(XMLDSIG11_DIR, "xml")
        .into_iter()
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().contains("hmac"))
        })
    {
        let signed = fs::read_to_string(&path).expect("HMAC vector must be readable");
        let template = clear_element_contents(
            &clear_element_contents(&signed, "dsig:DigestValue"),
            "dsig:SignatureValue",
        );
        let generated = SignContext::new(&signing_key)
            .policy(signing_policy.clone())
            .sign_template(&template)
            .unwrap_or_else(|error| panic!("{} must sign: {error}", path.display()));
        let result = VerifyContext::new()
            .key(&verification_key)
            .policy(compatibility_verification_policy())
            .verify(&generated)
            .unwrap_or_else(|error| {
                panic!("{} generated MAC must verify: {error}", path.display())
            });
        assert_valid(result.status, &path);
    }
}

#[test]
fn signing_policy_rejects_weak_hmac_output_before_key_dispatch() {
    // Explicit legacy-algorithm opt-in does not bypass the independent HMAC
    // output-strength policy selected for the operation.
    let signed = fs::read_to_string(format!(
        "{XMLDSIG11_DIR}/signature-enveloping-hmac-sha1-truncated40.xml"
    ))
    .expect("truncated HMAC fixture must be readable");
    let template = clear_element_contents(
        &clear_element_contents(&signed, "dsig:DigestValue"),
        "dsig:SignatureValue",
    );
    let key = HmacSigningKey::new([0x42; 16]).expect("fixed HMAC key must parse");
    let policy = SigningPolicy {
        signature_algorithms: Some(HashSet::from([SignatureAlgorithm::HmacSha1])),
        digest_algorithms: Some(HashSet::from([DigestAlgorithm::Sha1])),
        ..SigningPolicy::default()
    };
    assert!(matches!(
        SignContext::new(&key)
            .policy(policy)
            .sign_template(&template),
        Err(xml_sec::xmldsig::SigningError::Policy(
            PolicyViolation::HmacOutputLength {
                minimum: 128,
                maximum: 160,
                actual: 40,
            }
        ))
    ));
}

fn signing_key_for_template(path: &Path) -> Box<dyn SigningKey> {
    let name = path.file_name().and_then(|value| value.to_str()).unwrap();
    let key_path = |name: &str| format!("{XMLDSIG11_DIR}/keys/{name}");
    if name.contains("p256") || name == "signature-enveloping-derencoded-ec.tmpl" {
        Box::new(
            EcdsaP256SigningKey::from_pkcs8_der(
                &fs::read(key_path("p256-key-orig.der")).expect("P-256 key must be readable"),
            )
            .expect("P-256 key must parse"),
        )
    } else if name.contains("p384") {
        Box::new(
            EcdsaP384SigningKey::from_pkcs8_der(
                &fs::read(key_path("p384-key-orig.der")).expect("P-384 key must be readable"),
            )
            .expect("P-384 key must parse"),
        )
    } else if name.contains("p521") {
        Box::new(
            EcdsaP521SigningKey::from_pkcs8_der(
                &fs::read(key_path("p521-key-orig.der")).expect("P-521 key must be readable"),
            )
            .expect("P-521 key must parse"),
        )
    } else {
        Box::new(
            RsaSigningKey::from_pkcs8_der(
                &fs::read(key_path("rsa-key-orig.der")).expect("RSA key must be readable"),
            )
            .expect("RSA key must parse"),
        )
    }
}

#[test]
fn every_xmldsig11_template_signs_and_verifies() {
    // This exercises all 15 curve/hash combinations plus DEREncodedKeyValue,
    // KeyInfoReference, X509Digest, and RSA template wiring in both directions.
    let paths = sorted_files(XMLDSIG11_DIR, "tmpl");
    assert_eq!(paths.len(), 19, "fixture import must retain every template");
    let embedded_resolver = DefaultKeyResolver::default();
    let x509_resolver = x509_digest_resolver();
    let der_writer = DerEncodedKeyValueInfoWriter;
    let key_value_writer = KeyValueInfoWriter;
    let x509_digest_writer = X509DigestKeyInfoWriter::from_der(
        &fs::read(format!("{XMLDSIG11_DIR}/keys/rsa-key.crt"))
            .expect("RSA certificate fixture must be readable"),
        DigestAlgorithm::Sha256,
    )
    .expect("RSA certificate fixture must parse");

    for path in paths {
        let template = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let key = signing_key_for_template(&path);
        let name = path.file_name().and_then(|value| value.to_str()).unwrap();
        let mut signing = SignContext::new(key.as_ref()).policy(compatibility_signing_policy());
        if name.contains("derencoded") {
            signing = signing.key_info_writer(&der_writer);
        } else if name.contains("x509digest") {
            signing = signing.key_info_writer(&x509_digest_writer);
        } else if !name.contains("keyinforeference") {
            signing = signing.key_info_writer(&key_value_writer);
        }
        let signed = signing
            .sign_template(&template)
            .unwrap_or_else(|error| panic!("{} must sign: {error}", path.display()));
        let key_reference_resolver = if name.contains("keyinforeference") {
            let SigningPublicKeyInfo::Rsa { spki_der, .. } = key
                .public_key_info()
                .expect("RSA signing key must expose public material")
            else {
                panic!("KeyInfoReference fixture must use RSA");
            };
            let mut config = KeyResolverConfig::default();
            config.named_keys.insert(
                "TestKeyName-rsa-4096".into(),
                VerificationKey {
                    algorithm: SignatureAlgorithm::RsaSha256,
                    public_key_bytes: spki_der,
                    certificate_der: None,
                    name: Some("TestKeyName-rsa-4096".into()),
                },
            );
            Some(DefaultKeyResolver::new(config))
        } else {
            None
        };
        let resolver = if name.contains("x509digest") {
            &x509_resolver
        } else if let Some(resolver) = key_reference_resolver.as_ref() {
            resolver
        } else {
            &embedded_resolver
        };
        let result = VerifyContext::new()
            .key_resolver(resolver)
            .policy(compatibility_verification_policy())
            .verify(&signed)
            .unwrap_or_else(|error| {
                panic!("{} signed output must verify: {error}", path.display())
            });
        assert_valid(result.status, &path);
    }
}

#[test]
fn second_edition_vectors_remain_explicitly_fail_closed() {
    // This task must not accidentally widen the separate Second Edition scope.
    let paths = sorted_files(XMLDSIG2ED_DIR, "xml");
    assert_eq!(paths.len(), 9, "fixture import must retain the full corpus");
    let resolver = DefaultKeyResolver::default();
    for path in paths {
        let xml = fs::read_to_string(&path).expect("Second Edition fixture must be readable");
        assert!(
            VerifyContext::new()
                .key_resolver(&resolver)
                .verify(&xml)
                .is_err(),
            "{} must remain outside the implemented contract",
            path.display()
        );
    }
}

#[test]
fn dsa_sha256_upstream_vector_verifies_and_signs() {
    // XMLDSig 1.1 requires DSA-SHA256 even though the 2012 EC/HMAC corpus does
    // not include it; execute xmlsec1's encrypted-key vector in both directions.
    let key = DsaSigningKey::from_pkcs8_encrypted_der(
        include_bytes!("fixtures/xmldsig/keys/dsa/dsa-2048-key.p8-der"),
        b"secret123",
    )
    .expect("upstream encrypted DSA PKCS#8 key must parse");
    let SigningPublicKeyInfo::Dsa { spki_der, .. } = key
        .public_key_info()
        .expect("DSA signing key must expose public material")
    else {
        panic!("DSA signing key returned the wrong public-key kind");
    };
    let verification_key = VerificationKey {
        algorithm: SignatureAlgorithm::DsaSha256,
        public_key_bytes: spki_der,
        certificate_der: None,
        name: None,
    };
    let vector = fs::read_to_string(
        "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-dsa2048-sha256.xml",
    )
    .expect("DSA verification vector must be readable");
    let verified = VerifyContext::new()
        .key(&verification_key)
        .verify(&vector)
        .expect("upstream DSA-SHA256 vector must verify");
    assert_valid(
        verified.status,
        Path::new("enveloping-sha256-dsa2048-sha256.xml"),
    );

    let template = fs::read_to_string(
        "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-dsa2048-sha256.tmpl",
    )
    .expect("DSA signing template must be readable");
    let signed = SignContext::new(&key)
        .sign_template(&template)
        .expect("DSA-SHA256 template must sign");
    let result = VerifyContext::new()
        .key(&verification_key)
        .verify(&signed)
        .expect("generated DSA-SHA256 signature must verify");
    assert_valid(result.status, Path::new("generated DSA-SHA256"));
}

#[test]
fn dsa_sha1_rejects_a_key_with_a_256_bit_q() {
    // XMLDSig DSA-SHA1 fixes SignatureValue at two 160-bit components; a
    // 2048/256 key cannot be represented by that wire format.
    let key = DsaSigningKey::from_pkcs8_encrypted_der(
        include_bytes!("fixtures/xmldsig/keys/dsa/dsa-2048-key.p8-der"),
        b"secret123",
    )
    .expect("upstream encrypted DSA PKCS#8 key must parse");
    let policy = SigningPolicy {
        signature_algorithms: Some(HashSet::from([SignatureAlgorithm::DsaSha1])),
        ..SigningPolicy::default()
    };

    assert!(matches!(
        validate_signing_key(&key, SignatureAlgorithm::DsaSha1, &policy),
        Err(xml_sec::xmldsig::SigningError::Policy(
            PolicyViolation::InvalidKeyMaterial {
                operation: "signing",
                key_type: "DSA",
                reason: "DSA-SHA1 requires a 160-bit q parameter",
            }
        ))
    ));
    assert!(matches!(
        key.sign(SignatureAlgorithm::DsaSha1, b"signed info"),
        Err(SigningKeyError::InvalidPublicKeyInfo)
    ));
}
