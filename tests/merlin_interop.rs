//! End-to-end coverage for the upstream Merlin XMLDSig interoperability corpus.

use std::{
    collections::HashMap,
    path::PathBuf,
    time::{Duration, SystemTime},
};

use x509_parser::prelude::{FromDer, X509Certificate};
use xml_sec::policy::KeyTrustPolicy;
use xml_sec::xmldsig::{
    DefaultKeyResolver, DsigError, DsigStatus, FailureReason, HmacSha1VerificationKey,
    KeyResolutionError, KeyResolverConfig, ParseError, SignatureAlgorithm, UriTypeSet,
    VerificationKey, VerifyContext, X509ChainError, XPathHereSemantics,
};

const MERLIN: &str = "tests/fixtures/xmldsig/merlin-xmldsig-twenty-three";
const DONOR_EXTERNAL: &str = "tests/fixtures/xmldsig/external-data";
const VERIFY_2005: u64 = 1_104_580_800;

fn chain_policy(check_crls: bool) -> KeyTrustPolicy {
    KeyTrustPolicy {
        verify_x509_chains: true,
        check_crls,
        verification_time: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(VERIFY_2005)),
        ..KeyTrustPolicy::default()
    }
}

fn legacy_policy(algorithm: SignatureAlgorithm) -> xml_sec::policy::VerificationPolicy {
    let mut policy = xml_sec::policy::VerificationPolicy::default();
    policy
        .key_trust
        .allowed_legacy_signature_algorithms
        .insert(algorithm);
    if algorithm == SignatureAlgorithm::DsaSha1 {
        policy.key_trust.dsa_keys.minimum_modulus_bits = 1024;
    }
    policy
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn bytes(path: &str) -> Vec<u8> {
    std::fs::read(root().join(path)).unwrap_or_else(|error| panic!("read {path}: {error}"))
}

fn xml(name: &str) -> String {
    String::from_utf8(bytes(&format!("{MERLIN}/{name}.xml"))).expect("fixture is UTF-8")
}

fn cert(name: &str) -> Vec<u8> {
    let path = format!("{MERLIN}/certs/{name}");
    let data = bytes(&path);
    if name.ends_with(".der") {
        return data;
    }
    let (rest, pem) = x509_parser::pem::parse_x509_pem(&data).expect("certificate PEM");
    assert!(rest.iter().all(u8::is_ascii_whitespace));
    pem.contents
}

fn verification_key(name: &str, algorithm: SignatureAlgorithm) -> VerificationKey {
    let der = cert(name);
    let (rest, certificate) = X509Certificate::from_der(&der).expect("certificate DER");
    assert!(rest.is_empty());
    VerificationKey {
        algorithm,
        public_key_bytes: certificate.public_key().raw.to_vec(),
        certificate_der: Some(der),
        name: None,
    }
}

fn external_resources() -> HashMap<String, Vec<u8>> {
    HashMap::from([
        (
            "http://www.w3.org/TR/xml-stylesheet".into(),
            bytes(&format!("{DONOR_EXTERNAL}/xml-stylesheet-2005")),
        ),
        (
            "http://www.w3.org/Signature/2002/04/xml-stylesheet.b64".into(),
            bytes(&format!("{DONOR_EXTERNAL}/xml-stylesheet-2005.b64")),
        ),
        (
            "tests/merlin-xmldsig-twenty-three/certs/balor.der".into(),
            cert("balor.der"),
        ),
    ])
}

fn assert_valid(
    name: &str,
    result: Result<xml_sec::xmldsig::VerifyResult, xml_sec::xmldsig::DsigError>,
) {
    let result = result.unwrap_or_else(|error| panic!("{name}: {error}"));
    assert_eq!(result.status, DsigStatus::Valid, "{name}");
    assert!(
        result
            .signed_info_references
            .iter()
            .all(|reference| reference.status == DsigStatus::Valid),
        "{name}: SignedInfo reference failure"
    );
}

#[test]
fn verifies_all_merlin_documents_with_upstream_expectations() {
    // Every signed document used by xmlsec's Merlin runner is classified here.
    let default = DefaultKeyResolver::default();
    for name in [
        "signature-enveloped-dsa",
        "signature-enveloping-dsa",
        "signature-enveloping-b64-dsa",
    ] {
        assert_valid(
            name,
            VerifyContext::new()
                .policy(legacy_policy(SignatureAlgorithm::DsaSha1))
                .key_resolver(&default)
                .verify(&xml(name)),
        );
    }
    let legacy_rsa = DefaultKeyResolver::default();
    let mut rsa_policy = xml_sec::policy::VerificationPolicy::default();
    rsa_policy
        .key_trust
        .allowed_legacy_signature_algorithms
        .insert(SignatureAlgorithm::RsaSha1);
    rsa_policy.key_trust.rsa_keys.minimum_modulus_bits = 1024;
    assert_valid(
        "signature-enveloping-rsa",
        VerifyContext::new()
            .policy(rsa_policy)
            .key_resolver(&legacy_rsa)
            .verify(&xml("signature-enveloping-rsa")),
    );

    let hmac = HmacSha1VerificationKey::new(b"secret".to_vec()).expect("valid HMAC key");
    assert_valid(
        "signature-enveloping-hmac-sha1",
        VerifyContext::new()
            .policy(legacy_policy(SignatureAlgorithm::HmacSha1))
            .key(&hmac)
            .verify(&xml("signature-enveloping-hmac-sha1")),
    );
    let truncated_hmac = HmacSha1VerificationKey::new(b"secret".to_vec())
        .expect("valid HMAC key")
        .with_output_length_bits(80)
        .expect("valid XMLDSig truncation");
    assert_valid(
        "signature-enveloping-hmac-sha1-80",
        VerifyContext::new()
            .policy(legacy_policy(SignatureAlgorithm::HmacSha1))
            .key(&truncated_hmac)
            .verify(&xml("signature-enveloping-hmac-sha1-80")),
    );

    let resources = external_resources();
    for name in ["signature-external-dsa", "signature-external-b64-dsa"] {
        assert_valid(
            name,
            VerifyContext::new()
                .policy(legacy_policy(SignatureAlgorithm::DsaSha1))
                .key_resolver(&default)
                .allowed_uri_types(UriTypeSet::ALL)
                .external_resources(&resources)
                .verify(&xml(name)),
        );
    }

    let mut named = KeyResolverConfig::default();
    named.named_keys.insert(
        "Lugh".into(),
        verification_key("lugh-cert.pem", SignatureAlgorithm::DsaSha1),
    );
    let named = DefaultKeyResolver::new(named);
    assert_valid(
        "signature-keyname",
        VerifyContext::new()
            .policy(legacy_policy(SignatureAlgorithm::DsaSha1))
            .key_resolver(&named)
            .allowed_uri_types(UriTypeSet::ALL)
            .external_resources(&resources)
            .verify(&xml("signature-keyname")),
    );

    for (name, selected) in [
        ("signature-x509-crt", None),
        ("signature-x509-sn", Some("badb.pem")),
        ("signature-x509-is", Some("macha.pem")),
        ("signature-x509-ski", Some("nemain.pem")),
    ] {
        let lookup_certs = selected.into_iter().map(cert).collect();
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            lookup_certs,
            trusted_certs: vec![cert("ca.pem")],
            trust: chain_policy(false),
            ..KeyResolverConfig::default()
        });
        assert_valid(
            name,
            VerifyContext::new()
                .policy(legacy_policy(SignatureAlgorithm::DsaSha1))
                .key_resolver(&resolver)
                .allowed_uri_types(UriTypeSet::ALL)
                .external_resources(&resources)
                .verify(&xml(name)),
        );
    }

    let retrieval = DefaultKeyResolver::new(KeyResolverConfig {
        lookup_certs: vec![cert("balor.pem")],
        trusted_certs: vec![cert("ca.pem")],
        trust: chain_policy(false),
        ..KeyResolverConfig::default()
    });
    assert_valid(
        "signature-retrievalmethod-rawx509crt",
        VerifyContext::new()
            .policy(legacy_policy(SignatureAlgorithm::DsaSha1))
            .key_resolver(&retrieval)
            .allowed_uri_types(UriTypeSet::ALL)
            .allowed_retrieval_method_uri_types(UriTypeSet::ALL)
            .external_resources(&resources)
            .verify(&xml("signature-retrievalmethod-rawx509crt")),
    );

    // The upstream runner's newer detached resource also mismatches the old
    // digest. Use the signed 2005 bytes and a certificate-valid timestamp so
    // this assertion reaches and proves the embedded CRL decision itself.
    let revoked_resources = external_resources();
    let revoked = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: vec![cert("ca.pem")],
        trust: chain_policy(true),
        ..KeyResolverConfig::default()
    });
    let revoked_error = VerifyContext::new()
        .policy(legacy_policy(SignatureAlgorithm::DsaSha1))
        .key_resolver(&revoked)
        .allowed_uri_types(UriTypeSet::ALL)
        .external_resources(&revoked_resources)
        .verify(&xml("signature-x509-crt-crl"))
        .expect_err("the donor CRL revokes the signing certificate");
    // Merlin's CA restricts KeyUsage to keyCertSign, so RFC 5280 requires
    // rejecting its CRL before trusting the listed revoked serial. Dedicated
    // chain tests cover the Revoked result for an authorized cRLSign issuer.
    assert!(
        matches!(
            revoked_error,
            DsigError::KeyResolution(KeyResolutionError::Chain(X509ChainError::InvalidKeyUsage {
                position: 1,
                required: "cRLSign"
            }))
        ),
        "unexpected revoked-vector error: {revoked_error:?}"
    );

    let complex = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: vec![cert("merlin.pem")],
        trust: KeyTrustPolicy {
            verification_time: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(VERIFY_2005)),
            ..KeyTrustPolicy::default()
        },
        ..KeyResolverConfig::default()
    });
    let result = VerifyContext::new()
        .policy(legacy_policy(SignatureAlgorithm::DsaSha1))
        .key_resolver(&complex)
        .allowed_uri_types(UriTypeSet::ALL)
        .external_resources(&resources)
        .process_manifests(true)
        .store_pre_digest(true)
        .allow_internal_dtd(true)
        .xpath_here_semantics(XPathHereSemantics::XmlSecLegacy)
        .verify(&xml("signature"))
        .expect("complex signature pipeline");
    assert_eq!(result.status, DsigStatus::Valid);
    let expected_signed_info_uris = [
        "http://www.w3.org/TR/xml-stylesheet",
        "http://www.w3.org/Signature/2002/04/xml-stylesheet.b64",
        "#object-1",
        "",
        "#object-2",
        "#manifest-1",
        "#signature-properties-1",
        "",
        "",
        "#xpointer(/)",
        "#xpointer(/)",
        "#object-3",
        "#object-3",
        "#xpointer(id('object-3'))",
        "#xpointer(id('object-3'))",
        "#reference-2",
        "#manifest-reference-1",
        "#reference-1",
    ];
    assert_eq!(
        result.signed_info_references.len(),
        expected_signed_info_uris.len()
    );
    for (reference, expected_uri) in result
        .signed_info_references
        .iter()
        .zip(expected_signed_info_uris)
    {
        assert_eq!(reference.uri, expected_uri);
        assert_eq!(reference.status, DsigStatus::Valid, "{expected_uri}");
    }

    let expected_manifest = [
        ("http://www.w3.org/TR/xml-stylesheet", DsigStatus::Valid),
        ("#reference-1", DsigStatus::Valid),
        (
            "#notaries",
            // The donor uses an XSLT transform, which this pure-Rust profile
            // intentionally does not execute; failure occurs before digest comparison.
            DsigStatus::Invalid(FailureReason::ReferenceProcessingFailure { ref_index: 2 }),
        ),
    ];
    assert_eq!(result.manifest_references.len(), expected_manifest.len());
    for (reference, (expected_uri, expected_status)) in
        result.manifest_references.iter().zip(expected_manifest)
    {
        assert_eq!(reference.uri, expected_uri);
        assert_eq!(reference.status, expected_status, "{expected_uri}");
    }
}

#[test]
fn pre_resolved_dsa_key_obeys_the_relaxed_operation_strength_policy() {
    // Compatibility policy must apply identically to direct and resolved keys;
    // the built-in key must not reapply a stricter hidden default afterward.
    let key = verification_key("lugh-cert.pem", SignatureAlgorithm::DsaSha1);
    assert_valid(
        "direct legacy DSA key",
        VerifyContext::new()
            .policy(legacy_policy(SignatureAlgorithm::DsaSha1))
            .key(&key)
            .allowed_uri_types(UriTypeSet::ALL)
            .external_resources(&external_resources())
            .verify(&xml("signature-keyname")),
    );
}

#[test]
fn rejects_missing_or_tampered_external_resources() {
    // Detached references cannot trigger I/O and must fail on absent or altered caller bytes.
    let default = DefaultKeyResolver::default();
    let document = xml("signature-external-dsa");
    let missing = HashMap::new();
    assert!(matches!(
        VerifyContext::new()
            .policy(legacy_policy(SignatureAlgorithm::DsaSha1))
            .key_resolver(&default)
            .allowed_uri_types(UriTypeSet::ALL)
            .external_resources(&missing)
            .verify(&document),
        Err(DsigError::Reference(
            xml_sec::xmldsig::ReferenceProcessingError::UriDereference(
                xml_sec::xmldsig::TransformError::UnsupportedUri(uri)
            )
        )) if uri == "http://www.w3.org/TR/xml-stylesheet"
    ));

    let mut tampered = external_resources();
    tampered.insert(
        "http://www.w3.org/TR/xml-stylesheet".into(),
        b"tampered".to_vec(),
    );
    let result = VerifyContext::new()
        .policy(legacy_policy(SignatureAlgorithm::DsaSha1))
        .key_resolver(&default)
        .allowed_uri_types(UriTypeSet::ALL)
        .external_resources(&tampered)
        .verify(&document)
        .expect("tampering is a validation result");
    assert_ne!(result.status, DsigStatus::Valid);
}

#[test]
fn bounds_external_resources_before_dereference() {
    // Resource limits are enforced for the complete caller map, not only the referenced entry.
    let default = DefaultKeyResolver::default();
    let mut oversized = external_resources();
    oversized.insert("urn:oversized".into(), vec![0; 8 * 1024 * 1024 + 1]);
    assert!(matches!(
        VerifyContext::new()
            .policy(legacy_policy(SignatureAlgorithm::DsaSha1))
            .key_resolver(&default)
            .allowed_uri_types(UriTypeSet::ALL)
            .external_resources(&oversized)
            .verify(&xml("signature-external-dsa")),
        Err(DsigError::Policy(
            xml_sec::policy::PolicyViolation::ResourceLimit {
                resource: "external resource bytes",
                ..
            }
        ))
    ));

    let mut aggregate = external_resources();
    aggregate
        .extend((0..5).map(|index| (format!("urn:aggregate:{index}"), vec![0; 7 * 1024 * 1024])));
    assert!(matches!(
        VerifyContext::new()
            .policy(legacy_policy(SignatureAlgorithm::DsaSha1))
            .key_resolver(&default)
            .allowed_uri_types(UriTypeSet::ALL)
            .external_resources(&aggregate)
            .verify(&xml("signature-external-dsa")),
        Err(DsigError::Policy(
            xml_sec::policy::PolicyViolation::ResourceLimit {
                resource: "aggregate external resource bytes",
                ..
            }
        ))
    ));
}

#[test]
fn rejects_wrong_hmac_key_and_invalid_output_length() {
    // MAC mismatch is an invalid status; malformed truncation is a processing error.
    let wrong = HmacSha1VerificationKey::new(b"wrong".to_vec()).expect("valid HMAC key");
    let result = VerifyContext::new()
        .policy(legacy_policy(SignatureAlgorithm::HmacSha1))
        .key(&wrong)
        .verify(&xml("signature-enveloping-hmac-sha1"))
        .expect("wrong MAC is a validation result");
    assert_ne!(result.status, DsigStatus::Valid);

    let malformed = xml("signature-enveloping-hmac-sha1-80").replacen(
        "<HMACOutputLength>80</HMACOutputLength>",
        "<HMACOutputLength>72</HMACOutputLength>",
        1,
    );
    assert!(malformed.contains("<HMACOutputLength>72</HMACOutputLength>"));
    assert!(matches!(
        VerifyContext::new()
            .policy(legacy_policy(SignatureAlgorithm::HmacSha1))
            .key(&wrong)
            .verify(&malformed),
        Err(DsigError::ParseSignedInfo(ParseError::InvalidStructure(reason)))
            if reason == "HMACOutputLength must be a byte-aligned value from 80 through 160"
    ));

    let implicit_full_length = xml("signature-enveloping-hmac-sha1-80").replacen(
        "<HMACOutputLength>80</HMACOutputLength>",
        "",
        1,
    );
    assert!(matches!(
        VerifyContext::new()
            .policy(legacy_policy(SignatureAlgorithm::HmacSha1))
            .key(&wrong)
            .verify(&implicit_full_length),
        Err(DsigError::InvalidStructure {
            reason: "SignatureValue length does not match HMACOutputLength"
        })
    ));
}

#[test]
fn rejects_malformed_dsa_key_value() {
    // Invalid CryptoBinary input must be rejected before DSA key construction.
    let malformed = xml("signature-enveloped-dsa").replacen("cfYpihpAQeep", "!!!!ihpAQeep", 1);
    assert!(malformed.contains("!!!!ihpAQeep"));
    assert!(matches!(
        VerifyContext::new()
            .policy(legacy_policy(SignatureAlgorithm::DsaSha1))
            .key_resolver(&DefaultKeyResolver::default())
            .verify(&malformed),
        Err(DsigError::ParseKeyInfo(ParseError::Base64(_)))
    ));
}

#[test]
fn partial_dsa_key_value_falls_back_to_later_complete_key() {
    // XMLDSig permits Y-only DSAKeyValue sources; an unusable first source must
    // not prevent a later complete DSAKeyValue from verifying the signature.
    let document = xml("signature-enveloped-dsa").replacen(
        "<KeyInfo>\n      <KeyValue>",
        "<KeyInfo>\n      <KeyValue><DSAKeyValue><Y>AQ==</Y></DSAKeyValue></KeyValue>\n      <KeyValue>",
        1,
    );
    assert!(document.contains("<DSAKeyValue><Y>AQ==</Y></DSAKeyValue>"));

    assert_valid(
        "partial DSAKeyValue fallback",
        VerifyContext::new()
            .policy(legacy_policy(SignatureAlgorithm::DsaSha1))
            .key_resolver(&DefaultKeyResolver::default())
            .verify(&document),
    );
}

#[test]
fn rejects_missing_ambiguous_and_weak_key_resolution() {
    // KeyName, RetrievalMethod IDs, and legacy RSA policy each fail closed.
    let resources = external_resources();
    let missing = VerifyContext::new()
        .policy(legacy_policy(SignatureAlgorithm::DsaSha1))
        .key_resolver(&DefaultKeyResolver::default())
        .allowed_uri_types(UriTypeSet::ALL)
        .external_resources(&resources)
        .verify(&xml("signature-keyname"));
    assert!(matches!(
        missing,
        Ok(result) if result.status == DsigStatus::Invalid(FailureReason::KeyNotFound)
    ));

    let ambiguous = xml("signature").replacen(
        "<Object Id=\"object-4\">",
        "<Object Id=\"object-4\"/><Object Id=\"object-4\">",
        1,
    );
    let ambiguous_error = VerifyContext::new()
        .policy(legacy_policy(SignatureAlgorithm::DsaSha1))
        .key_resolver(&DefaultKeyResolver::default())
        .allow_internal_dtd(true)
        .allowed_uri_types(UriTypeSet::ALL)
        .external_resources(&resources)
        .verify(&ambiguous)
        .expect_err("duplicate ID must fail before key resolution");
    assert!(
        matches!(
            ambiguous_error,
            DsigError::InvalidStructure {
                reason: "X509Data RetrievalMethod target is missing or ambiguous"
            }
        ),
        "unexpected duplicate-ID error: {ambiguous_error:?}"
    );

    let weak = VerifyContext::new()
        .key_resolver(&DefaultKeyResolver::default())
        .verify(&xml("signature-enveloping-rsa"));
    assert!(matches!(
        weak,
        Err(DsigError::Policy(
            xml_sec::policy::PolicyViolation::Algorithm {
                operation: "verification",
                ..
            }
        ))
    ));
}

#[test]
fn rejects_dtd_and_unsupported_retrieval_defaults() {
    // Internal DTD parsing and RetrievalMethod transform compatibility require exact opt-ins.
    assert!(matches!(
        VerifyContext::new()
            .policy(legacy_policy(SignatureAlgorithm::DsaSha1))
            .key_resolver(&DefaultKeyResolver::default())
            .verify(&xml("signature")),
        Err(DsigError::XmlParse(_))
    ));

    let unsupported = xml("signature").replacen(
        "ancestor-or-self::dsig:X509Data",
        "descendant-or-self::dsig:X509Data",
        1,
    );
    let resources = external_resources();
    let unsupported_error = VerifyContext::new()
        .policy(legacy_policy(SignatureAlgorithm::DsaSha1))
        .key_resolver(&DefaultKeyResolver::default())
        .allow_internal_dtd(true)
        .allowed_uri_types(UriTypeSet::ALL)
        .external_resources(&resources)
        .verify(&unsupported)
        .expect_err("unsupported RetrievalMethod XPath must fail closed");
    assert!(matches!(
        unsupported_error,
        DsigError::ParseKeyInfo(ParseError::InvalidStructure(reason))
            if reason == "unsupported RetrievalMethod XPath selection"
    ));

    let retrieval = DefaultKeyResolver::new(KeyResolverConfig {
        lookup_certs: vec![cert("balor.pem")],
        trusted_certs: vec![cert("ca.pem")],
        trust: chain_policy(false),
        ..KeyResolverConfig::default()
    });
    let reference_error = VerifyContext::new()
        .policy(legacy_policy(SignatureAlgorithm::DsaSha1))
        .key_resolver(&retrieval)
        .external_resources(&resources)
        .verify(&xml("signature-retrievalmethod-rawx509crt"))
        .expect_err("external SignedInfo reference must require an explicit opt-in");
    assert!(matches!(
        reference_error,
        DsigError::DisallowedUri { uri }
            if uri == "http://www.w3.org/TR/xml-stylesheet"
    ));

    let retrieval_error = VerifyContext::new()
        .policy(legacy_policy(SignatureAlgorithm::DsaSha1))
        .key_resolver(&retrieval)
        .allowed_uri_types(UriTypeSet::ALL)
        .external_resources(&resources)
        .verify(&xml("signature-retrievalmethod-rawx509crt"))
        .expect_err("external key retrieval must require its own explicit opt-in");
    assert!(matches!(
        retrieval_error,
        DsigError::DisallowedUri { uri }
            if uri == "tests/merlin-xmldsig-twenty-three/certs/balor.der"
    ));
}
