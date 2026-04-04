//! Integration tests for real-world SAML response verification (ROADMAP P1-026).
//!
//! Uses a donor SAML 2.0 IdP response fixture to ensure XMLDSig verification
//! works against non-synthetic assertion payloads.

use xml_sec::xmldsig::{DsigStatus, FailureReason, verify_signature_with_pem_key};

const IDP_RESPONSE_SIGNED_XML: &str =
    include_str!("fixtures/saml/response_signed_by_idp_ecdsa.xml");

const IDP_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEyjU9gkG4ffc3WwyLF2Q4lmRlMmnw
lzJd31gHv5qBg74j1kKSaQWDZEkTHFt4g7AqIlRRqDt/u9euxVNa5RLqxg==
-----END PUBLIC KEY-----
";

#[test]
fn real_saml_idp_response_signature_is_valid() {
    let result = verify_signature_with_pem_key(IDP_RESPONSE_SIGNED_XML, IDP_PUBLIC_KEY_PEM, true)
        .expect("real SAML response should verify end-to-end");

    assert!(
        matches!(result.status, DsigStatus::Valid),
        "expected Valid status, got {:?}",
        result.status
    );
    assert_eq!(
        result.signed_info_references.len(),
        1,
        "expected exactly one SignedInfo reference"
    );
    assert!(matches!(
        result.signed_info_references[0].status,
        DsigStatus::Valid
    ));
}

#[test]
fn real_saml_idp_response_detects_reference_tampering() {
    assert!(
        IDP_RESPONSE_SIGNED_XML.contains("test@example.com"),
        "fixture must contain the signed value being tampered with"
    );

    let tampered = IDP_RESPONSE_SIGNED_XML.replacen("test@example.com", "tampered@example.com", 1);

    assert_ne!(
        tampered, IDP_RESPONSE_SIGNED_XML,
        "tampering must change the XML so this test exercises reference digest validation"
    );

    let result = verify_signature_with_pem_key(&tampered, IDP_PUBLIC_KEY_PEM, false)
        .expect("pipeline should complete with Invalid status on tampering");

    assert!(matches!(
        result.status,
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
    ));
}
