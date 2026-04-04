//! Integration tests for real-world SAML response verification.
//! Covers PR #44.
//!
//! Uses a donor SAML 2.0 IdP response fixture to ensure XMLDSig verification
//! works against non-synthetic assertion payloads.

use xml_sec::xmldsig::{DsigStatus, FailureReason, verify_signature_with_pem_key};

const IDP_RESPONSE_SIGNED_XML: &str =
    include_str!("fixtures/saml/response_signed_by_idp_ecdsa.xml");

// Fixture intentionally uses legacy SHA-1 DigestMethod for donor-compat coverage.
const IDP_PUBLIC_KEY_PEM: &str = include_str!("fixtures/keys/ec/saml-idp-ecdsa-pubkey.pem");

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
    assert!(
        result.signed_info_references[0].pre_digest_data.is_some(),
        "store_pre_digest=true must populate pre_digest_data for SignedInfo references"
    );
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
