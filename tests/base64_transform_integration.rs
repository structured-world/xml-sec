//! End-to-end XMLDSig Base64 transform coverage.

use std::fs;

use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::xmldsig::{
    BASE64_TRANSFORM_URI, DefaultKeyResolver, DigestAlgorithm, DsigError, DsigStatus,
    FailureReason, ReferenceBuilder, ReferenceProcessingError, RsaSigningKey, SignContext,
    SignatureAlgorithm, SignatureBuilder, Transform, TransformError, VerifyContext,
    X509CertificateKeyInfoWriter,
};

const ENCODED_XML: &str = r#"<root>
    <Encoded ID="payload">ZXh0<!-- split --><Chunk>ZXJuYWwg</Chunk><?ignored data?>dmVyaWZpZXIgY29udHJhY3Q=</Encoded>
</root>"#;

fn exclusive_c14n() -> C14nAlgorithm {
    C14nAlgorithm::new(C14nMode::Exclusive1_0, false)
}

fn signing_material() -> (RsaSigningKey, X509CertificateKeyInfoWriter) {
    let private_key = fs::read_to_string("tests/fixtures/keys/rsa/rsa-2048-key.pem")
        .expect("RSA private-key fixture must load");
    let certificate = fs::read_to_string("tests/fixtures/keys/rsa/rsa-2048-cert.pem")
        .expect("RSA certificate fixture must load");
    (
        RsaSigningKey::from_pkcs8_pem(&private_key).expect("RSA private key must parse"),
        X509CertificateKeyInfoWriter::from_pem(&certificate).expect("RSA certificate must parse"),
    )
}

fn base64_signature_builder() -> SignatureBuilder {
    SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#payload")
                .transform(Transform::Base64Decode),
        )
        .key_info(true)
}

fn sign_encoded_xml(xml: &str) -> String {
    let (key, key_info) = signing_material();
    SignContext::new(&key)
        .key_info_writer(&key_info)
        .sign_with_builder(xml, &base64_signature_builder())
        .expect("Base64 reference must sign")
}

#[test]
fn base64_reference_round_trips_through_signing_and_verification() {
    // This exercises template serialization, transform parsing, node-set text
    // extraction, digest generation, KeyInfo resolution, and verification.
    let signed = sign_encoded_xml(ENCODED_XML);
    assert!(signed.contains(&format!("Algorithm=\"{BASE64_TRANSFORM_URI}\"")));

    let resolver = DefaultKeyResolver::default();
    let verified = VerifyContext::new()
        .key_resolver(&resolver)
        .allowed_transforms([BASE64_TRANSFORM_URI])
        .store_pre_digest(true)
        .verify(&signed)
        .expect("signed Base64 reference must verify");

    assert_eq!(verified.status, DsigStatus::Valid);
    assert_eq!(verified.signed_info_references.len(), 1);
    assert_eq!(
        verified.signed_info_references[0]
            .pre_digest_data
            .as_deref(),
        Some(b"external verifier contract".as_slice())
    );
}

#[test]
fn base64_reference_tampering_is_a_digest_mismatch() {
    // A valid alternate Base64 payload must reach digest comparison and fail
    // there, rather than being misclassified as a transform processing error.
    let signed = sign_encoded_xml(ENCODED_XML);
    let tampered = signed.replacen(
        "dmVyaWZpZXIgY29udHJhY3Q=",
        "dGFtcGVyZWQgY29udGVudCAgICAgICA=",
        1,
    );
    let resolver = DefaultKeyResolver::default();

    let verified = VerifyContext::new()
        .key_resolver(&resolver)
        .verify(&tampered)
        .expect("well-formed tampered Base64 must complete verification");

    assert_eq!(
        verified.status,
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
    );
}

#[test]
fn malformed_base64_reference_fails_before_digest_comparison() {
    // Invalid encoded content has no well-defined digest input and therefore
    // must remain a processing error, distinct from a valid-but-changed value.
    let signed = sign_encoded_xml(ENCODED_XML);
    let malformed = signed.replacen("dmVyaWZpZXIgY29udHJhY3Q=", "not!base64", 1);
    let resolver = DefaultKeyResolver::default();

    let error = VerifyContext::new()
        .key_resolver(&resolver)
        .verify(&malformed)
        .expect_err("malformed Base64 transform input must fail closed");

    assert!(matches!(
        error,
        DsigError::Reference(ReferenceProcessingError::Transform(TransformError::Base64(
            _
        )))
    ));
}
