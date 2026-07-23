//! End-to-end XMLDSig XPath and XPath Filter 2.0 coverage.

use std::fs;

use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::xmldsig::{
    DEFAULT_IMPLICIT_C14N_URI, DefaultKeyResolver, DigestAlgorithm, DsigError, DsigStatus,
    FailureReason, ParseError, ReferenceBuilder, ReferenceProcessingError, RsaSigningKey,
    SignContext, SignatureAlgorithm, SignatureBuilder, Transform, TransformError, VerifyContext,
    X509CertificateKeyInfoWriter, XPATH_FILTER2_TRANSFORM_URI, XPATH_TRANSFORM_URI,
    XPathExpression, XPathFilter, XPathFilterOperation, XPathHereSemantics,
};

const DOCUMENT: &str = r#"<root>
  <Signed><Keep>covered</Keep><Excluded>mutable</Excluded></Signed>
  <Outside>also mutable</Outside>
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

fn filter2_builder() -> SignatureBuilder {
    let filters = vec![
        XPathFilter::new(
            XPathFilterOperation::Intersect,
            XPathExpression::new("/root/Signed"),
        ),
        XPathFilter::new(
            XPathFilterOperation::Subtract,
            XPathExpression::new("/root/Signed/Excluded"),
        ),
    ];
    SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("")
                .transform(Transform::XPathFilter2(filters)),
        )
        .key_info(true)
}

fn sign_document() -> String {
    let (key, key_info) = signing_material();
    SignContext::new(&key)
        .key_info_writer(&key_info)
        .sign_with_builder(DOCUMENT, &filter2_builder())
        .expect("XPath Filter 2.0 document must sign")
}

fn verify(signed: &str) -> Result<xml_sec::xmldsig::VerifyResult, DsigError> {
    let resolver = DefaultKeyResolver::default();
    VerifyContext::new()
        .key_resolver(&resolver)
        .allowed_transforms([XPATH_FILTER2_TRANSFORM_URI, DEFAULT_IMPLICIT_C14N_URI])
        .verify(signed)
}

#[test]
fn filter2_round_trips_through_signing_and_verification() {
    // This crosses template serialization, strict parsing, XPath evaluation,
    // implicit C14N, RSA signing, embedded-certificate resolution, and verify.
    let signed = sign_document();
    assert!(signed.contains(&format!("Algorithm=\"{XPATH_FILTER2_TRANSFORM_URI}\"")));

    let verified = verify(&signed).expect("generated Filter 2.0 signature must verify");
    assert_eq!(verified.status, DsigStatus::Valid);
}

#[test]
fn filter2_detects_tampering_in_intersected_subtree() {
    // Included text is part of the pre-digest octets, so a well-formed change
    // must reach digest comparison and produce a reference mismatch.
    let signed = sign_document();
    let tampered = signed.replacen("covered", "tampered", 1);

    let verified = verify(&tampered).expect("included-data tampering remains processable");
    assert_eq!(
        verified.status,
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
    );
}

#[test]
fn filter2_ignores_tampering_in_subtracted_and_outside_subtrees() {
    // Sequential intersect/subtract means neither the explicitly subtracted
    // node nor content outside the initial intersection contributes bytes.
    let signed = sign_document();
    let tampered =
        signed
            .replacen("mutable", "changed", 1)
            .replacen("also mutable", "also changed", 1);

    let verified = verify(&tampered).expect("excluded-data change must remain verifiable");
    assert_eq!(verified.status, DsigStatus::Valid);
}

#[test]
fn malformed_filter2_expression_fails_before_digest_comparison() {
    // An invalid expression has no defined node set and remains a transform
    // processing error rather than being reported as ordinary data tampering.
    let signed = sign_document();
    let malformed = signed.replacen("/root/Signed", "[", 1);

    let error = verify(&malformed).expect_err("malformed XPath must fail closed");
    assert!(matches!(
        error,
        DsigError::Reference(ReferenceProcessingError::Transform(TransformError::XPath(
            _
        ))) | DsigError::ParseSignedInfo(ParseError::Transform(TransformError::XPath(_)))
    ));
}

#[test]
fn filter2_transform_is_enforced_by_the_allowlist() {
    // Policy validation happens before transform execution and cannot be
    // bypassed merely because implicit C14N itself is allowed.
    let signed = sign_document();
    let resolver = DefaultKeyResolver::default();
    let error = VerifyContext::new()
        .key_resolver(&resolver)
        .allowed_transforms([DEFAULT_IMPLICIT_C14N_URI])
        .verify(&signed)
        .expect_err("unlisted Filter 2.0 transform must be rejected");

    assert!(
        matches!(error, DsigError::DisallowedTransform { algorithm } if algorithm == XPATH_FILTER2_TRANSFORM_URI)
    );
}

#[test]
fn here_semantics_are_explicit_across_signing_and_verification() {
    // The identity expression selects XPath under the specification and
    // Transform under libxmlsec1, proving the policy reaches both pipelines.
    let builder = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("")
                .transform(Transform::XPath(XPathExpression::new(
                    "count(. | here()) = 1",
                ))),
        )
        .key_info(true);
    let (key, key_info) = signing_material();
    let resolver = DefaultKeyResolver::default();

    let standard = SignContext::new(&key)
        .key_info_writer(&key_info)
        .sign_with_builder(DOCUMENT, &builder)
        .expect("standards-mode XPath document must sign");
    let standard_result = VerifyContext::new()
        .key_resolver(&resolver)
        .allowed_transforms([XPATH_TRANSFORM_URI, DEFAULT_IMPLICIT_C14N_URI])
        .verify(&standard)
        .expect("standards-mode signature must be processable");
    assert_eq!(standard_result.status, DsigStatus::Valid);
    let wrong_legacy_result = VerifyContext::new()
        .key_resolver(&resolver)
        .xpath_here_semantics(XPathHereSemantics::XmlSecLegacy)
        .verify(&standard)
        .expect("legacy-mode verification must reach digest comparison");
    assert_eq!(
        wrong_legacy_result.status,
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
    );

    let legacy = SignContext::new(&key)
        .key_info_writer(&key_info)
        .xpath_here_semantics(XPathHereSemantics::XmlSecLegacy)
        .sign_with_builder(DOCUMENT, &builder)
        .expect("xmlsec-legacy XPath document must sign");
    let legacy_result = VerifyContext::new()
        .key_resolver(&resolver)
        .xpath_here_semantics(XPathHereSemantics::XmlSecLegacy)
        .verify(&legacy)
        .expect("xmlsec-legacy signature must be processable");
    assert_eq!(legacy_result.status, DsigStatus::Valid);
    let wrong_standard_result = VerifyContext::new()
        .key_resolver(&resolver)
        .verify(&legacy)
        .expect("standards-mode verification must reach digest comparison");
    assert_eq!(
        wrong_standard_result.status,
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
    );
}
