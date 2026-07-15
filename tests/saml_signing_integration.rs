//! End-to-end signing tests for SAML Response XML documents.
//!
//! The SAML schema requires an enveloped XMLDSig signature immediately after
//! the response issuer. These tests ensure the generic XMLDSig signing API can
//! fill a SAML-shaped template without moving that schema-significant element.

use roxmltree::Document;
use xml_sec::xmldsig::{
    DefaultKeyResolver, DsigStatus, FailureReason, RsaSigningKey, SignContext, VerifyContext,
    X509CertificateKeyInfoWriter,
};

const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const SAML_ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const SAML_PROTOCOL_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const SAML_RESPONSE_TEMPLATE: &str = include_str!("fixtures/saml/response_signing_template.xml");
const RSA_PRIVATE_KEY_PEM: &str = include_str!("fixtures/keys/rsa/rsa-2048-key.pem");
const RSA_CERTIFICATE_PEM: &str = include_str!("fixtures/keys/rsa/rsa-2048-cert.pem");

fn signed_saml_response() -> String {
    let signing_key =
        RsaSigningKey::from_pkcs8_pem(RSA_PRIVATE_KEY_PEM).expect("RSA fixture key must parse");
    let key_info_writer = X509CertificateKeyInfoWriter::from_pem(RSA_CERTIFICATE_PEM)
        .expect("RSA fixture certificate must parse");

    SignContext::new(&signing_key)
        .key_info_writer(&key_info_writer)
        .sign_template(SAML_RESPONSE_TEMPLATE)
        .expect("SAML Response signing template must complete")
}

#[test]
fn signs_saml_response_with_schema_order_and_embedded_certificate() {
    // SAML consumers expect the response signature between Issuer and Status;
    // appending it to the root would make the document schema-invalid.
    let signed = signed_saml_response();
    let document = Document::parse(&signed).expect("signed response must remain well-formed XML");
    let response = document.root_element();

    assert_eq!(response.tag_name().name(), "Response");
    assert_eq!(response.tag_name().namespace(), Some(SAML_PROTOCOL_NS));
    assert_eq!(response.attribute("ID"), Some("_signed-response"));

    let children = response
        .children()
        .filter(|node| node.is_element())
        .collect::<Vec<_>>();
    assert_eq!(
        children.len(),
        4,
        "response must keep its four schema children"
    );
    assert_eq!(children[0].tag_name().name(), "Issuer");
    assert_eq!(children[0].tag_name().namespace(), Some(SAML_ASSERTION_NS));
    assert_eq!(children[1].tag_name().name(), "Signature");
    assert_eq!(children[1].tag_name().namespace(), Some(XMLDSIG_NS));
    assert_eq!(children[2].tag_name().name(), "Status");
    assert_eq!(children[2].tag_name().namespace(), Some(SAML_PROTOCOL_NS));
    assert_eq!(children[3].tag_name().name(), "Assertion");
    assert_eq!(children[3].tag_name().namespace(), Some(SAML_ASSERTION_NS));

    let signature = children[1];
    let signed_info = signature
        .children()
        .find(|node| node.has_tag_name((XMLDSIG_NS, "SignedInfo")))
        .expect("signature must include SignedInfo");
    let reference = signed_info
        .children()
        .find(|node| node.has_tag_name((XMLDSIG_NS, "Reference")))
        .expect("SignedInfo must include a Reference");
    assert_eq!(reference.attribute("URI"), Some("#_signed-response"));

    for element_name in ["DigestValue", "SignatureValue", "X509Certificate"] {
        let node = signature
            .descendants()
            .find(|node| node.has_tag_name((XMLDSIG_NS, element_name)))
            .unwrap_or_else(|| panic!("signature must include {element_name}"));
        assert!(
            node.text().is_some_and(|value| !value.trim().is_empty()),
            "{element_name} must be populated by the signing pipeline"
        );
    }

    let key_resolver = DefaultKeyResolver::default();
    let result = VerifyContext::new()
        .key_resolver(&key_resolver)
        .verify(&signed)
        .expect("embedded X.509 key resolution must complete");
    assert_eq!(result.status, DsigStatus::Valid);
    assert!(matches!(
        result.signed_info_references[0].status,
        DsigStatus::Valid
    ));
}

#[test]
fn rejects_tampered_saml_assertion_before_signature_verification() {
    // The response Reference covers the full document with the enveloped
    // signature removed. Changing assertion data must fail at the digest gate.
    let signed = signed_saml_response();
    let tampered = signed.replacen("administrator", "attacker", 1);
    assert_ne!(
        tampered, signed,
        "tampering must alter the signed assertion"
    );

    let key_resolver = DefaultKeyResolver::default();
    let result = VerifyContext::new()
        .key_resolver(&key_resolver)
        .verify(&tampered)
        .expect("digest mismatch must return an Invalid status");
    assert_eq!(
        result.status,
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
    );
}
