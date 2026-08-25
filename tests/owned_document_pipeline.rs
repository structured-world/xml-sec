//! Cross-component coverage for the reusable owned XML document boundary.

#![cfg(all(feature = "xmldsig", feature = "xmlenc"))]

use xml_sec::XmlDocument;
use xml_sec::c14n::{C14nAlgorithm, C14nMode, canonicalize_document};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, DsigStatus, ReferenceBuilder, RsaSigningKey, SignContext,
    SignatureAlgorithm, SignatureBuilder, Transform, VerifyContext, X509CertificateKeyInfoWriter,
    XPathExpression,
};
use xml_sec::xmlenc::{
    DataEncryptionAlgorithm, DecryptContext, DocumentEncryptionOptions, EncryptedDataBuilder,
    SymmetricKeyDecryptor,
};

const PRIVATE_KEY: &str = include_str!("fixtures/keys/rsa/rsa-2048-key.pem");
const CERTIFICATE: &str = include_str!("fixtures/keys/rsa/rsa-2048-cert.pem");

fn signature_builder() -> SignatureBuilder {
    let canonicalization = C14nAlgorithm::new(C14nMode::Exclusive1_0, false);
    SignatureBuilder::new(canonicalization.clone(), SignatureAlgorithm::RsaSha256)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("")
                .transform(Transform::Enveloped)
                .transform(Transform::C14n(canonicalization)),
        )
        .key_info(true)
}

#[test]
fn one_document_generation_flows_through_sign_verify_encrypt_and_decrypt() {
    // Exercise the public retained-document path across every operation. Read
    // operations must preserve generation; each structural mutation advances it.
    let mut document = XmlDocument::parse(
        "<root xmlns:app=\"urn:app\"><app:secret ID=\"secret\">payload</app:secret></root>",
    )
    .expect("owned XML fixture must parse");
    let signing_key =
        RsaSigningKey::from_pkcs8_pem(PRIVATE_KEY).expect("tracked private key must parse");
    let key_info = X509CertificateKeyInfoWriter::from_pem(CERTIFICATE)
        .expect("tracked certificate must parse");
    let signer = SignContext::new(&signing_key).key_info_writer(&key_info);

    signer
        .sign_document_with_builder(&mut document, &signature_builder())
        .expect("owned document must sign");
    let signed_generation = document.generation();

    let resolver = DefaultKeyResolver::default();
    let verified = VerifyContext::new()
        .key_resolver(&resolver)
        .verify_document(&document)
        .expect("owned document signature must verify");
    assert_eq!(verified.status, DsigStatus::Valid);
    assert_eq!(document.generation(), signed_generation);

    let content_key = [0x5a; 16];
    EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .direct_key(content_key)
        .encrypt_owned_document(
            &mut document,
            DocumentEncryptionOptions {
                element_id: Some("secret"),
            },
        )
        .expect("selected element must encrypt in place");
    assert_eq!(document.generation(), signed_generation + 1);

    DecryptContext::new(&SymmetricKeyDecryptor::new(content_key))
        .decrypt_owned_document(&mut document, None)
        .expect("encrypted element must decrypt in place");
    assert_eq!(document.generation(), signed_generation + 2);
    let verified = VerifyContext::new()
        .key_resolver(&resolver)
        .verify_document(&document)
        .expect("restored signed document must verify");
    assert_eq!(verified.status, DsigStatus::Valid);
}

#[test]
fn c14n_and_xpath_axis_identities_share_the_retained_view() {
    // Attribute and namespace identities must retain their exact owner while
    // canonicalization reuses the same parsed generation.
    let document = XmlDocument::parse("<p:root xmlns:p=\"urn:p\" p:a=\"1\"><p:child/></p:root>")
        .expect("owned XML fixture must parse");
    document.with_view(|view| {
        let root = view.root_element();
        let attribute = view
            .attribute_identity(root, Some("urn:p"), "a")
            .expect("qualified attribute must resolve");
        assert_eq!(attribute.owner(), root);
        assert!(
            view.namespace_identities(root)
                .expect("namespace axis must resolve")
                .iter()
                .any(|namespace| namespace.prefix() == "p" && namespace.uri() == "urn:p")
        );
    });

    let algorithm = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
    let first = canonicalize_document(&document, &algorithm).expect("C14N must succeed");
    let second = canonicalize_document(&document, &algorithm).expect("repeat C14N must succeed");
    assert_eq!(first, second);
    assert_eq!(document.generation(), 0);
}

#[test]
fn here_resolves_inside_the_exact_owned_generation() {
    // `here()` must bind to the XPath parameter in the retained document, not
    // to a separately parsed template or a node identity from an older view.
    let mut document =
        XmlDocument::parse("<root><payload/></root>").expect("owned XML fixture must parse");
    let canonicalization = C14nAlgorithm::new(C14nMode::Exclusive1_0, false);
    let builder = SignatureBuilder::new(canonicalization, SignatureAlgorithm::RsaSha256)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("")
                .transform(Transform::XPath(XPathExpression::new(
                    "count(. | here()) = 1",
                ))),
        )
        .key_info(true);
    let signing_key =
        RsaSigningKey::from_pkcs8_pem(PRIVATE_KEY).expect("tracked private key must parse");
    let key_info = X509CertificateKeyInfoWriter::from_pem(CERTIFICATE)
        .expect("tracked certificate must parse");
    SignContext::new(&signing_key)
        .key_info_writer(&key_info)
        .sign_document_with_builder(&mut document, &builder)
        .expect("XPath document must sign");

    let resolver = DefaultKeyResolver::default();
    let result = VerifyContext::new()
        .key_resolver(&resolver)
        .verify_document(&document)
        .expect("retained XPath document must verify");
    assert_eq!(result.status, DsigStatus::Valid);
}
