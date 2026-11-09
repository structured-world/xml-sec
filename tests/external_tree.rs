//! A document owned by an application's own tree, read and changed by the
//! operations exactly like a parsed one.

#![cfg(all(
    feature = "external-tree",
    feature = "xmldsig-sign",
    feature = "xmlenc"
))]

#[path = "support/cryptographic.rs"]
mod cryptographic;
#[path = "support/model_tree.rs"]
mod model_tree;

use model_tree::ModelTree;
use xml_sec::XmlDocument;
use xml_sec::c14n::{C14nAlgorithm, C14nMode, canonicalize_document, canonicalize_xml};
use xml_sec::policy::VerificationPolicy;
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, DsigStatus, ReferenceBuilder, RsaSigningKey, SignContext,
    SignatureAlgorithm, SignatureBuilder, Transform, X509CertificateKeyInfoWriter,
};
use xml_sec::xmlenc::{
    DataEncryptionAlgorithm, DecryptContext, DocumentEncryptionOptions, EncryptedDataBuilder,
    SymmetricKeyDecryptor,
};

const PRIVATE_KEY: &str = include_str!("fixtures/keys/rsa/rsa-2048-key.pem");
const CERTIFICATE: &str = include_str!("fixtures/keys/rsa/rsa-2048-cert.pem");
const PAYLOAD: &str = concat!(
    "<root xmlns:app=\"urn:app\"><app:secret ID=\"secret\">payload",
    "<app:inner a=\"1\"/></app:secret><public>kept</public></root>"
);

/// A signature over the whole document, enveloped, with the certificate in
/// `KeyInfo`; `canonical_transform` adds an explicit C14N transform, without
/// which signing generates the C14N 1.1 transform itself.
fn builder(canonical_transform: bool) -> SignatureBuilder {
    let canonicalization = C14nAlgorithm::new(C14nMode::Exclusive1_0, false);
    let mut reference = ReferenceBuilder::new(DigestAlgorithm::Sha256)
        .uri("")
        .transform(Transform::Enveloped);
    if canonical_transform {
        reference = reference.transform(Transform::C14n(canonicalization.clone()));
    }
    SignatureBuilder::new(canonicalization, SignatureAlgorithm::RsaSha256)
        .add_reference(reference)
        .key_info(true)
}

fn sign(document: &mut XmlDocument, builder: &SignatureBuilder) {
    let signing_key =
        RsaSigningKey::from_pkcs8_pem(PRIVATE_KEY).expect("tracked private key must parse");
    let key_info = X509CertificateKeyInfoWriter::from_pem(CERTIFICATE)
        .expect("tracked certificate must parse");
    SignContext::new(&signing_key)
        .key_info_writer(&key_info)
        .sign_document_with_builder(document, builder)
        .expect("the document signs");
}

fn signed_xml() -> String {
    let mut document = XmlDocument::parse(PAYLOAD).expect("owned XML fixture must parse");
    sign(&mut document, &builder(true));
    document.into_xml()
}

fn tree_document(tree: &ModelTree) -> XmlDocument {
    XmlDocument::from_external_tree(Box::new(tree.clone()), &VerificationPolicy::default())
        .expect("the tree must project")
}

fn status(document: &XmlDocument) -> DsigStatus {
    let resolver = DefaultKeyResolver::default();
    cryptographic::context()
        .key_resolver(&resolver)
        .verify_document(document)
        .expect("verification must run")
        .status
}

fn canonical(xml: &str) -> Vec<u8> {
    canonicalize_xml(
        xml.as_bytes(),
        &C14nAlgorithm::new(C14nMode::Inclusive1_0, true),
    )
    .expect("canonicalizes")
}

/// Sign `PAYLOAD` once as a tree and once as text, and check the tree
/// result against the text one.
fn signs_like_text(canonical_transform: bool) {
    let builder = builder(canonical_transform);
    let tree = ModelTree::parse(PAYLOAD);
    let public = tree.element("public");
    let mut document = tree_document(&tree);
    sign(&mut document, &builder);
    let signed = tree.to_xml();
    assert!(signed.contains("X509Certificate"), "{signed}");
    assert_eq!(
        signed.contains("http://www.w3.org/2006/12/xml-c14n11"),
        !canonical_transform,
        "{signed}"
    );
    // The signed content keeps its nodes; the signature joined the tree.
    assert!(tree.nodes().contains(&public));
    assert_eq!(status(&document), DsigStatus::Valid);
    assert_eq!(status(&tree_document(&tree)), DsigStatus::Valid);
    assert_eq!(tree.pending_undo(), 0);
    // RSA PKCS#1 v1.5 is deterministic, so the same request over the same
    // content gives the same signature through either backing.
    let mut text = XmlDocument::parse(PAYLOAD).expect("parses");
    sign(&mut text, &builder);
    assert_eq!(canonical(&signed), canonical(text.as_xml()));
}

#[test]
fn signing_fills_the_template_in_the_tree_like_text() {
    signs_like_text(true);
}

#[test]
fn signing_generates_the_c14n_transform_in_the_tree_like_text() {
    // Without a canonicalizing transform the reference gains the C14N 1.1
    // transform, which the tree receives as a node of its own.
    signs_like_text(false);
}

#[test]
fn a_transform_that_reads_node_content_signs_the_tree_like_text() {
    // An XPath filter can read any node, so the signature's own values may
    // enter a digest; the dependency analysis then needs the document with
    // placeholder text in every value signing fills, which a tree holds
    // without any serialization.
    let canonicalization = C14nAlgorithm::new(C14nMode::Exclusive1_0, false);
    let builder = SignatureBuilder::new(canonicalization.clone(), SignatureAlgorithm::RsaSha256)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#secret")
                .transform(Transform::XPath(xml_sec::xmldsig::XPathExpression::new(
                    "true()",
                )))
                .transform(Transform::C14n(canonicalization)),
        )
        .key_info(true);
    let tree = ModelTree::parse(PAYLOAD);
    let mut document = tree_document(&tree);
    sign(&mut document, &builder);
    assert_eq!(status(&tree_document(&tree)), DsigStatus::Valid);
    assert_eq!(tree.pending_undo(), 0);
    let mut text = XmlDocument::parse(PAYLOAD).expect("parses");
    sign(&mut text, &builder);
    assert_eq!(canonical(&tree.to_xml()), canonical(text.as_xml()));
}

#[test]
fn a_signature_verifies_on_the_tree_it_was_made_for() {
    // The projection is the whole signed content: an exact walk verifies.
    let tree = ModelTree::parse(&signed_xml());
    assert_eq!(status(&tree_document(&tree)), DsigStatus::Valid);
}

#[test]
fn a_changed_tree_does_not_verify() {
    // The digest is computed from the projected tree, not from a source the
    // tree no longer matches.
    let tree = ModelTree::parse(&signed_xml().replace(">payload<", ">changed<"));
    assert!(matches!(
        status(&tree_document(&tree)),
        DsigStatus::Invalid(_)
    ));
}

#[test]
fn a_stricter_operation_enforces_its_byte_ceiling_on_a_tree() {
    // A tree projected under a permissive policy and verified under one whose
    // document ceiling it exceeds is refused, as the same text would be: the
    // projection's bytes are the document's size.
    let tree = ModelTree::parse(&signed_xml());
    let document = tree_document(&tree);
    let mut policy = VerificationPolicy::default();
    policy.resources.max_xml_document_bytes = 64;
    let resolver = DefaultKeyResolver::default();
    let error = cryptographic::context()
        .policy(policy)
        .key_resolver(&resolver)
        .verify_document(&document)
        .expect_err("the document exceeds the active ceiling");
    assert!(error.to_string().contains("XML document"), "{error}");
}

#[test]
fn decryption_charges_the_projection_of_the_edited_tree() {
    // Committing a decryption reads the whole edited tree again; that walk is
    // parse work of the operation, as reparsing the text would be, so an
    // allowance that holds the plaintext but not the document refuses it and
    // leaves the tree encrypted.
    let padding = "p".repeat(4_096);
    let xml = format!("<root><pad>{padding}</pad><secret ID=\"secret\">payload</secret></root>");
    let tree = ModelTree::parse(&xml);
    let mut document = tree_document(&tree);
    let content_key = [0x5a; 16];
    EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .direct_key(content_key)
        .encrypt_owned_document(
            &mut document,
            DocumentEncryptionOptions {
                element_id: Some("secret"),
            },
        )
        .expect("the element encrypts");
    let encrypted = tree.to_xml();
    let mut policy = xml_sec::policy::DecryptionPolicy::default();
    policy.resources.max_xml_parse_work_bytes = 1_024;
    let refused = DecryptContext::new(&SymmetricKeyDecryptor::new(content_key))
        .policy(policy)
        .decrypt_owned_document(&mut document, None);
    assert!(refused.is_err(), "the projection exceeds the allowance");
    assert_eq!(
        tree.to_xml(),
        encrypted,
        "the refused decryption rolled back"
    );
    assert_eq!(tree.pending_undo(), 0);
}

#[test]
fn encryption_and_decryption_change_the_tree_in_place() {
    // The element is encrypted into the caller's tree and decrypted back;
    // every node outside it is the same node throughout, and the restored
    // tree still carries a valid signature.
    let tree = ModelTree::parse(&signed_xml());
    let mut document = tree_document(&tree);
    let original =
        canonicalize_document(&document, &C14nAlgorithm::new(C14nMode::Inclusive1_0, true))
            .expect("canonicalizes");
    let public = tree.element("public");
    let signature = tree.element("Signature");

    let content_key = [0x5a; 16];
    EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .direct_key(content_key)
        .encrypt_owned_document(
            &mut document,
            DocumentEncryptionOptions {
                element_id: Some("secret"),
            },
        )
        .expect("the selected element encrypts in the tree");
    let encrypted = tree.to_xml();
    assert!(encrypted.contains("EncryptedData"), "{encrypted}");
    assert!(!encrypted.contains("payload"), "{encrypted}");
    let nodes = tree.nodes();
    assert!(nodes.contains(&public) && nodes.contains(&signature));

    DecryptContext::new(&SymmetricKeyDecryptor::new(content_key))
        .decrypt_owned_document(&mut document, None)
        .expect("the encrypted element decrypts in the tree");
    assert_eq!(
        canonicalize_document(&document, &C14nAlgorithm::new(C14nMode::Inclusive1_0, true))
            .expect("canonicalizes"),
        original
    );
    assert_eq!(canonical(&tree.to_xml()), original);
    let nodes = tree.nodes();
    assert!(nodes.contains(&public) && nodes.contains(&signature));
    assert_eq!(status(&document), DsigStatus::Valid);
    // Each operation committed its own edits; nothing waits to be undone.
    assert_eq!(tree.pending_undo(), 0);
}
