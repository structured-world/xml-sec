//! A document owned by an application's own tree, read by the operations
//! exactly like a parsed one.

#![cfg(all(feature = "external-tree", feature = "xmldsig-sign"))]

#[path = "support/cryptographic.rs"]
mod cryptographic;

use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::document::external::{ExternalNode, ExternalTree, TreeSink};
use xml_sec::policy::VerificationPolicy;
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, DsigStatus, ReferenceBuilder, RsaSigningKey, SignContext,
    SignatureAlgorithm, SignatureBuilder, Transform, X509CertificateKeyInfoWriter,
};
use xml_sec::{Document, Node, NodeType, ParseError, XmlDocument};

const PRIVATE_KEY: &str = include_str!("fixtures/keys/rsa/rsa-2048-key.pem");
const CERTIFICATE: &str = include_str!("fixtures/keys/rsa/rsa-2048-cert.pem");

/// An application tree, here held as XML and walked node by node through the
/// public DOM, the way a libxml2 walk reports its tree.
struct Mirror(String);

fn report(node: Node<'_, '_>, sink: &mut TreeSink<'_>, next: &mut u64) -> Result<(), ParseError> {
    *next += 1;
    let reference = ExternalNode(*next);
    match node.node_type() {
        NodeType::Element => {
            let name = node.tag_name();
            sink.begin_element(reference, name.name(), node.prefix(), name.namespace())?;
            for namespace in node.namespaces() {
                let inherited = node.parent_element().is_some_and(|parent| {
                    parent.lookup_namespace_uri(namespace.name()) == Some(namespace.uri())
                });
                if !inherited {
                    sink.declare_namespace(namespace.name(), namespace.uri())?;
                }
            }
            for attribute in node.attributes() {
                sink.attribute(
                    attribute.name(),
                    attribute.prefix(),
                    attribute.namespace(),
                    attribute.value(),
                    false,
                )?;
            }
            sink.open_element()?;
            for child in node.children() {
                report(child, sink, next)?;
            }
            sink.end_element()
        }
        NodeType::Text => sink.text(reference, node.text().unwrap_or_default()),
        NodeType::Comment => sink.comment(reference, node.text().unwrap_or_default()),
        NodeType::PI => {
            let pi = node.pi().expect("a processing instruction");
            sink.processing_instruction(reference, pi.target, pi.value)
        }
        NodeType::Root => unreachable!("the root is reported by its children"),
    }
}

impl ExternalTree for Mirror {
    fn document(&self) -> ExternalNode {
        ExternalNode(1)
    }

    fn project(&self, sink: &mut TreeSink<'_>) -> Result<(), ParseError> {
        let document = Document::parse(&self.0)?;
        let mut next = 1;
        for child in document.root().children() {
            report(child, sink, &mut next)?;
        }
        Ok(())
    }
}

fn signed_xml() -> String {
    let mut document = XmlDocument::parse(
        "<root xmlns:app=\"urn:app\"><app:secret ID=\"secret\">payload</app:secret></root>",
    )
    .expect("owned XML fixture must parse");
    let signing_key =
        RsaSigningKey::from_pkcs8_pem(PRIVATE_KEY).expect("tracked private key must parse");
    let key_info = X509CertificateKeyInfoWriter::from_pem(CERTIFICATE)
        .expect("tracked certificate must parse");
    let canonicalization = C14nAlgorithm::new(C14nMode::Exclusive1_0, false);
    let builder = SignatureBuilder::new(canonicalization.clone(), SignatureAlgorithm::RsaSha256)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("")
                .transform(Transform::Enveloped)
                .transform(Transform::C14n(canonicalization)),
        )
        .key_info(true);
    SignContext::new(&signing_key)
        .key_info_writer(&key_info)
        .sign_document_with_builder(&mut document, &builder)
        .expect("owned document must sign");
    document.into_xml()
}

fn verify(xml: String) -> DsigStatus {
    let document =
        XmlDocument::from_external_tree(Box::new(Mirror(xml)), &VerificationPolicy::default())
            .expect("the tree must project");
    let resolver = DefaultKeyResolver::default();
    cryptographic::context()
        .key_resolver(&resolver)
        .verify_document(&document)
        .expect("verification must run")
        .status
}

#[test]
fn a_signature_verifies_on_the_tree_it_was_made_for() {
    // The projection is the whole signed content: an exact walk verifies.
    assert_eq!(verify(signed_xml()), DsigStatus::Valid);
}

#[test]
fn a_changed_tree_does_not_verify() {
    // The digest is computed from the projected tree, not from a source the
    // tree no longer matches.
    let tampered = signed_xml().replace(">payload<", ">changed<");
    assert!(matches!(verify(tampered), DsigStatus::Invalid(_)));
}
