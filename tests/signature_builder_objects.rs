//! `<Object>` children and the `SignatureValue` Id of generated templates.

#![cfg(all(feature = "xmldsig-sign", feature = "c14n"))]

#[path = "support/cryptographic.rs"]
mod cryptographic;

use xml_sec::XmlDocument;
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::policy::{PolicyViolation, ResourcePolicy, SigningPolicy};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, DsigStatus, ObjectBuilder, ObjectContent, ObjectElement,
    ReferenceBuilder, RsaSigningKey, SignContext, SignatureAlgorithm, SignatureBuilder,
    SignatureBuilderError, Transform, X509CertificateKeyInfoWriter,
};

const DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const PRIVATE_KEY: &str = include_str!("fixtures/keys/rsa/rsa-2048-key.pem");
const CERTIFICATE: &str = include_str!("fixtures/keys/rsa/rsa-2048-cert.pem");

fn exclusive_c14n() -> C14nAlgorithm {
    C14nAlgorithm::new(C14nMode::Exclusive1_0, false)
}

fn builder() -> SignatureBuilder {
    SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256).add_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("#object")
            .transform(Transform::C14n(exclusive_c14n())),
    )
}

fn element(markup: &str) -> ObjectContent {
    ObjectContent::Element(
        ObjectElement::parse(markup, &SigningPolicy::default()).expect("valid object element"),
    )
}

#[test]
fn objects_follow_key_info_with_their_attributes_and_content() {
    // XMLDSig 1.1 §4: Object elements come last, in insertion order, and the
    // SignatureValue carries the Id a countersignature references.
    let xml = builder()
        .ns_prefix("ds")
        .signature_value_id("value")
        .key_info(true)
        .add_object(
            ObjectBuilder::new(ObjectContent::Text("a < b & c".to_owned()))
                .id("object")
                .mime_type("text/plain")
                .encoding("urn:example:none"),
        )
        .add_object(ObjectBuilder::new(element(
            "<p:data xmlns:p=\"urn:p\" p:a=\"1\"><p:child/></p:data>",
        )))
        .build_template()
        .expect("valid template");
    let document = roxmltree::Document::parse(&xml).expect("builder emits valid XML");
    let children: Vec<_> = document
        .root_element()
        .children()
        .filter(roxmltree::Node::is_element)
        .collect();
    let names: Vec<_> = children.iter().map(|node| node.tag_name().name()).collect();
    assert_eq!(
        names,
        [
            "SignedInfo",
            "SignatureValue",
            "KeyInfo",
            "Object",
            "Object"
        ]
    );
    assert_eq!(children[1].attribute("Id"), Some("value"));
    assert_eq!(children[3].attribute("Id"), Some("object"));
    assert_eq!(children[3].attribute("MimeType"), Some("text/plain"));
    assert_eq!(children[3].attribute("Encoding"), Some("urn:example:none"));
    assert_eq!(children[3].text(), Some("a < b & c"));
    let data = children[4].first_element_child().expect("element content");
    assert_eq!(data.tag_name().namespace(), Some("urn:p"));
    assert_eq!(data.attribute(("urn:p", "a")), Some("1"));
    assert!(data.has_children());
}

#[test]
fn an_element_in_no_namespace_stays_out_of_the_signature_namespace() {
    // With an unprefixed XMLDSig namespace in scope, copying `<data/>` verbatim
    // would put it in that namespace (Namespaces in XML 1.0 §6.2).
    let xml = builder()
        .add_object(ObjectBuilder::new(element("<data><inner/></data>")).id("object"))
        .build_template()
        .expect("valid template");
    let document = roxmltree::Document::parse(&xml).expect("builder emits valid XML");
    let data = document
        .descendants()
        .find(|node| node.tag_name().name() == "data")
        .expect("object element");
    // roxmltree reports a name under `xmlns=""` with an empty namespace name,
    // which Namespaces in XML 1.0 §6.2 defines as no namespace.
    let inner = data.first_element_child().expect("inner element");
    for node in [data, inner] {
        assert!(
            node.tag_name().namespace().is_none_or(str::is_empty),
            "{:?} is in {:?}",
            node.tag_name().name(),
            node.tag_name().namespace()
        );
    }
}

#[test]
fn an_element_declaring_its_default_namespace_is_copied_unchanged() {
    // An element that already declares (or undeclares) the default namespace
    // needs no addition; a second `xmlns` would be a duplicate attribute.
    for markup in [
        "<data xmlns=\"urn:d\"><inner/></data>",
        "<data xmlns=\"\"><inner/></data>",
    ] {
        let xml = builder()
            .add_object(ObjectBuilder::new(element(markup)).id("object"))
            .build_template()
            .expect("valid template");
        assert!(xml.contains(markup), "content changed: {xml}");
    }
}

#[test]
fn object_markup_must_be_exactly_one_element() {
    // Anything outside one element cannot appear inside `<Object>`, and markup
    // that closes the enclosing element must never reach the template.
    let policy = SigningPolicy::default();
    for markup in [
        "<a/><b/>",
        "<?xml version=\"1.0\"?><a/>",
        "<!--c--><a/>",
        "<a/> ",
        "text",
        "</Object><a/>",
    ] {
        assert!(
            ObjectElement::parse(markup, &policy).is_err(),
            "accepted {markup:?}"
        );
    }
    assert!(matches!(
        ObjectElement::parse("<a/><!--trailing-->", &policy),
        Err(SignatureBuilderError::InvalidObjectContent(_))
    ));
    assert!(matches!(
        ObjectElement::parse("<p:a/>", &policy),
        Err(SignatureBuilderError::GeneratedXml(_))
    ));
    assert!(matches!(
        ObjectElement::parse("<!DOCTYPE a [<!ENTITY e 'x'>]><a>&e;</a>", &policy),
        Err(SignatureBuilderError::Policy(_) | SignatureBuilderError::GeneratedXml(_))
    ));
}

#[test]
fn object_markup_is_bounded_by_the_document_limit() {
    // Object content is copied into the template, so it is measured against
    // the same document ceiling before it is parsed.
    let policy = SigningPolicy {
        resources: ResourcePolicy {
            max_xml_document_bytes: 8,
            ..ResourcePolicy::default()
        },
        ..SigningPolicy::default()
    };
    assert!(matches!(
        ObjectElement::parse("<long-element/>", &policy),
        Err(SignatureBuilderError::Policy(
            PolicyViolation::ResourceLimit { .. }
        ))
    ));
}

#[test]
fn aggregate_object_output_is_bounded_before_the_template_is_written() {
    // Text that grows when escaped, and objects that each fit, are measured
    // together against the document ceiling before serialization: the refusal
    // reports their projected output, not a template already built past it.
    let policy = SigningPolicy {
        resources: ResourcePolicy {
            max_xml_document_bytes: 4096,
            ..ResourcePolicy::default()
        },
        ..SigningPolicy::default()
    };
    let escaped = builder()
        .add_object(ObjectBuilder::new(ObjectContent::Text("&".repeat(1000))))
        .build_template_with_policy(&policy);
    let markup = format!("<p:d xmlns:p=\"urn:p\">{}</p:d>", "x".repeat(1000));
    let mut many = builder();
    for _ in 0..5 {
        many = many.add_object(ObjectBuilder::new(element(&markup)));
    }
    for (built, projected) in [
        (escaped, 5 * 1000),
        (many.build_template_with_policy(&policy), 5 * markup.len()),
    ] {
        assert!(
            matches!(
                &built,
                Err(SignatureBuilderError::Policy(PolicyViolation::ResourceLimit {
                    resource: "XML document",
                    maximum: 4096,
                    actual,
                })) if *actual == projected
            ),
            "{built:?}"
        );
    }
}

#[test]
fn invalid_object_and_signature_value_attributes_are_rejected() {
    // Ids are XML IDs and Encoding is an anyURI; neither may be repaired silently.
    let text = || ObjectContent::Text("payload".to_owned());
    for (built, element) in [
        (
            builder().signature_value_id("1value").build_template(),
            "SignatureValue",
        ),
        (
            builder()
                .add_object(ObjectBuilder::new(text()).id("has space"))
                .build_template(),
            "Object",
        ),
    ] {
        assert!(
            matches!(&built, Err(SignatureBuilderError::InvalidId { element: actual, .. }) if *actual == element),
            "{element}: {built:?}"
        );
    }
    assert!(matches!(
        builder()
            .add_object(ObjectBuilder::new(text()).encoding(" urn:padded"))
            .build_template(),
        Err(SignatureBuilderError::InvalidObjectAttribute {
            attribute: "Encoding",
            ..
        })
    ));
    assert!(matches!(
        builder()
            .add_object(ObjectBuilder::new(text()).mime_type("text/\u{1}"))
            .build_template(),
        Err(SignatureBuilderError::InvalidObjectAttribute {
            attribute: "MimeType",
            ..
        })
    ));
    assert!(matches!(
        builder()
            .add_object(ObjectBuilder::new(ObjectContent::Text("a\0b".to_owned())))
            .build_template(),
        Err(SignatureBuilderError::InvalidObjectContent(_))
    ));
}

#[test]
fn an_enveloping_object_signs_and_verifies() {
    // The signing pipeline fills the template, resolves `#object` inside the
    // new Signature and keeps the SignatureValue Id through the final mutation.
    let mut document = XmlDocument::parse("<root/>").expect("fixture parses");
    let key = RsaSigningKey::from_pkcs8_pem(PRIVATE_KEY).expect("tracked key parses");
    let key_info =
        X509CertificateKeyInfoWriter::from_pem(CERTIFICATE).expect("tracked certificate parses");
    let template = builder()
        .ns_prefix("ds")
        .signature_value_id("value")
        .key_info(true)
        .add_object(
            ObjectBuilder::new(element("<data><inner>payload</inner></data>")).id("object"),
        );
    SignContext::new(&key)
        .key_info_writer(&key_info)
        .sign_document_with_builder(&mut document, &template)
        .expect("enveloping template signs");
    let resolver = DefaultKeyResolver::default();
    let verified = cryptographic::context()
        .key_resolver(&resolver)
        .verify_document(&document)
        .expect("signed document verifies");
    assert_eq!(verified.status, DsigStatus::Valid);
    let signed = roxmltree::Document::parse(document.as_xml()).expect("signed XML parses");
    let value = signed
        .descendants()
        .find(|node| node.has_tag_name((DSIG_NS, "SignatureValue")))
        .expect("SignatureValue");
    assert_eq!(value.attribute("Id"), Some("value"));
    assert!(value.text().is_some_and(|text| !text.is_empty()));
}
