use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::xmldsig::{
    DigestAlgorithm, ReferenceBuilder, SignatureAlgorithm, SignatureBuilder, SignatureBuilderError,
    Transform, parse_transforms,
};

const DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

fn exclusive_c14n() -> C14nAlgorithm {
    C14nAlgorithm::new(C14nMode::Exclusive1_0, false)
}

#[test]
fn builds_parseable_prefixed_template_in_required_order() {
    // This guards the schema order consumed by xmlsec1 and our strict parser.
    let xml = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .ns_prefix("ds")
        .signature_id("sig-1")
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#assertion&1")
                .id("ref-1")
                .ref_type("urn:test:kind")
                .transform(Transform::Enveloped)
                .transform(Transform::C14n(exclusive_c14n())),
        )
        .key_info(true)
        .build_template()
        .expect("valid template");

    let document = roxmltree::Document::parse(&xml).expect("builder must emit valid XML");
    let signature = document.root_element();
    assert_eq!(signature.tag_name().namespace(), Some(DSIG_NS));
    assert_eq!(signature.attribute("Id"), Some("sig-1"));
    let children: Vec<_> = signature
        .children()
        .filter(roxmltree::Node::is_element)
        .map(|node| node.tag_name().name())
        .collect();
    assert_eq!(children, ["SignedInfo", "SignatureValue", "KeyInfo"]);

    let signed_info = signature
        .children()
        .find(|node| node.has_tag_name((DSIG_NS, "SignedInfo")))
        .expect("SignedInfo");
    let reference = signed_info
        .children()
        .find(|node| node.has_tag_name((DSIG_NS, "Reference")))
        .expect("Reference");
    assert_eq!(reference.attribute("URI"), Some("#assertion&1"));
    let reference_children: Vec<_> = reference
        .children()
        .filter(roxmltree::Node::is_element)
        .map(|node| node.tag_name().name())
        .collect();
    assert_eq!(
        reference_children,
        ["Transforms", "DigestMethod", "DigestValue"]
    );
    let transforms = reference
        .children()
        .find(|node| node.has_tag_name((DSIG_NS, "Transforms")))
        .expect("Transforms");
    assert_eq!(
        parse_transforms(transforms)
            .expect("valid transforms")
            .len(),
        2
    );
    let digest_value = reference
        .children()
        .find(|node| node.has_tag_name((DSIG_NS, "DigestValue")))
        .expect("DigestValue");
    assert_eq!(digest_value.text(), None);
}

#[test]
fn preserves_reference_order_and_default_namespace() {
    // Reference order is signed data and must never be normalized or sorted.
    let xml = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::EcdsaP256Sha256)
        .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha384).uri("#first"))
        .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha512).uri("#second"))
        .build_template()
        .expect("valid template");
    let document = roxmltree::Document::parse(&xml).expect("valid XML");
    let signature = document.root_element();
    assert_eq!(signature.lookup_namespace_uri(None), Some(DSIG_NS));
    let reference_uris: Vec<_> = signature
        .first_element_child()
        .expect("SignedInfo")
        .children()
        .filter(|node| node.has_tag_name((DSIG_NS, "Reference")))
        .map(|node| node.attribute("URI"))
        .collect();
    assert_eq!(reference_uris, [Some("#first"), Some("#second")]);
}

#[test]
fn rejects_incomplete_or_unsafe_signing_templates() {
    // Builders fail before serialization rather than producing unusable templates.
    let missing = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .build_template()
        .expect_err("Reference is mandatory");
    assert!(matches!(missing, SignatureBuilderError::MissingReference));

    let invalid_prefix = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .ns_prefix("bad:prefix")
        .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256))
        .build_template()
        .expect_err("prefix must be an NCName");
    assert!(matches!(
        invalid_prefix,
        SignatureBuilderError::InvalidNamespacePrefix(_)
    ));

    let sha1_signature = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha1)
        .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256))
        .build_template()
        .expect_err("SHA-1 signatures are verify-only");
    assert!(matches!(
        sha1_signature,
        SignatureBuilderError::SigningAlgorithmDisabled(_)
    ));

    let sha1_digest = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha1))
        .build_template()
        .expect_err("SHA-1 digests are verify-only");
    assert!(matches!(
        sha1_digest,
        SignatureBuilderError::SigningAlgorithmDisabled(_)
    ));
}

#[test]
fn serializes_xpath_and_exclusive_prefix_list() {
    // Complex transforms retain the child content required by their specifications.
    let c14n = exclusive_c14n().with_prefix_list("saml #default ds");
    let xml = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .ns_prefix("ds")
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .transform(Transform::XpathExcludeAllSignatures)
                .transform(Transform::C14n(c14n)),
        )
        .build_template()
        .expect("valid template");
    let document = roxmltree::Document::parse(&xml).expect("valid XML");
    let xpath = document
        .descendants()
        .find(|node| node.has_tag_name((DSIG_NS, "XPath")))
        .expect("XPath child");
    assert_eq!(xpath.text(), Some("not(ancestor-or-self::dsig:Signature)"));
    let transforms = xpath
        .parent()
        .and_then(|node| node.parent())
        .expect("Transforms");
    assert!(matches!(
        parse_transforms(transforms).as_deref(),
        Ok([Transform::XpathExcludeAllSignatures, Transform::C14n(_)])
    ));
    let inclusive = document
        .descendants()
        .find(|node| node.tag_name().name() == "InclusiveNamespaces")
        .expect("InclusiveNamespaces child");
    assert_eq!(inclusive.attribute("PrefixList"), Some("#default ds saml"));
}

#[test]
fn accepts_unicode_xml_namespace_prefixes() {
    // XML 1.0 NCNames permit Unicode letters; prefix validation must not be ASCII-only.
    let xml = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .ns_prefix("подпись")
        .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256))
        .build_template()
        .expect("Unicode prefix is a valid XML NCName");
    let document = roxmltree::Document::parse(&xml).expect("valid XML");
    assert_eq!(
        document.root_element().tag_name().namespace(),
        Some(DSIG_NS)
    );
}

#[test]
fn rejects_non_ncname_signature_and_reference_ids() {
    // xsd:ID derives from NCName, so escaping an invalid value is not sufficient.
    let signature_id = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .signature_id("sig&1")
        .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256))
        .build_template()
        .expect_err("Signature Id must be an NCName");
    assert!(signature_id.to_string().contains("Signature Id"));

    let reference_id = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256).id("ref:1"))
        .build_template()
        .expect_err("Reference Id must be an NCName");
    assert!(reference_id.to_string().contains("Reference Id"));

    let injected_signature_id =
        SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
            .signature_id("!--comment--><valid")
            .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256))
            .build_template()
            .expect_err("markup must not satisfy Signature Id validation");
    assert!(injected_signature_id.to_string().contains("Signature Id"));

    let injected_reference_id =
        SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
            .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256).id("?check?><valid"))
            .build_template()
            .expect_err("markup must not satisfy Reference Id validation");
    assert!(injected_reference_id.to_string().contains("Reference Id"));
}
