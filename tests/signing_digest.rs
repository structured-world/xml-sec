use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::xmldsig::mutation::append_signature_to_root;
use xml_sec::xmldsig::parse::{find_signature_node, parse_signed_info};
use xml_sec::xmldsig::uri::UriReferenceResolver;
use xml_sec::xmldsig::verify::process_all_references;
use xml_sec::xmldsig::{
    DigestAlgorithm, ReferenceBuilder, SignatureAlgorithm, SignatureBuilder, SigningDigestError,
    Transform, compute_reference_digest_values, fill_reference_digest_values,
};

fn exclusive_c14n() -> C14nAlgorithm {
    C14nAlgorithm::new(C14nMode::Exclusive1_0, false)
}

fn template_with_reference(reference: ReferenceBuilder) -> String {
    SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(reference)
        .build_template()
        .expect("valid signature template")
}

fn assert_reference_digests_verify(xml: &str) {
    let document = roxmltree::Document::parse(xml).expect("filled XML must parse");
    let signature = find_signature_node(&document).expect("Signature element");
    let signed_info_node = signature
        .children()
        .find(|node| {
            node.is_element()
                && node.tag_name().name() == "SignedInfo"
                && node.tag_name().namespace() == Some("http://www.w3.org/2000/09/xmldsig#")
        })
        .expect("SignedInfo element");
    let signed_info = parse_signed_info(signed_info_node).expect("filled SignedInfo must parse");
    let resolver = UriReferenceResolver::new(&document);
    let result = process_all_references(&signed_info.references, &resolver, signature, true)
        .expect("reference verification must run");
    assert!(result.all_valid(), "filled digest values must verify");
}

#[test]
fn fills_single_same_document_reference_digest() {
    // Signing templates start with an empty DigestValue; the digest pass must
    // compute bytes from the referenced node and make the template parseable by
    // the stricter verification parser.
    let template = template_with_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("#payload")
            .transform(Transform::C14n(exclusive_c14n())),
    );
    let xml = append_signature_to_root(
        "<root><payload ID=\"payload\">hello</payload></root>",
        &template,
    )
    .expect("append signature");

    let digests = compute_reference_digest_values(&xml).expect("compute digest");
    assert_eq!(digests.len(), 1);
    assert_eq!(digests[0].index, 0);
    assert_eq!(digests[0].uri, "#payload");
    assert_eq!(digests[0].digest_method, DigestAlgorithm::Sha256);
    assert!(!digests[0].digest_value.is_empty());

    let filled = fill_reference_digest_values(&xml).expect("fill digest values");
    assert_reference_digests_verify(&filled);
}

#[test]
fn preserves_multiple_reference_digest_order() {
    // DigestValue replacement is positional; this prevents accidentally sorting
    // or otherwise normalizing Reference order before the SignedInfo pass.
    let template = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256).uri("#first"))
        .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha384).uri("#second"))
        .build_template()
        .expect("valid signature template");
    let xml = append_signature_to_root(
        "<root><first ID=\"first\">one</first><second ID=\"second\">two</second></root>",
        &template,
    )
    .expect("append signature");

    let digests = compute_reference_digest_values(&xml).expect("compute digests");
    assert_eq!(digests.len(), 2);
    assert_eq!(digests[0].index, 0);
    assert_eq!(digests[0].uri, "#first");
    assert_eq!(digests[0].digest_method, DigestAlgorithm::Sha256);
    assert_eq!(digests[1].index, 1);
    assert_eq!(digests[1].uri, "#second");
    assert_eq!(digests[1].digest_method, DigestAlgorithm::Sha384);
    assert_ne!(digests[0].digest_value, digests[1].digest_value);

    let filled = fill_reference_digest_values(&xml).expect("fill digest values");
    assert_reference_digests_verify(&filled);
}

#[test]
fn computes_enveloped_signature_digest_for_whole_document() {
    // URI="" signs the full document; the enveloped transform must exclude the
    // generated Signature subtree before digesting, matching verification.
    let template = template_with_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha512)
            .uri("")
            .transform(Transform::Enveloped)
            .transform(Transform::C14n(exclusive_c14n())),
    );
    let xml = append_signature_to_root("<root><payload>hello</payload></root>", &template)
        .expect("append signature");

    let filled = fill_reference_digest_values(&xml).expect("fill digest values");
    assert_reference_digests_verify(&filled);
}

#[test]
fn rejects_reference_without_uri() {
    // External/object reference support is not implicit: signing must know what
    // bytes are being digested, so an omitted URI fails before mutation.
    let template = template_with_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256));
    let xml = append_signature_to_root("<root><payload>hello</payload></root>", &template)
        .expect("append signature");

    let err = compute_reference_digest_values(&xml).expect_err("missing URI must fail");
    assert!(
        matches!(err, SigningDigestError::InvalidStructure(message) if message.contains("URI"))
    );
}

#[test]
fn rejects_sha1_digest_for_signing_template() {
    // SHA-1 remains verify-only. This manually crafted template bypasses the
    // builder, so the digest pass must enforce the same policy before signing.
    let xml = r##"<root><payload ID="payload">hello</payload><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#payload"><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue/></Reference></SignedInfo><SignatureValue/></Signature></root>"##;

    let err = compute_reference_digest_values(xml).expect_err("SHA-1 signing digest must fail");
    assert!(matches!(
        err,
        SigningDigestError::SigningAlgorithmDisabled {
            uri: "http://www.w3.org/2000/09/xmldsig#sha1"
        }
    ));
}
