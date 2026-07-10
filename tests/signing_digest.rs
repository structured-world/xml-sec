use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::xmldsig::mutation::append_signature_to_root;
use xml_sec::xmldsig::parse::{find_signature_node, parse_signed_info};
use xml_sec::xmldsig::uri::UriReferenceResolver;
use xml_sec::xmldsig::verify::process_all_references;
use xml_sec::xmldsig::{
    DigestAlgorithm, DsigStatus, EcdsaP256SigningKey, EcdsaP384SigningKey, ReferenceBuilder,
    RsaSigningKey, SignContext, SignatureAlgorithm, SignatureBuilder, SigningDigestError,
    Transform, compute_reference_digest_values, fill_reference_digest_values,
    verify_signature_with_pem_key,
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

fn read_fixture(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|err| panic!("failed to read {path}: {err}"))
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
fn fills_only_signed_info_reference_digest_values() {
    // Manifests can contain their own DigestValue elements inside the same
    // Signature. Signing the outer SignedInfo must not treat those as template
    // reference slots or overwrite their existing values.
    let template = template_with_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("#payload")
            .transform(Transform::C14n(exclusive_c14n())),
    );
    let template = template.replace(
        "</Signature>",
        "<Object><Manifest><Reference URI=\"#manifest-payload\"><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>keep-manifest-digest</DigestValue></Reference></Manifest></Object></Signature>",
    );
    let xml = append_signature_to_root(
        "<root><payload ID=\"payload\">hello</payload><manifest-payload ID=\"manifest-payload\">manifest</manifest-payload></root>",
        &template,
    )
    .expect("append signature");

    let filled = fill_reference_digest_values(&xml).expect("fill only SignedInfo digest values");

    assert!(filled.contains("<DigestValue>keep-manifest-digest</DigestValue>"));
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

#[test]
fn signs_rsa_sha256_template_and_verifies_round_trip() {
    // Full signing pipeline: append template, compute Reference digest,
    // canonicalize SignedInfo, RSA-sign it, fill SignatureValue, then verify
    // the final XML through the existing end-to-end verifier.
    let private_key =
        RsaSigningKey::from_pkcs8_pem(&read_fixture("tests/fixtures/keys/rsa/rsa-2048-key.pem"))
            .expect("RSA private key fixture must parse");
    let public_key_pem = read_fixture("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    let builder = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("")
                .transform(Transform::Enveloped)
                .transform(Transform::C14n(exclusive_c14n())),
        );

    let signed = SignContext::new(&private_key)
        .sign_with_builder("<root><payload>hello</payload></root>", &builder)
        .expect("RSA signing pipeline must succeed");
    let verify_result = verify_signature_with_pem_key(&signed, &public_key_pem, true)
        .expect("signed RSA XML must verify without pipeline errors");

    assert_eq!(verify_result.status, DsigStatus::Valid);
    assert!(signed.contains("<SignatureValue>"));
    assert!(!signed.contains("<DigestValue></DigestValue>"));
}

#[test]
fn signs_ecdsa_p256_template_and_verifies_round_trip() {
    // ECDSA XMLDSig SignatureValue must be fixed-width r||s bytes, not ASN.1
    // DER. The verifier accepts the generated value as a final interop check.
    let private_key = EcdsaP256SigningKey::from_pkcs8_pem(&read_fixture(
        "tests/fixtures/keys/ec/ec-prime256v1-key.pem",
    ))
    .expect("P-256 private key fixture must parse");
    let public_key_pem = read_fixture("tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem");
    let builder = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::EcdsaP256Sha256)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#payload")
                .transform(Transform::C14n(exclusive_c14n())),
        );

    let signed = SignContext::new(&private_key)
        .sign_with_builder(
            "<root><payload ID=\"payload\">hello</payload></root>",
            &builder,
        )
        .expect("ECDSA signing pipeline must succeed");
    let verify_result = verify_signature_with_pem_key(&signed, &public_key_pem, true)
        .expect("signed ECDSA XML must verify without pipeline errors");

    assert_eq!(verify_result.status, DsigStatus::Valid);
    assert!(signed.contains("<SignatureValue>"));
    assert!(!signed.contains("<DigestValue></DigestValue>"));
}

#[test]
fn signs_ecdsa_p384_template_and_verifies_round_trip() {
    // P-384 uses the XMLDSig ecdsa-sha384 URI and the same fixed-width r||s
    // SignatureValue encoding as P-256, with a wider component size.
    let private_key = EcdsaP384SigningKey::from_pkcs8_pem(&read_fixture(
        "tests/fixtures/keys/ec/ec-prime384v1-key.pem",
    ))
    .expect("P-384 private key fixture must parse");
    let public_key_pem = read_fixture("tests/fixtures/keys/ec/ec-prime384v1-pubkey.pem");
    let builder = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::EcdsaP384Sha384)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha384)
                .uri("#payload")
                .transform(Transform::C14n(exclusive_c14n())),
        );

    let signed = SignContext::new(&private_key)
        .sign_with_builder(
            "<root><payload ID=\"payload\">hello</payload></root>",
            &builder,
        )
        .expect("P-384 signing pipeline must succeed");
    let verify_result = verify_signature_with_pem_key(&signed, &public_key_pem, true)
        .expect("signed P-384 XML must verify without pipeline errors");

    assert_eq!(verify_result.status, DsigStatus::Valid);
    assert!(signed.contains("<SignatureValue>"));
    assert!(!signed.contains("<DigestValue></DigestValue>"));
}
