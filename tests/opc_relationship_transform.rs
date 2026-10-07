//! OPC normalization must use the normative contract, not donor omissions.

use xml_sec::Document;
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::policy::{
    OpcRelationshipEdition, SigningPolicy, VerificationPolicy, VerificationTrustMode,
};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, DsigStatus, ReferenceBuilder, RelationshipSelector,
    RsaSigningKey, SignContext, SignatureAlgorithm, SignatureBuilder, Transform, UriTypeSet,
    VerifyContext, X509CertificateKeyInfoWriter,
};
use xml_sec::xmldsig::{NodeSet, TransformData, execute_transforms, parse_transforms};

const REL: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
const PARAM: &str = "http://schemas.openxmlformats.org/package/2006/digital-signature";
const URI: &str = "http://schemas.openxmlformats.org/package/2006/RelationshipTransform";

#[path = "common/xmlsec1.rs"]
mod xmlsec1;

fn normalize(input: &str, selectors: &str) -> Result<Vec<u8>, String> {
    let parameters = format!(
        "<Transforms xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><Transform Algorithm=\"{URI}\">{selectors}</Transform><Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/></Transforms>"
    );
    let parameters = Document::parse(&parameters).unwrap();
    let transforms = parse_transforms(parameters.root_element()).map_err(|e| e.to_string())?;
    let document = Document::parse(input).unwrap();
    execute_transforms(
        document.root_element(),
        TransformData::NodeSet(NodeSet::entire_document_with_comments(&document).unwrap()),
        &transforms,
    )
    .map_err(|e| e.to_string())
}

#[test]
fn relationship_transform_selects_groups_and_normalizes() {
    // SourceType selects every matching relationship, then case-sensitive Id
    // sorting and TargetMode defaulting precede the mandatory C14N step.
    let input = format!(
        "<r:Relationships xmlns:r=\"{REL}\"><r:Relationship Id=\"z\" Type=\"urn:test\" Target=\"z&amp;x\"/><r:Relationship Id=\"A\" Type=\"urn:test\" Target=\"a\"/><r:Relationship Id=\"other\" Type=\"urn:other\" Target=\"b\"/></r:Relationships>"
    );
    let selectors =
        format!("<RelationshipsGroupReference xmlns=\"{PARAM}\" SourceType=\"URN:TEST\"/>");
    let expected = format!(
        "<Relationships xmlns=\"{REL}\"><Relationship Id=\"A\" Target=\"a\" TargetMode=\"Internal\" Type=\"urn:test\"></Relationship><Relationship Id=\"z\" Target=\"z&amp;x\" TargetMode=\"Internal\" Type=\"urn:test\"></Relationship></Relationships>"
    );
    assert_eq!(normalize(&input, &selectors).unwrap(), expected.as_bytes());
}

#[test]
fn relationship_transform_2021_matches_ids_without_collapsing_them() {
    // ASCII-insensitive selection does not change xsd:ID uniqueness or ordering.
    let input = format!(
        "<Relationships xmlns=\"{REL}\"><Relationship Id=\"rId\" Type=\"urn:t\" Target=\"a\"/><Relationship Id=\"RID\" Type=\"urn:t\" Target=\"b\"/></Relationships>"
    );
    let selectors = format!("<RelationshipReference xmlns=\"{PARAM}\" SourceId=\"rid\"/>");
    let output = String::from_utf8(normalize(&input, &selectors).unwrap()).unwrap();
    assert_eq!(output.matches("<Relationship ").count(), 2);
    assert!(output.find("Id=\"RID\"").unwrap() < output.find("Id=\"rId\"").unwrap());
}

#[test]
fn selectors_form_a_union_without_unicode_case_folding() {
    // 2021 folds ASCII only; repeated selectors must not duplicate a row.
    let input = format!(
        "<Relationships xmlns=\"{REL}\"><Relationship Id=\"Å\" Type=\"urn:t\" Target=\"a\"/><Relationship Id=\"å\" Type=\"urn:t\" Target=\"b\"/></Relationships>"
    );
    let selectors = format!(
        "<RelationshipReference xmlns=\"{PARAM}\" SourceId=\"Å\"/><RelationshipReference xmlns=\"{PARAM}\" SourceId=\"Å\"/>"
    );
    let expected = format!(
        "<Relationships xmlns=\"{REL}\"><Relationship Id=\"Å\" Target=\"a\" TargetMode=\"Internal\" Type=\"urn:t\"></Relationship></Relationships>"
    );
    assert_eq!(normalize(&input, &selectors).unwrap(), expected.as_bytes());
}

#[test]
fn malformed_parameters_and_canonicalization_chains_fail_before_execution() {
    // Mandatory selector syntax and C14N ordering are parse-time requirements.
    let canonical = "<Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>";
    for (selectors, tail) in [
        ("".to_owned(), canonical.to_owned()),
        (
            format!("<RelationshipReference xmlns=\"{PARAM}\"/>"),
            canonical.to_owned(),
        ),
        (
            format!("<RelationshipReference xmlns=\"{PARAM}\" SourceId=\"x\" Extra=\"y\"/>"),
            canonical.to_owned(),
        ),
        (
            format!(
                "<RelationshipReference xmlns=\"{PARAM}\" SourceId=\"x\"><child/></RelationshipReference>"
            ),
            canonical.to_owned(),
        ),
        (
            "<RelationshipReference SourceId=\"x\"/>".to_owned(),
            canonical.to_owned(),
        ),
        (
            format!("<RelationshipReference xmlns=\"{PARAM}\" SourceId=\"x\"/>"),
            String::new(),
        ),
        (
            format!("<RelationshipReference xmlns=\"{PARAM}\" SourceId=\"x\"/>"),
            "<Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#base64\"/>".to_owned(),
        ),
    ] {
        let xml = format!(
            "<Transforms xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><Transform Algorithm=\"{URI}\">{selectors}</Transform>{tail}</Transforms>"
        );
        let document = Document::parse(&xml).unwrap();
        assert!(
            parse_transforms(document.root_element()).is_err(),
            "accepted {xml}"
        );
    }
}

#[test]
fn internal_relationship_target_syntax_is_not_package_resolution() {
    // ECMA-376 Part 2 §6.5.3.4 requires Internal targets to be relative;
    // selection must not hide invalid unselected relationships.
    let selectors = format!("<RelationshipReference xmlns=\"{PARAM}\" SourceId=\"absent\"/>");
    for target in [
        "https://example.com/a",
        "urn:part:a",
        "file:/a",
        " HTTP://example.com/a ",
    ] {
        for mode in ["", " TargetMode=\"Internal\""] {
            let input = format!(
                "<Relationships xmlns=\"{REL}\"><Relationship Id=\"x\" Type=\"urn:t\" Target=\"{target}\"{mode}/></Relationships>"
            );
            assert!(normalize(&input, &selectors).is_err(), "{target} {mode}");
        }
    }
    // RFC 3986 §§4.2, 5.2.2: an authority is allowed in a relative reference.
    // The encoded pack authority can equal the base's authority; only a
    // package validator with that base can decide package membership.
    for target in [
        "a",
        "../a",
        "/a",
        "//http%3a,,example.com,package/a",
        "a/b:c",
        "a%3Ab",
    ] {
        let input = format!(
            "<Relationships xmlns=\"{REL}\"><Relationship Id=\"x\" Type=\"urn:t\" Target=\"{target}\"/></Relationships>"
        );
        assert!(normalize(&input, &selectors).is_ok(), "{target}");
    }
    for target in ["https://example.com/a", "//example.com/a"] {
        let external = format!(
            "<Relationships xmlns=\"{REL}\"><Relationship Id=\"x\" Type=\"urn:t\" Target=\"{target}\" TargetMode=\"External\"/></Relationships>"
        );
        assert!(normalize(&external, &selectors).is_ok());
    }
}

#[test]
fn builder_enforces_parameter_budget_before_template_generation() {
    // A denied parameter budget must stop before copying the selector chain.
    let key = RsaSigningKey::from_pkcs8_pem(
        &std::fs::read_to_string("tests/fixtures/keys/rsa/rsa-2048-key.pem").unwrap(),
    )
    .unwrap();
    let canonical = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
    let builder = SignatureBuilder::new(canonical.clone(), SignatureAlgorithm::RsaSha256)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .transform(Transform::Relationship(vec![
                    RelationshipSelector::SourceId("rid".into()),
                ]))
                .transform(Transform::C14n(canonical)),
        );
    let mut policy = SigningPolicy::default();
    policy.resources.max_opc_parameter_bytes = 0;
    let result = SignContext::new(&key)
        .policy(policy)
        .sign_with_builder("<root/>", &builder);
    assert!(format!("{result:?}").contains("OPC parameter bytes"));
}

#[test]
fn relationship_digest_authenticates_selected_rows_only() {
    // Editing a discarded row is allowed; editing a selected target is not.
    let input = format!(
        "<Relationships xmlns=\"{REL}\"><Relationship Id=\"rid\" Type=\"urn:t\" Target=\"a\"/><Relationship Id=\"other\" Type=\"urn:t\" Target=\"b\"/></Relationships>"
    );
    let (signed, mut resources) = signed_external_part(OpcRelationshipEdition::Ecma2021, &input);
    let resolver = DefaultKeyResolver::default();
    let mut policy = VerificationPolicy::default();
    policy.key_trust.mode = VerificationTrustMode::CryptographicOnly;
    policy.uris.references = UriTypeSet::ALL;
    for (old, new, expected) in [
        ("Target=\"b\"", "Target=\"c\"", DsigStatus::Valid),
        (
            "Target=\"a\"",
            "Target=\"c\"",
            DsigStatus::Invalid(xml_sec::xmldsig::FailureReason::ReferenceDigestMismatch {
                ref_index: 0,
            }),
        ),
    ] {
        resources.insert("_rels/.rels".into(), input.replace(old, new).into_bytes());
        let result = VerifyContext::new()
            .policy(policy.clone())
            .key_resolver(&resolver)
            .external_resources(&resources)
            .verify(&signed)
            .unwrap();
        assert_eq!(result.status, expected);
    }
}

#[test]
fn cipher_reference_uses_typed_edition_and_selected_backend_for_encoded_input() {
    // The XMLEnc adapter must share edition policy and octet decoding, not
    // silently use its own default transform configuration.
    let source = format!(
        "<Relationships xmlns=\"{REL}\"><Relationship Id=\"RID\" Type=\"urn:t\" Target=\"a\">metadata &amp; <![CDATA[данные]]></Relationship></Relationships>"
    );
    let utf16 = std::iter::once(0xfeffu16)
        .chain(source.encode_utf16())
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let xml = format!(
        "<CipherReference xmlns=\"http://www.w3.org/2001/04/xmlenc#\" URI=\"part.rels\"><Transforms><ds:Transform xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Algorithm=\"{URI}\"><RelationshipReference xmlns=\"{PARAM}\" SourceId=\"rid\"/></ds:Transform><ds:Transform xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/></Transforms></CipherReference>"
    );
    for backend in xml_sec::XmlBackend::available() {
        let document = Document::parse_with_backend(&xml, backend).unwrap();
        for bytes in [source.as_bytes().to_vec(), utf16.clone()] {
            let resources = std::collections::HashMap::from([("part.rels".into(), bytes)]);
            for edition in [
                OpcRelationshipEdition::Ecma2012,
                OpcRelationshipEdition::Ecma2021,
            ] {
                let mut policy = xml_sec::policy::DecryptionPolicy::default();
                policy.uris.references = UriTypeSet::ALL;
                policy.transforms.opc_relationship_edition = edition;
                let context = xml_sec::xmlenc::CipherReferenceContext::new(
                    &policy,
                    Some(&resources),
                    backend,
                    &[],
                )
                .unwrap();
                let output = context.resolve(document.root_element()).unwrap();
                let expected = if edition == OpcRelationshipEdition::Ecma2012 {
                    format!("<Relationships xmlns=\"{REL}\"></Relationships>")
                } else {
                    format!(
                        "<Relationships xmlns=\"{REL}\"><Relationship Id=\"RID\" Target=\"a\" TargetMode=\"Internal\" Type=\"urn:t\"></Relationship></Relationships>"
                    )
                };
                assert_eq!(output, expected.as_bytes(), "{backend:?} {edition:?}");
            }
        }
    }
}

#[test]
fn authenticated_manifest_uses_the_same_relationship_contract() {
    // Digest filling inside an authenticated Manifest must precede its parent
    // SignedInfo digest and use the operation's edition without another knob.
    use xml_sec::policy::ManifestProcessing;
    use xml_sec::xmldsig::{SigningKey, SigningPublicKeyInfo, VerificationKey};
    let key = RsaSigningKey::from_pkcs8_pem(
        &std::fs::read_to_string("tests/fixtures/keys/rsa/rsa-2048-key.pem").unwrap(),
    )
    .unwrap();
    let SigningPublicKeyInfo::Rsa { spki_der, .. } = key.public_key_info().unwrap() else {
        panic!("RSA fixture")
    };
    let verification_key = VerificationKey {
        algorithm: SignatureAlgorithm::RsaSha256,
        public_key_bytes: spki_der,
        certificate_der: None,
        name: None,
    };
    let template = format!(
        "<root><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><ds:Reference URI=\"#manifest\"><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:Object><ds:Manifest Id=\"manifest\"><ds:Reference URI=\"part.rels\"><ds:Transforms><ds:Transform Algorithm=\"{URI}\"><RelationshipReference xmlns=\"{PARAM}\" SourceId=\"rid\"/></ds:Transform><ds:Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue/></ds:Reference></ds:Manifest></ds:Object></ds:Signature></root>"
    );
    let part = format!(
        "<Relationships xmlns=\"{REL}\"><Relationship Id=\"RID\" Type=\"urn:t\" Target=\"a\"/></Relationships>"
    );
    let resources = std::collections::HashMap::from([("part.rels".into(), part.into_bytes())]);
    for edition in [
        OpcRelationshipEdition::Ecma2012,
        OpcRelationshipEdition::Ecma2021,
    ] {
        let mut signing = SigningPolicy {
            manifest_processing: ManifestProcessing::Process,
            ..SigningPolicy::default()
        };
        signing.uris.references = UriTypeSet::ALL;
        signing.transforms.opc_relationship_edition = edition;
        let signed = SignContext::new(&key)
            .policy(signing)
            .external_resources(&resources)
            .sign_template(&template)
            .unwrap();
        let mut verification = VerificationPolicy {
            manifest_processing: ManifestProcessing::Process,
            ..VerificationPolicy::default()
        };
        verification.uris.references = UriTypeSet::ALL;
        verification.transforms.opc_relationship_edition = edition;
        let result = VerifyContext::new()
            .policy(verification)
            .key(&verification_key)
            .external_resources(&resources)
            .verify(&signed)
            .unwrap();
        assert_eq!(result.status, DsigStatus::Valid);
        assert_eq!(result.manifest_references.len(), 1);
        assert_eq!(result.manifest_references[0].status, DsigStatus::Valid);
    }
}

#[test]
fn mce_depth_boundaries_keep_one_semantic_contract() {
    // Attacker-controlled depth must not change MCE selection semantics.
    let selector = format!("<RelationshipsGroupReference xmlns=\"{PARAM}\" SourceType=\"urn:t\"/>");
    for depth in [126, 127, 128, 129, 130] {
        let input = format!(
            "<Relationships xmlns=\"{REL}\" xmlns:mc=\"http://schemas.openxmlformats.org/markup-compatibility/2006\" xmlns:u=\"urn:extension\" mc:Ignorable=\"u\" mc:ProcessContent=\"u:wrapper\">{}<Relationship Id=\"rid\" Type=\"urn:t\" Target=\"a\"/>{}</Relationships>",
            "<u:wrapper>".repeat(depth),
            "</u:wrapper>".repeat(depth)
        );
        let expected = format!(
            "<Relationships xmlns=\"{REL}\"><Relationship Id=\"rid\" Target=\"a\" TargetMode=\"Internal\" Type=\"urn:t\"></Relationship></Relationships>"
        );
        assert_eq!(
            normalize(&input, &selector).unwrap(),
            expected.as_bytes(),
            "depth {depth}"
        );
    }
}

#[test]
fn relationship_transform_rejects_duplicate_ids_even_when_unselected() {
    // Schema validation covers the complete post-MCE part, not just selected rows.
    let input = format!(
        "<Relationships xmlns=\"{REL}\"><Relationship Id=\"x\" Type=\"urn:t\" Target=\"a\"/><Relationship Id=\"x\" Type=\"urn:t\" Target=\"b\"/></Relationships>"
    );
    let selectors = format!("<RelationshipReference xmlns=\"{PARAM}\" SourceId=\"absent\"/>");
    assert!(
        normalize(&input, &selectors)
            .unwrap_err()
            .contains("duplicate")
    );
}

#[test]
fn relationship_transform_preserves_processing_instructions() {
    // Part 2 §10.6 removes text and comments, not processing instructions.
    let input = format!(
        "<?before test?><Relationships xmlns=\"{REL}\"><?inside test?><Relationship Id=\"x\" Type=\"urn:t\" Target=\"a\"><?child test?></Relationship></Relationships><?after test?>"
    );
    let selectors = format!("<RelationshipReference xmlns=\"{PARAM}\" SourceId=\"x\"/>");
    let output = String::from_utf8(normalize(&input, &selectors).unwrap()).unwrap();
    assert!(output.starts_with("<?before test?>\n<Relationships"));
    assert!(output.contains("<?inside test?>"));
    assert!(output.contains("<?child test?>"));
    assert!(output.ends_with("</Relationships>\n<?after test?>"));
}

#[test]
fn relationship_transform_processes_mce_selected_and_ignored_branches() {
    // MustUnderstand in discarded branches must not affect processing.
    let input = format!(
        "<Relationships xmlns=\"{REL}\" xmlns:mc=\"http://schemas.openxmlformats.org/markup-compatibility/2006\" xmlns:u=\"urn:unknown\" xmlns:r=\"{REL}\" mc:Ignorable=\"u\"><u:ignored mc:MustUnderstand=\"u\"><invalid/></u:ignored><mc:AlternateContent><mc:Choice Requires=\"u\" mc:MustUnderstand=\"u\"><invalid/></mc:Choice><mc:Choice Requires=\"r\"><Relationship Id=\"x\" Type=\"urn:t\" Target=\"a\"/></mc:Choice><mc:Fallback><invalid/></mc:Fallback></mc:AlternateContent></Relationships>"
    );
    let selectors = format!("<RelationshipReference xmlns=\"{PARAM}\" SourceId=\"x\"/>");
    let output = String::from_utf8(normalize(&input, &selectors).unwrap()).unwrap();
    assert!(output.contains("Id=\"x\""));
    assert!(!output.contains("mc:"));
}

fn signed_external_part(
    edition: OpcRelationshipEdition,
    input: &str,
) -> (String, std::collections::HashMap<String, Vec<u8>>) {
    let key = RsaSigningKey::from_pkcs8_pem(
        &std::fs::read_to_string("tests/fixtures/keys/rsa/rsa-2048-key.pem").unwrap(),
    )
    .unwrap();
    let key_info = X509CertificateKeyInfoWriter::from_pem(
        &std::fs::read_to_string("tests/fixtures/keys/rsa/rsa-2048-cert.pem").unwrap(),
    )
    .unwrap();
    let resources =
        std::collections::HashMap::from([("_rels/.rels".to_owned(), input.as_bytes().to_vec())]);
    let canonical = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
    let builder = SignatureBuilder::new(canonical.clone(), SignatureAlgorithm::RsaSha256)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("_rels/.rels")
                .transform(Transform::Relationship(vec![
                    RelationshipSelector::SourceId("rid".into()),
                ]))
                .transform(Transform::C14n(canonical)),
        )
        .key_info(true);
    let mut policy = SigningPolicy::default();
    policy.uris.references = UriTypeSet::ALL;
    policy.transforms.opc_relationship_edition = edition;
    let signed = SignContext::new(&key)
        .policy(policy)
        .key_info_writer(&key_info)
        .external_resources(&resources)
        .sign_with_builder("<root/>", &builder)
        .unwrap();
    (signed, resources)
}

#[test]
fn typed_edition_policy_reaches_signing_and_verification_without_fallback() {
    // A trusted edition choice affects the digest; verification must not retry
    // another edition to make a mismatched signature appear valid.
    let input = format!(
        "<Relationships xmlns=\"{REL}\"><Relationship Id=\"RID\" Type=\"urn:t\" Target=\"a\"/></Relationships>"
    );
    let resolver = DefaultKeyResolver::default();
    for edition in [
        OpcRelationshipEdition::Ecma2012,
        OpcRelationshipEdition::Ecma2021,
    ] {
        let (signed, resources) = signed_external_part(edition, &input);
        let mut policy = VerificationPolicy::default();
        policy.key_trust.mode = VerificationTrustMode::CryptographicOnly;
        policy.uris.references = UriTypeSet::ALL;
        policy.transforms.opc_relationship_edition = edition;
        let result = VerifyContext::new()
            .policy(policy.clone())
            .key_resolver(&resolver)
            .external_resources(&resources)
            .store_pre_digest(true)
            .verify(&signed)
            .unwrap();
        assert_eq!(result.status, DsigStatus::Valid);
        let pre_digest = std::str::from_utf8(
            result.signed_info_references[0]
                .pre_digest_data
                .as_ref()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            pre_digest.contains("Id=\"RID\""),
            edition == OpcRelationshipEdition::Ecma2021
        );
        policy.transforms.opc_relationship_edition = match edition {
            OpcRelationshipEdition::Ecma2012 => OpcRelationshipEdition::Ecma2021,
            OpcRelationshipEdition::Ecma2021 => OpcRelationshipEdition::Ecma2012,
        };
        let mismatch = VerifyContext::new()
            .policy(policy)
            .key_resolver(&resolver)
            .external_resources(&resources)
            .verify(&signed)
            .unwrap();
        assert_ne!(mismatch.status, DsigStatus::Valid);
    }
}

#[test]
fn opc_workspace_limit_is_enforced_in_public_verification() {
    // Zero workspace must stop normalization before any digest computation.
    let input = format!(
        "<Relationships xmlns=\"{REL}\"><Relationship Id=\"rid\" Type=\"urn:t\" Target=\"a\"/></Relationships>"
    );
    let (signed, resources) = signed_external_part(OpcRelationshipEdition::Ecma2021, &input);
    let resolver = DefaultKeyResolver::default();
    let mut policy = VerificationPolicy::default();
    policy.key_trust.mode = VerificationTrustMode::CryptographicOnly;
    policy.uris.references = UriTypeSet::ALL;
    policy.resources.max_opc_workspace_bytes = 0;
    let result = VerifyContext::new()
        .policy(policy)
        .key_resolver(&resolver)
        .external_resources(&resources)
        .verify(&signed);
    assert!(format!("{result:?}").contains("OPC workspace bytes"));
}

#[test]
fn invalid_relationship_shapes_and_mce_are_rejected() {
    // Schema/MCE failures must remain failures even when no selector matches.
    let selector = format!("<RelationshipReference xmlns=\"{PARAM}\" SourceId=\"none\"/>");
    for content in [
        "<Relationship Id=\"x\" Target=\"a\"/>",
        "<Relationship Id=\"x\" Type=\"urn:t\" Target=\"a\" TargetMode=\"invalid\"/>",
        "<Relationship Id=\"x\" Type=\"urn:t\" Target=\"a\" Extra=\"value\"/>",
        "<Relationship Id=\"x\" Type=\"urn:t\" Target=\"a\"><Relationship/></Relationship>",
        "<mc:AlternateContent><mc:Fallback/></mc:AlternateContent>",
        "<mc:AlternateContent><mc:Choice Requires=\"unbound\"/></mc:AlternateContent>",
        "<Relationship Id=\"x\" Type=\"urn:t\" Target=\"a\" mc:MustUnderstand=\"u\"/>",
    ] {
        let input = format!(
            "<Relationships xmlns=\"{REL}\" xmlns:mc=\"http://schemas.openxmlformats.org/markup-compatibility/2006\" xmlns:u=\"urn:unknown\">{content}</Relationships>"
        );
        assert!(normalize(&input, &selector).is_err(), "accepted {content}");
    }
}

#[test]
fn mce_process_content_resolves_prefixes_at_declaration_scope() {
    // A descendant prefix rebind must not change an inherited ProcessContent rule.
    let input = format!(
        "<Relationships xmlns=\"{REL}\" xmlns:mc=\"http://schemas.openxmlformats.org/markup-compatibility/2006\" xmlns:u=\"urn:extension\" mc:Ignorable=\"u\" mc:ProcessContent=\"u:wrapper\"><u:wrapper xmlns:u=\"urn:other\" xmlns:e=\"urn:extension\"><invalid/></u:wrapper><e:wrapper xmlns:e=\"urn:extension\"><Relationship Id=\"x\" Type=\"urn:t\" Target=\"a\"/></e:wrapper></Relationships>"
    );
    // The rebound u:wrapper is not ignorable: it must be rejected, rather than
    // inheriting the declaration's lexical prefix as if it identified a URI.
    let selector = format!("<RelationshipReference xmlns=\"{PARAM}\" SourceId=\"x\"/>");
    assert!(normalize(&input, &selector).is_err());
    let valid = input.replace(
        "<u:wrapper xmlns:u=\"urn:other\" xmlns:e=\"urn:extension\"><invalid/></u:wrapper>",
        "",
    );
    assert!(
        String::from_utf8(normalize(&valid, &selector).unwrap())
            .unwrap()
            .contains("Id=\"x\"")
    );
}

#[test]
fn relationship_signatures_interoperate_reciprocally_with_xmlsec1() {
    // Use the shared 2012 contract; SourceType and 2021 selection are separately
    // proven against the specification, since libxmlsec1 omits SourceType.
    if !xmlsec1::is_available() {
        eprintln!("{}", xmlsec1::skip_reason());
        return;
    }
    let input = format!(
        "<Relationships xmlns=\"{REL}\"><Relationship Id=\"rid\" Type=\"urn:t\" Target=\"a\"/><Relationship Id=\"other\" Type=\"urn:t\" Target=\"b\"/></Relationships>"
    );
    let (signed, resources) = signed_external_part(OpcRelationshipEdition::Ecma2012, &input);
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir(directory.path().join("_rels")).unwrap();
    std::fs::write(directory.path().join("_rels/.rels"), input).unwrap();
    std::fs::write(directory.path().join("signed.xml"), signed).unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let certificate = root.join("tests/fixtures/keys/rsa/rsa-2048-cert.pem");
    let key = root.join("tests/fixtures/keys/rsa/rsa-2048-key.pem");
    let verified = xmlsec1::command()
        .current_dir(directory.path())
        .args(["--verify", "--lax-key-search", "--pubkey-cert-pem"])
        .arg(&certificate)
        .arg("signed.xml")
        .output()
        .unwrap();
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    let signed_by_oracle = xmlsec1::command()
        .current_dir(directory.path())
        .args(["--sign", "--lax-key-search", "--privkey-pem"])
        .arg(format!("{},{}", key.display(), certificate.display()))
        .args(["--output", "oracle.xml", "signed.xml"])
        .output()
        .unwrap();
    assert!(
        signed_by_oracle.status.success(),
        "{}",
        String::from_utf8_lossy(&signed_by_oracle.stderr)
    );
    let oracle_xml = std::fs::read_to_string(directory.path().join("oracle.xml")).unwrap();
    let resolver = DefaultKeyResolver::default();
    let mut policy = VerificationPolicy::default();
    policy.key_trust.mode = VerificationTrustMode::CryptographicOnly;
    policy.uris.references = UriTypeSet::ALL;
    policy.transforms.opc_relationship_edition = OpcRelationshipEdition::Ecma2012;
    assert_eq!(
        VerifyContext::new()
            .policy(policy)
            .key_resolver(&resolver)
            .external_resources(&resources)
            .verify(&oracle_xml)
            .unwrap()
            .status,
        DsigStatus::Valid
    );
}

#[test]
fn upstream_office_relationship_fixture_signs_and_verifies() {
    // This exact upstream Office-shaped vector exercises template signing and
    // original relative resource identity, rather than a hand-picked row copy.
    let root = "tools/xmlsec1/tests/fixtures/upstream/aleksey-xmldsig-01/";
    let template = std::fs::read_to_string(format!(
        "{root}enveloping-sha256-rsa-sha256-relationship.tmpl"
    ))
    .unwrap();
    let part = std::fs::read(format!("{root}relationship/xml-base-input.xml")).unwrap();
    let resources =
        std::collections::HashMap::from([("relationship/xml-base-input.xml".to_owned(), part)]);
    let key = RsaSigningKey::from_pkcs8_pem(
        &std::fs::read_to_string("tests/fixtures/keys/rsa/rsa-2048-key.pem").unwrap(),
    )
    .unwrap();
    let key_info = X509CertificateKeyInfoWriter::from_pem(
        &std::fs::read_to_string("tests/fixtures/keys/rsa/rsa-2048-cert.pem").unwrap(),
    )
    .unwrap();
    let mut signing = SigningPolicy::default();
    signing.uris.references = UriTypeSet::ALL;
    signing.transforms.opc_relationship_edition = OpcRelationshipEdition::Ecma2012;
    let signed = SignContext::new(&key)
        .policy(signing)
        .key_info_writer(&key_info)
        .external_resources(&resources)
        .sign_template(&template)
        .unwrap();
    let resolver = DefaultKeyResolver::default();
    let mut verification = VerificationPolicy::default();
    verification.key_trust.mode = VerificationTrustMode::CryptographicOnly;
    verification.uris.references = UriTypeSet::ALL;
    verification.transforms.opc_relationship_edition = OpcRelationshipEdition::Ecma2012;
    let result = VerifyContext::new()
        .policy(verification)
        .key_resolver(&resolver)
        .external_resources(&resources)
        .store_pre_digest(true)
        .verify(&signed)
        .unwrap();
    assert_eq!(result.status, DsigStatus::Valid);
    let bytes = result.signed_info_references[0]
        .pre_digest_data
        .as_ref()
        .unwrap();
    let xml = std::str::from_utf8(bytes).unwrap();
    assert_eq!(xml.matches("<Relationship ").count(), 1);
    assert!(xml.contains("Id=\"rId1\""));
}
