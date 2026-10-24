//! `XMLDSig` XSLT transform through the public signing and verification API.

use std::fs;

#[path = "support/cryptographic.rs"]
mod cryptographic;

use base64::Engine as _;
use xml_sec::XmlDomParseError;
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::document::XmlDocumentError;
use xml_sec::policy::{
    PolicyViolation, SigningPolicy, VerificationPolicy, XsltStylesheetSemantics,
};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, DsigError, DsigStatus, ReferenceBuilder,
    ReferenceProcessingError, RsaSigningKey, SignContext, SignatureAlgorithm, SignatureBuilder,
    SigningDigestError, SigningError, Transform, TransformError, X509CertificateKeyInfoWriter,
    XPathExpression, XSLT_TRANSFORM_URI, XsltStylesheet,
};

const XSL: &str = "http://www.w3.org/1999/XSL/Transform";

/// A stylesheet whose literal result elements have no namespace: it undeclares the
/// `XMLDSig` default namespace that the signature puts in scope at its `<Transform>`.
fn stylesheet(body: &str) -> XsltStylesheet {
    XsltStylesheet::new(format!(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="{XSL}" xmlns="">{body}</xsl:stylesheet>"#
    ))
    .expect("test stylesheet is valid markup")
}

/// Wraps every item value in `<v>` under `<values>`, sorted by value.
fn values() -> XsltStylesheet {
    stylesheet(concat!(
        r#"<xsl:template match="/"><values><xsl:for-each select="//item">"#,
        r#"<xsl:sort select="."/><v><xsl:value-of select="."/></v></xsl:for-each></values>"#,
        r#"</xsl:template>"#
    ))
}

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

fn builder(reference: ReferenceBuilder) -> SignatureBuilder {
    SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(reference)
        .key_info(true)
}

fn sign(document: &str, builder: &SignatureBuilder) -> Result<String, SigningError> {
    sign_with_policy(document, builder, SigningPolicy::default())
}

fn sign_with_policy(
    document: &str,
    builder: &SignatureBuilder,
    policy: SigningPolicy,
) -> Result<String, SigningError> {
    let (key, key_info) = signing_material();
    SignContext::new(&key)
        .key_info_writer(&key_info)
        .policy(policy)
        .sign_with_builder(document, builder)
}

/// Verify `signed` and return the pre-digest bytes of every `SignedInfo` reference.
fn verified_pre_digest(signed: &str) -> Vec<Vec<u8>> {
    let resolver = DefaultKeyResolver::default();
    let result = cryptographic::context()
        .key_resolver(&resolver)
        .store_pre_digest(true)
        .verify(signed)
        .expect("signature must verify");
    assert_eq!(result.status, DsigStatus::Valid);
    result
        .signed_info_references
        .into_iter()
        .map(|reference| {
            reference
                .pre_digest_data
                .expect("pre-digest data was requested")
        })
        .collect()
}

fn transform_error(error: SigningError) -> TransformError {
    match error {
        SigningError::Digest(SigningDigestError::Transform(error)) => error,
        other => panic!("expected a transform error, got {other:?}"),
    }
}

fn policy_error(error: SigningError) -> PolicyViolation {
    match error {
        SigningError::Policy(violation) => violation,
        other => panic!("expected a policy violation, got {other:?}"),
    }
}

const ITEMS: &str = r#"<root><item ID="payload">b</item><item>a</item></root>"#;

#[test]
fn detached_entity_uri_survives_sign_verify_and_current_query_replay() {
    // XSLT's unparsed entity map belongs to the detached XML resource. An
    // inherited XML Base on Reference resolves its identity before all three paths.
    use std::{collections::HashMap, sync::Arc};
    use structured_asn1::memory::{Memory, MemoryAccount};
    use xml_sec::xmldsig::{
        HmacSigningKey, HmacVerificationKey, ReplayMode, ReplayOutcome, UriTypeSet,
        VerificationRequest, VerifyContext, with_verified_request,
    };
    let resources = HashMap::from([(
        "https://example.org/data/input.xml".to_owned(),
        br#"<!DOCTYPE root [<!NOTATION image SYSTEM "image"><!ENTITY logo SYSTEM "images/logo.png" NDATA image>]><root/>"#.to_vec(),
    )]);
    let signing_key = HmacSigningKey::new(vec![0x31; 32]).unwrap();
    let verifying_key = HmacVerificationKey::new(vec![0x31; 32]).unwrap();
    let expected = b"https://example.org/data/images/logo.png";
    let sheet = stylesheet(
        r#"<xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="unparsed-entity-uri('logo')"/></xsl:template>"#,
    );
    let builder = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::HmacSha256)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("input.xml")
                .transform(Transform::Xslt(sheet)),
        );
    let mut signing = SigningPolicy::default();
    signing.uris.references = UriTypeSet::ALL;
    signing.xml.allow_internal_dtd = true;
    let signed = SignContext::new(&signing_key)
        .policy(signing)
        .external_resources(&resources)
        .sign_with_builder(r#"<root xml:base="https://example.org/data/"/>"#, &builder)
        .unwrap();
    let mut policy = VerificationPolicy::default();
    policy.uris.references = UriTypeSet::ALL;
    policy.xml.allow_internal_dtd = true;
    let context = VerifyContext::new()
        .key(&verifying_key)
        .policy(policy)
        .store_pre_digest(true);
    let request = VerificationRequest {
        external_resources: Some(&resources),
        ..Default::default()
    };
    let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 24, 1 << 30)));
    for backend in xml_sec::XmlBackend::available() {
        let document = xml_sec::XmlDocument::parse_with_backend(signed.clone(), backend).unwrap();
        with_verified_request(&document, &context, &request, &memory, |session| {
            assert!(session.evidence().all_valid());
            let evidence = &session.evidence().signatures()[0];
            assert_eq!(
                evidence.result().as_ref().unwrap().signed_info_references[0]
                    .pre_digest_data
                    .as_deref(),
                Some(expected.as_slice())
            );
            let selected = session.select_signature(evidence.identity())?;
            selected
                .visit_authenticated_references(|reference| {
                    let mut replay = Vec::new();
                    assert_eq!(
                        selected
                            .replay_reference(
                                reference.identity,
                                ReplayMode::ReferenceOutput,
                                &mut |bytes: &[u8]| {
                                    replay.extend_from_slice(bytes);
                                    Ok::<_, ()>(())
                                }
                            )
                            .unwrap(),
                        ReplayOutcome::Complete
                    );
                    assert_eq!(replay, expected);
                    Ok::<_, ()>(())
                })
                .unwrap();
            Ok(())
        })
        .unwrap();
        assert_eq!(memory.used(), 0);
    }
}

#[test]
fn referenced_whitespace_beside_stylesheet_signs_and_verifies() {
    // XPath 1.0 section 5.1 excludes text children of a document root. CR
    // references accepted in Transform content must not become document markup.
    let (key, key_info) = signing_material();
    for backend in xml_sec::XmlBackend::available() {
        for semantics in [
            XsltStylesheetSemantics::Specification,
            XsltStylesheetSemantics::Libxmlsec1,
        ] {
            let sheet = XsltStylesheet::new(format!(
                r#"&#13;<?before alpha?><!--one--><xsl:stylesheet xmlns:xsl="{XSL}" version="1.0"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="concat(count(document('')/processing-instruction()), ':', count(document('')/comment()), ':', count(document('')/text()))"/></xsl:template></xsl:stylesheet><!--two--><?after beta?>&#13;"#
            )).expect("CR is permitted whitespace in Transform content");
            let signature = builder(
                ReferenceBuilder::new(DigestAlgorithm::Sha256)
                    .uri("")
                    .transform(Transform::Enveloped)
                    .transform(Transform::Xslt(sheet)),
            );
            let mut signing = SigningPolicy::default();
            signing.transforms.xslt_stylesheet_semantics = semantics;
            let signed = SignContext::new(&key)
                .key_info_writer(&key_info)
                .policy(signing)
                .xml_backend(backend)
                .sign_with_builder(ITEMS, &signature)
                .expect("referenced stylesheet whitespace must sign");
            let mut verification = VerificationPolicy::default();
            verification.key_trust.mode = xml_sec::policy::VerificationTrustMode::CryptographicOnly;
            verification.transforms.xslt_stylesheet_semantics = semantics;
            let resolver = DefaultKeyResolver::default();
            let result = xml_sec::xmldsig::VerifyContext::new()
                .policy(verification)
                .xml_backend(backend)
                .key_resolver(&resolver)
                .store_pre_digest(true)
                .verify(&signed)
                .expect("referenced stylesheet whitespace must verify");
            assert_eq!(
                result.status,
                DsigStatus::Valid,
                "{backend:?}: {semantics:?}"
            );
            assert_eq!(
                result.signed_info_references[0].pre_digest_data.as_deref(),
                Some(b"2:2:0".as_slice()),
                "{backend:?}: {semantics:?}"
            );
        }
    }
}

#[test]
fn node_set_input_is_canonicalized_and_terminal_output_is_digested() {
    // XMLDSig 1.1 section 4.4.3.2 converts the node-set to octets with inclusive
    // C14N 1.0; the stylesheet then sees the whole document minus the Signature.
    let reference = ReferenceBuilder::new(DigestAlgorithm::Sha256)
        .uri("")
        .transform(Transform::Enveloped)
        .transform(Transform::Xslt(values()));
    let signed = sign(ITEMS, &builder(reference)).expect("node-set to XSLT must sign");
    assert!(signed.contains(&format!(r#"Algorithm="{XSLT_TRANSFORM_URI}""#)));
    assert_eq!(
        verified_pre_digest(&signed),
        [b"<?xml version=\"1.0\"?>\n<values><v>a</v><v>b</v></values>\n".to_vec()]
    );
}

#[test]
fn base64_output_feeds_the_stylesheet_and_xpath_reads_its_result() {
    // Binary input is used as is; a following XPath transform reparses the
    // serialized result tree into a node-set.
    let encoded =
        base64::engine::general_purpose::STANDARD.encode("<doc><item>z</item><item>y</item></doc>");
    let document = format!(r#"<root><data ID="payload">{encoded}</data></root>"#);
    let reference = ReferenceBuilder::new(DigestAlgorithm::Sha256)
        .uri("#payload")
        .transform(Transform::Base64Decode)
        .transform(Transform::Xslt(values()))
        .transform(Transform::XPath(XPathExpression::new(
            "ancestor-or-self::v[1]",
        )))
        .transform(Transform::C14n(exclusive_c14n()));
    let signed = sign(&document, &builder(reference)).expect("Base64 to XSLT must sign");
    assert_eq!(verified_pre_digest(&signed), [b"<v>y</v><v>z</v>".to_vec()]);
}

#[test]
fn chained_stylesheets_consume_each_others_output() {
    // The second stylesheet receives the first one's serialized document.
    let count = stylesheet(
        r#"<xsl:template match="/"><n><xsl:value-of select="count(//v)"/></n></xsl:template>"#,
    );
    let reference = ReferenceBuilder::new(DigestAlgorithm::Sha256)
        .uri("")
        .transform(Transform::Enveloped)
        .transform(Transform::Xslt(values()))
        .transform(Transform::Xslt(count));
    let signed = sign(ITEMS, &builder(reference)).expect("chained XSLT must sign");
    assert_eq!(
        verified_pre_digest(&signed),
        [b"<?xml version=\"1.0\"?>\n<n>2</n>\n".to_vec()]
    );
}

#[test]
fn output_allowance_is_shared_by_every_execution_in_an_operation() {
    // Each execution fits the output limit while their sum does not; the second
    // reference must see what the first one already produced. Verification runs
    // each reference once, so the operation total is exactly two outputs.
    let output = "<?xml version=\"1.0\"?>\n<values><v>a</v><v>b</v></values>\n".len();
    let reference = || {
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("")
            .transform(Transform::Enveloped)
            .transform(Transform::Xslt(values()))
    };
    let signed = sign(ITEMS, &builder(reference()).add_reference(reference()))
        .expect("two XSLT references sign");
    let verify = |maximum| {
        let mut policy = VerificationPolicy::default();
        policy.key_trust.mode = xml_sec::policy::VerificationTrustMode::CryptographicOnly;
        policy.resources.max_xslt_output_bytes = maximum;
        let resolver = DefaultKeyResolver::default();
        xml_sec::xmldsig::VerifyContext::new()
            .policy(policy)
            .key_resolver(&resolver)
            .verify(&signed)
    };

    let error = verify(output + output - 1).expect_err("second output must not fit");
    assert!(
        matches!(
            error,
            DsigError::Policy(PolicyViolation::ResourceLimit {
                resource: "XSLT output bytes",
                maximum,
                actual,
            }) if maximum == output + output - 1 && actual == output + output
        ),
        "{error:?}"
    );
    let result = verify(output + output).expect("both outputs fit exactly");
    assert_eq!(result.status, DsigStatus::Valid);
}

#[test]
fn work_limit_refuses_parameter_capture_before_execution() {
    // Native stylesheet capture belongs to the operation too; a one-unit
    // allowance refuses the second byte of the start-tag metadata scan,
    // before serialization/compilation/execution. No raw source
    // slice is copied before the tree is captured.
    let sheet = values();
    let reference = ReferenceBuilder::new(DigestAlgorithm::Sha256)
        .uri("")
        .transform(Transform::Enveloped)
        .transform(Transform::Xslt(sheet));
    let mut policy = SigningPolicy::default();
    policy.resources.max_xslt_work = 1;
    let error = policy_error(
        sign_with_policy(ITEMS, &builder(reference), policy).expect_err("work exceeds one unit"),
    );
    assert_eq!(
        error,
        PolicyViolation::ResourceLimit {
            resource: "XSLT work",
            maximum: 1,
            actual: 2,
        }
    );
}

#[test]
fn template_rejects_stylesheet_above_target_workspace() {
    // A stylesheet accepted by its constructor must still obey the policy of
    // the generated template, before the builder serializes its markup.
    let sheet = values();
    let bytes = sheet.source().len();
    let template = builder(
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("")
            .transform(Transform::Enveloped)
            .transform(Transform::Xslt(sheet)),
    );
    let mut policy = SigningPolicy::default();
    policy.resources.max_xslt_workspace_bytes = bytes - 1;
    let error = template
        .build_template_with_policy(&policy)
        .expect_err("target workspace must admit stylesheet markup");
    assert!(
        matches!(
            error,
            xml_sec::xmldsig::SignatureBuilderError::Policy(PolicyViolation::ResourceLimit {
                resource: "XSLT workspace bytes", maximum, actual,
            }) if maximum == bytes - 1 && actual == bytes
        ),
        "{error:?}"
    );
}

#[test]
fn workspace_limit_refuses_the_compilation() {
    let reference = ReferenceBuilder::new(DigestAlgorithm::Sha256)
        .uri("")
        .transform(Transform::Enveloped)
        .transform(Transform::Xslt(values()));
    let mut policy = SigningPolicy::default();
    policy.resources.max_xslt_workspace_bytes = 16;
    let error = policy_error(
        sign_with_policy(ITEMS, &builder(reference), policy)
            .expect_err("a stylesheet needs more than 16 bytes"),
    );
    assert!(
        matches!(
            error,
            PolicyViolation::ResourceLimit {
                resource: "XSLT workspace bytes",
                maximum: 16,
                actual,
            } if actual > 16
        ),
        "{error:?}"
    );
}

#[test]
fn policy_without_xslt_refuses_signing_and_verification() {
    // XSLT permission is the transform allowlist of the operation policy.
    let reference = ReferenceBuilder::new(DigestAlgorithm::Sha256)
        .uri("")
        .transform(Transform::Enveloped)
        .transform(Transform::Xslt(values()));
    let builder = builder(reference);
    let allowed = [
        "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
        "http://www.w3.org/2001/10/xml-exc-c14n#",
    ];
    let mut signing = SigningPolicy::default();
    signing.transforms.allowed_algorithms = Some(allowed.iter().map(|uri| (*uri).into()).collect());
    let error = sign_with_policy(ITEMS, &builder, signing).expect_err("XSLT is not allowed");
    assert!(
        matches!(
            &error,
            SigningError::Policy(PolicyViolation::Algorithm { algorithm, .. })
                if algorithm == XSLT_TRANSFORM_URI
        ),
        "{error:?}"
    );

    let signed = sign(ITEMS, &builder).expect("default policy allows XSLT");
    let mut verification = VerificationPolicy::default();
    verification.key_trust.mode = xml_sec::policy::VerificationTrustMode::CryptographicOnly;
    verification.transforms.allowed_algorithms =
        Some(allowed.iter().map(|uri| (*uri).into()).collect());
    let resolver = DefaultKeyResolver::default();
    let error = xml_sec::xmldsig::VerifyContext::new()
        .policy(verification)
        .key_resolver(&resolver)
        .verify(&signed)
        .expect_err("XSLT is not allowed");
    assert!(
        matches!(
            &error,
            DsigError::Policy(PolicyViolation::Algorithm { algorithm, .. })
                if algorithm == XSLT_TRANSFORM_URI
        ),
        "{error:?}"
    );
}

#[test]
fn node_set_input_to_xslt_needs_the_implicit_c14n_permission() {
    // XMLDSig 1.1 section 4.4.3.2 converts a node-set given to XSLT with inclusive
    // C14N 1.0, so that algorithm runs and must be on the transform allowlist even
    // though the chain ends with octets.
    let reference = ReferenceBuilder::new(DigestAlgorithm::Sha256)
        .uri("")
        .transform(Transform::Enveloped)
        .transform(Transform::Xslt(values()));
    let builder = builder(reference);
    let allowed = [
        "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
        "http://www.w3.org/2001/10/xml-exc-c14n#",
        XSLT_TRANSFORM_URI,
    ];
    let mut signing = SigningPolicy::default();
    signing.transforms.allowed_algorithms = Some(allowed.iter().map(|uri| (*uri).into()).collect());
    let error = sign_with_policy(ITEMS, &builder, signing).expect_err("inclusive C14N is excluded");
    assert!(
        matches!(
            &error,
            SigningError::Policy(PolicyViolation::Algorithm { algorithm, .. })
                if algorithm == xml_sec::xmldsig::DEFAULT_IMPLICIT_C14N_URI
        ),
        "{error:?}"
    );

    let signed = sign(ITEMS, &builder).expect("default policy allows the chain");
    let mut verification = VerificationPolicy::default();
    verification.key_trust.mode = xml_sec::policy::VerificationTrustMode::CryptographicOnly;
    verification.transforms.allowed_algorithms =
        Some(allowed.iter().map(|uri| (*uri).into()).collect());
    let resolver = DefaultKeyResolver::default();
    let error = xml_sec::xmldsig::VerifyContext::new()
        .policy(verification)
        .key_resolver(&resolver)
        .verify(&signed)
        .expect_err("inclusive C14N is excluded");
    assert!(
        matches!(
            &error,
            DsigError::Policy(PolicyViolation::Algorithm { algorithm, .. })
                if algorithm == xml_sec::xmldsig::DEFAULT_IMPLICIT_C14N_URI
        ),
        "{error:?}"
    );
}

#[test]
fn stylesheets_cannot_reach_external_resources() {
    // The transform has no resolver: imports and document() are policy refusals,
    // never empty results.
    for body in [
        r#"<xsl:import href="other.xsl"/><xsl:template match="/"><r/></xsl:template>"#,
        r#"<xsl:template match="/"><r><xsl:copy-of select="document('other.xml')"/></r></xsl:template>"#,
    ] {
        let reference = ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("")
            .transform(Transform::Enveloped)
            .transform(Transform::Xslt(stylesheet(body)));
        let error = policy_error(
            sign(ITEMS, &builder(reference)).expect_err("external resources are unavailable"),
        );
        assert!(
            matches!(
                error,
                PolicyViolation::Uri {
                    operation: "XSLT transform",
                    ..
                }
            ),
            "{body}: {error:?}"
        );
    }
}

#[test]
fn unbound_prefix_lists_follow_the_operation_policy() {
    // XSLT 1.0 section 7.1.1 makes an unbound prefix in exclude-result-prefixes an error by
    // default; the libxslt handling that libxmlsec1 applies is an explicit policy choice.
    let unbound = || {
        Transform::Xslt(
            XsltStylesheet::new(format!(
                r#"<xsl:stylesheet version="1.0" xmlns:xsl="{XSL}" exclude-result-prefixes="foo"><xsl:template match="/"><r/></xsl:template></xsl:stylesheet>"#
            ))
            .expect("well-formed stylesheet markup"),
        )
    };
    let builder = builder(
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("")
            .transform(Transform::Enveloped)
            .transform(unbound()),
    );
    let error = transform_error(sign(ITEMS, &builder).expect_err("specification rejects it"));
    assert!(matches!(error, TransformError::Xslt(_)), "{error:?}");

    let mut signing = SigningPolicy::default();
    signing.transforms.xslt_stylesheet_semantics = XsltStylesheetSemantics::Libxmlsec1;
    let signed = sign_with_policy(ITEMS, &builder, signing).expect("libxslt handling signs");
    let verify = |semantics| {
        let mut policy = VerificationPolicy::default();
        policy.key_trust.mode = xml_sec::policy::VerificationTrustMode::CryptographicOnly;
        policy.transforms.xslt_stylesheet_semantics = semantics;
        let resolver = DefaultKeyResolver::default();
        xml_sec::xmldsig::VerifyContext::new()
            .policy(policy)
            .key_resolver(&resolver)
            .store_pre_digest(true)
            .verify(&signed)
    };
    let result = verify(XsltStylesheetSemantics::Libxmlsec1).expect("libxslt handling verifies");
    assert_eq!(result.status, DsigStatus::Valid);
    assert_eq!(
        result.signed_info_references[0].pre_digest_data.as_deref(),
        Some(b"<?xml version=\"1.0\"?>\n<r/>\n".as_slice())
    );
    let error = verify(XsltStylesheetSemantics::Specification)
        .expect_err("specification rejects the stylesheet");
    assert!(
        matches!(
            error,
            DsigError::Reference(ReferenceProcessingError::Transform(TransformError::Xslt(_)))
        ),
        "{error:?}"
    );
}

#[test]
fn stylesheets_keep_the_namespaces_in_scope_at_their_transform() {
    // The stylesheet is an element of the signed document: a prefix declared on an
    // ancestor names the XSLT namespace (Namespaces in XML 1.0 section 6.1), and its
    // literal result element copies every namespace in scope but the XSLT one (XSLT 1.0
    // section 7.1.1), here `ds`. libxmlsec1 compiles the `<Transform>` content alone and
    // loses the `xsl` declaration.
    let template = format!(
        concat!(
            r#"<root xmlns:xsl="{xsl}"><item>a</item>"#,
            r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>"#,
            r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
            r#"<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"/>"#,
            r#"<ds:Reference URI=""><ds:Transforms>"#,
            r#"<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>"#,
            r#"<ds:Transform Algorithm="{xslt}"><xsl:stylesheet version="1.0">"#,
            r#"<xsl:template match="/"><out><xsl:value-of select="//item"/></out></xsl:template>"#,
            r#"</xsl:stylesheet></ds:Transform></ds:Transforms>"#,
            r#"<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>"#,
            r#"<ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/>"#,
            r#"</ds:Signature></root>"#
        ),
        xsl = XSL,
        xslt = XSLT_TRANSFORM_URI
    );
    let signing_key = xml_sec::xmldsig::HmacSigningKey::new(vec![7; 32]).unwrap();
    let verification_key = xml_sec::xmldsig::HmacVerificationKey::new(vec![7; 32]).unwrap();
    let sign = |semantics| {
        let mut policy = SigningPolicy::default();
        policy.transforms.xslt_stylesheet_semantics = semantics;
        SignContext::new(&signing_key)
            .policy(policy)
            .sign_template(&template)
    };

    let signed = sign(XsltStylesheetSemantics::Specification).expect("the stylesheet compiles");
    let result = xml_sec::xmldsig::VerifyContext::new()
        .key(&verification_key)
        .store_pre_digest(true)
        .verify(&signed)
        .expect("verification runs");
    assert_eq!(result.status, DsigStatus::Valid);
    assert_eq!(
        result.signed_info_references[0].pre_digest_data.as_deref(),
        Some(
            b"<?xml version=\"1.0\"?>\n<out xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">a</out>\n"
                .as_slice()
        )
    );

    let error = transform_error(
        sign(XsltStylesheetSemantics::Libxmlsec1).expect_err("`xsl` is unbound in the content"),
    );
    assert!(matches!(error, TransformError::Xslt(_)), "{error:?}");
}

#[test]
fn entity_stylesheet_after_literal_misc_uses_expanded_children() {
    // XML 1.0 section 4.4 replaces entity markup at the reference. Its DOM
    // source range may precede a literal PI/comment sibling in the document.
    let sheet = format!(
        r#"<xsl:stylesheet xmlns:xsl="{XSL}" version="1.0" exclude-result-prefixes="ds"><xsl:template match="/"><out>expanded</out></xsl:template></xsl:stylesheet>"#
    );
    for (backend, misc) in xml_sec::XmlBackend::available().flat_map(|backend| {
        ["<?before stylesheet?>", "<!--before stylesheet-->"].map(|misc| (backend, misc))
    }) {
        let template = format!(
            concat!(
                r#"<!DOCTYPE root [<!ENTITY sheet '{sheet}'>]><root>"#,
                r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>"#,
                r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
                r#"<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"/>"#,
                r#"<ds:Reference URI=""><ds:Transforms>"#,
                r#"<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>"#,
                r#"<ds:Transform Algorithm="{xslt}">{misc}&sheet;</ds:Transform>"#,
                r#"</ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>"#,
                r#"<ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/>"#,
                r#"</ds:Signature></root>"#
            ),
            sheet = sheet,
            misc = misc,
            xslt = XSLT_TRANSFORM_URI
        );
        let signing_key = xml_sec::xmldsig::HmacSigningKey::new(vec![7; 32]).unwrap();
        let verification_key = xml_sec::xmldsig::HmacVerificationKey::new(vec![7; 32]).unwrap();
        let mut policy = SigningPolicy::default();
        policy.xml.allow_internal_dtd = true;
        let signed = SignContext::new(&signing_key)
            .xml_backend(backend)
            .policy(policy)
            .sign_template(&template)
            .expect("entity-supplied stylesheet signs after Misc");
        let mut policy = VerificationPolicy::default();
        policy.xml.allow_internal_dtd = true;
        let verified = xml_sec::xmldsig::VerifyContext::new()
            .xml_backend(backend)
            .key(&verification_key)
            .policy(policy)
            .store_pre_digest(true)
            .verify(&signed)
            .expect("expanded stylesheet verifies");
        assert_eq!(verified.status, DsigStatus::Valid);
        assert_eq!(
            verified.signed_info_references[0]
                .pre_digest_data
                .as_deref(),
            Some(b"<?xml version=\"1.0\"?>\n<out>expanded</out>\n".as_slice())
        );
    }
}

#[test]
fn stylesheets_use_the_entities_of_their_document() {
    // An internal entity is replaced where it is referenced (XML 1.0 section 4.4), so a
    // stylesheet referring to one compiles with its replacement text, not as a fragment
    // detached from the document's DTD.
    let template = format!(
        concat!(
            r#"<!DOCTYPE root [<!ENTITY path "//item">]><root><item>a</item>"#,
            r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>"#,
            r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
            r#"<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"/>"#,
            r#"<ds:Reference URI=""><ds:Transforms>"#,
            r#"<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>"#,
            r#"<ds:Transform Algorithm="{xslt}"><xsl:stylesheet version="1.0" xmlns:xsl="{xsl}" "#,
            r#"exclude-result-prefixes="ds"><xsl:template match="/"><out>"#,
            r#"<xsl:value-of select="&path;"/></out></xsl:template></xsl:stylesheet>"#,
            r#"</ds:Transform></ds:Transforms>"#,
            r#"<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>"#,
            r#"<ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/>"#,
            r#"</ds:Signature></root>"#
        ),
        xsl = XSL,
        xslt = XSLT_TRANSFORM_URI
    );
    let signing_key = xml_sec::xmldsig::HmacSigningKey::new(vec![7; 32]).unwrap();
    let verification_key = xml_sec::xmldsig::HmacVerificationKey::new(vec![7; 32]).unwrap();
    let mut signing = SigningPolicy::default();
    signing.xml.allow_internal_dtd = true;
    let signed = SignContext::new(&signing_key)
        .policy(signing)
        .sign_template(&template)
        .expect("the stylesheet compiles with the replaced entity");
    let mut verification = VerificationPolicy::default();
    verification.xml.allow_internal_dtd = true;
    let result = xml_sec::xmldsig::VerifyContext::new()
        .policy(verification)
        .key(&verification_key)
        .store_pre_digest(true)
        .verify(&signed)
        .expect("verification runs");
    assert_eq!(result.status, DsigStatus::Valid);
    assert_eq!(
        result.signed_info_references[0].pre_digest_data.as_deref(),
        Some(b"<?xml version=\"1.0\"?>\n<out>a</out>\n".as_slice())
    );
}

#[cfg(feature = "xml-backend-xmloxide")]
#[test]
fn stylesheets_keep_namespace_declarations_defaulted_by_the_dtd() {
    // An attribute-list declaration can default an `xmlns:p` attribute (XML 1.0 section
    // 3.3.2); the stylesheet element then binds `p` as if it were written on it
    // (Namespaces in XML 1.0 section 3). The xmloxide parser applies such defaults;
    // roxmltree does not and rejects the document, so the backend is chosen here.
    let template = format!(
        concat!(
            r#"<!DOCTYPE root [<!ATTLIST xsl:stylesheet xmlns:p CDATA "urn:p">]>"#,
            r#"<root><item>a</item>"#,
            r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>"#,
            r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
            r#"<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"/>"#,
            r#"<ds:Reference URI=""><ds:Transforms>"#,
            r#"<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>"#,
            r#"<ds:Transform Algorithm="{xslt}"><xsl:stylesheet version="1.0" xmlns:xsl="{xsl}" "#,
            r#"exclude-result-prefixes="ds"><xsl:template match="/"><p:out>"#,
            r#"<xsl:value-of select="//item"/></p:out></xsl:template></xsl:stylesheet>"#,
            r#"</ds:Transform></ds:Transforms>"#,
            r#"<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>"#,
            r#"<ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/>"#,
            r#"</ds:Signature></root>"#
        ),
        xsl = XSL,
        xslt = XSLT_TRANSFORM_URI
    );
    let signing_key = xml_sec::xmldsig::HmacSigningKey::new(vec![7; 32]).unwrap();
    let verification_key = xml_sec::xmldsig::HmacVerificationKey::new(vec![7; 32]).unwrap();
    let mut signing = SigningPolicy::default();
    signing.xml.allow_internal_dtd = true;
    let signed = SignContext::new(&signing_key)
        .policy(signing)
        .xml_backend(xml_sec::XmlBackend::Xmloxide)
        .sign_template(&template)
        .expect("the defaulted prefix is bound");
    let mut verification = VerificationPolicy::default();
    verification.xml.allow_internal_dtd = true;
    let result = xml_sec::xmldsig::VerifyContext::new()
        .policy(verification)
        .xml_backend(xml_sec::XmlBackend::Xmloxide)
        .key(&verification_key)
        .store_pre_digest(true)
        .verify(&signed)
        .expect("verification runs");
    assert_eq!(result.status, DsigStatus::Valid);
    assert_eq!(
        result.signed_info_references[0].pre_digest_data.as_deref(),
        Some(b"<?xml version=\"1.0\"?>\n<p:out xmlns:p=\"urn:p\">a</p:out>\n".as_slice())
    );
}

#[test]
fn invalid_stylesheets_are_typed_errors() {
    assert!(matches!(
        XsltStylesheet::new("<xsl:stylesheet"),
        Err(TransformError::XmlParse(_))
    ));
    assert!(matches!(
        XsltStylesheet::new("<a/><b/>"),
        Err(TransformError::UnsupportedTransform(_))
    ));
    assert!(matches!(
        XsltStylesheet::new(r#"<?xml version="1.0"?><a/>"#),
        Err(TransformError::XmlParse(_))
    ));

    // Well-formed markup that is not a valid XSLT 1.0 stylesheet fails at execution.
    let reference = ReferenceBuilder::new(DigestAlgorithm::Sha256)
        .uri("")
        .transform(Transform::Enveloped)
        .transform(Transform::Xslt(stylesheet("<xsl:unknown/>")));
    let error = transform_error(sign(ITEMS, &builder(reference)).expect_err("unknown instruction"));
    assert!(matches!(error, TransformError::Xslt(_)), "{error:?}");
}

#[test]
fn the_stylesheet_must_be_the_sole_child_of_its_transform() {
    // XMLDSig 1.1 section 6.6.5: the stylesheet "MUST be the sole child of the
    // Transform element". Content beside it is refused when the transform is parsed,
    // not dropped from the stylesheet that is compiled.
    let parse = |content: &str| {
        let xml = format!(
            concat!(
                r#"<Transforms xmlns="http://www.w3.org/2000/09/xmldsig#">"#,
                r#"<Transform Algorithm="{xslt}">{content}</Transform></Transforms>"#
            ),
            xslt = XSLT_TRANSFORM_URI,
            content = content
        );
        let document = xml_sec::Document::parse(&xml).expect("fixed XML parses");
        xml_sec::xmldsig::parse_transforms(document.root_element()).map(|chain| chain.len())
    };
    let sheet = format!(r#"<xsl:stylesheet version="1.0" xmlns:xsl="{XSL}"/>"#);
    assert_eq!(parse(&format!("\n {sheet} <!--note-->\n")).ok(), Some(1));
    for content in [
        format!("{sheet}<extra/>"),
        format!("{sheet}text"),
        format!("text{sheet}"),
    ] {
        assert!(
            matches!(
                parse(&content),
                Err(TransformError::UnsupportedTransform(_))
            ),
            "{content}"
        );
    }
}

#[test]
fn the_stylesheet_root_is_an_xslt_stylesheet_element() {
    // XMLDSig 1.1 section 6.6.5 requires "the mandatory XSLT namespace-qualified
    // stylesheet element"; a literal result element used as a simplified stylesheet
    // (XSLT 1.0 section 2.3) is not one.
    let simplified = format!(r#"<out xsl:version="1.0" xmlns:xsl="{XSL}">x</out>"#);
    assert!(matches!(
        XsltStylesheet::new(simplified.clone()),
        Err(TransformError::UnsupportedTransform(_))
    ));
    let xml = format!(
        concat!(
            r#"<Transforms xmlns="http://www.w3.org/2000/09/xmldsig#">"#,
            r#"<Transform Algorithm="{xslt}">{content}</Transform></Transforms>"#
        ),
        xslt = XSLT_TRANSFORM_URI,
        content = simplified
    );
    let document = xml_sec::Document::parse(&xml).expect("fixed XML parses");
    assert!(matches!(
        xml_sec::xmldsig::parse_transforms(document.root_element()),
        Err(TransformError::UnsupportedTransform(_))
    ));
    let transform = format!(r#"<xsl:transform version="1.0" xmlns:xsl="{XSL}"/>"#);
    assert!(XsltStylesheet::new(transform).is_ok());
}

#[test]
fn stylesheet_size_is_checked_before_the_template_is_written() {
    // A stylesheet larger than the document limit is refused by its own size, before
    // it is copied into a signature template.
    let sheet = stylesheet(&format!(
        r#"<xsl:template match="/"><out>{}</out></xsl:template>"#,
        "x".repeat(4096)
    ));
    let mut policy = SigningPolicy::default();
    policy.resources.max_xml_document_bytes = 1024;
    let reference = ReferenceBuilder::new(DigestAlgorithm::Sha256)
        .uri("")
        .transform(Transform::Enveloped)
        .transform(Transform::Xslt(sheet.clone()));
    let violation = policy_error(
        sign_with_policy(ITEMS, &builder(reference), policy)
            .expect_err("the stylesheet exceeds the document limit"),
    );
    assert!(
        matches!(
            violation,
            PolicyViolation::ResourceLimit { maximum: 1024, actual, .. }
                if actual == sheet.source().len()
        ),
        "{violation:?}"
    );
}

#[test]
fn stylesheets_are_bounded_together_before_the_template_is_written() {
    // Each stylesheet fits the document limit, their sum does not: all of them are
    // refused by their combined size before any is copied into the template.
    let sheet = stylesheet(&format!(
        r#"<xsl:template match="/"><out>{}</out></xsl:template>"#,
        "x".repeat(600)
    ));
    let size = sheet.source().len();
    let mut policy = SigningPolicy::default();
    policy.resources.max_xml_document_bytes = size + size / 2;
    let reference = || {
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("")
            .transform(Transform::Enveloped)
            .transform(Transform::Xslt(sheet.clone()))
    };
    let violation = policy_error(
        sign_with_policy(
            ITEMS,
            &builder(reference()).add_reference(reference()),
            policy,
        )
        .expect_err("the stylesheets together exceed the document limit"),
    );
    assert!(
        matches!(
            violation,
            PolicyViolation::ResourceLimit { actual, .. } if actual == 2 * size
        ),
        "{violation:?}"
    );
}

#[test]
fn parsed_stylesheets_are_written_without_their_original_document() {
    // A stylesheet parsed from one document may use a prefix declared on an ancestor
    // of its `<Transform>` and an entity of that document's DTD. Written into another
    // signature, it must not depend on either.
    let source = format!(
        concat!(
            r#"<!DOCTYPE Transforms [<!ENTITY path "//item">]>"#,
            r#"<Transforms xmlns="http://www.w3.org/2000/09/xmldsig#" xmlns:xsl="{xsl}">"#,
            r#"<Transform Algorithm="{xslt}"><xsl:stylesheet version="1.0" xmlns="">"#,
            r#"<xsl:template match="/"><out><xsl:value-of select="&path;"/></out>"#,
            r#"</xsl:template></xsl:stylesheet></Transform></Transforms>"#
        ),
        xsl = XSL,
        xslt = XSLT_TRANSFORM_URI
    );
    let document = xml_sec::Document::parse_with_options(
        &source,
        xml_sec::ParsingOptions {
            allow_dtd: true,
            ..Default::default()
        },
    )
    .expect("fixed XML parses");
    let mut chain =
        xml_sec::xmldsig::parse_transforms(document.root_element()).expect("the stylesheet parses");
    let transform = chain.pop().expect("one transform");
    let reference = ReferenceBuilder::new(DigestAlgorithm::Sha256)
        .uri("")
        .transform(Transform::Enveloped)
        .transform(transform);
    let signed = sign(ITEMS, &builder(reference)).expect("the written stylesheet is complete");
    assert_eq!(
        verified_pre_digest(&signed),
        [b"<?xml version=\"1.0\"?>\n<out>b</out>\n".to_vec()]
    );
}

#[test]
fn binary_input_document_type_follows_the_xml_input_policy() {
    // Internal entities and attribute defaults change the transformed data, so a
    // DOCTYPE in decoded input is refused unless the operation allows internal DTDs,
    // with the same error as the binary-to-node-set adapter.
    let encoded = base64::engine::general_purpose::STANDARD
        .encode(r#"<!DOCTYPE doc [<!ENTITY e "y">]><doc><item>&e;</item></doc>"#);
    let document = format!(r#"<root><data ID="payload">{encoded}</data></root>"#);
    let reference = ReferenceBuilder::new(DigestAlgorithm::Sha256)
        .uri("#payload")
        .transform(Transform::Base64Decode)
        .transform(Transform::Xslt(values()));
    let error = transform_error(
        sign(&document, &builder(reference.clone())).expect_err("DTDs are not allowed"),
    );
    assert!(
        matches!(
            error,
            TransformError::XmlParse(XmlDocumentError::Parse(XmlDomParseError::DtdDetected))
        ),
        "{error:?}"
    );

    let mut policy = SigningPolicy::default();
    policy.xml.allow_internal_dtd = true;
    let signed =
        sign_with_policy(&document, &builder(reference), policy).expect("DTDs are allowed");
    let resolver = DefaultKeyResolver::default();
    let mut verification = VerificationPolicy::default();
    verification.key_trust.mode = xml_sec::policy::VerificationTrustMode::CryptographicOnly;
    verification.xml.allow_internal_dtd = true;
    let result = xml_sec::xmldsig::VerifyContext::new()
        .policy(verification)
        .key_resolver(&resolver)
        .store_pre_digest(true)
        .verify(&signed)
        .expect("signature with an allowed DTD verifies");
    assert_eq!(result.status, DsigStatus::Valid);
    assert_eq!(
        result.signed_info_references[0].pre_digest_data.as_deref(),
        Some(b"<?xml version=\"1.0\"?>\n<values><v>y</v></values>\n".as_slice())
    );
}

#[test]
fn verification_reports_xslt_failures_as_reference_errors() {
    // A stylesheet that compiles at signing but fails at verification is a
    // reference processing error, not a digest mismatch.
    let terminate = stylesheet(
        r#"<xsl:template match="/"><xsl:message terminate="yes">stop</xsl:message></xsl:template>"#,
    );
    let reference = ReferenceBuilder::new(DigestAlgorithm::Sha256)
        .uri("")
        .transform(Transform::Enveloped)
        .transform(Transform::Xslt(terminate));
    let error =
        transform_error(sign(ITEMS, &builder(reference)).expect_err("terminating message aborts"));
    assert!(matches!(error, TransformError::Xslt(_)), "{error:?}");

    let signed = sign(
        ITEMS,
        &builder(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("")
                .transform(Transform::Enveloped)
                .transform(Transform::Xslt(values())),
        ),
    )
    .expect("valid stylesheet signs");
    let broken = signed.replacen("<xsl:sort select=\".\"/>", "<xsl:sort select=\"(\"/>", 1);
    assert_ne!(broken, signed);
    let resolver = DefaultKeyResolver::default();
    let error = cryptographic::context()
        .key_resolver(&resolver)
        .verify(&broken)
        .expect_err("invalid XPath in the stylesheet");
    assert!(
        matches!(
            error,
            DsigError::Reference(ReferenceProcessingError::Transform(TransformError::Xslt(_)))
        ),
        "{error:?}"
    );
}
