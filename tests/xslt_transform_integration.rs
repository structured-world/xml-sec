//! XMLDSig XSLT transform through the public signing and verification API.

use std::fs;

#[path = "support/cryptographic.rs"]
mod cryptographic;

use base64::Engine as _;
use xml_sec::XmlDomParseError;
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::document::XmlDocumentError;
use xml_sec::policy::{
    PolicyViolation, SigningPolicy, VerificationPolicy, XsltPrefixListSemantics,
};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, DsigError, DsigStatus, ReferenceBuilder,
    ReferenceProcessingError, RsaSigningKey, SignContext, SignatureAlgorithm, SignatureBuilder,
    SigningDigestError, SigningError, Transform, TransformError, X509CertificateKeyInfoWriter,
    XPathExpression, XSLT_TRANSFORM_URI, XsltStylesheet,
};

const XSL: &str = "http://www.w3.org/1999/XSL/Transform";

fn stylesheet(body: &str) -> XsltStylesheet {
    XsltStylesheet::new(format!(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="{XSL}">{body}</xsl:stylesheet>"#
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

/// Verify `signed` and return the pre-digest bytes of every SignedInfo reference.
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
fn work_limit_refuses_the_execution() {
    // Template applications, XPath steps and result nodes all count against the work limit.
    let reference = ReferenceBuilder::new(DigestAlgorithm::Sha256)
        .uri("")
        .transform(Transform::Enveloped)
        .transform(Transform::Xslt(values()));
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
    signing.transforms.xslt_prefix_list_semantics = XsltPrefixListSemantics::Libxslt;
    let signed = sign_with_policy(ITEMS, &builder, signing).expect("libxslt handling signs");
    let verify = |semantics| {
        let mut policy = VerificationPolicy::default();
        policy.key_trust.mode = xml_sec::policy::VerificationTrustMode::CryptographicOnly;
        policy.transforms.xslt_prefix_list_semantics = semantics;
        let resolver = DefaultKeyResolver::default();
        xml_sec::xmldsig::VerifyContext::new()
            .policy(policy)
            .key_resolver(&resolver)
            .store_pre_digest(true)
            .verify(&signed)
    };
    let result = verify(XsltPrefixListSemantics::Libxslt).expect("libxslt handling verifies");
    assert_eq!(result.status, DsigStatus::Valid);
    assert_eq!(
        result.signed_info_references[0].pre_digest_data.as_deref(),
        Some(b"<?xml version=\"1.0\"?>\n<r/>\n".as_slice())
    );
    let error = verify(XsltPrefixListSemantics::Specification)
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
