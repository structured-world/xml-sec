use super::*;
use crate::policy::PolicyViolation;
use std::fmt::Write as _;

struct RejectingSigningKey;

impl SigningKey for RejectingSigningKey {
    fn sign(
        &self,
        _algorithm: SignatureAlgorithm,
        _canonical_signed_info: &[u8],
    ) -> Result<Vec<u8>, SigningKeyError> {
        Err(SigningKeyError::SigningFailed)
    }

    fn public_key_info(&self) -> Result<SigningPublicKeyInfo, SigningKeyError> {
        Err(SigningKeyError::PublicKeyEncodingFailed)
    }
}

struct FixedRsaSigningKey;

struct WrongWidthDsaSigningKey;

impl SigningKey for WrongWidthDsaSigningKey {
    fn sign(
        &self,
        _algorithm: SignatureAlgorithm,
        _canonical_signed_info: &[u8],
    ) -> Result<Vec<u8>, SigningKeyError> {
        unreachable!("preflight must reject this candidate")
    }

    fn public_key_info(&self) -> Result<SigningPublicKeyInfo, SigningKeyError> {
        Ok(SigningPublicKeyInfo::Dsa {
            spki_der: Vec::new(),
            p: Vec::new(),
            q: Vec::new(),
            g: Vec::new(),
            y: Vec::new(),
            modulus_bits: 2048,
            component_len: 20,
        })
    }
}

#[test]
fn dsa_q_width_mismatch_is_candidate_incompatibility() {
    // Lax search may skip an incompatible key but must not skip policy failures.
    let error = validate_signing_key(
        &WrongWidthDsaSigningKey,
        SignatureAlgorithm::DsaSha256,
        &crate::policy::SigningPolicy::default(),
    )
    .expect_err("SHA-256 requires a 256-bit q");
    assert!(matches!(
        error,
        SigningError::Key(SigningKeyError::UnsupportedAlgorithm { .. })
    ));
}

impl SigningKey for FixedRsaSigningKey {
    fn sign(
        &self,
        _algorithm: SignatureAlgorithm,
        _canonical_signed_info: &[u8],
    ) -> Result<Vec<u8>, SigningKeyError> {
        Ok(vec![0x5a; 256])
    }

    fn public_key_info(&self) -> Result<SigningPublicKeyInfo, SigningKeyError> {
        Ok(SigningPublicKeyInfo::Rsa {
            spki_der: Vec::new(),
            modulus: vec![0x80; 256],
            exponent: vec![1, 0, 1],
        })
    }
}

#[test]
fn namespace_exhaustion_preserves_typed_signing_errors() {
    // Template and builder conversions share the same typed namespace-budget refusal.
    let make_error = || {
        XmlDocumentError::Parse(crate::xml::dom::ParseError::NamespaceBindingLimitReached {
            maximum: 2,
            actual: 3,
        })
    };
    assert!(matches!(
        owned_document_policy_violation(make_error()),
        Ok(PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::XML_NAMESPACE_BINDINGS,
            maximum: 2,
            actual: 3,
        })
    ));
    let mut policy = crate::policy::SigningPolicy::default();
    policy.resources.max_xml_namespace_bindings = 0;
    let context = SignContext::new(&RejectingSigningKey).policy(policy);
    let builder = SignatureBuilder::new(
        crate::c14n::C14nAlgorithm::new(crate::c14n::C14nMode::Exclusive1_0, false),
        SignatureAlgorithm::RsaSha256,
    );
    let xml = "<root xmlns:p='urn:p'/>";
    for result in [
        context.sign_template(xml),
        context.sign_with_builder(xml, &builder),
    ] {
        assert!(
            matches!(
                result,
                Err(SigningError::Policy(PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_NAMESPACE_BINDINGS,
                    maximum: 0,
                    actual: 1,
                }))
            ),
            "unexpected signing result: {result:?}"
        );
    }
}

#[test]
fn signing_error_promotes_every_policy_failure() {
    // All policy refusals use one public pipeline variant regardless of
    // which internal signing stage first enforces the immutable snapshot.
    let digest = SigningError::from(SigningDigestError::Policy(PolicyViolation::Algorithm {
        operation: "signing",
        algorithm: "urn:test:digest".into(),
    }));
    assert!(matches!(digest, SigningError::Policy(_)));

    let mutation = SigningError::from(SigningDigestError::XmlMutation(XmlMutationError::Policy(
        PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::XML_DOCUMENT,
            maximum: 1,
            actual: 2,
        },
    )));
    assert!(matches!(mutation, SigningError::Policy(_)));
}

#[test]
fn manifest_reparse_consumes_the_signature_wide_xpath_budget() {
    // Signing reparses Manifest references after each dependency level.
    // Repeated parser/compiler work must consume the original signature
    // budget rather than receiving a fresh allowance for every level.
    let filter = r#"<xf:XPath xmlns:xf="http://www.w3.org/2002/06/xmldsig-filter2" Filter="intersect">true()</xf:XPath>"#;
    let signed_info_transforms = format!(
        r#"<ds:Transform Algorithm="http://www.w3.org/2002/06/xmldsig-filter2">{}</ds:Transform><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>true()</ds:XPath></ds:Transform><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>true()</ds:XPath></ds:Transform>"#,
        filter.repeat(64)
    );
    let mut signed_info_references = String::new();
    for index in 0..62 {
        let extra = if index == 0 {
            r#"<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>true()</ds:XPath></ds:Transform>"#
        } else {
            ""
        };
        write!(
            signed_info_references,
            r##"<ds:Reference URI="#payload"><ds:Transforms>{signed_info_transforms}{extra}</ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference>"##
        ).expect("writing into String is infallible");
    }
    let manifest_reference = |id: &str| {
        format!(
            r##"<ds:Reference URI="#{id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>true()</ds:XPath></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference>"##
        )
    };
    let xml = format!(
        r#"<root><payload Id="payload"/><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>{signed_info_references}</ds:SignedInfo><ds:SignatureValue/><ds:Object><ds:Manifest>{}{}</ds:Manifest></ds:Object></ds:Signature></root>"#,
        manifest_reference("payload"),
        manifest_reference("payload")
    );
    let policy = crate::policy::SigningPolicy {
        manifest_processing: crate::policy::ManifestProcessing::Process,
        ..crate::policy::SigningPolicy::default()
    };

    let mut document = XmlDocument::parse(xml).expect("fixture must parse");
    let error = fill_reference_digest_values_in_dependency_order(
        &mut document,
        TransformOptions::default(),
        &policy,
        crate::provider::default_provider(),
        &mut SigningOperationBudgets::default(),
        0,
        &[],
    )
    .expect_err("Manifest reparse must not reset the XPath parse budget");

    assert!(
        matches!(
            &error,
            SigningDigestError::Transform(TransformError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: "XPath expressions",
                    ..
                }
            ))
        ),
        "expected the shared XPath budget error, got: {error:?}"
    );
}

#[test]
fn dependency_levels_share_the_xml_parse_work_budget() {
    // Nested Manifest dependencies require successive digest generations.
    // Analysis mutations and every level's validation/commit parses must
    // consume one monotonic budget instead of resetting in recursive work.
    let xml = r##"<root><payload Id="payload">nested payload</payload><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#outer"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:Object><ds:Manifest Id="outer"><ds:Reference URI="#inner"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:Manifest><ds:Manifest Id="inner"><ds:Reference URI="#payload"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:Manifest></ds:Object></ds:Signature></root>"##;
    let policy = crate::policy::SigningPolicy {
        manifest_processing: crate::policy::ManifestProcessing::Process,
        ..crate::policy::SigningPolicy::default()
    };
    let mut document = XmlDocument::parse(xml).expect("fixture must parse");
    let mut budgets = SigningOperationBudgets::from_resources(&policy.resources);

    fill_reference_digest_values_in_dependency_order(
        &mut document,
        TransformOptions::default(),
        &policy,
        crate::provider::default_provider(),
        &mut budgets,
        0,
        &[],
    )
    .expect("the default cumulative budget must cover nested dependencies");
    let consumed = budgets.transforms.xml_parse_work().consumed();
    assert!(
        consumed > xml.len().saturating_mul(6),
        "analysis and dependency reparses must all be charged"
    );

    let mut constrained_policy = policy;
    constrained_policy.resources.max_xml_parse_work_bytes = consumed - 1;
    let mut constrained_document = XmlDocument::parse(xml).expect("fixture must parse");
    let mut constrained_budgets =
        SigningOperationBudgets::from_resources(&constrained_policy.resources);
    let error = fill_reference_digest_values_in_dependency_order(
        &mut constrained_document,
        TransformOptions::default(),
        &constrained_policy,
        crate::provider::default_provider(),
        &mut constrained_budgets,
        0,
        &[],
    )
    .expect_err("one byte below measured work must fail closed");

    assert!(matches!(
        error,
        SigningDigestError::Policy(PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::XML_PARSE_WORK_BYTES,
            maximum,
            actual,
        }) if maximum == consumed - 1 && actual >= consumed
    ));
}

#[test]
fn final_signed_info_parse_consumes_the_signing_xpath_budget() {
    // One XPath Reference is parsed while discovering references and while
    // analyzing dependencies; its single dependency level reuses the
    // discovered references. The final SignedInfo parse must consume the
    // same operation-wide budget.
    let xml = r##"<root><payload Id="payload">content</payload><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#payload"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>true()</ds:XPath></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature></root>"##;
    let mut policy = crate::policy::SigningPolicy::default();
    policy.resources.max_xpath_expressions = 2;

    let error = SignContext::new(&RejectingSigningKey)
        .policy(policy)
        .sign_template(xml)
        .expect_err("the final SignedInfo parse must not reset the XPath budget");

    assert!(
        matches!(
            error,
            SigningError::Policy(PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XPATH_EXPRESSIONS,
                maximum: 2,
                ..
            })
        ),
        "expected the shared XPath parse budget error, got: {error:?}"
    );
}

#[test]
fn signing_initial_parse_consumes_the_operation_xml_parse_budget() {
    // The input parse and every later retained-document reparse belong to
    // one monotonic operation allowance; helpers must not create a fresh
    // budget before digest or mutation work begins.
    let xml = r##"<root><payload Id="payload"/><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#payload"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature></root>"##;
    let mut policy = crate::policy::SigningPolicy::default();
    policy.resources.max_xml_parse_work_bytes = 0;

    let error = SignContext::new(&RejectingSigningKey)
        .policy(policy)
        .sign_template(xml)
        .expect_err("a zero parse-work budget must reject the initial parse");

    assert!(matches!(
        error,
        SigningError::Policy(PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::XML_PARSE_WORK_BYTES,
            maximum: 0,
            actual,
        }) if actual == xml.len()
    ));
}

#[test]
fn signing_string_entry_point_enforces_policy_depth() {
    // Operation parsing must use the compiled policy depth rather than the
    // process-wide hard ceiling, before template discovery or key use.
    let mut policy = crate::policy::SigningPolicy::default();
    policy.resources.max_xml_depth = 2;
    let xml = "<root><child><leaf/></child></root>";

    assert!(matches!(
        SignContext::new(&RejectingSigningKey)
            .policy(policy)
            .sign_template(xml),
        Err(SigningError::Policy(PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::XML_DEPTH,
            maximum: 2,
            actual: 3,
        }))
    ));
}

#[test]
fn builder_append_reports_policy_depth() {
    // The generated template fits as a standalone tree, but its methods
    // cross the same depth policy after the Signature is appended.
    let mut policy = crate::policy::SigningPolicy::default();
    policy.resources.max_xml_depth = 4;
    let builder = SignatureBuilder::new(
        crate::c14n::C14nAlgorithm::new(crate::c14n::C14nMode::Exclusive1_0, false),
        SignatureAlgorithm::RsaSha256,
    )
    .add_reference(crate::xmldsig::ReferenceBuilder::new(DigestAlgorithm::Sha256).uri(""));

    let result = SignContext::new(&FixedRsaSigningKey)
        .policy(policy)
        .sign_with_builder("<root/>", &builder);
    assert!(
        matches!(
            result,
            Err(SigningError::Policy(PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_DEPTH,
                maximum: 4,
                actual: 5,
            }))
        ),
        "unexpected builder depth result: {result:?}"
    );
}

#[test]
fn owned_signing_staged_copies_preserve_policy_errors() {
    // Both retained-document entry points must expose operation policy
    // exhaustion directly and leave the caller's generation untouched.
    let mut policy = crate::policy::SigningPolicy::default();
    policy.resources.max_xml_parse_work_bytes = 0;
    let context = SignContext::new(&RejectingSigningKey).policy(policy);

    let mut template_document = XmlDocument::parse("<root/>").expect("fixture must parse");
    let template_before = template_document.as_xml().to_owned();
    let error = context
        .sign_document(&mut template_document)
        .expect_err("the staged template copy must exhaust the operation budget");
    assert!(matches!(
        error,
        SigningError::Policy(PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::XML_PARSE_WORK_BYTES,
            maximum: 0,
            actual,
        }) if actual == template_before.len()
    ));
    assert_eq!(template_document.as_xml(), template_before);
    assert_eq!(template_document.generation(), 0);

    let mut builder_document = XmlDocument::parse("<root/>").expect("fixture must parse");
    let builder_before = builder_document.as_xml().to_owned();
    let builder = SignatureBuilder::new(
        crate::c14n::C14nAlgorithm::new(crate::c14n::C14nMode::Exclusive1_0, false),
        SignatureAlgorithm::RsaSha256,
    );
    let error = context
        .sign_document_with_builder(&mut builder_document, &builder)
        .expect_err("the staged builder copy must exhaust the operation budget");
    assert!(matches!(
        error,
        SigningError::Policy(PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::XML_PARSE_WORK_BYTES,
            maximum: 0,
            actual,
        }) if actual == builder_before.len()
    ));
    assert_eq!(builder_document.as_xml(), builder_before);
    assert_eq!(builder_document.generation(), 0);
}

#[test]
fn owned_signing_commits_the_validated_stage_without_reparsing() {
    // Atomic commit must adopt the already validated staged cell. Charging
    // another complete backend parse makes valid maximum-size inputs exceed
    // the operation ceiling only because they use the owned entry point.
    let xml = r##"<root><payload Id="payload">content</payload><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#payload"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature></root>"##;
    let policy = crate::policy::SigningPolicy::default();
    let context = SignContext::new(&FixedRsaSigningKey).policy(policy.clone());
    let source = XmlDocument::parse(xml).expect("fixture must parse");
    let mut measured = SigningOperationBudgets::from_resources(&policy.resources);
    let mut staged = source
        .staged_copy_with_budget(
            DocumentParseSettings::from_policy(policy.xml, &policy.resources),
            measured.transforms.xml_parse_work(),
        )
        .expect("staging must parse");
    context
        .sign_document_in_place::<CommitDocument>(&mut staged, &mut measured)
        .expect("staged signing must succeed");
    let exact_stage_work = measured.transforms.xml_parse_work().consumed();

    let mut constrained_policy = policy;
    constrained_policy.resources.max_xml_parse_work_bytes = exact_stage_work;
    let mut document = XmlDocument::parse(xml).expect("fixture must parse");
    SignContext::new(&FixedRsaSigningKey)
        .policy(constrained_policy)
        .sign_document(&mut document)
        .expect("commit must not parse the validated stage again");

    assert_eq!(document.generation(), 1);
    assert!(!document.as_xml().contains("<ds:DigestValue/>"));
    assert!(!document.as_xml().contains("<ds:SignatureValue/>"));
}

#[test]
fn builder_signing_fits_the_document_to_parse_work_ratio() {
    // A builder operation at the configured document ceiling must fit the
    // implementation's hard allowance. Generated base64 text and the
    // appended generated template need one committed candidate parse each,
    // not an untrusted-fragment validation parse plus commit. Differential
    // builds meter their comparison backend without reducing this envelope.
    let padding = "x".repeat(64 * 1024);
    let xml = format!("<root><payload Id=\"payload\"/><padding>{padding}</padding></root>");
    let builder = SignatureBuilder::new(
        crate::c14n::C14nAlgorithm::new(crate::c14n::C14nMode::Exclusive1_0, false),
        SignatureAlgorithm::RsaSha256,
    )
    .add_reference(crate::xmldsig::ReferenceBuilder::new(DigestAlgorithm::Sha256).uri("#payload"));
    let maximum_document_bytes = xml.len() + 4 * 1024;
    let mut policy = crate::policy::SigningPolicy::default();
    policy.resources.max_xml_document_bytes = maximum_document_bytes;
    policy.resources.max_xml_parse_work_bytes =
        maximum_document_bytes * crate::hard_limits::XML_PARSE_WORK_PASS_CEILING;

    let mut measurement_policy = policy.clone();
    measurement_policy.resources.max_xml_parse_work_bytes =
        crate::hard_limits::XML_PARSE_WORK_BYTE_CEILING;
    let measurement_context =
        SignContext::new(&FixedRsaSigningKey).policy(measurement_policy.clone());
    let mut measurement_budgets =
        SigningOperationBudgets::from_resources(&measurement_policy.resources);
    let mut measurement_document = XmlDocument::parse_with_settings_and_budget(
        xml.clone(),
        DocumentParseSettings::from_policy(measurement_policy.xml, &measurement_policy.resources),
        measurement_budgets.transforms.xml_parse_work(),
    )
    .expect("measurement input must parse");
    measurement_context
        .sign_document_with_builder_in_place::<CommitDocument>(
            &mut measurement_document,
            &builder,
            &mut measurement_budgets,
        )
        .expect("measurement signing must succeed");
    let consumed = measurement_budgets.transforms.xml_parse_work().consumed();
    assert!(
        consumed <= maximum_document_bytes * crate::hard_limits::XML_PARSE_WORK_PASS_CEILING,
        "builder signing consumed {consumed} bytes for a {maximum_document_bytes}-byte ceiling"
    );

    let signed = SignContext::new(&FixedRsaSigningKey)
        .policy(policy.clone())
        .sign_with_builder(&xml, &builder)
        .expect("string builder signing must fit the advertised parse-work ratio");
    assert!(signed.contains("DigestValue>"));
    assert!(signed.contains("SignatureValue>"));

    let mut owned = XmlDocument::parse(&xml).expect("fixture must parse");
    SignContext::new(&FixedRsaSigningKey)
        .policy(policy)
        .sign_document_with_builder(&mut owned, &builder)
        .expect("owned builder signing must fit the advertised parse-work ratio");
    assert!(owned.as_xml().contains("DigestValue>"));
    assert!(owned.as_xml().contains("SignatureValue>"));
}

#[test]
fn dtd_capable_staged_copy_charges_both_parser_passes() {
    // DTD-capable documents run a provenance parse before the retained
    // document parse. Both passes belong to the signing operation budget.
    let xml = "<root/>";
    let mut parsing_policy = crate::policy::SigningPolicy::default();
    parsing_policy.xml.allow_internal_dtd = true;
    let document = XmlDocument::parse_with_policy(xml, &parsing_policy)
        .expect("the fixture must retain DTD-capable parse settings");

    parsing_policy.resources.max_xml_parse_work_bytes = xml.len();
    let budget = XmlParseWorkBudget::from_resources(&parsing_policy.resources);
    assert!(matches!(
        document.staged_copy_with_budget(DocumentParseSettings::default(), &budget),
        Err(XmlDocumentError::Policy(PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::XML_PARSE_WORK_BYTES,
            maximum,
            actual,
        })) if maximum == xml.len() && actual == xml.len() * 2
    ));
}

#[test]
fn owned_signing_mappers_preserve_document_size_policy_errors() {
    // Template and digest mutations share one resource-error contract even
    // though their surrounding signing error types differ.
    let maximum = 8;
    let actual = 9;
    assert!(matches!(
        map_owned_document_mutation_error(XmlDocumentError::DocumentTooLarge { maximum, actual }),
        SigningError::Policy(PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::XML_DOCUMENT,
            maximum: 8,
            actual: 9,
        })
    ));
    assert!(matches!(
        map_owned_document_digest_mutation_error(XmlDocumentError::DocumentTooLarge {
            maximum,
            actual,
        }),
        SigningDigestError::Policy(PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::XML_DOCUMENT,
            maximum: 8,
            actual: 9,
        })
    ));
}

#[test]
fn signing_rejects_xpath_control_dependencies_on_digest_values() {
    // The second Reference excludes DigestValue nodes from its output but
    // reads the first DigestValue to decide whether payload remains. Filling
    // both references in one level would therefore invalidate the result.
    let xml = r##"<root><payload Id="payload">content</payload><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#payload"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>not(ancestor-or-self::ds:DigestValue) and (not(self::payload) or string(//ds:Reference[1]/ds:DigestValue) = '')</ds:XPath></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature></root>"##;

    let mut document = XmlDocument::parse(xml).expect("fixture must parse");
    let error = fill_reference_digest_values_in_dependency_order(
        &mut document,
        TransformOptions::default(),
        &crate::policy::SigningPolicy::default(),
        crate::provider::default_provider(),
        &mut SigningOperationBudgets::default(),
        0,
        &[],
    )
    .expect_err("mutable XPath control dependencies must fail closed");

    assert!(
        matches!(
            &error,
            SigningDigestError::InvalidStructure(message)
                if message.contains("dependency cycle")
        ),
        "expected a dependency-cycle rejection, got: {error:?}"
    );
}

#[test]
fn signing_allows_payload_local_xpath_value_predicates() {
    // Attribute comparisons read payload metadata, not mutable values in a
    // disjoint Signature subtree. They must not manufacture a self-cycle.
    let xml = r##"<root><payload Id="payload" kind="include">content</payload><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#payload"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>@kind = 'include'</ds:XPath></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature></root>"##;

    let mut document = XmlDocument::parse(xml).expect("fixture must parse");
    fill_reference_digest_values_in_dependency_order(
        &mut document,
        TransformOptions::default(),
        &crate::policy::SigningPolicy::default(),
        crate::provider::default_provider(),
        &mut SigningOperationBudgets::default(),
        0,
        &[],
    )
    .expect("payload-local XPath predicates must not depend on Signature values");

    assert_ne!(document.as_xml(), xml);
}

#[test]
fn signing_rejects_references_that_retain_signature_value() {
    // SignatureValue is filled after every Reference digest. A Reference
    // retaining that node is therefore an unavoidable signing cycle even
    // when all DigestValue nodes are excluded from the resulting node-set.
    let xml = r#"<root><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>not(ancestor-or-self::ds:DigestValue)</ds:XPath></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature></root>"#;

    let mut document = XmlDocument::parse(xml).expect("fixture must parse");
    let error = fill_reference_digest_values_in_dependency_order(
        &mut document,
        TransformOptions::default(),
        &crate::policy::SigningPolicy::default(),
        crate::provider::default_provider(),
        &mut SigningOperationBudgets::default(),
        0,
        &[],
    )
    .expect_err("a mutable SignatureValue dependency must fail before signing");

    assert!(
        matches!(
            &error,
            SigningDigestError::InvalidStructure(message)
                if message.contains("SignatureValue") && message.contains("cycle")
        ),
        "expected a SignatureValue dependency-cycle rejection, got: {error:?}"
    );
}

#[test]
fn second_edition_c14n_materialization_handles_both_reference_shapes() {
    // Templates may omit <Transforms> entirely or serialize an empty
    // prefixed element. Both forms must become one valid explicit chain.
    let xml = r##"<root><payload Id="payload"/><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#payload"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference><ds:Reference URI="#payload"><ds:Transforms/><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature></root>"##;
    let document = XmlDocument::parse(xml).expect("fixture must parse");
    let candidate = materialize_second_edition_c14n11_candidate(
        &document,
        0,
        &crate::policy::SigningPolicy::default(),
        false,
    )
    .expect("materialization planning must succeed")
    .expect("both node-set chains require explicit canonicalization");

    assert_eq!(
        candidate
            .matches(SECOND_EDITION_GENERATION_C14N_URI)
            .count(),
        3
    );
    assert!(candidate.contains("<ds:Transforms><ds:Transform"));
    XmlDocument::parse(candidate).expect("materialized candidate must remain well-formed");
}

#[test]
fn second_edition_c14n_materialization_is_idempotent_for_binary_chains() {
    // An explicit canonicalization already produces octets; planning must
    // avoid both duplicate transforms and a no-op document generation.
    let xml = r##"<root><payload Id="payload"/><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#payload"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature></root>"##;
    let document = XmlDocument::parse(xml).expect("fixture must parse");
    let candidate = materialize_second_edition_c14n11_candidate(
        &document,
        0,
        &crate::policy::SigningPolicy::default(),
        false,
    )
    .expect("materialization planning must succeed");

    assert!(candidate.is_none());
}
