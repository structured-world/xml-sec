use super::*;

fn document_root_identity(view: DocumentView<'_>) -> NodeIdentity {
    view.root_element()
}
use crate::c14n::C14nAlgorithm;
use crate::xml::dom::Document;
use crate::xmldsig::TransformError;
use crate::xmldsig::digest::DigestAlgorithm;
use crate::xmldsig::parse::{Reference, parse_signed_info};
use crate::xmldsig::transforms::Transform;
use crate::xmldsig::uri::UriReferenceResolver;
use base64::Engine;

// ── Helpers ──────────────────────────────────────────────────────

/// Build a Reference with given URI, transforms, digest method, and expected digest.
fn make_reference(
    uri: &str,
    transforms: Vec<Transform>,
    digest_method: DigestAlgorithm,
    digest_value: Vec<u8>,
) -> Reference {
    Reference {
        uri: Some(uri.to_string()),
        id: None,
        ref_type: None,
        transforms,
        digest_method,
        digest_value,
    }
}

#[test]
fn operation_borrows_caller_utc_facts_without_policy_rebinding()
-> Result<(), Box<dyn std::error::Error>> {
    // Synthetic caller facts test transport, not real-world UTC history.
    // Operation capture shares the original slice and never infers facts
    // from a different policy or creates a replacement timeline.
    let transitions = [structured_pkix::temporal::Transition::new(2_678_400, 1)];
    let facts = structured_pkix::temporal::LeapTable::new(0, 6_000_000, &transitions)
        .expect("valid synthetic UTC facts");
    let ctx = VerifyContext::new().utc_facts(facts);
    let budgets = VerificationOperationBudgets::with_transforms(
        &ctx.policy,
        TransformExecutionBudget::from_resources(&ctx.policy.resources),
        ctx.utc_facts,
    );
    let mut budget = budgets.key_candidates.borrow_mut();
    assert_eq!(
        budget
            .utc_facts()
            .ok_or("operation UTC facts")?
            .transitions()
            .as_ptr(),
        transitions.as_ptr()
    );
    budget.bind_policy(&ctx.policy)?;
    assert_eq!(
        budget
            .utc_facts()
            .ok_or("retained UTC facts")?
            .transitions()
            .as_ptr(),
        transitions.as_ptr()
    );
    let standalone =
        super::super::InspectedKeyCandidateBudget::new_with_utc_facts(&ctx.policy, facts);
    assert_eq!(
        standalone
            .utc_facts()
            .ok_or("standalone UTC facts")?
            .transitions()
            .as_ptr(),
        transitions.as_ptr()
    );
    assert!(
        super::super::InspectedKeyCandidateBudget::new(&ctx.policy)
            .utc_facts()
            .is_none()
    );
    Ok(())
}

#[test]
fn reference_resolution_uses_each_elements_effective_xml_base() {
    // Equal lexical URIs under different xml:base values identify distinct
    // caller-owned resources and must not collide in the resolver.
    let first = b"first payload";
    let second = b"second payload";
    let first_digest = base64::engine::general_purpose::STANDARD
        .encode(compute_digest(DigestAlgorithm::Sha256, first));
    let second_digest = base64::engine::general_purpose::STANDARD
        .encode(compute_digest(DigestAlgorithm::Sha256, second));
    let xml = format!(
        r#"<root xml:base="https://example.test/base/" xmlns:ds="{XMLDSIG_NS}">
                <ds:Signature><ds:SignedInfo>
                    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                    <ds:Reference xml:base="one/" URI="payload.bin">
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>{first_digest}</ds:DigestValue>
                    </ds:Reference>
                    <ds:Reference xml:base="../two/" URI="payload.bin">
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>{second_digest}</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo><ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature>
            </root>"#
    );
    let document = Document::parse(&xml).unwrap();
    let signature = document
        .descendants()
        .find(|node| node.has_tag_name((XMLDSIG_NS, "Signature")))
        .unwrap();
    let signed_info_node = signature
        .children()
        .find(|node| node.has_tag_name((XMLDSIG_NS, "SignedInfo")))
        .unwrap();
    let signed_info = parse_signed_info(signed_info_node).unwrap();
    let resources = HashMap::from([
        (
            "https://example.test/base/one/payload.bin".into(),
            first.to_vec(),
        ),
        (
            "https://example.test/two/payload.bin".into(),
            second.to_vec(),
        ),
    ]);
    let resolver = UriReferenceResolver::new(&document).with_external_resources(&resources);

    let result = process_all_references(&signed_info.references, &resolver, signature, false)
        .expect("each Reference should resolve against its own effective base");

    assert!(result.all_valid());
}

#[test]
fn internal_dtd_opt_in_applies_to_detached_xml_transforms() {
    // The parse policy covers every XML document in one verification
    // pipeline, including caller-owned octets converted to a node-set.
    let detached = b"<!DOCTYPE payload [<!ELEMENT payload (#PCDATA)>]><payload>ok</payload>";
    let digest = base64::engine::general_purpose::STANDARD.encode(compute_digest(
        DigestAlgorithm::Sha256,
        b"<payload>ok</payload>",
    ));
    let xml = format!(
        r#"<root xmlns:ds="{XMLDSIG_NS}">
  <ds:Signature>
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="urn:detached-dtd">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>{digest}</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>AQ==</ds:SignatureValue>
  </ds:Signature>
</root>"#
    );
    let resources = HashMap::from([("urn:detached-dtd".to_owned(), detached.to_vec())]);
    let key = AcceptingKey;

    // A refused detached parse is this Reference's own processing failure.
    let refused = DsigStatus::Invalid(FailureReason::ReferenceProcessingFailure { ref_index: 0 });
    let default_result = VerifyContext::new()
        .key(&key)
        .allowed_uri_types(UriTypeSet::ALL)
        .external_resources(&resources)
        .verify(&xml)
        .expect("a refused detached parse is a verification status");
    assert_eq!(default_result.status, refused);

    let result = VerifyContext::new()
        .key(&key)
        .allowed_uri_types(UriTypeSet::ALL)
        .external_resources(&resources)
        .allow_internal_dtd(true)
        .verify(&xml)
        .expect("the explicit DTD opt-in must cover detached XML transforms");

    assert_eq!(result.status, DsigStatus::Valid);

    let external_entity = br#"<!DOCTYPE payload [
            <!ENTITY ext SYSTEM "file:///etc/passwd">
        ]><payload>&ext;</payload>"#;
    let external_entity_resources =
        HashMap::from([("urn:detached-dtd".to_owned(), external_entity.to_vec())]);
    let external_entity_result = VerifyContext::new()
        .key(&key)
        .allowed_uri_types(UriTypeSet::ALL)
        .external_resources(&external_entity_resources)
        .allow_internal_dtd(true)
        .verify(&xml)
        .expect("the internal-DTD opt-in must not resolve external entities");
    assert_eq!(external_entity_result.status, refused);
}

#[test]
fn owned_verification_revalidates_internal_dtd_provenance() {
    // A document accepted by one permissive operation must not bypass a
    // later verification context's stricter XML input policy.
    let document = XmlDocument::parse_with_settings(
        "<!DOCTYPE root [<!ENTITY value \"ok\">]><root>&value;</root>".into(),
        DocumentParseSettings::new(
            true,
            crate::hard_limits::XML_DOCUMENT_NODE_CEILING,
            crate::hard_limits::XML_DOCUMENT_BYTE_CEILING,
        ),
    )
    .expect("explicitly permitted DTD fixture must parse");

    assert!(matches!(
        VerifyContext::new().verify_document(&document),
        Err(DsigError::Policy(
            crate::policy::PolicyViolation::XmlInput {
                reason: "owned document requires internal DTD support"
            }
        ))
    ));
    assert!(!matches!(
        VerifyContext::new()
            .allow_internal_dtd(true)
            .verify_document(&document),
        Err(DsigError::Policy(
            crate::policy::PolicyViolation::XmlInput { .. }
        ))
    ));
}

#[test]
fn verification_policy_bounds_reference_canonicalization() {
    // Reference transforms and SignedInfo canonicalization are one operation;
    // references must not fall back to the transform hard-limit budget.
    let digest = base64::engine::general_purpose::STANDARD.encode([0_u8; 32]);
    let xml = format!(
        r#"<root xmlns:ds="{XMLDSIG_NS}"><payload>{}</payload><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AQ==</ds:SignatureValue></ds:Signature></root>"#,
        "payload".repeat(16)
    );
    let policy = crate::policy::VerificationPolicy {
        resources: crate::policy::ResourcePolicy {
            max_canonicalized_bytes: 64,
            ..crate::policy::ResourcePolicy::default()
        },
        ..crate::policy::VerificationPolicy::default()
    };

    let error = VerifyContext::new()
        .key(&AcceptingKey)
        .policy(policy)
        .verify(&xml)
        .expect_err("reference canonicalization must consume the policy budget");

    assert!(
        matches!(
            error,
            SignatureVerificationPipelineError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::CANONICALIZED_BYTES,
                    maximum: 64,
                    ..
                }
            )
        ),
        "unexpected error: {error:?}"
    );
}

#[test]
fn verification_policy_bounds_document_bytes_before_parsing() {
    // A small node count does not bound parser work when one text node is
    // large, so the byte ceiling must reject before structural inspection.
    let xml = format!("<root>{}</root>", "x".repeat(1_024));
    let policy = crate::policy::VerificationPolicy {
        resources: crate::policy::ResourcePolicy {
            max_xml_document_bytes: xml.len() - 1,
            ..crate::policy::ResourcePolicy::default()
        },
        ..crate::policy::VerificationPolicy::default()
    };

    assert!(matches!(
        VerifyContext::new().policy(policy).verify(&xml),
        Err(SignatureVerificationPipelineError::Policy(
            crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_DOCUMENT,
                maximum,
                actual,
            }
        )) if maximum == xml.len() - 1 && actual == xml.len()
    ));
}

#[test]
fn verification_entry_points_enforce_policy_depth() {
    // Both borrowed XML and a retained document parsed under wider defaults
    // must be rejected before signature selection traverses the tree.
    let xml = "<root><child><leaf/></child></root>";
    let policy = crate::policy::VerificationPolicy {
        resources: crate::policy::ResourcePolicy {
            max_xml_depth: 2,
            ..crate::policy::ResourcePolicy::default()
        },
        ..crate::policy::VerificationPolicy::default()
    };
    let document = XmlDocument::parse(xml).expect("wide retained fixture must parse");

    assert!(matches!(
        VerifyContext::new().policy(policy.clone()).verify(xml),
        Err(DsigError::Policy(
            crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_DEPTH,
                maximum: 2,
                actual: 3,
            }
        ))
    ));
    assert!(matches!(
        VerifyContext::new()
            .policy(policy)
            .verify_document(&document),
        Err(DsigError::Policy(
            crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_DEPTH,
                maximum: 2,
                actual: 3,
            }
        ))
    ));
}

#[test]
fn verification_policy_bounds_base64_transform_input() {
    // The operation snapshot must reach the transform executor rather than
    // silently falling back to its implementation-wide default budget.
    let digest = base64::engine::general_purpose::STANDARD.encode([0_u8; 32]);
    let xml = format!(
        r##"<root xmlns:ds="{XMLDSIG_NS}"><payload ID="payload">QUJDRA==</payload><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#payload"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#base64"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AQ==</ds:SignatureValue></ds:Signature></root>"##
    );
    let policy = crate::policy::VerificationPolicy {
        resources: crate::policy::ResourcePolicy {
            max_base64_transform_input_bytes: 4,
            ..crate::policy::ResourcePolicy::default()
        },
        ..crate::policy::VerificationPolicy::default()
    };

    let error = VerifyContext::new()
        .key(&AcceptingKey)
        .policy(policy)
        .verify(&xml)
        .expect_err("Base64 input must use the operation policy ceiling");

    assert!(matches!(
        error,
        SignatureVerificationPipelineError::Policy(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::BASE64_TRANSFORM_INPUT_BYTES,
            maximum: 4,
            ..
        })
    ));
}

#[test]
fn verification_policy_bounds_cumulative_base64_transform_output() {
    // References share one operation budget. Validating each decoded value
    // against the full ceiling would let a signature multiply output work.
    let first_digest = base64::engine::general_purpose::STANDARD
        .encode(compute_digest(DigestAlgorithm::Sha256, b"a"));
    let second_digest = base64::engine::general_purpose::STANDARD
        .encode(compute_digest(DigestAlgorithm::Sha256, b"b"));
    let xml = format!(
        r##"<root xmlns:ds="{XMLDSIG_NS}"><first ID="first">YQ==</first><second ID="second">Yg==</second><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#first"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#base64"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{first_digest}</ds:DigestValue></ds:Reference><ds:Reference URI="#second"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#base64"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{second_digest}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AQ==</ds:SignatureValue></ds:Signature></root>"##
    );
    let policy = crate::policy::VerificationPolicy {
        resources: crate::policy::ResourcePolicy {
            max_base64_transform_input_bytes: 8,
            max_base64_transform_output_bytes: 1,
            ..crate::policy::ResourcePolicy::default()
        },
        ..crate::policy::VerificationPolicy::default()
    };

    let error = VerifyContext::new()
        .key(&AcceptingKey)
        .policy(policy)
        .verify(&xml)
        .expect_err("references must share the Base64 output allowance");

    assert!(matches!(
        error,
        SignatureVerificationPipelineError::Policy(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::BASE64_TRANSFORM_OUTPUT_BYTES,
            maximum: 1,
            actual: 2,
        })
    ));
}

#[test]
fn verification_policy_bounds_xpath_source_before_compilation() {
    // XPath parser limits are part of the same operation snapshot as the
    // evaluator limits; parsing cannot use a separate hard-coded budget.
    let digest = base64::engine::general_purpose::STANDARD.encode([0_u8; 32]);
    let xml = format!(
        r#"<root xmlns:ds="{XMLDSIG_NS}"><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>true()</ds:XPath></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AQ==</ds:SignatureValue></ds:Signature></root>"#
    );
    let policy = crate::policy::VerificationPolicy {
        resources: crate::policy::ResourcePolicy {
            max_xpath_expression_bytes: 4,
            ..crate::policy::ResourcePolicy::default()
        },
        ..crate::policy::VerificationPolicy::default()
    };

    let error = VerifyContext::new()
        .key(&AcceptingKey)
        .policy(policy)
        .verify(&xml)
        .expect_err("XPath source must use the operation policy ceiling");

    assert!(matches!(
        error,
        SignatureVerificationPipelineError::Policy(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::XPATH_EXPRESSION_BYTES,
            maximum: 4,
            ..
        })
    ));
}

#[test]
fn verification_policy_shares_canonicalization_budget_with_signed_info() {
    // Reference transforms and SignedInfo canonicalization are one operation.
    // Each output fits independently, but their aggregate must not receive
    // two separate copies of the configured canonicalization allowance.
    let payload_text = "x".repeat(700);
    let canonical_payload = format!("<payload ID=\"payload\">{payload_text}</payload>");
    let digest = base64::engine::general_purpose::STANDARD.encode(compute_digest(
        DigestAlgorithm::Sha256,
        canonical_payload.as_bytes(),
    ));
    let xml = format!(
        r##"<root xmlns:ds="{XMLDSIG_NS}">{canonical_payload}<ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#payload"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AQ==</ds:SignatureValue></ds:Signature></root>"##
    );
    let policy = crate::policy::VerificationPolicy {
        resources: crate::policy::ResourcePolicy {
            max_canonicalized_bytes: 1_024,
            ..crate::policy::ResourcePolicy::default()
        },
        ..crate::policy::VerificationPolicy::default()
    };

    let error = VerifyContext::new()
        .key(&AcceptingKey)
        .policy(policy)
        .verify(&xml)
        .expect_err("SignedInfo must consume the remaining operation C14N budget");

    assert!(
        matches!(
            &error,
            SignatureVerificationPipelineError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: "canonicalized bytes",
                    maximum: 1_024,
                    ..
                }
            )
        ),
        "unexpected error: {error:?}"
    );
}

#[test]
fn manifest_processing_stops_after_c14n_budget_exhaustion() {
    // A failed bounded render consumes the remaining operation allowance.
    // Later Manifest references, including cheap binary ones, must not run.
    let digest = base64::engine::general_purpose::STANDARD.encode([0_u8; 32]);
    let xml = format!(
        r##"<root xmlns:ds="{XMLDSIG_NS}"><payload Id="payload">too large</payload><ds:Signature><ds:Object Id="signed-object"><ds:Manifest><ds:Reference URI="#payload"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference><ds:Reference URI="urn:small"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:Manifest></ds:Object></ds:Signature></root>"##
    );
    let resources = HashMap::from([("urn:small".to_owned(), b"small".to_vec())]);
    let transform_budget = TransformExecutionBudget::with_c14n_limit(8);
    let ctx = VerifyContext::new()
        .allowed_uri_types(UriTypeSet::ALL)
        .external_resources(&resources);
    let document = XmlDocument::parse(xml).expect("test signature must parse");
    let results = document
        .with_view(|view| {
            let signature = view
                .document()
                .descendants()
                .find(|node| node.has_tag_name((XMLDSIG_NS, "Signature")))
                .expect("test signature must contain Signature");
            let object = signature
                .children()
                .find(|node| node.has_tag_name((XMLDSIG_NS, "Object")))
                .expect("test signature must contain Object");
            let resolver = UriReferenceResolver::with_document_view(view, &[])
                .with_external_resources(&resources);
            let budgets = VerificationOperationBudgets::with_transforms(
                &ctx.policy,
                transform_budget,
                ctx.utc_facts,
            );
            let mut operation = OperationExecutionContext::new(
                &ctx.policy,
                &budgets,
                Some((view.identity(), view.generation())),
            );
            let crypto =
                operation.add_node(OperationNodeKind::Crypto, OperationStage::Crypto, None);
            operation.compile().expect("base plan");
            operation
                .run(crypto, || Ok::<_, SignatureVerificationPipelineError>(()))
                .expect("crypto gate");
            operation.authenticate(view.node_identity(object));
            process_authenticated_manifest_references(
                &mut operation,
                view,
                signature,
                &resolver,
                &ManifestVerification {
                    context: &ctx,
                    capture: &(),
                },
                2,
                &[crypto],
            )
            .map(|(results, _)| results)
        })
        .expect("resource exhaustion is reported per Manifest reference");

    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|result| {
        matches!(
            result.status,
            DsigStatus::Invalid(FailureReason::ReferencePolicyViolation { .. })
        )
    }));
}

#[test]
fn verification_policy_bounds_detached_xml_nodes() {
    // Caller-owned detached octets become a second XML document during a
    // node-set transform and must inherit the same operation node ceiling.
    let detached = format!("<payload>{}</payload>", "<n/>".repeat(32));
    let digest = base64::engine::general_purpose::STANDARD.encode([0_u8; 32]);
    let xml = format!(
        r#"<root xmlns:ds="{XMLDSIG_NS}"><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="urn:detached-nodes"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>true()</ds:XPath></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AQ==</ds:SignatureValue></ds:Signature></root>"#
    );
    let resources = HashMap::from([("urn:detached-nodes".to_owned(), detached.into_bytes())]);
    let policy = crate::policy::VerificationPolicy {
        uris: crate::policy::UriPolicy {
            references: UriTypeSet::ALL,
            ..crate::policy::UriPolicy::default()
        },
        resources: crate::policy::ResourcePolicy {
            max_xml_nodes: 24,
            ..crate::policy::ResourcePolicy::default()
        },
        ..crate::policy::VerificationPolicy::default()
    };

    let error = VerifyContext::new()
        .key(&AcceptingKey)
        .policy(policy)
        .external_resources(&resources)
        .verify(&xml)
        .expect_err("detached XML must inherit the policy node ceiling");

    assert!(
        matches!(
            error,
            SignatureVerificationPipelineError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_NODES,
                    maximum: 24,
                    ..
                }
            )
        ),
        "unexpected error: {error:?}"
    );
}

#[test]
fn query_only_reference_resolves_against_relative_xml_base() {
    // A query-only URI replaces the inherited base query without changing
    // its relative path; no absolute document base is required by XML Base.
    let payload = b"query-selected payload";
    let digest = base64::engine::general_purpose::STANDARD
        .encode(compute_digest(DigestAlgorithm::Sha256, payload));
    let xml = format!(
        r#"<ds:Signature xmlns:ds="{XMLDSIG_NS}"><ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference xml:base="a/b?old" URI="?new">
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue>{digest}</ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo><ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature>"#
    );
    let document = Document::parse(&xml).unwrap();
    let signature = document.root_element();
    let signed_info_node = signature
        .children()
        .find(|node| node.has_tag_name((XMLDSIG_NS, "SignedInfo")))
        .unwrap();
    let signed_info = parse_signed_info(signed_info_node).unwrap();
    let resources = HashMap::from([("a/b?new".to_string(), payload.to_vec())]);
    let resolver = UriReferenceResolver::new(&document).with_external_resources(&resources);

    let result = process_all_references(&signed_info.references, &resolver, signature, false)
        .expect("query-only URI must resolve against the complete relative base path");

    assert!(result.all_valid());
}

#[test]
fn manifest_reference_resolution_uses_its_effective_xml_base() {
    // Manifest references carry their own XML Base context and must not
    // accidentally reuse the SignedInfo or Signature element context.
    let payload = b"manifest payload";
    let digest = base64::engine::general_purpose::STANDARD
        .encode(compute_digest(DigestAlgorithm::Sha256, payload));
    let xml = format!(
        r#"<ds:Signature xmlns:ds="{XMLDSIG_NS}" xml:base="https://example.test/">
                <ds:Object><ds:Manifest xml:base="manifests/">
                    <ds:Reference URI="payload.bin">
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>{digest}</ds:DigestValue>
                    </ds:Reference>
                </ds:Manifest></ds:Object>
            </ds:Signature>"#
    );
    let document = Document::parse(&xml).unwrap();
    let signature = document.root_element();
    let reference_node = signature
        .descendants()
        .find(|node| node.has_tag_name((XMLDSIG_NS, "Reference")))
        .unwrap();
    let reference = super::super::parse::parse_reference(reference_node).unwrap();
    let resources = HashMap::from([(
        "https://example.test/manifests/payload.bin".to_string(),
        payload.to_vec(),
    )]);
    let resolver = UriReferenceResolver::new(&document).with_external_resources(&resources);

    let result = process_reference(
        &reference,
        &resolver,
        signature,
        ReferenceSet::Manifest,
        0,
        false,
    )
    .expect("Manifest Reference should inherit its own XML Base context");

    assert_eq!(result.status, DsigStatus::Valid);
}

#[test]
fn manifest_reference_index_ignores_nested_manifest_descendants() {
    // The public Manifest index follows Signature/Object/Manifest structure;
    // wrapper descendants must not steal an index and supply another base URI.
    let payload = b"direct manifest payload";
    let digest = base64::engine::general_purpose::STANDARD
        .encode(compute_digest(DigestAlgorithm::Sha256, payload));
    let xml = format!(
        r#"<ds:Signature xmlns:ds="{XMLDSIG_NS}" xml:base="https://example.test/">
                <ds:Object><wrapper><ds:Manifest xml:base="nested/">
                    <ds:Reference URI="payload.bin">
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>{digest}</ds:DigestValue>
                    </ds:Reference>
                </ds:Manifest></wrapper></ds:Object>
                <ds:Object><ds:Manifest xml:base="direct/">
                    <ds:Reference URI="payload.bin">
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>{digest}</ds:DigestValue>
                    </ds:Reference>
                </ds:Manifest></ds:Object>
            </ds:Signature>"#
    );
    let document = Document::parse(&xml).unwrap();
    let signature = document.root_element();
    let direct_reference_node = signature
        .children()
        .filter(|node| node.has_tag_name((XMLDSIG_NS, "Object")))
        .nth(1)
        .unwrap()
        .children()
        .find(|node| node.has_tag_name((XMLDSIG_NS, "Manifest")))
        .unwrap()
        .children()
        .find(|node| node.has_tag_name((XMLDSIG_NS, "Reference")))
        .unwrap();
    let reference = super::super::parse::parse_reference(direct_reference_node).unwrap();
    let resources = HashMap::from([(
        "https://example.test/direct/payload.bin".to_string(),
        payload.to_vec(),
    )]);
    let resolver = UriReferenceResolver::new(&document).with_external_resources(&resources);

    let result = process_reference(
        &reference,
        &resolver,
        signature,
        ReferenceSet::Manifest,
        0,
        false,
    )
    .expect("Manifest index must select the direct Object/Manifest reference");

    assert_eq!(result.status, DsigStatus::Valid);
}

struct RejectingKey;

impl VerifyingKey for RejectingKey {
    fn verify(
        &self,
        _algorithm: SignatureAlgorithm,
        _signed_data: &[u8],
        _signature_value: &[u8],
    ) -> Result<bool, SignatureVerificationPipelineError> {
        Ok(false)
    }
}

struct AcceptingKey;

impl VerifyingKey for AcceptingKey {
    fn verify(
        &self,
        _algorithm: SignatureAlgorithm,
        _signed_data: &[u8],
        _signature_value: &[u8],
    ) -> Result<bool, SignatureVerificationPipelineError> {
        Ok(true)
    }
}

struct PanicResolver;

struct UntrustedTestResolver;

impl KeyResolver for UntrustedTestResolver {
    fn resolve<'a>(
        &'a self,
        _key_info: Option<&KeyInfo>,
        _algorithm: SignatureAlgorithm,
    ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, DsigError> {
        Ok(Some(Box::new(AcceptingKey)))
    }
}

#[test]
fn verification_requires_explicit_key_authorization() {
    // A resolver finding a working key must not authorize its signer.
    let xml = signature_with_target_reference("AQ==");
    let error = VerifyContext::new()
        .key_resolver(&UntrustedTestResolver)
        .verify(&xml)
        .expect_err("default verification must reject an untrusted resolver candidate");
    assert!(matches!(
        error,
        DsigError::Policy(crate::policy::PolicyViolation::KeyTrust { .. })
    ));
}

#[test]
fn cryptographic_only_is_explicit_and_never_reports_trust() {
    // Opting out of signer authorization must remain visible in the result.
    let mut policy = crate::policy::VerificationPolicy::default();
    policy.key_trust.mode = crate::policy::VerificationTrustMode::CryptographicOnly;
    let result = VerifyContext::new()
        .policy(policy)
        .key_resolver(&UntrustedTestResolver)
        .verify(&signature_with_target_reference("AQ=="))
        .expect("explicit mathematical mode permits an untrusted candidate");
    assert_eq!(result.status, DsigStatus::Valid);
    assert_eq!(
        result.key_trust,
        super::super::KeyTrustEvidence::NotEstablished
    );
}

#[test]
fn caller_key_authorization_does_not_authenticate_an_invalid_signature() {
    // A trusted key is not evidence that the signature itself verified.
    let result = VerifyContext::new()
        .key(&RejectingKey)
        .verify(&signature_with_target_reference("AQ=="))
        .expect("an invalid mathematical signature is a completed result");
    assert_eq!(
        result.status,
        DsigStatus::Invalid(FailureReason::SignatureMismatch)
    );
    assert_eq!(
        result.key_trust,
        super::super::KeyTrustEvidence::CallerTrusted
    );
}

impl KeyResolver for PanicResolver {
    fn resolve<'a>(
        &'a self,
        _key_info: Option<&KeyInfo>,
        _algorithm: SignatureAlgorithm,
    ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, SignatureVerificationPipelineError> {
        panic!("resolver must not be dispatched in this test");
    }
}

struct MissingKeyResolver;

impl KeyResolver for MissingKeyResolver {
    fn resolve<'a>(
        &'a self,
        _key_info: Option<&KeyInfo>,
        _algorithm: SignatureAlgorithm,
    ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, SignatureVerificationPipelineError> {
        Ok(None)
    }
}

struct ConsumingKeyInfoResolver;

impl KeyResolver for ConsumingKeyInfoResolver {
    fn resolve<'a>(
        &'a self,
        _key_info: Option<&KeyInfo>,
        _algorithm: SignatureAlgorithm,
    ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, SignatureVerificationPipelineError> {
        Ok(None)
    }

    fn consumes_document_key_info(&self) -> bool {
        true
    }
}

struct FallbackKeyInfoResolver;

impl KeyResolver for FallbackKeyInfoResolver {
    fn resolve_for_verification<'a>(
        &'a self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
        _policy: &crate::policy::VerificationPolicy,
        _provider: &dyn crate::provider::CryptoProvider,
    ) -> Result<Option<super::super::ResolvedVerificationKey<'a>>, DsigError> {
        // This test resolver explicitly authorizes its application-owned key.
        self.resolve(key_info, algorithm)
            .map(|key| key.map(super::super::ResolvedVerificationKey::CallerTrusted))
    }

    fn resolve<'a>(
        &'a self,
        key_info: Option<&KeyInfo>,
        _algorithm: SignatureAlgorithm,
    ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, SignatureVerificationPipelineError> {
        let sources = &key_info.expect("KeyInfo must be parsed").sources;
        assert!(matches!(
            sources.as_slice(),
            [
                super::super::parse::KeyInfoSource::RetrievalMethod { .. },
                super::super::parse::KeyInfoSource::KeyName(name),
            ] if name == "fallback"
        ));
        Ok(Some(Box::new(AcceptingKey)))
    }

    fn consumes_document_key_info(&self) -> bool {
        true
    }
}

struct EarlyKeyInfoResolver;

impl KeyResolver for EarlyKeyInfoResolver {
    fn resolve_for_verification<'a>(
        &'a self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
        _policy: &crate::policy::VerificationPolicy,
        _provider: &dyn crate::provider::CryptoProvider,
    ) -> Result<Option<super::super::ResolvedVerificationKey<'a>>, DsigError> {
        // Only the selected primary application key is authorized here.
        self.resolve(key_info, algorithm)
            .map(|key| key.map(super::super::ResolvedVerificationKey::CallerTrusted))
    }

    fn resolve<'a>(
        &'a self,
        key_info: Option<&KeyInfo>,
        _algorithm: SignatureAlgorithm,
    ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, SignatureVerificationPipelineError> {
        let sources = &key_info.expect("KeyInfo must be parsed").sources;
        assert!(matches!(
            sources.as_slice(),
            [
                super::super::parse::KeyInfoSource::KeyName(name),
                super::super::parse::KeyInfoSource::RetrievalMethod { .. },
            ] if name == "primary"
        ));
        Ok(Some(Box::new(AcceptingKey)))
    }

    fn consumes_document_key_info(&self) -> bool {
        true
    }
}

fn minimal_signature_xml(reference_uri: &str, transforms_xml: &str) -> String {
    format!(
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:Reference URI="{reference_uri}">
      {transforms_xml}
      <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>AQ==</ds:SignatureValue>
</ds:Signature>"#
    )
}

#[test]
fn retained_verification_preserves_original_authenticated_operation() {
    // Keep the original per-Signature graph/authentication state, not a new
    // set reconstructed from detached digest-result booleans.
    use structured_asn1::memory::{Memory, MemoryAccount};
    let work = Memory::new(std::sync::Arc::new(MemoryAccount::new(16_384, 100_000)));
    let document = XmlDocument::parse(signature_with_target_reference("AQ==")).unwrap();
    let context = VerifyContext::new().key(&AcceptingKey);
    with_verified_document(
        &document,
        &context,
        &VerificationRequest::default(),
        &ScopedRequestStorage(&work),
        |view, _, budgets, evidence, operations, _| {
            assert_eq!(evidence.signatures().len(), 1);
            assert_eq!(operations.len(), 1);
            let target = view.node_for_id("target", &[]).unwrap();
            assert!(operations[0].operation.is_authenticated(target));
            assert!(std::ptr::eq(*operations[0].operation.budgets(), budgets));
            assert!(budgets.canonicalized.remaining() < budgets.canonicalized.max_bytes);
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn retained_verification_accepts_borrowed_keys_and_admits_storage_first() {
    // The scoped storage projection must not impose 'static on request
    // keys. Refused report/state storage cannot reach the provider.
    use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
    struct BorrowedKey<'a>(&'a Cell<usize>);
    impl VerifyingKey for BorrowedKey<'_> {
        fn validate_signature_value(
            &self,
            _: SignatureAlgorithm,
            _: &[u8],
        ) -> Result<bool, DsigError> {
            Ok(true)
        }
        fn verify(&self, _: SignatureAlgorithm, _: &[u8], _: &[u8]) -> Result<bool, DsigError> {
            self.0.set(self.0.get() + 1);
            Ok(true)
        }
    }
    let calls = Cell::new(0);
    let key = BorrowedKey(&calls);
    let context = VerifyContext::new().key(&key);
    let document = XmlDocument::parse(signature_with_target_reference("AQ==")).unwrap();
    let denied = Memory::new(std::sync::Arc::new(MemoryAccount::new(0, 100_000)));
    let result: Result<(), DsigError> = with_verified_document(
        &document,
        &context,
        &VerificationRequest::default(),
        &ScopedRequestStorage(&denied),
        |_, _, _, _, _, _| panic!("refused storage must not reach the continuation"),
    );
    assert!(matches!(
        result,
        Err(DsigError::SharedExecution(MemoryError::LimitExceeded))
    ));
    assert_eq!(calls.get(), 0);
    let admitted = Memory::new(std::sync::Arc::new(MemoryAccount::new(16_384, 100_000)));
    with_verified_document(
        &document,
        &context,
        &VerificationRequest::default(),
        &ScopedRequestStorage(&admitted),
        |_, _, _, evidence, operations, _| {
            assert!(evidence.all_valid());
            assert_eq!(operations.len(), 1);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(calls.get(), 1);
}

#[test]
fn verified_continuation_keeps_the_consumed_operation_budget() {
    // Extension work continues after core verification with the very same
    // canonicalization allowance, not a fresh budget built from policy.
    let document = XmlDocument::parse(signature_with_target_reference("AQ==")).unwrap();
    let context = VerifyContext::new().key(&AcceptingKey);
    let called = Cell::new(false);
    let evidence = with_verified_document(
        &document,
        &context,
        &VerificationRequest::default(),
        &CollectedRequestStorage,
        |view, _captured_context, budgets, evidence, (), _| {
            called.set(true);
            assert_eq!(view.root(), evidence.document);
            assert!(evidence.signatures()[0].result().is_ok());
            let remaining = budgets.canonicalized.remaining();
            assert!(remaining < budgets.canonicalized.max_bytes);
            budgets.canonicalized.charge(remaining).unwrap();
            assert!(budgets.canonicalized.charge(1).is_err());
            Ok(evidence)
        },
    )
    .unwrap();
    assert!(called.get());
    assert_eq!(evidence.signatures().len(), 1);
}

#[test]
fn public_session_catalogue_replays_the_original_reference() {
    // The public continuation must retain the selected operation, expose
    // original Reference/parent identities, and stream the verified bytes.
    use structured_asn1::memory::{Memory, MemoryAccount};
    let document = XmlDocument::parse(signature_with_target_reference("AQ==")).unwrap();
    let context = VerifyContext::new().key(&AcceptingKey);
    let work = Memory::new(std::sync::Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &work,
        |session| {
            let signature = session.evidence().signatures()[0].identity();
            let selected = session.select_signature(signature)?;
            let mut count = 0;
            let completeness = selected
                .visit_authenticated_references(|reference| {
                    count += 1;
                    assert!(matches!(reference.parent, ReferenceParent::SignedInfo(_)));
                    assert_eq!(reference.uri, Some("#target"));
                    let mut bytes = Vec::new();
                    let outcome = selected
                        .replay_reference(
                            reference.identity,
                            ReplayMode::ReferenceOutput,
                            &mut |chunk: &[u8]| {
                                bytes.extend_from_slice(chunk);
                                Ok::<_, ()>(())
                            },
                        )
                        .unwrap();
                    assert_eq!(outcome, ReplayOutcome::Complete);
                    assert_eq!(bytes, b"<target ID=\"target\">payload</target>");
                    Ok::<_, ()>(())
                })
                .unwrap();
            assert_eq!(completeness, CatalogueCompleteness::Complete);
            assert_eq!(count, 1);
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn public_session_resolves_original_attribute_and_fragmented_simple_content() {
    // Both schema lexical sources must resolve through the same original
    // ID index. Fragmented text must not drop text after comments or CDATA.
    use structured_asn1::memory::{Memory, MemoryAccount};
    let document = XmlDocument::parse(signature_with_target_content(
        "AQ==",
        "<property URI=\"#ref\"/><content>#r<!--split--><![CDATA[ef]]></content>",
    ))
    .unwrap();
    let context = VerifyContext::new().key(&AcceptingKey);
    let work = Memory::new(std::sync::Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &work,
        |session| {
            let selected =
                session.select_signature(session.evidence().signatures()[0].identity())?;
            for (name, source) in [
                (
                    "property",
                    LexicalSource::Attribute {
                        namespace: None,
                        local_name: "URI",
                    },
                ),
                ("content", LexicalSource::SimpleContent),
            ] {
                let node = session
                    .view()
                    .document()
                    .descendants()
                    .find(|node| node.has_tag_name(name))
                    .unwrap();
                let ReferenceResolution::Reference(reference) =
                    selected.resolve_reference(session.view().node_identity(node), source)?
                else {
                    panic!("original Reference must resolve");
                };
                assert_eq!(reference.uri, Some("#target"));
            }
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn public_session_manifest_instruction_survives_old_digest_mismatch() {
    // Renewal covers the authenticated instruction with a new digest. It
    // must not require the old target digest to match first (EN §5.5.3).
    use structured_asn1::memory::{Memory, MemoryAccount};
    let document = XmlDocument::parse(signature_with_manifest_xml(false)).unwrap();
    let context = VerifyContext::new()
        .key(&AcceptingKey)
        .process_manifests(true);
    let work = Memory::new(std::sync::Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &work,
        |session| {
            let selected =
                session.select_signature(session.evidence().signatures()[0].identity())?;
            let mut manifests = 0;
            let completeness = selected
                .visit_authenticated_references(|reference| {
                    if let ReferenceParent::Manifest(_) = reference.parent {
                        manifests += 1;
                        assert!(matches!(
                            reference.result.unwrap().status,
                            DsigStatus::Invalid(_)
                        ));
                        let mut calls = 0;
                        let outcome = selected
                            .replay_reference(
                                reference.identity,
                                ReplayMode::ReferenceOutput,
                                &mut |_: &[u8]| {
                                    calls += 1;
                                    Ok::<_, ()>(())
                                },
                            )
                            .unwrap();
                        assert_eq!(outcome, ReplayOutcome::Complete);
                        assert!(calls > 0);
                    }
                    Ok::<_, ()>(())
                })
                .unwrap();
            assert_eq!(manifests, 1);
            assert_eq!(completeness, CatalogueCompleteness::Complete);
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn public_session_replay_keeps_original_receiver_failure_sticky() {
    // No later C14N fragment may overwrite a typed caller refusal or invoke
    // the receiver a second time after the first error.
    use structured_asn1::memory::{Memory, MemoryAccount};
    #[derive(Debug, PartialEq)]
    struct Refusal(u32);
    let document = XmlDocument::parse(signature_with_target_reference("AQ==")).unwrap();
    let context = VerifyContext::new().key(&AcceptingKey);
    let work = Memory::new(std::sync::Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &work,
        |session| {
            let selected =
                session.select_signature(session.evidence().signatures()[0].identity())?;
            selected
                .visit_authenticated_references(|reference| {
                    let mut calls = 0;
                    let result = selected.replay_reference(
                        reference.identity,
                        ReplayMode::ReferenceOutput,
                        &mut |_: &[u8]| {
                            calls += 1;
                            Err(Refusal(7))
                        },
                    );
                    assert!(matches!(result, Err(ReplayError::Receiver(Refusal(7)))));
                    assert_eq!(calls, 1);
                    Ok::<_, ()>(())
                })
                .unwrap();
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn verify_all_retains_each_signature_without_vacuous_success() {
    // Malformed signatures remain individually visible; an empty document
    // never satisfies a request merely because there were no failures.
    let document = XmlDocument::parse(format!(
        "<root xmlns:ds=\"{XMLDSIG_NS}\"><ds:Signature/><ds:Signature/></root>"
    ))
    .unwrap();
    let evidence = VerifyContext::new().verify_all(&document).unwrap();
    assert_eq!(evidence.signatures().len(), 2);
    assert!(
        evidence
            .signatures()
            .iter()
            .all(|entry| entry.result().is_err())
    );
    assert!(!evidence.all_valid());
    let empty = XmlDocument::parse("<root/>").unwrap();
    assert!(!VerifyContext::new().verify_all(&empty).unwrap().all_valid());
}

#[test]
fn verify_all_checks_cardinality_before_running_keys() {
    // The cardinality policy bounds report allocation and crypto work,
    // including malformed signatures that never reach core validation.
    let document = XmlDocument::parse(format!(
        "<root xmlns:ds=\"{XMLDSIG_NS}\"><ds:Signature/><ds:Signature/></root>"
    ))
    .unwrap();
    let mut policy = crate::policy::VerificationPolicy::default();
    policy.resources.max_signatures = 1;
    assert!(matches!(
        VerifyContext::new().policy(policy).verify_all(&document),
        Err(DsigError::Policy(
            crate::policy::PolicyViolation::ResourceLimit {
                resource: "verification signatures",
                maximum: 1,
                actual: 2,
            }
        ))
    ));
}

#[test]
fn verification_signature_limit_also_gates_the_single_api() {
    // The same compiled resource policy must apply to both public paths.
    let mut policy = crate::policy::VerificationPolicy::default();
    policy.resources.max_signatures = 0;
    assert!(matches!(
        VerifyContext::new()
            .policy(policy)
            .key(&AcceptingKey)
            .verify(&signature_with_target_reference("AQ==")),
        Err(DsigError::Policy(
            crate::policy::PolicyViolation::ResourceLimit {
                resource: "verification signatures",
                maximum: 0,
                actual: 1,
            }
        ))
    ));
}

#[test]
fn verify_all_preserves_generation_and_rejects_wrapped_siblings() {
    // A signature over one element never authenticates a lookalike sibling.
    let xml = signature_with_target_reference("AQ==")
        .replace("</root>", "<target ID=\"unsigned\">payload</target></root>");
    let document = XmlDocument::parse(xml).unwrap();
    let (signed, unsigned) = document.with_view(|view| {
        (
            view.node_for_id("target", &[]).unwrap(),
            view.node_for_id("unsigned", &[]).unwrap(),
        )
    });
    let evidence = VerifyContext::new()
        .key(&AcceptingKey)
        .verify_all(&document)
        .unwrap();
    assert!(evidence.all_valid());
    assert!(evidence.covers_element(&document, signed).unwrap());
    assert!(!evidence.covers_element(&document, unsigned).unwrap());
    let foreign = XmlDocument::parse("<target/>").unwrap();
    let target = foreign.with_view(document_root_identity);
    assert!(matches!(
        evidence.covers_element(&document, target),
        Err(DsigError::Document(XmlDocumentError::ForeignIdentity))
    ));
}

#[test]
fn verify_request_rejects_duplicate_targets_before_crypto() {
    // Ambiguous request mapping is not a successful duplicate assertion.
    let document = XmlDocument::parse(signature_with_target_reference("AQ==")).unwrap();
    let target = document.with_view(|view| view.node_for_id("target", &[]).unwrap());
    let targets = [target, target];
    let request = VerificationRequest {
        expected_targets: &targets,
        ..VerificationRequest::default()
    };
    assert!(matches!(
        VerifyContext::new().verify_request(&document, &request),
        Err(DsigError::InvalidRequest {
            reason: "duplicate expected coverage target"
        })
    ));
}

#[test]
fn verify_all_shares_canonicalization_retention_budget() {
    // Repeating a Signature may not reset the retained-data allowance.
    let xml = signature_with_target_reference("AQ==");
    let single = VerifyContext::new()
        .key(&AcceptingKey)
        .store_pre_digest(true)
        .verify(&xml)
        .unwrap();
    let bytes = single.canonicalized_signed_info.unwrap().len()
        + single.signed_info_references[0]
            .pre_digest_data
            .as_ref()
            .unwrap()
            .len();
    let parsed = Document::parse(&xml).unwrap();
    let signature = parsed
        .descendants()
        .find(|node| node.has_tag_name((XMLDSIG_NS, "Signature")))
        .unwrap();
    let xml = xml.replace("</root>", &format!("{}</root>", &xml[signature.range()]));
    let document = XmlDocument::parse(xml).unwrap();
    let mut policy = crate::policy::VerificationPolicy::default();
    policy.resources.max_canonicalized_bytes = bytes * 2 - 1;
    let evidence = VerifyContext::new()
        .key(&AcceptingKey)
        .store_pre_digest(true)
        .policy(policy)
        .verify_all(&document)
        .unwrap();
    assert_eq!(evidence.signatures.len(), 2);
    assert_eq!(
        evidence.signatures[0].result().as_ref().unwrap().status,
        DsigStatus::Valid
    );
    assert!(matches!(
        evidence.signatures[1].result(),
        Err(DsigError::Policy(
            crate::policy::PolicyViolation::ResourceLimit {
                resource: "canonicalized bytes",
                ..
            }
        ))
    ));
    assert!(!evidence.accepted(&document).unwrap());
}

#[test]
fn verify_all_manifest_coverage_requires_its_authenticated_digest() {
    // A valid enclosing Signature authenticates the Manifest declaration,
    // not a target whose separately checked Manifest digest mismatches.
    for valid in [true, false] {
        let document = XmlDocument::parse(signature_with_manifest_xml(valid)).unwrap();
        let target = document.with_view(|view| view.node_for_id("target", &[]).unwrap());
        let evidence = VerifyContext::new()
            .key(&AcceptingKey)
            .process_manifests(true)
            .verify_all(&document)
            .unwrap();
        let result = evidence.signatures()[0].result().as_ref().unwrap();
        assert_eq!(result.manifest_references.len(), 1);
        assert!(result.manifest_references[0].reference_identity.is_some());
        assert_eq!(evidence.covers_element(&document, target).unwrap(), valid);
        assert_eq!(evidence.accepted(&document).unwrap(), valid);
    }
}

#[test]
fn verify_all_filtered_digest_does_not_claim_original_subtree() {
    // A projection may discard content even when its local digest matches.
    // No arbitrary filter is promoted to complete original-node coverage.
    let mut reference = make_reference(
        "#target",
        vec![Transform::XpathExcludeAllSignatures],
        DigestAlgorithm::Sha256,
        vec![],
    );
    let document = XmlDocument::parse(signature_with_target_reference("AQ==")).unwrap();
    document.with_view(|view| {
        let target = view.node_for_id("target", &[]).unwrap();
        let mut result = manifest_reference_invalid_result(
            &reference,
            0,
            FailureReason::ReferenceProcessingFailure { ref_index: 0 },
        );
        result.status = DsigStatus::Valid;
        bind_reference_evidence(
            &mut result,
            &reference,
            view,
            None,
            &OperationResourceIdentity::DocumentNode(target),
        );
        assert_eq!(result.target_identity, Some(target));
        assert_eq!(result.coverage, ReferenceCoverage::TransformedData);
        reference.transforms = vec![Transform::C14n(crate::c14n::C14nAlgorithm::new(
            crate::c14n::C14nMode::Exclusive1_0,
            false,
        ))];
        bind_reference_evidence(
            &mut result,
            &reference,
            view,
            None,
            &OperationResourceIdentity::DocumentNode(target),
        );
        assert_eq!(result.coverage, ReferenceCoverage::ElementContent);
    });
}

#[test]
fn verify_request_rejects_conflicting_resource_owners() {
    // There is no implicit override between request bytes and old builder
    // configuration: ownership must be explicit before resolver work.
    let document = XmlDocument::parse("<root/>").unwrap();
    let resources = HashMap::new();
    let request = VerificationRequest {
        external_resources: Some(&resources),
        ..VerificationRequest::default()
    };
    assert!(matches!(
        VerifyContext::new()
            .external_resources(&resources)
            .verify_request(&document, &request),
        Err(DsigError::InvalidRequest {
            reason: "external resources configured in both context and request"
        })
    ));
}

fn signature_with_target_reference(signature_value_b64: &str) -> String {
    signature_with_target_content(signature_value_b64, "payload")
        .replace("<ds:Reference Id=\"ref\"", "<ds:Reference")
}

fn signature_with_target_content(signature_value_b64: &str, content: &str) -> String {
    let xml_template = r##"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <target ID="target">payload</target>
  <ds:Signature>
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference Id="ref" URI="#target">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>SIGNATURE_VALUE_PLACEHOLDER</ds:SignatureValue>
  </ds:Signature>
</root>"##
        .replace(">payload</target>", &format!(">{content}</target>"));

    let doc = Document::parse(&xml_template).unwrap();
    let sig_node = doc
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == "Signature")
        .unwrap();
    let signed_info_node = sig_node
        .children()
        .find(|node| node.is_element() && node.tag_name().name() == "SignedInfo")
        .unwrap();
    let signed_info = parse_signed_info(signed_info_node).unwrap();
    let reference = &signed_info.references[0];
    let resolver = UriReferenceResolver::new(&doc);
    let initial_data = resolver
        .dereference(reference.uri.as_deref().unwrap())
        .unwrap();
    let pre_digest =
        crate::xmldsig::execute_transforms(sig_node, initial_data, &reference.transforms).unwrap();
    let digest = compute_digest(reference.digest_method, &pre_digest);
    let digest_b64 = base64::engine::general_purpose::STANDARD.encode(digest);
    xml_template
        .replace("AAAAAAAAAAAAAAAAAAAAAAAAAAA=", &digest_b64)
        .replace("SIGNATURE_VALUE_PLACEHOLDER", signature_value_b64)
}

#[test]
fn verify_context_reports_key_not_found_status_without_key_or_resolver() {
    let xml = signature_with_target_reference("AQ==");

    let result = VerifyContext::new()
        .verify(&xml)
        .expect("missing key config must be reported as verification status");
    assert!(
        matches!(
            result.status,
            DsigStatus::Invalid(FailureReason::KeyNotFound)
        ),
        "unexpected status: {:?}",
        result.status
    );
}

#[test]
fn verify_context_rejects_disallowed_uri() {
    let xml = minimal_signature_xml("http://example.com/external", "");
    let err = VerifyContext::new()
        .key(&RejectingKey)
        .verify(&xml)
        .expect_err("external URI should be rejected by default policy");
    assert!(matches!(
        err,
        SignatureVerificationPipelineError::Policy(crate::policy::PolicyViolation::Uri {
            operation: "verification",
            ..
        })
    ));
}

#[test]
fn verify_context_bounds_effective_xml_base_components() {
    // External URI resolution must stop before repeatedly copying an
    // attacker-controlled chain of effective XML Base values.
    let mut xml = minimal_signature_xml("payload", "");
    for _ in 0..65 {
        xml = format!(r#"<n xml:base="segment/">{xml}</n>"#);
    }
    let resources = HashMap::new();
    let error = VerifyContext::new()
        .key(&AcceptingKey)
        .allowed_uri_types(UriTypeSet::ALL)
        .external_resources(&resources)
        .verify(&xml)
        .expect_err("XML Base component work must be bounded before lookup");

    assert!(matches!(
        error,
        SignatureVerificationPipelineError::Policy(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::XML_BASE_COMPONENTS,
            maximum: 64,
            actual: 65,
        })
    ));
}

#[test]
fn verify_context_bounds_cumulative_xml_base_resolution_bytes() {
    // The operation-wide byte budget charges intermediate URI copies, not
    // merely the small final external resource returned by the caller map.
    let mut xml = minimal_signature_xml("payload", "");
    for _ in 0..2 {
        xml = format!(r#"<n xml:base="segment/">{xml}</n>"#);
    }
    let resources = HashMap::new();
    let mut policy = crate::policy::VerificationPolicy::default();
    policy.resources.max_xml_base_resolution_bytes = 32;
    let error = VerifyContext::new()
        .policy(policy)
        .key(&AcceptingKey)
        .allowed_uri_types(UriTypeSet::ALL)
        .external_resources(&resources)
        .verify(&xml)
        .expect_err("cumulative XML Base copies must obey the operation budget");

    assert!(matches!(
        error,
        SignatureVerificationPipelineError::Policy(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::XML_BASE_RESOLUTION_BYTES,
            maximum: 32,
            ..
        })
    ));
}

#[test]
fn verify_context_applies_xml_base_policy_to_signed_info_c14n() {
    // The SignedInfo node-set excludes its ancestors, so C14N 1.1 must
    // resolve their inherited xml:base values through the same operation
    // budget already used by Reference processing.
    let xml = signature_with_target_reference("AQ==")
        .replacen(
            "http://www.w3.org/2001/10/xml-exc-c14n#",
            "http://www.w3.org/2006/12/xml-c14n11",
            1,
        )
        .replace(
            "  <ds:Signature>",
            "  <outer xml:base=\"one/\"><inner xml:base=\"two/\"><ds:Signature>",
        )
        .replace("  </ds:Signature>", "  </ds:Signature></inner></outer>");
    let policy = crate::policy::VerificationPolicy {
        resources: crate::policy::ResourcePolicy {
            max_xml_base_components: 1,
            ..crate::policy::ResourcePolicy::default()
        },
        ..crate::policy::VerificationPolicy::default()
    };

    let error = VerifyContext::new()
        .key(&AcceptingKey)
        .policy(policy)
        .verify(&xml)
        .expect_err("SignedInfo C14N must use the operation XML Base budget");

    assert!(matches!(
        error,
        SignatureVerificationPipelineError::Policy(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::XML_BASE_COMPONENTS,
            maximum: 1,
            actual: 2,
        })
    ));
}

#[test]
fn verify_context_classifies_signed_info_xml_base_byte_limit_as_policy() {
    // SignedInfo C14N 1.1 XML Base work is policy enforcement, not a
    // malformed canonicalization request, and must retain typed diagnostics.
    let xml = signature_with_target_reference("AQ==")
        .replacen(
            "http://www.w3.org/2001/10/xml-exc-c14n#",
            "http://www.w3.org/2006/12/xml-c14n11",
            1,
        )
        .replace(
            "  <ds:Signature>",
            "  <outer xml:base=\"segment/\"><ds:Signature>",
        )
        .replace("  </ds:Signature>", "  </ds:Signature></outer>");
    let policy = crate::policy::VerificationPolicy {
        resources: crate::policy::ResourcePolicy {
            max_xml_base_resolution_bytes: 1,
            ..crate::policy::ResourcePolicy::default()
        },
        ..crate::policy::VerificationPolicy::default()
    };

    let error = VerifyContext::new()
        .key(&AcceptingKey)
        .policy(policy)
        .verify(&xml)
        .expect_err("SignedInfo XML Base byte exhaustion must be a policy error");

    assert!(matches!(
        error,
        SignatureVerificationPipelineError::Policy(
            crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_BASE_RESOLUTION_BYTES,
                maximum: 1,
                actual,
            }
        ) if actual > 1
    ));
}

#[test]
fn verify_context_meters_repeated_external_dereferences() {
    // One caller-owned entry can be referenced repeatedly. The aggregate
    // ceiling bounds bytes cloned and processed, not just unique map data.
    let payload = b"payload";
    let digest = base64::engine::general_purpose::STANDARD.encode(crate::xmldsig::compute_digest(
        DigestAlgorithm::Sha1,
        payload,
    ));
    let reference = format!(
        r#"<ds:Reference URI="urn:payload"><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference>"#
    );
    let xml = format!(
        r#"<ds:Signature xmlns:ds="{XMLDSIG_NS}"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>{reference}{reference}</ds:SignedInfo><ds:SignatureValue>AQ==</ds:SignatureValue></ds:Signature>"#
    );
    let resources = HashMap::from([("urn:payload".to_owned(), payload.to_vec())]);
    let policy = crate::policy::VerificationPolicy {
        uris: crate::policy::UriPolicy {
            references: UriTypeSet::ALL,
            ..crate::policy::UriPolicy::default()
        },
        resources: crate::policy::ResourcePolicy {
            max_external_resource_bytes: payload.len(),
            max_external_resource_total_bytes: payload.len(),
            ..crate::policy::ResourcePolicy::default()
        },
        ..crate::policy::VerificationPolicy::default()
    };

    let error = VerifyContext::new()
        .key(&AcceptingKey)
        .policy(policy)
        .external_resources(&resources)
        .verify(&xml)
        .expect_err("the second dereference must exhaust the aggregate byte ceiling");

    assert!(
        error
            .to_string()
            .contains("aggregate external resource bytes")
    );
}

#[test]
fn verify_context_rejects_empty_uri_when_policy_disallows_empty() {
    let xml = minimal_signature_xml("", "");
    let err = VerifyContext::new()
        .key(&RejectingKey)
        .allowed_uri_types(UriTypeSet::new(false, true, false))
        .verify(&xml)
        .expect_err("empty URI must be rejected when empty references are disabled");
    assert!(matches!(
        err,
        SignatureVerificationPipelineError::Policy(crate::policy::PolicyViolation::Uri {
            operation: "verification",
            ..
        })
    ));
}

#[test]
fn verify_context_rejects_disallowed_transform() {
    let xml = minimal_signature_xml(
        "",
        r#"<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms>"#,
    );
    let err = VerifyContext::new()
        .key(&RejectingKey)
        .allowed_transforms(["http://www.w3.org/2001/10/xml-exc-c14n#"])
        .verify(&xml)
        .expect_err("enveloped transform should be rejected by allowlist");
    assert!(matches!(
        err,
        SignatureVerificationPipelineError::Policy(crate::policy::PolicyViolation::Algorithm {
            operation: "verification transform",
            ..
        })
    ));
}

#[test]
fn verify_context_applies_transform_allowlist_to_signed_info_c14n() {
    // Reference C14N remains allowlisted; only the distinct SignedInfo
    // canonicalization method should trigger this policy rejection.
    let xml = signature_with_target_reference("AQ==").replacen(
            "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
            "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>",
            1,
        );
    let error = VerifyContext::new()
        .key(&AcceptingKey)
        .allowed_transforms(["http://www.w3.org/2001/10/xml-exc-c14n#"])
        .verify(&xml)
        .expect_err("SignedInfo C14N must obey the operation transform allowlist");

    assert!(matches!(
        error,
        SignatureVerificationPipelineError::Policy(
            crate::policy::PolicyViolation::Algorithm {
                operation: "verification transform",
                ref algorithm,
            }
        )
            if algorithm == "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
    ));
}

#[test]
fn verify_context_applies_transform_allowlist_to_key_retrieval() {
    // The reference and SignedInfo both use exclusive C14N. The only XPath
    // operation is document-selected key retrieval and must be rejected.
    let xml = signature_with_target_reference("AQ==")
            .replacen(
                "</ds:Signature>",
                r##"<ds:KeyInfo><ds:RetrievalMethod URI="#keys" Type="http://www.w3.org/2000/09/xmldsig#X509Data"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>ancestor-or-self::ds:X509Data</ds:XPath></ds:Transform></ds:Transforms></ds:RetrievalMethod></ds:KeyInfo></ds:Signature>"##,
                1,
            )
            .replacen(
                "</root>",
                r#"<holder ID="keys"><ds:X509Data><ds:X509SubjectName>CN=leaf</ds:X509SubjectName></ds:X509Data></holder></root>"#,
                1,
            );
    let error = VerifyContext::new()
        .key_resolver(&ConsumingKeyInfoResolver)
        .allowed_transforms(["http://www.w3.org/2001/10/xml-exc-c14n#"])
        .verify(&xml)
        .expect_err("RetrievalMethod XPath must obey the operation transform allowlist");

    assert!(matches!(
        error,
        SignatureVerificationPipelineError::Policy(
            crate::policy::PolicyViolation::Algorithm {
                operation: "verification transform",
                ref algorithm,
            }
        )
            if algorithm == XPATH_TRANSFORM_URI
    ));
}

fn signature_with_manifest_xml(valid_manifest_digest: bool) -> String {
    signature_with_manifest_xml_with_manifest_mutation(valid_manifest_digest, |xml| xml)
}

fn signature_with_manifest_xml_with_manifest_mutation<F>(
    valid_manifest_digest: bool,
    mutate_manifest: F,
) -> String
where
    F: FnOnce(String) -> String,
{
    const TMP_SIGNED_INFO_DIGEST: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const INVALID_MANIFEST_DIGEST: &str = "//////////////////////////8=";
    let xml_template = r##"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <target ID="target">payload</target>
  <ds:Signature>
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#manifest">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <ds:DigestValue>SIGNEDINFO_OBJECT_DIGEST_PLACEHOLDER</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>AQ==</ds:SignatureValue>
    <ds:Object>
      <ds:Manifest ID="manifest">
        <ds:Reference URI="#target">
          <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
          <ds:DigestValue>MANIFEST_DIGEST_PLACEHOLDER</ds:DigestValue>
        </ds:Reference>
      </ds:Manifest>
    </ds:Object>
  </ds:Signature>
</root>"##;
    let seed_xml = xml_template.replace(
        "SIGNEDINFO_OBJECT_DIGEST_PLACEHOLDER",
        TMP_SIGNED_INFO_DIGEST,
    );
    let doc = Document::parse(&seed_xml).unwrap();
    let signature_node = doc
        .descendants()
        .find(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(XMLDSIG_NS)
                && node.tag_name().name() == "Signature"
        })
        .unwrap();
    let resolver = UriReferenceResolver::new(&doc);
    let initial_data = resolver.dereference("#target").unwrap();
    let manifest_pre_digest =
        crate::xmldsig::execute_transforms(signature_node, initial_data, &[]).unwrap();
    let computed_manifest_digest_b64 = base64::engine::general_purpose::STANDARD
        .encode(compute_digest(DigestAlgorithm::Sha1, &manifest_pre_digest));
    let final_manifest_digest_b64 = if valid_manifest_digest {
        computed_manifest_digest_b64.as_str()
    } else {
        INVALID_MANIFEST_DIGEST
    };
    let xml_with_manifest_digest =
        mutate_manifest(seed_xml.replace("MANIFEST_DIGEST_PLACEHOLDER", final_manifest_digest_b64));
    let signed_doc = Document::parse(&xml_with_manifest_digest).unwrap();
    let signed_signature_node = signed_doc
        .descendants()
        .find(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(XMLDSIG_NS)
                && node.tag_name().name() == "Signature"
        })
        .unwrap();
    let signed_info_node = signed_signature_node
        .children()
        .find(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(XMLDSIG_NS)
                && node.tag_name().name() == "SignedInfo"
        })
        .unwrap();
    let signed_info = parse_signed_info(signed_info_node).unwrap();
    let object_reference = &signed_info.references[0];
    let signed_resolver = UriReferenceResolver::new(&signed_doc);
    let signed_initial_data = signed_resolver
        .dereference(object_reference.uri.as_deref().unwrap())
        .unwrap();
    let signed_pre_digest = crate::xmldsig::execute_transforms(
        signed_signature_node,
        signed_initial_data,
        &object_reference.transforms,
    )
    .unwrap();
    let signed_digest_b64 = base64::engine::general_purpose::STANDARD.encode(compute_digest(
        object_reference.digest_method,
        &signed_pre_digest,
    ));

    xml_with_manifest_digest.replacen(TMP_SIGNED_INFO_DIGEST, &signed_digest_b64, 1)
}

fn replace_fixture_manifest_digest(xml: &str, replacement: &str) -> String {
    let object_marker = "<ds:Object>";
    let object_start = xml
        .find(object_marker)
        .expect("fixture should contain ds:Object")
        + object_marker.len();
    let open = "<ds:DigestValue>";
    let close = "</ds:DigestValue>";
    let value_start = xml[object_start..]
        .find(open)
        .map(|offset| object_start + offset + open.len())
        .expect("Manifest should contain DigestValue");
    let value_end = xml[value_start..]
        .find(close)
        .map(|offset| value_start + offset)
        .expect("Manifest DigestValue must be closed");

    format!("{}{replacement}{}", &xml[..value_start], &xml[value_end..])
}

#[test]
fn verify_context_processes_manifest_references_when_enabled() {
    let xml = signature_with_manifest_xml(true);

    let result_without_manifests = VerifyContext::new()
        .key(&RejectingKey)
        .verify(&xml)
        .expect("manifest processing disabled should still verify SignedInfo");
    assert!(
        result_without_manifests.manifest_references.is_empty(),
        "manifest results must stay empty when manifest processing is disabled",
    );
    assert!(matches!(
        result_without_manifests.status,
        DsigStatus::Invalid(FailureReason::SignatureMismatch)
    ));

    let malformed_manifest_xml = signature_with_manifest_xml(true).replacen(
        "</ds:Object>",
        "</ds:Object><ds:Object><ds:Manifest><ds:Foo/></ds:Manifest></ds:Object>",
        1,
    );
    let malformed_with_manifests_disabled = VerifyContext::new()
        .key(&RejectingKey)
        .verify(&malformed_manifest_xml)
        .expect("malformed Manifest must be ignored when manifest processing is disabled");
    assert!(
        malformed_with_manifests_disabled
            .manifest_references
            .is_empty(),
        "manifest parser must not run when process_manifests is disabled",
    );
    assert!(matches!(
        malformed_with_manifests_disabled.status,
        DsigStatus::Invalid(FailureReason::SignatureMismatch)
    ));

    let result_with_manifests = VerifyContext::new()
        .key(&AcceptingKey)
        .process_manifests(true)
        .verify(&xml)
        .expect("manifest references should be processed when enabled");
    assert_eq!(result_with_manifests.manifest_references.len(), 1);
    assert_eq!(
        result_with_manifests.manifest_references[0].reference_set,
        ReferenceSet::Manifest
    );
    assert_eq!(
        result_with_manifests.manifest_references[0].reference_index,
        0
    );
    assert!(matches!(
        result_with_manifests.manifest_references[0].status,
        DsigStatus::Valid
    ));
    assert!(matches!(result_with_manifests.status, DsigStatus::Valid));
}

#[test]
fn verify_context_skips_manifest_work_when_signature_value_is_invalid() {
    // SignedInfo authenticates the Manifest bytes only after SignatureValue
    // succeeds. Malformed nested content must not consume parsing work when
    // the cryptographic signature itself is invalid.
    let xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
        replace_fixture_manifest_digest(&xml, "!!!")
    });
    assert!(
        xml.split_once("<ds:Object>")
            .is_some_and(|(_, object)| object.contains("<ds:DigestValue>!!!</ds:DigestValue>")),
        "fixture mutation must corrupt the nested Manifest DigestValue",
    );

    let result = VerifyContext::new()
        .key(&RejectingKey)
        .process_manifests(true)
        .verify(&xml)
        .expect("invalid SignatureValue must short-circuit Manifest parsing");

    assert!(matches!(
        result.status,
        DsigStatus::Invalid(FailureReason::SignatureMismatch)
    ));
    assert!(result.manifest_references.is_empty());
}

#[test]
fn verify_context_shares_xpath_parse_budget_with_manifest_references() {
    // SignedInfo and every Manifest form one attacker-controlled parse unit:
    // splitting expressions across Reference sets must not reset the ceiling.
    let filters = r#"<XPath xmlns="http://www.w3.org/2002/06/xmldsig-filter2" Filter="intersect">true()</XPath>"#
            .repeat(64);
    let transform = format!(
        r#"<ds:Transform Algorithm="http://www.w3.org/2002/06/xmldsig-filter2">{filters}</ds:Transform>"#
    );
    let max_transforms = transform.repeat(16);
    let max_manifest_reference = format!(
        r##"<ds:Reference URI="#target"><ds:Transforms>{max_transforms}</ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue></ds:Reference>"##
    );
    let xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
        xml.replacen(
                r##"<ds:Reference URI="#target">"##,
                &format!(
                    r##"<ds:Reference URI="#target"><ds:Transforms>{max_transforms}</ds:Transforms>"##,
                ),
                1,
            )
            .replacen(
                "</ds:SignedInfo>",
                r##"<ds:Reference URI="#target"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>false()</ds:XPath></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>2jmj7l5rSw0yVb/vlWAYkK/YBwk=</ds:DigestValue></ds:Reference></ds:SignedInfo>"##,
                1,
            )
            .replacen(
                "</ds:Manifest>",
                &format!("{}</ds:Manifest>", max_manifest_reference.repeat(3)),
                1,
            )
    });

    let error = VerifyContext::new()
        .key(&AcceptingKey)
        .process_manifests(true)
        .verify(&xml)
        .expect_err("SignedInfo and Manifest References must share one XPath parse budget");

    assert!(
        matches!(
            &error,
            SignatureVerificationPipelineError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: "XPath expressions",
                    ..
                }
            )
        ),
        "unexpected error: {error:?}"
    );
}

#[test]
fn verify_context_processes_manifest_when_signedinfo_references_object() {
    let xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
        xml.replacen("URI=\"#manifest\"", "URI=\"#object-id\"", 1)
            .replacen("<ds:Object>", "<ds:Object ID=\"object-id\">", 1)
            .replacen("<ds:Manifest ID=\"manifest\">", "<ds:Manifest>", 1)
    });

    let result = VerifyContext::new()
        .key(&AcceptingKey)
        .process_manifests(true)
        .verify(&xml)
        .expect("manifest references should be processed when SignedInfo references ds:Object");
    assert_eq!(
        result.manifest_references.len(),
        1,
        "signed ds:Object should enable processing of its direct-child ds:Manifest",
    );
    assert_eq!(
        result.manifest_references[0].reference_set,
        ReferenceSet::Manifest
    );
    assert_eq!(result.manifest_references[0].reference_index, 0);
    assert!(matches!(
        result.manifest_references[0].status,
        DsigStatus::Valid
    ));
}

#[test]
fn verify_context_skips_manifest_removed_by_enveloped_transform() {
    // The owning Signature contains both eligible ID targets. Subtracting
    // its subtree therefore removes every target node from the digest input,
    // so neither form authenticates the Manifest structure for processing.
    for target_object in [false, true] {
        let xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
            let xml = xml.replacen(
                    r#"<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
                    r#"<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
                    1,
                );
            if target_object {
                xml.replacen("URI=\"#manifest\"", "URI=\"#object-id\"", 1)
                    .replacen("<ds:Object>", "<ds:Object ID=\"object-id\">", 1)
                    .replacen("<ds:Manifest ID=\"manifest\">", "<ds:Manifest>", 1)
            } else {
                xml
            }
        });

        let result = VerifyContext::new()
            .key(&AcceptingKey)
            .process_manifests(true)
            .store_pre_digest(true)
            .verify(&xml)
            .expect("an emptied reference remains a valid core digest input");

        assert!(matches!(result.status, DsigStatus::Valid));
        assert_eq!(
            result.signed_info_references[0].pre_digest_data.as_deref(),
            Some([].as_slice()),
            "target_object={target_object} must have empty transformed bytes",
        );
        assert!(
            result.manifest_references.is_empty(),
            "target_object={target_object} must not authenticate the Manifest",
        );
    }
}

#[test]
fn verify_context_ignores_manifest_excluded_from_signed_object() {
    // A Reference URI authenticates only its post-transform bytes. Excluding
    // the Manifest subtree must not let its independently valid digest chain
    // masquerade as data authenticated by SignedInfo.
    let xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
        xml.replacen("URI=\"#manifest\"", "URI=\"#object-id\"", 1)
                .replacen("<ds:Object>", "<ds:Object ID=\"object-id\">", 1)
                .replacen("<ds:Manifest ID=\"manifest\">", "<ds:Manifest>", 1)
                .replacen(
                    r#"<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
                    r#"<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>not(ancestor-or-self::ds:Manifest)</ds:XPath></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
                    1,
                )
    });

    let result = VerifyContext::new()
        .key(&AcceptingKey)
        .process_manifests(true)
        .verify(&xml)
        .expect("excluded Manifest content must be ignored, not parsed");

    assert!(matches!(result.status, DsigStatus::Valid));
    assert!(
        result.manifest_references.is_empty(),
        "a transform-excluded Manifest is not authenticated by SignedInfo",
    );
}

#[test]
fn verify_context_skips_manifest_digest_work_when_signature_is_invalid() {
    let xml = signature_with_manifest_xml(false);
    let result = VerifyContext::new()
        .key(&RejectingKey)
        .process_manifests(true)
        .verify(&xml)
        .expect("invalid SignatureValue must short-circuit Manifest digest work");
    assert!(result.manifest_references.is_empty());
    assert!(matches!(
        result.status,
        DsigStatus::Invalid(FailureReason::SignatureMismatch)
    ));
}

#[test]
fn verify_context_manifest_digest_mismatch_is_non_fatal_with_accepting_key() {
    let xml = signature_with_manifest_xml(false);
    let result = VerifyContext::new()
        .key(&AcceptingKey)
        .process_manifests(true)
        .verify(&xml)
        .expect("manifest digest mismatches should be recorded while signature stays valid");
    assert_eq!(result.manifest_references.len(), 1);
    assert!(matches!(
        result.manifest_references[0].status,
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
    ));
    assert!(matches!(result.status, DsigStatus::Valid));
}

#[test]
fn invalid_outer_manifest_digest_does_not_parse_nested_manifest() {
    // The malformed inner Manifest is not authenticated until its parent
    // Reference digest succeeds. A mismatch must therefore stop before
    // parsing or charging work for the nested structure.
    let xml = signature_with_manifest_xml_with_manifest_mutation(false, |xml| {
        xml.replacen("URI=\"#target\"", "URI=\"#inner-object\"", 1)
                .replacen(
                    "</ds:Object>",
                    "</ds:Object><ds:Object ID=\"inner-object\"><ds:Manifest>junk<ds:Unexpected/></ds:Manifest></ds:Object>",
                    1,
                )
    });

    let result = VerifyContext::new()
        .key(&AcceptingKey)
        .process_manifests(true)
        .verify(&xml)
        .expect("an unauthenticated nested Manifest must remain opaque");

    assert_eq!(result.manifest_references.len(), 1);
    assert!(matches!(
        result.manifest_references[0].status,
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
    ));
}

#[test]
fn verify_context_skips_manifest_parsing_when_signedinfo_reference_fails() {
    // Manifest content is not authenticated after a SignedInfo reference
    // failure, so parsing it would spend work on untrusted nested input.
    let xml = signature_with_manifest_xml(true);
    let (signed_info_prefix, object_suffix) = xml
        .split_once("<ds:Object>")
        .expect("fixture should contain ds:Object");
    let open = "<ds:DigestValue>";
    let close = "</ds:DigestValue>";
    let digest_start = signed_info_prefix
        .find(open)
        .expect("SignedInfo should contain DigestValue");
    let digest_end = signed_info_prefix[digest_start + open.len()..]
        .find(close)
        .map(|offset| digest_start + open.len() + offset)
        .expect("SignedInfo DigestValue must be closed");
    let broken_signed_info_prefix = format!(
        "{}{}AAAAAAAAAAAAAAAAAAAAAAAAAAA={}{}",
        &signed_info_prefix[..digest_start],
        open,
        close,
        &signed_info_prefix[digest_end + close.len()..],
    );
    let broken_xml = format!("{broken_signed_info_prefix}<ds:Object>{object_suffix}");
    let result = VerifyContext::new()
        .key(&AcceptingKey)
        .process_manifests(true)
        .verify(&broken_xml)
        .expect("SignedInfo digest failure should return without parsing Manifests");
    assert!(matches!(
        result.status,
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
    ));
    assert!(
        result.manifest_references.is_empty(),
        "unauthenticated Manifest content must not be parsed",
    );
}

#[test]
fn verify_context_skips_manifest_policy_work_when_signature_is_invalid() {
    // A digest-valid SignedInfo reference does not authenticate Manifest
    // policy inputs until SignatureValue also succeeds.
    let broken_xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
        xml.replacen("URI=\"#target\"", "URI=\"http://example.com/external\"", 1)
    });
    let result = VerifyContext::new()
        .key(&RejectingKey)
        .process_manifests(true)
        .verify(&broken_xml)
        .expect("invalid SignatureValue must short-circuit Manifest policy work");
    assert!(result.manifest_references.is_empty());
    assert!(matches!(
        result.status,
        DsigStatus::Invalid(FailureReason::SignatureMismatch)
    ));
}

#[test]
fn verify_context_records_manifest_policy_violations_with_accepting_key() {
    let broken_xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
        xml.replacen("URI=\"#target\"", "URI=\"http://example.com/external\"", 1)
    });
    let result = VerifyContext::new()
        .key(&AcceptingKey)
        .process_manifests(true)
        .verify(&broken_xml)
        .expect("manifest policy violations should be recorded while signature stays valid");
    assert_eq!(result.manifest_references.len(), 1);
    assert!(matches!(
        result.manifest_references[0].status,
        DsigStatus::Invalid(FailureReason::ReferencePolicyViolation { ref_index: 0 })
    ));
    assert!(matches!(result.status, DsigStatus::Valid));
}

#[test]
fn verify_context_applies_digest_policy_to_manifest_references() {
    // Manifest results are authenticated extension data and must obey the
    // same digest allowlist as SignedInfo references.
    let policy = crate::policy::VerificationPolicy {
        manifest_processing: crate::policy::ManifestProcessing::Process,
        digest_algorithms: Some(HashSet::from([DigestAlgorithm::Sha1])),
        ..crate::policy::VerificationPolicy::default()
    };
    let xml = signature_with_manifest_xml_with_manifest_mutation(true, |mut xml| {
        let legacy = "http://www.w3.org/2000/09/xmldsig#sha1";
        let offset = xml
            .rfind(legacy)
            .expect("Manifest DigestMethod must be present");
        xml.replace_range(offset..offset + legacy.len(), DigestAlgorithm::Sha256.uri());
        let value_start = xml[offset..]
            .find("<ds:DigestValue>")
            .map(|relative| offset + relative + "<ds:DigestValue>".len())
            .expect("Manifest DigestValue must be present");
        let value_end = xml[value_start..]
            .find("</ds:DigestValue>")
            .map(|relative| value_start + relative)
            .expect("Manifest DigestValue must be closed");
        xml.replace_range(
            value_start..value_end,
            &base64::engine::general_purpose::STANDARD.encode([0_u8; 32]),
        );
        xml
    });
    let result = VerifyContext::new()
        .key(&AcceptingKey)
        .policy(policy)
        .verify(&xml)
        .expect("a disallowed Manifest digest is a per-reference result");

    assert!(matches!(result.status, DsigStatus::Valid));
    assert!(matches!(
        result.manifest_references[0].status,
        DsigStatus::Invalid(FailureReason::ReferencePolicyViolation { ref_index: 0 })
    ));
}

#[test]
fn verify_context_applies_transform_count_policy_to_manifest_references() {
    // Authenticated Manifest references share the caller's per-reference
    // transform ceiling and fail before transform execution when exceeded.
    let policy = crate::policy::VerificationPolicy {
        manifest_processing: crate::policy::ManifestProcessing::Process,
        resources: crate::policy::ResourcePolicy {
            max_transforms_per_reference: 1,
            ..crate::policy::ResourcePolicy::default()
        },
        ..crate::policy::VerificationPolicy::default()
    };
    let xml = signature_with_manifest_xml_with_manifest_mutation(true, |mut xml| {
        let manifest_start = xml
            .find("<ds:Manifest")
            .expect("fixture must contain a Manifest");
        let manifest = xml[manifest_start..].replacen(
            "<ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>",
            concat!(
                "<ds:Transforms>",
                "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
                "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
                "</ds:Transforms>",
                "<ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>"
            ),
            1,
        );
        xml.replace_range(manifest_start.., &manifest);
        xml
    });
    let result = VerifyContext::new()
        .key(&AcceptingKey)
        .policy(policy)
        .verify(&xml)
        .expect("Manifest transform policy is a per-reference result");

    assert!(matches!(result.status, DsigStatus::Valid));
    assert!(matches!(
        result.manifest_references[0].status,
        DsigStatus::Invalid(FailureReason::ReferencePolicyViolation { ref_index: 0 })
    ));
}

#[test]
fn verify_context_skips_manifest_uri_work_when_signature_is_invalid() {
    // Missing Manifest URIs remain unauthenticated until SignatureValue
    // succeeds, so they cannot trigger Manifest policy processing here.
    let broken_xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
        xml.replacen("<ds:Reference URI=\"#target\">", "<ds:Reference>", 1)
    });

    let result = VerifyContext::new()
        .key(&RejectingKey)
        .process_manifests(true)
        .verify(&broken_xml)
        .expect("invalid SignatureValue must short-circuit Manifest URI processing");
    assert!(result.manifest_references.is_empty());
    assert!(matches!(
        result.status,
        DsigStatus::Invalid(FailureReason::SignatureMismatch)
    ));
}

#[test]
fn verify_context_records_manifest_missing_uri_with_accepting_key() {
    let broken_xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
        xml.replacen("<ds:Reference URI=\"#target\">", "<ds:Reference>", 1)
    });

    let result = VerifyContext::new()
        .key(&AcceptingKey)
        .process_manifests(true)
        .verify(&broken_xml)
        .expect("manifest missing URI should be recorded while signature stays valid");
    assert_eq!(result.manifest_references.len(), 1);
    assert_eq!(result.manifest_references[0].uri, "<omitted>");
    assert!(matches!(
        result.manifest_references[0].status,
        DsigStatus::Invalid(FailureReason::ReferenceProcessingFailure { ref_index: 0 })
    ));
    assert!(matches!(result.status, DsigStatus::Valid));
}

#[test]
fn manifest_reference_without_caller_bytes_is_unavailable() {
    // An external Reference whose bytes the caller has not supplied has the
    // same Unavailable outcome in a Manifest as in SignedInfo.
    let xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
        xml.replacen("URI=\"#target\"", "URI=\"urn:absent\"", 1)
    });
    let result = VerifyContext::new()
        .key(&AcceptingKey)
        .process_manifests(true)
        .allowed_uri_types(UriTypeSet::ALL)
        .verify(&xml)
        .expect("an unavailable Manifest payload is a per-reference result");
    assert_eq!(result.status, DsigStatus::Valid);
    assert_eq!(
        result.manifest_references[0].status,
        DsigStatus::Invalid(FailureReason::ReferenceUnavailable { ref_index: 0 })
    );
}

#[test]
fn verify_context_processes_authenticated_nested_manifests_in_object() {
    // XMLDSig §5.1 does not impose a direct Object-child restriction.
    // The original Reference authenticates this exact wrapped Manifest.
    // https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-Manifest
    let xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
        xml.replacen(
            "<ds:Manifest ID=\"manifest\">",
            "<wrapper><ds:Manifest ID=\"manifest\">",
            1,
        )
        .replacen("</ds:Manifest>", "</ds:Manifest></wrapper>", 1)
    });

    let result = VerifyContext::new()
        .key(&AcceptingKey)
        .process_manifests(true)
        .verify(&xml)
        .expect("authenticated nested Manifest is processed");
    assert_eq!(result.manifest_references.len(), 1);
    assert_eq!(result.manifest_references[0].uri, "#target");
    assert_eq!(result.manifest_references[0].status, DsigStatus::Valid);
    assert!(matches!(result.status, DsigStatus::Valid));
}

#[test]
fn verify_context_reports_manifest_reference_parse_errors_explicitly() {
    // Malformed nested DigestValue is parsed only after the enclosing
    // Manifest structure has been authenticated by SignedInfo.
    let broken_xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
        replace_fixture_manifest_digest(&xml, "!!!")
    });

    let err = VerifyContext::new()
        .key(&AcceptingKey)
        .process_manifests(true)
        .verify(&broken_xml)
        .expect_err("invalid Manifest DigestValue must map to ParseManifestReference");
    assert!(matches!(
        err,
        SignatureVerificationPipelineError::ParseManifestReference(_)
    ));
}

#[test]
fn verify_context_reports_unsupported_manifest_transform_with_declared_digest() {
    // Unsupported optional Manifest transforms do not invalidate core
    // SignedInfo, but their result must preserve the declared digest method.
    let xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
        let xml = xml.replacen(
                "<ds:Reference URI=\"#target\">",
                "<ds:Reference URI=\"#target\"><ds:Transforms><ds:Transform Algorithm=\"urn:unsupported\"/></ds:Transforms>",
                1,
            );
        let xml = xml.replacen(
                "</ds:Transforms>\n          <ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>",
                "</ds:Transforms>\n          <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
                1,
            );
        replace_fixture_manifest_digest(&xml, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    });
    assert!(xml.contains("urn:unsupported"));
    assert!(xml.contains("http://www.w3.org/2001/04/xmlenc#sha256"));

    let result = VerifyContext::new()
        .key(&AcceptingKey)
        .process_manifests(true)
        .verify(&xml)
        .expect("unsupported Manifest transform is a per-reference result");
    assert_eq!(result.status, DsigStatus::Valid);
    assert_eq!(result.manifest_references.len(), 1);
    assert_eq!(
        result.manifest_references[0].digest_algorithm,
        DigestAlgorithm::Sha256
    );
    assert!(matches!(
        result.manifest_references[0].status,
        DsigStatus::Invalid(FailureReason::ReferenceProcessingFailure { ref_index: 0 })
    ));

    let restricted = VerifyContext::new()
        .key(&AcceptingKey)
        .process_manifests(true)
        .allowed_transforms([
            DEFAULT_IMPLICIT_C14N_URI,
            "http://www.w3.org/2001/10/xml-exc-c14n#",
        ])
        .verify(&xml)
        .expect("a disallowed Manifest transform is a per-reference policy result");
    assert!(matches!(
        restricted.manifest_references[0].status,
        DsigStatus::Invalid(FailureReason::ReferencePolicyViolation { ref_index: 0 })
    ));
}

#[test]
fn manifest_reference_limit_counts_unsupported_entries() {
    use std::fmt::Write as _;
    let mut references = String::new();
    for index in 0..=MAX_REFERENCES_PER_SIGNATURE {
        write!(references,
                    r##"<ds:Reference URI="#target-{index}"><ds:Transforms><ds:Transform Algorithm="urn:unsupported"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue></ds:Reference>"##
        ).expect("writing to String cannot fail");
    }
    let xml = format!(
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Object Id="signed"><ds:Manifest>{references}</ds:Manifest></ds:Object></ds:Signature>"#
    );
    let document = XmlDocument::parse(xml).unwrap();
    let error = document.with_view(|view| {
        let signature = view.document().root_element();
        let object = signature.children().find(Node::is_element).unwrap();
        let policy = crate::policy::VerificationPolicy::default();
        let budgets = VerificationOperationBudgets::with_transforms(
            &policy,
            TransformExecutionBudget::from_resources(&policy.resources),
            None,
        );
        let operation = OperationExecutionContext::new(
            &policy,
            &budgets,
            Some((view.identity(), view.generation())),
        );
        operation.authenticate(view.node_identity(object));
        let mut processed = HashSet::new();
        let mut remaining = MAX_REFERENCES_PER_SIGNATURE;
        let mut next_index = 0;
        let mut xpath_parse = XPathSignatureParseBudget::default();
        let mut state = ManifestDiscoveryState {
            processed: &mut processed,
            remaining_capacity: &mut remaining,
            next_reference_index: &mut next_index,
            xpath_parse: &mut xpath_parse,
        };
        match parse_manifest_references(signature, &operation, view, &mut state, None) {
            Ok(_) => panic!("unsupported references must consume the same aggregate limit"),
            Err(error) => error,
        }
    });
    assert!(matches!(
        error,
        SignatureVerificationPipelineError::InvalidStructure {
            reason: "signed Manifests exceed the per-signature Reference limit"
        }
    ));
}

#[test]
fn unsigned_manifest_discovery_cannot_bypass_the_filter_work_budget() {
    // Unsigned appended nodes still cost discovery work after Signature
    // authentication. Even an all-unsigned frontier must admit its scan.
    let document = XmlDocument::parse(format!(
            "<ds:Signature xmlns:ds=\"{XMLDSIG_NS}\"><ds:Object><ds:Manifest/></ds:Object></ds:Signature>"
        )).unwrap();
    document.with_view(|view| {
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.resources.max_node_set_filter_work = 0;
        let budgets = VerificationOperationBudgets::with_transforms(
            &policy,
            TransformExecutionBudget::from_resources(&policy.resources),
            None,
        );
        let operation = OperationExecutionContext::new(
            &policy,
            &budgets,
            Some((view.identity(), view.generation())),
        );
        let mut processed = HashSet::new();
        let mut remaining = 1;
        let mut index = 0;
        let mut xpath = XPathSignatureParseBudget::default();
        let result = parse_manifest_references(
            view.document().root_element(),
            &operation,
            view,
            &mut ManifestDiscoveryState {
                processed: &mut processed,
                remaining_capacity: &mut remaining,
                next_reference_index: &mut index,
                xpath_parse: &mut xpath,
            },
            None,
        );
        assert!(result.is_err(), "unsigned scans are not free");
    });
}

#[test]
fn unsigned_manifest_remains_eligible_after_trust_expands() {
    // The second Object is not authenticated during the first discovery
    // pass. It must remain unprocessed so a valid reference from the first
    // Manifest can make its sibling Manifest eligible on the next pass.
    let digest = base64::engine::general_purpose::STANDARD.encode([0_u8; 32]);
    let xml = format!(
        r##"<ds:Signature xmlns:ds="{XMLDSIG_NS}"><ds:Object Id="outer"><ds:Manifest><ds:Reference URI="#inner"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:Manifest></ds:Object><ds:Object Id="inner"><ds:Manifest><ds:Reference URI="#payload"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:Manifest></ds:Object></ds:Signature>"##
    );
    let document = XmlDocument::parse(xml).expect("nested Manifest fixture must parse");
    document.with_view(|view| {
        let signature = view.document().root_element();
        let mut objects = signature.children().filter(Node::is_element);
        let outer = objects.next().expect("outer Object");
        let inner = objects.next().expect("inner Object");
        let policy = crate::policy::VerificationPolicy::default();
        let budgets = VerificationOperationBudgets::with_transforms(
            &policy,
            TransformExecutionBudget::from_resources(&policy.resources),
            None,
        );
        let operation = OperationExecutionContext::new(
            &policy,
            &budgets,
            Some((view.identity(), view.generation())),
        );
        operation.authenticate(view.node_identity(outer));
        let mut processed = HashSet::new();
        let mut remaining = 2;
        let mut next_index = 0;
        let mut xpath_budget = XPathSignatureParseBudget::default();

        let first = parse_manifest_references(
            signature,
            &operation,
            view,
            &mut ManifestDiscoveryState {
                processed: &mut processed,
                remaining_capacity: &mut remaining,
                next_reference_index: &mut next_index,
                xpath_parse: &mut xpath_budget,
            },
            None,
        )
        .expect("outer Manifest must be discovered");
        assert_eq!(first.references.len(), 1);
        assert_eq!(first.references[0].reference.uri.as_deref(), Some("#inner"));

        operation.authenticate(view.node_identity(inner));
        let second = parse_manifest_references(
            signature,
            &operation,
            view,
            &mut ManifestDiscoveryState {
                processed: &mut processed,
                remaining_capacity: &mut remaining,
                next_reference_index: &mut next_index,
                xpath_parse: &mut xpath_budget,
            },
            None,
        )
        .expect("newly authenticated sibling Manifest must remain eligible");
        assert_eq!(second.references.len(), 1);
        assert_eq!(
            second.references[0].reference.uri.as_deref(),
            Some("#payload")
        );
    });
}

#[test]
fn manifest_reference_limit_includes_signed_info_references() {
    // The per-signature ceiling is shared by core and authenticated
    // Manifest references; enabling Manifest processing must not reset it.
    let xml = signature_with_manifest_xml(true);
    let reference_start = xml
        .find(r##"<ds:Reference URI="#manifest">"##)
        .expect("fixture SignedInfo must reference the Manifest");
    let reference_end = xml[reference_start..]
        .find("</ds:Reference>")
        .map(|offset| reference_start + offset + "</ds:Reference>".len())
        .expect("fixture SignedInfo Reference must be closed");
    let repeated = xml[reference_start..reference_end].repeat(MAX_REFERENCES_PER_SIGNATURE);
    let xml = format!(
        "{}{repeated}{}",
        &xml[..reference_start],
        &xml[reference_end..]
    );

    let error = VerifyContext::new()
        .key(&AcceptingKey)
        .process_manifests(true)
        .verify(&xml)
        .expect_err("one Manifest Reference must exceed the exhausted signature-wide limit");

    assert!(matches!(
        error,
        SignatureVerificationPipelineError::InvalidStructure {
            reason: "signed Manifests exceed the per-signature Reference limit"
        }
    ));
}

#[test]
fn configured_reference_limit_is_shared_with_manifests() {
    // Lowering the operation policy must lower the aggregate SignedInfo and
    // Manifest capacity rather than falling back to the crate hard limit.
    let policy = crate::policy::VerificationPolicy {
        manifest_processing: crate::policy::ManifestProcessing::Process,
        resources: crate::policy::ResourcePolicy {
            max_references: 1,
            ..crate::policy::ResourcePolicy::default()
        },
        ..crate::policy::VerificationPolicy::default()
    };

    let error = VerifyContext::new()
        .key(&AcceptingKey)
        .policy(policy)
        .verify(&signature_with_manifest_xml(true))
        .expect_err("Manifest must exceed the caller-selected aggregate limit");
    assert!(matches!(
        error,
        SignatureVerificationPipelineError::InvalidStructure {
            reason: "signed Manifests exceed the per-signature Reference limit"
        }
    ));
}

#[test]
fn retrieval_method_materializes_single_x509_data_subtree() {
    for uri in [
        "#target",
        "#xpointer(id('target'))",
        "#xpointer(id(&quot;target&quot;))",
    ] {
        for target_xml in [
            r#"<ds:X509Data Id="target"><ds:X509SubjectName>CN=leaf</ds:X509SubjectName></ds:X509Data>"#,
            r#"<holder Id="target"><ds:X509Data><ds:X509SubjectName>CN=leaf</ds:X509SubjectName></ds:X509Data></holder>"#,
        ] {
            let xml = format!(
                r#"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:KeyInfo><ds:RetrievalMethod URI="{uri}" Type="http://www.w3.org/2000/09/xmldsig#X509Data"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>ancestor-or-self::ds:X509Data</ds:XPath></ds:Transform></ds:Transforms></ds:RetrievalMethod></ds:KeyInfo>{target_xml}</root>"#
            );
            let document = Document::parse(&xml).unwrap();
            let key_info_node = document
                .descendants()
                .find(|node| node.has_tag_name((XMLDSIG_NS, "KeyInfo")))
                .unwrap();
            let mut key_info = parse_key_info(key_info_node).unwrap();
            let resolver = UriReferenceResolver::new(&document);

            materialize_retrieval_methods(
                &mut key_info,
                &resolver,
                UriTypeSet::SAME_DOCUMENT,
                None,
                crate::provider::default_provider(),
            )
            .expect("XPath filter must produce one X509Data-rooted node-set");
            assert!(matches!(
                key_info.sources.as_slice(),
                [super::super::parse::KeyInfoSource::X509Data(info)]
                    if info.subject_names == ["CN=leaf"]
            ));
        }
    }
}

fn retrieval_method_xpath_signature() -> String {
    format!(
        r##"<root xmlns:ds="{XMLDSIG_NS}">
              <payload Id="payload">ok</payload>
              <ds:Signature>
                <ds:SignedInfo>
                  <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                  <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                  <ds:Reference URI="#payload">
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>
                  </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>AQ==</ds:SignatureValue>
                <ds:KeyInfo>
                  <ds:RetrievalMethod URI="#target" Type="http://www.w3.org/2000/09/xmldsig#X509Data">
                    <ds:Transforms><ds:Transform Algorithm="{XPATH_TRANSFORM_URI}">
                      <ds:XPath>ancestor-or-self::ds:X509Data</ds:XPath>
                    </ds:Transform></ds:Transforms>
                  </ds:RetrievalMethod>
                </ds:KeyInfo>
              </ds:Signature>
              <holder Id="target"><ds:X509Data><ds:X509SubjectName>CN=leaf</ds:X509SubjectName></ds:X509Data></holder>
            </root>"##
    )
}

#[test]
fn retrieval_method_xpath_uses_signature_expression_budget() {
    // RetrievalMethod XPath belongs to the same untrusted Signature as
    // Reference XPath and must not receive a separate parse allowance.
    let mut policy = crate::policy::VerificationPolicy::default();
    policy.resources.max_xpath_expressions = 0;

    let error = VerifyContext::new()
        .policy(policy)
        .verify(&retrieval_method_xpath_signature())
        .expect_err("RetrievalMethod XPath must consume the signature parse budget");

    assert!(
        matches!(
            &error,
            SignatureVerificationPipelineError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: "XPath expressions",
                    maximum: 0,
                    actual: 1,
                }
            )
        ),
        "unexpected error: {error:?}"
    );
}

#[test]
fn retrieval_method_xpath_obeys_expression_byte_limit() {
    // Edge whitespace is semantically harmless for this restricted shape,
    // but its raw untrusted bytes still belong to the operation budget.
    let expression = "ancestor-or-self::ds:X509Data";
    let padded_expression = format!("  {expression}  ");
    let xml = retrieval_method_xpath_signature().replace(expression, &padded_expression);
    let mut policy = crate::policy::VerificationPolicy::default();
    policy.resources.max_xpath_expression_bytes = expression.len();

    let error = VerifyContext::new()
        .policy(policy)
        .verify(&xml)
        .expect_err("RetrievalMethod XPath must obey the expression byte limit");

    assert!(
        matches!(
            &error,
            SignatureVerificationPipelineError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: "XPath expression bytes",
                    maximum,
                    actual,
                }
            ) if *maximum == expression.len() && *actual == padded_expression.len()
        ),
        "unexpected error: {error:?}"
    );
}

#[test]
fn retrieval_method_xpath_obeys_expression_complexity_limit() {
    // Recognizing a fixed safe predicate must not bypass the common XPath
    // complexity policy applied to every expression in the signature.
    let mut policy = crate::policy::VerificationPolicy::default();
    policy.resources.max_xpath_expression_complexity = 0;

    let error = VerifyContext::new()
        .policy(policy)
        .verify(&retrieval_method_xpath_signature())
        .expect_err("RetrievalMethod XPath must obey the complexity limit");

    assert!(
        matches!(
            &error,
            SignatureVerificationPipelineError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: "XPath expression complexity",
                    maximum: 0,
                    actual,
                }
            ) if *actual > 0
        ),
        "unexpected error: {error:?}"
    );
}

#[test]
fn retrieval_method_xpath_uses_node_filter_work_budget() {
    // Attribute and namespace XPath nodes participate in filtering even
    // though the optimized X509Data locator scans only tree descendants.
    let mut policy = crate::policy::VerificationPolicy::default();
    policy.resources.max_node_set_filter_work = 4;
    let xml = retrieval_method_xpath_signature().replace(
        "<holder Id=\"target\">",
        "<holder Id=\"target\" role=\"signing\" xmlns:metadata=\"urn:metadata\">",
    );

    let error = VerifyContext::new()
        .policy(policy)
        .verify(&xml)
        .expect_err("RetrievalMethod XPath must consume node-filter work");

    assert!(
        matches!(
            &error,
            SignatureVerificationPipelineError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::NODE_SET_FILTER_WORK,
                    maximum: 4,
                    actual,
                }
            ) if *actual > 4
        ),
        "unexpected error: {error:?}"
    );
}

#[test]
fn retrieval_method_xpath_charges_every_context_to_evaluation_work() {
    // The optimized predicate avoids a generic XPath engine, but every
    // attribute and namespace context still consumes evaluation work.
    let mut policy = crate::policy::VerificationPolicy::default();
    policy.resources.max_xpath_evaluation_work = 4;
    let xml = retrieval_method_xpath_signature().replace(
        "<holder Id=\"target\">",
        "<holder Id=\"target\" role=\"signing\" xmlns:metadata=\"urn:metadata\">",
    );

    let error = VerifyContext::new()
        .policy(policy)
        .verify(&xml)
        .expect_err("RetrievalMethod XPath must charge every evaluation context");

    assert!(matches!(
        error,
        SignatureVerificationPipelineError::Policy(
            crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XPATH_EVALUATION_WORK,
                maximum: 4,
                actual,
            }
        ) if actual > 4
    ));
}

#[test]
fn retrieval_method_xpath_obeys_namespace_binding_limit() {
    // The specialized RetrievalMethod path must retain the XPath element's
    // in-scope namespaces and enforce the same limit as ordinary XPath.
    let mut policy = crate::policy::VerificationPolicy::default();
    policy.resources.max_xpath_namespace_bindings = 0;

    let error = VerifyContext::new()
        .policy(policy)
        .verify(&retrieval_method_xpath_signature())
        .expect_err("RetrievalMethod XPath namespaces must obey the binding limit");

    assert!(matches!(
        error,
        SignatureVerificationPipelineError::Policy(
            crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XPATH_NAMESPACE_BINDINGS,
                maximum: 0,
                actual,
            }
        ) if actual > 0
    ));
}

#[test]
fn retrieval_method_xpath_obeys_namespace_byte_limit() {
    // Prefix and URI bytes retained from the XPath namespace axis consume
    // the same per-expression byte budget as an ordinary XPath transform.
    let mut policy = crate::policy::VerificationPolicy::default();
    policy.resources.max_xpath_namespace_bytes = 0;

    let error = VerifyContext::new()
        .policy(policy)
        .verify(&retrieval_method_xpath_signature())
        .expect_err("RetrievalMethod XPath namespaces must obey the byte limit");

    assert!(matches!(
        error,
        SignatureVerificationPipelineError::Policy(
            crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XPATH_NAMESPACE_BYTES,
                maximum: 0,
                actual,
            }
        ) if actual > 0
    ));
}

#[test]
fn retrieval_method_xpath_obeys_context_evaluation_limit() {
    // A bare fragment includes attribute and namespace XPath nodes in
    // addition to the four tree nodes below. Tree-only accounting would
    // incorrectly admit this input at the configured ceiling.
    let mut policy = crate::policy::VerificationPolicy::default();
    policy.resources.max_xpath_context_evaluations = 4;
    let xml = retrieval_method_xpath_signature().replace(
        "<holder Id=\"target\">",
        "<holder Id=\"target\" role=\"signing\" xmlns:metadata=\"urn:metadata\">",
    );

    let error = VerifyContext::new()
        .policy(policy)
        .verify(&xml)
        .expect_err("RetrievalMethod XPath contexts must obey the evaluation limit");

    assert!(matches!(
        error,
        SignatureVerificationPipelineError::Policy(
            crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XPATH_CONTEXT_EVALUATIONS,
                maximum: 4,
                actual,
            }
        ) if actual > 4
    ));
}

#[test]
fn retrieval_method_materializes_direct_untransformed_x509_data() {
    // A typed RetrievalMethod may point directly at the XML structure it
    // identifies; no transform is needed when X509Data is the URI root.
    let xml = r##"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <ds:KeyInfo><ds:RetrievalMethod URI="#target" Type="http://www.w3.org/2000/09/xmldsig#X509Data"/></ds:KeyInfo>
          <ds:X509Data Id="target"><ds:X509SubjectName>CN=leaf</ds:X509SubjectName></ds:X509Data>
        </root>"##;
    let document = Document::parse(xml).unwrap();
    let key_info_node = document
        .descendants()
        .find(|node| node.has_tag_name((XMLDSIG_NS, "KeyInfo")))
        .unwrap();
    let mut key_info = parse_key_info(key_info_node).unwrap();

    materialize_retrieval_methods(
        &mut key_info,
        &UriReferenceResolver::new(&document),
        UriTypeSet::SAME_DOCUMENT,
        None,
        crate::provider::default_provider(),
    )
    .expect("a direct X509Data target needs no transform");
    assert!(matches!(
        key_info.sources.as_slice(),
        [super::super::parse::KeyInfoSource::X509Data(info)]
            if info.subject_names == ["CN=leaf"]
    ));
}

#[test]
fn retrieval_method_respects_configured_same_document_id_semantics() {
    // RetrievalMethod is another consumer of same-document URIs and must
    // not bypass the grammar selected for normal Reference dereferencing.
    fn materialize(
        uri: &str,
        id: &str,
        semantics: crate::policy::SameDocumentIdSemantics,
    ) -> Result<RetrievalMaterialization, SignatureVerificationPipelineError> {
        let xml = format!(
            r#"<root xmlns:ds="{XMLDSIG_NS}">
                  <ds:KeyInfo><ds:RetrievalMethod URI="{uri}" Type="{XMLDSIG_NS}X509Data"/></ds:KeyInfo>
                  <ds:X509Data Id="{id}"><ds:X509SubjectName>CN=leaf</ds:X509SubjectName></ds:X509Data>
                </root>"#
        );
        let document = Document::parse(&xml).unwrap();
        let key_info_node = document
            .descendants()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "KeyInfo")))
            .unwrap();
        let mut key_info = parse_key_info(key_info_node).unwrap();
        let resolver =
            UriReferenceResolver::new(&document).with_same_document_id_semantics(semantics);

        materialize_retrieval_methods(
            &mut key_info,
            &resolver,
            UriTypeSet::SAME_DOCUMENT,
            None,
            crate::provider::default_provider(),
        )
    }

    assert!(
        materialize(
            "#12345",
            "12345",
            crate::policy::SameDocumentIdSemantics::Specification,
        )
        .is_err(),
        "the standards mode must reject a non-NCName bare fragment"
    );
    assert!(
        materialize(
            "#visa'3d",
            "visa'3d",
            crate::policy::SameDocumentIdSemantics::XmlSecBarename,
        )
        .is_err(),
        "the donor barename wrapper cannot represent an apostrophe"
    );
    assert!(
        materialize(
            "#visa'3d",
            "visa'3d",
            crate::policy::SameDocumentIdSemantics::XmlSecVisa3d,
        )
        .is_ok(),
        "Visa3D mode resolves the registered ID without an XPointer literal"
    );
}

#[test]
fn raw_x509_retrieval_method_uses_inherited_xml_base() {
    // RetrievalMethod URI is an attribute URI reference, so XML Base uses
    // the effective base of the element bearing that attribute.
    const RAW_X509_TYPE: &str = "http://www.w3.org/2000/09/xmldsig#rawX509Certificate";
    let xml = format!(
        r#"<root xml:base="https://example.test/keys/nested/" xmlns:ds="{XMLDSIG_NS}">
                <ds:KeyInfo><ds:RetrievalMethod URI="../signer.der" Type="{RAW_X509_TYPE}"/></ds:KeyInfo>
            </root>"#
    );
    let document = Document::parse(&xml).unwrap();
    let key_info_node = document
        .descendants()
        .find(|node| node.has_tag_name((XMLDSIG_NS, "KeyInfo")))
        .unwrap();
    let mut key_info = parse_key_info(key_info_node).unwrap();
    let certificate = include_bytes!(
        "../../../tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/certs/balor.der"
    )
    .to_vec();
    let resources = HashMap::from([(
        "https://example.test/keys/signer.der".to_string(),
        certificate,
    )]);
    let resolver = UriReferenceResolver::new(&document).with_external_resources(&resources);

    materialize_retrieval_methods(
        &mut key_info,
        &resolver,
        UriTypeSet::ALL,
        None,
        crate::provider::default_provider(),
    )
    .expect("RetrievalMethod should resolve against inherited xml:base");

    assert!(matches!(
        key_info.sources.as_slice(),
        [super::super::parse::KeyInfoSource::X509Data(info)]
            if info.certificates.len() == 1
    ));
}

#[test]
fn retrieval_method_requires_xpath_for_x509_data_below_uri_root() {
    // Without a transform the dereferenced holder, not its descendant,
    // is the result and therefore cannot masquerade as typed X509Data.
    let xml = r##"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <ds:KeyInfo><ds:RetrievalMethod URI="#target" Type="http://www.w3.org/2000/09/xmldsig#X509Data"/></ds:KeyInfo>
          <holder Id="target"><ds:X509Data><ds:X509SubjectName>CN=leaf</ds:X509SubjectName></ds:X509Data></holder>
        </root>"##;
    let document = Document::parse(xml).unwrap();
    let key_info_node = document
        .descendants()
        .find(|node| node.has_tag_name((XMLDSIG_NS, "KeyInfo")))
        .unwrap();
    let mut key_info = parse_key_info(key_info_node).unwrap();

    let error = materialize_retrieval_methods(
        &mut key_info,
        &UriReferenceResolver::new(&document),
        UriTypeSet::SAME_DOCUMENT,
        None,
        crate::provider::default_provider(),
    )
    .expect_err("a wrapper target requires an explicit selection transform");
    assert!(matches!(
        error,
        SignatureVerificationPipelineError::InvalidStructure {
            reason: "untransformed X509Data RetrievalMethod must target X509Data directly"
        }
    ));
}

#[test]
fn retrieval_method_rejects_target_inside_external_x509_data_ancestor() {
    // XPath filtering cannot add an ancestor that was outside the URI's
    // dereferenced node-set, so this result is not rooted at X509Data.
    let xml = r##"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <ds:KeyInfo><ds:RetrievalMethod URI="#target" Type="http://www.w3.org/2000/09/xmldsig#X509Data"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>ancestor-or-self::ds:X509Data</ds:XPath></ds:Transform></ds:Transforms></ds:RetrievalMethod></ds:KeyInfo>
          <ds:X509Data><ds:X509SubjectName Id="target">CN=leaf</ds:X509SubjectName></ds:X509Data>
        </root>"##;
    let document = Document::parse(xml).unwrap();
    let key_info_node = document
        .descendants()
        .find(|node| node.has_tag_name((XMLDSIG_NS, "KeyInfo")))
        .unwrap();
    let mut key_info = parse_key_info(key_info_node).unwrap();

    let error = materialize_retrieval_methods(
        &mut key_info,
        &UriReferenceResolver::new(&document),
        UriTypeSet::SAME_DOCUMENT,
        None,
        crate::provider::default_provider(),
    )
    .expect_err("filter output without an X509Data root must be rejected");
    assert!(matches!(
        error,
        SignatureVerificationPipelineError::InvalidStructure {
            reason: "X509Data RetrievalMethod selected no X509Data element"
        }
    ));
}

#[test]
fn retrieval_method_rejects_ambiguous_x509_data_relation() {
    // A transformed result with multiple X509Data roots is not one KeyInfo child.
    let xml = r##"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <ds:KeyInfo><ds:RetrievalMethod URI="#target" Type="http://www.w3.org/2000/09/xmldsig#X509Data"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>ancestor-or-self::ds:X509Data</ds:XPath></ds:Transform></ds:Transforms></ds:RetrievalMethod></ds:KeyInfo>
          <holder Id="target"><ds:X509Data/><ds:X509Data/></holder>
        </root>"##;
    let document = Document::parse(xml).unwrap();
    let key_info_node = document
        .descendants()
        .find(|node| node.has_tag_name((XMLDSIG_NS, "KeyInfo")))
        .unwrap();
    let mut key_info = parse_key_info(key_info_node).unwrap();

    let error = materialize_retrieval_methods(
        &mut key_info,
        &UriReferenceResolver::new(&document),
        UriTypeSet::SAME_DOCUMENT,
        None,
        crate::provider::default_provider(),
    )
    .expect_err("multiple transformed X509Data roots must be rejected");
    assert!(matches!(
        error,
        SignatureVerificationPipelineError::InvalidStructure {
            reason: "X509Data RetrievalMethod selected multiple X509Data elements"
        }
    ));
}

#[test]
fn retrieval_method_materialization_preserves_key_info_order() {
    // Replacing the source in place keeps a later fallback behind the
    // retrieved key material for first-match resolvers.
    let xml = r##"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <ds:KeyInfo>
            <ds:RetrievalMethod URI="#target" Type="http://www.w3.org/2000/09/xmldsig#X509Data"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>ancestor-or-self::ds:X509Data</ds:XPath></ds:Transform></ds:Transforms></ds:RetrievalMethod>
            <ds:KeyName>fallback</ds:KeyName>
          </ds:KeyInfo>
          <holder Id="target"><ds:X509Data><ds:X509SubjectName>CN=leaf</ds:X509SubjectName></ds:X509Data></holder>
        </root>"##;
    let document = Document::parse(xml).unwrap();
    let key_info_node = document
        .descendants()
        .find(|node| node.has_tag_name((XMLDSIG_NS, "KeyInfo")))
        .unwrap();
    let mut key_info = parse_key_info(key_info_node).unwrap();

    materialize_retrieval_methods(
        &mut key_info,
        &UriReferenceResolver::new(&document),
        UriTypeSet::SAME_DOCUMENT,
        None,
        crate::provider::default_provider(),
    )
    .unwrap();
    assert!(matches!(
        key_info.sources.as_slice(),
        [
            super::super::parse::KeyInfoSource::X509Data(_),
            super::super::parse::KeyInfoSource::KeyName(name)
        ] if name == "fallback"
    ));
}

#[test]
fn retrieval_method_materialization_bounds_repeated_sources() {
    // Repeating one allowed certificate must not multiply parsing and clones
    // before SignatureValue validation.
    const RAW_X509_TYPE: &str = "http://www.w3.org/2000/09/xmldsig#rawX509Certificate";
    let certificate = include_bytes!(
        "../../../tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/certs/balor.der"
    )
    .to_vec();
    let resources = HashMap::from([("urn:certificate".to_string(), certificate)]);
    let mut key_info = KeyInfo {
        sources: (0..=64)
            .map(|_| super::super::parse::KeyInfoSource::RetrievalMethod {
                uri: "urn:certificate".into(),
                resource_type: Some(RAW_X509_TYPE.into()),
                transforms: RetrievalMethodTransforms::None,
            })
            .collect(),
    };
    let document = Document::parse("<root/>").unwrap();
    let resolver = UriReferenceResolver::new(&document).with_external_resources(&resources);

    let error = materialize_retrieval_methods(
        &mut key_info,
        &resolver,
        UriTypeSet::ALL,
        None,
        crate::provider::default_provider(),
    )
    .expect_err("retrieval count must be bounded before materialization");
    assert!(matches!(
        error,
        SignatureVerificationPipelineError::InvalidStructure {
            reason: "KeyInfo contains too many RetrievalMethod elements"
        }
    ));
}

#[test]
fn key_info_reference_materializes_an_allowed_empty_uri() {
    // Empty URI is a same-document Reference URI. Element-valued
    // KeyInfoReference dereferencing therefore selects a KeyInfo document
    // element rather than consulting the external-resource map.
    let document = XmlDocument::parse(format!(
        r#"<ds:KeyInfo xmlns:ds="{XMLDSIG_NS}"><ds:KeyName>root-key</ds:KeyName></ds:KeyInfo>"#
    ))
    .unwrap();
    let mut key_info = KeyInfo {
        sources: vec![super::super::parse::KeyInfoSource::KeyInfoReference { uri: String::new() }],
    };
    let mut policy = crate::policy::VerificationPolicy::default();
    policy
        .key_sources
        .insert(crate::policy::KeySourceKind::KeyInfoReference);
    let mut xpath_parse_budget = XPathSignatureParseBudget::default();
    let execution_budget = TransformExecutionBudget::from_resources(&policy.resources);
    let mut budgets = RetrievalMaterializationBudgets {
        key_info_parse: &RefCell::new(super::super::parse::KeyInfoParseUsage::new(
            &policy.resources,
        )),
        xpath_parse: &mut xpath_parse_budget,
        execution: &execution_budget,
        resources: &policy.resources,
        certificate_signature_algorithms: policy
            .key_trust
            .certificate_signature_algorithms
            .as_ref(),
        xml_backend: crate::XmlBackend::default(),
    };
    let mut materialization = KeyInfoMaterializationState::default();

    document
        .with_view(|view| {
            materialize_key_info_references_with_budgets(
                &mut key_info,
                &UriReferenceResolver::with_document_view(view, &[]),
                &policy,
                crate::provider::default_provider(),
                &mut budgets,
                &mut materialization,
            )?;
            Ok::<_, SignatureVerificationPipelineError>(())
        })
        .unwrap();

    assert!(matches!(
        key_info.sources.as_slice(),
        [super::super::parse::KeyInfoSource::KeyName(name)] if name == "root-key"
    ));
}

#[test]
fn raw_certificate_retrieval_retains_spent_operation_work() {
    // Raw DER retrieval must not bypass the account used by XML KeyInfo parsing.
    let pair = rcgen::KeyPair::generate().expect("test key generation");
    let cert = rcgen::CertificateParams::new(Vec::<String>::new())
        .expect("empty SAN list")
        .self_signed(&pair)
        .expect("test certificate signing");
    let external = HashMap::from([("urn:cert".to_owned(), cert.der().to_vec())]);
    let document = Document::parse("<root/>").expect("test XML");
    let resolver = UriReferenceResolver::new(&document).with_external_resources(&external);
    let mut policy = crate::policy::VerificationPolicy::default();
    policy.resources.max_x509_work = 1;
    policy.uris.retrieval_methods = UriTypeSet::ALL;
    let usage = RefCell::new(super::super::parse::KeyInfoParseUsage::new(
        &policy.resources,
    ));
    usage
        .borrow()
        .certificates
        .memory()
        .charge_work(1)
        .expect("spend allowance");
    let mut xpath = XPathSignatureParseBudget::from_resources(&policy.resources);
    let execution = TransformExecutionBudget::from_resources(&policy.resources);
    let mut budgets = RetrievalMaterializationBudgets {
        key_info_parse: &usage,
        xpath_parse: &mut xpath,
        execution: &execution,
        resources: &policy.resources,
        certificate_signature_algorithms: None,
        xml_backend: crate::XmlBackend::default(),
    };
    let mut info = KeyInfo {
        sources: vec![super::super::parse::KeyInfoSource::RetrievalMethod {
            uri: "urn:cert".into(),
            resource_type: Some("http://www.w3.org/2000/09/xmldsig#rawX509Certificate".into()),
            transforms: RetrievalMethodTransforms::None,
        }],
    };
    let result = materialize_retrieval_methods_with_budgets(
        &mut info,
        &resolver,
        &policy,
        crate::provider::default_provider(),
        &mut budgets,
        &mut 0,
    );
    assert!(matches!(
        result,
        Err(SignatureVerificationPipelineError::Policy(
            crate::policy::PolicyViolation::ResourceLimitExceeded {
                resource: crate::policy::resource_name::X509_WORK,
                maximum: 1,
            }
        ))
    ));
}

#[test]
fn empty_key_info_reference_participates_in_cycle_detection() {
    // Empty URI resolves to the owning document's root KeyInfo. It must
    // recurse through the same traversal state rather than leave the
    // self-reference materialized and bypass cycle/depth enforcement.
    let document = XmlDocument::parse(format!(
            r#"<ds:KeyInfo xmlns:ds="{XMLDSIG_NS}" xmlns:dsig11="http://www.w3.org/2009/xmldsig11#"><dsig11:KeyInfoReference URI=""/></ds:KeyInfo>"#
        ))
        .unwrap();
    let mut key_info = KeyInfo {
        sources: vec![super::super::parse::KeyInfoSource::KeyInfoReference { uri: String::new() }],
    };
    let mut policy = crate::policy::VerificationPolicy::default();
    policy
        .key_sources
        .insert(crate::policy::KeySourceKind::KeyInfoReference);
    let mut xpath_parse_budget = XPathSignatureParseBudget::default();
    let execution_budget = TransformExecutionBudget::from_resources(&policy.resources);
    let mut budgets = RetrievalMaterializationBudgets {
        key_info_parse: &RefCell::new(super::super::parse::KeyInfoParseUsage::new(
            &policy.resources,
        )),
        xpath_parse: &mut xpath_parse_budget,
        execution: &execution_budget,
        resources: &policy.resources,
        certificate_signature_algorithms: policy
            .key_trust
            .certificate_signature_algorithms
            .as_ref(),
        xml_backend: crate::XmlBackend::default(),
    };
    let mut materialization = KeyInfoMaterializationState::default();

    let error = document
        .with_view(|view| {
            materialize_key_info_references_with_budgets(
                &mut key_info,
                &UriReferenceResolver::with_document_view(view, &[]),
                &policy,
                crate::provider::default_provider(),
                &mut budgets,
                &mut materialization,
            )
        })
        .expect_err("empty-URI self-reference must be rejected as a cycle");

    assert!(matches!(
        error,
        SignatureVerificationPipelineError::InvalidStructure {
            reason: "KeyInfoReference cycle detected"
        }
    ));
}

#[test]
fn key_info_materialization_shares_candidate_work_across_source_kinds() {
    // The reference, nested RetrievalMethod, and resulting certificate are
    // three units of materialization work in one operation.
    const RAW_X509_TYPE: &str = "http://www.w3.org/2000/09/xmldsig#rawX509Certificate";
    let document = XmlDocument::parse(format!(
            r#"<root xmlns:ds="{XMLDSIG_NS}" xmlns:dsig11="http://www.w3.org/2009/xmldsig11#"><ds:KeyInfo ID="target"><ds:RetrievalMethod URI="signer.der" Type="{RAW_X509_TYPE}"/></ds:KeyInfo></root>"#
        ))
        .unwrap();
    let certificate = include_bytes!(
        "../../../tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/certs/balor.der"
    )
    .to_vec();
    let resources = HashMap::from([("signer.der".to_owned(), certificate)]);
    let mut key_info = KeyInfo {
        sources: vec![super::super::parse::KeyInfoSource::KeyInfoReference {
            uri: "#target".into(),
        }],
    };
    let mut policy = crate::policy::VerificationPolicy::default();
    policy
        .key_sources
        .insert(crate::policy::KeySourceKind::KeyInfoReference);
    policy.uris.retrieval_methods = UriTypeSet::ALL;
    policy.resources.max_key_candidates = 2;
    let mut xpath_parse_budget = XPathSignatureParseBudget::default();
    let execution_budget = TransformExecutionBudget::from_resources(&policy.resources);
    let mut budgets = RetrievalMaterializationBudgets {
        key_info_parse: &RefCell::new(super::super::parse::KeyInfoParseUsage::new(
            &policy.resources,
        )),
        xpath_parse: &mut xpath_parse_budget,
        execution: &execution_budget,
        resources: &policy.resources,
        certificate_signature_algorithms: policy
            .key_trust
            .certificate_signature_algorithms
            .as_ref(),
        xml_backend: crate::XmlBackend::default(),
    };
    let mut materialization = KeyInfoMaterializationState::default();

    let error = document
        .with_view(|view| {
            let resolver = UriReferenceResolver::with_document_view(view, &[])
                .with_external_resources(&resources);
            let mut outcome = materialize_key_info_references_with_budgets(
                &mut key_info,
                &resolver,
                &policy,
                crate::provider::default_provider(),
                &mut budgets,
                &mut materialization,
            )?;
            outcome.merge(materialize_retrieval_methods_with_budgets(
                &mut key_info,
                &resolver,
                &policy,
                crate::provider::default_provider(),
                &mut budgets,
                &mut materialization.candidate_work,
            )?);
            Ok::<_, DsigError>(outcome)
        })
        .expect_err("all materializers must share the candidate-work limit");

    assert!(matches!(
        error,
        DsigError::Policy(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::KEY_CANDIDATES,
            maximum: 2,
            actual: 3,
        })
    ));
}

#[test]
fn public_key_info_materialization_binds_external_resource_policy() {
    // Public helpers must not inherit the resolver's permissive hard-limit
    // budget when the operation policy selects a stricter byte ceiling.
    let document = Document::parse("<root/>").unwrap();
    let external = format!(
        r#"<ds:KeyInfo xmlns:ds="{XMLDSIG_NS}"><ds:KeyName>external</ds:KeyName></ds:KeyInfo>"#
    );
    let resources = HashMap::from([("key.xml".to_owned(), external.into_bytes())]);
    let resolver = UriReferenceResolver::new(&document).with_external_resources(&resources);
    let mut key_info = KeyInfo {
        sources: vec![super::super::parse::KeyInfoSource::KeyInfoReference {
            uri: "key.xml".into(),
        }],
    };
    let mut policy = crate::policy::VerificationPolicy::default();
    policy
        .key_sources
        .insert(crate::policy::KeySourceKind::KeyInfoReference);
    policy.uris.key_info_references = UriTypeSet::ALL;
    policy.resources.max_external_resource_bytes = 0;

    let error = materialize_verification_key_info_references(
        &mut key_info,
        resolver,
        &policy,
        crate::provider::default_provider(),
        crate::XmlBackend::default(),
    )
    .expect_err("policy must reject non-empty external KeyInfo bytes");

    assert!(matches!(
        error,
        DsigError::Policy(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
            maximum: 0,
            actual,
        }) if actual == resources["key.xml"].len()
    ));
}

#[cfg(all(feature = "xml-backend-roxmltree", feature = "xml-backend-xmloxide"))]
#[test]
fn public_key_info_materialization_uses_the_selected_backend() {
    // Public materialization is a standalone parse boundary. Its backend
    // must be caller-selected just like the complete sign/verify pipeline.
    let external = format!(
        r#"<ds:KeyInfo xmlns:ds="{XMLDSIG_NS}"><ds:KeyName>external</ds:KeyName></ds:KeyInfo>"#
    );
    let resources = HashMap::from([("key.xml".to_owned(), external.into_bytes())]);
    let document = Document::parse("<root/>").unwrap();

    for backend in [crate::XmlBackend::Xmloxide, crate::XmlBackend::Roxmltree] {
        let resolver = UriReferenceResolver::new(&document).with_external_resources(&resources);
        let mut key_info = KeyInfo {
            sources: vec![super::super::parse::KeyInfoSource::KeyInfoReference {
                uri: "key.xml".into(),
            }],
        };
        let mut policy = crate::policy::VerificationPolicy::default();
        policy
            .key_sources
            .insert(crate::policy::KeySourceKind::KeyInfoReference);
        policy.uris.key_info_references = UriTypeSet::ALL;

        materialize_verification_key_info_references(
            &mut key_info,
            resolver,
            &policy,
            crate::provider::default_provider(),
            backend,
        )
        .unwrap_or_else(|error| panic!("{backend:?} materialization failed: {error}"));

        assert!(matches!(
            key_info.sources.as_slice(),
            [super::super::parse::KeyInfoSource::KeyName(name)] if name == "external"
        ));
    }
}

#[test]
fn public_key_info_materialization_defers_nested_retrieval_failure() {
    // Metadata expansion must preserve an earlier usable source when a
    // later retrieval candidate fails. The complete operation reports the
    // deferred error only if key selection exhausts all usable sources.
    const RAW_X509_TYPE: &str = "http://www.w3.org/2000/09/xmldsig#rawX509Certificate";
    let external = format!(
        r#"<ds:KeyInfo xmlns:ds="{XMLDSIG_NS}"><ds:KeyName>usable</ds:KeyName><ds:RetrievalMethod URI="missing.der" Type="{RAW_X509_TYPE}"/></ds:KeyInfo>"#
    );
    let resources = HashMap::from([("key.xml".to_owned(), external.into_bytes())]);
    let document = Document::parse("<root/>").unwrap();

    for operation in ["signing", "verification"] {
        let resolver = UriReferenceResolver::new(&document).with_external_resources(&resources);
        let mut key_info = KeyInfo {
            sources: vec![super::super::parse::KeyInfoSource::KeyInfoReference {
                uri: "key.xml".into(),
            }],
        };
        match operation {
            "signing" => {
                let mut policy = crate::policy::SigningPolicy::default();
                policy.uris.key_info_references = UriTypeSet::ALL;
                policy.uris.retrieval_methods = UriTypeSet::ALL;
                materialize_signing_key_info_references(
                    &mut key_info,
                    resolver,
                    &policy,
                    crate::provider::default_provider(),
                    crate::XmlBackend::default(),
                )
            }
            "verification" => {
                let mut policy = crate::policy::VerificationPolicy::default();
                policy
                    .key_sources
                    .insert(crate::policy::KeySourceKind::KeyInfoReference);
                policy.uris.key_info_references = UriTypeSet::ALL;
                policy.uris.retrieval_methods = UriTypeSet::ALL;
                materialize_verification_key_info_references(
                    &mut key_info,
                    resolver,
                    &policy,
                    crate::provider::default_provider(),
                    crate::XmlBackend::default(),
                )
            }
            _ => unreachable!(),
        }
        .unwrap_or_else(|error| panic!("{operation} materialization failed: {error}"));

        assert!(matches!(
            key_info.sources.as_slice(),
            [super::super::parse::KeyInfoSource::KeyName(name)] if name == "usable"
        ));
    }
}

#[test]
fn public_key_info_materialization_binds_xpath_policy() {
    // Both public helpers must carry the caller's XPath parse limits into
    // RetrievalMethod transforms nested in an external KeyInfo document.
    let external = format!(
        r##"<ds:KeyInfo xmlns:ds="{XMLDSIG_NS}">
                <ds:RetrievalMethod URI="#target" Type="http://www.w3.org/2000/09/xmldsig#X509Data">
                    <ds:Transforms><ds:Transform Algorithm="{XPATH_TRANSFORM_URI}">
                        <ds:XPath>ancestor-or-self::ds:X509Data</ds:XPath>
                    </ds:Transform></ds:Transforms>
                </ds:RetrievalMethod>
                <ds:X509Data Id="target"><ds:X509SubjectName>CN=leaf</ds:X509SubjectName></ds:X509Data>
            </ds:KeyInfo>"##
    );
    let resources = HashMap::from([("key.xml".to_owned(), external.into_bytes())]);
    let document = Document::parse("<root/>").unwrap();

    for operation in ["signing", "verification"] {
        let resolver = UriReferenceResolver::new(&document).with_external_resources(&resources);
        let mut key_info = KeyInfo {
            sources: vec![super::super::parse::KeyInfoSource::KeyInfoReference {
                uri: "key.xml".into(),
            }],
        };
        let error = match operation {
            "signing" => {
                let mut policy = crate::policy::SigningPolicy::default();
                policy.uris.key_info_references = UriTypeSet::ALL;
                policy.resources.max_xpath_expressions = 0;
                materialize_signing_key_info_references(
                    &mut key_info,
                    resolver,
                    &policy,
                    crate::provider::default_provider(),
                    crate::XmlBackend::default(),
                )
            }
            "verification" => {
                let mut policy = crate::policy::VerificationPolicy::default();
                policy
                    .key_sources
                    .insert(crate::policy::KeySourceKind::KeyInfoReference);
                policy.uris.key_info_references = UriTypeSet::ALL;
                policy.resources.max_xpath_expressions = 0;
                materialize_verification_key_info_references(
                    &mut key_info,
                    resolver,
                    &policy,
                    crate::provider::default_provider(),
                    crate::XmlBackend::default(),
                )
            }
            _ => unreachable!(),
        }
        .expect_err("the public helper must enforce the supplied XPath expression limit");

        assert!(
            matches!(
                error,
                DsigError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XPATH_EXPRESSIONS,
                    maximum: 0,
                    actual: 1,
                })
            ),
            "unexpected {operation} error: {error:?}"
        );
    }
}

fn materialize_external_key_info_chain(
    terminal_reference: &str,
) -> Result<KeyInfo, SignatureVerificationPipelineError> {
    let a = format!(
        r##"<doc xmlns:ds="{XMLDSIG_NS}" xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">
                <ds:KeyInfo ID="root"><dsig11:KeyInfoReference URI="#next"/></ds:KeyInfo>
                <ds:KeyInfo ID="next"><dsig11:KeyInfoReference URI="b.xml#root"/></ds:KeyInfo>
            </doc>"##
    );
    let b = format!(
        r##"<doc xmlns:ds="{XMLDSIG_NS}" xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">
                <ds:KeyInfo ID="root"><dsig11:KeyInfoReference URI="#next"/></ds:KeyInfo>
                <ds:KeyInfo ID="next">{terminal_reference}</ds:KeyInfo>
            </doc>"##
    );
    let resources = HashMap::from([
        ("a.xml".to_owned(), a.into_bytes()),
        ("b.xml".to_owned(), b.into_bytes()),
    ]);
    let document = XmlDocument::parse("<root/>").unwrap();
    let mut key_info = KeyInfo {
        sources: vec![super::super::parse::KeyInfoSource::KeyInfoReference {
            uri: "a.xml#root".into(),
        }],
    };
    let mut policy = crate::policy::VerificationPolicy::default();
    policy
        .key_sources
        .insert(crate::policy::KeySourceKind::KeyInfoReference);
    policy.uris.key_info_references = UriTypeSet::ALL;
    let mut xpath_parse_budget = XPathSignatureParseBudget::default();
    let execution_budget = TransformExecutionBudget::from_resources(&policy.resources);
    let mut budgets = RetrievalMaterializationBudgets {
        key_info_parse: &RefCell::new(super::super::parse::KeyInfoParseUsage::new(
            &policy.resources,
        )),
        xpath_parse: &mut xpath_parse_budget,
        execution: &execution_budget,
        resources: &policy.resources,
        certificate_signature_algorithms: policy
            .key_trust
            .certificate_signature_algorithms
            .as_ref(),
        xml_backend: crate::XmlBackend::default(),
    };
    let mut materialization = KeyInfoMaterializationState::default();

    document.with_view(|view| {
        let resolver =
            UriReferenceResolver::with_document_view(view, &[]).with_external_resources(&resources);
        materialize_key_info_references_with_budgets(
            &mut key_info,
            &resolver,
            &policy,
            crate::provider::default_provider(),
            &mut budgets,
            &mut materialization,
        )?;
        Ok::<_, SignatureVerificationPipelineError>(())
    })?;
    Ok(key_info)
}

fn materialize_external_key_info_bytes_with_limit(
    encoded: Vec<u8>,
    maximum_document_bytes: usize,
) -> Result<KeyInfo, SignatureVerificationPipelineError> {
    let resources = HashMap::from([("key.xml".to_owned(), encoded)]);
    let document = XmlDocument::parse("<root/>").unwrap();
    let mut key_info = KeyInfo {
        sources: vec![super::super::parse::KeyInfoSource::KeyInfoReference {
            uri: "key.xml".into(),
        }],
    };
    let mut policy = crate::policy::VerificationPolicy::default();
    policy
        .key_sources
        .insert(crate::policy::KeySourceKind::KeyInfoReference);
    policy.uris.key_info_references = UriTypeSet::ALL;
    policy.resources.max_xml_document_bytes = maximum_document_bytes;
    let mut xpath_parse_budget = XPathSignatureParseBudget::default();
    let execution_budget = TransformExecutionBudget::from_resources(&policy.resources);
    let mut budgets = RetrievalMaterializationBudgets {
        key_info_parse: &RefCell::new(super::super::parse::KeyInfoParseUsage::new(
            &policy.resources,
        )),
        xpath_parse: &mut xpath_parse_budget,
        execution: &execution_budget,
        resources: &policy.resources,
        certificate_signature_algorithms: policy
            .key_trust
            .certificate_signature_algorithms
            .as_ref(),
        xml_backend: crate::XmlBackend::default(),
    };
    let mut materialization = KeyInfoMaterializationState::default();

    document.with_view(|view| {
        let resolver =
            UriReferenceResolver::with_document_view(view, &[]).with_external_resources(&resources);
        materialize_key_info_references_with_budgets(
            &mut key_info,
            &resolver,
            &policy,
            crate::provider::default_provider(),
            &mut budgets,
            &mut materialization,
        )?;
        Ok::<_, SignatureVerificationPipelineError>(())
    })?;
    Ok(key_info)
}

fn materialize_external_key_info_bytes(
    encoded: Vec<u8>,
) -> Result<KeyInfo, SignatureVerificationPipelineError> {
    materialize_external_key_info_bytes_with_limit(
        encoded,
        crate::hard_limits::XML_DOCUMENT_BYTE_CEILING,
    )
}

#[test]
fn external_key_info_reference_decodes_utf16_xml_octets() {
    // External XML follows the XML encoding declaration/BOM contract, not
    // the UTF-8-only contract of Rust strings passed by direct callers.
    let xml = format!(
        r#"<ds:KeyInfo xmlns:ds="{XMLDSIG_NS}"><ds:KeyName>utf16-key</ds:KeyName></ds:KeyInfo>"#
    );
    let mut encoded = vec![0xff, 0xfe];
    encoded.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
    let key_info = materialize_external_key_info_bytes(encoded)
        .expect("UTF-16 external KeyInfo must materialize");
    assert!(matches!(
        key_info.sources.as_slice(),
        [super::super::parse::KeyInfoSource::KeyName(name)] if name == "utf16-key"
    ));
}

#[test]
fn external_key_info_reference_rejects_malformed_xml_encoding() {
    // A BOM selecting UTF-16 must not permit a truncated code unit to reach
    // the XML parser under a misleading structural diagnostic.
    let error = materialize_external_key_info_bytes(vec![0xff, 0xfe, b'<'])
        .expect_err("truncated UTF-16 must be rejected during octet decoding");

    assert!(matches!(
        error,
        SignatureVerificationPipelineError::InvalidStructure {
            reason: "KeyInfoReference external resource has an invalid XML encoding"
        }
    ));
}

#[test]
fn external_key_info_reference_preserves_decoded_document_limit() {
    // Decoding can expand a compact single-byte resource beyond the XML document policy.
    // That is a typed policy failure, not malformed KeyInfo structure.
    let encoded = b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:KeyName>\xe9\xe9</ds:KeyName></ds:KeyInfo>".to_vec();
    let maximum = encoded.len();
    let error = materialize_external_key_info_bytes_with_limit(encoded, maximum)
        .expect_err("decoded XML expansion must retain resource-limit classification");

    assert!(matches!(
        error,
        SignatureVerificationPipelineError::Policy(
            crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_DOCUMENT,
                maximum: observed_maximum,
                actual,
            }
        ) if observed_maximum == maximum && actual > maximum
    ));
}

#[test]
fn key_info_reference_cycle_identity_includes_the_owning_resource() {
    // Equal fragment spellings in separate external documents are distinct
    // references and must not be rejected as a recursive cycle.
    let key_info = materialize_external_key_info_chain("<ds:KeyName>terminal</ds:KeyName>")
        .expect("cross-document duplicate fragments must materialize");
    assert!(matches!(
        key_info.sources.as_slice(),
        [super::super::parse::KeyInfoSource::KeyName(name)] if name == "terminal"
    ));
}

#[test]
fn key_info_reference_cycle_identity_survives_external_reparse() {
    // Returning to the same external resource must remain a cycle even
    // though each dereference creates a fresh owned XML document.
    let error =
        materialize_external_key_info_chain("<dsig11:KeyInfoReference URI=\"a.xml#root\"/>")
            .expect_err("a resource cycle must fail before exhausting depth");
    assert!(matches!(
        error,
        SignatureVerificationPipelineError::InvalidStructure {
            reason: "KeyInfoReference cycle detected"
        }
    ));
}

#[test]
fn retrieval_method_materialization_deduplicates_within_count_limit() {
    // Repeated references to the same raw certificate produce one parsed
    // key source rather than one certificate clone per XML element.
    const RAW_X509_TYPE: &str = "http://www.w3.org/2000/09/xmldsig#rawX509Certificate";
    let certificate = include_bytes!(
        "../../../tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/certs/balor.der"
    )
    .to_vec();
    let resources = HashMap::from([("urn:certificate".to_string(), certificate)]);
    let mut key_info = KeyInfo {
        sources: (0..MAX_RETRIEVAL_METHOD_COUNT)
            .map(|_| super::super::parse::KeyInfoSource::RetrievalMethod {
                uri: "urn:certificate".into(),
                resource_type: Some(RAW_X509_TYPE.into()),
                transforms: RetrievalMethodTransforms::None,
            })
            .collect(),
    };
    let document = Document::parse("<root/>").unwrap();
    let resolver = UriReferenceResolver::new(&document).with_external_resources(&resources);

    materialize_retrieval_methods(
        &mut key_info,
        &resolver,
        UriTypeSet::ALL,
        None,
        crate::provider::default_provider(),
    )
    .unwrap();
    assert!(matches!(
        key_info.sources.as_slice(),
        [super::super::parse::KeyInfoSource::X509Data(info)]
            if info.certificates.len() == 1
    ));
}

#[test]
fn retrieval_method_candidate_budget_includes_embedded_key_values() {
    // A previously parsed KeyValue consumes the sole candidate slot, so
    // malformed retrieved DER must be rejected by policy before X.509 parsing.
    const RAW_X509_TYPE: &str = "http://www.w3.org/2000/09/xmldsig#rawX509Certificate";
    let resources = HashMap::from([("urn:certificate".to_string(), vec![1, 2, 3])]);
    let mut key_info = KeyInfo {
        sources: vec![
            super::super::parse::KeyInfoSource::KeyValue(
                super::super::parse::KeyValueInfo::Unsupported {
                    namespace: Some(XMLDSIG_NS.into()),
                    local_name: "FutureKeyValue".into(),
                },
            ),
            super::super::parse::KeyInfoSource::RetrievalMethod {
                uri: "urn:certificate".into(),
                resource_type: Some(RAW_X509_TYPE.into()),
                transforms: RetrievalMethodTransforms::None,
            },
        ],
    };
    let document = Document::parse("<root/>").unwrap();
    let resolver = UriReferenceResolver::new(&document).with_external_resources(&resources);
    let mut xpath_parse_budget = XPathSignatureParseBudget::default();
    let execution_budget = TransformExecutionBudget::default();
    let resource_policy = crate::policy::ResourcePolicy {
        max_key_candidates: 1,
        ..crate::policy::ResourcePolicy::default()
    };
    let mut budgets = RetrievalMaterializationBudgets {
        key_info_parse: &RefCell::new(super::super::parse::KeyInfoParseUsage::new(
            &resource_policy,
        )),
        xpath_parse: &mut xpath_parse_budget,
        execution: &execution_budget,
        resources: &resource_policy,
        certificate_signature_algorithms: None,
        xml_backend: crate::XmlBackend::default(),
    };
    let mut candidate_work = key_info.embedded_candidate_count();

    let mut policy = crate::policy::VerificationPolicy::default();
    policy.uris.retrieval_methods = UriTypeSet::ALL;
    let error = materialize_retrieval_methods_with_budgets(
        &mut key_info,
        &resolver,
        &policy,
        crate::provider::default_provider(),
        &mut budgets,
        &mut candidate_work,
    )
    .expect_err("the retrieved certificate must exceed the aggregate candidate limit");

    assert!(matches!(
        error,
        SignatureVerificationPipelineError::Policy(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::KEY_CANDIDATES,
            maximum: 1,
            actual: 2,
        })
    ));
}

#[test]
fn raw_x509_retrieval_rejects_empty_same_document_uri() {
    // rawX509Certificate consumes external DER octets; an empty URI denotes
    // the XML document and must never become a key into the external map.
    const RAW_X509_TYPE: &str = "http://www.w3.org/2000/09/xmldsig#rawX509Certificate";
    let certificate = include_bytes!(
        "../../../tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/certs/balor.der"
    )
    .to_vec();
    let resources = HashMap::from([(String::new(), certificate)]);
    let mut key_info = KeyInfo {
        sources: vec![super::super::parse::KeyInfoSource::RetrievalMethod {
            uri: String::new(),
            resource_type: Some(RAW_X509_TYPE.into()),
            transforms: RetrievalMethodTransforms::None,
        }],
    };
    let document = Document::parse("<root/>").unwrap();
    let resolver = UriReferenceResolver::new(&document).with_external_resources(&resources);

    let error = materialize_retrieval_methods(
        &mut key_info,
        &resolver,
        UriTypeSet::ALL,
        None,
        crate::provider::default_provider(),
    )
    .expect_err("empty URI must retain same-document semantics");
    assert!(matches!(
        error,
        SignatureVerificationPipelineError::InvalidStructure {
            reason: "raw X509 RetrievalMethod requires an untransformed external URI"
        }
    ));
}

#[test]
fn verify_context_does_not_hide_malformed_digest_behind_unsupported_transform() {
    // A bad DigestValue remains a parse error even when its transform URI is unsupported.
    let broken_xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
        let xml = xml.replacen(
                "<ds:Reference URI=\"#target\">",
                "<ds:Reference URI=\"#target\"><ds:Transforms><ds:Transform Algorithm=\"urn:unsupported\"/></ds:Transforms>",
                1,
            );
        replace_fixture_manifest_digest(&xml, "!!!")
    });

    let error = VerifyContext::new()
        .key(&AcceptingKey)
        .process_manifests(true)
        .verify(&broken_xml)
        .expect_err("malformed Manifest digest must not become a validity result");
    assert!(matches!(
        error,
        SignatureVerificationPipelineError::ParseManifestReference(_)
    ));
}

#[test]
fn verify_context_rejects_manifest_non_whitespace_mixed_content() {
    // Authenticated mixed content is still structurally invalid under the
    // Manifest element-only grammar.
    let xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
        xml.replacen(
            "<ds:Manifest ID=\"manifest\">",
            "<ds:Manifest ID=\"manifest\">junk",
            1,
        )
    });

    let err = VerifyContext::new()
        .key(&AcceptingKey)
        .process_manifests(true)
        .verify(&xml)
        .expect_err("Manifest mixed content must fail verification");
    assert!(matches!(
        err,
        SignatureVerificationPipelineError::InvalidStructure {
            reason: "Manifest contains non-whitespace mixed content"
        }
    ));
}

#[test]
fn verify_context_rejects_empty_manifest_children() {
    // An authenticated empty Manifest violates the required Reference+
    // content model rather than disappearing as an unsigned block.
    let xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
        let (prefix, rest) = xml
            .split_once("<ds:Manifest ID=\"manifest\">")
            .expect("fixture should contain Manifest");
        let (_, suffix) = rest
            .split_once("</ds:Manifest>")
            .expect("fixture should contain closing Manifest");
        format!("{prefix}<ds:Manifest ID=\"manifest\"></ds:Manifest>{suffix}")
    });

    let err = VerifyContext::new()
        .key(&AcceptingKey)
        .process_manifests(true)
        .verify(&xml)
        .expect_err("empty Manifest must fail verification");
    assert!(matches!(
        err,
        SignatureVerificationPipelineError::InvalidStructure {
            reason: "Manifest must contain at least one ds:Reference element child"
        }
    ));
}

#[test]
fn verify_context_ignores_unsigned_malformed_manifest_blocks() {
    let xml = signature_with_manifest_xml(true).replacen(
        "</ds:Object>",
        "</ds:Object><ds:Object><ds:Manifest>junk<ds:Foo/></ds:Manifest></ds:Object>",
        1,
    );
    let result = VerifyContext::new()
        .key(&AcceptingKey)
        .process_manifests(true)
        .verify(&xml)
        .expect("unsigned malformed Manifest must be ignored");
    assert_eq!(
        result.manifest_references.len(),
        1,
        "only signed Manifest references must be reported",
    );
    assert!(matches!(result.status, DsigStatus::Valid));
}

#[test]
fn verify_context_skips_ambiguous_manifest_id_blocks() {
    let xml = signature_with_manifest_xml(true).replacen(
            "</ds:Object>",
            "</ds:Object><ds:Object><ds:Manifest ID=\"manifest\">junk<ds:Foo/></ds:Manifest></ds:Object>",
            1,
        );
    // An ambiguous ID fails only the SignedInfo Reference that names it; no
    // Manifest is processed because core validation did not succeed.
    let result = VerifyContext::new()
        .key(&AcceptingKey)
        .process_manifests(true)
        .verify(&xml)
        .expect("ambiguous manifest IDs fail the #manifest Reference");
    assert_eq!(
        result.status,
        DsigStatus::Invalid(FailureReason::ReferenceProcessingFailure { ref_index: 0 })
    );
    assert!(result.manifest_references.is_empty());
}

#[test]
fn verify_context_rejects_implicit_default_c14n_when_not_allowlisted() {
    let xml = minimal_signature_xml("", "");
    let err = VerifyContext::new()
        .key(&RejectingKey)
        .allowed_transforms(["http://www.w3.org/2001/10/xml-exc-c14n#"])
        .verify(&xml)
        .expect_err("implicit default C14N must be checked against allowlist");
    assert!(matches!(
        err,
        SignatureVerificationPipelineError::Policy(crate::policy::PolicyViolation::Algorithm {
            operation: "verification transform",
            ..
        })
    ));
}

/// One Signature over `references`, each an already serialized `ds:Reference`.
fn signature_with_references(references: &[&str]) -> String {
    format!(
        r#"<root xmlns:ds="{XMLDSIG_NS}"><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>{}</ds:SignedInfo><ds:SignatureValue>AQ==</ds:SignatureValue></ds:Signature></root>"#,
        references.concat()
    )
}

fn sha1_reference(uri: &str, digest_b64: &str) -> String {
    format!(
        r#"<ds:Reference URI="{uri}"><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>{digest_b64}</ds:DigestValue></ds:Reference>"#
    )
}

fn external_reference_policy() -> crate::policy::VerificationPolicy {
    crate::policy::VerificationPolicy {
        uris: crate::policy::UriPolicy {
            references: UriTypeSet::ALL,
            ..crate::policy::UriPolicy::default()
        },
        ..crate::policy::VerificationPolicy::default()
    }
}

#[test]
fn verify_context_resolves_key_before_reference_processing() {
    // W3C XML Signature Best Practices BP1: the key and SignedInfo come first,
    // so an unresolvable key ends verification before any Reference runs.
    // The Reference names a missing ID that would fail if it were dereferenced.
    let xml =
        signature_with_references(&[&sha1_reference("#missing", "AAAAAAAAAAAAAAAAAAAAAAAAAAA=")]);
    let result = VerifyContext::new()
        .key_resolver(&MissingKeyResolver)
        .verify(&xml)
        .expect("a missing key is a verification status");
    assert_eq!(
        result.status,
        DsigStatus::Invalid(FailureReason::KeyNotFound)
    );
    assert_eq!(result.signed_info_references.len(), 1);
    assert_eq!(
        result.signed_info_references[0].status,
        DsigStatus::NotProcessed
    );
}

#[test]
fn signature_is_verified_before_any_reference_is_dereferenced() {
    // BP1: a Reference of an unauthenticated SignedInfo is never dereferenced
    // or transformed. A missing ID would fail processing if it were touched;
    // the result reports the signature and leaves the Reference unprocessed.
    let xml = signature_with_references(&[
        &sha1_reference("#missing", "AAAAAAAAAAAAAAAAAAAAAAAAAAA="),
        &sha1_reference("", "AAAAAAAAAAAAAAAAAAAAAAAAAAA="),
    ]);
    let result = VerifyContext::new()
        .key(&RejectingKey)
        .verify(&xml)
        .expect("an invalid signature is a verification status");
    assert_eq!(
        result.status,
        DsigStatus::Invalid(FailureReason::SignatureMismatch)
    );
    assert_eq!(result.signed_info_references.len(), 2);
    for (index, reference) in result.signed_info_references.iter().enumerate() {
        assert_eq!(reference.reference_index, index);
        assert_eq!(reference.status, DsigStatus::NotProcessed);
        assert_eq!(reference.target_identity, None);
        assert_eq!(reference.pre_digest_data, None);
    }
    assert_eq!(result.signed_info_references[0].uri, "#missing");
}

#[test]
fn valid_signature_gives_every_reference_its_own_result() {
    // XMLDSig 1.1 §3.2.1: each Reference is validated on its own. A failing
    // Reference no longer hides the later ones; the overall status names the
    // first failure in document order and stays Invalid.
    let payload = b"payload";
    let payload_digest = base64::engine::general_purpose::STANDARD.encode(
        crate::xmldsig::compute_digest(DigestAlgorithm::Sha1, payload),
    );
    let xml = signature_with_references(&[
        &sha1_reference("", "AAAAAAAAAAAAAAAAAAAAAAAAAAA="),
        &sha1_reference("#missing", "AAAAAAAAAAAAAAAAAAAAAAAAAAA="),
        &sha1_reference("urn:absent", "AAAAAAAAAAAAAAAAAAAAAAAAAAA="),
        &sha1_reference("urn:payload", &payload_digest),
    ]);
    let resources = HashMap::from([("urn:payload".to_owned(), payload.to_vec())]);
    let result = VerifyContext::new()
        .key(&AcceptingKey)
        .policy(external_reference_policy())
        .external_resources(&resources)
        .verify(&xml)
        .expect("reference outcomes are verification statuses");

    assert_eq!(
        result.status,
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
    );
    let statuses: Vec<_> = result
        .signed_info_references
        .iter()
        .map(|reference| reference.status)
        .collect();
    assert_eq!(
        statuses,
        [
            DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 }),
            DsigStatus::Invalid(FailureReason::ReferenceProcessingFailure { ref_index: 1 }),
            DsigStatus::Invalid(FailureReason::ReferenceUnavailable { ref_index: 2 }),
            DsigStatus::Valid,
        ]
    );
    let detached = &result.signed_info_references[3];
    assert!(detached.external_resource_fingerprint.is_some());
    assert!(result.manifest_references.is_empty());
}

#[test]
fn unavailable_detached_payload_does_not_hide_a_valid_signature() {
    // A detached Reference whose bytes the caller has not supplied yet is
    // Unavailable, distinct from a mismatch; the signature over SignedInfo
    // and the same-document Reference are still reported as verified.
    let xml = signature_with_target_content("AQ==", "payload").replacen(
        "</ds:SignedInfo>",
        &format!(
            "{}</ds:SignedInfo>",
            sha1_reference("urn:later", "AAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        ),
        1,
    );
    let result = VerifyContext::new()
        .key(&AcceptingKey)
        .policy(external_reference_policy())
        .verify(&xml)
        .expect("an unavailable payload is a verification status");
    assert_eq!(
        result.status,
        DsigStatus::Invalid(FailureReason::ReferenceUnavailable { ref_index: 1 })
    );
    assert_eq!(result.signed_info_references[0].status, DsigStatus::Valid);
    assert_eq!(
        result.signed_info_references[1].status,
        DsigStatus::Invalid(FailureReason::ReferenceUnavailable { ref_index: 1 })
    );
}

#[test]
fn reference_failure_does_not_unlock_manifest_processing() {
    // Manifest content is processed only after core validation succeeds;
    // per-reference reporting must not let a failed SignedInfo Reference
    // through to Manifest parsing.
    let xml = signature_with_manifest_xml(true).replacen(
        "</ds:SignedInfo>",
        &format!(
            "{}</ds:SignedInfo>",
            sha1_reference("", "AAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        ),
        1,
    );
    let result = VerifyContext::new()
        .key(&AcceptingKey)
        .process_manifests(true)
        .verify(&xml)
        .expect("a reference mismatch is a verification status");
    assert!(matches!(
        result.status,
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { .. })
    ));
    assert!(result.manifest_references.is_empty());
}

#[test]
fn verify_context_reports_key_not_found_when_resolver_misses() {
    let xml = signature_with_target_reference("AQ==");
    let result = VerifyContext::new()
        .key_resolver(&MissingKeyResolver)
        .verify(&xml)
        .expect("resolver miss should report status, not pipeline error");
    assert!(matches!(
        result.status,
        DsigStatus::Invalid(FailureReason::KeyNotFound)
    ));
    // Without a key nothing authenticates SignedInfo: each Reference is
    // still reported, bound to its original element, and left unprocessed.
    assert_eq!(result.signed_info_references.len(), 1);
    assert_eq!(
        result.signed_info_references[0].status,
        DsigStatus::NotProcessed
    );
    assert!(
        result.signed_info_references[0]
            .reference_identity
            .is_some()
    );
}

#[test]
fn verification_candidate_budget_covers_preset_and_custom_resolver_paths() {
    // Zero is a valid deny-all ceiling. Neither an already-resolved key nor
    // a custom resolver may bypass the operation-wide candidate policy.
    let xml = signature_with_target_reference("AQ==");
    let mut policy = crate::policy::VerificationPolicy::default();
    policy.resources.max_key_candidates = 0;

    let preset_error = VerifyContext::new()
        .key(&RejectingKey)
        .policy(policy.clone())
        .verify(&xml)
        .expect_err("a preset key consumes one candidate");
    assert!(matches!(
        preset_error,
        SignatureVerificationPipelineError::Policy(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::KEY_CANDIDATES,
            maximum: 0,
            actual: 1,
        })
    ));

    let resolver_error = VerifyContext::new()
        .key_resolver(&PanicResolver)
        .policy(policy)
        .verify(&xml)
        .expect_err("a custom resolver requires candidate capacity before dispatch");
    assert!(matches!(
        resolver_error,
        SignatureVerificationPipelineError::Policy(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::KEY_CANDIDATES,
            maximum: 0,
            actual: 1,
        })
    ));
}

#[test]
fn verification_candidate_account_is_not_reset_for_each_signature() {
    // A rejected signature still spends its candidate allowance in verify_all.
    let xml = signature_with_target_reference("AQ==");
    let start = xml
        .find("<ds:Signature>")
        .expect("generated signature start");
    let end = xml
        .find("</ds:Signature>")
        .expect("generated signature end")
        + "</ds:Signature>".len();
    let document =
        XmlDocument::parse(xml.replace("</root>", &format!("{}</root>", &xml[start..end])))
            .expect("two signatures");
    let mut policy = crate::policy::VerificationPolicy::default();
    policy.resources.max_key_candidates = 1;
    let evidence = VerifyContext::new()
        .key(&RejectingKey)
        .policy(policy)
        .verify_all(&document)
        .expect("signature-local failure report");
    assert_eq!(evidence.signatures().len(), 2);
    assert!(evidence.signatures()[0].result().is_ok());
    assert!(matches!(
        evidence.signatures()[1].result(),
        Err(DsigError::Policy(
            crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::KEY_CANDIDATES,
                maximum: 1,
                actual: 2,
            }
        ))
    ));
}

#[test]
fn resolver_receives_the_certificate_account_spent_by_ingestion() {
    // The public resolver hook receives prior parsing work, not a fresh allowance.
    struct ProbeResolver {
        called: Cell<bool>,
    }
    impl KeyResolver for ProbeResolver {
        fn resolve<'a>(
            &'a self,
            _info: Option<&KeyInfo>,
            _algorithm: SignatureAlgorithm,
        ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, DsigError> {
            panic!("core must dispatch through the budget-aware hook");
        }
        fn resolve_for_verification_with_budget<'a>(
            &'a self,
            _info: Option<&KeyInfo>,
            _algorithm: SignatureAlgorithm,
            _policy: &crate::policy::VerificationPolicy,
            _provider: &dyn crate::provider::CryptoProvider,
            budget: &mut super::super::InspectedKeyCandidateBudget,
        ) -> Result<Option<super::super::ResolvedVerificationKey<'a>>, DsigError> {
            assert!(budget.execution().work_used() > 0);
            budget.charge()?;
            self.called.set(true);
            Ok(Some(super::super::ResolvedVerificationKey::CallerTrusted(
                Box::new(AcceptingKey),
            )))
        }
        fn consumes_document_key_info(&self) -> bool {
            true
        }
    }
    let pair = rcgen::KeyPair::generate().expect("test key generation");
    let certificate = rcgen::CertificateParams::new(Vec::<String>::new())
        .expect("empty SAN list")
        .self_signed(&pair)
        .expect("test certificate");
    let encoded = base64::engine::general_purpose::STANDARD.encode(certificate.der());
    let xml = signature_with_target_reference("AQ==").replace("</ds:Signature>", &format!(
            "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{encoded}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>",
        ));
    let resolver = ProbeResolver {
        called: Cell::new(false),
    };
    let result = VerifyContext::new()
        .key_resolver(&resolver)
        .verify(&xml)
        .expect("shared-account resolver dispatch");
    assert!(matches!(result.status, DsigStatus::Valid));
    assert!(resolver.called.get());
}

#[test]
fn verification_candidate_budget_precedes_embedded_x509_parsing() {
    // The first certificate is valid and consumes the sole permitted slot;
    // malformed bytes in the second must never reach the X.509 parser.
    let first_certificate = base64::engine::general_purpose::STANDARD.encode(include_bytes!(
        "../../../tests/fixtures/xmldsig/phaos-xmldsig-three/certs/rsa-cert.der"
    ));
    let xml = signature_with_target_reference("AQ==").replace(
            "</ds:SignatureValue>\n  </ds:Signature>",
            &format!(
                "</ds:SignatureValue>\n    <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{first_certificate}</ds:X509Certificate><ds:X509Certificate>AQID</ds:X509Certificate></ds:X509Data></ds:KeyInfo>\n  </ds:Signature>"
            ),
        );
    let mut policy = crate::policy::VerificationPolicy::default();
    policy.resources.max_key_candidates = 1;

    let error = VerifyContext::new()
        .policy(policy)
        .verify(&xml)
        .expect_err("candidate policy must run before embedded certificate parsing");

    assert!(matches!(
        error,
        SignatureVerificationPipelineError::Policy(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::KEY_CANDIDATES,
            maximum: 1,
            actual: 2,
        })
    ));
}

#[test]
fn verify_context_resolver_can_ignore_malformed_keyinfo_by_default() {
    let base_xml = signature_with_target_reference("AQ==");
    let xml = base_xml
            .replace(
                r#"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
                r#"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">"#,
            )
            .replace(
                "</ds:SignatureValue>\n  </ds:Signature>",
                "</ds:SignatureValue>\n    <ds:KeyInfo><dsig11:DEREncodedKeyValue>%%%invalid%%%</dsig11:DEREncodedKeyValue></ds:KeyInfo>\n  </ds:Signature>",
            );

    let result = VerifyContext::new()
        .key_resolver(&MissingKeyResolver)
        .verify(&xml)
        .expect("resolver path should not hard-fail on advisory malformed KeyInfo by default");
    assert!(matches!(
        result.status,
        DsigStatus::Invalid(FailureReason::KeyNotFound)
    ));
}

#[test]
fn verify_context_resolver_can_opt_in_to_keyinfo_parse_failures() {
    let base_xml = signature_with_target_reference("AQ==");
    let xml = base_xml
            .replace(
                r#"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
                r#"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">"#,
            )
            .replace(
                "</ds:SignatureValue>\n  </ds:Signature>",
                "</ds:SignatureValue>\n    <ds:KeyInfo><dsig11:DEREncodedKeyValue>%%%invalid%%%</dsig11:DEREncodedKeyValue></ds:KeyInfo>\n  </ds:Signature>",
            );

    let err = VerifyContext::new()
        .key_resolver(&ConsumingKeyInfoResolver)
        .verify(&xml)
        .expect_err("resolver opted into KeyInfo parsing, malformed KeyInfo must fail");
    assert!(matches!(
        err,
        SignatureVerificationPipelineError::ParseKeyInfo(_)
    ));
}

#[test]
fn verify_context_ignores_unsupported_retrieval_before_valid_key_source() {
    // An advisory vendor RetrievalMethod cannot prevent the resolver from
    // reaching a later supported source in document order.
    let xml = signature_with_target_reference("AQ==").replace(
        "</ds:SignatureValue>\n  </ds:Signature>",
        r##"</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:RetrievalMethod URI="#vendor" Type="urn:vendor:key">
        <ds:Transforms><ds:Transform Algorithm="urn:vendor:transform"/></ds:Transforms>
      </ds:RetrievalMethod>
      <ds:KeyName>fallback</ds:KeyName>
    </ds:KeyInfo>
  </ds:Signature>"##,
    );

    let result = VerifyContext::new()
        .key_resolver(&FallbackKeyInfoResolver)
        .verify(&xml)
        .expect("unsupported advisory retrieval must not abort key resolution");
    assert_eq!(result.status, DsigStatus::Valid);
}

#[test]
fn verify_context_does_not_eagerly_fail_unused_retrieval_fallback() {
    // KeyInfo sources are alternatives in document order. Once an earlier
    // source resolves, a missing later RetrievalMethod is irrelevant.
    let xml = signature_with_target_reference("AQ==").replace(
            "</ds:SignatureValue>\n  </ds:Signature>",
            r#"</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:KeyName>primary</ds:KeyName>
      <ds:RetrievalMethod URI="missing.der" Type="http://www.w3.org/2000/09/xmldsig#rawX509Certificate"/>
    </ds:KeyInfo>
  </ds:Signature>"#,
        );

    let result = VerifyContext::new()
        .key_resolver(&EarlyKeyInfoResolver)
        .allowed_retrieval_method_uri_types(UriTypeSet::new(true, true, true))
        .verify(&xml)
        .expect("an unused missing retrieval fallback must not abort verification");

    assert_eq!(result.status, DsigStatus::Valid);
}

#[test]
fn verify_context_does_not_eagerly_fail_unused_same_document_x509_retrieval() {
    // Same-document X509Data retrieval is an ordered alternative just like
    // raw-certificate retrieval; a resolved earlier source makes it unused.
    let xml = signature_with_target_reference("AQ==").replace(
        "</ds:SignatureValue>\n  </ds:Signature>",
        r##"</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:KeyName>primary</ds:KeyName>
      <ds:RetrievalMethod URI="#missing" Type="http://www.w3.org/2000/09/xmldsig#X509Data"/>
    </ds:KeyInfo>
  </ds:Signature>"##,
    );

    let result = VerifyContext::new()
        .key_resolver(&EarlyKeyInfoResolver)
        .verify(&xml)
        .expect("an unused missing X509Data retrieval fallback must not abort verification");

    assert_eq!(result.status, DsigStatus::Valid);
}

#[test]
fn verify_context_reports_missing_same_document_x509_retrieval_without_fallback() {
    // Deferred failures retain their exact diagnostic when no alternative
    // source resolves the verification key.
    let xml = signature_with_target_reference("AQ==").replace(
        "</ds:SignatureValue>\n  </ds:Signature>",
        r##"</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:RetrievalMethod URI="#missing" Type="http://www.w3.org/2000/09/xmldsig#X509Data"/>
    </ds:KeyInfo>
  </ds:Signature>"##,
    );

    let error = VerifyContext::new()
        .key_resolver(&ConsumingKeyInfoResolver)
        .verify(&xml)
        .expect_err("a sole missing X509Data retrieval must remain an explicit error");

    assert!(matches!(
        error,
        SignatureVerificationPipelineError::InvalidStructure {
            reason: "X509Data RetrievalMethod target is missing or ambiguous"
        }
    ));
}

#[test]
fn verify_context_does_not_eagerly_parse_unused_retrieval_fallback() {
    // Materialization must preserve ordered fallback semantics even when
    // caller-supplied bytes exist but are not a certificate.
    let xml = signature_with_target_reference("AQ==").replace(
            "</ds:SignatureValue>\n  </ds:Signature>",
            r#"</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:KeyName>primary</ds:KeyName>
      <ds:RetrievalMethod URI="malformed.der" Type="http://www.w3.org/2000/09/xmldsig#rawX509Certificate"/>
    </ds:KeyInfo>
  </ds:Signature>"#,
        );
    let resources = HashMap::from([("malformed.der".to_string(), b"not DER".to_vec())]);

    let result = VerifyContext::new()
        .key_resolver(&EarlyKeyInfoResolver)
        .allowed_retrieval_method_uri_types(UriTypeSet::ALL)
        .external_resources(&resources)
        .verify(&xml)
        .expect("an unused malformed retrieval fallback must not abort verification");

    assert_eq!(result.status, DsigStatus::Valid);
}

#[test]
fn verify_context_reports_missing_retrieval_when_no_key_source_resolves() {
    // Deferral changes ordering, not diagnostics: if no alternative source
    // resolves, the first missing retrieval remains the pipeline failure.
    let xml = signature_with_target_reference("AQ==").replace(
            "</ds:SignatureValue>\n  </ds:Signature>",
            r#"</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:RetrievalMethod URI="missing.der" Type="http://www.w3.org/2000/09/xmldsig#rawX509Certificate"/>
    </ds:KeyInfo>
  </ds:Signature>"#,
        );

    let error = VerifyContext::new()
        .key_resolver(&ConsumingKeyInfoResolver)
        .allowed_retrieval_method_uri_types(UriTypeSet::new(true, true, true))
        .verify(&xml)
        .expect_err("a missing sole RetrievalMethod must remain an explicit error");

    assert!(matches!(
        error,
        SignatureVerificationPipelineError::Reference(ReferenceProcessingError::Transform(
            crate::xmldsig::TransformError::UnsupportedUri(uri)
        )) if uri == "missing.der"
    ));
}

#[test]
fn verify_context_reports_malformed_retrieval_when_no_key_source_resolves() {
    // Deferral must retain the parse error when the malformed certificate
    // is the only candidate rather than degrading it to KeyNotFound.
    let xml = signature_with_target_reference("AQ==").replace(
            "</ds:SignatureValue>\n  </ds:Signature>",
            r#"</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:RetrievalMethod URI="malformed.der" Type="http://www.w3.org/2000/09/xmldsig#rawX509Certificate"/>
    </ds:KeyInfo>
  </ds:Signature>"#,
        );
    let resources = HashMap::from([("malformed.der".to_string(), b"not DER".to_vec())]);

    let error = VerifyContext::new()
        .key_resolver(&ConsumingKeyInfoResolver)
        .allowed_retrieval_method_uri_types(UriTypeSet::ALL)
        .external_resources(&resources)
        .verify(&xml)
        .expect_err("a malformed sole RetrievalMethod must remain a parse error");

    assert!(matches!(
        error,
        SignatureVerificationPipelineError::ParseKeyInfo(_)
    ));
}

#[test]
fn verify_context_preserves_signaturevalue_decode_errors_when_resolver_misses() {
    let xml = signature_with_target_reference("@@@");

    let err = VerifyContext::new()
        .key_resolver(&MissingKeyResolver)
        .verify(&xml)
        .expect_err("invalid SignatureValue must remain a decode error on resolver miss");
    assert!(matches!(
        err,
        SignatureVerificationPipelineError::SignatureValueBase64(_)
    ));
}

#[test]
fn verify_context_preserves_signaturevalue_decode_errors_without_key() {
    let xml = signature_with_target_reference("@@@");

    let err = VerifyContext::new()
        .verify(&xml)
        .expect_err("invalid SignatureValue must remain a decode error");
    assert!(matches!(
        err,
        SignatureVerificationPipelineError::SignatureValueBase64(_)
    ));
}

#[test]
fn enforce_reference_policies_rejects_missing_uri_before_uri_type_checks() {
    let references = vec![Reference {
        uri: None,
        id: None,
        ref_type: None,
        transforms: vec![],
        digest_method: DigestAlgorithm::Sha256,
        digest_value: vec![0; 32],
    }];
    let uri_types = UriTypeSet {
        allow_empty: false,
        allow_same_document: true,
        allow_external: false,
    };

    let err = enforce_reference_policies(&references, uri_types, None)
        .expect_err("missing URI must fail before allow_empty policy is evaluated");
    assert!(matches!(
        err,
        SignatureVerificationPipelineError::Reference(ReferenceProcessingError::MissingUri)
    ));
}

#[test]
fn enforce_reference_policies_checks_only_terminal_binary_output() {
    let c14n = C14nAlgorithm::from_uri(DEFAULT_IMPLICIT_C14N_URI).unwrap();
    let allowed = HashSet::from([
        BASE64_TRANSFORM_URI.to_owned(),
        DEFAULT_IMPLICIT_C14N_URI.to_owned(),
    ]);
    let without_implicit_c14n = HashSet::from([BASE64_TRANSFORM_URI.to_owned()]);

    for transforms in [
        vec![Transform::Base64Decode, Transform::C14n(c14n)],
        vec![Transform::Base64Decode, Transform::Base64Decode],
    ] {
        let reference = make_reference("", transforms, DigestAlgorithm::Sha256, vec![0; 32]);
        enforce_reference_policies(
            std::slice::from_ref(&reference),
            UriTypeSet::default(),
            Some(&allowed),
        )
        .expect("terminal binary output must not require implicit C14N");
    }

    let terminal_base64 = make_reference(
        "",
        vec![Transform::Base64Decode, Transform::Base64Decode],
        DigestAlgorithm::Sha256,
        vec![0; 32],
    );
    enforce_reference_policies(
        std::slice::from_ref(&terminal_base64),
        UriTypeSet::default(),
        Some(&without_implicit_c14n),
    )
    .expect("terminal Base64 output must not require implicit C14N");

    let no_transforms = make_reference("", vec![], DigestAlgorithm::Sha256, vec![0; 32]);
    let error = enforce_reference_policies(
        std::slice::from_ref(&no_transforms),
        UriTypeSet::default(),
        Some(&without_implicit_c14n),
    )
    .expect_err("a node-set result must require allowlisted implicit C14N");
    assert!(matches!(
        error,
        SignatureVerificationPipelineError::Policy(
            crate::policy::PolicyViolation::Algorithm {
                operation: "verification transform",
                ref algorithm,
            }
        )
            if algorithm == DEFAULT_IMPLICIT_C14N_URI
    ));

    let detached = make_reference("urn:payload", vec![], DigestAlgorithm::Sha256, vec![0; 32]);
    enforce_reference_policies(
        std::slice::from_ref(&detached),
        UriTypeSet::ALL,
        Some(&without_implicit_c14n),
    )
    .expect("external octets without transforms must not require implicit C14N");

    let external_xpath = make_reference(
        "urn:payload",
        vec![Transform::XPath(
            super::super::transforms::XPathExpression::new("true()"),
        )],
        DigestAlgorithm::Sha256,
        vec![0; 32],
    );
    let error = enforce_reference_policies(
        std::slice::from_ref(&external_xpath),
        UriTypeSet::ALL,
        Some(&HashSet::from([XPATH_TRANSFORM_URI.to_owned()])),
    )
    .expect_err("external XML converted to a node-set must require implicit C14N");
    assert!(matches!(
        error,
        SignatureVerificationPipelineError::Policy(
            crate::policy::PolicyViolation::Algorithm {
                operation: "verification transform",
                ref algorithm,
            }
        )
            if algorithm == DEFAULT_IMPLICIT_C14N_URI
    ));
}

#[test]
fn stored_pre_digest_budget_counts_repeated_external_references() {
    // The caller map owns one bounded payload, but diagnostic retention is
    // charged per Reference because every result owns its pre-digest bytes.
    let document =
        Document::parse("<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"/>").unwrap();
    let payload = vec![b'x'; 7];
    let digest = compute_digest(DigestAlgorithm::Sha256, &payload);
    let references = (0..5)
        .map(|_| {
            make_reference(
                "urn:repeated",
                Vec::new(),
                DigestAlgorithm::Sha256,
                digest.clone(),
            )
        })
        .collect::<Vec<_>>();
    let resources = HashMap::from([("urn:repeated".to_owned(), payload)]);
    let resolver = UriReferenceResolver::new(&document).with_external_resources(&resources);
    let transform_budget = TransformExecutionBudget::default();
    let canonicalized_data_budget = CanonicalizedDataBudget::with_limit(32);
    let execution = ReferenceExecutionContext {
        store_pre_digest: true,
        transform_options: TransformOptions::default(),
        transform_budget: &transform_budget,
        canonicalized_data_budget: &canonicalized_data_budget,
        provider: crate::provider::default_provider(),
        capture: &(),
    };

    let error = process_all_references_with_options(
        &references,
        &resolver,
        document.root_element(),
        &execution,
    )
    .expect_err(
        "retained diagnostics must not multiply one external allocation past the aggregate cap",
    );
    assert!(matches!(
        error,
        ReferenceProcessingError::Policy(crate::policy::PolicyViolation::ResourceLimit {
            resource: "canonicalized bytes",
            maximum: 32,
            ..
        })
    ));
}

#[test]
fn public_reference_entries_inherit_custom_id_registration() {
    // Both public entry points must pass resolver registrations to XPath.
    let xml = format!(
        "<root xmlns:ds='{XMLDSIG_NS}'><data Token='target'>YWJj</data><ds:Signature/></root>"
    );
    let document = Document::parse(&xml).unwrap();
    let signature = document
        .descendants()
        .find(|node| node.has_tag_name((XMLDSIG_NS, "Signature")))
        .unwrap();
    let registrations = [crate::IdAttributeRegistration::global("Token")];
    let resolver = UriReferenceResolver::with_id_registrations(&document, &registrations);
    let expression = crate::xmldsig::transforms::XPathExpression::new(
        "count(id('target')) = 1 and count(ancestor-or-self::node() | id('target')) = count(ancestor-or-self::node())",
    );
    let reference = make_reference(
        "#target",
        vec![Transform::XPath(expression), Transform::Base64Decode],
        DigestAlgorithm::Sha256,
        compute_digest(DigestAlgorithm::Sha256, b"abc"),
    );
    let one = process_reference(
        &reference,
        &resolver,
        signature,
        ReferenceSet::SignedInfo,
        0,
        true,
    )
    .unwrap();
    assert_eq!(one.status, DsigStatus::Valid);
    let all = process_all_references(&[reference], &resolver, signature, true).unwrap();
    assert_eq!(all.results.len(), 1);
    assert_eq!(all.results[0].status, DsigStatus::Valid);
    assert!(all.first_failure.is_none());
}

#[test]
fn normalized_root_xpointers_bind_document_identity() {
    // Spelling changes must not discard coverage evidence for the root.
    let document = XmlDocument::parse("<root><item/></root>").unwrap();
    let budgets = VerificationOperationBudgets::with_transforms(
        &crate::policy::VerificationPolicy::default(),
        TransformExecutionBudget::default(),
        None,
    );
    document.with_view(|view| {
        let resolver = UriReferenceResolver::new(view.document());
        for uri in ["#xpointer(/)", "#xpointer( / )", "#xpointer(%2F)"] {
            let reference = make_reference(uri, Vec::new(), DigestAlgorithm::Sha256, vec![0; 32]);
            assert_eq!(
                budgets.resource_identity_for_reference(&reference, 0, &resolver, view, None),
                OperationResourceIdentity::DocumentNode(view.root()),
                "{uri}"
            );
        }
    });
}

#[test]
fn missing_external_identity_does_not_retain_uri_cache_copies() {
    // No bytes exist to fingerprint or reuse. The graph's Reference node
    // already carries provenance, so a missing URI must not enter the
    // available-resource memoization cache or be cloned with every decision.
    let document = XmlDocument::parse("<root/>").unwrap();
    let uri = format!("urn:missing:{}", "x".repeat(16384));
    let reference = make_reference(&uri, Vec::new(), DigestAlgorithm::Sha256, vec![0; 32]);
    let budgets = VerificationOperationBudgets::with_transforms(
        &crate::policy::VerificationPolicy::default(),
        TransformExecutionBudget::default(),
        None,
    );
    document.with_view(|view| {
        let resolver = UriReferenceResolver::new(view.document());
        let _ = budgets.resource_identity_for_reference(&reference, 0, &resolver, view, None);
        assert!(budgets.external_resource_identities.borrow().is_empty());
    });
}

#[test]
fn operation_memoizes_repeated_external_resource_identity() {
    // The external resource map is immutably borrowed for the operation,
    // so one content fingerprint safely identifies every repeated URI.
    let document = XmlDocument::parse("<root/>").expect("fixture must parse");
    let resources = HashMap::from([("urn:repeated".to_owned(), vec![b'x'; 8 * 1_024])]);
    let reference = make_reference(
        "urn:repeated",
        Vec::new(),
        DigestAlgorithm::Sha256,
        vec![0; 32],
    );
    let budgets = VerificationOperationBudgets::with_transforms(
        &crate::policy::VerificationPolicy::default(),
        TransformExecutionBudget::default(),
        None,
    );

    document.with_view(|view| {
        let resolver =
            UriReferenceResolver::new(view.document()).with_external_resources(&resources);
        let first = budgets.resource_identity_for_reference(&reference, 0, &resolver, view, None);
        let second = budgets.resource_identity_for_reference(&reference, 1, &resolver, view, None);

        assert_eq!(first, second);
        assert_eq!(budgets.external_resource_identities.borrow().len(), 1);
    });
}

#[test]
fn canonical_signed_info_obeys_policy_without_diagnostic_retention() {
    // SignedInfo is always materialized for crypto verification, so its
    // canonical bytes must consume the configured ceiling even when
    // diagnostics do not retain reference output.
    let xml = signature_with_target_reference("AQ==");
    let marker = "<ds:SignatureMethod";
    let padding = " ".repeat(1_025);
    let xml = xml.replacen(marker, &format!("{padding}{marker}"), 1);
    let policy = crate::policy::VerificationPolicy {
        resources: crate::policy::ResourcePolicy {
            max_canonicalized_bytes: 1_024,
            ..crate::policy::ResourcePolicy::default()
        },
        ..crate::policy::VerificationPolicy::default()
    };

    let error = VerifyContext::new()
        .key(&AcceptingKey)
        .policy(policy)
        .verify(&xml)
        .expect_err("canonicalized SignedInfo must remain policy-bounded");

    assert!(matches!(
        error,
        SignatureVerificationPipelineError::Policy(crate::policy::PolicyViolation::ResourceLimit {
            resource: "canonicalized bytes",
            ..
        })
    ));
}

#[test]
fn fragmented_pq_signature_value_decodes_at_exact_wire_limit() {
    // Comments split the largest supported signature into tiny text nodes;
    // decoding must preserve bytes and reject an oversized aggregate.
    let parameter = super::super::pq_algorithm::PqAlgorithm::SlhDsaSha2_256f;
    let bytes = vec![0x5a; parameter.signature_len()];
    let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
    let mut xml = String::from("<SignatureValue>");
    for chunk in encoded.as_bytes().chunks(4) {
        xml.push_str(std::str::from_utf8(chunk).unwrap());
        xml.push_str("<!--split-->\n");
    }
    xml.push_str("</SignatureValue>");
    let document = Document::parse(&xml).unwrap();
    let algorithm = SignatureAlgorithm::PostQuantum(parameter);
    assert_eq!(
        decode_signature_value(
            document.root_element(),
            algorithm,
            &crate::policy::ResourcePolicy::default()
        )
        .unwrap(),
        bytes
    );
    let oversized = xml.replace("</SignatureValue>", "AAAA</SignatureValue>");
    let document = Document::parse(&oversized).unwrap();
    assert!(matches!(
        decode_signature_value(
            document.root_element(),
            algorithm,
            &crate::policy::ResourcePolicy::default()
        ),
        Err(SignatureVerificationPipelineError::InvalidStructure {
            reason: "SignatureValue exceeds maximum allowed length"
        })
    ));
}

#[test]
fn push_normalized_signature_text_rejects_form_feed() {
    let mut normalized = Vec::new();
    let mut raw_text_len = 0usize;
    let err = push_normalized_signature_text(
        "ab\u{000C}cd",
        &mut raw_text_len,
        &mut normalized,
        SignatureAlgorithm::RsaSha256,
        &crate::policy::ResourcePolicy::default(),
    )
    .expect_err("form-feed must not be treated as XML base64 whitespace");
    assert!(matches!(
        err,
        SignatureVerificationPipelineError::SignatureValueBase64(base64::DecodeError::InvalidByte(
            _,
            0x0C
        ))
    ));
}

#[test]
fn push_normalized_signature_text_enforces_byte_limit_for_multibyte_chars() {
    let mut normalized = vec![b'A'; MAX_SIGNATURE_VALUE_LEN - 1];
    let mut raw_text_len = normalized.len();
    let err = push_normalized_signature_text(
        "é",
        &mut raw_text_len,
        &mut normalized,
        SignatureAlgorithm::RsaSha256,
        &crate::policy::ResourcePolicy::default(),
    )
    .expect_err("multibyte characters must not bypass byte-size limit");
    assert!(matches!(
        err,
        SignatureVerificationPipelineError::InvalidStructure {
            reason: "SignatureValue exceeds maximum allowed length"
        }
    ));
}

// ── process_reference: happy path ────────────────────────────────

#[test]
fn reference_with_correct_digest_passes() {
    // Create a simple document, compute its canonical form digest,
    // then verify that process_reference returns Valid status.
    let xml = r#"<root>
            <data>hello world</data>
            <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="sig1">
                <ds:SignedInfo/>
            </ds:Signature>
        </root>"#;
    let doc = Document::parse(xml).unwrap();
    let resolver = UriReferenceResolver::new(&doc);
    let sig_node = doc
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "Signature")
        .unwrap();

    // First, compute the expected digest by running the pipeline
    let initial_data = resolver.dereference("").unwrap();
    let transforms = vec![
        Transform::Enveloped,
        Transform::C14n(
            crate::c14n::C14nAlgorithm::from_uri("http://www.w3.org/2001/10/xml-exc-c14n#")
                .unwrap(),
        ),
    ];
    let pre_digest_bytes =
        crate::xmldsig::execute_transforms(sig_node, initial_data, &transforms).unwrap();
    let expected_digest = compute_digest(DigestAlgorithm::Sha256, &pre_digest_bytes);

    // Now build a Reference with the correct digest and verify
    let reference = make_reference("", transforms, DigestAlgorithm::Sha256, expected_digest);

    let result = process_reference(
        &reference,
        &resolver,
        sig_node,
        ReferenceSet::SignedInfo,
        0,
        false,
    )
    .unwrap();
    assert!(
        matches!(result.status, DsigStatus::Valid),
        "digest should match"
    );
    assert!(result.pre_digest_data.is_none());
}

#[test]
fn reference_with_wrong_digest_fails() {
    let xml = r#"<root>
            <data>hello</data>
            <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:SignedInfo/>
            </ds:Signature>
        </root>"#;
    let doc = Document::parse(xml).unwrap();
    let resolver = UriReferenceResolver::new(&doc);
    let sig_node = doc
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "Signature")
        .unwrap();

    let transforms = vec![Transform::Enveloped];
    // Wrong digest value: all zeros
    let wrong_digest = vec![0u8; 32];
    let reference = make_reference("", transforms, DigestAlgorithm::Sha256, wrong_digest);

    let result = process_reference(
        &reference,
        &resolver,
        sig_node,
        ReferenceSet::SignedInfo,
        0,
        false,
    )
    .unwrap();
    assert!(matches!(
        result.status,
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
    ));
}

#[test]
fn reference_with_wrong_digest_preserves_supplied_ref_index() {
    let xml = r#"<root>
            <data>hello</data>
            <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:SignedInfo/>
            </ds:Signature>
        </root>"#;
    let doc = Document::parse(xml).unwrap();
    let resolver = UriReferenceResolver::new(&doc);
    let sig_node = doc
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "Signature")
        .unwrap();

    let reference = make_reference(
        "",
        vec![Transform::Enveloped],
        DigestAlgorithm::Sha256,
        vec![0u8; 32],
    );
    let result = process_reference(
        &reference,
        &resolver,
        sig_node,
        ReferenceSet::SignedInfo,
        7,
        false,
    )
    .unwrap();
    assert!(matches!(
        result.status,
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 7 })
    ));
}

#[test]
fn reference_stores_pre_digest_data() {
    let xml = "<root><child>text</child></root>";
    let doc = Document::parse(xml).unwrap();
    let resolver = UriReferenceResolver::new(&doc);

    // No transforms, no enveloped: just canonicalize entire document
    let initial_data = resolver.dereference("").unwrap();
    let pre_digest =
        crate::xmldsig::execute_transforms(doc.root_element(), initial_data, &[]).unwrap();
    let digest = compute_digest(DigestAlgorithm::Sha256, &pre_digest);

    let reference = make_reference("", vec![], DigestAlgorithm::Sha256, digest);
    let result = process_reference(
        &reference,
        &resolver,
        doc.root_element(),
        ReferenceSet::SignedInfo,
        0,
        true,
    )
    .unwrap();

    assert!(matches!(result.status, DsigStatus::Valid));
    assert!(result.pre_digest_data.is_some());
    assert_eq!(result.pre_digest_data.unwrap(), pre_digest);
}

// ── process_reference: URI dereference ───────────────────────────

#[test]
fn reference_with_id_uri() {
    let xml = r#"<root>
            <item ID="target">specific content</item>
            <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:SignedInfo/>
            </ds:Signature>
        </root>"#;
    let doc = Document::parse(xml).unwrap();
    let resolver = UriReferenceResolver::new(&doc);
    let sig_node = doc
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "Signature")
        .unwrap();

    // Compute expected digest for the #target subtree
    let initial_data = resolver.dereference("#target").unwrap();
    let transforms = vec![Transform::C14n(
        crate::c14n::C14nAlgorithm::from_uri("http://www.w3.org/2001/10/xml-exc-c14n#").unwrap(),
    )];
    let pre_digest =
        crate::xmldsig::execute_transforms(sig_node, initial_data, &transforms).unwrap();
    let expected_digest = compute_digest(DigestAlgorithm::Sha256, &pre_digest);

    let reference = make_reference(
        "#target",
        transforms,
        DigestAlgorithm::Sha256,
        expected_digest,
    );
    let result = process_reference(
        &reference,
        &resolver,
        sig_node,
        ReferenceSet::SignedInfo,
        0,
        false,
    )
    .unwrap();
    assert!(matches!(result.status, DsigStatus::Valid));
}

#[test]
fn reference_with_nonexistent_id_fails() {
    let xml = "<root><child/></root>";
    let doc = Document::parse(xml).unwrap();
    let resolver = UriReferenceResolver::new(&doc);

    let reference = make_reference("#nonexistent", vec![], DigestAlgorithm::Sha256, vec![0; 32]);
    let result = process_reference(
        &reference,
        &resolver,
        doc.root_element(),
        ReferenceSet::SignedInfo,
        0,
        false,
    );
    assert!(result.is_err());
}

#[test]
fn reference_with_absent_uri_fails_closed() {
    let xml = "<root><child>text</child></root>";
    let doc = Document::parse(xml).unwrap();
    let resolver = UriReferenceResolver::new(&doc);

    let reference = Reference {
        uri: None, // absent URI
        id: None,
        ref_type: None,
        transforms: vec![],
        digest_method: DigestAlgorithm::Sha256,
        digest_value: vec![0; 32],
    };

    let result = process_reference(
        &reference,
        &resolver,
        doc.root_element(),
        ReferenceSet::SignedInfo,
        0,
        false,
    );
    assert!(matches!(result, Err(ReferenceProcessingError::MissingUri)));
}

// ── process_all_references: fail-fast ────────────────────────────

#[test]
fn all_references_pass() {
    let xml = "<root><child>text</child></root>";
    let doc = Document::parse(xml).unwrap();
    let resolver = UriReferenceResolver::new(&doc);

    // Compute correct digest
    let initial_data = resolver.dereference("").unwrap();
    let pre_digest =
        crate::xmldsig::execute_transforms(doc.root_element(), initial_data, &[]).unwrap();
    let digest = compute_digest(DigestAlgorithm::Sha256, &pre_digest);

    let refs = vec![
        make_reference("", vec![], DigestAlgorithm::Sha256, digest.clone()),
        make_reference("", vec![], DigestAlgorithm::Sha256, digest),
    ];

    let result = process_all_references(&refs, &resolver, doc.root_element(), false).unwrap();
    assert!(result.all_valid());
    assert_eq!(result.results.len(), 2);
    assert!(result.first_failure.is_none());
}

#[test]
fn reference_processing_shares_xpath_work_across_references() {
    // A signature-wide meter must not reset when processing the next
    // Reference, even though each transform chain is independently valid.
    let document = Document::parse("<root/>").unwrap();
    let resolver = UriReferenceResolver::new(&document);
    let transform = Transform::XPath(super::super::transforms::XPathExpression::new("true()"));
    let initial_data = resolver.dereference("").unwrap();
    let pre_digest = crate::xmldsig::execute_transforms(
        document.root_element(),
        initial_data,
        std::slice::from_ref(&transform),
    )
    .unwrap();
    let digest = compute_digest(DigestAlgorithm::Sha256, &pre_digest);
    let references = vec![
        make_reference(
            "",
            vec![transform.clone()],
            DigestAlgorithm::Sha256,
            digest.clone(),
        ),
        make_reference("", vec![transform], DigestAlgorithm::Sha256, digest),
    ];
    let budget = TransformExecutionBudget::with_xpath_limit(12);
    let canonicalized_data_budget = CanonicalizedDataBudget::default();
    let execution = ReferenceExecutionContext {
        store_pre_digest: false,
        transform_options: TransformOptions::default(),
        transform_budget: &budget,
        canonicalized_data_budget: &canonicalized_data_budget,
        provider: crate::provider::default_provider(),
        capture: &(),
    };

    let error = process_all_references_with_options(
        &references,
        &resolver,
        document.root_element(),
        &execution,
    )
    .expect_err("the second Reference must consume the first Reference's XPath work");

    assert!(matches!(
        error,
        ReferenceProcessingError::Transform(TransformError::Policy(
            crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XPATH_EVALUATION_WORK,
                ..
            }
        ))
    ));
}

#[test]
fn reference_processing_shares_node_set_materialization_across_references() {
    // Repeated references to the same small subtree must share one owned-
    // string budget. Otherwise a large inherited namespace can be cloned
    // once per Reference even when canonicalization emits little output.
    let document = Document::parse(
        r#"<root xmlns:n="urn:0123456789"><target Id="selected">payload</target></root>"#,
    )
    .unwrap();
    let resolver = UriReferenceResolver::new(&document);
    let initial_data = resolver.dereference("#selected").unwrap();
    let pre_digest =
        crate::xmldsig::execute_transforms(document.root_element(), initial_data, &[]).unwrap();
    let digest = compute_digest(DigestAlgorithm::Sha256, &pre_digest);
    let references = vec![
        make_reference("#selected", vec![], DigestAlgorithm::Sha256, digest.clone()),
        make_reference("#selected", vec![], DigestAlgorithm::Sha256, digest),
    ];
    let budget = TransformExecutionBudget::with_node_set_materialization_limit(30);
    let canonicalized_data_budget = CanonicalizedDataBudget::default();
    let execution = ReferenceExecutionContext {
        store_pre_digest: false,
        transform_options: TransformOptions::default(),
        transform_budget: &budget,
        canonicalized_data_budget: &canonicalized_data_budget,
        provider: crate::provider::default_provider(),
        capture: &(),
    };

    let error = process_all_references_with_options(
        &references,
        &resolver,
        document.root_element(),
        &execution,
    )
    .expect_err("the second Reference must consume the first Reference's materialization work");

    assert!(matches!(
        error,
        ReferenceProcessingError::UriDereference(TransformError::Policy(
            crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::NODE_SET_CUMULATIVE_OWNED_STRING_BYTES,
                ..
            }
        ))
    ));
}

#[test]
fn every_reference_is_processed_after_a_mismatch() {
    // XMLDSig 1.1 §3.2.1 validates each Reference on its own: the first
    // mismatch is recorded, the remaining references still get results.
    let xml = "<root><child>text</child></root>";
    let doc = Document::parse(xml).unwrap();
    let resolver = UriReferenceResolver::new(&doc);

    let wrong_digest = vec![0u8; 32];
    let refs = vec![
        make_reference("", vec![], DigestAlgorithm::Sha256, wrong_digest.clone()),
        make_reference("#missing", vec![], DigestAlgorithm::Sha256, wrong_digest),
    ];

    let result = process_all_references(&refs, &resolver, doc.root_element(), false).unwrap();
    assert!(!result.all_valid());
    assert_eq!(result.first_failure, Some(0));
    assert_eq!(result.results.len(), 2);
    assert_eq!(
        result.results[0].status,
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
    );
    assert_eq!(
        result.results[1].status,
        DsigStatus::Invalid(FailureReason::ReferenceProcessingFailure { ref_index: 1 })
    );
}

#[test]
fn fail_fast_second_reference() {
    let xml = "<root><child>text</child></root>";
    let doc = Document::parse(xml).unwrap();
    let resolver = UriReferenceResolver::new(&doc);

    // Compute correct digest for first ref
    let initial_data = resolver.dereference("").unwrap();
    let pre_digest =
        crate::xmldsig::execute_transforms(doc.root_element(), initial_data, &[]).unwrap();
    let correct_digest = compute_digest(DigestAlgorithm::Sha256, &pre_digest);
    let wrong_digest = vec![0u8; 32];

    let refs = vec![
        make_reference("", vec![], DigestAlgorithm::Sha256, correct_digest),
        make_reference("", vec![], DigestAlgorithm::Sha256, wrong_digest),
    ];

    let result = process_all_references(&refs, &resolver, doc.root_element(), false).unwrap();
    assert!(!result.all_valid());
    assert_eq!(result.first_failure, Some(1));
    // Both references should be in results
    assert_eq!(result.results.len(), 2);
    assert!(matches!(result.results[0].status, DsigStatus::Valid));
    assert!(matches!(
        result.results[1].status,
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 1 })
    ));
}

#[test]
fn empty_references_list() {
    let xml = "<root/>";
    let doc = Document::parse(xml).unwrap();
    let resolver = UriReferenceResolver::new(&doc);

    let result = process_all_references(&[], &resolver, doc.root_element(), false).unwrap();
    assert!(result.all_valid());
    assert!(result.results.is_empty());
}

// ── Digest algorithms ────────────────────────────────────────────

#[test]
fn reference_sha1_digest() {
    let xml = "<root>content</root>";
    let doc = Document::parse(xml).unwrap();
    let resolver = UriReferenceResolver::new(&doc);

    let initial_data = resolver.dereference("").unwrap();
    let pre_digest =
        crate::xmldsig::execute_transforms(doc.root_element(), initial_data, &[]).unwrap();
    let digest = compute_digest(DigestAlgorithm::Sha1, &pre_digest);

    let reference = make_reference("", vec![], DigestAlgorithm::Sha1, digest);
    let result = process_reference(
        &reference,
        &resolver,
        doc.root_element(),
        ReferenceSet::SignedInfo,
        0,
        false,
    )
    .unwrap();
    assert!(matches!(result.status, DsigStatus::Valid));
    assert_eq!(result.digest_algorithm, DigestAlgorithm::Sha1);
}

#[test]
fn reference_sha512_digest() {
    let xml = "<root>content</root>";
    let doc = Document::parse(xml).unwrap();
    let resolver = UriReferenceResolver::new(&doc);

    let initial_data = resolver.dereference("").unwrap();
    let pre_digest =
        crate::xmldsig::execute_transforms(doc.root_element(), initial_data, &[]).unwrap();
    let digest = compute_digest(DigestAlgorithm::Sha512, &pre_digest);

    let reference = make_reference("", vec![], DigestAlgorithm::Sha512, digest);
    let result = process_reference(
        &reference,
        &resolver,
        doc.root_element(),
        ReferenceSet::SignedInfo,
        0,
        false,
    )
    .unwrap();
    assert!(matches!(result.status, DsigStatus::Valid));
    assert_eq!(result.digest_algorithm, DigestAlgorithm::Sha512);
}

// ── SAML-like end-to-end ─────────────────────────────────────────

#[test]
fn saml_enveloped_reference_processing() {
    // Realistic SAML Response with enveloped signature
    let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                                     ID="_resp1">
            <saml:Assertion ID="_assert1">
                <saml:Subject>user@example.com</saml:Subject>
            </saml:Assertion>
            <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:SignedInfo>
                    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                    <ds:Reference URI="">
                        <ds:Transforms>
                            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                        </ds:Transforms>
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>fakesig==</ds:SignatureValue>
            </ds:Signature>
        </samlp:Response>"#;
    let doc = Document::parse(xml).unwrap();
    let resolver = UriReferenceResolver::new(&doc);
    let sig_node = doc
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "Signature")
        .unwrap();

    // Parse SignedInfo to get the Reference
    let signed_info_node = sig_node
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "SignedInfo")
        .unwrap();
    let signed_info = parse_signed_info(signed_info_node).unwrap();
    let reference = &signed_info.references[0];

    // Compute the correct digest by running the actual pipeline
    let initial_data = resolver.dereference("").unwrap();
    let pre_digest =
        crate::xmldsig::execute_transforms(sig_node, initial_data, &reference.transforms).unwrap();
    let correct_digest = compute_digest(reference.digest_method, &pre_digest);

    // Build a reference with the correct digest
    let corrected_ref = make_reference(
        "",
        reference.transforms.clone(),
        reference.digest_method,
        correct_digest,
    );

    // Verify: should pass
    let result = process_reference(
        &corrected_ref,
        &resolver,
        sig_node,
        ReferenceSet::SignedInfo,
        0,
        true,
    )
    .unwrap();
    assert!(
        matches!(result.status, DsigStatus::Valid),
        "SAML reference should verify"
    );
    assert!(result.pre_digest_data.is_some());

    // Verify the pre-digest data contains the canonicalized document without Signature
    let pre_digest_str = String::from_utf8(result.pre_digest_data.unwrap()).unwrap();
    assert!(
        pre_digest_str.contains("samlp:Response"),
        "pre-digest should contain Response"
    );
    assert!(
        !pre_digest_str.contains("SignatureValue"),
        "pre-digest should NOT contain Signature"
    );
}

#[test]
fn pipeline_missing_signed_info_returns_missing_element() {
    let xml = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"></ds:Signature>"#;

    let err = verify_signature_with_pem_key(xml, "dummy-key", false)
        .expect_err("missing SignedInfo must fail before crypto stage");
    assert!(matches!(
        err,
        SignatureVerificationPipelineError::MissingElement {
            element: "SignedInfo"
        }
    ));
}

#[test]
fn pipeline_multiple_signature_elements_are_rejected() {
    let xml = r#"
<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:Signature>
    <ds:SignedInfo/>
  </ds:Signature>
  <ds:Signature/>
</root>
"#;

    let err = verify_signature_with_pem_key(xml, "dummy-key", false)
        .expect_err("multiple signatures must fail closed");
    assert!(matches!(
        err,
        SignatureVerificationPipelineError::InvalidStructure {
            reason: "Signature must appear exactly once in document",
        }
    ));
}

#[test]
fn pipeline_start_node_limits_signature_cardinality_to_its_subtree() {
    // A start-node selector changes the operation root, not global ID or
    // reference resolution; another Signature outside the subtree is irrelevant.
    let xml = r#"
<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <scope Id="selected"><ds:Signature/></scope>
  <scope Id="other"><ds:Signature/></scope>
</root>
"#;
    let err = VerifyContext::new()
        .start_node_id("selected")
        .verify(xml)
        .expect_err("the selected Signature remains structurally incomplete");
    assert!(matches!(
        err,
        SignatureVerificationPipelineError::MissingElement {
            element: "SignedInfo"
        }
    ));
}

#[test]
fn pipeline_reports_keyinfo_parse_error() {
    let xml = r#"
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
              xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:Reference URI="">
      <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>AA==</ds:SignatureValue>
  <ds:KeyInfo>
    <dsig11:DEREncodedKeyValue>%%%invalid%%%</dsig11:DEREncodedKeyValue>
  </ds:KeyInfo>
</ds:Signature>
"#;

    let err = VerifyContext::new()
        .verify(xml)
        .expect_err("invalid KeyInfo must map to ParseKeyInfo when no explicit key is supplied");
    assert!(matches!(
        err,
        SignatureVerificationPipelineError::ParseKeyInfo(_)
    ));
}

#[test]
fn pipeline_ignores_malformed_keyinfo_when_explicit_key_is_supplied() {
    let base_xml = signature_with_target_reference("AQ==");
    let xml = base_xml
            .replace(
                r#"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
                r#"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">"#,
            )
            .replace(
                "</ds:SignatureValue>\n  </ds:Signature>",
                "</ds:SignatureValue>\n    <ds:KeyInfo><dsig11:DEREncodedKeyValue>%%%invalid%%%</dsig11:DEREncodedKeyValue></ds:KeyInfo>\n  </ds:Signature>",
            );

    let result = VerifyContext::new()
        .key(&RejectingKey)
        .verify(&xml)
        .expect("explicit key path should not fail on malformed KeyInfo");
    assert!(matches!(
        result.status,
        DsigStatus::Invalid(FailureReason::SignatureMismatch)
    ));
}

#[test]
fn pipeline_rejects_foreign_element_children_under_signature() {
    let base_xml = signature_with_target_reference("AQ==");
    let xml = base_xml
        .replace(
            r#"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
            r#"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:foo="urn:example:foo">"#,
        )
        .replace(
            "</ds:SignedInfo>\n    <ds:SignatureValue>",
            "</ds:SignedInfo>\n    <foo:Bar/>\n    <ds:SignatureValue>",
        );

    let err = VerifyContext::new()
        .key(&RejectingKey)
        .verify(&xml)
        .expect_err("foreign element children under Signature must fail closed");
    assert!(matches!(
        err,
        SignatureVerificationPipelineError::InvalidStructure {
            reason: "Signature must contain only XMLDSIG element children",
        }
    ));
}

#[test]
fn pipeline_rejects_non_whitespace_mixed_content_under_signature() {
    let base_xml = signature_with_target_reference("AQ==");
    let xml = base_xml.replace(
        "</ds:SignedInfo>\n    <ds:SignatureValue>",
        "</ds:SignedInfo>\n    oops\n    <ds:SignatureValue>",
    );

    let err = VerifyContext::new()
        .key(&RejectingKey)
        .verify(&xml)
        .expect_err("non-whitespace mixed content under Signature must fail closed");
    assert!(matches!(
        err,
        SignatureVerificationPipelineError::InvalidStructure {
            reason: "Signature must not contain non-whitespace mixed content",
        }
    ));
}

#[test]
fn pipeline_rejects_keyinfo_out_of_order() {
    let base_xml = signature_with_target_reference("AQ==");
    let xml = base_xml.replace(
            "</ds:SignatureValue>\n  </ds:Signature>",
            "</ds:SignatureValue>\n    <ds:Object/>\n    <ds:KeyInfo><ds:KeyName>late</ds:KeyName></ds:KeyInfo>\n  </ds:Signature>",
        );

    let err = VerifyContext::new()
        .key(&RejectingKey)
        .verify(&xml)
        .expect_err("KeyInfo after Object must be rejected by Signature child order checks");
    assert!(matches!(
        err,
        SignatureVerificationPipelineError::InvalidStructure {
            reason: "KeyInfo must be the third element child of Signature when present"
        }
    ));
}

#[test]
fn pipeline_accepts_comments_and_processing_instructions_under_signature() {
    let xml = r#"
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <?dbg keep ?>
  <!-- signature metadata -->
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:Reference URI="">
      <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <!-- between required children -->
  <ds:SignatureValue>AA==</ds:SignatureValue>
</ds:Signature>
"#;

    let doc = Document::parse(xml).expect("test XML must parse");
    let signature_node = doc.root_element();
    let parsed = parse_signature_children(signature_node)
        .expect("comment/PI nodes under Signature must be ignored");

    assert_eq!(parsed.signed_info.tag_name().name(), "SignedInfo");
    assert_eq!(parsed.signature_value.tag_name().name(), "SignatureValue");
    assert!(parsed.key_info.is_none());
}
