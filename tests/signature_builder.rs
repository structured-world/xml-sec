use std::collections::HashSet;

use xml_sec::c14n::{C14nAlgorithm, C14nMode, canonicalize};
use xml_sec::policy::{PolicyViolation, SigningPolicy};
use xml_sec::xmldsig::transforms::MAX_TRANSFORMS_PER_REFERENCE;
use xml_sec::xmldsig::{
    DigestAlgorithm, ReferenceBuilder, SignatureAlgorithm, SignatureBuilder, SignatureBuilderError,
    Transform, UriTypeSet, XPathExpression, XPathFilter, XPathFilterOperation, parse_transforms,
};

const DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const XMLNS_NS: &str = "http://www.w3.org/2000/xmlns/";

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
    let xml = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::EcdsaSha256)
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
fn default_reference_serializes_explicit_same_document_uri() {
    // The signing parser requires a URI attribute. The builder's ergonomic
    // default therefore denotes the empty same-document URI rather than an
    // omitted attribute that would fail only after template serialization.
    let xml = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256))
        .build_template()
        .expect("the default reference must remain signable");
    let document = roxmltree::Document::parse(&xml).expect("valid XML");
    let reference = document
        .descendants()
        .find(|node| node.has_tag_name((DSIG_NS, "Reference")))
        .expect("Reference");

    assert_eq!(reference.attribute("URI"), Some(""));
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
        .expect_err("SHA-1 signatures are disabled by the default policy");
    assert!(matches!(
        sha1_signature,
        SignatureBuilderError::SigningAlgorithmDisabled(_)
    ));

    let sha1_digest = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha1))
        .build_template()
        .expect_err("SHA-1 digests are disabled by the default policy");
    assert!(matches!(
        sha1_digest,
        SignatureBuilderError::SigningAlgorithmDisabled(_)
    ));
}

#[test]
fn rejects_reserved_signature_namespace_prefixes() {
    // XML Namespaces reserves both spellings independently of whether a parser
    // happens to accept the resulting declaration syntax. Neither may be bound
    // to the XMLDSig namespace by the public template builder.
    for prefix in ["xml", "xmlns"] {
        let error = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
            .ns_prefix(prefix)
            .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256))
            .build_template()
            .expect_err("reserved namespace prefixes must fail before serialization");

        assert!(matches!(
            error,
            SignatureBuilderError::InvalidNamespacePrefix(value) if value == prefix
        ));
    }
}

#[test]
fn rejects_too_many_references_before_serialization() {
    // Builder output must obey the same cardinality bound as strict parsing and
    // execution instead of producing a template that signing later rejects.
    let mut builder = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256);
    for index in 0..65 {
        builder = builder.add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256).uri(format!("#item-{index}")),
        );
    }

    let error = builder
        .build_template()
        .expect_err("the builder must reject the 65th Reference");

    assert!(matches!(
        error,
        SignatureBuilderError::Policy(PolicyViolation::ResourceLimit {
            resource: "signature references",
            maximum: 64,
            actual: 65,
        })
    ));
}

#[test]
fn rejects_transform_chains_that_execution_cannot_accept() {
    // A builder-produced template must remain parseable and executable by the
    // same crate instead of deferring an oversized chain failure until signing.
    let mut reference = ReferenceBuilder::new(DigestAlgorithm::Sha256);
    for _ in 0..=MAX_TRANSFORMS_PER_REFERENCE {
        reference = reference.transform(Transform::Enveloped);
    }
    let error = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(reference)
        .build_template()
        .expect_err("builder must reject an oversized transform chain");

    assert!(matches!(
        error,
        SignatureBuilderError::Policy(PolicyViolation::ResourceLimit {
            resource: "reference transforms",
            ..
        })
    ));
}

#[test]
fn rejects_node_set_reference_when_implicit_c14n_is_disallowed() {
    // A node-set reference receives inclusive C14N 1.0 implicitly during
    // digest computation, so template validation must enforce that hidden
    // transform before emitting a template that signing cannot consume.
    let mut policy = SigningPolicy::default();
    policy.transforms.allowed_algorithms = Some(
        [
            exclusive_c14n().uri().to_owned(),
            xml_sec::xmldsig::ENVELOPED_SIGNATURE_URI.to_owned(),
        ]
        .into_iter()
        .collect(),
    );
    let error = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256).transform(Transform::Enveloped),
        )
        .build_template_with_policy(&policy)
        .expect_err("builder must enforce the implicit canonicalization transform");

    assert!(matches!(
        error,
        SignatureBuilderError::Policy(PolicyViolation::Algorithm {
            operation: "signing transform",
            algorithm,
        }) if algorithm == xml_sec::xmldsig::DEFAULT_IMPLICIT_C14N_URI
    ));
}

#[test]
fn rejects_xpath_sources_that_parsing_cannot_accept() {
    // Programmatic XPath and Filter 2.0 parameters must pass the same source
    // contract as serialized parameters parsed back during signing.
    let invalid_transforms = [
        ("empty", Transform::XPath(XPathExpression::new(""))),
        ("malformed", Transform::XPath(XPathExpression::new("("))),
        (
            "oversized",
            Transform::XPath(XPathExpression::new("x".repeat(16 * 1024 + 1))),
        ),
        (
            "filter2 malformed",
            Transform::XPathFilter2(vec![XPathFilter::new(
                XPathFilterOperation::Intersect,
                XPathExpression::new("("),
            )]),
        ),
    ];

    for (case, transform) in invalid_transforms {
        let error = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
            .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256).transform(transform))
            .build_template()
            .expect_err("builder must reject an unusable XPath source");
        assert!(error.to_string().contains("XPath"), "case: {case}");
    }
}

#[test]
fn rejects_xpath_namespace_budget_before_serialization() {
    // Parsing enforces the namespace budget for each XPath expression. The
    // builder must reject the same oversized expression before serialization.
    let mut expression = XPathExpression::new("true()");
    for index in 0..=1_024 {
        expression = expression.with_namespace(format!("p{index}"), "urn:test");
    }

    let error = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256).transform(Transform::XPath(expression)),
        )
        .build_template()
        .expect_err("builder must enforce the parser's per-expression namespace budget");

    assert!(matches!(
        error,
        SignatureBuilderError::Policy(PolicyViolation::ResourceLimit {
            resource: "XPath namespace bindings",
            ..
        })
    ));
}

#[test]
fn policy_aware_builder_validates_optimized_xpath_wire_form() {
    // The optimized variant still serializes one XPath expression with one
    // namespace binding. Builder validation must account for that wire form so
    // signing cannot reject a template accepted under the same policy.
    let builder = || {
        SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256).add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .transform(Transform::XpathExcludeAllSignatures),
        )
    };
    let mut policies = Vec::new();

    let expression_count = SigningPolicy {
        resources: xml_sec::policy::ResourcePolicy {
            max_xpath_expressions: 0,
            ..xml_sec::policy::ResourcePolicy::default()
        },
        ..SigningPolicy::default()
    };
    policies.push(("XPath expressions", expression_count));

    let expression_bytes = SigningPolicy {
        resources: xml_sec::policy::ResourcePolicy {
            max_xpath_expression_bytes: 1,
            ..xml_sec::policy::ResourcePolicy::default()
        },
        ..SigningPolicy::default()
    };
    policies.push(("XPath expression bytes", expression_bytes));

    let expression_complexity = SigningPolicy {
        resources: xml_sec::policy::ResourcePolicy {
            max_xpath_expression_complexity: 0,
            ..xml_sec::policy::ResourcePolicy::default()
        },
        ..SigningPolicy::default()
    };
    policies.push(("XPath expression complexity", expression_complexity));

    let namespace_bindings = SigningPolicy {
        resources: xml_sec::policy::ResourcePolicy {
            max_xpath_namespace_bindings: 0,
            ..xml_sec::policy::ResourcePolicy::default()
        },
        ..SigningPolicy::default()
    };
    policies.push(("XPath namespace bindings", namespace_bindings));

    for (expected_resource, policy) in policies {
        let error = builder()
            .build_template_with_policy(&policy)
            .expect_err("optimized XPath wire content must obey builder policy");
        let SignatureBuilderError::Policy(PolicyViolation::ResourceLimit { resource, .. }) = error
        else {
            panic!("expected {expected_resource} resource rejection, got {error}");
        };
        assert_eq!(resource, expected_resource);
    }
}

#[test]
fn rejects_signature_wide_xpath_expression_budget() {
    // Builder output must obey the parser's aggregate bound rather than emit a
    // template that becomes unacceptable only when signing reparses SignedInfo.
    let filters = (0..64)
        .map(|_| {
            XPathFilter::new(
                XPathFilterOperation::Intersect,
                XPathExpression::new("true()"),
            )
        })
        .collect::<Vec<_>>();
    let mut max_reference = ReferenceBuilder::new(DigestAlgorithm::Sha256).uri("#item-0");
    for _ in 0..64 {
        max_reference = max_reference.transform(Transform::XPathFilter2(filters.clone()));
    }
    let mut builder = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(max_reference);
    builder
        .clone()
        .build_template()
        .expect("one maximum-shaped Reference must remain accepted");
    builder = builder.add_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("#item-1")
            .transform(Transform::XPath(XPathExpression::new("true()"))),
    );

    let error = builder
        .build_template()
        .expect_err("builder must enforce the signature-wide XPath expression budget");

    assert!(matches!(
        error,
        SignatureBuilderError::Policy(PolicyViolation::ResourceLimit {
            resource: "XPath expressions",
            ..
        })
    ));
}

#[test]
fn accepts_repeated_inherited_prefix_within_each_xpath_budget() {
    // Every serialized Filter2 XPath inherits the signature prefix independently;
    // one expression must not consume another expression's namespace allowance.
    let filters = (0..64)
        .map(|_| {
            XPathFilter::new(
                XPathFilterOperation::Intersect,
                XPathExpression::new("true()"),
            )
        })
        .collect::<Vec<_>>();
    let reference = (0..17).fold(
        ReferenceBuilder::new(DigestAlgorithm::Sha256),
        |reference, _| reference.transform(Transform::XPathFilter2(filters.clone())),
    );

    let policy = SigningPolicy {
        resources: xml_sec::policy::ResourcePolicy {
            max_xpath_namespace_bindings: 1,
            ..xml_sec::policy::ResourcePolicy::default()
        },
        ..SigningPolicy::default()
    };
    let xml = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .ns_prefix("ds")
        .add_reference(reference)
        .build_template_with_policy(&policy)
        .expect("each XPath contains exactly one inherited namespace binding");

    let document = roxmltree::Document::parse(&xml).expect("builder output must remain valid XML");
    assert_eq!(
        document
            .descendants()
            .filter(
                |node| node.has_tag_name((xml_sec::xmldsig::XPATH_FILTER2_TRANSFORM_URI, "XPath"))
            )
            .count(),
        17 * 64
    );
}

#[test]
fn policy_aware_builder_uses_the_callers_resource_snapshot() {
    // The high-level signing path must not silently validate against defaults
    // before applying its caller-selected immutable policy.
    let mut policy = SigningPolicy::default();
    policy.resources.max_references = 1;
    let builder = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256).uri("#first"))
        .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256).uri("#second"));

    let error = builder
        .build_template_with_policy(&policy)
        .expect_err("the selected signing policy must reach the builder");

    assert!(matches!(
        error,
        SignatureBuilderError::Policy(PolicyViolation::ResourceLimit {
            resource: "signature references",
            maximum: 1,
            actual: 2,
        })
    ));
}

#[test]
fn policy_aware_builder_bounds_the_serialized_template() {
    // Builder validation must cover the completed XML artifact, not only the
    // individual fields that contributed to it. Otherwise the same policy
    // accepts a template here and rejects it immediately when signing starts.
    let builder = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256));

    let mut byte_policy = SigningPolicy::default();
    byte_policy.resources.max_xml_document_bytes = 1;
    let byte_error = builder
        .build_template_with_policy(&byte_policy)
        .expect_err("serialized template must obey the XML byte limit");
    assert!(matches!(
        byte_error,
        SignatureBuilderError::Policy(PolicyViolation::ResourceLimit {
            resource: "XML document",
            maximum: 1,
            actual,
        }) if actual > 1
    ));

    let mut node_policy = SigningPolicy::default();
    node_policy.resources.max_xml_nodes = 1;
    let node_error = builder
        .build_template_with_policy(&node_policy)
        .expect_err("serialized template must obey the XML node limit");
    assert!(matches!(
        node_error,
        SignatureBuilderError::Policy(PolicyViolation::ResourceLimit {
            resource: "XML nodes",
            maximum: 1,
            actual: 2,
        })
    ));
}

#[test]
fn policy_aware_builder_bounds_signed_info_canonicalization() {
    // The policy-aware builder must not emit a template that the signing path
    // immediately rejects while canonicalizing the generated SignedInfo.
    let builder = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256));
    let mut policy = SigningPolicy::default();
    policy.resources.max_canonicalized_bytes = 0;

    let error = builder
        .build_template_with_policy(&policy)
        .expect_err("generated SignedInfo must obey the canonicalization budget");

    assert!(matches!(
        error,
        SignatureBuilderError::Policy(PolicyViolation::ResourceLimit {
            maximum: 0,
            actual,
            ..
        }) if actual > 0
    ));
}

#[test]
fn policy_aware_builder_accounts_for_filled_digest_values() {
    // Signing fills each DigestValue before canonicalizing SignedInfo, so an
    // empty-template measurement would undercount every reference digest.
    let builder = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256));
    let template = builder.build_template().expect("valid empty template");
    let document = roxmltree::Document::parse(&template).expect("builder output must parse");
    let signed_info = document
        .descendants()
        .find(|node| node.has_tag_name((DSIG_NS, "SignedInfo")))
        .expect("generated SignedInfo");
    let signed_info_subtree: HashSet<_> = signed_info.descendants().map(|node| node.id()).collect();
    let mut empty_canonical = Vec::new();
    canonicalize(
        &document,
        Some(&|node| signed_info_subtree.contains(&node.id())),
        &exclusive_c14n(),
        &mut empty_canonical,
    )
    .expect("empty SignedInfo must canonicalize");
    let mut policy = SigningPolicy::default();
    policy.resources.max_canonicalized_bytes = empty_canonical.len();

    let error = builder
        .build_template_with_policy(&policy)
        .expect_err("filled SHA-256 digest text must exceed the empty-form budget");

    assert!(matches!(
        error,
        SignatureBuilderError::Policy(PolicyViolation::ResourceLimit {
            maximum,
            actual,
            ..
        }) if maximum == empty_canonical.len() && actual > maximum
    ));
}

#[test]
fn policy_aware_builder_rejects_unavailable_external_references() {
    // Allowing an external URI class does not provide the request-scoped bytes
    // that the signing API would need to digest that resource.
    let builder = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256).uri("https://example.invalid/payload"),
        );
    let mut policy = SigningPolicy::default();
    policy.uris.references = UriTypeSet::ALL;

    let error = builder
        .build_template_with_policy(&policy)
        .expect_err("builder must not emit a template the signing API cannot resolve");

    assert!(matches!(
        error,
        SignatureBuilderError::Policy(PolicyViolation::Uri {
            operation: "signing",
            reason: "external signing references require request-scoped resource bytes",
        })
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
fn serializes_and_reparses_general_xpath_filter2_parameters() {
    // Builder output must preserve expression order, operations, escaping,
    // and prefix bindings because all four affect the resulting node set.
    let filters = vec![
        XPathFilter::new(
            XPathFilterOperation::Intersect,
            XPathExpression::new("//doc:Record[@active = 'yes']")
                .with_namespace("doc", "urn:documents"),
        ),
        XPathFilter::new(
            XPathFilterOperation::Subtract,
            XPathExpression::new("//doc:Secret").with_namespace("doc", "urn:documents"),
        ),
    ];
    let xml = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .ns_prefix("ds")
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .transform(Transform::XPathFilter2(filters)),
        )
        .build_template()
        .expect("valid XPath Filter 2.0 template");
    let document = roxmltree::Document::parse(&xml).expect("builder must emit valid XML");
    let transforms = document
        .descendants()
        .find(|node| node.has_tag_name((DSIG_NS, "Transforms")))
        .expect("Transforms element");
    let parsed = parse_transforms(transforms).expect("serialized filters must parse");
    let [Transform::XPathFilter2(parsed_filters)] = parsed.as_slice() else {
        panic!("expected XPath Filter 2.0 transform");
    };

    assert_eq!(parsed_filters.len(), 2);
    assert_eq!(
        parsed_filters[0].operation(),
        XPathFilterOperation::Intersect
    );
    assert_eq!(
        parsed_filters[0].xpath().expression(),
        "//doc:Record[@active = 'yes']"
    );
    assert_eq!(
        parsed_filters[0]
            .xpath()
            .namespaces()
            .get("doc")
            .map(String::as_str),
        Some("urn:documents")
    );
    assert_eq!(
        parsed_filters[1].operation(),
        XPathFilterOperation::Subtract
    );
}

#[test]
fn allows_filter2_binding_that_matches_signature_prefix() {
    // Filter2 XPath parameters use the Filter2 namespace as their default
    // namespace, so a local `ds` binding cannot rebind XMLDSig elements.
    let filters = vec![XPathFilter::new(
        XPathFilterOperation::Intersect,
        XPathExpression::new("//ds:Record").with_namespace("ds", "urn:documents"),
    )];
    let xml = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .ns_prefix("ds")
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .transform(Transform::XPathFilter2(filters)),
        )
        .build_template()
        .expect("Filter2-local bindings must not conflict with the signature prefix");
    let document = roxmltree::Document::parse(&xml).expect("builder must emit valid XML");
    let xpath = document
        .descendants()
        .find(|node| node.has_tag_name(("http://www.w3.org/2002/06/xmldsig-filter2", "XPath")))
        .expect("Filter2 XPath child");

    assert_eq!(
        xpath.lookup_namespace_uri(Some("ds")),
        Some("urn:documents")
    );
}

#[test]
fn rejects_xml_forbidden_characters_in_xpath_namespace_uris() {
    // XML escaping cannot legalize control characters forbidden by XML 1.0;
    // a successful builder result must therefore always remain parseable.
    for uri in ["urn:invalid:\0", "urn:invalid:\u{1}"] {
        let error = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
            .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256).transform(
                Transform::XPath(XPathExpression::new("//doc:item").with_namespace("doc", uri)),
            ))
            .build_template()
            .expect_err("XML-forbidden namespace URI characters must fail at the builder");

        assert!(error.to_string().contains("forbidden by XML 1.0"));
    }
}

#[test]
fn rejects_xml_forbidden_characters_in_xpath_expressions() {
    // XPath grammar accepts string literals that XML 1.0 cannot serialize. The
    // builder must reject both parameter forms rather than return an XML string
    // that the signing pipeline cannot parse again.
    let expression = "contains(., '\u{B}')";
    let transforms = [
        Transform::XPath(XPathExpression::new(expression)),
        Transform::XPathFilter2(vec![XPathFilter::new(
            XPathFilterOperation::Intersect,
            XPathExpression::new(expression),
        )]),
    ];

    for transform in transforms {
        let error = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
            .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256).transform(transform))
            .build_template()
            .expect_err("XML-forbidden XPath characters must fail at the builder boundary");

        assert!(error.to_string().contains("forbidden by XML 1.0"));
    }
}

#[test]
fn rejects_invalid_filter2_expression_counts() {
    // Builder output is reparsed by signing, so it must enforce the same
    // non-empty, bounded Filter2 sequence accepted by the transform parser.
    let oversized = (0..65)
        .map(|_| {
            XPathFilter::new(
                XPathFilterOperation::Intersect,
                XPathExpression::new("/root"),
            )
        })
        .collect::<Vec<_>>();

    let build = |filters| {
        SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
            .add_reference(
                ReferenceBuilder::new(DigestAlgorithm::Sha256)
                    .transform(Transform::XPathFilter2(filters)),
            )
            .build_template()
    };

    assert!(matches!(
        build(Vec::new()).expect_err("empty Filter2 must fail at the builder boundary"),
        SignatureBuilderError::InvalidXPath(_)
    ));
    assert!(matches!(
        build(oversized).expect_err("oversized Filter2 must fail at the builder boundary"),
        SignatureBuilderError::Policy(PolicyViolation::ResourceLimit {
            resource: "XPath filters",
            maximum: 64,
            actual: 65,
        })
    ));
}

#[test]
fn rejects_xpath_binding_that_shadows_signature_prefix() {
    // Rebinding the prefix used for ds:XPath changes the element namespace and
    // produces a template that neither the strict parser nor a signer can use.
    let error = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .ns_prefix("ds")
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256).transform(Transform::XPath(
                XPathExpression::new("//ds:item").with_namespace("ds", "urn:payload"),
            )),
        )
        .build_template()
        .expect_err("XPath namespace bindings must not shadow the signature prefix");

    assert!(error.to_string().contains("ds"));
}

#[test]
fn rejects_xpath_binding_that_redefines_xml_prefix() {
    // XML Namespaces permanently binds `xml` to the XML namespace. Accepting
    // another URI would change the XPath context when serialization omits the
    // reserved declaration.
    let error = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256).transform(Transform::XPath(
                XPathExpression::new("//xml:item").with_namespace("xml", "urn:not-xml"),
            )),
        )
        .build_template()
        .expect_err("the xml prefix cannot be rebound to another namespace");

    assert!(matches!(
        error,
        SignatureBuilderError::InvalidNamespacePrefix(prefix) if prefix == "xml"
    ));
}

#[test]
fn rejects_xpath_binding_that_aliases_xml_namespace() {
    // The XML namespace is reserved for the `xml` prefix; declaring an alias
    // would produce a document that violates the namespace constraints.
    let error = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256).transform(Transform::XPath(
                XPathExpression::new("//alias:item")
                    .with_namespace("alias", "http://www.w3.org/XML/1998/namespace"),
            )),
        )
        .build_template()
        .expect_err("the XML namespace cannot be assigned to another prefix");

    assert!(matches!(
        error,
        SignatureBuilderError::InvalidNamespacePrefix(prefix) if prefix == "alias"
    ));
}

#[test]
fn rejects_xpath_bindings_with_invalid_namespace_uris() {
    // Empty namespace names and the namespace-declaration namespace cannot be
    // bound to an XPath prefix in either XMLDSig XPath parameter form.
    let transforms = [
        Transform::XPath(XPathExpression::new("//doc:item").with_namespace("doc", "")),
        Transform::XPath(XPathExpression::new("//doc:item").with_namespace("doc", XMLNS_NS)),
        Transform::XPathFilter2(vec![XPathFilter::new(
            XPathFilterOperation::Intersect,
            XPathExpression::new("//doc:item").with_namespace("doc", ""),
        )]),
        Transform::XPathFilter2(vec![XPathFilter::new(
            XPathFilterOperation::Intersect,
            XPathExpression::new("//doc:item").with_namespace("doc", XMLNS_NS),
        )]),
    ];

    for transform in transforms {
        let error = SignatureBuilder::new(exclusive_c14n(), SignatureAlgorithm::RsaSha256)
            .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256).transform(transform))
            .build_template()
            .expect_err("invalid namespace URI must be rejected before serialization");
        assert!(matches!(
            error,
            SignatureBuilderError::InvalidNamespaceUri(uri)
                if uri.is_empty() || uri == XMLNS_NS
        ));
    }
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

    // Interpolation turns these into valid documents with comment/PI nodes before
    // `<valid/>`; parser success alone accepted them before the exact-name check.
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
