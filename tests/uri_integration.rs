//! Integration tests: URI dereference → NodeSet → C14N canonicalization.
//!
//! Verifies that dereferencing a URI produces a NodeSet that, when used as
//! a predicate for C14N, produces the correct canonical output.

#![cfg(all(feature = "xmldsig", feature = "c14n"))]

use xml_sec::c14n::{C14nAlgorithm, C14nMode, canonicalize};
use xml_sec::xmldsig::NodeSet;
use xml_sec::xmldsig::uri::UriReferenceResolver;

#[test]
fn xml_id_errors_are_reported_without_losing_id_assignment() {
    // xml:id sections 4/6 specify non-fatal diagnostics, not parse rejection.
    for backend in xml_sec::XmlBackend::available() {
        for (xml, expected) in [
            (
                "<root xml:id=' bad value '/>",
                Some(xml_sec::XmlIdError::InvalidNcName),
            ),
            (
                "<!DOCTYPE root [<!ATTLIST root xml:id CDATA #IMPLIED>]><root xml:id=' bad value '/>",
                Some(xml_sec::XmlIdError::InvalidNcNameAndDeclaredType),
            ),
            (
                "<!DOCTYPE root [<!ATTLIST root xml:id CDATA #IMPLIED>]><root xml:id='target'/>",
                Some(xml_sec::XmlIdError::InvalidDeclaredType),
            ),
            (
                "<!DOCTYPE root [<!ATTLIST root xml:id ID #IMPLIED><!ATTLIST root xml:id CDATA #IMPLIED>]><root xml:id='target'/>",
                Some(xml_sec::XmlIdError::InvalidDeclaredType),
            ),
            ("<root xml:id=' valid '/>", None),
        ] {
            let document = xml_sec::Document::parse_with_options_and_backend(
                xml,
                xml_sec::ParsingOptions {
                    allow_dtd: true,
                    ..Default::default()
                },
                backend,
            )
            .unwrap();
            let attribute = document.root_element().attributes().next().unwrap();
            assert!(attribute.is_id());
            assert_eq!(attribute.xml_id_error(), expected, "{backend:?}: {xml}");
        }
    }
}

#[test]
fn dtd_ids_and_xml_ids_share_the_normalized_semantic_index() {
    // Internal DTD ID assignment and xml:id normalization must be identical
    // across parsers, borrowed resolution and retained document identities.
    let xml = "<!DOCTYPE root [<!ATTLIST item Token ID #REQUIRED>]><root><item Token='  target  '/><other xml:id='  other  '/></root>";
    let mut policy = xml_sec::policy::VerificationPolicy::default();
    policy.xml.allow_internal_dtd = true;
    let document = xml_sec::XmlDocument::parse_with_policy(xml, &policy).unwrap();
    document.with_view(|view| {
        let target = view.node_for_id("target", &[]).unwrap();
        assert!(view.attribute_identity(target, None, "Token").is_ok());
        assert!(view.node_for_id("other", &[]).is_some());
        assert!(view.node_for_id("  target  ", &[]).is_none());
    });
    let parsed = xml_sec::Document::parse_with_options(
        xml,
        xml_sec::ParsingOptions {
            allow_dtd: true,
            ..Default::default()
        },
    )
    .unwrap();
    let resolver = UriReferenceResolver::new(&parsed);
    let target = resolver.node_for_id("target").unwrap();
    assert_eq!(target.attribute("Token"), Some("target"));
    assert!(target.attributes().next().unwrap().is_id());
    assert!(
        resolver
            .node_for_same_document_reference("#target")
            .unwrap()
            .is_some()
    );
    assert!(
        resolver
            .node_for_same_document_reference("#xpointer( id ( 'other' ) )")
            .unwrap()
            .is_some()
    );
}

#[test]
fn dtd_ids_use_lexical_qnames_and_xml_ids_preserve_character_references() {
    // DTD names are lexical QNames, not expanded names. XML 1.0 3.3.3
    // collapses spaces but preserves whitespace introduced by character refs.
    let xml = "<!DOCTYPE root [<!ATTLIST p:item p:Token ID #IMPLIED>]><root xmlns:p='urn:item' xmlns:q='urn:item'><p:item p:Token=' target '/><q:item q:Token='foreign'/><other xml:id=' a&#9;b '/></root>";
    let document = xml_sec::Document::parse_with_options(
        xml,
        xml_sec::ParsingOptions {
            allow_dtd: true,
            ..Default::default()
        },
    )
    .unwrap();
    let resolver = UriReferenceResolver::new(&document);
    assert!(resolver.has_id("target"));
    assert!(!resolver.has_id("foreign"));
    assert!(resolver.has_id("a\tb"));
    assert!(!resolver.has_id("a b"));
}

#[test]
fn unqualified_attribute_registration_and_duplicate_xml_ids() {
    // An explicit unqualified registration excludes foreign namespaced
    // attributes; normalized xml:id duplicates remain ambiguous.
    let source = "<root xmlns:f='urn:foreign'><item Token='target'/><other f:Token='target'/><a xml:id='same'/><b xml:id=' same '/></root>";
    let document = xml_sec::Document::parse(source).unwrap();
    let registrations =
        [xml_sec::IdAttributeRegistration::global("Token").with_attribute_namespace(None)];
    let resolver = UriReferenceResolver::with_id_registrations(&document, &registrations);
    assert_eq!(
        resolver.node_for_id("target").unwrap().tag_name().name(),
        "item"
    );
    assert!(resolver.dereference("#same").is_err());
    let retained = xml_sec::XmlDocument::parse(source).unwrap();
    retained.with_view(|view| {
        assert!(view.node_for_id("target", &registrations).is_some());
        assert!(view.node_for_id("same", &registrations).is_none());
    });
}

#[test]
fn exact_attribute_namespace_registration_rejects_foreign_collisions() {
    // A caller's exact namespace registration must not register an attacker
    // attribute with the same local name, on either resolver path.
    let xml = "<root xmlns:t='urn:trusted' xmlns:f='urn:foreign'><item t:Token='target'/><item f:Token='target'/></root>";
    let registrations = [xml_sec::IdAttributeRegistration::global("Token")
        .with_attribute_namespace(Some("urn:trusted"))];
    let parsed = xml_sec::Document::parse(xml).unwrap();
    let resolver = UriReferenceResolver::with_id_registrations(&parsed, &registrations);
    assert_eq!(
        resolver
            .node_for_id("target")
            .unwrap()
            .attribute(("urn:trusted", "Token")),
        Some("target")
    );
    let document = xml_sec::XmlDocument::parse(xml).unwrap();
    document.with_view(|view| {
        let target = view.node_for_id("target", &registrations).unwrap();
        assert!(
            view.attribute_identity(target, Some("urn:trusted"), "Token")
                .is_ok()
        );
        assert!(
            view.attribute_identity(target, Some("urn:foreign"), "Token")
                .is_err()
        );
    });
    let broad = [xml_sec::IdAttributeRegistration::global("Token")];
    assert!(
        UriReferenceResolver::with_id_registrations(&parsed, &broad)
            .node_for_id("target")
            .is_none()
    );
    document.with_view(|view| assert!(view.node_for_id("target", &broad).is_none()));
}

#[test]
fn dtd_type_assignment_ignores_quoted_and_commented_declarations() {
    // Declaration-like replacement text must never confer ID type; the first
    // real declaration wins, and registration remains element-name scoped.
    let xml = "<!DOCTYPE root [<!-- <!ATTLIST item Token ID #IMPLIED> --><!ENTITY dec '<!ATTLIST item Token ID #IMPLIED>'><!ATTLIST item Token CDATA #IMPLIED><!ATTLIST item Token ID #IMPLIED>]><root><item Token='target'/><other Token='other'/></root>";
    let parsed = xml_sec::Document::parse_with_options(
        xml,
        xml_sec::ParsingOptions {
            allow_dtd: true,
            ..Default::default()
        },
    )
    .unwrap();
    let resolver = UriReferenceResolver::new(&parsed);
    assert!(!resolver.has_id("target"));
    assert!(!resolver.has_id("other"));
}

#[test]
fn dtd_id_generation_is_rebuilt_after_controlled_mutation() {
    // Changing a DTD-typed ID must retire the old generation and update the
    // retained ID index, not preserve a stale target from the preceding parse.
    let mut policy = xml_sec::policy::VerificationPolicy::default();
    policy.xml.allow_internal_dtd = true;
    let mut document = xml_sec::XmlDocument::parse_with_policy(
        "<!DOCTYPE root [<!ATTLIST item Token ID #IMPLIED>]><root><item Token='old'/></root>",
        &policy,
    )
    .unwrap();
    let old = document.with_view(|view| view.node_for_id("old", &[]).unwrap());
    document
        .replace_element(old, "<item Token='new'/>")
        .unwrap();
    document.with_view(|view| {
        assert!(view.document_order(old).is_err());
        assert!(view.node_for_id("old", &[]).is_none());
        assert!(view.node_for_id("new", &[]).is_some());
    });
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Dereference `uri`, build a C14N predicate from the resulting NodeSet,
/// canonicalize with inclusive C14N 1.0, and return the canonical string.
fn deref_and_canonicalize(xml: &str, uri: &str) -> String {
    deref_and_canonicalize_impl(xml, uri, false)
}

/// Same but with comments enabled (for xpointer(/) which includes comments).
fn deref_and_canonicalize_with_comments(xml: &str, uri: &str) -> String {
    deref_and_canonicalize_impl(xml, uri, true)
}

/// Shared implementation for dereferencing and canonicalizing, parameterized
/// by whether comments should be included.
fn deref_and_canonicalize_impl(xml: &str, uri: &str, with_comments: bool) -> String {
    let doc = roxmltree::Document::parse(xml).expect("parse");
    let resolver = UriReferenceResolver::new(&doc);

    let data = resolver.dereference(uri).expect("dereference");
    let node_set = data.into_node_set().expect("into_node_set");

    let algo = C14nAlgorithm::new(C14nMode::Inclusive1_0, with_comments);
    let predicate = |n: roxmltree::Node| node_set.contains(n);
    let mut output = Vec::new();
    canonicalize(&doc, Some(&predicate), &algo, &mut output).expect("canonicalize");
    String::from_utf8(output).expect("utf8")
}

// ─── Empty URI: whole document without comments ─────────────────────────────

#[test]
fn empty_uri_canonicalizes_whole_document() {
    let xml = r#"<root b="2" a="1"><child/></root>"#;
    let result = deref_and_canonicalize(xml, "");
    // C14N sorts attributes and expands empty elements
    assert_eq!(result, r#"<root a="1" b="2"><child></child></root>"#);
}

#[test]
fn empty_uri_strips_comments() {
    let xml = "<root><!-- comment --><child>text</child></root>";
    let result = deref_and_canonicalize(xml, "");
    // Comment should be stripped for empty URI dereference
    assert_eq!(result, "<root><child>text</child></root>");
}

#[test]
fn empty_uri_with_namespaces() {
    let xml = r#"<root xmlns:a="http://a" xmlns:b="http://b"><a:child b:attr="val"/></root>"#;
    let result = deref_and_canonicalize(xml, "");
    // Inclusive C14N: root declares both ns, child suppresses redundant redeclarations
    assert_eq!(
        result,
        r#"<root xmlns:a="http://a" xmlns:b="http://b"><a:child b:attr="val"></a:child></root>"#
    );
}

#[test]
fn empty_uri_accepts_a_node_set_above_the_old_ceiling() {
    // A dense namespace projection with more than 65,536 entries must fit the
    // low-level hard ceiling; previously that ceiling rejected it.
    let namespaces = (0..257)
        .map(|index| format!(r#" xmlns:n{index}="urn:{index}""#))
        .collect::<String>();
    let xml = format!("<root{namespaces}>{}</root>", "<item/>".repeat(257));
    let document = roxmltree::Document::parse(&xml).expect("generated XML must parse");
    let set = NodeSet::entire_document_without_comments(&document)
        .expect("a node set just above the former limit must fit");
    assert!(set.contains(document.root_element()));
}

#[test]
fn empty_uri_rejects_quadratic_namespace_materialization() {
    // In-scope namespace nodes are projected for every owner element. Bound the
    // declarations-by-elements product before allocating the backing set.
    let namespaces = (0..257)
        .map(|index| format!(r#" xmlns:n{index}="urn:{index}""#))
        .collect::<String>();
    let xml = format!("<root{namespaces}>{}</root>", "<item/>".repeat(2048));
    let document = roxmltree::Document::parse(&xml).expect("generated XML must parse");
    let error = match UriReferenceResolver::new(&document).dereference("") {
        Err(error) => error,
        Ok(_) => panic!("oversized namespace projection must fail before materialization"),
    };

    assert!(matches!(
        error,
        xml_sec::xmldsig::TransformError::Policy(xml_sec::policy::PolicyViolation::ResourceLimit {
            resource: "node-set entries",
            maximum: 524_288,
            ..
        })
    ));

    let direct_error = match NodeSet::entire_document_without_comments(&document) {
        Err(error) => error,
        Ok(_) => panic!("public constructors must enforce the materialization budget"),
    };
    assert!(matches!(
        direct_error,
        xml_sec::xmldsig::TransformError::Policy(xml_sec::policy::PolicyViolation::ResourceLimit {
            resource: "node-set entries",
            maximum: 524_288,
            ..
        })
    ));
}

// ─── #id: subtree by ID ─────────────────────────────────────────────────────

#[test]
fn fragment_id_canonicalizes_subtree_only() {
    let xml = r#"<root><before>skip</before><target ID="t1"><inner a="1">text</inner></target><after>skip</after></root>"#;
    let result = deref_and_canonicalize(xml, "#t1");
    // Only the target subtree should appear; root, before, after excluded
    assert_eq!(
        result,
        r#"<target ID="t1"><inner a="1">text</inner></target>"#
    );
}

#[test]
fn fragment_id_excludes_comments_in_subtree() {
    // XMLDSig bare-name dereference strips comments even when C14N retains them.
    let xml = r#"<root><item ID="x"><!-- keep this --><child/></item></root>"#;
    let result = deref_and_canonicalize_with_comments(xml, "#x");
    assert_eq!(result, r#"<item ID="x"><child></child></item>"#);
}

#[test]
fn fragment_id_inherits_ancestor_namespaces() {
    // When canonicalizing a subtree, inclusive C14N emits in-scope namespaces
    // from ancestor elements even though those ancestors are not in the node set
    let xml =
        r#"<root xmlns:ns="http://example.com"><ns:item ID="sub"><ns:child/></ns:item></root>"#;
    let result = deref_and_canonicalize(xml, "#sub");
    // ns:item declares xmlns:ns (inherited from root ancestor outside subset).
    // ns:child suppresses redundant redeclaration since parent ns:item already declared it.
    assert_eq!(
        result,
        r#"<ns:item xmlns:ns="http://example.com" ID="sub"><ns:child></ns:child></ns:item>"#
    );
}

// ─── #xpointer(/) : whole document WITH comments ───────────────────────────

#[test]
fn xpointer_root_includes_comments() {
    let xml = "<root><!-- visible --><child/></root>";
    let result = deref_and_canonicalize_with_comments(xml, "#xpointer(/)");
    // xpointer(/) includes comments, unlike empty URI
    assert_eq!(result, "<root><!-- visible --><child></child></root>");
}

#[test]
fn xpointer_root_vs_empty_uri_comment_difference() {
    let xml = "<root><!-- comment --><child/></root>";

    let empty_uri = deref_and_canonicalize(xml, "");
    let xpointer_root = deref_and_canonicalize_with_comments(xml, "#xpointer(/)");

    // Empty URI: comments stripped
    assert_eq!(empty_uri, "<root><child></child></root>");
    // xpointer(/): comments preserved
    assert_eq!(
        xpointer_root,
        "<root><!-- comment --><child></child></root>"
    );
}

// ─── #xpointer(id('...')) : equivalent to bare-name ────────────────────────

#[test]
fn xpointer_id_canonicalizes_same_as_bare_name() {
    let xml = r#"<root><item ID="abc"><child>data</child></item></root>"#;

    let bare_name = deref_and_canonicalize(xml, "#abc");
    let xpointer = deref_and_canonicalize(xml, "#xpointer(id('abc'))");

    assert_eq!(bare_name, xpointer);
}

// ─── SAML-like scenario ─────────────────────────────────────────────────────

#[test]
fn saml_assertion_subtree_canonicalization() {
    // Realistic SAML: dereference assertion by ID, canonicalize the subtree
    let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1">
  <saml:Assertion ID="_a1">
    <saml:Subject>user@example.com</saml:Subject>
  </saml:Assertion>
</samlp:Response>"#;

    let result = deref_and_canonicalize(xml, "#_a1");

    // Assertion subtree with inherited namespace declarations
    assert!(
        result.contains("xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\""),
        "should inherit saml namespace from ancestor: {result}"
    );
    assert!(
        result.contains("<saml:Subject>user@example.com</saml:Subject>"),
        "should include Subject child: {result}"
    );
    // Response element should NOT appear
    assert!(
        !result.contains("samlp:Response"),
        "Response should not be in subtree: {result}"
    );
}

#[test]
fn saml_enveloped_signature_exclusion() {
    // Simulate enveloped signature: dereference whole doc, then exclude Signature subtree
    // This is what P1-014 (enveloped transform) will do, but we can test the
    // NodeSet.exclude_subtree() + C14N combination here
    let xml = r#"<Response ID="_r1">
  <Assertion>data</Assertion>
  <Signature Id="sig1">
    <SignedInfo>digest</SignedInfo>
  </Signature>
</Response>"#;

    let doc = roxmltree::Document::parse(xml).expect("parse");
    let resolver = UriReferenceResolver::new(&doc);

    let data = resolver.dereference("").expect("dereference");
    let mut node_set = data.into_node_set().expect("into_node_set");

    // Exclude the Signature subtree (simulating enveloped-signature transform)
    let sig_elem = doc
        .descendants()
        .find(|n| n.is_element() && n.has_tag_name("Signature"))
        .expect("Signature element");
    node_set.exclude_subtree(sig_elem);

    let algo = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
    let predicate = |n: roxmltree::Node| node_set.contains(n);
    let mut output = Vec::new();
    canonicalize(&doc, Some(&predicate), &algo, &mut output).expect("canonicalize");
    let result = String::from_utf8(output).expect("utf8");

    // Signature and its children should be gone
    assert!(
        !result.contains("Signature"),
        "Signature should be excluded: {result}"
    );
    assert!(
        !result.contains("SignedInfo"),
        "SignedInfo should be excluded: {result}"
    );
    // Assertion should remain
    assert!(
        result.contains("<Assertion>data</Assertion>"),
        "Assertion should remain: {result}"
    );
}
use xml_sec as roxmltree;
