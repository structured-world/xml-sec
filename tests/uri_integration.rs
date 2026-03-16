//! Integration tests: URI dereference → NodeSet → C14N canonicalization.
//!
//! Verifies that dereferencing a URI produces a NodeSet that, when used as
//! a predicate for C14N, produces the correct canonical output.

use xml_sec::c14n::{canonicalize, C14nAlgorithm, C14nMode};
use xml_sec::xmldsig::uri::UriReferenceResolver;

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
fn fragment_id_includes_comments_in_subtree() {
    // Unlike empty URI, #id subtrees include comments
    let xml = r#"<root><item ID="x"><!-- keep this --><child/></item></root>"#;
    let result = deref_and_canonicalize_with_comments(xml, "#x");
    assert_eq!(
        result,
        r#"<item ID="x"><!-- keep this --><child></child></item>"#
    );
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
