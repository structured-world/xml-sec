//! Integration tests: transform pipeline (enveloped signature + C14N).
//!
//! Tests the full chain: URI dereference → parse_transforms → execute_transforms
//! → verify canonical output matches expected bytes.
//!
//! These tests exercise multi-component interaction:
//! - `UriReferenceResolver` (URI dereference)
//! - `parse_transforms` (XML → Vec<Transform>)
//! - `execute_transforms` (sequential pipeline)
//! - `NodeSet::exclude_subtree` (enveloped-signature)
//! - `c14n::canonicalize` (C14N serializer)

use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::xmldsig::NodeSet;
use xml_sec::xmldsig::transforms::{Transform, execute_transforms, parse_transforms};
use xml_sec::xmldsig::uri::UriReferenceResolver;

// ── Helper ───────────────────────────────────────────────────────────────────

/// Find a descendant element by local name.
fn find_element<'a>(doc: &'a roxmltree::Document<'a>, name: &str) -> roxmltree::Node<'a, 'a> {
    doc.descendants()
        .find(|n| n.is_element() && n.tag_name().name() == name)
        .unwrap_or_else(|| panic!("element <{name}> not found"))
}

// ── Enveloped + Exclusive C14N (most common SAML pattern) ────────────────────

#[test]
fn enveloped_exc_c14n_saml_response() {
    // Standard SAML Response with enveloped signature over entire document.
    // Transform chain: enveloped-signature → exclusive C14N.
    let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                 xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                                 ID="_resp1" InResponseTo="_req1">
    <saml:Assertion ID="_assert1">
        <saml:Subject>user@example.com</saml:Subject>
        <saml:Conditions NotBefore="2026-01-01T00:00:00Z"/>
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
                <ds:DigestValue>placeholder==</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>fakesig==</ds:SignatureValue>
    </ds:Signature>
</samlp:Response>"#;

    let doc = roxmltree::Document::parse(xml).unwrap();
    let resolver = UriReferenceResolver::new(&doc);
    let sig_node = find_element(&doc, "Signature");

    // Parse transforms from the XML
    let reference = find_element(&doc, "Reference");
    let transforms_elem = reference
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "Transforms")
        .unwrap();
    let transforms = parse_transforms(transforms_elem).unwrap();
    assert_eq!(transforms.len(), 2);

    // Dereference empty URI → entire document without comments
    let initial = resolver.dereference("").unwrap();

    // Execute pipeline
    let result = execute_transforms(sig_node, initial, &transforms).unwrap();
    let output = String::from_utf8(result).unwrap();

    // Signature must be completely absent
    assert!(!output.contains("Signature"), "output: {output}");
    assert!(!output.contains("SignedInfo"), "output: {output}");
    assert!(!output.contains("SignatureValue"), "output: {output}");
    assert!(!output.contains("fakesig"), "output: {output}");
    assert!(!output.contains("DigestValue"), "output: {output}");

    // Document content must be present
    assert!(output.contains("samlp:Response"), "output: {output}");
    assert!(output.contains("saml:Assertion"), "output: {output}");
    assert!(output.contains("user@example.com"), "output: {output}");
    assert!(output.contains("_assert1"), "output: {output}");
    assert!(output.contains("_resp1"), "output: {output}");

    // Exclusive C14N: only visibly-utilized namespaces.
    // samlp: is used on Response, saml: is used on Assertion/Subject/Conditions
    assert!(
        output.contains("xmlns:samlp="),
        "samlp ns should be present: {output}"
    );
    assert!(
        output.contains("xmlns:saml="),
        "saml ns should be present: {output}"
    );
}

// ── Enveloped + Inclusive C14N ────────────────────────────────────────────────

#[test]
fn enveloped_inclusive_c14n() {
    // Less common but valid: enveloped + inclusive C14N 1.0
    let xml = r#"<root xmlns:ns="http://example.com">
    <data ns:attr="val">content</data>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo/>
        <ds:SignatureValue>sig</ds:SignatureValue>
    </ds:Signature>
</root>"#;

    let doc = roxmltree::Document::parse(xml).unwrap();
    let resolver = UriReferenceResolver::new(&doc);
    let sig_node = find_element(&doc, "Signature");

    let initial = resolver.dereference("").unwrap();
    let transforms = vec![
        Transform::Enveloped,
        Transform::C14n(C14nAlgorithm::new(C14nMode::Inclusive1_0, false)),
    ];

    let result = execute_transforms(sig_node, initial, &transforms).unwrap();
    let output = String::from_utf8(result).unwrap();

    // Signature gone
    assert!(!output.contains("Signature"), "output: {output}");
    assert!(!output.contains("SignedInfo"), "output: {output}");

    // Content present
    assert!(output.contains("<data"), "output: {output}");
    assert!(output.contains("content"), "output: {output}");

    // Inclusive C14N: all in-scope namespaces rendered, including ns:
    assert!(
        output.contains(r#"xmlns:ns="http://example.com""#),
        "ns namespace should appear: {output}"
    );
}

// ── Enveloped + C14N 1.1 ────────────────────────────────────────────────────

#[test]
fn enveloped_inclusive_c14n_1_1() {
    let xml = r#"<root xml:lang="en">
    <data>content</data>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo/>
    </ds:Signature>
</root>"#;

    let doc = roxmltree::Document::parse(xml).unwrap();
    let sig_node = find_element(&doc, "Signature");

    let initial =
        xml_sec::xmldsig::TransformData::NodeSet(NodeSet::entire_document_without_comments(&doc));
    let transforms = vec![
        Transform::Enveloped,
        Transform::C14n(C14nAlgorithm::new(C14nMode::Inclusive1_1, false)),
    ];

    let result = execute_transforms(sig_node, initial, &transforms).unwrap();
    let output = String::from_utf8(result).unwrap();

    assert!(!output.contains("Signature"), "output: {output}");
    assert!(output.contains("<data>content</data>"), "output: {output}");
}

// ── #id URI + enveloped (signature inside assertion) ─────────────────────────

#[test]
fn id_uri_enveloped_assertion_level_signature() {
    // Signature inside the Assertion, signing only the Assertion (not the whole Response).
    // URI="#_assert1" → subtree of Assertion, then enveloped removes Signature within it.
    let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                 xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                                 ID="_resp1">
    <saml:Assertion ID="_assert1">
        <saml:Subject>user@example.com</saml:Subject>
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo/>
            <ds:SignatureValue>sig</ds:SignatureValue>
        </ds:Signature>
    </saml:Assertion>
</samlp:Response>"#;

    let doc = roxmltree::Document::parse(xml).unwrap();
    let resolver = UriReferenceResolver::new(&doc);
    let sig_node = find_element(&doc, "Signature");

    // Dereference #_assert1 → subtree of Assertion element
    let initial = resolver.dereference("#_assert1").unwrap();

    let transforms = vec![
        Transform::Enveloped,
        Transform::C14n(
            C14nAlgorithm::from_uri("http://www.w3.org/2001/10/xml-exc-c14n#").unwrap(),
        ),
    ];

    let result = execute_transforms(sig_node, initial, &transforms).unwrap();
    let output = String::from_utf8(result).unwrap();

    // Should contain the Assertion element and Subject
    assert!(output.contains("saml:Assertion"), "output: {output}");
    assert!(output.contains("user@example.com"), "output: {output}");

    // Signature subtree removed
    assert!(!output.contains("Signature"), "output: {output}");
    assert!(!output.contains("SignedInfo"), "output: {output}");

    // Response should NOT appear (we dereferenced only the assertion subtree)
    assert!(!output.contains("samlp:Response"), "output: {output}");
}

// ── Nested signatures ────────────────────────────────────────────────────────

#[test]
fn nested_signatures_only_own_excluded() {
    // Two signatures: one at Response level, one inside Assertion.
    // When verifying the Response-level signature, only IT should be excluded.
    let xml = r#"<Response ID="_r1">
    <Assertion ID="_a1">
        <Subject>user</Subject>
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="inner-sig">
            <ds:SignedInfo/>
        </ds:Signature>
    </Assertion>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="outer-sig">
        <ds:SignedInfo/>
        <ds:SignatureValue>outer</ds:SignatureValue>
    </ds:Signature>
</Response>"#;

    let doc = roxmltree::Document::parse(xml).unwrap();
    let resolver = UriReferenceResolver::new(&doc);

    // The outer signature (Id="outer-sig") is being verified
    let outer_sig = doc
        .descendants()
        .find(|n| n.is_element() && n.attribute("Id") == Some("outer-sig"))
        .unwrap();

    let initial = resolver.dereference("").unwrap();
    let transforms = vec![
        Transform::Enveloped,
        Transform::C14n(C14nAlgorithm::new(C14nMode::Inclusive1_0, false)),
    ];

    let result = execute_transforms(outer_sig, initial, &transforms).unwrap();
    let output = String::from_utf8(result).unwrap();

    // Outer signature should be excluded
    assert!(!output.contains("outer-sig"), "output: {output}");
    assert!(!output.contains("outer"), "output: {output}");

    // Inner signature should REMAIN (it's not the one being verified)
    assert!(
        output.contains("inner-sig"),
        "inner signature should remain: {output}"
    );

    // Document content should be present
    assert!(
        output.contains("<Subject>user</Subject>"),
        "output: {output}"
    );
    assert!(output.contains("Assertion"), "output: {output}");
}

// ── No explicit C14N → default inclusive C14N 1.0 ────────────────────────────

#[test]
fn enveloped_only_falls_back_to_default_c14n() {
    // If transform chain has only enveloped (no explicit C14N),
    // the pipeline applies default inclusive C14N 1.0 per XMLDSig spec.
    let xml = r#"<root b="2" a="1">
    <data>content</data>
    <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
        <SignedInfo/>
    </Signature>
</root>"#;

    let doc = roxmltree::Document::parse(xml).unwrap();
    let sig_node = find_element(&doc, "Signature");

    let initial =
        xml_sec::xmldsig::TransformData::NodeSet(NodeSet::entire_document_without_comments(&doc));
    let transforms = vec![Transform::Enveloped];

    let result = execute_transforms(sig_node, initial, &transforms).unwrap();
    let output = String::from_utf8(result).unwrap();

    // Signature gone
    assert!(!output.contains("Signature"), "output: {output}");

    // Attributes sorted (inclusive C14N)
    assert!(
        output.contains(r#"a="1" b="2""#),
        "attributes should be sorted: {output}"
    );
}

// ── Exclusive C14N with InclusiveNamespaces PrefixList ───────────────────────

#[test]
fn exc_c14n_with_prefix_list_from_xml() {
    // Parse a transform chain that includes InclusiveNamespaces PrefixList,
    // then execute the pipeline.
    let xml = r#"<root xmlns:ns1="http://ns1" xmlns:ns2="http://ns2">
    <child ns1:attr="val">text</child>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo>
            <ds:Reference URI="">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
                        <ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"
                                                 PrefixList="ns2"/>
                    </ds:Transform>
                </ds:Transforms>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>sig</ds:SignatureValue>
    </ds:Signature>
</root>"#;

    let doc = roxmltree::Document::parse(xml).unwrap();
    let resolver = UriReferenceResolver::new(&doc);
    let sig_node = find_element(&doc, "Signature");

    // Parse transforms from the XML
    let reference = find_element(&doc, "Reference");
    let transforms_elem = reference
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "Transforms")
        .unwrap();
    let transforms = parse_transforms(transforms_elem).unwrap();
    assert_eq!(transforms.len(), 2);

    // Verify PrefixList was parsed
    match &transforms[1] {
        Transform::C14n(algo) => {
            assert!(
                algo.inclusive_prefixes().contains("ns2"),
                "PrefixList should include ns2"
            );
        }
        other => panic!("expected C14n transform, got: {other:?}"),
    }

    // Execute pipeline
    let initial = resolver.dereference("").unwrap();
    let result = execute_transforms(sig_node, initial, &transforms).unwrap();
    let output = String::from_utf8(result).unwrap();

    // Signature removed
    assert!(!output.contains("Signature"), "output: {output}");

    // ns1: is visibly utilized (attr on child) → should appear
    assert!(
        output.contains("xmlns:ns1="),
        "ns1 should be present (visibly utilized): {output}"
    );

    // ns2: is forced via PrefixList → should appear even though not visibly utilized on child
    // (It IS on root via inclusive ns rendering forced by PrefixList)
    assert!(
        output.contains("xmlns:ns2="),
        "ns2 should be present (forced by PrefixList): {output}"
    );
}

// ── parse_transforms end-to-end with realistic SAML ──────────────────────────

#[test]
fn parse_and_execute_transforms_roundtrip() {
    // Parse transforms from XML, execute them, verify output.
    // This tests the full integration path that verification will use.
    let xml = r#"<Document>
    <Content attr="value">important data</Content>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo>
            <ds:Reference URI="">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    <ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
                </ds:Transforms>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>base64sig==</ds:SignatureValue>
    </ds:Signature>
</Document>"#;

    let doc = roxmltree::Document::parse(xml).unwrap();
    let resolver = UriReferenceResolver::new(&doc);
    let sig_node = find_element(&doc, "Signature");

    // Step 1: Parse transforms from XML
    let reference = find_element(&doc, "Reference");
    let transforms_elem = reference
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "Transforms")
        .unwrap();
    let transforms = parse_transforms(transforms_elem).unwrap();

    // Step 2: Dereference URI
    let uri = reference.attribute("URI").unwrap_or("");
    let initial = resolver.dereference(uri).unwrap();

    // Step 3: Execute transforms
    let result = execute_transforms(sig_node, initial, &transforms).unwrap();
    let output = String::from_utf8(result).unwrap();

    // Step 4: Verify
    assert!(!output.contains("Signature"));
    assert!(output.contains(r#"<Content attr="value">important data</Content>"#));
}

// ── Edge case: signature is the only child ───────────────────────────────────

#[test]
fn enveloped_signature_only_child() {
    // Edge case: the Signature is the only element child of root.
    // After the enveloped transform, the Signature subtree is removed and
    // only the root element (plus any surrounding whitespace text nodes)
    // remains in the NodeSet / canonical output.
    let xml = r#"<root>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo/>
        <ds:SignatureValue>sig</ds:SignatureValue>
    </ds:Signature>
</root>"#;

    let doc = roxmltree::Document::parse(xml).unwrap();
    let sig_node = find_element(&doc, "Signature");

    let initial =
        xml_sec::xmldsig::TransformData::NodeSet(NodeSet::entire_document_without_comments(&doc));
    let transforms = vec![
        Transform::Enveloped,
        Transform::C14n(C14nAlgorithm::new(C14nMode::Inclusive1_0, false)),
    ];

    let result = execute_transforms(sig_node, initial, &transforms).unwrap();
    let output = String::from_utf8(result).unwrap();

    // The Signature subtree should be removed; only the root element and any
    // surrounding whitespace text nodes should remain.
    assert!(!output.contains("Signature"), "output: {output}");
    assert!(output.contains("<root>"), "output: {output}");
}

// ── Whitespace handling ──────────────────────────────────────────────────────

#[test]
fn enveloped_preserves_surrounding_whitespace() {
    // Whitespace text nodes between elements should be preserved
    // (they are part of the document, not part of the Signature subtree)
    let xml = "<root>\n  <data>text</data>\n  <Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n    <SignedInfo/>\n  </Signature>\n</root>";

    let doc = roxmltree::Document::parse(xml).unwrap();
    let sig_node = find_element(&doc, "Signature");

    let initial =
        xml_sec::xmldsig::TransformData::NodeSet(NodeSet::entire_document_without_comments(&doc));
    let transforms = vec![
        Transform::Enveloped,
        Transform::C14n(C14nAlgorithm::new(C14nMode::Inclusive1_0, false)),
    ];

    let result = execute_transforms(sig_node, initial, &transforms).unwrap();
    let output = String::from_utf8(result).unwrap();

    // The text nodes ("\n  ") around Signature are preserved — they're not
    // part of the Signature subtree (they're siblings). C14N will emit them.
    assert!(output.contains("<data>text</data>"), "output: {output}");
    // Verify whitespace around removed Signature is actually in the output
    assert!(
        output.contains("\n  <data>text</data>\n"),
        "whitespace around Signature should be preserved: {output}"
    );
    assert!(!output.contains("SignedInfo"), "output: {output}");
}
