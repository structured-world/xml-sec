//! Integration tests: Reference processing pipeline.
//!
//! Tests the full chain from parsed XML through to digest verification:
//! `<Signature>` → `parse_signed_info` → `UriReferenceResolver` → `process_reference`/`process_all_references`
//!
//! These tests exercise multi-component interaction:
//! - `parse_signed_info` (XML → SignedInfo with References)
//! - `UriReferenceResolver` (URI dereference)
//! - `execute_transforms` (enveloped + C14N pipeline)
//! - `compute_digest` + `constant_time_eq` (SHA-family digest comparison)
//! - `process_reference` / `process_all_references` (full wiring)

use base64::Engine;
use xml_sec::xmldsig::digest::{DigestAlgorithm, compute_digest};
use xml_sec::xmldsig::parse::{find_signature_node, parse_signed_info};
use xml_sec::xmldsig::transforms::execute_transforms;
use xml_sec::xmldsig::uri::UriReferenceResolver;
use xml_sec::xmldsig::verify::{
    DsigStatus, FailureReason, process_all_references, process_reference,
};

// ── Helper ───────────────────────────────────────────────────────────────────

/// Compute the correct digest for a Reference's URI+transforms with the
/// requested algorithm and return it as base64 for embedding in test XML.
fn compute_reference_digest_b64(
    doc: &roxmltree::Document<'_>,
    sig_node: roxmltree::Node<'_, '_>,
    uri: &str,
    transforms: &[xml_sec::xmldsig::Transform],
    digest_algo: DigestAlgorithm,
) -> String {
    let resolver = UriReferenceResolver::new(doc);
    let initial_data = resolver.dereference(uri).unwrap();
    let pre_digest = execute_transforms(sig_node, initial_data, transforms).unwrap();
    let digest = compute_digest(digest_algo, &pre_digest);
    base64::engine::general_purpose::STANDARD.encode(&digest)
}

// ── SAML Response: enveloped signature over entire document ──────────────────

#[test]
fn saml_response_enveloped_reference_valid() {
    // Step 1: Parse document with placeholder digest
    let xml_template = r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                                     ID="_resp1" InResponseTo="_req1"
                                     IssueInstant="2026-01-15T10:00:00Z">
        <saml:Issuer>https://idp.example.com</saml:Issuer>
        <saml:Assertion ID="_assert1" IssueInstant="2026-01-15T10:00:00Z">
            <saml:Issuer>https://idp.example.com</saml:Issuer>
            <saml:Subject>
                <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID>
            </saml:Subject>
            <saml:Conditions NotBefore="2026-01-15T09:55:00Z" NotOnOrAfter="2026-01-15T10:05:00Z"/>
            <saml:AuthnStatement AuthnInstant="2026-01-15T10:00:00Z">
                <saml:AuthnContext>
                    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
                </saml:AuthnContext>
            </saml:AuthnStatement>
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
    </samlp:Response>"##;

    let doc = roxmltree::Document::parse(xml_template).unwrap();
    let sig_node = find_signature_node(&doc).expect("Signature element not found");

    // Parse SignedInfo to get Reference with transforms
    let signed_info_node = sig_node
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "SignedInfo")
        .unwrap();
    let signed_info = parse_signed_info(signed_info_node).unwrap();
    let parsed_ref = &signed_info.references[0];

    // Compute correct digest
    let correct_b64 = compute_reference_digest_b64(
        &doc,
        sig_node,
        parsed_ref.uri.as_deref().unwrap_or(""),
        &parsed_ref.transforms,
        parsed_ref.digest_method,
    );

    // Rebuild XML with correct digest
    let xml_correct =
        xml_template.replace("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", &correct_b64);
    let doc = roxmltree::Document::parse(&xml_correct).unwrap();
    let sig_node = find_signature_node(&doc).unwrap();
    let resolver = UriReferenceResolver::new(&doc);
    let signed_info_node = sig_node
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "SignedInfo")
        .unwrap();
    let signed_info = parse_signed_info(signed_info_node).unwrap();

    // Verify: process_all_references should pass
    let result =
        process_all_references(&signed_info.references, &resolver, sig_node, true).unwrap();
    assert!(
        result.all_valid(),
        "SAML Response reference should verify. First failure: {:?}",
        result.first_failure
    );
    assert_eq!(result.results.len(), 1);

    // Pre-digest data should be the canonicalized doc without Signature
    let pre_digest_str =
        String::from_utf8(result.results[0].pre_digest_data.clone().unwrap()).unwrap();
    assert!(
        pre_digest_str.contains("samlp:Response"),
        "should contain Response element"
    );
    assert!(
        pre_digest_str.contains("user@example.com"),
        "should contain user data"
    );
    assert!(
        !pre_digest_str.contains("ds:Signature"),
        "should NOT contain Signature"
    );
    assert!(
        !pre_digest_str.contains("SignatureValue"),
        "should NOT contain SignatureValue"
    );
}

// ── SAML Assertion: enveloped signature inside assertion ─────────────────────

#[test]
fn saml_assertion_level_enveloped_reference_valid() {
    // Signature inside the Assertion, signing only the Assertion subtree (URI="#_assert1")
    let xml_template = r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                                     ID="_resp1">
        <saml:Assertion ID="_assert1">
            <saml:Subject>
                <saml:NameID>user@example.com</saml:NameID>
            </saml:Subject>
            <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:SignedInfo>
                    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                    <ds:Reference URI="#_assert1">
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
        </saml:Assertion>
    </samlp:Response>"##;

    let doc = roxmltree::Document::parse(xml_template).unwrap();
    let sig_node = find_signature_node(&doc).unwrap();

    let signed_info_node = sig_node
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "SignedInfo")
        .unwrap();
    let signed_info = parse_signed_info(signed_info_node).unwrap();
    let parsed_ref = &signed_info.references[0];
    assert_eq!(parsed_ref.uri.as_deref(), Some("#_assert1"));

    // Compute correct digest
    let correct_b64 = compute_reference_digest_b64(
        &doc,
        sig_node,
        "#_assert1",
        &parsed_ref.transforms,
        parsed_ref.digest_method,
    );

    // Rebuild with correct digest
    let xml_correct =
        xml_template.replace("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", &correct_b64);
    let doc = roxmltree::Document::parse(&xml_correct).unwrap();
    let sig_node = find_signature_node(&doc).unwrap();
    let resolver = UriReferenceResolver::new(&doc);
    let signed_info_node = sig_node
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "SignedInfo")
        .unwrap();
    let signed_info = parse_signed_info(signed_info_node).unwrap();

    let result =
        process_all_references(&signed_info.references, &resolver, sig_node, true).unwrap();
    assert!(
        result.all_valid(),
        "Assertion-level reference should verify"
    );

    // Pre-digest should contain Assertion but NOT Response
    let pre_digest_str =
        String::from_utf8(result.results[0].pre_digest_data.clone().unwrap()).unwrap();
    assert!(
        pre_digest_str.contains("saml:Assertion"),
        "should contain Assertion"
    );
    assert!(
        pre_digest_str.contains("user@example.com"),
        "should contain user data"
    );
    assert!(
        !pre_digest_str.contains("samlp:Response"),
        "should NOT contain Response (subtree only)"
    );
    assert!(
        !pre_digest_str.contains("ds:Signature"),
        "should NOT contain Signature"
    );
}

// ── Digest mismatch detection ────────────────────────────────────────────────

#[test]
fn tampered_document_detected() {
    // Create a valid signed document, then tamper with it and verify digest fails.
    let xml_template = r##"<root>
        <data>original content</data>
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
    </root>"##;

    // Step 1: compute correct digest
    let doc = roxmltree::Document::parse(xml_template).unwrap();
    let sig_node = find_signature_node(&doc).unwrap();
    let signed_info_node = sig_node
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "SignedInfo")
        .unwrap();
    let signed_info = parse_signed_info(signed_info_node).unwrap();
    let parsed_ref = &signed_info.references[0];

    let correct_b64 = compute_reference_digest_b64(
        &doc,
        sig_node,
        "",
        &parsed_ref.transforms,
        parsed_ref.digest_method,
    );

    // Step 2: create valid document
    let xml_valid =
        xml_template.replace("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", &correct_b64);

    // Step 3: tamper with content (change "original" to "TAMPERED")
    let xml_tampered = xml_valid.replace("original content", "TAMPERED content");

    // Step 4: verify tampered document — should fail
    let doc = roxmltree::Document::parse(&xml_tampered).unwrap();
    let sig_node = find_signature_node(&doc).unwrap();
    let resolver = UriReferenceResolver::new(&doc);
    let signed_info_node = sig_node
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "SignedInfo")
        .unwrap();
    let signed_info = parse_signed_info(signed_info_node).unwrap();

    let result =
        process_all_references(&signed_info.references, &resolver, sig_node, false).unwrap();
    assert!(
        !result.all_valid(),
        "tampered document should fail digest verification"
    );
    assert_eq!(result.first_failure, Some(0));
    assert!(matches!(
        result.results[0].status,
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
    ));
}

// ── Multiple references: fail-fast behavior ──────────────────────────────────

#[test]
fn multiple_references_fail_fast_on_second() {
    // Document with two signed objects. First reference valid, second tampered.
    let xml_template = r##"<root>
        <item ID="a">correct</item>
        <item ID="b">will be tampered</item>
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference URI="#a">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>
                </ds:Reference>
                <ds:Reference URI="#b">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue>AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=</ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>fakesig==</ds:SignatureValue>
        </ds:Signature>
    </root>"##;

    // Compute correct digests for both references
    let doc = roxmltree::Document::parse(xml_template).unwrap();
    let sig_node = find_signature_node(&doc).unwrap();
    let signed_info_node = sig_node
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "SignedInfo")
        .unwrap();
    let signed_info = parse_signed_info(signed_info_node).unwrap();

    let digest_a = compute_reference_digest_b64(
        &doc,
        sig_node,
        "#a",
        &signed_info.references[0].transforms,
        signed_info.references[0].digest_method,
    );
    let digest_b = compute_reference_digest_b64(
        &doc,
        sig_node,
        "#b",
        &signed_info.references[1].transforms,
        signed_info.references[1].digest_method,
    );

    // Build valid document, then tamper second item
    let xml_valid = xml_template
        .replace("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", &digest_a)
        .replace("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", &digest_b);
    let xml_tampered = xml_valid.replace("will be tampered", "TAMPERED");

    // Verify: first ref should pass, second should fail
    let doc = roxmltree::Document::parse(&xml_tampered).unwrap();
    let sig_node = find_signature_node(&doc).unwrap();
    let resolver = UriReferenceResolver::new(&doc);
    let signed_info_node = sig_node
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "SignedInfo")
        .unwrap();
    let signed_info = parse_signed_info(signed_info_node).unwrap();

    let result =
        process_all_references(&signed_info.references, &resolver, sig_node, false).unwrap();
    assert!(!result.all_valid());
    assert_eq!(result.first_failure, Some(1));
    assert_eq!(result.results.len(), 2);
    assert!(
        matches!(result.results[0].status, DsigStatus::Valid),
        "first ref should pass"
    );
    assert!(
        matches!(
            result.results[1].status,
            DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 1 })
        ),
        "second (tampered) ref should fail with the second-reference index"
    );
}

// ── Inclusive C14N variant ────────────────────────────────────────────────────

#[test]
fn reference_with_inclusive_c14n_valid() {
    // Tests that inclusive C14N (not just exclusive) works in the reference pipeline
    let xml_template = r##"<root xmlns:ns="http://example.com" ns:attr="val">
        <data>content</data>
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference URI="">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                        <ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>fakesig==</ds:SignatureValue>
        </ds:Signature>
    </root>"##;

    let doc = roxmltree::Document::parse(xml_template).unwrap();
    let sig_node = find_signature_node(&doc).unwrap();
    let signed_info_node = sig_node
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "SignedInfo")
        .unwrap();
    let signed_info = parse_signed_info(signed_info_node).unwrap();
    let parsed_ref = &signed_info.references[0];

    let correct_b64 = compute_reference_digest_b64(
        &doc,
        sig_node,
        "",
        &parsed_ref.transforms,
        parsed_ref.digest_method,
    );

    let xml_correct =
        xml_template.replace("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", &correct_b64);
    let doc = roxmltree::Document::parse(&xml_correct).unwrap();
    let sig_node = find_signature_node(&doc).unwrap();
    let resolver = UriReferenceResolver::new(&doc);
    let signed_info_node = sig_node
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "SignedInfo")
        .unwrap();
    let signed_info = parse_signed_info(signed_info_node).unwrap();

    let result =
        process_all_references(&signed_info.references, &resolver, sig_node, false).unwrap();
    assert!(result.all_valid(), "Inclusive C14N reference should verify");
}

// ── SHA-384 digest algorithm ─────────────────────────────────────────────────

#[test]
fn reference_with_sha384_digest_valid() {
    let xml_template = r##"<root>
        <data>content</data>
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference URI="">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#sha384"/>
                    <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>fakesig==</ds:SignatureValue>
        </ds:Signature>
    </root>"##;

    let doc = roxmltree::Document::parse(xml_template).unwrap();
    let sig_node = find_signature_node(&doc).unwrap();
    let signed_info_node = sig_node
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "SignedInfo")
        .unwrap();
    let signed_info = parse_signed_info(signed_info_node).unwrap();
    let parsed_ref = &signed_info.references[0];
    assert_eq!(parsed_ref.digest_method, DigestAlgorithm::Sha384);

    let correct_b64 = compute_reference_digest_b64(
        &doc,
        sig_node,
        "",
        &parsed_ref.transforms,
        parsed_ref.digest_method,
    );

    let xml_correct = xml_template.replace(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        &correct_b64,
    );
    let doc = roxmltree::Document::parse(&xml_correct).unwrap();
    let sig_node = find_signature_node(&doc).unwrap();
    let resolver = UriReferenceResolver::new(&doc);
    let signed_info_node = sig_node
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "SignedInfo")
        .unwrap();
    let signed_info = parse_signed_info(signed_info_node).unwrap();

    let result =
        process_all_references(&signed_info.references, &resolver, sig_node, false).unwrap();
    assert!(result.all_valid(), "SHA-384 reference should verify");
}

// ── No transforms (default C14N fallback) ────────────────────────────────────

#[test]
fn reference_without_transforms_uses_default_c14n() {
    // Per XMLDSig spec: if no explicit C14N transform, default inclusive C14N 1.0 is used
    let xml_template = r##"<root>
        <data>content</data>
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference URI="">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>fakesig==</ds:SignatureValue>
        </ds:Signature>
    </root>"##;

    let doc = roxmltree::Document::parse(xml_template).unwrap();
    let sig_node = find_signature_node(&doc).unwrap();
    let signed_info_node = sig_node
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "SignedInfo")
        .unwrap();
    let signed_info = parse_signed_info(signed_info_node).unwrap();
    let parsed_ref = &signed_info.references[0];

    // Only enveloped transform — no explicit C14N, so default kicks in
    assert_eq!(parsed_ref.transforms.len(), 1);

    let correct_b64 = compute_reference_digest_b64(
        &doc,
        sig_node,
        "",
        &parsed_ref.transforms,
        parsed_ref.digest_method,
    );

    let xml_correct =
        xml_template.replace("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", &correct_b64);
    let doc = roxmltree::Document::parse(&xml_correct).unwrap();
    let sig_node = find_signature_node(&doc).unwrap();
    let resolver = UriReferenceResolver::new(&doc);
    let signed_info_node = sig_node
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "SignedInfo")
        .unwrap();
    let signed_info = parse_signed_info(signed_info_node).unwrap();

    let result =
        process_all_references(&signed_info.references, &resolver, sig_node, false).unwrap();
    assert!(result.all_valid(), "Default C14N fallback should work");
}

// ── Single process_reference call with pre_digest ────────────────────────────

#[test]
fn process_single_reference_with_pre_digest_valid() {
    let xml_template = r##"<root>
        <data>important</data>
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
    </root>"##;

    let doc = roxmltree::Document::parse(xml_template).unwrap();
    let sig_node = find_signature_node(&doc).unwrap();
    let signed_info_node = sig_node
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "SignedInfo")
        .unwrap();
    let signed_info = parse_signed_info(signed_info_node).unwrap();
    let parsed_ref = &signed_info.references[0];

    let correct_b64 = compute_reference_digest_b64(
        &doc,
        sig_node,
        "",
        &parsed_ref.transforms,
        parsed_ref.digest_method,
    );

    let xml_correct =
        xml_template.replace("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", &correct_b64);
    let doc = roxmltree::Document::parse(&xml_correct).unwrap();
    let sig_node = find_signature_node(&doc).unwrap();
    let resolver = UriReferenceResolver::new(&doc);
    let signed_info_node = sig_node
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "SignedInfo")
        .unwrap();
    let signed_info = parse_signed_info(signed_info_node).unwrap();

    // Use process_reference directly (not process_all_references)
    let result = process_reference(
        &signed_info.references[0],
        &resolver,
        sig_node,
        0,
        true, // store pre-digest
    )
    .unwrap();

    assert!(matches!(result.status, DsigStatus::Valid));
    assert_eq!(result.uri, "");
    assert_eq!(result.digest_algorithm, DigestAlgorithm::Sha256);

    let pre_digest = result.pre_digest_data.unwrap();
    let pre_digest_str = String::from_utf8(pre_digest).unwrap();
    assert!(pre_digest_str.contains("important"));
    assert!(!pre_digest_str.contains("Signature"));
}
