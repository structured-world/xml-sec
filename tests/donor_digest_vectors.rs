//! Donor digest vectors from xmlsec1's `aleksey-xmldsig-01` corpus.
//!
//! These tests validate the `<Reference>` processing path end-to-end against
//! real xmlsec1-generated documents without requiring signature verification.
//! The coverage target for P1-018a is one donor vector for each currently
//! supported digest family: SHA-1, SHA-256, SHA-384, and SHA-512.

use std::fs;
use std::path::Path;

use xml_sec::xmldsig::parse::{find_signature_node, parse_signed_info};
use xml_sec::xmldsig::uri::UriReferenceResolver;
use xml_sec::xmldsig::verify::process_all_references;

fn donor_xml(name: &str) -> String {
    let path = Path::new("donors/xmlsec/tests/aleksey-xmldsig-01").join(name);
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn assert_donor_reference_digest_valid(name: &str) {
    let xml = donor_xml(name);
    let doc = roxmltree::Document::parse(&xml)
        .unwrap_or_else(|err| panic!("failed to parse donor XML {name}: {err}"));
    let sig_node = find_signature_node(&doc)
        .unwrap_or_else(|| panic!("missing Signature element in donor XML {name}"));
    let signed_info_node = sig_node
        .children()
        .find(|node| node.is_element() && node.tag_name().name() == "SignedInfo")
        .unwrap_or_else(|| panic!("missing SignedInfo element in donor XML {name}"));
    let signed_info = parse_signed_info(signed_info_node)
        .unwrap_or_else(|err| panic!("failed to parse SignedInfo for {name}: {err}"));
    let resolver = UriReferenceResolver::new(&doc);

    let result = process_all_references(&signed_info.references, &resolver, sig_node, true)
        .unwrap_or_else(|err| panic!("reference processing failed for {name}: {err}"));

    assert!(
        result.all_valid(),
        "donor digest mismatch for {name}; first failure: {:?}",
        result.first_failure
    );
    assert_eq!(
        result.results.len(),
        1,
        "expected exactly one Reference in {name}"
    );
}

#[test]
fn donor_sha1_reference_digest_matches() {
    assert_donor_reference_digest_valid("enveloped-sha1-rsa-sha1.xml");
}

#[test]
fn donor_sha256_reference_digest_matches() {
    assert_donor_reference_digest_valid("enveloped-sha256-ecdsa-sha256.xml");
}

#[test]
fn donor_sha384_reference_digest_matches() {
    assert_donor_reference_digest_valid("enveloped-sha384-ecdsa-sha384.xml");
}

#[test]
fn donor_sha512_reference_digest_matches() {
    assert_donor_reference_digest_valid("enveloped-x509-digest-sha512.xml");
}
