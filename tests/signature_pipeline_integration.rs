//! Integration tests for roadmap task P1-021.
//!
//! Verifies full XMLDSig verify pipeline:
//! reference digest checks + SignedInfo canonicalization + SignatureValue verify.

use std::path::Path;

use xml_sec::xmldsig::verify_signature_with_pem_key;

fn read_fixture(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read fixture {}: {err}", path.display()))
}

fn mutate_ds_tag_content(xml: &str, tag: &str) -> String {
    let prefixed_open = format!("<ds:{tag}>");
    let prefixed_close = format!("</ds:{tag}>");
    let plain_open = format!("<{tag}>");
    let plain_close = format!("</{tag}>");
    let (open, close) = if xml.contains(&prefixed_open) {
        (prefixed_open, prefixed_close)
    } else if xml.contains(&plain_open) {
        (plain_open, plain_close)
    } else {
        panic!("missing opening tag for {tag}");
    };
    let start = xml
        .find(&open)
        .unwrap_or_else(|| panic!("missing opening tag {open}"))
        + open.len();
    let end = xml[start..]
        .find(&close)
        .unwrap_or_else(|| panic!("missing closing tag {close}"))
        + start;

    let mut chars: Vec<char> = xml[start..end].chars().collect();
    if let Some((index, value)) = chars
        .iter()
        .enumerate()
        .find(|(_, ch)| ch.is_ascii_alphanumeric())
    {
        chars[index] = if *value == 'A' { 'B' } else { 'A' };
    } else {
        panic!("tag {tag} did not contain any mutable base64 chars");
    }

    let mutated = chars.into_iter().collect::<String>();
    format!("{}{}{}", &xml[..start], mutated, &xml[end..])
}

#[test]
fn donor_rsa_sha256_full_pipeline_matches() {
    let xml = read_fixture(Path::new(
        "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.xml",
    ));
    let public_key_pem = read_fixture(Path::new("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"));

    let result =
        verify_signature_with_pem_key(&xml, &public_key_pem, false).expect("pipeline should run");

    assert!(
        result.references.all_valid(),
        "all SignedInfo references must be valid"
    );
    assert!(result.signature_checked, "signature stage must run");
    assert!(result.signature_valid, "signature must verify");
}

#[test]
fn donor_ecdsa_sha256_full_pipeline_matches() {
    let xml = read_fixture(Path::new(
        "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloped-sha256-ecdsa-sha256.xml",
    ));
    let public_key_pem = read_fixture(Path::new("tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem"));

    let result =
        verify_signature_with_pem_key(&xml, &public_key_pem, false).expect("pipeline should run");

    assert!(
        result.references.all_valid(),
        "all SignedInfo references must be valid"
    );
    assert!(result.signature_checked, "signature stage must run");
    assert!(result.signature_valid, "signature must verify");
}

#[test]
fn tampered_signature_value_fails_after_references_pass() {
    let xml = read_fixture(Path::new(
        "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.xml",
    ));
    let public_key_pem = read_fixture(Path::new("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"));
    let tampered_xml = mutate_ds_tag_content(&xml, "SignatureValue");

    let result = verify_signature_with_pem_key(&tampered_xml, &public_key_pem, false)
        .expect("pipeline should still run for invalid signature bytes");

    assert!(
        result.references.all_valid(),
        "digest stage should still pass when only signature bytes are tampered"
    );
    assert!(result.signature_checked, "signature stage must run");
    assert!(!result.signature_valid, "tampered SignatureValue must fail");
}

#[test]
fn tampered_digest_value_fails_before_signature_stage() {
    let xml = read_fixture(Path::new(
        "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.xml",
    ));
    let public_key_pem = read_fixture(Path::new("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"));
    let tampered_xml = mutate_ds_tag_content(&xml, "DigestValue");

    let result = verify_signature_with_pem_key(&tampered_xml, &public_key_pem, false)
        .expect("pipeline should return structured invalid result on digest mismatch");

    assert!(
        !result.references.all_valid(),
        "digest mismatch must invalidate SignedInfo references"
    );
    assert!(
        !result.signature_checked,
        "signature stage must not run after reference failure"
    );
    assert!(!result.signature_valid, "result should be invalid");
}
