//! Integration tests for roadmap task P1-021.
//!
//! Verifies full XMLDSig verify pipeline:
//! reference digest checks + SignedInfo canonicalization + SignatureValue verify.

use std::path::Path;

use xml_sec::xmldsig::{SignatureVerificationPipelineError, verify_signature_with_pem_key};

fn read_fixture(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read fixture {}: {err}", path.display()))
}

fn mutate_ds_tag_content(xml: &str, tag: &str) -> String {
    replace_ds_tag_content_with(xml, tag, |chars| {
        if let Some((index, value)) = chars
            .iter()
            .enumerate()
            .find(|(_, ch)| ch.is_ascii_alphanumeric())
        {
            chars[index] = if *value == 'A' { 'B' } else { 'A' };
        } else {
            panic!("tag {tag} did not contain any mutable base64 chars");
        }
    })
}

fn replace_ds_tag_content(xml: &str, tag: &str, replacement: &str) -> String {
    replace_ds_tag_content_with(xml, tag, |chars| {
        chars.clear();
        chars.extend(replacement.chars());
    })
}

fn replace_ds_tag_content_with(
    xml: &str,
    tag: &str,
    mutate: impl FnOnce(&mut Vec<char>),
) -> String {
    let prefixed_open_prefix = format!("<ds:{tag}");
    let prefixed_close = format!("</ds:{tag}>");
    let plain_open_prefix = format!("<{tag}");
    let plain_close = format!("</{tag}>");
    let (open_start, close) = if let Some(index) = find_open_tag_start(xml, &prefixed_open_prefix) {
        (index, prefixed_close)
    } else if let Some(index) = find_open_tag_start(xml, &plain_open_prefix) {
        (index, plain_close)
    } else {
        panic!("missing opening tag for {tag}");
    };

    let start = xml[open_start..]
        .find('>')
        .unwrap_or_else(|| panic!("missing '>' for opening tag {tag}"))
        + open_start
        + 1;
    let end = xml[start..]
        .find(&close)
        .unwrap_or_else(|| panic!("missing closing tag {close}"))
        + start;

    let mut chars: Vec<char> = xml[start..end].chars().collect();
    mutate(&mut chars);
    let mutated = chars.into_iter().collect::<String>();
    format!("{}{}{}", &xml[..start], mutated, &xml[end..])
}

fn find_open_tag_start(xml: &str, open_prefix: &str) -> Option<usize> {
    let mut offset = 0;
    while let Some(relative_index) = xml[offset..].find(open_prefix) {
        let absolute_index = offset + relative_index;
        let boundary_index = absolute_index + open_prefix.len();
        let next_char = xml[boundary_index..].chars().next();
        if matches!(next_char, Some('>')) || next_char.is_some_and(|ch| ch.is_ascii_whitespace()) {
            return Some(absolute_index);
        }
        offset = boundary_index;
    }
    None
}

fn assert_invalid_structure_reason(
    err: SignatureVerificationPipelineError,
    expected_reason: &'static str,
) {
    match err {
        SignatureVerificationPipelineError::InvalidStructure { reason } => {
            assert_eq!(reason, expected_reason);
        }
        other => panic!("expected InvalidStructure error, got: {other:?}"),
    }
}

fn inject_invalid_base64_in_signature_value(xml: &str) -> String {
    replace_ds_tag_content_with(xml, "SignatureValue", |chars| {
        if let Some((index, _)) = chars
            .iter()
            .enumerate()
            .find(|(_, ch)| ch.is_ascii_alphanumeric())
        {
            chars[index] = '!';
        } else {
            panic!("SignatureValue did not contain any mutable base64 chars");
        }
    })
}

fn inject_non_ascii_whitespace_in_signature_value(xml: &str) -> String {
    replace_ds_tag_content_with(xml, "SignatureValue", |chars| {
        if let Some((index, _)) = chars
            .iter()
            .enumerate()
            .find(|(_, ch)| ch.is_ascii_alphanumeric())
        {
            chars.insert(index + 1, '\u{00A0}');
        } else {
            panic!("SignatureValue did not contain any mutable base64 chars");
        }
    })
}

fn inject_comment_in_signature_value(xml: &str) -> String {
    replace_ds_tag_content_with(xml, "SignatureValue", |chars| {
        if chars.len() < 4 {
            panic!("SignatureValue too short for comment split mutation");
        }
        let split_at = chars.len() / 2;
        let mut with_comment = Vec::with_capacity(chars.len() + 8);
        with_comment.extend_from_slice(&chars[..split_at]);
        with_comment.extend("<!--x-->".chars());
        with_comment.extend_from_slice(&chars[split_at..]);
        *chars = with_comment;
    })
}

fn insert_object_before_signed_info(xml: &str) -> String {
    let (signed_info_open, object_xml) = if xml.contains("<ds:SignedInfo") {
        ("<ds:SignedInfo", "<ds:Object/>")
    } else {
        ("<SignedInfo", "<Object/>")
    };
    let start = xml
        .find(signed_info_open)
        .unwrap_or_else(|| panic!("missing opening tag prefix {signed_info_open}"));
    format!("{}{}{}", &xml[..start], object_xml, &xml[start..])
}

fn duplicate_signed_info(xml: &str) -> String {
    let (open, close) = if xml.contains("<ds:SignedInfo") {
        ("<ds:SignedInfo", "</ds:SignedInfo>")
    } else {
        ("<SignedInfo", "</SignedInfo>")
    };
    let start = xml
        .find(open)
        .unwrap_or_else(|| panic!("missing opening tag prefix {open}"));
    let end = xml[start..]
        .find(close)
        .unwrap_or_else(|| panic!("missing closing tag {close}"))
        + start
        + close.len();
    let signed_info_block = &xml[start..end];
    format!("{}{}{}", &xml[..end], signed_info_block, &xml[end..])
}

fn insert_object_before_signature_value(xml: &str) -> String {
    let (signature_value_open, object_xml) = if xml.contains("<ds:SignatureValue") {
        ("<ds:SignatureValue", "<ds:Object/>")
    } else {
        ("<SignatureValue", "<Object/>")
    };
    let start = xml
        .find(signature_value_open)
        .unwrap_or_else(|| panic!("missing opening tag prefix {signature_value_open}"));
    format!("{}{}{}", &xml[..start], object_xml, &xml[start..])
}

fn duplicate_signature_value(xml: &str) -> String {
    let (open, close) = if xml.contains("<ds:SignatureValue") {
        ("<ds:SignatureValue", "</ds:SignatureValue>")
    } else {
        ("<SignatureValue", "</SignatureValue>")
    };
    let start = xml
        .find(open)
        .unwrap_or_else(|| panic!("missing opening tag prefix {open}"));
    let end = xml[start..]
        .find(close)
        .unwrap_or_else(|| panic!("missing closing tag {close}"))
        + start
        + close.len();
    let signature_value_block = &xml[start..end];
    format!("{}{}{}", &xml[..end], signature_value_block, &xml[end..])
}

fn insert_nested_element_in_signature_value(xml: &str) -> String {
    replace_ds_tag_content_with(xml, "SignatureValue", |chars| {
        if chars.len() < 4 {
            panic!("SignatureValue too short for nested-element mutation");
        }
        let split_at = chars.len() / 2;
        let mut mixed = Vec::with_capacity(chars.len() + 6);
        mixed.extend_from_slice(&chars[..split_at]);
        mixed.extend("<x/>".chars());
        mixed.extend_from_slice(&chars[split_at..]);
        *chars = mixed;
    })
}

#[test]
fn replace_ds_tag_content_with_allows_whitespace_before_closing_bracket() {
    let xml = "<Root><ds:SignatureValue   >ABC</ds:SignatureValue></Root>";

    let mutated = replace_ds_tag_content(xml, "SignatureValue", "XYZ");

    assert_eq!(
        mutated,
        "<Root><ds:SignatureValue   >XYZ</ds:SignatureValue></Root>"
    );
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

#[test]
fn tampered_signature_value_fails_after_references_pass_ecdsa() {
    let xml = read_fixture(Path::new(
        "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloped-sha256-ecdsa-sha256.xml",
    ));
    let public_key_pem = read_fixture(Path::new("tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem"));
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
fn tampered_digest_value_fails_before_signature_stage_ecdsa() {
    let xml = read_fixture(Path::new(
        "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloped-sha256-ecdsa-sha256.xml",
    ));
    let public_key_pem = read_fixture(Path::new("tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem"));
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

#[test]
fn malformed_signature_value_base64_returns_decode_error() {
    let xml = read_fixture(Path::new(
        "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.xml",
    ));
    let public_key_pem = read_fixture(Path::new("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"));
    let tampered_xml = inject_invalid_base64_in_signature_value(&xml);

    let err = verify_signature_with_pem_key(&tampered_xml, &public_key_pem, false)
        .expect_err("malformed SignatureValue base64 must fail decode stage");

    assert!(matches!(
        err,
        SignatureVerificationPipelineError::SignatureValueBase64(_)
    ));
}

#[test]
fn signature_value_with_non_ascii_whitespace_is_rejected() {
    let xml = read_fixture(Path::new(
        "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.xml",
    ));
    let public_key_pem = read_fixture(Path::new("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"));
    let tampered_xml = inject_non_ascii_whitespace_in_signature_value(&xml);

    let err = verify_signature_with_pem_key(&tampered_xml, &public_key_pem, false)
        .expect_err("non-XML whitespace in SignatureValue must fail base64 decode");

    assert!(matches!(
        err,
        SignatureVerificationPipelineError::SignatureValueBase64(_)
    ));
}

#[test]
fn signature_value_split_by_comment_still_verifies() {
    let xml = read_fixture(Path::new(
        "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.xml",
    ));
    let public_key_pem = read_fixture(Path::new("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"));
    let tampered_xml = inject_comment_in_signature_value(&xml);

    let result = verify_signature_with_pem_key(&tampered_xml, &public_key_pem, false)
        .expect("SignatureValue split by comment should still decode and verify");

    assert!(result.references.all_valid());
    assert!(result.signature_checked);
    assert!(result.signature_valid);
}

#[test]
fn signed_info_must_be_first_element_child_of_signature() {
    let xml = read_fixture(Path::new(
        "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.xml",
    ));
    let public_key_pem = read_fixture(Path::new("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"));
    let tampered_xml = insert_object_before_signed_info(&xml);

    let err = verify_signature_with_pem_key(&tampered_xml, &public_key_pem, false)
        .expect_err("SignedInfo not-first child must be rejected");

    assert_invalid_structure_reason(
        err,
        "SignedInfo must be the first element child of Signature",
    );
}

#[test]
fn duplicate_signed_info_is_rejected() {
    let xml = read_fixture(Path::new(
        "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.xml",
    ));
    let public_key_pem = read_fixture(Path::new("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"));
    let tampered_xml = duplicate_signed_info(&xml);

    let err = verify_signature_with_pem_key(&tampered_xml, &public_key_pem, false)
        .expect_err("duplicate SignedInfo must be rejected");

    assert_invalid_structure_reason(err, "SignedInfo must appear exactly once under Signature");
}

#[test]
fn missing_signed_info_is_reported_as_missing_element() {
    let xml = read_fixture(Path::new(
        "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.xml",
    ));
    let public_key_pem = read_fixture(Path::new("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"));
    let tampered_xml = replace_ds_tag_content_with(&xml, "Signature", |chars| {
        chars.clear();
    });

    let err = verify_signature_with_pem_key(&tampered_xml, &public_key_pem, false)
        .expect_err("missing SignedInfo must be rejected as missing element");
    assert!(matches!(
        err,
        SignatureVerificationPipelineError::MissingElement {
            element: "SignedInfo"
        }
    ));
}

#[test]
fn multiple_signature_elements_are_rejected() {
    let xml = read_fixture(Path::new(
        "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.xml",
    ));
    let xml_without_decl = xml.replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n", "");
    let additional_signature = "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"></Signature>";
    let tampered_xml = format!("<Root>{xml_without_decl}{additional_signature}</Root>");
    let public_key_pem = read_fixture(Path::new("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"));

    let err = verify_signature_with_pem_key(&tampered_xml, &public_key_pem, false)
        .expect_err("documents with multiple Signature elements must be rejected");
    assert!(matches!(
        err,
        SignatureVerificationPipelineError::InvalidStructure {
            reason: "Signature must appear exactly once in document",
        }
    ));
}

#[test]
fn signature_value_must_be_second_element_child_of_signature() {
    let xml = read_fixture(Path::new(
        "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.xml",
    ));
    let public_key_pem = read_fixture(Path::new("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"));
    let tampered_xml = insert_object_before_signature_value(&xml);

    let err = verify_signature_with_pem_key(&tampered_xml, &public_key_pem, false)
        .expect_err("SignatureValue not-second child must be rejected");
    assert_invalid_structure_reason(
        err,
        "SignatureValue must be the second element child of Signature",
    );
}

#[test]
fn duplicate_signature_value_is_rejected() {
    let xml = read_fixture(Path::new(
        "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.xml",
    ));
    let public_key_pem = read_fixture(Path::new("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"));
    let tampered_xml = duplicate_signature_value(&xml);

    let err = verify_signature_with_pem_key(&tampered_xml, &public_key_pem, false)
        .expect_err("duplicate SignatureValue must be rejected");
    assert_invalid_structure_reason(err, "SignatureValue must appear exactly once under Signature");
}

#[test]
fn signature_value_with_nested_element_is_rejected() {
    let xml = read_fixture(Path::new(
        "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.xml",
    ));
    let public_key_pem = read_fixture(Path::new("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"));
    let tampered_xml = insert_nested_element_in_signature_value(&xml);

    let err = verify_signature_with_pem_key(&tampered_xml, &public_key_pem, false)
        .expect_err("nested elements inside SignatureValue must be rejected");
    assert_invalid_structure_reason(err, "SignatureValue must not contain element children");
}

#[test]
fn empty_signature_value_is_not_reported_as_missing_element() {
    let xml = read_fixture(Path::new(
        "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.xml",
    ));
    let public_key_pem = read_fixture(Path::new("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"));
    let tampered_xml = replace_ds_tag_content(&xml, "SignatureValue", "");

    let result = verify_signature_with_pem_key(&tampered_xml, &public_key_pem, false)
        .expect("empty SignatureValue should not be treated as missing element");

    assert!(result.references.all_valid());
    assert!(result.signature_checked);
    assert!(!result.signature_valid);
}
