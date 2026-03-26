//! Integration tests for XMLDSig RSA signature verification.
//!
//! These tests validate the low-level crypto layer for roadmap task P1-019:
//! canonicalized `<SignedInfo>` bytes plus a real RSA public key must verify
//! against donor `SignatureValue` bytes for the declared `SignatureMethod`.

use std::path::Path;

use base64::Engine;
use xml_sec::c14n::canonicalize;
use xml_sec::xmldsig::parse::{SignatureAlgorithm, find_signature_node, parse_signed_info};
use xml_sec::xmldsig::signature::{
    SignatureVerificationError, verify_rsa_signature_pem, verify_rsa_signature_spki,
};

fn read_fixture(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read fixture {}: {err}", path.display()))
}

fn canonicalized_signed_info_and_signature(xml: &str) -> (SignatureAlgorithm, Vec<u8>, Vec<u8>) {
    let doc = roxmltree::Document::parse(xml).expect("fixture XML should parse");
    let signature_node = find_signature_node(&doc).expect("fixture XML should contain Signature");
    let signed_info_node = signature_node
        .children()
        .find(|node| node.is_element() && node.tag_name().name() == "SignedInfo")
        .expect("fixture XML should contain SignedInfo");
    let signed_info = parse_signed_info(signed_info_node).expect("SignedInfo should parse");

    let mut canonical = Vec::new();
    canonicalize(
        &doc,
        Some(&|node| {
            node == signed_info_node
                || node
                    .ancestors()
                    .any(|ancestor| ancestor == signed_info_node)
        }),
        &signed_info.c14n_method,
        &mut canonical,
    )
    .expect("SignedInfo canonicalization should succeed");

    let signature_value_text = signature_node
        .children()
        .find(|node| node.is_element() && node.tag_name().name() == "SignatureValue")
        .and_then(|node| node.text())
        .expect("fixture XML should contain SignatureValue text")
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    let signature_value = base64::engine::general_purpose::STANDARD
        .decode(signature_value_text)
        .expect("SignatureValue should be valid base64");

    (signed_info.signature_method, canonical, signature_value)
}

fn assert_donor_signature_valid(
    xml_path: &Path,
    public_key_path: &Path,
    expected_algorithm: SignatureAlgorithm,
) {
    let xml = read_fixture(xml_path);
    let public_key_pem = read_fixture(public_key_path);
    let (algorithm, canonical_signed_info, signature_value) =
        canonicalized_signed_info_and_signature(&xml);

    assert_eq!(algorithm, expected_algorithm, "unexpected SignatureMethod");

    let valid = verify_rsa_signature_pem(
        algorithm,
        &public_key_pem,
        &canonical_signed_info,
        &signature_value,
    )
    .expect("RSA verification should not error on valid fixtures");
    assert!(valid, "donor RSA signature should verify");
}

#[test]
fn donor_rsa_sha1_signature_matches() {
    assert_donor_signature_valid(
        Path::new("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloped-sha1-rsa-sha1.xml"),
        Path::new("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem"),
        SignatureAlgorithm::RsaSha1,
    );
}

#[test]
fn donor_rsa_sha256_signature_matches() {
    assert_donor_signature_valid(
        Path::new("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.xml"),
        Path::new("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"),
        SignatureAlgorithm::RsaSha256,
    );
}

#[test]
fn donor_rsa_sha384_signature_matches() {
    assert_donor_signature_valid(
        Path::new("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha384-rsa-sha384.xml"),
        Path::new("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem"),
        SignatureAlgorithm::RsaSha384,
    );
}

#[test]
fn donor_rsa_sha512_signature_matches() {
    assert_donor_signature_valid(
        Path::new("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha512-rsa-sha512.xml"),
        Path::new("tests/fixtures/keys/rsa/rsa-4096-pubkey.pem"),
        SignatureAlgorithm::RsaSha512,
    );
}

#[test]
fn tampered_signed_info_fails_verification() {
    let xml = read_fixture(Path::new(
        "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.xml",
    ));
    let public_key_pem = read_fixture(Path::new("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"));
    let (algorithm, mut canonical_signed_info, signature_value) =
        canonicalized_signed_info_and_signature(&xml);

    let last_index = canonical_signed_info.len() - 1;
    canonical_signed_info[last_index] ^= 0x01;

    let valid = verify_rsa_signature_pem(
        algorithm,
        &public_key_pem,
        &canonical_signed_info,
        &signature_value,
    )
    .expect("tampered data should still be a valid verification attempt");

    assert!(
        !valid,
        "tampering SignedInfo bytes must break signature verification"
    );
}

#[test]
fn wrong_spki_key_fails_verification() {
    let xml = read_fixture(Path::new(
        "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha512-rsa-sha512.xml",
    ));
    let public_key_pem = read_fixture(Path::new("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"));
    let (algorithm, canonical_signed_info, signature_value) =
        canonicalized_signed_info_and_signature(&xml);

    let valid = verify_rsa_signature_pem(
        algorithm,
        &public_key_pem,
        &canonical_signed_info,
        &signature_value,
    )
    .expect("wrong key should still be a valid verification attempt");

    assert!(
        !valid,
        "verification must fail with a different RSA public key"
    );
}

#[test]
fn non_public_key_pem_returns_invalid_key_format() {
    let err = verify_rsa_signature_pem(
        SignatureAlgorithm::RsaSha256,
        "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n",
        b"payload",
        b"signature",
    )
    .expect_err("non-public-key PEM should be rejected");

    assert!(matches!(
        err,
        SignatureVerificationError::InvalidKeyFormat { .. }
    ));
}

#[test]
fn malformed_pem_returns_typed_error() {
    let err = verify_rsa_signature_pem(
        SignatureAlgorithm::RsaSha256,
        "-----BEGIN PUBLIC KEY-----\n%%%%\n-----END PUBLIC KEY-----\n",
        b"payload",
        b"signature",
    )
    .expect_err("corrupt PEM should be rejected");

    assert!(matches!(err, SignatureVerificationError::InvalidKeyPem));
}

#[test]
fn pem_with_trailing_garbage_returns_typed_error() {
    let public_key_pem = format!(
        "{}TRAILING",
        read_fixture(Path::new("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"))
    );

    let err = verify_rsa_signature_pem(
        SignatureAlgorithm::RsaSha256,
        &public_key_pem,
        b"payload",
        b"signature",
    )
    .expect_err("PEM with trailing garbage should be rejected");

    assert!(matches!(err, SignatureVerificationError::InvalidKeyPem));
}

#[test]
fn malformed_spki_der_returns_typed_error() {
    let err = verify_rsa_signature_spki(
        SignatureAlgorithm::RsaSha256,
        &[0x01, 0x02, 0x03],
        b"payload",
        b"signature",
    )
    .expect_err("malformed SPKI DER should be rejected");

    assert!(matches!(err, SignatureVerificationError::InvalidKeyDer));
}

#[test]
fn spki_der_with_trailing_garbage_returns_typed_error() {
    let mut public_key_der = x509_parser::pem::parse_x509_pem(
        read_fixture(Path::new("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem")).as_bytes(),
    )
    .expect("fixture PEM should parse")
    .1
    .contents;
    public_key_der.extend_from_slice(b"TRAILING");

    let err = verify_rsa_signature_spki(
        SignatureAlgorithm::RsaSha256,
        &public_key_der,
        b"payload",
        b"signature",
    )
    .expect_err("SPKI DER with trailing garbage should be rejected");

    assert!(matches!(err, SignatureVerificationError::InvalidKeyDer));
}
