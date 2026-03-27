//! Integration tests for XMLDSig ECDSA signature verification.
//!
//! These tests validate roadmap task P1-020: canonicalized `<SignedInfo>` bytes
//! plus real donor EC public keys must verify against XMLDSig raw `r || s`
//! `SignatureValue` bytes for the declared `SignatureMethod`.

use std::path::Path;

use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P384_SHA384_ASN1_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair,
};
use xml_sec::c14n::canonicalize;
use xml_sec::xmldsig::parse::{SignatureAlgorithm, find_signature_node, parse_signed_info};
use xml_sec::xmldsig::{
    SignatureVerificationError, verify_ecdsa_signature_pem, verify_ecdsa_signature_spki,
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

    let valid = verify_ecdsa_signature_pem(
        algorithm,
        &public_key_pem,
        &canonical_signed_info,
        &signature_value,
    )
    .expect("ECDSA verification should not error on valid fixtures");
    assert!(valid, "donor ECDSA signature should verify");
}

#[test]
fn donor_ecdsa_p256_signature_matches() {
    assert_donor_signature_valid(
        Path::new("tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloped-sha256-ecdsa-sha256.xml"),
        Path::new("tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem"),
        SignatureAlgorithm::EcdsaP256Sha256,
    );
}

#[test]
fn local_p384_signature_matches() {
    let xml = read_fixture(Path::new(
        "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloped-sha384-ecdsa-sha384.xml",
    ));
    let private_key_pem = read_fixture(Path::new("tests/fixtures/keys/ec/ec-prime384v1-key.pem"));
    let public_key_pem = read_fixture(Path::new("tests/fixtures/keys/ec/ec-prime384v1-pubkey.pem"));
    let (signature_algorithm, canonical_signed_info, _) =
        canonicalized_signed_info_and_signature(&xml);
    assert_eq!(
        SignatureAlgorithm::EcdsaP384Sha384,
        signature_algorithm,
        "fixture SignatureMethod should be EcdsaP384Sha384",
    );

    let pkcs8_der = x509_parser::pem::parse_x509_pem(private_key_pem.as_bytes())
        .expect("fixture PEM should parse")
        .1
        .contents;
    let rng = SystemRandom::new();
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &pkcs8_der, &rng)
        .expect("fixture PKCS#8 should parse");
    let signature = key_pair
        .sign(&rng, &canonical_signed_info)
        .expect("fixture P-384 key should sign");

    let valid = verify_ecdsa_signature_pem(
        SignatureAlgorithm::EcdsaP384Sha384,
        &public_key_pem,
        &canonical_signed_info,
        signature.as_ref(),
    )
    .expect("P-384 verification should not error on valid fixtures");

    assert!(valid, "locally signed P-384 signature should verify");
}

#[test]
fn local_p384_der_signature_matches() {
    let xml = read_fixture(Path::new(
        "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloped-sha384-ecdsa-sha384.xml",
    ));
    let private_key_pem = read_fixture(Path::new("tests/fixtures/keys/ec/ec-prime384v1-key.pem"));
    let public_key_pem = read_fixture(Path::new("tests/fixtures/keys/ec/ec-prime384v1-pubkey.pem"));
    let (signature_algorithm, canonical_signed_info, _) =
        canonicalized_signed_info_and_signature(&xml);
    assert_eq!(
        SignatureAlgorithm::EcdsaP384Sha384,
        signature_algorithm,
        "fixture SignatureMethod should be EcdsaP384Sha384",
    );

    let pkcs8_der = x509_parser::pem::parse_x509_pem(private_key_pem.as_bytes())
        .expect("fixture PEM should parse")
        .1
        .contents;
    let rng = SystemRandom::new();
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &pkcs8_der, &rng)
        .expect("fixture PKCS#8 should parse");
    let signature = key_pair
        .sign(&rng, &canonical_signed_info)
        .expect("fixture P-384 key should sign");

    let valid = verify_ecdsa_signature_pem(
        SignatureAlgorithm::EcdsaP384Sha384,
        &public_key_pem,
        &canonical_signed_info,
        signature.as_ref(),
    )
    .expect("P-384 DER verification should not error on valid fixtures");

    assert!(valid, "locally signed DER P-384 signature should verify");
}

#[test]
fn tampered_signed_info_fails_verification() {
    let xml = read_fixture(Path::new(
        "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloped-sha256-ecdsa-sha256.xml",
    ));
    let public_key_pem = read_fixture(Path::new("tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem"));
    let (algorithm, mut canonical_signed_info, signature_value) =
        canonicalized_signed_info_and_signature(&xml);

    let last = canonical_signed_info
        .last_mut()
        .expect("canonical SignedInfo should not be empty");
    *last ^= 0x01;

    let valid = verify_ecdsa_signature_pem(
        algorithm,
        &public_key_pem,
        &canonical_signed_info,
        &signature_value,
    )
    .expect("tampered data should still be a valid verification attempt");

    assert!(
        !valid,
        "tampering SignedInfo bytes must break ECDSA signature verification"
    );
}

#[test]
fn curve_mismatched_public_key_returns_typed_key_error() {
    let xml = read_fixture(Path::new(
        "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloped-sha256-ecdsa-sha256.xml",
    ));
    let public_key_pem = read_fixture(Path::new("tests/fixtures/keys/ec/ec-prime384v1-pubkey.pem"));
    let (algorithm, canonical_signed_info, signature_value) =
        canonicalized_signed_info_and_signature(&xml);

    let err = verify_ecdsa_signature_pem(
        algorithm,
        &public_key_pem,
        &canonical_signed_info,
        &signature_value,
    )
    .expect_err("curve-mismatched EC key should be rejected before verification");

    assert!(matches!(
        err,
        SignatureVerificationError::KeyAlgorithmMismatch { .. }
    ));
}

#[test]
fn non_public_key_pem_returns_invalid_key_format() {
    let err = verify_ecdsa_signature_pem(
        SignatureAlgorithm::EcdsaP256Sha256,
        "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n",
        b"payload",
        &[0_u8; 64],
    )
    .expect_err("non-public-key PEM should be rejected");

    assert!(matches!(
        err,
        SignatureVerificationError::InvalidKeyFormat { .. }
    ));
}

#[test]
fn malformed_pem_returns_typed_error() {
    let err = verify_ecdsa_signature_pem(
        SignatureAlgorithm::EcdsaP256Sha256,
        "-----BEGIN PUBLIC KEY-----\n%%%%\n-----END PUBLIC KEY-----\n",
        b"payload",
        &[0_u8; 64],
    )
    .expect_err("corrupt PEM should be rejected");

    assert!(matches!(err, SignatureVerificationError::InvalidKeyPem));
}

#[test]
fn pem_with_trailing_garbage_returns_typed_error() {
    let public_key_pem = format!(
        "{}TRAILING",
        read_fixture(Path::new("tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem"))
    );

    let err = verify_ecdsa_signature_pem(
        SignatureAlgorithm::EcdsaP256Sha256,
        &public_key_pem,
        b"payload",
        &[0_u8; 64],
    )
    .expect_err("PEM with trailing garbage should be rejected");

    assert!(matches!(err, SignatureVerificationError::InvalidKeyPem));
}

#[test]
fn malformed_spki_der_returns_typed_error() {
    let err = verify_ecdsa_signature_spki(
        SignatureAlgorithm::EcdsaP256Sha256,
        &[0x01, 0x02, 0x03],
        b"payload",
        &[0_u8; 64],
    )
    .expect_err("malformed SPKI DER should be rejected");

    assert!(
        matches!(err, SignatureVerificationError::InvalidKeyDer),
        "expected InvalidKeyDer, got {err:?}"
    );
}

#[test]
fn non_ec_spki_key_returns_algorithm_mismatch_error() {
    let public_key_der = x509_parser::pem::parse_x509_pem(
        read_fixture(Path::new("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem")).as_bytes(),
    )
    .expect("fixture PEM should parse")
    .1
    .contents;

    let err = verify_ecdsa_signature_spki(
        SignatureAlgorithm::EcdsaP256Sha256,
        &public_key_der,
        b"payload",
        &[0_u8; 64],
    )
    .expect_err("non-EC SPKI key should be rejected by ECDSA verifier");

    assert!(matches!(
        err,
        SignatureVerificationError::KeyAlgorithmMismatch { .. }
    ));
}

#[test]
fn non_ecdsa_algorithm_is_rejected_before_key_parsing() {
    let rsa_public_key_der = x509_parser::pem::parse_x509_pem(
        read_fixture(Path::new("tests/fixtures/keys/rsa/rsa-2048-pubkey.pem")).as_bytes(),
    )
    .expect("fixture PEM should parse")
    .1
    .contents;

    for public_key_der in [&rsa_public_key_der[..], &[0x01_u8, 0x02, 0x03]] {
        let err = verify_ecdsa_signature_spki(
            SignatureAlgorithm::RsaSha256,
            public_key_der,
            b"payload",
            &[0_u8; 64],
        )
        .expect_err("non-ECDSA algorithm must be rejected before key parsing");

        assert!(matches!(
            err,
            SignatureVerificationError::UnsupportedAlgorithm { .. }
        ));
    }
}

#[test]
fn spki_der_valid_signature_matches() {
    let xml = read_fixture(Path::new(
        "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloped-sha256-ecdsa-sha256.xml",
    ));
    let (algorithm, canonical_signed_info, signature_value) =
        canonicalized_signed_info_and_signature(&xml);
    let public_key_der = x509_parser::pem::parse_x509_pem(
        read_fixture(Path::new("tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem")).as_bytes(),
    )
    .expect("fixture PEM should parse")
    .1
    .contents;

    let valid = verify_ecdsa_signature_spki(
        algorithm,
        &public_key_der,
        &canonical_signed_info,
        &signature_value,
    )
    .expect("SPKI verifier should accept valid fixture key and signature");

    assert!(valid, "SPKI verifier should validate donor P-256 signature");
}

#[test]
fn spki_with_invalid_ec_point_prefix_returns_typed_error() {
    let xml = read_fixture(Path::new(
        "tests/fixtures/xmldsig/aleksey-xmldsig-01/enveloped-sha256-ecdsa-sha256.xml",
    ));
    let (algorithm, canonical_signed_info, signature_value) =
        canonicalized_signed_info_and_signature(&xml);
    let mut public_key_der = x509_parser::pem::parse_x509_pem(
        read_fixture(Path::new("tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem")).as_bytes(),
    )
    .expect("fixture PEM should parse")
    .1
    .contents;

    // For P-256 fixtures we expect BIT STRING header 03 42 00 followed by
    // uncompressed SEC1 prefix 0x04; mutating it to 0x02 keeps SPKI parseable
    // but should be rejected as invalid key encoding for ring.
    let marker = [0x03_u8, 0x42, 0x00, 0x04];
    let marker_pos = public_key_der
        .windows(marker.len())
        .position(|window| window == marker)
        .expect("fixture SPKI should contain uncompressed EC point marker");
    public_key_der[marker_pos + 3] = 0x02;

    let err = verify_ecdsa_signature_spki(
        algorithm,
        &public_key_der,
        &canonical_signed_info,
        &signature_value,
    )
    .expect_err("invalid EC point encoding should be rejected as key error");

    assert!(
        matches!(err, SignatureVerificationError::InvalidKeyDer),
        "expected InvalidKeyDer, got {err:?}"
    );
}

#[test]
fn signature_with_wrong_length_returns_typed_error() {
    let public_key_pem = read_fixture(Path::new("tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem"));

    let err = verify_ecdsa_signature_pem(
        SignatureAlgorithm::EcdsaP256Sha256,
        &public_key_pem,
        b"payload",
        &[0_u8; 63],
    )
    .expect_err("odd-sized XMLDSig ECDSA signature should be rejected");

    assert!(matches!(
        err,
        SignatureVerificationError::InvalidSignatureFormat
    ));
}

#[test]
fn malformed_der_signature_with_non_raw_length_returns_typed_error() {
    let public_key_pem = read_fixture(Path::new("tests/fixtures/keys/ec/ec-prime384v1-pubkey.pem"));
    let malformed_der_signature = {
        let mut signature = vec![0_u8; 95];
        signature[0] = 0x30;
        signature[1] = 93;
        signature
    };

    let err = verify_ecdsa_signature_pem(
        SignatureAlgorithm::EcdsaP384Sha384,
        &public_key_pem,
        b"payload",
        &malformed_der_signature,
    )
    .expect_err("malformed DER-encoded signature should be rejected");

    assert!(matches!(
        err,
        SignatureVerificationError::InvalidSignatureFormat
    ));
}

#[test]
fn spki_der_with_trailing_garbage_returns_typed_error() {
    let mut public_key_der = x509_parser::pem::parse_x509_pem(
        read_fixture(Path::new("tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem")).as_bytes(),
    )
    .expect("fixture PEM should parse")
    .1
    .contents;
    public_key_der.extend_from_slice(b"TRAILING");

    let err = verify_ecdsa_signature_spki(
        SignatureAlgorithm::EcdsaP256Sha256,
        &public_key_der,
        b"payload",
        &[0_u8; 64],
    )
    .expect_err("SPKI DER with trailing garbage should be rejected");

    assert!(matches!(err, SignatureVerificationError::InvalidKeyDer));
}
