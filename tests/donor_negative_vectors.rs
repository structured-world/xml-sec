//! Negative XMLDSig vectors from the Phaos interoperability corpus.
//!
//! Each check targets the first stable rejection boundary in the public API.
//! The historical fixtures combine invalid signatures with advisory X.509
//! metadata, so tests that exercise SignedInfo validation supply a caller key
//! and deliberately bypass document KeyInfo resolution.

use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use roxmltree::Document;
use x509_parser::prelude::{FromDer, X509Certificate};
use xml_sec::xmldsig::{
    DsigError, DsigStatus, FailureReason, KeyInfoSource, ParseError, SignatureAlgorithm,
    SignatureVerificationError, VerificationKey, VerifyContext, X509ChainError, X509ChainOptions,
    X509DataInfo, parse_key_info, verify_signature_with_pem_key, verify_x509_certificate_chain,
};

const PHAOS_DIR: &str = "tests/fixtures/xmldsig/phaos-xmldsig-three";
const STRONG_RSA_PUBLIC_KEY: &str = include_str!("fixtures/keys/rsa/rsa-2048-pubkey.pem");
const PHAOS_RSA_CERTIFICATE: &[u8] =
    include_bytes!("fixtures/xmldsig/phaos-xmldsig-three/certs/rsa-cert.der");
const PHAOS_RSA_CA_CERTIFICATE: &[u8] =
    include_bytes!("fixtures/xmldsig/phaos-xmldsig-three/certs/rsa-ca-cert.der");

fn read_vector(name: &str) -> String {
    let path = Path::new(PHAOS_DIR).join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn phaos_x509_data() -> X509DataInfo {
    let xml = format!(
        concat!(
            "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data>",
            "<X509Certificate>{}</X509Certificate>",
            "<X509Certificate>{}</X509Certificate>",
            "</X509Data></KeyInfo>"
        ),
        STANDARD.encode(PHAOS_RSA_CERTIFICATE),
        STANDARD.encode(PHAOS_RSA_CA_CERTIFICATE),
    );
    let document = Document::parse(&xml).expect("Phaos certificate wrapper must parse");
    let key_info = parse_key_info(document.root_element()).expect("Phaos chain must parse");
    match key_info
        .sources
        .into_iter()
        .next()
        .expect("Phaos chain must produce X509Data")
    {
        KeyInfoSource::X509Data(info) => info,
        other => panic!("expected X509Data, got {other:?}"),
    }
}

fn phaos_verification_key() -> VerificationKey {
    let (rest, certificate) = X509Certificate::from_der(PHAOS_RSA_CERTIFICATE)
        .expect("Phaos RSA certificate must be valid DER");
    assert!(rest.is_empty(), "Phaos certificate must consume all DER");
    VerificationKey {
        algorithm: SignatureAlgorithm::RsaSha1,
        public_key_bytes: certificate.public_key().raw.to_vec(),
        certificate_der: Some(PHAOS_RSA_CERTIFICATE.to_vec()),
        name: None,
    }
}

#[test]
fn phaos_bad_digest_reports_reference_mismatch_before_key_use() {
    // Supplying a caller key mirrors xmlsec1/Samael semantics: document KeyInfo
    // is advisory. The unrelated strong key is never used because digest
    // validation fails first, proving the exact fail-fast boundary.
    let xml = read_vector("signature-rsa-enveloped-bad-digest-val.xml");
    let result = verify_signature_with_pem_key(&xml, STRONG_RSA_PUBLIC_KEY, false)
        .expect("bad DigestValue must be a completed invalid verification");

    assert_eq!(
        result.status,
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
    );
    assert_eq!(result.signed_info_references.len(), 1);
    assert_eq!(result.signed_info_references[0].status, result.status);
}

#[test]
fn phaos_bad_signature_artifact_fails_on_its_unsupported_md5_reference() {
    // Despite its filename, the donor adds a second Reference using MD5 and
    // omits DigestValue. Unsupported MD5 is encountered first, so treating
    // this artifact as a SignatureValue mismatch would hide malformed input.
    let xml = read_vector("signature-rsa-enveloped-bad-sig.xml");
    let error = verify_signature_with_pem_key(&xml, STRONG_RSA_PUBLIC_KEY, false)
        .expect_err("unsupported donor Reference must fail processing");

    assert!(matches!(
        error,
        DsigError::ParseSignedInfo(ParseError::UnsupportedAlgorithm { ref uri })
            if uri == "http://www.w3.org/2001/04/xmldsig-more#md5"
    ));
}

#[test]
fn phaos_valid_baseline_rejects_legacy_rsa_key_policy() {
    // References in the historical positive vector are valid, but its
    // 1024-bit RSA key is below the crate's 2048-bit verification minimum.
    let xml = read_vector("signature-rsa-enveloped.xml");
    let key = phaos_verification_key();
    let error = VerifyContext::new()
        .key(&key)
        .verify(&xml)
        .expect_err("legacy Phaos RSA key must remain rejected");

    assert!(matches!(
        error,
        DsigError::Crypto(SignatureVerificationError::InvalidKeyDer)
    ));
}

#[test]
fn phaos_certificate_chain_is_expired_at_a_modern_verification_time() {
    // The Phaos leaf and CA expired in 2012. A deterministic 2026 verification
    // time must reject the leaf before its key can establish trust.
    let info = phaos_x509_data();
    let trusted = vec![PHAOS_RSA_CA_CERTIFICATE.to_vec()];
    let options = X509ChainOptions {
        trusted_certs: &trusted,
        verification_time: UNIX_EPOCH + Duration::from_secs(1_767_225_600),
        max_chain_depth: 2,
        check_crls: false,
    };

    assert_eq!(
        verify_x509_certificate_chain(&info, &options),
        Err(X509ChainError::CertificateNotValid(0))
    );
}
