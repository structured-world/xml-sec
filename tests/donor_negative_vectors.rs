//! Negative XMLDSig vectors from the Phaos interoperability corpus.
//!
//! These files are intentionally malformed or cryptographically unusable. The
//! checks document which validation boundary rejects each case, so a parser or
//! key-policy relaxation cannot silently turn a hostile vector into `Valid`.

use std::path::Path;

use xml_sec::xmldsig::{DefaultKeyResolver, DsigError, DsigStatus, ParseError, VerifyContext};

const PHAOS_DIR: &str = "tests/fixtures/xmldsig/phaos-xmldsig-three";

fn read_vector(name: &str) -> String {
    let path = Path::new(PHAOS_DIR).join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

#[test]
fn phaos_bad_digest_vector_rejects_inconsistent_embedded_x509_selectors() {
    // The Phaos fixture contains X509 selectors inconsistent with its embedded
    // certificate. KeyInfo consumers must reject that ambiguity before use.
    let xml = read_vector("signature-rsa-enveloped-bad-digest-val.xml");
    let error = VerifyContext::new()
        .verify(&xml)
        .expect_err("inconsistent X509Data must reject the vector");

    assert!(
        matches!(
            error,
            DsigError::ParseKeyInfo(ParseError::InvalidStructure(_))
        ),
        "unexpected error: {error:?}"
    );
}

#[test]
fn phaos_bad_signature_vector_rejects_inconsistent_embedded_x509_selectors() {
    // SignatureValue is not reached: invalid X509Data selectors must fail
    // closed before any embedded key could become a verification candidate.
    let xml = read_vector("signature-rsa-enveloped-bad-sig.xml");
    let resolver = DefaultKeyResolver::default();
    let error = VerifyContext::new()
        .key_resolver(&resolver)
        .verify(&xml)
        .expect_err("inconsistent X509Data must reject the vector");

    assert!(
        matches!(
            error,
            DsigError::ParseKeyInfo(ParseError::InvalidStructure(_))
        ),
        "unexpected error: {error:?}"
    );
}

#[test]
fn phaos_valid_baseline_never_becomes_valid_without_explicit_legacy_policy() {
    // The matching historical positive vector carries the same unacceptable
    // 1024-bit key. This guards against adding an implicit compatibility path.
    let xml = read_vector("signature-rsa-enveloped.xml");
    let resolver = DefaultKeyResolver::default();
    let result = VerifyContext::new().key_resolver(&resolver).verify(&xml);

    assert!(
        !matches!(result, Ok(ref result) if matches!(result.status, DsigStatus::Valid)),
        "legacy Phaos RSA material must remain rejected by default"
    );
}
