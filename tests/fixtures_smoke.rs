//! Smoke tests verifying that donor test fixtures are present, readable,
//! and structurally valid. These tests validate the P1-014a fixture setup
//! so that downstream tasks (P1-014b, P1-018a, P1-019a, P1-020a, etc.)
//! can rely on fixtures being available.

use std::fs;
use std::path::Path;

/// Base path for all test fixtures.
fn fixtures_dir() -> &'static Path {
    Path::new("tests/fixtures")
}

// ─── Key fixtures ───────────────────────────────────────────────────────────

/// Verify RSA 2048 key triplet (private key, certificate, public key) exists
/// and contains valid PEM markers.
#[test]
fn rsa_2048_key_files_are_valid_pem() {
    let dir = fixtures_dir().join("keys/rsa");
    assert_pem_file(&dir.join("rsa-2048-key.pem"), "PRIVATE KEY");
    assert_pem_file(&dir.join("rsa-2048-cert.pem"), "CERTIFICATE");
    assert_pem_file(&dir.join("rsa-2048-pubkey.pem"), "PUBLIC KEY");
}

/// Verify RSA 4096 key triplet exists and contains valid PEM markers.
#[test]
fn rsa_4096_key_files_are_valid_pem() {
    let dir = fixtures_dir().join("keys/rsa");
    assert_pem_file(&dir.join("rsa-4096-key.pem"), "PRIVATE KEY");
    assert_pem_file(&dir.join("rsa-4096-cert.pem"), "CERTIFICATE");
    assert_pem_file(&dir.join("rsa-4096-pubkey.pem"), "PUBLIC KEY");
}

/// Verify RSA expired key triplet exists (needed for P2-025a negative tests).
#[test]
fn rsa_expired_key_files_are_valid_pem() {
    let dir = fixtures_dir().join("keys/rsa");
    assert_pem_file(&dir.join("rsa-expired-key.pem"), "PRIVATE KEY");
    assert_pem_file(&dir.join("rsa-expired-cert.pem"), "CERTIFICATE");
    assert_pem_file(&dir.join("rsa-expired-pubkey.pem"), "PUBLIC KEY");
}

/// Verify revoked certificate CRL exists (needed for P2-005 chain verification).
#[test]
fn rsa_revoked_crl_is_valid_pem() {
    let dir = fixtures_dir().join("keys/rsa");
    assert_pem_file(&dir.join("rsa-2048-cert-revoked-crl.pem"), "X509 CRL");
}

/// Verify EC P-256 key triplet exists and contains valid PEM markers.
#[test]
fn ec_p256_key_files_are_valid_pem() {
    let dir = fixtures_dir().join("keys/ec");
    assert_pem_file(&dir.join("ec-prime256v1-key.pem"), "PRIVATE KEY");
    assert_pem_file(&dir.join("ec-prime256v1-cert.pem"), "CERTIFICATE");
    assert_pem_file(&dir.join("ec-prime256v1-pubkey.pem"), "PUBLIC KEY");
}

/// Verify EC P-384 key triplet exists and contains valid PEM markers.
#[test]
fn ec_p384_key_files_are_valid_pem() {
    let dir = fixtures_dir().join("keys/ec");
    assert_pem_file(&dir.join("ec-prime384v1-key.pem"), "PRIVATE KEY");
    assert_pem_file(&dir.join("ec-prime384v1-cert.pem"), "CERTIFICATE");
    assert_pem_file(&dir.join("ec-prime384v1-pubkey.pem"), "PUBLIC KEY");
}

/// Verify CA chain certificates exist (root CA + intermediate CA2).
#[test]
fn ca_chain_certificates_are_valid_pem() {
    let dir = fixtures_dir().join("keys");
    assert_pem_file(&dir.join("cacert.pem"), "CERTIFICATE");
    assert_pem_file(&dir.join("ca2cert.pem"), "CERTIFICATE");
    assert_pem_file(&dir.join("cakey.pem"), "ENCRYPTED PRIVATE KEY");
    assert_pem_file(&dir.join("ca2key.pem"), "PRIVATE KEY");
}

/// Verify HMAC key exists and is non-empty binary (6 bytes per xmlsec1 test suite).
#[test]
fn hmac_key_is_readable_binary() {
    let path = fixtures_dir().join("keys/hmackey.bin");
    let data = fs::read(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    assert_eq!(
        data.len(),
        6,
        "HMAC key should be 6 bytes (xmlsec1 test suite standard)"
    );
    assert!(
        data.iter().any(|&b| b != 0),
        "HMAC key should not be all zeros"
    );
}

// ─── C14N golden files ──────────────────────────────────────────────────────

/// Verify all 28 Merlin C14N golden output files exist (c14n-0.txt through c14n-27.txt)
/// plus the source signature.xml.
#[test]
fn merlin_c14n_three_golden_files_complete() {
    let dir = fixtures_dir().join("c14n/merlin-c14n-three");

    // Source document must exist and be valid XML
    let sig_xml = fs::read_to_string(dir.join("signature.xml")).expect("signature.xml must exist");
    assert!(
        sig_xml.contains("<foo:Root"),
        "signature.xml should contain Merlin's test document root element"
    );

    // All 28 golden output files (c14n-0.txt through c14n-27.txt)
    for i in 0..28 {
        let name = format!("c14n-{i}.txt");
        let path = dir.join(&name);
        assert!(
            path.exists(),
            "missing golden file: {name} (needed for Merlin C14N test vector #{i})"
        );
        // Files may be empty (e.g., c14n-15, c14n-16, c14n-25 — empty XPath selections)
        // but they must exist
    }
}

/// Verify non-empty golden files contain valid XML fragments (basic structure check).
#[test]
fn merlin_c14n_three_non_empty_goldens_are_xml() {
    let dir = fixtures_dir().join("c14n/merlin-c14n-three");

    // c14n-0.txt is a known non-empty golden — should contain XML element
    let c14n_0 = fs::read_to_string(dir.join("c14n-0.txt")).expect("c14n-0.txt must be readable");
    assert!(!c14n_0.is_empty(), "c14n-0.txt should not be empty");
    assert!(
        c14n_0.contains('<'),
        "c14n-0.txt should contain XML elements"
    );
}

/// Verify Merlin exclusive C14N input files exist.
#[test]
fn merlin_exc_c14n_one_input_files_present() {
    let dir = fixtures_dir().join("c14n/merlin-exc-c14n-one");

    let exc_xml =
        fs::read_to_string(dir.join("exc-signature.xml")).expect("exc-signature.xml must exist");
    assert!(
        exc_xml.contains("Signature"),
        "exc-signature.xml should contain a Signature element"
    );

    let exc_tmpl =
        fs::read_to_string(dir.join("exc-signature.tmpl")).expect("exc-signature.tmpl must exist");
    assert!(
        exc_tmpl.contains("Signature"),
        "exc-signature.tmpl should contain a Signature template"
    );
}

/// Verify C14N 1.1 test vector (xml:base fixup input) exists.
#[test]
fn c14n11_xml_base_input_present() {
    let dir = fixtures_dir().join("c14n/c14n11");

    let xml =
        fs::read_to_string(dir.join("xml-base-input.xml")).expect("xml-base-input.xml must exist");
    assert!(
        xml.contains("xml:base"),
        "xml-base-input.xml should contain xml:base attributes for C14N 1.1 testing"
    );
}

// ─── Fixture completeness summary ───────────────────────────────────────────

/// Verify total fixture file count matches expected (guards against accidental deletion).
#[test]
fn fixture_file_count_matches_expected() {
    let mut count = 0;
    count_files_recursive(fixtures_dir(), &mut count);
    assert_eq!(
        count, 62,
        "expected 62 fixture files total (21 keys + 41 c14n); \
         if you added/removed files, update this count"
    );
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Assert that a file exists and contains the expected PEM header marker.
fn assert_pem_file(path: &Path, expected_marker: &str) {
    let content = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read PEM file {}: {e}", path.display()));

    let begin_marker = format!("-----BEGIN {expected_marker}-----");
    let end_marker = format!("-----END {expected_marker}-----");

    assert!(
        content.contains(&begin_marker),
        "{} should contain '{begin_marker}' but got:\n{}",
        path.display(),
        &content[..content.len().min(200)]
    );
    assert!(
        content.contains(&end_marker),
        "{} should contain '{end_marker}'",
        path.display()
    );
}

/// Recursively count files in a directory. Panics on I/O errors
/// so missing/unreadable fixtures produce a clear diagnostic.
fn count_files_recursive(dir: &Path, count: &mut usize) {
    let entries = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("cannot read directory {}: {e}", dir.display()));
    for entry in entries {
        let entry = entry.unwrap_or_else(|e| panic!("cannot read entry in {}: {e}", dir.display()));
        let path = entry.path();
        if path.is_dir() {
            count_files_recursive(&path, count);
        } else {
            *count += 1;
        }
    }
}
