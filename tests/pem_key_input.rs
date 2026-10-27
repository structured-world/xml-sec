//! PEM public-key input for `verify_signature_with_pem_key` (RFC 7468 section 2).
#![cfg(all(
    feature = "xmldsig",
    any(feature = "xml-backend-xmloxide", feature = "xml-backend-roxmltree")
))]

use xml_sec::xmldsig::{
    DsigError, DsigStatus, SignatureVerificationError, verify_signature_with_pem_key,
};

const RSA_DOCUMENT: &str =
    include_str!("fixtures/xmldsig/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256.xml");
const RSA_PUBLIC_KEY: &str = include_str!("fixtures/keys/rsa/rsa-2048-pubkey.pem");

/// The base64 body of the fixture, re-wrapped to `width` characters per line.
fn rewrapped(label: &str, width: usize) -> String {
    let body: String = RSA_PUBLIC_KEY
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let mut text = format!("-----BEGIN {label}-----\n");
    for chunk in body.as_bytes().chunks(width) {
        text.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        text.push('\n');
    }
    text.push_str("-----END ");
    text.push_str(label);
    text.push_str("-----\n");
    text
}

fn verifies(pem: &str) -> bool {
    matches!(
        verify_signature_with_pem_key(RSA_DOCUMENT, pem, false).map(|result| result.status),
        Ok(DsigStatus::Valid)
    )
}

#[test]
fn explanatory_text_wrapping_and_trailing_whitespace_are_accepted() {
    // RFC 7468 section 2 permits text before the block; tools wrap at 64 or 76.
    assert!(verifies(RSA_PUBLIC_KEY));
    assert!(verifies(&format!(
        "Public key of the test signer\n{RSA_PUBLIC_KEY}"
    )));
    assert!(verifies(&rewrapped("PUBLIC KEY", 76)));
    assert!(verifies(&format!("{RSA_PUBLIC_KEY}\n  \r\n")));
    assert!(verifies(&RSA_PUBLIC_KEY.replace('\n', "\r\n")));
}

#[test]
fn malformed_blocks_are_rejected_as_invalid_pem() {
    // A second block or other trailing data, a mismatched end label and a
    // missing end boundary each leave no single unambiguous key.
    let end_label = RSA_PUBLIC_KEY.replace("-----END PUBLIC KEY-----", "-----END CERTIFICATE-----");
    let truncated = RSA_PUBLIC_KEY.replace("-----END PUBLIC KEY-----", "");
    for pem in [
        format!("{RSA_PUBLIC_KEY}trailing"),
        format!("{RSA_PUBLIC_KEY}{RSA_PUBLIC_KEY}"),
        end_label,
        truncated,
        String::new(),
    ] {
        let error = verify_signature_with_pem_key(RSA_DOCUMENT, &pem, false)
            .expect_err("malformed PEM must be rejected");
        assert!(
            matches!(
                error,
                DsigError::Crypto(SignatureVerificationError::InvalidKeyPem)
            ),
            "unexpected error for {pem:?}: {error:?}"
        );
    }
}

#[test]
fn a_block_with_another_label_reports_that_label() {
    // A well-formed block of the wrong type is a format error, not a PEM error.
    let error = verify_signature_with_pem_key(RSA_DOCUMENT, &rewrapped("CERTIFICATE", 64), false)
        .expect_err("a certificate label is not a public key");
    assert!(
        matches!(
            &error,
            DsigError::Crypto(SignatureVerificationError::InvalidKeyFormat { label })
                if label == "CERTIFICATE"
        ),
        "unexpected error: {error:?}"
    );
}
