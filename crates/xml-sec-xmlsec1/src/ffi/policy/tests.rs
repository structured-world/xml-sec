//! `xsPolicyRestrict`: a deployment's `xml-sec-config` layer narrows the
//! library's published snapshots, every operation's at once, and can never
//! widen them.

use std::ffi::{CStr, c_int};
use std::sync::Arc;

use xml_sec::policy::KemContentAuthentication;
use xml_sec::xmldsig::{SignatureAlgorithm, UriTypeSet};

use super::super::tests::own_process;
use super::*;

/// The library's current revision.
fn current() -> Pinned {
    Pinned::current(super::super::errors::here!("test")).expect("the library policy compiles")
}

/// `xsPolicyRestrict` over `toml` and `profile`.
fn restrict(toml: &str, profile: &CStr) -> c_int {
    // SAFETY: the document's bytes and a NUL-terminated name.
    unsafe { xsPolicyRestrict(toml.as_ptr(), toml.len(), profile.as_ptr()) }
}

#[test]
fn a_layer_narrows_every_operation_at_once() {
    // One call narrows verification and decryption in one revision, and
    // keeps what the library's boundary grants beyond the profile (external
    // reference URIs read from the caller's callbacks), since it narrows the
    // published snapshots rather than recompiling the profile.
    own_process();
    let before = current();
    assert_eq!(
        before
            .decryption
            .key_establishment
            .kem_content_authentication,
        KemContentAuthentication::ExternalAuthenticated
    );
    let toml = r#"
schema_version = 1
[profiles.deployment]
base = "XmlSecCompatible"
[profiles.deployment.verification.hmac]
minimum_key_bits = 256
minimum_output_bits = 160
[profiles.deployment.decryption.key_establishment]
kem_content_authentication = "RequireAuthenticatedCipher"
"#;
    assert_eq!(restrict(toml, c"deployment"), 0);
    let after = current();
    assert_eq!(after.verification.hmac.minimum_key_bits, 256);
    assert_eq!(after.verification.hmac.minimum_output_bits, 160);
    assert_eq!(
        after
            .decryption
            .key_establishment
            .kem_content_authentication,
        KemContentAuthentication::RequireAuthenticatedCipher
    );
    assert_eq!(after.verification.uris.references, UriTypeSet::ALL);
    assert_eq!(after.signing.uris.references, UriTypeSet::ALL);
    assert_eq!(after.decryption.uris.references, UriTypeSet::ALL);
}

#[test]
fn a_layer_cannot_widen_the_library_policy() {
    // A layer asking for weaker HMAC keys than the library admits, or for an
    // authentication the library already requires to be lifted, leaves the
    // stricter value; a later call narrows what an earlier one left.
    own_process();
    let strict = r#"
schema_version = 1
[profiles.strict]
base = "XmlSecCompatible"
[profiles.strict.verification.hmac]
minimum_key_bits = 256
minimum_output_bits = 160
[profiles.strict.decryption.key_establishment]
kem_content_authentication = "RequireAuthenticatedCipher"
"#;
    assert_eq!(restrict(strict, c"strict"), 0);
    let lax = r#"
schema_version = 1
[profiles.lax]
base = "XmlSecCompatible"
[profiles.lax.verification.hmac]
minimum_key_bits = 8
minimum_output_bits = 8
[profiles.lax.decryption.key_establishment]
kem_content_authentication = "ExternalAuthenticated"
"#;
    assert_eq!(restrict(lax, c"lax"), 0);
    let after = current();
    assert_eq!(after.verification.hmac.minimum_key_bits, 256);
    assert_eq!(after.verification.hmac.minimum_output_bits, 160);
    assert_eq!(
        after
            .decryption
            .key_establishment
            .kem_content_authentication,
        KemContentAuthentication::RequireAuthenticatedCipher
    );
}

#[test]
fn a_layer_removes_algorithms_from_verification_and_signing() {
    // A layer listing only RSA-SHA256 takes RSA-SHA1, which libxmlsec1 signs
    // and verifies with, away from both operations.
    own_process();
    let before = current();
    for policy in [
        before
            .verification
            .check_signature_algorithm(SignatureAlgorithm::RsaSha1),
        before
            .signing
            .check_signature_algorithm(SignatureAlgorithm::RsaSha1),
    ] {
        assert!(policy.is_ok());
    }
    let toml = r#"
schema_version = 1
[profiles.sha2]
base = "XmlSecCompatible"
[profiles.sha2.verification]
signature_algorithms = ["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"]
[profiles.sha2.signing]
signature_algorithms = ["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"]
"#;
    assert_eq!(restrict(toml, c"sha2"), 0);
    let after = current();
    for policy in [
        after
            .verification
            .check_signature_algorithm(SignatureAlgorithm::RsaSha1),
        after
            .signing
            .check_signature_algorithm(SignatureAlgorithm::RsaSha1),
    ] {
        assert!(policy.is_err());
    }
    for policy in [
        after
            .verification
            .check_signature_algorithm(SignatureAlgorithm::RsaSha256),
        after
            .signing
            .check_signature_algorithm(SignatureAlgorithm::RsaSha256),
    ] {
        assert!(policy.is_ok());
    }
}

#[test]
fn a_base_with_other_interpretations_is_refused() {
    // Interpretation choices (ID lookup, here(), key name reading) are not
    // ordered by strictness, so a layer based on the modern profile cannot be
    // composed onto the libxmlsec1-compatible library policy; it is refused
    // and nothing is published.
    own_process();
    let before = current();
    let toml = r#"
schema_version = 1
[profiles.modern]
base = "Modern"
"#;
    assert_eq!(restrict(toml, c"modern"), -1);
    assert!(Arc::ptr_eq(&before.verification, &current().verification));
}

#[test]
fn a_refused_layer_publishes_nothing() {
    // Malformed TOML, an unknown profile, a non-UTF-8 name, a profile that
    // disables an operation the library runs and missing arguments each fail
    // after a report and leave the published revision as it was.
    own_process();
    let before = current();
    let disabling = r#"
schema_version = 1
[profiles.no-encryption]
base = "XmlSecCompatible"
[profiles.no-encryption.encryption]
enabled = false
"#;
    assert_eq!(restrict("not toml", c"deployment"), -1);
    assert_eq!(restrict(disabling, c"unknown"), -1);
    assert_eq!(restrict(disabling, c"\xff"), -1);
    assert_eq!(restrict(disabling, c"no-encryption"), -1);
    // SAFETY: null arguments, refused before any read.
    unsafe {
        assert_eq!(xsPolicyRestrict(std::ptr::null(), 4, c"p".as_ptr()), -1);
        assert_eq!(xsPolicyRestrict(c"x".as_ptr().cast(), 0, c"p".as_ptr()), -1);
        assert_eq!(
            xsPolicyRestrict(c"x".as_ptr().cast(), 1, std::ptr::null()),
            -1
        );
    }
    let after = current();
    assert!(Arc::ptr_eq(&before.verification, &after.verification));
    assert!(Arc::ptr_eq(&before.signing, &after.signing));
    assert!(Arc::ptr_eq(&before.encryption, &after.encryption));
    assert!(Arc::ptr_eq(&before.decryption, &after.decryption));
}
