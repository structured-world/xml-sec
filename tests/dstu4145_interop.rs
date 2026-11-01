//! DSTU 4145 verification against the test signatures published by the Central
//! Certification Authority of Ukraine (<https://czo.gov.ua/testexamples>).
#![cfg(feature = "dstu4145")]

use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::collections::BTreeSet;
use xml_sec::policy::{
    CertificateSignatureAlgorithms, Instant, VerificationPolicy, VerificationTrustMode,
};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, DsigError, DsigStatus, FailureReason, KeyResolverConfig,
    SignatureAlgorithm, VerifyContext,
};

const GOST: &str = include_str!("fixtures/xmldsig/dstu4145/dstu-enveloped-bb.xml");
const KUPYNA: &str = include_str!("fixtures/xmldsig/dstu4145/kupyna-enveloped-bb.xml");
const LTA: &str = include_str!("fixtures/xmldsig/dstu4145/dstu-detached-lta.xml");
/// June 2024, inside the validity of every published certificate.
const MOMENT: i64 = 1_717_200_000;

fn permissive() -> VerificationPolicy {
    let mut policy = VerificationPolicy::default();
    policy.key_trust.mode = VerificationTrustMode::CryptographicOnly;
    policy.digest_algorithms = Some(BTreeSet::from([
        DigestAlgorithm::Gost34311,
        DigestAlgorithm::Dstu7564_256,
    ]));
    let signatures = BTreeSet::from([
        SignatureAlgorithm::Dstu4145Gost34311,
        SignatureAlgorithm::Dstu4145Dstu7564_256,
    ]);
    policy.signature_algorithms = Some(signatures.clone());
    policy.key_trust.allowed_legacy_signature_algorithms = signatures;
    policy
}

fn status(xml: &str) -> DsigStatus {
    let resolver = DefaultKeyResolver::default();
    VerifyContext::new()
        .policy(permissive())
        .key_resolver(&resolver)
        .verify(xml)
        .expect("verification must run")
        .status
}

/// The issuing CA and the self-signed root, in the order the LTA sample keeps them.
fn published_chain() -> (Vec<u8>, Vec<u8>) {
    let mut certificates = LTA
        .split("<xades:EncapsulatedX509Certificate>")
        .skip(1)
        .map(|part| {
            let (encoded, _) = part
                .split_once("</xades:EncapsulatedX509Certificate>")
                .expect("fixture closes its certificate");
            STANDARD.decode(encoded).expect("fixture value is Base64")
        });
    let issuing = certificates.next().expect("fixture carries the issuing CA");
    let root = certificates.next().expect("fixture carries the root");
    (issuing, root)
}

/// Verify the signature in `GOST` under full X.509 path validation at a moment
/// inside the published certificates' validity.
fn chain_result(
    lookup: Vec<Vec<u8>>,
    trusted: Vec<Vec<u8>>,
    allowed: Option<CertificateSignatureAlgorithms>,
) -> Result<DsigStatus, DsigError> {
    chain_result_at(MOMENT, lookup, trusted, allowed)
}

fn chain_result_at(
    seconds: i64,
    lookup: Vec<Vec<u8>>,
    trusted: Vec<Vec<u8>>,
    allowed: Option<CertificateSignatureAlgorithms>,
) -> Result<DsigStatus, DsigError> {
    let mut policy = permissive();
    policy.key_trust.mode = VerificationTrustMode::RequireTrustedKey;
    policy.key_trust.verify_x509_chains = true;
    policy.key_trust.verification_time = Some(Instant::new(seconds, 0).expect("an instant"));
    policy.key_trust.certificate_signature_algorithms = allowed;
    let resolver = DefaultKeyResolver::new(KeyResolverConfig {
        lookup_certs: lookup,
        trusted_certs: trusted,
        ..KeyResolverConfig::default()
    });
    VerifyContext::new()
        .policy(policy)
        .key_resolver(&resolver)
        .verify(GOST)
        .map(|result| result.status)
}

/// `xml` with the `SignatureValue` octet at `index` flipped.
fn with_flipped_signature_octet(xml: &str, index: usize) -> String {
    let (head, rest) = xml
        .split_once("<ds:SignatureValue>")
        .expect("fixture has a SignatureValue");
    let (value, tail) = rest
        .split_once("</ds:SignatureValue>")
        .expect("fixture closes its SignatureValue");
    let mut octets = STANDARD.decode(value).expect("fixture value is Base64");
    octets[index] ^= 1;
    format!(
        "{head}<ds:SignatureValue>{}</ds:SignatureValue>{tail}",
        STANDARD.encode(octets)
    )
}

#[test]
fn published_gost34311_signature_verifies() {
    assert_eq!(status(GOST), DsigStatus::Valid);
}

#[test]
fn published_dstu7564_signature_verifies() {
    assert_eq!(status(KUPYNA), DsigStatus::Valid);
}

#[test]
fn every_reference_of_a_published_signature_is_digested_and_valid() {
    // A passing status alone could hide a Reference that was never processed.
    let resolver = DefaultKeyResolver::default();
    let result = VerifyContext::new()
        .policy(permissive())
        .key_resolver(&resolver)
        .verify(GOST)
        .expect("verification must run");
    assert_eq!(result.signed_info_references.len(), 2);
    for reference in &result.signed_info_references {
        assert_eq!(reference.digest_algorithm, DigestAlgorithm::Gost34311);
        assert_eq!(reference.status, DsigStatus::Valid);
    }
}

#[test]
fn an_altered_signature_of_either_component_is_invalid() {
    // Index 0 falls in r and 40 in s, which the verifier reads separately.
    for xml in [GOST, KUPYNA] {
        for index in [0, 40] {
            assert!(matches!(
                status(&with_flipped_signature_octet(xml, index)),
                DsigStatus::Invalid(_)
            ));
        }
    }
}

#[test]
fn altered_signed_content_fails_its_reference() {
    // The fixture signs its enveloping element, including the Signature's
    // absence, so a new attribute reaches the Reference digest.
    let tampered = KUPYNA.replacen("<ServiceStatusList>", "<ServiceStatusList a=\"1\">", 1);
    assert_ne!(tampered, KUPYNA);
    assert_eq!(
        status(&tampered),
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
    );
}

#[test]
fn the_digest_of_one_family_does_not_stand_for_the_other() {
    // Same width, different function: swapping the method must not verify.
    let swapped = KUPYNA.replace(
        "http://www.w3.org/2001/04/xmlenc#dstu7564-256",
        "http://www.w3.org/2001/04/xmlenc#gost34311",
    );
    assert!(matches!(status(&swapped), DsigStatus::Invalid(_)));
}

#[test]
fn identifiers_outside_the_published_set_are_unsupported() {
    // The variants without a published sample stay unknown, never a neighbour.
    for uri in [
        "http://www.w3.org/2001/04/xmlenc#dstu7564-384",
        "http://www.w3.org/2001/04/xmlenc#dstu7564-512",
        "http://www.w3.org/2001/04/xmlenc#GOST34311",
    ] {
        assert_eq!(DigestAlgorithm::from_uri(uri), None);
    }
    for uri in [
        "http://www.w3.org/2001/04/xmldsig-more#dstu4145-dstu7564-384",
        "http://www.w3.org/2001/04/xmldsig-more#dstu4145",
    ] {
        assert_eq!(SignatureAlgorithm::from_uri(uri), None);
    }
}

#[test]
fn the_identifiers_round_trip() {
    for algorithm in [DigestAlgorithm::Gost34311, DigestAlgorithm::Dstu7564_256] {
        assert_eq!(DigestAlgorithm::from_uri(algorithm.uri()), Some(algorithm));
    }
    for algorithm in [
        SignatureAlgorithm::Dstu4145Gost34311,
        SignatureAlgorithm::Dstu4145Dstu7564_256,
    ] {
        assert_eq!(
            SignatureAlgorithm::from_uri(algorithm.uri()),
            Some(algorithm)
        );
    }
}

#[test]
fn the_default_policy_refuses_the_methods_without_explicit_permission() {
    // Building the capability must not grant it.
    let resolver = DefaultKeyResolver::default();
    let mut policy = VerificationPolicy::default();
    policy.key_trust.mode = VerificationTrustMode::CryptographicOnly;
    let error = VerifyContext::new()
        .policy(policy)
        .key_resolver(&resolver)
        .verify(GOST)
        .expect_err("capability is not permission");
    assert!(matches!(error, DsigError::Policy(_)), "{error:?}");
}

#[test]
fn a_key_under_another_substitution_table_is_refused() {
    // The URI cannot name a table, so a key that states one other than number
    // one must not verify as if it had. The sample states the table explicitly.
    let (head, rest) = GOST
        .split_once("<ds:X509Certificate>")
        .expect("fixture has a certificate");
    let (encoded, tail) = rest
        .split_once("</ds:X509Certificate>")
        .expect("fixture closes its certificate");
    let mut certificate = STANDARD.decode(encoded).expect("fixture value is Base64");
    let table = certificate
        .windows(4)
        .position(|window| window == [0xa9, 0xd6, 0xeb, 0x45])
        .expect("the key states the table");
    certificate[table] ^= 1;
    let xml = format!(
        "{head}<ds:X509Certificate>{}</ds:X509Certificate>{tail}",
        STANDARD.encode(certificate)
    );
    let resolver = DefaultKeyResolver::default();
    let result = VerifyContext::new()
        .policy(permissive())
        .key_resolver(&resolver)
        .verify(&xml)
        .map(|result| result.status);
    assert_ne!(result.ok(), Some(DsigStatus::Valid));
}

#[test]
fn a_published_signature_chains_to_its_root() {
    // The leaf is under a 257-bit CA, which is under a 431-bit root that
    // writes its substitution table out: three keys, two curves.
    let (issuing, root) = published_chain();
    assert_eq!(
        chain_result(
            vec![issuing],
            vec![root],
            Some(CertificateSignatureAlgorithms::AllSupported)
        )
        .expect("the chain must validate"),
        DsigStatus::Valid
    );
}

#[test]
fn a_historical_signature_validates_only_at_its_own_time() {
    // The leaf expired in 2026: a verifier reasons about the moment it is given,
    // so the same chain that holds in 2024 must not hold a decade later.
    let (issuing, root) = published_chain();
    let at = |seconds| {
        chain_result_at(
            seconds,
            vec![issuing.clone()],
            vec![root.clone()],
            Some(CertificateSignatureAlgorithms::AllSupported),
        )
    };
    assert_eq!(at(MOMENT).expect("inside validity"), DsigStatus::Valid);
    at(2_000_000_000).expect_err("after every certificate expired");
}

#[test]
fn a_certificate_chain_needs_explicit_permission() {
    // No allowlist means classical algorithms only, as for post-quantum ones.
    let (issuing, root) = published_chain();
    let error = chain_result(vec![issuing], vec![root], None)
        .expect_err("capability is not permission for certificates either");
    assert!(error.to_string().contains("Dstu4145"), "{error}");
}

#[test]
fn a_forged_certificate_breaks_the_chain() {
    // The last octet belongs to the CA's signature, so its issuer must refuse it.
    let (mut issuing, root) = published_chain();
    *issuing.last_mut().expect("a certificate") ^= 1;
    chain_result(
        vec![issuing],
        vec![root],
        Some(CertificateSignatureAlgorithms::AllSupported),
    )
    .expect_err("a forged intermediate must not chain");
}

#[test]
fn a_chain_without_its_anchor_is_refused() {
    let (issuing, _) = published_chain();
    chain_result(
        vec![issuing],
        Vec::new(),
        Some(CertificateSignatureAlgorithms::AllSupported),
    )
    .expect_err("no anchor, no trust");
}

#[test]
fn the_methods_never_sign() {
    for algorithm in [
        SignatureAlgorithm::Dstu4145Gost34311,
        SignatureAlgorithm::Dstu4145Dstu7564_256,
    ] {
        assert!(!algorithm.signing_allowed());
    }
    assert!(!DigestAlgorithm::Gost34311.signing_allowed());
    assert!(!DigestAlgorithm::Dstu7564_256.signing_allowed());
}
