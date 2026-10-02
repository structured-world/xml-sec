//! Public verification must distinguish discovery, authorization and mathematics.

#![cfg(feature = "xmldsig")]

use std::sync::atomic::{AtomicUsize, Ordering};

use base64::{Engine, engine::general_purpose::STANDARD};
use xml_sec::policy::{PolicyViolation, VerificationPolicy, VerificationTrustMode};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DsigError, DsigStatus, KeyInfo, KeyResolver, KeyResolverConfig,
    KeyTrustEvidence, SignatureAlgorithm, VerifyContext, VerifyingKey,
};

const SIGNED: &str = include_str!("fixtures/saml/response_signed_by_idp_ecdsa.xml");

struct CandidateResolver(AtomicUsize);
struct ObservedKey<'a>(&'a AtomicUsize);

impl VerifyingKey for ObservedKey<'_> {
    fn verify(&self, _: SignatureAlgorithm, _: &[u8], _: &[u8]) -> Result<bool, DsigError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(true)
    }
}

impl KeyResolver for CandidateResolver {
    fn resolve<'a>(
        &'a self,
        _: Option<&KeyInfo>,
        _: SignatureAlgorithm,
    ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, DsigError> {
        Ok(Some(Box::new(ObservedKey(&self.0))))
    }
}

#[test]
fn authorization_gates_actual_signature_work() {
    // Discovery through the old hook cannot silently become a trust declaration.
    let resolver = CandidateResolver(AtomicUsize::new(0));
    let error = VerifyContext::new()
        .key_resolver(&resolver)
        .verify(SIGNED)
        .expect_err("untrusted discovery must fail before signature dispatch");
    assert!(matches!(
        error,
        DsigError::Policy(PolicyViolation::KeyTrust { .. })
    ));
    assert_eq!(resolver.0.load(Ordering::Relaxed), 0);

    // Only an explicit immutable-policy choice permits this candidate to execute.
    let mut policy = VerificationPolicy::default();
    policy.key_trust.mode = VerificationTrustMode::CryptographicOnly;
    let result = VerifyContext::new()
        .policy(policy)
        .key_resolver(&resolver)
        .verify(SIGNED)
        .expect("explicit mathematical mode must reach the verifier");
    assert_eq!(resolver.0.load(Ordering::Relaxed), 1);
    assert_eq!(result.status, DsigStatus::Valid);
    assert_eq!(result.key_trust, KeyTrustEvidence::NotEstablished);
}

#[test]
fn real_embedded_signature_needs_explicit_trust_each_operation() {
    // The real fixture signature verifies mathematically but its signer is not
    // authorized by simply having embedded its own certificate.
    let resolver = DefaultKeyResolver::default();
    assert!(matches!(
        VerifyContext::new().key_resolver(&resolver).verify(SIGNED),
        Err(DsigError::Policy(PolicyViolation::KeyTrust { .. }))
    ));
    let mut mathematical = VerificationPolicy::default();
    mathematical.key_trust.mode = VerificationTrustMode::CryptographicOnly;
    let result = VerifyContext::new()
        .policy(mathematical)
        .key_resolver(&resolver)
        .verify(SIGNED)
        .expect("real embedded signature must verify mathematically");
    assert_eq!(result.status, DsigStatus::Valid);
    assert_eq!(result.key_trust, KeyTrustEvidence::NotEstablished);

    let document = roxmltree::Document::parse(SIGNED).expect("fixture XML must parse");
    let text = document
        .descendants()
        .find(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "X509Certificate")))
        .and_then(|node| node.text())
        .expect("fixture must contain its certificate");
    let certificate = STANDARD
        .decode(text.split_whitespace().collect::<String>())
        .expect("fixture certificate must decode");
    let pinned = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: vec![certificate],
        ..KeyResolverConfig::default()
    });
    let result = VerifyContext::new()
        .key_resolver(&pinned)
        .verify(SIGNED)
        .expect("an exact caller pin authorizes the real signature key");
    assert_eq!(result.status, DsigStatus::Valid);
    assert_eq!(result.key_trust, KeyTrustEvidence::CallerTrusted);

    // Removing the pin in the next operation must not retain cached authorization.
    assert!(matches!(
        VerifyContext::new().key_resolver(&resolver).verify(SIGNED),
        Err(DsigError::Policy(PolicyViolation::KeyTrust { .. }))
    ));
}
