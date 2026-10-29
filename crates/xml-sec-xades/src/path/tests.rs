use super::signers;
use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use xml_sec::XmlDocument;
use xml_sec::policy::{Instant, VerificationPolicy};
use xml_sec::xmldsig::{
    DefaultKeyResolver, KeyResolverConfig, VerificationRequest, VerifyContext,
    with_verified_request,
};

/// Signer identities chosen for the first Signature of `xml`, given which
/// Signatures (by request position) are its incorporated countersignatures.
fn chosen(xml: &str, counters: &[usize]) -> Vec<usize> {
    let resolver = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: vec![include_bytes!("../../tests/fixtures/root.der").to_vec()],
        ..KeyResolverConfig::default()
    });
    let mut policy = VerificationPolicy::default();
    policy.key_trust.verify_x509_chains = true;
    // 2027-01-15 UTC, inside the fixture certificates' validity.
    policy.key_trust.verification_time = Instant::new(500_000 * 3600, 0);
    let context = VerifyContext::new().policy(policy).key_resolver(&resolver);
    let document = XmlDocument::parse(xml).unwrap();
    let work = Memory::new(Arc::new(MemoryAccount::new(1 << 24, 1 << 30)));
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &work,
        |session| {
            let all: Vec<_> = session
                .evidence()
                .signatures()
                .iter()
                .map(xml_sec::xmldsig::SignatureEvidence::identity)
                .collect();
            let counters: Vec<_> = counters.iter().map(|index| all[*index]).collect();
            let found = signers(&session, all[0], &counters, &work).unwrap();
            Ok(found
                .iter()
                .map(|(identity, _)| all.iter().position(|each| each == identity).unwrap())
                .collect())
        },
    )
    .unwrap()
}

#[test]
fn only_the_root_and_its_countersignatures_need_paths() {
    // A Signature nested in the root's signed Object is not an actor of the
    // root, although it lies in the root's subtree and has a validated path:
    // its certificates must not be decoded, hashed or re-checked for this root.
    assert_eq!(
        chosen(include_str!("../../tests/fixtures/nested.xml"), &[]),
        [0]
    );
    // An incorporated countersignature is one, with its own path.
    assert_eq!(
        chosen(include_str!("../../tests/fixtures/countersigned.xml"), &[1]),
        [0, 1]
    );
}
