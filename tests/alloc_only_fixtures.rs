//! Reproduces the pre-signed documents that `alloc_only_verification` checks
//! without signing. HMAC signatures are deterministic, so each committed file
//! must equal what the signer produces now; set `XML_SEC_WRITE_FIXTURES=1` to
//! rewrite them after an intentional signing change.

#![cfg(feature = "xmldsig-sign")]

use std::collections::BTreeMap;
use std::path::Path;

use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::policy::SigningPolicy;
use xml_sec::xmldsig::{
    DigestAlgorithm, HmacSigningKey, ReferenceBuilder, SignContext, SignatureAlgorithm,
    SignatureBuilder, Transform, UriTypeSet,
};

const DIR: &str = "tests/fixtures/xmldsig/alloc-only";

fn reference(uri: &str) -> SignatureBuilder {
    SignatureBuilder::new(
        C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
        SignatureAlgorithm::HmacSha256,
    )
    .add_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri(uri)
            .transform(Transform::C14n(C14nAlgorithm::new(
                C14nMode::Exclusive1_0,
                false,
            ))),
    )
}

fn check(name: &str, xml: &str) {
    let path = Path::new(DIR).join(name);
    if std::env::var_os("XML_SEC_WRITE_FIXTURES").is_some() {
        std::fs::create_dir_all(DIR).unwrap();
        std::fs::write(&path, xml).unwrap();
    }
    let committed = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    assert_eq!(
        committed, xml,
        "{name} differs from its deterministic signing"
    );
}

#[test]
fn two_signatures_over_distinct_ids() {
    // Two independently keyed HMAC signatures, one per ID'd payload.
    let first = HmacSigningKey::new(vec![0x31; 32]).unwrap();
    let second = HmacSigningKey::new(vec![0x72; 32]).unwrap();
    let xml = SignContext::new(&first)
        .sign_with_builder(
            "<root><payload ID=\"first\">one</payload><payload ID=\"second\">two</payload></root>",
            &reference("#first"),
        )
        .unwrap();
    let xml = SignContext::new(&second)
        .sign_with_builder(&xml, &reference("#second"))
        .unwrap();
    check("two-signatures.xml", &xml);
}

#[test]
fn detached_payload_signature() {
    // A same-document reference plus one reference to caller-supplied bytes.
    let key = HmacSigningKey::new(vec![0x5d; 32]).unwrap();
    let mut policy = SigningPolicy::default();
    policy.uris.references = UriTypeSet::ALL;
    let resources = BTreeMap::from([(
        "https://example.test/payload".to_owned(),
        b"detached payload".to_vec(),
    )]);
    let builder = reference("#local").add_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha256).uri("https://example.test/payload"),
    );
    let xml = SignContext::new(&key)
        .policy(policy)
        .external_resources(&resources)
        .sign_with_builder(
            "<root><payload ID=\"local\">here</payload></root>",
            &builder,
        )
        .unwrap();
    check("detached.xml", &xml);
}
