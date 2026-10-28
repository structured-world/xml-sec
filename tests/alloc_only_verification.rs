//! Target-coverage guarantees of verification, checked without signing so the
//! same tests also run against the build without `std`. Documents come from
//! `alloc_only_fixtures`, which reproduces them with the signer.

#![cfg(feature = "xmldsig")]

use std::collections::BTreeMap;

use xml_sec::XmlDocument;
use xml_sec::xmldsig::{
    CallerTrustedSignatureKey, HmacVerificationKey, SignatureRequirement, UriTypeSet,
    VerificationRequest, VerifyContext,
};

const TWO_SIGNATURES: &str = include_str!("fixtures/xmldsig/alloc-only/two-signatures.xml");
const DETACHED: &str = include_str!("fixtures/xmldsig/alloc-only/detached.xml");
const DETACHED_URI: &str = "https://example.test/payload";

fn first_key() -> HmacVerificationKey {
    HmacVerificationKey::new(vec![0x31; 32]).unwrap()
}

fn second_key() -> HmacVerificationKey {
    HmacVerificationKey::new(vec![0x72; 32]).unwrap()
}

/// Verifies with `key` and requires exactly `targets` to be authenticated.
fn accepted(document: &XmlDocument, key: &HmacVerificationKey, ids: &[&str]) -> bool {
    let targets = document.with_view(|view| {
        ids.iter()
            .map(|id| view.node_for_id(id, &[]).unwrap())
            .collect::<Vec<_>>()
    });
    VerifyContext::new()
        .key(key)
        .verify_request(
            document,
            &VerificationRequest {
                expected_targets: &targets,
                signatures: SignatureRequirement::AtLeast(1),
                ..VerificationRequest::default()
            },
        )
        .unwrap()
        .accepted(document)
        .unwrap()
}

#[test]
fn coverage_is_exactly_the_referenced_element() {
    // Each signature authenticates its own ID'd element and nothing else.
    let document = XmlDocument::parse(TWO_SIGNATURES).unwrap();
    let signatures = VerifyContext::new()
        .signature_identities(&document)
        .unwrap();
    let (first, second) = (first_key(), second_key());
    let keys = [
        CallerTrustedSignatureKey {
            signature: signatures[0],
            key: &first,
        },
        CallerTrustedSignatureKey {
            signature: signatures[1],
            key: &second,
        },
    ];
    let (root, targets) = document.with_view(|view| {
        (
            view.root_element(),
            [
                view.node_for_id("first", &[]).unwrap(),
                view.node_for_id("second", &[]).unwrap(),
            ],
        )
    });
    let evidence = VerifyContext::new()
        .verify_request(
            &document,
            &VerificationRequest {
                expected_targets: &targets,
                trusted_keys: &keys,
                signatures: SignatureRequirement::Exactly(2),
                ..VerificationRequest::default()
            },
        )
        .unwrap();
    assert!(evidence.all_valid());
    assert!(evidence.accepted(&document).unwrap());
    for target in targets {
        assert!(evidence.covers_element(&document, target).unwrap());
    }
    assert!(!evidence.covers_element(&document, root).unwrap());
    // One key authenticates only its own signature's element.
    assert!(accepted(&document, &first, &["first"]));
    assert!(!accepted(&document, &first, &["first", "second"]));
}

#[test]
fn wrapped_original_cannot_authenticate_a_decoy() {
    // XMLDSig 1.1 §8.1.1: moving the signed element under a wrapper keeps
    // the signature valid but must not authenticate a lookalike target.
    // https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-Secure
    let wrapped = TWO_SIGNATURES.replace(
        "<payload ID=\"first\">one</payload>",
        "<hidden><payload ID=\"first\">one</payload></hidden><payload ID=\"decoy\">one</payload>",
    );
    assert_ne!(wrapped, TWO_SIGNATURES);
    let document = XmlDocument::parse(wrapped).unwrap();
    assert!(accepted(&document, &first_key(), &["first"]));
    assert!(!accepted(&document, &first_key(), &["decoy"]));
}

#[test]
fn duplicate_ids_never_resolve_to_an_authenticated_target() {
    // Duplicating the referenced ID makes the reference ambiguous; neither
    // element may be reported as covered.
    let duplicated = TWO_SIGNATURES.replace("ID=\"second\"", "ID=\"first\"");
    assert_ne!(duplicated, TWO_SIGNATURES);
    if let Ok(document) = XmlDocument::parse(duplicated) {
        let evidence = VerifyContext::new()
            .key(&first_key())
            .verify_all(&document)
            .unwrap();
        assert!(!evidence.all_valid());
        assert!(!evidence.accepted(&document).unwrap());
    }
}

#[test]
fn signature_lookalikes_in_other_namespaces_are_not_signatures() {
    // A Signature element outside the XMLDSig namespace is application data:
    // it neither counts as a signature nor authenticates its target.
    let foreign = TWO_SIGNATURES.replacen(
        "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/><Reference URI=\"#second\">",
        "<Signature xmlns=\"urn:example:not-xmldsig\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/><Reference URI=\"#second\">",
        1,
    );
    assert_ne!(foreign, TWO_SIGNATURES);
    let document = XmlDocument::parse(foreign).unwrap();
    assert_eq!(
        VerifyContext::new()
            .signature_identities(&document)
            .unwrap()
            .len(),
        1
    );
    assert!(!accepted(&document, &second_key(), &["second"]));

    // A SignedInfo rebound to another namespace inside a real Signature is
    // not the signed information the signature value covers.
    let rebound = TWO_SIGNATURES.replacen(
        "<SignedInfo>",
        "<SignedInfo xmlns=\"urn:example:not-xmldsig\">",
        1,
    );
    let document = XmlDocument::parse(rebound).unwrap();
    assert!(!accepted(&document, &first_key(), &["first"]));
}

#[test]
fn absent_detached_payload_keeps_the_signature_unaccepted() {
    // Detached bytes come only from the caller; without them the external
    // reference is unverified and the signature authenticates nothing.
    let document = XmlDocument::parse(DETACHED).unwrap();
    let key = HmacVerificationKey::new(vec![0x5d; 32]).unwrap();
    let targets = document.with_view(|view| [view.node_for_id("local", &[]).unwrap()]);
    let context = VerifyContext::new()
        .key(&key)
        .allowed_uri_types(UriTypeSet::ALL);
    let request = VerificationRequest {
        expected_targets: &targets,
        ..VerificationRequest::default()
    };
    let without = context.verify_request(&document, &request).unwrap();
    assert!(!without.all_valid());
    assert!(!without.accepted(&document).unwrap());

    let resources = BTreeMap::from([(DETACHED_URI.to_owned(), b"detached payload".to_vec())]);
    let with = context
        .verify_request(
            &document,
            &VerificationRequest {
                external_resources: Some(&resources),
                ..request
            },
        )
        .unwrap();
    assert!(with.all_valid());
    assert!(with.accepted(&document).unwrap());
}
