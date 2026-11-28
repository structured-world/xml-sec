//! `Manifest`s built with [`ManifestBuilder`], signed and verified through the
//! public signing and verification operations.

use std::fs;

use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::policy::{ManifestProcessing, SigningPolicy};
use xml_sec::xmldsig::{
    DigestAlgorithm, DsigStatus, ManifestBuilder, ObjectBuilder, ObjectContent, ReferenceBuilder,
    RsaSigningKey, SignContext, SignatureAlgorithm, SignatureBuilder, SignatureBuilderError,
    SigningKey, SigningPublicKeyInfo, Transform, VerificationKey, VerifyContext, XPathExpression,
    XPathFilter, XPathFilterOperation,
};

const DOCUMENT: &str = "<root><payload Id=\"payload\">signed <part>kept</part></payload></root>";
const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const MANIFEST_TYPE: &str = "http://www.w3.org/2000/09/xmldsig#Manifest";

fn exclusive() -> C14nAlgorithm {
    C14nAlgorithm::new(C14nMode::Exclusive1_0, false)
}

fn key() -> RsaSigningKey {
    let pem = fs::read_to_string("tests/fixtures/keys/rsa/rsa-2048-key.pem")
        .expect("RSA private-key fixture must load");
    RsaSigningKey::from_pkcs8_pem(&pem).expect("RSA private key must parse")
}

fn spki(key: &RsaSigningKey) -> Vec<u8> {
    let SigningPublicKeyInfo::Rsa { spki_der, .. } =
        key.public_key_info().expect("public key info")
    else {
        panic!("RSA key must expose RSA public-key info");
    };
    spki_der
}

fn processing() -> SigningPolicy {
    SigningPolicy {
        manifest_processing: ManifestProcessing::Process,
        ..SigningPolicy::default()
    }
}

/// A Manifest whose entries carry transforms of their own: the enveloping
/// document without the signature, and a Filter 2.0 selection of one part.
fn manifest(policy: &SigningPolicy) -> Result<ObjectContent, SignatureBuilderError> {
    let element = ManifestBuilder::new("manifest")
        .ns_prefix("ds")
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("")
                .transform(Transform::Enveloped)
                .transform(Transform::C14n(exclusive())),
        )
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha512)
                .uri("#payload")
                .id("manifest-part")
                .transform(Transform::XPathFilter2(vec![XPathFilter::new(
                    XPathFilterOperation::Intersect,
                    XPathExpression::new("//part"),
                )])),
        )
        .build_with_policy(policy)?;
    Ok(ObjectContent::Element(element))
}

#[test]
fn a_built_manifest_is_filled_by_signing_and_checked_by_verification() {
    // XMLDSig 1.1 §5.1: each Manifest Reference is digested with its own
    // transforms and digest method; signing fills both values before it
    // digests the Manifest, and verification processing Manifests finds
    // every entry intact.
    let policy = processing();
    let builder = SignatureBuilder::new(exclusive(), SignatureAlgorithm::RsaSha256)
        .ns_prefix("ds")
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri("#manifest")
                .ref_type(MANIFEST_TYPE)
                .transform(Transform::C14n(C14nAlgorithm::new(
                    C14nMode::Inclusive1_1,
                    false,
                ))),
        )
        .add_object(ObjectBuilder::new(
            manifest(&policy).expect("the Manifest builds"),
        ));
    let key = key();
    let signed = SignContext::new(&key)
        .policy(policy)
        .sign_with_builder(DOCUMENT, &builder)
        .expect("the Manifest signs")
        .output;
    assert!(signed.contains(&format!("<ds:Manifest xmlns:ds=\"{DS}\" Id=\"manifest\">")));
    let verified = VerifyContext::new()
        .key(&VerificationKey {
            algorithm: SignatureAlgorithm::RsaSha256,
            public_key_bytes: spki(&key),
            certificate_der: None,
            name: None,
        })
        .process_manifests(true)
        .verify(&signed)
        .expect("the signature verifies");
    assert_eq!(verified.status, DsigStatus::Valid);
    assert_eq!(verified.manifest_references.len(), 2);
    for reference in &verified.manifest_references {
        assert!(
            matches!(reference.status, DsigStatus::Valid),
            "{reference:?}"
        );
    }
}

#[test]
fn a_manifest_needs_an_id_and_a_reference() {
    // XMLDSig 1.1 §5.1: a Manifest has one or more References, and a
    // reference names it through its xs:ID.
    let policy = processing();
    assert!(matches!(
        ManifestBuilder::new("manifest").build_with_policy(&policy),
        Err(SignatureBuilderError::MissingReference)
    ));
    assert!(matches!(
        ManifestBuilder::new("not an id")
            .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256).uri("#payload"))
            .build_with_policy(&policy),
        Err(SignatureBuilderError::InvalidId {
            element: "Manifest",
            ..
        })
    ));
}

#[test]
fn a_manifest_declares_each_id_once() {
    // XMLDSig 1.1 types Manifest/@Id and Reference/@Id as xs:ID, unique in
    // the document: two references with one Id, or one sharing the
    // Manifest's own, are refused; references without an Id stay valid.
    let policy = processing();
    let reference = |id: Option<&str>| {
        let built = ReferenceBuilder::new(DigestAlgorithm::Sha256).uri("#payload");
        match id {
            Some(id) => built.id(id),
            None => built,
        }
    };
    for (first, second) in [(Some("entry"), Some("entry")), (Some("manifest"), None)] {
        let result = ManifestBuilder::new("manifest")
            .add_reference(reference(first))
            .add_reference(reference(second))
            .build_with_policy(&policy);
        assert!(
            matches!(
                result,
                Err(SignatureBuilderError::InvalidId {
                    element: "Reference",
                    ..
                })
            ),
            "{first:?} {second:?}: {result:?}"
        );
    }
    ManifestBuilder::new("manifest")
        .add_reference(reference(None))
        .add_reference(reference(None))
        .build_with_policy(&policy)
        .expect("references without an Id");
}

#[test]
fn a_manifest_reference_meets_the_signing_policy() {
    // The same policy that admits a SignedInfo reference admits a Manifest
    // one: an external URI the policy refuses is refused when building.
    let policy = processing();
    assert!(matches!(
        ManifestBuilder::new("manifest")
            .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256).uri("data.txt"))
            .build_with_policy(&policy),
        Err(SignatureBuilderError::Policy(_))
    ));
}
