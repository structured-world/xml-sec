#![cfg(feature = "xmldsig-sign")]
//! Key material a verified Signature's `KeyInfo` offered, visited through the
//! verified session without a second parse and without a trust decision.

use std::{collections::HashMap, sync::Arc};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
use xml_sec::{
    XmlDocument,
    c14n::{C14nAlgorithm, C14nMode},
    policy::{VerificationPolicy, VerificationTrustMode},
    xmldsig::*,
};

const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const DS11: &str = "http://www.w3.org/2009/xmldsig11#";

fn account() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 22, 1 << 28)))
}

fn der(pem: &str) -> Vec<u8> {
    pem::parse(pem).unwrap().into_contents()
}

fn signing_certificate() -> Vec<u8> {
    der(include_str!("fixtures/keys/rsa/rsa-2048-cert.pem"))
}

fn other_public_key() -> Vec<u8> {
    der(include_str!("fixtures/keys/rsa/rsa-4096-pubkey.pem"))
}

/// An enveloped RSA signature over `<root/>` with `key_info` and `object`
/// inserted afterwards: the enveloped transform leaves both outside the
/// signed content, so the signature stays valid.
fn signed_with(key_info: &str, object: &str) -> XmlDocument {
    let signer =
        RsaSigningKey::from_pkcs8_pem(include_str!("fixtures/keys/rsa/rsa-2048-key.pem")).unwrap();
    let builder = SignatureBuilder::new(
        C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
        SignatureAlgorithm::RsaSha256,
    )
    .add_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("")
            .transform(Transform::Enveloped),
    );
    let mut xml = SignContext::new(&signer)
        .sign_with_builder("<root/>", &builder)
        .unwrap();
    // The second occurrence closes SignatureValue; its Base64 text holds no tag.
    let marker = "SignatureValue>";
    let open = xml.find(marker).unwrap() + marker.len();
    let close = open + xml[open..].find(marker).unwrap() + marker.len();
    xml.insert_str(close, &format!("{key_info}{object}"));
    XmlDocument::parse(xml).unwrap()
}

fn certificate_element(id: &str, der: &[u8]) -> String {
    format!(
        "<X509Certificate xmlns=\"{DS}\" Id=\"{id}\">{}</X509Certificate>",
        STANDARD.encode(der)
    )
}

fn cryptographic_only() -> VerificationPolicy {
    let mut policy = VerificationPolicy::default();
    policy.key_trust.mode = VerificationTrustMode::CryptographicOnly;
    policy
}

#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Certificate(KeyInfoOrigin, Vec<u8>),
    KeyValue(KeyInfoOrigin),
    SubjectPublicKeyInfo(KeyInfoOrigin, Vec<u8>),
    Unmaterialized(KeyInfoOrigin, String),
}

fn record(candidate: KeyInfoCandidate<'_>) -> Seen {
    match candidate.material {
        KeyInfoMaterial::Certificate(der) => Seen::Certificate(candidate.origin, der.to_vec()),
        KeyInfoMaterial::KeyValue(_) => Seen::KeyValue(candidate.origin),
        KeyInfoMaterial::SubjectPublicKeyInfo(der) => {
            Seen::SubjectPublicKeyInfo(candidate.origin, der.to_vec())
        }
        KeyInfoMaterial::Unmaterialized { uri, .. } => {
            Seen::Unmaterialized(candidate.origin, uri.to_owned())
        }
        _ => unreachable!("no other material in these fixtures"),
    }
}

/// Visit the only Signature's candidates with a fresh query account.
fn visit(
    document: &XmlDocument,
    context: &VerifyContext<'_>,
    request: &VerificationRequest<'_>,
) -> (KeyInfoReading, Vec<Seen>) {
    with_verified_request(document, context, request, &account(), |session| {
        let signature = session.evidence().signatures()[0].identity();
        let mut seen = Vec::new();
        let reading = session
            .visit_key_info_candidates_in(signature, &account(), |candidate| {
                seen.push(record(candidate));
                Ok::<_, ()>(())
            })
            .unwrap();
        Ok((reading, seen))
    })
    .unwrap()
}

fn id(document: &XmlDocument, value: &str) -> xml_sec::NodeIdentity {
    document.with_view(|view| view.node_for_id(value, &[]).unwrap())
}

#[test]
fn every_offered_material_is_visited_with_its_own_element() {
    // The certificate that verified, a later SPKI and a KeyValue are all
    // offered candidates; the KeyName offers no material and is not one.
    let key_info = format!(
        "<KeyInfo xmlns=\"{DS}\"><X509Data>{}</X509Data><KeyName>lookup</KeyName>\
         <dsig11:DEREncodedKeyValue xmlns:dsig11=\"{DS11}\" Id=\"spki\">{}</dsig11:DEREncodedKeyValue>\
         <KeyValue Id=\"value\"><RSAKeyValue><Modulus>AQAB</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue>\
         </KeyInfo>",
        certificate_element("leaf", &signing_certificate()),
        STANDARD.encode(other_public_key()),
    );
    let document = signed_with(&key_info, "");
    let resolver = DefaultKeyResolver::default();
    let context = VerifyContext::new()
        .policy(cryptographic_only())
        .key_resolver(&resolver);
    let (reading, seen) = visit(&document, &context, &VerificationRequest::default());
    assert_eq!(reading, KeyInfoReading::Read);
    assert_eq!(
        seen,
        [
            Seen::Certificate(
                KeyInfoOrigin::Element(id(&document, "leaf")),
                signing_certificate()
            ),
            Seen::SubjectPublicKeyInfo(
                KeyInfoOrigin::Element(id(&document, "spki")),
                other_public_key()
            ),
            Seen::KeyValue(KeyInfoOrigin::Element(id(&document, "value"))),
        ]
    );
}

#[test]
fn a_caller_key_leaves_key_info_unread_not_empty() {
    // An explicit key never consults KeyInfo: that is a distinct outcome,
    // not a KeyInfo that offered nothing.
    let key_info = format!(
        "<KeyInfo xmlns=\"{DS}\"><X509Data>{}</X509Data></KeyInfo>",
        certificate_element("leaf", &signing_certificate()),
    );
    let document = signed_with(&key_info, "");
    let key = VerificationKey {
        algorithm: SignatureAlgorithm::RsaSha256,
        public_key_bytes: der(include_str!("fixtures/keys/rsa/rsa-2048-pubkey.pem")),
        certificate_der: None,
        name: None,
    };
    let context = VerifyContext::new().key(&key);
    let (reading, seen) = visit(&document, &context, &VerificationRequest::default());
    assert_eq!(reading, KeyInfoReading::NotRead);
    assert_eq!(seen, []);

    let document = signed_with("", "");
    let (reading, seen) = visit(&document, &context, &VerificationRequest::default());
    assert_eq!(reading, KeyInfoReading::Absent);
    assert_eq!(seen, []);
}

#[test]
fn referenced_and_retrieved_same_document_material_keeps_its_element() {
    // A same-document KeyInfoReference and an X509Data RetrievalMethod read
    // elements of this document: each certificate names its own element.
    let key_info = format!(
        "<KeyInfo xmlns=\"{DS}\">\
         <dsig11:KeyInfoReference xmlns:dsig11=\"{DS11}\" URI=\"#referenced\"/>\
         <RetrievalMethod URI=\"#retrieved\" Type=\"http://www.w3.org/2000/09/xmldsig#X509Data\"/>\
         </KeyInfo>"
    );
    let object = format!(
        "<Object xmlns=\"{DS}\"><KeyInfo Id=\"referenced\"><X509Data>{}</X509Data></KeyInfo>\
         <X509Data Id=\"retrieved\">{}</X509Data></Object>",
        certificate_element("by-reference", &signing_certificate()),
        certificate_element("by-retrieval", &signing_certificate()),
    );
    let document = signed_with(&key_info, &object);
    let resolver = DefaultKeyResolver::default();
    let context = VerifyContext::new()
        .policy(cryptographic_only())
        .key_resolver(&resolver);
    let (reading, seen) = visit(&document, &context, &VerificationRequest::default());
    assert_eq!(reading, KeyInfoReading::Read);
    assert_eq!(
        seen,
        [
            Seen::Certificate(
                KeyInfoOrigin::Element(id(&document, "by-reference")),
                signing_certificate()
            ),
            Seen::Certificate(
                KeyInfoOrigin::Element(id(&document, "by-retrieval")),
                signing_certificate()
            ),
        ]
    );
}

#[test]
fn external_material_is_attributed_to_its_retrieving_instruction() {
    // Bytes from a caller-supplied resource have no element in this document;
    // the instruction that read them is named instead. A raw certificate the
    // caller did not supply stays an unmaterialized candidate.
    let key_info = format!(
        "<KeyInfo xmlns=\"{DS}\">\
         <RetrievalMethod Id=\"missing\" URI=\"https://example.test/missing.der\" \
           Type=\"http://www.w3.org/2000/09/xmldsig#rawX509Certificate\"/>\
         <RetrievalMethod Id=\"raw\" URI=\"https://example.test/leaf.der\" \
           Type=\"http://www.w3.org/2000/09/xmldsig#rawX509Certificate\"/>\
         <dsig11:KeyInfoReference xmlns:dsig11=\"{DS11}\" Id=\"external\" \
           URI=\"https://example.test/keyinfo.xml\"/>\
         </KeyInfo>"
    );
    let document = signed_with(&key_info, "");
    let external_key_info = format!(
        "<KeyInfo xmlns=\"{DS}\"><X509Data>{}</X509Data></KeyInfo>",
        certificate_element("elsewhere", &signing_certificate()),
    );
    let resources = HashMap::from([
        (
            "https://example.test/leaf.der".to_owned(),
            signing_certificate(),
        ),
        (
            "https://example.test/keyinfo.xml".to_owned(),
            external_key_info.into_bytes(),
        ),
    ]);
    let mut policy = cryptographic_only();
    policy.uris.retrieval_methods = UriTypeSet::ALL;
    policy.uris.key_info_references = UriTypeSet::ALL;
    let resolver = DefaultKeyResolver::default();
    let context = VerifyContext::new().policy(policy).key_resolver(&resolver);
    let request = VerificationRequest {
        external_resources: Some(&resources),
        ..VerificationRequest::default()
    };
    let (reading, seen) = visit(&document, &context, &request);
    assert_eq!(reading, KeyInfoReading::Read);
    assert_eq!(
        seen,
        [
            Seen::Unmaterialized(
                KeyInfoOrigin::Element(id(&document, "missing")),
                "https://example.test/missing.der".to_owned()
            ),
            Seen::Certificate(
                KeyInfoOrigin::Retrieved(id(&document, "raw")),
                signing_certificate()
            ),
            Seen::Certificate(
                KeyInfoOrigin::Retrieved(id(&document, "external")),
                signing_certificate()
            ),
        ]
    );
}

#[test]
fn unauthenticated_signatures_offer_no_candidates() {
    // A Signature that failed verification is not selectable: its KeyInfo
    // claims stay unanswered rather than looking like offered keys.
    let key_info = format!(
        "<KeyInfo xmlns=\"{DS}\"><X509Data>{}</X509Data></KeyInfo>",
        certificate_element("leaf", &signing_certificate()),
    );
    let document = signed_with(&key_info, "");
    let key = VerificationKey {
        algorithm: SignatureAlgorithm::RsaSha256,
        public_key_bytes: other_public_key(),
        certificate_der: None,
        name: None,
    };
    let context = VerifyContext::new().key(&key);
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &account(),
        |session| {
            let signature = session.evidence().signatures()[0].identity();
            let result =
                session.visit_key_info_candidates_in(signature, &account(), |_| Ok::<_, ()>(()));
            assert!(matches!(
                result,
                Err(CatalogueError::Processing(DsigError::InvalidRequest {
                    reason: "selected Signature is not authenticated"
                }))
            ));
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn query_work_and_visitor_errors_stay_distinct() {
    // Exhausted query work refuses before any candidate; a visitor error stops
    // the walk at once and returns unchanged.
    let key_info = format!(
        "<KeyInfo xmlns=\"{DS}\"><X509Data>{}</X509Data></KeyInfo>",
        certificate_element("leaf", &signing_certificate()),
    );
    let document = signed_with(&key_info, "");
    let resolver = DefaultKeyResolver::default();
    let context = VerifyContext::new()
        .policy(cryptographic_only())
        .key_resolver(&resolver);
    with_verified_request(
        &document,
        &context,
        &VerificationRequest::default(),
        &account(),
        |session| {
            let signature = session.evidence().signatures()[0].identity();
            let exhausted = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 0)));
            let mut visits = 0;
            let result = session.visit_key_info_candidates_in(signature, &exhausted, |_| {
                visits += 1;
                Ok::<_, ()>(())
            });
            assert!(matches!(
                result,
                Err(CatalogueError::Processing(DsigError::SharedExecution(
                    MemoryError::WorkExceeded
                )))
            ));
            assert_eq!(visits, 0);

            let result = session
                .select_signature(signature)?
                .visit_key_info_candidates(|_| Err("stop"));
            assert!(matches!(result, Err(CatalogueError::Visitor("stop"))));
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn retained_material_is_charged_until_the_session_ends() {
    // Retention moves the parsed DER and reserves its capacity on the
    // session's account: nothing is copied, nothing outlives the session.
    let key_info = format!(
        "<KeyInfo xmlns=\"{DS}\"><X509Data>{}</X509Data></KeyInfo>",
        certificate_element("leaf", &signing_certificate()),
    );
    let document = signed_with(&key_info, "");
    let held = |context: &VerifyContext<'_>| {
        let work = account();
        let held = with_verified_request(
            &document,
            context,
            &VerificationRequest::default(),
            &work,
            |_| Ok(work.used()),
        )
        .unwrap();
        assert_eq!(work.used(), 0, "retention ends with the session");
        held
    };
    let resolver = DefaultKeyResolver::default();
    let read = held(
        &VerifyContext::new()
            .policy(cryptographic_only())
            .key_resolver(&resolver),
    );
    // The same Signature verified by a caller key retains no KeyInfo.
    let key = VerificationKey {
        algorithm: SignatureAlgorithm::RsaSha256,
        public_key_bytes: der(include_str!("fixtures/keys/rsa/rsa-2048-pubkey.pem")),
        certificate_der: None,
        name: None,
    };
    let unread = held(&VerifyContext::new().key(&key));
    assert!(read - unread >= signing_certificate().len());
}
