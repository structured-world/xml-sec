//! CMS `SignedData` with DSTU 4145: the RFC 3161 tokens embedded in the XAdES-LTA
//! sample published by the Central Certification Authority of Ukraine.
#![cfg(all(feature = "dstu4145", feature = "cms"))]

use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::collections::BTreeSet;
use std::sync::Arc;
use structured_asn1::Parser;
use structured_asn1::memory::{Memory, MemoryAccount, Work};
use structured_cms::binding::Scope;
use structured_cms::prepare::{self, Preparation};
use structured_cms::provider::SignatureAnswer;
use structured_cms::signed::SignedData;
use structured_cms::timestamp::{CheckContext, Token, TokenSignature};
use structured_cms::verify::{self, ContentAgreement};
use structured_pkix::path::WorkingKey;
use structured_pkix::temporal::{Instant, LeapTable};
use xml_sec::policy::{CertificateSignatureAlgorithms, VerificationPolicy};
use xml_sec::provider::RustCryptoProvider;
use xml_sec::xmldsig::DigestAlgorithm;
use xml_sec::xmldsig::cms::CmsProvider;

const LTA: &str = include_str!("fixtures/xmldsig/dstu4145/dstu-detached-lta.xml");
const GOST_CADES: &[u8] = include_bytes!("fixtures/xmldsig/dstu4145/gost-detached-bes.p7s");
const KUPYNA_CADES: &[u8] = include_bytes!("fixtures/xmldsig/dstu4145/kupyna-detached-bes.p7s");
const CONTENT: &[u8] = include_bytes!("fixtures/xmldsig/dstu4145/cades-content.bin");

fn tokens() -> Vec<Vec<u8>> {
    LTA.split("<xades:EncapsulatedTimeStamp")
        .skip(1)
        .map(|part| {
            let (_, value) = part.split_once('>').expect("fixture opens its token");
            let (encoded, _) = value
                .split_once("</xades:EncapsulatedTimeStamp>")
                .expect("fixture closes its token");
            STANDARD.decode(encoded).expect("fixture value is Base64")
        })
        .collect()
}

/// The answer for `token` under the certificate it carries.
fn answer(
    token: &[u8],
    allowed: Option<CertificateSignatureAlgorithms>,
) -> Option<SignatureAnswer> {
    let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 22, 1 << 26)));
    let parser = Parser::ber(memory);
    let token = Token::read(&parser, token, 0).expect("the token must parse");
    let parent = parser.read(&[], 0).expect("an empty parent");
    let certificate = token
        .message()
        .certificates()
        .first()
        .expect("the token carries its authority");
    let utc = LeapTable::new(0, 2_000_000_000, &[]).expect("UTC facts");
    let mut policy = VerificationPolicy {
        digest_algorithms: Some(BTreeSet::from([DigestAlgorithm::Gost34311])),
        ..VerificationPolicy::default()
    };
    policy.key_trust.certificate_signature_algorithms = allowed;
    let provider = RustCryptoProvider;
    let cms = CmsProvider::new(&provider, &policy);
    let context = CheckContext {
        certificate,
        certificate_parent: &parent,
        key: WorkingKey::standing(certificate.tbs().public_key()),
        requested: None,
        utc: &utc,
        reference: Some(Instant::new(1_717_200_000, 0).expect("instant")),
        window: None,
        policy_accuracy: None,
    };
    let covered: &[u8] = b"content other than the signature";
    let checked = token
        .check(&cms, &parent, &context, &mut [covered], |_, _| {
            Ok::<_, ()>(false)
        })
        .ok()?;
    match &checked.signature {
        TokenSignature::Checked(checked) => checked.signature(),
        TokenSignature::Unsupported(_) | TokenSignature::Malformed(_) => None,
    }
}

/// What a detached `SignedData` check answers.
#[derive(Debug, PartialEq, Eq)]
enum Detached {
    /// Whether the content matched, and the answer for the signed attributes.
    Checked(bool, Option<SignatureAnswer>),
    /// The signer's declarations contradict each other.
    Malformed,
}

/// Check the published detached `sample` over `content`, under the certificate
/// it carries and with both Ukrainian digests permitted.
fn detached(sample: &[u8], content: &[u8]) -> Detached {
    let mut policy = VerificationPolicy {
        digest_algorithms: Some(BTreeSet::from([
            DigestAlgorithm::Gost34311,
            DigestAlgorithm::Dstu7564_256,
        ])),
        ..VerificationPolicy::default()
    };
    policy.key_trust.certificate_signature_algorithms =
        Some(CertificateSignatureAlgorithms::AllSupported);
    let provider = RustCryptoProvider;
    let cms = CmsProvider::new(&provider, &policy);
    let parser = Parser::ber(Memory::new(Arc::new(MemoryAccount::new(1 << 22, 1 << 26))));
    let message = SignedData::read(&parser, sample, 0).expect("the sample must parse");
    let parent = parser.read(&[], 0).expect("an empty parent");
    let certificate = &message.certificates()[0];
    let preparation = prepare::resolve(
        &cms,
        &message.signers()[0],
        WorkingKey::standing(certificate.tbs().public_key()),
        &parent,
        Scope::Content(message.content().kind()),
    )
    .expect("the provider must answer");
    let request = match preparation {
        Preparation::Ready(request) => request,
        Preparation::Malformed(_) => return Detached::Malformed,
        Preparation::Unsupported(part) => panic!("unsupported {part:?}"),
    };
    let work = parent.execution();
    let mut requests = work.vector();
    requests.try_push(request).expect("one request");
    let batch = verify::Batch::prepare(&cms, requests.into_owned(), &work, "content", 0)
        .expect("the batch must admit one signer");
    let results = batch
        .run(&mut [content], &work)
        .expect("the pass must complete");
    let checked = &results[0];
    Detached::Checked(
        matches!(checked.content(), ContentAgreement::Matches),
        checked.signature(),
    )
}

#[test]
fn published_detached_signatures_verify_with_both_digests() {
    // Unlike the tokens, these carry their signer, so the content digest and the
    // Kupyna signature method run against bytes signed by another implementation.
    for sample in [GOST_CADES, KUPYNA_CADES] {
        assert_eq!(
            detached(sample, CONTENT),
            Detached::Checked(true, Some(SignatureAnswer::Valid))
        );
    }
}

#[test]
fn other_detached_content_disagrees_before_any_signature_runs() {
    assert_eq!(
        detached(KUPYNA_CADES, b"another"),
        Detached::Checked(false, None)
    );
}

#[test]
fn a_signature_method_naming_another_digest_is_malformed() {
    // digestAlgorithm stays Kupyna while signatureAlgorithm becomes the shorter
    // GOST 34.311 method at the same place: the published offsets of this
    // sample, one octet less in each of the five enclosing lengths.
    const METHOD: usize = 3440;
    let mut sample = KUPYNA_CADES.to_vec();
    assert_eq!(sample[METHOD..METHOD + 4], [0x30, 0x0e, 0x06, 0x0c]);
    sample.splice(
        METHOD..METHOD + 16,
        [
            0x30, 0x0d, 0x06, 0x0b, 0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x03, 0x01,
            0x01,
        ],
    );
    for header in [0, 15, 19, 1581, 1585] {
        let length = u16::from_be_bytes([sample[header + 2], sample[header + 3]]) - 1;
        sample[header + 2..header + 4].copy_from_slice(&length.to_be_bytes());
    }
    assert_eq!(detached(&sample, CONTENT), Detached::Malformed);
}

#[test]
fn a_published_timestamp_token_verifies() {
    // Each token is a DSTU 4145 SignedData over a TSTInfo. SignerInfo holds the
    // signature octets directly, where a certificate nests an OCTET STRING.
    let tokens = tokens();
    assert_ne!(tokens.len(), 0);
    for token in &tokens {
        assert_eq!(
            answer(token, Some(CertificateSignatureAlgorithms::AllSupported)),
            Some(SignatureAnswer::Valid)
        );
    }
}

#[test]
fn a_forged_timestamp_signature_is_invalid() {
    // The last octet of the token belongs to the signature of its only signer.
    let mut token = tokens().remove(0);
    *token.last_mut().expect("a token") ^= 1;
    assert_eq!(
        answer(&token, Some(CertificateSignatureAlgorithms::AllSupported)),
        Some(SignatureAnswer::Invalid)
    );
}

#[test]
fn the_cms_path_needs_explicit_permission() {
    // Without an allowlist the provider refuses before it reads a signed byte.
    assert_eq!(answer(&tokens()[0], None), None);
}
