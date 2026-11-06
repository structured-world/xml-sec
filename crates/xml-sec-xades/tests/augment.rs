//! B-T augmentation through the public entry points.
//!
//! The fixtures under `augmentation/` come from `xml-sec-tools xades fixtures
//! --augmentation`: OpenSSL issues the signer chain and a TSA, the
//! `augment_probe` example writes the requests of the B-B signature these tests
//! create again, and the OpenSSL TSA answers them. Every completed document is
//! checked again by an independent verification and B-T assessment.

#![cfg(feature = "produce")]

use std::sync::Arc;

use structured_asn1::Oid;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_cms::timestamp::response::Status;
use structured_cms::timestamp::{ImprintAgreement, RequestAgreement, RequestWindow, Timeliness};
use structured_pkix::algorithm::digest::Algorithm;
use structured_pkix::temporal::{Instant as UtcInstant, LeapTable};
use xml_sec::XmlDocument;
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::policy::{Instant, SigningPolicy, VerificationPolicy};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, KeyResolverConfig, RsaSigningKey, SignatureAlgorithm,
    UriTypeSet, VerificationRequest, VerifyContext, with_verified_request,
};
use xml_sec_xades::{
    Assessment, AugmentError, Completion, Countersignature, DataObject, Envelope, Inputs, Outcome,
    PendingTimestamp, Request, Requirements, Signer, TimestampFailure, TimestampRequest,
    TokenFacts, complete_timestamp, countersign, create, request_timestamp, validate,
};

const ROOT: &[u8] = include_bytes!("fixtures/augmentation/root.der");
const INTERMEDIATE: &[u8] = include_bytes!("fixtures/augmentation/intermediate.der");
const SIGNER: &[u8] = include_bytes!("fixtures/augmentation/signer.der");
const KEY: &str = include_str!("fixtures/augmentation/signer.key");
const REQUEST: &[u8] = include_bytes!("fixtures/augmentation/request.tsq");
const REQUEST_POLICY: &[u8] = include_bytes!("fixtures/augmentation/request-policy.tsq");
const REQUEST_NO_NONCE: &[u8] = include_bytes!("fixtures/augmentation/request-no-nonce.tsq");
const RESPONSE: &[u8] = include_bytes!("fixtures/augmentation/response.tsr");
const RESPONSE_NO_NONCE: &[u8] = include_bytes!("fixtures/augmentation/response-no-nonce.tsr");
const RESPONSE_OTHER_IMPRINT: &[u8] =
    include_bytes!("fixtures/augmentation/response-other-imprint.tsr");
const RESPONSE_REJECTED: &[u8] = include_bytes!("fixtures/augmentation/response-rejected.tsr");
const XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";
const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const DOCUMENT: &str = "<Document><Data Id=\"payload\">Augmented payload</Data></Document>";
const TIME: &str = "2026-10-18T12:00:00Z";
/// The nonce of every fixture request that carries one.
const NONCE: &[u8] = &[0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71];
/// `1.3.6.1.4.1.13762.4`, a policy the test TSA does not issue under.
const OTHER_POLICY: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xeb, 0x42, 0x04];
/// Unix time `1_800_000_000`, after every fixture token and inside every certificate.
const AT: i64 = 500_000 * 3600;

fn account_of(memory: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(memory, work)))
}

fn account() -> Memory {
    account_of(1 << 26, 1 << 31)
}

fn utc() -> LeapTable<'static> {
    LeapTable::new(-2_208_988_800, 4_102_444_800, &[]).expect("UTC coverage")
}

/// Everything one augmentation needs, owned by the test.
struct Fixture {
    key: RsaSigningKey,
    signing: SigningPolicy,
    resolver: DefaultKeyResolver,
    verification: VerificationPolicy,
}

/// The caller evidence of a completion beyond its assessment.
#[derive(Clone, Copy)]
struct Given<'a> {
    requirements: Requirements,
    anchors: &'a [&'a [u8]],
    certificates: &'a [&'a [u8]],
    window: Option<RequestWindow>,
}

const B_T: Given<'static> = Given {
    requirements: Requirements::Timestamped,
    anchors: &[ROOT],
    certificates: &[INTERMEDIATE],
    window: None,
};

impl Fixture {
    fn new() -> Self {
        let mut signing = SigningPolicy::default();
        signing.uris.references = UriTypeSet::ALL;
        let mut verification = VerificationPolicy::default();
        verification.key_trust.verify_x509_chains = true;
        verification.key_trust.verification_time = Instant::new(AT, 0);
        Self {
            key: RsaSigningKey::from_pkcs8_pem(KEY).expect("fixture key parses"),
            signing,
            resolver: DefaultKeyResolver::new(KeyResolverConfig {
                trusted_certs: vec![ROOT.to_vec()],
                ..KeyResolverConfig::default()
            }),
            verification,
        }
    }

    fn with_assessment<R>(&self, operation: impl FnOnce(&Assessment<'_, '_>) -> R) -> R {
        let context = VerifyContext::new()
            .policy(self.verification.clone())
            .key_resolver(&self.resolver);
        let request = VerificationRequest::default();
        operation(&Assessment {
            context: &context,
            request: &request,
            certificates: &[ROOT],
        })
    }

    fn signer(&self) -> Signer<'_> {
        Signer {
            key: &self.key,
            provider: xml_sec::provider::default_provider(),
            policy: &self.signing,
            chain: &[SIGNER, INTERMEDIATE],
            method: SignatureAlgorithm::RsaSha256,
            digest: DigestAlgorithm::Sha256,
            canonicalization: C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
        }
    }

    /// The enveloped B-B signature `sig` the fixture requests were made over.
    fn created(&self) -> XmlDocument {
        let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
        self.with_assessment(|assessment| {
            create(
                &mut document,
                &self.signer(),
                Request {
                    id: "sig",
                    signing_time: TIME,
                    objects: vec![DataObject::Document {
                        mime_type: "text/xml",
                        envelope: Envelope::Enveloped,
                    }],
                    parent: None,
                    resources: None,
                    id_attributes: &[],
                },
                assessment,
                &account(),
            )
        })
        .expect("B-B signature");
        document
    }

    fn request(
        &self,
        document: &XmlDocument,
        policy: Option<&'static [u8]>,
        nonce: Option<&'static [u8]>,
        work: &Memory,
    ) -> Result<PendingTimestamp, AugmentError> {
        self.with_assessment(|assessment| {
            request_timestamp(
                document,
                &TimestampRequest {
                    signature: "sig",
                    digest: Algorithm::Sha256,
                    policy: policy.map(Oid::from_bytes),
                    nonce,
                    id_attributes: &[],
                },
                assessment,
                work,
            )
        })
    }

    fn complete(
        &self,
        document: &mut XmlDocument,
        pending: &PendingTimestamp,
        response: &[u8],
        given: Given<'_>,
        work: &Memory,
    ) -> Result<(), AugmentError> {
        let utc = utc();
        let inputs = Inputs {
            requirements: given.requirements,
            anchors: given.anchors,
            certificates: given.certificates,
            utc: &utc,
            accuracies: &[],
            responders: &[],
            crls: &[],
            responses: &[],
        };
        self.with_assessment(|assessment| {
            complete_timestamp(
                document,
                pending,
                response,
                &Completion {
                    assessment,
                    inputs: &inputs,
                    window: given.window,
                    id_attributes: &[],
                },
                work,
            )
        })
    }

    /// An independent verification and B-T assessment of `sig`.
    fn meets_timestamped(&self, xml: &str) -> bool {
        let document = XmlDocument::parse(xml).expect("augmented XML parses");
        let context = VerifyContext::new()
            .policy(self.verification.clone())
            .key_resolver(&self.resolver);
        let utc = utc();
        with_verified_request(
            &document,
            &context,
            &VerificationRequest::default(),
            &account(),
            |session| {
                assert!(session.evidence().accepted(&document)?);
                let signature = session.view().node_for_id("sig", &[]).expect("sig");
                let inputs = Inputs {
                    requirements: Requirements::Timestamped,
                    anchors: &[ROOT],
                    certificates: &[INTERMEDIATE],
                    utc: &utc,
                    accuracies: &[],
                    responders: &[],
                    crls: &[],
                    responses: &[],
                };
                Ok(validate(&session, signature, &inputs, |level| {
                    level.all_requirements_met()
                }))
            },
        )
        .expect("augmented document verifies")
        .map(|outcome| matches!(outcome, Outcome::Assessed(true)))
        .expect("B-T assessment completes")
    }
}

/// Assert that `operation` failed with `matches` and left `document` as it was.
fn refused(
    document: &mut XmlDocument,
    operation: impl FnOnce(&mut XmlDocument) -> Result<(), AugmentError>,
    matches: impl FnOnce(&AugmentError) -> bool,
) {
    let before = document.as_xml().to_owned();
    let generation = document.generation();
    let result = operation(document);
    match &result {
        Err(error) if matches(error) => {}
        other => panic!("unexpected result {other:?}"),
    }
    assert_eq!(document.as_xml(), before, "the document is unchanged");
    assert_eq!(document.generation(), generation, "nothing is published");
}

/// The `CanonicalizationMethod` algorithm of `parent`.
fn method<'a>(parent: roxmltree::Node<'a, '_>) -> Option<&'a str> {
    parent
        .children()
        .find(|node| node.has_tag_name((DS, "CanonicalizationMethod")))
        .and_then(|node| node.attribute("Algorithm"))
}

/// The token facts of an `Unproven` refusal.
fn unproven(error: &AugmentError) -> Option<TokenFacts> {
    match error {
        AugmentError::Unproven(facts) => Some(*facts),
        _ => None,
    }
}

#[test]
fn a_granted_token_completes_b_t() {
    // EN 319 132-1 §5.3: the token covers the canonicalized SignatureValue
    // and is added as a SignatureTimeStamp; the new generation meets B-T.
    let fixture = Fixture::new();
    let mut document = fixture.created();
    let pending = fixture
        .request(&document, None, Some(NONCE), &account())
        .expect("request");
    // The same signature and nonce give the request the TSA answered.
    assert_eq!(pending.request(), REQUEST);
    let generation = document.generation();
    fixture
        .complete(&mut document, &pending, RESPONSE, B_T, &account())
        .expect("completion");
    assert!(document.generation() > generation);
    assert!(fixture.meets_timestamped(document.as_xml()));
    let completed = roxmltree::Document::parse(document.as_xml()).expect("XML parses");
    let stamp = completed
        .descendants()
        .find(|node| node.has_tag_name((XADES, "SignatureTimeStamp")))
        .expect("SignatureTimeStamp");
    assert_eq!(
        stamp.parent().map(|node| node.tag_name().name()),
        Some("UnsignedSignatureProperties")
    );
    // The property repeats the method its input was canonicalized with.
    let signed_info = completed
        .descendants()
        .find(|node| node.has_tag_name((DS, "SignedInfo")))
        .expect("SignedInfo");
    assert_eq!(method(stamp), method(signed_info));
    assert!(
        stamp
            .children()
            .any(|node| node.has_tag_name((XADES, "EncapsulatedTimeStamp")))
    );
}

#[test]
fn requests_are_the_ones_the_tsa_answered() {
    // RFC 3161 §2.4.1: policy and nonce are carried as requested, so the
    // request encoding is a function of the signature and those choices.
    let fixture = Fixture::new();
    let document = fixture.created();
    let request = |policy, nonce| {
        fixture
            .request(&document, policy, nonce, &account())
            .expect("request")
    };
    assert_eq!(
        request(Some(OTHER_POLICY), Some(NONCE)).request(),
        REQUEST_POLICY
    );
    assert_eq!(request(None, None).request(), REQUEST_NO_NONCE);
}

#[test]
fn a_token_over_other_data_is_refused() {
    // The token's imprint is neither the requested one nor the signature's
    // timestamp input.
    let fixture = Fixture::new();
    let mut document = fixture.created();
    let pending = fixture
        .request(&document, None, Some(NONCE), &account())
        .expect("request");
    refused(
        &mut document,
        |document| fixture.complete(document, &pending, RESPONSE_OTHER_IMPRINT, B_T, &account()),
        |error| {
            unproven(error).is_some_and(|facts| {
                facts.imprint == ImprintAgreement::Differs
                    && facts.requested_imprint == Some(RequestAgreement::HashDiffers)
            })
        },
    );
}

#[test]
fn a_token_without_the_requested_nonce_is_refused() {
    // RFC 3161 §2.4.2: the token MUST repeat the requested nonce.
    let fixture = Fixture::new();
    let mut document = fixture.created();
    let pending = fixture
        .request(&document, None, Some(NONCE), &account())
        .expect("request");
    refused(
        &mut document,
        |document| fixture.complete(document, &pending, RESPONSE_NO_NONCE, B_T, &account()),
        |error| {
            unproven(error).is_some_and(|facts| {
                facts.requested_imprint == Some(RequestAgreement::Matches)
                    && facts.requested_fields.and_then(|fields| fields.nonce) == Some(false)
            })
        },
    );
}

#[test]
fn a_token_under_another_policy_is_refused() {
    // RFC 3161 §2.4.2: a requested policy must be the token's policy.
    let fixture = Fixture::new();
    let mut document = fixture.created();
    let pending = fixture
        .request(&document, Some(OTHER_POLICY), Some(NONCE), &account())
        .expect("request");
    refused(
        &mut document,
        |document| fixture.complete(document, &pending, RESPONSE, B_T, &account()),
        |error| {
            unproven(error).is_some_and(|facts| {
                facts.requested_fields.and_then(|fields| fields.policy) == Some(false)
            })
        },
    );
}

#[test]
fn a_rejection_publishes_nothing() {
    // RFC 3161 §2.4.2: a rejection carries no token.
    let fixture = Fixture::new();
    let mut document = fixture.created();
    let pending = fixture
        .request(&document, None, Some(NONCE), &account())
        .expect("request");
    refused(
        &mut document,
        |document| fixture.complete(document, &pending, RESPONSE_REJECTED, B_T, &account()),
        |error| matches!(error, AugmentError::Refused(Status::Rejection)),
    );
}

#[test]
fn without_a_nonce_only_a_caller_window_proves_freshness() {
    // RFC 3161 §6: without a nonce the requester itself establishes that the
    // response belongs to its uniquely outstanding request.
    let fixture = Fixture::new();
    let mut document = fixture.created();
    let pending = fixture
        .request(&document, None, None, &account())
        .expect("request");
    refused(
        &mut document,
        |document| fixture.complete(document, &pending, RESPONSE_NO_NONCE, B_T, &account()),
        |error| unproven(error).is_some_and(|facts| facts.timeliness == Timeliness::Unverified),
    );
    // 2026-01-01 to 2045-01-01, the fixtures' certificate validity.
    let window = RequestWindow::for_unique_imprint(
        UtcInstant::new(1_767_225_600, 0).expect("instant"),
        UtcInstant::new(2_366_841_600, 0).expect("instant"),
    );
    fixture
        .complete(
            &mut document,
            &pending,
            RESPONSE_NO_NONCE,
            Given { window, ..B_T },
            &account(),
        )
        .expect("completion within the window");
    assert!(fixture.meets_timestamped(document.as_xml()));
}

#[test]
fn a_changed_document_makes_the_request_stale() {
    // The token's input is the requested generation's; a countersignature
    // added while waiting for the TSA leaves a request for another document.
    let fixture = Fixture::new();
    let mut document = fixture.created();
    let pending = fixture
        .request(&document, None, Some(NONCE), &account())
        .expect("request");
    fixture
        .with_assessment(|assessment| {
            countersign(
                &mut document,
                &fixture.signer(),
                &Countersignature {
                    parent: "sig",
                    id: "counter",
                    signing_time: TIME,
                    id_attributes: &[],
                },
                assessment,
                &account(),
            )
        })
        .expect("countersignature");
    refused(
        &mut document,
        |document| fixture.complete(document, &pending, RESPONSE, B_T, &account()),
        |error| matches!(error, AugmentError::Changed),
    );
    // Another parse of the same bytes is another document.
    let mut reparsed = XmlDocument::parse(fixture.created().as_xml()).expect("parses");
    refused(
        &mut reparsed,
        |document| fixture.complete(document, &pending, RESPONSE, B_T, &account()),
        |error| matches!(error, AugmentError::Changed),
    );
}

#[test]
fn a_tsa_without_a_trusted_path_is_not_published() {
    // The checked token is added only when the new generation meets B-T,
    // which requires the TSA's path to end at a caller anchor. The root is
    // still a certificate the signer's verified path may use.
    let fixture = Fixture::new();
    let mut document = fixture.created();
    let pending = fixture
        .request(&document, None, Some(NONCE), &account())
        .expect("request");
    refused(
        &mut document,
        |document| {
            fixture.complete(
                document,
                &pending,
                RESPONSE,
                Given {
                    anchors: &[],
                    certificates: &[INTERMEDIATE, ROOT],
                    ..B_T
                },
                &account(),
            )
        },
        |error| {
            matches!(
                error,
                AugmentError::Unmet(Outcome::Timestamp {
                    failure: TimestampFailure::Path(_),
                    ..
                })
            )
        },
    );
    // Revocation material B-LT needs is not part of a timestamp completion.
    refused(
        &mut document,
        |document| {
            fixture.complete(
                document,
                &pending,
                RESPONSE,
                Given {
                    requirements: Requirements::LongTerm,
                    ..B_T
                },
                &account(),
            )
        },
        |error| matches!(error, AugmentError::Unmet(_)),
    );
    refused(
        &mut document,
        |document| {
            fixture.complete(
                document,
                &pending,
                RESPONSE,
                Given {
                    requirements: Requirements::Basic,
                    ..B_T
                },
                &account(),
            )
        },
        |error| matches!(error, AugmentError::BelowTimestamped(Requirements::Basic)),
    );
}

#[test]
fn an_unknown_signature_is_refused() {
    let fixture = Fixture::new();
    let document = fixture.created();
    let result = fixture.with_assessment(|assessment| {
        request_timestamp(
            &document,
            &TimestampRequest {
                signature: "payload",
                digest: Algorithm::Sha256,
                policy: None,
                nonce: Some(NONCE),
                id_attributes: &[],
            },
            assessment,
            &account(),
        )
    });
    assert!(
        matches!(result, Err(AugmentError::UnknownSignature(_))),
        "{result:?}"
    );
}

/// Complete under every account from `start` upward, growing by a third:
/// below what completion needs each refusal leaves the document as it was,
/// and once a ceiling succeeds every larger one does.
fn scan_ceilings(limit: usize, account: impl Fn(usize) -> Memory) {
    let fixture = Fixture::new();
    let mut succeeded = false;
    let mut ceiling = 0;
    while ceiling <= limit {
        let mut document = fixture.created();
        let pending = fixture
            .request(&document, None, Some(NONCE), &self::account())
            .expect("request");
        let before = document.as_xml().to_owned();
        let generation = document.generation();
        let result = fixture.complete(&mut document, &pending, RESPONSE, B_T, &account(ceiling));
        match result {
            Ok(()) => succeeded = true,
            Err(error) => {
                assert!(!succeeded, "a larger ceiling {ceiling} failed: {error}");
                assert_eq!(document.as_xml(), before, "{ceiling}: {error}");
                assert_eq!(document.generation(), generation, "{ceiling}: {error}");
            }
        }
        ceiling += ceiling / 3 + 1;
    }
    assert!(succeeded, "the largest ceiling completes");
}

#[test]
fn every_work_ceiling_publishes_all_or_nothing() {
    // Checking the response, staging the property and the B-T assessment all
    // spend the caller's work; a refusal at any of them publishes nothing.
    scan_ceilings(1 << 28, |work| account_of(1 << 26, work));
}

#[test]
fn every_storage_ceiling_publishes_all_or_nothing() {
    // The same scan over retained storage, the property draft included.
    scan_ceilings(1 << 26, |memory| account_of(memory, 1 << 31));
}
