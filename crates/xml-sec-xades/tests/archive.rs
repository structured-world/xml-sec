//! B-LTA augmentation and archive renewal through the public entry points.
//!
//! The fixtures under `augmentation/` come from `xml-sec-tools xades fixtures
//! --augmentation`: OpenSSL issues the PKI, an empty CRL of each CA and a TSA,
//! the `augment_probe` example writes the requests of the lifecycle these
//! tests run again (B-B created, B-T, the CRLs added, the first archive, its
//! renewal), and the OpenSSL TSA answers each one. Every archived document is
//! checked again by an independent verification and B-LTA assessment.

#![cfg(feature = "produce")]

use std::sync::Arc;

use structured_asn1::memory::{Memory, MemoryAccount};
use structured_cms::timestamp::response::Status;
use structured_cms::timestamp::{ImprintAgreement, RequestAgreement};
use structured_pkix::algorithm::digest::Algorithm;
use structured_pkix::temporal::LeapTable;
use xml_sec::XmlDocument;
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::policy::{Instant, SigningPolicy, VerificationPolicy};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, KeyResolverConfig, RsaSigningKey, SignatureAlgorithm,
    UriTypeSet, VerificationRequest, VerifyContext, with_verified_request,
};
use xml_sec_xades::{
    Assessment, AugmentError, Completion, DataObject, Envelope, Inputs, Level, Outcome,
    PendingTimestamp, Request, Requirements, Signer, StatusFailure, TimestampFailure,
    TimestampRequest, ValidationData, ValidationError, add_validation_data, complete_timestamp,
    create, request_archive_timestamp, request_timestamp, validate,
};

const ROOT: &[u8] = include_bytes!("fixtures/augmentation/root.der");
const INTERMEDIATE: &[u8] = include_bytes!("fixtures/augmentation/intermediate.der");
const SIGNER: &[u8] = include_bytes!("fixtures/augmentation/signer.der");
const KEY: &str = include_str!("fixtures/augmentation/signer.key");
const ROOT_CRL: &[u8] = include_bytes!("fixtures/augmentation/root.crl");
const INTERMEDIATE_CRL: &[u8] = include_bytes!("fixtures/augmentation/intermediate.crl");
const RESPONSE: &[u8] = include_bytes!("fixtures/augmentation/response.tsr");
const ARCHIVE_REQUEST: &[u8] = include_bytes!("fixtures/augmentation/archive.tsq");
const ARCHIVE_RESPONSE: &[u8] = include_bytes!("fixtures/augmentation/archive.tsr");
const RENEWAL_REQUEST: &[u8] = include_bytes!("fixtures/augmentation/renewal.tsq");
const RENEWAL_RESPONSE: &[u8] = include_bytes!("fixtures/augmentation/renewal.tsr");
const REJECTED: &[u8] = include_bytes!("fixtures/augmentation/response-rejected.tsr");
const DOCUMENT: &str = "<Document><Data Id=\"payload\">Augmented payload</Data></Document>";
const TIME: &str = "2026-10-18T12:00:00Z";
/// The nonce of every fixture request that carries one.
const NONCE: &[u8] = &[0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71];
/// Unix time `1_800_000_000`, after every fixture token and inside every
/// certificate and CRL window.
const AT: i64 = 500_000 * 3600;
const ARCHIVE_END: &str = "</xades141:ArchiveTimeStamp>";

fn account() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 26, 1 << 31)))
}

fn utc() -> LeapTable<'static> {
    LeapTable::new(-2_208_988_800, 4_102_444_800, &[]).expect("UTC coverage")
}

const TIMESTAMP: TimestampRequest<'static> = TimestampRequest {
    signature: "sig",
    digest: Algorithm::Sha256,
    policy: None,
    nonce: Some(NONCE),
    id_attributes: &[],
};

/// Everything the lifecycle needs, owned by the test.
struct Fixture {
    key: RsaSigningKey,
    signing: SigningPolicy,
    resolver: DefaultKeyResolver,
    verification: VerificationPolicy,
    utc: LeapTable<'static>,
}

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
            utc: utc(),
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

    /// The caller's evidence at `requirements`, with the CRLs if `statuses`.
    fn inputs(&self, requirements: Requirements, statuses: bool) -> Inputs<'_> {
        const CRLS: &[&[u8]] = &[ROOT_CRL, INTERMEDIATE_CRL];
        Inputs {
            requirements,
            anchors: &[ROOT],
            certificates: &[INTERMEDIATE],
            utc: &self.utc,
            accuracies: &[],
            responders: &[],
            crls: if statuses { CRLS } else { &[] },
            responses: &[],
        }
    }

    /// The created B-B signature `sig`, completed to B-T with the fixture token.
    fn timestamped(&self) -> XmlDocument {
        let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
        let chain: [&[u8]; 2] = [SIGNER, INTERMEDIATE];
        let signer = Signer {
            key: &self.key,
            provider: xml_sec::provider::default_provider(),
            policy: &self.signing,
            chain: &chain,
            method: SignatureAlgorithm::RsaSha256,
            digest: DigestAlgorithm::Sha256,
            canonicalization: C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
        };
        self.with_assessment(|assessment| {
            create(
                &mut document,
                &signer,
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
            .expect("B-B signature");
            let pending = request_timestamp(&document, &TIMESTAMP, assessment, &account())
                .expect("B-T request");
            self.complete(&mut document, &pending, RESPONSE, Requirements::Timestamped)
                .expect("B-T completion");
        });
        document
    }

    /// Add the CRLs and require `requirements`.
    fn add_statuses(&self, document: &mut XmlDocument, requirements: Requirements) {
        self.with_assessment(|assessment| {
            add_validation_data(
                document,
                &ValidationData {
                    signature: "sig",
                    assessment,
                    inputs: &self.inputs(requirements, true),
                    id_attributes: &[],
                },
                &account(),
            )
        })
        .expect("validation data");
    }

    /// The B-T fixture with its CRLs: B-LT.
    fn long_term(&self) -> XmlDocument {
        let mut document = self.timestamped();
        self.add_statuses(&mut document, Requirements::LongTerm);
        document
    }

    fn request(
        &self,
        document: &XmlDocument,
        requirements: Requirements,
        statuses: bool,
    ) -> Result<PendingTimestamp, AugmentError> {
        self.with_assessment(|assessment| {
            request_archive_timestamp(
                document,
                &TIMESTAMP,
                assessment,
                &self.inputs(requirements, statuses),
                &account(),
            )
        })
    }

    fn complete(
        &self,
        document: &mut XmlDocument,
        pending: &PendingTimestamp,
        response: &[u8],
        requirements: Requirements,
    ) -> Result<(), AugmentError> {
        self.with_assessment(|assessment| {
            complete_timestamp(
                document,
                pending,
                response,
                &Completion {
                    assessment,
                    inputs: &self.inputs(requirements, true),
                    window: None,
                    id_attributes: &[],
                },
                &account(),
            )
        })
    }

    /// The B-LT fixture with its first archive timestamp: B-LTA.
    fn archived(&self) -> XmlDocument {
        let mut document = self.long_term();
        let pending = self
            .request(&document, Requirements::LongTerm, true)
            .expect("archive request");
        self.complete(
            &mut document,
            &pending,
            ARCHIVE_RESPONSE,
            Requirements::Archival,
        )
        .expect("archive completion");
        document
    }

    /// An independent verification and assessment of `sig` at `requirements`,
    /// on the document's own material.
    fn level(&self, xml: &str, requirements: Requirements) -> Outcome<bool> {
        let document = XmlDocument::parse(xml).expect("archived XML parses");
        let context = VerifyContext::new()
            .policy(self.verification.clone())
            .key_resolver(&self.resolver);
        with_verified_request(
            &document,
            &context,
            &VerificationRequest::default(),
            &account(),
            |session| {
                let signature = session.view().node_for_id("sig", &[]).expect("sig");
                Ok(validate(
                    &session,
                    signature,
                    &self.inputs(requirements, false),
                    all_met,
                ))
            },
        )
        .expect("archived document verifies")
        .expect("assessment completes")
    }
}

fn all_met(level: &Level<'_>) -> bool {
    level.all_requirements_met()
}

/// Assert that `operation` failed with `matches` and left `document` as it was.
fn refused<T: std::fmt::Debug>(
    document: &mut XmlDocument,
    operation: impl FnOnce(&mut XmlDocument) -> Result<T, AugmentError>,
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

#[test]
fn the_archive_request_is_the_one_the_tsa_answered() {
    // The archive input (EN 319 132-1 §5.5.2.3) of the B-LT document covers
    // every reference output, the signature and all unsigned properties; the
    // request over it is byte for byte the one the fixture TSA answered.
    let fixture = Fixture::new();
    let document = fixture.long_term();
    let pending = fixture
        .request(&document, Requirements::LongTerm, true)
        .expect("archive request");
    assert_eq!(pending.request(), ARCHIVE_REQUEST);
}

#[test]
fn a_granted_archive_token_completes_b_lta() {
    let fixture = Fixture::new();
    let document = fixture.archived();
    let xml = document.as_xml();
    assert_eq!(xml.matches(ARCHIVE_END).count(), 1);
    // The archive follows every property it protects.
    assert!(
        xml.find("AnyValidationData").expect("material") < xml.find(ARCHIVE_END).expect("archive")
    );
    let level = fixture.level(xml, Requirements::Archival);
    assert!(matches!(level, Outcome::Assessed(true)), "{level:?}");
}

#[test]
fn a_renewal_covers_the_earlier_archive() {
    // The renewal input includes the first ArchiveTimeStamp, so the second
    // archive protects it; both archives are assessed in the new generation.
    let fixture = Fixture::new();
    let mut document = fixture.archived();
    fixture.add_statuses(&mut document, Requirements::Archival);
    let pending = fixture
        .request(&document, Requirements::Archival, true)
        .expect("renewal request");
    assert_eq!(pending.request(), RENEWAL_REQUEST);
    fixture
        .complete(
            &mut document,
            &pending,
            RENEWAL_RESPONSE,
            Requirements::Archival,
        )
        .expect("renewal completion");
    let xml = document.as_xml();
    assert_eq!(xml.matches(ARCHIVE_END).count(), 2);
    let level = fixture.level(xml, Requirements::Archival);
    assert!(matches!(level, Outcome::Assessed(true)), "{level:?}");
    // A change to the first archive's element leaves its own token valid,
    // since its input precedes it: alone, that archive still meets B-LTA.
    // The renewal's input includes the element, so its imprint breaks.
    let open = "<xades141:ArchiveTimeStamp";
    let changed = |xml: &str| xml.replacen(open, &format!("{open} Id=\"first-archive\""), 1);
    let alone = fixture.level(
        &changed(fixture.archived().as_xml()),
        Requirements::Archival,
    );
    assert!(matches!(alone, Outcome::Assessed(true)), "{alone:?}");
    let level = fixture.level(&changed(xml), Requirements::Archival);
    assert!(
        matches!(
            level,
            Outcome::Timestamp {
                failure: TimestampFailure::Rejected,
                ..
            }
        ),
        "{level:?}"
    );
}

#[test]
fn an_archive_is_requested_at_b_lt_or_above() {
    // An archive timestamp protects validation data; below B-LT there is none.
    let fixture = Fixture::new();
    let document = fixture.long_term();
    let result = fixture.request(&document, Requirements::Timestamped, true);
    assert!(
        matches!(
            result,
            Err(AugmentError::BelowLongTerm(Requirements::Timestamped))
        ),
        "{result:?}"
    );
}

#[test]
fn a_signature_without_statuses_gets_no_archive_request() {
    // The B-T document and no CRLs: the signer's path has no status source, so
    // the B-LT gate the shared rules require is not met.
    let fixture = Fixture::new();
    let document = fixture.timestamped();
    let result = fixture.request(&document, Requirements::LongTerm, false);
    assert!(
        matches!(
            result,
            Err(AugmentError::Unmet(Outcome::Status(
                StatusFailure::NoSource
            )))
        ),
        "{result:?}"
    );
}

#[test]
fn a_renewal_needs_a_document_with_an_archive() {
    // A renewal is assessed at B-LTA, which a B-LT document cannot meet.
    let fixture = Fixture::new();
    let document = fixture.long_term();
    let result = fixture.request(&document, Requirements::Archival, true);
    assert!(
        matches!(
            &result,
            Err(AugmentError::Validation(ValidationError::Prepare(error)))
                if matches!(
                    error.as_ref(),
                    structured_xades::prepare::Error::Property(
                        structured_xades::properties::Error::Missing {
                            local: "ArchiveTimeStamp",
                            ..
                        }
                    )
                )
        ),
        "{result:?}"
    );
}

#[test]
fn an_archive_completion_is_assessed_at_b_lta() {
    let fixture = Fixture::new();
    let mut document = fixture.long_term();
    let pending = fixture
        .request(&document, Requirements::LongTerm, true)
        .expect("archive request");
    refused(
        &mut document,
        |document| fixture.complete(document, &pending, ARCHIVE_RESPONSE, Requirements::LongTerm),
        |error| matches!(error, AugmentError::BelowArchival(Requirements::LongTerm)),
    );
}

#[test]
fn a_signature_token_does_not_complete_an_archive() {
    // The B-T token repeats the nonce but covers the SignatureValue, not the
    // archive input: it is not evidence for the archive request.
    let fixture = Fixture::new();
    let mut document = fixture.long_term();
    let pending = fixture
        .request(&document, Requirements::LongTerm, true)
        .expect("archive request");
    refused(
        &mut document,
        |document| fixture.complete(document, &pending, RESPONSE, Requirements::Archival),
        |error| {
            matches!(
                error,
                AugmentError::Unproven(facts)
                    if facts.imprint == ImprintAgreement::Differs
                        && facts.requested_imprint == Some(RequestAgreement::HashDiffers)
            )
        },
    );
}

#[test]
fn the_renewal_token_does_not_complete_the_first_archive() {
    // A genuine archive token over a later input is not evidence for this one.
    let fixture = Fixture::new();
    let mut document = fixture.long_term();
    let pending = fixture
        .request(&document, Requirements::LongTerm, true)
        .expect("archive request");
    refused(
        &mut document,
        |document| fixture.complete(document, &pending, RENEWAL_RESPONSE, Requirements::Archival),
        |error| {
            matches!(
                error,
                AugmentError::Unproven(facts)
                    if facts.imprint == ImprintAgreement::Differs
                        && facts.requested_imprint == Some(RequestAgreement::HashDiffers)
            )
        },
    );
}

#[test]
fn a_rejected_archive_request_adds_nothing() {
    let fixture = Fixture::new();
    let mut document = fixture.long_term();
    let pending = fixture
        .request(&document, Requirements::LongTerm, true)
        .expect("archive request");
    refused(
        &mut document,
        |document| fixture.complete(document, &pending, REJECTED, Requirements::Archival),
        |error| matches!(error, AugmentError::Refused(status) if *status == Status::Rejection),
    );
}

#[test]
fn a_completed_request_is_stale() {
    // The first completion publishes a new generation whose archive input now
    // includes the archive itself; the same request cannot complete it again.
    let fixture = Fixture::new();
    let mut document = fixture.long_term();
    let pending = fixture
        .request(&document, Requirements::LongTerm, true)
        .expect("archive request");
    fixture
        .complete(
            &mut document,
            &pending,
            ARCHIVE_RESPONSE,
            Requirements::Archival,
        )
        .expect("archive completion");
    refused(
        &mut document,
        |document| fixture.complete(document, &pending, ARCHIVE_RESPONSE, Requirements::Archival),
        |error| matches!(error, AugmentError::Changed),
    );
}
