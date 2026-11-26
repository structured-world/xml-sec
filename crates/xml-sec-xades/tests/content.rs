//! Content timestamps of a new signature through the public entry points.
//!
//! The fixtures under `content/` come from `xml-sec-tools xades fixtures
//! --content`: OpenSSL issues the PKI and a TSA, the `augment_probe` example
//! writes the content timestamp requests of the signatures these tests
//! create, and the OpenSSL TSA answers each one. Every created document is
//! checked again by an independent verification, B-B assessment and token
//! check.

#![cfg(feature = "produce")]

use std::sync::Arc;

use structured_asn1::memory::{Memory, MemoryAccount};
use structured_pkix::algorithm::digest::Algorithm;
use structured_pkix::temporal::LeapTable;
use xml_sec::XmlDocument;
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::policy::{Instant, SigningPolicy, VerificationPolicy};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, KeyResolverConfig, RsaSigningKey, SignatureAlgorithm,
    Transform, UriTypeSet, VerificationRequest, VerifyContext, XPathExpression,
    with_verified_request,
};
use xml_sec_xades::properties::Properties;
use xml_sec_xades::{
    Assessment, ContentError, ContentEvidence, ContentScope, ContentTimestamp, CreateError,
    DataObject, Envelope, Inputs, Outcome, Request, Requirements, Signer, TimestampRole,
    TokenIntegrity, check_tokens, create, request_content_timestamps, validate_basic,
};

const ROOT: &[u8] = include_bytes!("fixtures/content/root.der");
const INTERMEDIATE: &[u8] = include_bytes!("fixtures/content/intermediate.der");
const SIGNER: &[u8] = include_bytes!("fixtures/content/signer.der");
const KEY: &str = include_str!("fixtures/content/signer.key");
const ALL_REQUEST: &[u8] = include_bytes!("fixtures/content/content-all.tsq");
const ALL_RESPONSE: &[u8] = include_bytes!("fixtures/content/content-all.tsr");
const INDIVIDUAL_REQUEST: &[u8] = include_bytes!("fixtures/content/content-individual.tsq");
const INDIVIDUAL_RESPONSE: &[u8] = include_bytes!("fixtures/content/content-individual.tsr");
const CHANGING_RESPONSE: &[u8] = include_bytes!("fixtures/content/content-changing.tsr");
const DOCUMENT: &str = "<Document><Data Id=\"payload\">Augmented payload</Data></Document>";
const TIME: &str = "2026-10-18T12:00:00Z";
const NONCE: &[u8] = &[0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71];
const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";
/// Unix time `1_800_000_000`, after every fixture token and inside every
/// certificate window.
const AT: i64 = 500_000 * 3600;
/// The probe's reference over the document that keeps the qualifying
/// properties, which the content timestamp then changes.
const CHANGING: &str =
    "not(ancestor-or-self::ds:SignedInfo or ancestor-or-self::ds:SignatureValue)";

fn account() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 26, 1 << 31)))
}

fn stamp(
    scope: ContentScope<'static>,
    response: Option<&'static [u8]>,
) -> ContentTimestamp<'static> {
    ContentTimestamp {
        scope,
        digest: Algorithm::Sha256,
        policy: None,
        nonce: Some(NONCE),
        response,
    }
}

/// The document without signatures and the payload element, as the probe signs.
fn objects() -> Vec<DataObject<'static>> {
    vec![
        DataObject::Document {
            mime_type: "text/xml",
            envelope: Envelope::ExcludingSignatures,
        },
        DataObject::Element {
            id: "payload",
            mime_type: "text/xml",
        },
    ]
}

/// Both data objects, in the reverse of reference order.
const INDIVIDUAL: ContentScope<'static> =
    ContentScope::Individual(&["#sig-reference-1", "#sig-reference-0"]);

/// Everything the creations need, owned by the test.
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
            utc: LeapTable::new(-2_208_988_800, 4_102_444_800, &[]).expect("UTC coverage"),
        }
    }

    fn signer<'a>(&'a self, chain: &'a [&'a [u8]]) -> Signer<'a> {
        Signer {
            key: &self.key,
            provider: xml_sec::provider::default_provider(),
            policy: &self.signing,
            chain,
            method: SignatureAlgorithm::RsaSha256,
            digest: DigestAlgorithm::Sha256,
            canonicalization: C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
            prefixes: xml_sec_xades::Prefixes::default(),
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

    fn evidence(&self) -> ContentEvidence<'_> {
        ContentEvidence {
            certificates: &[INTERMEDIATE],
            utc: &self.utc,
            accuracies: &[],
            window: None,
        }
    }

    fn request<'a>(
        &'a self,
        objects: Vec<DataObject<'a>>,
        stamps: &'a [ContentTimestamp<'a>],
    ) -> Request<'a> {
        Request {
            id: "sig",
            signing_time: TIME,
            objects,
            placement: xml_sec_xades::Placement::DocumentEnd,
            resources: None,
            id_attributes: &[],
            properties: Properties {
                content_timestamps: stamps,
                content_evidence: Some(self.evidence()),
                ..Properties::default()
            },
        }
    }

    fn create(&self, document: &mut XmlDocument, request: Request<'_>) -> Result<(), CreateError> {
        let chain: [&[u8]; 2] = [SIGNER, INTERMEDIATE];
        self.with_assessment(|assessment| {
            create(
                document,
                &self.signer(&chain),
                request,
                assessment,
                &account(),
            )
        })
    }

    /// The independent B-B assessment and own token checks of `sig`.
    fn assessed(&self, xml: &str) -> (bool, Vec<(TimestampRole, TokenIntegrity)>) {
        let document = XmlDocument::parse(xml).expect("created XML parses");
        let context = VerifyContext::new()
            .policy(self.verification.clone())
            .key_resolver(&self.resolver);
        let inputs = Inputs {
            requirements: Requirements::Basic,
            anchors: &[ROOT],
            certificates: &[INTERMEDIATE],
            utc: &self.utc,
            accuracies: &[],
            responders: &[],
            crls: &[],
            responses: &[],
        };
        with_verified_request(
            &document,
            &context,
            &VerificationRequest::default(),
            &account(),
            |session| {
                assert!(session.evidence().accepted(&document)?);
                let signature = session.view().node_for_id("sig", &[]).expect("signature");
                let basic = validate_basic(&session, signature, &[ROOT], |report| {
                    report.all_root_requirements_met()
                })
                .expect("B-B assessment completes");
                let tokens = check_tokens(&session, signature, &inputs, |results| {
                    results
                        .iter()
                        .map(|result| (result.role(), result.integrity()))
                        .collect::<Vec<_>>()
                })
                .expect("token checks complete");
                Ok((
                    matches!(basic, Outcome::Assessed(true)),
                    match tokens {
                        Outcome::Assessed(tokens) => tokens,
                        outcome => panic!("token checks: {outcome:?}"),
                    },
                ))
            },
        )
        .expect("created document verifies")
    }
}

#[test]
fn content_timestamps_are_requested_before_signing_and_kept_in_order() {
    // EN 319 132-1 §5.2.8: the requests cover the data references' outputs
    // before the signature exists, the TSA's tokens over them are checked
    // against those exact requests and kept as AllDataObjectsTimeStamp and
    // IndividualDataObjectsTimeStamp after the formats; the signature meets
    // B-B and each token's own checks pass.
    let fixture = Fixture::new();
    let chain: [&[u8]; 2] = [SIGNER, INTERMEDIATE];
    let asked = [stamp(ContentScope::All, None), stamp(INDIVIDUAL, None)];
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    let requests = fixture.with_assessment(|assessment| {
        request_content_timestamps(
            &mut document,
            &fixture.signer(&chain),
            &fixture.request(objects(), &asked),
            assessment,
            &account(),
        )
    });
    let requests = requests.expect("content requests");
    assert_eq!(document.as_xml(), DOCUMENT, "requesting changes nothing");
    assert_eq!(requests.len(), 2);
    assert_eq!(requests.get(0), Some(ALL_REQUEST), "the fixture's request");
    assert_eq!(requests.get(1), Some(INDIVIDUAL_REQUEST));
    let answered = [
        stamp(ContentScope::All, Some(ALL_RESPONSE)),
        stamp(INDIVIDUAL, Some(INDIVIDUAL_RESPONSE)),
    ];
    fixture
        .create(&mut document, fixture.request(objects(), &answered))
        .expect("creation with content timestamps");
    let (basic, tokens) = fixture.assessed(document.as_xml());
    assert!(basic, "B-B");
    assert_eq!(
        tokens,
        [
            (TimestampRole::AllDataObjects, TokenIntegrity::Intact),
            (TimestampRole::IndividualDataObjects, TokenIntegrity::Intact),
        ]
    );
    let created = roxmltree::Document::parse(document.as_xml()).expect("XML parses");
    let properties: Vec<&str> = created
        .descendants()
        .find(|node| node.has_tag_name((XADES, "SignedDataObjectProperties")))
        .expect("data object properties")
        .children()
        .filter(roxmltree::Node::is_element)
        .map(|node| node.tag_name().name())
        .collect();
    assert_eq!(
        properties,
        [
            "DataObjectFormat",
            "DataObjectFormat",
            "AllDataObjectsTimeStamp",
            "IndividualDataObjectsTimeStamp"
        ]
    );
    // The Include order is the requested one, not the reference order.
    let includes: Vec<(Option<&str>, Option<&str>)> = created
        .descendants()
        .filter(|node| node.has_tag_name((XADES, "Include")))
        .map(|node| (node.attribute("URI"), node.attribute("referencedData")))
        .collect();
    assert_eq!(
        includes,
        [
            (Some("#sig-reference-1"), Some("true")),
            (Some("#sig-reference-0"), Some("true"))
        ]
    );
    let method = created
        .descendants()
        .find(|node| node.has_tag_name((XADES, "AllDataObjectsTimeStamp")))
        .and_then(|stamp| {
            stamp
                .children()
                .find(|node| node.has_tag_name((DS, "CanonicalizationMethod")))
        })
        .expect("the timestamp's method");
    assert_eq!(
        method.attribute("Algorithm"),
        Some("http://www.w3.org/2001/10/xml-exc-c14n#")
    );
}

#[test]
fn a_response_to_another_request_publishes_nothing() {
    // Each response is checked against the request of its own timestamp:
    // swapped tokens cover other inputs and are refused, as is a timestamp
    // without a response or responses without evidence to check them with.
    let fixture = Fixture::new();
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    let swapped = [
        stamp(ContentScope::All, Some(INDIVIDUAL_RESPONSE)),
        stamp(INDIVIDUAL, Some(ALL_RESPONSE)),
    ];
    let error = fixture
        .create(&mut document, fixture.request(objects(), &swapped))
        .expect_err("swapped responses");
    assert!(
        matches!(
            &error,
            CreateError::Content(cause)
                if matches!(**cause, ContentError::Check(_) | ContentError::Unproven(_))
        ),
        "{error:?}"
    );
    let missing = [stamp(ContentScope::All, None)];
    let error = fixture
        .create(&mut document, fixture.request(objects(), &missing))
        .expect_err("no response");
    assert!(
        matches!(&error, CreateError::Content(cause) if matches!(**cause, ContentError::MissingResponse(0))),
        "{error:?}"
    );
    let answered = [stamp(ContentScope::All, Some(ALL_RESPONSE))];
    let mut unchecked = fixture.request(objects(), &answered);
    unchecked.properties.content_evidence = None;
    let error = fixture
        .create(&mut document, unchecked)
        .expect_err("no evidence");
    assert!(
        matches!(&error, CreateError::Content(cause) if matches!(**cause, ContentError::MissingEvidence)),
        "{error:?}"
    );
    assert_eq!(document.as_xml(), DOCUMENT, "nothing is published");
}

#[test]
fn a_reference_over_its_own_timestamps_is_refused() {
    // A reference that covers the signature's qualifying properties digests
    // other bytes once the timestamp joins them: the token would cover data
    // the signature does not sign, so the creation is refused.
    let fixture = Fixture::new();
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    let changing = vec![DataObject::Reference {
        uri: "",
        transforms: vec![
            Transform::XPath(XPathExpression::new(CHANGING).with_namespace("ds", DS)),
            Transform::C14n(C14nAlgorithm::new(C14nMode::Exclusive1_0, false)),
        ],
        mime_type: "text/xml",
    }];
    let answered = [stamp(ContentScope::All, Some(CHANGING_RESPONSE))];
    let error = fixture
        .create(&mut document, fixture.request(changing, &answered))
        .expect_err("a self-covering reference");
    assert!(
        matches!(&error, CreateError::Content(cause) if matches!(**cause, ContentError::Changed)),
        "{error:?}"
    );
    assert_eq!(document.as_xml(), DOCUMENT, "nothing is published");
}
