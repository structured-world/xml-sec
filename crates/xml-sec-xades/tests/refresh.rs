//! Fresher validation data added to a signature that already meets B-LT,
//! through the public entry points, over the content fixtures: OpenSSL issued
//! two generations of each CA's CRL and answered the signature timestamp
//! request of the B-B signature these tests create.

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
    UriTypeSet, VerificationRequest, VerifyContext,
};
use xml_sec_xades::properties::Properties;
use xml_sec_xades::{
    Assessment, Completion, DataAdded, DataObject, Envelope, Inputs, Request, Requirements, Signer,
    TimestampRequest, ValidationData, add_validation_data, complete_timestamp, create,
    refresh_validation_data, request_timestamp,
};

const ROOT: &[u8] = include_bytes!("fixtures/content/root.der");
const INTERMEDIATE: &[u8] = include_bytes!("fixtures/content/intermediate.der");
const SIGNER: &[u8] = include_bytes!("fixtures/content/signer.der");
const KEY: &str = include_str!("fixtures/content/signer.key");
const RESPONSE: &[u8] = include_bytes!("fixtures/content/signature.tsr");
const CRLS: [&[u8]; 2] = [
    include_bytes!("fixtures/content/root.crl"),
    include_bytes!("fixtures/content/intermediate.crl"),
];
const NEXT_CRLS: [&[u8]; 2] = [
    include_bytes!("fixtures/content/root-next.crl"),
    include_bytes!("fixtures/content/intermediate-next.crl"),
];
/// Responses for the signer and the TSA their CA signed.
const OCSP: [&[u8]; 2] = [
    include_bytes!("fixtures/content/signer.ocsp"),
    include_bytes!("fixtures/content/tsa.ocsp"),
];
/// The document and signing time of the probe's B-B signature.
const DOCUMENT: &str = "<Document><Data Id=\"payload\">Augmented payload</Data></Document>";
const TIME: &str = "2026-10-18T12:00:00Z";
const NONCE: &[u8] = &[0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71];

fn account() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 26, 1 << 31)))
}

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
        verification.key_trust.verification_time = Instant::new(1_800_000_000, 0);
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

    fn inputs<'a>(&'a self, requirements: Requirements, crls: &'a [&'a [u8]]) -> Inputs<'a> {
        Inputs {
            requirements,
            anchors: &[ROOT],
            certificates: &[INTERMEDIATE],
            utc: &self.utc,
            accuracies: &[],
            responders: &[],
            crls,
            responses: &[],
        }
    }

    /// The probe's B-B signature `sig`, completed to B-T with the fixture token.
    fn timestamped(&self) -> XmlDocument {
        let chain: [&[u8]; 2] = [SIGNER, INTERMEDIATE];
        let signer = Signer {
            key: &self.key,
            provider: xml_sec::provider::default_provider(),
            policy: &self.signing,
            chain: &chain,
            method: SignatureAlgorithm::RsaSha256,
            digest: DigestAlgorithm::Sha256,
            canonicalization: C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
            prefixes: xml_sec_xades::Prefixes::default(),
        };
        let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
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
                    placement: xml_sec_xades::Placement::DocumentEnd,
                    resources: None,
                    id_attributes: &[],
                    properties: Properties::default(),
                },
                assessment,
                &account(),
            )
            .expect("B-B");
            let pending = request_timestamp(
                &document,
                &TimestampRequest {
                    signature: "sig",
                    digest: Algorithm::Sha256,
                    policy: None,
                    nonce: Some(NONCE),
                    id_attributes: &[],
                },
                assessment,
                &account(),
            )
            .expect("the probe's request");
            complete_timestamp(
                &mut document,
                &pending,
                RESPONSE,
                &Completion {
                    assessment,
                    inputs: &self.inputs(Requirements::Timestamped, &[]),
                    window: None,
                    id_attributes: &[],
                },
                &account(),
            )
            .expect("B-T");
        });
        document
    }

    fn extend(
        &self,
        document: &mut XmlDocument,
        crls: &[&[u8]],
        refresh: bool,
    ) -> Result<DataAdded, xml_sec_xades::AugmentError> {
        self.extend_with(document, crls, &[], refresh)
    }

    fn extend_with(
        &self,
        document: &mut XmlDocument,
        crls: &[&[u8]],
        responses: &[&[u8]],
        refresh: bool,
    ) -> Result<DataAdded, xml_sec_xades::AugmentError> {
        let inputs = Inputs {
            responses,
            ..self.inputs(Requirements::LongTerm, crls)
        };
        self.with_assessment(|assessment| {
            let data = ValidationData {
                signature: "sig",
                assessment,
                inputs: &inputs,
                id_attributes: &[],
            };
            if refresh {
                refresh_validation_data(document, &data, &account())
            } else {
                add_validation_data(document, &data, &account())
            }
        })
    }
}

/// How many `EncapsulatedCRLValue`s the document carries.
fn crls(xml: &str) -> usize {
    roxmltree::Document::parse(xml)
        .expect("XML parses")
        .descendants()
        .filter(|node| node.tag_name().name() == "EncapsulatedCRLValue")
        .count()
}

#[test]
fn a_refresh_takes_the_callers_crl_over_the_documents_ocsp_response() {
    // A refresh takes each member's status from the caller first, whatever
    // kind it is: the signer's newer CRL beats the OCSP response the
    // document already carries, and is added.
    let fixture = Fixture::new();
    let mut document = fixture.timestamped();
    assert_eq!(
        fixture
            .extend_with(&mut document, &CRLS[..1], &OCSP, false)
            .expect("B-LT over the OCSP response"),
        DataAdded::Published
    );
    let ocsp = roxmltree::Document::parse(document.as_xml())
        .expect("XML parses")
        .descendants()
        .filter(|node| node.tag_name().name() == "EncapsulatedOCSPValue")
        .count();
    assert_eq!(ocsp, 2, "both members' statuses are the OCSP responses");
    let before = crls(document.as_xml());
    assert_eq!(
        fixture
            .extend_with(&mut document, &NEXT_CRLS[1..], &[], true)
            .expect("refresh"),
        DataAdded::Published
    );
    assert_eq!(crls(document.as_xml()), before + 1);
}

#[test]
fn a_refresh_adds_the_fresher_statuses_a_complete_signature_lacks() {
    // EN 319 132-1 §5.5.2: a B-LT signature may take fresher validation data
    // before its next archive. Adding the missing data finds nothing once the
    // first CRLs are incorporated; a refresh takes each path member's status
    // from the caller's newer CRLs, adds them beside the old ones and keeps
    // B-LT, and a second refresh with the same CRLs adds nothing.
    let fixture = Fixture::new();
    let mut document = fixture.timestamped();
    assert_eq!(
        fixture.extend(&mut document, &CRLS, false).expect("B-LT"),
        DataAdded::Published
    );
    assert_eq!(crls(document.as_xml()), 2);
    let complete = document.as_xml().to_owned();
    assert_eq!(
        fixture
            .extend(&mut document, &NEXT_CRLS, false)
            .expect("nothing missing"),
        DataAdded::AlreadyPresent
    );
    assert_eq!(document.as_xml(), complete, "missing data only");
    assert_eq!(
        fixture
            .extend(&mut document, &NEXT_CRLS, true)
            .expect("refresh"),
        DataAdded::Published
    );
    assert_eq!(crls(document.as_xml()), 4, "both generations are carried");
    let refreshed = document.as_xml().to_owned();
    assert_eq!(
        fixture
            .extend(&mut document, &NEXT_CRLS, true)
            .expect("second refresh"),
        DataAdded::AlreadyPresent
    );
    assert_eq!(document.as_xml(), refreshed);
}
