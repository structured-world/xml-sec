//! Native latency of B-T augmentation over the augmentation fixtures
//! (RSA-SHA256 signer and an OpenSSL TSA under one root). Each run gets a
//! fresh resource account and asserts its result; creating the B-B signature
//! and the pending request is excluded.

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
use xml_sec_xades::{
    Assessment, Completion, DataObject, Envelope, Inputs, PendingTimestamp, Request, Requirements,
    Signer, TimestampRequest, complete_timestamp, create, request_timestamp,
};

const ROOT: &[u8] = include_bytes!("../tests/fixtures/augmentation/root.der");
const INTERMEDIATE: &[u8] = include_bytes!("../tests/fixtures/augmentation/intermediate.der");
const SIGNER: &[u8] = include_bytes!("../tests/fixtures/augmentation/signer.der");
const KEY: &str = include_str!("../tests/fixtures/augmentation/signer.key");
const REQUEST: &[u8] = include_bytes!("../tests/fixtures/augmentation/request.tsq");
const RESPONSE: &[u8] = include_bytes!("../tests/fixtures/augmentation/response.tsr");
const DOCUMENT: &str = "<Document><Data Id=\"payload\">Augmented payload</Data></Document>";
const TIME: &str = "2026-10-18T12:00:00Z";
const NONCE: &[u8] = &[0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71];

fn main() {
    divan::main();
}

fn account() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 26, 1 << 30)))
}

/// Everything the signer, the verifier and the TSA check need.
struct Setup {
    key: RsaSigningKey,
    signing: SigningPolicy,
    resolver: DefaultKeyResolver,
    verification: VerificationPolicy,
    utc: LeapTable<'static>,
}

impl Setup {
    fn new() -> Self {
        let mut signing = SigningPolicy::default();
        signing.uris.references = UriTypeSet::ALL;
        let mut verification = VerificationPolicy::default();
        verification.key_trust.verify_x509_chains = true;
        // After the fixture token and inside every certificate's validity.
        verification.key_trust.verification_time = Instant::new(1_800_000_000, 0);
        Self {
            key: RsaSigningKey::from_pkcs8_pem(KEY).expect("fixture key"),
            signing,
            resolver: DefaultKeyResolver::new(KeyResolverConfig {
                trusted_certs: vec![ROOT.to_vec()],
                ..KeyResolverConfig::default()
            }),
            verification,
            utc: LeapTable::new(-2_208_988_800, 4_102_444_800, &[]).expect("UTC coverage"),
        }
    }

    fn with<R>(&self, operation: impl FnOnce(&Assessment<'_, '_>) -> R) -> R {
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

    /// The enveloped B-B signature the fixture request was made over.
    fn created(&self) -> XmlDocument {
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
        let mut document = XmlDocument::parse(DOCUMENT).expect("fixture document");
        self.with(|assessment| {
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
        })
        .expect("B-B creation");
        document
    }

    fn request(&self, document: &XmlDocument, work: &Memory) -> PendingTimestamp {
        self.with(|assessment| {
            request_timestamp(
                document,
                &TimestampRequest {
                    signature: "sig",
                    digest: Algorithm::Sha256,
                    policy: None,
                    nonce: Some(NONCE),
                    id_attributes: &[],
                },
                assessment,
                work,
            )
        })
        .expect("timestamp request")
    }
}

/// The B-B assessment that gates a request, the `SignatureTimeStamp` input
/// and its digest, and the DER request.
#[divan::bench]
fn request_signature_timestamp(bencher: divan::Bencher) {
    let setup = Setup::new();
    let document = setup.created();
    bencher.with_inputs(account).bench_local_values(|work| {
        let pending = setup.request(&document, &work);
        assert_eq!(pending.request(), REQUEST);
        (pending, work)
    });
}

/// Checking the TSA response against the request and the input, staging the
/// property, and the verification and B-T assessment that gate publication.
#[divan::bench]
fn complete_signature_timestamp(bencher: divan::Bencher) {
    let setup = Setup::new();
    let anchors: [&[u8]; 1] = [ROOT];
    let certificates: [&[u8]; 1] = [INTERMEDIATE];
    let inputs = Inputs {
        requirements: Requirements::Timestamped,
        anchors: &anchors,
        certificates: &certificates,
        utc: &setup.utc,
        accuracies: &[],
        responders: &[],
        crls: &[],
        responses: &[],
    };
    bencher
        .with_inputs(|| {
            let document = setup.created();
            let pending = setup.request(&document, &account());
            (document, pending, account())
        })
        .bench_local_values(|(mut document, pending, work)| {
            let generation = document.generation();
            setup
                .with(|assessment| {
                    complete_timestamp(
                        &mut document,
                        &pending,
                        RESPONSE,
                        &Completion {
                            assessment,
                            inputs: &inputs,
                            window: None,
                            id_attributes: &[],
                        },
                        &work,
                    )
                })
                .expect("B-T completion");
            assert!(document.generation() > generation);
            (document, pending, work)
        });
}
