//! Native latency of B-B creation, countersigning and validation over the
//! creation fixtures (RSA-SHA256, root -> intermediate -> signer). Each run
//! gets a fresh resource account and asserts its result, so no timing is
//! reported for a failing operation; preparing inputs is excluded.

use std::collections::BTreeMap;
use std::sync::Arc;

use structured_asn1::memory::{Memory, MemoryAccount};
use xml_sec::XmlDocument;
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::policy::{Instant, SigningPolicy, VerificationPolicy};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, KeyResolverConfig, RsaSigningKey, SignatureAlgorithm,
    UriTypeSet, VerificationRequest, VerifyContext, with_verified_request,
};
use xml_sec_xades::{
    Assessment, Countersignature, DataObject, Envelope, Outcome, Request, Signer, countersign,
    create, validate_basic,
};

const ROOT: &[u8] = include_bytes!("../tests/fixtures/creation/root.der");
const INTERMEDIATE: &[u8] = include_bytes!("../tests/fixtures/creation/intermediate.der");
const SIGNER: &[u8] = include_bytes!("../tests/fixtures/creation/signer.der");
const KEY: &str = include_str!("../tests/fixtures/creation/signer.key");
const TIME: &str = "2026-10-18T12:00:00Z";
const DOCUMENT: &str = "<Document><Data Id=\"payload\">Created payload</Data></Document>";

fn main() {
    divan::main();
}

fn account() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 26, 1 << 30)))
}

/// Everything one signer and its verifier need, built once per benchmark.
struct Setup {
    key: RsaSigningKey,
    signing: SigningPolicy,
    resolver: DefaultKeyResolver,
    verification: VerificationPolicy,
    resources: BTreeMap<String, Vec<u8>>,
}

impl Setup {
    fn new() -> Self {
        let mut signing = SigningPolicy::default();
        signing.uris.references = UriTypeSet::ALL;
        let mut verification = VerificationPolicy::default();
        verification.key_trust.verify_x509_chains = true;
        // Inside every fixture certificate's validity (2026-01-01 to 2045-01-01).
        verification.key_trust.verification_time = Instant::new(1_800_000_000, 0);
        verification.uris.references = UriTypeSet::ALL;
        Self {
            key: RsaSigningKey::from_pkcs8_pem(KEY).expect("fixture key"),
            signing,
            resolver: DefaultKeyResolver::new(KeyResolverConfig {
                trusted_certs: vec![ROOT.to_vec()],
                ..KeyResolverConfig::default()
            }),
            verification,
            resources: BTreeMap::new(),
        }
    }

    /// Run `operation` with this setup's signer and assessment.
    fn with<R>(&self, operation: impl FnOnce(&Signer<'_>, &Assessment<'_, '_>) -> R) -> R {
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
        let context = self.context();
        let request = self.request();
        let assessment = Assessment {
            context: &context,
            request: &request,
            certificates: &[ROOT],
        };
        operation(&signer, &assessment)
    }

    fn context(&self) -> VerifyContext<'_> {
        VerifyContext::new()
            .policy(self.verification.clone())
            .key_resolver(&self.resolver)
    }

    fn request(&self) -> VerificationRequest<'_> {
        VerificationRequest {
            external_resources: Some(&self.resources),
            ..VerificationRequest::default()
        }
    }
}

fn enveloped(id: &str) -> Request<'_> {
    Request {
        id,
        signing_time: TIME,
        objects: vec![DataObject::Document {
            mime_type: "text/xml",
            envelope: Envelope::ExcludingSignatures,
        }],
        parent: None,
        resources: None,
        id_attributes: &[],
    }
}

fn sign(setup: &Setup, document: &mut XmlDocument, work: &Memory) {
    setup
        .with(|signer, assessment| create(document, signer, enveloped("sig"), assessment, work))
        .expect("B-B creation");
}

fn countersigned(setup: &Setup, document: &mut XmlDocument, work: &Memory) {
    let countersignature = Countersignature {
        parent: "sig",
        id: "counter",
        signing_time: TIME,
        id_attributes: &[],
    };
    setup
        .with(|signer, assessment| {
            countersign(document, signer, &countersignature, assessment, work)
        })
        .expect("countersignature");
}

fn parse(xml: &str) -> XmlDocument {
    XmlDocument::parse(xml).expect("fixture document")
}

/// Enveloped B-B creation: signed properties, template, signing, then the
/// verification and B-B assessment that gate publication.
#[divan::bench]
fn create_enveloped(bencher: divan::Bencher) {
    let setup = Setup::new();
    let mut expected = parse(DOCUMENT);
    sign(&setup, &mut expected, &account());
    let expected = expected.into_xml();
    bencher
        .with_inputs(|| (parse(DOCUMENT), account()))
        .bench_local_values(|(mut document, work)| {
            sign(&setup, &mut document, &work);
            assert_eq!(document.as_xml(), expected);
            document
        });
}

/// Countersigning an existing B-B signature; both the countersignature and
/// its parent are assessed before publication.
#[divan::bench]
fn countersign_parent(bencher: divan::Bencher) {
    let setup = Setup::new();
    let mut parent = parse(DOCUMENT);
    sign(&setup, &mut parent, &account());
    let parent = parent.into_xml();
    let mut expected = parse(&parent);
    countersigned(&setup, &mut expected, &account());
    let expected = expected.into_xml();
    bencher
        .with_inputs(|| (parse(&parent), account()))
        .bench_local_values(|(mut document, work)| {
            countersigned(&setup, &mut document, &work);
            assert_eq!(document.as_xml(), expected);
            document
        });
}

/// Verification of every signature in the document followed by the B-B
/// assessment of the selected one, over a retained parsed document.
#[divan::bench(args = ["sig", "counter"])]
fn validate(bencher: divan::Bencher, id: &str) {
    let setup = Setup::new();
    let mut document = parse(DOCUMENT);
    sign(&setup, &mut document, &account());
    countersigned(&setup, &mut document, &account());
    let context = setup.context();
    let request = setup.request();
    bencher.with_inputs(account).bench_local_values(|work| {
        let met = with_verified_request(&document, &context, &request, &work, |session| {
            assert!(session.evidence().accepted(&document)?);
            let signature = session
                .view()
                .node_for_id(id, &[])
                .expect("signature has its ID");
            Ok(validate_basic(&session, signature, &[ROOT], |report| {
                report.all_root_requirements_met()
            }))
        })
        .expect("document verifies")
        .expect("B-B assessment completes");
        assert!(matches!(met, Outcome::Assessed(true)));
        work
    });
}
