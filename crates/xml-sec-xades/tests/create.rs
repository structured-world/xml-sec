//! B-B creation and countersigning through the public entry points.
//!
//! The fixtures under `creation/` come from `xml-sec-tools xades fixtures
//! --creation`: OpenSSL issues a root -> intermediate -> signer path and keeps
//! the signer's key. Every created document is checked again by an independent
//! verification and B-B assessment, not only by the creation's own result.

#![cfg(feature = "produce")]

use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
use xml_sec::XmlDocument;
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::policy::{Instant, SigningPolicy, VerificationPolicy};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, KeyInfoWriteError, KeyResolverConfig, ObjectContent,
    ObjectElement, RsaSigningKey, SignatureAlgorithm, SigningError, UriTypeSet,
    VerificationRequest, VerifyContext, with_verified_request,
};
use xml_sec_xades::{
    Assessment, Countersignature, CreateError, DataObject, DraftError, Envelope, Outcome, Request,
    Signer, countersign, create, validate_basic,
};

const ROOT: &[u8] = include_bytes!("fixtures/creation/root.der");
const INTERMEDIATE: &[u8] = include_bytes!("fixtures/creation/intermediate.der");
const SIGNER: &[u8] = include_bytes!("fixtures/creation/signer.der");
const KEY: &str = include_str!("fixtures/creation/signer.key");
const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";
const TIME: &str = "2026-10-18T12:00:00Z";
const DOCUMENT: &str = "<Document><Data Id=\"payload\">Created payload</Data></Document>";

fn account_of(memory: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(memory, work)))
}

fn account(work: usize) -> Memory {
    account_of(1 << 24, work)
}

fn signing_policy() -> SigningPolicy {
    let mut policy = SigningPolicy::default();
    policy.uris.references = UriTypeSet::ALL;
    policy
}

fn verification_policy() -> VerificationPolicy {
    let mut policy = VerificationPolicy::default();
    policy.key_trust.verify_x509_chains = true;
    // Inside every fixture certificate's validity (2026-01-01 to 2045-01-01).
    policy.key_trust.verification_time = Instant::new(500_000 * 3600, 0);
    policy.uris.references = UriTypeSet::ALL;
    policy
}

fn anchored(root: &[u8]) -> DefaultKeyResolver {
    DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: vec![root.to_vec()],
        ..KeyResolverConfig::default()
    })
}

fn c14n() -> C14nAlgorithm {
    C14nAlgorithm::new(C14nMode::Exclusive1_0, false)
}

/// Everything one creation needs, owned by the test.
struct Fixture {
    key: RsaSigningKey,
    policy: SigningPolicy,
    resolver: DefaultKeyResolver,
    context_policy: VerificationPolicy,
    resources: BTreeMap<String, Vec<u8>>,
}

impl Fixture {
    fn new() -> Self {
        Self {
            key: RsaSigningKey::from_pkcs8_pem(KEY).expect("fixture key parses"),
            policy: signing_policy(),
            resolver: anchored(ROOT),
            context_policy: verification_policy(),
            resources: BTreeMap::from([(
                "detached.txt".to_owned(),
                b"Detached payload\n".to_vec(),
            )]),
        }
    }

    fn signer<'a>(&'a self, chain: &'a [&'a [u8]]) -> Signer<'a> {
        Signer {
            key: &self.key,
            provider: xml_sec::provider::default_provider(),
            policy: &self.policy,
            chain,
            method: SignatureAlgorithm::RsaSha256,
            digest: DigestAlgorithm::Sha256,
            canonicalization: c14n(),
        }
    }

    /// Run `operation` with an assessment anchored at `root`.
    fn with_assessment<R>(
        &self,
        resolver: &DefaultKeyResolver,
        operation: impl FnOnce(&Assessment<'_, '_>) -> R,
    ) -> R {
        let context = VerifyContext::new()
            .policy(self.context_policy.clone())
            .key_resolver(resolver);
        let request = VerificationRequest {
            external_resources: Some(&self.resources),
            ..VerificationRequest::default()
        };
        operation(&Assessment {
            context: &context,
            request: &request,
            certificates: &[ROOT],
        })
    }

    fn create(&self, document: &mut XmlDocument, request: Request<'_>) -> Result<(), CreateError> {
        self.create_with(
            document,
            request,
            &[SIGNER, INTERMEDIATE],
            &self.resolver,
            1 << 30,
        )
    }

    fn create_with(
        &self,
        document: &mut XmlDocument,
        request: Request<'_>,
        chain: &[&[u8]],
        resolver: &DefaultKeyResolver,
        work: usize,
    ) -> Result<(), CreateError> {
        self.with_assessment(resolver, |assessment| {
            create(
                document,
                &self.signer(chain),
                request,
                assessment,
                &account(work),
            )
        })
    }

    fn countersign(
        &self,
        document: &mut XmlDocument,
        countersignature: &Countersignature<'_>,
    ) -> Result<(), CreateError> {
        self.with_assessment(&self.resolver, |assessment| {
            countersign(
                document,
                &self.signer(&[SIGNER, INTERMEDIATE]),
                countersignature,
                assessment,
                &account(1 << 30),
            )
        })
    }

    /// An independent verification and B-B assessment of signature `id`.
    fn meets_basic(&self, xml: &str, id: &str) -> bool {
        let document = XmlDocument::parse(xml).expect("created XML parses");
        let context = VerifyContext::new()
            .policy(self.context_policy.clone())
            .key_resolver(&self.resolver);
        let request = VerificationRequest {
            external_resources: Some(&self.resources),
            ..VerificationRequest::default()
        };
        with_verified_request(
            &document,
            &context,
            &request,
            &account(1 << 30),
            |session| {
                // Every signature in the document, countersignatures included,
                // must verify, not only the assessed one.
                assert!(session.evidence().accepted(&document)?);
                let signature = session
                    .view()
                    .node_for_id(id, &[])
                    .expect("signature has its ID");
                Ok(validate_basic(&session, signature, &[ROOT], |report| {
                    report.all_root_requirements_met()
                }))
            },
        )
        .expect("created document verifies")
        .map(|outcome| matches!(outcome, Outcome::Assessed(true)))
        .expect("B-B assessment completes")
    }
}

fn request<'a>(id: &'a str, objects: &[DataObject<'a>]) -> Request<'a> {
    Request {
        id,
        signing_time: TIME,
        objects: objects.to_vec(),
        parent: None,
        resources: None,
        id_attributes: &[],
    }
}

fn enveloped(envelope: Envelope) -> [DataObject<'static>; 1] {
    [DataObject::Document {
        mime_type: "text/xml",
        envelope,
    }]
}

fn parse(xml: &str) -> roxmltree::Document<'_> {
    roxmltree::Document::parse(xml).expect("XML parses")
}

#[test]
fn every_packaging_mode_meets_basic() {
    // EN 319 132-1 §6.3 B-B for enveloped, enveloping, internally detached
    // and detached data, checked by an assessment independent of creation.
    let fixture = Fixture::new();
    let element = ObjectElement::parse("<Data>Enveloped object</Data>", &fixture.policy)
        .expect("valid object element");
    let cases: Vec<(&str, Vec<DataObject<'_>>)> = vec![
        ("enveloped", enveloped(Envelope::Enveloped).to_vec()),
        (
            "excluding",
            enveloped(Envelope::ExcludingSignatures).to_vec(),
        ),
        (
            "enveloping",
            vec![
                DataObject::Enveloping {
                    content: ObjectContent::Text("Enveloping text".to_owned()),
                    mime_type: "text/plain",
                },
                DataObject::Enveloping {
                    content: ObjectContent::Element(element),
                    mime_type: "text/xml",
                },
            ],
        ),
        (
            "internal",
            vec![DataObject::Element {
                id: "payload",
                mime_type: "text/xml",
            }],
        ),
        (
            "detached",
            vec![DataObject::Detached {
                uri: "detached.txt",
                mime_type: "text/plain",
            }],
        ),
    ];
    for (id, objects) in &cases {
        let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
        let start = document.generation();
        let request = Request {
            resources: Some(&fixture.resources),
            ..request(id, objects)
        };
        fixture
            .create(&mut document, request)
            .unwrap_or_else(|error| panic!("{id}: {error}"));
        assert!(document.generation() > start, "{id}: a new generation");
        assert!(fixture.meets_basic(document.as_xml(), id), "{id}: B-B");
        let created = parse(document.as_xml());
        let formats = created
            .descendants()
            .filter(|node| node.has_tag_name((XADES, "DataObjectFormat")))
            .count();
        assert_eq!(formats, objects.len(), "{id}: one format per object");
    }
}

#[test]
fn the_signing_certificate_is_bound_and_carried() {
    // §5.2.2 SigningCertificateV2 digests the complete certificate and §6.3(a)
    // requires the certificate itself in KeyInfo.
    let fixture = Fixture::new();
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    fixture
        .create(
            &mut document,
            request("sig", &enveloped(Envelope::Enveloped)),
        )
        .expect("creation succeeds");
    let created = parse(document.as_xml());
    let carried: Vec<_> = created
        .descendants()
        .filter(|node| node.has_tag_name((DS, "X509Certificate")))
        .map(|node| node.text().expect("certificate text").to_owned())
        .collect();
    let encode = |der| STANDARD.encode(der);
    assert_eq!(carried, [encode(SIGNER), encode(INTERMEDIATE)]);
    let time = created
        .descendants()
        .find(|node| node.has_tag_name((XADES, "SigningTime")))
        .and_then(|node| node.text());
    assert_eq!(time, Some(TIME));
    let value = created
        .descendants()
        .find(|node| node.has_tag_name((DS, "SignatureValue")))
        .expect("SignatureValue");
    assert_eq!(value.attribute("Id"), Some("sig-value"));
}

#[test]
fn parallel_signatures_that_exclude_each_other_both_meet_basic() {
    // Signatures over the whole document leave each other out with the
    // XPath filter, so each stays valid when the other is added.
    let fixture = Fixture::new();
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    let objects = enveloped(Envelope::ExcludingSignatures);
    for id in ["first", "second"] {
        fixture
            .create(&mut document, request(id, &objects))
            .unwrap_or_else(|error| panic!("{id}: {error}"));
    }
    for id in ["first", "second"] {
        assert!(fixture.meets_basic(document.as_xml(), id), "{id}: B-B");
    }
}

#[test]
fn a_signature_that_would_break_an_earlier_one_is_not_published() {
    // The first signature's enveloped reference covers everything but itself,
    // so a second signature changes what the first signs. The signed
    // generation no longer satisfies the request that every signature
    // verifies, and nothing is published.
    let fixture = Fixture::new();
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    fixture
        .create(
            &mut document,
            request("first", &enveloped(Envelope::Enveloped)),
        )
        .expect("first signature");
    let before = document.as_xml().to_owned();
    let generation = document.generation();
    let result = fixture.create(
        &mut document,
        request("second", &enveloped(Envelope::ExcludingSignatures)),
    );
    assert!(
        matches!(result, Err(CreateError::NotAccepted)),
        "{result:?}"
    );
    assert_eq!(document.as_xml(), before);
    assert_eq!(document.generation(), generation);
}

#[test]
fn a_countersignature_meets_basic_with_its_parent() {
    // §5.2.7.2: the countersignature signs the parent's SignatureValue and
    // sits in the parent's unsigned signature properties; it verifies, and the
    // parent's B-B assessment binds its path, key and hash use.
    let fixture = Fixture::new();
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    fixture
        .create(
            &mut document,
            request("sig", &enveloped(Envelope::ExcludingSignatures)),
        )
        .expect("parent signature");
    fixture
        .countersign(
            &mut document,
            &Countersignature {
                parent: "sig",
                id: "counter",
                signing_time: TIME,
                id_attributes: &[],
            },
        )
        .expect("countersignature");
    assert!(fixture.meets_basic(document.as_xml(), "sig"));
    // Selected itself, the countersignature is a B-B signature too: its
    // countersigned-value reference is exempt from DataObjectFormat (§6.3(k))
    // through the binding to the SignatureValue it covers.
    assert!(fixture.meets_basic(document.as_xml(), "counter"));
    let created = parse(document.as_xml());
    let counter = created
        .descendants()
        .find(|node| node.has_tag_name((XADES, "CounterSignature")))
        .expect("CounterSignature");
    assert_eq!(
        counter.parent().map(|node| node.tag_name().name()),
        Some("UnsignedSignatureProperties")
    );
    let reference = counter
        .descendants()
        .find(|node| {
            node.has_tag_name((DS, "Reference"))
                && node.attribute("Type")
                    == Some("http://uri.etsi.org/01903#CountersignedSignature")
        })
        .expect("countersigned reference");
    assert_eq!(reference.attribute("URI"), Some("#sig-value"));
}

#[test]
fn a_second_countersignature_follows_the_first() {
    // A new unsigned property is appended after the existing ones.
    let fixture = Fixture::new();
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    fixture
        .create(
            &mut document,
            request("sig", &enveloped(Envelope::ExcludingSignatures)),
        )
        .expect("parent signature");
    for id in ["counter-a", "counter-b"] {
        fixture
            .countersign(
                &mut document,
                &Countersignature {
                    parent: "sig",
                    id,
                    signing_time: TIME,
                    id_attributes: &[],
                },
            )
            .unwrap_or_else(|error| panic!("{id}: {error}"));
    }
    let created = parse(document.as_xml());
    let order: Vec<_> = created
        .descendants()
        .filter(|node| node.has_tag_name((XADES, "CounterSignature")))
        .filter_map(|node| node.first_element_child()?.attribute("Id"))
        .collect();
    assert_eq!(order, ["counter-a", "counter-b"]);
    assert!(fixture.meets_basic(document.as_xml(), "sig"));
}

#[test]
fn signature_properties_precede_existing_data_object_properties() {
    // §4.3 orders UnsignedSignatureProperties before
    // UnsignedDataObjectProperties; the new container is inserted before it.
    let fixture = Fixture::new();
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    fixture
        .create(
            &mut document,
            request("sig", &enveloped(Envelope::ExcludingSignatures)),
        )
        .expect("parent signature");
    // Unsigned properties are outside what the signature signs.
    let xml = document.as_xml().replace(
        "</xades:SignedProperties>",
        &format!(
            "</xades:SignedProperties><xades:UnsignedProperties xmlns:xades=\"{XADES}\"><xades:UnsignedDataObjectProperties><xades:UnsignedDataObjectProperty>note</xades:UnsignedDataObjectProperty></xades:UnsignedDataObjectProperties></xades:UnsignedProperties>"
        ),
    );
    let mut document = XmlDocument::parse(xml).expect("augmented fixture parses");
    fixture
        .countersign(
            &mut document,
            &Countersignature {
                parent: "sig",
                id: "counter",
                signing_time: TIME,
                id_attributes: &[],
            },
        )
        .expect("countersignature");
    let created = parse(document.as_xml());
    let unsigned = created
        .descendants()
        .find(|node| node.has_tag_name((XADES, "UnsignedProperties")))
        .expect("UnsignedProperties");
    let children: Vec<_> = unsigned
        .children()
        .filter(roxmltree::Node::is_element)
        .map(|node| node.tag_name().name())
        .collect();
    assert_eq!(
        children,
        [
            "UnsignedSignatureProperties",
            "UnsignedDataObjectProperties"
        ]
    );
    assert!(fixture.meets_basic(document.as_xml(), "sig"));
}

/// Assert that `operation` failed with `matches` and left `document` as it was.
fn refused(
    document: &mut XmlDocument,
    operation: impl FnOnce(&mut XmlDocument) -> Result<(), CreateError>,
    matches: impl FnOnce(&CreateError) -> bool,
) {
    let before = document.as_xml().to_owned();
    let generation = document.generation();
    let result = operation(document);
    match &result {
        Err(error) if matches(error) => {}
        other => panic!("unexpected result {other:?}"),
    }
    assert_eq!(document.as_xml(), before, "the document is unchanged");
    assert_eq!(
        document.generation(),
        generation,
        "no generation is published"
    );
}

#[test]
fn a_certificate_without_the_signing_key_is_refused() {
    // The intermediate certificate does not hold the signer's key, so it
    // cannot be presented as the signing certificate.
    let fixture = Fixture::new();
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    refused(
        &mut document,
        |document| {
            fixture.create_with(
                document,
                request("sig", &enveloped(Envelope::Enveloped)),
                &[INTERMEDIATE],
                &fixture.resolver,
                1 << 30,
            )
        },
        |error| {
            matches!(
                error,
                CreateError::Signing(SigningError::KeyInfo(
                    KeyInfoWriteError::CertificateKeyMismatch
                ))
            )
        },
    );
}

#[test]
fn malformed_inputs_are_refused_without_a_partial_signature() {
    let fixture = Fixture::new();
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    let objects = enveloped(Envelope::Enveloped);
    // An ID the document already declares, directly or as a derived part.
    for id in ["payload", "sig"] {
        let mut taken = XmlDocument::parse(
            "<Document><Data Id=\"payload\"/><Other Id=\"sig-value\"/></Document>",
        )
        .expect("fixture parses");
        refused(
            &mut taken,
            |document| fixture.create(document, request(id, &objects)),
            |error| matches!(error, CreateError::IdInUse(_)),
        );
    }
    // XSD 1.0 §3.2.7: a time without a timezone is not an instant.
    refused(
        &mut document,
        |document| {
            fixture.create(
                document,
                Request {
                    signing_time: "2026-10-18T12:00:00",
                    ..request("sig", &objects)
                },
            )
        },
        |error| {
            matches!(
                error,
                CreateError::Properties(structured_xades::produce::Error::Writer(
                    DraftError::Value { .. }
                ))
            )
        },
    );
    // A MIME type outside RFC 2045 syntax is refused by the shared rules.
    refused(
        &mut document,
        |document| {
            fixture.create(
                document,
                request(
                    "sig",
                    &[DataObject::Document {
                        mime_type: "not a type",
                        envelope: Envelope::Enveloped,
                    }],
                ),
            )
        },
        |error| {
            matches!(
                error,
                CreateError::Properties(structured_xades::produce::Error::Value(_))
            )
        },
    );
    refused(
        &mut document,
        |document| fixture.create(document, request("sig", &[])),
        |error| matches!(error, CreateError::NoDataObject),
    );
    refused(
        &mut document,
        |document| {
            fixture.create_with(
                document,
                request("sig", &objects),
                &[],
                &fixture.resolver,
                1 << 30,
            )
        },
        |error| matches!(error, CreateError::EmptyChain),
    );
}

#[test]
fn a_signature_without_a_trusted_path_is_not_published() {
    // The assessment requires a validated signer path; anchored at the root
    // of another chain, the signed generation is not accepted or not B-B.
    let fixture = Fixture::new();
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    let elsewhere = anchored(include_bytes!("fixtures/root.der"));
    refused(
        &mut document,
        |document| {
            fixture.create_with(
                document,
                request("sig", &enveloped(Envelope::Enveloped)),
                &[SIGNER, INTERMEDIATE],
                &elsewhere,
                1 << 30,
            )
        },
        |error| {
            matches!(
                error,
                CreateError::NotAccepted
                    | CreateError::Verification(_)
                    | CreateError::Unmet(Outcome::Path { .. })
            )
        },
    );
}

/// Create under every account from `start` upward, growing by a third: below
/// what creation needs each refusal leaves the document as it was, and once a
/// ceiling succeeds every larger one does.
fn scan_ceilings(start: usize, limit: usize, account: impl Fn(usize) -> Memory) {
    let fixture = Fixture::new();
    let mut succeeded = false;
    let mut ceiling = start;
    while ceiling <= limit {
        let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
        let result = fixture.with_assessment(&fixture.resolver, |assessment| {
            create(
                &mut document,
                &fixture.signer(&[SIGNER, INTERMEDIATE]),
                request("sig", &enveloped(Envelope::Enveloped)),
                assessment,
                &account(ceiling),
            )
        });
        match result {
            Ok(()) => succeeded = true,
            Err(error) => {
                assert!(!succeeded, "a larger ceiling {ceiling} failed: {error}");
                assert_eq!(document.as_xml(), DOCUMENT, "{ceiling}: {error}");
                assert_eq!(document.generation(), 0, "{ceiling}: {error}");
            }
        }
        ceiling += ceiling / 3 + 1;
    }
    assert!(succeeded, "the largest ceiling completes");
}

#[test]
fn every_work_ceiling_publishes_all_or_nothing() {
    // Construction, signing and assessment all spend the caller's work; a
    // refusal at any of them publishes nothing.
    scan_ceilings(0, 1 << 26, |work| account_of(1 << 24, work));
}

#[test]
fn every_storage_ceiling_publishes_all_or_nothing() {
    // The same scan over retained storage, the property draft included.
    scan_ceilings(0, 1 << 24, |memory| account_of(memory, 1 << 30));
}

#[test]
fn a_refused_draft_reports_its_resource_cause() {
    // A work refusal inside the property draft keeps its original class.
    let fixture = Fixture::new();
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    refused(
        &mut document,
        |document| {
            fixture.with_assessment(&fixture.resolver, |assessment| {
                create(
                    document,
                    &fixture.signer(&[SIGNER, INTERMEDIATE]),
                    request("sig", &enveloped(Envelope::Enveloped)),
                    assessment,
                    &account_of(1 << 24, 0),
                )
            })
        },
        |error| {
            matches!(
                error,
                CreateError::Certificate(_)
                    | CreateError::Resource(MemoryError::WorkExceeded)
                    | CreateError::Properties(
                        structured_xades::produce::Error::Resource(MemoryError::WorkExceeded)
                            | structured_xades::produce::Error::Writer(DraftError::Resource(
                                MemoryError::WorkExceeded
                            ))
                    )
            )
        },
    );
}

#[test]
fn a_parent_that_cannot_be_countersigned_is_refused() {
    let fixture = Fixture::new();
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    fixture
        .create(
            &mut document,
            request("sig", &enveloped(Envelope::ExcludingSignatures)),
        )
        .expect("parent signature");
    let counter = |parent| Countersignature {
        parent,
        id: "counter",
        signing_time: TIME,
        id_attributes: &[],
    };
    refused(
        &mut document,
        |document| fixture.countersign(document, &counter("absent")),
        |error| matches!(error, CreateError::UnknownSignature(_)),
    );
    refused(
        &mut document,
        |document| fixture.countersign(document, &counter("payload")),
        |error| matches!(error, CreateError::UnknownSignature(_)),
    );
    // Without a SignatureValue ID the reference would need new bytes in a
    // value that timestamps may already cover.
    let mut without_id = XmlDocument::parse(document.as_xml().replace(
        "<ds:SignatureValue Id=\"sig-value\">",
        "<ds:SignatureValue>",
    ))
    .expect("fixture parses");
    refused(
        &mut without_id,
        |document| fixture.countersign(document, &counter("sig")),
        |error| matches!(error, CreateError::Uncountersignable(_)),
    );
    // A plain XML signature has no qualifying properties to extend.
    let mut plain = XmlDocument::parse(
        document
            .as_xml()
            .replace("Target=\"#sig\"", "Target=\"#elsewhere\""),
    )
    .expect("fixture parses");
    refused(
        &mut plain,
        |document| fixture.countersign(document, &counter("sig")),
        |error| matches!(error, CreateError::NotXades(_)),
    );
}
