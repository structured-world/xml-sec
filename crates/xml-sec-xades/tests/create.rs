//! B-B creation and countersigning through the public entry points.
//!
//! The fixtures under `creation/` come from `xml-sec-tools xades fixtures
//! --creation`: OpenSSL issues a root -> intermediate -> signer path and keeps
//! the signer's key. Every created document is checked again by an independent
//! verification and B-B assessment, not only by the creation's own result.

#![cfg(feature = "produce")]

use std::collections::BTreeMap;
use std::sync::Arc;

use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
use xml_sec::XmlDocument;
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::document::{NodeIdentity, XmlDocumentError};
use xml_sec::policy::{Instant, ManifestProcessing, SigningPolicy, VerificationPolicy};
use xml_sec::xmldsig::extension;
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, KeyInfoWriteError, KeyResolverConfig, ObjectContent,
    ObjectElement, RsaSigningKey, SignatureAlgorithm, SigningError, Transform, UriTypeSet,
    VerificationRequest, VerifyContext, XPathExpression, XPathFilter, XPathFilterOperation,
    with_verified_request,
};
use xml_sec_xades::{
    Assessment, Countersignature, CreateError, DataObject, DraftError, Envelope, ManifestEntry,
    Outcome, Placement, Prefixes, Request, Signer, countersign, create, validate_basic,
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
            prefixes: Prefixes::default(),
        }
    }

    /// Run `operation` with an assessment anchored at `root`.
    fn with_assessment<R>(
        &self,
        resolver: &DefaultKeyResolver,
        operation: impl FnOnce(&Assessment<'_, '_>) -> R,
    ) -> R {
        self.with_targets(resolver, &[], operation)
    }

    /// [`Self::with_assessment`] whose request also expects these elements
    /// of the document's current generation to be covered.
    fn with_targets<R>(
        &self,
        resolver: &DefaultKeyResolver,
        targets: &[NodeIdentity],
        operation: impl FnOnce(&Assessment<'_, '_>) -> R,
    ) -> R {
        let context = VerifyContext::new()
            .policy(self.context_policy.clone())
            .key_resolver(resolver);
        let request = VerificationRequest {
            expected_targets: targets,
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
        placement: Placement::DocumentEnd,
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
fn references_the_caller_composes_meet_basic() {
    // XMLDSig 1.1 §4.4.3.1/§6.6: a reference keeps the URI and transforms the
    // caller gives, in order; each document is assessed independently, and the
    // written Transforms are the ones requested.
    let fixture = Fixture::new();
    let exclusive = || Transform::C14n(c14n());
    let filter = |operation, expression: &str| {
        XPathFilter::new(
            operation,
            XPathExpression::new(expression).with_namespace("ds", DS),
        )
    };
    let cases: Vec<(&str, Vec<Transform>, &str, Vec<&str>)> = vec![
        (
            "filter2",
            vec![
                Transform::XPathFilter2(vec![filter(
                    XPathFilterOperation::Subtract,
                    "/descendant::ds:Signature",
                )]),
                exclusive(),
            ],
            "",
            vec![XPATH_FILTER2_URI, EXCLUSIVE],
        ),
        (
            "xpath",
            vec![
                Transform::XPath(
                    XPathExpression::new("not(ancestor-or-self::ds:Signature)")
                        .with_namespace("ds", DS),
                ),
                exclusive(),
            ],
            "",
            vec![XPATH_URI, EXCLUSIVE],
        ),
        (
            // A chain ending in a node set gains the explicit Exclusive C14N
            // the default signing policy generates (XMLDSig 1.1 §4.4.3.2).
            "enveloped-only",
            vec![Transform::Enveloped],
            "",
            vec![ENVELOPED, EXCLUSIVE],
        ),
        ("by-id", Vec::new(), "#payload", vec![EXCLUSIVE]),
        (
            "with-comments",
            vec![Transform::C14n(C14nAlgorithm::new(
                C14nMode::Exclusive1_0,
                true,
            ))],
            "#xpointer(id('payload'))",
            vec![EXCLUSIVE_WITH_COMMENTS],
        ),
    ];
    for (id, transforms, uri, written) in cases {
        let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
        let objects = [DataObject::Reference {
            uri,
            transforms,
            mime_type: "text/xml",
        }];
        fixture
            .create(&mut document, request(id, &objects))
            .unwrap_or_else(|error| panic!("{id}: {error}"));
        assert!(fixture.meets_basic(document.as_xml(), id), "{id}: B-B");
        let created = parse(document.as_xml());
        let reference = created
            .descendants()
            .find(|node| node.has_tag_name((DS, "Reference")))
            .expect("the data reference comes first");
        assert_eq!(reference.attribute("URI"), Some(uri), "{id}: URI");
        let algorithms: Vec<&str> = reference
            .descendants()
            .filter(|node| node.has_tag_name((DS, "Transform")))
            .filter_map(|node| node.attribute("Algorithm"))
            .collect();
        assert_eq!(algorithms, written, "{id}: transforms");
    }
}

#[test]
fn a_reference_with_comments_signs_the_comments_of_its_data() {
    // XML-C14N 1.0 §1.1 / Exc-C14N §3: a URI naming the element by XPointer
    // keeps its comments, and #WithComments canonicalization signs them, so a
    // changed comment breaks the reference.
    const COMMENTED: &str =
        "<Document><Data Id=\"payload\">Created <!--signed note--> payload</Data></Document>";
    let fixture = Fixture::new();
    let mut document = XmlDocument::parse(COMMENTED).expect("fixture parses");
    let objects = [DataObject::Reference {
        uri: "#xpointer(id('payload'))",
        transforms: vec![Transform::C14n(C14nAlgorithm::new(
            C14nMode::Exclusive1_0,
            true,
        ))],
        mime_type: "text/xml",
    }];
    fixture
        .create(&mut document, request("sig", &objects))
        .expect("creation with a commented reference");
    assert!(fixture.meets_basic(document.as_xml(), "sig"), "B-B");
    let accepted = |xml: &str| {
        let account = account(1 << 30);
        let parsed = XmlDocument::parse(xml).expect("XML parses");
        let context = VerifyContext::new()
            .policy(fixture.context_policy.clone())
            .key_resolver(&fixture.resolver);
        let request = VerificationRequest {
            external_resources: Some(&fixture.resources),
            ..VerificationRequest::default()
        };
        with_verified_request(&parsed, &context, &request, &account, |session| {
            session.evidence().accepted(&parsed)
        })
        .expect("the document is read")
    };
    assert!(accepted(document.as_xml()), "the created document verifies");
    let tampered = document
        .as_xml()
        .replacen("<!--signed note-->", "<!--changed note-->", 1);
    assert_ne!(tampered, document.as_xml(), "the comment was kept");
    assert!(
        !accepted(&tampered),
        "a changed comment breaks the reference"
    );
}

#[test]
fn objects_the_caller_names_meet_basic_and_their_ids_must_be_free() {
    // XMLDSig 1.1 §4.5/§6.6.2: an Object with the caller's Id, MimeType and
    // Encoding, signed through a reference to that Id with the caller's
    // transforms: base64 content decoded before the digest, and XML content
    // canonicalized. An Id the document already declares is refused before
    // anything is published.
    let fixture = Fixture::new();
    let element = ObjectElement::parse("<Data>Named object</Data>", &fixture.policy)
        .expect("valid object element");
    let objects = [
        DataObject::Object {
            id: "image",
            content: ObjectContent::Text("SGVsbG8gYmFzZTY0".to_owned()),
            encoding: Some("http://www.w3.org/2000/09/xmldsig#base64"),
            transforms: vec![Transform::Base64Decode],
            mime_type: "image/png",
        },
        DataObject::Object {
            id: "xml",
            content: ObjectContent::Element(element),
            encoding: None,
            transforms: vec![Transform::C14n(c14n())],
            mime_type: "text/xml",
        },
    ];
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    fixture
        .create(&mut document, request("sig", &objects))
        .expect("creation with named objects");
    assert!(fixture.meets_basic(document.as_xml(), "sig"), "B-B");
    let created = parse(document.as_xml());
    let image = created
        .descendants()
        .find(|node| node.has_tag_name((DS, "Object")) && node.attribute("Id") == Some("image"))
        .expect("the named object");
    assert_eq!(image.attribute("MimeType"), Some("image/png"));
    assert_eq!(
        image.attribute("Encoding"),
        Some("http://www.w3.org/2000/09/xmldsig#base64")
    );
    let taken = [DataObject::Object {
        id: "payload",
        content: ObjectContent::Text("text".to_owned()),
        encoding: None,
        transforms: Vec::new(),
        mime_type: "text/plain",
    }];
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    let error = fixture
        .create(&mut document, request("sig", &taken))
        .expect_err("the document already declares payload");
    assert!(
        matches!(error, CreateError::IdInUse(ref id) if id == "payload"),
        "{error}"
    );
    assert_eq!(document.as_xml(), DOCUMENT, "nothing published");
}

#[test]
fn a_manifest_of_detached_data_is_signed_with_its_digests_filled() {
    // XMLDSig 1.1 §5.1: the signature signs a Manifest, typed as one, whose
    // own references name detached data; the signing operation fills their
    // digests before it digests the Manifest, and B-B holds.
    let mut fixture = Fixture::new();
    fixture
        .resources
        .insert("second.txt".to_owned(), b"Second payload\n".to_vec());
    // Both operations process Manifests by their policies: signing fills the
    // Manifest's digests, verification checks them before B-B is assessed.
    fixture.policy.manifest_processing = ManifestProcessing::Process;
    fixture.context_policy.manifest_processing = ManifestProcessing::Process;
    let entry = |uri| ManifestEntry {
        uri,
        mime_type: "text/plain",
    };
    let objects = [DataObject::Manifest {
        id: "manifest",
        entries: vec![entry("detached.txt"), entry("second.txt")],
        mime_type: "text/xml",
    }];
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    let request = Request {
        resources: Some(&fixture.resources),
        ..request("sig", &objects)
    };
    fixture
        .create(&mut document, request)
        .expect("creation over a Manifest");
    assert!(fixture.meets_basic(document.as_xml(), "sig"), "B-B");
    let created = parse(document.as_xml());
    let signed = created
        .descendants()
        .find(|node| node.has_tag_name((DS, "Reference")))
        .expect("the Manifest reference comes first");
    assert_eq!(signed.attribute("URI"), Some("#manifest"));
    assert_eq!(
        signed.attribute("Type"),
        Some("http://www.w3.org/2000/09/xmldsig#Manifest")
    );
    let manifest = created
        .descendants()
        .find(|node| node.has_tag_name((DS, "Manifest")))
        .expect("the Manifest");
    let digests: Vec<&str> = manifest
        .descendants()
        .filter(|node| node.has_tag_name((DS, "DigestValue")))
        .map(|node| node.text().unwrap_or_default())
        .collect();
    assert_eq!(digests.len(), 2);
    assert!(
        digests.iter().all(|digest| !digest.is_empty()),
        "{digests:?}"
    );
}

#[test]
fn a_reference_to_key_info_signs_the_written_certificates() {
    // XMLDSig 1.1 §4.5: KeyInfo may be signed. The reference to
    // `{id}-key-info` covers the certificates the operation writes into
    // KeyInfo, so the signature meets B-B as created and breaks when a
    // carried certificate is removed afterwards.
    let fixture = Fixture::new();
    let objects = [
        enveloped(Envelope::ExcludingSignatures)[0].clone(),
        DataObject::KeyInfo {
            mime_type: "text/xml",
        },
    ];
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    fixture
        .create(&mut document, request("sig", &objects))
        .expect("creation with a signed KeyInfo");
    assert!(fixture.meets_basic(document.as_xml(), "sig"), "B-B");
    let created = parse(document.as_xml());
    let key_info = created
        .descendants()
        .find(|node| node.has_tag_name((DS, "KeyInfo")))
        .expect("KeyInfo");
    assert_eq!(key_info.attribute("Id"), Some("sig-key-info"));
    // Whitespace between the carried certificates changes the canonical
    // KeyInfo but neither certificate, so the path still validates and only
    // the KeyInfo reference (the second) can fail.
    let tampered = document.as_xml().replacen(
        "</X509Certificate><X509Certificate>",
        "</X509Certificate> <X509Certificate>",
        1,
    );
    assert_ne!(tampered, document.as_xml(), "two certificates were carried");
    let account = account(1 << 30);
    let parsed = XmlDocument::parse(tampered.as_str()).expect("tampered XML parses");
    let context = VerifyContext::new()
        .policy(fixture.context_policy.clone())
        .key_resolver(&fixture.resolver);
    let request = VerificationRequest {
        external_resources: Some(&fixture.resources),
        ..VerificationRequest::default()
    };
    let status = with_verified_request(&parsed, &context, &request, &account, |session| {
        Ok(session
            .evidence()
            .signatures()
            .iter()
            .map(|entry| format!("{:?}", entry.result().as_ref().map(|result| result.status)))
            .collect::<Vec<_>>())
    })
    .expect("the tampered document is read");
    assert_eq!(status.len(), 1);
    assert!(status[0].contains("ref_index: 1"), "{status:?}");
}

#[test]
fn every_placement_puts_the_signature_where_requested_and_meets_basic() {
    // A signature excluding every signature from its document reference
    // signs the same data wherever it stands; it goes before, after, as the
    // first or the last child of the element the placement names.
    const PLACED: &str = "<Document><Head Id=\"head\"><Title>T</Title></Head><Data Id=\"payload\">Created payload</Data></Document>";
    let fixture = Fixture::new();
    let cases = [
        (Placement::FirstChildOf("head"), "Head", true),
        (Placement::LastChildOf("head"), "Head", false),
        (Placement::Before("payload"), "Document", false),
        (Placement::After("head"), "Document", false),
    ];
    for (placement, parent, first) in cases {
        let mut document = XmlDocument::parse(PLACED).expect("fixture parses");
        let objects = enveloped(Envelope::ExcludingSignatures);
        fixture
            .create(
                &mut document,
                Request {
                    placement,
                    ..request("sig", &objects)
                },
            )
            .unwrap_or_else(|error| panic!("{placement:?}: {error}"));
        assert!(
            fixture.meets_basic(document.as_xml(), "sig"),
            "{placement:?}: B-B"
        );
        let created = parse(document.as_xml());
        let signature = created
            .descendants()
            .find(|node| node.has_tag_name((DS, "Signature")))
            .expect("the signature");
        let holder = signature.parent_element().expect("a parent");
        assert_eq!(holder.tag_name().name(), parent, "{placement:?}: parent");
        let position = holder
            .children()
            .filter(roxmltree::Node::is_element)
            .position(|node| node == signature);
        match placement {
            Placement::Before(_) => assert_eq!(
                signature
                    .next_sibling_element()
                    .and_then(|node| node.attribute("Id")),
                Some("payload")
            ),
            Placement::After(_) => assert_eq!(
                signature
                    .prev_sibling_element()
                    .and_then(|node| node.attribute("Id")),
                Some("head")
            ),
            _ if first => assert_eq!(position, Some(0), "{placement:?}: first"),
            _ => assert!(
                signature.next_sibling_element().is_none(),
                "{placement:?}: last"
            ),
        }
    }
    let mut document = XmlDocument::parse(PLACED).expect("fixture parses");
    let objects = enveloped(Envelope::ExcludingSignatures);
    let error = fixture
        .create(
            &mut document,
            Request {
                placement: Placement::After("missing"),
                ..request("sig", &objects)
            },
        )
        .expect_err("no element has the ID");
    assert!(
        matches!(error, CreateError::UnknownPlacement(ref id) if id == "missing"),
        "{error}"
    );
    assert_eq!(document.as_xml(), PLACED, "nothing published");
}

#[test]
fn chosen_and_default_namespace_prefixes_meet_basic() {
    // A prefix is a serialization choice: a signature and its countersignature
    // written with other prefixes, or with both namespaces as default ones
    // (each redeclared where the other one takes over), meet B-B, and the
    // elements carry the chosen names.
    let fixture = Fixture::new();
    for (ds, xades) in [("dsig", "xa"), ("", "")] {
        let chain: [&[u8]; 2] = [SIGNER, INTERMEDIATE];
        let signer = Signer {
            prefixes: Prefixes { ds, xades },
            ..fixture.signer(&chain)
        };
        let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
        fixture.with_assessment(&fixture.resolver, |assessment| {
            create(
                &mut document,
                &signer,
                request("sig", &enveloped(Envelope::ExcludingSignatures)),
                assessment,
                &account(1 << 30),
            )
            .expect("creation with chosen prefixes");
            countersign(
                &mut document,
                &signer,
                &Countersignature {
                    parent: "sig",
                    id: "counter",
                    signing_time: TIME,
                    id_attributes: &[],
                },
                assessment,
                &account(1 << 30),
            )
            .expect("countersignature with chosen prefixes");
        });
        let label = format!("{ds:?}/{xades:?}");
        assert!(
            fixture.meets_basic(document.as_xml(), "sig"),
            "{label}: sig"
        );
        assert!(
            fixture.meets_basic(document.as_xml(), "counter"),
            "{label}: counter"
        );
        let qualified = |prefix: &str, local: &str| {
            if prefix.is_empty() {
                format!("<{local}")
            } else {
                format!("<{prefix}:{local}")
            }
        };
        let xml = document.as_xml();
        assert!(xml.contains(&qualified(ds, "SignedInfo")), "{label}");
        assert!(
            xml.contains(&qualified(xades, "SignedProperties")),
            "{label}"
        );
        assert!(
            xml.contains(&qualified(xades, "CounterSignature")),
            "{label}"
        );
    }
}

#[test]
fn an_unusable_prefix_is_refused_before_anything_is_published() {
    // A prefix must be an XML name without a colon, or empty.
    let fixture = Fixture::new();
    let chain: [&[u8]; 2] = [SIGNER, INTERMEDIATE];
    let signer = Signer {
        prefixes: Prefixes {
            ds: "ds",
            xades: "x:y",
        },
        ..fixture.signer(&chain)
    };
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    let error = fixture.with_assessment(&fixture.resolver, |assessment| {
        create(
            &mut document,
            &signer,
            request("sig", &enveloped(Envelope::Enveloped)),
            assessment,
            &account(1 << 30),
        )
        .expect_err("x:y is no prefix")
    });
    assert!(
        matches!(error, CreateError::Draft(DraftError::Name(_))),
        "{error}"
    );
    assert_eq!(document.as_xml(), DOCUMENT);
}

const XPATH_FILTER2_URI: &str = "http://www.w3.org/2002/06/xmldsig-filter2";
const XPATH_URI: &str = "http://www.w3.org/TR/1999/REC-xpath-19991116";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const EXCLUSIVE: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const EXCLUSIVE_WITH_COMMENTS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";

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
    let encode = |der: &[u8]| {
        structured_base64::STANDARD
            .encode(der)
            .expect("test encoding")
    };
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

/// The element with ID `id` in the document's current generation.
fn element(document: &XmlDocument, id: &str) -> NodeIdentity {
    document.with_view(|view| view.node_for_id(id, &[]).expect("element has its ID"))
}

#[test]
fn expected_targets_hold_for_the_published_generation() {
    // The caller names the elements that must stay covered in the generation
    // it hands over; signing publishes a new one, where the same elements are
    // checked rather than refused as stale identities.
    let fixture = Fixture::new();
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    let payload = element(&document, "payload");
    fixture
        .with_targets(&fixture.resolver, &[payload], |assessment| {
            create(
                &mut document,
                &fixture.signer(&[SIGNER, INTERMEDIATE]),
                request(
                    "sig",
                    &[DataObject::Element {
                        id: "payload",
                        mime_type: "text/xml",
                    }],
                ),
                assessment,
                &account(1 << 30),
            )
        })
        .expect("creation with an expected target");
    let payload = element(&document, "payload");
    fixture
        .with_targets(&fixture.resolver, &[payload], |assessment| {
            countersign(
                &mut document,
                &fixture.signer(&[SIGNER, INTERMEDIATE]),
                &Countersignature {
                    parent: "sig",
                    id: "counter",
                    signing_time: TIME,
                    id_attributes: &[],
                },
                assessment,
                &account(1 << 30),
            )
        })
        .expect("countersignature with an expected target");
    assert!(fixture.meets_basic(document.as_xml(), "sig"));
}

#[test]
fn an_uncovered_expected_target_still_refuses() {
    // Carrying the requirement into the new generation keeps it a
    // requirement: an element no signature covers fails it there.
    let fixture = Fixture::new();
    let mut document = XmlDocument::parse(
        "<Document><Data Id=\"payload\">Created payload</Data><Other Id=\"other\"/></Document>",
    )
    .expect("fixture parses");
    let other = element(&document, "other");
    refused(
        &mut document,
        |document| {
            fixture.with_targets(&fixture.resolver, &[other], |assessment| {
                create(
                    document,
                    &fixture.signer(&[SIGNER, INTERMEDIATE]),
                    request(
                        "sig",
                        &[DataObject::Element {
                            id: "payload",
                            mime_type: "text/xml",
                        }],
                    ),
                    assessment,
                    &account(1 << 30),
                )
            })
        },
        |error| matches!(error, CreateError::NotAccepted),
    );
}

#[test]
fn a_target_that_cannot_be_carried_publishes_nothing() {
    // A text node is no coverage target; it has no counterpart to carry into
    // the signed generation, and the creation is refused whole.
    let fixture = Fixture::new();
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    let text = document.with_view(|view| {
        let payload = view.node_for_id("payload", &[]).expect("payload");
        extension::first_child(view, payload, &account(1 << 20))
            .expect("tree")
            .expect("text")
    });
    refused(
        &mut document,
        |document| {
            fixture.with_targets(&fixture.resolver, &[text], |assessment| {
                create(
                    document,
                    &fixture.signer(&[SIGNER, INTERMEDIATE]),
                    request("sig", &enveloped(Envelope::Enveloped)),
                    assessment,
                    &account(1 << 30),
                )
            })
        },
        |error| matches!(error, CreateError::Document(XmlDocumentError::MissingNode)),
    );
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
