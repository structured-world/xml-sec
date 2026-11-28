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
use xml_sec::policy::{
    Instant, ManifestProcessing, PolicyViolation, SigningPolicy, VerificationPolicy,
};
use xml_sec::xmldsig::extension;
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, DsigStatus, FailureReason, KeyInfoWriteError,
    KeyResolverConfig, ObjectContent, ObjectElement, RsaSigningKey, SignatureAlgorithm,
    SignatureBuilderError, SigningError, Transform, UriTypeSet, VerificationRequest, VerifyContext,
    XPathExpression, XPathFilter, XPathFilterOperation, with_verified_request,
};
use xml_sec_xades::properties::{
    Commitment, CommitmentScope, ExplicitPolicy, FormatDetails, Fragment, Identifier,
    NoticeReference, Policy, PolicyDocument, PolicyQualifier, PolicyStore, PolicyTransform,
    PolicyTransforms, ProductionPlace, Properties, PropertyError, Qualifier, SignaturePolicy,
    SignerRole, UserNotice,
};
use xml_sec_xades::{
    Assessment, Countersignature, CreateError, DataObject, DraftError, Envelope, ManifestEntry,
    Outcome, Placement, Prefixes, Request, Signer, SuppliedEntry, countersign, create,
    validate_basic,
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
        properties: Properties::default(),
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

/// The local names of the element children of `parent` in `document`.
fn children<'a>(document: &'a roxmltree::Document<'_>, parent: &str) -> Vec<&'a str> {
    document
        .descendants()
        .find(|node| node.has_tag_name((XADES, parent)))
        .unwrap_or_else(|| panic!("{parent} is written"))
        .children()
        .filter(roxmltree::Node::is_element)
        .map(|node| node.tag_name().name())
        .collect()
}

/// The decoded `DigestValue` under `parent`.
fn digest_under(document: &roxmltree::Document<'_>, parent: &str) -> Vec<u8> {
    let value = document
        .descendants()
        .find(|node| node.has_tag_name((XADES, parent)))
        .and_then(|node| {
            node.descendants()
                .find(|node| node.has_tag_name((DS, "DigestValue")))
        })
        .and_then(|node| node.text())
        .unwrap_or_else(|| panic!("{parent} has a digest"));
    structured_base64::STANDARD
        .decode(value.as_bytes())
        .expect("base64 digest")
}

const POLICY_DOCUMENT: &[u8] =
    b"<Policy xmlns=\"urn:policy\">  <Rule  b=\"2\" a=\"1\">Sign</Rule></Policy>";
const POLICY_ID: &str = "urn:oid:1.2.3.4.5";

fn policy_identifier() -> Identifier<'static> {
    Identifier {
        uri: POLICY_ID,
        qualifier: None,
        description: Some("Test policy"),
        documentation: &[],
    }
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    xml_sec::xmldsig::compute_digest_with_provider(
        xml_sec::provider::default_provider(),
        DigestAlgorithm::Sha256,
        bytes,
        &account(1 << 24),
    )
    .expect("digest")
    .as_ref()
    .to_vec()
}

/// An explicit policy over [`POLICY_DOCUMENT`] with SHA-256.
fn explicit<'a>(
    transform: PolicyTransform<'a, Fragment>,
    qualifiers: &'a [PolicyQualifier<'a, Fragment>],
) -> Policy<'a> {
    Policy::Document(SignaturePolicy::Explicit(ExplicitPolicy {
        identifier: policy_identifier(),
        document: POLICY_DOCUMENT,
        digest_method: DigestAlgorithm::Sha256.uri(),
        transform,
        qualifiers,
    }))
}

/// A policy store of the given form, an ISO 19115 document specification.
fn policy_store(document: PolicyDocument<'_>) -> PolicyStore<'_> {
    PolicyStore {
        specification: Identifier {
            uri: "urn:oid:1.0.19115.1.1.1",
            qualifier: None,
            description: None,
            documentation: &[],
        },
        document,
    }
}

impl Fixture {
    /// The creation of `sig` over `objects` with `properties`, which must be
    /// refused without publishing anything.
    fn refused(&self, properties: Properties<'_>, objects: &[DataObject<'_>]) -> CreateError {
        let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
        refused(
            &mut document,
            |document| {
                self.create(
                    document,
                    Request {
                        properties,
                        ..request("sig", objects)
                    },
                )
            },
            |_| true,
        )
    }
}

#[test]
fn signature_properties_are_signed_in_schema_order_and_meet_basic() {
    // EN 319 132-1 §5.2.5, §5.2.6, §5.2.9, §5.2.10: an explicit policy with
    // the digest of its document as given, a production place and a claimed
    // role among the signed signature properties, and the policy store as an
    // unsigned property; the signature still meets B-B.
    let fixture = Fixture::new();
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    let objects = enveloped(Envelope::ExcludingSignatures);
    let role = ObjectElement::parse("<Role xmlns=\"urn:role\">Approver</Role>", &fixture.policy)
        .expect("role element");
    let claimed = [
        Fragment::Text("Manager".to_owned()),
        Fragment::Element(role),
    ];
    let properties = Properties {
        policy: Some(explicit(
            PolicyTransform::None,
            &[PolicyQualifier::Uri("https://example.org/policy.xml")],
        )),
        policy_store: Some(policy_store(PolicyDocument::Embedded)),
        production_place: Some(ProductionPlace {
            city: Some("Prague"),
            country: Some("CZ"),
            ..ProductionPlace::default()
        }),
        signer_role: Some(SignerRole {
            claimed: &claimed,
            certified: &[],
            assertions: &[],
        }),
        ..Properties::default()
    };
    fixture
        .create(
            &mut document,
            Request {
                properties,
                ..request("sig", &objects)
            },
        )
        .expect("creation with signature properties");
    assert!(fixture.meets_basic(document.as_xml(), "sig"), "B-B");
    let created = parse(document.as_xml());
    assert_eq!(
        children(&created, "SignedSignatureProperties"),
        [
            "SigningTime",
            "SigningCertificateV2",
            "SignaturePolicyIdentifier",
            "SignatureProductionPlaceV2",
            "SignerRoleV2"
        ]
    );
    assert_eq!(
        children(&created, "ClaimedRoles"),
        ["ClaimedRole", "ClaimedRole"]
    );
    assert_eq!(
        digest_under(&created, "SigPolicyHash"),
        sha256(POLICY_DOCUMENT),
        "the policy digest covers the document as given"
    );
    let stored = created
        .descendants()
        .find(|node| node.tag_name().name() == "SignaturePolicyDocument")
        .and_then(|node| node.text())
        .expect("the store embeds the policy");
    assert_eq!(
        structured_base64::STANDARD
            .decode(stored.as_bytes())
            .expect("base64"),
        POLICY_DOCUMENT
    );
    let store = created
        .descendants()
        .find(|node| node.tag_name().name() == "SignaturePolicyStore")
        .expect("policy store");
    assert_eq!(
        store.tag_name().namespace(),
        Some("http://uri.etsi.org/01903/v1.4.1#")
    );
    assert_eq!(
        store.parent().map(|node| node.tag_name().name()),
        Some("UnsignedSignatureProperties")
    );
}

#[test]
fn data_object_properties_are_signed_in_schema_order_and_meet_basic() {
    // EN 319 132-1 §5.2.3, §5.2.4: format details join the baseline MIME
    // type of their object, and a commitment over every object follows the
    // formats; the signature still meets B-B.
    let fixture = Fixture::new();
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    let objects = enveloped(Envelope::ExcludingSignatures);
    let commitment = Commitment {
        identifier: Identifier {
            uri: "http://uri.etsi.org/01903/v1.2.2#ProofOfOrigin",
            qualifier: None,
            description: None,
            documentation: &[],
        },
        scope: CommitmentScope::All,
        qualifiers: &[],
    };
    let formats = [FormatDetails {
        reference: "#sig-reference-0",
        description: Some("The document"),
        identifier: Some(Identifier {
            uri: "urn:oid:1.2.840.113549.1.7.1",
            qualifier: Some(Qualifier::Urn),
            description: None,
            documentation: &[],
        }),
        encoding: None,
    }];
    let properties = Properties {
        commitments: std::slice::from_ref(&commitment),
        formats: &formats,
        ..Properties::default()
    };
    fixture
        .create(
            &mut document,
            Request {
                properties,
                ..request("sig", &objects)
            },
        )
        .expect("creation with data object properties");
    assert!(fixture.meets_basic(document.as_xml(), "sig"), "B-B");
    let created = parse(document.as_xml());
    assert_eq!(
        children(&created, "SignedDataObjectProperties"),
        ["DataObjectFormat", "CommitmentTypeIndication"]
    );
    assert_eq!(
        children(&created, "DataObjectFormat"),
        ["Description", "ObjectIdentifier", "MimeType"]
    );
    assert_eq!(
        children(&created, "CommitmentTypeIndication"),
        ["CommitmentTypeId", "AllSignedDataObjects"]
    );
}

#[test]
fn a_policy_digest_covers_the_document_after_its_transforms() {
    // EN 319 132-1 §5.2.9.2: with ds:Transforms the digest covers the policy
    // document after them, and the same Transforms are written beside it.
    let fixture = Fixture::new();
    let transforms = PolicyTransforms::parse(
        format!(
            "<ds:Transforms xmlns:ds=\"{DS}\"><ds:Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/></ds:Transforms>"
        ),
        &fixture.policy,
    )
    .expect("policy transforms");
    let transforms = Fragment::Transforms(transforms);
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    let objects = enveloped(Envelope::ExcludingSignatures);
    fixture
        .create(
            &mut document,
            Request {
                properties: Properties {
                    policy: Some(explicit(PolicyTransform::Xml(&transforms), &[])),
                    ..Properties::default()
                },
                ..request("sig", &objects)
            },
        )
        .expect("creation with a transformed policy digest");
    assert!(fixture.meets_basic(document.as_xml(), "sig"), "B-B");
    let created = parse(document.as_xml());
    assert_eq!(
        children(&created, "SignaturePolicyId"),
        ["SigPolicyId", "Transforms", "SigPolicyHash"]
    );
    let canonical = xml_sec::c14n::canonicalize_xml(
        POLICY_DOCUMENT,
        &C14nAlgorithm::new(C14nMode::Inclusive1_0, false),
    )
    .expect("canonical policy");
    assert_ne!(
        canonical, POLICY_DOCUMENT,
        "the transform changes the bytes"
    );
    assert_eq!(digest_under(&created, "SigPolicyHash"), sha256(&canonical));
}

#[test]
fn inconsistent_properties_are_refused_before_publication() {
    // EN 319 132-1 §5.2.10 and §5.2.4: a store without an explicit policy,
    // details for no data object, and an encoding the ds:Object does not
    // declare are refused, and the document is left as it was.
    let fixture = Fixture::new();
    let objects = enveloped(Envelope::ExcludingSignatures);
    assert!(matches!(
        fixture.refused(
            Properties {
                policy: Some(Policy::Document(SignaturePolicy::Implied)),
                policy_store: Some(policy_store(PolicyDocument::LocalUri("policy.xml"))),
                ..Properties::default()
            },
            &objects
        ),
        CreateError::PolicyStoreWithoutPolicy
    ));
    let unknown = [FormatDetails {
        reference: "#sig-reference-7",
        description: Some("none"),
        identifier: None,
        encoding: None,
    }];
    assert!(matches!(
        fixture.refused(Properties { formats: &unknown, ..Properties::default() }, &objects),
        CreateError::FormatReference(reference) if reference == "#sig-reference-7"
    ));
    let base64 = [DataObject::Object {
        id: "data",
        content: ObjectContent::Text("SGVsbG8=".to_owned()),
        encoding: Some("http://www.w3.org/2000/09/xmldsig#base64"),
        transforms: vec![Transform::Base64Decode],
        mime_type: "text/plain",
    }];
    let wrong_encoding = [FormatDetails {
        reference: "#sig-reference-0",
        description: None,
        identifier: None,
        encoding: Some("urn:other-encoding"),
    }];
    assert!(matches!(
        fixture.refused(
            Properties {
                formats: &wrong_encoding,
                ..Properties::default()
            },
            &base64
        ),
        CreateError::Properties(structured_xades::produce::Error::Value(
            "dataObjectFormat.encoding"
        ))
    ));
}

#[test]
fn policy_values_xml_sec_cannot_draft_are_refused_before_publication() {
    // A digest as a specification computes it needs the caller's rule for
    // that specification, a notice number must be an xsd:integer, and a ds:Transforms cannot stand
    // where a role is due; none of them publishes anything.
    let fixture = Fixture::new();
    let objects = enveloped(Envelope::ExcludingSignatures);
    let specified = fixture.refused(
        Properties {
            policy: Some(explicit(
                PolicyTransform::InSpecification(Identifier {
                    uri: "urn:example:spec",
                    qualifier: None,
                    description: None,
                    documentation: &[],
                }),
                &[],
            )),
            ..Properties::default()
        },
        &objects,
    );
    assert!(
        matches!(
            specified,
            CreateError::Properties(structured_xades::produce::Error::Writer(
                PropertyError::Specification(_)
            ))
        ),
        "{specified:?}"
    );
    let notice = [PolicyQualifier::Notice(UserNotice {
        reference: Some(NoticeReference {
            organization: "Example",
            numbers: &["1", "two"],
        }),
        text: None,
    })];
    let integer = fixture.refused(
        Properties {
            policy: Some(explicit(PolicyTransform::None, &notice)),
            ..Properties::default()
        },
        &objects,
    );
    assert!(
        matches!(
            &integer,
            CreateError::Properties(structured_xades::produce::Error::Writer(
                PropertyError::Integer(value)
            )) if value == "two"
        ),
        "{integer:?}"
    );
    let transforms = Fragment::Transforms(
        PolicyTransforms::parse(
            format!("<ds:Transforms xmlns:ds=\"{DS}\"/>"),
            &fixture.policy,
        )
        .expect("empty transforms"),
    );
    let misplaced = fixture.refused(
        Properties {
            signer_role: Some(SignerRole {
                claimed: std::slice::from_ref(&transforms),
                certified: &[],
                assertions: &[],
            }),
            ..Properties::default()
        },
        &objects,
    );
    assert!(
        matches!(
            misplaced,
            CreateError::Properties(structured_xades::produce::Error::Writer(
                PropertyError::Slot(_)
            ))
        ),
        "{misplaced:?}"
    );
}

#[test]
fn a_countersignature_takes_no_data_object_property() {
    // A countersignature signs no data object (EN 319 132-1 §5.2.7.2), so a
    // commitment on it would qualify nothing; the parent stays as it was.
    let fixture = Fixture::new();
    let objects = enveloped(Envelope::ExcludingSignatures);
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    fixture
        .create(&mut document, request("sig", &objects))
        .expect("parent");
    let commitment = Commitment {
        identifier: policy_identifier(),
        scope: CommitmentScope::All,
        qualifiers: &[],
    };
    let parent = document.as_xml().to_owned();
    let error = fixture
        .countersign(
            &mut document,
            &Countersignature {
                parent: "sig",
                id: "counter",
                signing_time: TIME,
                id_attributes: &[],
                properties: Properties {
                    commitments: std::slice::from_ref(&commitment),
                    ..Properties::default()
                },
            },
        )
        .expect_err("a countersignature qualifies no data object");
    assert!(matches!(error, CreateError::NoQualifiedObject));
    assert_eq!(document.as_xml(), parent);
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
            // The expression binds the signature's own prefix to another
            // namespace; the choice of signature prefix does not limit it.
            "xpath-own-ds",
            vec![
                Transform::XPath(
                    XPathExpression::new(
                        "not(ancestor-or-self::dsig:Signature) and not(ancestor-or-self::ds:Item)",
                    )
                    .with_namespace("dsig", DS)
                    .with_namespace("ds", "urn:payload"),
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
        transforms: Vec::new(),
        mime_type: "text/plain",
    };
    let objects = [DataObject::Manifest {
        id: "manifest",
        entries: vec![entry("detached.txt"), entry("second.txt")],
        transforms: Vec::new(),
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
    // The verifier processed both entries, not only the Manifest reference.
    assert_eq!(
        manifest_statuses(&fixture, document.as_xml()),
        [
            ("detached.txt".to_owned(), DsigStatus::Valid),
            ("second.txt".to_owned(), DsigStatus::Valid)
        ]
    );
}

/// The URI and status of each `Manifest` reference an independent
/// verification processing Manifests reports for `xml`.
fn manifest_statuses(fixture: &Fixture, xml: &str) -> Vec<(String, DsigStatus)> {
    let parsed = XmlDocument::parse(xml).expect("created XML parses");
    let context = VerifyContext::new()
        .policy(fixture.context_policy.clone())
        .key_resolver(&fixture.resolver);
    let verification = VerificationRequest {
        external_resources: Some(&fixture.resources),
        ..VerificationRequest::default()
    };
    with_verified_request(
        &parsed,
        &context,
        &verification,
        &account(1 << 30),
        |session| {
            Ok(session
                .evidence()
                .signatures()
                .iter()
                .filter_map(|entry| entry.result().as_ref().ok())
                .flat_map(|result| result.manifest_references.iter())
                .map(|reference| (reference.uri.clone(), reference.status))
                .collect::<Vec<_>>())
        },
    )
    .expect("the created document is read")
}

#[test]
fn an_empty_manifest_chain_takes_the_signers_canonicalization() {
    // The signer's canonicalization is the one of its XML references; a
    // Manifest reference with no transforms of the caller's is canonicalized
    // with it, not with whatever the policy generates for a node set.
    let mut fixture = processing_manifests();
    fixture.policy.transforms.generated_canonicalization =
        xml_sec::policy::GeneratedCanonicalization::Implicit;
    let manifest = ObjectElement::parse(SUPPLIED_MANIFEST, &fixture.policy).expect("one element");
    let entries = vec![
        SuppliedEntry {
            id: "supplied-file",
            mime_type: "text/plain",
        },
        SuppliedEntry {
            id: "supplied-entry",
            mime_type: "text/xml",
        },
    ];
    let objects = [
        DataObject::Manifest {
            id: "manifest",
            entries: vec![ManifestEntry {
                uri: "detached.txt",
                transforms: Vec::new(),
                mime_type: "text/plain",
            }],
            transforms: Vec::new(),
            mime_type: "text/xml",
        },
        DataObject::SuppliedManifest {
            manifest,
            entries,
            transforms: Vec::new(),
            mime_type: "text/xml",
        },
    ];
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    let request = Request {
        resources: Some(&fixture.resources),
        ..request("sig", &objects)
    };
    fixture
        .create(&mut document, request)
        .expect("creation over two Manifests");
    let created = parse(document.as_xml());
    for uri in ["#manifest", "#supplied"] {
        let reference = created
            .descendants()
            .find(|node| node.has_tag_name((DS, "Reference")) && node.attribute("URI") == Some(uri))
            .expect("the Manifest reference");
        let algorithms: Vec<&str> = reference
            .descendants()
            .filter(|node| node.has_tag_name((DS, "Transform")))
            .filter_map(|node| node.attribute("Algorithm"))
            .collect();
        assert_eq!(algorithms, [c14n().uri()], "{uri}");
    }
}

#[test]
fn a_supplied_manifest_is_read_under_the_signers_limits() {
    // The element may have been parsed under a looser policy; the signer's
    // own document limit applies when the operation reads it again, and the
    // refusal is that limit, not a malformed Manifest.
    let mut fixture = processing_manifests();
    let manifest = ObjectElement::parse(SUPPLIED_MANIFEST, &fixture.policy).expect("one element");
    fixture.policy.resources.max_xml_document_bytes = SUPPLIED_MANIFEST.len() - 1;
    let objects = [DataObject::SuppliedManifest {
        manifest,
        entries: Vec::new(),
        transforms: Vec::new(),
        mime_type: "text/xml",
    }];
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    let error = fixture
        .create(&mut document, request("sig", &objects))
        .expect_err("the Manifest exceeds the signer's limit");
    assert!(
        matches!(
            error,
            CreateError::Document(XmlDocumentError::Policy(
                PolicyViolation::ResourceLimit { .. }
            ))
        ),
        "{error:?}"
    );
    assert_eq!(document.as_xml(), DOCUMENT, "nothing published");
}

#[test]
fn an_unprocessed_manifest_is_refused_as_unchecked() {
    // A reference to a Manifest nobody processes leaves its data unchecked,
    // so the signature meets no B-B (EN 319 132-1 §6.3(k)); its entries are
    // not planned as signed data objects either, so the refusal names the
    // Manifest reference itself and nothing is published.
    let fixture = Fixture::new();
    assert_eq!(
        fixture.policy.manifest_processing,
        ManifestProcessing::Ignore
    );
    let generated = DataObject::Manifest {
        id: "manifest",
        entries: vec![ManifestEntry {
            uri: "detached.txt",
            transforms: Vec::new(),
            mime_type: "text/plain",
        }],
        transforms: Vec::new(),
        mime_type: "text/xml",
    };
    let supplied = DataObject::SuppliedManifest {
        manifest: ObjectElement::parse(SUPPLIED_MANIFEST, &fixture.policy).expect("one element"),
        entries: Vec::new(),
        transforms: Vec::new(),
        mime_type: "text/xml",
    };
    for object in [generated, supplied] {
        let objects = [object];
        let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
        let request = Request {
            resources: Some(&fixture.resources),
            ..request("sig", &objects)
        };
        let error = fixture
            .create(&mut document, request)
            .expect_err("an unprocessed Manifest meets no B-B");
        assert!(
            matches!(
                error,
                CreateError::Validation(xml_sec_xades::ValidationError::Prepare(_))
            ),
            "{error:?}"
        );
        assert!(
            format!("{error:?}").contains("Unchecked {"),
            "the Manifest reference, not an entry: {error:?}"
        );
        assert_eq!(document.as_xml(), DOCUMENT, "nothing published");
    }
}

/// A fixture whose signing and verification both process Manifests.
fn processing_manifests() -> Fixture {
    let mut fixture = Fixture::new();
    fixture.policy.manifest_processing = ManifestProcessing::Process;
    fixture.context_policy.manifest_processing = ManifestProcessing::Process;
    fixture
}

#[test]
fn each_manifest_entry_is_digested_after_its_own_transforms() {
    // XMLDSig 1.1 §5.1, §4.4.3: a Manifest Reference carries its own
    // transforms, as a SignedInfo one does: the document holding the
    // signature without it, and a Filter 2.0 selection of the payload; the
    // signature's reference to the Manifest canonicalizes it with C14N 1.1.
    let fixture = processing_manifests();
    let objects = [DataObject::Manifest {
        id: "manifest",
        entries: vec![
            ManifestEntry {
                uri: "",
                transforms: vec![
                    Transform::Enveloped,
                    Transform::C14n(C14nAlgorithm::new(C14nMode::Exclusive1_0, false)),
                ],
                mime_type: "text/xml",
            },
            ManifestEntry {
                uri: "#payload",
                transforms: vec![Transform::XPathFilter2(vec![XPathFilter::new(
                    XPathFilterOperation::Intersect,
                    XPathExpression::new("//Data"),
                )])],
                mime_type: "text/xml",
            },
        ],
        transforms: vec![Transform::C14n(C14nAlgorithm::new(
            C14nMode::Inclusive1_1,
            false,
        ))],
        mime_type: "text/xml",
    }];
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    fixture
        .create(&mut document, request("sig", &objects))
        .expect("creation over a Manifest with transforms");
    assert!(fixture.meets_basic(document.as_xml(), "sig"), "B-B");
    let created = parse(document.as_xml());
    let manifest = created
        .descendants()
        .find(|node| node.has_tag_name((DS, "Manifest")))
        .expect("the Manifest");
    let algorithms: Vec<&str> = manifest
        .descendants()
        .filter(|node| node.has_tag_name((DS, "Transform")))
        .filter_map(|node| node.attribute("Algorithm"))
        .collect();
    assert_eq!(
        algorithms,
        [
            "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
            "http://www.w3.org/2001/10/xml-exc-c14n#",
            "http://www.w3.org/2002/06/xmldsig-filter2",
            "http://www.w3.org/2001/10/xml-exc-c14n#",
        ],
        "the generated canonicalization ends the Filter 2.0 chain"
    );
    assert_eq!(
        manifest_statuses(&fixture, document.as_xml()),
        [
            (String::new(), DsigStatus::Valid),
            ("#payload".to_owned(), DsigStatus::Valid)
        ]
    );
}

/// A `ds:Manifest` of detached data, built outside the signature, as DSS's
/// external Manifest tests sign one.
const SUPPLIED_MANIFEST: &str = concat!(
    "<ds:Manifest xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"supplied\">",
    "<ds:Reference Id=\"supplied-file\" URI=\"detached.txt\">",
    "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
    "<ds:DigestValue/></ds:Reference>",
    "<ds:Reference Id=\"supplied-entry\" URI=\"#payload\">",
    "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha512\"/>",
    "<ds:DigestValue/></ds:Reference></ds:Manifest>"
);

#[test]
fn a_supplied_manifest_is_signed_through_its_id() {
    // XMLDSig 1.1 §5.1: a Manifest the caller built goes into an Object and
    // the signature references its root's Id, typed as a Manifest; signing
    // processing Manifests digests its references, which then verify.
    let fixture = processing_manifests();
    let objects = [DataObject::SuppliedManifest {
        manifest: ObjectElement::parse(SUPPLIED_MANIFEST, &fixture.policy).expect("one element"),
        // Each reference is a signed data object of its own (EN 319 132-1
        // §6.3(k)) once the policies process the Manifest.
        entries: vec![
            SuppliedEntry {
                id: "supplied-file",
                mime_type: "text/plain",
            },
            SuppliedEntry {
                id: "supplied-entry",
                mime_type: "text/xml",
            },
        ],
        transforms: vec![Transform::C14n(C14nAlgorithm::new(
            C14nMode::Inclusive1_0,
            false,
        ))],
        mime_type: "text/xml",
    }];
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    let request = Request {
        resources: Some(&fixture.resources),
        ..request("sig", &objects)
    };
    fixture
        .create(&mut document, request)
        .expect("creation over a supplied Manifest");
    assert!(fixture.meets_basic(document.as_xml(), "sig"), "B-B");
    let created = parse(document.as_xml());
    let signed = created
        .descendants()
        .find(|node| node.has_tag_name((DS, "Reference")))
        .expect("the Manifest reference comes first");
    assert_eq!(signed.attribute("URI"), Some("#supplied"));
    assert_eq!(
        signed.attribute("Type"),
        Some("http://www.w3.org/2000/09/xmldsig#Manifest")
    );
    assert_eq!(
        manifest_statuses(&fixture, document.as_xml()),
        [
            ("detached.txt".to_owned(), DsigStatus::Valid),
            ("#payload".to_owned(), DsigStatus::Valid)
        ]
    );
}

#[test]
fn a_supplied_manifest_needs_an_id_and_its_own_ids_free() {
    // No reference can name a Manifest without an Id (XMLDSig 1.1 §5.1),
    // and the IDs a supplied Manifest declares become the document's own,
    // so neither may collide with one it already declares.
    let fixture = processing_manifests();
    let cases = [
        (
            SUPPLIED_MANIFEST.replace(" Id=\"supplied\"", ""),
            DOCUMENT,
            "no Id",
        ),
        (
            "<Data xmlns=\"urn:x\" Id=\"x\"/>".to_owned(),
            DOCUMENT,
            "not a Manifest",
        ),
        (
            SUPPLIED_MANIFEST.to_owned(),
            "<Document><Data Id=\"payload\">x</Data><Item Id=\"supplied-entry\"/></Document>",
            "taken entry Id",
        ),
        (SUPPLIED_MANIFEST.to_owned(), DOCUMENT, "unknown entry"),
    ];
    for (manifest, xml, case) in cases {
        // A format for a reference the Manifest does not have names nothing.
        let entries = match case {
            "unknown entry" => vec![SuppliedEntry {
                id: "elsewhere",
                mime_type: "text/plain",
            }],
            _ => Vec::new(),
        };
        let objects = [DataObject::SuppliedManifest {
            manifest: ObjectElement::parse(manifest, &fixture.policy).expect("one element"),
            entries,
            transforms: Vec::new(),
            mime_type: "text/xml",
        }];
        let mut document = XmlDocument::parse(xml).expect("fixture parses");
        let error = fixture
            .create(&mut document, request("sig", &objects))
            .expect_err(case);
        match case {
            "no Id" => assert!(matches!(error, CreateError::ManifestWithoutId), "{error}"),
            "not a Manifest" => assert!(matches!(error, CreateError::NotManifest), "{error}"),
            "unknown entry" => assert!(
                matches!(error, CreateError::FormatReference(ref uri) if uri == "#elsewhere"),
                "{error}"
            ),
            _ => assert!(
                matches!(error, CreateError::IdInUse(ref id) if id == "supplied-entry"),
                "{error}"
            ),
        }
        assert_eq!(document.as_xml(), xml, "{case}: nothing published");
    }
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
            .map(|entry| entry.result().as_ref().ok().map(|result| result.status))
            .collect::<Vec<_>>())
    })
    .expect("the tampered document is read");
    assert_eq!(
        status,
        [Some(DsigStatus::Invalid(
            FailureReason::ReferenceDigestMismatch { ref_index: 1 }
        ))]
    );
}

#[test]
fn a_request_beyond_the_reference_limit_is_refused_before_its_ids() {
    // Signing counts the SignedInfo references and, when the policy
    // processes them, the Manifest ones against one limit. A request beyond
    // it is refused by that limit before any of its IDs is laid out or looked
    // for in the document, here one that also declares the Manifest's ID.
    const TAKEN: &str = "<Document><Data Id=\"manifest\">x</Data></Document>";
    let mut fixture = Fixture::new();
    fixture.policy.manifest_processing = ManifestProcessing::Process;
    fixture.policy.resources.max_references = 2;
    let entry = |uri| ManifestEntry {
        uri,
        transforms: Vec::new(),
        mime_type: "text/plain",
    };
    let objects = [DataObject::Manifest {
        id: "manifest",
        entries: vec![entry("a.txt"), entry("b.txt"), entry("c.txt")],
        transforms: Vec::new(),
        mime_type: "text/xml",
    }];
    let mut document = XmlDocument::parse(TAKEN).expect("fixture parses");
    let error = fixture
        .create(&mut document, request("sig", &objects))
        .expect_err("five references against a limit of two");
    assert!(
        matches!(
            &error,
            CreateError::Template(SignatureBuilderError::Policy(
                PolicyViolation::ResourceLimit {
                    maximum: 2,
                    actual: 5,
                    ..
                }
            ))
        ),
        "{error:?}"
    );
    assert_eq!(document.as_xml(), TAKEN, "nothing published");
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
                    properties: Properties::default(),
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
                properties: Properties::default(),
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
                    properties: Properties::default(),
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
                    properties: Properties::default(),
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
                properties: Properties::default(),
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
) -> CreateError {
    let before = document.as_xml().to_owned();
    let generation = document.generation();
    let error = match operation(document) {
        Err(error) if matches(&error) => error,
        other => panic!("unexpected result {other:?}"),
    };
    assert_eq!(document.as_xml(), before, "the document is unchanged");
    assert_eq!(
        document.generation(),
        generation,
        "no generation is published"
    );
    error
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
                    PropertyError::Draft(DraftError::Value { .. })
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
    // A leaf that is not a certificate keeps its parse cause, whatever
    // writes KeyInfo after it.
    refused(
        &mut document,
        |document| {
            fixture.create_with(
                document,
                request("sig", &objects),
                &[b"\x30\x03\x02\x01\x01", INTERMEDIATE],
                &fixture.resolver,
                1 << 30,
            )
        },
        |error| matches!(error, CreateError::Certificate(_)),
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
    // A work refusal inside the property draft keeps its original class:
    // some ceiling passes the certificate reads and stops in the draft, and
    // that refusal is the draft's own resource error.
    let fixture = Fixture::new();
    let mut ceiling = 0;
    let mut reached = false;
    while ceiling <= 1 << 26 && !reached {
        let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
        let result = refused(
            &mut document,
            |document| {
                fixture.with_assessment(&fixture.resolver, |assessment| {
                    create(
                        document,
                        &fixture.signer(&[SIGNER, INTERMEDIATE]),
                        request("sig", &enveloped(Envelope::Enveloped)),
                        assessment,
                        &account_of(1 << 24, ceiling),
                    )
                })
            },
            |_| true,
        );
        reached = matches!(
            result,
            CreateError::Properties(structured_xades::produce::Error::Writer(
                PropertyError::Draft(DraftError::Resource(MemoryError::WorkExceeded))
            ))
        );
        ceiling += ceiling / 16 + 1;
    }
    assert!(
        reached,
        "a ceiling stops creation inside the property draft"
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
        properties: Properties::default(),
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
