//! Signature policy digests (computed from the document, supplied by the
//! signer, or as a technical specification defines) and a
//! `SignaturePolicyStore` added to an existing signature, through the public
//! entry points, over the creation fixtures.

#![cfg(feature = "produce")]

#[path = "../examples/support/asn1_policy.rs"]
mod asn1_policy;

use std::sync::Arc;

use structured_asn1::memory::{Memory, MemoryAccount};
use structured_cms::signature_policy::PolicyDigestError;
use structured_pkix::temporal::LeapTable;
use structured_xades::produce::Error as ProduceError;
use xml_sec::XmlDocument;
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::policy::{Instant, SigningPolicy, VerificationPolicy};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, KeyResolverConfig, RsaSigningKey, SignatureAlgorithm,
    UriTypeSet, VerificationRequest, VerifyContext,
};
use xml_sec_xades::properties::{
    DigestRule, ExplicitPolicy, Fragment, Identifier, Policy, PolicyDocument, PolicyStore,
    PolicyTransform, PolicyTransforms, Properties, PropertyError, Qualifier, SignaturePolicy,
    SpecifiedDigest, SuppliedPolicy,
};
use xml_sec_xades::{
    Assessment, AugmentError, CreateError, DataObject, Envelope, Inputs, PolicyStoreRequest,
    Request, Requirements, Signer, add_policy_store, create,
};

const ROOT: &[u8] = include_bytes!("fixtures/creation/root.der");
const INTERMEDIATE: &[u8] = include_bytes!("fixtures/creation/intermediate.der");
const SIGNER: &[u8] = include_bytes!("fixtures/creation/signer.der");
const KEY: &str = include_str!("fixtures/creation/signer.key");
const DOCUMENT: &str = "<Document><Data Id=\"payload\">Stored policy</Data></Document>";
const TIME: &str = "2026-10-18T12:00:00Z";
const POLICY: &[u8] = b"<Policy xmlns=\"urn:policy\">  <Rule  b=\"2\" a=\"1\">Sign</Rule></Policy>";
const STORE: &str = "SignaturePolicyStore";

fn account() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 24, 1 << 30)))
}

const fn identifier(uri: &'static str) -> Identifier<'static> {
    Identifier {
        uri,
        qualifier: None,
        description: None,
        documentation: &[],
    }
}

fn explicit<'a>(
    document: &'a [u8],
    transform: PolicyTransform<'a, Fragment>,
) -> ExplicitPolicy<'a, Fragment> {
    ExplicitPolicy {
        identifier: identifier("urn:oid:1.2.3.4.5"),
        document,
        digest_method: DigestAlgorithm::Sha256.uri(),
        transform,
        qualifiers: &[],
    }
}

fn store() -> PolicyStore<'static> {
    PolicyStore {
        specification: identifier("urn:oid:1.0.19115.1.1.1"),
        document: PolicyDocument::Embedded,
    }
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
        verification.key_trust.verification_time = Instant::new(500_000 * 3600, 0);
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

    /// A document with the B-B signature `sig` under `policy`.
    fn signed(&self, policy: Option<SignaturePolicy<'_, Fragment>>) -> XmlDocument {
        self.created(Properties {
            policy: policy.map(Policy::Document),
            ..Properties::default()
        })
        .expect("signed")
    }

    /// A document with the B-B signature `sig` carrying `properties`.
    fn created(&self, properties: Properties<'_>) -> Result<XmlDocument, CreateError> {
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
                        envelope: Envelope::ExcludingSignatures,
                    }],
                    placement: xml_sec_xades::Placement::DocumentEnd,
                    resources: None,
                    id_attributes: &[],
                    properties,
                },
                assessment,
                &account(),
            )
        })?;
        Ok(document)
    }

    /// Add the store of `policy` to `sig`, assessed at B-B.
    fn store(
        &self,
        document: &mut XmlDocument,
        policy: &ExplicitPolicy<'_, Fragment>,
    ) -> Result<(), AugmentError> {
        self.store_specified(document, policy, None)
    }

    /// Add the store of `policy`, digested under `specified`, to `sig`.
    fn store_specified(
        &self,
        document: &mut XmlDocument,
        policy: &ExplicitPolicy<'_, Fragment>,
        specified: Option<SpecifiedDigest<'_>>,
    ) -> Result<(), AugmentError> {
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
        self.with_assessment(|assessment| {
            add_policy_store(
                document,
                &PolicyStoreRequest {
                    signature: "sig",
                    policy,
                    store: store(),
                    specified,
                    provider: xml_sec::provider::default_provider(),
                    signing: &self.signing,
                    assessment,
                    inputs: &inputs,
                    id_attributes: &[],
                },
                &account(),
            )
        })
    }
}

fn stores(xml: &str) -> usize {
    roxmltree::Document::parse(xml)
        .expect("XML parses")
        .descendants()
        .filter(|node| node.tag_name().name() == STORE)
        .count()
}

#[test]
fn the_signed_policy_is_stored_once_after_signing() {
    // EN 319 132-1 §5.2.10: the store of the explicit policy the signature
    // signed joins its unsigned properties and the signature still meets
    // B-B; a second store is refused, and a store of another document or of
    // a signature without an explicit policy is too, with nothing published.
    let fixture = Fixture::new();
    let mut document = fixture.signed(Some(SignaturePolicy::Explicit(explicit(
        POLICY,
        PolicyTransform::None,
    ))));
    fixture
        .store(&mut document, &explicit(POLICY, PolicyTransform::None))
        .expect("the store of the signed policy");
    assert_eq!(stores(document.as_xml()), 1);
    let stored = document.as_xml().to_owned();
    let again = fixture
        .store(&mut document, &explicit(POLICY, PolicyTransform::None))
        .expect_err("a second store");
    assert!(matches!(again, AugmentError::PolicyStored(_)), "{again:?}");
    assert_eq!(document.as_xml(), stored);

    let mut other = fixture.signed(Some(SignaturePolicy::Explicit(explicit(
        POLICY,
        PolicyTransform::None,
    ))));
    let original = other.as_xml().to_owned();
    let foreign = fixture
        .store(
            &mut other,
            &explicit(b"<Policy>other</Policy>", PolicyTransform::None),
        )
        .expect_err("another document");
    assert!(
        matches!(&foreign, AugmentError::Store(error) if matches!(**error, structured_xades::produce::Error::Foreign)),
        "{foreign:?}"
    );
    assert_eq!(other.as_xml(), original);

    let mut implied = fixture.signed(Some(SignaturePolicy::Implied));
    let refused = fixture
        .store(&mut implied, &explicit(POLICY, PolicyTransform::None))
        .expect_err("no explicit policy");
    assert!(
        matches!(refused, AugmentError::NoExplicitPolicy(_)),
        "{refused:?}"
    );
    assert_eq!(stores(implied.as_xml()), 0);
}

#[test]
fn a_policy_digested_after_transforms_is_stored_with_the_same_plan() {
    // The signed hash covers the document after its transforms, not its raw
    // bytes; the store checks the document under the signed plan, whatever
    // plan the caller states.
    let fixture = Fixture::new();
    let transforms = Fragment::Transforms(
        PolicyTransforms::parse(
            "<ds:Transforms xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/></ds:Transforms>",
            &fixture.signing,
        )
        .expect("policy transforms"),
    );
    let mut document = fixture.signed(Some(SignaturePolicy::Explicit(explicit(
        POLICY,
        PolicyTransform::Xml(&transforms),
    ))));
    assert_ne!(signed_digest(document.as_xml()), sha256(POLICY));
    fixture
        .store(&mut document, &explicit(POLICY, PolicyTransform::None))
        .expect("the signed plan");
    assert_eq!(stores(document.as_xml()), 1);
}

#[test]
fn a_store_is_checked_under_the_plan_the_signature_signed() {
    // EN 319 132-1 §5.2.9.2 and §5.2.10: the stored document must give the
    // signed hash under the signed plan. A signature over the canonical
    // bytes without transforms does not take a differently formatted
    // document whose canonicalization, supplied by the caller, gives them.
    let fixture = Fixture::new();
    let canonical: &[u8] =
        b"<Policy xmlns=\"urn:policy\"><Rule a=\"1\" b=\"2\">Sign</Rule></Policy>";
    let formatted: &[u8] =
        b"<Policy xmlns=\"urn:policy\"><Rule b=\"2\"  a=\"1\">Sign</Rule></Policy>";
    let transforms = Fragment::Transforms(
        PolicyTransforms::parse(
            "<ds:Transforms xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/></ds:Transforms>",
            &fixture.signing,
        )
        .expect("policy transforms"),
    );
    let mut document = fixture.signed(Some(SignaturePolicy::Explicit(explicit(
        canonical,
        PolicyTransform::None,
    ))));
    let original = document.as_xml().to_owned();
    let refused = fixture
        .store(
            &mut document,
            &explicit(formatted, PolicyTransform::Xml(&transforms)),
        )
        .expect_err("a plan the signature did not sign");
    assert!(matches!(refused, AugmentError::Store(_)), "{refused:?}");
    assert_eq!(document.as_xml(), original);
    fixture
        .store(&mut document, &explicit(canonical, PolicyTransform::None))
        .expect("the signed plan");
}

#[test]
fn policy_identifiers_compare_as_collapsed_any_uris() {
    // XML Schema 1.0 Part 2 §3.2.17: anyURI collapses whitespace, so an
    // identifier signed with a run of spaces names the same policy as its
    // collapsed form.
    let fixture = Fixture::new();
    let spaced = ExplicitPolicy {
        identifier: identifier("urn:example:policy  v1"),
        ..explicit(POLICY, PolicyTransform::None)
    };
    let collapsed = ExplicitPolicy {
        identifier: identifier("urn:example:policy v1"),
        ..explicit(POLICY, PolicyTransform::None)
    };
    let mut document = fixture.signed(Some(SignaturePolicy::Explicit(spaced)));
    fixture
        .store(&mut document, &collapsed)
        .expect("the same anyURI");
    assert_eq!(stores(document.as_xml()), 1);
}

/// The refusal of a creation that must not succeed.
fn refusal(result: Result<XmlDocument, CreateError>, what: &str) -> CreateError {
    match result {
        Ok(_) => panic!("{what} is refused"),
        Err(error) => error,
    }
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    xml_sec::xmldsig::compute_digest_with_provider(
        xml_sec::provider::default_provider(),
        DigestAlgorithm::Sha256,
        bytes,
        &account(),
    )
    .expect("digest")
    .as_ref()
    .to_vec()
}

/// The decoded `SigPolicyHash/DigestValue` of `xml`.
fn signed_digest(xml: &str) -> Vec<u8> {
    let document = roxmltree::Document::parse(xml).expect("XML parses");
    let value = document
        .descendants()
        .find(|node| node.tag_name().name() == "SigPolicyHash")
        .and_then(|hash| {
            hash.children()
                .find(|node| node.tag_name().name() == "DigestValue")
        })
        .and_then(|node| node.text())
        .expect("SigPolicyHash/DigestValue");
    structured_base64::STANDARD
        .decode(value.as_bytes())
        .expect("base64")
}

fn supplied(digest: &[u8]) -> Policy<'_> {
    Policy::Supplied(SuppliedPolicy {
        identifier: identifier("urn:oid:1.2.3.4.5"),
        digest_method: DigestAlgorithm::Sha256.uri(),
        digest,
        transform: PolicyTransform::None,
        qualifiers: &[],
    })
}

#[test]
fn a_supplied_policy_digest_is_signed_without_the_document() {
    // EN 319 132-1 §5.2.9: the signer may hold only the digest of the policy
    // version; it is signed as given when its width is the method's, a
    // digest of another width is refused (an 11-byte value under SHA-256),
    // and no store can be written for a document the signer does not hold.
    let fixture = Fixture::new();
    let digest = sha256(POLICY);
    let document = fixture
        .created(Properties {
            policy: Some(supplied(&digest)),
            ..Properties::default()
        })
        .expect("a supplied digest");
    assert_eq!(signed_digest(document.as_xml()), digest);

    let short = refusal(
        fixture.created(Properties {
            policy: Some(supplied(b"digestvalue")),
            ..Properties::default()
        }),
        "a digest of another width",
    );
    assert!(
        matches!(
            short,
            CreateError::Properties(ProduceError::Value("signaturePolicyId.digestWidth"))
        ),
        "{short:?}"
    );
    let stored = refusal(
        fixture.created(Properties {
            policy: Some(supplied(&digest)),
            policy_store: Some(store()),
            ..Properties::default()
        }),
        "a store without the document",
    );
    assert!(
        matches!(stored, CreateError::PolicyStoreWithoutPolicy),
        "{stored:?}"
    );
}

const ASN1_RULE: SpecifiedDigest<'static> = SpecifiedDigest {
    specification: asn1_policy::SPECIFICATION,
    rule: DigestRule::Asn1Policy,
};

fn asn1_explicit<'a>(document: &'a [u8], method: &'a str) -> ExplicitPolicy<'a, Fragment> {
    ExplicitPolicy {
        identifier: Identifier {
            qualifier: Some(Qualifier::Urn),
            ..identifier(asn1_policy::POLICY_OID)
        },
        document,
        digest_method: method,
        transform: PolicyTransform::InSpecification(identifier(asn1_policy::SPECIFICATION)),
        qualifiers: &[],
    }
}

#[test]
fn an_asn1_policy_is_digested_as_its_specification_defines() {
    // ETSI TR 102 272 §6.1: the digest covers the DER signPolicyHashAlg and
    // signPolicyInfo, not the whole document, when the caller states that
    // rule for the specification the policy names; the store recomputes it.
    let fixture = Fixture::new();
    let der = asn1_policy::document(None);
    // The document is under 128 bytes: a two-byte SEQUENCE header.
    assert!(der.len() < 130);
    let covered = sha256(&der[2..]);
    let policy = asn1_explicit(&der, DigestAlgorithm::Sha256.uri());
    let mut document = fixture
        .created(Properties {
            policy: Some(Policy::Document(SignaturePolicy::Explicit(asn1_explicit(
                &der,
                DigestAlgorithm::Sha256.uri(),
            )))),
            specified: Some(ASN1_RULE),
            ..Properties::default()
        })
        .expect("an ASN.1 policy");
    assert_eq!(signed_digest(document.as_xml()), covered);
    assert_ne!(covered, sha256(&der), "not the whole document");

    let unstated = fixture
        .store(&mut document, &policy)
        .expect_err("a store without the rule");
    assert!(
        matches!(&unstated, AugmentError::Store(error)
            if matches!(**error, ProduceError::Writer(PropertyError::Specification(_)))),
        "{unstated:?}"
    );
    fixture
        .store_specified(&mut document, &policy, Some(ASN1_RULE))
        .expect("the store under the rule");
    assert_eq!(stores(document.as_xml()), 1);
}

#[test]
fn an_asn1_policy_that_contradicts_its_digest_is_refused() {
    // TR 102 272 §6.1: the document names its own hash, which must be the
    // policy digest method, and a stored signPolicyHash must be the digest;
    // a policy breaking either is refused, while a correct stored hash is
    // accepted.
    let fixture = Fixture::new();
    let create = |document: &[u8], method: &str| {
        fixture.created(Properties {
            policy: Some(Policy::Document(SignaturePolicy::Explicit(asn1_explicit(
                document, method,
            )))),
            specified: Some(ASN1_RULE),
            ..Properties::default()
        })
    };
    let der = asn1_policy::document(None);
    let mismatch = refusal(
        create(&der, DigestAlgorithm::Sha384.uri()),
        "another method",
    );
    assert!(
        matches!(&mismatch, CreateError::Properties(ProduceError::Writer(PropertyError::Asn1Digest(error)))
            if matches!(**error, PolicyDigestError::AlgorithmMismatch { .. })),
        "{mismatch:?}"
    );
    let wrong = asn1_policy::document(Some(&[0; 32]));
    let differs = refusal(
        create(&wrong, DigestAlgorithm::Sha256.uri()),
        "a wrong stored hash",
    );
    assert!(
        matches!(&differs, CreateError::Properties(ProduceError::Writer(PropertyError::Asn1Digest(error)))
            if matches!(**error, PolicyDigestError::StoredDigestMismatch(_))),
        "{differs:?}"
    );
    let correct = asn1_policy::document(Some(&sha256(&der[2..])));
    create(&correct, DigestAlgorithm::Sha256.uri()).expect("a correct stored hash");
    let malformed = refusal(
        create(b"<Policy/>", DigestAlgorithm::Sha256.uri()),
        "not DER",
    );
    assert!(
        matches!(
            malformed,
            CreateError::Properties(ProduceError::Writer(
                PropertyError::Der(_) | PropertyError::Asn1(_)
            ))
        ),
        "{malformed:?}"
    );
}
