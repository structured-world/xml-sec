//! A `SignaturePolicyStore` added to an existing signature, through the
//! public entry points, over the creation fixtures.

#![cfg(feature = "produce")]

use std::sync::Arc;

use structured_asn1::memory::{Memory, MemoryAccount};
use structured_pkix::temporal::LeapTable;
use xml_sec::XmlDocument;
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::policy::{Instant, SigningPolicy, VerificationPolicy};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, KeyResolverConfig, RsaSigningKey, SignatureAlgorithm,
    UriTypeSet, VerificationRequest, VerifyContext,
};
use xml_sec_xades::properties::{
    ExplicitPolicy, Fragment, Identifier, PolicyDocument, PolicyStore, PolicyTransform,
    PolicyTransforms, Properties, SignaturePolicy,
};
use xml_sec_xades::{
    Assessment, AugmentError, DataObject, Envelope, Inputs, PolicyStoreRequest, Request,
    Requirements, Signer, add_policy_store, create,
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
                    properties: Properties {
                        policy,
                        ..Properties::default()
                    },
                },
                assessment,
                &account(),
            )
        })
        .expect("signed");
        document
    }

    /// Add the store of `policy` to `sig`, assessed at B-B.
    fn store(
        &self,
        document: &mut XmlDocument,
        policy: &ExplicitPolicy<'_, Fragment>,
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
    // The signed hash covers the document after its transforms; the stored
    // policy matches it under the same plan and not as the raw bytes.
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
    let raw = fixture
        .store(&mut document, &explicit(POLICY, PolicyTransform::None))
        .expect_err("the raw bytes digest otherwise");
    assert!(matches!(raw, AugmentError::Store(_)), "{raw:?}");
    fixture
        .store(
            &mut document,
            &explicit(POLICY, PolicyTransform::Xml(&transforms)),
        )
        .expect("the same plan");
    assert_eq!(stores(document.as_xml()), 1);
}
