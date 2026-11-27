//! A B-T signature over the content fixtures: OpenSSL issued two generations
//! of each CA's CRL and answered the signature timestamp request of the B-B
//! signature this fixture creates.

// Each test binary that includes the fixture uses a part of it.
#![allow(dead_code, reason = "each test binary uses a part of the fixture")]

use std::sync::Arc;

use structured_asn1::memory::{Memory, MemoryAccount};
use structured_pkix::algorithm::digest::Algorithm;
use structured_pkix::temporal::LeapTable;
use xml_sec::XmlDocument;
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::policy::{Instant, SigningPolicy, VerificationPolicy};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, KeyResolverConfig, RsaSigningKey, SignContext,
    SignatureAlgorithm, UriTypeSet, VerificationRequest, VerifyContext,
};
use xml_sec_xades::properties::Properties;
use xml_sec_xades::{
    Assessment, Completion, Countersignature, CreateError, DataObject, Envelope, Inputs, Request,
    Requirements, Signer, TimestampRequest, complete_timestamp, countersign, create,
    request_timestamp,
};

pub(crate) const ROOT: &[u8] = include_bytes!("../fixtures/content/root.der");
pub(crate) const INTERMEDIATE: &[u8] = include_bytes!("../fixtures/content/intermediate.der");
const SIGNER: &[u8] = include_bytes!("../fixtures/content/signer.der");
const KEY: &str = include_str!("../fixtures/content/signer.key");
const RESPONSE: &[u8] = include_bytes!("../fixtures/content/signature.tsr");
const EXCLUDING_RESPONSE: &[u8] = include_bytes!("../fixtures/content/seal-signature.tsr");
pub(crate) const CRLS: [&[u8]; 2] = [
    include_bytes!("../fixtures/content/root.crl"),
    include_bytes!("../fixtures/content/intermediate.crl"),
];
pub(crate) const NEXT_CRLS: [&[u8]; 2] = [
    include_bytes!("../fixtures/content/root-next.crl"),
    include_bytes!("../fixtures/content/intermediate-next.crl"),
];
/// The document and signing time of the probe's B-B signature.
const DOCUMENT: &str = "<Document><Data Id=\"payload\">Augmented payload</Data></Document>";
const TIME: &str = "2026-10-18T12:00:00Z";
const NONCE: &[u8] = &[0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71];

pub(crate) fn account() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 26, 1 << 31)))
}

pub(crate) struct Fixture {
    key: RsaSigningKey,
    signing: SigningPolicy,
    resolver: DefaultKeyResolver,
    verification: VerificationPolicy,
    utc: LeapTable<'static>,
}

/// `xml` with its `SignedInfo` canonicalization naming the
/// `InclusiveNamespaces` `PrefixList` `ds` and every digest and signature
/// value emptied, a template to sign again.
pub(crate) fn prefixed_template(xml: &str) -> String {
    const METHOD: &str =
        "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>";
    const PREFIXED: &str = "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"><ec:InclusiveNamespaces xmlns:ec=\"http://www.w3.org/2001/10/xml-exc-c14n#\" PrefixList=\"ds\"/></ds:CanonicalizationMethod>";
    assert!(xml.contains(METHOD), "an exclusive SignedInfo method");
    let mut template = xml.replacen(METHOD, PREFIXED, 1);
    for (open, close) in [
        ("<ds:DigestValue>", "</ds:DigestValue>"),
        (
            "<ds:SignatureValue Id=\"sig-value\">",
            "</ds:SignatureValue>",
        ),
    ] {
        let mut from = 0;
        while let Some(start) = template[from..].find(open).map(|at| from + at + open.len()) {
            let end = start + template[start..].find(close).expect("closed value");
            template.replace_range(start..end, "");
            from = start;
        }
    }
    template
}

impl Fixture {
    pub(crate) fn new() -> Self {
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

    /// `document`'s signature signed again with its `SignedInfo`
    /// canonicalization naming the `InclusiveNamespaces` `PrefixList` `ds`,
    /// as `augment_probe prefixed-request-v111` does: a signature this
    /// library's creation does not write, but one it receives.
    pub(crate) fn with_prefix_list(&self, document: &XmlDocument) -> XmlDocument {
        let template = prefixed_template(document.as_xml());
        let signed = SignContext::new(&self.key)
            .policy(self.signing.clone())
            .sign_template(&template)
            .expect("the prefixed template signs")
            .output;
        XmlDocument::parse(&signed).expect("signed XML parses")
    }

    /// The fixture under a verification policy that reads the historical
    /// vocabularies an operation names.
    #[allow(dead_code, reason = "only the historical tests read them")]
    pub(crate) fn historical() -> Self {
        Self::with_syntax(xml_sec::policy::XadesSyntax::WithHistoricalVocabularies)
    }

    /// The fixture under a verification policy that reads `syntax`.
    #[allow(dead_code, reason = "only the historical tests read them")]
    pub(crate) fn with_syntax(syntax: xml_sec::policy::XadesSyntax) -> Self {
        let mut fixture = Self::new();
        fixture.verification.xades_syntax = syntax;
        fixture
    }

    pub(crate) fn with_assessment<R>(&self, operation: impl FnOnce(&Assessment<'_, '_>) -> R) -> R {
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

    pub(crate) fn inputs<'a>(
        &'a self,
        requirements: Requirements,
        crls: &'a [&'a [u8]],
    ) -> Inputs<'a> {
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

    /// The enveloped signature `sig` of the probe's document with `properties`.
    pub(crate) fn signed(&self, properties: Properties<'_>) -> Result<XmlDocument, CreateError> {
        let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
        self.sign_in(&mut document, "sig", properties)?;
        Ok(document)
    }

    /// Add the enveloped signature `id` with `properties` to `document`.
    pub(crate) fn sign_in(
        &self,
        document: &mut XmlDocument,
        id: &str,
        properties: Properties<'_>,
    ) -> Result<(), CreateError> {
        self.with_signer(|signer| {
            self.with_assessment(|assessment| {
                create(
                    document,
                    signer,
                    Request {
                        id,
                        signing_time: TIME,
                        objects: vec![DataObject::Document {
                            mime_type: "text/xml",
                            envelope: Envelope::Enveloped,
                        }],
                        placement: xml_sec_xades::Placement::DocumentEnd,
                        resources: None,
                        id_attributes: &[],
                        properties,
                    },
                    assessment,
                    &account(),
                )
            })
        })
    }

    /// Countersign the signature `parent` of `document` with `properties`.
    pub(crate) fn countersign_in(
        &self,
        document: &mut XmlDocument,
        parent: &str,
        properties: Properties<'_>,
    ) -> Result<(), CreateError> {
        self.with_signer(|signer| {
            self.with_assessment(|assessment| {
                countersign(
                    document,
                    signer,
                    &Countersignature {
                        parent,
                        id: "counter",
                        signing_time: TIME,
                        id_attributes: &[],
                        properties,
                    },
                    assessment,
                    &account(),
                )
            })
        })
    }

    /// Run `then` with the fixture's signer.
    fn with_signer<R>(&self, then: impl FnOnce(&Signer<'_>) -> R) -> R {
        let chain: [&[u8]; 2] = [SIGNER, INTERMEDIATE];
        then(&Signer {
            key: &self.key,
            provider: xml_sec::provider::default_provider(),
            policy: &self.signing,
            chain: &chain,
            method: SignatureAlgorithm::RsaSha256,
            digest: DigestAlgorithm::Sha256,
            canonicalization: C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
            prefixes: xml_sec_xades::Prefixes::default(),
        })
    }

    /// The probe's B-B signature `sig`, completed to B-T with the fixture token.
    pub(crate) fn timestamped(&self) -> XmlDocument {
        self.timestamped_in(Envelope::Enveloped, RESPONSE)
    }

    /// The probe's signature `sig` that excludes every signature from what it
    /// signs, completed to B-T with its own fixture token.
    pub(crate) fn excluding_timestamped(&self) -> XmlDocument {
        self.timestamped_in(Envelope::ExcludingSignatures, EXCLUDING_RESPONSE)
    }

    fn timestamped_in(&self, envelope: Envelope, response: &[u8]) -> XmlDocument {
        let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
        self.with_signer(|signer| {
            self.with_assessment(|assessment| {
                create(
                    &mut document,
                    signer,
                    Request {
                        id: "sig",
                        signing_time: TIME,
                        objects: vec![DataObject::Document {
                            mime_type: "text/xml",
                            envelope,
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
                    response,
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
        });
        document
    }
}
