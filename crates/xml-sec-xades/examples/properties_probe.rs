//! B-B signatures carrying the optional qualifying properties, created
//! through the public API for independent validation.
//!
//! `properties_probe FIXTURES OUTPUT` signs with the creation fixtures'
//! `signer.key` and `signer.der`/`intermediate.der` chain, assesses each
//! result against `FIXTURES/root.der` at Unix time 1800000000, and writes one
//! document per case to `OUTPUT`: an explicit signature policy with its store
//! (`policy-explicit`), one digested after its transforms (`policy-transforms`),
//! an implied one (`policy-implied`), a store naming a local copy
//! (`policy-local-uri`), commitments over all objects and over one
//! (`commitment`), claimed roles and a signed assertion (`signer-role`), a
//! production place (`production-place`), format details of an encoded
//! object (`data-object-format`), a countersignature with a production
//! place and a role (`countersigned-properties`) and two signatures under one
//! policy, the first with a store added after signing (`policy-store-added`),
//! with the detached data as `OUTPUT/detached.txt`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use structured_asn1::memory::{Memory, MemoryAccount};
use structured_pkix::temporal::LeapTable;
use xml_sec::XmlDocument;
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::policy::{Instant, SigningPolicy, VerificationPolicy};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, KeyResolverConfig, ObjectContent, ObjectElement,
    RsaSigningKey, SignatureAlgorithm, Transform, UriTypeSet, VerificationRequest, VerifyContext,
};
use xml_sec_xades::properties::{
    Commitment, CommitmentScope, ExplicitPolicy, FormatDetails, Fragment, Identifier,
    NoticeReference, PolicyDocument, PolicyQualifier, PolicyStore, PolicyTransform,
    PolicyTransforms, ProductionPlace, Properties, Qualifier, SignaturePolicy, SignerRole,
    UserNotice,
};
use xml_sec_xades::{
    Assessment, Countersignature, DataObject, Envelope, Inputs, Placement, PolicyStoreRequest,
    Request, Requirements, Signer, add_policy_store, countersign, create,
};

const DOCUMENT: &str = "<Document><Data Id=\"payload\">Qualified payload</Data></Document>";
const DETACHED: &[u8] = b"Detached payload\n";
const TIME: &str = "2026-10-18T12:00:00Z";
/// The signature policy document every explicit policy names.
const POLICY: &[u8] =
    b"<SignaturePolicy xmlns=\"urn:example:policy\">  <Rule  order=\"2\" id=\"r1\">Sign</Rule></SignaturePolicy>";
const POLICY_ID: &str = "urn:oid:1.3.6.1.4.1.13762.3.1";
/// Canonical XML 1.0, as a `ds:Transforms` of a policy digest.
const POLICY_TRANSFORMS: &str = "<ds:Transforms xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/></ds:Transforms>";

fn read(directory: &Path, name: &str) -> Result<Vec<u8>, String> {
    std::fs::read(directory.join(name)).map_err(|error| format!("read {name}: {error}"))
}

const fn identifier(uri: &'static str) -> Identifier<'static> {
    Identifier {
        uri,
        qualifier: None,
        description: None,
        documentation: &[],
    }
}

/// An explicit policy over [`POLICY`] with SHA-256.
fn explicit<'a>(
    transform: PolicyTransform<'a, Fragment>,
    qualifiers: &'a [PolicyQualifier<'a, Fragment>],
) -> SignaturePolicy<'a, Fragment> {
    SignaturePolicy::Explicit(ExplicitPolicy {
        identifier: Identifier {
            description: Some("Example signature policy"),
            ..identifier(POLICY_ID)
        },
        document: POLICY,
        digest_method: DigestAlgorithm::Sha256.uri(),
        transform,
        qualifiers,
    })
}

/// A policy store of `document` with its syntax specification.
fn store(document: PolicyDocument<'_>) -> PolicyStore<'_> {
    PolicyStore {
        specification: identifier("urn:oid:1.3.6.1.4.1.13762.3.2"),
        document,
    }
}

/// A production place with every field of EN 319 132-1 §5.2.5.
const PLACE: ProductionPlace<'static> = ProductionPlace {
    city: Some("Prague"),
    street: Some("Main Street 1"),
    state_or_province: Some("Prague"),
    postal_code: Some("11000"),
    country: Some("CZ"),
};

/// The property values the cases share, built once over their fragments.
struct Values<'f> {
    fragments: &'f Fragments,
    notice: [PolicyQualifier<'static, Fragment>; 2],
    commitments: [Commitment<'f, Fragment>; 2],
    formats: [FormatDetails<'static>; 1],
}

impl<'f> Values<'f> {
    fn new(fragments: &'f Fragments) -> Self {
        Self {
            fragments,
            notice: [
                PolicyQualifier::Uri("https://example.org/policy.xml"),
                PolicyQualifier::Notice(UserNotice {
                    reference: Some(NoticeReference {
                        organization: "Example Organization",
                        numbers: &["1", "2"],
                    }),
                    text: Some("Signed under the example policy"),
                }),
            ],
            commitments: [
                Commitment {
                    identifier: identifier("http://uri.etsi.org/01903/v1.2.2#ProofOfOrigin"),
                    scope: CommitmentScope::All,
                    qualifiers: &fragments.qualifiers,
                },
                Commitment {
                    identifier: identifier("http://uri.etsi.org/01903/v1.2.2#ProofOfApproval"),
                    scope: CommitmentScope::References(&["#sig-reference-1"]),
                    qualifiers: &[],
                },
            ],
            formats: [FormatDetails {
                reference: "#sig-reference-0",
                description: Some("Base64 encoded text"),
                identifier: Some(Identifier {
                    qualifier: Some(Qualifier::Urn),
                    ..identifier("urn:oid:1.2.840.113549.1.7.1")
                }),
                encoding: Some("http://www.w3.org/2000/09/xmldsig#base64"),
            }],
        }
    }

    /// Claimed roles and a signed assertion.
    fn role(&self) -> SignerRole<'f, Fragment> {
        SignerRole {
            claimed: &self.fragments.roles,
            certified: &[],
            assertions: &self.fragments.assertion,
        }
    }

    /// The data objects and properties of `case`.
    fn case(&self, case: &str) -> (Vec<DataObject<'static>>, Properties<'_>) {
        let properties = match case {
            "policy-explicit" => Properties {
                policy: Some(explicit(PolicyTransform::None, &self.notice)),
                policy_store: Some(store(PolicyDocument::Embedded)),
                ..Properties::default()
            },
            "policy-transforms" => Properties {
                policy: Some(explicit(
                    PolicyTransform::Xml(&self.fragments.transforms),
                    &[],
                )),
                policy_store: Some(store(PolicyDocument::Embedded)),
                ..Properties::default()
            },
            "policy-implied" => Properties {
                policy: Some(SignaturePolicy::Implied),
                ..Properties::default()
            },
            "policy-store-added" => Properties {
                policy: Some(explicit(PolicyTransform::None, &[])),
                ..Properties::default()
            },
            "policy-local-uri" => Properties {
                policy: Some(explicit(PolicyTransform::None, &[])),
                policy_store: Some(store(PolicyDocument::LocalUri("policy.xml"))),
                ..Properties::default()
            },
            "commitment" => Properties {
                commitments: &self.commitments,
                ..Properties::default()
            },
            "signer-role" => Properties {
                signer_role: Some(self.role()),
                ..Properties::default()
            },
            "production-place" => Properties {
                production_place: Some(PLACE),
                ..Properties::default()
            },
            "data-object-format" => Properties {
                formats: &self.formats,
                ..Properties::default()
            },
            _ => Properties::default(),
        };
        let objects = match case {
            "commitment" => vec![
                document_object(),
                DataObject::Detached {
                    uri: "detached.txt",
                    mime_type: "text/plain",
                },
            ],
            "data-object-format" => vec![DataObject::Object {
                id: "encoded",
                content: ObjectContent::Text("U2lnbmVkIHRleHQ=".to_owned()),
                encoding: Some("http://www.w3.org/2000/09/xmldsig#base64"),
                transforms: vec![Transform::Base64Decode],
                mime_type: "text/plain",
            }],
            _ => vec![document_object()],
        };
        (objects, properties)
    }
}

/// The XML each case's properties carry, owned for the whole run.
struct Fragments {
    transforms: Fragment,
    roles: [Fragment; 2],
    assertion: [Fragment; 1],
    qualifiers: [Fragment; 1],
}

impl Fragments {
    fn new(policy: &SigningPolicy) -> Result<Self, String> {
        let element = |markup: &str| {
            ObjectElement::parse(markup, policy)
                .map(Fragment::Element)
                .map_err(|error| error.to_string())
        };
        Ok(Self {
            transforms: Fragment::Transforms(
                PolicyTransforms::parse(POLICY_TRANSFORMS, policy)
                    .map_err(|error| error.to_string())?,
            ),
            roles: [
                Fragment::Text("Manager".to_owned()),
                Fragment::Text("Approver".to_owned()),
            ],
            assertion: [element(
                "<Assertion xmlns=\"urn:example:assertion\">Signer is authorized</Assertion>",
            )?],
            qualifiers: [Fragment::Text("Reviewed".to_owned())],
        })
    }
}

fn main() -> Result<(), String> {
    let mut args = std::env::args_os().skip(1).map(PathBuf::from);
    let (Some(fixtures), Some(output), None) = (args.next(), args.next(), args.next()) else {
        return Err("usage: properties_probe FIXTURES OUTPUT".into());
    };
    let root = read(&fixtures, "root.der")?;
    let signer_der = read(&fixtures, "signer.der")?;
    let intermediate = read(&fixtures, "intermediate.der")?;
    let key_pem = String::from_utf8(read(&fixtures, "signer.key")?)
        .map_err(|error| format!("signer.key: {error}"))?;
    let key = RsaSigningKey::from_pkcs8_pem(&key_pem).map_err(|error| error.to_string())?;
    let mut signing = SigningPolicy::default();
    signing.uris.references = UriTypeSet::ALL;
    let chain: [&[u8]; 2] = [&signer_der, &intermediate];
    let signer = Signer {
        key: &key,
        provider: xml_sec::provider::default_provider(),
        policy: &signing,
        chain: &chain,
        method: SignatureAlgorithm::RsaSha256,
        digest: DigestAlgorithm::Sha256,
        canonicalization: C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
        prefixes: xml_sec_xades::Prefixes::default(),
    };
    let mut verification = VerificationPolicy::default();
    verification.key_trust.verify_x509_chains = true;
    verification.key_trust.verification_time = Instant::new(1_800_000_000, 0);
    verification.uris.references = UriTypeSet::ALL;
    let resolver = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: vec![root.clone()],
        ..KeyResolverConfig::default()
    });
    let context = VerifyContext::new()
        .policy(verification)
        .key_resolver(&resolver);
    let resources = BTreeMap::from([("detached.txt".to_owned(), DETACHED.to_vec())]);
    let request = VerificationRequest {
        external_resources: Some(&resources),
        ..VerificationRequest::default()
    };
    let assessment = Assessment {
        context: &context,
        request: &request,
        certificates: &[&root],
    };
    let fragments = Fragments::new(&signing)?;
    std::fs::create_dir_all(&output).map_err(|error| error.to_string())?;
    std::fs::write(output.join("detached.txt"), DETACHED).map_err(|error| error.to_string())?;
    let work = Memory::new(Arc::new(MemoryAccount::new(1 << 26, 1 << 30)));
    let write = |name: &str, document: &XmlDocument| {
        std::fs::write(output.join(format!("{name}.xml")), document.as_xml())
            .map_err(|error| error.to_string())?;
        println!("{name}");
        Ok::<_, String>(())
    };
    let values = Values::new(&fragments);
    for case in CASES {
        let mut document = XmlDocument::parse(DOCUMENT).map_err(|error| error.to_string())?;
        let (objects, properties) = values.case(case);
        let request = Request {
            id: "sig",
            signing_time: TIME,
            objects,
            placement: Placement::DocumentEnd,
            resources: Some(&resources),
            id_attributes: &[],
            properties,
        };
        create(&mut document, &signer, request, &assessment, &work)
            .map_err(|error| format!("{case}: {error}"))?;
        let then = Then {
            signer: &signer,
            assessment: &assessment,
            values: &values,
            pki: [&root, &intermediate],
            work: &work,
        };
        then.run(case, &mut document)?;
        write(case, &document)?;
    }
    Ok(())
}

/// What a case does after its first signature.
struct Then<'a> {
    signer: &'a Signer<'a>,
    assessment: &'a Assessment<'a, 'a>,
    values: &'a Values<'a>,
    /// The root and intermediate certificates.
    pki: [&'a [u8]; 2],
    work: &'a Memory,
}

impl Then<'_> {
    /// A countersignature with a production place and a role, or a second
    /// signature under the same policy and a store of the first signature's.
    fn run(&self, case: &str, document: &mut XmlDocument) -> Result<(), String> {
        match case {
            "countersigned-properties" => countersign(
                document,
                self.signer,
                &Countersignature {
                    parent: "sig",
                    id: "counter",
                    signing_time: TIME,
                    id_attributes: &[],
                    properties: Properties {
                        production_place: Some(PLACE),
                        signer_role: Some(self.values.role()),
                        ..Properties::default()
                    },
                },
                self.assessment,
                self.work,
            )
            .map_err(|error| format!("{case} counter: {error}")),
            "policy-store-added" => {
                let request = Request {
                    id: "second",
                    signing_time: TIME,
                    objects: vec![document_object()],
                    placement: Placement::DocumentEnd,
                    resources: None,
                    id_attributes: &[],
                    properties: Properties {
                        policy: Some(explicit(PolicyTransform::None, &[])),
                        ..Properties::default()
                    },
                };
                create(document, self.signer, request, self.assessment, self.work)
                    .map_err(|error| format!("{case} second: {error}"))?;
                let utc = LeapTable::new(-2_208_988_800, 4_102_444_800, &[])
                    .map_err(|error| format!("UTC coverage: {error:?}"))?;
                let [root, intermediate] = self.pki;
                let (anchors, certificates) = ([root], [intermediate]);
                let policy = explicit(PolicyTransform::None, &[]);
                let SignaturePolicy::Explicit(policy) = &policy else {
                    return Err("an explicit policy".into());
                };
                add_policy_store(
                    document,
                    &PolicyStoreRequest {
                        signature: "sig",
                        policy,
                        store: store(PolicyDocument::Embedded),
                        provider: self.signer.provider,
                        signing: self.signer.policy,
                        assessment: self.assessment,
                        inputs: &Inputs {
                            requirements: Requirements::Basic,
                            anchors: &anchors,
                            certificates: &certificates,
                            utc: &utc,
                            accuracies: &[],
                            responders: &[],
                            crls: &[],
                            responses: &[],
                        },
                        id_attributes: &[],
                    },
                    self.work,
                )
                .map_err(|error| format!("{case} store: {error}"))
            }
            _ => Ok(()),
        }
    }
}

/// Every case, in the order they are written.
const CASES: [&str; 10] = [
    "policy-explicit",
    "policy-transforms",
    "policy-implied",
    "policy-local-uri",
    "commitment",
    "signer-role",
    "production-place",
    "data-object-format",
    "countersigned-properties",
    "policy-store-added",
];

fn document_object() -> DataObject<'static> {
    DataObject::Document {
        mime_type: "text/xml",
        envelope: Envelope::ExcludingSignatures,
    }
}
