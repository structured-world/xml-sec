//! Signatures created in a historical vocabulary through the public entry
//! points, over the content fixtures: ETSI TS 101 903 V1.1.1 and V1.2.2,
//! and the TS 103 171 profile of V1.3.2.

#![cfg(feature = "produce")]

#[path = "support/content.rs"]
mod content;

use content::{CRLS, Fixture, account};
use structured_pkix::algorithm::digest::Algorithm;
use xml_sec::xmldsig::DigestAlgorithm;
use xml_sec_xades::{
    AugmentError, CompleteReferences, Completion, CreateError, DataAdded, ExtendedKind, Inputs,
    Outcome, ReferenceSyntax, Requirements, TimestampFailure, TimestampRequest, ValidationData,
    add_historical_references, add_historical_values, complete_timestamp,
    request_historical_extended_timestamp, request_historical_timestamp,
};

/// The TSA's answer to the probe's signature timestamp request in each
/// historical vocabulary.
const RESPONSES: [(Profile, &[u8]); 3] = [
    (
        Profile::PreEn,
        include_bytes!("fixtures/content/historical.tsr"),
    ),
    (
        Profile::V111,
        include_bytes!("fixtures/content/historical-v111.tsr"),
    ),
    (
        Profile::V122,
        include_bytes!("fixtures/content/historical-v122.tsr"),
    ),
];
/// The nonce of the probe's historical request.
const NONCE: &[u8] = &[0x1c, 0x2d, 0x3e, 0x4f, 0x50, 0x61, 0x72, 0x03];

#[test]
fn a_timestamped_historical_signature_takes_its_validation_values() {
    // TS 103 171 V2.1.1 §8.1, TS 101 903 V1.2.2 §7.6 and V1.1.1 §7.6: the
    // values of the signer's path, the TSA's path and their statuses are
    // added in the profile's own CertificateValues and RevocationValues; a
    // second call finds them all present. The V1.1.1 signature timestamp
    // is replayed through HashDataInfo, whose Transforms lie in the V1.1.1
    // namespace.
    for (profile, response) in RESPONSES {
        timestamped_values(profile, response);
    }
}

fn timestamped_values(profile: Profile, response: &[u8]) {
    let fixture = Fixture::historical();
    let mut document = timestamped(&fixture, profile, response);
    let inputs = fixture.inputs(Requirements::LongTerm, &CRLS);
    let add = |document: &mut xml_sec::XmlDocument| {
        fixture.with_assessment(|assessment| {
            add_historical_values(
                document,
                &ValidationData {
                    signature: "sig",
                    assessment,
                    inputs: &inputs,
                    id_attributes: &[],
                },
                profile,
                &account(),
            )
        })
    };
    assert_eq!(
        add(&mut document).unwrap_or_else(|error| panic!("{profile:?}: {error}")),
        DataAdded::Published
    );
    assert_eq!(
        unsigned_names(document.as_xml()),
        [
            "SignatureTimeStamp",
            "CertificateValues",
            "RevocationValues"
        ],
        "{profile:?}"
    );
    assert_eq!(
        add(&mut document).expect("values"),
        DataAdded::AlreadyPresent,
        "{profile:?}"
    );
}

/// The local names of the unsigned signature properties, in order.
fn unsigned_names(xml: &str) -> Vec<String> {
    let parsed = roxmltree::Document::parse(xml).expect("XML parses");
    parsed
        .descendants()
        .find(|node| node.tag_name().name() == "UnsignedSignatureProperties")
        .expect("unsigned properties")
        .children()
        .filter(roxmltree::Node::is_element)
        .map(|node| node.tag_name().name().to_owned())
        .collect()
}

/// The probe's signature in the vocabulary of `profile`, completed with its
/// signature timestamp `response`.
fn timestamped(fixture: &Fixture, profile: Profile, response: &[u8]) -> xml_sec::XmlDocument {
    let mut document = fixture
        .signed(Properties {
            historical: Some(profile),
            // V1.1.1 §7.2.3 requires SignaturePolicyIdentifier.
            policy: (profile == Profile::V111)
                .then_some(Policy::Document(SignaturePolicy::Implied)),
            ..Properties::default()
        })
        .unwrap_or_else(|error| panic!("{profile:?}: {error}"));
    let request = TimestampRequest {
        signature: "sig",
        digest: Algorithm::Sha256,
        policy: None,
        nonce: Some(NONCE),
        id_attributes: &[],
    };
    let stamped = fixture.inputs(Requirements::Timestamped, &[]);
    fixture.with_assessment(|assessment| {
        let pending =
            request_historical_timestamp(&document, &request, profile, assessment, &account())
                .unwrap_or_else(|error| panic!("{profile:?}: {error}"));
        complete_timestamp(
            &mut document,
            &pending,
            response,
            &Completion {
                assessment,
                inputs: &stamped,
                window: None,
                id_attributes: &[],
            },
            &account(),
        )
        .unwrap_or_else(|error| panic!("{profile:?}: {error}"));
    });
    document
}

/// The TSA's answers to the probe's pre-EN X and archive timestamp
/// requests.
const X_PRE_EN: &[u8] = include_bytes!("fixtures/content/x-pre-en.tsr");
const A_PRE_EN: &[u8] = include_bytes!("fixtures/content/a-pre-en.tsr");
const LTA_PRE_EN: &[u8] = include_bytes!("fixtures/content/lta-pre-en.tsr");

/// Request and complete one `kind` timestamp of the pre-EN signature.
fn stamp(
    fixture: &Fixture,
    document: &mut xml_sec::XmlDocument,
    kind: ExtendedKind,
    response: &[u8],
) {
    let request = TimestampRequest {
        signature: "sig",
        digest: Algorithm::Sha256,
        policy: None,
        nonce: Some(NONCE),
        id_attributes: &[],
    };
    let inputs = fixture.inputs(Requirements::LongTerm, &CRLS);
    fixture.with_assessment(|assessment| {
        let pending = request_historical_extended_timestamp(
            document,
            &request,
            kind,
            Profile::PreEn,
            assessment,
            &account(),
        )
        .unwrap_or_else(|error| panic!("{kind:?} request: {error}"));
        complete_timestamp(
            document,
            &pending,
            response,
            &Completion {
                assessment,
                inputs: &inputs,
                window: None,
                id_attributes: &[],
            },
            &account(),
        )
        .unwrap_or_else(|error| panic!("{kind:?}: {error}"));
    });
}

/// Add the values the pre-EN signature's census finds missing.
fn values(fixture: &Fixture, document: &mut xml_sec::XmlDocument) {
    let inputs = fixture.inputs(Requirements::LongTerm, &CRLS);
    fixture.with_assessment(|assessment| {
        add_historical_values(
            document,
            &ValidationData {
                signature: "sig",
                assessment,
                inputs: &inputs,
                id_attributes: &[],
            },
            Profile::PreEn,
            &account(),
        )
        .expect("values")
    });
}

#[test]
fn a_pre_en_signature_goes_through_the_ts101903_levels() {
    // TS 101 903 V1.4.2 §§7.4-7.7 and 8.2, in the names of V1.3.2 the
    // TS 103 171 profile keeps: the complete references of XAdES-C, the X
    // timestamp over the signature, its timestamp and the references, the
    // values of XAdES-XL, then the archive timestamp of XAdES-A, each
    // published only while the signature meets BES.
    let fixture = Fixture::historical();
    let (_, response) = RESPONSES[0];
    let mut document = timestamped(&fixture, Profile::PreEn, response);
    let inputs = fixture.inputs(Requirements::LongTerm, &CRLS);
    fixture.with_assessment(|assessment| {
        add_historical_references(
            &mut document,
            &CompleteReferences {
                signature: "sig",
                syntax: ReferenceSyntax::Original,
                digest: DigestAlgorithm::Sha256,
                assessment,
                inputs: &inputs,
                id_attributes: &[],
            },
            Profile::PreEn,
            &account(),
        )
        .expect("XAdES-C");
    });
    stamp(
        &fixture,
        &mut document,
        ExtendedKind::SignatureAndReferences(ReferenceSyntax::Original),
        X_PRE_EN,
    );
    values(&fixture, &mut document);
    stamp(&fixture, &mut document, ExtendedKind::Archive141, A_PRE_EN);
    assert_eq!(
        unsigned_names(document.as_xml()),
        [
            "SignatureTimeStamp",
            "CompleteCertificateRefs",
            "CompleteRevocationRefs",
            "SigAndRefsTimeStamp",
            "CertificateValues",
            "RevocationValues",
            "ArchiveTimeStamp"
        ]
    );
}

#[test]
fn a_pre_en_signature_with_its_values_takes_an_archive_timestamp() {
    // TS 103 171 V2.1.1 §8.2: the LTA level of the profile is the archive
    // timestamp of TS 101 903 over the signature with its values.
    let fixture = Fixture::historical();
    let (_, response) = RESPONSES[0];
    let mut document = timestamped(&fixture, Profile::PreEn, response);
    values(&fixture, &mut document);
    stamp(
        &fixture,
        &mut document,
        ExtendedKind::Archive141,
        LTA_PRE_EN,
    );
    assert_eq!(
        unsigned_names(document.as_xml()),
        [
            "SignatureTimeStamp",
            "CertificateValues",
            "RevocationValues",
            "ArchiveTimeStamp"
        ]
    );
}

#[test]
fn a_historical_timestamp_without_a_trusted_tsa_path_is_not_published() {
    // As for a baseline B-T: the checked token joins the signature only when
    // its TSA's path ends at a caller anchor, whatever certificates the
    // token carries; the root is still one the signer's path may use.
    let fixture = Fixture::historical();
    let (profile, response) = RESPONSES[0];
    let mut document = fixture
        .signed(Properties {
            historical: Some(profile),
            ..Properties::default()
        })
        .expect("pre-EN B-B");
    let before = document.as_xml().to_owned();
    let request = TimestampRequest {
        signature: "sig",
        digest: Algorithm::Sha256,
        policy: None,
        nonce: Some(NONCE),
        id_attributes: &[],
    };
    let untrusted = Inputs {
        anchors: &[],
        certificates: &[content::INTERMEDIATE, content::ROOT],
        ..fixture.inputs(Requirements::Timestamped, &[])
    };
    let refused = fixture.with_assessment(|assessment| {
        let pending =
            request_historical_timestamp(&document, &request, profile, assessment, &account())
                .expect("the request");
        complete_timestamp(
            &mut document,
            &pending,
            response,
            &Completion {
                assessment,
                inputs: &untrusted,
                window: None,
                id_attributes: &[],
            },
            &account(),
        )
    });
    assert!(
        matches!(
            refused,
            Err(AugmentError::Unmet(Outcome::Timestamp {
                failure: TimestampFailure::Path(_),
                ..
            }))
        ),
        "{refused:?}"
    );
    assert_eq!(document.as_xml(), before, "nothing published");
}

#[test]
fn a_historical_countersignature_is_refused() {
    // The historical profiles carry no countersignature this library writes:
    // asking for one is refused before anything is published, rather than
    // writing an EN 319 132-1 countersignature the caller did not ask for.
    let fixture = Fixture::historical();
    let mut document = fixture.signed(Properties::default()).expect("B-B");
    let before = document.as_xml().to_owned();
    for profile in [Profile::PreEn, Profile::V111, Profile::V122] {
        let refused = fixture.countersign_in(
            &mut document,
            "sig",
            Properties {
                historical: Some(profile),
                ..Properties::default()
            },
        );
        assert!(
            matches!(refused, Err(CreateError::HistoricalProperty)),
            "{profile:?}: {refused:?}"
        );
        assert_eq!(document.as_xml(), before, "{profile:?}: nothing published");
    }
}

#[test]
fn a_historical_vocabulary_needs_a_policy_that_reads_it() {
    // The operation's XadesSyntax, not the caller's argument alone, decides
    // which vocabularies are read: under EN 319 132-1 only, creating a
    // pre-EN signature is refused before anything is published, and under
    // V1.2.2 a V1.1.1 one is.
    let syntaxes = [
        (xml_sec::policy::XadesSyntax::En319132, Profile::PreEn),
        (
            xml_sec::policy::XadesSyntax::WithTs101903V122,
            Profile::V111,
        ),
    ];
    for (syntax, profile) in syntaxes {
        let fixture = Fixture::with_syntax(syntax);
        let refused = fixture
            .signed(Properties {
                historical: Some(profile),
                policy: (profile == Profile::V111)
                    .then_some(Policy::Document(SignaturePolicy::Implied)),
                ..Properties::default()
            })
            .err()
            .expect("the policy does not read the vocabulary");
        assert!(
            matches!(
                &refused,
                CreateError::Validation(xml_sec_xades::ValidationError::Ts101903(error))
                    if matches!(**error, xml_sec_xades::Ts101903Error::NotAdmitted(named) if named == profile)
            ),
            "{syntax:?} {profile:?}: {refused:?}"
        );
    }
}

#[test]
fn the_levels_beyond_t_are_refused_in_the_earlier_vocabularies() {
    // V1.1.1 and V1.2.2 name these properties in their own namespaces, which
    // the shared writers do not produce; nothing is requested for them.
    let fixture = Fixture::historical();
    let (profile, response) = RESPONSES[2];
    let document = timestamped(&fixture, profile, response);
    let request = TimestampRequest {
        signature: "sig",
        digest: Algorithm::Sha256,
        policy: None,
        nonce: Some(NONCE),
        id_attributes: &[],
    };
    let refused = fixture.with_assessment(|assessment| {
        request_historical_extended_timestamp(
            &document,
            &request,
            ExtendedKind::Archive141,
            profile,
            assessment,
            &account(),
        )
    });
    assert!(
        matches!(refused, Err(AugmentError::HistoricalLevel(Profile::V122))),
        "{refused:?}"
    );
}
use xml_sec_xades::properties::{
    ExplicitPolicy, Identifier, Policy, PolicyTransform, Profile, Properties, SignaturePolicy,
};

const POLICY: &[u8] = b"<Policy xmlns=\"urn:policy\">Sign</Policy>";

fn policy() -> Policy<'static> {
    Policy::Document(SignaturePolicy::Explicit(ExplicitPolicy {
        identifier: Identifier {
            uri: "urn:oid:1.2.3.4.5",
            qualifier: None,
            description: None,
            documentation: &[],
        },
        document: POLICY,
        digest_method: DigestAlgorithm::Sha256.uri(),
        transform: PolicyTransform::None,
        qualifiers: &[],
    }))
}

/// The namespace of `QualifyingProperties`, the names of the signed
/// signature properties and the `Type` of the reference that signs them.
fn shape(xml: &str) -> (String, Vec<String>, String) {
    let document = roxmltree::Document::parse(xml).expect("XML parses");
    let qualifying = document
        .descendants()
        .find(|node| node.tag_name().name() == "QualifyingProperties")
        .expect("qualifying properties");
    let signed = document
        .descendants()
        .find(|node| node.tag_name().name() == "SignedSignatureProperties")
        .expect("signed signature properties")
        .children()
        .filter(roxmltree::Node::is_element)
        .map(|node| node.tag_name().name().to_owned())
        .collect();
    let kind = document
        .descendants()
        .filter(|node| node.tag_name().name() == "Reference")
        .find_map(|node| node.attribute("Type"))
        .expect("typed reference")
        .to_owned();
    (
        qualifying
            .tag_name()
            .namespace()
            .expect("namespace")
            .to_owned(),
        signed,
        kind,
    )
}

#[test]
fn each_profile_writes_its_own_vocabulary_and_meets_bes() {
    // TS 101 903 V1.1.1 §7.1 and V1.2.2 §6, TS 103 171: the properties take
    // the profile's namespace, SigningCertificate (with IssuerSerial) in
    // place of SigningCertificateV2, and the SignedProperties reference the
    // profile's Type; each signature meets the profile's BES requirements,
    // which creation checks before it publishes.
    let fixture = Fixture::historical();
    for (profile, namespace, kind) in [
        (
            Profile::V111,
            "http://uri.etsi.org/01903/v1.1.1#",
            "http://uri.etsi.org/01903/v1.1.1#SignedProperties",
        ),
        (
            Profile::V122,
            "http://uri.etsi.org/01903/v1.2.2#",
            "http://uri.etsi.org/01903/v1.2.2#SignedProperties",
        ),
        (
            Profile::PreEn,
            "http://uri.etsi.org/01903/v1.3.2#",
            "http://uri.etsi.org/01903#SignedProperties",
        ),
    ] {
        let document = fixture
            .signed(Properties {
                policy: Some(policy()),
                historical: Some(profile),
                ..Properties::default()
            })
            .unwrap_or_else(|error| panic!("{profile:?}: {error}"));
        let (written, signed, typed) = shape(document.as_xml());
        assert_eq!(written, namespace, "{profile:?}");
        assert_eq!(
            signed,
            [
                "SigningTime",
                "SigningCertificate",
                "SignaturePolicyIdentifier"
            ],
            "{profile:?}"
        );
        assert_eq!(typed, kind, "{profile:?}");
    }
}

#[test]
fn a_historical_signature_carries_only_what_its_profile_allows() {
    // TS 101 903 V1.1.1 §7.2.3 requires a signature policy; and a historical
    // signature here carries a policy beside the signing certificate and no
    // other optional property.
    let fixture = Fixture::historical();
    let missing = fixture
        .signed(Properties {
            historical: Some(Profile::V111),
            ..Properties::default()
        })
        .err()
        .expect("V1.1.1 without a policy");
    assert!(
        matches!(
            missing,
            CreateError::Properties(structured_xades::produce::Error::Value(
                "signaturePolicy.required"
            ))
        ),
        "{missing:?}"
    );
    let beyond = fixture
        .signed(Properties {
            historical: Some(Profile::V122),
            production_place: Some(xml_sec_xades::properties::ProductionPlace {
                city: Some("Prague"),
                ..xml_sec_xades::properties::ProductionPlace::default()
            }),
            ..Properties::default()
        })
        .err()
        .expect("a production place");
    assert!(
        matches!(beyond, CreateError::HistoricalProperty),
        "{beyond:?}"
    );
}
