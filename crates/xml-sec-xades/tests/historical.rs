//! Signatures created in a historical vocabulary through the public entry
//! points, over the content fixtures: ETSI TS 101 903 V1.1.1 and V1.2.2,
//! and the TS 103 171 profile of V1.3.2.

#![cfg(feature = "produce")]

#[path = "../examples/support/asn1_policy.rs"]
mod asn1_policy;
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

#[test]
fn partial_values_completed_in_held_containers() {
    // TS 101 903 V1.1.1 §7.6 places at most one CertificateValues and one
    // RevocationValues in the UnsignedSignatureProperties sequence, and the
    // historical readers of V1.2.2 and of the TS 103 171 profile refuse a
    // second one too: a signature that already holds some of the values
    // takes the missing ones in those containers, not in second ones.
    for (profile, response) in RESPONSES {
        partial_values(profile, response);
    }
}

fn partial_values(profile: Profile, response: &[u8]) {
    let fixture = Fixture::historical();
    let mut document = timestamped(&fixture, profile, response);
    values_of(&fixture, &mut document, profile).expect("full values");
    let full = document.as_xml().to_owned();
    let count = |xml: &str, local: &str| {
        roxmltree::Document::parse(xml)
            .expect("XML parses")
            .descendants()
            .filter(|node| node.tag_name().name() == local)
            .count()
    };
    for local in ["EncapsulatedCRLValue", "EncapsulatedX509Certificate"] {
        let parsed = roxmltree::Document::parse(&full).expect("XML parses");
        let first = parsed
            .descendants()
            .find(|node| node.tag_name().name() == local)
            .expect("a value")
            .range();
        let partial = format!("{}{}", &full[..first.start], &full[first.end..]);
        let mut document = xml_sec::XmlDocument::parse(partial).expect("partial parses");
        assert_eq!(
            values_of(&fixture, &mut document, profile)
                .unwrap_or_else(|error| panic!("{local}: {error}")),
            DataAdded::Published,
            "{local}"
        );
        assert_eq!(
            unsigned_names(document.as_xml()),
            [
                "SignatureTimeStamp",
                "CertificateValues",
                "RevocationValues"
            ],
            "{local}"
        );
        assert_eq!(
            count(document.as_xml(), local),
            count(&full, local),
            "{local}"
        );
    }
}

/// Add the values `profile` needs to `document` from the fixture's CRLs.
fn values_of(
    fixture: &Fixture,
    document: &mut xml_sec::XmlDocument,
    profile: Profile,
) -> Result<DataAdded, xml_sec_xades::AugmentError> {
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
            profile,
            &account(),
        )
    })
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
    stamped(fixture, signed(fixture, profile), profile, response)
}

/// The probe's B-B signature in the vocabulary of `profile`.
fn signed(fixture: &Fixture, profile: Profile) -> xml_sec::XmlDocument {
    fixture
        .signed(Properties {
            historical: Some(profile),
            // V1.1.1 §7.2.3 requires SignaturePolicyIdentifier.
            policy: (profile == Profile::V111)
                .then_some(Policy::Document(SignaturePolicy::Implied)),
            ..Properties::default()
        })
        .unwrap_or_else(|error| panic!("{profile:?}: {error}"))
}

/// `document`, a signature in the vocabulary of `profile`, completed with
/// its signature timestamp `response`.
fn stamped(
    fixture: &Fixture,
    mut document: xml_sec::XmlDocument,
    profile: Profile,
    response: &[u8],
) -> xml_sec::XmlDocument {
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

/// The archive TSA's CA and its CRL; that TSA's answer to the pre-EN archive
/// timestamp request, and the TSA's answer to the second archive timestamp
/// request after the first one's validation data.
const ARCHIVE_CA: &[u8] = include_bytes!("fixtures/content/archive-ca.der");
const ARCHIVE_CRL: &[u8] = include_bytes!("fixtures/content/archive-ca.crl");
const A_PRE_EN_OTHER: &[u8] = include_bytes!("fixtures/content/a-pre-en-other.tsr");
const A2_PRE_EN: &[u8] = include_bytes!("fixtures/content/a2-pre-en.tsr");
/// The TSA's answer to the signature timestamp request of the V1.1.1
/// signature whose canonicalization names the `PrefixList` `ds`.
const PREFIXED_V111: &[u8] = include_bytes!("fixtures/content/prefixed-v111.tsr");

/// Request and complete one `kind` timestamp of the pre-EN signature.
fn stamp(
    fixture: &Fixture,
    document: &mut xml_sec::XmlDocument,
    kind: ExtendedKind,
    response: &[u8],
) {
    stamp_with(
        fixture,
        document,
        kind,
        response,
        &fixture.inputs(Requirements::LongTerm, &CRLS),
    );
}

/// [`stamp`] completed under `inputs`.
fn stamp_with(
    fixture: &Fixture,
    document: &mut xml_sec::XmlDocument,
    kind: ExtendedKind,
    response: &[u8],
    inputs: &Inputs<'_>,
) {
    let request = TimestampRequest {
        signature: "sig",
        digest: Algorithm::Sha256,
        policy: None,
        nonce: Some(NONCE),
        id_attributes: &[],
    };
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
                inputs,
                window: None,
                id_attributes: &[],
            },
            &account(),
        )
        .unwrap_or_else(|error| panic!("{kind:?}: {error}"));
    });
}

/// Add the values the pre-EN signature's census finds missing.
fn values(fixture: &Fixture, document: &mut xml_sec::XmlDocument) -> DataAdded {
    values_with(
        fixture,
        document,
        &fixture.inputs(Requirements::LongTerm, &CRLS),
    )
}

/// [`values`] from `inputs`.
fn values_with(
    fixture: &Fixture,
    document: &mut xml_sec::XmlDocument,
    inputs: &Inputs<'_>,
) -> DataAdded {
    fixture.with_assessment(|assessment| {
        add_historical_values(
            document,
            &ValidationData {
                signature: "sig",
                assessment,
                inputs,
                id_attributes: &[],
            },
            Profile::PreEn,
            &account(),
        )
        .expect("values")
    })
}

#[test]
fn a_pre_en_signature_goes_through_the_ts101903_levels() {
    // TS 101 903 V1.4.2 §§7.4-7.7 and 8.2, in the names of V1.3.2 the
    // TS 103 171 profile keeps: the complete references of XAdES-C, the X
    // timestamp over the signature, its timestamp and the references, the
    // values of XAdES-XL, then the archive timestamp of XAdES-A, each
    // published only while the signature meets BES.
    let fixture = Fixture::historical();
    let mut document = pre_en_xl(&fixture);
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
    // One CA issues the signer's and the TSA's certificates, so the values
    // already hold every copy the archive timestamp's TSA needs: before a
    // second archive timestamp nothing is added, no TimeStampValidationData
    // duplicates them (TS 101 903 V1.4.2 §8.1.1 allows usable copies
    // elsewhere in the signature).
    let archived = document.as_xml().to_owned();
    assert_eq!(values(&fixture, &mut document), DataAdded::AlreadyPresent);
    assert_eq!(document.as_xml(), archived);
}

#[test]
fn a_second_archive_timestamp_follows_the_first_ones_tsa_data() {
    // TS 101 903 V1.4.2 §8.1.1 and TS 103 171 V2.1.1 §8.1.5, as DSS's
    // XAdESDoubleATest: the first archive timestamp comes from a TSA under a
    // CA the signature holds nothing of. Before the second, that TSA's values
    // go into a TimeStampValidationData right after the first archive
    // timestamp, outside its input and never into the values it covers; the
    // second archive timestamp then covers them.
    let fixture = Fixture::historical();
    let mut document = pre_en_xl(&fixture);
    let (certificates, crls) = (
        [content::INTERMEDIATE, ARCHIVE_CA],
        [CRLS[0], CRLS[1], ARCHIVE_CRL],
    );
    let inputs = Inputs {
        certificates: &certificates,
        crls: &crls,
        ..fixture.inputs(Requirements::LongTerm, &[])
    };
    stamp_with(
        &fixture,
        &mut document,
        ExtendedKind::Archive141,
        A_PRE_EN_OTHER,
        &inputs,
    );
    let encoded = |der: &[u8]| {
        structured_base64::STANDARD
            .encode(der)
            .expect("fixture base64")
    };
    assert!(!document.as_xml().contains(&encoded(ARCHIVE_CA)));
    assert_eq!(
        values_with(&fixture, &mut document, &inputs),
        DataAdded::Published
    );
    let xl = [
        "SignatureTimeStamp",
        "CompleteCertificateRefs",
        "CompleteRevocationRefs",
        "SigAndRefsTimeStamp",
        "CertificateValues",
        "RevocationValues",
    ];
    assert_eq!(
        unsigned_names(document.as_xml()),
        [&xl[..], &["ArchiveTimeStamp", "TimeStampValidationData"]].concat()
    );
    for value in [ARCHIVE_CA, ARCHIVE_CRL] {
        assert!(document.as_xml().contains(&encoded(value)));
    }
    // The copy after its timestamp is found: a second call adds nothing.
    assert_eq!(
        values_with(&fixture, &mut document, &inputs),
        DataAdded::AlreadyPresent
    );
    stamp_with(
        &fixture,
        &mut document,
        ExtendedKind::Archive141,
        A2_PRE_EN,
        &inputs,
    );
    assert_eq!(
        unsigned_names(document.as_xml()),
        [
            &xl[..],
            &[
                "ArchiveTimeStamp",
                "TimeStampValidationData",
                "ArchiveTimeStamp"
            ]
        ]
        .concat()
    );
}

#[test]
fn a_canonicalization_prefix_list_is_repeated_in_the_timestamp() {
    // TS 101 903 V1.1.1 §7.3: the SignatureTimeStamp names the signature's
    // canonicalization with its parameters. Exclusive C14N §3 reads the
    // InclusiveNamespaces PrefixList from the CanonicalizationMethod itself,
    // so a signature that names one takes its timestamp, and the timestamp
    // repeats the list.
    let fixture = Fixture::historical();
    let prefixed = fixture.with_prefix_list(&signed(&fixture, Profile::V111));
    let document = stamped(&fixture, prefixed, Profile::V111, PREFIXED_V111);
    let parsed = roxmltree::Document::parse(document.as_xml()).expect("XML parses");
    let methods: Vec<_> = parsed
        .descendants()
        .filter(|node| node.tag_name().name() == "InclusiveNamespaces")
        .map(|node| node.attribute("PrefixList"))
        .collect();
    // The SignedInfo method's and the timestamp transform's copy.
    assert_eq!(methods, [Some("ds"), Some("ds")]);
}

/// The probe's pre-EN signature at XAdES-XL: its signature timestamp, the
/// complete references, the X timestamp and the values.
fn pre_en_xl(fixture: &Fixture) -> xml_sec::XmlDocument {
    let (_, response) = RESPONSES[0];
    let mut document = timestamped(fixture, Profile::PreEn, response);
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
        fixture,
        &mut document,
        ExtendedKind::SignatureAndReferences(ReferenceSyntax::Original),
        X_PRE_EN,
    );
    values(fixture, &mut document);
    document
}

#[test]
fn historical_v2_references_refused_before_writing() {
    // CompleteCertificateRefsV2 and SigAndRefsTimeStampV2 are the names of
    // EN 319 132-1 Annex A; the TS 103 171 profile of V1.3.2 has only the
    // original ones, so a historical signature refuses V2 up front.
    let fixture = Fixture::historical();
    let (_, response) = RESPONSES[0];
    let mut document = timestamped(&fixture, Profile::PreEn, response);
    let before = document.as_xml().to_owned();
    let inputs = fixture.inputs(Requirements::LongTerm, &CRLS);
    let request = TimestampRequest {
        signature: "sig",
        digest: Algorithm::Sha256,
        policy: None,
        nonce: Some(NONCE),
        id_attributes: &[],
    };
    fixture.with_assessment(|assessment| {
        let references = add_historical_references(
            &mut document,
            &CompleteReferences {
                signature: "sig",
                syntax: ReferenceSyntax::V2,
                digest: DigestAlgorithm::Sha256,
                assessment,
                inputs: &inputs,
                id_attributes: &[],
            },
            Profile::PreEn,
            &account(),
        );
        assert!(
            matches!(
                references,
                Err(AugmentError::HistoricalReferenceSyntax(ReferenceSyntax::V2))
            ),
            "{references:?}"
        );
        let timestamp = request_historical_extended_timestamp(
            &document,
            &request,
            ExtendedKind::SignatureAndReferences(ReferenceSyntax::V2),
            Profile::PreEn,
            assessment,
            &account(),
        );
        assert!(
            matches!(
                timestamp,
                Err(AugmentError::HistoricalReferenceSyntax(ReferenceSyntax::V2))
            ),
            "{timestamp:?}"
        );
    });
    assert_eq!(document.as_xml(), before);
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
fn historical_timestamp_malformed_unrelated_crl_published() {
    // A completion checks only the TSA paths; revocation material is not
    // part of it, so a CRL it never reads cannot refuse the timestamp.
    let fixture = Fixture::historical();
    let (profile, response) = RESPONSES[0];
    let mut document = fixture
        .signed(Properties {
            historical: Some(profile),
            ..Properties::default()
        })
        .expect("pre-EN B-B");
    let request = TimestampRequest {
        signature: "sig",
        digest: Algorithm::Sha256,
        policy: None,
        nonce: Some(NONCE),
        id_attributes: &[],
    };
    let malformed: [&[u8]; 1] = [b"not a CRL"];
    let inputs = fixture.inputs(Requirements::Timestamped, &malformed);
    fixture.with_assessment(|assessment| {
        let pending =
            request_historical_timestamp(&document, &request, profile, assessment, &account())
                .expect("the request");
        complete_timestamp(
            &mut document,
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
        .expect("the timestamp is published");
    });
}

#[test]
fn historical_policy_digested_in_specification_refused_as_beyond_profile() {
    // EN 319 132-1 §5.2.9.2 introduced the policy digested as its
    // specification defines; TS 101 903 has no such transform, so even with
    // the rule supplied a historical signature cannot carry it, and creation
    // refuses it as beyond the profile before anything is signed.
    let fixture = Fixture::historical();
    let der = asn1_policy::document(None);
    let explicit = ExplicitPolicy {
        identifier: Identifier {
            uri: asn1_policy::POLICY_OID,
            qualifier: Some(Qualifier::Urn),
            description: None,
            documentation: &[],
        },
        document: &der,
        digest_method: DigestAlgorithm::Sha256.uri(),
        transform: PolicyTransform::InSpecification(Identifier {
            uri: asn1_policy::SPECIFICATION,
            qualifier: None,
            description: None,
            documentation: &[],
        }),
        qualifiers: &[],
    };
    let refused = fixture.signed(Properties {
        historical: Some(Profile::PreEn),
        policy: Some(Policy::Document(SignaturePolicy::Explicit(explicit))),
        specified: Some(SpecifiedDigest {
            specification: asn1_policy::SPECIFICATION,
            rule: DigestRule::Asn1Policy,
        }),
        ..Properties::default()
    });
    let refused = refused.err().expect("refused");
    assert!(
        matches!(refused, CreateError::HistoricalProperty),
        "{refused:?}"
    );
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
    DigestRule, ExplicitPolicy, Identifier, Policy, PolicyTransform, Profile, Properties,
    Qualifier, SignaturePolicy, SpecifiedDigest,
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
