//! ETSI TS 101 903 augmentation beyond T through the public entry points,
//! over the content fixtures.

#![cfg(feature = "produce")]

#[path = "support/content.rs"]
mod content;

use content::{CRLS, Fixture, account};
use structured_pkix::algorithm::digest::Algorithm;
use xml_sec::XmlDocument;
use xml_sec::xmldsig::DigestAlgorithm;
use xml_sec_xades::{
    CompleteReferences, Completion, DataAdded, ExtendedKind, ReferenceSyntax, Requirements,
    TimestampRequest, ValidationData, add_complete_references, add_extended_values,
    complete_timestamp, request_extended_timestamp,
};

const X_REQUEST: &[u8] = include_bytes!("fixtures/content/x.tsq");
const X_RESPONSE: &[u8] = include_bytes!("fixtures/content/x.tsr");
const A_REQUEST: &[u8] = include_bytes!("fixtures/content/a.tsq");
const A_RESPONSE: &[u8] = include_bytes!("fixtures/content/a.tsr");
const A2_REQUEST: &[u8] = include_bytes!("fixtures/content/a2.tsq");
const A2_RESPONSE: &[u8] = include_bytes!("fixtures/content/a2.tsr");
/// The nonce of the probe's extended requests.
const NONCE: &[u8] = &[0x1c, 0x2d, 0x3e, 0x4f, 0x50, 0x61, 0x72, 0x03];

/// Request the `kind` timestamp the probe requested, check it is the probe's
/// `expected` request and complete it with the TSA's `response`.
fn stamp(
    fixture: &Fixture,
    document: &mut XmlDocument,
    kind: ExtendedKind,
    [expected, response]: [&[u8]; 2],
) {
    let inputs = fixture.inputs(Requirements::Timestamped, &CRLS);
    let request = TimestampRequest {
        signature: "sig",
        digest: Algorithm::Sha256,
        policy: None,
        nonce: Some(NONCE),
        id_attributes: &[],
    };
    fixture.with_assessment(|assessment| {
        let pending =
            request_extended_timestamp(document, &request, kind, assessment, &inputs, &account())
                .expect("extended request");
        assert_eq!(pending.request(), expected, "{kind:?}");
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
        .expect("extended completion");
    });
}

/// The probe's B-T signature with its V2 complete references: XAdES-C.
fn complete(fixture: &Fixture) -> XmlDocument {
    let mut document = fixture.timestamped();
    let inputs = fixture.inputs(Requirements::Timestamped, &CRLS);
    fixture
        .with_assessment(|assessment| {
            add_complete_references(
                &mut document,
                &CompleteReferences {
                    signature: "sig",
                    syntax: ReferenceSyntax::V2,
                    digest: DigestAlgorithm::Sha256,
                    assessment,
                    inputs: &inputs,
                    id_attributes: &[],
                },
                &account(),
            )
        })
        .expect("XAdES-C");
    document
}

#[test]
fn a_complete_signature_takes_x_xl_and_a() {
    // TS 101 903 V1.4.2 §§7.5, 7.6 and 8.2: the X timestamp covers the
    // signature and its references, XL adds the values they name as direct
    // properties, and the archive timestamp covers all of it. Each request
    // is the probe's, which the TSA answered, so each covers the same input.
    let fixture = Fixture::new();
    let mut document = complete(&fixture);
    stamp(
        &fixture,
        &mut document,
        ExtendedKind::SignatureAndReferences(ReferenceSyntax::V2),
        [X_REQUEST, X_RESPONSE],
    );
    let inputs = fixture.inputs(Requirements::Timestamped, &CRLS);
    let added = fixture
        .with_assessment(|assessment| {
            add_extended_values(
                &mut document,
                &ValidationData {
                    signature: "sig",
                    assessment,
                    inputs: &inputs,
                    id_attributes: &[],
                },
                &account(),
            )
        })
        .expect("XAdES-XL");
    assert_eq!(added, DataAdded::Published);
    stamp(
        &fixture,
        &mut document,
        ExtendedKind::Archive141,
        [A_REQUEST, A_RESPONSE],
    );
    // The renewal covers the first archive timestamp too.
    stamp(
        &fixture,
        &mut document,
        ExtendedKind::Archive141,
        [A2_REQUEST, A2_RESPONSE],
    );
    assert_eq!(
        unsigned_properties(document.as_xml()),
        [
            "SignatureTimeStamp",
            "CompleteCertificateRefsV2",
            "CompleteRevocationRefs",
            "SigAndRefsTimeStampV2",
            "CertificateValues",
            "RevocationValues",
            "ArchiveTimeStamp",
            "ArchiveTimeStamp"
        ]
    );
}

#[test]
fn extended_partial_values_completed_in_held_containers() {
    // TS 101 903 V1.4.2 §§7.6.1-7.6.2 allow one CertificateValues and one
    // RevocationValues: an XAdES-XL that already holds some values, none of
    // them under an archive timestamp yet, takes the missing ones in those
    // containers.
    let fixture = Fixture::new();
    let mut document = complete(&fixture);
    stamp(
        &fixture,
        &mut document,
        ExtendedKind::SignatureAndReferences(ReferenceSyntax::V2),
        [X_REQUEST, X_RESPONSE],
    );
    let inputs = fixture.inputs(Requirements::Timestamped, &CRLS);
    let add = |document: &mut XmlDocument| {
        fixture.with_assessment(|assessment| {
            add_extended_values(
                document,
                &ValidationData {
                    signature: "sig",
                    assessment,
                    inputs: &inputs,
                    id_attributes: &[],
                },
                &account(),
            )
        })
    };
    add(&mut document).expect("XAdES-XL");
    let full = document.as_xml().to_owned();
    for local in ["EncapsulatedCRLValue", "EncapsulatedX509Certificate"] {
        let parsed = roxmltree::Document::parse(&full).expect("XML parses");
        let first = parsed
            .descendants()
            .find(|node| node.tag_name().name() == local)
            .expect("a value")
            .range();
        let partial = format!("{}{}", &full[..first.start], &full[first.end..]);
        let mut document = XmlDocument::parse(partial).expect("partial parses");
        assert_eq!(
            add(&mut document).unwrap_or_else(|error| panic!("{local}: {error}")),
            DataAdded::Published,
            "{local}"
        );
        assert_eq!(
            unsigned_properties(document.as_xml()),
            [
                "SignatureTimeStamp",
                "CompleteCertificateRefsV2",
                "CompleteRevocationRefs",
                "SigAndRefsTimeStampV2",
                "CertificateValues",
                "RevocationValues"
            ],
            "{local}"
        );
    }
}

#[test]
fn extended_timestamp_unmet_requirements_refused() {
    // The level the caller names is the basis the signature must meet when
    // its extended timestamp is requested: an XAdES-C without its values is
    // not long-term, so neither the request nor a completion may go ahead.
    let fixture = Fixture::new();
    let document = complete(&fixture);
    let inputs = fixture.inputs(Requirements::LongTerm, &CRLS);
    let request = TimestampRequest {
        signature: "sig",
        digest: Algorithm::Sha256,
        policy: None,
        nonce: Some(NONCE),
        id_attributes: &[],
    };
    let refused = fixture.with_assessment(|assessment| {
        request_extended_timestamp(
            &document,
            &request,
            ExtendedKind::SignatureAndReferences(ReferenceSyntax::V2),
            assessment,
            &inputs,
            &account(),
        )
    });
    assert!(
        matches!(refused, Err(xml_sec_xades::AugmentError::Unmet(_))),
        "{refused:?}"
    );
}

#[test]
fn extended_completion_unmet_basis_refused() {
    // The pending basis must still hold when the timestamp is completed:
    // without the caller's anchor the signature timestamp's TSA path no
    // longer reaches one, so the X timestamp is not published.
    let fixture = Fixture::new();
    let mut document = complete(&fixture);
    let before = document.as_xml().to_owned();
    let inputs = fixture.inputs(Requirements::Timestamped, &CRLS);
    let unanchored = xml_sec_xades::Inputs {
        anchors: &[],
        ..fixture.inputs(Requirements::Timestamped, &CRLS)
    };
    let request = TimestampRequest {
        signature: "sig",
        digest: Algorithm::Sha256,
        policy: None,
        nonce: Some(NONCE),
        id_attributes: &[],
    };
    let refused = fixture.with_assessment(|assessment| {
        let pending = request_extended_timestamp(
            &document,
            &request,
            ExtendedKind::SignatureAndReferences(ReferenceSyntax::V2),
            assessment,
            &inputs,
            &account(),
        )
        .expect("extended request");
        complete_timestamp(
            &mut document,
            &pending,
            X_RESPONSE,
            &Completion {
                assessment,
                inputs: &unanchored,
                window: None,
                id_attributes: &[],
            },
            &account(),
        )
    });
    assert!(
        matches!(refused, Err(xml_sec_xades::AugmentError::Unmet(_))),
        "{refused:?}"
    );
    assert_eq!(document.as_xml(), before, "nothing published");
}

/// The local names of the direct unsigned signature properties, in order.
fn unsigned_properties(xml: &str) -> Vec<String> {
    let document = roxmltree::Document::parse(xml).expect("XML parses");
    document
        .descendants()
        .find(|node| node.tag_name().name() == "UnsignedSignatureProperties")
        .expect("unsigned signature properties")
        .children()
        .filter(roxmltree::Node::is_element)
        .map(|node| node.tag_name().name().to_owned())
        .collect()
}

/// How many elements named `local` lie below the first one named `within`.
fn count(xml: &str, within: &str, local: &str) -> usize {
    let document = roxmltree::Document::parse(xml).expect("XML parses");
    document
        .descendants()
        .find(|node| node.tag_name().name() == within)
        .map_or(0, |parent| {
            parent
                .descendants()
                .filter(|node| node.tag_name().name() == local)
                .count()
        })
}

#[test]
fn complete_references_name_the_signer_path_and_its_statuses() {
    // TS 101 903 V1.4.2 §§7.4.1, 7.4.2: XAdES-C adds references to the CA
    // certificates of the signer's path, here the intermediate and the root,
    // never the signer's own, and to the CRL of each certificate's status;
    // the values are not added and the signature still meets B-T.
    let fixture = Fixture::new();
    let mut document = fixture.timestamped();
    let inputs = fixture.inputs(Requirements::Timestamped, &CRLS);
    fixture
        .with_assessment(|assessment| {
            add_complete_references(
                &mut document,
                &CompleteReferences {
                    signature: "sig",
                    syntax: ReferenceSyntax::V2,
                    digest: DigestAlgorithm::Sha256,
                    assessment,
                    inputs: &inputs,
                    id_attributes: &[],
                },
                &account(),
            )
        })
        .expect("XAdES-C");
    let xml = document.as_xml();
    assert_eq!(
        unsigned_properties(xml),
        [
            "SignatureTimeStamp",
            "CompleteCertificateRefsV2",
            "CompleteRevocationRefs"
        ]
    );
    assert_eq!(
        count(xml, "CompleteCertificateRefsV2", "Cert"),
        2,
        "the intermediate and the root"
    );
    assert_eq!(
        count(xml, "CompleteRevocationRefs", "CRLRef"),
        2,
        "one CRL per CA"
    );
    assert_eq!(
        count(xml, "Signature", "EncapsulatedCRLValue"),
        0,
        "references only"
    );
}
