//! ETSI TS 119 132-3 evidence records added to a B-LT signature through the
//! public entry points, over the content fixtures: `augment_probe` wrote the
//! requests of the initial and of a parallel record and the OpenSSL TSA
//! answered both.

#![cfg(feature = "produce")]

#[path = "support/content.rs"]
mod content;

use content::{CRLS, Fixture, account};
use structured_pkix::algorithm::digest::Algorithm;
use xml_sec::XmlDocument;
use xml_sec_xades::properties::Properties;
use xml_sec_xades::{
    AugmentError, Completion, CreateError, EvidenceError, PendingTimestamp, Requirements, SealKind,
    TimestampRequest, ValidationData, add_validation_data, complete_timestamp,
    request_archive_timestamp, request_evidence_record, request_timestamp,
};

const SEAL_REQUEST: &[u8] = include_bytes!("fixtures/content/seal.tsq");
const SEAL_RESPONSE: &[u8] = include_bytes!("fixtures/content/seal.tsr");
const PARALLEL_REQUEST: &[u8] = include_bytes!("fixtures/content/parallel.tsq");
const PARALLEL_RESPONSE: &[u8] = include_bytes!("fixtures/content/parallel.tsr");
/// The nonces of the probe's initial and parallel requests.
const NONCES: [&[u8]; 2] = [
    &[0x2e, 0x3f, 0x40, 0x51, 0x62, 0x73, 0x04, 0x15],
    &[0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x0f, 0x10, 0x21],
];
const ERS: &str = "urn:ietf:params:xml:ns:ers";
const XADES_ERS: &str = "http://uri.etsi.org/19132/v1.1.1#";

fn request(nonce: &'static [u8], digest: Algorithm) -> TimestampRequest<'static> {
    TimestampRequest {
        signature: "sig",
        digest,
        policy: None,
        nonce: Some(nonce),
        id_attributes: &[],
    }
}

/// The probe's B-T signature that excludes every signature from what it
/// signs, with the first generation of CRLs: B-LT.
fn long_term(fixture: &Fixture) -> XmlDocument {
    let mut document = fixture.excluding_timestamped();
    let inputs = fixture.inputs(Requirements::LongTerm, &CRLS);
    fixture
        .with_assessment(|assessment| {
            add_validation_data(
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
        .expect("B-LT");
    document
}

fn seal_request(
    fixture: &Fixture,
    document: &XmlDocument,
    kind: SealKind,
    requirements: Requirements,
) -> Result<PendingTimestamp, AugmentError> {
    // ETSI TS 119 132-3 §5: from one TSA, the parallel record hashes with
    // another algorithm.
    let (nonce, digest) = match kind {
        SealKind::Initial => (NONCES[0], Algorithm::Sha256),
        SealKind::Parallel => (NONCES[1], Algorithm::Sha512),
    };
    let inputs = fixture.inputs(requirements, &CRLS);
    fixture.with_assessment(|assessment| {
        request_evidence_record(
            document,
            &request(nonce, digest),
            kind,
            assessment,
            &inputs,
            &account(),
        )
    })
}

fn complete(
    fixture: &Fixture,
    document: &mut XmlDocument,
    pending: &PendingTimestamp,
    response: &[u8],
    requirements: Requirements,
) -> Result<(), AugmentError> {
    let inputs = fixture.inputs(requirements, &CRLS);
    fixture.with_assessment(|assessment| {
        complete_timestamp(
            document,
            pending,
            response,
            &Completion {
                assessment,
                inputs: &inputs,
                window: None,
                id_attributes: &[],
            },
            &account(),
        )
    })
}

/// The B-LT signature sealed by the fixture's initial record.
fn sealed(fixture: &Fixture) -> XmlDocument {
    let mut document = long_term(fixture);
    let pending = seal_request(
        fixture,
        &document,
        SealKind::Initial,
        Requirements::LongTerm,
    )
    .expect("seal request");
    complete(
        fixture,
        &mut document,
        &pending,
        SEAL_RESPONSE,
        Requirements::LongTerm,
    )
    .expect("seal");
    document
}

/// The sealing properties of `xml` and the evidence records of each.
fn census(xml: &str) -> Vec<usize> {
    let document = roxmltree::Document::parse(xml).expect("XML parses");
    document
        .descendants()
        .filter(|node| node.has_tag_name((XADES_ERS, "SealingEvidenceRecords")))
        .map(|property| {
            property
                .children()
                .filter(|node| node.has_tag_name((ERS, "EvidenceRecord")))
                .count()
        })
        .collect()
}

#[test]
fn seal_tsa_intermediate_only_in_document_values_published() {
    // A seal's TSA path may run through any certificate the document already
    // holds, as a level assessment's does: with nothing supplied by the
    // caller, the intermediate in the signature's CertificateValues still
    // links the TSA to the caller's anchor.
    let fixture = Fixture::new();
    let mut document = long_term(&fixture);
    let pending = seal_request(
        &fixture,
        &document,
        SealKind::Initial,
        Requirements::LongTerm,
    )
    .expect("seal request");
    let inputs = xml_sec_xades::Inputs {
        certificates: &[],
        ..fixture.inputs(Requirements::LongTerm, &CRLS)
    };
    fixture
        .with_assessment(|assessment| {
            complete_timestamp(
                &mut document,
                &pending,
                SEAL_RESPONSE,
                &Completion {
                    assessment,
                    inputs: &inputs,
                    window: None,
                    id_attributes: &[],
                },
                &account(),
            )
        })
        .expect("the TSA path reaches the anchor");
    assert_eq!(census(document.as_xml()), [1]);
}

#[test]
fn a_long_term_signature_takes_an_initial_and_a_parallel_record() {
    // The requests are the probe's, so each covers the protected objects of
    // TS 119 132-3 §5.2.2.1 the TSA's token answers; the completion verifies
    // the staged record and publishes it as the generation's one change.
    let fixture = Fixture::new();
    let mut document = long_term(&fixture);
    let pending = seal_request(
        &fixture,
        &document,
        SealKind::Initial,
        Requirements::LongTerm,
    )
    .expect("seal request");
    assert_eq!(pending.request(), SEAL_REQUEST);
    complete(
        &fixture,
        &mut document,
        &pending,
        SEAL_RESPONSE,
        Requirements::LongTerm,
    )
    .expect("seal");
    assert_eq!(census(document.as_xml()), [1]);
    let pending = seal_request(
        &fixture,
        &document,
        SealKind::Parallel,
        Requirements::LongTerm,
    )
    .expect("parallel request");
    assert_eq!(pending.request(), PARALLEL_REQUEST);
    complete(
        &fixture,
        &mut document,
        &pending,
        PARALLEL_RESPONSE,
        Requirements::LongTerm,
    )
    .expect("parallel record");
    assert_eq!(census(document.as_xml()), [2]);
}

#[test]
fn a_parallel_signature_leaves_the_sealed_one_intact() {
    // The sealed signature excludes every signature from what it signs, so
    // a new signature over the document changes nothing it or its record
    // protects; the new one is published beside it.
    let fixture = Fixture::new();
    let mut document = sealed(&fixture);
    fixture
        .sign_in(&mut document, "sig2", Properties::default())
        .expect("parallel signature");
    assert_eq!(census(document.as_xml()), [1]);
    let refused = seal_request(
        &fixture,
        &document,
        SealKind::Parallel,
        Requirements::LongTerm,
    );
    // The record's group input is unchanged, so its parallel request is the
    // probe's.
    assert_eq!(
        refused.expect("parallel request").request(),
        PARALLEL_REQUEST
    );
}

#[test]
fn a_seal_needs_long_term_validation_data() {
    // TS 119 132-3 §5.1.2: every validation datum of the signed components
    // precedes the first seal, which a B-T signature lacks.
    let fixture = Fixture::new();
    let document = fixture.timestamped();
    assert!(matches!(
        seal_request(
            &fixture,
            &document,
            SealKind::Initial,
            Requirements::Timestamped
        ),
        Err(AugmentError::BelowLongTerm(Requirements::Timestamped))
    ));
    let refused = seal_request(
        &fixture,
        &document,
        SealKind::Initial,
        Requirements::LongTerm,
    );
    assert!(
        matches!(refused, Err(AugmentError::Unmet(_))),
        "{refused:?}"
    );
}

#[test]
fn the_record_kind_must_match_the_seals_present() {
    // An initial record goes only to an unsealed signature, a parallel one
    // only next to an existing record.
    let fixture = Fixture::new();
    let unsealed = long_term(&fixture);
    let refused = seal_request(
        &fixture,
        &unsealed,
        SealKind::Parallel,
        Requirements::LongTerm,
    );
    assert!(
        matches!(&refused, Err(AugmentError::Evidence(error)) if matches!(**error, EvidenceError::Kind(SealKind::Parallel))),
        "{refused:?}"
    );
    let sealed = sealed(&fixture);
    let refused = seal_request(&fixture, &sealed, SealKind::Initial, Requirements::LongTerm);
    assert!(
        matches!(&refused, Err(AugmentError::Evidence(error)) if matches!(**error, EvidenceError::Kind(SealKind::Initial))),
        "{refused:?}"
    );
}

#[test]
fn a_token_for_another_request_publishes_nothing() {
    // The parallel token stamps the same objects under another nonce, so it
    // is no evidence for the initial request; the document is unchanged.
    let fixture = Fixture::new();
    let mut document = long_term(&fixture);
    let before = document.as_xml().to_owned();
    let pending = seal_request(
        &fixture,
        &document,
        SealKind::Initial,
        Requirements::LongTerm,
    )
    .expect("seal request");
    let refused = complete(
        &fixture,
        &mut document,
        &pending,
        PARALLEL_RESPONSE,
        Requirements::LongTerm,
    );
    assert!(
        matches!(refused, Err(AugmentError::Unproven(_))),
        "{refused:?}"
    );
    assert_eq!(document.as_xml(), before);
}

#[test]
fn a_completion_below_long_term_is_refused() {
    let fixture = Fixture::new();
    let mut document = long_term(&fixture);
    let pending = seal_request(
        &fixture,
        &document,
        SealKind::Initial,
        Requirements::LongTerm,
    )
    .expect("seal request");
    assert!(matches!(
        complete(
            &fixture,
            &mut document,
            &pending,
            SEAL_RESPONSE,
            Requirements::Timestamped
        ),
        Err(AugmentError::BelowLongTerm(Requirements::Timestamped))
    ));
}

#[test]
fn a_sealed_signature_takes_no_other_unsigned_property() {
    // TS 119 132-3 §5.1.1: after the seal only the records themselves
    // change. A timestamp, an archive timestamp, validation data and a
    // countersignature are each refused before any request is made.
    let fixture = Fixture::new();
    let mut document = sealed(&fixture);
    let inputs = fixture.inputs(Requirements::LongTerm, &CRLS);
    fixture.with_assessment(|assessment| {
        let sealed = |result: Result<PendingTimestamp, AugmentError>| {
            matches!(result, Err(AugmentError::Sealed(id)) if id == "sig")
        };
        assert!(sealed(request_timestamp(
            &document,
            &request(NONCES[0], Algorithm::Sha256),
            assessment,
            &account()
        )));
        assert!(sealed(request_archive_timestamp(
            &document,
            &request(NONCES[0], Algorithm::Sha256),
            assessment,
            &inputs,
            &account()
        )));
        let added = add_validation_data(
            &mut document,
            &ValidationData {
                signature: "sig",
                assessment,
                inputs: &inputs,
                id_attributes: &[],
            },
            &account(),
        );
        assert!(matches!(added, Err(AugmentError::Sealed(_))), "{added:?}");
    });
    let countersigned = fixture.countersign_in(&mut document, "sig", Properties::default());
    assert!(
        matches!(countersigned, Err(CreateError::Sealed(_))),
        "{countersigned:?}"
    );
}
