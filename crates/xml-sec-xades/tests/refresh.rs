//! Fresher validation data added to a signature that already meets B-LT,
//! through the public entry points, over the content fixtures.

#![cfg(feature = "produce")]

#[path = "support/content.rs"]
mod content;

use content::{CRLS, Fixture, NEXT_CRLS, account};
use xml_sec::XmlDocument;
use xml_sec_xades::{
    DataAdded, Inputs, Requirements, ValidationData, add_validation_data, refresh_validation_data,
};

/// An empty delta over the intermediate CA's first CRL.
const DELTA: &[u8] = include_bytes!("fixtures/content/intermediate-delta.crl");
/// The intermediate CA's CRL listing the signer, revoked after its timestamp.
const REVOKING: &[u8] = include_bytes!("fixtures/content/intermediate-revoking.crl");
/// A response stating the same revocation.
const REVOKED: &[u8] = include_bytes!("fixtures/content/signer-revoked.ocsp");
/// Responses for the signer and the TSA their CA signed.
const OCSP: [&[u8]; 2] = [
    include_bytes!("fixtures/content/signer.ocsp"),
    include_bytes!("fixtures/content/tsa.ocsp"),
];

fn extend(
    fixture: &Fixture,
    document: &mut XmlDocument,
    crls: &[&[u8]],
    refresh: bool,
) -> Result<DataAdded, xml_sec_xades::AugmentError> {
    extend_with(fixture, document, crls, &[], refresh)
}

fn extend_with(
    fixture: &Fixture,
    document: &mut XmlDocument,
    crls: &[&[u8]],
    responses: &[&[u8]],
    refresh: bool,
) -> Result<DataAdded, xml_sec_xades::AugmentError> {
    let inputs = Inputs {
        responses,
        ..fixture.inputs(Requirements::LongTerm, crls)
    };
    fixture.with_assessment(|assessment| {
        let data = ValidationData {
            signature: "sig",
            assessment,
            inputs: &inputs,
            id_attributes: &[],
        };
        if refresh {
            refresh_validation_data(document, &data, &account())
        } else {
            add_validation_data(document, &data, &account())
        }
    })
}

/// How many elements of local name `local` the document carries.
fn count(xml: &str, local: &str) -> usize {
    roxmltree::Document::parse(xml)
        .expect("XML parses")
        .descendants()
        .filter(|node| node.tag_name().name() == local)
        .count()
}

/// How many `EncapsulatedCRLValue`s the document carries.
fn crls(xml: &str) -> usize {
    count(xml, "EncapsulatedCRLValue")
}

#[test]
fn a_refresh_takes_the_callers_crl_over_the_documents_ocsp_response() {
    // A refresh takes each member's status from the caller first, whatever
    // kind it is: the signer's newer CRL beats the OCSP response the
    // document already carries, and is added.
    let fixture = Fixture::new();
    let mut document = fixture.timestamped();
    assert_eq!(
        extend_with(&fixture, &mut document, &CRLS[..1], &OCSP, false)
            .expect("B-LT over the OCSP response"),
        DataAdded::Published
    );
    assert_eq!(
        count(document.as_xml(), "EncapsulatedOCSPValue"),
        2,
        "both members' statuses are the OCSP responses"
    );
    let before = crls(document.as_xml());
    assert_eq!(
        extend_with(&fixture, &mut document, &NEXT_CRLS[1..], &[], true).expect("refresh"),
        DataAdded::Published
    );
    assert_eq!(crls(document.as_xml()), before + 1);
}

#[test]
fn a_refresh_binds_the_callers_delta_to_the_documents_complete_crl() {
    // RFC 5280 §5.2.4: a delta needs its base complete list, which the
    // document may already carry. Once the document holds the intermediate
    // CA's complete CRL and OCSP responses for its members, a refresh given
    // only the caller's delta over that CRL takes the delta before the
    // document's OCSP responses, and adds it.
    let fixture = Fixture::new();
    let mut document = fixture.timestamped();
    assert_eq!(
        extend(&fixture, &mut document, &CRLS, false).expect("B-LT from the CRLs"),
        DataAdded::Published
    );
    assert_eq!(
        extend_with(&fixture, &mut document, &[], &OCSP, true)
            .expect("refresh with the OCSP responses"),
        DataAdded::Published
    );
    let before = crls(document.as_xml());
    assert_eq!(
        extend_with(&fixture, &mut document, &[DELTA], &[], true).expect("refresh with the delta"),
        DataAdded::Published
    );
    assert_eq!(crls(document.as_xml()), before + 1);
}

#[test]
fn a_refresh_takes_the_callers_revoked_response_for_a_listed_member() {
    // RFC 5280 §6.3.3(i): a listed entry decides whatever another source
    // omits, so a good response never hides it; a caller's response that
    // also states revocation is still the caller's status and is added.
    let fixture = Fixture::new();
    let mut document = fixture.timestamped();
    assert_eq!(
        extend(&fixture, &mut document, &[CRLS[0], REVOKING], false)
            .expect("B-LT with the signer listed"),
        DataAdded::Published
    );
    let before = count(document.as_xml(), "EncapsulatedOCSPValue");
    assert_eq!(
        extend_with(&fixture, &mut document, &[], &[REVOKED], true)
            .expect("refresh with the revoked response"),
        DataAdded::Published
    );
    assert_eq!(
        count(document.as_xml(), "EncapsulatedOCSPValue"),
        before + 1
    );
}

#[test]
fn a_refresh_adds_the_fresher_statuses_a_complete_signature_lacks() {
    // EN 319 132-1 §5.5.2: a B-LT signature may take fresher validation data
    // before its next archive. Adding the missing data finds nothing once the
    // first CRLs are incorporated; a refresh takes each path member's status
    // from the caller's newer CRLs, adds them beside the old ones and keeps
    // B-LT, and a second refresh with the same CRLs adds nothing.
    let fixture = Fixture::new();
    let mut document = fixture.timestamped();
    assert_eq!(
        extend(&fixture, &mut document, &CRLS, false).expect("B-LT"),
        DataAdded::Published
    );
    assert_eq!(crls(document.as_xml()), 2);
    let complete = document.as_xml().to_owned();
    assert_eq!(
        extend(&fixture, &mut document, &NEXT_CRLS, false).expect("nothing missing"),
        DataAdded::AlreadyPresent
    );
    assert_eq!(document.as_xml(), complete, "missing data only");
    assert_eq!(
        extend(&fixture, &mut document, &NEXT_CRLS, true).expect("refresh"),
        DataAdded::Published
    );
    assert_eq!(crls(document.as_xml()), 4, "both generations are carried");
    let refreshed = document.as_xml().to_owned();
    assert_eq!(
        extend(&fixture, &mut document, &NEXT_CRLS, true).expect("second refresh"),
        DataAdded::AlreadyPresent
    );
    assert_eq!(document.as_xml(), refreshed);
}
