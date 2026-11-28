//! ETSI TS 119 132-3 evidence records of one B-LT signature, over the content
//! fixtures, through the public augmentation API.

use std::path::Path;

use structured_asn1::memory::Memory;
use structured_pkix::algorithm::digest::Algorithm;
use structured_pkix::temporal::LeapTable;
use xml_sec::XmlDocument;
use xml_sec_xades::{
    Assessment, Completion, Inputs, Requirements, SealKind, TimestampRequest, ValidationData,
    add_validation_data, complete_timestamp, request_evidence_record,
};

/// The nonces of the initial and the parallel record's requests.
const NONCES: [&[u8]; 2] = [
    &[0x2e, 0x3f, 0x40, 0x51, 0x62, 0x73, 0x04, 0x15],
    &[0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x0f, 0x10, 0x21],
];

/// Writes one named output file.
type Write<'w> = dyn Fn(&str, &[u8]) -> Result<(), String> + 'w;

/// Take the B-T `document` to B-LT and seal it as `action` says:
/// `seal-request` writes the initial record's request `seal.tsq`, `seal`
/// completes it with `seal.tsr` and writes `e-ers.xml`, `parallel-request`
/// goes on to write the parallel record's request `parallel.tsq`, and
/// `parallel` completes both and also writes `e-ers-parallel.xml`.
pub(crate) fn sealed(
    document: &mut XmlDocument,
    assessment: &Assessment<'_, '_>,
    fixtures: &Path,
    [root, intermediate]: [&[u8]; 2],
    action: &str,
    write: &Write<'_>,
    work: &Memory,
) -> Result<(), String> {
    let read = |name: &str| {
        std::fs::read(fixtures.join(name)).map_err(|error| format!("read {name}: {error}"))
    };
    let lists = [read("root.crl")?, read("intermediate.crl")?];
    let crls: [&[u8]; 2] = [&lists[0], &lists[1]];
    let utc = LeapTable::new(-2_208_988_800, 4_102_444_800, &[])
        .map_err(|error| format!("UTC coverage: {error:?}"))?;
    let (anchors, certificates) = ([root], [intermediate]);
    let inputs = Inputs {
        requirements: Requirements::LongTerm,
        anchors: &anchors,
        certificates: &certificates,
        utc: &utc,
        accuracies: &[],
        responders: &[],
        crls: &crls,
        responses: &[],
    };
    add_validation_data(
        document,
        &ValidationData {
            signature: "sig",
            assessment,
            inputs: &inputs,
            id_attributes: &[],
        },
        work,
    )
    .map_err(|error| format!("validation data: {error}"))?;
    let completion = Completion {
        assessment,
        inputs: &inputs,
        window: None,
        id_attributes: &[],
    };
    // ETSI TS 119 132-3 §5: parallel records come from different TSAs or use
    // different hash algorithms; with one TSA, the parallel record hashes
    // with SHA-512.
    for (kind, nonce, digest, query, response, sealed) in [
        (
            SealKind::Initial,
            NONCES[0],
            Algorithm::Sha256,
            "seal.tsq",
            "seal.tsr",
            "e-ers.xml",
        ),
        (
            SealKind::Parallel,
            NONCES[1],
            Algorithm::Sha512,
            "parallel.tsq",
            "parallel.tsr",
            "e-ers-parallel.xml",
        ),
    ] {
        let request = TimestampRequest {
            signature: "sig",
            digest,
            policy: None,
            nonce: Some(nonce),
            id_attributes: &[],
        };
        let pending = request_evidence_record(document, &request, kind, assessment, &inputs, work)
            .map_err(|error| format!("{query}: {error}"))?;
        if action == format!("{}-request", query.trim_end_matches(".tsq")) {
            return write(query, pending.request());
        }
        complete_timestamp(document, &pending, &read(response)?, &completion, work)
            .map_err(|error| format!("{response}: {error}"))?;
        write(sealed, document.as_xml().as_bytes())?;
        if action == query.trim_end_matches(".tsq") {
            return Ok(());
        }
    }
    Ok(())
}
