use super::{Case, assess};
use std::path::Path;

/// Writes a diagnostic and a detailed report with one signature `S-1` whose
/// signature value is `intact`, whose one reference is `reference_intact`, and
/// whose ISC conclusion is `isc`, plus these `timestamps` reports.
fn reports(directory: &Path, intact: bool, reference_intact: bool, isc: &str, timestamps: &str) {
    std::fs::write(
        directory.join("diagnostic.xml"),
        format!(
            "<DiagnosticData><Signatures><Signature Id=\"S-1\"><BasicSignature><SignatureIntact>{intact}</SignatureIntact></BasicSignature><DigestMatchers><DigestMatcher uri=\"#r\"><DataFound>true</DataFound><DataIntact>{reference_intact}</DataIntact></DigestMatcher></DigestMatchers></Signature></Signatures><UsedTimestamps>{timestamps}</UsedTimestamps></DiagnosticData>"
        ),
    )
    .expect("write diagnostic report");
    std::fs::write(
        directory.join("detailed.xml"),
        format!(
            "<DetailedReport><BasicBuildingBlocks Id=\"S-1\" Type=\"SIGNATURE\"><ISC><Conclusion><Indication>{isc}</Indication></Conclusion></ISC><CV><Conclusion><Indication>PASSED</Indication></Conclusion></CV></BasicBuildingBlocks></DetailedReport>"
        ),
    )
    .expect("write detailed report");
}

/// One timestamp report whose signature value and message imprint are as given.
fn timestamp(intact: bool, imprint: bool) -> String {
    format!(
        "<Timestamp Id=\"T-1\"><DigestMatchers><DigestMatcher type=\"MESSAGE_IMPRINT\"><DataFound>true</DataFound><DataIntact>{imprint}</DataIntact></DigestMatcher></DigestMatchers><BasicSignature><SignatureIntact>{intact}</SignatureIntact></BasicSignature></Timestamp>"
    )
}

const BASIC: Case = Case {
    name: "case",
    signatures: 1,
    format: "XAdES-BASELINE-B",
    timestamps: 0,
    fixtures: "creation",
};

const TIMESTAMPED: Case = Case {
    format: "XAdES-BASELINE-T",
    timestamps: 1,
    ..BASIC
};

struct Reported<'a> {
    output: &'a str,
    intact: bool,
    reference: bool,
    isc: &'a str,
    timestamps: &'a str,
}

const INTACT: Reported<'static> = Reported {
    output: B,
    intact: true,
    reference: true,
    isc: "PASSED",
    timestamps: "",
};

fn problems(case: &Case, reported: &Reported<'_>) -> Vec<String> {
    let directory = tempfile::tempdir().expect("temporary directory");
    reports(
        directory.path(),
        reported.intact,
        reported.reference,
        reported.isc,
        reported.timestamps,
    );
    let row = assess(case, reported.output, directory.path()).expect("reports parse");
    row["problems"]
        .as_array()
        .expect("problem list")
        .iter()
        .map(|problem| problem.as_str().expect("text").to_owned())
        .collect()
}

const B: &str = "S-1 format=XAdES-BASELINE-B indication=INDETERMINATE subindication=X errors=[]\n";
const T: &str = "S-1 format=XAdES-BASELINE-T indication=INDETERMINATE subindication=X errors=[]\n";

#[test]
fn an_intact_identified_baseline_signature_qualifies() {
    // Missing revocation data leaves the indication INDETERMINATE under DSS's
    // default policy; that is not a creation defect and is not checked.
    assert_eq!(problems(&BASIC, &INTACT), Vec::<String>::new());
}

#[test]
fn every_independent_finding_is_reported() {
    // Each failed condition is named, so a regression shows which property
    // DSS no longer confirms.
    let other = Reported {
        output: "S-1 format=XAdES-BES indication=TOTAL_PASSED subindication= errors=[]\n",
        ..INTACT
    };
    assert!(problems(&BASIC, &other)[0].contains("not XAdES-BASELINE-B"));
    let broken = Reported {
        intact: false,
        ..INTACT
    };
    assert!(problems(&BASIC, &broken)[0].contains("signature value not intact"));
    let missing = Reported {
        reference: false,
        ..INTACT
    };
    assert!(problems(&BASIC, &missing)[0].contains("not found or not intact"));
    let unidentified = Reported {
        isc: "INDETERMINATE",
        ..INTACT
    };
    assert!(problems(&BASIC, &unidentified)[0].contains("ISC"));
    let counted = problems(
        &Case {
            signatures: 2,
            ..BASIC
        },
        &INTACT,
    );
    assert!(
        counted
            .iter()
            .any(|problem| problem.contains("1 signatures reported, 2 expected"))
    );
    assert!(
        counted
            .iter()
            .any(|problem| problem.contains("1 signature blocks, 2 expected"))
    );
}

#[test]
fn a_timestamped_signature_needs_an_intact_token() {
    // B-T needs the token's own signature and its imprint over the signature
    // value confirmed, not only the signature's classification.
    let stamped = timestamp(true, true);
    let intact = Reported {
        output: T,
        timestamps: &stamped,
        ..INTACT
    };
    assert_eq!(problems(&TIMESTAMPED, &intact), Vec::<String>::new());
    let broken = timestamp(false, true);
    assert!(
        problems(
            &TIMESTAMPED,
            &Reported {
                timestamps: &broken,
                ..intact
            }
        )[0]
        .contains("timestamp signature not intact")
    );
    let other = timestamp(true, false);
    assert!(
        problems(
            &TIMESTAMPED,
            &Reported {
                timestamps: &other,
                ..intact
            }
        )[0]
        .contains("message imprint not found or not intact")
    );
    assert!(
        problems(
            &TIMESTAMPED,
            &Reported {
                timestamps: "",
                ..intact
            }
        )[0]
        .contains("0 timestamps, 1 expected")
    );
}
