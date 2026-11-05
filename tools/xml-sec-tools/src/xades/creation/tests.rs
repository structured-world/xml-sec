use super::assess;
use std::path::Path;

/// Writes a diagnostic and a detailed report with one signature `S-1` whose
/// signature value is `intact`, whose one reference is `reference_intact`, and
/// whose ISC conclusion is `isc`.
fn reports(directory: &Path, intact: bool, reference_intact: bool, isc: &str) {
    std::fs::write(
        directory.join("diagnostic.xml"),
        format!(
            "<DiagnosticData><Signatures><Signature Id=\"S-1\"><BasicSignature><SignatureIntact>{intact}</SignatureIntact></BasicSignature><DigestMatchers><DigestMatcher uri=\"#r\"><DataFound>true</DataFound><DataIntact>{reference_intact}</DataIntact></DigestMatcher></DigestMatchers></Signature></Signatures></DiagnosticData>"
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

fn problems(
    output: &str,
    signatures: usize,
    intact: bool,
    reference: bool,
    isc: &str,
) -> Vec<String> {
    let directory = tempfile::tempdir().expect("temporary directory");
    reports(directory.path(), intact, reference, isc);
    let row = assess("case", signatures, output, directory.path()).expect("reports parse");
    row["problems"]
        .as_array()
        .expect("problem list")
        .iter()
        .map(|problem| problem.as_str().expect("text").to_owned())
        .collect()
}

const B: &str = "S-1 format=XAdES-BASELINE-B indication=INDETERMINATE subindication=X errors=[]\n";

#[test]
fn an_intact_identified_baseline_signature_qualifies() {
    // Missing revocation data leaves the indication INDETERMINATE under DSS's
    // default policy; that is not a creation defect and is not checked.
    assert_eq!(problems(B, 1, true, true, "PASSED"), Vec::<String>::new());
}

#[test]
fn every_independent_finding_is_reported() {
    // Each failed condition is named, so a regression shows which property
    // DSS no longer confirms.
    let other = "S-1 format=XAdES-BES indication=TOTAL_PASSED subindication= errors=[]\n";
    assert!(problems(other, 1, true, true, "PASSED")[0].contains("not XAdES-BASELINE-B"));
    assert!(problems(B, 1, false, true, "PASSED")[0].contains("signature value not intact"));
    assert!(problems(B, 1, true, false, "PASSED")[0].contains("not found or not intact"));
    assert!(problems(B, 1, true, true, "INDETERMINATE")[0].contains("ISC"));
    let counted = problems(B, 2, true, true, "PASSED");
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
