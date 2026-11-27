use super::{Case, FORMS, Form, assess, assess_form, detached_files};
use std::path::Path;

#[test]
fn a_dss_form_qualifies_only_with_every_signature_valid_at_b_b() {
    // `level_probe` prints one `signature:`/`level:` pair per signature; each
    // must be a valid signature that meets B-B, and the count must match the
    // form, so a countersignature xml-sec did not read is a problem too.
    let form = Form {
        name: "countersigned",
        signatures: 2,
    };
    let valid = "signature: Ok(Valid)\nlevel: Ok(Assessed(true))\n";
    let accepted = assess_form(&form, &valid.repeat(2));
    assert_eq!(accepted["problems"], serde_json::json!([]));
    let refused = format!(
        "{valid}signature: Ok(Invalid(ReferenceProcessingFailure {{ ref_index: 1 }}))\nlevel: Err(Prepare(Binding(Target)))\n"
    );
    let problems = assess_form(&form, &refused)["problems"].clone();
    assert_eq!(problems.as_array().map(Vec::len), Some(1));
    assert!(problems[0].as_str().unwrap().starts_with("signature 1: "));
    let missing = assess_form(&form, valid)["problems"].clone();
    assert_eq!(missing[0], "1 signatures reported, 2 expected");
}

#[test]
fn every_form_with_detached_references_names_its_files() {
    // The detached forms are validated with the files their references name;
    // the others need none.
    for form in FORMS {
        let files = detached_files(form.name);
        assert_eq!(files.is_empty(), !form.name.starts_with("detached"));
    }
    assert_eq!(
        detached_files("detached-multiple"),
        ["detached.txt", "detached-2.txt"]
    );
}

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
    let row =
        assess(case, reported.output, directory.path(), "<Document/>").expect("reports parse");
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
fn a_property_dss_did_not_read_is_reported() {
    // A case with optional properties qualifies only when DSS reads each of
    // them back: a policy whose stored document's digest does not match, or
    // a commitment DSS does not see, is named. A matching certificate digest
    // elsewhere in the report does not stand in for the policy's.
    let diagnostic = |policy: &str| {
        format!(
            "<DiagnosticData><Signature><Policy><Id>1.3.6.1.4.1.13762.3.1</Id><Identified>true</Identified><Organization>Example Organization</Organization><ExplicitText>Signed under the example policy</ExplicitText>{policy}</Policy><CertificateRef><DigestAlgoAndValue match=\"true\"/></CertificateRef></Signature></DiagnosticData>"
        )
    };
    let problems_of = |name: &str, text: &str| {
        let document = super::xml::parse(text, "diagnostic").expect("parses");
        let mut problems = Vec::new();
        super::property_problems(name, document.root_element(), &mut problems);
        problems
    };
    let matched = diagnostic("<DigestAlgoAndValue match=\"true\"/>");
    assert_eq!(
        problems_of("policy-explicit", &matched),
        Vec::<String>::new()
    );
    let mismatched = diagnostic("<DigestAlgoAndValue match=\"false\"/>");
    assert_eq!(
        problems_of("policy-explicit", &mismatched),
        ["DSS did not read Policy/DigestAlgoAndValue@match \"true\""]
    );
    assert_eq!(
        problems_of("commitment", &matched).len(),
        2,
        "no commitment was read"
    );
    assert_eq!(problems_of("enveloped", &matched), Vec::<String>::new());
}

/// The problems `property_problems` finds for case `name` in `text`.
fn diagnostic_problems(name: &str, text: &str) -> Vec<String> {
    let document = super::xml::parse(text, "diagnostic").expect("parses");
    let mut problems = Vec::new();
    super::property_problems(name, document.root_element(), &mut problems);
    problems
}

#[test]
fn facts_that_belong_together_are_read_together() {
    // Each commitment with its own scope: the identifiers and scopes found
    // in two different indications do not stand for the pairs.
    let commitment = |origin: &str, approval: &str| {
        format!(
            "<DiagnosticData><Signature><CommitmentTypeIndication><Identifier>http://uri.etsi.org/01903/v1.2.2#ProofOfOrigin</Identifier>{origin}</CommitmentTypeIndication><CommitmentTypeIndication><Identifier>http://uri.etsi.org/01903/v1.2.2#ProofOfApproval</Identifier>{approval}</CommitmentTypeIndication></Signature></DiagnosticData>"
        )
    };
    let all = "<AllDataSignedObjects>true</AllDataSignedObjects>";
    let one = "<ObjectReference>sig-reference-1</ObjectReference>";
    assert_eq!(
        diagnostic_problems("commitment", &commitment(all, one)),
        Vec::<String>::new()
    );
    assert_eq!(
        diagnostic_problems("commitment", &commitment(one, all)).len(),
        2
    );
}

#[test]
fn a_fact_of_one_signature_is_read_in_that_signature() {
    // The store added to `sig` matches its policy and `second` has none: a
    // store attached to `second` instead is reported, though the document
    // still holds both a match and a mismatch.
    let signature = |id: &str, matched: &str, identified: &str| {
        format!(
            "<Signature><BasicSignature/><DAIdentifier>{id}</DAIdentifier><Policy><Id>1.3.6.1.4.1.13762.3.1</Id><Identified>{identified}</Identified><DigestAlgoAndValue match=\"{matched}\"/></Policy></Signature>"
        )
    };
    let document = |first: (&str, &str), second: (&str, &str)| {
        format!(
            "<DiagnosticData><Signatures>{}{}</Signatures></DiagnosticData>",
            signature("sig", first.0, first.1),
            signature("second", second.0, second.1)
        )
    };
    assert_eq!(
        diagnostic_problems(
            "policy-store-added",
            &document(("true", "true"), ("false", "false"))
        ),
        Vec::<String>::new()
    );
    assert_eq!(
        diagnostic_problems(
            "policy-store-added",
            &document(("false", "false"), ("true", "true"))
        )
        .len(),
        4
    );
}

#[test]
fn counted_facts_need_their_number() {
    // Two all-data-object timestamps, not one of each role; both Manifests
    // of a two-Manifest signature.
    let timestamps = |kinds: [&str; 2]| {
        format!(
            "<DiagnosticData><Timestamp Type=\"{}\"/><Timestamp Type=\"{}\"/></DiagnosticData>",
            kinds[0], kinds[1]
        )
    };
    let all = "ALL_DATA_OBJECTS_TIMESTAMP";
    let individual = "INDIVIDUAL_DATA_OBJECTS_TIMESTAMP";
    assert_eq!(
        diagnostic_problems("content-repeated", &timestamps([all, all])),
        Vec::<String>::new()
    );
    assert_eq!(
        diagnostic_problems("content-repeated", &timestamps([all, individual])).len(),
        1
    );
    let manifests = "<DiagnosticData><DigestMatcher type=\"MANIFEST\"/><DigestMatcher type=\"MANIFEST_ENTRY\"/></DiagnosticData>";
    assert_eq!(diagnostic_problems("manifest-multiple", manifests).len(), 2);
}

#[test]
fn the_format_details_are_read_in_the_created_document() {
    // DSS keeps only the MIME type of a DataObjectFormat: the description,
    // identifier and encoding are checked in the document itself.
    let format = |description: &str| {
        format!(
            "<Root><DataObjectFormat ObjectReference=\"#sig-reference-0\"><Description>{description}</Description><ObjectIdentifier><Identifier>urn:oid:1.2.840.113549.1.7.1</Identifier></ObjectIdentifier><Encoding>http://www.w3.org/2000/09/xmldsig#base64</Encoding></DataObjectFormat></Root>"
        )
    };
    let problems_of = |document: &str| {
        let mut problems = Vec::new();
        super::document_problems("data-object-format", document, &mut problems);
        problems
    };
    assert_eq!(
        problems_of(&format("Base64 encoded text")),
        Vec::<String>::new()
    );
    assert_eq!(problems_of(&format("other")).len(), 1);
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
