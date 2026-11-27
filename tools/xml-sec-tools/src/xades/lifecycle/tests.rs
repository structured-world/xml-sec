use super::{
    Actor, Algorithm, Evidence, Packaging, cases, compare, deviations, preserved, refusal,
    xml_sec_outcome,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;

#[test]
fn the_short_p521_alternative_needs_the_short_encoding() {
    // The reviewed alternative describes DSS's 130-octet P-521 value; the
    // same refusal of a conformant 132-octet value keeps the primary
    // expectation and fails the comparison.
    let expected = json!({ "cases": { "p521": {
        "steps": [{ "step": "b", "validated": { "crypto": "Valid" } }],
        "alternatives": [{ "note": "p521", "steps": [
            { "step": "b", "signature_octets": 130, "validated": { "crypto": "Err" } }
        ] }]
    } } });
    let observed = |octets: u64| {
        json!({ "case": "p521", "steps": [
            { "step": "b", "signature_octets": octets, "validated": { "crypto": "Err" } }
        ] })
    };
    assert_eq!(compare(&expected, &[observed(130)]), Vec::<String>::new());
    assert_eq!(
        compare(&expected, &[observed(132)]),
        ["p521[0].validated.crypto: expected \"Valid\", got \"Err\""]
    );
    // The recorded alternative carries that condition.
    let recorded: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../interop/xades/lifecycle/expectations.json"
    ))
    .expect("expectations parse");
    assert_eq!(
        recorded["cases"]["dss-first-enveloping-ec-p521-crl"]["alternatives"][0]["steps"][0]["signature_octets"],
        130
    );
    let created = signature(
        "s",
        "<SignedInfo>a</SignedInfo><SignatureValue>AAEC\nAw==</SignatureValue>",
    );
    assert_eq!(super::signature_octets(&created), Ok(4));
}

#[test]
fn unreadable_expectations_are_never_recorded_over() {
    // A first recording starts from nothing; an existing file that does not
    // parse is an error, so its reviewed alternatives and notes are not
    // replaced by this run's outcomes.
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("expectations.json");
    assert_eq!(super::previous_expectations(&path), Ok(Value::Null));
    std::fs::write(&path, "{ \"cases\": ").expect("write");
    assert!(super::previous_expectations(&path).is_err());
    std::fs::write(&path, "{ \"cases\": {} }").expect("write");
    assert_eq!(
        super::previous_expectations(&path),
        Ok(json!({ "cases": {} }))
    );
}

#[test]
fn every_signature_keeps_its_ber_reading_and_dss_crypto_result() {
    // A later signature whose BER reading or whose signature value DSS finds
    // broken must show in its own entry, not be hidden by the first one.
    let der = json!({ "crypto": "Valid", "structure": "Tokens",
        "others": [{ "crypto": "Valid", "structure": "Tokens" }] });
    let ber = json!({ "structure": "met", "others": [{ "structure": "unmet" }] });
    let merged = super::with_ber(der, &ber);
    assert_eq!(merged["structure_ber"], "met");
    assert_eq!(merged["others"][0]["structure_ber"], "unmet");
    // One signature keeps the shape its recorded expectations have.
    let single = super::with_ber(
        json!({ "structure": "Tokens" }),
        &json!({ "structure": "met" }),
    );
    assert_eq!(
        single,
        json!({ "structure": "Tokens", "structure_ber": "met" })
    );

    let reports = tempfile::tempdir().expect("temporary directory");
    std::fs::write(
        reports.path().join("diagnostic.xml"),
        "<DiagnosticData><Signatures>\
         <Signature Id=\"S-1\"><BasicSignature><SignatureIntact>true</SignatureIntact></BasicSignature></Signature>\
         <Signature Id=\"S-2\"><BasicSignature><SignatureIntact>false</SignatureIntact></BasicSignature></Signature>\
         </Signatures></DiagnosticData>",
    )
    .expect("write diagnostic report");
    // EN 319 102-1 building blocks: each signature's own conclusions,
    // matched by token, beside its entry.
    std::fs::write(
        reports.path().join("detailed.xml"),
        "<DetailedReport>\
         <BasicBuildingBlocks Id=\"S-1\" Type=\"SIGNATURE\"><CV><Conclusion><Indication>PASSED</Indication></Conclusion></CV></BasicBuildingBlocks>\
         <BasicBuildingBlocks Id=\"S-2\" Type=\"COUNTER_SIGNATURE\"><CV><Conclusion><Indication>FAILED</Indication><SubIndication>SIG_CRYPTO_FAILURE</SubIndication></Conclusion></CV></BasicBuildingBlocks>\
         </DetailedReport>",
    )
    .expect("write detailed report");
    std::fs::write(
        reports.path().join("simple.xml"),
        "<SimpleReport><Signature Id=\"S-1\"/><Signature Id=\"S-2\"/></SimpleReport>",
    )
    .expect("write simple report");
    let output = "S-1 format=XAdES-BASELINE-B indication=TOTAL_PASSED subindication=null errors=[]\n\
                  S-2 format=XAdES-BASELINE-B indication=TOTAL_FAILED subindication=SIG_CRYPTO_FAILURE errors=[]\n";
    let outcome = super::dss_outcome(output, reports.path()).expect("reports read");
    assert_eq!(outcome["crypto"], "intact");
    assert_eq!(outcome["others"][0]["crypto"], "broken");
    assert_eq!(outcome["blocks"]["CV"], "PASSED");
    assert_eq!(
        outcome["others"][0]["blocks"]["CV"],
        "FAILED:SIG_CRYPTO_FAILURE"
    );
}

#[test]
fn xml_sec_verdicts_stand_beside_each_signature() {
    // The corpus probe's facts give one verdict per block and signature, in
    // document order; a later signature's verdicts go to its own entry.
    let facts = json!({ "signatures": [
        { "declared_timestamps": 0, "verification": { "status": "Valid", "references": ["Valid"], "trust": "ValidatedX509" } },
        { "declared_timestamps": 0, "verification": { "status": "Invalid", "references": ["Valid"], "trust": "ValidatedX509" } }
    ] });
    let verdicts = super::our_verdicts(&facts);
    let outcome = super::with_blocks(
        json!({ "crypto": "Valid", "others": [{ "crypto": "Invalid" }] }),
        verdicts,
    );
    assert_eq!(outcome["blocks"]["CV"], "pass");
    assert_eq!(outcome["blocks"]["TIMESTAMPS"], "none");
    assert_eq!(outcome["others"][0]["blocks"]["CV"], "fail");
}

#[test]
fn recording_a_reviewed_alternative_keeps_the_expected_outcome() {
    // A run that happens to observe the reviewed refusal must not replace the
    // conformant expectation with it; a new outcome is recorded for review
    // and keeps the reviewed alternatives.
    let previous = json!({
        "steps": [{ "step": "b", "made": "made" }],
        "alternatives": [{ "note": "p521", "steps": [{ "step": "b", "made": { "refused": "r" } }] }]
    });
    let refused = json!([{ "step": "b", "made": { "refused": "r" } }]);
    assert_eq!(super::recorded_case(&previous, &refused), previous);
    let new = json!([{ "step": "b", "made": { "refused": "other" } }]);
    assert_eq!(
        super::recorded_case(&previous, &new),
        json!({ "steps": new, "alternatives": previous["alternatives"] })
    );
    assert_eq!(
        super::recorded_case(&serde_json::Value::Null, &refused),
        json!({ "steps": refused })
    );
}

#[test]
fn a_reviewed_alternative_outcome_matches_and_an_unknown_one_does_not() {
    // DSS's randomized r || s width makes one P-521 lifecycle end either way;
    // both reviewed outcomes match, anything else is a deviation of the
    // expected one.
    let expected = json!({ "cases": { "c": {
        "steps": [{ "step": "b", "made": "made" }],
        "alternatives": [{ "note": "p521", "steps": [{ "step": "b", "made": { "refused": "r" } }] }]
    } } });
    let row =
        |made: serde_json::Value| json!({ "case": "c", "steps": [{ "step": "b", "made": made }] });
    assert_eq!(
        compare(&expected, &[row(json!("made"))]),
        Vec::<String>::new()
    );
    assert_eq!(
        compare(&expected, &[row(json!({ "refused": "r" }))]),
        Vec::<String>::new()
    );
    assert_eq!(
        compare(&expected, &[row(json!({ "refused": "other" }))]),
        ["c[0].made: expected \"made\", got {\"refused\":\"other\"}"]
    );
}

#[test]
fn every_signature_after_the_first_is_reported_and_one_signature_keeps_its_shape() {
    // A form with several signatures must not hide a refused countersignature
    // behind a valid first signature; a single signature's outcome keeps the
    // fields the existing expectations record, with no `others`.
    let one = "signature: Ok(Valid)\nlevel: Ok(Assessed(true))\n";
    let single = xml_sec_outcome(one);
    assert!(single.get("others").is_none());
    assert_eq!(single["crypto"], "Valid");
    let several = format!("{one}signature: Ok(Valid)\nlevel: Ok(Assessed(false))\n");
    assert_eq!(
        xml_sec_outcome(&several)["others"],
        json!([{ "crypto": "Valid", "structure": "unmet" }])
    );
}

#[test]
fn every_case_has_its_own_name_and_alternates_the_implementations() {
    // Both directions cover every packaging and signer with CRL and OCSP
    // evidence, and every further algorithm over an enveloping signature;
    // the step after creation and the renewal swap implementations, so each
    // step is validated by the side that did not make it.
    let cases = cases();
    // Each form runs in both directions, except DSS's indented serialization,
    // which only DSS makes.
    let forms = 2 * Packaging::FORMS.len() - 1;
    assert_eq!(
        cases.len(),
        2 * (4 * 2 * 2 + 1 + Algorithm::MORE.len()) + forms
    );
    for packaging in Packaging::FORMS {
        let dss_first = super::Case {
            first: Actor::Dss,
            packaging,
            algorithm: Algorithm::Rsa,
            evidence: Evidence::Crl,
        };
        assert!(cases.contains(&dss_first), "missing {}", dss_first.name());
        let xml_sec_first = super::Case {
            first: Actor::XmlSec,
            ..dss_first
        };
        assert_eq!(
            cases.contains(&xml_sec_first),
            packaging != Packaging::PrettyPrint,
            "{}: only DSS makes the indented form",
            xml_sec_first.name()
        );
    }
    for first in [Actor::XmlSec, Actor::Dss] {
        for algorithm in Algorithm::MORE {
            let case = super::Case {
                first,
                packaging: Packaging::Enveloping,
                algorithm,
                evidence: Evidence::Crl,
            };
            assert!(cases.contains(&case), "missing {}", case.name());
        }
    }
    let names: BTreeSet<String> = cases.iter().map(|case| case.name()).collect();
    assert_eq!(names.len(), cases.len(), "two cases share a name");
    for first in [Actor::XmlSec, Actor::Dss] {
        for packaging in Packaging::ALL {
            for algorithm in [Algorithm::Rsa, Algorithm::Ec] {
                for evidence in [Evidence::Crl, Evidence::Ocsp] {
                    let case = super::Case {
                        first,
                        packaging,
                        algorithm,
                        evidence,
                    };
                    assert!(cases.contains(&case), "missing {}", case.name());
                }
            }
        }
    }
    let revoked: Vec<_> = cases
        .iter()
        .filter(|case| case.evidence == Evidence::Revoked)
        .collect();
    assert_eq!(revoked.len(), 2, "one revoked case per direction");
    let case = cases[0];
    assert_eq!(case.name(), "xml-sec-first-enveloped-rsa-crl");
    let actors: Vec<Actor> = case.steps().iter().map(|(_, actor)| *actor).collect();
    assert_eq!(
        actors,
        [
            Actor::XmlSec,
            Actor::Dss,
            Actor::Dss,
            Actor::Dss,
            Actor::XmlSec
        ]
    );
}

#[test]
fn parts_are_matched_by_expanded_name_and_owner() {
    // An application element that shares a local name with a XAdES container
    // is not one: changing it keeps the signature, changing the real
    // property does not.
    let document = |application: &str, property: &str| {
        format!(
            concat!(
                r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" "#,
                r#"xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="s">"#,
                "<ds:SignedInfo>a</ds:SignedInfo><ds:SignatureValue>v</ds:SignatureValue>",
                "<ds:Object><xades:QualifyingProperties><xades:UnsignedProperties>",
                "<xades:UnsignedSignatureProperties>{}</xades:UnsignedSignatureProperties>",
                "</xades:UnsignedProperties></xades:QualifyingProperties></ds:Object>",
                r#"<ds:Object><app:UnsignedSignatureProperties xmlns:app="urn:app">"#,
                "{}</app:UnsignedSignatureProperties></ds:Object></ds:Signature>"
            ),
            property, application
        )
    };
    let earlier = document("<A>1</A>", "<xades:T>1</xades:T>");
    let kept = |later: &str| preserved(&earlier, &earlier, later).unwrap();
    assert!(kept(&document("<A>2</A>", "<xades:T>1</xades:T>")));
    assert!(!kept(&document("<A>1</A>", "<xades:T>9</xades:T>")));
}

#[test]
fn signature_parts_match_under_any_prefix() {
    // DSS writes `ds:` prefixes and xml-sec may not: parts match by expanded
    // name, and their bytes are compared exactly as the documents hold them.
    let created = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo Id="x"><ds:Reference/></ds:SignedInfo><SignatureValue xmlns="http://www.w3.org/2000/09/xmldsig#">AA==</SignatureValue></ds:Signature>"#;
    let appended = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo Id="x"><ds:Reference/></ds:SignedInfo><SignatureValue xmlns="http://www.w3.org/2000/09/xmldsig#">AA==</SignatureValue><ds:Object/></ds:Signature>"#;
    assert!(preserved(created, created, appended).unwrap());
    let rewritten = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo Id="x"><ds:Reference /></ds:SignedInfo><SignatureValue xmlns="http://www.w3.org/2000/09/xmldsig#">AA==</SignatureValue></ds:Signature>"#;
    assert!(!preserved(created, created, rewritten).unwrap());
}

/// `body` inside an `XMLDSig` `Signature` with the given `Id`.
fn signature(id: &str, body: &str) -> String {
    format!(
        r#"<Signature xmlns="http://www.w3.org/2000/09/xmldsig#" xmlns:x="http://uri.etsi.org/01903/v1.3.2#" Id="{id}">{body}</Signature>"#
    )
}

/// `properties` as the unsigned signature properties of a signature.
fn unsigned(properties: &str) -> String {
    format!(
        "<Object><x:QualifyingProperties><x:UnsignedProperties><x:UnsignedSignatureProperties>{properties}</x:UnsignedSignatureProperties></x:UnsignedProperties></x:QualifyingProperties></Object>"
    )
}

#[test]
fn preservation_requires_both_signature_parts_unchanged() {
    // An augmentation that re-serializes the signed part, or changes the
    // value, no longer carries the created signature.
    let created = signature(
        "s",
        "<SignedInfo>a</SignedInfo><SignatureValue>v</SignatureValue>",
    );
    let augmented = signature(
        "s",
        "<SignedInfo>a</SignedInfo><SignatureValue>v</SignatureValue><Object/>",
    );
    let kept = |later: &str| preserved(&created, &created, later).unwrap();
    assert!(kept(&augmented));
    assert!(!kept(&signature(
        "s",
        "<SignedInfo >a</SignedInfo><SignatureValue>v</SignatureValue>"
    )));
    assert!(!kept(&signature(
        "s",
        "<SignedInfo>a</SignedInfo><SignatureValue>w</SignatureValue>"
    )));
    assert!(!preserved("<S/>", "<S/>", &created).unwrap());
}

#[test]
fn preservation_holds_for_every_signature_of_the_document() {
    // A later parallel signature or a countersignature keeps its signed parts
    // and earlier unsigned properties too, matched by the signature's Id: a
    // step that rewrites only the second signature is no preservation.
    let signed = |id: &str, value: &str, properties: &str| {
        signature(
            id,
            &format!(
                "<SignedInfo>{id}</SignedInfo><SignatureValue>{value}</SignatureValue>{}",
                unsigned(properties)
            ),
        )
    };
    let document = |second_value: &str, second_unsigned: &str| {
        format!(
            "<D>{}{}</D>",
            signed("one", "v1", "<T>1</T>"),
            signed("two", second_value, second_unsigned)
        )
    };
    let earlier = document("v2", "<T>2</T>");
    let kept = |later: &str| preserved(&earlier, &earlier, later).unwrap();
    assert!(kept(&document("v2", "<T>2</T><V>3</V>")));
    assert!(!kept(&document("w2", "<T>2</T>")));
    assert!(!kept(&document("v2", "<T>9</T>")));
    assert!(!kept(&format!(
        "<D>{}</D>",
        signed("one", "v1", "<T>1</T>")
    )));
}

#[test]
fn preservation_requires_earlier_unsigned_properties_unchanged() {
    // A later step only appends: rewriting or dropping a property an earlier
    // step made, such as its timestamp or evidence, is not preservation.
    let signed = "<SignedInfo>a</SignedInfo><SignatureValue>v</SignatureValue>";
    let document = |properties: &str| signature("s", &format!("{signed}{}", unsigned(properties)));
    let timestamped = document(r#"<T xmlns:a="urn:a">1</T>"#);
    let kept = |later: &str| preserved(&timestamped, &timestamped, later).unwrap();
    assert!(kept(&document(r#"<T xmlns:a="urn:a">1</T><V>2</V>"#)));
    // An archive timestamp covers the exclusive canonical form, so dropping a
    // namespace declaration nothing uses, as EU DSS does when it serializes
    // the document again, changes nothing it covers.
    assert!(kept(&document("<T>1</T><V>2</V>")));
    assert!(!kept(&document("<T>9</T><V>2</V>")));
    assert!(!kept(&document("<V>2</V><T>1</T>")));
    assert!(!kept(&signature("s", signed)));
}

#[test]
fn the_xml_sec_report_separates_crypto_from_structure() {
    // A met level, an unmet one and an outcome that stopped validation are
    // three different structural results; trust is never claimed.
    let met = xml_sec_outcome("signature: Ok(Valid)\nlevel: Ok(Assessed(true))\n");
    assert_eq!(
        met,
        json!({ "crypto": "Valid", "structure": "met", "trust": "not assessed" })
    );
    let unmet = xml_sec_outcome("signature: Ok(Valid)\nlevel: Ok(Assessed(false))\n");
    assert_eq!(unmet["structure"], "unmet");
    let stopped = xml_sec_outcome("signature: Ok(Valid)\nlevel: Ok(Timestamp(Rejected))\n");
    assert_eq!(stopped["structure"], "Timestamp");
    let missing = xml_sec_outcome("");
    assert_eq!(missing["crypto"], serde_json::Value::Null);
}

#[test]
fn a_refusal_is_the_stated_reason_not_a_stack_frame() {
    // Expectations compare the reason, so it must be the message a probe
    // gives, stable across runs, never the frame that happens to come last.
    assert_eq!(
        refusal("refused revoked signer\n", "noise"),
        "revoked signer"
    );
    let java = "SLF4J(W): No providers\nException in thread \"main\" java.lang.NullPointerException: ID not defined\n\tat SignProbe.main(SignProbe.java:48)\n";
    assert_eq!(
        refusal("", java),
        "java.lang.NullPointerException: ID not defined"
    );
    assert_eq!(
        refusal("", "Error: \"archive request: below B-LT\"\n"),
        "archive request: below B-LT"
    );
    assert_eq!(refusal("", "first\nlast\n\n"), "last");
    assert_eq!(refusal("", ""), "");
    // A fresh PKI changes certificate hashes and offsets, never the reason.
    assert_eq!(
        refusal(
            "refused Revoked/Suspended certificate(s) detected. [C-1218: Certificate is revoked/suspended!]\n",
            ""
        ),
        "Revoked/Suspended certificate(s) detected."
    );
    assert_eq!(
        refusal(
            "",
            "Error: \"validation data: timestamp check failed: Token(Callback { offset: 1100 })\"\n"
        ),
        "validation data: timestamp check failed: Token"
    );
    // A variant's payload is cut whatever it opens with, so a unit or tuple
    // payload is no part of the recorded reason; only the variant name is.
    assert_eq!(
        refusal(
            "",
            "Error: \"completion: the required level is not met: Assessed(())\"\n"
        ),
        "completion: the required level is not met: Assessed"
    );
}

#[test]
fn a_deviation_names_the_field_and_ignores_notes() {
    // Explanations change without changing an outcome; any compared field
    // that differs, or is missing, is reported with its path.
    let expected =
        json!({ "made": "made", "validated": { "trust": "TOTAL_PASSED/", "note": "why" } });
    let mut found = Vec::new();
    deviations(
        &expected,
        &json!({ "made": "made", "validated": { "trust": "TOTAL_PASSED/" } }),
        "c[0]",
        &mut found,
    );
    assert!(found.is_empty(), "{found:?}");
    deviations(
        &expected,
        &json!({ "made": { "refused": "no" } }),
        "c[0]",
        &mut found,
    );
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(found[0].starts_with("c[0].made: expected"));
    assert!(found[1].starts_with("c[0].validated.trust: expected"));
}

#[test]
fn every_case_must_match_and_none_may_be_missing_or_extra() {
    // A case without an expectation, a step count change and an expected case
    // that did not run are each a failure, never a silent skip.
    let expected = json!({ "cases": {
        "a": { "steps": [{ "made": "made" }, { "made": "made" }] },
        "gone": { "steps": [] },
    }});
    let observed = vec![
        json!({ "case": "a", "steps": [{ "made": "made" }] }),
        json!({ "case": "new", "steps": [] }),
    ];
    let found = compare(&expected, &observed);
    assert_eq!(
        found,
        [
            "a: 2 steps expected, 1 observed",
            "new: no expectation",
            "gone: expected but not run",
        ]
    );
    let complete = [
        json!({ "case": "a", "steps": [{ "made": "made" }, { "made": "made" }] }),
        json!({ "case": "gone", "steps": [] }),
    ];
    assert_eq!(compare(&expected, &complete), Vec::<String>::new());
}
