use super::{
    Actor, Algorithm, Evidence, Packaging, cases, compare, deviations, element, preserved, refusal,
    xml_sec_outcome,
};
use serde_json::json;
use std::collections::BTreeSet;

#[test]
fn every_case_has_its_own_name_and_alternates_the_implementations() {
    // Both directions cover every packaging and signer with CRL and OCSP
    // evidence; the step after creation and the renewal swap implementations,
    // so each step is validated by the side that did not make it.
    let cases = cases();
    assert_eq!(cases.len(), 2 * (4 * 2 * 2 + 1));
    let names: BTreeSet<String> = cases.iter().map(|case| case.name()).collect();
    assert_eq!(names.len(), cases.len());
    for first in [Actor::XmlSec, Actor::Dss] {
        for packaging in Packaging::ALL {
            for algorithm in [Algorithm::Rsa, Algorithm::Ec] {
                for evidence in [Evidence::Crl, Evidence::Ocsp] {
                    assert!(cases.contains(&super::Case {
                        first,
                        packaging,
                        algorithm,
                        evidence
                    }));
                }
            }
        }
    }
    let revoked: Vec<_> = cases
        .iter()
        .filter(|case| case.evidence == Evidence::Revoked)
        .collect();
    assert_eq!(revoked.len(), 2);
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
fn an_element_is_cut_at_its_own_end_tag_under_any_prefix() {
    // DSS writes `ds:` prefixes and xml-sec may not; an end tag of another
    // element or a closing tag must never be taken as the start.
    let text = r#"<a><ds:SignedInfo Id="x"><ds:Reference/></ds:SignedInfo><SignatureValue>AA==</SignatureValue></a>"#;
    assert_eq!(
        element(text, "SignedInfo"),
        Some(r#"<ds:SignedInfo Id="x"><ds:Reference/></ds:SignedInfo>"#)
    );
    assert_eq!(
        element(text, "SignatureValue"),
        Some("<SignatureValue>AA==</SignatureValue>")
    );
    assert_eq!(element(text, "Missing"), None);
    assert_eq!(element("<SignedInfo>unterminated", "SignedInfo"), None);
}

#[test]
fn preservation_requires_both_signature_parts_unchanged() {
    // An augmentation that re-serializes the signed part, or changes the
    // value, no longer carries the created signature.
    let created = "<S><SignedInfo>a</SignedInfo><SignatureValue>v</SignatureValue></S>";
    let augmented = "<S><SignedInfo>a</SignedInfo><SignatureValue>v</SignatureValue><Q/></S>";
    assert!(preserved(created, augmented));
    assert!(!preserved(
        created,
        "<S><SignedInfo >a</SignedInfo><SignatureValue>v</SignatureValue></S>"
    ));
    assert!(!preserved(
        created,
        "<S><SignedInfo>a</SignedInfo><SignatureValue>w</SignatureValue></S>"
    ));
    assert!(!preserved("<S/>", created));
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
