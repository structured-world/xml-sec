use super::{Operation, accepted, case_name, distribution, qualified, report, selected};
use crate::xades::lifecycle::{Actor, Algorithm, Packaging};
use serde_json::json;

#[test]
fn a_dss_reading_qualifies_an_xml_sec_result_only_at_its_level() {
    // DSS must find the signature intact in exactly that baseline format, and
    // once evidence is complete it must also pass it.
    let reading = |structure: &str, trust: &str| json!({ "crypto": "intact", "structure": structure, "trust": trust });
    let indeterminate = "INDETERMINATE/CERTIFICATE_CHAIN_GENERAL_FAILURE";
    assert!(qualified(
        Actor::XmlSec,
        "b",
        &reading("XAdES-BASELINE-B", indeterminate)
    ));
    assert!(qualified(
        Actor::XmlSec,
        "lta",
        &reading("XAdES-BASELINE-LTA", "TOTAL_PASSED/null")
    ));
    // A lower format than the step claims is not the step's result.
    assert!(!qualified(
        Actor::XmlSec,
        "lt",
        &reading("XAdES-BASELINE-T", "TOTAL_PASSED/null")
    ));
    // Complete evidence that does not pass is not a qualified B-LT.
    assert!(!qualified(
        Actor::XmlSec,
        "lt",
        &reading("XAdES-BASELINE-LT", indeterminate)
    ));
    let broken = json!({ "crypto": "broken", "structure": "XAdES-BASELINE-B" });
    assert!(!qualified(Actor::XmlSec, "b", &broken));
}

#[test]
fn an_xml_sec_reading_qualifies_a_dss_result_under_its_cms_profile() {
    // DSS's tokens are BER; the declared DER reading refuses them, so the CMS
    // profile decides, and a level it finds unmet is not equivalent work.
    let met = json!({ "crypto": "Valid", "structure": "Tokens", "structure_ber": "met" });
    assert!(qualified(Actor::Dss, "t", &met));
    let unmet = json!({ "crypto": "Valid", "structure": "Tokens", "structure_ber": "unmet" });
    assert!(!qualified(Actor::Dss, "lt", &unmet));
    let invalid = json!({ "crypto": "Invalid", "structure_ber": "met" });
    assert!(!qualified(Actor::Dss, "b", &invalid));
}

#[test]
fn a_validation_is_equivalent_only_when_it_accepts_its_input() {
    // A refusal path is different work from an acceptance.
    assert!(accepted(
        Actor::XmlSec,
        "lta",
        "signature: Ok(Valid)\nlevel: Ok(Assessed(true))\n"
    ));
    assert!(!accepted(
        Actor::XmlSec,
        "lta",
        "signature: Ok(Valid)\nlevel: Ok(Assessed(false))\n"
    ));
    let dss = |format: &str, indication: &str| {
        format!("id-1 format={format} indication={indication} subindication=null errors=[]\n")
    };
    assert!(accepted(
        Actor::Dss,
        "lta",
        &dss("XAdES-BASELINE-LTA", "TOTAL_PASSED")
    ));
    assert!(accepted(
        Actor::Dss,
        "b",
        &dss("XAdES-BASELINE-B", "INDETERMINATE")
    ));
    assert!(!accepted(
        Actor::Dss,
        "lta",
        &dss("XAdES-BASELINE-LTA", "INDETERMINATE")
    ));
    // The LTA label must not satisfy the LT check by prefix.
    assert!(!accepted(
        Actor::Dss,
        "lt",
        &dss("XAdES-BASELINE-LTA", "TOTAL_PASSED")
    ));
    assert!(!accepted(Actor::Dss, "b", ""));
}

#[test]
fn a_report_must_describe_the_requested_measurement() {
    // A harness that measured something else, or a sample short, must not
    // pass for the requested series.
    let line = |engine: &str, operation: &str, samples: &[u64]| {
        format!(
            "noise\n{}\n",
            json!({ "engine": engine, "operation": operation, "samples_ns": samples })
        )
    };
    let renew = line("xml-sec", "augment-renew", &[5, 7]);
    assert!(report(&renew, Actor::XmlSec, Operation::Renew, 2).is_ok());
    assert!(report(&renew, Actor::XmlSec, Operation::Renew, 3).is_err());
    assert!(report(&renew, Actor::Dss, Operation::Renew, 2).is_err());
    let dss = line("dss", "augment-lta", &[9]);
    assert!(report(&dss, Actor::Dss, Operation::Renew, 1).is_ok());
    assert!(report(&dss, Actor::Dss, Operation::AugmentLta, 1).is_ok());
    let zero = line("xml-sec", "create", &[0]);
    assert!(report(&zero, Actor::XmlSec, Operation::Create, 1).is_err());
    assert!(report("not json", Actor::XmlSec, Operation::Create, 1).is_err());
}

#[test]
fn a_distribution_keeps_every_raw_sample() {
    let summary = distribution(&[30, 10, 20]).unwrap();
    assert_eq!(summary["raw_ns"], json!([30, 10, 20]));
    assert_eq!(summary["p50_ns"], json!(20));
    assert_eq!(summary["p99_ns"], json!(30));
    assert!(distribution(&[]).is_err());
}

#[test]
fn every_operation_starts_from_the_chain_step_below_its_result() {
    // An augmentation reads the document one level below what it makes; a
    // validation reads the document of its own level.
    for operation in Operation::ALL {
        let expected = match operation {
            Operation::Create => None,
            Operation::ValidateBasic | Operation::AugmentT => Some("b"),
            Operation::AugmentLt => Some("t"),
            Operation::AugmentLta => Some("lt"),
            Operation::Renew | Operation::ValidateArchival => Some("lta"),
        };
        assert_eq!(operation.input(), expected, "{}", operation.name());
    }
    assert!(Operation::ValidateBasic.validates() && !Operation::Renew.validates());
}

#[test]
fn cases_are_selected_by_name_or_all() {
    assert_eq!(selected(None).unwrap().len(), 8);
    let chosen = selected(Some("enveloped-rsa,detached-ec")).unwrap();
    assert_eq!(
        chosen,
        [
            (Packaging::Enveloped, Algorithm::Rsa),
            (Packaging::Detached, Algorithm::Ec)
        ]
    );
    assert_eq!(
        case_name(Packaging::InternallyDetached, Algorithm::Ec),
        "internally-detached-ec"
    );
    assert!(selected(Some("enveloped-dsa")).is_err());
}
