use super::{BLOCKS, automatic_class, compare, differences, dss_signatures, observed, our_blocks};
use serde_json::{Value, json};

const DIAGNOSTIC: &str = r#"<DiagnosticData xmlns="http://dss.esig.europa.eu/validation/diagnostic">
  <Signatures>
    <Signature Id="S-1"><DAIdentifier>sig</DAIdentifier></Signature>
  </Signatures>
  <UsedTimestamps>
    <Timestamp Id="T-1"><TimestampedObjects>
      <TimestampedObject Token="S-1" Category="SIGNATURE"/>
    </TimestampedObjects></Timestamp>
    <Timestamp Id="T-2"><TimestampedObjects>
      <TimestampedObject Token="S-other" Category="SIGNATURE"/>
    </TimestampedObjects></Timestamp>
  </UsedTimestamps>
</DiagnosticData>"#;

const DETAILED: &str = r#"<DetailedReport xmlns="http://dss.esig.europa.eu/validation/detailed-report">
  <BasicBuildingBlocks Id="S-1" Type="SIGNATURE">
    <FC><Conclusion><Indication>PASSED</Indication></Conclusion></FC>
    <ISC><Conclusion><Indication>PASSED</Indication></Conclusion></ISC>
    <CV><Conclusion><Indication>PASSED</Indication></Conclusion></CV>
    <XCV><Conclusion><Indication>INDETERMINATE</Indication></Conclusion></XCV>
    <SAV><Conclusion><Indication>PASSED</Indication></Conclusion></SAV>
  </BasicBuildingBlocks>
  <BasicBuildingBlocks Id="T-1" Type="TIMESTAMP">
    <Conclusion><Indication>PASSED</Indication></Conclusion>
  </BasicBuildingBlocks>
  <BasicBuildingBlocks Id="T-2" Type="TIMESTAMP">
    <Conclusion><Indication>FAILED</Indication></Conclusion>
  </BasicBuildingBlocks>
</DetailedReport>"#;

/// Facts of a signature that verified with a validated path and met B-B and B-T.
fn verified() -> Value {
    json!({
        "id": "sig",
        "verification": { "status": "Valid", "trust": "ValidatedX509", "references": ["Valid", "Valid"] },
        "basic": { "bound": true, "included": true, "assessed": true },
        "timestamped": { "assessed": true },
    })
}

#[test]
fn a_signature_keeps_only_the_timestamps_that_cover_it() {
    // T-2 covers another signature; its FAILED block must not reach S-1.
    let signatures = dss_signatures(DIAGNOSTIC, DETAILED).unwrap();
    assert_eq!(signatures.len(), 1);
    assert_eq!(signatures[0]["id"], "sig");
    assert_eq!(signatures[0]["blocks"]["XCV"], "INDETERMINATE");
    assert_eq!(signatures[0]["blocks"]["TIMESTAMPS"], "PASSED");
}

#[test]
fn each_block_compares_with_its_own_fact() {
    let signatures = dss_signatures(DIAGNOSTIC, DETAILED).unwrap();
    let rows = compare(&signatures, &[verified()], true);
    let blocks = &rows[0]["blocks"];
    for name in ["FC", "ISC", "CV", "SAV", "TIMESTAMPS"] {
        assert_eq!(blocks[name]["agrees"], true, "{name}");
    }
    // DSS cannot conclude the chain without revocation data, while the path
    // xml-sec validated needs none: a difference that stays visible.
    assert_eq!(blocks["XCV"]["dss"], "INDETERMINATE");
    assert_eq!(blocks["XCV"]["ours"], "pass");
    assert_eq!(blocks["XCV"]["agrees"], false);
    assert_eq!(automatic_class(&rows, false, 1), "unreviewed");
    assert_eq!(observed(&rows)[0]["XCV"], "INDETERMINATE/pass");
}

#[test]
fn a_policy_refusal_lands_on_the_block_it_concerns() {
    let refused = |detail: &str| json!({ "verification": { "error": "Policy", "detail": detail } });
    let transform = our_blocks(
        &refused(
            "verification transform policy rejects algorithm http://www.w3.org/TR/1999/REC-xpath-19991116",
        ),
        false,
    );
    assert_eq!(transform["SAV"]["verdict"], "fail");
    assert_eq!(transform["FC"]["verdict"], "not-reached");
    let structure = our_blocks(&refused("XAdES requires SignedProperties"), false);
    assert_eq!(structure["FC"]["verdict"], "fail");
    assert_eq!(structure["SAV"]["verdict"], "not-reached");
    // Without a timestamp in the document there is nothing to compare.
    assert_eq!(structure["TIMESTAMPS"]["verdict"], "none");
}

#[test]
fn a_tampered_signature_fails_cryptographic_verification_only() {
    let mut facts = verified();
    facts["verification"]["references"] = json!(["Invalid", "Valid"]);
    let blocks = our_blocks(&facts, false);
    assert_eq!(blocks["CV"]["verdict"], "fail");
    assert_eq!(blocks["XCV"]["verdict"], "pass");
}

#[test]
fn an_unmatched_or_missing_signature_never_counts_as_agreement() {
    let signatures = dss_signatures(DIAGNOSTIC, DETAILED).unwrap();
    let mut other = verified();
    other["id"] = json!("elsewhere");
    let rows = compare(&signatures, &[other], true);
    assert_eq!(rows[0]["matched"], false);
    assert_eq!(automatic_class(&rows, false, 1), "unreviewed");
    // Neither side found a signature: the input is not one.
    assert_eq!(automatic_class(&[], true, 0), "not-a-signature");
    // A document without a chain to anchor is classified as such.
    let agreeing = compare(&signatures, &[verified()], true);
    assert_eq!(automatic_class(&agreeing, false, 0), "no-usable-anchor");
}

#[test]
fn every_block_is_compared() {
    let signatures = dss_signatures(DIAGNOSTIC, DETAILED).unwrap();
    let rows = compare(&signatures, &[verified()], true);
    for name in BLOCKS {
        assert!(rows[0]["blocks"][name].is_object(), "{name}");
    }
}

#[test]
fn a_reviewed_difference_needs_a_class_and_a_reason() {
    let summary = json!({ "cases": { "a.xml": { "instant": {
        "observed": [{ "XCV": "INDETERMINATE/pass" }], "class": "unreviewed"
    } } } });
    let expected = |class: &str, reason: Option<&str>| {
        json!({ "cases": { "a.xml": { "instant": {
            "observed": [{ "XCV": "INDETERMINATE/pass" }], "class": class, "reason": reason
        } } } })
    };
    assert_eq!(
        differences(&expected("unreviewed", None), &summary).len(),
        1
    );
    assert_eq!(
        differences(&expected("normative-difference", None), &summary).len(),
        1
    );
    let reviewed = expected(
        "normative-difference",
        Some("EN 319 102-1 5.2.6: revocation status"),
    );
    assert_eq!(differences(&reviewed, &summary), Vec::<String>::new());
    // A changed observation or an unlisted input fails whatever its class.
    let changed = json!({ "cases": { "a.xml": { "instant": {
        "observed": [{ "XCV": "PASSED/pass" }], "class": "agreement"
    } } } });
    assert_eq!(differences(&changed, &summary).len(), 1);
    assert_eq!(differences(&json!({ "cases": {} }), &summary).len(), 1);
}
