use super::{
    BLOCKS, automatic_class, compare, differences, dss_signatures, observed, our_blocks, report,
};
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

const SIMPLE: &str = r#"<SimpleReport xmlns="http://dss.esig.europa.eu/validation/simple-report">
  <Signature Id="S-1">
    <Indication>INDETERMINATE</Indication>
    <SubIndication>TRY_LATER</SubIndication>
  </Signature>
</SimpleReport>"#;

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
    let signatures = dss_signatures(DIAGNOSTIC, DETAILED, SIMPLE).unwrap();
    assert_eq!(signatures.len(), 1);
    assert_eq!(signatures[0]["id"], "sig");
    assert_eq!(signatures[0]["blocks"]["XCV"], "INDETERMINATE");
    assert_eq!(signatures[0]["blocks"]["TIMESTAMPS"], "PASSED");
    // The overall verdict is the simple report's, found by the same token.
    assert_eq!(signatures[0]["overall"]["indication"], "INDETERMINATE");
    assert_eq!(signatures[0]["overall"]["sub"], "TRY_LATER");
}

#[test]
fn each_block_compares_with_its_own_fact() {
    let signatures = dss_signatures(DIAGNOSTIC, DETAILED, SIMPLE).unwrap();
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
    assert_eq!(automatic_class(&rows, 1), "unreviewed");
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
fn agreement_is_the_overall_indication_and_sub_indication() {
    // The verdict compared is DSS's simple report against the ETSI process
    // over xml-sec's facts; the blocks only diagnose a difference, so an
    // XCV difference alone does not deny agreement, and the same indication
    // with another sub-indication is not agreement.
    let signatures = dss_signatures(DIAGNOSTIC, DETAILED, SIMPLE).unwrap();
    let mut facts = verified();
    facts["etsi"] = json!({ "indication": "INDETERMINATE", "sub": "TRY_LATER" });
    let rows = compare(&signatures, &[facts.clone()], true);
    assert_eq!(rows[0]["blocks"]["XCV"]["agrees"], false);
    assert_eq!(automatic_class(&rows, 1), "agreement");
    assert_eq!(
        observed(&rows)[0]["OVERALL"],
        "INDETERMINATE:TRY_LATER/INDETERMINATE:TRY_LATER"
    );
    facts["etsi"]["sub"] = json!("CERTIFICATE_CHAIN_GENERAL_FAILURE");
    let rows = compare(&signatures, &[facts], true);
    assert_eq!(rows[0]["overall"]["indication"], true);
    assert_eq!(automatic_class(&rows, 1), "unreviewed");
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
    let signatures = dss_signatures(DIAGNOSTIC, DETAILED, SIMPLE).unwrap();
    let mut other = verified();
    other["id"] = json!("elsewhere");
    let rows = compare(&signatures, &[other], true);
    assert_eq!(rows[0]["matched"], false);
    assert_eq!(automatic_class(&rows, 1), "unreviewed");
    // Neither side found a signature, whether DSS refused the input or
    // reported none: the input is not one.
    assert_eq!(
        automatic_class(&compare(&[], &[], true), 0),
        "not-a-signature"
    );
    // A document without a chain to anchor is classified as such.
    let agreeing = compare(&signatures, &[verified()], true);
    assert_eq!(automatic_class(&agreeing, 0), "no-usable-anchor");
}

#[test]
fn a_signature_only_xml_sec_reads_stays_a_difference() {
    // DSS reporting no signature must not hide one xml-sec validated: it is
    // compared against an absent one, so the input is neither in agreement
    // nor "not a signature".
    let mut facts = verified();
    facts["etsi"] = json!({ "indication": "TOTAL_PASSED" });
    let rows = compare(&[], &[facts], true);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["matched"], false);
    assert_eq!(rows[0]["overall"]["dss"], "absent:-");
    assert_eq!(rows[0]["overall"]["ours"], "TOTAL_PASSED:-");
    assert_eq!(automatic_class(&rows, 1), "unreviewed");
}

#[test]
fn every_block_is_compared() {
    let signatures = dss_signatures(DIAGNOSTIC, DETAILED, SIMPLE).unwrap();
    let rows = compare(&signatures, &[verified()], true);
    for name in BLOCKS {
        assert!(rows[0]["blocks"][name].is_object(), "{name}");
    }
}

#[test]
fn the_report_counts_each_profile_of_each_pass() {
    // The published table is what a reader compares policies by: each
    // profile counts its own inputs, and a pass no input took is left out.
    let entry = |class: &str, passed: bool, indication: bool| json!({ "class": class, "passed": passed, "indication": indication, "dss_passed": true });
    let expectations = json!({
        "dss": "6.5.1",
        "instant": 1_800_000_000,
        "cases": {
            "a.xml": {
                "instant/strict": entry("policy-refusal", false, false),
                "instant/extended": entry("agreement", true, true),
                "instant/conformant": entry("agreement", true, true),
            },
            "b.xml": {
                "instant/strict": entry("agreement", true, true),
                "instant/extended": entry("agreement", true, true),
                "instant/conformant": entry("agreement", true, true),
            },
        },
    });
    let text = report(&expectations);
    assert!(text.contains("EU DSS 6.5.1"), "{text}");
    assert!(
        text.contains("| `xades` | 2 | 2 | 1 | 1 | 1 | agreement 1, policy-refusal 1 |"),
        "{text}"
    );
    assert!(
        text.contains("| `xades-conformant` | 2 | 2 | 2 | 2 | 2 | agreement 2 |"),
        "{text}"
    );
    assert!(!text.contains("signing-time"), "{text}");
}

#[test]
fn the_dss_policy_takes_the_profiles_cryptography_and_keeps_the_rest() {
    // DSS must decide under the profile's algorithm and key-size rules, not
    // its own dated catalogue: the signature's constraints carry exactly the
    // profile's suites, certificates keep every SHA family at the same key
    // sizes, and the non-cryptographic constraints stay DSS's.
    let template = r#"<ConstraintsParameters xmlns="http://dss.esig.europa.eu/validation/policy">
  <SignatureConstraints><BasicSignatureConstraints>
    <SigningCertificate><NotExpired Level="FAIL" /><Cryptographic /></SigningCertificate>
    <Cryptographic />
  </BasicSignatureConstraints></SignatureConstraints>
  <Timestamp><BasicSignatureConstraints><Cryptographic /></BasicSignatureConstraints></Timestamp>
  <Cryptographic Level="FAIL"><AcceptableDigestAlgo><Algo>MD5</Algo></AcceptableDigestAlgo></Cryptographic>
</ConstraintsParameters>"#;
    let constraints = json!({
        "signature": { "families": ["ECDSA", "RSA"], "hashes": ["SHA256"] },
        "minimum_bits": { "RSA": 2048, "ECDSA": 256 },
    });
    let policy = super::dss_policy::policy(template, &constraints).unwrap();
    assert!(!policy.contains("MD5"), "{policy}");
    assert!(
        policy.contains(r#"<NotExpired Level="FAIL" />"#),
        "{policy}"
    );
    let document = crate::xades::xml::parse(&policy, "policy").unwrap();
    let digests = |element: crate::xades::xml::Node<'_, '_>| -> Vec<String> {
        crate::xades::xml::below(element, "AcceptableDigestAlgo", None)
            .flat_map(crate::xades::xml::elements)
            .map(|algo| algo.text().unwrap_or_default().to_owned())
            .collect()
    };
    let cryptographic: Vec<_> =
        crate::xades::xml::below(document.root_element(), "Cryptographic", None).collect();
    assert_eq!(cryptographic.len(), 4);
    for element in cryptographic {
        let parent = element.parent().unwrap().tag_name().name().to_owned();
        let grand = element
            .parent()
            .and_then(crate::xades::xml::Node::parent)
            .unwrap()
            .tag_name()
            .name()
            .to_owned();
        let certificate = parent == "SigningCertificate" || grand == "Timestamp";
        let expected: Vec<String> = if certificate {
            [
                "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SHA3-256", "SHA3-384", "SHA3-512",
            ]
            .map(str::to_owned)
            .to_vec()
        } else {
            vec!["SHA256".to_owned()]
        };
        assert_eq!(digests(element), expected, "{parent}/{grand}");
        // XMLDSig ECDSA values are r || s: DSS calls them PLAIN-ECDSA.
        assert!(
            crate::xades::xml::below(element, "MiniPublicKeySize", None)
                .flat_map(crate::xades::xml::elements)
                .any(|algo| algo.text() == Some("PLAIN-ECDSA")
                    && algo.attribute("Size") == Some("256"))
        );
    }
}

/// A summary of `a.xml` whose two profiles observe the same unreviewed
/// overall difference.
fn unreviewed_summary() -> Value {
    let pass = json!({
        "observed": [{ "XCV": "INDETERMINATE/pass", "OVERALL": "TOTAL_PASSED:-/INDETERMINATE:TRY_LATER" }],
        "class": "unreviewed",
    });
    json!({ "cases": { "a.xml": { "instant/strict": pass, "instant/conformant": pass } } })
}

fn review(class: &str, reason: &str) -> Value {
    json!({ "a.xml": [{
        "overall": ["TOTAL_PASSED:-/INDETERMINATE:TRY_LATER"],
        "class": class,
        "reason": reason,
    }] })
}

#[test]
fn a_reviewed_difference_needs_a_class_and_a_reason() {
    let summary = unreviewed_summary();
    let none = json!({});
    // Nobody reviewed it: recording keeps it unreviewed and the check fails
    // for each pass.
    let unreviewed = super::recorded(&summary, &none);
    assert_eq!(differences(&unreviewed, &summary, &none).len(), 2);
    // A review without a reason does not classify.
    let unreasoned = review("normative-difference", "");
    let recorded = super::recorded(&summary, &unreasoned);
    assert_eq!(differences(&recorded, &summary, &unreasoned).len(), 2);
    // One review covers every pass that observes its overall comparison.
    let reviews = review(
        "normative-difference",
        "EN 319 102-1 5.2.6.4 step 4: revocation status",
    );
    let recorded = super::recorded(&summary, &reviews);
    assert_eq!(
        recorded["cases"]["a.xml"]["instant/strict"]["class"],
        "normative-difference"
    );
    assert_eq!(
        differences(&recorded, &summary, &reviews),
        Vec::<String>::new()
    );
    // Expectations not recorded with the current reviews fail.
    assert_eq!(differences(&unreviewed, &summary, &reviews).len(), 2);
    // A changed observation or an unlisted input fails whatever its class.
    let mut changed = recorded.clone();
    changed["cases"]["a.xml"]["instant/strict"]["observed"] =
        json!([{ "XCV": "PASSED/pass", "OVERALL": "TOTAL_PASSED:-/TOTAL_PASSED:-" }]);
    assert_eq!(differences(&changed, &summary, &reviews).len(), 1);
    assert_eq!(
        differences(&json!({ "cases": {} }), &summary, &reviews).len(),
        2
    );
}

#[test]
fn a_review_no_observation_matches_fails() {
    // A review whose comparison is no longer observed would otherwise
    // outlive the difference it explains.
    let summary = unreviewed_summary();
    let reviews = json!({ "a.xml": [
        { "overall": ["TOTAL_PASSED:-/INDETERMINATE:TRY_LATER"], "class": "dss-deviation", "reason": "r" },
        { "overall": ["TOTAL_PASSED:-/TOTAL_FAILED:HASH_FAILURE"], "class": "dss-deviation", "reason": "r" },
    ] });
    let recorded = super::recorded(&summary, &reviews);
    let found = differences(&recorded, &summary, &reviews);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("matches no observation"), "{found:?}");
}
