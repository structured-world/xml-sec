use super::{
    BLOCKS, automatic_class, compare, differences, dss_signatures, observed, our_blocks, report,
};
use serde_json::{Value, json};

/// A diagnostic report shaped as DSS 6.5.1 writes it: each signature lists
/// the tokens it carries under `FoundTimestamps`, and each token lists what
/// it stamps. T-1 is S-1's signature timestamp, T-3 its `RefsOnlyTimeStamp`,
/// which stamps certificates and revocation data but no SIGNATURE object,
/// and T-2 belongs to another signature although it stamps S-1 too.
const DIAGNOSTIC: &str = r#"<DiagnosticData xmlns="http://dss.esig.europa.eu/validation/diagnostic">
  <Signatures>
    <Signature Id="S-1">
      <DAIdentifier>sig</DAIdentifier>
      <FoundTimestamps>
        <FoundTimestamp Timestamp="T-1"/>
        <FoundTimestamp Timestamp="T-3"/>
      </FoundTimestamps>
    </Signature>
    <Signature Id="S-other">
      <DAIdentifier>other</DAIdentifier>
      <FoundTimestamps>
        <FoundTimestamp Timestamp="T-2"/>
      </FoundTimestamps>
    </Signature>
  </Signatures>
  <UsedTimestamps>
    <Timestamp Type="SIGNATURE_TIMESTAMP" Id="T-1"><TimestampedObjects>
      <TimestampedObject Token="S-1" Category="SIGNATURE"/>
    </TimestampedObjects></Timestamp>
    <Timestamp Type="SIGNATURE_TIMESTAMP" Id="T-2"><TimestampedObjects>
      <TimestampedObject Token="S-other" Category="SIGNATURE"/>
      <TimestampedObject Token="S-1" Category="SIGNATURE"/>
    </TimestampedObjects></Timestamp>
    <Timestamp Type="VALIDATION_DATA_REFSONLY_TIMESTAMP" Id="T-3"><TimestampedObjects>
      <TimestampedObject Token="C-1" Category="CERTIFICATE"/>
      <TimestampedObject Token="R-1" Category="REVOCATION"/>
    </TimestampedObjects></Timestamp>
  </UsedTimestamps>
</DiagnosticData>"#;

const DETAILED: &str = r#"<DetailedReport xmlns="http://dss.esig.europa.eu/validation/detailed-report">
  <BasicBuildingBlocks Id="S-1" Type="SIGNATURE">
    <FC><Conclusion><Indication>PASSED</Indication></Conclusion></FC>
    <ISC><Conclusion><Indication>PASSED</Indication></Conclusion></ISC>
    <CV><Conclusion><Indication>PASSED</Indication></Conclusion></CV>
    <XCV><Conclusion><Indication>INDETERMINATE</Indication><SubIndication>TRY_LATER</SubIndication></Conclusion></XCV>
    <SAV><Conclusion><Indication>PASSED</Indication></Conclusion></SAV>
  </BasicBuildingBlocks>
  <BasicBuildingBlocks Id="T-1" Type="TIMESTAMP">
    <Conclusion><Indication>PASSED</Indication></Conclusion>
  </BasicBuildingBlocks>
  <BasicBuildingBlocks Id="T-2" Type="TIMESTAMP">
    <Conclusion><Indication>FAILED</Indication><SubIndication>HASH_FAILURE</SubIndication></Conclusion>
  </BasicBuildingBlocks>
  <BasicBuildingBlocks Id="T-3" Type="TIMESTAMP">
    <Conclusion><Indication>PASSED</Indication></Conclusion>
  </BasicBuildingBlocks>
</DetailedReport>"#;

const SIMPLE: &str = r#"<SimpleReport xmlns="http://dss.esig.europa.eu/validation/simple-report">
  <Signature Id="S-1">
    <Indication>INDETERMINATE</Indication>
    <SubIndication>TRY_LATER</SubIndication>
  </Signature>
</SimpleReport>"#;

/// `DETAILED` with S-1's `RefsOnlyTimeStamp` failed.
fn refs_only_failed() -> String {
    DETAILED.replace(
        r#"<BasicBuildingBlocks Id="T-3" Type="TIMESTAMP">
    <Conclusion><Indication>PASSED</Indication></Conclusion>"#,
        r#"<BasicBuildingBlocks Id="T-3" Type="TIMESTAMP">
    <Conclusion><Indication>FAILED</Indication><SubIndication>HASH_FAILURE</SubIndication></Conclusion>"#,
    )
}

/// One token's decision as the probe reports it.
fn token(indication: Option<&str>) -> Value {
    json!({
        "role": "Signature",
        "current": indication.map(|indication| json!({ "indication": indication, "sub": null })),
    })
}

/// Facts of a signature that verified with a validated path, met B-B and
/// whose two tokens passed their own validation.
fn verified() -> Value {
    json!({
        "id": "sig",
        "verification": { "status": "Valid", "trust": "ValidatedX509", "references": ["Valid", "Valid"] },
        "basic": { "bound": true, "included": true, "assessed": true },
        "declared_timestamps": 2,
        "timestamps": [token(Some("PASSED")), token(Some("PASSED"))],
    })
}

#[test]
fn a_signature_keeps_the_timestamps_it_carries() {
    // T-2 is another signature's token, though it also stamps S-1; its
    // FAILED block must not reach S-1. S-1's RefsOnlyTimeStamp stamps no
    // SIGNATURE object and is S-1's all the same.
    let signatures = dss_signatures(DIAGNOSTIC, DETAILED, SIMPLE).unwrap();
    assert_eq!(signatures.len(), 2);
    assert_eq!(signatures[0]["id"], "sig");
    assert_eq!(signatures[0]["blocks"]["TIMESTAMPS"], "PASSED");
    assert_eq!(signatures[1]["blocks"]["TIMESTAMPS"], "FAILED:HASH_FAILURE");
    // The overall verdict is the simple report's, found by the same token.
    assert_eq!(signatures[0]["overall"]["indication"], "INDETERMINATE");
    assert_eq!(signatures[0]["overall"]["sub"], "TRY_LATER");
}

#[test]
fn a_failed_refs_only_timestamp_reaches_its_own_signature_only() {
    // Linking tokens by their SIGNATURE coverage left a RefsOnlyTimeStamp
    // out, so its failure could not fail the block of the signature it is in.
    // With T-2 passing, only T-3 can fail a block: S-1's, never S-other's.
    let passing_other = refs_only_failed().replace(
        r#"<BasicBuildingBlocks Id="T-2" Type="TIMESTAMP">
    <Conclusion><Indication>FAILED</Indication><SubIndication>HASH_FAILURE</SubIndication></Conclusion>"#,
        r#"<BasicBuildingBlocks Id="T-2" Type="TIMESTAMP">
    <Conclusion><Indication>PASSED</Indication></Conclusion>"#,
    );
    assert_ne!(passing_other, refs_only_failed());
    let signatures = dss_signatures(DIAGNOSTIC, &passing_other, SIMPLE).unwrap();
    assert_eq!(signatures[0]["blocks"]["TIMESTAMPS"], "FAILED:HASH_FAILURE");
    assert_eq!(signatures[1]["blocks"]["TIMESTAMPS"], "PASSED");
}

#[test]
fn a_reached_block_agrees_only_with_the_same_conclusion() {
    // EN 319 102-1 V1.4.1 clause 5.1.3: OUT_OF_BOUNDS_NO_POE and
    // CERTIFICATE_CHAIN_GENERAL_FAILURE are different XCV results, though
    // both INDETERMINATE and the overall results match; the block the ETSI
    // decision names carries that decision's conclusion.
    let detailed = DETAILED.replace(
        "TRY_LATER</SubIndication></Conclusion></XCV>",
        "OUT_OF_BOUNDS_NO_POE</SubIndication></Conclusion></XCV>",
    );
    let signatures = dss_signatures(DIAGNOSTIC, &detailed, SIMPLE).unwrap();
    let mut facts = verified();
    facts["verification"]["trust"] = "Unknown".into();
    facts["etsi"] = json!({ "indication": "INDETERMINATE", "sub": "TRY_LATER" });
    let rows = compare(&signatures[..1], &[facts.clone()]);
    assert_eq!(rows[0]["overall"]["agrees"], true);
    assert_eq!(rows[0]["blocks"]["XCV"]["ours"], "INDETERMINATE:TRY_LATER");
    assert_eq!(rows[0]["blocks"]["XCV"]["agrees"], false);
    assert_eq!(automatic_class(&rows, 1), "unreviewed");
    // The same conclusion on both sides agrees.
    let same = dss_signatures(DIAGNOSTIC, DETAILED, SIMPLE).unwrap();
    let rows = compare(&same[..1], &[facts]);
    assert_eq!(rows[0]["blocks"]["XCV"]["agrees"], true);
    assert_eq!(automatic_class(&rows, 1), "agreement");
}

#[test]
fn the_timestamps_block_keeps_the_tokens_conclusion() {
    // A token xml-sec found INDETERMINATE/TRY_LATER is not the token DSS
    // found FAILED/HASH_FAILURE; both conclusions stay in the observation.
    let mut facts = verified();
    facts["timestamps"] = json!([{
        "role": "Signature",
        "current": { "indication": "INDETERMINATE", "sub": "TRY_LATER" },
    }]);
    assert_eq!(
        our_blocks(&facts)["TIMESTAMPS"]["verdict"],
        "INDETERMINATE:TRY_LATER"
    );
    let failed =
        json!([{ "id": "sig", "blocks": { "TIMESTAMPS": "FAILED:HASH_FAILURE" }, "overall": {} }]);
    let rows = compare(failed.as_array().unwrap(), &[facts]);
    assert_eq!(rows[0]["blocks"]["TIMESTAMPS"]["agrees"], false);
    assert_eq!(
        observed(&rows)[0]["TIMESTAMPS"],
        "FAILED:HASH_FAILURE/INDETERMINATE:TRY_LATER"
    );
}

#[test]
fn a_block_keeps_its_sub_indication() {
    // EN 319 102-1 V1.4.1 clause 5.1.3: the sub-indication says why a block
    // did not pass; TRY_LATER and REVOKED_NO_POE are different results.
    let signatures = dss_signatures(DIAGNOSTIC, DETAILED, SIMPLE).unwrap();
    assert_eq!(signatures[0]["blocks"]["XCV"], "INDETERMINATE:TRY_LATER");
    let revoked = DETAILED.replace(
        "TRY_LATER</SubIndication></Conclusion></XCV>",
        "REVOKED_NO_POE</SubIndication></Conclusion></XCV>",
    );
    let changed = dss_signatures(DIAGNOSTIC, &revoked, SIMPLE).unwrap();
    let rows = |signatures: &[Value]| observed(&compare(signatures, &[verified()]));
    assert_ne!(rows(&signatures), rows(&changed));
    assert_eq!(
        rows(&changed)[0]["XCV"],
        "INDETERMINATE:REVOKED_NO_POE/pass"
    );
}

#[test]
fn each_block_compares_with_its_own_fact() {
    let signatures = dss_signatures(DIAGNOSTIC, DETAILED, SIMPLE).unwrap();
    let rows = compare(&signatures, &[verified()]);
    let blocks = &rows[0]["blocks"];
    for name in ["FC", "ISC", "CV", "SAV", "TIMESTAMPS"] {
        assert_eq!(blocks[name]["agrees"], true, "{name}");
    }
    // DSS cannot conclude the chain without revocation data, while the path
    // xml-sec validated needs none: a difference that stays visible.
    assert_eq!(blocks["XCV"]["dss"], "INDETERMINATE:TRY_LATER");
    assert_eq!(blocks["XCV"]["ours"], "pass");
    assert_eq!(blocks["XCV"]["agrees"], false);
    assert_eq!(automatic_class(&rows, 1), "unreviewed");
    assert_eq!(observed(&rows)[0]["XCV"], "INDETERMINATE:TRY_LATER/pass");
}

#[test]
fn a_refusal_lands_on_the_block_the_etsi_decision_names() {
    // A refused signature's block is the one of the ETSI decision the probe
    // reports for it (EN 319 102-1 V1.4.1 Table 6): an external reference
    // the comparison supplies no bytes for is signed data not found (CV),
    // not a constraint, though the policy is what refused it; a profile
    // constraint is acceptance; a bound of the implementation is no finding.
    let refused = |sub: Value| {
        json!({
            "verification": { "error": "Policy", "detail": "reference URI class is not permitted" },
            "etsi": { "indication": "INDETERMINATE", "sub": sub },
        })
    };
    let external = our_blocks(&refused(json!("SIGNED_DATA_NOT_FOUND")));
    assert_eq!(
        external["CV"]["verdict"],
        "INDETERMINATE:SIGNED_DATA_NOT_FOUND"
    );
    assert_eq!(external["SAV"]["verdict"], "not-reached");
    let structure = our_blocks(&refused(json!("SIG_CONSTRAINTS_FAILURE")));
    assert_eq!(
        structure["SAV"]["verdict"],
        "INDETERMINATE:SIG_CONSTRAINTS_FAILURE"
    );
    assert_eq!(structure["FC"]["verdict"], "not-reached");
    let key = our_blocks(&refused(json!("NO_SIGNING_CERTIFICATE_FOUND")));
    assert_eq!(
        key["ISC"]["verdict"],
        "INDETERMINATE:NO_SIGNING_CERTIFICATE_FOUND"
    );
    let bound = our_blocks(&refused(json!("CUSTOM")));
    for name in ["FC", "ISC", "CV", "XCV", "SAV"] {
        assert_eq!(bound[name]["verdict"], "not-reached", "{name}");
    }
    // Without a timestamp in the signature there is nothing to compare.
    assert_eq!(structure["TIMESTAMPS"]["verdict"], "none");
}

#[test]
fn the_block_the_etsi_decision_fails_does_not_pass() {
    // A path the XMLDSig verification validated at the instant may still
    // fail the X.509 validation block, which also needs each member's status
    // (EN 319 102-1 V1.4.1 clause 5.2.6.4 step 4); when the ETSI decision
    // over the same facts names that block, the block failed with the
    // decision's conclusion; a signature's TOTAL_FAILED is a block's FAILED.
    let mut facts = verified();
    facts["etsi"] =
        json!({ "indication": "INDETERMINATE", "sub": "CERTIFICATE_CHAIN_GENERAL_FAILURE" });
    assert_eq!(
        our_blocks(&facts)["XCV"]["verdict"],
        "INDETERMINATE:CERTIFICATE_CHAIN_GENERAL_FAILURE"
    );
    assert_eq!(our_blocks(&facts)["CV"]["verdict"], "pass");
    facts["etsi"] = json!({ "indication": "TOTAL_PASSED" });
    assert_eq!(our_blocks(&facts)["XCV"]["verdict"], "pass");
    facts["verification"]["references"] = json!(["Invalid", "Valid"]);
    facts["etsi"] = json!({ "indication": "TOTAL_FAILED", "sub": "HASH_FAILURE" });
    assert_eq!(our_blocks(&facts)["CV"]["verdict"], "FAILED:HASH_FAILURE");
}

#[test]
fn a_b_b_refusal_lands_on_the_block_it_concerns() {
    // A property the baseline profile forbids is an acceptance finding, not
    // a format failure; a value that did not verify is CV's, which already
    // fails; a schema refusal is the format's.
    let refused = |detail: &str| {
        let mut facts = verified();
        facts["basic"] = json!({ "error": "Prepare", "detail": detail });
        our_blocks(&facts)
    };
    let forbidden = refused("Prepare(Property(Forbidden { node: N }))");
    assert_eq!(forbidden["SAV"]["verdict"], "fail");
    assert_eq!(forbidden["FC"]["verdict"], "not-reached");
    let invalid = refused("Prepare(Binding(Signature { node: N, status: Invalid }))");
    assert_eq!(invalid["FC"]["verdict"], "not-reached");
    assert_eq!(invalid["SAV"]["verdict"], "not-reached");
    let schema = refused("Prepare(Timestamp(Duplicate { node: N }))");
    assert_eq!(schema["FC"]["verdict"], "fail");
    // EN 319 132-1 V1.3.1 clause 5.3 lets a SignatureTimeStamp carry one or
    // more tokens; only the baseline's clause 6.3 (n) limits it to one, an
    // acceptance requirement. A repeated singleton field stays the format's.
    let mut facts = verified();
    facts["basic"] = json!({
        "error": "Prepare",
        "detail": "Prepare(Timestamp(Duplicate { node: N }))",
        "duplicate": "EncapsulatedTimeStamp",
    });
    let tokens = our_blocks(&facts);
    assert_eq!(tokens["SAV"]["verdict"], "fail");
    assert_eq!(tokens["FC"]["verdict"], "not-reached");
    facts["basic"]["duplicate"] = "CanonicalizationMethod".into();
    assert_eq!(our_blocks(&facts)["FC"]["verdict"], "fail");
    // The baseline's own requirements (EN 319 132-1 V1.3.1 clause 6.3):
    // format coverage of every object, MimeType, an explicit timestamp
    // canonicalization method. The schema's ObjectReference is the format's.
    for baseline in [
        "Prepare(Format(Missing { reference: N }))",
        "Prepare(Format(Format(Property(Missing { parent: N, local: \"MimeType\" }))))",
        "Prepare(Timestamp(Missing { node: N, local: \"CanonicalizationMethod\" }))",
    ] {
        assert_eq!(refused(baseline)["SAV"]["verdict"], "fail", "{baseline}");
    }
    let reference = refused(
        "Prepare(Format(Format(Property(Missing { parent: N, local: \"ObjectReference\" }))))",
    );
    assert_eq!(reference["FC"]["verdict"], "fail");
}

#[test]
fn the_timestamps_block_reads_every_token_of_the_signature() {
    // DSS's block covers each token the signature carries, archive and
    // validation-data ones included; a B-T result alone would pass a
    // signature whose archive token failed.
    let mut facts = verified();
    facts["timestamps"] = json!([token(Some("PASSED")), token(Some("INDETERMINATE"))]);
    assert_eq!(our_blocks(&facts)["TIMESTAMPS"]["verdict"], "INDETERMINATE");
    // FAILED is the worse conclusion, wherever its token is.
    facts["timestamps"] = json!([token(Some("INDETERMINATE")), token(Some("FAILED"))]);
    assert_eq!(our_blocks(&facts)["TIMESTAMPS"]["verdict"], "FAILED");
    facts["timestamps"] = json!([token(Some("PASSED")), token(None)]);
    assert_eq!(our_blocks(&facts)["TIMESTAMPS"]["verdict"], "not-reached");
    facts["timestamps"] = json!([token(Some("PASSED")), token(Some("PASSED"))]);
    assert_eq!(our_blocks(&facts)["TIMESTAMPS"]["verdict"], "pass");
    // Declared tokens without per-token decisions were not reached.
    facts["timestamps"] = Value::Null;
    assert_eq!(our_blocks(&facts)["TIMESTAMPS"]["verdict"], "not-reached");
}

#[test]
fn a_ts_101_903_signature_is_read_by_its_bes_facts() {
    // EN 319 132-1 B-B does not apply to a TS 101 903 V1.2.2 signature; its
    // BES facts decide the format, signing-certificate and acceptance blocks.
    let facts = |met: bool| {
        json!({
            "verification": { "status": "Valid", "trust": "ValidatedX509", "references": ["Valid"] },
            "ts101903_bes": { "assessed": met },
        })
    };
    let met = our_blocks(&facts(true));
    for name in ["FC", "ISC", "SAV"] {
        assert_eq!(met[name]["verdict"], "pass", "{name}");
    }
    let unmet = our_blocks(&facts(false));
    assert_eq!(unmet["FC"]["verdict"], "pass");
    assert_eq!(unmet["ISC"]["verdict"], "fail");
    assert_eq!(unmet["SAV"]["verdict"], "fail");
}

#[test]
fn agreement_needs_the_overall_result_and_every_block_both_reached() {
    // The overall indication and sub-indication must match, and so must
    // every block both validators reached: a block difference under the same
    // overall result can hide a defect another refusal masks. A block only
    // one side reached is recorded and checked, not reviewed.
    let signatures = dss_signatures(DIAGNOSTIC, DETAILED, SIMPLE).unwrap();
    let signatures = &signatures[..1];
    let mut facts = verified();
    facts["etsi"] = json!({ "indication": "INDETERMINATE", "sub": "TRY_LATER" });
    // SAV reached by both and different: a difference to review.
    let mut unmet = facts.clone();
    unmet["basic"]["assessed"] = false.into();
    let rows = compare(signatures, &[unmet]);
    assert_eq!(rows[0]["blocks"]["SAV"]["reached"], true);
    assert_eq!(rows[0]["blocks"]["SAV"]["agrees"], false);
    assert_eq!(automatic_class(&rows, 1), "unreviewed");
    // Our facts stopping before FC, ISC, CV and SAV leave the overall match
    // standing: those blocks are recorded, not reviewed.
    let mut stopped = facts.clone();
    stopped["verification"] =
        json!({ "error": "Policy", "detail": "XAdES requires SignedProperties" });
    let rows = compare(signatures, &[stopped]);
    assert_eq!(rows[0]["blocks"]["SAV"]["reached"], false);
    assert_eq!(automatic_class(&rows, 1), "agreement");
    // Every reached block agreeing, the same overall result is agreement.
    let rows = compare(signatures, &[facts.clone()]);
    assert_eq!(automatic_class(&rows, 1), "agreement");
    assert_eq!(
        observed(&rows)[0]["OVERALL"],
        "INDETERMINATE:TRY_LATER/INDETERMINATE:TRY_LATER"
    );
    // The same indication with another sub-indication is not agreement.
    facts["etsi"]["sub"] = json!("CERTIFICATE_CHAIN_GENERAL_FAILURE");
    let rows = compare(signatures, &[facts]);
    assert_eq!(rows[0]["overall"]["indication"], true);
    assert_eq!(automatic_class(&rows, 1), "unreviewed");
}

#[test]
fn a_tampered_signature_fails_cryptographic_verification_only() {
    let mut facts = verified();
    facts["verification"]["references"] = json!(["Invalid", "Valid"]);
    let blocks = our_blocks(&facts);
    assert_eq!(blocks["CV"]["verdict"], "fail");
    assert_eq!(blocks["XCV"]["verdict"], "pass");
}

#[test]
fn an_unmatched_or_missing_signature_never_counts_as_agreement() {
    let signatures = dss_signatures(DIAGNOSTIC, DETAILED, SIMPLE).unwrap();
    let mut other = verified();
    other["id"] = json!("elsewhere");
    let rows = compare(&signatures[..1], &[other]);
    assert_eq!(rows[0]["matched"], false);
    assert_eq!(automatic_class(&rows, 1), "unreviewed");
    // Neither side found a signature, whether DSS refused the input or
    // reported none: the input is not one.
    assert_eq!(automatic_class(&compare(&[], &[]), 0), "not-a-signature");
    // A document without a chain to anchor is classified as such.
    let agreeing = compare(&signatures, &[verified()]);
    assert_eq!(automatic_class(&agreeing, 0), "no-usable-anchor");
}

#[test]
fn a_signature_only_xml_sec_reads_stays_a_difference() {
    // DSS reporting no signature must not hide one xml-sec validated: it is
    // compared against an absent one, so the input is neither in agreement
    // nor "not a signature".
    let mut facts = verified();
    facts["etsi"] = json!({ "indication": "TOTAL_PASSED" });
    let rows = compare(&[], &[facts]);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["matched"], false);
    assert_eq!(rows[0]["overall"]["dss"], "absent:-");
    assert_eq!(rows[0]["overall"]["ours"], "TOTAL_PASSED:-");
    assert_eq!(automatic_class(&rows, 1), "unreviewed");
}

#[test]
fn every_block_is_compared() {
    let signatures = dss_signatures(DIAGNOSTIC, DETAILED, SIMPLE).unwrap();
    let rows = compare(&signatures, &[verified()]);
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
    assert!(text.contains("Recorded with EU DSS 6.5.1"), "{text}");
    assert!(
        text.contains("| `xades` | 2 | 2 | 1 | 1 | 1 | agreement 1, policy-refusal 1 |"),
        "{text}"
    );
    assert!(
        text.contains("| `xades-conformant` | 2 | 2 | 2 | 2 | 2 | agreement 2 |"),
        "{text}"
    );
    assert!(!text.contains("signing-time"), "{text}");
    // A reader must tell automatic classes from reviewed ones: agreement is
    // automatic too, and a policy refusal rests on a deployment rationale
    // rather than a clause.
    assert!(
        text.contains("*agreement*, *not-a-signature* and *no-usable-anchor* are automatic"),
        "{text}"
    );
    assert!(text.contains("deployment rationale"), "{text}");
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
        "certificate": { "families": ["DSA", "ECDSA", "RSA"] },
        "minimum_bits": { "RSA": 2048, "DSA": 2048, "ECDSA": 256 },
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
        // A DSA CA key above the DSA minimum certifies an RSA XML signer in
        // xml-sec's certificate rules, which size every family: DSS's
        // certificate constraints must accept it too, and its signature
        // constraint keeps only the XML suites.
        let dsa = crate::xades::xml::below(element, "AcceptableEncryptionAlgo", None)
            .flat_map(crate::xades::xml::elements)
            .any(|algo| algo.text() == Some("DSA"));
        assert_eq!(dsa, certificate, "{parent}/{grand}");
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
        "observed": [unreviewed_summary()["cases"]["a.xml"]["instant/strict"]["observed"]],
        "class": class,
        "reason": reason,
    }] })
}

#[test]
fn a_review_approves_only_the_block_results_it_lists() {
    // A review explains a difference block by block; the same overall pair
    // over other block results is a difference it never covered, and stays
    // unreviewed when recorded.
    let mut summary = unreviewed_summary();
    summary["cases"]["a.xml"]["instant/conformant"]["observed"] = json!([{ "XCV": "INDETERMINATE/fail", "OVERALL": "TOTAL_PASSED:-/INDETERMINATE:TRY_LATER" }]);
    let reviews = review("normative-difference", "EN 319 102-1 5.2.6.4 step 4");
    let recorded = super::recorded(&summary, &reviews);
    assert_eq!(
        recorded["cases"]["a.xml"]["instant/strict"]["class"],
        "normative-difference"
    );
    assert_eq!(
        recorded["cases"]["a.xml"]["instant/conformant"]["class"],
        "unreviewed"
    );
    let found = differences(&recorded, &summary, &reviews);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("instant/conformant"), "{found:?}");
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
fn the_validity_horizon_of_each_passing_signature_is_recorded_and_checked() {
    // Until when each signature keeps passing is part of what a run
    // observes: listed per signature where any has one, and a changed
    // horizon fails the check like a changed comparison.
    let facts = json!({ "signatures": [
        { "id": "A", "etsi": { "indication": "TOTAL_PASSED", "valid_until": 1_820_055_894 } },
        { "id": "B", "etsi": { "indication": "INDETERMINATE" } },
    ] });
    let ours = facts["signatures"].as_array().unwrap().clone();
    let rows = compare(&[theirs(Some("A"), "a"), theirs(Some("B"), "b")], &ours);
    assert_eq!(
        super::horizons(&rows, &facts),
        Some(json!([1_820_055_894, null]))
    );
    let unbounded = json!({ "signatures": [{ "etsi": {} }] });
    let one = unbounded["signatures"].as_array().unwrap().clone();
    assert_eq!(super::horizons(&compare(&[], &one), &unbounded), None);
    let mut summary = unreviewed_summary();
    summary["cases"]["a.xml"]["instant/strict"]["valid_until"] = json!([1]);
    let reviews = review("normative-difference", "EN 319 102-1 5.2.6.4 step 4");
    let recorded = super::recorded(&summary, &reviews);
    assert_eq!(
        recorded["cases"]["a.xml"]["instant/strict"]["valid_until"],
        json!([1])
    );
    assert_eq!(
        differences(&recorded, &summary, &reviews),
        Vec::<String>::new()
    );
    let mut changed = summary.clone();
    changed["cases"]["a.xml"]["instant/strict"]["valid_until"] = json!([2]);
    assert_eq!(differences(&recorded, &changed, &reviews).len(), 1);
}

#[test]
fn each_signature_is_compared_at_its_own_claimed_time() {
    // Two signatures claiming 2019 and 2021 are run once per time, since
    // each validator takes one time for the whole document; the signing-time
    // comparison takes each signature's row and facts from the run at its own
    // claim, so the 2021 signature is never judged in 2019.
    let at = |first: &str, second: &str| {
        let facts = json!({ "signatures": [
            { "id": "A", "etsi": { "indication": first } },
            { "id": "B", "etsi": { "indication": second } },
        ] });
        let ours = facts["signatures"].as_array().unwrap().clone();
        let rows = compare(
            &[theirs(Some("A"), first), theirs(Some("B"), second)],
            &ours,
        );
        (rows, facts)
    };
    let claimed = super::claimed_times(&json!({ "signing_times": [2019, 2021] }));
    let times = super::distinct_times(&claimed);
    assert_eq!(times, [2019, 2021]);
    let runs = vec![
        at("TOTAL_PASSED", "INDETERMINATE"),
        at("INDETERMINATE", "TOTAL_PASSED"),
    ];
    let (rows, facts) = super::per_signature(runs, &times, &claimed);
    assert_eq!(rows[0]["overall"]["ours"], "TOTAL_PASSED:-");
    assert_eq!(rows[1]["overall"]["ours"], "TOTAL_PASSED:-");
    assert_eq!(facts["signatures"][1]["etsi"]["indication"], "TOTAL_PASSED");
    assert_eq!(super::time_run(0), "signing-time");
    assert_eq!(super::time_run(1), "signing-time-2");
}

#[test]
fn each_validity_horizon_names_the_signature_of_its_row() {
    // The rows follow DSS's order of signatures, the facts xml-sec's; a
    // horizon listed in facts order would give row 0 the bound of the
    // signature xml-sec lists first, not of the row's own signature.
    let facts = json!({ "signatures": [
        { "id": "A", "etsi": { "indication": "TOTAL_PASSED", "valid_until": 1 } },
        { "id": "B", "etsi": { "indication": "TOTAL_PASSED", "valid_until": 2 } },
    ] });
    let ours = facts["signatures"].as_array().unwrap().clone();
    let rows = compare(&[theirs(Some("B"), "b"), theirs(Some("A"), "a")], &ours);
    assert_eq!(super::horizons(&rows, &facts), Some(json!([2, 1])));
}

/// A DSS signature with `id`, whose overall indication names it.
fn theirs(id: Option<&str>, name: &str) -> Value {
    json!({ "id": id, "blocks": {}, "overall": { "indication": name } })
}

/// Our facts of a signature with `id`, whose ETSI indication names it.
fn mine(id: Option<&str>, name: &str) -> Value {
    json!({ "id": id, "etsi": { "indication": name } })
}

/// Each row's pairing as `DSS name/our name`, `absent` for no counterpart.
fn pairs(rows: &[Value]) -> Vec<String> {
    rows.iter()
        .map(|row| {
            let side = |side: &str| {
                row["overall"][side]
                    .as_str()
                    .unwrap_or_default()
                    .trim_end_matches(":-")
                    .to_owned()
            };
            format!("{}/{}", side("dss"), side("ours"))
        })
        .collect()
}

#[test]
fn an_identified_signature_is_paired_once_before_any_positional_match() {
    // Positional pairing used to take our `B` for DSS's unidentified first
    // signature, after which DSS's `B` took it again by its Id.
    let rows = compare(
        &[theirs(None, "first"), theirs(Some("B"), "b")],
        &[mine(Some("B"), "b"), mine(None, "second")],
    );
    assert_eq!(pairs(&rows), ["first/absent", "b/b", "absent/second"]);
}

#[test]
fn a_signature_only_one_side_identifies_is_paired_by_position() {
    // An Id on one side and none on the other does not contradict a pairing;
    // two different Ids do.
    let rows = compare(&[theirs(Some("S"), "s")], &[mine(None, "s")]);
    assert_eq!(pairs(&rows), ["s/s"]);
    let rows = compare(&[theirs(Some("S"), "s")], &[mine(Some("T"), "t")]);
    assert_eq!(pairs(&rows), ["s/absent", "absent/t"]);
}

#[test]
fn distinct_inputs_get_distinct_result_directories() {
    // Two inputs sharing a directory would overwrite each other's anchors and
    // reports, and both names would read the survivor's.
    assert_ne!(super::slug("a/b.xml"), super::slug("a__b.xml"));
    assert_ne!(super::slug("a/b.xml"), super::slug("a\\b.xml"));
    assert_ne!(super::slug("a_/b.xml"), super::slug("a/_b.xml"));
    assert!(!super::slug("dss-xades/src/x.xml").contains('/'));
}

#[test]
fn a_symlinked_corpus_directory_is_not_read_twice() {
    // A directory alias would list its XML files under two names and count
    // them as two corpus inputs; the tree holds the alias as one link entry,
    // which is no corpus file.
    let listing = b"100644 blob aa\tdss-xades/src/test/resources/real/a.xml\0\
120000 blob bb\tdss-xades/src/test/resources/alias\0";
    assert_eq!(
        super::regular_files(listing).unwrap(),
        ["dss-xades/src/test/resources/real/a.xml"]
    );
}

#[test]
fn an_xades_named_signature_is_a_corpus_input() {
    // DSS names some XML signatures `.xades` (validation/valid.xades); every
    // XML input must be classified, whatever its extension.
    assert!(super::is_xml("dss-xades/src/test/resources/valid.xades"));
    assert!(super::is_xml("dss-xades/src/test/resources/a.xml"));
    assert!(!super::is_xml("dss-xades/src/test/resources/notes.txt"));
}

#[test]
fn a_cached_corpus_checkout_must_still_be_its_release() {
    // A reused checkout that moved to another commit, or whose inputs were
    // edited, would be validated under the release name it no longer holds.
    let checkout = std::path::Path::new("corpus-6.5.1");
    assert!(super::checkout_matches(checkout, "6.5.1", "a", "a", "").is_ok());
    let moved = super::checkout_matches(checkout, "6.5.1", "b", "a", "").unwrap_err();
    assert!(moved.contains("not at DSS 6.5.1"), "{moved}");
    let edited =
        super::checkout_matches(checkout, "6.5.1", "a", "a", " M dss-xades/x.xml").unwrap_err();
    assert!(edited.contains("local changes"), "{edited}");
}

#[test]
fn a_probe_failure_fails_the_check_even_where_dss_finds_no_signature() {
    // A probe that panics on an input DSS also refuses reads no signature,
    // like an unsigned input: the failure itself must reach the check, so a
    // crash can neither pass as `not-a-signature` nor be recorded away.
    let facts = json!({ "probe": { "code": 101, "stderr": "panicked at probe" } });
    let entry = super::observation(&[], &facts, &json!({ "anchors": 0 }));
    let summary = json!({ "cases": { "a.xml": { "instant/strict": entry } } });
    let recorded = super::recorded(&summary, &json!({}));
    let found = differences(&recorded, &summary, &json!({}));
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("the probe failed"), "{found:?}");
}

#[test]
fn a_dss_or_conditions_failure_is_never_an_unsigned_input() {
    // DSS failing after it read the input, or the conditions probe failing,
    // leaves no signature on that side, which an unsigned input also shows.
    // Both are failures of the run; a successful probe that finds no anchor
    // stays an ordinary observation.
    let conditions = json!({ "anchors": 0 });
    let dss = super::observation(
        &[],
        &json!({ "dss_error": "java.lang.IllegalStateException: x\n\tat Probe" }),
        &conditions,
    );
    let unread = super::observation(
        &[],
        &json!({}),
        &json!({ "anchors": 0, "probe": "panicked" }),
    );
    let unsigned = super::observation(&[], &json!({}), &conditions);
    let summary = json!({ "cases": {
        "a.xml": { "instant/strict": dss },
        "b.xml": { "instant/strict": unread },
        "c.xml": { "instant/strict": unsigned },
    } });
    let recorded = super::recorded(&summary, &json!({}));
    let found = differences(&recorded, &summary, &json!({}));
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(
        found[0].starts_with("a.xml") && found[0].contains("DSS failed"),
        "{found:?}"
    );
    assert!(
        found[1].starts_with("b.xml") && found[1].contains("conditions probe failed"),
        "{found:?}"
    );
}

#[test]
fn each_validator_passes_by_its_own_signatures() {
    // A signature only DSS reads stands against an absent one of ours; it
    // decides agreement, not whether xml-sec passed what it read.
    let passed =
        |id| json!({ "id": id, "blocks": {}, "overall": { "indication": "TOTAL_PASSED" } });
    let ours = [json!({ "id": "A", "etsi": { "indication": "TOTAL_PASSED" } })];
    let rows = compare(&[passed("A"), passed("B")], &ours);
    let facts = json!({ "signatures": ours });
    let entry = super::observation(&rows, &facts, &json!({ "anchors": 1 }));
    assert_eq!(entry["passed"], true);
    assert_eq!(entry["dss_passed"], true);
    assert_eq!(entry["class"], "unreviewed");
    // And the other way round.
    let rows = compare(&[passed("A")], &[ours[0].clone(), ours[0].clone()]);
    let entry = super::observation(
        &rows,
        &json!({ "signatures": [ours[0], ours[0]] }),
        &json!({ "anchors": 1 }),
    );
    assert_eq!(entry["dss_passed"], true);
}

#[test]
fn the_release_is_provenance_and_the_instant_a_condition() {
    // The release and the corpus commit resolve at run time: a new release
    // that observes every input as recorded passes, or CI would hold the
    // corpus to the recorded release. A run at another instant observes
    // under other conditions than the recording, so it differs.
    let mut summary = unreviewed_summary();
    summary["dss"] = "6.5.1".into();
    summary["corpus_commit"] = "a".into();
    summary["instant"] = 1_800_000_000.into();
    let reviews = review("normative-difference", "EN 319 102-1 5.2.6.4 step 4");
    let recorded = super::recorded(&summary, &reviews);
    for (field, value) in [("dss", json!("6.6")), ("corpus_commit", json!("b"))] {
        let mut other = summary.clone();
        other[field] = value;
        assert_eq!(
            differences(&recorded, &other, &reviews),
            Vec::<String>::new(),
            "{field}"
        );
    }
    let mut moved = summary.clone();
    moved["instant"] = 1_900_000_000.into();
    let found = differences(&recorded, &moved, &reviews);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("validated at"), "{found:?}");
}

#[test]
fn a_run_with_a_failed_probe_is_not_recorded() {
    // Recording would replace the reviewed expectations and the report with
    // an observation the check rejects; a healthy run that differs from the
    // old expectations is what recording is for.
    let failed = super::observation(&[], &json!({ "probe": { "code": 101 } }), &json!({}));
    let summary = json!({ "cases": { "a.xml": { "instant/strict": failed } } });
    let refused = super::recordable(&summary).unwrap_err();
    assert!(
        refused.contains("a.xml instant/strict: the probe failed"),
        "{refused}"
    );
    assert!(super::recordable(&unreviewed_summary()).is_ok());
}

#[test]
fn a_review_no_observation_matches_fails() {
    // A review whose comparison is no longer observed would otherwise
    // outlive the difference it explains.
    let summary = unreviewed_summary();
    let observed = &summary["cases"]["a.xml"]["instant/strict"]["observed"];
    let reviews = json!({ "a.xml": [
        { "overall": ["TOTAL_PASSED:-/INDETERMINATE:TRY_LATER"], "observed": [observed], "class": "dss-deviation", "reason": "r" },
        { "overall": ["TOTAL_PASSED:-/TOTAL_FAILED:HASH_FAILURE"], "observed": [[{ "OVERALL": "TOTAL_PASSED:-/TOTAL_FAILED:HASH_FAILURE" }]], "class": "dss-deviation", "reason": "r" },
    ] });
    let recorded = super::recorded(&summary, &reviews);
    let found = differences(&recorded, &summary, &reviews);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("matches no observation"), "{found:?}");
}

#[test]
fn a_review_moves_onto_the_new_form_of_the_comparison_it_explained() {
    // A change of how blocks are written leaves the difference a review
    // explains in place: our `fail` at the block the ETSI decision names is
    // that decision's conclusion, which the overall comparison already shows.
    // A pass that now observes another overall result is a new difference,
    // which keeps the review as it was for the check.
    let mut old = unreviewed_summary();
    for label in ["instant/strict", "instant/conformant"] {
        old["cases"]["a.xml"][label]["observed"] = json!([{ "XCV": "INDETERMINATE:TRY_LATER/fail", "OVERALL": "TOTAL_PASSED:-/INDETERMINATE:TRY_LATER" }]);
    }
    let mut reviews = review("normative-difference", "EN 319 102-1 5.2.6.4 step 4");
    reviews["a.xml"][0]["observed"] = json!([old["cases"]["a.xml"]["instant/strict"]["observed"]]);
    let previous = super::recorded(&old, &reviews);
    let mut summary = unreviewed_summary();
    let rewritten = json!([{ "XCV": "INDETERMINATE:TRY_LATER/INDETERMINATE:TRY_LATER", "OVERALL": "TOTAL_PASSED:-/INDETERMINATE:TRY_LATER" }]);
    summary["cases"]["a.xml"]["instant/strict"]["observed"] = rewritten.clone();
    summary["cases"]["a.xml"]["instant/conformant"]["observed"] =
        json!([{ "XCV": "PASSED/pass", "OVERALL": "TOTAL_PASSED:-/TOTAL_PASSED:-" }]);
    let moved = super::carried(&previous, &summary, &reviews);
    assert_eq!(moved["a.xml"][0]["observed"], json!([rewritten]));
    assert_eq!(moved["a.xml"][0]["reason"], reviews["a.xml"][0]["reason"]);
    let recorded = super::recorded(&summary, &moved);
    assert_eq!(
        recorded["cases"]["a.xml"]["instant/strict"]["class"],
        "normative-difference"
    );
    assert_eq!(
        recorded["cases"]["a.xml"]["instant/conformant"]["class"],
        "unreviewed"
    );
    // Carrying again over the same run moves nothing back: the review that
    // already lists the new form still explains it.
    assert_eq!(super::carried(&previous, &summary, &moved), moved);
    // Nothing it explained is observed with the same overall result: the
    // review stays as written.
    let mut changed = unreviewed_summary();
    for label in ["instant/strict", "instant/conformant"] {
        changed["cases"]["a.xml"][label]["observed"] =
            json!([{ "OVERALL": "TOTAL_PASSED:-/TOTAL_PASSED:-" }]);
    }
    assert_eq!(super::carried(&previous, &changed, &reviews), reviews);
    // The same overall result over another block conclusion is a difference
    // the review never explained: missing revocation data (TRY_LATER) is no
    // reason for a revoked certificate (REVOKED_NO_POE).
    let mut revoked = unreviewed_summary();
    for label in ["instant/strict", "instant/conformant"] {
        revoked["cases"]["a.xml"][label]["observed"] = json!([{ "XCV": "INDETERMINATE:REVOKED_NO_POE/INDETERMINATE:TRY_LATER", "OVERALL": "TOTAL_PASSED:-/INDETERMINATE:TRY_LATER" }]);
    }
    assert_eq!(super::carried(&previous, &revoked, &reviews), reviews);
}

#[test]
fn every_dss_run_takes_the_same_time_zone() {
    // DSS's choice of the latest acceptable revocation data follows the
    // JVM's default time zone: OJ_C_2017_173_FULL concludes differently under
    // EET and UTC, so a run must not inherit the host's zone.
    let command = crate::xades::dss::java("cp", "CorpusProbe", &[&"manifest.tsv"]);
    let words: Vec<&str> = command.iter().filter_map(|word| word.to_str()).collect();
    assert_eq!(
        words,
        [
            "java",
            "-Duser.timezone=UTC",
            "-cp",
            "cp",
            "CorpusProbe",
            "manifest.tsv"
        ]
    );
}

#[test]
fn the_inputs_are_the_regular_files_of_the_release_tree() {
    // The tree of the verified commit names the inputs: a file the work tree
    // adds (ignored, so `git status` is silent) is never listed, and a
    // symbolic link or a submodule is no corpus file.
    let listing = b"100644 blob aa\tdss-xades/src/test/resources/b.xml\0\
120000 blob bb\tdss-xades/src/test/resources/link.xml\0\
160000 commit cc\tdss-xades/src/test/resources/module\0\
100755 blob dd\tdss-xades/src/test/resources/a.xades\0\
100644 blob ee\tdss-xades/src/test/resources/sample.png\0";
    let files = super::regular_files(listing).unwrap();
    assert_eq!(
        files,
        [
            "dss-xades/src/test/resources/a.xades",
            "dss-xades/src/test/resources/b.xml",
            "dss-xades/src/test/resources/sample.png",
        ]
    );
    assert_eq!(
        super::not_xml(&files),
        json!({ "dss-xades/src/test/resources/sample.png": "not-xml" })
    );
}

#[test]
fn a_changed_set_of_files_that_are_not_xml_fails_the_check() {
    // Every corpus file has a disposition; a file that is not XML, added or
    // gone, is a change of the corpus the recording did not account for.
    let mut summary = unreviewed_summary();
    summary["not_xml"] = json!({ "sample.txt": "not-xml" });
    let reviews = review("normative-difference", "EN 319 102-1 5.2.6.4 step 4");
    let recorded = super::recorded(&summary, &reviews);
    assert_eq!(recorded["not_xml"], summary["not_xml"]);
    assert_eq!(
        differences(&recorded, &summary, &reviews),
        Vec::<String>::new()
    );
    let mut added = summary.clone();
    added["not_xml"]["sample.png"] = "not-xml".into();
    let found = differences(&recorded, &added, &reviews);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("not XML"), "{found:?}");
}

#[test]
fn carrying_a_review_keeps_an_exact_approval_observed_under_another_pass() {
    // A review approved A (strict) and B (conformant). The new run observes
    // A' equivalent to A under strict, and B exactly, now under a signing-time
    // pass. Carrying A' forward must not drop B: the reviewer approved that
    // very observation, wherever it is now observed.
    let overall = "TOTAL_PASSED:-/INDETERMINATE:TRY_LATER";
    let a = json!([{ "XCV": "INDETERMINATE:TRY_LATER/fail", "OVERALL": overall }]);
    let a_rewritten =
        json!([{ "XCV": "INDETERMINATE:TRY_LATER/INDETERMINATE:TRY_LATER", "OVERALL": overall }]);
    let b = json!([{ "XCV": "INDETERMINATE:TRY_LATER/fail", "SAV": "PASSED/fail", "OVERALL": overall }]);
    let mut old = unreviewed_summary();
    old["cases"]["a.xml"]["instant/strict"]["observed"] = a.clone();
    old["cases"]["a.xml"]["instant/conformant"]["observed"] = b.clone();
    let mut reviews = review("normative-difference", "EN 319 102-1 5.2.6.4 step 4");
    reviews["a.xml"][0]["observed"] = json!([a, b]);
    let previous = super::recorded(&old, &reviews);
    let mut summary = unreviewed_summary();
    summary["cases"]["a.xml"]["instant/strict"]["observed"] = a_rewritten.clone();
    summary["cases"]["a.xml"]["signing-time/strict"] =
        json!({ "observed": b, "class": "unreviewed" });
    let moved = super::carried(&previous, &summary, &reviews);
    assert_eq!(moved["a.xml"][0]["observed"], json!([b, a_rewritten]));
}

#[test]
fn a_review_covers_every_difference_of_its_input_nothing_explains_yet() {
    // A reviewer classifies one input: each pass still unreviewed takes the
    // review, one per overall comparison, and the recording then holds; a
    // review named for some passes leaves the others to their own.
    let mut summary = unreviewed_summary();
    summary["cases"]["a.xml"]["instant/conformant"]["observed"] =
        json!([{ "OVERALL": "TOTAL_PASSED:-/TOTAL_FAILED:HASH_FAILURE" }]);
    let strict = super::reviewed(
        &summary,
        &json!({}),
        "a.xml",
        "normative-difference",
        "EN 319 102-1 5.2.6.4 step 4",
        &["instant/strict"],
    )
    .unwrap();
    let recorded = super::recorded(&summary, &strict);
    assert_eq!(differences(&recorded, &summary, &strict).len(), 1);
    let reviews = super::reviewed(&summary, &strict, "a.xml", "dss-deviation", "r", &[]).unwrap();
    assert_eq!(reviews["a.xml"].as_array().map(Vec::len), Some(2));
    let recorded = super::recorded(&summary, &reviews);
    assert_eq!(
        differences(&recorded, &summary, &reviews),
        Vec::<String>::new()
    );
    // Nothing is left, and a review needs a reviewed class and a reason.
    let class = "normative-difference";
    assert!(super::reviewed(&summary, &reviews, "a.xml", class, "r", &[]).is_err());
    assert!(super::reviewed(&summary, &json!({}), "a.xml", "agreement", "r", &[]).is_err());
    assert!(super::reviewed(&summary, &json!({}), "a.xml", class, " ", &[]).is_err());
}

#[test]
fn pruning_drops_only_the_reviews_no_pass_observes() {
    // The check fails on a review that matches no observation; pruning
    // removes exactly those and keeps every review a pass still takes.
    let summary = unreviewed_summary();
    let live = review("normative-difference", "r")["a.xml"][0].clone();
    let stale = json!({ "overall": ["TOTAL_PASSED:-/TOTAL_PASSED:-"], "observed": [[]], "class": "dss-deviation", "reason": "r" });
    let reviews = json!({ "a.xml": [live.clone(), stale], "gone.xml": [live.clone()] });
    assert_eq!(
        super::pruned(&summary, &reviews),
        json!({ "a.xml": [live] })
    );
    let recorded = super::recorded(&summary, &super::pruned(&summary, &reviews));
    assert_eq!(
        differences(&recorded, &summary, &super::pruned(&summary, &reviews)),
        Vec::<String>::new()
    );
}

#[test]
fn a_manifest_field_cannot_split_its_line() {
    // The DSS probe splits each manifest line at tabs: a path holding one
    // would hand DSS a truncated anchor directory.
    assert_eq!(super::manifest_field("/tmp/a b"), Ok("/tmp/a b"));
    for field in ["/tmp/a\tb", "/tmp/a\nb", "/tmp/a\rb"] {
        assert!(super::manifest_field(field).is_err(), "{field:?}");
    }
}

#[test]
fn only_a_token_that_passed_proves_existence() {
    // EN 319 102-1 V1.4.1 clause 5.4: a proof of existence is a timestamp
    // that validated. Text naming a token, a rejected token or an unjudged
    // one leaves the signing-time pass due.
    let facts = |tokens: Value| json!({ "signatures": [{ "timestamps": tokens }] });
    assert!(super::proves_existence(&facts(json!([token(Some(
        "PASSED"
    ))]))));
    assert!(!super::proves_existence(&facts(json!([
        token(Some("INDETERMINATE")),
        token(None)
    ]))));
    assert!(!super::proves_existence(&facts(Value::Null)));
    // A content timestamp proves the signed data existed, not the signature
    // (EN 319 132-1 section 5.2.8); a references-only one stamps the
    // references alone. Signature, SigAndRefs and archive tokens cover the
    // signature value.
    let passed =
        |role: &str| json!({ "role": role, "current": { "indication": "PASSED", "sub": null } });
    for role in ["AllDataObjects", "IndividualDataObjects", "ReferencesOnly"] {
        assert!(
            !super::proves_existence(&facts(json!([passed(role)]))),
            "{role}"
        );
    }
    for role in ["Signature", "SignatureAndReferences", "Archive"] {
        assert!(
            super::proves_existence(&facts(json!([passed(role)]))),
            "{role}"
        );
    }
}

#[test]
fn each_profile_takes_the_signing_time_pass_its_own_facts_call_for() {
    // A strict refusal of an expired self-anchored signer is time, not
    // policy: the profile whose own path is invalid and whose tokens prove
    // nothing takes the pass, whatever a wider profile validated.
    let validated = json!({ "signatures": [{ "verification": { "trust": "ValidatedX509" } }] });
    let invalid = json!({ "signatures": [{ "verification": { "trust": "Unknown" } }] });
    let proven = json!({ "signatures": [{
        "verification": { "trust": "Unknown" },
        "timestamps": [{ "role": "Signature", "current": { "indication": "PASSED" } }],
    }] });
    let due = super::signing_time_profiles(&[
        ("strict", &invalid),
        ("extended", &proven),
        ("conformant", &validated),
    ]);
    assert_eq!(due, ["strict"]);
}

#[test]
fn a_recomparison_missing_a_listed_pass_is_refused() {
    // A saved pass whose artifacts are gone would drop out of the rewritten
    // summary and be recorded away; the next complete run would then reject
    // it as unlisted.
    let saved = unreviewed_summary();
    let mut short = saved.clone();
    short["cases"]["a.xml"]
        .as_object_mut()
        .unwrap()
        .remove("instant/conformant");
    let refused = super::complete(&saved, &short).unwrap_err();
    assert!(refused.contains("a.xml instant/conformant"), "{refused}");
    assert!(super::complete(&saved, &saved).is_ok());
}
