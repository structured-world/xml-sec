use super::{counts, known_cases, problems, test_classes};
use serde_json::{Value, json};
use std::collections::BTreeSet;

fn catalogue() -> Value {
    json!({
        "capabilities": { "signature-policy": "policy" },
        "reasons": { "dss-api": "api" },
        "classes": {
            "signature/AlphaTest": { "covered": ["creation/enveloped"] },
            "signature/BetaTest": { "unsupported": "signature-policy" },
            "extension/GammaTest": { "not-applicable": "dss-api" }
        }
    })
}

fn classes() -> Vec<String> {
    [
        "extension/GammaTest",
        "signature/AlphaTest",
        "signature/BetaTest",
    ]
    .map(str::to_owned)
    .to_vec()
}

fn cases() -> BTreeSet<String> {
    BTreeSet::from(["creation/enveloped".to_owned()])
}

#[test]
fn test_classes_are_junit_classes_below_the_root_without_abstract_bases() {
    // Only `*Test.java` files are JUnit classes; abstract bases and helpers
    // are not classified, and the key drops the tree prefix and `.java`.
    let root = "dss-xades/src/test/java/eu/europa/esig/dss/xades/";
    let files: Vec<String> = [
        "signature/XAdESLevelBTest.java",
        "signature/AbstractXAdESCounterSignatureTest.java",
        "signature/AbstractXAdESTestSignature.java",
        "extension/prettyprint/XAdESLevelLTPrettyPrintTest.java",
        "signature/ManifestBuilder.java",
    ]
    .iter()
    .map(|path| format!("{root}{path}"))
    .chain(["dss-xades/src/test/resources/sample.xml".to_owned()])
    .collect();
    assert_eq!(
        test_classes(&files),
        [
            "extension/prettyprint/XAdESLevelLTPrettyPrintTest",
            "signature/XAdESLevelBTest"
        ]
    );
}

#[test]
fn a_complete_catalogue_has_no_problems() {
    assert_eq!(
        problems(&catalogue(), &classes(), &cases()),
        Vec::<String>::new()
    );
    assert_eq!(
        counts(&catalogue()),
        json!({ "covered": 1, "unsupported": 1, "not-applicable": 1 })
    );
}

#[test]
fn a_new_release_class_and_a_removed_one_are_both_reported() {
    // A class the release added must be classified before the check passes,
    // and an entry for a class the release dropped is stale.
    let mut release = classes();
    release.retain(|class| class != "signature/BetaTest");
    release.push("signature/DeltaTest".into());
    let found = problems(&catalogue(), &release, &cases());
    assert_eq!(
        found,
        [
            "signature/DeltaTest: not in the catalogue",
            "signature/BetaTest: not a test class of the release",
        ]
    );
}

#[test]
fn unknown_names_and_ambiguous_entries_are_reported() {
    // A covered entry must name real harness cases, a status must name a
    // defined capability or reason (several of them when a class lacks more
    // than one), an entry takes exactly one status, and a definition no class
    // uses is reported. Problems follow the catalogue's own order.
    let mut catalogue = catalogue();
    catalogue["classes"]["signature/AlphaTest"] = json!({ "covered": ["creation/missing"] });
    catalogue["classes"]["signature/BetaTest"] =
        json!({ "unsupported": ["signature-policy", "manifest"] });
    catalogue["classes"]["extension/GammaTest"] =
        json!({ "not-applicable": "dss-api", "covered": ["creation/enveloped"] });
    let found = problems(&catalogue, &classes(), &cases());
    assert_eq!(
        found,
        [
            "signature/AlphaTest: covered names unknown \"creation/missing\"",
            "signature/BetaTest: unsupported names unknown \"manifest\"",
            "extension/GammaTest: 2 statuses, one expected",
            "reasons: \"dss-api\" is named by no class",
        ]
    );
}

#[test]
fn a_capability_or_reason_without_a_description_is_reported() {
    // A classification must say why: an empty or non-string definition
    // explains nothing, even when classes name it.
    let mut catalogue = catalogue();
    catalogue["capabilities"]["signature-policy"] = json!("");
    catalogue["reasons"]["dss-api"] = json!(7);
    let found = problems(&catalogue, &classes(), &cases());
    assert_eq!(
        found,
        [
            "signature/BetaTest: unsupported names unknown \"signature-policy\"",
            "extension/GammaTest: not-applicable names unknown \"dss-api\"",
        ]
    );
}

#[test]
fn a_non_string_name_in_a_list_is_reported() {
    // Every element of a list names something: an object beside a valid
    // name is reported, not dropped, so the entry does not pass on the
    // name that resolves.
    let mut catalogue = catalogue();
    catalogue["classes"]["signature/BetaTest"] =
        json!({ "unsupported": ["signature-policy", { "capability": "missing" }] });
    let found = problems(&catalogue, &classes(), &cases());
    assert_eq!(
        found,
        ["signature/BetaTest: unsupported element 2 is not a name"]
    );
}

#[test]
fn an_entry_naming_nothing_is_reported() {
    // An empty list classifies nothing, whatever its status.
    let mut catalogue = catalogue();
    catalogue["classes"]["signature/AlphaTest"] = json!({ "covered": [] });
    let found = problems(&catalogue, &classes(), &cases());
    assert_eq!(found, ["signature/AlphaTest: covered names nothing"]);
}

#[test]
fn the_committed_catalogue_names_only_known_cases_capabilities_and_reasons() {
    // Offline half of the check: whatever the release lists, every entry of
    // the committed catalogue must resolve against the harness as built.
    let path = crate::repo::root().join("interop/xades/dss-catalogue.json");
    let catalogue: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let listed: Vec<String> = catalogue["classes"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        problems(&catalogue, &listed, &known_cases()),
        Vec::<String>::new()
    );
}
