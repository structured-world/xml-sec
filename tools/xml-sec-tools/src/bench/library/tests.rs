use super::{
    BOUNDARIES, Engine, Outcome, Request, engines_from, execute, harness_outcome, validate_report,
};
use crate::bench::Captured;
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

fn captured(code: Option<i32>, stdout: &str, stderr: &str) -> Captured {
    Captured {
        code,
        stdout: stdout.into(),
        stderr: stderr.into(),
        ..Captured::default()
    }
}

fn request() -> Request<'static> {
    Request {
        engine: "xml-sec",
        scenario: "assertion",
        operation: "verify",
        boundary: "parse",
        samples: 2,
    }
}

fn report() -> Value {
    json!({
        "engine": "xml-sec", "scenario": "assertion", "operation": "verify", "boundary": "parse",
        "samples_ns": [10, 20], "allocations": null, "input_bytes": 5, "output_bytes": null,
    })
}

#[test]
fn harness_exit_statuses_separate_unsupported_work_from_failures() {
    // An unsupported operation is recorded with its reason, never as a failure or a timing.
    assert_eq!(
        harness_outcome(&captured(Some(3), "", "unsupported: no XSLT\n")),
        Outcome::Unsupported("no XSLT".into())
    );
    assert!(matches!(
        harness_outcome(&captured(Some(4), "", "operation: digest mismatch")),
        Outcome::Failed(_)
    ));
    assert!(matches!(
        harness_outcome(&Captured {
            signal: Some(9),
            ..Captured::default()
        }),
        Outcome::Failed(_)
    ));
    assert!(matches!(
        harness_outcome(&captured(
            Some(0),
            "{\"engine\":\"x\",\"rejected\":true}\n",
            ""
        )),
        Outcome::Rejected(_)
    ));
    assert!(matches!(
        harness_outcome(&captured(Some(0), &report().to_string(), "")),
        Outcome::Measured(_)
    ));
}

#[test]
fn malformed_or_mismatched_harness_reports_are_refused() {
    // A truncated line or a report for another request must never become a timing entry.
    assert_eq!(
        harness_outcome(&captured(Some(0), "{\"engine\":", "")),
        Outcome::Failed("malformed harness report".into())
    );
    validate_report(&report(), &request()).unwrap();
    let broken = |field: &str, value: Value| {
        let mut report = report();
        report[field] = value;
        report
    };
    for invalid in [
        broken("engine", json!("bergshamra")),
        broken("boundary", json!("prepared")),
        broken("samples_ns", json!([10])),
        broken("samples_ns", json!([10, 0])),
        broken("samples_ns", json!([10, 1.5])),
        broken(
            "allocations",
            json!({ "calls": 1, "bytes": -1, "peak_bytes": 0 }),
        ),
        broken("allocations", json!({ "calls": 1 })),
        broken("input_bytes", json!(0)),
    ] {
        assert!(validate_report(&invalid, &request()).is_err(), "{invalid}");
    }
    validate_report(
        &broken(
            "allocations",
            json!({ "calls": 3, "bytes": 64, "peak_bytes": 32 }),
        ),
        &request(),
    )
    .unwrap();
}

#[test]
fn every_harness_binary_must_exist_before_any_measurement_starts() {
    // A named profile build that does not exist is an error, not an unprofiled run.
    let directory = tempfile::tempdir().unwrap();
    let binary = directory.path().join("harness");
    std::fs::write(&binary, "").unwrap();
    let binary = binary.display().to_string();
    let absent = directory.path().join("absent").display().to_string();
    let complete = [
        "LIBRARY_XMLSEC_BIN",
        "LIBRARY_BERGSHAMRA_BIN",
        "LIBRARY_LIBXMLSEC1_BIN",
    ];
    let variables = |overrides: &[(&str, Option<&str>)]| {
        let binary = binary.clone();
        let overrides: Vec<(String, Option<String>)> = overrides
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.map(str::to_owned)))
            .collect();
        move |name: &str| match overrides.iter().find(|(key, _)| key == name) {
            Some((_, value)) => value.clone(),
            None => complete.contains(&name).then(|| binary.clone()),
        }
    };
    let engines = engines_from(variables(&[])).unwrap();
    assert_eq!(engines.len(), 3);
    assert!(engines.iter().all(|engine| engine.profile.is_none()));
    for variable in complete {
        for value in [None, Some(absent.as_str())] {
            assert_eq!(
                engines_from(variables(&[(variable, value)])).unwrap_err(),
                format!("Missing {variable}")
            );
        }
    }
    assert_eq!(
        engines_from(variables(&[(
            "LIBRARY_XMLSEC_PROFILE_BIN",
            Some(absent.as_str())
        )]))
        .unwrap_err(),
        "Missing LIBRARY_XMLSEC_PROFILE_BIN"
    );
}

#[test]
fn each_boundary_carries_its_published_description() {
    // The dashboard explains what each boundary includes.
    assert_eq!(BOUNDARIES.map(|(name, _)| name), ["parse", "prepared"]);
}

/// A fake harness following the request protocol; `behaviour` selects one defect.
fn fake_harness(directory: &Path, name: &str, behaviour: &str) -> PathBuf {
    let file = directory.join(name);
    let script = format!(
        r#"#!/bin/sh
scenario=$1 operation=$2 boundary=$3 corpus=$4 output=$6 samples=$7
behaviour='{behaviour}'
signed='<samlp:Response><saml:Assertion ID="assertion"><ds:Signature><ds:X509Certificate>c</ds:X509Certificate></ds:Signature><saml:Subject><saml:NameID>user@example.invalid</saml:NameID></saml:Subject><saml:AttributeValue>value</saml:AttributeValue></saml:Assertion></samlp:Response>'
if [ "$operation" = sign ] && [ "$behaviour" = no-signing ]; then echo 'unsupported: cannot sign' >&2; exit 3; fi
if [ "$operation" = reject ]; then
  if [ "$behaviour" = accept-forgery ]; then echo 'verification accepted an input it must refuse' >&2; exit 4; fi
  printf '{{"engine":"{name}","rejected":true}}\n'; exit 0
fi
result=
case $operation in
  sign) result=$signed ;;
  encrypt) result='<EncryptedData/>' ;;
  decrypt)
    if [ "$behaviour" = wrong-plaintext ] || {{ [ "$behaviour" = wrong-prepared-plaintext ] && [ "$boundary" = prepared ]; }}; then result='<Other/>'
    else result=$(cat "$corpus/element-16.plain.xml"); fi ;;
esac
if [ -n "$result" ] && [ "$output" != - ]; then printf '%s' "$result" > "$output"; fi
values= i=0
while [ "$i" -lt "$samples" ]; do values="$values${{values:+,}}1000"; i=$((i + 1)); done
if [ -n "$result" ]; then bytes=${{#result}}; else bytes=null; fi
printf '{{"engine":"{name}","scenario":"%s","operation":"%s","boundary":"%s","samples_ns":[%s],"allocations":null,"input_bytes":10,"output_bytes":%s}}\n' "$scenario" "$operation" "$boundary" "$values" "$bytes"
"#
    );
    std::fs::write(&file, script).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
    file
}

fn fake_comparison(
    scenario: &str,
    behaviours: &[(&str, &str)],
) -> (Result<(), String>, Option<Value>) {
    let directory = tempfile::tempdir().unwrap();
    let corpus = directory.path().join("corpus");
    std::fs::create_dir(&corpus).unwrap();
    std::fs::write(
        corpus.join("cases.json"),
        json!([{ "name": format!("{scenario}-16"), "scenario": scenario, "units": 16 }])
            .to_string(),
    )
    .unwrap();
    for file in ["assertion-16.template.xml", "element-16.plain.xml"] {
        std::fs::write(corpus.join(file), "<Payment Id=\"payment\"/>").unwrap();
    }
    let behaviour = |id: &str| {
        behaviours
            .iter()
            .find(|(engine, _)| *engine == id)
            .map_or("honest", |(_, behaviour)| behaviour)
    };
    let engines: Vec<Engine> = [
        ("xml-sec / xmloxide / RustCrypto", "xml-sec"),
        ("bergshamra / Uppsala / RustCrypto", "bergshamra"),
        ("libxmlsec1 / libxml2 / OpenSSL", "libxmlsec1"),
    ]
    .into_iter()
    .map(|(name, id)| Engine {
        name,
        id,
        binary: fake_harness(directory.path(), id, behaviour(id)),
        profile: None,
    })
    .collect();
    let result = execute(directory.path(), 2, &engines);
    let report = std::fs::read_to_string(directory.path().join("library.json"))
        .ok()
        .map(|text| serde_json::from_str(&text).unwrap());
    (result, report)
}

#[test]
fn a_verifier_that_accepts_a_forgery_stops_the_run_before_any_timing() {
    // Timing a verifier that cannot refuse a forgery would rank a broken engine.
    let (result, report) = fake_comparison("assertion", &[("bergshamra", "accept-forgery")]);
    assert!(
        result
            .unwrap_err()
            .contains("Invalid tampered rejection: bergshamra")
    );
    assert_eq!(report, None);
}

#[test]
fn a_decryptor_that_returns_other_plaintext_stops_the_run_before_any_timing() {
    // Speed of a wrong answer is not a measurement.
    let (result, report) = fake_comparison("element", &[("libxmlsec1", "wrong-plaintext")]);
    let error = result.unwrap_err();
    assert!(
        error.starts_with("Plaintext mismatch: ") && error.contains(" -> libxmlsec1"),
        "{error}"
    );
    assert_eq!(report, None);
}

#[test]
fn a_prepared_decryptor_that_returns_other_plaintext_stops_the_run_before_any_timing() {
    // The prepared boundary is timed separately, so its result is checked on its own.
    let (result, report) = fake_comparison("element", &[("xml-sec", "wrong-prepared-plaintext")]);
    let error = result.unwrap_err();
    assert!(
        error.contains(" -> xml-sec / ") && error.contains(" prepared,"),
        "{error}"
    );
    assert_eq!(report, None);
}

#[test]
fn an_operation_an_engine_lacks_is_recorded_with_its_reason_and_never_timed() {
    // Every other engine and operation is measured, three repetitions each.
    let (result, report) = fake_comparison("assertion", &[("bergshamra", "no-signing")]);
    result.unwrap();
    let report = report.unwrap();
    let results = report["results"].as_array().unwrap();
    let lacking: Vec<(&str, &str, &str)> = results
        .iter()
        .filter(|entry| entry["operation"] == "sign" && entry.get("unsupported").is_some())
        .map(|entry| {
            (
                entry["engine"].as_str().unwrap(),
                entry["boundary"].as_str().unwrap(),
                entry["unsupported"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        lacking,
        [
            ("bergshamra / Uppsala / RustCrypto", "parse", "cannot sign"),
            (
                "bergshamra / Uppsala / RustCrypto",
                "prepared",
                "cannot sign"
            )
        ]
    );
    assert!(
        results
            .iter()
            .filter(|entry| entry.get("unsupported").is_some())
            .all(|entry| entry.get("repetitions").is_none())
    );
    assert_eq!(results.len(), 3 * 2 * 2);
    assert!(
        results
            .iter()
            .filter(|entry| entry.get("unsupported").is_none())
            .all(|entry| entry["repetitions"]
                .as_array()
                .is_some_and(|items| items.len() == 3))
    );
}

#[test]
fn the_product_dependency_graph_never_contains_the_competitor() {
    // The competitor may be linked only from the separate benchmark project.
    let root = crate::repo::root();
    let metadata = std::process::Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--all-features"])
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(
        metadata.status.success(),
        "{}",
        String::from_utf8_lossy(&metadata.stderr)
    );
    let metadata: Value = serde_json::from_slice(&metadata.stdout).unwrap();
    let names: Vec<&str> = metadata["packages"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert!(names.contains(&"xml-sec"));
    let competitor: Vec<&&str> = names
        .iter()
        .filter(|name| {
            name.starts_with("bergshamra") || **name == "kryptering" || **name == "uppsala"
        })
        .collect();
    assert_eq!(competitor, Vec::<&&str>::new());
    let competitors = std::process::Command::new("cargo")
        .args([
            "metadata",
            "--format-version",
            "1",
            "--manifest-path",
            "benchmarks/competitors/Cargo.toml",
            "--no-deps",
        ])
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(
        competitors.status.success(),
        "{}",
        String::from_utf8_lossy(&competitors.stderr)
    );
    let competitors: Value = serde_json::from_slice(&competitors.stdout).unwrap();
    assert_ne!(competitors["workspace_root"], root.display().to_string());
}
