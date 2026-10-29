use super::cli::{Files, Kind, corpus_file, engine_arguments};
use super::dashboard::{EXPECTED_CLI, EXPECTED_LIBRARY};
use super::{
    SCENARIOS, case_files, create_evidence_directory, document_body, format_timestamp, heap_stats,
    number, percentile, policy_refusal, read_json, resources, tamper, unsupported, wrap,
};
use crate::repo::root;
use crate::test_support::read;
use serde_json::{Value, json};
use std::path::Path;
use std::time::Duration;

#[test]
fn only_a_default_resource_limit_refusal_is_recorded_instead_of_failing() {
    // An engine over its own default limit is reported with its reason; any other
    // failure, including an invalid signature, must still stop the comparison.
    assert_eq!(
        policy_refusal(
            "Error: XML signature operation failed: signing policy violation: XSLT workspace bytes exceeds policy maximum 67108864: got 67280426\n"
        )
        .as_deref(),
        Some("XSLT workspace bytes exceeds policy maximum 67108864: got 67280426")
    );
    assert_eq!(
        policy_refusal("Error: signature verification failed: digest mismatch\n"),
        None
    );
    assert_eq!(
        policy_refusal("verification policy violation: signing policy rejects algorithm sha1\n"),
        None
    );
}

#[test]
fn wrapping_places_an_unsigned_forgery_with_the_signed_id_before_the_signed_assertion() {
    // Engines are checked to reject this; a no-op wrap would check an intact document.
    let signed = "<samlp:Response><saml:Assertion ID=\"assertion\"><ds:Signature xmlns:ds=\"d\"><ds:SignedInfo/></ds:Signature>\
        <saml:Subject><saml:NameID>user@example.invalid</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>";
    let wrapped = wrap(signed).unwrap();
    let forged = wrapped.find("attacker@example.invalid").unwrap();
    let original = wrapped.find("user@example.invalid").unwrap();
    assert!(forged > 0 && original > forged);
    assert_eq!(wrapped.matches("ID=\"assertion\"").count(), 2);
    assert_eq!(wrapped.matches("<ds:Signature").count(), 1);
    assert_eq!(
        wrap("<samlp:Response/>").unwrap_err(),
        "Signed assertion missing"
    );
}

#[test]
fn unsupported_work_is_recorded_per_operation_not_per_workload() {
    // Bergshamra verifies assertions and decrypts in-place documents it cannot produce.
    assert!(unsupported("bergshamra", "assertion", "sign").is_some());
    assert_eq!(unsupported("bergshamra", "assertion", "verify"), None);
    assert!(unsupported("bergshamra", "element_in_place", "encrypt").is_some());
    assert_eq!(
        unsupported("bergshamra", "element_in_place", "decrypt"),
        None
    );
    assert_eq!(unsupported("xml-sec", "xslt", "sign"), None);
}

#[test]
fn tampering_changes_a_signed_value_in_every_signing_workload() {
    // A replacement that matches nothing would make the rejection check verify an intact document.
    let signed = [
        ("payload", "<Doc><Payload Id=\"payload\">x</Payload></Doc>"),
        (
            "assertion",
            "<saml:Attribute><saml:AttributeValue>value</saml:AttributeValue></saml:Attribute>",
        ),
        (
            "xslt",
            "<List Id=\"list\"><Item n=\"0\">value</Item></List>",
        ),
    ];
    for (scenario, operations) in SCENARIOS {
        if !operations.contains(&"verify") {
            continue;
        }
        let (_, document) = signed.iter().find(|(name, _)| *name == scenario).unwrap();
        assert_ne!(tamper(document, scenario).unwrap(), *document, "{scenario}");
    }
    assert!(
        tamper("<Doc/>", "assertion")
            .unwrap_err()
            .contains("Tamper target missing")
    );
}

#[test]
fn xml_round_trips_ignore_only_the_declaration_and_outer_whitespace() {
    // A decrypted element may gain a declaration, never different content.
    let plain = b"<?xml version=\"1.0\"?><Order><Payment/></Order>";
    assert_eq!(
        document_body(b"<Order><Payment/></Order>\n"),
        document_body(plain)
    );
    assert_ne!(
        document_body(b"<Order><Payment> </Payment></Order>"),
        document_body(plain)
    );
}

#[test]
fn every_measured_engine_has_arguments_for_each_workload_operation() {
    // A missing combination would fail mid-run after minutes of earlier measurements.
    let files = Files {
        template: "t",
        signed: "s",
        plain: "p",
        encrypted: "e",
        destination: "d",
        corpus: Path::new("c"),
    };
    for (scenario, operations) in SCENARIOS {
        for (kind, engine) in [
            (Kind::Xmlsec, "xml-sec"),
            (Kind::Xmlsec, "libxmlsec1"),
            (Kind::Bergshamra, "bergshamra"),
        ] {
            for operation in operations {
                if unsupported(engine, scenario, operation).is_some() {
                    continue;
                }
                let args = engine_arguments(kind, scenario, operation, &files).unwrap_or_default();
                assert_eq!(
                    args.first().map(String::as_str),
                    Some(*operation),
                    "{engine} {scenario} {operation}"
                );
            }
        }
    }
}

#[test]
fn in_place_encryption_reads_the_whole_document_standalone_reads_the_element() {
    // Each workload encrypts exactly the input its contract names.
    assert_eq!(
        case_files("element_in_place-16", "element_in_place", &json!(16)).plain,
        "order-16.plain.xml"
    );
    assert_eq!(
        case_files("element-16", "element", &json!(16)).plain,
        "element-16.plain.xml"
    );
    assert_eq!(
        case_files("saml-16", "payload", &json!(16)).plain,
        "saml-16.plain.xml"
    );
}

#[test]
fn fresh_nested_evidence_directories_work_without_overwriting_prior_results() {
    // Clean CI has no performance directory; only parents may be reused.
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("target/performance/comparison");
    create_evidence_directory(&output).unwrap();
    assert!(output.is_dir());
    std::fs::write(output.join("evidence"), "preserved").unwrap();
    assert!(create_evidence_directory(&output).is_err());
    assert_eq!(
        std::fs::read_to_string(output.join("evidence")).unwrap(),
        "preserved"
    );
}

#[test]
fn nearest_rank_sorts_independently_and_rejects_missing_samples() {
    // Tail samples keep their rank; an empty set is a failure, not zero.
    let input = [30.0, 10.0, 20.0];
    assert!((percentile(&input, 50).unwrap() - 20.0).abs() < f64::EPSILON);
    assert!((percentile(&input, 99).unwrap() - 30.0).abs() < f64::EPSILON);
    assert_eq!(input, [30.0, 10.0, 20.0]);
    assert!(percentile(&[], 99).is_err());
}

#[test]
fn rss_units_differ_between_gnu_time_and_macos() {
    // GNU time reports KiB, macOS bytes; a missing report is a failure.
    assert_eq!(
        resources("diagnostic\n__METRICS 1.2 0.3 1024\n", "linux").unwrap(),
        (1.5, 1_048_576.0)
    );
    assert_eq!(
        resources(
            " 1.5 real 1.2 user 0.3 sys\n 1024 maximum resident set size",
            "darwin"
        )
        .unwrap(),
        (1.5, 1024.0)
    );
    assert!(resources("aborted", "linux").is_err());
}

#[test]
fn heap_high_water_mark_is_simultaneous_requested_plus_allocator_bytes() {
    // The peak is one snapshot's sum, not the sum of separate maxima.
    assert_eq!(
        heap_stats(
            "total heap usage: 1,234 allocs, 10 frees, 12,345 bytes allocated",
            "mem_heap_B=100\nmem_heap_extra_B=30\nmem_heap_B=80\nmem_heap_extra_B=60\n"
        )
        .unwrap(),
        (1234, 12_345, 140)
    );
    assert!(heap_stats("", "").is_err());
}

#[test]
fn integral_report_numbers_are_written_without_a_fraction() {
    // Reports from earlier runs wrote integral values as integers.
    assert_eq!(number(205.0).to_string(), "205");
    assert_eq!(number(1.5).to_string(), "1.5");
}

#[test]
fn measured_values_survive_a_read_and_rewrite_unchanged() {
    // Reports copy earlier measurements; a lossy parse would alter their last digits.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("report.json");
    let text = r#"{"p50_ns":24992391.999999654,"rss":3784272.9999974836}"#;
    std::fs::write(&path, text).unwrap();
    assert_eq!(read_json(&path).unwrap().to_string(), text);
}

#[test]
fn timestamps_are_iso_utc_with_milliseconds() {
    // Report readers parse the same format earlier runs wrote.
    assert_eq!(
        format_timestamp(Duration::from_millis(1_000_000_000_123)),
        "2001-09-09T01:46:40.123Z"
    );
    assert_eq!(
        format_timestamp(Duration::from_hours(264_384)),
        "2000-02-29T00:00:00.000Z"
    );
    assert_eq!(format_timestamp(Duration::ZERO), "1970-01-01T00:00:00.000Z");
}

#[test]
fn the_corpus_digest_covers_case_inputs_and_signed_cases_only() {
    // Generated outputs never enter the corpus identity that runs are compared by.
    for name in [
        "saml-16.template.xml",
        "order-16.plain.xml",
        "assertion-16.signed.xml",
        "element_in_place-256.signed.xml",
    ] {
        assert!(corpus_file(name), "{name}");
    }
    for name in [
        "assertion-16.signed-0.xml",
        "Saml-16.signed.xml",
        "saml-x.signed.xml",
        "saml-16.tampered.xml",
    ] {
        assert!(!corpus_file(name), "{name}");
    }
}

fn dashboard_input(directory: &Path, cli: &[Value], library: &[Value], build: &Value) {
    let write = |name: &str, value: &Value| {
        std::fs::write(directory.join(name), value.to_string()).unwrap();
    };
    write("comparison.json", &json!({ "schema": 2, "results": cli }));
    write("library.json", &json!({ "schema": 1, "results": library }));
    write("build.json", build);
}

#[test]
fn incomplete_reports_cannot_publish_a_dashboard() {
    // A partial run must fail publication rather than present missing engines as
    // zeros; a run without its build identity is incomplete too.
    let directory = tempfile::tempdir().unwrap();
    let assets = root().join("benchmarks/dashboard");
    let complete = vec![json!({ "repetitions": [{}] }); EXPECTED_CLI];
    let library = vec![json!({ "repetitions": [{}] }); EXPECTED_LIBRARY];
    let unmeasured = |list: &[Value]| [&list[1..], &[json!({ "engine": "unmeasured" })]].concat();
    let schema = json!({ "schema": 1 });
    for (cli, in_process, build, accepted) in [
        (Vec::new(), library.clone(), &schema, false),
        (unmeasured(&complete), library.clone(), &schema, false),
        (complete.clone(), Vec::new(), &schema, false),
        (complete.clone(), unmeasured(&library), &schema, false),
        (
            complete.clone(),
            library.clone(),
            &json!({ "schema": 2 }),
            false,
        ),
        (complete.clone(), library.clone(), &schema, true),
    ] {
        dashboard_input(directory.path(), &cli, &in_process, build);
        let output = directory.path().join("site");
        assert_eq!(
            super::dashboard::build(directory.path(), &output, &assets).is_ok(),
            accepted
        );
        assert_eq!(output.exists(), accepted);
        if output.exists() {
            std::fs::remove_dir_all(&output).unwrap();
        }
    }
}

#[test]
fn the_dashboard_publishes_assets_reports_and_identity_without_local_commands() {
    // Runtime absolute paths stay local; the next baseline needs the build identity.
    let directory = tempfile::tempdir().unwrap();
    let cli: Vec<Value> = (0..EXPECTED_CLI)
        .map(|index| {
            if index < 8 {
                json!({ "unsupported": "not available" })
            } else {
                json!({ "commands": ["private path"], "repetitions": [{}] })
            }
        })
        .collect();
    let library: Vec<Value> = (0..EXPECTED_LIBRARY)
        .map(|index| {
            if index < 4 {
                json!({ "unsupported": "not available" })
            } else {
                json!({ "repetitions": [{}] })
            }
        })
        .collect();
    dashboard_input(
        directory.path(),
        &cli,
        &library,
        &json!({ "schema": 1, "rustc": "rustc 1.92.0" }),
    );
    std::fs::write(directory.path().join("regression.md"), "report\n").unwrap();
    let output = directory.path().join("site");
    let assets = root().join("benchmarks/dashboard");
    super::dashboard::build(directory.path(), &output, &assets).unwrap();
    for file in ["index.html", "app.js", "style.css"] {
        assert_eq!(
            std::fs::read(output.join(file)).unwrap(),
            std::fs::read(assets.join(file)).unwrap()
        );
    }
    let published: Value =
        serde_json::from_str(&std::fs::read_to_string(output.join("comparison.json")).unwrap())
            .unwrap();
    let results = published["results"].as_array().unwrap();
    assert_eq!(results.len(), EXPECTED_CLI);
    assert!(results.iter().all(|entry| entry.get("commands").is_none()));
    let build: Value =
        serde_json::from_str(&std::fs::read_to_string(output.join("build.json")).unwrap()).unwrap();
    assert_eq!(build["rustc"], "rustc 1.92.0");
    assert_eq!(
        std::fs::read_to_string(output.join("regression.md")).unwrap(),
        "report\n"
    );
    assert!(!output.join("regression.json").exists());
}

#[test]
fn the_published_package_includes_every_benchmark_entry_point() {
    // The crate archive keeps the benchmark harness and dashboard assets.
    let listed = std::process::Command::new("cargo")
        .args(["package", "--list", "--allow-dirty", "-p", "xml-sec"])
        .current_dir(root())
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let files = String::from_utf8_lossy(&listed.stdout);
    for file in [
        "benches/security.rs",
        "benches/support/mod.rs",
        "examples/benchmark_latency.rs",
        "benchmarks/dashboard/index.html",
        "benchmarks/dashboard/app.js",
        "benchmarks/dashboard/style.css",
        "benchmarks/Dockerfile",
    ] {
        assert!(
            files.lines().any(|line| line == file),
            "Missing packaged {file}"
        );
    }
}

#[test]
fn ci_benchmark_evidence_stays_outside_the_restored_build_cache() {
    // A cache hit must never supply old evidence to a runner that forbids overwrite.
    let workflow = read(".github/workflows/ci.yml");
    assert!(workflow.contains(
        "bench-latency \"$RUNNER_TEMP/benchmark-smoke-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT\""
    ));
    assert!(workflow.contains(
        "path: ${{ runner.temp }}/benchmark-smoke-${{ github.run_id }}-${{ github.run_attempt }}"
    ));
    assert!(!workflow.contains("target/performance/smoke"));
    let comparison = read(".github/workflows/benchmark-comparison.yml");
    assert!(
        comparison
            .contains("\"$RUNNER_TEMP/benchmark-comparison-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT\"")
    );
    assert!(
        comparison.contains("\"$RUNNER_TEMP/benchmark-site-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT\"")
    );
    assert!(comparison.contains("bench-compare \"$COMPARISON_OUTPUT\""));
    assert!(comparison.contains("bench-dashboard \"$COMPARISON_OUTPUT\" \"$SITE_OUTPUT\""));
    // The regression report runs before the dashboard, so the site publishes it.
    assert!(
        comparison
            .contains("\"$RUNNER_TEMP/benchmark-baseline-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT\"")
    );
    let report = comparison
        .find("bench-regression \"$BASELINE_OUTPUT\" \"$COMPARISON_OUTPUT\" \"$COMPARISON_OUTPUT\"")
        .unwrap();
    assert!(report < comparison.find("bench-dashboard").unwrap());
    assert!(comparison.contains("path: ${{ env.COMPARISON_OUTPUT }}"));
    assert!(comparison.contains("path: ${{ env.SITE_OUTPUT }}"));
    assert!(!comparison.contains("target/performance/"));
}
