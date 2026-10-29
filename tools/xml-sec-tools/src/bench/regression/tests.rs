use super::{Run, ordering, report, summary};
use serde_json::{Value, json};
use std::path::Path;

fn environment(samples: u32, repetitions: u32) -> Value {
    json!({ "platform": "linux", "architecture": "x64", "cpu": "Xeon", "samples": samples, "repetitions": repetitions })
}

fn build() -> Value {
    json!({ "schema": 1, "profile": "release", "rustc": "rustc 1.92.0", "features": { "cli": "benchmark-internals,xslt" } })
}

fn repetition(p50: f64) -> Value {
    json!({ "p50_ns": p50, "p95_ns": p50 * 2.0, "p99_ns": p50 * 3.0, "raw": [{ "wall_ns": p50, "rss_bytes": 1000 }] })
}

fn entry(name: &str, p50s: &[f64]) -> Value {
    json!({
        "level": "cli", "engine": "xml-sec", "scenario": "assertion", "name": name, "operation": "verify", "boundary": "process",
        "memory": { "allocation_calls": 10, "allocated_bytes": 100, "peak_heap_bytes": 50 },
        "repetitions": p50s.iter().map(|p50| repetition(*p50)).collect::<Vec<_>>(),
    })
}

fn cli(results: &[Value]) -> Value {
    json!({ "schema": 2, "source_revision": "abc", "environment": environment(30, 3), "corpus": [{ "name": "a", "sha256": "1" }], "results": results })
}

fn usable(cli: Value, library: Value, build: Value) -> Run {
    Run::Usable {
        cli,
        library,
        build,
    }
}

fn run(results: &[Value]) -> Run {
    usable(
        cli(results),
        json!({ "schema": 1, "environment": environment(30, 3), "results": [] }),
        build(),
    )
}

#[test]
fn identical_runs_compare_every_case_and_find_every_distribution_overlapping() {
    // Equal evidence yields equal medians and no change, not a verdict.
    let results = vec![entry("saml-16", &[100.0, 110.0, 105.0])];
    let report = report(&run(&results), &run(&results)).unwrap();
    assert_eq!(report["comparable"], true);
    assert_eq!(report["counts"], json!({ "compared, p50 overlapping": 1 }));
    assert_eq!(report["entries"][0]["latency"]["p50_ns"]["median_ratio"], 1);
    assert_eq!(
        report["entries"][0]["allocations"]["allocation_calls"]["change"],
        0
    );
}

#[test]
fn a_candidate_slower_in_every_repetition_is_reported_as_an_observation_not_a_verdict() {
    // No threshold: the report states the separation and both medians only.
    let report = report(
        &run(&[entry("saml-16", &[100.0, 110.0, 105.0])]),
        &run(&[entry("saml-16", &[200.0, 210.0, 205.0])]),
    )
    .unwrap();
    let p50 = &report["entries"][0]["latency"]["p50_ns"];
    assert_eq!(p50["ordering"], "higher in every repetition");
    assert!((p50["median_ratio"].as_f64().unwrap() - 205.0 / 105.0).abs() < 1e-12);
    let text = summary(&report);
    assert!(
        regex::Regex::new(r"saml-16.*higher in every repetition \| 105 \| 205")
            .unwrap()
            .is_match(&text),
        "{text}"
    );
    assert!(text.contains("nothing here is a pass or fail verdict"));
    assert_eq!(ordering(&[1.0, 2.0], &[0.0, 3.0]), "overlapping");
    assert_eq!(
        ordering(&[5.0, 6.0], &[1.0, 2.0]),
        "lower in every repetition"
    );
}

#[test]
fn a_separated_case_keeps_its_four_table_cells_in_the_summary() {
    // The case identity must not split the Markdown row into extra columns.
    let report = report(
        &run(&[entry("saml-16", &[100.0, 110.0, 105.0])]),
        &run(&[entry("saml-16", &[200.0, 210.0, 205.0])]),
    )
    .unwrap();
    let text = summary(&report);
    let row = text.lines().find(|line| line.contains("saml-16")).unwrap();
    let mut cells = 0;
    let mut escaped = false;
    for c in row.chars() {
        if c == '|' && !escaped {
            cells += 1;
        }
        escaped = c == '\\';
    }
    assert_eq!(cells - 1, 4, "{row}");
}

#[test]
fn a_one_sample_or_under_repeated_run_proves_harness_operation_only() {
    // The contract needs at least three repetitions of more than one sample.
    let results = vec![entry("saml-16", &[100.0])];
    for smoke_environment in [environment(1, 3), environment(30, 1)] {
        let mut smoke_cli = cli(&results);
        smoke_cli["environment"] = smoke_environment;
        let smoke = usable(
            smoke_cli,
            json!({ "schema": 1, "environment": environment(30, 3), "results": [] }),
            build(),
        );
        let report = report(&run(&results), &smoke).unwrap();
        assert_eq!(report["comparable"], false);
        let reasons: Vec<&str> = report["incomparable_reasons"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(
            reasons
                .iter()
                .any(|reason| reason.starts_with("candidate cli run has")
                    && reason.ends_with("it proves harness operation only"))
        );
        assert_eq!(report["counts"], json!({ "incomparable": 1 }));
    }
}

#[test]
fn different_hosts_builds_or_corpora_are_incomparable_with_their_reasons() {
    // Comparing across environments would attribute host or build effects to the code.
    let results = vec![entry("saml-16", &[100.0, 110.0, 105.0])];
    let library = || json!({ "schema": 1, "environment": environment(30, 3), "results": [] });
    let mut host = cli(&results);
    host["environment"]["cpu"] = json!("EPYC");
    let mut toolchain = build();
    toolchain["rustc"] = json!("rustc 1.99.0");
    let mut features = build();
    features["features"] = json!({ "cli": "benchmark-internals" });
    let mut corpus = cli(&results);
    corpus["corpus"] = json!([{ "name": "a", "sha256": "2" }]);
    for (candidate, reason) in [
        (
            usable(host, library(), build()),
            "cli environment cpu differs",
        ),
        (
            usable(cli(&results), library(), toolchain),
            "build rustc differs",
        ),
        (
            usable(cli(&results), library(), features),
            "build features differs",
        ),
        (usable(corpus, library(), build()), "corpus digests differ"),
    ] {
        let report = report(&run(&results), &candidate).unwrap();
        assert_eq!(report["comparable"], false);
        assert!(
            report["incomparable_reasons"].to_string().contains(reason),
            "{reason}"
        );
        assert!(
            report["entries"]
                .as_array()
                .unwrap()
                .iter()
                .all(|entry| entry["status"] == "incomparable")
        );
    }
}

#[test]
fn cases_present_on_one_side_only_and_unsupported_cases_are_explicit() {
    // A case can disappear or become unsupported; neither may pass silently.
    let mut unsupported = entry("xslt-16", &[]);
    unsupported["unsupported"] = json!("no XSLT transform");
    let report = report(
        &run(&[
            entry("old", &[1.0, 2.0, 3.0]),
            entry("xslt-16", &[1.0, 2.0, 3.0]),
        ]),
        &run(&[entry("new", &[1.0, 2.0, 3.0]), unsupported]),
    )
    .unwrap();
    let status: Vec<(String, String)> = report["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            let name = entry["case"]
                .as_str()
                .unwrap()
                .split(" | ")
                .nth(3)
                .unwrap()
                .to_owned();
            (name, entry["status"].as_str().unwrap().to_owned())
        })
        .collect();
    let expected: Vec<(String, String)> = [
        ("old", "missing in candidate"),
        ("xslt-16", "unsupported"),
        ("new", "missing in baseline"),
    ]
    .iter()
    .map(|(name, status)| ((*name).to_owned(), (*status).to_owned()))
    .collect();
    assert_eq!(status, expected);
    let unsupported = report["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["status"] == "unsupported")
        .unwrap();
    assert_eq!(unsupported["candidate"], "no XSLT transform");
}

#[test]
fn a_missing_allocation_profile_stays_missing_instead_of_becoming_zero() {
    // Zero would read as a measured improvement.
    let mut unprofiled = entry("saml-16", &[1.0, 2.0, 3.0]);
    unprofiled["memory"] = Value::Null;
    let report = report(
        &run(&[entry("saml-16", &[1.0, 2.0, 3.0])]),
        &run(&[unprofiled]),
    )
    .unwrap();
    assert_eq!(
        report["entries"][0]["allocations"],
        json!({ "not_measured": "candidate" })
    );
}

/// Writes a run directory from parts; a string part is written verbatim.
fn write_run(directory: &Path, name: &str, parts: [Option<Value>; 3]) -> std::path::PathBuf {
    let location = directory.join(name);
    std::fs::create_dir_all(&location).unwrap();
    for (file, content) in ["comparison.json", "library.json", "build.json"]
        .into_iter()
        .zip(parts)
    {
        if let Some(content) = content {
            let text = content
                .as_str()
                .map_or_else(|| content.to_string(), str::to_owned);
            std::fs::write(location.join(file), text).unwrap();
        }
    }
    location
}

fn parts(results: &[Value]) -> [Option<Value>; 3] {
    [
        Some(cli(results)),
        Some(json!({ "schema": 1, "environment": environment(30, 3), "results": [] })),
        Some(build()),
    ]
}

#[test]
fn an_unusable_baseline_is_reported_as_missing_evidence_never_as_a_comparison() {
    // A malformed, absent or other-schema baseline yields explicit no-baseline entries.
    let directory = tempfile::tempdir().unwrap();
    let results = vec![entry("saml-16", &[1.0, 2.0, 3.0])];
    let candidate = Run::load(&write_run(directory.path(), "candidate", parts(&results)));
    for (index, (baseline, reason)) in [
        (
            {
                let mut p = parts(&results);
                p[2] = None;
                p
            },
            "build.json is missing",
        ),
        (
            {
                let mut p = parts(&results);
                p[0] = Some(json!("{not json"));
                p
            },
            "comparison.json is not valid JSON",
        ),
        (
            {
                let mut p = parts(&results);
                p[1] = Some(json!({ "schema": 9, "results": [] }));
                p
            },
            "library.json has schema 9",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let baseline = Run::load(&write_run(
            directory.path(),
            &format!("baseline-{index}"),
            baseline,
        ));
        let report = report(&baseline, &candidate).unwrap();
        assert_eq!(report["comparable"], false);
        assert_eq!(report["baseline"], Value::Null);
        assert!(
            report["incomparable_reasons"][0]
                .as_str()
                .unwrap()
                .contains(reason),
            "{reason}"
        );
        assert_eq!(report["counts"], json!({ "no baseline": 1 }));
    }
}

#[test]
fn malformed_case_measurements_make_a_baseline_unusable_and_a_candidate_fail() {
    // Schema-valid files can still carry empty, short or non-numeric repetitions.
    let directory = tempfile::tempdir().unwrap();
    let valid = Run::load(&write_run(
        directory.path(),
        "valid",
        parts(&[entry("saml-16", &[1.0, 2.0, 3.0])]),
    ));
    let mut null_percentile = entry("saml-16", &[100.0, 105.0, 105.0]);
    null_percentile["repetitions"][1] = Value::Null;
    for (index, results) in [
        vec![entry("saml-16", &[])],
        vec![null_percentile],
        vec![entry("saml-16", &[100.0, 110.0])],
    ]
    .into_iter()
    .enumerate()
    {
        let malformed = Run::load(&write_run(
            directory.path(),
            &format!("malformed-{index}"),
            parts(&results),
        ));
        let report = report(&malformed, &valid).unwrap();
        assert_eq!(report["comparable"], false);
        let reason = report["incomparable_reasons"][0].as_str().unwrap();
        assert!(
            reason.starts_with("no usable baseline: comparison.json case ")
                && reason.contains("saml-16"),
            "{reason}"
        );
        let failure = super::report(&valid, &malformed).unwrap_err();
        assert!(
            failure.starts_with("candidate run is unusable: comparison.json case ")
                && failure.contains("saml-16"),
            "{failure}"
        );
    }
}

#[test]
fn an_unusable_candidate_fails_the_report_instead_of_writing_one() {
    // The candidate is this run's own evidence; a broken one is a failure.
    let directory = tempfile::tempdir().unwrap();
    let baseline = Run::load(&write_run(
        directory.path(),
        "baseline",
        parts(&[entry("saml-16", &[1.0, 2.0, 3.0])]),
    ));
    let mut broken = parts(&[]);
    broken[2] = None;
    let candidate = Run::load(&write_run(directory.path(), "candidate", broken));
    assert_eq!(
        report(&baseline, &candidate).unwrap_err(),
        "candidate run is unusable: build.json is missing"
    );
    let complete = Run::load(&write_run(
        directory.path(),
        "complete",
        parts(&[entry("saml-16", &[1.0, 2.0, 3.0])]),
    ));
    assert_eq!(report(&baseline, &complete).unwrap()["comparable"], true);
}
