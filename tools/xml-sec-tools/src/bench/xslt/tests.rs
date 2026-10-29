use super::{Expected, check_output_location, resources, summary, validate};
use serde_json::{Value, json};

#[test]
fn an_output_symlink_alias_cannot_put_evidence_inside_the_cleaned_target() {
    // A lexical path check loses evidence when an existing parent aliases target.
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("target");
    std::fs::create_dir(&target).unwrap();
    std::os::unix::fs::symlink(&target, root.path().join("alias")).unwrap();
    assert!(check_output_location(&root.path().join("alias/results"), &target).is_err());
    check_output_location(&root.path().join("results"), &target).unwrap();
}

#[test]
fn nearest_rank_percentiles_retain_outliers_without_mutating_raw_samples() {
    // Tail samples must not vanish into an average or interpolation.
    let raw = json!([100, 1, 2, 3]);
    assert_eq!(
        summary(raw.as_array().unwrap()).unwrap(),
        json!({ "p50_ns": 2, "p95_ns": 100, "p99_ns": 100 })
    );
    assert_eq!(raw, json!([100, 1, 2, 3]));
}

#[test]
fn rss_units_remain_platform_specific_and_missing_rss_is_a_failure() {
    // macOS reports bytes; Linux reports KiB. Setup high-water marks are never subtracted.
    assert_eq!(
        resources("123 maximum resident set size", "darwin").unwrap()["peak_rss_bytes"],
        123
    );
    assert_eq!(
        resources("Maximum resident set size (kbytes): 123", "linux").unwrap()["peak_rss_bytes"],
        125_952
    );
    assert!(resources("", "linux").is_err());
}

#[test]
fn absent_invalid_and_mismatched_measurements_are_refused_instead_of_timing_unsupported_work() {
    // Missing observations are failures, never zero-cost or successful results.
    for samples in [
        json!([]),
        json!([0]),
        json!([-1]),
        json!([1.5]),
        json!(["x"]),
    ] {
        assert!(summary(samples.as_array().unwrap()).is_err(), "{samples}");
    }
    let result = json!({ "engine": "xml-sec", "phase": "tree", "samples_ns": [1], "source_bytes": 10, "stylesheet_bytes": 20, "output_bytes": 100 });
    let expected =
        |samples: usize, output_bytes: u64, engine: &'static str, phase: &'static str| Expected {
            samples,
            source_bytes: 10,
            stylesheet_bytes: 20,
            output_bytes,
            engine,
            phase,
        };
    let record: Value = validate(&result, &expected(1, 100, "xml-sec", "tree")).unwrap();
    assert_eq!(record["output_amplification"], 10);
    assert!(validate(&result, &expected(2, 100, "xml-sec", "tree")).is_err());
    assert!(validate(&result, &expected(1, 101, "xml-sec", "tree")).is_err());
    assert!(validate(&result, &expected(1, 100, "libxslt", "tree")).is_err());
    assert!(validate(&result, &expected(1, 100, "xml-sec", "retained")).is_err());
}

#[test]
fn the_native_oracle_configures_with_pkg_config_libxml2_without_a_vendor_cmake_config() {
    // Ubuntu libxml2-dev supplies pkg-config metadata, not LibXml2Config.cmake.
    // Only meaningful where the pinned native source is provisioned.
    let Some(source) = std::env::var_os("LIBXSLT_SOURCE_DIR") else {
        return;
    };
    let build = tempfile::tempdir().unwrap();
    let root = crate::repo::root();
    let result = std::process::Command::new("cmake")
        .arg("-S")
        .arg(&source)
        .arg("-B")
        .arg(build.path())
        .arg(format!(
            "-DLibXml2_DIR={}",
            root.join("benchmarks/cmake/libxml2").display()
        ))
        .args([
            "-DLIBXSLT_WITH_PYTHON=OFF",
            "-DLIBXSLT_WITH_TESTS=OFF",
            "-DLIBXSLT_WITH_PROGRAMS=OFF",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}
