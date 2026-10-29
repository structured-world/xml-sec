//! Contracts the workflows and local actions must keep: build-cache writers,
//! fuzz corpus identities, evidence retention, oracle pins and the required
//! aggregate.

use crate::test_support::{jobs, literal_block, read, section};
use regex::Regex;
use std::os::unix::fs::PermissionsExt as _;
use std::process::Command;

fn pattern(source: &str) -> Regex {
    Regex::new(source).unwrap()
}

fn count(text: &str, needle: &str) -> usize {
    text.matches(needle).count()
}

#[test]
fn dependency_saving_precedes_successful_cleanup_with_failed_builds_retained() {
    // Reverse post-action order must save before cargo clean, never after it.
    let cache = read(".github/actions/rust-build-cache/action.yml");
    let cleanup = cache
        .find("uses: ./.github/actions/clean-build-output")
        .unwrap();
    let saving = cache.find("uses: Swatinem/rust-cache").unwrap();
    assert!(cleanup < saving);
    assert!(read(".github/actions/clean-build-output/action.yml").contains("post-if: success()"));
    assert!(cache.contains("shared-key: ${{ inputs.domain }}-${{ steps.image.outputs.identity }}"));
    assert!(cache.contains("save-if: ${{ inputs.save }}"));
    assert!(!cache.contains("add-rust-environment-hash-key: false"));
}

/// Runs the cleanup action script with a recording `cargo` whose behaviour is
/// `body`; returns whether the action succeeded and the arguments cargo saw.
fn cleanup(manifest: &str, toolchain: &str, body: &str) -> (bool, String) {
    let directory = tempfile::tempdir().unwrap();
    let calls = directory.path().join("calls");
    let cargo = directory.path().join("cargo");
    std::fs::write(
        &cargo,
        format!(
            "#!/bin/sh\nprintf '%s' \"$*\" > '{}'\n{body}\n",
            calls.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&cargo, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!(
        "{}:{}",
        directory.path().display(),
        std::env::var("PATH").unwrap()
    );
    let status = Command::new("node")
        .arg(crate::repo::root().join(".github/actions/clean-build-output/cleanup.mjs"))
        .env("PATH", path)
        .env("INPUT_MANIFEST", manifest)
        .env("INPUT_TOOLCHAIN", toolchain)
        .status()
        .expect("node runs this JavaScript action on GitHub runners");
    (
        status.success(),
        std::fs::read_to_string(calls).unwrap_or_default(),
    )
}

#[test]
fn cleanup_addresses_the_selected_workspace_and_propagates_process_failures() {
    // Cleanup may not touch another workspace or conceal a failed clean command.
    assert_eq!(
        cleanup("fuzz/Cargo.toml", "nightly", "exit 0"),
        (
            true,
            "+nightly clean --manifest-path fuzz/Cargo.toml".into()
        )
    );
    assert!(!cleanup("Cargo.toml", "stable", "exit 7").0);
    assert!(!cleanup("Cargo.toml", "stable", "kill -TERM $$").0);
    assert_eq!(cleanup("", "stable", "exit 0"), (false, String::new()));
}

#[test]
fn saving_dependencies_cannot_remove_the_toolchain_needed_by_post_cleanup() {
    // rust-cache bin cleanup can remove runner-provided Cargo and rustup shims.
    assert!(read(".github/actions/rust-build-cache/action.yml").contains("cache-bin: 'false'"));
}

#[test]
fn pr_smoke_uses_three_jobs_while_long_campaigns_retain_target_parallelism() {
    // Only runner granularity changes: every campaign target and FIPS remain.
    let workflow = read(".github/workflows/fuzz.yml");
    let expression = &pattern(r"target: \$\{\{ fromJSON\((.*?)\) \}\}")
        .captures(&workflow)
        .unwrap()[1];
    let arrays: Vec<Vec<String>> = pattern(r"'(\[[^']+\])'")
        .captures_iter(expression)
        .map(|array| serde_json::from_str(&array[1]).unwrap())
        .collect();
    assert_eq!(arrays[1], ["asan"]);
    assert_eq!(
        arrays[0],
        [
            "xmldsig_verify",
            "xml_semantics",
            "security_roundtrip",
            "transform_parameters",
            "xslt_execution",
            "key_formats",
            "policy_compilation",
            "provider_operations"
        ]
    );
    assert!(pattern(r"target: provider_operations\n\s+fips: true").is_match(&workflow));
    assert!(pattern(r"target: xmlsec_oracle\n\s+fips: false").is_match(&workflow));
    assert!(workflow.contains(r#"fuzz-security "$TARGET" "$MODE" --cache-managed"#));
}

#[test]
fn earlier_corpus_cache_identities_remain_independently_restorable() {
    // Grouping must not discard the evolving corpora already saved by target.
    let action = read(".github/actions/fuzz-corpus/action.yml");
    for target in [
        "xmldsig_verify",
        "xml_semantics",
        "security_roundtrip",
        "transform_parameters",
        "xslt_execution",
        "key_formats",
        "policy_compilation",
        "provider_operations",
        "xmlsec_oracle",
    ] {
        assert!(
            action.contains(&format!("path: fuzz/corpus/{target}\n")),
            "{target}"
        );
        assert!(
            action.contains(&format!(
                "restore-keys: fuzz-corpus-${{{{ runner.os }}}}-{target}-"
            )),
            "{target}"
        );
    }
    assert!(action.contains("provider_operations-${{ inputs.fips }}"));
}

#[test]
fn a_failed_fuzz_run_keeps_its_grown_corpus_although_the_cache_is_not_saved() {
    // actions/cache saves only on success; the artifact is the failed run's only copy.
    let workflow = read(".github/workflows/fuzz.yml");
    assert!(pattern(
        r"if: failure\(\)\n\s+uses: actions/upload-artifact@v7\n\s+with:\n\s+name: fuzz-corpus-[^\n]+\n\s+path: fuzz/corpus\n"
    )
    .is_match(&workflow));
}

#[test]
fn benchmark_and_fuzz_evidence_is_kept_for_one_day() {
    // These artifacts serve inspection of a recent run only; no later run reads them.
    let upload = pattern(
        r"uses: actions/upload-artifact@v7\n(?:\s+if: [^\n]+\n)?\s+with:\n\s+name: ([^\n]+)\n(?s:.*?)retention-days: (\d+)",
    );
    let evidence = pattern(r"^(benchmark-comparison|benchmark-smoke-|fuzz-)");
    let mut uploads = Vec::new();
    for file in ["ci.yml", "benchmark-comparison.yml", "fuzz.yml"] {
        let workflow = read(&format!(".github/workflows/{file}"));
        for upload in upload.captures_iter(&workflow) {
            if evidence.is_match(&upload[1]) {
                uploads.push((upload[1].to_owned(), upload[2].to_owned()));
            }
        }
    }
    assert_eq!(uploads.len(), 5, "{uploads:?}");
    for (name, days) in uploads {
        assert_eq!(days, "1", "{name}");
    }
}

#[test]
fn the_benchmark_observatory_deletes_its_site_artifact_after_deploying_it() {
    // The Pages artifact is consumed by the deployment of the same run only.
    let workflow = read(".github/workflows/benchmarks.yml");
    let deployed = workflow.find("uses: actions/deploy-pages@v5").unwrap();
    let deleted = workflow
        .find(r#"gh api --method DELETE "repos/$GITHUB_REPOSITORY/actions/artifacts/$id""#)
        .unwrap();
    assert!(deleted > deployed);
    assert!(workflow.contains("actions/runs/$GITHUB_RUN_ID/artifacts?name=github-pages"));
    assert!(workflow.contains("actions: write"));
}

#[test]
fn ordinary_jobs_have_one_matrix_writer_and_separate_instrumented_domains() {
    // Compatible readers share dependencies without partial feature writers racing.
    let workflow = read(".github/workflows/ci.yml");
    assert!(workflow.contains("save: ${{ matrix.block == 'extended' }}"));
    assert!(workflow.contains("save: ${{ !matrix.minimal }}"));
    assert!(pattern(r"domain: coverage\n\s+save: 'true'").is_match(&workflow));
    assert!(workflow.contains("check-xslt-conformance.sh --cache-managed"));
    assert!(!workflow.contains("run: cargo clean"));
    assert!(workflow.contains("CARGO_TARGET_DIR: ${{ runner.temp }}/xslt-measurement"));
}

#[test]
fn cached_native_oracles_still_pass_installer_provenance_and_capability_validation() {
    // A cache hit must not bypass validation or share modern and earlier profiles.
    let workflow = read(".github/workflows/ci.yml");
    assert_eq!(count(&workflow, "profile: modern"), 2);
    assert_eq!(count(&workflow, "profile: legacy"), 1);
    assert!(!pattern(r"if:.*cache-hit").is_match(&workflow));
    assert!(read(".github/actions/xmlsec-oracle-cache/action.yml").contains(
        "hashFiles('scripts/install-xmlsec1.sh', 'compatibility/libxmlsec1-1.3.13-donor-commit.txt')"
    ));
    assert_eq!(
        pattern(r"(?:bash )?scripts/install-xmlsec1.sh\n")
            .find_iter(&workflow)
            .count(),
        3
    );
}

/// Runs the runner-image action's script with `image` as `ImageOS`.
fn identity(image: Option<&str>) -> Option<String> {
    let action = read(".github/actions/runner-image/action.yml");
    let script = literal_block(&action, "      run: |\n", 8);
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("output");
    let mut command = Command::new("bash");
    command
        .args(["-e", "-c", &script])
        .env("GITHUB_OUTPUT", &output)
        .env_remove("ImageOS");
    if let Some(image) = image {
        command.env("ImageOS", image);
    }
    let status = command.status().unwrap();
    status
        .success()
        .then(|| std::fs::read_to_string(output).unwrap())
}

#[test]
fn runner_image_identity_is_read_at_runtime_rather_than_an_empty_env_context() {
    // Hosted-runner ImageOS is process environment, not a workflow env entry.
    assert!(!read(".github/workflows/ci.yml").contains("${{ env.ImageOS }}"));
    assert!(
        read(".github/actions/rust-build-cache/action.yml")
            .contains("steps.image.outputs.identity")
    );
    assert!(
        read(".github/actions/xmlsec-oracle-cache/action.yml")
            .contains("steps.image.outputs.identity")
    );
    for image in ["ubuntu24", "ubuntu26", "macos26", "win25"] {
        assert_eq!(identity(Some(image)), Some(format!("identity={image}\n")));
    }
    for image in [None, Some(""), Some("ubuntu24\nother=value")] {
        assert_eq!(identity(image), None, "{image:?}");
    }
}

#[test]
fn coverage_checkout_references_resolve_existing_pinned_oracle_revisions() {
    // Validate the actual setup program, not just YAML syntax: a misspelled
    // metadata filename otherwise prevents the coverage runner from starting.
    let workflow = read(".github/workflows/ci.yml");
    let coverage = section(&workflow, "coverage");
    let script = literal_block(coverage, "id: coverage-oracles\n        run: |\n", 10);
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("output");
    let status = Command::new("bash")
        .args(["-e", "-o", "pipefail", "-c", &script])
        .current_dir(crate::repo::root())
        .env("GITHUB_OUTPUT", &output)
        .status()
        .unwrap();
    assert!(status.success());
    let pins = std::fs::read_to_string(output).unwrap();
    for donor in ["libxmlsec1-1.3.13", "libxslt-1.1.45"] {
        let pinned = read(&format!("compatibility/{donor}-donor-commit.txt"));
        assert!(
            pins.lines()
                .any(|line| line == format!("{donor}={}", pinned.trim())),
            "{donor}"
        );
        assert!(
            coverage.contains(&format!("steps.coverage-oracles.outputs['{donor}']")),
            "{donor}"
        );
    }
}

#[test]
fn the_required_aggregate_reaches_every_job_and_checks_every_direct_result() {
    // These owned workflow blocks use single-line needs; fail on an unconnected
    // job rather than accepting a green subset of the qualification graph.
    let workflow = read(".github/workflows/ci.yml");
    let jobs = jobs(&workflow);
    assert!(jobs.len() > 10);
    let needs = |body: &str| -> Vec<String> {
        body.lines()
            .find_map(|line| line.strip_prefix("    needs: "))
            .map(|value| {
                value
                    .trim_matches(['[', ']'])
                    .split(',')
                    .map(|need| need.trim().to_owned())
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut seen = std::collections::BTreeSet::new();
    let mut pending = vec!["test".to_owned()];
    while let Some(name) = pending.pop() {
        let (_, body) = jobs
            .iter()
            .find(|(job, _)| *job == name)
            .unwrap_or_else(|| panic!("unknown job {name}"));
        if seen.insert(name) {
            pending.extend(needs(body));
        }
    }
    let all: std::collections::BTreeSet<String> =
        jobs.iter().map(|(name, _)| name.clone()).collect();
    assert_eq!(seen, all);
    let (_, aggregate) = jobs.iter().find(|(name, _)| name == "test").unwrap();
    assert!(aggregate.contains("if: ${{ always() }}"));
    for name in needs(aggregate) {
        assert!(
            aggregate.contains(&format!(
                r#"test "${{{{ needs.{name}.result }}}}" = "success""#
            )),
            "{name}"
        );
    }
}
