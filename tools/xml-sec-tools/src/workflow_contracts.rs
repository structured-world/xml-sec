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
    assert!(workflow.contains("xslt-conformance --cache-managed"));
    assert!(!workflow.contains("run: cargo clean"));
    assert!(workflow.contains("CARGO_TARGET_DIR: ${{ runner.temp }}/xslt-measurement"));
}

#[test]
fn cached_native_oracles_still_pass_installer_provenance_and_capability_validation() {
    // A cache hit must not bypass validation or share modern and earlier profiles.
    let workflow = read(".github/workflows/ci.yml");
    assert_eq!(count(&workflow, "profile: modern"), 3);
    assert_eq!(count(&workflow, "profile: legacy"), 1);
    assert!(!pattern(r"if:.*cache-hit").is_match(&workflow));
    assert!(read(".github/actions/xmlsec-oracle-cache/action.yml").contains(
        "hashFiles('tools/xml-sec-tools/src/install_xmlsec1.rs', 'compatibility/libxmlsec1-1.3.13-donor-commit.txt')"
    ));
    assert_eq!(count(&workflow, "xml-sec-tools -- install-xmlsec1\n"), 4);
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

/// Runs the apt-packages action's script with recording `sudo`, `timeout` and
/// `apt-get` stubs; `apt-get` call number N exits with `exits[N]` (0 past the
/// end). Returns whether the action succeeded, each apt-get call prefixed by
/// its time limit, and what the action exported to later steps.
fn apt(
    packages: &str,
    recommends: &str,
    refreshed: bool,
    exits: &[u8],
) -> (bool, Vec<String>, String) {
    apt_after(0, packages, recommends, refreshed, exits)
}

/// [`apt`] with the action's clock started `elapsed` seconds in, as bash
/// takes `SECONDS` from the environment.
fn apt_after(
    elapsed: u32,
    packages: &str,
    recommends: &str,
    refreshed: bool,
    exits: &[u8],
) -> (bool, Vec<String>, String) {
    let action = read(".github/actions/apt-packages/action.yml");
    let script = literal_block(&action, "      run: |\n", 8);
    let directory = tempfile::tempdir().unwrap();
    let stub = |name: &str, body: String| {
        let path = directory.path().join(name);
        std::fs::write(&path, format!("#!/bin/bash\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    let calls = directory.path().join("calls");
    stub("sudo", "exec \"$@\"".into());
    stub(
        "timeout",
        "[ \"$1\" = --kill-after=30 ] || exit 125\nLIMIT=$2 exec \"${@:3}\"".into(),
    );
    let codes: Vec<String> = exits.iter().map(u8::to_string).collect();
    stub(
        "apt-get",
        format!(
            "codes=({})\ncount={dir}/count\nn=$(cat \"$count\" 2>/dev/null || echo 0)\n\
             echo $((n + 1)) > \"$count\"\necho \"${{LIMIT:--}} $*\" >> {calls}\n\
             exit \"${{codes[$n]:-0}}\"",
            codes.join(" "),
            dir = directory.path().display(),
            calls = calls.display(),
        ),
    );
    let environment = directory.path().join("environment");
    let mut command = Command::new("bash");
    command
        .args(["-e", "-c", &script])
        .env(
            "PATH",
            format!(
                "{}:{}",
                directory.path().display(),
                std::env::var("PATH").unwrap()
            ),
        )
        .env("GITHUB_ENV", &environment)
        .env("PACKAGES", packages)
        .env("RECOMMENDS", recommends)
        .env("SECONDS", elapsed.to_string())
        .env_remove("APT_INDEX_REFRESHED");
    if refreshed {
        command.env("APT_INDEX_REFRESHED", "1");
    }
    let status = command.status().unwrap();
    let calls = std::fs::read_to_string(calls).unwrap_or_default();
    (
        status.success(),
        calls.lines().map(str::to_owned).collect(),
        std::fs::read_to_string(environment).unwrap_or_default(),
    )
}

const APT: &str =
    "-q -o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30";

#[test]
fn a_stalled_apt_attempt_is_cut_off_and_retried_with_a_fresh_index() {
    // A mirror that stops answering held a fuzz job until its 35-minute limit:
    // every apt-get runs under a time limit (exit 124 when it fires), and the
    // index refresh that stalled is attempted again.
    let (success, calls, environment) = apt("softhsm2 valgrind", "true", false, &[124]);
    assert!(success);
    assert_eq!(
        calls,
        [
            format!("120 {APT} update"),
            format!("120 {APT} update"),
            format!("300 {APT} install --yes softhsm2 valgrind"),
        ]
    );
    assert_eq!(environment, "APT_INDEX_REFRESHED=1\n");
}

#[test]
fn apt_retries_fit_one_budget_that_leaves_the_job_time() {
    // Per-attempt limits alone let three stalled installs outlast the 35-minute
    // fuzz job before the last retry starts; the whole action has a 600-second
    // budget, every attempt is cut to what remains of it, and none starts once
    // it is spent.
    let (success, calls, _) = apt_after(550, "softhsm2", "true", false, &[]);
    assert!(success);
    assert_eq!(
        calls,
        [
            format!("50 {APT} update"),
            format!("50 {APT} install --yes softhsm2"),
        ]
    );
    let (success, calls, environment) = apt_after(600, "softhsm2", "true", false, &[]);
    assert!(!success);
    assert!(calls.is_empty(), "{calls:?}");
    assert_eq!(environment, "");
}

#[test]
fn the_package_index_is_refreshed_once_per_job_unless_an_install_fails() {
    // A later step installs from the index an earlier step refreshed; a failed
    // install refreshes it again, since the mirror may have changed under it.
    let (success, calls, _) = apt("mold", "false", true, &[]);
    assert!(success);
    assert_eq!(
        calls,
        [format!(
            "300 {APT} install --yes --no-install-recommends mold"
        )]
    );
    let (success, calls, _) = apt("mold", "true", true, &[100]);
    assert!(success);
    assert_eq!(
        calls,
        [
            format!("300 {APT} install --yes mold"),
            format!("120 {APT} update"),
            format!("300 {APT} install --yes mold"),
        ]
    );
}

#[test]
fn apt_fails_the_step_after_three_attempts() {
    // Retries are bounded: a mirror that never answers fails the job, it does
    // not let it continue without its packages.
    let (success, calls, environment) = apt("softhsm2", "true", false, &[124, 124, 124, 0]);
    assert!(!success);
    assert_eq!(calls, vec![format!("120 {APT} update"); 3]);
    assert_eq!(environment, "");
}

#[test]
fn every_package_installation_goes_through_the_bounded_apt_action() {
    // A direct apt-get bypasses the time limit and retries above.
    let mut files = Vec::new();
    for directory in [".github/workflows", ".github/actions"] {
        for entry in std::fs::read_dir(crate::repo::root().join(directory)).unwrap() {
            let path = entry.unwrap().path();
            files.push(if path.is_dir() {
                path.join("action.yml")
            } else {
                path
            });
        }
    }
    let owner = crate::repo::root().join(".github/actions/apt-packages/action.yml");
    for file in files.iter().filter(|file| **file != owner && file.exists()) {
        let text = std::fs::read_to_string(file).unwrap();
        assert!(!text.contains("apt-get"), "{}", file.display());
    }
    assert!(files.contains(&owner));
}

#[test]
fn the_heaviest_jobs_free_hosted_runner_disk_before_restoring_any_cache() {
    // Full-workspace builds beside the caches and the native oracle exhaust the
    // hosted image's disk; the space must be freed before anything is restored.
    let action = read(".github/actions/free-runner-disk/action.yml");
    assert!(action.contains("if: runner.os == 'Linux' && runner.environment == 'github-hosted'"));
    let workflow = read(".github/workflows/ci.yml");
    for job in ["coverage", "test-matrix"] {
        let body = section(&workflow, job);
        let freed = body
            .find("uses: ./.github/actions/free-runner-disk")
            .unwrap_or_else(|| panic!("{job} frees no disk"));
        for cache in ["rust-build-cache", "xmlsec-oracle-cache"] {
            let restored = body
                .find(&format!("uses: ./.github/actions/{cache}"))
                .unwrap();
            assert!(freed < restored, "{job}: {cache}");
        }
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
