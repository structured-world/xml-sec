use super::{Family, Graph, blocks, execute, plan};
use crate::repo::Step;
use crate::test_support::{read, section};
use std::os::unix::process::ExitStatusExt as _;
use std::process::ExitStatus;

const MODULE: Option<&str> = Some("/test/token.so");

#[test]
fn grouping_retains_every_isolated_test_graph() {
    // Batching must not turn separate Cargo feature resolutions into a union.
    let all = blocks();
    let profiles: Vec<_> = all.iter().flat_map(|(_, block)| block).collect();
    let mut names: Vec<_> = profiles
        .iter()
        .map(|profile| profile.name.as_str())
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "all-features",
            "aws-fips-differential",
            "aws-fips-fat-runtime",
            "aws-fips-roxmltree",
            "aws-fips-xmloxide",
            "default-features",
            "differential",
            "experimental-pq-differential",
            "experimental-pq-roxmltree",
            "experimental-pq-xmloxide",
            "fat-runtime",
            "legacy-aws-fips",
            "legacy-fat-runtime",
            "roxmltree",
            "xmldsig-minimal",
            "xmldsig-sign-minimal",
            "xmlenc-minimal",
            "xmloxide",
            "xslt-fat-runtime",
            "xslt-minimal",
            "xslt-xmloxide",
        ]
    );
    let count = |keep: &dyn Fn(&super::Profile) -> bool| {
        profiles.iter().filter(|profile| keep(profile)).count()
    };
    assert_eq!(count(&|profile| profile.graph == Graph::All), 1);
    assert_eq!(count(&|profile| profile.family == Family::Fips), 5);
    assert_eq!(count(&|profile| profile.family == Family::PostQuantum), 3);
    for (name, block) in &all {
        let steps = plan(name, MODULE).unwrap();
        let tested: Vec<_> = block.iter().filter(|profile| !profile.lint_only).collect();
        let ending = |suffix: &str| {
            steps
                .iter()
                .filter(|step| step.label.ends_with(suffix))
                .count()
        };
        assert_eq!(ending(": tests"), tested.len());
        assert_eq!(ending(": docs"), tested.len());
        for profile in tested {
            let label = format!("{}: tests", profile.name);
            let step = steps.iter().find(|step| step.label == label).unwrap();
            assert!(step.args.iter().any(|arg| arg == "--workspace"));
            assert_eq!(
                step.args[step.args.len() - 2..],
                ["-E", "not binary(libxslt_oracle)"]
            );
            let all = profile.graph == Graph::All;
            assert_eq!(step.program == crate::repo::TOOL, all);
            if all {
                assert!(step.args.iter().any(|arg| arg == "/test/token.so"));
            }
        }
    }
}

#[test]
fn build_and_lint_contracts_remain_separately_resolved() {
    // No workspace feature unification may enrich the XMLEnc inventory build.
    let steps: Vec<Step> = blocks()
        .iter()
        .flat_map(|(name, _)| plan(name, MODULE).unwrap())
        .collect();
    assert_eq!(
        steps
            .iter()
            .filter(|step| step.label.ends_with(": build"))
            .count(),
        6
    );
    let inventory = steps
        .iter()
        .find(|step| step.label == "xmlenc-inventory: build")
        .unwrap();
    assert_eq!(
        inventory.args,
        [
            "build",
            "-p",
            "xml-sec",
            "--no-default-features",
            "--features",
            "xmlenc,xml-backend-xmloxide"
        ]
    );
    let lints: Vec<_> = steps
        .iter()
        .filter(|step| step.label.ends_with(": lint"))
        .collect();
    assert_eq!(lints.len(), 20);
    // Workspace lints carry clippy::pedantic; every lint denies its warnings,
    // and none silences a finding on behalf of an older compiler.
    for lint in &lints {
        let separator = lint.args.iter().position(|arg| arg == "--").unwrap();
        assert_eq!(
            lint.args[separator..],
            ["--", "-D", "warnings"],
            "{}",
            lint.label
        );
    }
    // Former scoped pedantic gates remain separately resolved library graphs.
    for feature in ["xmldsig", "xmldsig-sign", "xmlenc", "xslt"] {
        let label = format!("{feature}-minimal: lint");
        let lint = lints.iter().find(|step| step.label == label).unwrap();
        assert_eq!(
            lint.args,
            [
                "clippy",
                "-p",
                "xml-sec",
                "--lib",
                "--no-default-features",
                "--features",
                &format!("{feature},xml-backend-differential"),
                "--",
                "-D",
                "warnings"
            ]
        );
        let prefix = format!("{feature}-minimal: ");
        assert_eq!(
            steps
                .iter()
                .filter(|step| step.label.starts_with(&prefix))
                .count(),
            1
        );
    }
    assert_eq!(
        steps
            .iter()
            .filter(|step| step.label == "FIPS without encryption")
            .count(),
        1
    );
    assert!(plan("unknown", MODULE).unwrap_err().contains("Unknown"));
    assert!(
        plan("extended", None)
            .unwrap_err()
            .contains("PKCS11_MODULE")
    );
    assert!(
        plan("extended", Some(""))
            .unwrap_err()
            .contains("PKCS11_MODULE")
    );
}

#[test]
fn the_workflow_wires_every_block_on_stable_and_retains_required_aggregates() {
    // A correct standalone plan is insufficient if CI omits a block or required check.
    let workflow = read(".github/workflows/ci.yml");
    let wired: Vec<&str> = workflow
        .split("- block: ")
        .skip(1)
        .map(|rest| rest.split('\n').next().unwrap())
        .collect();
    let names: Vec<&str> = blocks().iter().map(|(name, _)| *name).collect();
    assert_eq!(wired, names);
    let matrix = section(&workflow, "test-matrix");
    assert!(matrix.contains("uses: dtolnay/rust-toolchain@stable"));
    assert!(
        !matrix.contains("toolchain:")
            && !matrix.contains("RUSTUP_TOOLCHAIN")
            && !matrix
                .match_indices('+')
                .any(|(at, _)| matrix[at + 1..].starts_with(|c: char| c.is_ascii_digit())),
        "the block job names no compiler release"
    );
    for name in ["build", "clippy"] {
        let job = section(&workflow, name);
        assert!(job.contains("needs: test-matrix"), "{name}");
        assert!(job.contains("always()"), "{name}");
        assert!(job.contains("needs.test-matrix.result"), "{name}");
        assert!(job.contains("= \"success\""), "{name}");
    }
    let oracle = section(&workflow, "xslt-oracle");
    assert!(oracle.contains("xml-sec-tools -- xades check --output"));
    assert!(oracle.contains("bash scripts/check-xslt-conformance.sh"));
    assert!(oracle.contains("name: xades-interop-results"));
    assert!(oracle.contains("name: xslt-performance"));
}

#[test]
fn each_failed_process_stops_its_block_without_a_successful_later_command() {
    // The aggregate must see the original refusal, not a final successful doc test.
    let steps = plan("core", MODULE).unwrap();
    for failed in [0, 2, steps.len() - 1] {
        let mut observed = 0;
        let error = execute(&steps, |_| {
            observed += 1;
            Ok(ExitStatus::from_raw(if observed - 1 == failed {
                37 << 8
            } else {
                0
            }))
        })
        .unwrap_err();
        assert!(error.ends_with("status=37, signal=null"), "{error}");
        assert_eq!(observed, failed + 1);
    }
    let signalled = execute(&steps, |_| Ok(ExitStatus::from_raw(15))).unwrap_err();
    assert!(signalled.ends_with("status=null, signal=15"), "{signalled}");
    assert!(execute(&steps, |_| Err("spawn failed".into())).is_err());
    let mut completed = 0;
    execute(&steps, |_| {
        completed += 1;
        Ok(ExitStatus::from_raw(0))
    })
    .unwrap();
    assert_eq!(completed, steps.len());
}

#[test]
fn stacked_pull_requests_run_the_same_ci_without_a_base_branch_filter() {
    // An empty event configuration intentionally admits feature-branch bases too.
    let workflow = read(".github/workflows/ci.yml");
    assert!(workflow.lines().any(|line| line == "  pull_request: {}"));
    assert!(workflow.lines().any(|line| line == "    branches: [main]"));
}
