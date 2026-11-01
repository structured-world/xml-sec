use super::{Action, Coverage, Runner, execute, parse_env, plan, remapped_flags, unpacked_package};
use crate::repo::{Failure, Run, Step, require};
use serde_json::{Value, json};
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

fn coverage(flags: &str) -> Coverage {
    Coverage {
        evidence: PathBuf::from("/evidence"),
        module: "/test/module".into(),
        flags: flags.into(),
    }
}

/// Records every call; the call whose line starts with `fail` exits 37.
#[derive(Default)]
struct Recorder {
    fail: Option<&'static str>,
    calls: Vec<String>,
    env_seen_by_tests: Vec<(String, String)>,
}

impl Recorder {
    fn outcome(&mut self, line: String) -> ExitStatus {
        let failed = self.fail.is_some_and(|fail| line.starts_with(fail));
        self.calls.push(line);
        ExitStatus::from_raw(if failed { 37 << 8 } else { 0 })
    }
}

fn line(step: &Step) -> String {
    format!("{} {}", step.program, step.args.join(" "))
}

impl Run for Recorder {
    fn status(&mut self, step: &Step) -> Result<ExitStatus, String> {
        Ok(self.outcome(line(step)))
    }

    fn stdout(&mut self, step: &Step) -> Result<(ExitStatus, String), String> {
        let status = self.outcome(line(step));
        Ok((
            status,
            "CARGO_LLVM_COV=1\nLLVM_PROFILE_FILE='/target/x-%p.profraw'\n".into(),
        ))
    }

    fn combined(&mut self, step: &Step) -> Result<(ExitStatus, String), String> {
        self.stdout(step)
    }
}

impl Runner for Recorder {
    fn token_tests(
        &mut self,
        module: &str,
        args: &[String],
        env: &[(String, String)],
    ) -> Result<(), Failure> {
        let status = self.outcome(format!("tokens {module} {}", args.join(" ")));
        self.env_seen_by_tests = env.to_vec();
        require(status)
    }

    fn create_dir(&mut self, path: &Path) -> Result<(), String> {
        self.calls.push(format!("mkdir {}", path.display()));
        Ok(())
    }

    fn check_report(&mut self, path: &Path) -> Result<Value, String> {
        self.calls.push(format!("check {}", path.display()));
        Ok(json!({ "sources": 1 }))
    }

    fn write(&mut self, path: &Path, _: &str) -> Result<(), String> {
        self.calls.push(format!("write {}", path.display()));
        Ok(())
    }

    fn unpacked(&mut self, target: &Path) -> Result<PathBuf, String> {
        Ok(target.join("package/xml-sec-1.2.3"))
    }
}

fn index(calls: &[String], prefix: &str) -> usize {
    calls
        .iter()
        .position(|call| call.starts_with(prefix))
        .unwrap_or_else(|| panic!("{prefix} in {calls:?}"))
}

#[test]
fn the_runner_preserves_every_source_and_delegates_the_85_percent_gate_to_llvm() {
    // No package exclusion or tolerated test failure can manufacture coverage.
    let flags = remapped_flags(None, Some("-Dwarnings"), Path::new("/repo"));
    let coverage = coverage(&flags);
    let actions = plan("all", Some(&coverage)).unwrap();
    let mut recorder = Recorder::default();
    execute(&actions, Some(&coverage), &mut recorder).unwrap();
    let calls = &recorder.calls;
    for expected in [
        "cargo deny --all-features check --config deny.toml advisories sources licenses",
        "cargo deny --manifest-path fuzz/Cargo.toml --all-features check --config deny.toml advisories sources licenses",
        "cargo clippy --workspace --lib --all-features -- -D warnings -D unsafe_code",
        "tokens /test/module --workspace --all-features",
        "cargo llvm-cov report --package * --fail-under-lines 85",
        "cargo llvm-cov report --package * --lcov",
    ] {
        index(calls, expected);
    }
    assert!(
        index(calls, "rustup component add llvm-tools-preview")
            < index(calls, "cargo llvm-cov show-env")
    );
    assert!(index(calls, "mkdir /evidence") < index(calls, "rustup"));
    assert!(
        index(
            calls,
            "cargo llvm-cov report --package * --fail-under-lines"
        ) < index(calls, "check /evidence/coverage.json")
    );
    assert!(!calls.iter().any(|call| {
        ["--exclude", "--ignore", "--filter"]
            .iter()
            .any(|flag| call.contains(flag))
    }));
    // The instrumented tests see both the remapped flags and the listed environment.
    let env = &recorder.env_seen_by_tests;
    assert!(env.contains(&("CARGO_ENCODED_RUSTFLAGS".into(), flags.clone())));
    assert!(env.contains(&("LLVM_PROFILE_FILE".into(), "/target/x-%p.profraw".into())));
    assert!(flags.starts_with("-Dwarnings\x1f"));
    for name in [
        "xml-sec-xslt",
        "sxd-document-no-unsafe",
        "sxd-xpath-no-unsafe",
        "xml-sec-xml-input",
    ] {
        assert!(flags.contains(name), "{name}");
    }
    assert!(flags.contains("--remap-path-prefix=/repo/crates/xml-sec-xslt/../..=/repo"));
    let encoded = "-C\x1flink-arg=one two";
    assert!(
        remapped_flags(Some(encoded), Some("-Dwarnings"), Path::new("/repo"))
            .starts_with(&format!("{encoded}\x1f"))
    );
    assert!(remapped_flags(Some(""), Some("-A b"), Path::new("/repo")).starts_with("-A\x1fb\x1f"));
}

#[test]
fn the_package_phase_tests_the_archive_rather_than_the_workspace() {
    // Workspace tests cannot notice a target that needs a file outside the
    // archive, so the tests must run from the unpacked package.
    let inputs = coverage("");
    let actions = plan("package", Some(&inputs)).unwrap();
    let mut recorder = Recorder::default();
    execute(&actions, Some(&inputs), &mut recorder).unwrap();
    assert_eq!(
        recorder.calls,
        [
            "cargo package -p xml-sec --all-features --target-dir /evidence",
            "tokens /test/module --workspace --manifest-path /evidence/package/xml-sec-1.2.3/Cargo.toml --all-features --target-dir /evidence",
        ]
    );
}

#[test]
fn the_package_phase_refuses_a_missing_directory_and_stops_on_failure() {
    // A failed package must not fall through to tests of an older unpacked copy.
    assert!(plan("package", None).is_err());
    let inputs = coverage("");
    let actions = plan("package", Some(&inputs)).unwrap();
    let mut recorder = Recorder {
        fail: Some("cargo package"),
        ..Recorder::default()
    };
    assert_eq!(
        execute(&actions, Some(&inputs), &mut recorder)
            .unwrap_err()
            .code,
        37
    );
    assert_eq!(recorder.calls.len(), 1);
}

#[test]
fn unpacked_package_is_the_single_directory_named_for_the_crate() {
    // The compressed archive beside the directory shares its name prefix.
    let root = tempfile::tempdir().unwrap();
    assert!(unpacked_package(root.path()).is_err());
    let package = root.path().join("package");
    std::fs::create_dir(&package).unwrap();
    std::fs::write(package.join("xml-sec-1.2.3.crate"), "").unwrap();
    assert!(unpacked_package(root.path()).is_err());
    std::fs::create_dir(package.join("xml-sec-1.2.3")).unwrap();
    assert_eq!(
        unpacked_package(root.path()).unwrap(),
        package.join("xml-sec-1.2.3")
    );
    std::fs::create_dir(package.join("xml-sec-1.2.2")).unwrap();
    assert!(unpacked_package(root.path()).is_err());
}

#[test]
fn every_failed_gate_stops_qualification_with_the_original_exit_status() {
    // A report or later command must never mask setup, safety or test failure.
    let coverage = coverage("");
    let actions = plan("all", Some(&coverage)).unwrap();
    for gate in [
        "cargo deny",
        "cargo clippy",
        "rustup",
        "cargo llvm-cov clean",
        "cargo llvm-cov show-env",
        "tokens",
        "cargo llvm-cov report",
    ] {
        let mut recorder = Recorder {
            fail: Some(gate),
            ..Recorder::default()
        };
        assert_eq!(
            execute(&actions, Some(&coverage), &mut recorder)
                .unwrap_err()
                .code,
            37,
            "{gate}"
        );
        assert!(
            !recorder.calls.iter().any(|call| call.contains("--lcov")),
            "{gate}"
        );
        assert_eq!(
            recorder
                .calls
                .iter()
                .filter(|call| call.starts_with(gate))
                .count(),
            1,
            "{gate}"
        );
    }
}

#[test]
fn unknown_phases_and_missing_coverage_inputs_fail_without_invoking_cargo() {
    // A typo must not silently skip a required gate, and coverage cannot run
    // without its evidence directory and an isolated token module.
    assert_eq!(plan("typo", None).unwrap_err().code, 2);
    assert!(plan("coverage", None).is_err());
    assert!(plan("all", None).is_err());
    assert_eq!(plan("dependencies", None).unwrap().len(), 2);
    assert_eq!(
        plan("safety", None).unwrap(),
        [Action::Run(Step::new(
            "safety",
            "cargo",
            &[
                "clippy",
                "--workspace",
                "--lib",
                "--all-features",
                "--",
                "-D",
                "warnings",
                "-D",
                "unsafe_code"
            ],
        ))]
    );
}

#[test]
fn the_coverage_environment_listing_is_read_with_shell_quoting() {
    // The listing is shell syntax; values with spaces or quotes must survive.
    assert_eq!(
        parse_env("A=1\nB='x y'\nC='it'\\''s'\nD=a\\ b\n\n").unwrap(),
        [
            ("A".to_owned(), "1".to_owned()),
            ("B".to_owned(), "x y".to_owned()),
            ("C".to_owned(), "it's".to_owned()),
            ("D".to_owned(), "a b".to_owned()),
        ]
    );
    for invalid in ["A='open", "A=$HOME", "A=\"x\"", "no assignment", "A=\\"] {
        assert!(parse_env(invalid).is_err(), "{invalid}");
    }
}
