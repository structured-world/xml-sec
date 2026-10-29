use super::{Action, VERIFY_ONLY_FORBIDDEN, execute, forbidden_crate, plan};
use crate::repo::{Failure, Run, Step};
use std::os::unix::process::ExitStatusExt as _;
use std::process::ExitStatus;

/// The planned command lines, as the original runner's Cargo log recorded them.
fn lines(actions: &[Action]) -> Vec<String> {
    actions
        .iter()
        .map(|action| {
            let (Action::Run(step) | Action::VerifyOnlyGraph(step) | Action::MissingBackend(step)) =
                action;
            step.args.join(" ")
        })
        .collect()
}

fn planned(profile: &str, phase: &str) -> Vec<String> {
    lines(&plan(profile, phase, None).unwrap())
}

/// Replays recorded outcomes instead of starting processes.
#[derive(Default)]
struct Recorded {
    fail_at: Option<usize>,
    output: String,
    calls: usize,
}

impl Recorded {
    fn next(&mut self) -> ExitStatus {
        self.calls += 1;
        ExitStatus::from_raw(if Some(self.calls) == self.fail_at {
            37 << 8
        } else {
            0
        })
    }
}

impl Run for Recorded {
    fn status(&mut self, _: &Step) -> Result<ExitStatus, String> {
        Ok(self.next())
    }

    fn stdout(&mut self, _: &Step) -> Result<(ExitStatus, String), String> {
        Ok((self.next(), self.output.clone()))
    }

    fn combined(&mut self, step: &Step) -> Result<(ExitStatus, String), String> {
        self.stdout(step)
    }
}

#[test]
fn minimal_signature_checks_isolate_the_package_and_do_not_enable_encryption() {
    // Workspace defaults must not make an invalid minimal core appear healthy.
    assert_eq!(
        planned("dsig-roxmltree", "all"),
        [
            "tree -p xml-sec --no-default-features --features xmldsig,xml-backend-roxmltree -e normal --prefix none --format {p}",
            "clippy -p xml-sec --no-default-features --features xmldsig,xml-backend-roxmltree --all-targets -- -D warnings",
            "nextest run -p xml-sec --no-default-features --features xmldsig,xml-backend-roxmltree --lib --test verify_only_build",
            "test --doc -p xml-sec --no-default-features --features xmldsig,xml-backend-roxmltree",
        ]
    );
}

#[test]
fn a_verification_only_graph_with_signing_or_import_crates_fails_before_lint() {
    // The verify-only feature exists to keep these crates out of the dependency
    // graph; one reappearing through any edge must fail qualification.
    let actions = plan("dsig-xmloxide", "lint", None).unwrap();
    assert!(matches!(actions[0], Action::VerifyOnlyGraph(_)));
    for name in VERIFY_ONLY_FORBIDDEN {
        let mut runner = Recorded {
            output: format!("xml-sec v0.2.0\n{name} v1.0.0\n"),
            ..Recorded::default()
        };
        let failure = execute(&actions, &mut runner).unwrap_err();
        assert_eq!(
            failure,
            Failure {
                code: 1,
                message: format!("verification-only graph contains {name}")
            }
        );
        assert_eq!(runner.calls, 1, "{name}");
    }
    // A crate whose name merely starts with a forbidden name is not a match.
    assert_eq!(
        forbidden_crate("xml-sec v0.2.0\npkcs12-extra v1.0.0\n"),
        None
    );
    let mut prefixed = Recorded {
        output: "xml-sec v0.2.0\npkcs12-extra v1.0.0\n".into(),
        ..Recorded::default()
    };
    execute(&actions, &mut prefixed).unwrap();
}

#[test]
fn default_qualification_uses_actual_defaults_rather_than_a_hand_built_equivalent() {
    // A newly added default feature must automatically enter this gate.
    assert_eq!(
        planned("default", "test"),
        ["nextest run -p xml-sec --lib --test rust_api"]
    );
    assert_eq!(planned("default", "all").len(), 3);
}

#[test]
fn each_failed_phase_terminates_qualification_without_running_later_phases() {
    // A successful subsequent Cargo invocation must not mask an earlier failure.
    let actions = plan("xmlenc-xmloxide", "all", None).unwrap();
    for calls in 1..=3 {
        let mut runner = Recorded {
            fail_at: Some(calls),
            ..Recorded::default()
        };
        assert_eq!(execute(&actions, &mut runner).unwrap_err().code, 37);
        assert_eq!(runner.calls, calls);
    }
}

#[test]
fn missing_backend_is_accepted_only_for_the_intended_compile_diagnostic() {
    // A broken dependency or missing tool is not proof of the backend contract.
    let actions = plan("no-backend", "all", None).unwrap();
    assert_eq!(
        lines(&actions),
        ["check -p xml-sec --lib --no-default-features"]
    );
    let mut intended = Recorded {
        fail_at: Some(1),
        output: "error: compile at least one XML backend\n".into(),
        ..Recorded::default()
    };
    execute(&actions, &mut intended).unwrap();
    let mut unrelated = Recorded {
        fail_at: Some(1),
        output: "error: registry unavailable\n".into(),
        ..Recorded::default()
    };
    assert!(execute(&actions, &mut unrelated).is_err());
    let mut compiled = Recorded::default();
    assert_eq!(
        execute(&actions, &mut compiled).unwrap_err().message,
        "missing XML backend unexpectedly compiled"
    );
}

#[test]
fn each_minimal_profile_selects_only_its_declared_feature_graph() {
    // In particular XMLEnc, PQ and FIPS must not gain C14N or other providers
    // merely because the enclosing workspace has richer defaults.
    for (profile, features) in [
        ("dom-xmloxide", "xml-backend-xmloxide"),
        ("dom-roxmltree", "xml-backend-roxmltree"),
        ("c14n-xmloxide", "c14n,xml-backend-xmloxide"),
        ("c14n-roxmltree", "c14n,xml-backend-roxmltree"),
        ("dsig-xmloxide", "xmldsig,xml-backend-xmloxide"),
        ("dsig-roxmltree", "xmldsig,xml-backend-roxmltree"),
        ("dsig-sign-xmloxide", "xmldsig-sign,xml-backend-xmloxide"),
        ("xmlenc-xmloxide", "xmlenc,xml-backend-xmloxide"),
        ("xmlenc-roxmltree", "xmlenc,xml-backend-roxmltree"),
        ("xslt", "xslt,xml-backend-xmloxide"),
        (
            "legacy",
            "xmldsig-sign,legacy-algorithms,xml-backend-xmloxide",
        ),
        (
            "experimental",
            "experimental-pq,xmldsig-sign,xml-backend-xmloxide",
        ),
        ("fips-dsig", "aws-lc-fips,xmldsig-sign,xml-backend-xmloxide"),
        ("pkcs11", "pkcs11,xml-backend-xmloxide"),
    ] {
        let mut expected = Vec::new();
        if profile.starts_with("dsig-") && !profile.starts_with("dsig-sign") {
            expected.push(format!(
                "tree -p xml-sec --no-default-features --features {features} -e normal --prefix none --format {{p}}"
            ));
        }
        expected.push(format!(
            "clippy -p xml-sec --no-default-features --features {features} --all-targets -- -D warnings"
        ));
        assert_eq!(planned(profile, "lint"), expected, "{profile}");
    }
}

#[test]
fn token_tests_execute_the_real_disposable_store_harness() {
    // The runner must not turn a missing native module into an ignored test;
    // with explicit setup its Cargo arguments retain the isolated core graph.
    let actions = plan("pkcs11", "test", Some("/explicit/test/module.so")).unwrap();
    let [Action::Run(step)] = actions.as_slice() else {
        panic!("{actions:?}");
    };
    assert_eq!(step.program, crate::repo::TOOL);
    let harness = crate::pkcs11::nextest(&step.args[2..]);
    assert_eq!(step.args[..2], ["pkcs11-tests", "/explicit/test/module.so"]);
    assert_eq!(
        harness.args.join(" "),
        "nextest run --features pkcs11 --test pkcs11 -p xml-sec --no-default-features --features pkcs11,xml-backend-xmloxide --lib --test rust_api --no-capture"
    );
}

#[test]
fn unknown_profiles_phases_and_missing_token_setup_fail_before_cargo() {
    // Typos and absent native setup must never silently fall back to defaults.
    assert_eq!(plan("unknown", "all", None).unwrap_err().code, 2);
    assert_eq!(plan("default", "typo", None).unwrap_err().code, 2);
    assert!(plan("pkcs11", "test", Some("")).is_err());
    assert!(plan("pkcs11", "all", None).is_err());
}
