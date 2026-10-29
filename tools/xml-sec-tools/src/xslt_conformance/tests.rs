use super::{SLICING, execute};
use crate::repo::{Failure, Run, Step, root};
use std::os::unix::process::ExitStatusExt as _;
use std::path::Path;
use std::process::ExitStatus;

/// A recorded oracle and suite run: the oracle's answers and which suite fails.
struct Recorder {
    version: &'static str,
    transforms: &'static str,
    failing: Option<&'static str>,
    steps: Vec<Step>,
}

impl Recorder {
    fn new() -> Self {
        Self {
            version: "xmlsec1 1.3.13 (openssl)\n",
            transforms: "\"xslt\",\"sha256\"\n",
            failing: None,
            steps: Vec::new(),
        }
    }

    fn suites(&self) -> Vec<&str> {
        self.steps
            .iter()
            .map(|step| step.args[0].as_str())
            .collect()
    }
}

impl Run for Recorder {
    fn status(&mut self, step: &Step) -> Result<ExitStatus, String> {
        let failed = self
            .failing
            .is_some_and(|package| step.args.iter().any(|arg| arg == package));
        self.steps.push(step.clone());
        Ok(ExitStatus::from_raw(if failed { 57 << 8 } else { 0 }))
    }

    fn stdout(&mut self, step: &Step) -> Result<(ExitStatus, String), String> {
        let answer = if step.args[0] == "--version" {
            self.version
        } else {
            self.transforms
        };
        Ok((ExitStatus::from_raw(0), answer.into()))
    }

    fn combined(&mut self, step: &Step) -> Result<(ExitStatus, String), String> {
        Err(format!("unexpected combined run: {}", step.label))
    }
}

/// An installed oracle whose provenance marker names `commit`.
fn oracle(directory: &Path, commit: &str) -> String {
    std::fs::create_dir_all(directory.join("bin")).unwrap();
    std::fs::write(
        directory.join(".xmlsec-source-commit"),
        format!("{commit}\n"),
    )
    .unwrap();
    directory.join("bin/xmlsec1").display().to_string()
}

fn pinned() -> String {
    std::fs::read_to_string(root().join("compatibility/libxmlsec1-1.3.13-donor-commit.txt"))
        .unwrap()
        .trim()
        .to_owned()
}

fn gate(recorder: &mut Recorder, xmlsec: &str, cleanup: bool) -> (Result<(), Failure>, bool) {
    let mut checked = false;
    let result = execute(
        recorder,
        |name| match name {
            "LIBXSLT_SOURCE_DIR" => Some("/libxslt".into()),
            "XMLSEC1_BIN" => Some(xmlsec.into()),
            _ => None,
        },
        cleanup,
        || {
            checked = true;
            Ok(())
        },
    );
    (result, checked)
}

#[test]
fn the_cache_managed_gate_runs_every_suite_and_keeps_the_build() {
    // The complete reciprocal gate still runs; only the cleanup changes owner.
    let directory = tempfile::tempdir().unwrap();
    let xmlsec = oracle(directory.path(), &pinned());
    let mut recorder = Recorder::new();
    let (result, checked) = gate(&mut recorder, &xmlsec, false);
    result.unwrap();
    assert!(checked);
    assert_eq!(recorder.suites(), ["nextest", "nextest"]);
}

#[test]
fn the_gate_never_inherits_a_sliced_corpus_and_cleans_after_both_halves() {
    // A developer's single-case diagnosis must never pass as the full gate,
    // and an oracle under target survives until the reciprocal checks finish.
    let directory = tempfile::tempdir().unwrap();
    let xmlsec = oracle(directory.path(), &pinned());
    let mut recorder = Recorder::new();
    gate(&mut recorder, &xmlsec, true).0.unwrap();
    assert_eq!(recorder.suites(), ["nextest", "nextest", "clean"]);
    for step in &recorder.steps[..2] {
        assert_eq!(step.unset, SLICING);
    }
}

#[test]
fn a_failed_suite_keeps_its_status_and_the_build_evidence() {
    // No cleanup or later suite can overwrite a failing test status.
    for (package, ran) in [("xml-sec-xslt", 1), ("xml-sec", 2)] {
        let directory = tempfile::tempdir().unwrap();
        let xmlsec = oracle(directory.path(), &pinned());
        let mut recorder = Recorder::new();
        recorder.failing = Some(package);
        let failure = gate(&mut recorder, &xmlsec, true).0.unwrap_err();
        assert_eq!(failure.code, 57, "{package}");
        assert_eq!(recorder.steps.len(), ran, "{package}");
    }
}

#[test]
fn an_unqualified_oracle_fails_before_any_suite() {
    // A different version, a missing XSLT transform, no oracle or a foreign
    // source revision cannot fall through to tests that would skip.
    let directory = tempfile::tempdir().unwrap();
    let qualified = oracle(&directory.path().join("qualified"), &pinned());
    let foreign = oracle(
        &directory.path().join("foreign"),
        "different-source-revision",
    );
    let mut older = Recorder::new();
    older.version = "xmlsec1 1.3.12 (openssl)\n";
    let mut without_xslt = Recorder::new();
    without_xslt.transforms = "\"sha256\"\n";
    let cases = [
        ("version", older, qualified.clone()),
        ("transforms", without_xslt, qualified),
        ("binary", Recorder::new(), String::new()),
        ("provenance", Recorder::new(), foreign),
    ];
    for (name, mut recorder, xmlsec) in cases {
        let (result, checked) = gate(&mut recorder, &xmlsec, true);
        assert!(result.is_err(), "{name}");
        assert!(!checked && recorder.steps.is_empty(), "{name}");
    }
}
