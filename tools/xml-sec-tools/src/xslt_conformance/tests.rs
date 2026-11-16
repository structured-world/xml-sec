use super::{SLICING, execute};
use crate::install_xmlsec1::{MARKER, Source};
use crate::repo::{Failure, Run, Step};
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
            version: "xmlsec1 1.3.14 (openssl)\n",
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

/// An upstream commit the installer recorded.
const COMMIT: &str = "fb90c09adb1f8e1d5f638e2919a922c9201a22ed";

/// An installed oracle whose provenance marker, as the installer writes it,
/// names `version`, or one without a marker.
fn oracle(directory: &Path, version: Option<&str>) -> String {
    std::fs::create_dir_all(directory.join("bin")).unwrap();
    if let Some(version) = version {
        let source = Source {
            commit: COMMIT.to_owned(),
            version: version.to_owned(),
        };
        std::fs::write(directory.join(MARKER), source.marker()).unwrap();
    }
    directory.join("bin/xmlsec1").display().to_string()
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
    let xmlsec = oracle(directory.path(), Some("1.3.14"));
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
    let xmlsec = oracle(directory.path(), Some("1.3.14"));
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
        let xmlsec = oracle(directory.path(), Some("1.3.14"));
        let mut recorder = Recorder::new();
        recorder.failing = Some(package);
        let failure = gate(&mut recorder, &xmlsec, true).0.unwrap_err();
        assert_eq!(failure.code, 57, "{package}");
        assert_eq!(recorder.steps.len(), ran, "{package}");
    }
}

#[test]
fn an_unqualified_oracle_fails_before_any_suite() {
    // A binary that is not the recorded source's version, a missing XSLT
    // transform, no oracle or no installer provenance cannot fall through to
    // tests that would skip.
    let directory = tempfile::tempdir().unwrap();
    let qualified = oracle(&directory.path().join("qualified"), Some("1.3.14"));
    let unrecorded = oracle(&directory.path().join("unrecorded"), None);
    let mut other = Recorder::new();
    other.version = "xmlsec1 1.3.13 (openssl)\n";
    let mut without_xslt = Recorder::new();
    without_xslt.transforms = "\"sha256\"\n";
    let cases = [
        ("version", other, qualified.clone()),
        ("transforms", without_xslt, qualified),
        ("binary", Recorder::new(), String::new()),
        ("provenance", Recorder::new(), unrecorded),
    ];
    for (name, mut recorder, xmlsec) in cases {
        let (result, checked) = gate(&mut recorder, &xmlsec, true);
        assert!(result.is_err(), "{name}");
        assert!(!checked && recorder.steps.is_empty(), "{name}");
    }
}

#[test]
fn a_recorded_oracle_below_the_interop_minimum_fails_before_any_suite() {
    // An installer-built 1.3.12 matches its own marker, but the interop tests
    // skip below their minimum version, so the gate would pass without them.
    let directory = tempfile::tempdir().unwrap();
    let xmlsec = oracle(directory.path(), Some("1.3.12"));
    let mut recorder = Recorder::new();
    recorder.version = "xmlsec1 1.3.12 (openssl)\n";
    let (result, checked) = gate(&mut recorder, &xmlsec, true);
    let failure = result.unwrap_err();
    assert!(failure.message.contains("1.3.13"), "{}", failure.message);
    assert!(!checked && recorder.steps.is_empty());
}

#[test]
fn the_interop_minimum_is_read_from_the_test_helper() {
    // The gate takes its floor from the declaration the interop tests skip by.
    let source = "pub const REQUIRED_VERSION: (u16, u16, u16) = (2, 10, 4);\n";
    assert_eq!(super::declared_minimum(source), Some((2, 10, 4)));
    assert_eq!(super::declared_minimum("no declaration"), None);
}
