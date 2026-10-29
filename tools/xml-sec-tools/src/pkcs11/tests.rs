use super::{config, nextest};
use std::path::Path;

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|&value| value.to_owned()).collect()
}

#[test]
fn token_target_runs_alone_with_captured_harness_output_visible() {
    // Without `--workspace` only the token test target runs, keeping the
    // caller's isolated feature graph, and its output is not captured.
    let step = nextest(&args(&["-p", "xml-sec", "--no-default-features"]));
    assert_eq!(
        step.args,
        args(&[
            "nextest",
            "run",
            "--features",
            "pkcs11",
            "--test",
            "pkcs11",
            "-p",
            "xml-sec",
            "--no-default-features",
            "--no-capture"
        ])
    );
}

#[test]
fn workspace_runs_every_test_with_the_token_feature() {
    // The all-feature gates execute every workspace test against the real token.
    let step = nextest(&args(&["--workspace", "--all-features"]));
    assert_eq!(
        step.args,
        args(&[
            "nextest",
            "run",
            "--workspace",
            "--features",
            "pkcs11",
            "--all-features"
        ])
    );
}

#[test]
fn tokens_are_confined_to_the_disposable_store() {
    // SoftHSM must never fall back to a system token directory.
    assert_eq!(
        config(Path::new("/tmp/store")),
        "directories.tokendir = /tmp/store/tokens\nobjectstore.backend = file\nlog.level = ERROR\n"
    );
}
