use std::{path::Path, process::Command};

fn run_upstream(script: &str, selected_test: &str) {
    let tests = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/upstream");
    let output = Command::new(tests.join("testrun.sh"))
        .arg(tests.join(script))
        .arg("rustcrypto")
        .arg(&tests)
        .arg(env!("CARGO_BIN_EXE_xmlsec1"))
        .arg("der")
        .env("XMLSEC_TEST_NAME", selected_test)
        .env("XMLSEC_TEST_REPRODUCIBLE", "1")
        .output()
        .expect("the checked-in upstream runner must execute");
    assert!(
        output.status.success(),
        "{script} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("TOTAL OK:"), "runner summary is missing");
    assert!(
        stdout.contains("TOTAL FAILED: 0"),
        "runner reported a failed operation"
    );
}

#[test]
fn unmodified_dsig_runner_observes_failure_status() {
    // This upstream negative vector proves that digest tampering reaches the
    // native process and is reported with the status expected by testrun.sh.
    run_upstream("testDSig.sh", "signature-rsa-enveloped-bad-digest-val");
}

#[test]
fn unmodified_enc_runner_round_trips_aes_gcm() {
    run_upstream(
        "testEnc.sh",
        "xmlenc11-interop-2012/xenc11-example-AES128-GCM",
    );
}

#[test]
fn unmodified_keys_runner_generates_aes_key_store() {
    run_upstream("testKeys.sh", "test-aes128");
}
