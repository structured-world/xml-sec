use std::{fs, path::Path, process::Command};

fn run_upstream(script: &str, selected_test: &str) -> String {
    let tests = Path::new(env!("CARGO_MANIFEST_DIR")).join("tools/xmlsec1/tests/fixtures/upstream");
    let run_root = tempfile::tempdir().expect("the upstream runner needs a private log directory");
    // The upstream runner uses Bash-only `source` and `[[` despite its `/bin/sh`
    // shebang. Invoke its actual language explicitly on platforms where `sh` is dash.
    let output = Command::new("bash")
        .arg(tests.join("testrun.sh"))
        .arg(tests.join(script))
        .arg("rustcrypto")
        .arg(&tests)
        .arg(env!("CARGO_BIN_EXE_xmlsec1"))
        .arg("der")
        .env("XMLSEC_TEST_NAME", selected_test)
        .env("XMLSEC_TEST_REPRODUCIBLE", "1")
        .env("TMPFOLDER", run_root.path())
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
    let total_ok = stdout
        .lines()
        .find_map(|line| line.split_once("TOTAL OK:").map(|(_, count)| count))
        .and_then(|count| count.split(';').next())
        .and_then(|count| count.trim().parse::<usize>().ok())
        .expect("runner TOTAL OK count must be numeric");
    assert!(total_ok > 0, "selected upstream test did not execute");
    assert!(
        stdout.contains("TOTAL FAILED: 0"),
        "runner reported a failed operation"
    );
    let mut run_directories = fs::read_dir(run_root.path())
        .expect("the runner log root must be readable")
        .map(|entry| entry.expect("the runner log directory entry must be readable"))
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    run_directories.sort();
    let [run_directory] = run_directories.as_slice() else {
        panic!("the runner must create exactly one log directory: {run_directories:?}");
    };
    fs::read_to_string(run_directory.join("full.log"))
        .expect("the unmodified runner must preserve its full operation log")
}

#[test]
fn unmodified_dsig_runner_observes_failure_status() {
    // This upstream negative vector proves that digest tampering reaches the
    // native process and is reported with the status expected by testrun.sh.
    let log = run_upstream("testDSig.sh", "signature-rsa-enveloped-bad-digest-val");
    assert!(log.contains("Error: signature is invalid"), "{log}");
    assert!(!log.contains("unsupported option"), "{log}");
}

#[test]
fn unmodified_enc_runner_round_trips_aes_gcm() {
    let _ = run_upstream(
        "testEnc.sh",
        "xmlenc11-interop-2012/xenc11-example-AES128-GCM",
    );
}

#[test]
fn unmodified_keys_runner_generates_aes_key_store() {
    // The complete donor script is retained byte-for-byte, but this test claims
    // only the selected AES generation scenario. `check-key-data rsa` describes
    // RSA loading/resolution and does not imply `keys --gen-key rsa-*` support.
    let _ = run_upstream("testKeys.sh", "test-aes128");
}
