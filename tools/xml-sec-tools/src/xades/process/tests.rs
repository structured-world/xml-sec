use super::{Logged, run, sibling};
use std::ffi::OsString;
use std::path::Path;
use std::time::{Duration, Instant};

fn shell(script: &str) -> Vec<OsString> {
    ["sh", "-c", script].map(OsString::from).to_vec()
}

fn run_shell(directory: &Path, script: &str, limit: Duration) -> Result<Logged, String> {
    run(
        &shell(script),
        &directory.join("log"),
        directory,
        &[],
        limit,
    )
}

fn stream(directory: &Path, suffix: &str) -> String {
    std::fs::read_to_string(sibling(&directory.join("log"), suffix)).unwrap()
}

fn alive(pid: &str) -> bool {
    std::process::Command::new("kill")
        .args(["-0", pid])
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap()
        .success()
}

/// Waits until `pid` is gone; a killed process is reaped by its new parent.
fn stops(pid: &str) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if !alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

#[test]
fn a_finished_command_keeps_its_exit_code_streams_and_arguments() {
    // The log is the evidence: arguments before launch, streams as written.
    let directory = tempfile::tempdir().unwrap();
    let result = run_shell(
        directory.path(),
        "printf out; printf err >&2; exit 3",
        Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(result.code, Some(3));
    assert_eq!(
        (result.stdout.as_slice(), result.stderr.as_slice()),
        (&b"out"[..], &b"err"[..])
    );
    let recorded: Vec<String> =
        serde_json::from_str(&stream(directory.path(), ".command.json")).unwrap();
    assert_eq!(recorded, ["sh", "-c", "printf out; printf err >&2; exit 3"]);
}

#[test]
fn a_stuck_command_fails_with_its_partial_streams() {
    // A hung validator must fail with its diagnostics instead of waiting for the job timeout.
    let directory = tempfile::tempdir().unwrap();
    let error = run_shell(
        directory.path(),
        "echo ready; echo waiting >&2; sleep 30",
        Duration::from_secs(1),
    )
    .unwrap_err();
    assert!(error.contains("timed out"), "{error}");
    assert!(error.contains("log.command.json"), "{error}");
    assert_eq!(stream(directory.path(), ".stdout"), "ready\n");
    assert_eq!(stream(directory.path(), ".stderr"), "waiting\n");
}

#[test]
fn a_timeout_before_any_output_leaves_empty_stream_files() {
    // Inspectable files exist even when nothing was printed.
    let directory = tempfile::tempdir().unwrap();
    let error = run_shell(directory.path(), "sleep 30", Duration::from_secs(1)).unwrap_err();
    assert!(error.contains("timed out"), "{error}");
    assert_eq!(stream(directory.path(), ".stdout"), "");
    assert_eq!(stream(directory.path(), ".stderr"), "");
}

#[test]
fn a_timeout_stops_descendants_whether_or_not_their_parent_waits() {
    // A descendant holding the streams open belongs to the command and dies with it.
    for wait in ["; wait", ""] {
        let directory = tempfile::tempdir().unwrap();
        let script = format!("sleep 30 & echo $! > pid; echo ready{wait}");
        let error = run_shell(directory.path(), &script, Duration::from_secs(1)).unwrap_err();
        assert!(error.contains("timed out"), "{error}");
        let pid = std::fs::read_to_string(directory.path().join("pid")).unwrap();
        assert!(stops(pid.trim()), "descendant survived: {script}");
    }
}

#[test]
fn a_descendant_that_left_the_group_cannot_hold_the_deadline() {
    // Job control moves the background job to its own group; the command
    // still fails at its deadline instead of waiting for the open streams.
    let directory = tempfile::tempdir().unwrap();
    let start = Instant::now();
    let error = run_shell(
        directory.path(),
        "set -m; sleep 30 & echo $! > pid; echo ready; wait",
        Duration::from_secs(1),
    )
    .unwrap_err();
    assert!(error.contains("timed out"), "{error}");
    assert!(start.elapsed() < Duration::from_secs(10));
    let pid = std::fs::read_to_string(directory.path().join("pid")).unwrap();
    let pid = pid.trim();
    assert!(
        std::process::Command::new("kill")
            .arg(pid)
            .status()
            .unwrap()
            .success()
    );
    assert!(stops(pid));
}
