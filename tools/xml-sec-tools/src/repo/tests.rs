use super::{Step, TOOL, command, wait_until};
use std::ffi::OsStr;
use std::process::Command;
use std::time::{Duration, Instant};

#[test]
fn an_exit_is_reported_with_its_status_before_the_deadline() {
    // The wait ends at the exit, not at the deadline.
    let mut child = Command::new("sh").args(["-c", "exit 3"]).spawn().unwrap();
    let started = Instant::now();
    let status = wait_until(&mut child, started + Duration::from_secs(30))
        .unwrap()
        .unwrap();
    assert_eq!(status.code(), Some(3));
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn a_running_child_at_the_deadline_stays_owned_and_stoppable() {
    // The waiter never reaps, so the caller's kill reaches this very child.
    let mut child = Command::new("sleep").arg("30").spawn().unwrap();
    let outcome = wait_until(&mut child, Instant::now() + Duration::from_millis(50)).unwrap();
    assert!(outcome.is_none());
    child.kill().unwrap();
    let status = child.wait().unwrap();
    assert_eq!(
        std::os::unix::process::ExitStatusExt::signal(&status),
        Some(libc::SIGKILL)
    );
}

#[test]
fn a_tool_step_runs_through_cargo_not_through_the_running_binary() {
    // An earlier step may rebuild the tool with other workspace features and
    // replace the running binary; Linux then reports its own path as deleted.
    // Cargo resolves the current build of the tool instead.
    let step = Step::new("tests", TOOL, &["pkcs11-tests", "/module.so"]).with_env("KEY", "value");
    let command = command(&step);
    assert_eq!(command.get_program(), OsStr::new("cargo"));
    let args: Vec<&OsStr> = command.get_args().collect();
    assert_eq!(
        args,
        [
            "run",
            "--quiet",
            "-p",
            "xml-sec-tools",
            "--",
            "pkcs11-tests",
            "/module.so"
        ]
        .map(OsStr::new)
    );
    assert!(
        command
            .get_envs()
            .any(|(key, value)| key == "KEY" && value == Some(OsStr::new("value")))
    );
}

#[test]
fn other_steps_run_their_own_program() {
    // Only the tool itself is resolved through Cargo.
    let command = command(&Step::new("build", "make", &["all"]));
    assert_eq!(command.get_program(), OsStr::new("make"));
    assert_eq!(command.get_args().collect::<Vec<_>>(), [OsStr::new("all")]);
}
