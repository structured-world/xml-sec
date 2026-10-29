//! Locations and process helpers shared by the subcommands.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Instant;

#[cfg(test)]
mod tests;

/// The repository root, independent of the directory the tool runs from.
pub(crate) fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the tool crate lives two levels below the repository root")
        .to_path_buf()
}

/// One planned process: a label for logs, the program, its arguments, the
/// environment it adds, the inherited variables it removes and the directory
/// it runs in (the repository root unless given).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Step {
    pub(crate) label: String,
    pub(crate) program: String,
    pub(crate) args: Vec<String>,
    pub(crate) env: Vec<(String, String)>,
    pub(crate) unset: Vec<String>,
    pub(crate) directory: Option<PathBuf>,
}

impl Step {
    pub(crate) fn new(label: impl Into<String>, program: &str, args: &[&str]) -> Self {
        Self {
            label: label.into(),
            program: program.into(),
            args: args.iter().map(|&arg| arg.to_owned()).collect(),
            env: Vec::new(),
            unset: Vec::new(),
            directory: None,
        }
    }

    /// Runs the step in `directory` instead of the repository root.
    pub(crate) fn in_directory(mut self, directory: &Path) -> Self {
        self.directory = Some(directory.to_owned());
        self
    }

    /// Adds `key=value` to the step's environment.
    pub(crate) fn with_env(mut self, key: &str, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Removes `key` from the environment the step inherits.
    pub(crate) fn without_env(mut self, key: &str) -> Self {
        self.unset.push(key.into());
        self
    }
}

/// Describes a process outcome the way CI logs report it.
pub(crate) fn describe(status: ExitStatus) -> String {
    let code = status
        .code()
        .map_or_else(|| "null".to_owned(), |code| code.to_string());
    #[cfg(unix)]
    let signal = std::os::unix::process::ExitStatusExt::signal(&status)
        .map_or_else(|| "null".to_owned(), |signal| signal.to_string());
    #[cfg(not(unix))]
    let signal = "null".to_owned();
    format!("status={code}, signal={signal}")
}

/// A step program that names this tool: the step runs another subcommand.
pub(crate) const TOOL: &str = "xml-sec-tools";

/// The process for `step`, from the repository root. The tool runs through
/// Cargo, never through its own path: an earlier step may rebuild the tool
/// with other workspace features and replace the running binary.
pub(crate) fn command(step: &Step) -> Command {
    let mut command = if step.program == TOOL {
        let mut command = Command::new("cargo");
        command.args(["run", "--quiet", "-p", TOOL, "--"]);
        command
    } else {
        Command::new(&step.program)
    };
    command
        .args(&step.args)
        .envs(step.env.iter().map(|(key, value)| (key, value)));
    match &step.directory {
        Some(directory) => command.current_dir(directory),
        None => command.current_dir(root()),
    };
    for key in &step.unset {
        command.env_remove(key);
    }
    command
}

/// Runs `step` from the repository root with inherited output.
pub(crate) fn spawn(step: &Step) -> Result<ExitStatus, String> {
    command(step)
        .status()
        .map_err(|error| format!("{}: {error}", step.label))
}

/// How subcommands reach processes; tests substitute recorded outcomes.
pub(crate) trait Run {
    /// Runs with inherited output.
    fn status(&mut self, step: &Step) -> Result<ExitStatus, String>;
    /// Runs with stdout captured and stderr inherited.
    fn stdout(&mut self, step: &Step) -> Result<(ExitStatus, String), String>;
    /// Runs with stdout and stderr captured together, in order.
    fn combined(&mut self, step: &Step) -> Result<(ExitStatus, String), String>;
}

/// The operating system's processes.
pub(crate) struct System;

impl Run for System {
    fn status(&mut self, step: &Step) -> Result<ExitStatus, String> {
        spawn(step)
    }

    fn stdout(&mut self, step: &Step) -> Result<(ExitStatus, String), String> {
        let output = command(step)
            .stderr(Stdio::inherit())
            .output()
            .map_err(|error| format!("{}: {error}", step.label))?;
        Ok((
            output.status,
            String::from_utf8_lossy(&output.stdout).into_owned(),
        ))
    }

    fn combined(&mut self, step: &Step) -> Result<(ExitStatus, String), String> {
        let (mut reader, writer) =
            std::io::pipe().map_err(|error| format!("{}: {error}", step.label))?;
        let duplicate = writer
            .try_clone()
            .map_err(|error| format!("{}: {error}", step.label))?;
        let mut child = command(step)
            .stdout(writer)
            .stderr(duplicate)
            .spawn()
            .map_err(|error| format!("{}: {error}", step.label))?;
        // The command held the only write ends; with it dropped the read end
        // sees end of file when the child exits.
        let mut text = Vec::new();
        reader
            .read_to_end(&mut text)
            .map_err(|error| format!("{}: {error}", step.label))?;
        let status = child
            .wait()
            .map_err(|error| format!("{}: {error}", step.label))?;
        Ok((status, String::from_utf8_lossy(&text).into_owned()))
    }
}

/// Waits for `child` until `deadline`: its status as soon as it exits, or
/// `None` with the child still running and still owned by the caller.
#[cfg(unix)]
pub(crate) fn wait_until(
    child: &mut Child,
    deadline: Instant,
) -> std::io::Result<Option<ExitStatus>> {
    let pid = libc::id_t::from(child.id());
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // WNOWAIT leaves the child unreaped, so its pid cannot be reused
        // before the caller kills or reaps it through `Child`.
        let outcome = loop {
            // SAFETY: an all-zero siginfo_t is a valid value to fill in.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // SAFETY: `info` is a valid, writable siginfo_t for the call.
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid,
                    &raw mut info,
                    libc::WEXITED | libc::WNOWAIT,
                )
            };
            if result == 0 {
                break Ok(());
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                break Err(error);
            }
        };
        if sender.send(outcome).is_err() {
            // The caller passed its deadline and no longer listens.
        }
    });
    // A deadline already passed waits for nothing.
    let remaining = deadline.saturating_duration_since(Instant::now());
    match receiver.recv_timeout(remaining) {
        Ok(Ok(())) => child.wait().map(Some),
        Ok(Err(error)) => Err(error),
        Err(_) => Ok(None),
    }
}

/// Waits for `child` until `deadline`, polling where no exit notification is
/// available; `None` leaves it running.
#[cfg(not(unix))]
pub(crate) fn wait_until(
    child: &mut Child,
    deadline: Instant,
) -> std::io::Result<Option<ExitStatus>> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

/// Turns a failed child into the tool's failure.
pub(crate) fn require(status: ExitStatus) -> Result<(), Failure> {
    if status.success() {
        Ok(())
    } else {
        Err(Failure::of(status))
    }
}

/// A refusal and the exit code it ends the tool with.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Failure {
    pub(crate) code: u8,
    /// Printed to stderr unless empty: a failed child already reported itself.
    pub(crate) message: String,
}

impl Failure {
    /// Ends the tool the way a shell propagates a failed child: its exit code,
    /// or 128 plus the terminating signal.
    pub(crate) fn of(status: ExitStatus) -> Self {
        #[cfg(unix)]
        let signal = std::os::unix::process::ExitStatusExt::signal(&status);
        #[cfg(not(unix))]
        let signal: Option<i32> = None;
        let code = status
            .code()
            .or_else(|| signal.map(|signal| 128 + signal))
            .and_then(|code| u8::try_from(code).ok())
            .filter(|&code| code != 0)
            .unwrap_or(1);
        Self {
            code,
            message: String::new(),
        }
    }
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self { code: 1, message }
    }
}

impl From<&str> for Failure {
    fn from(message: &str) -> Self {
        message.to_owned().into()
    }
}
