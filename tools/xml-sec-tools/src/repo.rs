//! Locations and process helpers shared by the subcommands.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

/// The repository root, independent of the directory the tool runs from.
pub(crate) fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the tool crate lives two levels below the repository root")
        .to_path_buf()
}

/// One planned process: a label for logs, the program, its arguments, the
/// environment it adds and the inherited variables it removes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Step {
    pub(crate) label: String,
    pub(crate) program: String,
    pub(crate) args: Vec<String>,
    pub(crate) env: Vec<(String, String)>,
    pub(crate) unset: Vec<String>,
}

impl Step {
    pub(crate) fn new(label: impl Into<String>, program: &str, args: &[&str]) -> Self {
        Self {
            label: label.into(),
            program: program.into(),
            args: args.iter().map(|&arg| arg.to_owned()).collect(),
            env: Vec::new(),
            unset: Vec::new(),
        }
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

/// The process for `step`, from the repository root.
pub(crate) fn command(step: &Step) -> Result<Command, String> {
    let program = if step.program == TOOL {
        std::env::current_exe().map_err(|error| format!("{}: {error}", step.label))?
    } else {
        PathBuf::from(&step.program)
    };
    let mut command = Command::new(program);
    command
        .args(&step.args)
        .envs(step.env.iter().map(|(key, value)| (key, value)))
        .current_dir(root());
    for key in &step.unset {
        command.env_remove(key);
    }
    Ok(command)
}

/// Runs `step` from the repository root with inherited output.
pub(crate) fn spawn(step: &Step) -> Result<ExitStatus, String> {
    command(step)?
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
        let output = command(step)?
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
        let mut child = command(step)?
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
