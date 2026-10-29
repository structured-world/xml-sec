//! Locations and process helpers shared by the subcommands.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

/// The repository root, independent of the directory the tool runs from.
pub(crate) fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the tool crate lives two levels below the repository root")
        .to_path_buf()
}

/// One planned process: a label for logs, the program and its arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Step {
    pub(crate) label: String,
    pub(crate) program: String,
    pub(crate) args: Vec<String>,
}

impl Step {
    pub(crate) fn new(label: impl Into<String>, program: &str, args: &[&str]) -> Self {
        Self {
            label: label.into(),
            program: program.into(),
            args: args.iter().map(|&arg| arg.to_owned()).collect(),
        }
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
    command.args(&step.args).current_dir(root());
    Ok(command)
}

/// Runs `step` from the repository root with inherited output.
pub(crate) fn spawn(step: &Step) -> Result<ExitStatus, String> {
    command(step)?
        .status()
        .map_err(|error| format!("{}: {error}", step.label))
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
