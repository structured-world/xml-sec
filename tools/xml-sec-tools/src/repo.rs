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

/// Runs `step` from the repository root with inherited output.
pub(crate) fn spawn(step: &Step) -> Result<ExitStatus, String> {
    Command::new(&step.program)
        .args(&step.args)
        .current_dir(root())
        .status()
        .map_err(|error| format!("{}: {error}", step.label))
}
