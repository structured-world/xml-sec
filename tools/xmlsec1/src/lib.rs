//! Native command-line compatibility surface for libxmlsec1 automation.

mod args;
mod capabilities;
mod commands;
mod key_material;

use std::{ffi::OsString, io::Write, process::ExitCode};

pub use args::{Command, Invocation, OptionValue, ParseError};

/// Parse and execute one `xmlsec1` process invocation.
pub fn run(
    args: impl IntoIterator<Item = OsString>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let invocation = match Invocation::parse(args) {
        Ok(invocation) => invocation,
        Err(error) => {
            let _ = writeln!(stderr, "Error: {error}");
            return ExitCode::FAILURE;
        }
    };
    match commands::execute(invocation, stdout, stderr) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(stderr, "Error: {error}");
            ExitCode::FAILURE
        }
    }
}
