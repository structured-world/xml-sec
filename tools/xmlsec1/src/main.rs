mod args;
mod capabilities;
mod commands;
mod key_material;
mod policy_commands;
mod utc_facts;

use std::{ffi::OsString, io::Write, process::ExitCode};

pub use args::{Command, Invocation, OptionValue, ParseError};

/// Report `error` and fail. A diagnostic that cannot reach stderr leaves no
/// other channel, so the process outcome is failure either way.
fn failure(stderr: &mut dyn Write, error: &dyn std::fmt::Display) -> ExitCode {
    match writeln!(stderr, "Error: {error}") {
        Ok(()) | Err(_) => ExitCode::FAILURE,
    }
}

fn run(
    args: impl IntoIterator<Item = OsString>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let mut args = args.into_iter();
    let program = args.next();
    let command = args.next();
    if command.as_deref() == Some(std::ffi::OsStr::new("policy")) {
        return match policy_commands::execute(args, stdout)
            .and_then(|()| stdout.flush().map_err(|e| e.to_string()))
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => failure(stderr, &error),
        };
    }
    let invocation = match args::Invocation::parse(program.into_iter().chain(command).chain(args)) {
        Ok(invocation) => invocation,
        Err(error) => return failure(stderr, &error),
    };
    match commands::execute(&invocation, stdout, stderr) {
        Ok(()) => match stdout.flush() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => failure(stderr, &error),
        },
        Err(error) => failure(stderr, &error),
    }
}

fn main() -> ExitCode {
    run(
        std::env::args_os(),
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    )
}

#[cfg(test)]
mod tests;
