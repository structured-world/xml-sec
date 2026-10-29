//! Repository tooling: one subcommand per responsibility.

mod ci_blocks;
mod kernel_examples;
mod repo;
#[cfg(test)]
mod test_support;

use std::process::ExitCode;

const USAGE: &str = "usage: xml-sec-tools COMMAND [ARGS...]
commands:
  ci-blocks BLOCK
  kernel-examples roxmltree|xmloxide ROOT SOURCE...";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let result = match args.next().as_deref() {
        Some("ci-blocks") => ci_blocks::run(args),
        Some("kernel-examples") => kernel_examples::run(args),
        _ => Err(USAGE.into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}
