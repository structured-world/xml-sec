//! Repository tooling: one subcommand per responsibility.

mod kernel_examples;

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let result = match args.next().as_deref() {
        Some("kernel-examples") => kernel_examples::run(args),
        _ => Err("usage: xml-sec-tools kernel-examples roxmltree|xmloxide ROOT SOURCE...".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}
