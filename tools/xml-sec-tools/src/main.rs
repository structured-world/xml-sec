//! Repository tooling: one subcommand per responsibility.

mod check_features;
mod ci_blocks;
mod coverage;
mod hardening;
mod kernel_examples;
mod pkcs11;
mod repo;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod workflow_contracts;

use repo::Failure;
use std::process::ExitCode;

const USAGE: &str = "usage: xml-sec-tools COMMAND [ARGS...]
commands:
  check-features PROFILE [all|lint|test|doc]
  ci-blocks BLOCK
  hardening [all|dependencies|safety|coverage] [EVIDENCE_DIR]
  kernel-examples roxmltree|xmloxide ROOT SOURCE...
  pkcs11-tests MODULE [--workspace] ARGS...";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let result: Result<(), Failure> = match args.next().as_deref() {
        Some("check-features") => check_features::run(args),
        Some("ci-blocks") => ci_blocks::run(args).map_err(Failure::from),
        Some("hardening") => hardening::run(args),
        Some("kernel-examples") => kernel_examples::run(args).map_err(Failure::from),
        Some("pkcs11-tests") => pkcs11::run(args),
        _ => Err(Failure {
            code: 2,
            message: USAGE.into(),
        }),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            if !failure.message.is_empty() {
                eprintln!("{}", failure.message);
            }
            ExitCode::from(failure.code)
        }
    }
}
