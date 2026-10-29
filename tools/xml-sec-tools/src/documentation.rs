//! `documentation [all|docs]`: qualifies the published core contract and
//! executes the examples users actually read.

use crate::repo::{Failure, Run, Step, System, require};
use std::path::Path;

#[cfg(test)]
mod tests;

const PUBLIC_KEY: &str = "tests/fixtures/keys/rsa/rsa-2048-pubkey.pem";
const TARGET: &str = "invoice-2026-07";
/// The verification example's refusal of tampered content. A compiler or
/// setup error is not proof of a cryptographic rejection.
pub(crate) const REJECTION: &str = "expected target was not authenticated";

/// One step of the qualification; file names are inside a disposable store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Action {
    Run(Step),
    /// A process whose stdout becomes the named file.
    Capture(Step, &'static str),
    /// Changes the signed amount of `from` into `to`.
    Tamper(&'static str, &'static str),
    /// A process that must fail with the given diagnostic.
    Refused(Step, &'static str),
}

fn example(name: &str, args: &[&str]) -> Step {
    let mut all = vec!["run", "--quiet", "-p", "xml-sec", "--example", name];
    if !args.is_empty() {
        all.push("--");
        all.extend(args);
    }
    Step::new(name, "cargo", &all)
}

/// Plans `phase`; `store` holds example output and `rustdocflags` is the
/// caller's own `RUSTDOCFLAGS`.
pub(crate) fn plan(phase: &str, store: &Path, rustdocflags: &str) -> Result<Vec<Action>, Failure> {
    if !matches!(phase, "all" | "docs") {
        return Err(Failure {
            code: 2,
            message: format!("unknown documentation phase: {phase}"),
        });
    }
    let doc = Step::new(
        "docs",
        "cargo",
        &[
            "doc",
            "-p",
            "xml-sec",
            "-p",
            "xml-sec-config",
            "--all-features",
            "--no-deps",
        ],
    )
    .with_env(
        "RUSTDOCFLAGS",
        format!("{rustdocflags} -D warnings -D missing-docs"),
    );
    let mut actions = vec![Action::Run(doc)];
    if phase == "docs" {
        return Ok(actions);
    }
    let file = |name: &str| store.join(name).display().to_string();
    let (signed, tampered) = (file("signed.xml"), file("tampered.xml"));
    actions.extend([
        Action::Run(Step::new(
            "doctests",
            "cargo",
            &["test", "--doc", "--workspace", "--all-features"],
        )),
        Action::Run(Step::new(
            "configuration documentation",
            "cargo",
            &[
                "nextest",
                "run",
                "-p",
                "xml-sec-config",
                "--test",
                "documentation",
            ],
        )),
        Action::Run(example("policy_roundtrip", &[])),
        Action::Capture(example("sign", &[]), "signed.xml"),
        Action::Run(example("verify", &[&signed, PUBLIC_KEY, TARGET])),
        Action::Tamper("signed.xml", "tampered.xml"),
        Action::Refused(
            example("verify", &[&tampered, PUBLIC_KEY, TARGET]),
            REJECTION,
        ),
        Action::Capture(example("encrypt", &[]), "encrypted.xml"),
        Action::Run(Step::new(
            "policy check",
            "cargo",
            &[
                "run",
                "--quiet",
                "-p",
                "xml-sec-cli",
                "--bin",
                "xmlsec1",
                "--",
                "policy",
                "check",
                "--file",
                "docs/examples/policy-v1.toml",
                "--profile",
                "tenant",
                "--target-evidence",
            ],
        )),
    ]);
    Ok(actions)
}

/// Raises the signed invoice amount: the first `42.00` of each line.
pub(crate) fn tamper(signed: &str) -> Result<String, String> {
    let tampered: String = signed
        .split_inclusive('\n')
        .map(|line| line.replacen("42.00", "99.00", 1))
        .collect();
    if tampered.contains("99.00") {
        Ok(tampered)
    } else {
        Err("the signed example contains no amount to tamper with".into())
    }
}

fn store_error(name: &str, error: &std::io::Error) -> String {
    format!("{name}: {error}")
}

/// Executes `actions` in order; the first failure stops qualification.
pub(crate) fn execute(
    actions: &[Action],
    store: &Path,
    runner: &mut impl Run,
) -> Result<(), Failure> {
    for action in actions {
        match action {
            Action::Run(step) => require(runner.status(step)?)?,
            Action::Capture(step, name) => {
                let (status, output) = runner.stdout(step)?;
                require(status)?;
                std::fs::write(store.join(name), output)
                    .map_err(|error| store_error(name, &error))?;
            }
            Action::Tamper(from, to) => {
                let signed = std::fs::read_to_string(store.join(from))
                    .map_err(|error| store_error(from, &error))?;
                std::fs::write(store.join(to), tamper(&signed)?)
                    .map_err(|error| store_error(to, &error))?;
            }
            Action::Refused(step, expected) => {
                let (status, output) = runner.combined(step)?;
                if status.success() {
                    return Err("verification example accepted tampered signed content".into());
                }
                if !output.contains(expected) {
                    return Err(
                        format!("{}: refused without `{expected}`:\n{output}", step.label).into(),
                    );
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn run(mut args: impl Iterator<Item = String>) -> Result<(), Failure> {
    let phase = args.next().unwrap_or_else(|| "all".into());
    // Removed when dropped, on success and on failure alike.
    let store = tempfile::Builder::new()
        .prefix("xml-sec-doc-examples.")
        .tempdir()
        .map_err(|error| format!("create example store: {error}"))?;
    let rustdocflags = std::env::var("RUSTDOCFLAGS").unwrap_or_default();
    let actions = plan(&phase, store.path(), &rustdocflags)?;
    execute(&actions, store.path(), &mut System)
}
