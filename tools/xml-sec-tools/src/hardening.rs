//! `hardening [all|dependencies|safety|coverage] [EVIDENCE_DIR]`: dependency
//! policy, native safety and canonical line coverage. Coverage evidence is
//! kept outside build output.

use crate::repo::{Failure, Step, command};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};

#[cfg(test)]
mod tests;

/// Directories through which one physical source is compiled both embedded
/// and standalone.
const SOURCE_ALIASES: [&str; 4] = [
    "crates/xml-sec-xslt/../..",
    "vendor/sxd-document-no-unsafe/../..",
    "vendor/sxd-xpath-no-unsafe/../..",
    "crates/xml-sec-xml-input/src/../../..",
];

/// One step of the qualification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Action {
    /// A process that must succeed.
    Run(Step),
    /// Creates the evidence directory, which must be new; later steps see the
    /// remapped compiler flags.
    CreateEvidence,
    /// A process whose `KEY=value` stdout extends the environment of later steps.
    ShowEnv(Step),
    /// The token-backed workspace tests under the instrumented build.
    TokenTests(Vec<String>),
    /// Validates the JSON coverage report.
    CheckReport,
    /// A process whose stdout becomes the named evidence file.
    Record(Step, &'static str),
}

/// Inputs of a coverage run that the caller must state explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Coverage {
    pub(crate) evidence: PathBuf,
    pub(crate) module: String,
    /// `CARGO_ENCODED_RUSTFLAGS` for the instrumented build.
    pub(crate) flags: String,
}

/// Compiler flags with every source alias remapped to the physical root.
/// Remapping before instrumentation makes LLVM merge the executions instead
/// of a postprocessor choosing the better of two percentages.
pub(crate) fn remapped_flags(encoded: Option<&str>, plain: Option<&str>, root: &Path) -> String {
    let mut flags: Vec<String> = match (encoded, plain) {
        (Some(encoded), _) if !encoded.is_empty() => vec![encoded.to_owned()],
        (_, Some(plain)) => plain.split_whitespace().map(String::from).collect(),
        _ => Vec::new(),
    };
    let root = root.display();
    flags.extend(
        SOURCE_ALIASES
            .iter()
            .map(|alias| format!("--remap-path-prefix={root}/{alias}={root}")),
    );
    flags.join("\x1f")
}

fn cargo(label: &str, args: &[&str]) -> Step {
    Step::new(label, "cargo", args)
}

/// Plans `phase`; `coverage` is required exactly when the phase includes it.
pub(crate) fn plan(phase: &str, coverage: Option<&Coverage>) -> Result<Vec<Action>, Failure> {
    let (dependencies, safety, measure) = match phase {
        "all" => (true, true, true),
        "dependencies" => (true, false, false),
        "safety" => (false, true, false),
        "coverage" => (false, false, true),
        _ => {
            return Err(Failure {
                code: 2,
                message: format!("unknown hardening phase: {phase}"),
            });
        }
    };
    let mut actions = Vec::new();
    if dependencies {
        actions.push(Action::Run(cargo(
            "deny",
            &[
                "deny",
                "--all-features",
                "check",
                "--config",
                "deny.toml",
                "advisories",
                "sources",
            ],
        )));
        actions.push(Action::Run(cargo(
            "deny fuzz",
            &[
                "deny",
                "--manifest-path",
                "fuzz/Cargo.toml",
                "--all-features",
                "check",
                "--config",
                "deny.toml",
                "advisories",
                "sources",
            ],
        )));
    }
    if safety {
        // Diagnostic allocator probes in tests and benches are not native library code.
        actions.push(Action::Run(cargo(
            "safety",
            &[
                "clippy",
                "--workspace",
                "--lib",
                "--all-features",
                "--",
                "-D",
                "warnings",
                "-D",
                "unsafe_code",
            ],
        )));
    }
    if measure {
        let coverage = coverage
            .ok_or("pass a new coverage evidence directory outside target and PKCS11_MODULE")?;
        actions.extend(coverage_actions(coverage));
    }
    Ok(actions)
}

fn coverage_actions(coverage: &Coverage) -> [Action; 10] {
    let evidence = |name: &str| coverage.evidence.join(name).display().to_string();
    let json = evidence("coverage.json");
    let lcov = evidence("coverage.lcov");
    [
        Action::CreateEvidence,
        // Keep first-install rustup output separate from the environment listing.
        Action::Run(Step::new(
            "llvm tools",
            "rustup",
            &["component", "add", "llvm-tools-preview"],
        )),
        Action::Run(cargo(
            "coverage clean",
            &["llvm-cov", "clean", "--workspace"],
        )),
        Action::ShowEnv(cargo("coverage environment", &["llvm-cov", "show-env"])),
        Action::TokenTests(vec!["--workspace".into(), "--all-features".into()]),
        // The report consumes the completed instrumented build. Every package
        // is selected explicitly: the default covers only the root package.
        Action::Run(cargo(
            "coverage report",
            &[
                "llvm-cov",
                "report",
                "--package",
                "*",
                "--fail-under-lines",
                "85",
                "--json",
                "--summary-only",
                "--output-path",
                &json,
            ],
        )),
        Action::CheckReport,
        Action::Run(cargo(
            "coverage lcov",
            &[
                "llvm-cov",
                "report",
                "--package",
                "*",
                "--lcov",
                "--output-path",
                &lcov,
            ],
        )),
        Action::Record(
            Step::new("revision", "git", &["rev-parse", "HEAD"]),
            "revision.txt",
        ),
        Action::Record(Step::new("toolchain", "rustc", &["-Vv"]), "toolchain.txt"),
    ]
}

/// Parses `KEY=value` lines whose values use POSIX shell quoting.
pub(crate) fn parse_env(listing: &str) -> Result<Vec<(String, String)>, String> {
    let mut env = Vec::new();
    for line in listing.lines().filter(|line| !line.is_empty()) {
        let (key, quoted) = line
            .split_once('=')
            .ok_or_else(|| format!("unexpected environment line: {line}"))?;
        let mut value = String::new();
        let mut chars = quoted.chars();
        while let Some(c) = chars.next() {
            match c {
                '\'' => loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(c) => value.push(c),
                        None => return Err(format!("unterminated quote: {line}")),
                    }
                },
                '\\' => value.push(
                    chars
                        .next()
                        .ok_or_else(|| format!("dangling escape: {line}"))?,
                ),
                '"' | '$' | '`' => return Err(format!("unsupported shell syntax: {line}")),
                c => value.push(c),
            }
        }
        env.push((key.to_owned(), value));
    }
    Ok(env)
}

/// How the actions reach processes and files; tests substitute a recorder.
pub(crate) trait Runner {
    fn status(&mut self, step: &Step, env: &[(String, String)]) -> Result<ExitStatus, String>;
    fn stdout(
        &mut self,
        step: &Step,
        env: &[(String, String)],
    ) -> Result<(ExitStatus, String), String>;
    fn token_tests(
        &mut self,
        module: &str,
        args: &[String],
        env: &[(String, String)],
    ) -> Result<(), Failure>;
    fn create_dir(&mut self, path: &Path) -> Result<(), String>;
    fn check_report(&mut self, path: &Path) -> Result<Value, String>;
    fn write(&mut self, path: &Path, text: &str) -> Result<(), String>;
}

struct Processes;

impl Runner for Processes {
    fn status(&mut self, step: &Step, env: &[(String, String)]) -> Result<ExitStatus, String> {
        command(step)?
            .envs(env.iter().map(|(key, value)| (key, value)))
            .status()
            .map_err(|error| format!("{}: {error}", step.label))
    }

    fn stdout(
        &mut self,
        step: &Step,
        env: &[(String, String)],
    ) -> Result<(ExitStatus, String), String> {
        let output = command(step)?
            .envs(env.iter().map(|(key, value)| (key, value)))
            .stderr(Stdio::inherit())
            .output()
            .map_err(|error| format!("{}: {error}", step.label))?;
        Ok((
            output.status,
            String::from_utf8_lossy(&output.stdout).into_owned(),
        ))
    }

    fn token_tests(
        &mut self,
        module: &str,
        args: &[String],
        env: &[(String, String)],
    ) -> Result<(), Failure> {
        crate::pkcs11::run_tests(module, args, env)
    }

    fn create_dir(&mut self, path: &Path) -> Result<(), String> {
        std::fs::create_dir(path).map_err(|error| format!("create {}: {error}", path.display()))
    }

    fn check_report(&mut self, path: &Path) -> Result<Value, String> {
        crate::coverage::check_file(path)
    }

    fn write(&mut self, path: &Path, text: &str) -> Result<(), String> {
        std::fs::write(path, text).map_err(|error| format!("write {}: {error}", path.display()))
    }
}

fn require(status: ExitStatus) -> Result<(), Failure> {
    if status.success() {
        Ok(())
    } else {
        Err(Failure::of(status))
    }
}

/// Executes `actions` in order; the first failure stops qualification.
pub(crate) fn execute(
    actions: &[Action],
    coverage: Option<&Coverage>,
    runner: &mut impl Runner,
) -> Result<(), Failure> {
    let mut env: Vec<(String, String)> = Vec::new();
    for action in actions {
        let measured = || coverage.ok_or_else(|| Failure::from("coverage inputs are missing"));
        match action {
            Action::Run(step) => require(runner.status(step, &env)?)?,
            Action::CreateEvidence => {
                let coverage = measured()?;
                runner.create_dir(&coverage.evidence)?;
                env.push(("CARGO_ENCODED_RUSTFLAGS".into(), coverage.flags.clone()));
            }
            Action::ShowEnv(step) => {
                let (status, listing) = runner.stdout(step, &env)?;
                require(status)?;
                env.extend(parse_env(&listing)?);
            }
            Action::TokenTests(args) => runner.token_tests(&measured()?.module, args, &env)?,
            Action::CheckReport => {
                let summary = runner.check_report(&measured()?.evidence.join("coverage.json"))?;
                println!("{summary}");
            }
            Action::Record(step, name) => {
                let (status, text) = runner.stdout(step, &env)?;
                require(status)?;
                runner.write(&measured()?.evidence.join(name), &text)?;
            }
        }
    }
    Ok(())
}

pub(crate) fn run(mut args: impl Iterator<Item = String>) -> Result<(), Failure> {
    let phase = args.next().unwrap_or_else(|| "all".into());
    let coverage = match (args.next(), std::env::var("PKCS11_MODULE")) {
        (Some(evidence), Ok(module)) if !module.is_empty() => {
            let root = std::fs::canonicalize(crate::repo::root())
                .map_err(|error| format!("resolve the repository root: {error}"))?;
            Some(Coverage {
                // Steps run from the repository root; the caller named it from here.
                evidence: std::path::absolute(&evidence)
                    .map_err(|error| format!("resolve {evidence}: {error}"))?,
                module,
                flags: remapped_flags(
                    std::env::var("CARGO_ENCODED_RUSTFLAGS").ok().as_deref(),
                    std::env::var("RUSTFLAGS").ok().as_deref(),
                    &root,
                ),
            })
        }
        _ => None,
    };
    let actions = plan(&phase, coverage.as_ref())?;
    execute(&actions, coverage.as_ref(), &mut Processes)
}
