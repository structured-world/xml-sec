//! `hardening [all|dependencies|safety|coverage|package] [DIR]`: dependency
//! policy, native safety, canonical line coverage and the packaged crate's own
//! tests. `DIR` receives the evidence or the package build and lies outside the
//! repository, because a package unpacked inside it would join its workspace.

use crate::repo::{Failure, Run, Step, System, require};
use serde_json::Value;
use std::path::{Path, PathBuf};

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
    /// Every test of the unpacked package, token-backed ones included.
    PackagedTests,
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
        "package" => {
            let inputs = coverage.ok_or("pass a package build directory and PKCS11_MODULE")?;
            let target = inputs.evidence.display().to_string();
            return Ok(vec![
                Action::Run(cargo(
                    "package",
                    &[
                        "package",
                        "-p",
                        "xml-sec",
                        "--all-features",
                        "--target-dir",
                        &target,
                    ],
                )),
                Action::PackagedTests,
            ]);
        }
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
                "licenses",
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
                "licenses",
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

/// The coverage-specific effects; tests substitute a recorder.
pub(crate) trait Runner: Run {
    fn token_tests(
        &mut self,
        module: &str,
        args: &[String],
        env: &[(String, String)],
    ) -> Result<(), Failure>;
    fn create_dir(&mut self, path: &Path) -> Result<(), String>;
    fn check_report(&mut self, path: &Path) -> Result<Value, String>;
    fn write(&mut self, path: &Path, text: &str) -> Result<(), String>;
    fn unpacked(&mut self, target: &Path) -> Result<PathBuf, String>;
}

/// The directory `cargo package` unpacked under `target`; the name holds the
/// version, and a second match means a stale build rather than this package.
pub(crate) fn unpacked_package(target: &Path) -> Result<PathBuf, String> {
    let root = target.join("package");
    let entries =
        std::fs::read_dir(&root).map_err(|error| format!("read {}: {error}", root.display()))?;
    let mut found = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|error| format!("read {}: {error}", root.display()))?
            .path();
        let named = path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with("xml-sec-"));
        if named && path.is_dir() {
            found.push(path);
        }
    }
    match found.as_slice() {
        [package] => Ok(package.clone()),
        _ => Err(format!(
            "expected one unpacked package in {}, found {}",
            root.display(),
            found.len()
        )),
    }
}

impl Runner for System {
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

    fn unpacked(&mut self, target: &Path) -> Result<PathBuf, String> {
        unpacked_package(target)
    }
}

/// `step` with the environment accumulated by earlier actions.
fn under(step: &Step, env: &[(String, String)]) -> Step {
    let mut step = step.clone();
    step.env.extend_from_slice(env);
    step
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
            Action::Run(step) => require(runner.status(&under(step, &env))?)?,
            Action::CreateEvidence => {
                let coverage = measured()?;
                runner.create_dir(&coverage.evidence)?;
                env.push(("CARGO_ENCODED_RUSTFLAGS".into(), coverage.flags.clone()));
            }
            Action::ShowEnv(step) => {
                let (status, listing) = runner.stdout(&under(step, &env))?;
                require(status)?;
                env.extend(parse_env(&listing)?);
            }
            Action::TokenTests(args) => runner.token_tests(&measured()?.module, args, &env)?,
            Action::PackagedTests => {
                let inputs = measured()?;
                let manifest = runner.unpacked(&inputs.evidence)?.join("Cargo.toml");
                let args = [
                    "--workspace".into(),
                    "--manifest-path".into(),
                    manifest.display().to_string(),
                    "--all-features".into(),
                    "--target-dir".into(),
                    inputs.evidence.display().to_string(),
                ];
                runner.token_tests(&inputs.module, &args, &env)?;
            }
            Action::CheckReport => {
                let summary = runner.check_report(&measured()?.evidence.join("coverage.json"))?;
                println!("{summary}");
            }
            Action::Record(step, name) => {
                let (status, text) = runner.stdout(&under(step, &env))?;
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
    execute(&actions, coverage.as_ref(), &mut System)
}
