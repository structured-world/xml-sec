//! `fuzz-security TARGET|asan [smoke|campaign|replay] [--cache-managed]`:
//! one fuzz target, or every ordinary `ASan` target sharing one compilation,
//! with seeds, evidence and crash artifacts kept per target.

use crate::repo::{Failure, Step, require};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

#[cfg(test)]
mod tests;

/// The ordinary targets of the shared `ASan` block.
pub(crate) const ASAN: [&str; 8] = [
    "xmldsig_verify",
    "xml_semantics",
    "security_roundtrip",
    "transform_parameters",
    "xslt_execution",
    "key_formats",
    "policy_compilation",
    "provider_operations",
];

/// How a campaign runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Replays the whole evolving corpus, then admits new mutations. An
    /// optimized build with debug assertions keeps overflow checks while
    /// replaying far faster than a development build.
    Smoke,
    Campaign,
    Replay,
}

impl Mode {
    fn parse(mode: &str) -> Option<Self> {
        Some(match mode {
            "smoke" => Self::Smoke,
            "campaign" => Self::Campaign,
            "replay" => Self::Replay,
            _ => return None,
        })
    }

    fn build(self) -> &'static [&'static str] {
        match self {
            Self::Smoke => &["--debug-assertions"],
            Self::Campaign => &["--codegen-units", "16"],
            Self::Replay => &["--dev"],
        }
    }

    /// libFuzzer arguments; `corpus` counts the retained inputs. Seed execution
    /// counts toward `-runs`, so smoke reserves its mutations beyond every
    /// retained input and the initial empty input.
    fn arguments(self, corpus: usize) -> String {
        match self {
            Self::Smoke => format!("-runs={}", corpus + 257),
            Self::Campaign => "-max_total_time=600".into(),
            Self::Replay => "-runs=0".into(),
        }
    }
}

/// The parsed invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Request {
    pub(crate) selection: String,
    pub(crate) mode: Mode,
    /// CI saves dependencies before its post action cleans, so the run leaves
    /// successful build output in place.
    pub(crate) cache_managed: bool,
    /// The real FIPS module disables its integrity checks under `ASan`, so a
    /// FIPS campaign runs without a sanitizer.
    pub(crate) fips: bool,
    pub(crate) output: Option<PathBuf>,
}

fn usage(message: String) -> Failure {
    Failure { code: 2, message }
}

pub(crate) fn parse(
    args: &[String],
    fips: bool,
    output: Option<PathBuf>,
) -> Result<Request, Failure> {
    let selection = args.first().ok_or_else(|| {
        usage("usage: fuzz-security TARGET|asan [smoke|campaign|replay] [--cache-managed]".into())
    })?;
    let mode = args.get(1).map_or("smoke", String::as_str);
    let mode = Mode::parse(mode).ok_or_else(|| usage(format!("Unknown fuzz mode: {mode}")))?;
    let cache_managed = match args.get(2).map(String::as_str) {
        None | Some("") => false,
        Some("--cache-managed") => true,
        Some(option) => return Err(usage(format!("Unknown cleanup option: {option}"))),
    };
    Ok(Request {
        selection: selection.clone(),
        mode,
        cache_managed,
        fips,
        output,
    })
}

impl Request {
    fn targets(&self) -> Vec<&str> {
        if self.selection == "asan" {
            ASAN.to_vec()
        } else {
            vec![self.selection.as_str()]
        }
    }

    /// The `cargo fuzz run` arguments for `target`.
    pub(crate) fn run_args(
        &self,
        target: &str,
        corpus: &Path,
        corpus_size: usize,
        crashes: &Path,
    ) -> Vec<String> {
        let mut args: Vec<String> = ["+nightly", "fuzz", "run", target]
            .map(String::from)
            .to_vec();
        args.extend(self.mode.build().iter().map(|&arg| arg.to_owned()));
        if self.fips {
            args.extend(["--features".into(), "aws-lc-fips".into()]);
        }
        let sanitizer = if self.fips { "none" } else { "address" };
        args.extend([
            "--sanitizer".into(),
            sanitizer.into(),
            corpus.display().to_string(),
            "--".into(),
            self.mode.arguments(corpus_size),
            "-max_len=65536".into(),
            "-timeout=30".into(),
            "-rss_limit_mb=2048".into(),
            format!("-artifact_prefix={}/", crashes.display()),
        ]);
        args
    }
}

/// The seed sources `seeds.tsv` (`target\tsource` lines, `#` comments)
/// selects for `target`, as listed; a line without a source names none.
pub(crate) fn seeds<'a>(listing: &'a str, target: &str) -> Vec<&'a str> {
    listing
        .lines()
        .map(|line| line.split_once('\t').unwrap_or((line, "")))
        .filter(|(selected, _)| !selected.starts_with('#') && *selected == target)
        .map(|(_, source)| source)
        .collect()
}

/// Quotes `arg` for a POSIX shell when it holds anything but plain characters.
pub(crate) fn shell_quote(arg: &str) -> String {
    let plain = !arg.is_empty()
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-./=+:,@%".contains(c));
    if plain {
        arg.to_owned()
    } else {
        format!("'{}'", arg.replace('\'', r"'\''"))
    }
}

/// The processes a run starts; tests substitute a recorder.
pub(crate) trait Fuzzer {
    /// Runs from `root` with inherited output.
    fn status(&mut self, root: &Path, step: &Step) -> Result<ExitStatus, String>;
    /// Runs from `root` and returns stdout.
    fn stdout(&mut self, root: &Path, step: &Step) -> Result<(ExitStatus, Vec<u8>), String>;
    /// Runs from `root`, copying stdout and stderr to the terminal and `log`.
    fn tee(&mut self, root: &Path, step: &Step, log: &Path) -> Result<ExitStatus, String>;
}

struct Host;

fn spawned(root: &Path, step: &Step) -> Command {
    let mut command = Command::new(&step.program);
    command.args(&step.args).current_dir(root);
    command
}

impl Fuzzer for Host {
    fn status(&mut self, root: &Path, step: &Step) -> Result<ExitStatus, String> {
        spawned(root, step)
            .status()
            .map_err(|error| format!("{}: {error}", step.label))
    }

    fn stdout(&mut self, root: &Path, step: &Step) -> Result<(ExitStatus, Vec<u8>), String> {
        let output = spawned(root, step)
            .stderr(Stdio::inherit())
            .output()
            .map_err(|error| format!("{}: {error}", step.label))?;
        Ok((output.status, output.stdout))
    }

    fn tee(&mut self, root: &Path, step: &Step, log: &Path) -> Result<ExitStatus, String> {
        let fail = |error: std::io::Error| format!("{}: {error}", step.label);
        let mut file = std::fs::File::create(log).map_err(fail)?;
        let (mut reader, writer) = std::io::pipe().map_err(fail)?;
        let duplicate = writer.try_clone().map_err(fail)?;
        let mut child = spawned(root, step)
            .stdout(writer)
            .stderr(duplicate)
            .spawn()
            .map_err(fail)?;
        let mut terminal = std::io::stdout();
        let mut buffer = [0; 8192];
        loop {
            let read = reader.read(&mut buffer).map_err(fail)?;
            if read == 0 {
                break;
            }
            terminal.write_all(&buffer[..read]).map_err(fail)?;
            file.write_all(&buffer[..read]).map_err(fail)?;
        }
        child.wait().map_err(fail)
    }
}

fn io(path: &Path) -> impl Fn(std::io::Error) -> String + '_ {
    move |error| format!("{}: {error}", path.display())
}

fn count_files(directory: &Path) -> Result<usize, String> {
    let mut count = 0;
    for entry in std::fs::read_dir(directory).map_err(io(directory))? {
        let entry = entry.map_err(io(directory))?;
        let kind = entry.file_type().map_err(io(directory))?;
        if kind.is_dir() {
            count += count_files(&entry.path())?;
        } else if kind.is_file() {
            count += 1;
        }
    }
    Ok(count)
}

/// Records `step`'s stdout as an evidence file.
fn record(fuzzer: &mut impl Fuzzer, root: &Path, step: &Step, path: &Path) -> Result<(), Failure> {
    let (status, output) = fuzzer.stdout(root, step)?;
    require(status)?;
    std::fs::write(path, output).map_err(io(path))?;
    Ok(())
}

fn keep_lock(root: &Path, output: &Path) -> Result<(), String> {
    let lock = root.join("fuzz/Cargo.lock");
    if lock.is_file() {
        std::fs::copy(&lock, output.join("Cargo.lock")).map_err(io(&lock))?;
    }
    Ok(())
}

/// Runs every target of `request`; the first failure stops the block.
fn targets(
    request: &Request,
    root: &Path,
    fuzzer: &mut impl Fuzzer,
    output: &mut PathBuf,
) -> Result<(), Failure> {
    let base = request
        .output
        .clone()
        .unwrap_or_else(|| root.join("fuzz/evidence").join(&request.selection));
    output.clone_from(&base);
    for target in request.targets() {
        let corpus = root.join("fuzz/corpus").join(target);
        *output = if request.selection == "asan" {
            base.join(target)
        } else {
            base.clone()
        };
        let crashes = root.join("fuzz/artifacts").join(target);
        for directory in [&corpus, &*output, &crashes] {
            std::fs::create_dir_all(directory).map_err(io(directory))?;
        }
        // Selection metadata, not a recursive import of every third-party
        // fixture; sources keep their repository provenance and notices.
        let listing = root.join("fuzz/seeds.tsv");
        let listing = std::fs::read_to_string(&listing).map_err(io(&listing))?;
        for source in seeds(&listing, target) {
            let path = root.join(source);
            if !path.is_file() {
                return Err(usage(format!("Missing seed: {source}")));
            }
            let bytes = std::fs::read(&path).map_err(io(&path))?;
            let seed = corpus.join(format!("seed-{}", crate::security_corpus::sha256(&bytes)));
            std::fs::write(&seed, bytes).map_err(io(&seed))?;
        }
        let corpus_size = if request.mode == Mode::Smoke {
            count_files(&corpus)?
        } else {
            0
        };
        record(
            fuzzer,
            root,
            &Step::new("revision", "git", &["rev-parse", "HEAD"]),
            &output.join("revision.txt"),
        )?;
        record(
            fuzzer,
            root,
            &Step::new(
                "worktree",
                "git",
                &["status", "--short", "--untracked-files=normal"],
            ),
            &output.join("worktree.txt"),
        )?;
        record(
            fuzzer,
            root,
            &Step::new("toolchain", "rustc", &["+nightly", "-Vv"]),
            &output.join("toolchain.txt"),
        )?;
        let args = request.run_args(target, &corpus, corpus_size, &crashes);
        let mut command = String::from("cargo ");
        for arg in &args {
            command.push_str(&shell_quote(arg));
            command.push(' ');
        }
        command.push('\n');
        let path = output.join("command.txt");
        std::fs::write(&path, command).map_err(io(&path))?;
        let mut run = Step::new(target, "cargo", &[]);
        run.args = args;
        // Crashes and timeouts keep their status; failed runs retain artifacts
        // and build output for diagnosis.
        require(fuzzer.tee(root, &run, &output.join("run.log"))?)?;
        keep_lock(root, output)?;
    }
    Ok(())
}

/// Runs `request` from `root`.
pub(crate) fn execute(
    request: &Request,
    root: &Path,
    fuzzer: &mut impl Fuzzer,
) -> Result<(), Failure> {
    let list = Step::new("fuzz list", "cargo", &["+nightly", "fuzz", "list"]);
    let (status, listed) = fuzzer.stdout(root, &list)?;
    require(status)?;
    let listed = String::from_utf8_lossy(&listed);
    for target in request.targets() {
        if !listed.lines().any(|line| line == target) {
            return Err(usage(format!("Unknown fuzz target: {target}")));
        }
    }
    let mut output = PathBuf::new();
    let result = targets(request, root, fuzzer, &mut output);
    // Evidence keeps the resolved lock whatever the outcome; only a complete
    // successful block may clean, so a failure retains its build.
    let kept = keep_lock(root, &output).map_err(Failure::from);
    let result = result.and(kept);
    if result.is_ok() && !request.cache_managed {
        let clean = Step::new(
            "clean",
            "cargo",
            &["+nightly", "clean", "--manifest-path", "fuzz/Cargo.toml"],
        );
        require(fuzzer.status(root, &clean)?)?;
    }
    result
}

pub(crate) fn run(args: impl Iterator<Item = String>) -> Result<(), Failure> {
    let args: Vec<String> = args.collect();
    let request = parse(
        &args,
        std::env::var("FUZZ_AWS_LC_FIPS").is_ok_and(|value| value == "1"),
        std::env::var_os("FUZZ_OUTPUT").map(PathBuf::from),
    )?;
    execute(&request, &crate::repo::root(), &mut Host)
}
