//! `bench-latency OUTPUT_DIR [SAMPLES] [EXTRA_FEATURES]`: one child process
//! per security benchmark case, so RSS and CPU observations stay independent
//! of earlier cases, plus the Divan timing and allocation runs.

use crate::repo::{Failure, root};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[cfg(test)]
mod tests;

const IDENTITY_FILES: [&str; 7] = [
    "Cargo.toml",
    "benches/security.rs",
    "benches/support/mod.rs",
    "examples/benchmark_latency.rs",
    "tools/xml-sec-tools/src/bench/latency.rs",
    "src/benchmark_support.rs",
    "src/xml/dom/benchmark.rs",
];

fn usage(message: String) -> Failure {
    Failure { code: 2, message }
}

/// The parsed invocation.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Request {
    pub(crate) output: PathBuf,
    pub(crate) samples: u32,
    pub(crate) features: String,
}

pub(crate) fn parse(args: &[String]) -> Result<Request, Failure> {
    let output = args.first().ok_or_else(|| {
        usage("usage: bench-latency OUTPUT_DIR [SAMPLES] [EXTRA_FEATURES]".into())
    })?;
    let samples = args.get(1).map_or("1000", String::as_str);
    let samples = Some(samples)
        .filter(|samples| (1..=6).contains(&samples.len()))
        .and_then(|samples| super::sample_count(samples, 100_000))
        .ok_or_else(|| usage("Samples must be an integer in 1..=100000.".into()))?;
    let features = match args.get(2).filter(|extra| !extra.is_empty()) {
        Some(extra) => format!("benchmark-internals,{extra}"),
        None => "benchmark-internals".into(),
    };
    if Path::new(output).exists() {
        return Err(usage(format!("Output directory already exists: {output}")));
    }
    Ok(Request {
        output: output.into(),
        samples,
        features,
    })
}

/// Native library directories Cargo's build scripts linked, unique and sorted.
pub(crate) fn native_paths(build_messages: &str) -> String {
    let mut paths: Vec<String> = build_messages
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|message| message["reason"] == "build-script-executed")
        .flat_map(|message| {
            message["linked_paths"]
                .as_array()
                .cloned()
                .unwrap_or_default()
        })
        .filter_map(|path| path.as_str().map(str::to_owned))
        .filter(|path| path.starts_with("native=") || path.starts_with("all="))
        .filter_map(|path| path.split_once('=').map(|(_, rest)| rest.to_owned()))
        .collect();
    paths.sort();
    paths.dedup();
    paths.join(":")
}

/// The loader prefix that keeps Cargo's native search paths for a direct
/// child, especially the dynamically linked FIPS module on macOS: protected
/// `/usr/bin/time` strips `DYLD_*` from what it inherits.
pub(crate) fn loader(native: &str, platform: &str, current: Option<&str>) -> Vec<String> {
    let variable = match platform {
        "darwin" => "DYLD_LIBRARY_PATH",
        "linux" => "LD_LIBRARY_PATH",
        _ => return Vec::new(),
    };
    if native.is_empty() {
        return Vec::new();
    }
    let value = current.filter(|current| !current.is_empty()).map_or_else(
        || native.to_owned(),
        |current| format!("{native}:{current}"),
    );
    vec!["/usr/bin/env".into(), format!("{variable}={value}")]
}

fn output_of(root: &Path, program: &str, args: &[&str]) -> Result<Vec<u8>, Failure> {
    let output = Command::new(program)
        .args(args)
        .current_dir(root)
        .stderr(Stdio::inherit())
        .output()
        .map_err(|error| format!("{program}: {error}"))?;
    crate::repo::require(output.status)?;
    Ok(output.stdout)
}

fn sha_lines(root: &Path, files: &[&str]) -> Result<String, Failure> {
    let mut text = String::new();
    for file in files {
        text.push_str(&super::digest_file(&root.join(file))?);
        text.push_str("  ");
        text.push_str(file);
        text.push('\n');
    }
    Ok(text)
}

/// The revision, uncommitted source changes and the runner's own inputs.
fn source_identity(root: &Path) -> Result<Vec<u8>, Failure> {
    let mut identity = output_of(root, "git", &["rev-parse", "HEAD"])?;
    identity.extend(output_of(
        root,
        "git",
        &[
            "diff",
            "--binary",
            "HEAD",
            "--",
            "Cargo.toml",
            "src",
            "benches",
            "examples",
            "scripts",
            "tools",
        ],
    )?);
    identity.extend(sha_lines(root, &IDENTITY_FILES)?.into_bytes());
    Ok(identity)
}

fn environment(root: &Path, request: &Request) -> Result<Vec<u8>, Failure> {
    let mut text = output_of(root, "git", &["rev-parse", "HEAD"])?;
    text.extend(output_of(root, "git", &["status", "--porcelain"])?);
    text.extend(output_of(root, "git", &["diff", "--stat"])?);
    let mut files = IDENTITY_FILES.to_vec();
    files.extend(["src/xml/dom/roxmltree.rs", "src/xml/dom/xmloxide.rs"]);
    text.extend(sha_lines(root, &files)?.into_bytes());
    text.extend(output_of(root, "rustc", &["-Vv"])?);
    text.extend(output_of(root, "uname", &["-a"])?);
    text.extend(output_of(root, "uptime", &[])?);
    text.extend(
        format!(
            "features={} samples={}\n",
            request.features, request.samples
        )
        .into_bytes(),
    );
    if super::platform() == "darwin" {
        // Informational only: a missing value does not stop the run.
        if let Ok(brand) = output_of(root, "sysctl", &["-n", "machdep.cpu.brand_string"]) {
            text.extend(brand);
        }
    }
    Ok(text)
}

fn write(path: &Path, bytes: impl AsRef<[u8]>) -> Result<(), Failure> {
    std::fs::write(path, bytes).map_err(|error| format!("write {}: {error}", path.display()).into())
}

/// How every measured case runs: one child process under the metrics wrapper.
struct Child<'a> {
    root: &'a Path,
    output: &'a Path,
    time_args: &'a [&'a str],
    loader: &'a [String],
    binary: &'a str,
    samples: &'a str,
}

impl Child<'_> {
    /// Measures one `--list` line; other lines are not cases.
    fn run(&self, case: &str) -> Result<(), Failure> {
        let fields: Vec<&str> = case.split_whitespace().collect();
        let [operation, shape, units, backend, provider] = fields.as_slice() else {
            return Ok(());
        };
        let name = format!("{operation}-{shape}-{units}-{backend}-{provider}");
        let create = |file: String| {
            std::fs::File::create(self.output.join(file)).map_err(|error| error.to_string())
        };
        let status = Command::new("/usr/bin/time")
            .args(self.time_args)
            .args(self.loader)
            .args([
                self.binary,
                operation,
                shape,
                units,
                backend,
                provider,
                self.samples,
            ])
            .current_dir(self.root)
            .stdout(create(format!("{name}.json"))?)
            .stderr(create(format!("{name}.resources.txt"))?)
            .status()
            .map_err(|error| format!("{name}: {error}"))?;
        crate::repo::require(status)
    }
}

/// Builds the case runner and keeps its build messages, lockfile and graph;
/// returns the loader prefix its children need and the lockfile bytes.
fn build(root: &Path, output: &Path, features: &str) -> Result<(Vec<String>, Vec<u8>), Failure> {
    let build = output_of(
        root,
        "cargo",
        &[
            "build",
            "--release",
            "--example",
            "benchmark_latency",
            "--features",
            features,
            "--message-format=json",
        ],
    )?;
    write(&output.join("build.jsonl"), &build)?;
    let loader = loader(
        &native_paths(&String::from_utf8_lossy(&build)),
        super::platform(),
        std::env::var(if super::platform() == "darwin" {
            "DYLD_LIBRARY_PATH"
        } else {
            "LD_LIBRARY_PATH"
        })
        .ok()
        .as_deref(),
    );
    // The repository does not track the workspace lockfile: persist the resolved graph.
    let lock = std::fs::read(root.join("Cargo.lock")).map_err(|error| error.to_string())?;
    write(&output.join("Cargo.lock"), &lock)?;
    write(
        &output.join("dependencies.json"),
        output_of(
            root,
            "cargo",
            &[
                "metadata",
                "--locked",
                "--features",
                features,
                "--format-version",
                "1",
            ],
        )?,
    )?;
    Ok((loader, lock))
}

fn execute(request: &Request) -> Result<(), Failure> {
    let root = root();
    let time_args: &[&str] = match super::platform() {
        "darwin" => &["-l"],
        "linux" => &["-v"],
        _ => {
            return Err(usage(
                "RSS runner requires macOS or Linux; Divan works independently.".into(),
            ));
        }
    };
    std::fs::create_dir_all(&request.output)
        .map_err(|error| format!("{}: {error}", request.output.display()))?;
    let output = std::fs::canonicalize(&request.output).map_err(|error| error.to_string())?;
    let identity = source_identity(&root)?;
    write(&output.join("source-identity.txt"), &identity)?;
    write(
        &output.join("environment.txt"),
        environment(&root, request)?,
    )?;
    let features = request.features.as_str();
    let (loader, lock) = build(&root, &output, features)?;
    let target = std::env::var("CARGO_TARGET_DIR")
        .ok()
        .filter(|target| !target.is_empty())
        .unwrap_or_else(|| "target".into());
    let binary = root.join(target).join("release/examples/benchmark_latency");
    let binary = binary.display().to_string();
    let mut list: Vec<&str> = loader.iter().map(String::as_str).collect();
    list.extend([binary.as_str(), "--list"]);
    let cases = output_of(&root, list[0], &list[1..])?;
    write(&output.join("cases.txt"), &cases)?;
    let samples = request.samples.to_string();
    let child = Child {
        root: &root,
        output: &output,
        time_args,
        loader: &loader,
        binary: &binary,
        samples: &samples,
    };
    for case in String::from_utf8_lossy(&cases).lines() {
        child.run(case)?;
    }
    // Allocation counters perturb time: their timing columns are never the latency baseline.
    let divan = |features: &str| {
        output_of(
            &root,
            "cargo",
            &[
                "bench",
                "--locked",
                "--bench",
                "security",
                "--features",
                features,
                "--",
                "--sample-count",
                &samples,
                "--sample-size",
                "1",
            ],
        )
    };
    write(&output.join("divan-timing.txt"), divan(features)?)?;
    write(
        &output.join("divan-allocations.txt"),
        divan(&format!("{features},benchmark-alloc"))?,
    )?;
    let after = source_identity(&root)?;
    write(&output.join("source-identity-after.txt"), &after)?;
    let current_lock = std::fs::read(root.join("Cargo.lock")).map_err(|error| error.to_string())?;
    if after != identity || current_lock != lock {
        return Err(Failure {
            code: 3,
            message: "Source or dependency graph changed during measurement; discard this run."
                .into(),
        });
    }
    Ok(())
}

pub(crate) fn run(args: impl Iterator<Item = String>) -> Result<(), Failure> {
    let args: Vec<String> = args.collect();
    execute(&parse(&args)?)
}
