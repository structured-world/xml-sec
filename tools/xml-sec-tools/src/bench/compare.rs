//! `bench-compare NEW_OUTPUT_DIR [SAMPLES] [--heap]`: builds every engine at
//! its pinned revision, runs the command-line and library comparisons and
//! records the evidence a regression report needs.
//!
//! `competitor-lock`: refreshes only the xml-sec entry of the competitor
//! project's lockfile.

use super::identity::build_identity;
use crate::repo::{Failure, TOOL, root};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[cfg(test)]
mod tests;

const SOURCE_PATHS: [&str; 15] = [
    "Cargo.toml",
    "rust-toolchain.toml",
    "src",
    "crates",
    "vendor",
    "benches",
    "examples",
    "tools",
    "benchmarks",
    "compatibility/bergshamra-0.9.2-benchmark-commit.txt",
    "compatibility/libxmlsec1-1.3.13-donor-commit.txt",
    "tests/fixtures/keys/rsa",
    "tests/fixtures/keys/cacert.pem",
    "tests/fixtures/keys/ca2cert.pem",
    "scripts",
];
const CLI_FEATURES: &str = "benchmark-internals,xslt";
const LATENCY_FEATURES: &str = "benchmark-internals";
const BERGSHAMRA_FEATURES: &str = "rustcrypto";
const PROFILE_FEATURES: &str = "allocation-profile";
const NATIVE_FLAGS: [&str; 2] = ["-std=c11", "-O2"];

fn usage(message: &str) -> Failure {
    Failure {
        code: 2,
        message: message.into(),
    }
}

fn changed(message: &str) -> Failure {
    Failure {
        code: 3,
        message: message.into(),
    }
}

/// The parsed invocation.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Request {
    pub(crate) output: PathBuf,
    pub(crate) samples: u32,
    pub(crate) heap: bool,
}

pub(crate) fn parse(args: &[String]) -> Result<Request, Failure> {
    let output = args
        .first()
        .ok_or_else(|| usage("usage: bench-compare NEW_OUTPUT_DIR [SAMPLES] [--heap]"))?;
    if Path::new(output).exists() {
        return Err(usage("Output already exists"));
    }
    let samples = args.get(1).map_or("30", String::as_str);
    let samples = Some(samples)
        .filter(|samples| (1..=4).contains(&samples.len()))
        .and_then(|samples| super::sample_count(samples, 1000))
        .ok_or_else(|| usage("Invalid sample count"))?;
    let heap = match args.get(2).map(String::as_str) {
        None | Some("") => false,
        Some("--heap") => true,
        Some(_) => return Err(usage("Unknown profiling mode")),
    };
    Ok(Request {
        output: output.into(),
        samples,
        heap,
    })
}

fn run_in(
    root: &Path,
    program: impl AsRef<std::ffi::OsStr>,
    args: &[&str],
    env: &[(String, String)],
) -> Result<String, Failure> {
    let program = program.as_ref();
    let output = Command::new(program)
        .args(args)
        .current_dir(root)
        .envs(env.iter().map(|(key, value)| (key, value)))
        .stderr(Stdio::inherit())
        .output()
        .map_err(|error| format!("{}: {error}", program.to_string_lossy()))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(Failure::of(output.status))
    }
}

fn status_in(
    root: &Path,
    program: impl AsRef<std::ffi::OsStr>,
    args: &[&str],
    env: &[(String, String)],
) -> Result<(), Failure> {
    let program = program.as_ref();
    let status = Command::new(program)
        .args(args)
        .current_dir(root)
        .envs(env.iter().map(|(key, value)| (key, value)))
        .status()
        .map_err(|error| format!("{}: {error}", program.to_string_lossy()))?;
    crate::repo::require(status)
}

/// `sha256  path` lines of every tracked or untracked, unignored file of the
/// measured sources, sorted by path.
pub(crate) fn source_identity(root: &Path) -> Result<String, Failure> {
    let mut args = vec!["ls-files", "-c", "-o", "--exclude-standard", "-z", "--"];
    args.extend(SOURCE_PATHS);
    let listed = run_in(root, "git", &args, &[])?;
    let mut paths: Vec<&str> = listed.split('\0').filter(|path| !path.is_empty()).collect();
    paths.sort_unstable();
    paths.dedup();
    let mut lines = Vec::new();
    for path in paths {
        lines.push(format!("{}  {path}", super::digest_file(&root.join(path))?));
    }
    Ok(lines.join("\n"))
}

/// `sha256  path` lines of the three lockfiles that fix the measured graphs.
fn lock_identity(root: &Path, competitor: &Path) -> Result<String, Failure> {
    let mut lines = Vec::new();
    for path in [
        root.join("Cargo.lock"),
        competitor.join("Cargo.lock"),
        root.join("benchmarks/competitors/Cargo.lock"),
    ] {
        lines.push(format!(
            "{}  {}",
            super::digest_file(&path)?,
            path.display()
        ));
    }
    Ok(lines.join("\n"))
}

/// Every `[[package]]` block of a lockfile except xml-sec's own.
pub(crate) fn other_packages(lock: &str) -> Vec<&str> {
    lock.split("\n\n")
        .map(|block| block.trim_matches('\n'))
        .filter(|block| {
            !block.is_empty() && !block.starts_with("[[package]]\nname = \"xml-sec\"\n")
        })
        .collect()
}

/// Refreshes only the xml-sec entry of the competitor lockfile. A product
/// dependency the locked graph cannot satisfy changes the competitor's graph,
/// which is a reviewed lockfile change, not a side effect of a run; a refused
/// refresh restores the lockfile so a rerun cannot accept what this one refused.
pub(crate) fn refresh_competitor_lock(root: &Path) -> Result<(), Failure> {
    let manifest = root.join("benchmarks/competitors/Cargo.toml");
    let lock = root.join("benchmarks/competitors/Cargo.lock");
    let saved =
        std::fs::read_to_string(&lock).map_err(|error| format!("{}: {error}", lock.display()))?;
    let restore = |message: String| -> Failure {
        match std::fs::write(&lock, &saved) {
            Ok(()) => message.into(),
            Err(error) => format!("{message}; restoring {} failed: {error}", lock.display()).into(),
        }
    };
    let manifest = manifest.display().to_string();
    if status_in(
        root,
        "cargo",
        &["update", "--manifest-path", &manifest, "-p", "xml-sec"],
        &[],
    )
    .is_err()
    {
        return Err(restore(format!(
            "Refreshing xml-sec in {} failed",
            lock.display()
        )));
    }
    let refreshed =
        std::fs::read_to_string(&lock).map_err(|error| format!("{}: {error}", lock.display()))?;
    if other_packages(&saved) != other_packages(&refreshed) {
        return Err(restore(format!(
            "Refreshing xml-sec changed other entries of {}; update and commit that lockfile deliberately",
            lock.display()
        )));
    }
    Ok(())
}

/// The pinned competitor checkout, fetched once and refused unless clean.
fn competitor(root: &Path, revision: &str) -> Result<PathBuf, Failure> {
    let source = std::env::var("BERGSHAMRA_SOURCE_DIR")
        .ok()
        .filter(|source| !source.is_empty())
        .map_or_else(
            || root.join(format!(".tools/benchmark-bergshamra-{revision}")),
            PathBuf::from,
        );
    let text = source.display().to_string();
    if !source.exists() {
        status_in(root, "git", &["init", &text], &[])?;
        status_in(
            root,
            "git",
            &[
                "-C",
                &text,
                "remote",
                "add",
                "origin",
                "https://github.com/kushaldas/bergshamra.git",
            ],
            &[],
        )?;
        status_in(
            root,
            "git",
            &["-C", &text, "fetch", "--depth=1", "origin", revision],
            &[],
        )?;
        status_in(
            root,
            "git",
            &["-C", &text, "checkout", "--detach", revision],
            &[],
        )?;
    }
    if run_in(root, "git", &["-C", &text, "rev-parse", "HEAD"], &[])?.trim() != revision {
        return Err("the competitor checkout is not at the pinned revision".into());
    }
    if !run_in(root, "git", &["-C", &text, "status", "--porcelain"], &[])?
        .trim()
        .is_empty()
    {
        return Err(usage("Competitor checkout must be clean"));
    }
    Ok(source)
}

fn pinned(root: &Path, file: &str) -> Result<String, Failure> {
    Ok(std::fs::read_to_string(root.join(file))
        .map_err(|error| format!("{file}: {error}"))?
        .trim()
        .to_owned())
}

fn words(text: &str) -> Vec<String> {
    text.split_whitespace().map(String::from).collect()
}

/// Builds the native library harness, and on Linux its allocation-counting twin.
fn native_harness(root: &Path, prefix: &Path, native: &Path) -> Result<Option<PathBuf>, Failure> {
    let pkg_path = [(
        "PKG_CONFIG_PATH".to_owned(),
        prefix.join("lib/pkgconfig").display().to_string(),
    )];
    let xmlsec = words(&run_in(
        root,
        "pkg-config",
        &["--cflags", "xmlsec1-openssl"],
        &pkg_path,
    )?);
    let libxml = if super::platform() == "darwin" {
        vec![format!(
            "-I{}/usr/include/libxml2",
            run_in(root, "xcrun", &["--show-sdk-path"], &[])?.trim()
        )]
    } else {
        words(&run_in(
            root,
            "pkg-config",
            &["--cflags", "libxml-2.0"],
            &[],
        )?)
    };
    // OpenSSL is linked into libxmlsec1-openssl itself; linking another copy
    // here would load a second, unused library.
    let mut build: Vec<String> = NATIVE_FLAGS.iter().map(|flag| (*flag).to_owned()).collect();
    build.extend(["-Wall", "-Wextra", "-Werror"].map(String::from));
    build.extend(xmlsec);
    build.extend(libxml);
    build.extend([
        "benchmarks/libxmlsec1-library.c".into(),
        format!("-L{}", prefix.join("lib").display()),
        "-lxmlsec1-openssl".into(),
        "-lxmlsec1".into(),
        "-lxslt".into(),
        "-lxml2".into(),
    ]);
    let compile = |extra: &[&str], output: &Path| {
        let mut args: Vec<&str> = build.iter().map(String::as_str).collect();
        args.extend(extra);
        let output = output.display().to_string();
        args.extend(["-o", &output]);
        status_in(root, "cc", &args, &[])
    };
    compile(&[], &native.join("libxmlsec1-library"))?;
    // Counting every native allocation replaces glibc's malloc family; elsewhere
    // the native allocation profile is reported as not measured.
    if super::platform() == "linux" {
        let profile = native.join("libxmlsec1-library-profile");
        compile(&["-DLIBRARY_PROFILE"], &profile)?;
        return Ok(Some(profile));
    }
    Ok(None)
}

fn record_environment(
    root: &Path,
    request: &Request,
    revision: &str,
    donor: &str,
    binaries: &[&Path],
) -> Result<String, Failure> {
    let mut text = format!("bergshamra={revision}\nlibxmlsec1={donor}\n");
    text.push_str(&run_in(root, "rustc", &["-Vv"], &[])?);
    for name in ["RUSTFLAGS", "CFLAGS"] {
        text.push_str(name);
        text.push('=');
        text.push_str(&std::env::var(name).unwrap_or_default());
        text.push('\n');
    }
    text.push_str(&run_in(root, "cc", &["--version"], &[])?);
    if request.heap {
        text.push_str(&run_in(root, "valgrind", &["--version"], &[])?);
    }
    text.push_str(&run_in(root, "uname", &["-a"], &[])?);
    text.push_str(&run_in(root, "uptime", &[], &[])?);
    let paths: Vec<String> = binaries
        .iter()
        .map(|path| path.display().to_string())
        .collect();
    let mut args: Vec<&str> = paths.iter().map(String::as_str).collect();
    if super::platform() == "darwin" {
        args.insert(0, "-L");
        text.push_str(&run_in(root, "otool", &args, &[])?);
    } else {
        text.push_str(&run_in(root, "ldd", &args, &[])?);
    }
    Ok(text)
}

/// The binaries one comparison measures.
struct Built {
    native: PathBuf,
    native_profile: Option<PathBuf>,
    library: PathBuf,
    library_profile: PathBuf,
}

/// Builds every engine. The library repository does not track `Cargo.lock`:
/// the graph is resolved once, then frozen for measurement and kept with the
/// evidence.
fn build_engines(
    root: &Path,
    target: &Path,
    competitor: &Path,
    prefix: &Path,
) -> Result<Built, Failure> {
    let target_dir = |name: &str| target.join(name).display().to_string();
    status_in(
        root,
        "cargo",
        &[
            "build",
            "--release",
            "-p",
            "xml-sec-cli",
            "--bin",
            "xmlsec1",
            "--features",
            CLI_FEATURES,
        ],
        &[],
    )?;
    status_in(
        root,
        "cargo",
        &[
            "build",
            "--release",
            "-p",
            "xml-sec",
            "--example",
            "benchmark_latency",
            "--features",
            LATENCY_FEATURES,
        ],
        &[],
    )?;
    let manifest = competitor.join("Cargo.toml").display().to_string();
    status_in(
        root,
        "cargo",
        &[
            "build",
            "--release",
            "--locked",
            "--manifest-path",
            &manifest,
            "-p",
            "bergshamra",
            "--no-default-features",
            "--features",
            BERGSHAMRA_FEATURES,
            "--target-dir",
            &target_dir("competitors/bergshamra"),
        ],
        &[],
    )?;
    // Library level: in-process harnesses from a project outside the product
    // workspace. Timing and allocation counting are separate builds.
    let competitors = "benchmarks/competitors/Cargo.toml";
    status_in(
        root,
        "cargo",
        &[
            "build",
            "--release",
            "--locked",
            "--manifest-path",
            competitors,
            "--target-dir",
            &target_dir("competitors/library"),
        ],
        &[],
    )?;
    status_in(
        root,
        "cargo",
        &[
            "build",
            "--release",
            "--locked",
            "--manifest-path",
            competitors,
            "--target-dir",
            &target_dir("competitors/library-profile"),
            "--features",
            PROFILE_FEATURES,
        ],
        &[],
    )?;
    let native = target.join("competitors/libxmlsec1");
    std::fs::create_dir_all(&native).map_err(|error| format!("{}: {error}", native.display()))?;
    let native_profile = native_harness(root, prefix, &native)?;
    Ok(Built {
        native: native.join("libxmlsec1-library"),
        native_profile,
        library: target.join("competitors/library/release"),
        library_profile: target.join("competitors/library-profile/release"),
    })
}

/// The environment the comparison subcommands read their binaries from.
fn measurement_env(target: &Path, prefix: &Path, built: &Built) -> Vec<(String, String)> {
    let path = |path: PathBuf| path.display().to_string();
    let mut env = vec![
        (
            "XML_SEC_BENCH_BIN".to_owned(),
            path(target.join("release/xmlsec1")),
        ),
        (
            "BENCH_EXPORT_BIN".to_owned(),
            path(target.join("release/examples/benchmark_latency")),
        ),
        (
            "BERGSHAMRA_BIN".to_owned(),
            path(target.join("competitors/bergshamra/release/bergshamra")),
        ),
        ("XMLSEC1_BIN".to_owned(), path(prefix.join("bin/xmlsec1"))),
        (
            "LIBRARY_XMLSEC_BIN".to_owned(),
            path(built.library.join("xml-sec-library")),
        ),
        (
            "LIBRARY_BERGSHAMRA_BIN".to_owned(),
            path(built.library.join("bergshamra-library")),
        ),
        (
            "LIBRARY_LIBXMLSEC1_BIN".to_owned(),
            path(built.native.clone()),
        ),
        (
            "LIBRARY_XMLSEC_PROFILE_BIN".to_owned(),
            path(built.library_profile.join("xml-sec-library")),
        ),
        (
            "LIBRARY_BERGSHAMRA_PROFILE_BIN".to_owned(),
            path(built.library_profile.join("bergshamra-library")),
        ),
        (
            "LIBRARY_LIBXMLSEC1_PROFILE_BIN".to_owned(),
            built.native_profile.clone().map(path).unwrap_or_default(),
        ),
    ];
    let library_path = |name: &str| {
        let current = std::env::var(name).ok().filter(|value| !value.is_empty());
        let lib = prefix.join("lib").display().to_string();
        (
            name.to_owned(),
            current.map_or_else(|| lib.clone(), |current| format!("{lib}:{current}")),
        )
    };
    match super::platform() {
        "darwin" => env.push(library_path("DYLD_LIBRARY_PATH")),
        "linux" => env.push(library_path("LD_LIBRARY_PATH")),
        _ => {}
    }
    env
}

fn execute(request: &Request) -> Result<(), Failure> {
    let root = root();
    let revision = pinned(&root, "compatibility/bergshamra-0.9.2-benchmark-commit.txt")?;
    if revision.len() != 40
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("the pinned competitor revision is not a commit".into());
    }
    let competitor = competitor(&root, &revision)?;
    let target = std::env::var("CARGO_TARGET_DIR")
        .ok()
        .filter(|target| !target.is_empty())
        .map_or_else(|| root.join("target"), PathBuf::from);
    let target = if target.is_absolute() {
        target
    } else {
        root.join(target)
    };
    let donor = pinned(&root, "compatibility/libxmlsec1-1.3.13-donor-commit.txt")?;
    let prefix = std::env::var("XMLSEC1_PREFIX")
        .ok()
        .filter(|prefix| !prefix.is_empty())
        .map_or_else(
            || {
                root.join(format!(
                    ".tools/xmlsec1-1.3.13-{}",
                    donor.get(..12).unwrap_or(&donor)
                ))
            },
            PathBuf::from,
        );
    tool_step(
        &root,
        &["install-xmlsec1"],
        &[("XMLSEC1_PREFIX".into(), prefix.display().to_string())],
    )?;
    refresh_competitor_lock(&root)?;
    let before = source_identity(&root)?;
    let built = build_engines(&root, &target, &competitor, &prefix)?;
    if source_identity(&root)? != before {
        return Err(changed("Source changed during build; discard binaries"));
    }
    let locks_before = lock_identity(&root, &competitor)?;
    let env = measurement_env(&target, &prefix, &built);
    let output = request.output.display().to_string();
    let samples = request.samples.to_string();
    let mut cli = vec!["bench-cli", output.as_str(), samples.as_str()];
    if request.heap {
        cli.push("--heap");
    }
    tool_step(&root, &cli, &env)?;
    tool_step(&root, &["bench-library", &output, &samples], &env)?;
    if source_identity(&root)? != before {
        return Err(changed(
            "Source changed during measurement; discard results",
        ));
    }
    if lock_identity(&root, &competitor)? != locks_before {
        return Err(changed(
            "Dependency graph changed during measurement; discard results",
        ));
    }
    record(
        &root,
        request,
        &competitor,
        &before,
        &revision,
        &donor,
        &env,
    )
}

/// The lockfiles, dependency graphs, sources, environment and build identity
/// the evidence keeps.
fn record(
    root: &Path,
    request: &Request,
    competitor: &Path,
    before: &str,
    revision: &str,
    donor: &str,
    env: &[(String, String)],
) -> Result<(), Failure> {
    let output = &request.output;
    let copy = |from: PathBuf, to: &str| {
        std::fs::copy(&from, output.join(to))
            .map(drop)
            .map_err(|error| format!("{}: {error}", from.display()))
    };
    copy(root.join("Cargo.lock"), "xml-sec.Cargo.lock")?;
    copy(competitor.join("Cargo.lock"), "bergshamra.Cargo.lock")?;
    copy(
        root.join("benchmarks/competitors/Cargo.lock"),
        "competitors.Cargo.lock",
    )?;
    let write = |name: &str, text: &str| {
        std::fs::write(output.join(name), text).map_err(|error| format!("{name}: {error}"))
    };
    write("source-sha256.txt", &format!("{before}\n"))?;
    let manifest = competitor.join("Cargo.toml").display().to_string();
    let graphs: [(&str, &[&str]); 3] = [
        (
            "competitors.dependencies.json",
            &["--manifest-path", "benchmarks/competitors/Cargo.toml"],
        ),
        (
            "xml-sec.dependencies.json",
            &["--features", "benchmark-internals"],
        ),
        (
            "bergshamra.dependencies.json",
            &[
                "--manifest-path",
                &manifest,
                "--no-default-features",
                "--features",
                BERGSHAMRA_FEATURES,
            ],
        ),
    ];
    for (name, selection) in graphs {
        let mut args = vec!["metadata", "--locked"];
        args.extend(selection);
        args.extend(["--format-version", "1"]);
        write(name, &run_in(root, "cargo", &args, &[])?)?;
    }
    let variable = |name: &str| {
        env.iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| PathBuf::from(value))
            .unwrap_or_default()
    };
    let binaries = [variable("XMLSEC1_BIN"), variable("LIBRARY_LIBXMLSEC1_BIN")];
    write(
        "build-environment.txt",
        &record_environment(
            root,
            request,
            revision,
            donor,
            &[&binaries[0], &binaries[1]],
        )?,
    )?;
    // The build identity a regression report requires to match between two runs.
    let selections: Vec<(String, String)> = [
        ("cli_features", CLI_FEATURES.to_owned()),
        ("latency_features", LATENCY_FEATURES.to_owned()),
        ("bergshamra_features", BERGSHAMRA_FEATURES.to_owned()),
        ("library_profile_features", PROFILE_FEATURES.to_owned()),
        ("native_flags", NATIVE_FLAGS.join(" ")),
        (
            "heap",
            if request.heap {
                "--heap".to_owned()
            } else {
                "none".to_owned()
            },
        ),
        ("bergshamra", revision.to_owned()),
        ("libxmlsec1", donor.to_owned()),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value))
    .collect();
    let environment: Vec<(String, String)> = std::env::vars().collect();
    let identity = build_identity(&selections, &environment, root)?;
    write("build.json", &format!("{identity}\n"))?;
    Ok(())
}

pub(crate) fn run(args: impl Iterator<Item = String>) -> Result<(), Failure> {
    let args: Vec<String> = args.collect();
    execute(&parse(&args)?)
}

pub(crate) fn run_lock(mut args: impl Iterator<Item = String>) -> Result<(), Failure> {
    if args.next().is_some() {
        return Err("usage: xml-sec-tools competitor-lock".into());
    }
    refresh_competitor_lock(&root())
}

fn tool_step(root: &Path, args: &[&str], env: &[(String, String)]) -> Result<(), Failure> {
    let program = std::env::current_exe().map_err(|error| format!("{TOOL}: {error}"))?;
    status_in(root, program, args, env)
}
