//! `bench-xslt NEW_OUTPUT [SAMPLES]`: XSLT phase latency and allocations of
//! xml-sec against the pinned native libxslt, with the evidence kept outside
//! the cleaned build directory.

use super::{
    Captured, capture, digest_file, number, platform, safe_integer, sample_count, to_f64,
    write_pretty,
};
use crate::repo::{Failure, root};
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

#[cfg(test)]
mod tests;

const PHASES: [&str; 5] = ["compile", "tree", "serialize", "retained", "end_to_end"];
const SHAPES: [&str; 2] = ["items", "amplification"];
const SIZES: [u32; 2] = [16, 256];
const SOURCES: [&str; 10] = [
    "Cargo.toml",
    "crates/xml-sec-xslt/Cargo.toml",
    "src/xslt/lib.rs",
    "src/xslt/runtime.rs",
    "benches/support/xslt.rs",
    "benchmarks/xslt-latency.rs",
    "benchmarks/xslt-alloc.rs",
    "benchmarks/xslt-oracle.c",
    "benchmarks/cmake/libxml2/LibXml2Config.cmake",
    "tools/xml-sec-tools/src/bench/xslt.rs",
];

/// Nearest-rank percentiles that keep outliers and do not reorder the samples.
pub(crate) fn summary(samples: &[Value]) -> Result<Value, String> {
    let values: Vec<f64> = samples
        .iter()
        .filter_map(safe_integer)
        .filter(|value| *value > 0.0)
        .collect();
    if samples.is_empty() || values.len() != samples.len() {
        return Err("invalid timing samples".into());
    }
    Ok(json!({
        "p50_ns": number(super::percentile(&values, 50)?),
        "p95_ns": number(super::percentile(&values, 95)?),
        "p99_ns": number(super::percentile(&values, 99)?),
    }))
}

/// The byte sizes and identity one measurement must report.
pub(crate) struct Expected<'a> {
    pub(crate) samples: usize,
    pub(crate) source_bytes: u64,
    pub(crate) stylesheet_bytes: u64,
    pub(crate) output_bytes: u64,
    pub(crate) engine: &'a str,
    pub(crate) phase: &'a str,
}

/// Refuses a measurement that does not describe exactly the expected run.
pub(crate) fn validate(result: &Value, expected: &Expected<'_>) -> Result<Value, String> {
    let samples = result["samples_ns"]
        .as_array()
        .ok_or("inconsistent measurement")?;
    let consistent = samples.len() == expected.samples
        && result["source_bytes"] == expected.source_bytes
        && result["stylesheet_bytes"] == expected.stylesheet_bytes
        && result["output_bytes"] == expected.output_bytes
        && result["engine"] == expected.engine
        && result["phase"] == expected.phase;
    if !consistent {
        return Err("inconsistent measurement".into());
    }
    let mut record = result.as_object().cloned().unwrap_or_default();
    record.extend(summary(samples)?.as_object().cloned().unwrap_or_default());
    record.insert(
        "output_amplification".into(),
        number(to_f64(expected.output_bytes) / to_f64(expected.source_bytes)),
    );
    Ok(Value::Object(record))
}

/// Peak RSS of the whole process; macOS reports bytes, Linux KiB.
pub(crate) fn resources(text: &str, os: &str) -> Result<Value, String> {
    let pattern = if os == "darwin" {
        r"(\d+)\s+maximum resident set size"
    } else {
        r"Maximum resident set size \(kbytes\):\s*(\d+)"
    };
    let found = regex::Regex::new(pattern)
        .expect("valid pattern")
        .captures(text)
        .ok_or("missing process peak RSS")?;
    let value: u64 = found[1].parse().map_err(|_| "missing process peak RSS")?;
    let bytes = if os == "darwin" {
        value
    } else {
        value.checked_mul(1024).ok_or("peak RSS out of range")?
    };
    Ok(
        json!({ "peak_rss_bytes": bytes, "rss_scope": "whole process including preparation and warmups" }),
    )
}

/// The canonical form of `path`, resolving the existing part of it.
fn canonical_location(path: &Path) -> Result<PathBuf, String> {
    match std::fs::canonicalize(path) {
        Ok(path) => Ok(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or("no existing ancestor")?;
            let name = path.file_name().ok_or("no file name")?;
            Ok(canonical_location(parent)?.join(name))
        }
        Err(error) => Err(error.to_string()),
    }
}

/// Refuses evidence inside the build directory a successful run cleans,
/// including through a symlinked alias.
pub(crate) fn check_output_location(output: &Path, target: &Path) -> Result<(), String> {
    let output =
        canonical_location(&std::path::absolute(output).map_err(|error| error.to_string())?)?;
    let target =
        canonical_location(&std::path::absolute(target).map_err(|error| error.to_string())?)?;
    if output.starts_with(&target) {
        return Err("evidence must be outside the cleaned build directory".into());
    }
    Ok(())
}

const LIMIT: Duration = Duration::from_mins(30);

fn run_in(
    directory: &Path,
    program: impl AsRef<std::ffi::OsStr>,
    args: &[String],
    env: &[(String, String)],
) -> Result<String, String> {
    let mut command = Command::new(program.as_ref());
    command
        .args(args)
        .current_dir(directory)
        .envs(env.iter().map(|(key, value)| (key, value)));
    let result = capture(&mut command, true, LIMIT);
    if result.succeeded() {
        Ok(result.stdout)
    } else {
        Err(format!(
            "{} failed: {}",
            program.as_ref().to_string_lossy(),
            result.error.clone().unwrap_or(result.stderr)
        ))
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|&value| value.to_owned()).collect()
}

/// `[path, sha256]` pairs; a relative path is read below `root` and written as given.
fn fingerprint(root: &Path, paths: &[PathBuf]) -> Result<Value, String> {
    paths
        .iter()
        .map(|path| {
            Ok(json!([
                path.display().to_string(),
                digest_file(&root.join(path))?
            ]))
        })
        .collect::<Result<Vec<_>, String>>()
        .map(Value::Array)
}

fn write(path: &Path, bytes: impl AsRef<[u8]>) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|error| format!("write {}: {error}", path.display()))
}

/// Builds the pinned native libxslt and its oracle binaries into `output`.
fn native(
    root: &Path,
    source: &Path,
    output: &Path,
) -> Result<(Vec<String>, String, [PathBuf; 2]), String> {
    let build = output.join("native-build");
    let prefix = output.join("native");
    let cmake = |args: Vec<String>| run_in(root, "cmake", &args, &[]);
    cmake(vec![
        "-S".into(),
        source.display().to_string(),
        "-B".into(),
        build.display().to_string(),
        "-DCMAKE_BUILD_TYPE=Release".into(),
        format!("-DCMAKE_INSTALL_PREFIX={}", prefix.display()),
        format!(
            "-DLibXml2_DIR={}",
            root.join("benchmarks/cmake/libxml2").display()
        ),
        "-DBUILD_SHARED_LIBS=OFF".into(),
        "-DCMAKE_INSTALL_LIBDIR=lib".into(),
        "-DLIBXSLT_WITH_PYTHON=OFF".into(),
        "-DLIBXSLT_WITH_TESTS=OFF".into(),
        "-DLIBXSLT_WITH_PROGRAMS=OFF".into(),
    ])?;
    cmake(vec![
        "--build".into(),
        build.display().to_string(),
        "--parallel".into(),
        "2".into(),
    ])?;
    cmake(vec!["--install".into(), build.display().to_string()])?;
    let pkg_path = std::env::var("PKG_CONFIG_PATH")
        .ok()
        .filter(|path| !path.is_empty())
        .map_or_else(
            || prefix.join("lib/pkgconfig").display().to_string(),
            |path| format!("{}:{path}", prefix.join("lib/pkgconfig").display()),
        );
    let env = [("PKG_CONFIG_PATH".to_owned(), pkg_path)];
    let pkg = |args: &[&str]| {
        run_in(root, "pkg-config", &strings(args), &env).map(|text| text.trim().to_owned())
    };
    let flags: Vec<String> = pkg(&["--static", "--cflags", "--libs", "libxslt"])?
        .split_whitespace()
        .map(String::from)
        .collect();
    if pkg(&["--variable=prefix", "libxslt"])? != prefix.display().to_string()
        || pkg(&["--modversion", "libxslt"])? != "1.1.45"
    {
        return Err("native link configuration escaped the pinned build".into());
    }
    let libxml = pkg(&["--modversion", "libxml-2.0"])?;
    write(
        &output.join("native-cmake-cache.txt"),
        std::fs::read(build.join("CMakeCache.txt")).map_err(|error| error.to_string())?,
    )?;
    let oracle = output.join("xslt-oracle");
    let allocation = output.join("xslt-oracle-alloc");
    for (binary, extra) in [(&oracle, None), (&allocation, Some("-DXSLT_PROFILE"))] {
        let mut args = strings(&["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]);
        args.extend(extra.map(String::from));
        args.push("benchmarks/xslt-oracle.c".into());
        args.extend(flags.iter().cloned());
        args.extend(["-o".into(), binary.display().to_string()]);
        run_in(root, "cc", &args, &[])?;
    }
    Ok((flags, libxml, [oracle, allocation]))
}

/// The measurement loop: three repetitions, alternating which engine runs first.
fn measure(
    binary: &Path,
    oracle: &Path,
    corpus: &Path,
    output: &Path,
    count: &str,
    samples: usize,
) -> Result<Vec<Value>, String> {
    let mut observations = Vec::new();
    for repetition in 0..3_u32 {
        for shape in SHAPES {
            for size in SIZES {
                let base = corpus.join(format!("{shape}-{size}"));
                let read = |extension: &str| {
                    std::fs::metadata(base.with_extension(extension))
                        .map(|meta| meta.len())
                        .map_err(|error| error.to_string())
                };
                let (input, style, expected) = (read("xml")?, read("xsl")?, read("expected")?);
                for phase in PHASES {
                    let engines = if repetition % 2 == 1 {
                        ["libxslt", "xml-sec"]
                    } else {
                        ["xml-sec", "libxslt"]
                    };
                    for engine in engines {
                        let name = format!("{engine}-{shape}-{size}-{phase}-{repetition}");
                        let (program, args) = if engine == "xml-sec" {
                            (
                                binary,
                                vec![
                                    phase.to_owned(),
                                    shape.to_owned(),
                                    size.to_string(),
                                    count.to_owned(),
                                ],
                            )
                        } else {
                            let file = |extension: &str| {
                                base.with_extension(extension).display().to_string()
                            };
                            (
                                oracle,
                                vec![
                                    phase.to_owned(),
                                    file("xsl"),
                                    file("xml"),
                                    file("expected"),
                                    count.to_owned(),
                                ],
                            )
                        };
                        let mut command = Command::new("/usr/bin/time");
                        command
                            .arg(if platform() == "darwin" { "-l" } else { "-v" })
                            .arg(program)
                            .args(&args);
                        let result: Captured =
                            capture(&mut command, true, Duration::from_secs(120));
                        write(
                            &output.join(format!("{name}.resources.txt")),
                            &result.stderr,
                        )?;
                        if !result.succeeded() {
                            return Err(format!(
                                "measurement {name} failed: {}",
                                result.error.clone().unwrap_or(result.stderr)
                            ));
                        }
                        let reported: Value = serde_json::from_str(&result.stdout)
                            .map_err(|error| format!("{name}: {error}"))?;
                        let expected = Expected {
                            samples,
                            source_bytes: input,
                            stylesheet_bytes: style,
                            output_bytes: expected,
                            engine,
                            phase,
                        };
                        let mut record = validate(&reported, &expected)?
                            .as_object()
                            .cloned()
                            .unwrap_or_default();
                        record.extend(
                            resources(&result.stderr, platform())?
                                .as_object()
                                .cloned()
                                .unwrap_or_default(),
                        );
                        record.insert("shape".into(), shape.into());
                        record.insert("size".into(), size.into());
                        record.insert("repetition".into(), repetition.into());
                        record.insert("resources".into(), format!("{name}.resources.txt").into());
                        let record = Value::Object(record);
                        write_pretty(&output.join(format!("{name}.json")), &record)?;
                        observations.push(record);
                    }
                }
            }
        }
    }
    Ok(observations)
}

/// Native allocation counts per phase; their instrumented timings are never published.
fn native_allocations(
    root: &Path,
    allocation: &Path,
    oracle: &Path,
    corpus: &Path,
    output: &Path,
) -> Result<(), String> {
    for shape in SHAPES {
        for size in SIZES {
            let base = corpus.join(format!("{shape}-{size}"));
            let file = |extension: &str| base.with_extension(extension).display().to_string();
            for phase in PHASES {
                let args = vec![
                    phase.to_owned(),
                    file("xsl"),
                    file("xml"),
                    file("expected"),
                    "1".into(),
                ];
                let mut result: Map<String, Value> =
                    serde_json::from_str(&run_in(root, allocation, &args, &[])?)
                        .map_err(|error| error.to_string())?;
                let positive = |key: &str| {
                    super::float(result.get(key).unwrap_or(&Value::Null))
                        .is_some_and(|value| value > 0.0)
                };
                let negative_peak =
                    super::float(result.get("extra_peak_xml_bytes").unwrap_or(&Value::Null))
                        .is_some_and(|value| value < 0.0);
                if !positive("allocation_calls") || !positive("allocated_bytes") || negative_peak {
                    return Err("native allocation hooks did not observe the phase".into());
                }
                result.remove("samples_ns");
                write_pretty(
                    &output.join(format!("allocations-libxslt-{shape}-{size}-{phase}.json")),
                    &Value::Object(result),
                )?;
                // Native-aware allocations use separate instrumented processes: full-process
                // measurements, not comparable to the per-phase counters of the Rust bench.
                if std::env::var("XSLT_BENCH_HEAP").is_ok_and(|value| value == "1") {
                    let name = format!("libxslt-{shape}-{size}-{phase}");
                    let mut tail = vec![oracle.display().to_string()];
                    tail.extend(args.iter().take(4).cloned());
                    tail.push("1".into());
                    let mut memcheck = vec![
                        "--tool=memcheck".to_owned(),
                        "--error-exitcode=91".into(),
                        format!(
                            "--log-file={}",
                            output.join(format!("{name}.memcheck.txt")).display()
                        ),
                    ];
                    memcheck.extend(tail.iter().cloned());
                    run_in(root, "valgrind", &memcheck, &[])?;
                    let mut massif = vec![
                        "--tool=massif".to_owned(),
                        format!(
                            "--massif-out-file={}",
                            output.join(format!("{name}.massif")).display()
                        ),
                    ];
                    massif.extend(tail);
                    run_in(root, "valgrind", &massif, &[])?;
                }
            }
        }
    }
    Ok(())
}

/// The pinned native source, refused unless it is the exact clean revision.
fn pinned_native(root: &Path) -> Result<(PathBuf, String), String> {
    let pinned =
        std::fs::read_to_string(root.join("compatibility/libxslt-1.1.45-donor-commit.txt"))
            .map_err(|error| error.to_string())?
            .trim()
            .to_owned();
    let source = std::env::var("LIBXSLT_SOURCE_DIR")
        .ok()
        .filter(|source| !source.is_empty());
    let git = |source: &str, args: &[&str]| {
        let mut all = strings(&["-C", source]);
        all.extend(strings(args));
        run_in(root, "git", &all, &[])
    };
    let Some(source) = source.filter(|source| {
        git(source, &["rev-parse", "HEAD"]).is_ok_and(|head| head.trim() == pinned)
    }) else {
        return Err("LIBXSLT_SOURCE_DIR must be the pinned libxslt checkout".into());
    };
    if !git(&source, &["status", "--porcelain", "--untracked-files=no"])?
        .trim()
        .is_empty()
    {
        return Err("pinned native source has tracked modifications".into());
    }
    Ok((PathBuf::from(source), pinned))
}

/// What the evidence must show unchanged between the start and the end of a run.
fn unchanged(
    root: &Path,
    output: &Path,
    sources: &Value,
    corpus: &(Vec<PathBuf>, Value),
    diff: &str,
) -> Result<(), String> {
    let source_paths: Vec<PathBuf> = SOURCES.iter().map(PathBuf::from).collect();
    let lock = |path: &Path| std::fs::read(path).map_err(|error| error.to_string());
    let same = *sources == fingerprint(root, &source_paths)?
        && corpus.1 == fingerprint(root, &corpus.0)?
        && diff == run_in(root, "git", &strings(&["diff", "--binary", "HEAD"]), &[])?
        && lock(&root.join("Cargo.lock"))? == lock(&output.join("Cargo.lock"))?;
    if same {
        Ok(())
    } else {
        Err("sources, corpus or dependency graph changed during run".into())
    }
}

/// Exports the measured corpus; returns its files and their fingerprint.
fn export_corpus(
    root: &Path,
    binary: &Path,
    corpus: &Path,
) -> Result<(Vec<PathBuf>, Value), String> {
    run_in(
        root,
        binary,
        &["--export".into(), corpus.display().to_string()],
        &[],
    )?;
    let paths: Vec<PathBuf> = SHAPES
        .iter()
        .flat_map(|shape| SIZES.iter().map(move |size| format!("{shape}-{size}")))
        .flat_map(|base| {
            ["xml", "xsl", "expected"].map(|extension| corpus.join(format!("{base}.{extension}")))
        })
        .collect();
    let fingerprint = fingerprint(root, &paths)?;
    Ok((paths, fingerprint))
}

/// The workspace build directory, as Cargo resolves it.
fn target_directory(root: &Path) -> Result<PathBuf, String> {
    let metadata: Value = serde_json::from_str(&run_in(
        root,
        "cargo",
        &strings(&["metadata", "--no-deps", "--format-version", "1"]),
        &[],
    )?)
    .map_err(|error| error.to_string())?;
    Ok(PathBuf::from(
        metadata["target_directory"]
            .as_str()
            .ok_or("cargo metadata without a target directory")?,
    ))
}

/// Builds the Rust runner and keeps the lockfile and graph it was built from.
fn build_runner(root: &Path, output: &Path) -> Result<(), String> {
    let text = |args: &[&str]| run_in(root, "cargo", &strings(args), &[]);
    text(&[
        "build",
        "--release",
        "-p",
        "xml-sec-xslt",
        "--example",
        "xslt_latency",
        "--features",
        "benchmark-internals",
    ])?;
    write(
        &output.join("Cargo.lock"),
        std::fs::read(root.join("Cargo.lock")).map_err(|error| error.to_string())?,
    )?;
    write(
        &output.join("dependencies.json"),
        text(&[
            "metadata",
            "--locked",
            "--format-version",
            "1",
            "--features",
            "xml-sec-xslt/benchmark-internals",
        ])?,
    )
}

fn execute(directory: &Path, count: &str, samples: usize) -> Result<(), String> {
    let root = root();
    let (native_source, pinned) = pinned_native(&root)?;
    let output = std::path::absolute(directory).map_err(|error| error.to_string())?;
    let target = target_directory(&root)?;
    check_output_location(&output, &target)?;
    // Refuses to overwrite evidence.
    std::fs::create_dir(&output)
        .map_err(|error| format!("create {}: {error}", output.display()))?;
    let source_paths: Vec<PathBuf> = SOURCES.iter().map(PathBuf::from).collect();
    let before = fingerprint(&root, &source_paths)?;
    let diff = run_in(&root, "git", &strings(&["diff", "--binary", "HEAD"]), &[])?;
    let text = |program: &str, args: &[&str]| run_in(&root, program, &strings(args), &[]);
    let mut environment = json!({
        "revision": text("git", &["rev-parse", "HEAD"])?.trim(),
        "dirty": text("git", &["status", "--porcelain"])?,
        "toolchain": text("rustc", &["-Vv"])?,
        "os": platform(),
        "release": text("uname", &["-r"])?.trim(),
        "cpu": super::cpu_model(),
        "sources": before,
        "samples": samples,
        "repetitions": 3,
    });
    write_pretty(&output.join("environment.json"), &environment)?;
    build_runner(&root, &output)?;
    let (flags, libxml, [oracle, allocation]) = native(&root, &native_source, &output)?;
    environment["native_source"] = pinned.into();
    environment["native_flags"] = json!(flags);
    environment["libxml_version"] = libxml.into();
    write_pretty(&output.join("environment.json"), &environment)?;
    let binary = target.join("release/examples/xslt_latency");
    let corpus = output.join("corpus");
    let (corpus_paths, corpus_before) = export_corpus(&root, &binary, &corpus)?;
    write_pretty(&output.join("corpus-sha256.json"), &corpus_before)?;
    let binaries = [&binary, &oracle, &allocation]
        .into_iter()
        .map(|path| Ok(json!({ "path": path.display().to_string(), "sha256": digest_file(path)? })))
        .collect::<Result<Vec<Value>, String>>()?;
    write_pretty(&output.join("binaries.json"), &Value::Array(binaries))?;
    let observations = measure(&binary, &oracle, &corpus, &output, count, samples)?;
    // Instrumented allocation counts are kept out of the latency records.
    write(
        &output.join("allocations.txt"),
        text(
            "cargo",
            &[
                "bench",
                "--locked",
                "-p",
                "xml-sec-xslt",
                "--bench",
                "xslt",
                "--features",
                "benchmark-internals",
                "--",
                "--sample-count",
                "3",
                "--sample-size",
                "1",
            ],
        )?,
    )?;
    native_allocations(&root, &allocation, &oracle, &corpus, &output)?;
    unchanged(
        &root,
        &output,
        &before,
        &(corpus_paths, corpus_before),
        &diff,
    )?;
    write_pretty(
        &output.join("results.json"),
        &json!({ "schema": 1, "observations": observations }),
    )?;
    clean_builds(&root, &output, [&oracle, &allocation])?;
    println!(
        "XSLT measurements passed; evidence retained in {}",
        output.display()
    );
    Ok(())
}

/// Removes every build product of the run; only the evidence stays.
fn clean_builds(root: &Path, output: &Path, binaries: [&PathBuf; 2]) -> Result<(), String> {
    run_in(root, "cargo", &strings(&["clean"]), &[])?;
    for binary in binaries {
        std::fs::remove_file(binary).map_err(|error| error.to_string())?;
    }
    let build = output.join("native-build");
    run_in(
        root,
        "cmake",
        &[
            "--build".into(),
            build.display().to_string(),
            "--target".into(),
            "clean".into(),
        ],
        &[],
    )?;
    for directory in [&build, &output.join("native")] {
        std::fs::remove_dir_all(directory).map_err(|error| error.to_string())?;
    }
    Ok(())
}

pub(crate) fn run(args: impl Iterator<Item = String>) -> Result<(), Failure> {
    let args: Vec<String> = args.collect();
    let usage = || Failure::from("usage: bench-xslt NEW_OUTPUT [1..100000 samples]");
    let directory = args.first().ok_or_else(usage)?;
    let count = args.get(1).map_or("100", String::as_str);
    let samples = sample_count(count, 100_000).ok_or_else(usage)?;
    execute(
        Path::new(directory),
        count,
        usize::try_from(samples).map_err(|_| usage())?,
    )?;
    Ok(())
}
