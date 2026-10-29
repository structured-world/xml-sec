//! `bench-library COMPARISON_DIR SAMPLES`: in-process harnesses of every
//! engine on the exported corpus, at two boundaries. Produced results are
//! cross-checked by every engine before anything is timed.

use super::cli::{loader, time_args};
use super::{
    Captured, capture, case_files, cpu_model, digest_file, document_body, number, operations,
    platform, read_json, resources, safe_integer, sample_count, tamper, timestamp, wrap,
    write_json,
};
use crate::repo::Failure;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

#[cfg(test)]
mod tests;

pub(crate) const BOUNDARIES: [(&str, &str); 2] = [
    (
        "parse",
        "one in-process operation from serialized input to serialized result, parsing included; keys and trust loaded beforehand",
    ),
    (
        "prepared",
        "one in-process operation on an already parsed document, without serialization; a mutating operation receives a fresh copy outside the timer",
    ),
];
const WORKLOADS: [&str; 4] = ["assertion", "element", "element_in_place", "xslt"];

/// What one harness process established.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Outcome {
    Measured(Value),
    Rejected(Value),
    Unsupported(String),
    Failed(String),
}

/// Interprets one harness process: measured, rejected, unsupported (with its
/// reason) or failure.
pub(crate) fn harness_outcome(result: &Captured) -> Outcome {
    if let Some(error) = &result.error {
        return Outcome::Failed(error.clone());
    }
    if let Some(signal) = result.signal {
        return Outcome::Failed(format!("signal {signal}"));
    }
    let stderr = result.stderr.trim();
    match result.code {
        Some(3) => {
            return Outcome::Unsupported(
                stderr
                    .strip_prefix("unsupported: ")
                    .unwrap_or(stderr)
                    .to_owned(),
            );
        }
        Some(0) => {}
        code => {
            let reason = if stderr.is_empty() {
                format!(
                    "exit {}",
                    code.map_or_else(|| "null".into(), |code| code.to_string())
                )
            } else {
                stderr.to_owned()
            };
            return Outcome::Failed(reason);
        }
    }
    let last = result.stdout.trim().lines().last().unwrap_or_default();
    match serde_json::from_str::<Value>(last) {
        Ok(report) if report["rejected"] == true => Outcome::Rejected(report),
        Ok(report) => Outcome::Measured(report),
        Err(_) => Outcome::Failed("malformed harness report".into()),
    }
}

/// The measurement a harness was asked for.
pub(crate) struct Request<'a> {
    pub(crate) engine: &'a str,
    pub(crate) scenario: &'a str,
    pub(crate) operation: &'a str,
    pub(crate) boundary: &'a str,
    pub(crate) samples: u32,
}

/// Refuses a report that does not describe exactly the requested measurement.
pub(crate) fn validate_report(report: &Value, request: &Request<'_>) -> Result<(), String> {
    let Request {
        engine,
        scenario,
        operation,
        boundary,
        samples,
    } = *request;
    let what = format!("{engine} {scenario} {operation} {boundary}");
    if report["engine"] != engine
        || report["scenario"] != scenario
        || report["operation"] != operation
        || report["boundary"] != boundary
    {
        return Err(format!("report identity differs from request: {what}"));
    }
    let valid_samples = report["samples_ns"].as_array().is_some_and(|values| {
        values.len() == usize::try_from(samples).unwrap_or(usize::MAX)
            && values
                .iter()
                .all(|value| safe_integer(value).is_some_and(|value| value > 0.0))
    });
    if !valid_samples {
        return Err(format!("invalid timing samples: {what}"));
    }
    let allocations = &report["allocations"];
    if !allocations.is_null()
        && !["calls", "bytes", "peak_bytes"]
            .iter()
            .all(|key| safe_integer(&allocations[*key]).is_some_and(|value| value >= 0.0))
    {
        return Err(format!("invalid allocation profile: {what}"));
    }
    if !safe_integer(&report["input_bytes"]).is_some_and(|value| value > 0.0) {
        return Err("invalid input size".into());
    }
    Ok(())
}

/// One engine's harness binaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Engine {
    pub(crate) name: &'static str,
    pub(crate) id: &'static str,
    pub(crate) binary: PathBuf,
    pub(crate) profile: Option<PathBuf>,
}

/// Engines from `variable`; every binary must exist before any work starts.
pub(crate) fn engines_from(
    variable: impl Fn(&str) -> Option<String>,
) -> Result<Vec<Engine>, String> {
    let engines = [
        (
            "xml-sec / xmloxide / RustCrypto",
            "xml-sec",
            "LIBRARY_XMLSEC_BIN",
            "LIBRARY_XMLSEC_PROFILE_BIN",
        ),
        (
            "bergshamra / Uppsala / RustCrypto",
            "bergshamra",
            "LIBRARY_BERGSHAMRA_BIN",
            "LIBRARY_BERGSHAMRA_PROFILE_BIN",
        ),
        (
            "libxmlsec1 / libxml2 / OpenSSL",
            "libxmlsec1",
            "LIBRARY_LIBXMLSEC1_BIN",
            "LIBRARY_LIBXMLSEC1_PROFILE_BIN",
        ),
    ];
    engines
        .into_iter()
        .map(|(name, id, binary, profile)| {
            let resolve = |key: &str, path: String| {
                std::fs::canonicalize(path).map_err(|_| format!("Missing {key}"))
            };
            let found = variable(binary)
                .filter(|path| !path.is_empty())
                .ok_or_else(|| format!("Missing {binary}"))?;
            let profiled = variable(profile)
                .filter(|path| !path.is_empty())
                .map(|path| resolve(profile, path))
                .transpose()?;
            Ok(Engine {
                name,
                id,
                binary: resolve(binary, found)?,
                profile: profiled,
            })
        })
        .collect()
}

struct Harness<'a> {
    corpus: &'a Path,
    loader: Vec<String>,
}

impl Harness<'_> {
    /// The command line asking `binary` for `request` on `input`.
    fn line(
        &self,
        binary: &Path,
        request: &Request<'_>,
        input: &Path,
        output: Option<&Path>,
    ) -> Vec<String> {
        let mut line = self.loader.clone();
        line.push(binary.display().to_string());
        line.extend([
            request.scenario.to_owned(),
            request.operation.to_owned(),
            request.boundary.to_owned(),
            self.corpus.display().to_string(),
            input.display().to_string(),
            output.map_or_else(|| "-".into(), |output| output.display().to_string()),
            request.samples.to_string(),
        ]);
        line
    }
}

fn invoke(line: &[String]) -> Outcome {
    let mut command = Command::new(&line[0]);
    command.args(&line[1..]);
    harness_outcome(&capture(&mut command, true, Duration::from_mins(10)))
}

/// One case's validation state: refusals by `engine/operation/boundary`.
type Unsupported = BTreeMap<String, String>;

fn key(engine: &Engine, operation: &str, boundary: &str) -> String {
    format!("{}/{operation}/{boundary}", engine.id)
}

/// One case and the facts its validation established.
struct Case<'a> {
    item: &'a Value,
    name: &'a str,
    scenario: &'a str,
    producing: &'static str,
    consuming: &'static str,
    source: PathBuf,
    plain: Option<Vec<u8>>,
    unsupported: Unsupported,
}

/// A result one engine produced at one boundary.
struct Produced {
    engine: usize,
    boundary: &'static str,
    out: PathBuf,
}

fn reason(outcome: &Outcome, otherwise: &str) -> String {
    match outcome {
        Outcome::Failed(reason) | Outcome::Unsupported(reason) => reason.clone(),
        Outcome::Measured(_) | Outcome::Rejected(_) => otherwise.to_owned(),
    }
}

impl Case<'_> {
    /// Runs one probe; an unsupported operation is recorded, any other refusal fails.
    fn probe(
        &mut self,
        harness: &Harness<'_>,
        engine: &Engine,
        operation: &str,
        boundary: &str,
        input: &Path,
        out: &Path,
    ) -> Result<bool, String> {
        let request = Request {
            engine: engine.id,
            scenario: self.scenario,
            operation,
            boundary,
            samples: 1,
        };
        match invoke(&harness.line(&engine.binary, &request, input, Some(out))) {
            Outcome::Unsupported(reason) => {
                self.unsupported
                    .insert(key(engine, operation, boundary), reason);
                Ok(false)
            }
            Outcome::Measured(report) => {
                validate_report(&report, &request)?;
                Ok(true)
            }
            other => Err(format!(
                "{} {operation} {boundary}, {}: {}",
                engine.name,
                self.name,
                reason(&other, "unexpected rejection")
            )),
        }
    }

    /// XML results may differ only in the declaration and surrounding whitespace.
    fn check_plaintext(
        &self,
        out: &Path,
        origin: &str,
        engine: &Engine,
        boundary: &str,
    ) -> Result<(), String> {
        let Some(plain) = &self.plain else {
            return Ok(());
        };
        let decrypted =
            std::fs::read(out).map_err(|error| format!("{}: {error}", out.display()))?;
        if document_body(&decrypted) != document_body(plain) {
            return Err(format!(
                "Plaintext mismatch: {origin} -> {} {boundary}, {}",
                engine.name, self.name
            ));
        }
        Ok(())
    }
}

/// Every produced result must be consumed by every engine that consumes the
/// workload before anything is timed. The xml-sec result is the timed input,
/// or the first engine's when xml-sec refuses the input under its default policy.
fn validate_case(
    harness: &Harness<'_>,
    engines: &[Engine],
    case: &mut Case<'_>,
    work: &Path,
) -> Result<PathBuf, String> {
    let name = case.name;
    let mut produced = Vec::new();
    for (index, engine) in engines.iter().enumerate() {
        for (boundary, _) in BOUNDARIES {
            let out = work.join(format!(
                "{name}.{}-{}-{boundary}.xml",
                case.producing, engine.id
            ));
            let source = case.source.clone();
            if case.probe(harness, engine, case.producing, boundary, &source, &out)? {
                produced.push(Produced {
                    engine: index,
                    boundary,
                    out,
                });
            }
        }
    }
    let parsed: Vec<&Produced> = produced
        .iter()
        .filter(|entry| entry.boundary == "parse")
        .collect();
    let canonical = parsed
        .iter()
        .find(|entry| engines[entry.engine].id == "xml-sec")
        .or_else(|| parsed.first())
        .ok_or_else(|| format!("no engine produced a {} result for {name}", case.producing))?;
    let (canonical_out, canonical_origin) = (
        canonical.out.clone(),
        format!("{} {}", engines[canonical.engine].name, canonical.boundary),
    );
    if case.scenario == "assertion" {
        for entry in &produced {
            let text = std::fs::read_to_string(&entry.out).map_err(|error| error.to_string())?;
            if !text.contains("X509Certificate>") {
                return Err(format!(
                    "No signer certificate: {}, {name}",
                    engines[entry.engine].name
                ));
            }
        }
    }
    for engine in engines {
        for (boundary, _) in BOUNDARIES {
            // Each boundary is timed on its own, so its result is checked on its own.
            let probed = work.join(format!(
                "{name}.{}-probe-{}-{boundary}.xml",
                case.consuming, engine.id
            ));
            if !case.probe(
                harness,
                engine,
                case.consuming,
                boundary,
                &canonical_out,
                &probed,
            )? {
                continue;
            }
            case.check_plaintext(&probed, &canonical_origin, engine, boundary)?;
            if boundary == "parse" {
                cross_check(
                    harness,
                    engines,
                    case,
                    engine,
                    &produced,
                    &canonical_out,
                    work,
                )?;
            }
        }
    }
    Ok(canonical_out)
}

/// `engine` consumes every produced result; a verifier also refuses forgeries.
fn cross_check(
    harness: &Harness<'_>,
    engines: &[Engine],
    case: &Case<'_>,
    engine: &Engine,
    produced: &[Produced],
    canonical: &Path,
    work: &Path,
) -> Result<(), String> {
    let name = case.name;
    let request = |operation| Request {
        engine: engine.id,
        scenario: case.scenario,
        operation,
        boundary: "parse",
        samples: 1,
    };
    for entry in produced {
        let out = work.join(format!("{name}.{}-{}.xml", case.consuming, engine.id));
        let outcome = invoke(&harness.line(
            &engine.binary,
            &request(case.consuming),
            &entry.out,
            Some(&out),
        ));
        let origin = format!("{} {}", engines[entry.engine].name, entry.boundary);
        if !matches!(outcome, Outcome::Measured(_)) {
            return Err(format!(
                "{} cannot {} {origin} output, {name}: {}",
                engine.name,
                case.consuming,
                reason(&outcome, "rejected")
            ));
        }
        case.check_plaintext(&out, &origin, engine, "parse")?;
    }
    if case.consuming == "verify" {
        let signed = std::fs::read_to_string(canonical).map_err(|error| error.to_string())?;
        let mut forged = vec![("tampered", tamper(&signed, case.scenario)?)];
        if case.scenario == "assertion" {
            forged.push(("wrapped", wrap(&signed)?));
        }
        for (kind, text) in forged {
            let input = work.join(format!("{name}.{kind}.xml"));
            std::fs::write(&input, text).map_err(|error| error.to_string())?;
            let outcome = invoke(&harness.line(&engine.binary, &request("reject"), &input, None));
            if !matches!(outcome, Outcome::Rejected(_)) {
                return Err(format!("Invalid {kind} rejection: {}, {name}", engine.name));
            }
        }
    }
    Ok(())
}

/// The entry fields every result of `engine` shares, in report order.
fn entry(
    case: &Case<'_>,
    engine: &Engine,
    operation: &str,
    boundary: &str,
    description: &str,
) -> Map<String, Value> {
    let mut entry = Map::new();
    entry.insert("level".into(), "library".into());
    entry.insert("engine".into(), engine.name.into());
    entry.insert("operation".into(), operation.into());
    entry.insert("boundary".into(), boundary.into());
    entry.extend(case.item.as_object().cloned().unwrap_or_default());
    entry.insert("boundary_description".into(), description.into());
    entry
}

/// The GNU time metrics line removed from a harness's diagnostics.
fn without_metrics(stderr: &str) -> String {
    match stderr.find("__METRICS ") {
        Some(start) => stderr[..start]
            .strip_suffix('\n')
            .unwrap_or(&stderr[..start])
            .to_owned(),
        None => stderr.to_owned(),
    }
}

/// Three rotated repetitions of `samples` timings for each supported engine.
fn time_operation(
    harness: &Harness<'_>,
    engines: &[&Engine],
    case: &Case<'_>,
    operation: &str,
    boundary: &str,
    input: &Path,
    samples: u32,
) -> Result<Vec<Map<String, Value>>, String> {
    let description = BOUNDARIES
        .iter()
        .find(|(name, _)| *name == boundary)
        .map_or("", |(_, text)| text);
    let mut entries: Vec<Map<String, Value>> = engines
        .iter()
        .map(|engine| {
            let mut entry = entry(case, engine, operation, boundary, description);
            entry.insert("repetitions".into(), json!([]));
            entry.insert("memory".into(), Value::Null);
            entry
        })
        .collect();
    for repetition in 0..3 {
        for step in 0..engines.len() {
            // Rotate order so no engine always runs first.
            let index = (step + repetition) % engines.len();
            let engine = engines[index];
            let request = Request {
                engine: engine.id,
                scenario: case.scenario,
                operation,
                boundary,
                samples,
            };
            let (report, summary) =
                repetition_summary(harness, engine, case.name, &request, input)?;
            entries[index].insert("input_bytes".into(), report["input_bytes"].clone());
            entries[index]["repetitions"]
                .as_array_mut()
                .expect("repetitions list")
                .push(summary);
        }
    }
    for (index, engine) in engines.iter().enumerate() {
        if let Some(profile) = &engine.profile {
            let request = Request {
                engine: engine.id,
                scenario: case.scenario,
                operation,
                boundary,
                samples: 1,
            };
            let memory = allocation_profile(harness, engine, profile, case.name, &request, input)?;
            entries[index].insert("memory".into(), memory);
        }
    }
    Ok(entries)
}

/// One timed harness process: its report and the repetition summary.
fn repetition_summary(
    harness: &Harness<'_>,
    engine: &Engine,
    name: &str,
    request: &Request<'_>,
    input: &Path,
) -> Result<(Value, Value), String> {
    let mut command = Command::new("/usr/bin/time");
    command.args(time_args());
    command.args(harness.line(&engine.binary, request, input, None));
    let measured = capture(&mut command, true, Duration::from_mins(30));
    // GNU time appends its metrics line to the harness's stderr.
    let outcome = harness_outcome(&Captured {
        stderr: without_metrics(&measured.stderr),
        ..measured.clone()
    });
    let Outcome::Measured(report) = outcome else {
        return Err(format!(
            "{} {} {}, {name}: {}",
            engine.name,
            request.operation,
            request.boundary,
            reason(&outcome, "rejected")
        ));
    };
    validate_report(&report, request)?;
    let raw: Vec<f64> = report["samples_ns"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_f64)
        .collect();
    let (cpu, rss) = resources(&measured.stderr, platform())?;
    let summary = json!({
        "raw": report["samples_ns"],
        "p50_ns": number(super::percentile(&raw, 50)?),
        "p95_ns": number(super::percentile(&raw, 95)?),
        "p99_ns": number(super::percentile(&raw, 99)?),
        "cpu_seconds": number(cpu),
        "rss_bytes": number(rss),
        "rss_scope": "whole process including key loading, warmups and every sample",
    });
    Ok((report, summary))
}

/// The allocation profile of one operation from the engine's instrumented build.
fn allocation_profile(
    harness: &Harness<'_>,
    engine: &Engine,
    profile: &Path,
    name: &str,
    request: &Request<'_>,
    input: &Path,
) -> Result<Value, String> {
    let outcome = invoke(&harness.line(profile, request, input, None));
    let Outcome::Measured(report) = outcome else {
        return Err(format!(
            "{} allocation profile {} {}, {name}: {}",
            engine.name,
            request.operation,
            request.boundary,
            reason(&outcome, "rejected")
        ));
    };
    validate_report(&report, request)?;
    let allocations = &report["allocations"];
    if allocations.is_null() {
        return Err(format!(
            "{} profile build reported no allocations",
            engine.name
        ));
    }
    Ok(json!({
        "allocation_calls": allocations["calls"],
        "allocated_bytes": allocations["bytes"],
        "peak_heap_bytes": allocations["peak_bytes"],
        "scope": "every heap allocation in the process during one operation, from a separate instrumented build",
    }))
}

fn run_case(
    harness: &Harness<'_>,
    engines: &[Engine],
    item: &Value,
    work: &Path,
    samples: u32,
) -> Result<Vec<Value>, String> {
    let name = item["name"].as_str().unwrap_or_default();
    let scenario = item["scenario"].as_str().unwrap_or_default();
    let operations = operations(scenario)?;
    let producing = if operations.contains(&"sign") {
        "sign"
    } else {
        "encrypt"
    };
    let files = case_files(name, scenario, &item["units"]);
    let source = harness.corpus.join(if producing == "sign" {
        &files.template
    } else {
        &files.plain
    });
    let plain = if producing == "encrypt" {
        Some(std::fs::read(&source).map_err(|error| error.to_string())?)
    } else {
        None
    };
    let mut case = Case {
        item,
        name,
        scenario,
        producing,
        consuming: if producing == "sign" {
            "verify"
        } else {
            "decrypt"
        },
        source,
        plain,
        unsupported: Unsupported::new(),
    };
    let canonical = validate_case(harness, engines, &mut case, work)?;
    let mut results = Vec::new();
    for operation in operations {
        for (boundary, description) in BOUNDARIES {
            let input = if *operation == producing {
                case.source.clone()
            } else {
                canonical.clone()
            };
            let supported: Vec<&Engine> = engines
                .iter()
                .filter(|engine| {
                    !case
                        .unsupported
                        .contains_key(&key(engine, operation, boundary))
                })
                .collect();
            results.extend(
                time_operation(
                    harness, &supported, &case, operation, boundary, &input, samples,
                )?
                .into_iter()
                .map(Value::Object),
            );
            for engine in engines {
                if let Some(reason) = case.unsupported.get(&key(engine, operation, boundary)) {
                    let mut entry = entry(&case, engine, operation, boundary, description);
                    entry.insert("unsupported".into(), reason.clone().into());
                    results.push(Value::Object(entry));
                }
            }
        }
    }
    Ok(results)
}

pub(crate) fn run(args: impl Iterator<Item = String>) -> Result<(), Failure> {
    let args: Vec<String> = args.collect();
    let usage = || Failure::from("Usage: bench-library COMPARISON_DIR SAMPLES");
    let (Some(output), Some(samples)) = (
        args.first(),
        args.get(1).and_then(|samples| sample_count(samples, 1000)),
    ) else {
        return Err(usage());
    };
    if !matches!(platform(), "linux" | "darwin") {
        return Err("CPU/RSS requires Linux or macOS".into());
    }
    let engines = engines_from(|name| std::env::var(name).ok())?;
    execute(Path::new(output), samples, &engines)?;
    Ok(())
}

/// Validates and times every library case of the corpus in `output`, then
/// writes `library.json` there.
pub(crate) fn execute(output: &Path, samples: u32, engines: &[Engine]) -> Result<(), String> {
    let root = std::fs::canonicalize(output).map_err(|error| error.to_string())?;
    let corpus = root.join("corpus");
    let work = root.join("library");
    // Refuses to overwrite earlier evidence.
    std::fs::create_dir(&work).map_err(|error| format!("create {}: {error}", work.display()))?;
    let harness = Harness {
        corpus: &corpus,
        loader: loader(),
    };
    let cases = read_json(&corpus.join("cases.json"))?;
    let mut results = Vec::new();
    for item in cases.as_array().into_iter().flatten() {
        if WORKLOADS.contains(&item["scenario"].as_str().unwrap_or_default()) {
            results.extend(run_case(&harness, engines, item, &work, samples)?);
        }
    }
    let mut binaries = Vec::new();
    for engine in engines {
        for binary in [Some(&engine.binary), engine.profile.as_ref()]
            .into_iter()
            .flatten()
        {
            let bytes = std::fs::metadata(binary)
                .map_err(|error| error.to_string())?
                .len();
            binaries.push(
                json!({ "engine": engine.id, "sha256": digest_file(binary)?, "bytes": bytes }),
            );
        }
    }
    let boundaries: Map<String, Value> = BOUNDARIES
        .iter()
        .map(|(name, text)| ((*name).to_owned(), Value::from(*text)))
        .collect();
    let report = json!({
        "schema": 1,
        "generated": timestamp(),
        "environment": {
            "platform": platform(),
            "architecture": super::architecture(),
            "cpu": cpu_model(),
            "samples": samples,
            "repetitions": 3,
            "timing": "in-process monotonic clock around each operation; three warmups per process",
            "memory": "allocation profiles come from separate instrumented builds and are never timed",
        },
        "boundaries": boundaries,
        "binaries": binaries,
        "results": results,
    });
    write_json(&root.join("library.json"), &report)?;
    let measured = results
        .iter()
        .filter(|entry| entry.get("unsupported").is_none())
        .count();
    println!(
        "Validated {measured} library cases, {} unsupported; {samples} samples x 3 repetitions",
        results.len() - measured
    );
    Ok(())
}
