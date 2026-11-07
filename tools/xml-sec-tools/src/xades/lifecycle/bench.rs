//! `xades lifecycle --bench SAMPLES [--cold SAMPLES] [--cases PACKAGING-ALGORITHM,...]`:
//! the lifecycle operations xml-sec and EU DSS both perform, timed over the
//! same input at the same boundaries.
//!
//! xml-sec makes a qualified chain over the run's PKI: B-B, B-T, B-LT and
//! B-LTA, each read by DSS at its level. Every operation starts from the same
//! chain document for both implementations, and each result is read by the
//! other implementation before anything is timed. An operation whose result
//! the other implementation does not accept at its level is recorded with that
//! reading and never timed: its work is not equivalent. A validation is timed
//! only when both implementations accept its input.
//!
//! Timestamp tokens are acquired once, by the run that qualifies a result, and
//! replayed afterwards; a timed run is given no TSA and fails if it would
//! acquire. Warm samples run in one process after warmups, three repetitions
//! per implementation, with process CPU and RSS from `/usr/bin/time`. Cold
//! samples start a fresh process each: native start or JVM start included.
//! Native allocations come from a separate instrumented build; JVM thread
//! allocation, GC and heap counters are reported apart from them, as the
//! different metrics they are.

use super::{Actor, Algorithm, Case, Evidence, Packaging, Run, Step, date_time, now, refusal};
use crate::bench::cli::{loader, time_args};
use crate::bench::{
    architecture, capture, cpu_model, digest_file, number, percentile, platform, resources,
    timestamp, to_f64,
};
use crate::xades::{Build, Corpus, line, write_json};
use serde_json::{Map, Value, json};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

#[cfg(test)]
mod tests;

/// Repetitions of every warm and cold measurement, in alternating order.
const REPETITIONS: usize = 3;

/// What one sample of each boundary contains.
pub(crate) const BOUNDARIES: [(&str, &str); 3] = [
    (
        "warm",
        "one in-process run from the serialized input to the serialized output; keys, anchors and evidence are loaded and the run's warmups, the same count for both implementations, precede the samples",
    ),
    (
        "cold",
        "one fresh process per sample: native or JVM start, loading keys, anchors and evidence, the run and writing its output; wall time includes the launch of the measuring /usr/bin/time",
    ),
    (
        "acquisition",
        "not measured: every timestamp token is acquired once before timing and replayed; a timed run that would acquire fails",
    ),
];

/// A lifecycle operation both implementations perform.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Operation {
    Create,
    ValidateBasic,
    AugmentT,
    AugmentLt,
    AugmentLta,
    Renew,
    ValidateArchival,
}

impl Operation {
    pub(crate) const ALL: [Self; 7] = [
        Self::Create,
        Self::ValidateBasic,
        Self::AugmentT,
        Self::AugmentLt,
        Self::AugmentLta,
        Self::Renew,
        Self::ValidateArchival,
    ];

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::ValidateBasic => "validate-b",
            Self::AugmentT => "augment-t",
            Self::AugmentLt => "augment-lt",
            Self::AugmentLta => "augment-lta",
            Self::Renew => "renew",
            Self::ValidateArchival => "validate-lta",
        }
    }

    /// The level its result, or for a validation its input, is read at.
    pub(crate) fn level(self) -> &'static str {
        match self {
            Self::Create | Self::ValidateBasic => "b",
            Self::AugmentT => "t",
            Self::AugmentLt => "lt",
            Self::AugmentLta | Self::Renew | Self::ValidateArchival => "lta",
        }
    }

    /// The chain document it starts from; the signed data for creation.
    pub(crate) fn input(self) -> Option<&'static str> {
        match self {
            Self::Create => None,
            Self::ValidateBasic | Self::AugmentT => Some("b"),
            Self::AugmentLt => Some("t"),
            Self::AugmentLta => Some("lt"),
            Self::Renew | Self::ValidateArchival => Some("lta"),
        }
    }

    pub(crate) fn validates(self) -> bool {
        matches!(self, Self::ValidateBasic | Self::ValidateArchival)
    }

    /// The step `lifecycle_probe augment` takes, and the level DSS extends to.
    fn step(self) -> (&'static str, &'static str) {
        match self {
            Self::AugmentT => ("t", "T"),
            Self::AugmentLt => ("lt", "LT"),
            Self::AugmentLta => ("lta", "LTA"),
            _ => ("renew", "LTA"),
        }
    }

    /// The operation `engine`'s harness names in its report.
    pub(crate) fn reported(self, engine: Actor) -> &'static str {
        match (self, engine) {
            (Self::Renew, Actor::XmlSec) => "augment-renew",
            (Self::Renew, Actor::Dss) => "augment-lta",
            _ => self.name(),
        }
    }
}

/// Whether the other implementation's `reading` of a result `maker` made
/// accepts it at `level`. DSS must find the signature intact in that baseline
/// format, and with complete evidence (B-LT and above) `TOTAL_PASSED`. xml-sec
/// reads DSS's tokens under its CMS profile (RFC 5652 BER), which it supports
/// for them, and must find the level met.
pub(crate) fn qualified(maker: Actor, level: &str, reading: &Value) -> bool {
    match maker {
        Actor::XmlSec => {
            reading["crypto"] == "intact"
                && reading["structure"] == format!("XAdES-BASELINE-{}", level.to_uppercase())
                && (matches!(level, "b" | "t") || reading["trust"] == "TOTAL_PASSED/null")
        }
        Actor::Dss => reading["crypto"] == "Valid" && reading["structure_ber"] == "met",
    }
}

/// Whether `engine`'s own validation `output` accepts its input at `level`.
pub(crate) fn accepted(engine: Actor, level: &str, output: &str) -> bool {
    match engine {
        Actor::XmlSec => {
            output.contains("signature: Ok(Valid)") && output.contains("level: Ok(Assessed(true))")
        }
        Actor::Dss => {
            let format = format!("format=XAdES-BASELINE-{} ", level.to_uppercase());
            output.lines().next().is_some_and(|line| {
                line.contains(&format)
                    && (matches!(level, "b" | "t") || line.contains("indication=TOTAL_PASSED "))
            })
        }
    }
}

/// The report a harness printed last, if it is the one requested.
pub(crate) fn report(
    stdout: &str,
    engine: Actor,
    operation: Operation,
    samples: usize,
) -> Result<Value, String> {
    let what = format!("{} {}", engine.name(), operation.name());
    let last = stdout.trim().lines().last().unwrap_or_default();
    let report: Value =
        serde_json::from_str(last).map_err(|_| format!("{what}: malformed harness report"))?;
    if report["engine"] != engine.name() || report["operation"] != operation.reported(engine) {
        return Err(format!("{what}: the report describes another measurement"));
    }
    let valid = report["samples_ns"].as_array().is_some_and(|values| {
        values.len() == samples
            && values
                .iter()
                .all(|value| value.as_u64().is_some_and(|value| value > 0))
    });
    if !valid {
        return Err(format!("{what}: invalid timing samples"));
    }
    Ok(report)
}

/// Raw samples in nanoseconds with their nearest-rank percentiles.
pub(crate) fn distribution(raw: &[u64]) -> Result<Map<String, Value>, String> {
    let values: Vec<f64> = raw.iter().copied().map(to_f64).collect();
    let mut summary = Map::new();
    summary.insert("raw_ns".into(), json!(raw));
    for (name, percent) in [("p50_ns", 50), ("p95_ns", 95), ("p99_ns", 99)] {
        summary.insert(name.into(), number(percentile(&values, percent)?));
    }
    Ok(summary)
}

/// The probe binaries the measurement runs, copied out of the build so a
/// later build with other features cannot replace them.
struct Binaries {
    lifecycle: PathBuf,
    level: PathBuf,
    lifecycle_profile: PathBuf,
    level_profile: PathBuf,
}

impl Binaries {
    fn build(corpus: &Corpus, directory: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(directory).map_err(|error| error.to_string())?;
        let build = |name: &str, features: &[&str], copy: &str| {
            let built = corpus.build_example(
                name,
                features,
                Build::Release,
                &directory.join(format!("{copy}-build")),
            )?;
            let copied = directory.join(copy);
            std::fs::copy(&built, &copied)
                .map_err(|error| format!("copy {}: {error}", built.display()))?;
            Ok::<_, String>(copied)
        };
        Ok(Self {
            lifecycle: build("lifecycle_probe", &["produce"], "lifecycle_probe")?,
            level: build("level_probe", &[], "level_probe")?,
            lifecycle_profile: build(
                "lifecycle_probe",
                &["produce", "allocation-profile"],
                "lifecycle_probe-profile",
            )?,
            level_profile: build(
                "level_probe",
                &["allocation-profile"],
                "level_probe-profile",
            )?,
        })
    }

    fn describe(&self) -> Result<Vec<Value>, String> {
        [
            &self.lifecycle,
            &self.level,
            &self.lifecycle_profile,
            &self.level_profile,
        ]
        .iter()
        .map(|binary| {
            Ok(json!({
                "name": binary.file_name().map(|name| name.to_string_lossy().into_owned()),
                "sha256": digest_file(binary)?,
            }))
        })
        .collect()
    }
}

/// What one operation of one case needs to run.
struct Target<'a> {
    case: Case,
    operation: Operation,
    input: PathBuf,
    evidence: &'a Path,
    /// Where each implementation's files of this operation go.
    directory: PathBuf,
}

impl Target<'_> {
    fn directory(&self, engine: Actor) -> PathBuf {
        self.directory.join(engine.name())
    }

    /// Where `engine`'s qualifying result goes: the output of its step.
    fn output(&self, engine: Actor) -> PathBuf {
        self.directory(engine)
            .join(format!("{}.xml", self.operation.level()))
    }
}

/// How a harness run is made.
#[derive(Clone, Copy)]
enum Mode {
    /// The qualifying run: it may acquire tokens at this Unix time, and
    /// records them.
    Record(u64),
    /// A timed run of `n` samples in one process, or with `None` one run.
    Timed(Option<usize>),
    /// The instrumented build counting one run's allocations.
    Profile,
}

impl Mode {
    fn samples(self) -> Option<usize> {
        match self {
            Self::Timed(samples) => samples,
            Self::Profile => Some(1),
            Self::Record(_) => None,
        }
    }
}

/// A measurement of one process: its capture and its wall time.
struct Timed {
    stdout: String,
    stderr: String,
    wall_ns: u64,
}

struct Bench<'a> {
    run: &'a Run<'a>,
    binaries: &'a Binaries,
    /// The signing time of every creation, in Unix seconds.
    time: u64,
    /// Untimed runs before the warm samples of either implementation: enough
    /// for the JVM's compiler to settle, the same count for the native side.
    warmups: usize,
}

impl Bench<'_> {
    /// The command line of `engine` for `target` in `mode`, writing `output`.
    fn command(
        &self,
        engine: Actor,
        target: &Target<'_>,
        mode: Mode,
        output: &Path,
    ) -> Vec<OsString> {
        let mut args = match engine {
            Actor::XmlSec => self.xml_sec(target, mode, output),
            Actor::Dss => self.dss(target, mode, output),
        };
        if let Some(samples) = mode.samples() {
            args.extend(line(&[
                &"--samples",
                &samples.to_string(),
                &"--warmups",
                &self.warmups.to_string(),
            ]));
        }
        args
    }

    fn xml_sec(&self, target: &Target<'_>, mode: Mode, output: &Path) -> Vec<OsString> {
        let (run, case) = (self.run, target.case);
        let profile = matches!(mode, Mode::Profile);
        let lifecycle = if profile {
            &self.binaries.lifecycle_profile
        } else {
            &self.binaries.lifecycle
        };
        let operation = target.operation;
        let mut args = if operation == Operation::Create {
            line(&[
                lifecycle,
                &"create",
                &case.algorithm.name(),
                &case.packaging.name(),
                &run.pki.join(case.algorithm.name()),
                &run.data(case),
                &date_time(self.time),
                &run.at.to_string(),
                &output,
            ])
        } else if operation.validates() {
            line(&[
                if profile {
                    &self.binaries.level_profile
                } else {
                    &self.binaries.level
                },
                &target.input,
                &run.pki.join("root.der"),
                &run.at.to_string(),
                &operation.level(),
                &"1",
            ])
        } else {
            line(&[
                lifecycle,
                &"augment",
                &operation.step().0,
                &run.pki,
                &target.evidence,
                &run.at.to_string(),
                &target.input,
                &output,
                &"--accuracy",
                &"1",
                &"--tokens",
                &target.directory(Actor::XmlSec).join("tokens"),
            ])
        };
        if operation != Operation::Create {
            args.extend(detached_option(run, case));
        }
        if operation != Operation::Create && !operation.validates() {
            args.push("--".into());
            if matches!(mode, Mode::Record(_)) {
                args.extend(line(&[
                    &run.corpus.openssl,
                    &"ts",
                    &"-reply",
                    &"-config",
                    &run.pki.join("tsa.cnf"),
                    &"-queryfile",
                    &"{request}",
                    &"-out",
                    &"{response}",
                ]));
            }
        }
        args
    }

    fn dss(&self, target: &Target<'_>, mode: Mode, output: &Path) -> Vec<OsString> {
        let (run, case) = (self.run, target.case);
        let mut args = run.java("LifecycleBench");
        let operation = target.operation;
        if operation == Operation::Create {
            args.extend(line(&[
                &"create",
                &run.pki.join(format!("{}.p12", case.algorithm.signer())),
                &case.packaging.dss(),
                &run.data(case),
                &self.time.to_string(),
                &output,
            ]));
            return args;
        }
        if operation.validates() {
            args.extend(line(&[
                &"validate",
                &target.input,
                &run.pki.join("root.der"),
                &run.at.to_string(),
                &operation.level(),
                &output,
            ]));
        } else {
            args.extend(line(&[
                &"augment",
                &target.input,
                &output,
                &operation.step().1,
                &run.pki.join("root.der"),
                &target.evidence,
                &target.directory(Actor::Dss).join("tokens"),
            ]));
            if let Mode::Record(time) = mode {
                args.extend(line(&[
                    &"--tsa",
                    &run.pki.join("tsa.p12"),
                    &"--tsa-time",
                    &time.to_string(),
                ]));
            }
        }
        args.extend(detached_option(run, case));
        args
    }

    /// Makes `engine`'s result of `target` once, recording its tokens, and
    /// reads it: whether it is qualified, and the reading that decided.
    fn qualify(&self, engine: Actor, target: &Target<'_>) -> Result<(bool, Value), String> {
        let directory = target.directory(engine);
        std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
        let output = target.output(engine);
        let args = self.command(engine, target, Mode::Record(now()?), &output);
        let made = self.run.corpus.command(&args, &directory.join("record"))?;
        let (stdout, stderr) = (
            String::from_utf8_lossy(&made.stdout),
            String::from_utf8_lossy(&made.stderr),
        );
        if !made.success() {
            return Ok((false, json!({ "refused": refusal(&stdout, &stderr) })));
        }
        let level = target.operation.level();
        if target.operation.validates() {
            // xml-sec reports its levels on stdout, DSS in its output file.
            let text = match engine {
                Actor::XmlSec => stdout.into_owned(),
                Actor::Dss => crate::xades::read(&output)
                    .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())?,
            };
            return Ok((accepted(engine, level, &text), json!(text.trim())));
        }
        let step = Step {
            case: target.case,
            name: level,
            actor: engine,
            directory: &directory,
            evidence: target.evidence,
        };
        let reading = self.run.validate(&step)?;
        Ok((qualified(engine, level, &reading), reading))
    }

    /// Runs `args` under `/usr/bin/time`; anything but success fails the run.
    fn timed(args: &[OsString]) -> Result<Timed, String> {
        let mut command = Command::new("/usr/bin/time");
        command.args(time_args()).args(loader()).args(args);
        let start = Instant::now();
        let captured = capture(&mut command, true, Duration::from_mins(30));
        let wall = start.elapsed();
        if !captured.succeeded() {
            return Err(format!(
                "{} failed: {}\n{}",
                args.first()
                    .map(|program| program.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                captured.failure(),
                captured.stderr
            ));
        }
        Ok(Timed {
            stdout: captured.stdout,
            stderr: captured.stderr,
            wall_ns: u64::try_from(wall.as_nanos()).map_err(|_| "wall time exceeds u64")?,
        })
    }

    /// One warm repetition: `samples` timed runs in one process.
    fn warm(&self, engine: Actor, target: &Target<'_>, samples: usize) -> Result<Value, String> {
        let output = target.directory(engine).join("timed.out");
        let args = self.command(engine, target, Mode::Timed(Some(samples)), &output);
        let measured = Self::timed(&args)?;
        let report = report(&measured.stdout, engine, target.operation, samples)?;
        let raw: Vec<u64> = report["samples_ns"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_u64)
            .collect();
        let mut summary = distribution(&raw)?;
        let (cpu, rss) = resources(&measured.stderr, platform())?;
        summary.insert("cpu_seconds".into(), number(cpu));
        summary.insert("rss_bytes".into(), number(rss));
        if !report["jvm"].is_null() {
            summary.insert("jvm".into(), report["jvm"].clone());
        }
        summary.insert("input_bytes".into(), report["input_bytes"].clone());
        summary.insert("output_bytes".into(), report["output_bytes"].clone());
        Ok(Value::Object(summary))
    }

    /// One cold repetition: `count` fresh processes of one run each.
    fn cold(&self, engine: Actor, target: &Target<'_>, count: usize) -> Result<Value, String> {
        let output = target.directory(engine).join("timed.out");
        let args = self.command(engine, target, Mode::Timed(None), &output);
        let (mut walls, mut cpu, mut rss) = (Vec::new(), Vec::new(), Vec::new());
        for _ in 0..count {
            let measured = Self::timed(&args)?;
            let (seconds, bytes) = resources(&measured.stderr, platform())?;
            walls.push(measured.wall_ns);
            cpu.push(number(seconds));
            rss.push(number(bytes));
        }
        let mut summary = distribution(&walls)?;
        summary.insert("cpu_seconds".into(), Value::Array(cpu));
        summary.insert("rss_bytes".into(), Value::Array(rss));
        Ok(Value::Object(summary))
    }

    /// The native allocations of one run, from the instrumented build.
    fn allocations(&self, target: &Target<'_>) -> Result<Value, String> {
        let output = target.directory(Actor::XmlSec).join("profiled.out");
        let args = self.command(Actor::XmlSec, target, Mode::Profile, &output);
        let measured = Self::timed(&args)?;
        let report = report(&measured.stdout, Actor::XmlSec, target.operation, 1)?;
        if report["allocations"].is_null() {
            return Err("the instrumented build reported no allocations".into());
        }
        Ok(report["allocations"].clone())
    }

    /// Every entry of one operation: qualified implementations measured in
    /// alternating order, the others recorded with their reading.
    fn operation(
        &self,
        target: &Target<'_>,
        samples: usize,
        cold: usize,
    ) -> Result<Vec<Value>, String> {
        let mut entries = Vec::new();
        let mut measured = Vec::new();
        for engine in [Actor::XmlSec, Actor::Dss] {
            let (qualified, reading) = self.qualify(engine, target)?;
            let mut entry = Map::new();
            entry.insert("engine".into(), engine.name().into());
            entry.insert("operation".into(), target.operation.name().into());
            entry.insert("qualified".into(), qualified.into());
            entry.insert("reading".into(), reading);
            if qualified {
                measured.push((engine, entries.len()));
            } else {
                let reason = if entry["reading"].get("refused").is_some() {
                    "the implementation refused the operation"
                } else if target.operation.validates() {
                    "the implementation does not accept this input"
                } else {
                    "the other implementation does not accept the result at its level"
                };
                entry.insert("not_measured".into(), reason.into());
            }
            entries.push(entry);
        }
        if target.operation.validates() && measured.len() < 2 {
            // A validation is equivalent work only when both accept the input.
            for (_, index) in measured.drain(..) {
                entries[index].insert("qualified".into(), false.into());
                entries[index].insert(
                    "not_measured".into(),
                    "the other implementation does not accept this input".into(),
                );
            }
        }
        for (_, index) in &measured {
            entries[*index].insert("warm".into(), json!([]));
            entries[*index].insert("cold".into(), json!([]));
        }
        for repetition in 0..REPETITIONS {
            for step in 0..measured.len() {
                // Alternate the order so neither implementation always runs first.
                let (engine, index) = measured[(step + repetition) % measured.len()];
                let warm = self.warm(engine, target, samples)?;
                let cold = self.cold(engine, target, cold)?;
                for (key, value) in [("warm", warm), ("cold", cold)] {
                    if let Some(list) = entries[index].get_mut(key).and_then(Value::as_array_mut) {
                        list.push(value);
                    }
                }
            }
        }
        for (engine, index) in &measured {
            let allocations = match engine {
                Actor::XmlSec => self.allocations(target)?,
                Actor::Dss => json!(
                    "not measured: a JVM has no native allocation counter; see the jvm counters of each warm repetition"
                ),
            };
            entries[*index].insert("allocations".into(), allocations);
        }
        Ok(entries.into_iter().map(Value::Object).collect())
    }

    /// The qualified chain xml-sec makes over `case`: B-B, B-T, B-LT and
    /// B-LTA, each accepted by DSS at its level.
    fn chain(&self, case: Case, directory: &Path, evidence: &Path) -> Result<(), String> {
        for (name, previous) in [
            ("b", None),
            ("t", Some("b")),
            ("lt", Some("t")),
            ("lta", Some("lt")),
        ] {
            if name == "lt" || name == "lta" {
                // Strictly after the token it follows, at one-second resolution.
                std::thread::sleep(Duration::from_secs(1));
                if name == "lt" {
                    self.run.evidence(case, evidence)?;
                }
            }
            let step = Step {
                case,
                name,
                actor: Actor::XmlSec,
                directory,
                evidence,
            };
            let input = previous.map(|previous| directory.join(format!("{previous}.xml")));
            let made = self.run.make(&step, input.as_deref())?;
            if made != "made" {
                return Err(format!("xml-sec could not make the chain's {name}: {made}"));
            }
            let reading = self.run.validate(&step)?;
            if !qualified(Actor::XmlSec, name, &reading) {
                return Err(format!("DSS does not accept the chain's {name}: {reading}"));
            }
        }
        Ok(())
    }
}

fn detached_option(run: &Run<'_>, case: Case) -> Vec<OsString> {
    run.detached(case)
        .map(|detached| line(&[&"--detached", &detached]))
        .unwrap_or_default()
}

/// The packaging and signer of a measured case, as `PACKAGING-ALGORITHM`.
pub(crate) fn case_name(packaging: Packaging, algorithm: Algorithm) -> String {
    format!("{}-{}", packaging.name(), algorithm.name())
}

/// Every case, or those `selection` names, each once: a case owns its
/// directories and recorded timestamps for the whole run.
pub(crate) fn selected(selection: Option<&str>) -> Result<Vec<(Packaging, Algorithm)>, String> {
    let all: Vec<(Packaging, Algorithm)> = Packaging::ALL
        .iter()
        .flat_map(|packaging| {
            [Algorithm::Rsa, Algorithm::Ec].map(|algorithm| (*packaging, algorithm))
        })
        .collect();
    let Some(selection) = selection else {
        return Ok(all);
    };
    let mut chosen = Vec::new();
    for name in selection.split(',') {
        let case = all
            .iter()
            .find(|(packaging, algorithm)| case_name(*packaging, *algorithm) == name)
            .copied()
            .ok_or_else(|| format!("unknown case {name}"))?;
        if chosen.contains(&case) {
            return Err(format!("case {name} is selected twice"));
        }
        chosen.push(case);
    }
    Ok(chosen)
}

/// The first line a version command printed, on stdout or stderr.
fn version(program: &str, args: &[&str]) -> Value {
    let captured = capture(
        Command::new(program).args(args),
        true,
        Duration::from_mins(1),
    );
    captured
        .stdout
        .lines()
        .chain(captured.stderr.lines())
        .next()
        .map_or(Value::Null, Into::into)
}

/// The measurement options of `--bench`.
pub(crate) struct Options {
    pub(crate) samples: usize,
    pub(crate) warmups: usize,
    pub(crate) cold: usize,
    pub(crate) cases: Vec<(Packaging, Algorithm)>,
}

/// Qualifies and times every operation of every selected case and writes
/// `lifecycle-bench.json` into `results`.
pub(crate) fn execute(corpus: &Corpus, results: &Path, options: &Options) -> Result<(), String> {
    if results.exists() {
        return Err("results already exist; select a fresh --results directory".into());
    }
    std::fs::create_dir_all(results).map_err(|error| error.to_string())?;
    crate::xades::dss::build(corpus, &results.join("dss-build"))?;
    let binaries = Binaries::build(corpus, &results.join("bin"))?;
    let run = Run {
        corpus,
        results: results.join("chain"),
        pki: results.join("pki"),
        classpath: crate::xades::dss::classpath(corpus)?,
        lifecycle_probe: binaries.lifecycle.clone(),
        level_probe: binaries.level.clone(),
        at: now()? + 86_400,
    };
    run.issue()?;
    let bench = Bench {
        run: &run,
        binaries: &binaries,
        time: now()?,
        warmups: options.warmups,
    };
    let empty = results.join("no-evidence");
    std::fs::create_dir_all(&empty).map_err(|error| error.to_string())?;
    let mut entries = Vec::new();
    for (packaging, algorithm) in &options.cases {
        let case = Case {
            first: Actor::XmlSec,
            packaging: *packaging,
            algorithm: *algorithm,
            evidence: Evidence::Crl,
        };
        let name = case_name(*packaging, *algorithm);
        let chain = run.results.join(&name);
        let evidence = chain.join("evidence");
        std::fs::create_dir_all(&evidence).map_err(|error| error.to_string())?;
        bench.chain(case, &chain, &evidence)?;
        for operation in Operation::ALL {
            let target = Target {
                case,
                operation,
                input: operation.input().map_or_else(
                    || run.data(case),
                    |input| chain.join(format!("{input}.xml")),
                ),
                evidence: if operation == Operation::AugmentT {
                    &empty
                } else {
                    &evidence
                },
                directory: results
                    .join("operations")
                    .join(&name)
                    .join(operation.name()),
            };
            for mut entry in bench.operation(&target, options.samples, options.cold)? {
                entry["case"] = name.clone().into();
                println!("{entry}");
                entries.push(entry);
            }
        }
    }
    let boundaries: Map<String, Value> = BOUNDARIES
        .iter()
        .map(|(name, text)| ((*name).to_owned(), Value::from(*text)))
        .collect();
    write_json(
        &results.join("lifecycle-bench.json"),
        &json!({
            "schema": 1,
            "generated": timestamp(),
            "environment": {
                "platform": platform(),
                "architecture": architecture(),
                "cpu": cpu_model(),
                "samples": options.samples,
                "warmups": options.warmups,
                "cold_samples": options.cold,
                "repetitions": REPETITIONS,
                "rustc": version("rustc", &["-V"]),
                "java": version("java", &["-version"]),
                "dss": "6.5.1",
                "timing": "monotonic clock around each run inside the process (warm) or around each process (cold)",
                "memory": "native allocations come from a separate instrumented build and are never timed; JVM thread allocation, GC and heap counters cover the warm samples and are a different metric",
            },
            "boundaries": boundaries,
            "binaries": binaries.describe()?,
            "results": entries,
        }),
    )?;
    println!(
        "EU DSS lifecycle benchmark: {} entries in {}",
        entries.len(),
        results.display()
    );
    Ok(())
}
