//! Measurement protocol shared by the in-process engine harnesses.
//!
//! One process measures one engine, scenario, operation and boundary:
//!
//! ```text
//! HARNESS SCENARIO OPERATION BOUNDARY CORPUS INPUT OUTPUT SAMPLES
//! ```
//!
//! `OPERATION` is `sign`, `verify`, `encrypt`, `decrypt`, or `reject` (verification
//! that must refuse `INPUT`). `BOUNDARY` is `parse` (serialized input to serialized
//! result) or `prepared` (an already parsed document; a mutating operation gets a
//! fresh copy outside the timer). The first run's result is written to `OUTPUT`
//! (`-` for none) for cross-engine validation. Keys, trust anchors and operation
//! settings are loaded once, before any sample.
//!
//! Built with `allocation-profile`, a further untimed run counts the operation's
//! heap work; that build's timings are never reported.
//!
//! Exit status: 0 measured or rejected as required, 2 usage, 3 unsupported or
//! refused under the engine's default resource policy (the reason on stderr), 4
//! operation failure.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[path = "../../support/measure.rs"]
mod timing;

pub use timing::{Allocations, Measurement};

/// Untimed runs before the samples, matching the other library harnesses.
const WARMUPS: usize = 3;

/// Validate once, warm up three runs, then time `samples` runs of
/// `operation` on fresh inputs from `prepare`; see the shared timing loop.
///
/// # Errors
/// Returns the first preparation or operation failure.
pub fn measure<I, O, E: std::fmt::Display>(
    samples: usize,
    prepare: impl FnMut() -> Result<I, E>,
    operation: impl FnMut(I) -> Result<O, E>,
    output: impl FnOnce(&O) -> Option<Vec<u8>>,
) -> Result<Measurement, String> {
    timing::measure_warmed(samples, WARMUPS, prepare, operation, output)
}

/// Which work a sample contains.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Boundary {
    /// Serialized input to serialized result, parsing included.
    Parse,
    /// An already parsed document to the operation's in-memory result.
    Prepared,
}

/// One measurement request.
pub struct Args {
    pub scenario: String,
    pub operation: String,
    pub boundary: Boundary,
    pub corpus: PathBuf,
    pub input: PathBuf,
    pub output: Option<PathBuf>,
    pub samples: usize,
}

impl Args {
    /// Read a corpus file that the engine configuration needs.
    ///
    /// # Errors
    /// Returns the I/O failure with the path.
    pub fn corpus_text(&self, name: &str) -> Result<String, String> {
        read_text(&self.corpus.join(name))
    }

    /// The operation input.
    ///
    /// # Errors
    /// Returns the I/O failure with the path.
    pub fn input_text(&self) -> Result<String, String> {
        read_text(&self.input)
    }
}

fn read_text(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))
}

/// What a harness did with a request.
pub enum Outcome {
    Measured(Measurement),
    /// Verification refused the input, as `reject` requires.
    Rejected,
    /// Verification accepted an input that `reject` requires it to refuse.
    Accepted,
    /// The engine cannot perform the request; never timed.
    Unsupported(&'static str),
    /// The engine refuses this input under its default resource policy, with the
    /// engine's own reason; never timed. It is decided per input, so a later
    /// engine revision that accepts the input is measured again.
    Refused(String),
}

fn parse_args() -> Result<Args, String> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let [
        scenario,
        operation,
        boundary,
        corpus,
        input,
        output,
        samples,
    ] = arguments.as_slice()
    else {
        return Err(
            "usage: HARNESS SCENARIO OPERATION BOUNDARY CORPUS INPUT OUTPUT SAMPLES".into(),
        );
    };
    let boundary = match boundary.as_str() {
        "parse" => Boundary::Parse,
        "prepared" => Boundary::Prepared,
        other => return Err(format!("unknown boundary {other}")),
    };
    if !["sign", "verify", "encrypt", "decrypt", "reject"].contains(&operation.as_str()) {
        return Err(format!("unknown operation {operation}"));
    }
    let samples: usize = samples.parse().map_err(|_| "SAMPLES must be a count")?;
    if !(1..=100_000).contains(&samples) {
        return Err("SAMPLES must be 1..=100000".into());
    }
    Ok(Args {
        scenario: scenario.clone(),
        operation: operation.clone(),
        boundary,
        corpus: PathBuf::from(corpus),
        input: PathBuf::from(input),
        output: (output != "-").then(|| PathBuf::from(output)),
        samples,
    })
}

/// Run one request and report it as one JSON line on stdout. Engine versions
/// are recorded by the runner from this project's locked dependency graph.
pub fn main(engine: &str, execute: impl FnOnce(&Args) -> Result<Outcome, String>) -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    let rejecting = args.operation == "reject";
    match execute(&args) {
        Ok(Outcome::Unsupported(reason)) => {
            eprintln!("unsupported: {reason}");
            ExitCode::from(3)
        }
        Ok(Outcome::Refused(reason)) => {
            eprintln!("unsupported: refused under the engine's default policy: {reason}");
            ExitCode::from(3)
        }
        Ok(Outcome::Rejected) if rejecting => {
            println!(
                "{}",
                serde_json::json!({ "engine": engine, "rejected": true })
            );
            ExitCode::SUCCESS
        }
        Ok(Outcome::Rejected) => {
            eprintln!("verification refused a valid input");
            ExitCode::from(4)
        }
        Ok(Outcome::Accepted | Outcome::Measured(_)) if rejecting => {
            eprintln!("verification accepted an input it must refuse");
            ExitCode::from(4)
        }
        Ok(Outcome::Accepted) => {
            eprintln!("acceptance is reported only for reject requests");
            ExitCode::from(4)
        }
        Ok(Outcome::Measured(measurement)) => report(engine, &args, measurement),
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(4)
        }
    }
}

fn report(engine: &str, args: &Args, measurement: Measurement) -> ExitCode {
    let output_bytes = measurement.output.as_ref().map(Vec::len);
    if let (Some(path), Some(bytes)) = (&args.output, &measurement.output)
        && let Err(error) = std::fs::write(path, bytes)
    {
        eprintln!("{}: {error}", path.display());
        return ExitCode::from(4);
    }
    let input_bytes = match std::fs::metadata(&args.input) {
        Ok(metadata) => metadata.len(),
        Err(error) => {
            eprintln!("{}: {error}", args.input.display());
            return ExitCode::from(4);
        }
    };
    let allocations = measurement.allocations.map(|allocations| {
        serde_json::json!({
            "calls": allocations.calls,
            "bytes": allocations.bytes,
            "peak_bytes": allocations.peak_bytes,
        })
    });
    println!(
        "{}",
        serde_json::json!({
            "engine": engine,
            "scenario": args.scenario,
            "operation": args.operation,
            "boundary": if args.boundary == Boundary::Parse { "parse" } else { "prepared" },
            "samples_ns": measurement.samples_ns,
            "allocations": allocations,
            "input_bytes": input_bytes,
            "output_bytes": output_bytes,
        })
    );
    ExitCode::SUCCESS
}
