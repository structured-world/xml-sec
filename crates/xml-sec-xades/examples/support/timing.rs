//! The probes' measurement mode: `--samples N [--warmups W]` times `N`
//! in-process runs of the probe's operation after a validated first run and
//! `W` warmups (three by default), and reports them as the last stdout line.
//! Built with `allocation-profile`, the report carries one further untimed
//! run's heap work and its timings are not used.

#[path = "../../../../benchmarks/support/measure.rs"]
mod measure;

pub use measure::{Measurement, measure_warmed};

/// How many runs a measurement times, after how many warmups.
#[derive(Clone, Copy)]
pub struct Sampling {
    pub samples: usize,
    pub warmups: usize,
}

/// The count of `flag N`, taken out of `args`.
fn count(args: &mut Vec<String>, flag: &str, minimum: usize) -> Result<Option<usize>, String> {
    let Some(index) = args.iter().position(|arg| arg == flag) else {
        return Ok(None);
    };
    let count: usize = args
        .get(index + 1)
        .and_then(|value| value.parse().ok())
        .filter(|count| (minimum..=100_000).contains(count))
        .ok_or_else(|| format!("{flag} needs a count of {minimum}..=100000"))?;
    args.drain(index..index + 2);
    Ok(Some(count))
}

/// The sampling of `--samples N [--warmups W]`, taken out of `args`.
pub fn sampling(args: &mut Vec<String>) -> Result<Option<Sampling>, String> {
    let warmups = count(args, "--warmups", 0)?;
    let Some(samples) = count(args, "--samples", 1)? else {
        return match warmups {
            Some(_) => Err("--warmups needs --samples".into()),
            None => Ok(None),
        };
    };
    Ok(Some(Sampling {
        samples,
        warmups: warmups.unwrap_or(3),
    }))
}

/// Times `operation` as `sampling` asks; see `measure_warmed`.
pub fn measure<I, O, E: std::fmt::Display>(
    sampling: Sampling,
    prepare: impl FnMut() -> Result<I, E>,
    operation: impl FnMut(I) -> Result<O, E>,
    output: impl FnOnce(&O) -> Option<Vec<u8>>,
) -> Result<Measurement, String> {
    measure_warmed(
        sampling.samples,
        sampling.warmups,
        prepare,
        operation,
        output,
    )
}

/// The report of `measurement` for `operation` over `input_bytes` of input.
pub fn report(operation: &str, input_bytes: usize, measurement: &Measurement) -> String {
    let allocations = measurement.allocations.as_ref().map(|allocations| {
        serde_json::json!({
            "calls": allocations.calls,
            "bytes": allocations.bytes,
            "peak_bytes": allocations.peak_bytes,
        })
    });
    serde_json::json!({
        "engine": "xml-sec",
        "operation": operation,
        "samples_ns": measurement.samples_ns,
        "allocations": allocations,
        "input_bytes": input_bytes,
        "output_bytes": measurement.output.as_ref().map(Vec::len),
    })
    .to_string()
}
