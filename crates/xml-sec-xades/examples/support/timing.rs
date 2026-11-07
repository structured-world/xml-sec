//! The probes' measurement mode: `--samples N` times `N` in-process runs of
//! the probe's operation after a validated first run and warmups, and reports
//! them as the last stdout line. Built with `allocation-profile`, the report
//! carries one further untimed run's heap work and its timings are not used.

#[path = "../../../../benchmarks/support/measure.rs"]
mod measure;

pub use measure::{Measurement, measure};

/// The sample count of `--samples N`, taken out of `args`.
pub fn samples(args: &mut Vec<String>) -> Result<Option<usize>, String> {
    let Some(flag) = args.iter().position(|arg| arg == "--samples") else {
        return Ok(None);
    };
    let count: usize = args
        .get(flag + 1)
        .and_then(|value| value.parse().ok())
        .filter(|count| (1..=100_000).contains(count))
        .ok_or("--samples needs a count of 1..=100000")?;
    args.drain(flag..flag + 2);
    Ok(Some(count))
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
