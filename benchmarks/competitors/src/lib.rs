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

use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

/// Untimed runs before the samples, matching the other benchmark harnesses.
const WARMUPS: usize = 3;

#[cfg(all(test, feature = "allocation-profile"))]
mod tests;

#[cfg(feature = "allocation-profile")]
mod profile {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering::Relaxed};

    struct CountingAllocator;

    #[global_allocator]
    static ALLOCATOR: CountingAllocator = CountingAllocator;

    static COUNTING: AtomicBool = AtomicBool::new(false);
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static BYTES: AtomicUsize = AtomicUsize::new(0);
    static LIVE: AtomicIsize = AtomicIsize::new(0);
    static PEAK: AtomicIsize = AtomicIsize::new(0);

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    unsafe extern "C" {
        fn malloc_usable_size(pointer: *mut core::ffi::c_void) -> usize;
    }

    #[cfg(target_os = "macos")]
    unsafe extern "C" {
        fn malloc_size(pointer: *const core::ffi::c_void) -> usize;
    }

    #[cfg(not(any(all(target_os = "linux", target_env = "gnu"), target_os = "macos")))]
    compile_error!("allocation profiling reads block sizes from glibc or the macOS allocator");

    /// Bytes the system allocator reserves for a live block. Live and peak bytes
    /// count these, as the glibc profile of the C harness does, so every engine's
    /// peak includes allocator rounding the same way.
    fn usable(pointer: *mut u8) -> usize {
        // SAFETY: `pointer` is a live block that `System` returned, which on these
        // targets comes from the platform malloc family.
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        let size = unsafe { malloc_usable_size(pointer.cast()) };
        // SAFETY: as above.
        #[cfg(target_os = "macos")]
        let size = unsafe { malloc_size(pointer.cast_const().cast()) };
        size
    }

    fn observe_growth(bytes: usize, reserved: usize, released: usize) {
        if !COUNTING.load(Relaxed) {
            return;
        }
        CALLS.fetch_add(1, Relaxed);
        BYTES.fetch_add(bytes, Relaxed);
        // Block sizes never exceed isize::MAX, so the casts and difference cannot overflow.
        let delta = reserved.cast_signed() - released.cast_signed();
        PEAK.fetch_max(LIVE.fetch_add(delta, Relaxed) + delta, Relaxed);
    }

    // SAFETY: every method forwards the caller's pointer and layout unchanged to
    // `System`, which upholds the `GlobalAlloc` contract; counting touches no memory.
    unsafe impl GlobalAlloc for CountingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: forwarded contract.
            let pointer = unsafe { System.alloc(layout) };
            if !pointer.is_null() && COUNTING.load(Relaxed) {
                observe_growth(layout.size(), usable(pointer), 0);
            }
            pointer
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            // SAFETY: forwarded contract.
            let pointer = unsafe { System.alloc_zeroed(layout) };
            if !pointer.is_null() && COUNTING.load(Relaxed) {
                observe_growth(layout.size(), usable(pointer), 0);
            }
            pointer
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            // The block size is read while the block is still live.
            if COUNTING.load(Relaxed) {
                LIVE.fetch_sub(usable(pointer).cast_signed(), Relaxed);
            }
            // SAFETY: forwarded contract.
            unsafe { System.dealloc(pointer, layout) };
        }

        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            let counting = COUNTING.load(Relaxed);
            let released = if counting { usable(pointer) } else { 0 };
            // SAFETY: forwarded contract.
            let moved = unsafe { System.realloc(pointer, layout, new_size) };
            if !moved.is_null() && counting {
                observe_growth(new_size, usable(moved), released);
            }
            moved
        }
    }

    /// Count the heap work of `operation` alone: calls, requested bytes, and the
    /// peak of bytes it holds live above its starting point.
    pub(crate) fn counted<R>(operation: impl FnOnce() -> R) -> (R, super::Allocations) {
        CALLS.store(0, Relaxed);
        BYTES.store(0, Relaxed);
        LIVE.store(0, Relaxed);
        PEAK.store(0, Relaxed);
        COUNTING.store(true, Relaxed);
        let result = operation();
        COUNTING.store(false, Relaxed);
        let allocations = super::Allocations {
            calls: CALLS.load(Relaxed),
            bytes: BYTES.load(Relaxed),
            peak_bytes: PEAK.load(Relaxed).max(0).cast_unsigned(),
        };
        (result, allocations)
    }
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

/// Heap work of one counted operation.
pub struct Allocations {
    pub calls: usize,
    pub bytes: usize,
    pub peak_bytes: usize,
}

/// Timing samples, the profile build's allocations, and the first run's result.
pub struct Measurement {
    pub samples_ns: Vec<u64>,
    pub allocations: Option<Allocations>,
    /// The first run's result, written for cross-engine validation.
    pub output: Option<Vec<u8>>,
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

/// Validate once, warm up, then time `samples` runs of `operation` on fresh
/// inputs from `prepare`. Preparation, result conversion and drops stay outside
/// every sample. The profile build counts one further untimed run.
///
/// # Errors
/// Returns the first preparation or operation failure.
pub fn measure<I, O, E: Display>(
    samples: usize,
    mut prepare: impl FnMut() -> Result<I, E>,
    mut operation: impl FnMut(I) -> Result<O, E>,
    output: impl FnOnce(&O) -> Option<Vec<u8>>,
) -> Result<Measurement, String> {
    let mut run = |timed: bool| -> Result<(O, u64), String> {
        let input = prepare().map_err(|error| format!("prepare: {error}"))?;
        let start = Instant::now();
        let result = operation(input).map_err(|error| format!("operation: {error}"));
        let elapsed = start.elapsed();
        let result = result?;
        let nanoseconds = if timed {
            u64::try_from(elapsed.as_nanos()).map_err(|_| "sample exceeds u64 nanoseconds")?
        } else {
            0
        };
        Ok((result, nanoseconds))
    };
    let (first, _) = run(false)?;
    let output = output(&first);
    drop(first);
    for _ in 0..WARMUPS {
        run(false)?;
    }
    let mut samples_ns = Vec::with_capacity(samples);
    for _ in 0..samples {
        samples_ns.push(run(true)?.1);
    }
    #[cfg(feature = "allocation-profile")]
    let allocations = {
        let input = prepare().map_err(|error| format!("prepare: {error}"))?;
        let (counted, allocations) = profile::counted(|| operation(input));
        counted.map_err(|error| format!("operation: {error}"))?;
        Some(allocations)
    };
    #[cfg(not(feature = "allocation-profile"))]
    let allocations = None;
    Ok(Measurement {
        samples_ns,
        allocations,
        output,
    })
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
