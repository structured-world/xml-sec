//! In-process timing shared by the benchmark harnesses: validate once, warm
//! up as many runs as the harness asks, then time each sample around the
//! operation alone.
//!
//! A harness built with its `allocation-profile` feature counts the heap work
//! of one further untimed run; that build's timings are never reported.

use std::fmt::Display;
use std::time::Instant;

#[cfg(all(test, feature = "allocation-profile"))]
#[path = "measure_tests.rs"]
mod tests;

#[cfg(feature = "allocation-profile")]
pub mod profile {
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
    pub fn counted<R>(operation: impl FnOnce() -> R) -> (R, super::Allocations) {
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

/// Validate once, run `warmups` untimed runs, then time `samples` runs of
/// `operation` on fresh inputs from `prepare`. Preparation, result conversion
/// and drops stay outside every sample. The profile build counts one further
/// untimed run.
///
/// # Errors
/// Returns the first preparation or operation failure.
pub fn measure_warmed<I, O, E: Display>(
    samples: usize,
    warmups: usize,
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
    for _ in 0..warmups {
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
