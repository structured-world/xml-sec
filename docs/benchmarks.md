# Reproducible XML Security Benchmarks

The benchmark suite uses Divan 0.1.21, a development-only dependency. It never
changes the allocator in the published library or disables policy enforcement.
The default build contains no measurement hooks. `benchmark-internals` enables
unstable, hidden measurement entry points, not application APIs.

## Run

```sh
cargo bench --bench security --features benchmark-internals
cargo bench --bench security --features benchmark-alloc
bash scripts/benchmark-security.sh target/performance/run-1 1000
# Optional native FIPS provider, never a fallback to RustCrypto:
bash scripts/benchmark-security.sh target/performance/fips-1 1000 aws-lc-fips
```

The runner requires macOS or Linux, `jq`, and `/usr/bin/time`; initial compilation resolves
the graph and records the lockfile and dependency metadata; subsequent runs within
that invocation are locked. Set `CARGO_TARGET_DIR` consistently if using another
build directory. Results belong in an ignored directory, not the source tree.
Do not reuse an output directory from an earlier revision or feature set.
The runner rejects source or lockfile changes during measurement. Dependency metadata
records the selected feature graph, not just the default features.
Native library search paths come from that build's Cargo messages, allowing direct
FIPS-binary execution without measuring Cargo startup or guessing build directories.

## Corpus And Boundaries

Every XML backend runs identical SAML-shaped, namespace-heavy, text-heavy,
attribute-heavy, four-signature, nested-Manifest, caller-owned external-reference,
and deep escaping-heavy workloads at two sizes. These are synthetic benchmarks,
not tenant captures or a claim of SAML protocol validation. Inputs and test keys
are fixed; encryption continues to use fresh secure randomness. Never replace
production RNG with deterministic randomness to improve a benchmark number.

Parse includes owned input and semantic arena construction. C14N uses a retained
signed document. Sign includes template copying and controlled mutations. Verify
has separate parse+operation and retained-document cases; both authenticate all
signatures. Encrypt/decrypt include XML processing and AES-256-GCM through the
selected provider. Rejection cases check corrupted signature evidence and malformed
XML on every backend, rather than interpreting an error as a successful operation.
RSA-SHA256 sign/verify use the
selected provider's actual key handle.
Projection calls the production normalizer over a prepared backend DOM and lexical
positions, without a second parser invocation. Differential parsing has no
single-backend projection measurement. Graph compilation and execution are separate
synthetic fan-out measurements at 1/8/32/64 references, not substitutes for complete
operation measurements. Typed policy validation/checks are measured independently;
their cost must not be subtracted from an end-to-end result to claim an unsafe path.
The latency runner also samples these phases individually. Its graph widths are
16 and 64 (recorded in JSON), while Divan covers 1/8/32/64. Projection includes arena
destruction; graph-input construction and destruction are outside the measured phase.
Phase RSS still includes the common prepared corpus and is not an isolated phase heap.

Setup imports keys, generates signatures/ciphertexts and validates verification
and decryption before measurement. Timed operations retain correctness assertions:
canonical bytes, deterministic RSA signature output, valid evidence and decrypted
plaintext. Their cost is included and disclosed rather than silently elided.

## Artifacts And Interpretation

Each latency JSON contains raw per-operation wall times, nearest-rank p50/p95/p99,
operations/s, actual input bytes/s, input/output lengths and relevant amplification.
Input throughput counts offered XML plus caller-owned external-reference bytes where
applicable; it is not a claim that every supplied byte was consumed on rejection.
Eight warmups and preparation are excluded from those samples. Small smoke runs
are correctness checks, not credible tail-latency baselines.

Each case runs in a fresh process. Its resources file records process CPU and peak
RSS using system `time` (macOS RSS bytes; Linux RSS KiB). This includes fixture setup,
warmup, live input/output and reporting, not just the timed operation. It is not
the allocation peak, and setup RSS must not be subtracted from a process high-water
mark. Preserve raw reports and environment metadata when comparing revisions.

Divan allocation runs wrap the system allocator and therefore perturb timing.
Only uninstrumented runs establish timing baselines. Counts cover Rust allocator
calls on the measured thread, not AWS-LC native allocations; process RSS covers
native memory too. See [Divan allocator limitations](https://docs.rs/divan/0.1.21/divan/struct.AllocProfiler.html).
Provider availability is not FIPS approval; use the supported native module environment.

Run at least three isolated repetitions on the same machine, toolchain, features,
power mode and workload; preserve all observations. This suite provides evidence,
not fixed performance thresholds or an unsupported superiority claim. Establish
stable host-specific baselines before enabling regression gates. For hot-path
investigation use `cargo flamegraph --bench security --features benchmark-internals`
with a selected Divan filter; allocation profiling remains a separate run.

The oracle CLI's `--repeat` CPU time excludes parsing and result writing. Do not
compare it directly with this suite's end-to-end wall time. Comparative native/C/ABI
measurements require separately matched boundaries and build configurations.
