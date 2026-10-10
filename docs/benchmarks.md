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

## Comparative CLI Dashboard

```sh
# External competitor binary only; never a dependency of xml-sec.
bash scripts/benchmark-compare.sh target/performance/comparison 30
# Linux: separately profile malloc-family allocations and peak heap, including C.
bash scripts/benchmark-compare.sh target/performance/comparison-heap 30 --heap
node scripts/build-benchmark-dashboard.mjs target/performance/comparison target/performance/site
node --test scripts/compare-security.test.mjs
```

The runner builds the pinned Bergshamra 0.9.2 source (RustCrypto only) and the
existing libxmlsec1 1.3.13 oracle, independently of the product dependency graph.
It compares both xml-sec XML backends against those CLIs: single-reference
RSA-2048/SHA-256 sign/verify and AES-256-GCM encrypt/decrypt of identical plaintext
octets, at two sizes for five deterministic document shapes. AES keys use the
same named XML key store; RSA keys use named PEM imports. Encrypt/decrypt is
byte-oriented XML payload encryption, not element/content selection parity.
Before timing, each engine's signature is verified by every engine, each
ciphertext is decrypted by every engine with exact plaintext equality, and all
engines must reject a modified signed payload. A crash or timeout is failure,
not successful rejection. Unsupported work never produces a timing entry.

Every sample includes fresh process launch, key loading, file I/O and operation;
three interleaved repetitions rotate engine order. File caches are warm. CPU
and RSS use system `time`; wall time also includes the common measurement wrapper
and parent launch overhead. No CLI result is compared with retained-DOM or other
library-only measurements. Sign/encrypt outputs are written to files equally.
Input throughput and output amplification are derived from those actual files.
System `time` CPU counters have coarse resolution; very short operations can
legitimately report zero CPU seconds. They are not high-resolution phase profiles.
The first build resolves the untracked library lockfile; measurement freezes and
archives both Rust dependency graphs and source fingerprints.

Optional Linux Valgrind runs record total malloc-family allocation calls/bytes
with Memcheck and sampled peak live heap plus allocator overhead with Massif.
These cover Rust and native allocations on the same boundary, include startup
and teardown, and exclude stacks and non-malloc memory mappings. Massif peaks
are sampled, not an exact allocation high-water oracle. Their times are never
used as latency samples; they are not directly comparable to Divan counters.
The raw logs, commands, source/binary identities, lockfiles and feature graphs
are retained in CI artifacts. Missing metrics are displayed as not measured.

CI uses the shared comparison workflow to build dashboard artifacts on PRs;
Benchmark Observatory publishes only validated default-branch results to GitHub Pages. One-sample PR
runs prove correctness, not performance. Shared runners and 30-sample runs do
not establish reliable p99 thresholds. The dashboard deliberately makes no
speed superiority claim. Standalone parse/C14N, multiple signatures, Manifests
and external resources are not ranked without matching processor boundaries.

References: [Bergshamra CLI](https://github.com/kushaldas/bergshamra/blob/v0.9.2/crates/bergshamra/src/main.rs),
[Valgrind Massif](https://valgrind.org/docs/manual/ms-manual.html),
[GitHub Pages workflow](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages).

`benchmarks/Dockerfile` supplies the Linux profiling tools. Mount source read-only
and a separate writable output/build directory; select it through `CARGO_TARGET_DIR`
and `XMLSEC1_PREFIX`. Resolve `Cargo.lock` before mounting source read-only
(`cargo +1.92.0 generate-lockfile`). The competitor checkout must be clean and match the pinned
revision. Container results describe that container's architecture, not the host.
Both Rust binaries use Rust 1.92.0 by default (`BENCH_RUST_TOOLCHAIN` selects
another installed toolchain for both). Keep build artifacts on a Linux-native
volume when running Docker on macOS; only source and exported reports need bind mounts.
