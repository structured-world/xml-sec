# Reproducible XML Security Benchmarks

XSLT phase, immutable reuse and amplification measurements have a separate
[reproducible runbook](xslt-performance.md).

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

Node-set measurements parse one 1K/16K-element signed shape outside the timer.
`node_set_enveloped` projects the whole document, excludes the enveloped element
and canonicalizes; `node_set_sparse` and `node_set_dense` select every Nth element
with its attribute and namespace nodes, build the selection directly in the named
explicit representation regardless of density (no conversion between the two), and
canonicalize. Comparing the two at each
stride, with allocation runs for peak memory, is how the sparse/dense threshold
is chosen.

`large_reference_verify` and `large_reference_sign` sign or verify one `#payload`
Reference over 256 KiB and 4 MiB of entity-free text (the `bulk` shape, kept out
of the general matrix). The canonical output dominates the input, so the
allocation run's peak shows whether the Reference digest retains that output;
with streamed digests the verification peak no longer grows with the payload.

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

## Comparative Dashboard

```sh
# Competitors are built outside the product dependency graph.
bash scripts/benchmark-compare.sh target/performance/comparison 30
# Linux: separately profile malloc-family allocations and peak heap, including C.
bash scripts/benchmark-compare.sh target/performance/comparison-heap 30 --heap
node scripts/build-benchmark-dashboard.mjs target/performance/comparison target/performance/site
node --test scripts/compare-security.test.mjs scripts/compare-library.test.mjs
```

The comparison has two levels, reported in separate dashboard sections and never
ranked against each other: command-line processes, where launch and key loading
dominate small documents, and library operations, which isolate the cost of one
operation inside a process.

### Command-line process

The runner builds the pinned Bergshamra 0.9.2 source (RustCrypto only) and the
existing libxmlsec1 1.3.13 oracle, independently of the product dependency graph.
It compares both xml-sec XML backends against those CLIs: single-reference
RSA-2048/SHA-256 sign/verify and AES-256-GCM encrypt/decrypt of identical plaintext
octets, at three sizes for five deterministic document shapes. AES keys use the
same named XML key store; RSA keys use named PEM imports. These payload cases
are byte-oriented encryption, not element selection.

Every case runs at 16, 256 and 16384 repeated units. The largest size is a
production-sized document (the 16384-attribute SAML response is about 1.7 MB):
there the cost of each byte outweighs process launch and key loading, which
dominate the two small sizes.

Four workloads cover the main application uses:

| Workload | Operations | Configuration |
|----------|------------|---------------|
| SAML assertion | sign, verify | Enveloped exclusive-C14N signature over an `Assertion` inside a `Response`. The signer writes its certificate into `X509Data`; verification trusts only a root CA, receives an untrusted intermediate CA, and must also reject a wrapped forgery that repeats the signed ID. Bergshamra verifies with `--enabled-key-data x509 --strict`. |
| Element | encrypt, decrypt | A standalone `Payment` element as `Element` `EncryptedData`: AES-256-GCM content key transported with RSA-OAEP to the recipient certificate, decrypted with its private key. |
| Element in place | encrypt, decrypt | The same `Payment` encrypted where it stands inside an `Order` (`--node-id`); decryption restores the whole document. |
| XSLT reference | sign, verify | A same-document reference transformed by an XSLT 1.0 stylesheet before exclusive C14N. |

Pinned Bergshamra 0.9.2 has no XSLT transform, leaves a template's `X509Data`
empty when signing, and its CLI `--node-id` writes a standalone `EncryptedData`
instead of replacing the element inside its document. Those operations are
recorded as unsupported with the reason and are never timed; it still verifies
the other engines' assertions and decrypts their in-place documents.

Before timing, each engine's signature is verified by every engine, each
ciphertext is decrypted by every engine, and all engines must reject a modified
signed value. Payload plaintexts must match exactly; XML documents may differ
only in the XML declaration and surrounding whitespace the writing engine emits.
A crash or timeout is failure, not successful rejection.

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

### Library operation

The same corpus and keys drive one in-process harness per engine:

- xml-sec through its Rust API (`SignContext`, `VerifyContext`,
  `EncryptedDataBuilder`, `DecryptContext`, xmloxide backend, RustCrypto);
- Bergshamra 0.9.2 through its Rust API, linked only from
  `benchmarks/competitors`, a project outside the xml-sec workspace with its own
  `Cargo.lock` and the revision pinned in
  `compatibility/bergshamra-0.9.2-benchmark-commit.txt`. Before building, the
  runner refreshes only that lockfile's entry for xml-sec itself
  (`scripts/refresh-competitor-lock.sh`), so a new product version leaves the
  Bergshamra graph as locked; a product dependency the locked graph cannot
  satisfy stops the run until the lockfile is updated and committed;
- libxmlsec1 1.3.13 through its C API (`benchmarks/libxmlsec1-library.c`),
  linked against the oracle build and the OpenSSL inside it.

Each process loads keys, trust anchors and settings once, validates its first
result, runs three warmups and then times every sample around the operation
alone. Two boundaries are measured:

| Boundary | Inside each sample |
|----------|--------------------|
| Parse and operation | Parsing the serialized input, the operation and serializing its result. |
| Prepared document | The operation on an already parsed document, without serialization. A mutating operation receives a fresh parsed copy outside the timer. libxml2 registers declared IDs while preparing the document. |

Each engine is configured for the same workload, as its own command line would be:

| Engine | Configuration beyond defaults |
|--------|-------------------------------|
| xml-sec | Chain validation of `X509Data` to the trusted root (`key_trust.verify_x509_chains`); libxmlsec1 XSLT stylesheet semantics; encryption and decryption policies permitting exactly AES-256-GCM with RSA-OAEP MGF1-SHA1, the one key transport all engines share. |
| Bergshamra | `DsigContext::new_permissive` with `enabled_key_data_x509` and `strict_verification`, trusted root and untrusted intermediate, as `verify --trusted --untrusted --enabled-key-data x509 --strict`. |
| libxmlsec1 | The keys and trust of the command-line comparison, a 256-bit AES session key, and declared IDs registered with duplicates refused. |

Before timing, every result each engine produces at either boundary is consumed
by every other engine: signatures verified, ciphertexts decrypted to the
original document. Every verifier must reject the changed signed value and the
wrapped SAML forgery. A harness answers an operation its engine lacks with the
reason (exit status 3); the runner records it as unsupported and never times it.
Bergshamra signs no X509Data, has no XSLT 1.0 transform, cannot encrypt in place,
and encrypts or decrypts only serialized XML.

Every process is wrapped by system `time` for RSS, which covers the whole
process including key loading and warmups. Allocation counts come from separate
instrumented builds whose timings are never reported: the Rust harnesses'
`allocation-profile` feature installs a counting global allocator, and on glibc
the C harness replaces the malloc family. Both count every heap allocation in the
process during one operation: calls, requested bytes and the peak of live bytes
above the operation's start. Live bytes are the allocator's usable block sizes
for every engine, so the peak includes allocator rounding the same way.
Elsewhere the C allocation profile is reported as not measured.

### Regression report

```sh
node scripts/compare-regression.mjs BASELINE_DIR CANDIDATE_DIR OUTPUT_DIR
node --test scripts/compare-regression.test.mjs
```

The report compares two comparison runs, each a directory with `comparison.json`,
`library.json` and `build.json`. `scripts/build-identity.mjs` writes the latter:
compiler versions, the features of every binary, native flags, the heap-profiling
mode and the pinned competitor revisions, every environment override of the build
(`RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, `CARGO_PROFILE_*`, `CARGO_BUILD_*`, `CC`,
`CFLAGS` and similar) and digests of the Cargo configuration files that apply. A
run whose identity cannot be recorded fails. The report writes
`regression.json` with every case of either run and a short `regression.md`.

Runs are compared only when both have more than one sample and at least three
repetitions, and they match in platform, architecture, CPU model, sample and
repetition counts, build identity and corpus digests. Otherwise every case is
reported as incomparable with the reasons; a one-sample run proves that the
harness works, not how fast anything is. A case one run lacks, an unsupported
operation and a missing allocation profile are stated as such, never as zero.
A supported case without the run's number of repetitions, or with a missing or
non-positive percentile, makes a baseline unusable and fails the candidate.

For comparable cases the report keeps each repetition's p50/p95/p99 and peak RSS
from both runs, their medians and ratio, the change in allocation counts, and
whether the candidate's repetitions lie above, below or within the baseline's.
It applies no threshold and gives no pass or fail verdict: thresholds need
repeated comparable baselines on a controlled host, which shared runners are not.

CI fetches the last published default-branch run from Pages as the baseline,
writes the report into the comparison artifact and the job summary, and the
dashboard publishes it with the run. When the published site has no usable run,
the report says that no baseline exists.

CI uses the shared comparison workflow to build dashboard artifacts on PRs;
Benchmark Observatory publishes only validated default-branch results to GitHub Pages. One-sample PR
runs prove correctness, not performance. Shared runners and 30-sample runs do
not establish reliable p99 thresholds. The dashboard deliberately makes no
speed superiority claim. Standalone parse/C14N, multiple signatures, Manifests
and external resources are not ranked without matching processor boundaries.

References: [Bergshamra CLI](https://github.com/kushaldas/bergshamra/blob/v0.9.2/crates/bergshamra/src/main.rs),
[Valgrind Massif](https://valgrind.org/docs/manual/ms-manual.html),
[Replacing malloc in glibc](https://www.gnu.org/software/libc/manual/html_node/Replacing-malloc.html),
[GitHub Pages workflow](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages).

`benchmarks/Dockerfile` supplies the Linux profiling tools. Mount source read-only
and a separate writable output/build directory; select it through `CARGO_TARGET_DIR`
and `XMLSEC1_PREFIX`. Resolve `Cargo.lock` before mounting source read-only
(`cargo +1.92.0 generate-lockfile`). The competitor checkout must be clean and match the pinned
revision. Container results describe that container's architecture, not the host.
Both Rust binaries use Rust 1.92.0 by default (`BENCH_RUST_TOOLCHAIN` selects
another installed toolchain for both). Keep build artifacts on a Linux-native
volume when running Docker on macOS; only source and exported reports need bind mounts.
