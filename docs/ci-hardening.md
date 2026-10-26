# Required CI Qualification

The required `test` aggregate rejects failed or skipped feature, documentation,
provider/oracle, compatibility-ledger, build, alloc-only, lint, format, fuzz,
dependency/safety and coverage jobs. A green subset is not complete qualification.

## Coverage

Install cargo-llvm-cov 0.8.5, cargo-nextest, Node.js and the Rust toolchain's
`llvm-tools-preview` component. Provision the [isolated SoftHSM harness](crypto-providers.md)
and pinned [XML security](features.md) and [XSLT oracles](xslt-conformance.md), then run:

```sh
PKCS11_MODULE=/absolute/path/to/libsofthsm2.so \
  bash scripts/check-hardening.sh coverage /absolute/new/evidence-directory
```

The evidence directory must be new and outside Cargo build output. All-feature
workspace tests execute with the real isolated token provider. Known lexical
aliases of embedded XSLT/SXD/XML-input sources are remapped by rustc before
coverage instrumentation. LLVM merges their executions against one source;
no file or package is excluded, and no better-looking percentage is selected.
The report check rejects noncanonical or duplicate physical source identities.
Reports explicitly select `--package '*'`; the report command's root-package
default would omit other workspace libraries and tools from the denominator.
LLVM itself enforces at least 85% total line coverage. JSON, LCOV, revision and
toolchain evidence remain available separately from cleaned build artifacts.

Coverage is an executable-line metric, not proof of full branch exploration,
protocol conformance or an independent audit. Separate feature/backend/provider,
negative corpus and fuzz gates remain required. Test, oracle setup, report or
threshold failures stop qualification; they are never accepted as negative cases.

## Dependencies And Native Safety

```sh
bash scripts/check-hardening.sh dependencies
bash scripts/check-hardening.sh safety
node --test scripts/check-hardening.test.mjs
```

cargo-deny 0.19.0 checks both the production and fuzz graphs, including optional
features and development dependencies. Vulnerable, unsound and notice advisories
fail under the tool's policy; yanked crates and unapproved git/registry sources
are refused. There is no blanket ignore list. Refresh an ignored local lockfile
when it retains a yanked dependency; do not weaken the gate to accept that lock.

The native safety gate lints all workspace library targets with unsafe-code
refusal. Test/benchmark diagnostic allocator probes are not product library
permission to use unsafe. Native dependencies retain their separate upstream
safety and FIPS/module boundaries; this check is not an audit of external code.

## Pedantic Lint

`clippy::pedantic` is part of the workspace lint table in the root
`Cargo.toml`, and every workspace member inherits it with
`[lints] workspace = true`. Locally it reports warnings; every CI lint invocation
denies them with `-D warnings`, so there is no accepted-warning baseline.

No source can opt out of a pedantic lint. The table forbids every pedantic lint
by name, so a local `#[allow]` or `#[expect]` of one is error E0453. A forbidden
group is not enough: rustc lets a member allow override it and only warns
(`forbidden_lint_groups`). The list covers the pedantic group of clippy 1.92 and
of stable, limited to names both toolchains know; a lint only one of them knows
is caught there as an unknown or renamed lint. Two lints stay out of the list:
`used_underscore_binding`, which thiserror's derive allows in its own expansion,
and `large_stack_arrays` (see below). The same check rejects any source that
allows either of them or the whole pedantic group.

```sh
node scripts/check-pedantic-lints.mjs 1.92.0 stable
node --test scripts/check-pedantic-lints.test.mjs
```

The check fails when either toolchain's pedantic group has a lint the list does
not cover, or the list names a lint a toolchain does not know. The test proves
on clippy 1.92 that a local allow of each listed lint fails, and that a forbidden
group alone would not have.

The lint matrix in `scripts/ci-test-blocks.mjs` resolves each feature graph
separately: the default, backend, all-feature, experimental, FIPS and XSLT
workspace graphs, plus library-only minimal graphs for `xmldsig`, `xmlenc` and
`xslt` on the differential backend. The alloc-only job lints the separate
XML-input crate without default features. MSRV lint invocations allow
`clippy::large_stack_arrays`, which clippy 1.92 reports without a span for the
libtest descriptor array (rust-lang/rust-clippy#13774); stable lint keeps it.

The standalone legacy `raw-pointer-backend` is not selected by the product or by
the safe workspace all-feature graph and is not claimed as pedantic-qualified.
Performance regression reports compare only matching runs and apply no threshold;
see [benchmarks](benchmarks.md#regression-report).

## Grouped Qualification

`node scripts/ci-test-blocks.mjs BLOCK` runs one of `stable-core`, `msrv-core`,
`msrv-extended`, `stable-extended`, or `msrv-fips`. These blocks retain separate
Cargo invocations for every toolchain/feature/backend profile; grouping does not
union their features. Builds, lint, tests and doctests share runner and oracle
setup. The XMLenc inventory build still resolves only the core package, and
all-feature tests still require an explicit disposable SoftHSM module.

Documentation and benchmark-contract checks run in their matching toolchain
blocks. Token-only backend checks share a separate job; corpus provenance runs
with native safety/dependency checks. Coverage, long-running fuzz campaigns,
cross-platform feature checks and independent oracle/performance measurements
remain isolated. The required `build`, `clippy` and `test` checks fail if any
constituent block fails, is cancelled or is skipped; existing required check
names remain unchanged.

Pull-request qualification runs for every base branch, including dependent
branches in a PR stack. Push qualification remains limited to `main`; PR jobs
retain read-only repository permissions.

### Build Reuse

PR fuzz smoke uses three runner blocks: eight ordinary ASan targets share one
compilation, while the external oracle and real FIPS module stay separate.
Scheduled and explicitly dispatched campaigns retain independent target jobs.
Every target keeps its original corpus cache key, mutation allowance, timeout,
reproducer directory and evidence. A failed target stops its block and retains
the failed build; the required fuzz aggregate cannot pass a failed block.

The local `rust-build-cache` action uses explicit compatibility domains rather
than job IDs. Hosted image family is captured from the runner process environment;
OS, architecture, compiler, manifests and compiler environment remain part of
the cache fingerprint. Ordinary jobs read a shared
dependency cache; only the extended Linux matrix block for each compiler saves
it. Each other OS has its own default-feature writer, avoiding competing partial
writers without leaving desktop caches permanently cold. Coverage, alloc-only targets, benchmark,
fuzz harness, ASan and FIPS use separate domains; smoke and optimized campaigns
also remain separate. Scheduled differential qualification has its own writer.
The pinned native xmlsec1 installation is cached separately by OS image family,
architecture, installer/source revision and modern/legacy capability profile;
the installer still validates its source marker, version and capabilities on a
cache hit. Cache hits never substitute for executing qualification.

Cleanup registers before the cache action, so reverse-order post actions save
dependencies before removing successful build output. Cargo-bin caching is
disabled so upstream cache pruning cannot remove runner-provided Cargo/rustup
shims needed by later post actions. The cache-managed fuzz
and conformance entrypoints leave cleanup to that action; standalone invocations
still clean immediately on success. Failed jobs retain build evidence. XSLT
measurements use a separate temporary target directory and fresh evidence,
so cleaning a measurement does not erase the qualification dependency cache.
Concurrent jobs restore prior caches, not unfinished output from another job in
the same run; sharing does not impose a producer dependency on the critical path.

The XML-oracle block runs both the live XMLDSig/XAdES corpus and XSLT conformance
with their original independent validators and separate evidence artifacts.
Shared mechanisms are resolved as one registry version across ASN.1, PKIX, CMS,
LTV and XAdES. `scripts/check-shared-pkix.sh` rejects duplicate generations and
path/git substitutes, then independently checks the PKIX and XAdES alloc graphs
on bare-metal and WASM targets. Core XMLDSig still requires `std`; the shared
dependency qualification is not a root alloc-only claim.

Custom resolvers and other consumers using the exposed shared memory or PKIX
types must upgrade their direct shared dependencies together with xml-sec.
Different coordinated generations are distinct Rust types, even when the
individual method signatures remain unchanged.
