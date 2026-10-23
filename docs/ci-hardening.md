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

## XML Kernel Pedantic Lint

```sh
node --test scripts/check-xml-kernels.test.mjs
node scripts/check-xml-kernels.mjs
```

The required hardening job checks XML input, both maintained parser kernels,
semantic DOM/document code, C14N, and the safe SXD document/XPath implementation.
It checks the full-feature workspace, the default workspace, an isolated minimal
core graph, and the separate alloc-only XML-input crate. Root no-default builds
are not root alloc-only claims. Physical source identities join standalone and
embedded paths;
macro expansion callsites cannot hide diagnostics. `--force-warn clippy::pedantic`
exposes diagnostics even behind an existing local lint attribute. Every warning
in these implementations fails the gate; there is no accepted-warning baseline.
Compiler errors, missing build completion, malformed diagnostic output and Cargo
failures are terminal regardless of source scope.

The standalone legacy `raw-pointer-backend` is not selected by the product or by
the safe workspace all-feature graph and is not claimed as pedantic-qualified.
Other subsystems retain the existing warning-denying Clippy matrix; this scoped
gate does not claim their independent pedantic qualification. Comparable
performance regression reporting remains a separate check.

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

The XML-oracle block runs both the live XMLDSig/XAdES corpus and XSLT conformance
with their original independent validators and separate evidence artifacts.
Shared mechanisms are resolved as one registry version across ASN.1, PKIX, CMS,
LTV and XAdES. `scripts/check-shared-pkix.sh` rejects duplicate generations and
path/git substitutes, then independently checks the PKIX and XAdES alloc graphs
on bare-metal and WASM targets. Core XMLDSig still requires `std`; the shared
dependency qualification is not a root alloc-only claim.
