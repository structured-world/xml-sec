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

Component pedantic qualification and comparable performance regression reporting
are tracked separately. This gate does not claim those later changes are delivered.
