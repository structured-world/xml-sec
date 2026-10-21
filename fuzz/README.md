# Security fuzzing

The targets call public APIs. They are defensive tests, not an independent
security audit or proof that every accepted document is interoperable.

| Target | Invariant / exercised surface |
| --- | --- |
| `xmldsig_verify` | Unstructured signature, Manifest, KeyInfo and transform parsing; offline certificate lookup |
| `xml_semantics` | Exact C14N bytes for common accepted backend inputs; idempotence; stale identity rejection after mutation |
| `security_roundtrip` | Real HMAC signing, compiled reference execution, cross-backend verification, wrong-key and authenticated-target tamper rejection; XMLenc round trips and malformed ciphertext parsing |
| `transform_parameters` | Arbitrary XPath AST/evaluation, Filter 2.0, OPC parameters and binary-to-XML/Base64 transitions; deterministic bytes and refusals |
| `xslt_execution` | Arbitrary compilation, bounded runtime/serializer execution, replay determinism and admitted work ceilings |
| `key_formats` | DER private/public keys and XML key stores with bounded KDF work; certificate parsing never establishes trust |
| `policy_compilation` | Strict configuration, immutable compiler, effective-policy round trip, restrictive composition and unknown-field rejection |
| `provider_operations` | Incremental digest equivalence, enabled-provider digest agreement, GCM authentication and key-wrap integrity |
| `xmlsec_oracle` | Reciprocal HMAC signatures over mutated namespace/comment payloads and every C14N variant against explicitly provisioned libxmlsec1 |

The structured targets cap their source prefix at 8 KiB to keep expensive
operations useful under mutation. This is a campaign bound, not a product
limit. The verification target accepts the complete input up to libFuzzer's
64 KiB campaign limit. Core safety ceilings and typed operation policies remain
unchanged. No fuzz harness performs implicit network or filesystem resolution.

## Run And Replay

Install `cargo-fuzz` 0.13.2 and a nightly toolchain. From the repository root:

```sh
bash scripts/fuzz-security.sh xml_semantics smoke
bash scripts/fuzz-security.sh xml_semantics campaign
bash scripts/fuzz-security.sh xml_semantics replay
cargo nextest run --manifest-path fuzz/Cargo.toml --lib
```

`xmlsec_oracle` requires an explicit `XMLSEC1_BIN` built by
`scripts/install-xmlsec1.sh`, including its reported library path. It runs only
fixed offline operations in an isolated temporary directory; a missing oracle,
nonzero exit or ten-second timeout is a failure, never an implicit skip. Native
C code is an independent test oracle only, not a product dependency.

The seed manifest selects specific existing fixtures; it never imports an entire
fixture tree. Generated coverage corpus lives in ignored `fuzz/corpus/TARGET`.
Reviewed minimized regression inputs belong in tracked `fuzz/regressions/TARGET`,
with a companion Markdown record naming the invariant, exact failure class,
toolchain, command, reproducing revision and fixing test. Do not include private
captures or credentials. Add the input to the seed manifest so every future run
replays it. There are no known failures to waive or silently exclude.

On failure, preserve `fuzz/artifacts/TARGET`, `fuzz/evidence/TARGET` and the build
output until diagnosis. Evidence logs are deliberately outside the directory
cargo-fuzz interprets as crash inputs.
The runner returns the original failing status, including hangs and timeouts.
Its command, source revision, worktree state and toolchain accompany the log.
Minimize only after confirming the original reproducer:

```sh
cargo +nightly fuzz run TARGET fuzz/artifacts/TARGET/crash-HASH
cargo +nightly fuzz tmin TARGET fuzz/artifacts/TARGET/crash-HASH
```

Classify disagreement against the relevant normative contract first. Parser
rejections outside a shared accepted language are not byte-equivalence evidence.
Never weaken an oracle or exclude an input just to make a campaign green.
Successful runner invocations clean their own reproducible build output; failed
output is retained for diagnosis. CI uploads the coverage corpus and artifacts.

## Differential Gates

Pull requests run bounded mutation smoke tests for every target. Scheduled runs
extend the mutation budget and execute pinned libxmlsec1 reciprocal integration
tests, provider contracts and backend comparison tests. AWS-LC FIPS enables an
additional provider campaign; PKCS#11 remains covered by its isolated token CI
suite rather than pretending arbitrary keys are portable token handles.
Smoke reserves new mutations on top of corpus replay (including libFuzzer's
initial empty input); restoring a large corpus cannot consume that allowance.
Smoke/replay builds use cargo-fuzz's development mode; scheduled campaigns use
optimized builds with 16 codegen units. Both retain AddressSanitizer, coverage
instrumentation, debug assertions and overflow checks.

The standalone XSLT engine is fuzzed through its existing crate. Its private
XMLDSig embedding is exercised through public transform/signature APIs and the
reciprocal XSLT integration suite; no internal module is exposed for fuzzing.
