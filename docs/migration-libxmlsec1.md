# Migrating From libxmlsec1

The comparison baseline is pinned libxmlsec1 1.3.13. Consult the generated
[declaration and behavior ledgers](compatibility-ledger.md) for exact outcomes.
Native Rust, the process CLI, C source compatibility, libxml2 DOM compatibility
and binary ABI are independent tiers. This source tree implements no libxmlsec1
C headers, exported C ABI, SONAME replacement or backend-specific OpenSSL/NSS/
GnuTLS object shim. An unmodified C binary cannot load this Rust crate instead.

## Choose A Migration Boundary

| Existing integration | Current migration |
| --- | --- |
| XMLDSig/XMLEnc documents and templates | Exercise the original bytes through the Rust API and reciprocal corpus/oracle tests |
| A subprocess using `xmlsec1` | Build the separate `xml-sec-cli` package and test the same argv, exit result and output bytes |
| New or ported Rust application | Compile typed policy and use `XmlSecurity` with explicit provider, keys and expected targets |
| C calls such as `xmlSecDSigCtxVerify` or `xmlDocPtr` | Requires an application port; source/DOM/ABI compatibility is not delivered |
| Backend-specific key pointers or custom transform classes | No pointer/layout equivalence; use provider-neutral Rust handles or retain the existing integration |

The [CLI guide](cli.md) owns complete option, output and exit semantics. Use a
distinct executable path during qualification, not a system-wide replacement.
Do not overwrite an existing installation merely because the command name matches.

## Translate Intent, Not Context Layout

| libxmlsec1 concept | Rust boundary |
| --- | --- |
| Crypto initialization/selection | Explicit `CryptoProvider`; no process-global provider registry or fallback |
| DSig/Enc context flags | Typed compiled operation policy, separate from request data |
| Trusted keys and key manager | Caller-owned `KeyInventory`, usage constraints and explicit trusted-key/path validation |
| `KeyInfo` lookup | Untrusted candidate discovery; not a trust-anchor grant |
| Registered ID attributes / start node | Explicit `IdAttributeRegistration`, retained identities and request target selection |
| URI callbacks | Caller-provided resource maps/resolvers within compiled URI and work limits |
| Signature status | Typed processing result plus authenticated expected-target evidence |
| In-place DOM changes | `XmlDocument` generation-aware sign/encrypt/decrypt commit; not libxml2 pointer mutation |
| Debug/global error queue | Typed errors; no shared OpenSSL error queue or credential-bearing token diagnostics |

Use the [executable examples](examples.md). The sign/verify pair executes a
real RSA-SHA256 template with an explicit public key and expected Invoice ID.
The policy-bound round-trip also demonstrates why an unsigned sibling must not
be accepted even when every cryptographic signature is valid.

## Preserve Security Differences

- Library defaults are restrictive. The compatibility CLI explicitly admits
  some legacy donor algorithms, key sizes and semantics that the Rust API denies.
  Do not copy CLI permissions into a production library profile indiscriminately.
- `XmlSecCompatible` preserves specific documented reading semantics; it does
  not mean every native backend, option, callback or struct is supported.
- Certificate discovery and X.509 signature verification are not application
  trust. Keep anchors, purpose, time, revocation and selected-key provenance explicit.
- SAML audience/recipient/replay and SOAP/XAdES application semantics remain
  caller responsibilities. The optional XAdES adapter currently delivers B-B,
  not complete timestamp or long-term validation levels.
- Optional provider names do not attest approved-service status. Protected key
  containers may still be decoded by RustCrypto before native import.
- The root XMLDSig graph currently requires `std`. Independent XML-input
  alloc-only/WASM qualification does not imply alloc-only XMLDSig.

## Qualification Checklist

Pin the source/release, feature set, provider and deployment target. Replay
representative templates, detached bytes, namespaces, multiple signatures,
IDs, malformed data, wrong keys and tampered ciphertext. Compare actual payloads
and failure classes, not just exit zero. Query `list-*`/`check-*` for the selected
engine, then verify operation policy separately. For the library, check
`accepted(document)` against the expected identity and generation.

Classify every unsupported case in the existing ledger rather than counting it
as a passing interoperability vector. Run `cargo run -p xml-sec-tools -- check-features PROFILE`
and the applicable oracle/provider suites. Use [benchmark artifacts](benchmarks.md)
for performance claims; native results do not prove C bridge performance.

## Pre-1.0 Rust Changes

The unreleased facade after 0.2.0 binds one compiled policy/provider. Its request
handles cannot replace either. `XmlSecError` is a non-exhaustive typed sum of
original causes instead of the former string-only variants; match typed variants
with a wildcard for future additions, never parse diagnostics. Low-level modules
remain available but must receive the same effective policy when used directly.
`CryptoProvider::begin_digest` supplies streaming digest state; custom providers
implement it rather than an independent one-shot hash path. Pin the matching
source revision until the release containing these changes is published.

The 0.2.0 umbrella declared string-only `XmlParse`, `Canonicalization`,
`SignatureInvalid`, `UnsupportedAlgorithm`, `Certificate`, `Crypto` and `Key`
variants. They were not the low-level operation error contract. Do not perform
a mechanical string-variant rename: retained parsing now reports `Document`,
canonicalization reports typed `Canonicalization`, operation failures preserve
their `Verification`, `Signing` or `Encryption` cause, and inventory errors use
`KeyStore`. Permission refusal uses `Policy`, while disabled factories report
`OperationDisabled`. Mathematical invalidity belongs to signature evidence,
not a fabricated `SignatureInvalid` processing error.
