# libxmlsec1 compatibility ledger

The machine-readable ledger at
[`compatibility/libxmlsec1-1.3.13.json`](../compatibility/libxmlsec1-1.3.13.json)
is the compatibility baseline for libxmlsec1 1.3.13. It inventories the public
surface from the upstream commit recorded in the canonical
[`libxmlsec1-1.3.13-donor-commit.txt`](../compatibility/libxmlsec1-1.3.13-donor-commit.txt)
pin:

- installed headers (including configured template values), exported functions
  and variables, the functions libxmlsec1 exports for its crypto backends from
  headers it does not install (`src/*.h`, kind `internal-export`), every
  conditional macro definition, compiler-provided build
  defines, typedef aliases, public enums, structure layouts, callbacks, class
  IDs, complete registry families, and the exact nested preprocessor branch
  path controlling every header item;
- generic and crypto-backend-specific APIs;
- algorithm and key-data URI constants and key serialization formats;
- `xmlsec1` CLI commands, typed option definitions (including aliases, argument
  syntax, topic availability, value types, and flags), and exit statuses;
- top-level upstream conformance and interoperability test families.

The companion behavioral ledger at
[`compatibility/libxmlsec1-1.3.13-behavior.json`](../compatibility/libxmlsec1-1.3.13-behavior.json)
tracks operation semantics that a declaration inventory cannot express: XPath
`here()` bindings, direct Visa3D ID lookup, ASN.1 ECDSA framing, implicit
adapters, URI identity, ID registration, signature selection, Manifest status,
error classification, callback order, mutable context state, and DOM mutation.
Every entry identifies its typed policy, request, CLI, or future C-boundary
control and references both positive and negative tests. Donor source anchors
are resolved to exact lines during generation. Ambiguous or missing anchors,
missing categories, incomplete controls, and stale test names fail generation.
Positive and negative evidence entries are behavioral assertions rather than a
requirement for separate test executables. A differential test may support both
lists when distinct descriptions identify the accepted and rejected outcomes;
an identical assertion repeated within either list or across both lists is
rejected as duplicate evidence.
Evidence declarations are parsed as Rust items and must be unconditional,
non-ignored `#[test]` functions with ordinary assertion semantics; syntax inside
comments or literals and tests behind `cfg`, `cfg_attr`, `ignore`, or
`should_panic` cannot certify ledger behavior. The normal module-level
`#[cfg(test)]` harness boundary is the sole permitted condition.
Context, callback, and in-place libxml2 mutation behavior is deliberately
classified as future C compatibility work rather than being attributed to the
owned native Rust API. A test-only C probe is compiled through the pinned
`xmlsec1-config` and measures success, invalid-result, callback-abort, retained
reference state, pre-execution callback order, `userData` propagation, and
signing-mutation state; libxmlsec1 remains absent from the product runtime.

The ledger is an honest parity map, not a blanket compatibility claim. Every
item references one entry in the top-level `classifications` table, which owns
the outcome, rationale, and evidence reference without repeating that metadata
for thousands of items:

| Outcome | Meaning |
|---|---|
| `exact` | The relevant public contract, representation, and behavior match libxmlsec1 without a compatibility caveat. Reserved until an item satisfies that complete contract. |
| `source-compatible` | Existing libxmlsec1 source can use the compatibility surface without call-site changes, while binary ABI identity is not implied. Reserved until the C compatibility layer exists. |
| `behavior-compatible` | The native Rust API implements the wire behavior and has repository test coverage. |
| `compatibility-profile-only` | The behavior exists but requires an explicit compatibility policy, normally for a legacy algorithm. |
| `provider-limited` | The Rust provider abstraction implements the corresponding cryptographic transform, but not the backend-specific C symbol. Other backend APIs remain `planned`. |
| `binary-abi-incompatible` | The item belongs to libxmlsec1's C source/ABI surface, which the crate does not yet expose. |
| `intentionally-unsupported` | The item is deliberately excluded, currently limited to deprecated C aliases. |
| `planned` | The item is a visible parity target and is not implemented yet. |

A planned donor test family may reference executable corpus evidence. This
means every vector is imported, run, and assigned an exact current outcome; it
does not promote the family to behavior-compatible while any vector still
depends on a planned algorithm or transform.

The classification source is
[`compatibility/libxmlsec1-1.3.13-rules.json`](../compatibility/libxmlsec1-1.3.13-rules.json).
Rules are evaluated in order, so precise supported and policy-gated URI and
backend-transform rules precede explicit planned fallbacks. A rule that matches
nothing fails generation, as does an extracted item without a rule or evidence
reference. Declaration extraction is comment-, literal-, and nesting-aware;
multiline macro bodies and typedef aliases therefore participate in donor-drift
checks rather than only their first physical line. Definitions in separate
preprocessor branches remain separate line-addressed entries, and configured
header templates are rendered from the pinned `configure.ac` version contract.
The schema derives item identity from `kind`, `name`, `source`, and `line`; it
does not duplicate that tuple in a serialized ID. C lexical normalization
removes comments and collapses formatting trivia while preserving exact bytes
inside string and character literals. Unterminated comments or literals fail
generation.

The top-level `availability` table stores source/line spans instead of repeating
the same condition array on each item. A span records the complete active
directive history, including prior `#if` branches before `#elif` or `#else`, so
changing platform or feature availability produces a generated ledger diff even
when declaration text is unchanged. An item outside these spans is
unconditional. Malformed, overlapping, or unbalanced donor condition data fails
generation.

## Binary ABI baseline

The ledger describes the sources. The binary baseline at
[`compatibility/libxmlsec1-1.3.13-abi-linux-x86_64.json`](../compatibility/libxmlsec1-1.3.13-abi-linux-x86_64.json)
records what a C compatibility layer must match in an installed build of the
same pinned commit, for one platform tuple:

- the exported symbols of `libxmlsec1` and `libxmlsec1-openssl`, each tied to
  the ledger item declaring it, including the internal exports prebuilt
  backend libraries link against; exports outside the `xmlSec` namespace (the
  build's statically embedded OpenSSL) are counted and digested, not listed;
- the size, alignment and field offsets of every public struct, every
  enumerator value, the sizes of pointers, `long`, `size_t` and `time_t`, and
  the sizes of exported data objects, measured by a C program compiled with the
  build's own `xmlsec1-config --cflags`, so members that depend on configure
  options appear exactly as that build's consumers see them;
- the feature defines of the build and its crypto backend;
- the ownership of every exported function: whether a returned pointer is a
  value, static, borrowed from an argument, owned by the caller (and released
  with which function) or a container element; what each parameter pointing to
  a writable pointer hands out (constness is checked at that pointer, so
  `const xmlChar **` counts, and an array the function only reads is
  classified as input explicitly); and which arguments the function adopts.

Ownership comes from the reviewed
[`compatibility/libxmlsec1-1.3.13-ownership-rules.json`](../compatibility/libxmlsec1-1.3.13-ownership-rules.json).
A returned pointer or output parameter that no rule covers fails generation,
and so does a rule that matches nothing, a release function the build does not
export and a rule without a rationale. A few symbols are exported only because
the donor links without a visibility list: no header declares them with an
export marker, so no consumer can rely on them. The rules file lists each with
its rationale; any other export without a declaration, or a listed name that
is declared or not exported, fails generation.

The committed tuple is the CI build: Linux x86_64, OpenSSL backend, built by
`xml-sec-tools install-xmlsec1` with `XMLSEC1_MODERN_ORACLE=1`. Toolchain
versions are not part of the baseline; the generator prints the compiler it
used. CI regenerates the baseline from that build, keeps the result as the
`libxmlsec1-abi-baseline` artifact and fails on any difference, so a reviewed
change can be committed from the artifact.

```sh
cargo run -p xml-sec-capability-ledger -- abi-check \
  compatibility/libxmlsec1-1.3.13.json \
  compatibility/libxmlsec1-1.3.13-ownership-rules.json \
  "$XMLSEC1_PREFIX" \
  compatibility/libxmlsec1-1.3.13-abi-linux-x86_64.json
```

`abi-generate` takes the same arguments and writes the snapshot. Both refuse an
installation built from another commit than the pinned one.

## Regenerating

Check out the pinned donor revision under `donors/xmlsec`, then run:

```sh
cargo run -p xml-sec-capability-ledger -- generate \
  donors/xmlsec \
  compatibility/libxmlsec1-1.3.13-rules.json \
  compatibility/libxmlsec1-1.3.13.json
```

To verify the committed artifact without rewriting it:

```sh
cargo run -p xml-sec-capability-ledger -- check \
  donors/xmlsec \
  compatibility/libxmlsec1-1.3.13-rules.json \
  compatibility/libxmlsec1-1.3.13.json
```

Generate and check the behavioral artifact with the same donor checkout:

```sh
cargo run -p xml-sec-capability-ledger -- behavior-generate \
  donors/xmlsec \
  compatibility/libxmlsec1-1.3.13-behavior-rules.json \
  compatibility/libxmlsec1-1.3.13-behavior.json

cargo run -p xml-sec-capability-ledger -- behavior-check \
  donors/xmlsec \
  compatibility/libxmlsec1-1.3.13-behavior-rules.json \
  compatibility/libxmlsec1-1.3.13-behavior.json
```

All four commands reject any donor version or commit other than the pinned
baseline. Extraction reads a detached snapshot of the recorded Git object, so
tracked edits and build-generated files in the donor checkout cannot affect the
artifact or be overwritten by generation. CI performs the same check from a
clean upstream checkout. Updating the donor requires reviewing the extracted
diff, changing classification rules where capabilities changed, and updating
category-count regression tests.
