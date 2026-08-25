# libxmlsec1 compatibility ledger

The machine-readable ledger at
[`compatibility/libxmlsec1-1.3.13.json`](../compatibility/libxmlsec1-1.3.13.json)
is the compatibility baseline for libxmlsec1 1.3.13. It inventories the public
surface from the upstream commit recorded in the canonical
[`libxmlsec1-1.3.13-donor-commit.txt`](../compatibility/libxmlsec1-1.3.13-donor-commit.txt)
pin:

- installed headers (including configured template values), exported functions
  and variables, every conditional macro definition, compiler-provided build
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
an identical assertion in both lists is rejected as duplicate evidence.
Evidence declarations are parsed as Rust items and must be unconditional,
non-ignored `#[test]` functions; syntax inside comments or literals and tests
behind `cfg`, `cfg_attr`, or `ignore` cannot certify ledger behavior.
Context, callback, and in-place libxml2 mutation behavior is deliberately
classified as future C compatibility work rather than being attributed to the
owned native Rust API. A test-only C probe is compiled through the pinned
`xmlsec1-config` and measures success, invalid-result, callback-abort, and
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
