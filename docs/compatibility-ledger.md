# libxmlsec1 compatibility ledger

The machine-readable ledger at
[`compatibility/libxmlsec1-1.3.13.json`](../compatibility/libxmlsec1-1.3.13.json)
is the compatibility baseline for libxmlsec1 1.3.13. It inventories the public
surface from the upstream commit recorded in the canonical
[`libxmlsec1-1.3.13-donor-commit.txt`](../compatibility/libxmlsec1-1.3.13-donor-commit.txt)
pin:

- installed headers, exported functions and variables, complete macro
  definitions, compiler-provided build defines, typedef aliases, public enums,
  structure layouts, callbacks, class IDs, and registries;
- generic and crypto-backend-specific APIs;
- algorithm and key-data URI constants and key serialization formats;
- `xmlsec1` CLI commands and exit statuses;
- top-level upstream conformance and interoperability test families.

The ledger is an honest parity map, not a blanket compatibility claim. Every
entry has one outcome, a rationale, and an evidence reference:

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
checks rather than only their first physical line.

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

Both commands reject any donor version or commit other than the pinned
baseline. CI performs the same check from a clean upstream checkout. Updating
the donor requires reviewing the extracted diff, changing classification rules
where capabilities changed, and updating category-count regression tests.
