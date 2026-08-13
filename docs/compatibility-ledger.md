# libxmlsec1 compatibility ledger

The machine-readable ledger at
[`compatibility/libxmlsec1-1.3.13.json`](../compatibility/libxmlsec1-1.3.13.json)
is the compatibility baseline for libxmlsec1 1.3.13. It inventories the public
surface from upstream commit `5fdd47dc35753438bdc38b6e96c1a3805c67a483`:

- installed headers, exported functions and variables, macros, build defines,
  public enums, structure layouts, callbacks, class IDs, and registries;
- generic and crypto-backend-specific APIs;
- algorithm and key-data URI constants and key serialization formats;
- `xmlsec1` CLI commands and exit statuses;
- top-level upstream conformance and interoperability test families.

The ledger is an honest parity map, not a blanket compatibility claim. Every
entry has one outcome, a rationale, and an evidence reference:

| Outcome | Meaning |
|---|---|
| `behavior-compatible` | The native Rust API implements the wire behavior and has repository test coverage. |
| `compatibility-profile-only` | The behavior exists but requires an explicit compatibility policy, normally for a legacy algorithm. |
| `provider-limited` | The Rust provider abstraction covers the capability, but not the backend-specific C API. |
| `binary-abi-incompatible` | The item belongs to libxmlsec1's C source/ABI surface, which the crate does not yet expose. |
| `intentionally-unsupported` | The item is deliberately excluded, currently limited to deprecated C aliases. |
| `planned` | The item is a visible parity target and is not implemented yet. |

The classification source is
[`compatibility/libxmlsec1-1.3.13-rules.json`](../compatibility/libxmlsec1-1.3.13-rules.json).
Rules are evaluated in order, so precise supported and policy-gated URI rules
precede the explicit planned fallback. A rule that matches nothing fails
generation, as does an extracted item without a rule or evidence reference.

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
