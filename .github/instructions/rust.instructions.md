---
applyTo: "**/*.rs"
---

# Rust Code Review Instructions

## Review Priority (HIGH → LOW)

Focus review effort on real bugs, not cosmetics. Stop after finding issues in higher tiers — do not pad reviews with low-priority nitpicks.

### Tier 1 — Logic Bugs and Correctness (MUST flag)
- Incorrect algorithm: wrong canonicalization order, wrong namespace handling, off-by-one, TOCTOU
- Missing validation: unchecked array index, unvalidated input from XML/base64
- Resource leaks: unclosed handles, missing cleanup
- Concurrency: data races, lock ordering, shared mutable state without sync
- Error swallowing: `let _ = fallible_call()` silently dropping errors that affect correctness
- Integer overflow/truncation on security-critical paths (nonces, sizes, lengths)

### Tier 2 — Safety and Security (MUST flag)
- `unsafe` without `// SAFETY:` invariant explanation
- `unwrap()`/`expect()` on I/O or network data (must use `Result` propagation)
- Sensitive data (keys, passwords) exposed in logs or error messages
- Constant-time comparison not used for digest/signature comparison
- Hardcoded secrets, credentials, or private URLs

### Tier 3 — API Design and Robustness (flag if clear improvement)
- Public API missing `#[must_use]` on `Result`-returning methods
- `pub` visibility where `pub(crate)` suffices
- Missing `Send + Sync` bounds on types used across threads
- `Clone` on large types where a reference would work

### Tier 4 — Style (ONLY flag if misleading or confusing)
- Variable/function names that actively mislead about behavior
- Dead code (unused functions, unreachable branches)

## DO NOT Flag (Explicit Exclusions)

These are not actionable review findings. Do not raise them:

- **Comment wording vs code behavior**: If a comment describes intent that slightly differs from implementation details, the intent is clear. Do not suggest rewording comments to match implementation details. Comments describe intent and context, not repeat the code.
- **Comment precision**: "returns X" when it technically returns `Result<X>` — the comment conveys meaning, not type signature.
- **Magic numbers with context**: Algorithm URI strings used once with a descriptive variable name or comment. Do not suggest extracting a named constant when the value is used once with clear context.
- **Minor naming preferences**: `algo` vs `algorithm`, `ns` vs `namespace` — these are team style, not bugs.
- **Import organization**: Single unused import that clippy would catch anyway.
- **Test code style**: Tests prioritize readability and explicitness over DRY. Repeated setup code in tests is acceptable.
- **`#[allow(clippy::...)]` with justification comment**: Respect the author's suppression if explained.
- **W3C spec section references**: Comments referencing W3C spec sections (e.g., "XMLDSig §4.3.3.2", "Exc-C14N §3") are documentation, not noise. Do not flag as unnecessary or suggest removal.

## Scope Rules

- **Review ONLY code within the PR's diff.** Do not suggest inline fixes for unchanged lines.
- For issues **outside the diff**, suggest opening a separate issue.
- **Read the PR description.** If it lists known limitations or deferred items, do not re-flag them.

## Rust-Specific Standards

- Prefer `#[expect(lint)]` over `#[allow(lint)]` — `#[expect]` warns when suppression becomes unnecessary
- `TryFrom`/`TryInto` for fallible conversions; `as` casts need justification
- No `unwrap()` / `expect()` on I/O paths — use `?` propagation
- `expect()` is acceptable for programmer invariants (e.g., `const` construction) with reason
- Code must pass `cargo clippy --all-features -- -D warnings`
- W3C/RFC compliance comments (e.g., "XMLDSig §4.3.3.2", "RFC 3986 §5.3") are documentation, not noise — preserve them

## Testing Standards

- Test naming: `fn test_<what>_<condition>()` or `fn test_<scenario>()`
- Integration tests that require infrastructure use `#[ignore = "reason"]`
- Prefer `assert_eq!` with message over bare `assert!` for better failure output
- Hardcoded values in tests are fine when accompanied by explanatory comments or assertion messages
