---
applyTo: "**/*.rs"
---

# Rust Code Review Instructions

## Review Priority (HIGH -> LOW)

Focus review effort on real bugs, not cosmetics. Stop after finding issues in higher tiers -- do not pad reviews with low-priority nitpicks.

### Tier 1 -- Logic Bugs and Correctness (MUST flag)
- Data corruption: wrong algorithm, incorrect ordering, dropped or duplicated data
- Off-by-one in boundaries, index lookups, or range operations
- Checksum/hash mismatches: computing over wrong byte range, verifying against stale value
- TOCTOU: checking state then acting on it without holding a lock or atomic operation
- Missing validation: unchecked index, unvalidated input from network/disk/external source
- Resource leaks: unclosed file handles, missing cleanup on error paths
- Concurrency: data races, lock ordering violations, missing synchronization
- Error swallowing: `let _ = fallible_call()` silently dropping errors that affect correctness
- Integer overflow/truncation on sizes, offsets, lengths, or security-critical values

### Tier 2 -- Safety and Crash Recovery (MUST flag)
- `unsafe` without `// SAFETY:` invariant explanation
- `unwrap()`/`expect()` on I/O, network, or deserialization paths (must use `Result` propagation)
- Crash safety: write ordering that leaves data unrecoverable after power loss
- Sensitive data (keys, passwords, tokens) not wrapped in `Zeroize`/`Zeroizing`
- Constant-time comparison not used for cryptographic MACs/checksums
- Hardcoded secrets, credentials, or private URLs

### Tier 3 -- API Design and Robustness (flag if clear improvement)
- Public API missing `#[must_use]` on builder-style methods or non-`Result` types callers might discard
- `pub` visibility where `pub(crate)` suffices
- Missing `Send + Sync` bounds on types used across threads
- `Clone` on large types where a reference would work
- Fallible operations returning `()` instead of `Result`

### Tier 4 -- Style (ONLY flag if misleading or confusing)
- Variable/function names that actively mislead about behavior
- Dead code (unused functions, unreachable branches)

## DO NOT Flag (Explicit Exclusions)

These are not actionable review findings. Do not raise them:

- **Comment wording vs code behavior**: If a comment says "flush when full" but the threshold uses `>=` not `>`, the intent is clear. Do not suggest rewording comments to match exact operators or implementation details. Comments describe intent, not repeat the code.
- **Comment precision**: "returns the key" when it technically returns `Result<Key>` -- the comment conveys meaning, not type signature.
- **Magic numbers with context**: `4` in `assert_eq!(header.len(), 4, "expected u32 checksum")` -- the assertion message provides context. Do not suggest a named constant when the value is used once in a test with an explanatory message.
- **Domain constants**: Specific numeric values for block sizes (e.g., `4096`), key sizes, protocol version numbers, port numbers, or configuration defaults are domain constants, not magic numbers, when used with surrounding context.
- **Minor naming preferences**: `lvl` vs `level`, `opts` vs `options`, `enc_part` vs `encrypted_part` -- these are team style, not bugs.
- **Import ordering**: Import grouping or ordering style. Unused imports are NOT cosmetic -- they cause `clippy -D warnings` failures and must be removed.
- **Test code style**: Tests prioritize readability and explicitness over DRY. Repeated setup code in tests is acceptable.
- **`#[allow(clippy::...)]` with justification comment**: When `#[allow]` has an adjacent comment explaining why it is used instead of `#[expect]`, do not suggest switching. Common reason: the lint does not fire on the current code but the suppression is kept defensively. `#[expect]` would fail the build with "unfulfilled expectation" in that case.
- **`#[allow(clippy::...)]` in existing/unchanged code**: Do not flag `#[allow]` suppressions in unchanged lines. New code should use `#[expect]` when the lint actually fires.
- **Temporary directory strategies in existing code**: Existing tests using manual temp paths are not a finding. New tests should prefer `tempfile::tempdir()`.
- **Semver concerns on pre-1.0 crates**: Adding required methods to public traits, changing public API signatures, or restructuring modules in a crate with version `0.x.y` is expected and does not require a default implementation or sealed trait pattern. Semver breakage only matters at `>= 1.0.0`.
- **Test infrastructure scripts (shell)**: Shell scripts in `tests/` that set up Docker containers, KDCs, databases, or other test infrastructure are not production code. Do not flag hardcoded test credentials (they are overridable via env vars), redundant principal creation (required by the specific technology), or non-production patterns in these scripts.
- **Previously resolved review threads**: If the same suggestion was already raised and resolved in a prior review round on this PR, do not re-raise it. Check the resolved threads before flagging.

## Scope Rules

- **Review ONLY code within the PR's diff.** Do not suggest inline fixes for unchanged lines.
- For issues **outside the diff**, suggest opening a separate issue.
- **Read the PR description.** If it lists known limitations or deferred items, do not re-flag them.

## Rust-Specific Standards

- Prefer `#[expect(lint)]` over `#[allow(lint)]` when the lint actually fires -- `#[expect]` warns when suppression becomes unnecessary. Use `#[allow(lint)]` with a justification comment when the lint does not fire but defensive suppression is desired.
- `TryFrom`/`TryInto` for fallible conversions; `as` casts need justification
- No `unwrap()` / `expect()` on I/O paths -- use `?` propagation
- `expect()` is acceptable for programmer invariants (e.g., lock poisoning, `const` construction) with reason
- Code must pass `cargo clippy --all-features -- -D warnings`
- RFC/spec compliance comments (e.g., "RFC 4120 section 7.5.1") are documentation -- preserve them

## Testing Standards

- Test naming: `fn <what>_<condition>_<expected>()` or `fn test_<scenario>()`
- Use `tempfile::tempdir()` for test directories -- ensures cleanup even on panic
- Integration tests that require infrastructure use `#[ignore = "reason"]`
- Prefer `assert_eq!` with message over bare `assert!` for better failure output
- Hardcoded values in tests are fine when accompanied by explanatory comments or assertion messages
