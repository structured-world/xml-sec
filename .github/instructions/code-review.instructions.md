---
applyTo: "**/*.rs"
---

# Code Review Instructions for xml-sec

## Scope Rules (CRITICAL)

- **Review ONLY code within the PR's diff.** Do not suggest inline fixes for unchanged lines.
- For issues in code **outside the diff**, suggest creating a **separate issue** instead of proposing code changes. Example: "Consider opening an issue to add namespace validation here — this is outside this PR's scope."
- **Read the PR description carefully.** If the PR body has an "out of scope" section listing items handled by other PRs, do NOT flag those items.

## Rust Standards

- `unsafe` blocks require `// SAFETY:` comments explaining the invariant
- Prefer `#[expect(lint)]` over `#[allow(lint)]` — `#[expect]` warns when suppression becomes unnecessary
- Use `TryFrom`/`TryInto` for fallible conversions; `as` casts need `#[expect(clippy::cast_possible_truncation)]` with reason
- No `unwrap()` / `expect()` on I/O paths — use `Result` propagation
- `expect()` is acceptable for programmer invariants (lock poisoning) with `#[expect(clippy::expect_used, reason = "...")]`
- Code must pass `cargo clippy --all-features -- -D warnings`

## Testing

- Corruption/validation tests: tamper the relevant field (e.g., digest value, signature bytes, base64 encoding) and assert the error
- Use same serialization as production (e.g., canonical XML output, not shortcuts)
- Test naming: `fn <what>_<condition>_<expected>()`
