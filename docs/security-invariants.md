# Security Invariants

These are implementation assurances, not a claim of an independent security
audit. Policy permission, provider capability, cryptographic validity, and
application authorization are separate decisions.

The deterministic [historical attack corpus](historical-security.md) ties
public-path regressions to their original advisories and specification
invariants, with positive controls and explicit compatibility boundaries.

## Secrets and Ownership

HMAC verification, reference-digest equality, and exported recovered-key
deduplication use constant-time comparisons for equal, public algorithm widths.
Recovered-key equality combines byte equality and recovery validity without
short-circuiting on either secret. Non-exportable keys are compared by handle
identity, never by exporting their bytes. This is not a claim that the entire
XML processor is constant-time: parsing, public lengths, algorithms, and errors
are observable. Cryptographic providers own their primitive timing guarantees.

Owned symmetric keys, recipient KEKs, HMAC secrets, imported private keys,
derived secrets, and recovered candidates have zeroizing storage or a drop-wipe
implementation. Explicit clones own independent secrets and wipe independently.
Borrowed KEKs remain borrowed and are not cleared by the resolver. Callers must
protect their original buffers and any copies they create; low-level APIs that
return secret bytes transfer that responsibility to the caller. Debug output of
secret-bearing wrappers is redacted. Zeroization cannot erase prior copies,
swapped pages, crash dumps, or data retained by an external provider.

Regression coverage: `tests/secret_ownership.rs`,
`owned_secret_wipe_reuses_storage_and_preserves_independent_clones`,
`recovered_candidate_equality_includes_every_byte_and_validity`, and
`hmac_key_debug_redacts_secret_material`. Timing is established by the primitive
and source audit, not a statistical wall-clock test. Drop coverage uses the
`ZeroizeOnDrop` contract rather than reading freed memory.

## Bounded Work

Every operation uses its immutable typed resource policy, validated against
central non-configurable safety ceilings. Initial parsing, reparsing after
mutation, transforms, external resources, key search, and output construction
must consume the operation's budgets rather than reset them in helpers.
Exhaustion is terminal, including arithmetic overflow. Policy refusals remain
distinct from malformed input and cryptographic failures.

Boundary and aggregate coverage includes:

- `selected_backend_enforces_exact_depth_boundary` and
  `xmloxide_backend_enforces_exact_depth_boundary` for parser depth.
- `verification_entry_points_enforce_policy_depth`,
  `signing_string_entry_point_enforces_policy_depth`,
  `encryption_entry_points_enforce_policy_depth`, and
  `decryption_entry_points_enforce_policy_depth` for public operation wiring.
- `retained_mutations_share_one_sticky_parse_work_budget` and the four
  operation-specific initial-parse work-budget tests for parse accounting.
- `verify_all_shares_canonicalization_retention_budget`,
  `configured_reference_limit_is_shared_with_manifests`, and
  `stored_pre_digest_budget_counts_repeated_external_references` for fan-out.
- `typed_kem_ciphertext_shares_aggregate_cipher_value_budget`,
  `candidate_budget_exhaustion_is_fatal_after_a_key_was_found`, and
  `byte_budgets_remain_exhausted_after_overflow` for sticky exhaustion.

## Authenticated Targets

Verification evidence is bound to the retained document and generation. A
valid signature does not authorize an unsigned sibling or a lookalike target.
Applications should use explicit expected targets and trusted keys, not infer
authorization from a successful primitive or an embedded certificate.
[XMLDSig 1.1 §§8.1.1 and 8.1.3](https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-Security)
explain the distinction between signed content and what the application uses.

Duplicate registered IDs are ambiguous and cannot resolve to a signing target.
Caller registration must not shadow a conflicting default ID. Retained proofs
cannot authorize a different document or a later generation.

Regression coverage: `tests/verification_evidence.rs`, including cryptographic
wrapping with an unsigned decoy across compiled XML backends, duplicate IDs,
foreign/stale identities, distinct trusted keys, and mutation invalidation;
`duplicate_and_caller_registered_ids_share_one_index` and
`duplicate_default_id_stays_ambiguous_with_caller_registration` cover indexing.

## Provider Failure Isolation

The selected `CryptoProvider` is the only primitive dispatcher. Capability does
not grant policy permission, and an unsupported or failed operation does not
trigger a different engine. Opaque keys stay opaque. Recovery uncertainty is
preserved until authenticated content validation or an explicit caller-owned
authentication policy decides acceptance.

Regression coverage: `tests/provider_contract.rs` exercises opaque keys through
public encrypt/decrypt paths, policy refusal before dispatch, exact capability
checks, and no software fallback; `explicit_provider_digest_failures_are_returned`
checks error propagation. Provider-specific FIPS and PKCS#11 suites additionally
check binding and primitive behavior. No engine's presence in a build implies
that every algorithm is available from that engine.
