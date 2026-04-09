# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.5](https://github.com/structured-world/xml-sec/compare/v0.1.4...v0.1.5) - 2026-04-09

### Added

- *(xmldsig)* add keyinfo dispatch parsing

### Documentation

- *(xmldsig)* clarify keyinfo lax vs strict behavior
- *(xmldsig)* align verify pipeline rustdoc
- *(xmldsig)* clarify deferred keyinfo consumption
- *(xmldsig)* document whitespace helper and signature checks

### Fixed

- *(xmldsig)* stream digestvalue normalization
- *(xmldsig)* gate keyinfo parse by resolver intent
- *(xmldsig)* address KeyInfo review feedback
- *(xmldsig)* preserve keyvalue qname and whitespace coverage
- *(xmldsig)* restrict eckeyvalue dispatch to dsig11
- *(xmldsig)* allow lax empty x509data parsing
- *(xmldsig)* require supported x509data children
- *(xmldsig)* harden x509data namespace validation
- *(xmldsig)* reject unknown ds children in x509data
- *(xmldsig)* bound keyname text length
- *(xmldsig)* tighten keyinfo and signature child parsing
- *(xmldsig)* harden signature child validation
- *(xmldsig)* cap keyinfo der payload and clarify errors
- *(xmldsig)* harden keyinfo and signature child parsing

### Refactored

- *(xmldsig)* remove unreachable signature child check

### Testing

- *(xmldsig)* isolate signature-child structure regressions
- *(xmldsig)* tighten saml idp fixture coverage
- *(xmldsig)* stabilize saml fixture integration
- *(xmldsig)* add real saml idp integration test

## [0.1.4](https://github.com/structured-world/xml-sec/compare/v0.1.3...v0.1.4) - 2026-04-04

### Added

- *(xmldsig)* process manifest references

### Documentation

- *(xmldsig)* clarify manifest error semantics
- *(xmldsig)* update process_reference rustdoc

### Fixed

- *(xmldsig)* match signed manifests by node identity
- *(xmldsig)* gate manifest processing to signed refs
- *(xmldsig)* refine manifest verdict contract
- *(xmldsig)* harden manifest child validation
- *(xmldsig)* classify manifest precheck failures accurately
- *(xmldsig)* make manifest processing non-fatal
- *(xmldsig)* clarify manifest reference diagnostics

### Testing

- *(xmldsig)* cover signed-object manifest path
- *(xmldsig)* keep accepting-key manifest tests valid
- *(xmldsig)* tighten manifest non-fatal contracts
- *(xmldsig)* decouple manifest fixture from parser

## [0.1.3](https://github.com/structured-world/xml-sec/compare/v0.1.2...v0.1.3) - 2026-04-04

### Fixed

- *(xmldsig)* remove redundant rsa modulus check
- *(xmldsig)* align review feedback on docs and mismatch errors
- *(xmldsig)* tighten p521 checks and docs
- *(xmldsig)* preserve source chain for reference errors

### Refactored

- *(xmldsig)* migrate ring to rustcrypto
- *(test)* make donor vector xml_path required

### Testing

- *(xmldsig)* assert concrete skip outcomes
- *(xmldsig)* clarify x509 skip blocker reasons
- *(xmldsig)* tighten skipped vector guardrails
- *(xmldsig)* document intentional fixture discard pattern
- *(xmldsig)* align donor vector fixture coverage
- *(xmldsig)* validate skip vector fixture paths
- *(xmldsig)* align donor skip case metadata
- *(xmldsig)* use assert_eq for failure count
- *(xmldsig)* skip fixture reads for skipped vectors
- *(xmldsig)* add donor full verification suite accounting

## [0.1.2](https://github.com/structured-world/xml-sec/compare/v0.1.1...v0.1.2) - 2026-03-29

### Added

- *(xmldsig)* add VerifyResult status model
- *(xmldsig)* add VerifyContext builder policies
- *(xmldsig)* add full signature verify pipeline
- *(xmldsig)* add ecdsa signature verification

### Documentation

- *(xmldsig)* document verify ok/err contract
- *(xmldsig)* note fail-fast truncation in verify result
- *(xmldsig)* clarify resolver miss contract
- *(xmldsig)* clarify canonicalized SignedInfo pre-digest semantics
- *(xmldsig)* clarify external uri policy limitation
- *(xmldsig)* clarify manifest fail-closed behavior
- *(readme)* clarify xmldsig verify-only status
- *(xmldsig)* document pipeline structural constraints
- *(xmldsig)* clarify strict der parsing fallback

### Fixed

- *(xmldsig)* preserve decode errors before key lookup
- *(xmldsig)* carry reference index at mismatch source
- *(xmldsig)* fail closed on manifest-typed references
- *(xmldsig)* remove redundant builder must_use attrs
- *(xmldsig)* detect nested manifests in object subtree
- *(xmldsig)* address verifier policy review feedback
- *(xmldsig)* enforce URI and implicit C14N policies
- *(xmldsig)* tighten digest and signature child parsing
- *(xmldsig)* align DigestValue whitespace normalization
- *(xmldsig)* harden SignatureValue text parsing
- *(xmldsig)* tighten verify result and char handling
- *(xmldsig)* tighten signaturevalue limits and module docs
- *(xmldsig)* enforce xml whitespace set in signaturevalue
- *(xmldsig)* bound signaturevalue size and c14n node checks
- *(xmldsig)* return MissingElement when SignedInfo absent
- *(xmldsig)* treat malformed ecdsa signature bytes as invalid
- *(xmldsig)* align signaturevalue base64 whitespace rules
- *(xmldsig)* reject ambiguous signature selection
- *(xmldsig)* classify missing signedinfo as missing element
- *(xmldsig)* enforce signaturevalue structure
- *(xmldsig)* enforce SignedInfo position and uniqueness
- *(xmldsig)* normalize signature value text nodes
- *(xmldsig)* handle empty SignatureValue as present element
- *(xmldsig)* reject non-ecdsa algorithms early
- *(xmldsig)* tighten ecdsa der classification
- *(xmldsig)* cover spki happy path and der parsing
- *(xmldsig)* align signature format error mapping
- *(xmldsig)* retry fixed verifier for ambiguous ecdsa
- *(xmldsig)* prefer raw width and round ec bytes
- *(xmldsig)* harden ecdsa key validation
- *(xmldsig)* handle raw signatures with 0x30 prefix
- *(xmldsig)* harden ecdsa signature parsing

### Performance

- *(xmldsig)* defer key resolution to final verify step

### Refactored

- *(xmldsig)* require URI in ReferenceResult
- *(xmldsig)* reuse per-reference invalid status
- *(xmldsig)* re-export transform uri constants
- *(xmldsig)* mark uri policy type as must-use
- *(xmldsig)* share transform URI constants
- *(xmldsig)* mark verify context as must-use
- *(xmldsig)* relax key resolver object lifetime
- *(xmldsig)* make ascii narrowing explicit
- *(xmldsig)* simplify ascii whitespace byte path
- *(xmldsig)* clarify shared constants and ECDSA flow
- *(xmldsig)* unify signature child parsing

### Testing

- *(xmldsig)* harden verify result API and resolver-miss checks
- *(xmldsig)* assert mismatch reasons in tamper tests
- *(xmldsig)* rename key-not-found status test
- *(xmldsig)* align panic resolver with trait lifetime
- *(xmldsig)* cover nested manifest rejection
- *(xmldsig)* add verify context policy regressions
- *(xmldsig)* reject oversized SignatureValue payloads
- *(xmldsig)* cover non-empty signature without SignedInfo
- *(xmldsig)* make xml decl stripping line-ending agnostic
- *(xmldsig)* cover signature selection guards
- *(xmldsig)* relax ds tag opener parsing in fixtures
- *(xmldsig)* add ecdsa tamper pipeline coverage
- *(xmldsig)* reuse ds-aware helper for SignatureValue mutation
- *(xmldsig)* harden verify pipeline review fixes

## [0.1.1](https://github.com/structured-world/xml-sec/compare/v0.1.0...v0.1.1) - 2026-03-26

### Added

- *(xmldsig)* add RSA signature verification
- *(xmldsig)* add reference verification pipeline
- *(test)* add donor test fixtures and C14N golden file tests
- *(c14n)* add xml:* attr inheritance, C14N 1.1 mode, xml:base URI resolution
- *(xmldsig)* add URI dereference for Reference elements
- *(c14n)* implement XML canonicalization (inclusive + exclusive)
- initial scaffold — Cargo.toml, src/lib.rs, CI workflows, README

### Documentation

- *(readme)* add c14n 1.1 spec row
- *(xmldsig)* tighten review follow-ups
- *(xmldsig)* tighten review follow-ups
- *(test)* add xmllint with-comments note to golden test module doc
- *(c14n)* document schemeless base behavior in resolve_uri
- *(xmldsig)* clarify NodeSet::subtree doc re attribute/namespace tracking
- *(c14n)* add UTF-8 requirement doc, remove stale file reference
- *(c14n)* clarify with_prefix_list is exclusive-mode only

### Fixed

- *(release)* publish without generated lockfile
- *(release)* address remaining review threads
- *(release)* tighten workflow housekeeping
- *(release)* align release automation with crates.io
- *(release)* harden release workflows
- *(xmldsig)* harden verifier API usage
- *(xmldsig)* prevalidate RSA key constraints
- *(xmldsig)* harden RSA key parsing
- *(xmldsig)* tighten parser invariants
- *(review)* tighten remaining review follow-ups
- *(review)* address PR feedback
- *(xmldsig)* tighten compat xpath child parsing
- *(lint)* replace map_or with is_none_or (clippy::unnecessary_map_or)
- *(test)* panic on I/O errors in fixture file counter
- *(test)* use char-safe truncation in golden test error messages
- *(xmldsig)* validate Transforms element and reject unexpected children
- *(c14n)* replace expect() with ? in parse_base for clippy compliance
- *(c14n)* validate scheme in parse_base, merge paths for schemeless bases
- *(c14n)* preserve query/fragment from reference during URI resolution
- *(c14n)* merge_paths returns reference unchanged for non-hierarchical base
- *(c14n)* preserve relative leading .. segments, update stale docs
- *(c14n)* correct RFC 3986 URI recomposition and edge cases
- *(c14n)* skip xml:* inheritance for Exclusive C14N per Exc-C14N §3
- *(c14n)* seed xml:base walk with included ancestor, filter empty values
- *(c14n)* correct RFC 3986 URI parsing, skip empty xml:base values
- *(c14n)* stop xml:* ancestor walk at nearest included ancestor
- *(xmldsig)* reject empty xpointer id, document local-name matching
- *(xmldsig)* safe xpointer quote parsing, same-element dedup guard
- *(xmldsig)* prevent duplicate ID re-insertion on 3+ occurrences
- *(xmldsig)* reject duplicate IDs, guard foreign nodes, reject empty fragment
- *(xmldsig)* harden URI dereference error handling and DoS safety
- *(c14n)* treat default ns as visibly utilized for unprefixed elements
- *(c14n)* use Result in doctests, fix has_in_scope_default_namespace doc
- *(c14n)* correct xmlns="" suppression for document subsets
- *(c14n)* use lexical prefixes from source XML instead of lookup_prefix()
- *(c14n)* clarify UTF-8 error, fix inclusive ns doc, document subset edge case
- *(c14n)* escape CR in PI/node content, reject C14N 1.1

### Performance

- *(c14n)* document clone() cost and deferred optimization path

### Refactored

- *(xmldsig)* mark signature uri accessor as must_use
- *(xmldsig)* mark all_valid as must_use
- *(xmldsig)* mark signature lookup as must_use
- *(xmldsig)* mark signing_allowed as must_use
- *(xmldsig)* use expect() for hardcoded C14N URI invariant
- *(xmldsig)* use #[expect] over #[allow] in test module, trim doc comment
- *(c14n)* use as_deref/as_ref for Option<String> borrowing
- *(c14n)* restrict xml:* inheritance to spec whitelist, remove expect()
- *(c14n)* use impl Fn for ns predicate instead of &dyn Fn
- *(c14n)* extract shared namespace-declaration pipeline into ns_common
- *(xmldsig)* derive doc from element in NodeSet::subtree, consolidate test helpers
- *(xmldsig)* remove unused UriDeref error variant
- *(c14n)* encapsulate C14nAlgorithm fields, remove dead code

### Testing

- *(xmldsig)* vendor donor RSA fixtures
- *(xmldsig)* update digest parser fixtures
- *(c14n)* add schemeless base URI resolution test
