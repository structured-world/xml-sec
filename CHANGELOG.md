# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
