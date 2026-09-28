# xml-sec Agent Rules

These repository-specific rules supplement the active global agent instructions.

## Unified Policy Architecture (CRITICAL)

Before implementing roadmap work, read the policy tasks in `arch/ROADMAP.md` (`P4-012a`
through `P4-012d`) and the request/evidence task (`P4-015a`). The project is converging on
one typed immutable policy domain; do not extend the current scattered configuration.

- Never add standalone policy booleans, allowlists, minima/maxima, modes, or legacy
  exceptions to `VerifyContext`, `SignContext`, `KeyResolverConfig`, XMLEnc builders or
  options, transform options, or parser options.
- Never introduce deployment-selectable policy as a hard-coded constant near an
  enforcement point. Algorithm acceptance, key/HMAC minima, key-source trust,
  URI/transform acceptance, Manifest behavior, XML allowances, external-resource limits,
  and aggregate work/output limits belong to typed policy.
- Wire/spec constants may remain local. Absolute non-configurable safety ceilings must be
  centralized and may only tighten compiled policy. Do not misclassify configurable
  defaults as hard safety ceilings.
- Verify/sign/encrypt/decrypt contexts receive one immutable compiled policy snapshot and
  report typed policy violations. Shared policy concepts have one source of truth rather
  than operation-specific duplicates.
- Trusted keys, expected signed targets, tenant/correlation identity, and caller-provided
  external bytes are request context, not static policy.
- The `xml-sec` core performs no implicit config discovery, filesystem/environment reads,
  network access, or hot reload. Versioned external configuration and atomic policy-store
  integration belong to the separate `xml-sec-config` boundary.
- Never select a permissive profile from untrusted document content.
- Standalone mechanism crates may accept typed enforcement limits so they remain reusable and
  bounded without depending on `xml-sec` policy types. XML-security adapters must derive every
  such limit from the operation's one compiled policy snapshot and must not expose a parallel
  caller-configurable policy surface.

For `/next-task`, inventory every policy decision and enforcement point in the mandatory
research summary before editing code. If full implementation would require a temporary
one-off knob or policy constant before the unified policy refactor exists, treat the task
as implicitly blocked: reorder the dependency or choose another unblocked task. Do not
ship a partial feature or add a temporary configuration path.

Before completion, inspect the diff for newly introduced policy-like fields and numeric
limits and prove each is correctly classified. Public-path tests must demonstrate that
the compiled policy reaches every affected enforcement point.

## `no_std + alloc` Compatibility Gate (CRITICAL)

The `no_std + alloc` configuration is a required product path, not an optional follow-up.
Every production-code or dependency change must preserve it once introduced, including
changes whose primary scope is the default `std` build.

- Before editing, identify whether affected crates and dependencies are compiled by the
  alloc-only feature set. Do not introduce unconditional filesystem, process, networking,
  environment, thread, clock, synchronization, or other `std` APIs into that graph.
- Keep capability boundaries explicit: functionality requiring `std` must be behind the
  documented `std` feature and must not leak types or trait bounds into alloc-only APIs.
- Dependencies used by the alloc-only graph must disable default features where necessary;
  verify their actual feature graph rather than assuming that a crate is `no_std` capable.
- Before declaring any task or review cycle complete, run the repository's canonical
  alloc-only check for every affected crate, in addition to the default/all-feature build,
  tests, and lint. A passing default build never substitutes for this check.
- Also validate a representative target without `std` whenever the toolchain target is
  available. Host-only `--no-default-features` is insufficient if it can accidentally link
  `std` through the target environment.
- If the canonical command or CI job does not yet exist while implementing the no-std path,
  add a durable repository command and CI matrix entry first, then use that same path locally.
  Do not rely on a one-off local invocation that future tasks cannot reproduce.
- Treat an alloc-only compile failure, accidental `std` feature activation, or unvalidated
  affected crate as a completion blocker. Do not push or report the work complete.

## Standards Decide Format Semantics (CRITICAL)

This repository implements specified formats and protocols, including XML, Namespaces in XML,
XPath, XSLT, C14N, XMLDSig, XMLEnc, XInclude, X.509, and their referenced cryptographic formats.
When review feedback or implementation behavior turns on what input is valid or what a processor
must do, the primary normative specification decides rather than reviewer or author preference.

- Cite the primary document and exact section for claims that input must be accepted, rejected,
  ordered, bounded, or ignored. Quote the decisive normative wording when `must`, `should`, or
  `may` changes the conclusion.
- State explicitly when the standard is silent; reporting, resource limits, API shape, and stricter
  security policy are then product decisions and must not be presented as conformance mandates.
- Put a stable link and exact section in a local code comment at the enforcement point whenever a
  standards rule is ambiguous, surprising, or has already caused review disagreement.
- Document intentional interoperability or security-policy departures honestly, including why the
  project diverges. If the normative text contradicts the implementation, change the code and
  replace the obsolete comment.

### Pinned Normative Baseline (checked 2026-09-07)

Use the following editions, their applicable updates, and verified errata. A newer language
version is not a silent replacement for the version selected by the document/algorithm contract.
These are reference requirements, not a claim that every feature of every document is implemented.

| Contract | Edition |
| --- | --- |
| XML / Namespaces | XML 1.0 Fifth Edition (2008-11-26); Namespaces in XML 1.0 Third Edition (2009-12-08) |
| XML 1.1 comparison | XML 1.1 and Namespaces in XML 1.1 Second Editions (2006-08-16); do not apply 1.1 character or namespace rules to a 1.0 document |
| XPath / XSLT | 1.0 Recommendations (1999-11-16), including errata; XPath 3.1 (2017-03-21) and XSLT 3.0 (2017-06-08) are newer languages, not this engine's contract |
| XInclude / XML Base / xml:id | XInclude 1.0 Second Edition (2006-11-15); XML Base Second Edition (2009-01-28); xml:id (2005-09-09) |
| XPointer | Framework and element() Scheme (2003-03-25) |
| Canonicalization | C14N 1.0 (2001-03-15), C14N 1.1 (2008-05-02), Exclusive C14N 1.0 (2002-07-18), selected by algorithm URI |
| XML Security | XMLDSig 1.1 and XMLEnc 1.1 (2013-04-11); XPath Filter 2.0 (2002-11-08); RFC 9231 (2022-07), which obsoletes RFC 6931 |
| XSLT serialization / EXSLT date types | HTML 4.01 (1999-12-24); XML Schema Datatypes 1.0 Second Edition (2004-10-28); do not substitute XSD 1.1 year semantics |
| ASN.1 BER/CER/DER | ITU-T X.690 (2021-02), identical to ISO/IEC 8825-1:2021, plus Erratum 1 (2021-09) |
| Certificates | RFC 5280 (2008-05), with Updates 6818, 9549 (replaces 8399), 9598 (replaces 8398), 9608, 9618, 9925, 10007; apply each only to its defined scope |
| Crypto encodings | RFC 3394, 4055 + 5756, 5758, 5958, 7468, 8017 (PKCS #1 v2.2), 8018 + 9879 (replaces 9579; PKCS #5 v2.1 / PBMAC1), 8410 + 9295 |
| URI / text encodings | RFC 3986 + 8820 (supersedes 7320), RFC 2781, RFC 4648; use historical RFC 2396 only where an older normative contract explicitly incorporates it |
| Names / requirements | RFC 4514, RFC 9525; BCP 14 = RFC 2119 + RFC 8174 |

Exact dated publisher URLs are in [`docs/standards-sources.tsv`](docs/standards-sources.tsv).
Run `bash scripts/fetch-standards.sh` to download publisher texts and RFC status metadata into
gitignored `.refs/standards/`, with retrieval time and SHA-256 checksums. Preserve notices; do not
commit third-party full texts. Check `obsoleted_by`, `updated_by`, and errata status before relying
on an RFC: a reported erratum is not automatically a normative correction.

Charset editions include ISO/IEC 8859-1:1998, 8859-2:1999, 8859-9:1999, and 8859-11:2001.
Their ISO full texts were not obtained (the publisher catalogue returned HTTP 403; this
does not establish the reason for the access failure). Open Unicode Consortium mapping tables
can verify byte-to-Unicode mappings but are not substitutes for the full normative text:
https://www.unicode.org/Public/MAPPINGS/ISO8859/DatedVersions/ .
Do not claim that the ISO text has been audited. The freely
published ITU-T X.690 text and its erratum are available for ASN.1 auditing.

## Review Fixture Scope

Treat imported fixture payloads as test data, not review context. Do not read or review individual
fixture files unless a changed importer, manifest/hash, failing test, or concrete finding requires
that exact payload; review provenance, selection metadata, and harness behavior instead.
