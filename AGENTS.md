# xml-sec Agent Rules

These rules extend `/Users/polaz/projects/sw/AGENTS.md` for this repository.

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
