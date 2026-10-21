# XSLT Conformance Gate

The contract is XSLT 1.0 and XPath 1.0, with applicable errata. Newer XSLT/XPath
editions are not substituted. Normative behavior takes precedence over a donor
quirk; compatibility and secure-policy decisions remain distinct.

## Corpus And Evidence

| Surface | Executable evidence |
| --- | --- |
| Pinned libxslt 1.1.45 corpus | `xml-sec-xslt::libxslt_oracle`: all 554 registered invocations and the complete 2,021-file source inventory |
| Selected W3C Recommendation examples | All 83 REC/REC2 invocations, including standalone stylesheets; independently checked selection, executed by the full corpus harness |
| Historical XMLDSig XSLT vectors | Second Edition, Merlin and Phaos suites through public sign/verify and compiled reference execution |
| Certificate-independent reference execution | Phaos XSLT chains verified with an explicit caller key; the separate trust tests retain their exact negative outcomes |
| Exact digest/signature agreement | Reciprocal `xmlsec1_interop` tests for terminal XSLT and XSLT followed by canonicalization |
| Adapters and failure classes | `xslt_transform_integration`: node-set/octet conversion, Base64, chained stylesheets, compilation, sandbox and cumulative work/output limits |
| Resolver and runtime accounting | Engine tests check authorization order, stable resource identity, URI handling, recursion, result growth and typed budget refusals |
| Mutation coverage | `xslt_execution` and `transform_parameters`, with malformed, recursive, amplification, sandbox, serializer and in-memory module-cycle seeds |

The REC/REC2 selection comes from libxslt's tests of W3C Recommendation examples.
It is not the complete W3C test suite, the unrelated XSL-FO suite, or an XSLT 3.0
compatibility-mode claim. Source revision, licensing and all fixture hashes are
retained with the corpus; no fixture is rewritten to match this implementation.

The engine harness compares portable serialized bytes with pinned golden output.
Its narrowly scoped exceptions document the decisive normative clause or donor
lexical behavior at the comparison point, and have negative tests against
truncation and unrelated changes. Examples include generated identifiers, permitted
attribute ordering, numeric rounding and invalid standalone output. A processing
error is not an arbitrary substitute for successful output. Historical defCan-3
is disabled by upstream itself: our test still executes it and asserts its exact
pre-digest output and digest mismatch instead of silently skipping it.

## Reproduce

Provision the existing pinned oracle with `bash scripts/install-xmlsec1.sh` and
set its reported library path. Use a checkout of the libxslt commit recorded in
`compatibility/libxslt-1.1.45-donor-commit.txt`:

```sh
LIBXSLT_SOURCE_DIR=/path/to/pinned/libxslt \
XMLSEC1_BIN=/path/to/provisioned/bin/xmlsec1 \
bash scripts/check-xslt-conformance.sh
```

The command verifies source/fixture provenance, requires xmlsec1 1.3.13 with its
XSLT capability, runs the full engine suite and all selected public-pipeline
suites, and cleans successful builds. Developer case-range variables cannot
reduce this gate. Missing or incompatible oracles fail before any tests; failed
builds and reproducer data remain available for diagnosis.

Mutation smoke tests and longer campaigns use the commands in
[`fuzz/README.md`](../fuzz/README.md). CI requires the conformance job and mutation
jobs; test-only native oracles are never production dependencies. Performance,
cache qualification and superiority claims require separate measurements.
