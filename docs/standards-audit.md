# Normative reference audit

Checked on 2026-09-07. The edition baseline is in [AGENTS.md](../AGENTS.md), and
[standards-sources.tsv](standards-sources.tsv) records the exact publisher URLs.
`bash scripts/fetch-standards.sh` obtains local reference copies, RFC status metadata,
the RFC errata registry, and retrieval checksums without adding third-party texts to Git.

## Findings and applicability

| Reference | Code / conclusion |
| --- | --- |
| XML 1.0 Fifth Edition, sections 4.1, 4.2, 5.1 | XSLT DTD preprocessing now rejects unknown EntityDef/PEDef forms and trailing tokens. The unused general-entity graph is checked for undeclared references and cycles, with the standalone/external-subset distinction preserved. Regression tests cover both the preprocessor and public parsing. |
| XML 1.0 Fifth Edition, sections 2.8, 3.3.3, 4.5 | Internal-subset entity declarations reject parameter-entity references. General-entity replacement text expands numeric character references before parsing markup. Removing the DTD preserves tokenized attribute normalization and referenced whitespace in attribute defaults. |
| XSLT 1.0 section 16.1, erratum E4 | XML output with an emitted standalone or DOCTYPE declaration requires a well-formed document, not an arbitrary fragment. The historical libxslt `exslt/math/max.3.xsl` fixture violates this requirement; the harness asserts rejection, then reruns its complete computation with only the standalone attribute removed and compares the complete remaining output. |
| XSLT 1.0 section 16.2; XML 1.1 section 2.11 | HTML inference considers preceding text, namespace-qualified HTML-output elements retain XML attribute escaping, and XML 1.1 NEL/LS text is emitted through references so reparsing does not normalize it to LF. |
| RFC 9231 section 2.3.6 | Replaces RFC 6931. The ECDSA decoder already selects fixed-width concatenation of `r` and `s` for XMLDSig and DER only for an explicitly selected compatibility representation; the obsolete reference was corrected. |
| RFC 9231 Appendix B | The emitted RSA-SHA224 and C14N 1.1 URIs already use the corrected spellings. The recommendation to understand historical erroneous aliases is distinct from the canonical output URI and from an obligation to implement every registered algorithm. |
| X.690 (2021), Erratum 1 (2021-09) | Corrects Figure 4's high-tag-number illustration. The erratum does not redefine BER/DER or require accepting noncanonical DER. The free ITU-T text is the ISO/IEC 8825-1:2021 counterpart. |
| RFC 5280, updated by RFC 10007 section 4 | CRL validation requires KeyUsage and cRLSign for a v3 issuer certificate. The version-specific authorization check preserves the v1/v2 exception; independent chain CA constraints still apply. Public-path tests cover absent usage, missing cRLSign, valid usage, and CRL-disabled verification; a unit test covers the version exception. |
| RFC 5280 Updates / RFC 8018 Updates | Downloaded current amendments, including RFC 9925/10007 and RFC 9879 (which replaces 9579). Their presence in the reference set is not a claim of implemented unsigned-certificate, policy-graph, or PKCS #12 PBMAC1 support. |

## Audit boundaries

- This is a reference inventory and a targeted code audit, not a full conformance certificate
  for every clause of every listed specification or every third-party crypto implementation.
- XPath 3.1, XSLT 3.0, and XSD 1.1 are downloaded comparison references. They do not silently
  replace XPath/XSLT 1.0 or the XSD 1.0 datatypes used by the existing engine.
- Reported errata are not automatically accepted corrections. Check the publisher's status
  and normative scope before changing behavior.
- ISO 8859 full texts were not obtained. The catalogue's HTTP 403 does not establish a
  licensing restriction. Open Unicode Consortium mapping tables support checking byte-to-Unicode
  conversion, not a claim that the full ISO normative text has been audited.
- Memory budgets, callback/reentrancy safety, typed API errors, and mutation atomicity are
  product invariants, not purported XML/RFC requirements.
