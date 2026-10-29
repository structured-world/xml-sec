# Provenance and use

All XML payloads, test identities, certificates and keys in `fixtures/` are synthetic.
They contain no invoices, real people, production keys, purchased signatures or customer data.
The included signer private key is deliberately public test material and grants no real trust.

The initial chain and baseline variants were generated locally with the repository's
fixture generator (`xades fixtures` of `xml-sec-tools`) with a separate output directory,
so the existing checked-in fixtures remain untouched. The new variants are defined by
`xades corpus --generate` of `xml-sec-tools`; independent libxmlsec1 computes every base signature.
Adversarial mutations preserve or break selected boundaries intentionally. `cases.json`
states expected XMLDSig validity, not expected application or XAdES acceptance.

The Filter2 expression reproduces the algorithm and selector from dotnet/runtime #82363;
no attachment, third-party signed XML or Business Central customer's corpus was copied.
Issue references supply scenario provenance only. No third-party normative full text,
JDK, native executable, Maven distribution or dependency jar is redistributed in the bundle.
The source and synthetic fixture contribution uses the repository's Apache-2.0 AND MIT
license declaration; retain the root LICENSE and LICENSE-THIRD-PARTY. DSS itself is a
separately downloaded LGPL-2.1-or-later test oracle, not a Rust runtime dependency.

The generation runners encode the signing commands. Only selected signed inputs and
construction inputs are retained; unrelated output from the broader baseline generator
is excluded. The `expected-*.bin` files are independently captured libxmlsec1 vectors,
never Rust outputs. Every retained vector is checked against fresh execution in CI.
The `*expectations.json` files pin the observed behavior of DSS 6.5.1, including known
disagreements with the normative profile; they are consumed by the same live check.
Actual Rust/replay bytes, computed comparisons, tool/dependency snapshots, full DSS
reports, stdout/stderr, build logs and command captures remain run artifacts, excluded
from Git and the distributable bundle.
`dss-investigation/` contains additional synthetic, independently signed minimal
binding examples and compact DSS observations. They reuse the same public test keys and chain.
Its source-audit manifest records upstream source URLs and hashes without bundling
third-party source jars or normative full texts.
The corpus `SHA256SUMS` pins its maintained assets. Packaging adds a separate root
inventory for the complete source overlay and verifies all archived bytes.
