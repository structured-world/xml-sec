# Provenance and use

All XML payloads, test identities, certificates and keys in `fixtures/` are synthetic.
They contain no invoices, real people, production keys, purchased signatures or customer data.
The included signer private key is deliberately public test material and grants no real trust.

The initial chain and baseline variants were generated locally with the repository's
`scripts/generate-xades-fixtures.sh`. Its only change is an optional output directory,
so the existing checked-in fixtures remain untouched. The new variants are defined by
`scripts/xades-interop.py`; independent libxmlsec1 computes every base signature.
Adversarial mutations preserve or break selected boundaries intentionally. `cases.json`
states expected XMLDSig validity, not expected application or XAdES acceptance.

The Filter2 expression reproduces the algorithm and selector from dotnet/runtime #82363;
no attachment, third-party signed XML or Business Central customer's corpus was copied.
Issue references supply scenario provenance only. No third-party normative full text,
JDK, native executable, Maven distribution or dependency jar is redistributed in the bundle.
The source and synthetic fixture contribution uses the repository's Apache-2.0 AND MIT
license declaration; retain the root LICENSE and LICENSE-THIRD-PARTY. DSS itself is a
separately downloaded LGPL-2.1-or-later test oracle, not a Rust runtime dependency.

The generation runners encode the signing commands. `results/` records native oracle
and Rust verification, byte artifacts and comparisons. `dss-evidence/` contains independently
produced validation reports and a portable dependency tree; configuration source is
under `dss/`. Reports are observations, including indeterminate and differing outcomes.
Process stdout/stderr, build logs, command captures and transient check records remain
local diagnostic artifacts, excluded from Git and the distributable bundle.
`dss-investigation/` contains additional synthetic, independently signed minimal
binding examples and DSS reports. They reuse the same public test keys and chain.
Its source-audit manifest records upstream source URLs and hashes without bundling
third-party source jars or normative full texts.
`SHA256SUMS` inventories distributable inputs, tools and evidence at packaging time.
