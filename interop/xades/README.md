# XAdES interoperability corpus

Transform/C14N and XMLDSig interoperability is **verified** for the cases below.
This is not a claim of complete XAdES, trusted-signature or Business Central compatibility.
All validation runs are local; fixtures are never uploaded to online validators.

## Frozen baseline and API

- Repository: `structured-world/xml-sec`, commit `834c463798060dca613bb93dd78dcdc7f949c948`.
  The frozen implementation baseline is independent of the accompanying test-tooling overlay.
- `xml-sec 0.2.0`, `xml-sec-xades 0.1.0`; published `structured-{asn1,pkix,cms,ltv,xades} 0.11.0`.
- Probe: `cargo build -p xml-sec-xades --example interop_probe`, default XAdES features.
  Core features: `std,xmldsig,c14n,xml-backend-xmloxide,embedded,no-unsafe`.
  This probe does not enable XMLEnc, XSLT, FIPS, PKCS#11 or legacy crypto.
- Initial capture: Rust/cargo 1.99.0 and Python 3.11.9. Each live run records its own
  tool versions and dependency/features metadata in the output directory, outside Git.
- Independent oracle: Homebrew **libxmlsec1 1.3.12 (openssl)**, native Mach-O binary.
  This is not this repository's Rust `tools/xmlsec1`. Its linked OpenSSL is **3.6.4**;
  the credential generator's separate `openssl` executable is **4.0.3**.
- Independent profile diagnostics: **EU DSS 6.5.1**, Maven **3.9.12**, OpenJDK **21.0.12.1**.
  Versioned expectations are in `dss-evidence/expectations.json` and
  `dss-investigation/*expectations.json`; CI compares fresh observations with them.
  Dependency trees, actual outputs and full reports are run artifacts, excluded from Git and the bundle.
  CI uses native libxmlsec1 1.3.13 from the repository's pinned installer, Rust 1.92.0 and JDK 21.

The Rust probe uses `with_verified_request`, original `SignatureEvidence`,
`select_signature`, `visit_authenticated_references`, and
`replay_reference(ReferenceOutput)`. `validate_basic` receives that same verified session.
It records `accepted(document)` separately from `all_valid()`. It never reconstructs a
verification context to bypass failed authentication or requests replay on an unauthenticated
instruction. `store_pre_digest(true)` captures the original attempt's diagnostic octets and
SignedInfo; authenticated replay bytes are compared separately. Failed references may stop the
pipeline before later references or SignedInfo; those artifacts are **not run or blocked**.
In particular a failed digest does not make replay an authenticated evidence channel.

## Inputs and byte evidence

`cases.json` enumerates **34** synthetic signed documents and mutations. The base
XAdES envelope has two references: business data and typed `#sp` SignedProperties.
Every positive base input is signed by independent libxmlsec1 with RSA-SHA256/SHA-256.
There is no Rust self-sign/self-verify evidence in this package.

| Scenario / boundary | Status | Observation |
| --- | --- | --- |
| Exact reproducer's `/descendant::ds:Signature` Filter2 subtract | verified | Reference octets, digests, SignedInfo and XMLDSig agree |
| Ordinary enveloped-signature control | verified | Both references and signature agree |
| Filter2 intersect → subtract → union; subsequent union restores a removed subtree | verified | Order and restored content reflected in exact octets; mutation of union-selected content fails |
| Attribute / namespace-axis selection | verified | Both engines emit the same subset bytes; original-owner coverage is not inferred |
| C14N 1.1 as Reference transform | verified | Omitted ancestors contribute normalized `xml:base` and `xml:lang`; their `xml:id` is not inherited |
| C14N 1.1 as SignedInfo CanonicalizationMethod | verified | Independent SignedInfo bytes include inherited base/lang, not the ancestor ID |
| Comments | verified | Explicit `#xpointer(/)` plus WithComments retains comments; changing them fails. Ordinary empty URI omits comments and their mutation survives |
| Namespace, namespaced attribute, xml:id and xml:base mutations | verified | Each covered mutation fails reference digest comparison |
| Included content / SignatureValue / KeyInfo signer certificate mutation | verified | Digest, signature mismatch or key validation refuses as appropriate |
| Excluded subtree / appended unsigned Signature Object mutation | verified | Original signature remains valid; reference bytes are unchanged |
| Empty transform result | verified | SHA-256(empty) verifies; expected business-object acceptance is false |
| Duplicate ID | verified | Rust refuses ambiguous `#payload` resolution; oracle also refuses with equivalent ID registrations |
| Wrapping / wrong expected object | verified | Original signed Data remains valid under Wrapper; replacement Data is rejected as expected target |
| Unknown algorithm / malformed XPath | verified | Explicit parse/transform errors; no permissive retry |
| External HTTPS / file URI | verified | Explicit URI-policy refusal before resource resolution; no caller external bytes or implicit I/O |
| `here()` with explicit libxmlsec legacy mode | verified | Independent signature verifies, bytes agree |
| Same legacy `here()` input in specification mode | failed | Intentional semantic difference: first Reference differs at byte 0, expected length 344 vs actual 0; no hidden mode switch |
| XAdES Target, missing/wrong SignedProperties Type, certificate digest substitution, Rust | verified | XMLDSig stays valid; `validate_basic` refuses binding or returns unbound certificate / unmet B-B requirements |
| DSS semantic Target binding | failed | Required XAdES binding is not checked in the tested path, even with StructuralValidation=FAIL; FC alone only covers base format |
| DSS signing-certificate digest check in ISC | failed | A matching root digest is counted despite no reference to the selected signer; see the focused investigation |
| DSS missing Type classification | verified | DSS reports XAdES-BES rather than Baseline-B; Rust refuses SignedProperties binding |
| Full XAdES/trust verdict from DSS | failed | All nine global outcomes are INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE; no revocation data was supplied |
| B-T/B-LT/B-LTA, TSA/OCSP/CRL, EU Trusted Lists, legal qualification | not run or blocked | Outside this corpus; no such evidence or trust service inputs |
| AL/SignedXml pipeline or direct Rust invocation from AL/SaaS | not run or blocked | No Business Central environment; no deployment assumption |

Only the 100 independent libxmlsec1 `expected-reference-N.bin` and
`expected-signedinfo.bin` vectors are retained in `results/` and `dss-investigation/`.
Every vector is consumed by the mandatory live check. Rust Reference/SignedInfo outputs,
authenticated replay bytes, versions and verification summaries are regenerated outside
the corpus. For each available pair the run records lengths, SHA-256 hashes, decoded DigestValue,
computed digests, first differing byte (zero-based), and 24 preceding / 25 following
bytes in hexadecimal. Absence is never counted as a byte match. All positive valid
cases require two reference dumps, SignedInfo, matching DigestValues and completed replay.
The documented `here()` difference is retained, not normalized away.
The frozen run contains 96 matching Reference-octet pairs and 41 matching SignedInfo
pairs across the two explicit modes. These include negative cases that remain processable;
they are not counts of fully valid signatures. Authentication failures retain their typed
causes, and later fail-fast steps remain unexecuted.

libxmlsec1 1.3.12 needs `--verbose --store-references --store-signatures` to print the
buffers. They are **hex dumps**, not serialized XML. `debug_buffer` decodes them without
stripping canonical whitespace. A null empty buffer has no marker; the harness accepts
that representation only with successful reference processing and a signed
SHA-256(empty) DigestValue. It never shifts the second reference into the first slot.
Harness regression tests guard these evidence and output-directory boundaries.

## Reproduce

Run from the repository root at the recorded commit, with this package's source overlay:

```sh
XMLSEC1_BIN=/path/to/native/xmlsec1 python3 scripts/check-xades-interop.py --output /tmp/xades-live-check
```

This is the same entry point used by the required `XAdES interoperability corpus` CI job.
It runs harness regressions, every retained signed fixture, both explicit here modes,
authenticated replay, all independent octet vectors and default/strict DSS expectations.
No part may skip on a missing oracle. The existing aggregate `test` job requires its success.
CI publishes actual octets, hashes, first-difference diagnostics and full DSS reports as
`xades-interop-results` run artifacts. It never updates fixtures or expectations.

Individual investigation commands:

```sh
XMLSEC1_BIN=/opt/homebrew/bin/xmlsec1 python3 scripts/xades-interop.py --results /tmp/xml-sec-xades-recheck
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-xades-interop.py
python3 scripts/xades-dss.py --results target/xades-dss-recheck
python3 scripts/xades-dss.py --results target/xades-dss-recheck --summarize
```

Set XMLSEC1_BIN to native **1.3.12 or 1.3.13 openssl**; both are explicitly qualified
against the retained independent vectors. The XML verification run uses only empty/same-document
Reference, RetrievalMethod and KeyInfoReference URI classes, plus explicit Id registrations
for Signature, SignedProperties, Data and Outside. Equivalent declarations matter for the
duplicate-ID probe. There is no `--insecure`, `--xxe`, network retrieval or file fallback.
The only network activity in the DSS runner is downloading public Maven build dependencies;
the validation step reads local documents, local test root, and no AIA/OCSP/CRL sources.
The deliberate external-URI probes are not fed to DSS.

Normal verification preserves the supplied signatures and never overwrites an existing
results directory; this also applies to the DSS runner's `--results` directory.
`--summarize` explicitly reanalyzes existing DSS reports without rerunning the engine.
`--generate` explicitly rebuilds synthetic variants, reusing retained
test credentials when present. Starting with no `fixtures/` uses the existing
`scripts/generate-xades-fixtures.sh` to create a new random test chain and B-B variants.
Random new credentials change the signed bytes and hashes: archive the new set as a new
corpus, rather than comparing its signatures with this frozen run.

The distributable archive contains this directory, the probe and runner source overlay,
and license notices. Extract it over a checkout at the recorded baseline before building.
Verify corpus assets with `shasum -a 256 -c interop/xades/SHA256SUMS`.
The archive also contains a root `SHA256SUMS` covering its source overlay and corpus inventory.
Repackage with `python3 scripts/package-xades-interop.py /tmp/xades-interop-new.tar.gz`;
the packager allows only declared inputs, independent vectors, expected DSS conclusions,
provenance and source/docs. Actual outputs, builds, logs and unselected generator outputs
are excluded. Update an intentionally changed corpus inventory explicitly with
`python3 scripts/package-xades-interop.py --refresh-inventory`; ordinary checks and
packaging never rewrite it.

The runners encode per-case oracle and probe commands. New runs also capture commands
and stdout/stderr locally for diagnosis; Git and the distributable bundle exclude these
captures. Verification commands:

```sh
cargo nextest run -p xml-sec -p xml-sec-xades --no-fail-fast --status-level fail --final-status-level fail
cargo clippy -p xml-sec-xades --example interop_probe -- -D warnings
cargo fmt -p xml-sec-xades --check
cargo +1.92.0 check -p xml-sec-xml-input --no-default-features
cargo +1.92.0 check -p xml-sec-xml-input --no-default-features --target thumbv7em-none-eabihf
cargo clean
```

Core XMLDSig and the current XAdES adapter require std; passing XML-input alloc checks
does not establish alloc-only XMLDSig/XAdES support. No production dependency or policy
surface was changed. Probe memory/work ceilings are test execution accounts.
Generated `.tar.gz` bundles remain local artifacts; Git contains
the reviewable sources, selected fixtures, independent expected bytes, expected conclusions and provenance.
The full workspace CLI suite requires native libxmlsec1 1.3.13 and the pinned
`donors/xmlsec` checkout, unlike the frozen byte-dump parser's 1.3.12 requirement.
After checking out the revision in `compatibility/libxmlsec1-1.3.13-donor-commit.txt`,
the macOS readiness commands are:

```sh
XMLSEC1_SOURCE_DIR="$PWD/donors/xmlsec" XMLSEC1_PREFIX="$PWD/.tools/xmlsec1-pr" XMLSEC1_MODERN_ORACLE=1 bash scripts/install-xmlsec1.sh
XMLSEC1_BIN="$PWD/.tools/xmlsec1-pr/bin/xmlsec1" OPENSSL_BIN="$PWD/.tools/xmlsec1-pr/bin/openssl" DYLD_LIBRARY_PATH="$PWD/.tools/xmlsec1-pr/lib" cargo nextest run --workspace --no-fail-fast --status-level fail --final-status-level fail
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo test --doc --workspace
cargo nextest run -p xml-sec-xades --all-features
cargo clippy -p xml-sec-xades --all-features --all-targets -- -D warnings
```

Alloc-only checks use the host/thumb commands above. The additional native oracle is
an isolated test dependency; it does not change the frozen fixtures or Rust runtime.

## Standards, profile disagreement and existing work

- [Filter2 Recommendation, §§3.3–3.4](https://www.w3.org/TR/2002/REC-xmldsig-filter2-20021108/):
  context, ordered set operations, subtree expansion and intersection with input.
- [C14N 1.1, §§2.3–2.4](https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/):
  subset namespace/attribute processing and xml:base fixup.
- [XMLDSig 1.1, §§4.4.3.2, 6.6.3, 8.1.1](https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/):
  digest input, here() and the separation of transformed data from application meaning.
- [ETSI EN 319 132-1 V1.3.1](https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf),
  §4.3.1: Target “shall refer to the Id attribute of the corresponding ds:Signature”.
  §4.4.2 requires the SignedProperties Reference Type. §5.2.2 requires the first
  certificate reference to identify the signer, including its certificate digest.
  These rules determine the Rust negative expectations, not DSS's reported format label.
  `dss-evidence/expectations.json` pins FC/ISC/SAV and overall conclusions separately.
  On the wrong-certificate case DSS matches the root digest while identifying the leaf
  as signer; this and its Target handling are reproducible observations of this exact
  configuration, not a general claim about every DSS policy or version.

The [focused DSS binding investigation](dss-investigation/README.md) reduces these
observations to nine signed inputs and separates a profile-checking gap for Target
from an ISC digest-association error. It also tests StructuralValidation=FAIL.
FC=PASSED and the Baseline-B format label must not be used as a full XAdES
conformance verdict. In particular, generic ISC may find a signer in a later Cert
reference while XAdES separately requires that the first reference identify it.

Arbitrary Filter2 projections deliberately have `TransformedData` coverage in the existing
Rust API. Even subtracting just Signature cannot satisfy `expected_targets` automatically.
This is conservative application-proof behavior, not an octet interoperability failure.
The positive ID-reference and wrapping examples demonstrate identity-based expected-target
checking when complete content coverage is provable. Replay exposes the authenticated
transformed octets for a consumer's separate content contract; no acceptance bypass is used.

Reuse assessment: this adds XML corpus/evidence tooling only, no new signature primitive,
certificate engine, C14N, transform or XAdES implementation. Existing work was inspected:

- [#102 — closed XPath/Filter2 implementation](https://github.com/structured-world/xml-sec/issues/102)
  and `tests/xpath_transform_integration.rs`: reused rather than reimplemented.
- [#243 — closed B-B adapter](https://github.com/structured-world/xml-sec/issues/243),
  `crates/xml-sec-xades/tests/basic.rs`, and its generator: existing negative expectations reused.
- [#221 — closed authenticated replay](https://github.com/structured-world/xml-sec/issues/221):
  existing verified-session API used for every authenticated replay.
- [#248 — independent reference/signature outcomes](https://github.com/structured-world/xml-sec/issues/248):
  current fail-fast behavior explains unexecuted diagnostics after a failed reference.
- [#250 — verification/import isolation](https://github.com/structured-world/xml-sec/issues/250)
  and [#282 — complete XAdES levels](https://github.com/structured-world/xml-sec/issues/282):
  existing boundaries; this corpus does not close them.

No duplicate backlog was created. Trust in this package means only the explicitly supplied
synthetic root at the fixed test instant. No revocation, reliable signing time or legal
qualification follows from that path or from `all_root_requirements_met()`.

## Intended collaboration

The source scenario is [BCApps #10215](https://github.com/microsoft/BCApps/issues/10215),
the preferred contract is [BCApps #10221's author comment](https://github.com/microsoft/BCApps/issues/10221#issuecomment-5465429200),
and the public reproducer is [dotnet/runtime #82363](https://github.com/dotnet/runtime/issues/82363).
The offer is a reference/test corpus for URI-dispatched handlers **inside** AL/SignedXml:
the owner retains sequencing, digest comparison, SignedInfo and signature verification.
It is not a replacement of Business Central with Rust or an assumed Rust/AL/SaaS bridge.
See `COMMENT-DRAFT.md` for the unpublished English comment.
