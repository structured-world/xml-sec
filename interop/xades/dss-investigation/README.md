# XAdES binding investigation: DSS 6.5.1

Checked locally on 23 October 2026 against xml-sec commit
`834c463798060dca613bb93dd78dcdc7f949c948`: xml-sec 0.2.0,
xml-sec-xades 0.1.0 and structured-xades 0.11.0. Independent implementations:
native libxmlsec1 1.3.12 (OpenSSL) and EU DSS 6.5.1, with Maven 3.9.12 and
Homebrew OpenJDK 21.0.12.1. This contribution changes test tooling and evidence.

**Finding:** the tested xml-sec binding checks agree with the normative requirements.
Negative fixtures deliberately violate XAdES while retaining valid XMLDSig signatures.
The DSS findings have different causes: a semantic Target profile-checking gap and a
false-positive certificate-digest association in Identification of the Signing Certificate
(ISC). Every overall DSS result remains INDETERMINATE; no complete successful DSS
validation or trusted-signature acceptance is claimed.

## Normative boundaries

[ETSI EN 319 132-1 V1.3.1](https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf):

- §4.3.1, printed page 14: Target must refer to the corresponding ds:Signature Id.
  This local construction requires a bare-name fragment reference. A business-object
  target, an unresolved target or an absent Target violates the QualifyingProperties contract.
- §4.4.2: a SignedProperties Reference needs the specified Type. Both References and
  the correct Type remain present throughout these nine cases.
- §5.2.2, pages 27–28: the first SigningCertificateV2 Cert reference must identify the
  signing certificate. Subsequent references may identify certificates in its path,
  including the trust anchor. A root-only reference does not replace the signer reference.

[ETSI EN 319 102-1 V1.4.1](https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf):

- §5.2.2, page 44: Format Checking (FC) establishes whether the base format permits
  cryptographic processing. Its note separates profile/level conformance, which may be
  checked in Signature Acceptance Validation (SAV) or a conformance checker (Annex C).
  FC=PASSED therefore does not establish Target correctness or B-B conformance.
- §5.2.3.4, page 45, steps 1–2: reference digests are compared with the actual signing
  certificate digest. No matching reference requires INDETERMINATE /
  NO_SIGNING_CERTIFICATE_FOUND. Matching another certificate in the chain does not suffice.
- Generic ISC may search subsequent references. Thus ISC=PASSED for `[root, signer]`
  is not itself an ISC error; this ordering violates the separate XAdES first-reference rule.

## Reduced signed cases

Each linked directory contains the complete `signed.xml`; `template.xml` shows the
construction before native signing. Business data is only `<Data Id="payload">x</Data>`.
Every case has two References, `#payload` and typed `#sp`, exclusive C14N, SHA-256 and
RSA-SHA256. There is no XPath, Filter2, enveloped transform, xml:base or network URI.

The Target-only difference is:

```xml
<!-- control: the corresponding ds:Signature has Id="sig" -->
<x:QualifyingProperties Target="#sig">
<!-- target-payload: the only change -->
<x:QualifyingProperties Target="#payload">
```

Target is outside SignedProperties. The control, target-payload, target-unresolved
and target-absent cases have identical SignatureValue bytes. Both Reference digests,
SignedInfo and XMLDSig verification survive these mutations. This is expected XAdES
structure rather than a broken cryptographic fixture.

The certificate-only difference is:

```text
control:   SigningCertificateV2/Cert[1]/CertDigest = SHA256(signer.der)
cert-root: SigningCertificateV2/Cert[1]/CertDigest = SHA256(root.der)
```

libxmlsec1 recomputes SignedProperties and SignatureValue with the same signer.key.
KeyInfo still contains signer and intermediate; root is supplied separately as a
synthetic trust anchor. XMLDSig remains valid while the XAdES certificate binding fails.

| Case | XAdES expectation | Our validate_basic | DSS structure / ISC / SAV, default policy |
| --- | --- | --- | --- |
| [control](control/signed.xml) | permitted | B-B requirements met | true / PASSED / PASSED |
| [target-payload](target-payload/signed.xml) | prohibited | Binding(Target) | true / PASSED / PASSED |
| [target-unresolved](target-unresolved/signed.xml) | prohibited | Binding(Target) | true / PASSED / PASSED |
| [target-absent](target-absent/signed.xml) | prohibited | Binding(Target) | false / PASSED / PASSED with warning |
| [cert-root](cert-root/signed.xml) | prohibited | unbound certificate, B-B requirements unmet | true / PASSED / PASSED |
| [cert-intermediate](cert-intermediate/signed.xml) | prohibited | unbound certificate, B-B requirements unmet | true / INDETERMINATE / PASSED |
| [cert-unmatched](cert-unmatched/signed.xml) | prohibited | unbound certificate, B-B requirements unmet | true / INDETERMINATE / PASSED |
| [cert-root-then-signer](cert-root-then-signer/signed.xml) | prohibited ordering | unbound certificate, B-B requirements unmet | true / PASSED / PASSED |
| [cert-signer-then-root](cert-signer-then-root/signed.xml) | permitted | B-B requirements met | true / PASSED / PASSED |

DSS labels every case XAdES-BASELINE-B. This classification does not establish that
mandatory profile semantics were checked. The overall subindication is
NO_SIGNING_CERTIFICATE_FOUND for cert-intermediate and cert-unmatched, and
CERTIFICATE_CHAIN_GENERAL_FAILURE otherwise. The root-only finding must not be
generalized to every certificate substitution.

## Target: a DSS profile-checking coverage gap

[XAdES132Path.java, lines 68–81](https://github.com/esig/dss/blob/6.5.1/dss-xades/src/main/java/eu/europa/esig/dss/xades/definition/xades132/XAdES132Path.java#L68)
selects QualifyingProperties by its position under ds:Object, without Target association.
[XAdESStructureValidator.java, lines 62–73](https://github.com/esig/dss/blob/6.5.1/dss-xades/src/main/java/eu/europa/esig/dss/xades/validation/XAdESStructureValidator.java#L62)
performs XSD validation. An anyURI declaration checks presence and syntax, not identity
with the selected Signature. XAdESBaselineRequirementsChecker, lines 80–213, likewise
does not establish Target identity. A literal Target/TARGET search through the Java
validation package found no accesses; this supports, but does not replace, the tests
and call-path inspection.

The actual loaded `dss-policy-jaxb-6.5.1.jar!/policy/constraint.xml` sets
StructuralValidation=WARN and CertDigestMatch=FAIL. A missing Target consequently
produces diagnostic structure=false and a warning, not a negative FC. The original
FC/ISC-agreement summary was too coarse for complete profile conformance; the harness
now explicitly reports that FC does not attest semantic Target checking.

Changing **only** StructuralValidation from WARN to FAIL gives:

- target-absent: SAV becomes INDETERMINATE / SIG_CONSTRAINTS_FAILURE;
- target-payload and target-unresolved: structure=true, ISC=PASSED and SAV=PASSED;
- control and cert-root: ISC/SAV remain PASSED.

See [strict-policy-expectations.json](strict-policy-expectations.json). A new run generates each
case's local `dss-structure-fail/` reports. The stronger constraint detects an XSD violation but
does not add semantic Target validation. This is missing XAdES profile coverage in
the tested DSS path, not evidence that generic FC violates EN 319 102-1.

## Signing certificate: a false-positive DSS ISC digest check

[AbstractTokenProxy.java, lines 176–226](https://github.com/esig/dss/blob/6.5.1/dss-diagnostic-jaxb/src/main/java/eu/europa/esig/dss/diagnostic/AbstractTokenProxy.java#L176)
distinguishes the selected certificate's reference from a combined list of references
with SIGNING_CERTIFICATE origin. The combined list includes references associated
with different found certificates, plus orphan references.

[DigestValueMatchCheck.java, lines 58–67](https://github.com/esig/dss/blob/6.5.1/dss-validation/src/main/java/eu/europa/esig/dss/validation/process/bbb/isc/checks/DigestValueMatchCheck.java#L58)
iterates this combined list and succeeds on any digest match, losing the association
with the selected signer. IdentificationOfTheSigningCertificate, lines 105–120,
uses this predicate for ISC.

The retained public DSS diagnostic API facts for cert-root are:

```text
selected_certificate=C-B77E6878076E42AEB916698199F27F2123C2561BCED05F43CA1887405C30813D
selected_certificate_reference_null=true
reference.0.match=true
reference.0.digest=/PsVcXqRQ4cZ2J6zsDztfJYHtstVPDeL45xSBDXPeVc=
```

The selected signer is leaf, its own reference is missing, and the matched digest
belongs to root. SHA-256 of the DER certificates:

```text
signer b77e6878076e42aeb916698199f27f2123c2561bced05f43ca1887405c30813d
root   fcfb15717a91438719d89eb3b03ced7c9607b6cb553c378be39c520435cf7957
```

SigningCertificateReferencesValidityCheck, lines 65–90, checks whether referenced
certificates belong to the chain. Root belongs to it, so this separate predicate
does not restore signer association. StructuralValidation=FAIL also leaves ISC PASSED.
This is a false-positive ISC result in DSS 6.5.1, contradicting §5.2.3.4's signer-digest
comparison rather than merely a WARN-level profile constraint.

Our `signature.rs:195–216` resolves Target through the verified session.
structured-xades 0.11.0 `binding.rs:287–315` compares stable identity with the selected
Signature; `certificate.rs:559–590` compares the first reference with the actual
selected signing certificate. The tested adapter behavior matches these contracts.

## Reproduce

From the checkout root with this package's source overlay, first bootstrap the pinned
Maven dependencies with `cargo run -p xml-sec-tools -- xades dss --results target/xades-dss-recheck`.
Only public build dependencies are downloaded; no XML is uploaded. Then use a fresh
output directory to preserve the supplied evidence:

```sh
XMLSEC1_BIN=/opt/homebrew/bin/xmlsec1 cargo run -p xml-sec-tools -- xades binding --output target/xades-binding-repro
cargo run -p xml-sec-tools -- xades binding --output target/xades-binding-repro --strict-policy
```

On another machine, set the path to native libxmlsec1; the Rust CLI is not an oracle.
The investigation's Maven calls use `-o` after bootstrap. Process and command captures
and full DSS reports remain local and ignored. The distributed evidence retains byte
artifacts, digests and compact verification/certificate-selection summaries. Authenticated replay uses the existing
verified-session API; reanalysis needs no process logs.

Normal runs verify the retained signed fixtures and check their construction templates.
`--generate` explicitly signs a new set using the synthetic test key. CI compares fresh
default/strict DSS results with `expectations.json` and `strict-policy-expectations.json`,
and every independent expected octet vector with fresh native output. Rust and replay
octets, comparison summaries and full DSS reports are generated only as run artifacts.

Recheck retained octets without running either engine:

```sh
cargo run -p xml-sec-tools -- xades binding --output target/xades-binding-repro --analyze
```

[source-audit.json](source-audit.json) records the source-jar URLs, SHA-256 hashes,
entry hashes and inspected line ranges. Download those jars and verify their hashes
to independently inspect the same code. The actual default policy is hashed too.
Third-party source jars and complete normative texts are not bundled.

## Status and limits

Status vocabulary: **verified**, **failed**, or **not run or blocked**.

| Check | Status | Evidence |
| --- | --- | --- |
| XMLDSig for all nine cases, native and Rust | verified | expectations.json; live check generates summary.json |
| 18 Reference pairs, digest/DigestValue and replay | verified | independent expected-reference-*.bin; live octet-comparison.json and rust/*.bin |
| Nine canonicalized SignedInfo pairs | verified | independent expected-signedinfo.bin; live octet-comparison.json and rust/signature-0.bin |
| No first differing byte | verified | first_different_byte=null throughout these comparisons |
| Our Target and first-certificate-reference outcomes | verified | expectations.json: two positive controls, seven negative cases |
| DSS semantic Target rejection as an XAdES requirement | failed | default and StructuralValidation=FAIL; scope distinction above |
| DSS ISC refusal of root-only digest instead of signer digest | failed | expectations.json: cert-root dss_binding_facts and dss_blocks; strict-policy-expectations.json |
| Positive complete DSS validation | failed | overall INDETERMINATE; no offline revocation evidence |
| Trust, revocation, timestamps and legal status | not run or blocked | not established by this corpus; only the synthetic root is trusted |
| Other DSS versions or policies | not run or blocked | findings cover this pinned version and the two tested configurations |

Keys, certificates and payloads are synthetic; see [PROVENANCE.md](../PROVENANCE.md).
No payload or key was submitted to an online validator.
