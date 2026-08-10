# XML Digital Signatures

The `xmldsig` feature provides signing and verification pipelines for same-document XML
signatures and detached references whose payloads the caller supplies. It supports inclusive and
exclusive canonicalization, enveloped signatures,
Base64, XPath 1.0, and XPath Filter 2.0 transforms, RSA PKCS#1 v1.5, ECDSA SHA-256/SHA-384
with P-256/P-384/P-521 verification keys,
DSA-SHA1 and HMAC-SHA1 verification, embedded X.509 certificates, and configured key
resolution.

## Examples

`examples/sign.rs` builds an enveloped RSA-SHA256 signature with an embedded X.509
certificate. `examples/verify.rs` verifies that document through `DefaultKeyResolver`:

```sh
cargo run --example sign --all-features > signed.xml
cargo run --example verify --all-features -- signed.xml
```

The signing and verification contexts share the same reference-transform implementation.
[`XPathHereSemantics::Specification`] follows the XMLDSig `<XPath>` contract; callers
interoperating with legacy libxmlsec1 `here()` behavior can explicitly select
[`XPathHereSemantics::XmlSecLegacy`] on both contexts.

`SigningPolicy::transforms` applies to every canonicalization algorithm the signing pipeline
executes, including the default C14N 1.0 coercion when a reference transform chain ends as a node
set and the declared canonicalization method for `<SignedInfo>`. Reference output and
`<SignedInfo>` serialization consume one bounded canonicalization budget, so policy rejection
occurs during rendering rather than after an oversized buffer has already been allocated.
The same immutable policy controls every signing parse and mutation reparse, including source
validation in `sign_with_builder`, digest filling, `SignedInfo` parsing, signature filling, and
optional `KeyInfo` filling. An internal-DTD opt-in and XML node ceiling therefore cannot be lost
between stages.

`SignContext::provider` selects both digest primitives and operation randomness. Built-in ECDSA
signing obtains its prehash from that provider, while built-in RSA signing routes its blinding
randomness through the provider rather than acquiring operating-system randomness behind the
boundary. Custom `SigningKey` implementations that hash or use randomness inside their primitive
must implement `SigningKey::sign_with_provider`; externally managed keys can use the default
implementation only when the provider has no primitive work to observe.

`VerifyContext::provider` covers every verification-time cryptographic operation, including
reference digests, document signatures, `X509Digest` selector evaluation, X.509 candidate-path
edges, complete certificate paths, and CRL authentication performed by `DefaultKeyResolver`.
Certificate authentication uses a separate typed algorithm contract so RSA-PSS parameters and
Ed25519 are not collapsed into the narrower XMLDSig `SignatureMethod` enum. Unsupported certificate
OIDs remain typed path errors rather than ordinary signature mismatches. Every certificate OID
represented by that contract reaches the selected provider; the built-in provider may reject a
capability such as ECDSA-SHA512 while a custom provider can implement it. For an
`id-RSASSA-PSS` issuer key, the built-in provider requires typed SPKI parameters and enforces their
hash, MGF, minimum salt, and trailer-field restrictions before verifying a certificate signature.
Custom resolvers that evaluate cryptographic key metadata should override
`KeyResolver::resolve_with_policy_and_provider`; source-only resolvers can retain the default hook.

## Verification Policy

For production verification, configure `KeyResolverConfig::lookup_certs` with untrusted
certificates that selector-only `X509Data` may address or use as path intermediates, and configure
`KeyResolverConfig::trusted_certs` only with explicit trust anchors. With chain validation
enabled, a selected lookup certificate may chain through other lookup certificates but must end at
a trusted anchor. A trusted certificate selected directly remains an anchor, while embedded
certificates provide key material and do not become trusted merely because they appear in
`<KeyInfo>`. Exact DER duplicates across configured pools are evaluated once; when the same
certificate is present in both pools, its explicit trusted classification is retained.
Configured chain depth and candidate-path limits are validated after resolver defaults compose with
the operation policy. Candidate-path accounting includes every generated partial path, and
self-issued rollover certificates continue toward a distinct same-name issuer when its signature
validates; neither condition can bypass the configured work bounds or trust anchor requirement.
Path validation excludes self-issued rollover CAs from `pathLenConstraint`, applies supported RFC
5280 NameConstraints to every subordinate certificate, and rejects critical extensions whose
semantics are not implemented. Repeated extension OIDs are rejected certificate-wide before any
extension-specific interpretation. Empty certificate subjects require exactly one critical, non-empty
SubjectAlternativeName, and malformed GeneralName entries fail path validation regardless of whether
the subject is empty. Invalid DNS-based constraints, including email-domain and URI-host forms,
malformed IPv4/IPv6 encodings, non-contiguous CIDR masks, nonzero `minimum`, and any `maximum`
distance fail the path rather than behaving as ordinary name mismatches. Processed critical certificate
extensions are KeyUsage
(`2.5.29.15`), SubjectAlternativeName (`2.5.29.17`), BasicConstraints (`2.5.29.19`), and
NameConstraints (`2.5.29.30`). A chain using critical ExtendedKeyUsage (`2.5.29.37`) or
CertificatePolicies (`2.5.29.32`) therefore fails closed until those semantics are implemented;
encode them as non-critical only when that matches the issuing PKI's security contract.
When `X509Data` supplies multiple selector categories, every
category must match certificates on the same selected, policy-valid path rather than unrelated
certificates from the lookup pool.

`VerifyResult::status` reports core validation: `Valid` means the cryptographic signature and
every `<SignedInfo>` reference succeeded. `Invalid(reason)` means core validation completed but
failed, such as a `<SignedInfo>` digest mismatch or invalid signature value.

When `VerifyContext::process_manifests(true)` is enabled, Manifest parsing starts only after the
`<SignedInfo>` references and `SignatureValue` both validate. Each authenticated Manifest reference
then has an independent status in `VerifyResult::manifest_references`. A failed Manifest reference
does not change the core `VerifyResult::status`; callers must inspect every Manifest result before
accepting data whose integrity depends on that Manifest. An empty Manifest result list is not proof
that the input contained no Manifest. `VerifyContext::process_manifests(false)` leaves the list empty
because Manifests were not processed; core validation failures and unsigned, unreferenced, or
structurally excluded Manifest blocks can also produce an empty list. Callers must distinguish the
disabled state from an enabled pass with no authenticated Manifest references.
Manifest references obey the same per-reference transform-count ceiling and transform allowlist as
`<SignedInfo>` references; a violation is recorded in that Manifest reference's independent status.
They also share `ResourcePolicy::max_references` with `<SignedInfo>`: every parsed Manifest
reference consumes that operation-wide budget, including entries whose transforms are unsupported
and retained only as independent failure results.

Malformed XMLDSig structure, unsupported algorithms in core signature processing, disallowed URIs
in `<SignedInfo>` references, and inconsistent `KeyInfo` metadata are processing errors rather
than validity statuses. Manifest policy violations and unsupported transforms remain independent
per-reference statuses as described above. Treat both `Invalid(reason)` and an API error as a
rejected document; never continue an authentication flow after either outcome.

External references are disabled by default. Callers must both allow their URI class with
`UriTypeSet` and provide every payload through `VerifyContext::external_resources`; verification
never performs network or filesystem I/O. Individual resources are limited to 8 MiB and the
complete map to 32 MiB. The same aggregate ceiling is charged again per successful dereference,
so repeatedly referencing one map entry cannot multiply transform work or retained diagnostics
without bound. External key retrieval has an independent policy boundary: callers must
also opt in with `VerifyContext::allowed_retrieval_method_uri_types`. Allowing external signed
payloads never implicitly allows external key material. `RetrievalMethod` currently accepts
untransformed external `rawX509Certificate` data, untransformed direct same-document `X509Data`,
and the Merlin same-document `X509Data` XPath selection. Relative external `Reference` and
`RetrievalMethod` URIs are resolved against the owning element's effective `xml:base` using RFC
3986 before lookup, so resource-map keys must use that resolved URI. The compiled resource policy
bounds both inherited `xml:base` components and cumulative URI-resolution bytes across external
References, `RetrievalMethod`, Reference transforms, and SignedInfo C14N 1.1 fixup; implementation
ceilings are 64 components and 1 MiB per operation. Other retrieval transform chains fail closed
instead of being ignored.
`VerifyContext::allowed_transforms` applies to Reference transforms and implicit C14N,
the declared SignedInfo canonicalization method, and supported RetrievalMethod transforms.
Allowing XPath for signed payload processing therefore also explicitly permits the bounded
Merlin X509Data retrieval selector; omitting XPath rejects that key-retrieval path.

CRL checking is meaningful only inside authenticated X.509 path validation. A policy that enables
CRLs without enabling certificate-chain validation is rejected during context construction rather
than silently accepting a control the resolver cannot enforce.

Internal DTD declarations are disabled by default. Verification requires the operation's
`VerificationPolicy::xml.allow_internal_dtd` decision; the
`VerifyContext::allow_internal_dtd(true)` convenience method updates that same policy snapshot
rather than bypassing a separate policy gate. The decision applies consistently to the signed
document and caller-supplied detached XML parsed by node-set transforms. Direct transform callers
can set the corresponding option with `TransformOptions::allow_internal_dtd(true)`. Signing uses
`SigningPolicy::xml.allow_internal_dtd` across its complete pipeline. External entity resolution
remains disabled. XSLT is intentionally not executed because transforms operate on
attacker-controlled documents; an authenticated Manifest reference using unsupported XSLT is
reported as an invalid per-reference result without changing core `SignedInfo` validity.

## Current Scope

Implemented algorithms include RSA PKCS#1 v1.5 with SHA-1/SHA-256/SHA-384/SHA-512 for
verification, SHA-256/SHA-384/SHA-512 for signing, and ECDSA with SHA-256 or SHA-384. ECDSA
verification selects P-256, P-384, or P-521 from the SPKI independently of the hash identifier;
the built-in P-256 and P-384 signing keys support either ECDSA hash identifier.
DSA-SHA1 and HMAC-SHA1 (including XMLDSig's byte-aligned 80-160-bit truncation range) are
verify-only legacy algorithms. They follow the general
`VerificationPolicy::signature_algorithms` allowlist: the default `None` accepts every implemented
method subject to its other policy gates, while deployments that require explicit legacy opt-in
should supply a modern-only allowlist and add these methods only for operations that need them.
RSA-SHA1 verification is independently default-deny: `None` in the general allowlist does not
bypass `VerificationPolicy::key_trust.allow_legacy_rsa_sha1`, which callers must explicitly enable.
Selecting the algorithm in untrusted XML does not opt the operation into legacy cryptography, and
this gate runs before key resolution.
RSA-SHA1 signing remains unsupported.
X.509 path and CRL authentication additionally supports standard RSA-PSS with SHA-256/SHA-384/
SHA-512 parameters, including RFC 4055 issuer-key restrictions, and Ed25519. Signature
`AlgorithmIdentifier` parameters are validated before provider dispatch: DSA, ECDSA, and Ed25519
require absent parameters; RSA PKCS#1 accepts NULL or absent; RSA-PSS requires valid typed
parameters. DSA-SHA256, broader HMAC verification/signing, XMLDSig `SignatureMethod` RSA-PSS, and
implicit external resource loading are not currently supported.
