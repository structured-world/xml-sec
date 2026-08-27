# XML Digital Signatures

## Migrating from 0.1.10

`SignatureAlgorithm::EcdsaP256Sha256` and `EcdsaP384Sha384` are now
`EcdsaSha256` and `EcdsaSha384`, because the signature URI selects a digest while
the key selects P-256, P-384, or P-521. The enum also covers DSA, HMAC, RSA,
and ECDSA SHA-1/SHA-224/SHA-256/SHA-384/SHA-512 methods implemented by the
XMLDSig 1.1 interop pipeline. `SignedInfo` reports optional HMAC truncation through
`hmac_output_length_bits`. Both public types are non-exhaustive; consumers should
use wildcard match arms and obtain `SignedInfo` through the parser.

The `xmldsig` feature provides signing and verification pipelines for same-document XML
signatures and detached references whose payloads the caller supplies. It supports inclusive and
exclusive canonicalization, enveloped signatures,
Base64, XPath 1.0, and XPath Filter 2.0 transforms, RSA PKCS#1 v1.5, DSA,
ECDSA with P-256/P-384/P-521 keys, HMAC truncation, embedded X.509 certificates,
and configured key resolution.

The complete Phaos XMLDSig 3 and 2012 XMLDSig 1.1 corpora are checked in for
deterministic offline interoperability testing. Every signature document is executed through the
public verification API and must be classified exactly once. Supported vectors
must verify, invalid vectors must return their exact failure class, and vectors
that depend on an unavailable capability such as XSLT or HMAC-MD5 must fail at
an explicit typed boundary rather than being skipped.

## Examples

`examples/sign.rs` builds an enveloped RSA-SHA256 signature with an embedded X.509
certificate. `examples/verify.rs` verifies that document through `DefaultKeyResolver`:

```sh
cargo run --example sign --all-features > signed.xml
cargo run --example verify --all-features -- signed.xml
```

The signing and verification contexts share the same reference-transform implementation.
`SigningPolicy::manifest_processing` controls direct `<Object>/<Manifest>`
reference generation. Processing fills Manifest digests before SignedInfo so a
SignedInfo reference to the Manifest authenticates the final values; Manifest
and SignedInfo references share transform work and the aggregate reference
ceiling. Nested Manifest dependencies are filled from leaves to dependants so
every digest observes finalized content; cycles are rejected before mutation.
Dependency analysis uses the effective XPath/XPath Filter 2.0 node-set, so a
self-reference that excludes its mutable `DigestValue` is not misclassified as
a cycle.
The default core policy leaves application-defined Manifest values
untouched, while the `xmlsec1` compatibility CLI enables processing unless
`--ignore-manifests` is present.
[`XPathHereSemantics::Specification`] follows the XMLDSig `<XPath>` contract; callers
interoperating with legacy libxmlsec1 `here()` behavior can explicitly select
[`XPathHereSemantics::XmlSecLegacy`] on both contexts.

`SigningPolicy::transforms` applies to every canonicalization algorithm the signing pipeline
executes, including the default C14N 1.0 coercion when a reference transform chain ends as a node
set and the declared canonicalization method for `<SignedInfo>`. Reference output and
`<SignedInfo>` serialization consume one bounded canonicalization budget, so policy rejection
occurs during rendering rather than after an oversized buffer has already been allocated.
The same immutable policy controls the retained owned document and every committed signing
generation, including source validation in `sign_with_builder`, digest filling, `SignedInfo`
parsing, signature filling, and optional `KeyInfo` filling. An internal-DTD opt-in and XML node
ceiling therefore cannot be lost between stages. `SignContext::sign_document` and
`sign_document_with_builder` reuse an `XmlDocument`; string APIs are adapters over that boundary.
External callers that need non-default XML input rules construct that retained document with
`XmlDocument::parse_with_policy(xml, &signing_or_verification_policy)`, so parsing and the later
operation share one immutable policy snapshot rather than independent DTD or resource settings.
Owned entry points revalidate the document's parse provenance, so a document that required the
internal-DTD opt-in cannot cross into a stricter signing or verification context. Builder signing
stages template append, optional `KeyInfo`, every `DigestValue`, and `SignatureValue` in a private
document. A successful operation commits the complete result as one generation; any policy,
provider, key, transform, or serialization failure leaves the caller's XML and generation
unchanged. Every staged mutation checks the active projected node count before commit.
Custom `KeyInfoWriter` output is treated as a separate untrusted XML input: its
byte ceiling is enforced before namespace wrapping or parsing, and its merged nodes remain under
the same operation ceiling as the rest of the signature.
Built-in writers emit `RSAKeyValue`/`ECKeyValue`, `DEREncodedKeyValue`, embedded
X.509 certificate chains, or `X509Digest` selectors. Cryptographic writer work,
including the certificate digest used by `X509Digest`, runs through the same
operation provider as reference digests and signature generation. DSA signing accepts plain
or password-encrypted PKCS#8 DER and emits XMLDSig's fixed-width `r || s` value;
DSA-SHA1 requires a 160-bit `q`, while DSA-SHA256 requires a 256-bit `q`, so a
key whose component width cannot be represented by the selected wire format is
rejected before signing.
P-521 signing and verification use the same key-selected ECDSA framing contract
as P-256 and P-384.
Recursive `KeyInfoReference` materialization shares one candidate-work budget
across the complete reference graph. Each dereference and terminal source is
charged before expansion, so a shallow fan-out DAG cannot allocate an
exponential flattened source list while remaining below the depth limit.
Cycle identities include the owning document or stable external-resource URI:
equal fragment names in distinct documents remain independent, while reparsing
an external resource cannot hide a cycle that returns to that resource.
`IdAttributeRegistration` supplies immutable request context for non-standard ID attributes.
`SignContext::id_attributes` and `VerifyContext::id_attributes` apply the same global or
element-scoped registrations to operation start-node selection and every same-document Reference.
`scoped_any_namespace` matches one element local name across namespaces, while `scoped` matches
one exact expanded name and uses `None` for no namespace. The registration is not stored in policy
and never comes from document content.
`SignContext::sign_template` selects the last descendant `Signature` template by default, preserving
append-then-sign workflows when a document already contains signatures. Process compatibility
boundaries that use donor document-order lookup can explicitly select
`SignatureTemplateSelection::FirstDescendant`; `start_node_id` scopes that selection to one subtree.
`VerifyContext` instead requires one unique document-level `Signature` by default and rejects
documents containing multiple candidates. Callers that intentionally consume multi-signature
documents must choose `first_document_signature()` or scope lookup with `start_node_id()`.
`SigningPolicy::rsa_keys` validates normalized modulus width and public exponent before provider
dispatch. The default accepts 2048-8192-bit RSA keys for new signatures; compatibility callers can
raise or lower the minimum explicitly, while the 8192-bit implementation ceiling cannot be relaxed.

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
Before document-signature provider dispatch, the facade calls
`VerifyingKey::validate_signature_value`. Built-in resolved keys enforce the exact RSA modulus or
EC curve width there, so a permissive custom provider cannot reinterpret malformed XMLDSig wire
framing. Custom opaque keys must override that hook when their accepted framing depends on key
metadata unavailable through the generic algorithm URI. Providers that implement policy-selected
framing must also override `validate_signature_value_with_policy` and `verify_with_policy`; their
defaults intentionally preserve the standard-only hooks.

## Verification Policy

ECDSA `SignatureValue` uses the XMLDSig fixed-width `r || s` representation by
default for both signing and verification. Set
`SigningPolicy::ecdsa_signature_value_encoding` or
`VerificationPolicy::ecdsa_signature_value_encoding` to
`EcdsaSignatureValueEncoding::XmlSecAsn1Der` only at a trusted compatibility
boundary. DER is never auto-detected. Same-document bare fragments use
`TransformPolicy::same_document_id_semantics`; the library default requires the
standards form. `SameDocumentIdSemantics::XmlSecBarename` models libxmlsec1's
default barename grammar backed by its single-quoted `xpointer(id(...))` wrapper,
while preserving the barename rule that excludes comments. In contrast,
`SameDocumentIdSemantics::XmlSecVisa3d` performs direct registered-ID lookup.
The native CLI selects the donor barename mode by default and the direct mode for
`--enable-visa3d-hack`. ID registrations remain request context and duplicate
IDs fail in every mode.

For production verification, configure `KeyResolverConfig::lookup_certs` with untrusted
certificates that selector-only `X509Data` may address or use as path intermediates, and configure
`KeyResolverConfig::trusted_certs` only with explicit trust anchors. With chain validation
enabled, a selected lookup certificate may chain through other lookup certificates but must end at
a trusted anchor. A trusted certificate selected directly remains an anchor, while embedded
certificates provide key material and do not become trusted merely because they appear in
`<KeyInfo>`. Exact DER duplicates across configured pools are evaluated once; when the same
certificate is present in both pools, its explicit trusted classification is retained.
`ResourcePolicy::max_xml_document_bytes` rejects verification and signing inputs before DOM
parsing; the same immutable ceiling is rechecked after signing mutations that enlarge the XML.
The selected node and depth ceilings are enforced by a streaming preflight before either parser
backend allocates a DOM, then rechecked on every staged copy, adapter parse, and committed generation.
`ResourcePolicy::max_xml_parse_work_bytes` separately bounds cumulative parser work across the
whole operation. Initial parsing, generated-template validation, binary-to-node-set adapters,
staged copies, digest dependency levels, Manifest recursion, and committed generations all charge
the same monotonic allowance. Recursive internal-entity replacement traversal is charged before a
DOM parser runs; failed parses do not restore the allowance.
Configured chain depth and candidate-path limits are validated after resolver defaults compose with
the operation policy. Candidate-path accounting includes every generated partial path, and
self-issued rollover certificates continue toward a distinct same-name issuer when its signature
validates; neither condition can bypass the configured work bounds or trust anchor requirement.
An explicit verification time may come from either boundary; if both boundaries provide one, the
timestamps must be identical because silently preferring either clock would discard caller policy.
Path validation excludes self-issued rollover CAs from `pathLenConstraint`, applies supported RFC
5280 NameConstraints to every subordinate certificate, and rejects critical extensions whose
semantics are not implemented. Repeated extension OIDs are rejected certificate-wide before any
extension-specific interpretation. Issuing certificates must assert BasicConstraints `cA=true`
and, when KeyUsage is present, `keyCertSign`. RFC 5280 requires conforming issuers to encode CA
BasicConstraints as critical, but path validation retains OpenSSL/xmlsec1 compatibility with
historical non-critical encodings. Empty certificate subjects require exactly one critical, non-empty
SubjectAlternativeName, and malformed GeneralName entries fail path validation regardless of whether
the subject is empty. Invalid DNS-based constraints, including email-domain and URI-host forms,
malformed IPv4/IPv6 encodings, non-contiguous CIDR masks, nonzero `minimum`, and any `maximum`
distance fail the path rather than behaving as ordinary name mismatches. Processed critical certificate
extensions are KeyUsage
(`2.5.29.15`), SubjectAlternativeName (`2.5.29.17`), BasicConstraints (`2.5.29.19`), and
NameConstraints (`2.5.29.30`). ExtendedKeyUsage (`2.5.29.37`) is processed whether critical or
non-critical on every certificate in the path: absent EKU and `anyExtendedKeyUsage` remain
unrestricted, while every other EKU must intersect
`KeyTrustPolicy::allowed_extended_key_usages`. The resolver-local and operation policy sets are
independent approvals, so a purpose must appear in both when `VerifyContext` composes them. Their
default empty sets therefore reject TLS-, code-signing-, and other purpose-restricted paths unless
the deployment explicitly approves that typed purpose at both boundaries. Critical
CertificatePolicies (`2.5.29.32`) still fails closed because policy-tree processing is not
implemented.
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
Successful Manifest references whose transforms preserve the referenced XML structure extend the
authenticated set recursively. A sibling Manifest reached through such a reference is processed
once; failed digests and node-set transforms that discard structure never extend that trust frontier.
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
XMLDSig 1.1 `KeyInfoReference` has separate source and URI policy gates plus a
bounded recursion depth. Same-document and caller-owned external targets must
resolve to exactly one `KeyInfo`; missing targets, non-`KeyInfo` targets, and
cycles fail closed. Fragment lookup and nested references inside an external XML
document use that document's ID namespace. Its fetched resource identity is the
RFC 3986 base for relative nested references, with inherited `xml:base` applied
on top. All nested external dereferences
consume the operation's shared aggregate external-resource budget and never
trigger implicit I/O.

Direct policy-free calls on `HmacVerificationKey` enforce the secure default
HMAC key and output minima. Compatibility truncation is available only through
the policy-aware hooks used by `VerifyContext` with an explicit `HmacPolicy`.
`VerifyContext::allowed_transforms` applies to Reference transforms and implicit C14N,
the declared SignedInfo canonicalization method, and supported RetrievalMethod transforms.
Allowing XPath for signed payload processing therefore also explicitly permits the bounded
Merlin X509Data retrieval selector; omitting XPath rejects that key-retrieval path.

CRL checking is meaningful only inside authenticated X.509 path validation. A policy that enables
CRLs without enabling certificate-chain validation is rejected during context construction rather
than silently accepting a control the resolver cannot enforce.
CRL structure is validated before authority-key applicability is selected: duplicate CRL or
CRL-entry extension OIDs fail closed, and `deltaCRLIndicator` is rejected regardless of criticality.
Applicable CRLs must include the RFC 5280 `nextUpdate` field and the verification time must remain
inside the bounded `thisUpdate` through `nextUpdate` validity window.
The `removeFromCRL` reason is rejected in complete CRLs because it is meaningful only in a delta
CRL. URI subject alternative names
likewise require one RFC 3986 authority, including syntactically valid userinfo, before their host
can participate in NameConstraints matching.
Critical `NameConstraints` also retain their DER structure during validation: the extension must
contain at least one permitted or excluded subtree, every present subtree collection must be
non-empty, and unsupported minimum/maximum distance fields fail closed.

Internal DTD declarations are disabled by default. Verification requires the operation's
`VerificationPolicy::xml.allow_internal_dtd` decision; the
`VerifyContext::allow_internal_dtd(true)` convenience method updates that same policy snapshot
rather than bypassing a separate policy gate. The decision applies consistently to the signed
document and caller-supplied detached XML parsed by node-set transforms. Direct transform callers
can set the corresponding option with `TransformOptions::allow_internal_dtd(true)`. Signing uses
`SigningPolicy::xml.allow_internal_dtd` across its complete pipeline. External entity resolution
remains disabled. Internal-DTD parsing does not import DTD attribute types into the owned Rust ID
index; attributes outside the built-in XMLDSig spellings and `xml:id` still require an explicit
request-scoped ID registration. XSLT is intentionally not executed because transforms operate on
attacker-controlled documents; an authenticated Manifest reference using unsupported XSLT is
reported as an invalid per-reference result without changing core `SignedInfo` validity.

## Current Scope

Implemented signature methods include DSA-SHA1/SHA256; HMAC-SHA1/SHA224/SHA256/SHA384/SHA512;
RSA PKCS#1 v1.5 with SHA-1/SHA224/SHA256/SHA384/SHA512; and ECDSA
SHA-1/SHA224/SHA256/SHA384/SHA512. ECDSA selects P-256, P-384, or P-521 from the key independently
of the hash identifier. Digest methods include SHA-1/SHA224/SHA256/SHA384/SHA512.
HMAC output can be omitted for full width or explicitly truncated on an octet boundary, subject to
`HmacPolicy` key and output minima.

RSA-SHA1, DSA-SHA1, HMAC-SHA1, and ECDSA-SHA1 are legacy algorithms disabled by default.
Verification requires an independent opt-in: `None` in the general
`VerificationPolicy::signature_algorithms` allowlist does not bypass
`VerificationPolicy::key_trust.allowed_legacy_signature_algorithms`, where callers must explicitly
opt in to each legacy method needed by that operation. Signing requires the method in an explicit
`SigningPolicy::signature_algorithms` allowlist; selecting a SHA-1 method in document content never
enables it. `KeyTrustPolicy::rsa_keys` and
`KeyTrustPolicy::dsa_keys` separately enforce key-strength minima on resolved verification keys and
on issuer keys used to authenticate certificate paths and applicable CRLs; their secure defaults
are 2048 bits. Compatibility operations may lower the DSA minimum to 1024 bits, but the
non-configurable DSA implementation ceiling remains 3072 bits.
Built-in keys supplied directly through `VerifyContext::key` enforce the same immutable operation
policy as keys produced by `DefaultKeyResolver`; selecting a key source cannot tighten or weaken
the configured minimum. Custom opaque `VerifyingKey` implementations remain responsible for key
metadata that the core cannot inspect.
Selecting the algorithm in untrusted XML does not opt the operation into legacy cryptography, and
this gate runs before key resolution.
X.509 path and CRL authentication additionally supports standard RSA-PSS with SHA-256/SHA-384/
SHA-512 parameters, including RFC 4055 issuer-key restrictions, and Ed25519. Signature
`AlgorithmIdentifier` parameters are validated before provider dispatch: DSA, ECDSA, and Ed25519
require absent parameters; RSA PKCS#1 accepts NULL or absent; RSA-PSS requires valid typed
parameters. An `id-RSASSA-PSS` issuer key with absent parameters imposes no parameter restrictions,
as required by RFC 4055 section 3.3; present key parameters constrain the signature hash, MGF,
minimum salt length, and trailer field. XMLDSig `SignatureMethod` RSA-PSS and implicit external
resource loading are not currently supported.
