# XML Security Policy Profiles

Trusted application code selects a profile; document content never selects one.
Profiles constrain XML Security processing, not complete application protocol
conformance, certificate trust deployment or every XAdES signature level.

| Profile | Contract |
| --- | --- |
| `XmlSecCompatible` | Explicit inbound compatibility permissions and libxslt stylesheet error handling; outbound signing remains modern |
| `Modern` | Modern signatures and digests, restricted transforms and authenticated outbound encryption |
| `SecureSaml` | SAML signature placement, restricted references/transforms and explicit authenticated target coverage |
| `WsSecurity` | SOAP Security-header placement and explicit authenticated target coverage |
| `Xades` | Typed, authenticated SignedProperties references and explicit target coverage |
| `LegacyVerify` | Verification only, requiring an auditable, expiring caller authorization |

`PolicyCompiler` composes complete `PolicySet` layers in system, application,
then tenant order. Permissions intersect, strength minima increase, resource
ceilings decrease, and a disabled operation cannot be re-enabled. `None` means
disabled, not unspecified inheritance. Conflicting interpretation modes and
protocol constraints are errors, not an implicit precedence rule.

```rust
use xml_sec::policy::{PolicyCompileContext, PolicyCompiler, PolicyProfile};
use xml_sec::provider::default_provider;
use xml_sec::xmldsig::VerifyContext;

let provider = default_provider();
let policies = PolicyCompiler::new(PolicyProfile::Modern, provider, None)?
    .compile(&PolicyCompileContext {
        external_resources: false,
        target_evidence: false,
    })?;
let verification = policies.verification().expect("enabled verification").clone();
let verifier = VerifyContext::new().provider(provider).policy(verification);
```

Compilation checks provider capabilities and contradictions before XML work.
The compiler borrows the engine supplied to `new` for its entire lifecycle;
compile context cannot silently substitute another engine.
Content and key-wrap permissions are filtered by the operation's direction:
decryption uses `Decrypt`/`KeyUnwrap`, never outbound capability sets.
Compatibility explicitly grants supported inbound CBC, legacy and extended
methods; it does not turn an absent allowlist into permission or relax outbound
modern permissions.
Explicit RSA-OAEP permissions are checked for every allowed digest/MGF tuple.
When path validation is enabled, exact certificate/CRL signature allowlists
are checked against `VerifyCertificate` capabilities, including parameters.
An empty certificate allowlist denies certificate/CRL signatures; it does not
disable requests using caller-trusted preset keys without certificate resolution.
Each enabled signature operation must retain an implemented canonicalization
method; a reference-only or empty transform set is not a usable compiled policy.
SAML additionally retains its mandatory enveloped transform and this profile's
exclusive canonicalization requirement.
Modern signing and verification retain supported secure parameterized RSA-PSS;
compatibility verification additionally permits supported legacy PSS tuples.
Restrictive layers can narrow that family permission independently of exact methods.
Untrusted XML profile failures return `PolicyViolation::SignatureProfile`, not
the `Configuration` error used for trusted policy compilation.
Compile-context promises do not supply actual resources or target identities:
operations still need caller-provided resource maps, trusted key material and,
for protocol profiles, nonempty expected targets through `verify_request`.
Application checks such as SAML audience, recipient and replay protection remain
the application's responsibility.

The SAML binding requires an `Assertion` root or a defined protocol-message root,
not an arbitrary child sharing a SAML namespace (SAML Core 2.0 §5.4.2).
The extensible `SubjectQuery` root remains supported; validating its derived
schema and other message payloads belongs to the application.
The XAdES binding requires nonempty, ordered `SignedProperties` containers
(ETSI EN 319 132-1 V1.3.1 §4.3.2). It does not validate the contents of individual
qualifying properties or claim a complete XAdES baseline level.

Relaxation uses `authorize_replacement` with `PolicyValidity`: authorization
identity, granting authority, reason and a half-open validity interval. The
application authenticates the grant. Earlier authorization lifetimes still
intersect, so replacement cannot extend a previous grant; operation entry
checks expiry again. No implicit configuration discovery or provider fallback
is performed.

Certificate and CRL processing uses the same immutable resource/trust policy
and selected provider. Caller-supplied UTC facts are request evidence, not a
profile default; see [key management](key-management.md).

Standalone certificate-path validation accepts explicit resource limits through
`verify_x509_certificate_chain_with_resources`; its convenience counterpart uses
the documented default allowance through the same admission path. Both admit every
supplied certificate, CRL and trust anchor against the per-input and shared total
byte limits before parsing, including unused evidence; preflight traversal also
consumes the operation's X.509 work allowance.
The CLI's explicit UTC-facts file is subject to the per-input and shared
external-material byte allowance before buffer growth, alongside certificates
and mapped reference resources; X.509 workspace/work limits also apply.
Built-in certificate and `X509Digest` writers
share the signing operation's certificate account through
`KeyInfoWriter::write_key_info_in_session`, including multi-signature work.
For bounded ingestion before signing, use `from_der_chain_in_session` or
`X509DigestKeyInfoWriter::from_der_in_session` with a caller-owned parsing session.
