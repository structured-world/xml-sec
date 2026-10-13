# XML Security Policy Profiles

Trusted application code selects a profile; document content never selects one.
Profiles constrain XML Security processing, not complete application protocol
conformance, certificate trust deployment or every XAdES signature level.

| Profile | Contract |
| --- | --- |
| `XmlSecCompatible` | Explicit inbound compatibility permissions; outbound signing remains modern |
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
        provider,
        external_resources: false,
        target_evidence: false,
    })?;
let verification = policies.verification().expect("enabled verification").clone();
let verifier = VerifyContext::new().provider(provider).policy(verification);
```

Compilation checks provider capabilities and contradictions before XML work.
Compile-context promises do not supply actual resources or target identities:
operations still need caller-provided resource maps, trusted key material and,
for protocol profiles, nonempty expected targets through `verify_request`.
Application checks such as SAML audience, recipient and replay protection remain
the application's responsibility.

Relaxation uses `authorize_replacement` with `PolicyValidity`: authorization
identity, granting authority, reason and a half-open validity interval. The
application authenticates the grant. Earlier authorization lifetimes still
intersect, so replacement cannot extend a previous grant; operation entry
checks expiry again. No implicit configuration discovery or provider fallback
is performed.

Certificate and CRL processing uses the same immutable resource/trust policy
and selected provider. Caller-supplied UTC facts are request evidence, not a
profile default; see [key management](key-management.md).
