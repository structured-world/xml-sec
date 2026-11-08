## Policy-Bound Rust API

`XmlSecurity` is a reusable binding of caller-compiled policies and one explicitly
selected `CryptoProvider`. It performs no configuration discovery, key fetching,
network access or provider fallback. Its operation handles expose request data,
not policy replacement. Disabled operations fail before XML or key processing.

```rust
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use xml_sec::{XmlSecurity, api::Operation};
use xml_sec::policy::{PolicyCompileContext, PolicyCompiler, PolicyProfile};
use xml_sec::provider::RustCryptoProvider;

let provider = RustCryptoProvider;
let policies = PolicyCompiler::new(PolicyProfile::Modern, &provider, None)?
    .compile(&PolicyCompileContext {
        external_resources: false,
        target_evidence: true,
    })?;
let security = XmlSecurity::new(&policies, &provider)?;
let document = security.parse_document("<root/>", Operation::Verify)?;
assert_eq!(document.generation(), 0);
# Ok(())
# }
```

### Verification And Identity

Use `security.verifier()?.key(&trusted_key).verify(&document, &request)` for
application acceptance. The existing `VerificationRequest` borrows expected
element identities, authorized Signature/key mappings, external bytes and
cardinality requirements. Inspect `evidence.accepted(&document)?`, then consume
only the authenticated targets. `Ok`, `all_valid()` and a valid signature value
alone are not expected-target authorization. Evidence cannot authorize another
document or a later generation. Custom resolvers use `key_resolver`; a
`KeyInventory::verification_resolver()` is the same existing policy-aware adapter,
not a separate trust engine.

`verify_signature_xml` borrows XML for a single-signature diagnostic operation.
Its result is the existing `VerifyResult`, not a claim about an application's
selected element or complete multi-signature acceptance. Profiles requiring
target evidence still require the retained-document request API.

### Signing And Encryption

`security.signer(&key)?` accepts an opaque caller-owned signing handle. Its
`sign`/`sign_xml` methods use `SignatureBuilder`; `sign_template` and
`sign_template_xml` fill existing templates. Request bindings support `KeyInfo`
writers, detached resources, ID attributes and template/append selection. A
`KeyInfo` writer fills an existing placeholder: request it with
`SignatureBuilder::key_info(true)` when using a builder.
`security.signing_key(&inventory, name, algorithm)` selects/imports an authorized
named key into the same selected provider. Inventory lookup is not permission
to trust a document's embedded certificate.

With `xmlenc`, `security.encryptor(&builder)?` borrows encryption request material
and exposes retained-document, string-document, standalone-fragment and binary
operations. The facade's compiled encryption policy/provider govern execution;
policy/provider/backend settings stored in that low-level builder do not override
the binding. Keys, recipients and opaque handles are not cloned to achieve this.
`security.decryptor(&resolver)?` similarly supports retained-document,
string-document and standalone-fragment recovery. Named recovery selection uses
`security.decryption_key(&inventory, name)`. Detached inputs and ID registrations
remain explicit request bindings.

Retained sign/encrypt/decrypt calls commit through the existing operation plan
and advance the document generation only on success. Failed operations preserve
the original document. They never create a new parser, crypto dispatcher or
certificate stack. C14N and advanced scoped extension/current-query APIs remain
available in their existing low-level modules.

### Policy Audit

Every operation reports what its policy decided as a `PolicyAudit`:
`VerifyResult::policy` for single-signature verification, `Audited<T>`
(`output` plus `policy`) from the string, fragment and binary operations, and a
bare `PolicyAudit` from the retained-document operations, whose output is the
document itself. `EncryptionResult::policy` carries it for the low-level
encryption builder. Retained-document verification reports per Signature:
`SignatureEvidence::policy` holds each Signature's decisions whatever its
outcome, ending with the refusal when the policy failed it, and
`VerifyEvidence::policy_identity` names the enforced snapshot even for a
document without a Signature. Completing detached References in a verified
session appends the Manifest processing it runs to that Signature's audit.

- `identity` names the published snapshot the operation enforced: profile,
  configuration schema version, publication revision and the SHA-256 of the
  canonical effective settings. It is present when the compiled policies carry
  one (`CompiledPolicies::with_identity`, or every `xml-sec-config`
  `PolicyStore` publication) and absent once a low-level builder customized the
  policy, because the settings then differ from the published ones. Limits the
  operation stayed within are identified by that digest.
- `decisions` lists, in the order the operation made them, every algorithm the
  policy permitted with its role (signature, canonicalization, digest,
  transform, content encryption, key transport, OAEP digest, mask generation,
  key wrap), including the inclusive C14N 1.0 that a Reference's transform
  chain applies implicitly and the OAEP digests a key transport implies (each
  by its standard URI), the class of every
  Reference, Manifest Reference and `CipherReference` URI it resolved, the
  Manifest processing it applied, the exception grant it ran under, and each
  input it refused while continuing, such as one Reference among several. A
  refusal that ends the operation is its error instead.

Records carry public algorithm URIs and URI classes only, never document
content, URIs, key material or resource bytes, so they can be logged as they
are; a refused algorithm this build does not recognize is named
`UNRECOGNIZED_ALGORITHM`. How a verification key was authorized stays in `VerifyResult::key_trust`.

### Ownership And Errors

The facade borrows its provider and compiled policies. Copying it copies only
references and the parser selection. Operation contexts share the compiled policy
snapshot at creation instead of copying it; no per-node policy cloning is added. Keys/resolvers,
external resource maps and writers are borrowed for the operation handle's lifetime.
Encryption execution also borrows its builder, avoiding secret copies and provider
reference-count operations. Signing, encryption and decryption handles can outlive
the facade value, including a temporary facade; their policy/provider and request
inputs must still remain alive. Verification handles borrow the facade as well as
their request inputs. Returned strings/bytes/evidence have their existing
ownership contracts. `parse_document` moves an owned `String` into its retained
document; a borrowed string requires the document's one owning copy. Preparation
has its own parse budget. The string operation methods instead retain the existing
single parse+operation cumulative-budget path, without an extra facade parse.

`XmlSecurity` is `Send + Sync`; individual handles do not impose additional bounds
on non-thread-safe caller keys/resolvers. Share immutable policies/providers using
application-owned storage or `Arc`, not a global registry. The facade requires
`xmldsig`, which builds without `std`; its signer, `Operation::Sign` and the
signing error variant need `xmldsig-sign`, which requires `std`. C14N-only
builds remain independent of both.

`XmlSecError` is now a non-exhaustive typed sum of original document, policy,
verification, signing, key-store, encryption and C14N failures, plus
`OperationDisabled`. Match the appropriate variant and its original error; no
diagnostic-string parsing is necessary. This replaces the old unused string-only
variants during pre-1.0 API stabilization. Invalid signatures remain evidence,
not processing errors. Existing low-level error types and APIs remain available.
