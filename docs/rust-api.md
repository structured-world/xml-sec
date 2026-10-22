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
`sign_template_xml` fill existing templates. Request bindings support KeyInfo
writers, detached resources, ID attributes and template/append selection. A
KeyInfo writer fills an existing placeholder: request it with
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

### Ownership And Errors

The facade borrows its provider and compiled policies. Copying it copies only
references and the parser selection. Operation contexts retain the existing owned
policy snapshot at creation; no per-node policy cloning is added. Keys/resolvers,
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
`xmldsig` (which currently requires `std`); C14N-only and alloc-only XML input
remain independent. It does not claim alloc-only XMLDSig.

`XmlSecError` is now a non-exhaustive typed sum of original document, policy,
verification, signing, key-store, encryption and C14N failures, plus
`OperationDisabled`. Match the appropriate variant and its original error; no
diagnostic-string parsing is necessary. This replaces the old unused string-only
variants during pre-1.0 API stabilization. Invalid signatures remain evidence,
not processing errors. Existing low-level error types and APIs remain available.
