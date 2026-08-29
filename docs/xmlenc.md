# XML Encryption

Enable the `xmlenc` feature for AES-CBC/GCM content encryption and decryption, RSA-OAEP key
transport, AES Key Wrap, multiple recipients, and Element/Content document replacement.

Encryption and decryption compile explicit operation plans that order document parsing,
key resolution, provider dispatch, evidence finalization, and optional mutation. The
operation context owns the immutable policy, stable document identity/generation, XML
parse-work and key-candidate budgets, and deterministic decision state. All recipient
retries consume that single context; a successful provider call is not reported as an
accepted operation until output validation succeeds, and document replacement remains
the terminal graph node. Failed candidates or replacement validation leave an owned
document and its generation unchanged.
Dependency and resource checks run before the closure that performs each phase. A
controlled replacement must start at the context's expected generation, commit exactly
one new generation, and advance that expectation before any later node can execute;
stale or foreign document state is therefore rejected before mutation work begins.
Compiled graph failures are reported as `XmlEncError::OperationPlan`; malformed XMLEnc
element order or namespaces remain `XmlEncError::InvalidStructure`.

## Direct-Key Encryption

`EncryptedDataBuilder` can encrypt opaque bytes, one XML element, an XML content fragment, or a
selected element in a complete document. This direct-key example creates an `EncryptedData`
fragment and verifies it through the reciprocal decrypt path:

```rust
use xml_sec::xmlenc::{
    DataEncryptionAlgorithm, DecryptedContent, EncryptedDataBuilder,
    SymmetricKeyDecryptor, decrypt,
};

fn example() -> Result<(), Box<dyn std::error::Error>> {
    let key = [0x42_u8; 16];
    let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
        .direct_key(key)
        .direct_key_name("application-content-key")
        .encrypt_xml("<secret>value</secret>")?;

    assert_eq!(
        decrypt(
            &encrypted.encrypted_data_xml,
            &SymmetricKeyDecryptor::new(key),
        )?,
        DecryptedContent::Xml("<secret>value</secret>".into()),
    );
    Ok(())
}
```

For embedded decryption, `DecryptContext::id_attributes` accepts the same immutable global or
element-scoped `IdAttributeRegistration` request context as XMLDSig. Element scope can match a
local name in any namespace or one exact expanded name. It affects only operation start-node
lookup; policy remains a separate compiled snapshot.

For recipient transport, add one or more `EncryptionRecipient::rsa_oaep` entries with recipient
public keys, or use `recipient_aes_kw` with a shared KEK. `EncryptedDataBuilder` obtains each fresh
content key through `CryptoProvider::fill_random` and wraps it once per recipient. The default
`RustCryptoProvider` uses the operating-system RNG; `.provider(...)` can replace that behavior
together with the cryptographic primitives. The crate's secure RSA-OAEP default is
SHA-256/MGF1-SHA-256 and generated recipients serialize those choices explicitly. When consuming
templates or encrypted input, both RSA-OAEP URIs default an omitted `ds:DigestMethod` and
`xenc11:MGF` to SHA-1/MGF1-SHA-1. libxmlsec1 1.3.13 also accepts an explicit XMLEnc 1.1
`xenc11:MGF` child under the legacy `rsa-oaep-mgf1p` URI; `xml-sec` parses, executes, and preserves
that interoperable form. Serializing the legacy URI omits only a default MGF1-SHA1 choice and emits
the child for every non-default MGF.
`recipient_key_transport` accepts an opaque `KeyTransportKey` for provider-owned public keys;
the RSA convenience constructor wraps a RustCrypto key into the same contract. The handle exposes
only normalized public modulus/exponent metadata required by encryption policy and framing checks.
On decryption, `PrivateKeyDecryptor::provider_key` accepts an opaque `KeyRecoveryKey`; private key
material never enters XML orchestration. Capability checks receive complete OAEP digest, MGF, and
label parameters. Key transport and key recovery are independent capabilities, so a private-key
provider can advertise recovery without public-key wrapping support. An unsupported provider fails
without invoking the key or falling back.
`validate_key_transport_recipient` gives provider-owned key registries the same policy preflight;
the existing `validate_rsa_recipient_key` remains the RustCrypto convenience form.
`EncryptionPolicy::rsa_keys` validates every recipient modulus and exponent before provider
dispatch. New output defaults to 2048-8192-bit RSA keys; callers can explicitly tighten or relax
the minimum for a deployment profile, but cannot exceed the implementation ceiling.
Encryption preflight also applies the operation-wide `ResourcePolicy::max_key_candidates` limit
before inspecting or dispatching any configured key: a direct content key consumes one candidate,
while recipient mode consumes one candidate per independently wrapped recipient. The separate
`max_encryption_recipients` ceiling still applies, so the tighter of the two limits wins.
`validate_rsa_recipient_key` exposes that same preflight to ordered key registries, allowing them
to skip policy-invalid candidates before committing to one without duplicating policy limits.
AES-KW configuration similarly validates the KEK size fixed by its algorithm URI before provider
dispatch, so custom providers cannot reinterpret `kw-aes128` with a 256-bit KEK or `kw-aes256`
with a 128-bit KEK. A custom provider's wrapped-key output must contain the complete RFC 3394 value,
which is exactly eight bytes longer than the content key; the facade validates that framing before
serializing `EncryptedKey`.
The same `EncryptionMethod` structural validation applies to parsed XML and caller-constructed
typed values: an explicit `xenc11:MGF` is valid with either RSA-OAEP URI and rejected on non-OAEP
methods. Every supplied `KeySize` must be positive; fixed-width AES methods additionally require it
to match the selected algorithm.

`encrypt_document` selects the root or an element by `Id`, `ID`, or `id`, then replaces either
the complete element or only its child content according to `EncryptedDataType`. See
`examples/encrypt.rs` for RSA-OAEP document encryption.

## Decryption

Parse once and retain the caller-owned encrypted model when a resolver must be configured before
decryption:

```rust
use xml_sec::xmlenc::{
    DecryptedContent, SymmetricKeyDecryptor, decrypt_data, parse_encrypted_data,
};

fn example(encrypted_xml: &str) -> Result<(), Box<dyn std::error::Error>> {
    let encrypted = parse_encrypted_data(encrypted_xml)?;
    let resolver = SymmetricKeyDecryptor::new([0_u8; 16]);
    let plaintext = decrypt_data(&encrypted, &resolver)?;

    match plaintext {
        DecryptedContent::Xml(xml) => println!("{xml}"),
        DecryptedContent::Bytes(bytes) => println!("{} plaintext bytes", bytes.len()),
    }
    Ok(())
}
```

Callers that already parsed a containing XML document can use
`parse_encrypted_data_node_with_policy` on the backend-neutral `xml_sec::Node`. Encryption frontends
that inspect caller-owned templates use `parse_encrypted_data_template_node_with_policy`, which
applies the same complete structure and metadata limits but permits empty `CipherValue`
placeholders. Both node-oriented APIs avoid serializing a subtree and losing namespace declarations
inherited from its ancestors. Their `_and_backend` variants retain an explicitly selected compiled
backend while revalidating the containing document; the shorter entry points use the build default.

`PrivateKeyDecryptor` unwraps embedded RSA-OAEP `EncryptedKey` values and `KekDecryptor`
unwraps AES-KW values. RSA PKCS#1 v1.5 transport, `CipherReference`, and unauthenticated external
resource loading are rejected; only inline `CipherValue` is accepted. Encryption plaintext,
recipient counts, and the complete serialized `EncryptedData` fragment are bounded. Decryption
applies the same aggregate recipient ceiling while parsing, bounds each retained identifier,
algorithm URI, key name, OAEP label, and reference URI, and rechecks caller-constructed
`EncryptedData` before decoding or key resolution.
That typed-input check validates the top-level content `EncryptionMethod` and every embedded key
method before resolver dispatch, and bounds both encoded and projected decoded `CipherValue`
sizes. Callers therefore cannot bypass parser structural or allocation limits by constructing the
public model directly.

For multiple recipients, `DecryptContext` validates transport, wrap, digest, and MGF policy as
each `EncryptedKey` becomes a resolver candidate. A malformed or disallowed key for another
recipient therefore cannot suppress a later matching candidate. A resolver that supplies a direct
symmetric key remains authoritative and does not consult unrelated embedded key hints.
The operation shares one `KeyCandidateBudget` across the direct lookup and every recipient;
custom `DecryptionKeyResolver` implementations must charge it before each lookup or unwrap attempt.
The context additionally accounts for returned candidates, so a resolver cannot multiply work by
resetting a per-recipient allowance. Candidate-local lookup or unwrap failures may be recorded while
later recipients are tried, but any policy violation returned by
`DecryptionKeyResolver::resolve_key_candidates` is terminal for the complete operation. Resolution
does not continue after a resolver rejects resource bounds, key trust, or any other compiled-policy
requirement. Explicit
`ReferenceList/DataReference` and `CarriedKeyName`
metadata restricts an embedded key to the referenced `EncryptedData` or matching `ds:KeyName`.
Association metadata may be omitted, but an explicit contradiction is skipped rather than tried.
Wrong-width symmetric candidates are discarded before AES-CBC ambiguity checks because they cannot
reach the selected primitive.
Unknown key transport and wrap URIs fail closed before an application resolver is invoked.

AES-CBC framing is bounded before decryption and the exact plaintext bound is checked again after
padding removal. Invalid padding is reported only as `XmlEncError::InvalidPadding`; neither the
provider error nor the public error exposes the final decrypted octet or derived padding length.
Successful custom-provider output is also checked against the wire-derived contract: AES-GCM has
one exact plaintext length, while AES-CBC output must fit the range permitted by one padding block.
That uniform diagnostic does not authenticate CBC or remove the success-versus-failure signal.
Applications processing attacker-controlled ciphertext must authenticate the enclosing protocol
before acting on plaintext, or exclude AES-CBC with `DecryptionPolicy::data_algorithms` and use
AES-GCM.

Use `decrypt_document` to replace one typed `EncryptedData` in a complete XML string. Pass its
`Id` when the document contains multiple encrypted regions. The compiled decryption policy checks
the shared `ResourcePolicy::max_xml_document_bytes` ceiling before DOM allocation and applies its
XML node and depth ceilings to the initial document and every replacement generation. A bounded
streaming preflight enforces these limits before either parser backend allocates a DOM and charges
recursive internal-entity replacement traversal to cumulative XML parse work.
`encrypt_owned_document` and
`decrypt_owned_document` reuse the retained parsed view, validate replacement XML in the parent
namespace context, and invalidate prior node identities after a successful mutation. String APIs
remain adapters over this boundary. `ResourcePolicy::max_xml_parse_work_bytes` is cumulative across
the initial document, generated or decrypted fragment validation, committed generations, and all
key-candidate retries, so nested helpers cannot reset parser work. Use
`XmlDocument::parse_with_policy(xml, &encryption_or_decryption_policy)` when constructing a retained
document with non-default XML rules; this derives parsing directly from the operation's immutable
policy snapshot. The projected output byte length is checked before constructing
the replacement, and expanded decryption plaintext is parsed against the operation's projected
node and depth ceilings before any generation is committed. Owned entry points also revalidate parse
provenance, preventing a document that required internal DTD support from crossing into a stricter
operation context. DTD parsing remains disabled by
default; legacy documents that need an internal DTD can opt in only through
`DecryptionPolicy::xml.allow_internal_dtd`. The API never installs an external entity resolver.

`encrypt_document` also checks the exact projected document byte length and XML node count after
cipher framing, base64, and `EncryptedData` serialization but before allocating the replacement
document. Element replacement subtracts the complete selected subtree; Content replacement
retains its selected element and subtracts only its descendants. This keeps generated Element and
Content output within the same document policy accepted by reciprocal decryption.
