# XML Encryption

Enable the `xmlenc` feature for AES-CBC/GCM content encryption and decryption, RSA-OAEP key
transport, AES Key Wrap, multiple recipients, and Element/Content document replacement.

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
SHA-256/MGF1-SHA-256. XMLEnc 1.1 itself defaults omitted parameters to SHA-1/MGF1-SHA-1, so for
the XML Encryption 1.1 RSA-OAEP URI `xml-sec` emits explicit `ds:DigestMethod` and `xenc11:MGF`
values rather than relying on those implicit legacy defaults. SHA-1 OAEP remains available only
through explicit parameters. The legacy `rsa-oaep-mgf1p` URI fixes MGF1 to SHA-1 and has no
`xenc11:MGF` wire field.
`EncryptionPolicy::rsa_keys` validates every recipient modulus and exponent before provider
dispatch. New output defaults to 2048-8192-bit RSA keys; callers can explicitly tighten or relax
the minimum for a deployment profile, but cannot exceed the implementation ceiling.
`validate_rsa_recipient_key` exposes that same preflight to ordered key registries, allowing them
to skip policy-invalid candidates before committing to one without duplicating policy limits.
Configuration validation rejects any non-SHA-1 MGF digest for the legacy URI before provider
dispatch because its wire format cannot represent an alternative.
AES-KW configuration similarly validates the KEK size fixed by its algorithm URI before provider
dispatch, so custom providers cannot reinterpret `kw-aes128` with a 256-bit KEK or `kw-aes256`
with a 128-bit KEK. A custom provider's wrapped-key output must contain the complete RFC 3394 value,
which is exactly eight bytes longer than the content key; the facade validates that framing before
serializing `EncryptedKey`.
The same `EncryptionMethod` structural validation applies to parsed XML and caller-constructed
typed values: an explicit `xenc11:MGF` is valid only with the XML Encryption 1.1 RSA-OAEP URI and
is rejected before key resolution on the legacy URI. Every supplied `KeySize` must be positive;
fixed-width AES methods additionally require it to match the selected algorithm.

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
`parse_encrypted_data_node_with_policy` on the selected `roxmltree::Node`. Encryption frontends
that inspect caller-owned templates use `parse_encrypted_data_template_node_with_policy`, which
applies the same complete structure and metadata limits but permits empty `CipherValue`
placeholders. Both node-oriented APIs avoid serializing a subtree and losing namespace declarations
inherited from its ancestors.

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
XML node ceiling to
the initial document, replacement-boundary validation, and final output reparse. The projected
output byte length is checked before constructing the replacement. DTD parsing remains disabled by
default; legacy documents that need an internal DTD can opt in only when both
`DecryptionPolicy::xml.allow_internal_dtd` and `DocumentDecryptionOptions::allow_dtd` are enabled.
The per-call option cannot weaken the operation policy, and the API never installs an external
entity resolver.

`encrypt_document` also checks the exact projected document byte length and XML node count after
cipher framing, base64, and `EncryptedData` serialization but before allocating the replacement
document. Element replacement subtracts the complete selected subtree; Content replacement
retains its selected element and subtracts only its descendants. This keeps generated Element and
Content output within the same document policy accepted by reciprocal decryption.
