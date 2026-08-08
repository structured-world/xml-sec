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

For recipient transport, add one or more `EncryptionRecipient::rsa_oaep` entries with recipient
public keys, or use `recipient_aes_kw` with a shared KEK. A fresh content key is generated from
the operating-system RNG and wrapped once per recipient. The crate's secure RSA-OAEP default is
SHA-256/MGF1-SHA-256. XMLEnc 1.1 itself defaults omitted parameters to SHA-1/MGF1-SHA-1, so
`xml-sec` always emits explicit `ds:DigestMethod` and `xenc11:MGF` values rather than relying on
those implicit legacy defaults. SHA-1 OAEP remains available only through explicit parameters.

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

`PrivateKeyDecryptor` unwraps embedded RSA-OAEP `EncryptedKey` values and `KekDecryptor`
unwraps AES-KW values. RSA PKCS#1 v1.5 transport, `CipherReference`, and unauthenticated external
resource loading are rejected; only inline `CipherValue` is accepted. Encryption inputs and
recipient counts are bounded before allocation. Decryption applies the same aggregate recipient
ceiling while parsing and rechecks caller-constructed `EncryptedData` before key resolution.

For multiple recipients, `DecryptContext` validates transport, wrap, digest, and MGF policy as
each `EncryptedKey` becomes a resolver candidate. A malformed or disallowed key for another
recipient therefore cannot suppress a later matching candidate. A resolver that supplies a direct
symmetric key remains authoritative and does not consult unrelated embedded key hints.

AES-CBC framing is bounded before decryption and the exact plaintext bound is checked again after
padding removal. Invalid padding is reported only as `XmlEncError::InvalidPadding`; neither the
provider error nor the public error exposes the final decrypted octet or derived padding length.

Use `decrypt_document` to replace one typed `EncryptedData` in a complete XML string. Pass its
`Id` when the document contains multiple encrypted regions. The compiled decryption policy checks
the caller-owned document byte ceiling before DOM allocation and applies its XML node ceiling to
the initial document, replacement-boundary validation, and final output reparse. The projected
output byte length is checked before constructing the replacement. DTD parsing remains disabled by
default; legacy documents that need an internal DTD can opt in through
`decrypt_document_with_options` and `DocumentDecryptionOptions`. That API never installs an
external entity resolver.
