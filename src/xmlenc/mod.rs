//! XML Encryption (XMLEnc).
//!
//! Implements [XML Encryption Syntax and Processing](https://www.w3.org/TR/xmlenc-core1/).
//!
//! `EncryptedDataBuilder` encrypts opaque bytes, XML elements, XML content, or
//! a selected node in a caller-owned document. It supports direct AES content
//! keys and generated session keys wrapped independently for one or more
//! RSA-OAEP or AES-KW recipients. The reciprocal decrypt APIs accept the same
//! inline `CipherValue` profile.
//!
//! External `CipherReference` resources, RSA PKCS#1 v1.5 key transport, and
//! unauthenticated legacy ciphers are intentionally outside this profile.

use roxmltree::Node;

mod decrypt;
mod encrypt;
mod parse;
mod types;

pub use decrypt::{
    DecryptionKeyResolver, DocumentDecryptionOptions, KekDecryptor, PrivateKeyDecryptor,
    SymmetricKeyDecryptor, decrypt, decrypt_data, decrypt_document, decrypt_document_with_options,
};
pub use encrypt::EncryptedDataBuilder;
pub use parse::parse_encrypted_data;
pub use types::{
    CipherData, DataEncryptionAlgorithm, DecryptedContent, DocumentEncryptionOptions,
    EncryptedData, EncryptedDataType, EncryptedKey, EncryptionMethod, EncryptionRecipient,
    EncryptionResult, KeyTransportAlgorithm, KeyWrapAlgorithm, OaepDigestAlgorithm, ReferenceList,
    ReplacementMode, RsaOaepParameters, XmlEncError,
};

fn has_single_element_with_boundary_trivia(parent: Node<'_, '_>) -> bool {
    let mut element_count = 0;
    let valid_children = parent.children().all(|node| {
        if node.is_element() {
            element_count += 1;
            true
        } else if node.is_comment() {
            true
        } else if node.is_text() {
            // XML permits boundary whitespace around a document element; processing
            // instructions and every other node kind are unsafe replacement payloads.
            node.text().is_some_and(|text| {
                text.chars()
                    .all(|character| matches!(character, ' ' | '\t' | '\n' | '\r'))
            })
        } else {
            false
        }
    });
    valid_children && element_count == 1
}
