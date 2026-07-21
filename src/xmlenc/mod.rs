//! XML Encryption (XMLEnc).
//!
//! Implements [XML Encryption Syntax and Processing](https://www.w3.org/TR/xmlenc-core1/).

mod decrypt;
mod parse;
mod types;

pub use decrypt::{
    DecryptionKeyResolver, DocumentDecryptionOptions, KekDecryptor, PrivateKeyDecryptor,
    SymmetricKeyDecryptor, decrypt, decrypt_data, decrypt_document, decrypt_document_with_options,
};
pub use parse::parse_encrypted_data;
pub use types::{
    CipherData, DataEncryptionAlgorithm, DecryptedContent, EncryptedData, EncryptedDataType,
    EncryptedKey, EncryptionMethod, KeyTransportAlgorithm, KeyWrapAlgorithm, ReferenceList,
    XmlEncError,
};
