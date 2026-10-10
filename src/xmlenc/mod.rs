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
//! External `CipherReference` resources are outside this profile. Optional
//! `legacy-algorithms` adds independently policy-gated RSA-1.5 and TripleDES
//! mechanisms; it does not grant permission or authenticate CBC content.
#![doc = include_str!("../../docs/xmlenc.md")]

use crate::xml::dom::Node;

mod agreement;
mod encapsulation;
pub use encapsulation::EncapsulationDecryptor;
mod cipher_reference;
pub use agreement::{AgreementDecryptor, AgreementMethod};
mod decrypt;
pub use cipher_reference::CipherReferenceContext;
mod derived_key;
pub(crate) use decrypt::validate_key_len;
pub use derived_key::DerivedKey;
mod encrypt;
mod hkdf_agreement;
mod key_derivation;
pub use hkdf_agreement::{HkdfAgreement, parse_hkdf_agreement_method};
mod key_establishment_budget;
pub use key_establishment_budget::KeyEstablishmentBudget;
mod parse;
mod types;

pub use decrypt::{
    DecryptContext, DecryptionKeyResolver, DerivedKeyDecryptor, DerivedKeyInput,
    DocumentDecryptionOptions, KekDecryptor, KeyCandidateBudget, KeyEncryptionKeySource,
    OpaqueContentKeyResolver, OpaqueKekDecryptor, PrivateKeyDecryptor, SymmetricKeyDecryptor,
    decrypt, decrypt_data, decrypt_document, decrypt_document_with_options,
};
pub use encrypt::{
    EncryptedDataBuilder, validate_key_transport_recipient, validate_rsa_recipient_key,
};
pub use key_derivation::{
    ConcatKdfField, KeyDerivationMethod, parse_key_derivation_method,
    parse_key_derivation_method_with_backend,
};
pub use parse::{
    EncryptedDataInspection, EncryptedDataTemplate, inspect_encrypted_data_node_with_context,
    inspect_encrypted_data_template_node_with_context, parse_encrypted_data,
    parse_encrypted_data_node_with_context, parse_encrypted_data_node_with_policy,
    parse_encrypted_data_node_with_policy_and_backend,
    parse_encrypted_data_template_node_with_policy,
    parse_encrypted_data_template_node_with_policy_and_backend,
};
pub use types::{
    ChaChaParameters, ChaChaParametersRef, CipherData, DataEncryptionAlgorithm, DecryptedContent,
    DocumentEncryptionOptions, EncryptedData, EncryptedDataType, EncryptedKey,
    EncryptionKeySources, EncryptionMethod, EncryptionRecipient, EncryptionResult,
    KeyTransportAlgorithm, KeyWrapAlgorithm, OaepDigestAlgorithm, ReferenceList, ReplacementMode,
    RsaOaepParameters, XmlEncError,
};

fn map_document_error(
    error: crate::document::XmlDocumentError,
    settings: crate::document::DocumentParseSettings,
) -> XmlEncError {
    match error.into_policy_violation(settings) {
        Ok(error) => XmlEncError::Policy(error),
        Err(crate::document::XmlDocumentError::Parse(error)) => XmlEncError::XmlParse(error),
        Err(crate::document::XmlDocumentError::ProjectedNodeLimit { maximum }) => {
            crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_NODES,
                maximum,
                actual: maximum.saturating_add(1),
            }
            .into()
        }
        Err(error) => XmlEncError::Document(error),
    }
}

fn has_single_element_with_boundary_trivia(parent: Node<'_, '_>) -> bool {
    let mut element_count = 0;
    for node in parent.children() {
        if node.is_element() {
            element_count += 1;
            if element_count > 1 {
                return false;
            }
        } else if node.is_comment() {
            continue;
        } else if node.is_text() {
            // XML permits boundary whitespace around a document element; processing
            // instructions and every other node kind are unsafe replacement payloads.
            if !node.text().is_some_and(|text| {
                text.chars()
                    .all(|character| matches!(character, ' ' | '\t' | '\n' | '\r'))
            }) {
                return false;
            }
        } else {
            return false;
        }
    }
    element_count == 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::{DocumentParseSettings, XmlDocumentError};

    #[test]
    fn document_errors_have_one_xmlenc_policy_mapping() {
        // Borrowed parsing and owned mutation must expose identical typed
        // resource failures rather than depending on their entry-point mapper.
        let settings = DocumentParseSettings::new_with_depth(false, 8, 3, 128);
        assert!(matches!(
            map_document_error(
                XmlDocumentError::DocumentTooDeep {
                    maximum: 3,
                    actual: 4,
                },
                settings,
            ),
            XmlEncError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_DEPTH,
                maximum: 3,
                actual: 4,
            })
        ));
        assert!(matches!(
            map_document_error(
                XmlDocumentError::ProjectedNodeLimit { maximum: 8 },
                settings,
            ),
            XmlEncError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_NODES,
                maximum: 8,
                actual: 9,
            })
        ));
    }
}
