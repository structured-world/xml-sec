//! Explicit recipient key for the experimental libxmlsec1 KEM protocol.

use super::{
    DataEncryptionAlgorithm, DecryptionKeyResolver, KeyCandidateBudget, KeyEncryptionKeySource,
    KeyWrapAlgorithm, XmlEncError,
};
use crate::provider::{CryptoProvider, KeyDecapsulationKey, RecoveredContentKey};

/// Recipient-owned private handle; no key is derived from untrusted hints.
pub struct EncapsulationDecryptor<'a> {
    key: RecipientKey<'a>,
}

enum RecipientKey<'a> {
    Borrowed(&'a dyn KeyDecapsulationKey),
    Owned(std::sync::Arc<dyn KeyDecapsulationKey>),
}

impl RecipientKey<'_> {
    fn as_ref(&self) -> &dyn KeyDecapsulationKey {
        match self {
            Self::Borrowed(key) => *key,
            Self::Owned(key) => key.as_ref(),
        }
    }
}

impl<'a> EncapsulationDecryptor<'a> {
    /// Bind one explicit trusted recipient key for content or nested KEK recovery.
    pub fn new(key: &'a dyn KeyDecapsulationKey) -> Self {
        Self {
            key: RecipientKey::Borrowed(key),
        }
    }

    /// Retain a provider-owned handle selected from an inventory.
    pub fn provider_key(key: std::sync::Arc<dyn KeyDecapsulationKey>) -> Self {
        Self {
            key: RecipientKey::Owned(key),
        }
    }

    fn recover(
        &self,
        provider: &dyn CryptoProvider,
        width: usize,
        descriptor: &crate::key_establishment::EncapsulationMechanism,
        policy: &crate::policy::DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<RecoveredContentKey>, XmlEncError> {
        if width == 0 || width > 32 {
            return Err(crate::key_establishment::KeyEstablishmentError::Structure(
                "consuming key exceeds KEM secret width",
            )
            .into());
        }
        budget.consume(1)?;
        budget.key_establishment.commit_all(
            &policy.key_establishment,
            0,
            0,
            (width + core::mem::size_of::<RecoveredContentKey>()) as u128,
        )?;
        let secret = budget.key_establishment.decapsulate(
            &policy.key_establishment,
            provider,
            self.key.as_ref(),
            descriptor.algorithm,
            &descriptor.ciphertext,
        )?;
        // libxmlsec1 1.3.13's experimental extension supplies the first requested
        // octets directly (no KDF). This is interoperability, not RFC 9935 framing.
        // https://github.com/lsh123/xmlsec/blob/xmlsec-1_3_13/src/xmlenc.c
        // FIPS 203 section 7.3 returns the real-or-rejection secret without a
        // validity bit. This candidate does not attest ciphertext validity;
        // the consuming content cipher/key wrap must still verify integrity,
        // unless check_kem_content explicitly delegates it to the caller.
        // https://doi.org/10.6028/NIST.FIPS.203
        Ok(vec![RecoveredContentKey::confirmed(
            secret[..width].to_vec(),
        )])
    }
}

impl DecryptionKeyResolver for EncapsulationDecryptor<'_> {
    fn resolve_key(
        &self,
        _: &dyn CryptoProvider,
        _: DataEncryptionAlgorithm,
        _: Option<&super::EncryptedKey>,
    ) -> Result<Vec<u8>, XmlEncError> {
        Err(XmlEncError::KeyNotFound)
    }

    fn resolve_encapsulation_content_keys_with_policy(
        &self,
        provider: &dyn CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        descriptor: &crate::key_establishment::EncapsulationMechanism,
        policy: &crate::policy::DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<RecoveredContentKey>, XmlEncError> {
        policy.key_establishment.check_kem_content(algorithm)?;
        self.recover(provider, algorithm.key_len(), descriptor, policy, budget)
    }

    fn resolve_key_encryption_keys_with_policy(
        &self,
        provider: &dyn CryptoProvider,
        algorithm: KeyWrapAlgorithm,
        source: KeyEncryptionKeySource<'_>,
        policy: &crate::policy::DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<RecoveredContentKey>, XmlEncError> {
        let KeyEncryptionKeySource::Encapsulation(descriptor) = source else {
            return Err(XmlEncError::KeyNotFound);
        };
        self.recover(provider, algorithm.key_len(), descriptor, policy, budget)
    }
}
