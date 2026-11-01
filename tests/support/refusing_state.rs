//! A provider whose digest state runs out, and which counts finalizations.

use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use structured_asn1::memory::{Memory, MemoryError};
use xml_sec::provider::{
    CryptoProvider, DigestState, KdfParameters, ProviderCapability, ProviderError,
    RustCryptoProvider,
};
use xml_sec::xmldsig::{
    DigestAlgorithm, DsigError, MAX_DIGEST_OUTPUT, SignatureAlgorithm, SigningKey, SigningKeyError,
    VerifyingKey,
};

/// Refuses to create a state after `allowed` of them, as a spent account or the
/// allocator does.
pub struct RefusingStateProvider {
    allowed: AtomicUsize,
    finalized: AtomicUsize,
}

impl RefusingStateProvider {
    pub fn after(allowed: usize) -> Self {
        Self {
            allowed: AtomicUsize::new(allowed),
            finalized: AtomicUsize::new(0),
        }
    }

    /// Provider finalizations so far.
    pub fn finalized(&self) -> usize {
        self.finalized.load(Relaxed)
    }
}

struct CountedState<'p> {
    state: Box<dyn DigestState + 'p>,
    finalized: &'p AtomicUsize,
}

impl DigestState for CountedState<'_> {
    fn update(&mut self, data: &[u8]) -> Result<(), ProviderError> {
        self.state.update(data)
    }
    fn finalize(&mut self, output: &mut [u8; MAX_DIGEST_OUTPUT]) -> Result<usize, ProviderError> {
        self.finalized.fetch_add(1, Relaxed);
        self.state.finalize(output)
    }
}

impl CryptoProvider for RefusingStateProvider {
    fn name(&self) -> &'static str {
        "refusing-state"
    }
    fn supports(&self, capability: ProviderCapability<'_>) -> bool {
        RustCryptoProvider.supports(capability)
    }
    fn fill_random(&self, output: &mut [u8]) -> Result<(), ProviderError> {
        RustCryptoProvider.fill_random(output)
    }
    fn derive_key(
        &self,
        parameters: &KdfParameters<'_>,
        secret: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        RustCryptoProvider.derive_key(parameters, secret)
    }
    fn begin_digest(
        &self,
        algorithm: DigestAlgorithm,
        memory: &Memory,
    ) -> Result<Box<dyn DigestState + '_>, ProviderError> {
        let remaining = self
            .allowed
            .load(Relaxed)
            .checked_sub(1)
            .ok_or(ProviderError::Resource(MemoryError::OutOfMemory))?;
        self.allowed.store(remaining, Relaxed);
        Ok(Box::new(CountedState {
            state: xml_sec::provider::default_provider().begin_digest(algorithm, memory)?,
            finalized: &self.finalized,
        }))
    }
    fn sign(
        &self,
        key: &dyn SigningKey,
        algorithm: SignatureAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>, SigningKeyError> {
        RustCryptoProvider.sign(key, algorithm, data)
    }
    fn verify(
        &self,
        key: &dyn VerifyingKey,
        algorithm: SignatureAlgorithm,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, DsigError> {
        RustCryptoProvider.verify(key, algorithm, data, signature)
    }
    #[cfg(feature = "xmlenc")]
    fn encrypt_data(
        &self,
        algorithm: xml_sec::xmlenc::DataEncryptionAlgorithm,
        key: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        RustCryptoProvider.encrypt_data(algorithm, key, plaintext)
    }
    #[cfg(feature = "xmlenc")]
    fn decrypt_data(
        &self,
        algorithm: xml_sec::xmlenc::DataEncryptionAlgorithm,
        key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        RustCryptoProvider.decrypt_data(algorithm, key, ciphertext)
    }
    #[cfg(feature = "xmlenc")]
    fn wrap_key(
        &self,
        algorithm: xml_sec::xmlenc::KeyWrapAlgorithm,
        kek: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        RustCryptoProvider.wrap_key(algorithm, kek, key)
    }
    #[cfg(feature = "xmlenc")]
    fn unwrap_key(
        &self,
        algorithm: xml_sec::xmlenc::KeyWrapAlgorithm,
        kek: &[u8],
        wrapped: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        RustCryptoProvider.unwrap_key(algorithm, kek, wrapped)
    }
    #[cfg(feature = "xmlenc")]
    fn transport_key(
        &self,
        key: &dyn xml_sec::provider::KeyTransportKey,
        parameters: &xml_sec::xmlenc::RsaOaepParameters,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        RustCryptoProvider.transport_key(key, parameters, plaintext)
    }
    #[cfg(feature = "xmlenc")]
    fn recover_key(
        &self,
        key: &dyn xml_sec::provider::KeyRecoveryKey,
        parameters: &xml_sec::xmlenc::RsaOaepParameters,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        RustCryptoProvider.recover_key(key, parameters, ciphertext)
    }
}
