//! Provider-neutral KEM contract. XML orchestration and deployment permission
//! live outside the primitive; no key handle exposes its secret through Debug.

use super::{CryptoProvider, ProviderBinding, ProviderError};
use zeroize::Zeroizing;

/// Experimental libxmlsec1 ML-KEM parameter sets (not signature algorithms).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyEncapsulationAlgorithm {
    /// FIPS 203 category 1.
    MlKem512,
    /// FIPS 203 category 3.
    MlKem768,
    /// FIPS 203 category 5.
    MlKem1024,
}

impl KeyEncapsulationAlgorithm {
    /// Exact libxmlsec1 experimental wire identifier, not a W3C algorithm URI.
    pub const fn uri(self) -> &'static str {
        match self {
            Self::MlKem512 => "http://www.aleksey.com/xmlsec/2025/12/xmldsig-more#ml-kem-512",
            Self::MlKem768 => "http://www.aleksey.com/xmlsec/2025/12/xmldsig-more#ml-kem-768",
            Self::MlKem1024 => "http://www.aleksey.com/xmlsec/2025/12/xmldsig-more#ml-kem-1024",
        }
    }

    /// Recognize only the exact parameter-set URI.
    pub fn from_uri(uri: &str) -> Option<Self> {
        [Self::MlKem512, Self::MlKem768, Self::MlKem1024]
            .into_iter()
            .find(|algorithm| algorithm.uri() == uri)
    }

    /// Raw encapsulation-key length, RFC 9935 Appendix B.
    pub const fn public_key_len(self) -> usize {
        match self {
            Self::MlKem512 => 800,
            Self::MlKem768 => 1184,
            Self::MlKem1024 => 1568,
        }
    }

    /// Expanded private-key length, RFC 9935 Appendix B.
    pub const fn expanded_key_len(self) -> usize {
        match self {
            Self::MlKem512 => 1632,
            Self::MlKem768 => 2400,
            Self::MlKem1024 => 3168,
        }
    }

    /// Fixed ciphertext length, RFC 9935 Appendix B.
    pub const fn ciphertext_len(self) -> usize {
        match self {
            Self::MlKem512 => 768,
            Self::MlKem768 => 1088,
            Self::MlKem1024 => 1568,
        }
    }

    /// RFC 9935 section 3 AlgorithmIdentifier OID.
    pub const fn oid(self) -> pkcs8::ObjectIdentifier {
        match self {
            Self::MlKem512 => pkcs8::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.1"),
            Self::MlKem768 => pkcs8::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.2"),
            Self::MlKem1024 => pkcs8::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.3"),
        }
    }

    /// Recognize the RFC 9935 parameter-set OID independently of capability.
    pub fn from_oid(oid: pkcs8::ObjectIdentifier) -> Option<Self> {
        [Self::MlKem512, Self::MlKem768, Self::MlKem1024]
            .into_iter()
            .find(|algorithm| algorithm.oid() == oid)
    }
}

/// One encapsulation result. The secret is always exactly 32 bytes and erased on drop.
pub struct EncapsulatedKey {
    /// Public ciphertext to serialize into EncapsulationMechanism.
    pub ciphertext: Vec<u8>,
    /// Shared secret; callers retain its erasing owner through the consuming operation.
    pub shared_secret: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for EncapsulatedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncapsulatedKey")
            .field("ciphertext_len", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
}

/// Opaque recipient public key. The selected provider supplies randomness.
pub trait KeyEncapsulationKey: Send + Sync {
    /// Parameter set of this actual key, not a caller-provided hint.
    fn algorithm(&self) -> KeyEncapsulationAlgorithm;
    /// Engine ownership, when an external engine owns this handle.
    fn provider_binding(&self) -> Option<&ProviderBinding> {
        None
    }
    /// Primitive invoked only by its owning CryptoProvider after operation gates.
    fn encapsulate_with_provider(
        &self,
        provider: &dyn CryptoProvider,
    ) -> Result<EncapsulatedKey, ProviderError>;
}

/// Opaque recipient private key. Valid-size ciphertext rejection stays implicit.
pub trait KeyDecapsulationKey: Send + Sync {
    /// Parameter set of this actual key.
    fn algorithm(&self) -> KeyEncapsulationAlgorithm;
    /// Engine ownership, when an external engine owns this handle.
    fn provider_binding(&self) -> Option<&ProviderBinding> {
        None
    }
    /// FIPS 203 section 7.3: return the real-or-rejection secret without validity metadata.
    fn decapsulate(&self, ciphertext: &[u8]) -> Result<Zeroizing<[u8; 32]>, ProviderError>;
}

#[cfg(feature = "experimental-pq")]
mod rustcrypto;
#[cfg(feature = "experimental-pq")]
pub use rustcrypto::{
    MlKemPrivateKeyEncoding, RustCryptoMlKemPrivateKey, RustCryptoMlKemPublicKey,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{ExternalProviderError, ProviderCapability, RustCryptoProvider};

    struct ForeignKey(ProviderBinding);
    impl KeyEncapsulationKey for ForeignKey {
        fn algorithm(&self) -> KeyEncapsulationAlgorithm {
            KeyEncapsulationAlgorithm::MlKem768
        }
        fn provider_binding(&self) -> Option<&ProviderBinding> {
            Some(&self.0)
        }
        fn encapsulate_with_provider(
            &self,
            _: &dyn CryptoProvider,
        ) -> Result<EncapsulatedKey, ProviderError> {
            panic!("foreign key must not execute")
        }
    }
    impl KeyDecapsulationKey for ForeignKey {
        fn algorithm(&self) -> KeyEncapsulationAlgorithm {
            KeyEncapsulationAlgorithm::MlKem768
        }
        fn provider_binding(&self) -> Option<&ProviderBinding> {
            Some(&self.0)
        }
        fn decapsulate(&self, _: &[u8]) -> Result<Zeroizing<[u8; 32]>, ProviderError> {
            panic!("foreign key must not execute")
        }
    }

    #[test]
    fn capability_and_binding_gate_both_callbacks() {
        // Compiled capability is exact; an unavailable engine or foreign handle
        // must fail before either callback, including for a valid-size ciphertext.
        let algorithm = KeyEncapsulationAlgorithm::MlKem768;
        assert_eq!(
            RustCryptoProvider.supports(ProviderCapability::Encapsulate(algorithm)),
            cfg!(feature = "experimental-pq")
        );
        assert_eq!(
            RustCryptoProvider.supports(ProviderCapability::Decapsulate(algorithm)),
            cfg!(feature = "experimental-pq")
        );
        let key = ForeignKey(ProviderBinding::default());
        let encapsulation = RustCryptoProvider
            .encapsulate_key(&key)
            .expect_err("foreign key");
        let decapsulation = RustCryptoProvider
            .decapsulate_key(&key, &vec![0; algorithm.ciphertext_len()])
            .expect_err("foreign key");
        if cfg!(feature = "experimental-pq") {
            assert_eq!(
                encapsulation,
                ProviderError::External(ExternalProviderError::Binding)
            );
            assert_eq!(
                decapsulation,
                ProviderError::External(ExternalProviderError::Binding)
            );
        } else {
            assert!(matches!(encapsulation, ProviderError::Unsupported { .. }));
            assert!(matches!(decapsulation, ProviderError::Unsupported { .. }));
        }
    }

    #[test]
    fn parameter_identity_is_exact() {
        // Prevent URI normalization or parameter-set aliasing at the security boundary.
        for algorithm in [
            KeyEncapsulationAlgorithm::MlKem512,
            KeyEncapsulationAlgorithm::MlKem768,
            KeyEncapsulationAlgorithm::MlKem1024,
        ] {
            assert_eq!(
                KeyEncapsulationAlgorithm::from_uri(algorithm.uri()),
                Some(algorithm)
            );
            assert_eq!(
                KeyEncapsulationAlgorithm::from_uri(&format!("{} ", algorithm.uri())),
                None
            );
            assert_ne!(
                algorithm.oid(),
                pkcs8::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.1")
            );
        }
    }
}
