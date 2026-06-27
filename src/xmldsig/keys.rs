//! Configuration and key material for XMLDSig key resolution.

use std::{collections::HashMap, time::SystemTime};

use super::SignatureAlgorithm;

/// A public verification key available to key resolvers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationKey {
    /// Signature algorithm this key is configured to verify.
    pub algorithm: SignatureAlgorithm,
    /// DER-encoded SubjectPublicKeyInfo bytes.
    pub public_key_bytes: Vec<u8>,
    /// DER certificate from which the key was extracted, when applicable.
    pub certificate_der: Option<Vec<u8>>,
    /// Name used to register this key for `<KeyName>` resolution.
    pub name: Option<String>,
}

/// Configuration for the default XMLDSig key resolver.
///
/// The configuration owns all key material and has no global registry. Chain
/// verification is opt-in so callers that pin an embedded certificate can use
/// the documented TOFU model without constructing a certificate path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyResolverConfig {
    /// DER-encoded certificates accepted as trust anchors.
    pub trusted_certs: Vec<Vec<u8>>,
    /// Verification keys addressable by `<KeyName>` content.
    pub named_keys: HashMap<String, VerificationKey>,
    /// Whether embedded X.509 certificate chains must terminate at a trust anchor.
    pub verify_chains: bool,
    /// Certificate verification time override; `None` selects the system clock.
    pub verification_time: Option<SystemTime>,
    /// Maximum certificates in a validated path, including the trust anchor.
    pub max_chain_depth: usize,
}

impl Default for KeyResolverConfig {
    fn default() -> Self {
        Self {
            trusted_certs: Vec::new(),
            named_keys: HashMap::new(),
            verify_chains: false,
            verification_time: None,
            max_chain_depth: 9,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_key_resolution_policy() {
        // Defaults must remain compatible with xmlsec1's depth and opt-in trust policy.
        let config = KeyResolverConfig::default();

        assert!(config.trusted_certs.is_empty());
        assert!(config.named_keys.is_empty());
        assert!(!config.verify_chains);
        assert_eq!(config.verification_time, None);
        assert_eq!(config.max_chain_depth, 9);
    }

    #[test]
    fn stores_named_verification_key_metadata() {
        // Named resolution must retain every field needed by the later resolver wiring.
        let key = VerificationKey {
            algorithm: SignatureAlgorithm::RsaSha256,
            public_key_bytes: vec![1, 2, 3],
            certificate_der: Some(vec![4, 5, 6]),
            name: Some("idp-signing".into()),
        };
        let mut config = KeyResolverConfig::default();
        config.named_keys.insert("idp-signing".into(), key.clone());

        assert_eq!(config.named_keys.get("idp-signing"), Some(&key));
    }
}
