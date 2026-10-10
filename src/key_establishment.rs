//! Shared operation-wide key establishment accounting and KEM dispatch.
//!
//! Requests supply keys; the immutable policy supplies permission. Keep one
//! usage value across every key source and retry, including failed attempts.

use crate::policy::{KeyEstablishmentPolicy, PolicyViolation};
use crate::provider::{
    CryptoProvider, EncapsulatedKey, KeyDecapsulationKey, KeyEncapsulationAlgorithm,
    KeyEncapsulationKey, ProviderCapability, ProviderError, ProviderInputError,
};
use zeroize::Zeroizing;

/// Failures at the shared policy/provider boundary.
#[derive(Debug, thiserror::Error)]
pub enum KeyEstablishmentError {
    /// Experimental XML grammar or consuming key width is invalid.
    #[error("invalid EncapsulationMechanism: {0}")]
    Structure(&'static str),
    /// Deployment permission or operation allowance was denied.
    #[error(transparent)]
    Policy(#[from] PolicyViolation),
    /// Selected engine rejected the operation. No other engine is tried.
    #[error(transparent)]
    Provider(#[from] ProviderError),
}

/// libxmlsec1's experimental namespace, distinct from the W3C namespaces.
pub const ENCAPSULATION_NS: &str = "http://www.aleksey.com/xmlsec/2025/12/xmldsig-more#";

/// Owned experimental mechanism retained by parsed XML Encryption input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncapsulationMechanism {
    /// Exact parameter set, not deployment permission.
    pub algorithm: KeyEncapsulationAlgorithm,
    /// Recipient hints; trusted private keys remain request-owned.
    pub key_info: crate::xmldsig::KeyInfo,
    /// Public KEM ciphertext with the parameter set's exact fixed width.
    pub ciphertext: Vec<u8>,
}

/// Borrowed, fully framed mechanism. Public ciphertext is decoded into fixed
/// storage, so parsing cannot allocate an attacker-selected temporary buffer.
pub struct ParsedEncapsulation<'a, 'input> {
    /// Exact parameter set decoded from the mechanism.
    pub algorithm: KeyEncapsulationAlgorithm,
    /// Borrowed recipient hints, never a trust grant.
    pub key_info: crate::Node<'a, 'input>,
    /// Original ciphertext element for controlled template mutation.
    pub cipher_value: crate::Node<'a, 'input>,
    ciphertext: [u8; 1568],
    ciphertext_len: usize,
}

impl ParsedEncapsulation<'_, '_> {
    /// Fixed-width public ciphertext; empty only for a validated template.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext[..self.ciphertext_len]
    }

    #[cfg(feature = "xmldsig")]
    pub(crate) fn into_ciphertext(self) -> [u8; 1568] {
        self.ciphertext
    }
}

/// Validate the experimental ordered grammar and decode into fixed storage.
pub fn parse_encapsulation<'a, 'input>(
    node: crate::Node<'a, 'input>,
    template: bool,
) -> Result<ParsedEncapsulation<'a, 'input>, KeyEstablishmentError> {
    use base64::Engine as _;
    let invalid = KeyEstablishmentError::Structure;
    if !node.has_tag_name((ENCAPSULATION_NS, "EncapsulationMechanism")) {
        return Err(invalid("wrong element name or namespace"));
    }
    let algorithm = node
        .attribute("Algorithm")
        .and_then(KeyEncapsulationAlgorithm::from_uri)
        .ok_or(invalid("unsupported or missing Algorithm"))?;
    // This is the experimental donor contract, not a W3C schema requirement:
    // xmlsec 1.3.13 src/transform_helpers.c, xmlSecTransformKEMRead.
    // https://github.com/lsh123/xmlsec/blob/xmlsec-1_3_13/src/transform_helpers.c
    let mut children = node.children().filter(crate::Node::is_element);
    let key_info = children
        .next()
        .filter(|n| n.has_tag_name((crate::xmldsig::parse::XMLDSIG_NS, "KeyInfo")))
        .ok_or(invalid("expected KeyInfo first"))?;
    let data = children
        .next()
        .filter(|n| n.has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "CipherData")))
        .ok_or(invalid("expected CipherData after KeyInfo"))?;
    if children.next().is_some() {
        return Err(invalid("unexpected mechanism child"));
    }
    let mut children = data.children().filter(crate::Node::is_element);
    let cipher_value = children
        .next()
        .filter(|n| n.has_tag_name(("http://www.w3.org/2001/04/xmlenc#", "CipherValue")))
        .ok_or(invalid("expected CipherValue"))?;
    if children.next().is_some() || cipher_value.children().any(|n| n.is_element()) {
        return Err(invalid("unexpected CipherData or CipherValue child"));
    }
    for parent in [node, data] {
        if parent.children().filter(crate::Node::is_text).any(|n| {
            n.text()
                .is_some_and(|s| !s.bytes().all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n')))
        }) {
            return Err(invalid("non-whitespace mixed content"));
        }
    }
    let mut encoded = [0u8; 2092];
    let mut len = 0;
    for text in cipher_value.children().filter(crate::Node::is_text) {
        for byte in text.text().unwrap_or_default().bytes() {
            if matches!(byte, b' ' | b'\t' | b'\r' | b'\n') {
                continue;
            }
            if len == encoded.len() {
                return Err(invalid("oversized ciphertext"));
            }
            encoded[len] = byte;
            len += 1;
        }
    }
    let mut ciphertext = [0u8; 1568];
    // GeneralPurpose checks actual output bytes, including terminal padding,
    // not decoded_len_estimate (1569 for a padded 1568-byte ciphertext).
    // Decode directly into retained storage; no staging copy is necessary.
    // https://docs.rs/base64/0.23.1/src/base64/engine/general_purpose/decode_suffix.rs.html
    let ciphertext_len = base64::engine::general_purpose::STANDARD
        .decode_slice(&encoded[..len], &mut ciphertext)
        .map_err(|_| invalid("invalid ciphertext base64"))?;
    if ciphertext_len != algorithm.ciphertext_len() && !(template && ciphertext_len == 0) {
        return Err(invalid("ciphertext size does not match Algorithm"));
    }
    Ok(ParsedEncapsulation {
        algorithm,
        key_info,
        cipher_value,
        ciphertext,
        ciphertext_len,
    })
}

/// Find a single direct mechanism, rejecting ambiguity rather than choosing one.
pub fn direct_encapsulation<'a, 'input>(
    key_info: crate::Node<'a, 'input>,
    template: bool,
) -> Result<Option<ParsedEncapsulation<'a, 'input>>, KeyEstablishmentError> {
    let mut mechanisms = key_info
        .children()
        .filter(|n| n.has_tag_name((ENCAPSULATION_NS, "EncapsulationMechanism")));
    let Some(node) = mechanisms.next() else {
        return Ok(None);
    };
    if mechanisms.next().is_some() {
        return Err(KeyEstablishmentError::Structure(
            "multiple mechanisms in one KeyInfo",
        ));
    }
    parse_encapsulation(node, template).map(Some)
}

/// Monotonic reservations shared by KDF, agreement, and encapsulation.
#[derive(Debug, Default)]
pub struct KeyEstablishmentUsage {
    pub(crate) hash_blocks: usize,
    pub(crate) owned_bytes: usize,
    pub(crate) modular_work: usize,
    encapsulation_operations: usize,
}

impl KeyEstablishmentUsage {
    /// Generate a fresh secret after permission, capability and resource gates.
    pub fn encapsulate(
        &mut self,
        policy: &KeyEstablishmentPolicy,
        provider: &dyn CryptoProvider,
        key: &dyn KeyEncapsulationKey,
    ) -> Result<EncapsulatedKey, KeyEstablishmentError> {
        let algorithm = key.algorithm();
        policy.validate()?;
        policy.check_encapsulation(algorithm)?;
        provider.require_capability(ProviderCapability::Encapsulate(algorithm))?;
        provider.require_capability(ProviderCapability::Random)?;
        self.reserve_encapsulation(policy, algorithm.ciphertext_len())?;
        let result = provider.encapsulate_key(key)?;
        if result.ciphertext.len() != algorithm.ciphertext_len() {
            return Err(ProviderError::InvalidInput(ProviderInputError::MlKemCiphertext).into());
        }
        Ok(result)
    }

    /// Recover the real-or-rejection secret; never expose ciphertext validity.
    pub fn decapsulate(
        &mut self,
        policy: &KeyEstablishmentPolicy,
        provider: &dyn CryptoProvider,
        key: &dyn KeyDecapsulationKey,
        algorithm: KeyEncapsulationAlgorithm,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, KeyEstablishmentError> {
        policy.validate()?;
        policy.check_encapsulation(algorithm)?;
        if key.algorithm() != algorithm || ciphertext.len() != algorithm.ciphertext_len() {
            return Err(ProviderError::InvalidInput(ProviderInputError::MlKemCiphertext).into());
        }
        provider.require_capability(ProviderCapability::Decapsulate(algorithm))?;
        self.reserve_encapsulation(policy, 0)?;
        Ok(provider.decapsulate_key(key, ciphertext)?)
    }

    fn reserve_encapsulation(
        &mut self,
        policy: &KeyEstablishmentPolicy,
        output_bytes: usize,
    ) -> Result<(), PolicyViolation> {
        let operations = reserve(
            "key encapsulation operations",
            self.encapsulation_operations,
            1,
            policy.max_encapsulation_operations,
        )?;
        // RustCrypto ml-kem 0.3.2 operates on fixed arrays when using already
        // imported handles: pke.rs encrypt/decrypt and encapsulation_key.rs
        // encapsulate_deterministic allocate no heap workspace. The adapter's
        // ciphertext Vec is the only primitive-owned allocation; consumers
        // reserve their secret copies separately. Do not invent a workspace
        // multiplier from encoded key size.
        self.commit_all(policy, 0, 0, output_bytes as u128)?;
        self.encapsulation_operations = operations;
        Ok(())
    }

    pub(crate) fn commit_all(
        &mut self,
        policy: &KeyEstablishmentPolicy,
        blocks: u128,
        modular: u128,
        allocations: u128,
    ) -> Result<(), PolicyViolation> {
        let work = reserve(
            crate::policy::resource_name::KEY_ESTABLISHMENT_HASH_BLOCKS,
            self.hash_blocks,
            blocks,
            policy.max_hash_blocks,
        )?;
        let bytes = reserve(
            crate::policy::resource_name::KEY_ESTABLISHMENT_OWNED_BYTES,
            self.owned_bytes,
            allocations,
            policy.max_owned_bytes,
        )?;
        let modular = reserve(
            crate::policy::resource_name::KEY_ESTABLISHMENT_MODULAR_WORK,
            self.modular_work,
            modular,
            policy.max_modular_work,
        )?;
        self.hash_blocks = work;
        self.owned_bytes = bytes;
        self.modular_work = modular;
        Ok(())
    }
}

pub(crate) fn reserve(
    resource: &'static str,
    used: usize,
    count: u128,
    maximum: usize,
) -> Result<usize, PolicyViolation> {
    if used > maximum || count > (maximum - used) as u128 {
        return Err(PolicyViolation::ResourceLimit {
            resource,
            maximum,
            actual: usize::try_from(used as u128 + count).unwrap_or(usize::MAX),
        });
    }
    Ok(used + count as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::RustCryptoProvider;

    #[cfg(feature = "experimental-pq")]
    struct FailedRandom;

    #[cfg(feature = "experimental-pq")]
    impl CryptoProvider for FailedRandom {
        fn name(&self) -> &'static str {
            "failed-random"
        }
        fn supports(&self, capability: ProviderCapability<'_>) -> bool {
            RustCryptoProvider.supports(capability)
        }
        fn fill_random(&self, _: &mut [u8]) -> Result<(), ProviderError> {
            Err(ProviderError::Random("test entropy failure".into()))
        }
        fn encapsulate_key(
            &self,
            key: &dyn KeyEncapsulationKey,
        ) -> Result<EncapsulatedKey, ProviderError> {
            key.encapsulate_with_provider(self)
        }
        fn digest(
            &self,
            _: crate::xmldsig::DigestAlgorithm,
            _: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            unreachable!("no digest after failed entropy")
        }
        fn sign(
            &self,
            _: &dyn crate::xmldsig::SigningKey,
            _: crate::xmldsig::SignatureAlgorithm,
            _: &[u8],
        ) -> Result<Vec<u8>, crate::xmldsig::SigningKeyError> {
            unreachable!("no signing after failed entropy")
        }
        fn verify(
            &self,
            _: &dyn crate::xmldsig::VerifyingKey,
            _: crate::xmldsig::SignatureAlgorithm,
            _: &[u8],
            _: &[u8],
        ) -> Result<bool, crate::xmldsig::DsigError> {
            unreachable!("no verification in encapsulation")
        }
        fn derive_key(
            &self,
            _: &crate::provider::KdfParameters<'_>,
            _: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            unreachable!("KEM does not use a KDF")
        }
        #[cfg(feature = "xmlenc")]
        fn encrypt_data(
            &self,
            _: crate::xmlenc::DataEncryptionAlgorithm,
            _: &[u8],
            _: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            unreachable!("no encryption after failed entropy")
        }
        #[cfg(feature = "xmlenc")]
        fn decrypt_data(
            &self,
            _: crate::xmlenc::DataEncryptionAlgorithm,
            _: &[u8],
            _: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            unreachable!("no decryption in encapsulation")
        }
        #[cfg(feature = "xmlenc")]
        fn wrap_key(
            &self,
            _: crate::xmlenc::KeyWrapAlgorithm,
            _: &[u8],
            _: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            unreachable!("no wrapping after failed entropy")
        }
        #[cfg(feature = "xmlenc")]
        fn unwrap_key(
            &self,
            _: crate::xmlenc::KeyWrapAlgorithm,
            _: &[u8],
            _: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            unreachable!("no unwrapping in encapsulation")
        }
        #[cfg(feature = "xmlenc")]
        fn transport_key(
            &self,
            _: &dyn crate::provider::KeyTransportKey,
            _: &crate::xmlenc::RsaOaepParameters,
            _: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            unreachable!("no RSA in encapsulation")
        }
        #[cfg(feature = "xmlenc")]
        fn recover_key(
            &self,
            _: &dyn crate::provider::KeyRecoveryKey,
            _: &crate::xmlenc::RsaOaepParameters,
            _: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            unreachable!("no RSA in encapsulation")
        }
    }

    #[cfg(feature = "experimental-pq")]
    #[test]
    fn entropy_failure_is_terminal_and_charged() {
        // Actual RustCrypto key execution must use this provider's RNG, and
        // failure must not release the reservation or fall back to OS entropy.
        let algorithm = KeyEncapsulationAlgorithm::MlKem512;
        let key = crate::provider::RustCryptoMlKemPrivateKey::from_seed(algorithm, &[1; 64])
            .expect("deterministic test recipient")
            .public_key();
        let policy = KeyEstablishmentPolicy {
            encapsulation_algorithms: [algorithm].into(),
            max_encapsulation_operations: 1,
            ..KeyEstablishmentPolicy::default()
        };
        let mut usage = KeyEstablishmentUsage::default();
        assert!(matches!(
            usage.encapsulate(&policy, &FailedRandom, &key),
            Err(KeyEstablishmentError::Provider(ProviderError::Random(_)))
        ));
        assert_eq!(usage.encapsulation_operations, 1);
        assert!(matches!(
            usage.encapsulate(&policy, &RustCryptoProvider, &key),
            Err(KeyEstablishmentError::Policy(
                PolicyViolation::ResourceLimit { .. }
            ))
        ));
        assert!(
            crate::provider::RustCryptoMlKemPrivateKey::generate(&FailedRandom, algorithm).is_err()
        );
    }

    #[test]
    fn maximum_ciphertext_decodes_without_estimate_workspace() {
        use base64::Engine as _;
        // The final padded quad needs two bytes, not the three in the
        // conservative length estimate. Exact-capacity decoding must remain
        // valid; a 1569-byte ciphertext with the same encoded length must fail.
        let mechanism = |bytes: &[u8]| {
            format!(
                "<e:EncapsulationMechanism xmlns:e=\"{ENCAPSULATION_NS}\" xmlns:d=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:x=\"http://www.w3.org/2001/04/xmlenc#\" Algorithm=\"{}\"><d:KeyInfo/><x:CipherData><x:CipherValue>{}</x:CipherValue></x:CipherData></e:EncapsulationMechanism>",
                KeyEncapsulationAlgorithm::MlKem1024.uri(),
                base64::engine::general_purpose::STANDARD.encode(bytes)
            )
        };
        let bytes = [7; 1568];
        let xml = mechanism(&bytes);
        let document = crate::Document::parse(&xml).expect("maximum ciphertext XML");
        let parsed = parse_encapsulation(document.root_element(), false).expect("exact capacity");
        assert_eq!(parsed.ciphertext(), bytes);
        let spaced = xml.replace("BwcH", "Bw\n cH");
        let document = crate::Document::parse(&spaced).expect("whitespace ciphertext XML");
        assert_eq!(
            parse_encapsulation(document.root_element(), false)
                .expect("whitespace does not consume ciphertext capacity")
                .ciphertext(),
            bytes
        );
        let oversized = mechanism(&[7; 1569]);
        let document = crate::Document::parse(&oversized).expect("oversized ciphertext XML");
        assert!(parse_encapsulation(document.root_element(), false).is_err());
    }

    #[test]
    fn mechanism_grammar_rejects_ambiguous_and_malformed_input() {
        // The extension requires exactly ordered KeyInfo/CipherData; a
        // template may omit ciphertext, but a decryption input may not.
        let valid = format!(
            "<e:EncapsulationMechanism xmlns:e=\"{ENCAPSULATION_NS}\" xmlns:d=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:x=\"http://www.w3.org/2001/04/xmlenc#\" Algorithm=\"{}\"><d:KeyInfo/><x:CipherData><x:CipherValue/></x:CipherData></e:EncapsulationMechanism>",
            KeyEncapsulationAlgorithm::MlKem512.uri()
        );
        let document = crate::Document::parse(&valid).expect("template XML");
        assert!(parse_encapsulation(document.root_element(), true).is_ok());
        assert!(parse_encapsulation(document.root_element(), false).is_err());
        for invalid in [
            valid.replace("<d:KeyInfo/>", "<d:KeyInfo/><d:KeyInfo/>"),
            valid.replace("<d:KeyInfo/>", "unexpected<d:KeyInfo/>"),
            valid.replace(
                "<x:CipherValue/>",
                "<x:CipherValue><d:KeyInfo/></x:CipherValue>",
            ),
            valid.replace("<x:CipherValue/>", "<x:CipherValue>AA==</x:CipherValue>"),
            valid.replace("<x:CipherValue/>", "<x:CipherValue>!</x:CipherValue>"),
            valid.replace("#ml-kem-512", "#ml-kem-512 "),
        ] {
            let document = crate::Document::parse(&invalid).expect("well-formed invalid mechanism");
            assert!(parse_encapsulation(document.root_element(), true).is_err());
        }
    }

    struct NeverCalled;
    impl KeyDecapsulationKey for NeverCalled {
        fn algorithm(&self) -> KeyEncapsulationAlgorithm {
            KeyEncapsulationAlgorithm::MlKem768
        }
        fn decapsulate(&self, _: &[u8]) -> Result<Zeroizing<[u8; 32]>, ProviderError> {
            panic!("preflight must reject before private key work")
        }
    }

    #[test]
    fn permission_and_framing_precede_private_key_work() {
        // Compiled capability cannot enable an experimental algorithm by itself.
        let algorithm = KeyEncapsulationAlgorithm::MlKem768;
        let mut usage = KeyEstablishmentUsage::default();
        let mut policy = KeyEstablishmentPolicy::default();
        assert!(matches!(
            usage.decapsulate(&policy, &RustCryptoProvider, &NeverCalled, algorithm, &[]),
            Err(KeyEstablishmentError::Policy(
                PolicyViolation::Algorithm { .. }
            ))
        ));
        policy.encapsulation_algorithms.insert(algorithm);
        assert!(matches!(
            usage.decapsulate(&policy, &RustCryptoProvider, &NeverCalled, algorithm, &[]),
            Err(KeyEstablishmentError::Provider(
                ProviderError::InvalidInput(_)
            ))
        ));
    }

    #[test]
    fn failed_attempts_cannot_reset_shared_allowance() {
        // KEM and KDF reservations consume the same bytes; failed reservation
        // leaves all counters unchanged, while completed reservations persist.
        let mut usage = KeyEstablishmentUsage::default();
        let mut policy = KeyEstablishmentPolicy {
            max_encapsulation_operations: 1,
            ..KeyEstablishmentPolicy::default()
        };
        usage
            .reserve_encapsulation(&policy, 768)
            .expect("first attempt fits");
        let bytes = usage.owned_bytes;
        assert!(usage.reserve_encapsulation(&policy, 768).is_err());
        assert_eq!(usage.owned_bytes, bytes);
        policy.max_owned_bytes = bytes;
        assert!(usage.commit_all(&policy, 0, 0, 1).is_err());
        assert_eq!(usage.owned_bytes, bytes);
    }
}
