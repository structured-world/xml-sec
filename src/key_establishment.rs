//! Shared operation-wide key establishment accounting and KEM dispatch.
//!
//! Requests supply keys; the immutable policy supplies permission. Keep one
//! usage value across every key source and retry, including failed attempts.

use alloc::vec::Vec;

use crate::policy::{KeyEstablishmentPolicy, PolicyViolation};
use crate::provider::{
    CryptoProvider, EncapsulatedKey, KeyDecapsulationKey, KeyEncapsulationAlgorithm,
    KeyEncapsulationKey, ProviderCapability, ProviderError, ProviderInputError,
};
use zeroize::Zeroizing;

/// Failures at the shared policy/provider boundary.
#[derive(Debug, thiserror::Error)]
pub enum KeyEstablishmentError {
    /// ML-KEM `EncryptedKey` grammar or consuming key width is invalid.
    #[error("invalid ML-KEM EncryptedKey: {0}")]
    Structure(&'static str),
    /// Deployment permission or operation allowance was denied.
    #[error(transparent)]
    Policy(#[from] PolicyViolation),
    /// Selected engine rejected the operation. No other engine is tried.
    #[error(transparent)]
    Provider(#[from] ProviderError),
}

const XMLENC_NS: &str = "http://www.w3.org/2001/04/xmlenc#";

/// ML-KEM key transport retained by parsed input: an `EncryptedKey` whose
/// `EncryptionMethod` names an ML-KEM parameter set and whose `CipherValue`
/// holds the FIPS 203 ciphertext (draft-eastlake-rfc9231bis-xmlsec-uris-09
/// section 3.6.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncapsulationMechanism {
    /// Exact parameter set, not deployment permission.
    pub algorithm: KeyEncapsulationAlgorithm,
    /// Recipient hints; trusted private keys remain request-owned.
    pub key_info: crate::xmldsig::KeyInfo,
    /// Public KEM ciphertext with the parameter set's exact fixed width.
    pub ciphertext: Vec<u8>,
}

/// The ML-KEM `EncryptedKey` a caller already established its HMAC key from,
/// named by parameter set and ciphertext: an operation takes that key only
/// when the signature's `KeyInfo` carries exactly this mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EstablishedEncapsulation<'a> {
    /// Exact parameter set.
    pub algorithm: KeyEncapsulationAlgorithm,
    /// The FIPS 203 ciphertext the key was encapsulated with.
    pub ciphertext: &'a [u8],
}

/// The ciphertext of an encapsulation a caller keeps to serialize later, with
/// the recipient it was encapsulated to. The shared secret is that recipient's
/// alone, so the ciphertext keys content for no other recipient: a second
/// recipient of the same content cannot recover a key from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeptEncapsulation<'a> {
    /// Exact parameter set the ciphertext was produced under.
    pub algorithm: KeyEncapsulationAlgorithm,
    /// The FIPS 203 ciphertext.
    pub ciphertext: &'a [u8],
    /// DER `SubjectPublicKeyInfo` of the recipient (RFC 9935 section 4).
    pub recipient: &'a [u8],
}

impl<'a> KeptEncapsulation<'a> {
    /// The ciphertext to write into the `EncryptedKey` of `recipient` (its DER
    /// `SubjectPublicKeyInfo`) under `algorithm`, whole.
    ///
    /// # Errors
    /// Returns a structure error when the ciphertext does not have the
    /// parameter set's width, or when `algorithm` or `recipient` is not the
    /// one the ciphertext was encapsulated for.
    pub fn ciphertext_for(
        &self,
        algorithm: KeyEncapsulationAlgorithm,
        recipient: &[u8],
    ) -> Result<&'a [u8], KeyEstablishmentError> {
        if self.ciphertext.len() != self.algorithm.ciphertext_len() {
            return Err(KeyEstablishmentError::Structure(
                "kept ciphertext size does not match its parameter set",
            ));
        }
        if algorithm != self.algorithm || recipient != self.recipient {
            return Err(KeyEstablishmentError::Structure(
                "an ML-KEM secret keys content for its own recipient only",
            ));
        }
        Ok(self.ciphertext)
    }
}

/// Borrowed, fully framed mechanism. Public ciphertext is decoded into fixed
/// storage, so parsing cannot allocate an attacker-selected temporary buffer.
pub struct ParsedEncapsulation<'a, 'input> {
    /// Exact parameter set decoded from the mechanism.
    pub algorithm: KeyEncapsulationAlgorithm,
    /// Borrowed recipient hints, never a trust grant; `EncryptedKey` makes
    /// its `KeyInfo` optional.
    pub key_info: Option<crate::Node<'a, 'input>>,
    /// Original ciphertext element for controlled template mutation.
    pub cipher_value: crate::Node<'a, 'input>,
    ciphertext: [u8; 1568],
    ciphertext_len: usize,
}

impl ParsedEncapsulation<'_, '_> {
    /// Fixed-width public ciphertext; empty only for a validated template.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext[..self.ciphertext_len]
    }

    #[cfg(feature = "xmldsig")]
    pub(crate) fn into_ciphertext(self) -> [u8; 1568] {
        self.ciphertext
    }
}

/// The ML-KEM parameter set `node` transports a key with: `node` is an
/// `EncryptedKey` whose first element child is an `EncryptionMethod` naming
/// one. Any other element, including an RSA or key-wrap `EncryptedKey`, is not.
#[must_use]
pub fn encapsulation_algorithm(node: crate::Node<'_, '_>) -> Option<KeyEncapsulationAlgorithm> {
    if !node.has_tag_name((XMLENC_NS, "EncryptedKey")) {
        return None;
    }
    node.children()
        .find(crate::Node::is_element)
        .filter(|method| method.has_tag_name((XMLENC_NS, "EncryptionMethod")))
        .and_then(|method| method.attribute("Algorithm"))
        .and_then(KeyEncapsulationAlgorithm::from_uri)
}

/// Validate an ML-KEM `EncryptedKey` and decode its ciphertext into fixed
/// storage. XML Encryption 1.1 section 3.5.1 orders `EncryptionMethod`,
/// optional `ds:KeyInfo` and `CipherData`; the ML-KEM method takes no
/// parameters, and the `ReferenceList` and `CarriedKeyName` this transport
/// does not process are refused rather than ignored.
/// <https://www.w3.org/TR/xmlenc-core1/#sec-EncryptedKey>
///
/// # Errors
/// Returns a structure error for an unknown algorithm, malformed child order,
/// invalid Base64 or ciphertext width that does not match the parameter set.
pub fn parse_encapsulation<'a, 'input>(
    node: crate::Node<'a, 'input>,
    template: bool,
) -> Result<ParsedEncapsulation<'a, 'input>, KeyEstablishmentError> {
    let invalid = KeyEstablishmentError::Structure;
    let algorithm = encapsulation_algorithm(node)
        .ok_or(invalid("not an EncryptedKey with an ML-KEM method"))?;
    let mut children = node.children().filter(crate::Node::is_element).peekable();
    let method = children
        .next()
        .ok_or(invalid("expected EncryptionMethod"))?;
    if method.children().any(|n| n.is_element()) {
        return Err(invalid("ML-KEM EncryptionMethod takes no parameters"));
    }
    let key_info =
        children.next_if(|n| n.has_tag_name((crate::xmldsig::parse::XMLDSIG_NS, "KeyInfo")));
    let data = children
        .next()
        .filter(|n| n.has_tag_name((XMLENC_NS, "CipherData")))
        .ok_or(invalid(
            "expected CipherData after EncryptionMethod and KeyInfo",
        ))?;
    if children.next().is_some() {
        return Err(invalid("unexpected child after CipherData"));
    }
    let mut children = data.children().filter(crate::Node::is_element);
    let cipher_value = children
        .next()
        .filter(|n| n.has_tag_name((XMLENC_NS, "CipherValue")))
        .ok_or(invalid("expected CipherValue"))?;
    if children.next().is_some() || cipher_value.children().any(|n| n.is_element()) {
        return Err(invalid("unexpected CipherData or CipherValue child"));
    }
    for parent in [node, method, data] {
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
    // The profile needs room for the exact decoded length after padding, so
    // a padded 1568-byte ciphertext decodes directly into retained storage.
    let ciphertext_len = structured_base64::STANDARD
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
///
/// # Errors
/// Returns a structure error for multiple direct mechanisms or an invalid
/// mechanism; absence is reported separately as `Ok(None)`.
pub fn direct_encapsulation<'a, 'input>(
    key_info: crate::Node<'a, 'input>,
    template: bool,
) -> Result<Option<ParsedEncapsulation<'a, 'input>>, KeyEstablishmentError> {
    let mut mechanisms = key_info
        .children()
        .filter(|n| encapsulation_algorithm(*n).is_some());
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
///
/// A caller that runs one operation in parts carries the value from one part
/// to the next, so every part spends one allowance.
#[cfg_attr(
    feature = "xmlenc",
    doc = "",
    doc = "The XML Encryption budget resumes from it: [`crate::xmlenc::KeyEstablishmentBudget::resume`]."
)]
#[derive(Debug, Default, Clone, Copy)]
pub struct KeyEstablishmentUsage {
    pub(crate) hash_blocks: usize,
    pub(crate) owned_bytes: usize,
    pub(crate) modular_work: usize,
    encapsulation_operations: usize,
}

impl KeyEstablishmentUsage {
    /// Generate a fresh secret after permission, capability and resource gates.
    ///
    /// # Errors
    /// Returns policy or resource refusal before dispatch, or the selected
    /// provider's capability, entropy, encapsulation or output-framing failure.
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
    ///
    /// # Errors
    /// Returns policy or resource refusal, a key/algorithm/framing mismatch,
    /// or the selected provider's capability or decapsulation failure.
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

    /// Reserve `bytes` of owned storage a consumer allocates for a secret it
    /// keeps, such as its copy of a decapsulated secret, before allocating
    /// it: the primitives reserve only their own allocations.
    ///
    /// # Errors
    /// Returns an invalid policy or the owned-byte limit's refusal.
    pub fn reserve_owned_bytes(
        &mut self,
        policy: &KeyEstablishmentPolicy,
        bytes: usize,
    ) -> Result<(), KeyEstablishmentError> {
        policy.validate()?;
        Ok(self.commit_all(policy, 0, 0, bytes as u128)?)
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

    #[test]
    fn a_kept_ciphertext_serves_only_its_own_recipient() {
        // The secret is the encapsulation recipient's alone: the same
        // recipient and parameter set get the ciphertext whole, another
        // recipient or parameter set gets nothing, and a ciphertext of the
        // wrong width is refused for everyone.
        let ciphertext = [0x11_u8; 768];
        let kept = KeptEncapsulation {
            algorithm: KeyEncapsulationAlgorithm::MlKem512,
            ciphertext: &ciphertext,
            recipient: b"first",
        };
        assert_eq!(
            kept.ciphertext_for(KeyEncapsulationAlgorithm::MlKem512, b"first")
                .expect("its own recipient"),
            &ciphertext[..]
        );
        for (algorithm, recipient) in [
            (KeyEncapsulationAlgorithm::MlKem512, &b"second"[..]),
            (KeyEncapsulationAlgorithm::MlKem768, &b"first"[..]),
        ] {
            assert!(matches!(
                kept.ciphertext_for(algorithm, recipient),
                Err(KeyEstablishmentError::Structure(_))
            ));
        }
        let cut = KeptEncapsulation {
            ciphertext: &ciphertext[..767],
            ..kept
        };
        assert!(matches!(
            cut.ciphertext_for(KeyEncapsulationAlgorithm::MlKem512, b"first"),
            Err(KeyEstablishmentError::Structure(_))
        ));
    }

    #[cfg(feature = "experimental-pq")]
    struct FailedRandom;

    #[cfg(feature = "experimental-pq")]
    impl CryptoProvider for FailedRandom {
        fn name(&self) -> &'static str {
            "failed-random"
        }
        fn supports(&self, capability: ProviderCapability<'_>) -> bool {
            // Its own source, which fails, exists in every build.
            matches!(
                capability,
                ProviderCapability::Random | ProviderCapability::Encapsulate(_)
            ) || RustCryptoProvider.supports(capability)
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
        fn begin_digest(
            &self,
            _: crate::xmldsig::DigestAlgorithm,
            _: &structured_asn1::memory::Memory,
        ) -> Result<Box<dyn crate::provider::DigestState + '_>, ProviderError> {
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
            usage.encapsulate(&policy, &FailedRandom, &key),
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
        // The final padded quad needs two bytes, not the three in the
        // conservative length estimate. Exact-capacity decoding must remain
        // valid; a 1569-byte ciphertext with the same encoded length must fail.
        let mechanism = |bytes: &[u8]| {
            format!(
                "<x:EncryptedKey xmlns:d=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:x=\"{XMLENC_NS}\"><x:EncryptionMethod Algorithm=\"{}\"/><d:KeyInfo/><x:CipherData><x:CipherValue>{}</x:CipherValue></x:CipherData></x:EncryptedKey>",
                KeyEncapsulationAlgorithm::MlKem1024.uri(),
                crate::base64::encode(bytes)
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
        // XML Encryption orders EncryptionMethod, optional KeyInfo and
        // CipherData; a template may omit ciphertext, a decryption input may
        // not, and what the transport does not process is refused.
        let valid = format!(
            "<x:EncryptedKey xmlns:d=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:x=\"{XMLENC_NS}\" Id=\"EK\"><x:EncryptionMethod Algorithm=\"{}\"/><d:KeyInfo/><x:CipherData><x:CipherValue/></x:CipherData></x:EncryptedKey>",
            KeyEncapsulationAlgorithm::MlKem512.uri()
        );
        let document = crate::Document::parse(&valid).expect("template XML");
        assert!(parse_encapsulation(document.root_element(), true).is_ok());
        assert!(parse_encapsulation(document.root_element(), false).is_err());
        let without_key_info = valid.replace("<d:KeyInfo/>", "");
        let document = crate::Document::parse(&without_key_info).expect("template XML");
        let parsed = parse_encapsulation(document.root_element(), true).expect("KeyInfo optional");
        assert!(parsed.key_info.is_none());
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
            valid.replace(
                "</x:CipherData>",
                "</x:CipherData><x:CarriedKeyName>k</x:CarriedKeyName>",
            ),
            valid.replace(
                "</x:CipherData>",
                "</x:CipherData><x:ReferenceList><x:DataReference URI=\"#d\"/></x:ReferenceList>",
            ),
            valid.replace("\"/><d:KeyInfo/>", "\"><x:KeySize>256</x:KeySize></x:EncryptionMethod><d:KeyInfo/>"),
            valid.replace(
                &format!("<x:EncryptionMethod Algorithm=\"{}\"/>", KeyEncapsulationAlgorithm::MlKem512.uri()),
                "<x:EncryptionMethod Algorithm=\"http://www.aleksey.com/xmlsec/2025/12/xmldsig-more#ml-kem-512\"/>",
            ),
        ] {
            let document = crate::Document::parse(&invalid).expect("well-formed invalid mechanism");
            assert!(parse_encapsulation(document.root_element(), true).is_err(), "{invalid}");
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
