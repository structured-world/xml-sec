//! RustCrypto ML-KEM plus the complete RFC 9935 encoding boundary.

use super::*;
use crate::provider::{ProviderCapability, ProviderInputError};
use der::{
    AnyRef, Decode, Encode, Reader, Tag, TagMode, TagNumber, Tagged,
    asn1::{BitStringRef, ContextSpecific, OctetStringRef},
};
use ml_kem::{Decapsulate, KeyExport};
use subtle::ConstantTimeEq;

enum PrivateKey {
    K512(ml_kem::DecapsulationKey<ml_kem::MlKem512>),
    K768(ml_kem::DecapsulationKey<ml_kem::MlKem768>),
    K1024(ml_kem::DecapsulationKey<ml_kem::MlKem1024>),
}

enum PublicKey {
    K512(ml_kem::EncapsulationKey<ml_kem::MlKem512>),
    K768(ml_kem::EncapsulationKey<ml_kem::MlKem768>),
    K1024(ml_kem::EncapsulationKey<ml_kem::MlKem1024>),
}

/// RFC 9935 section 6 private-key encoding selected explicitly by the exporter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlKemPrivateKeyEncoding {
    /// Compact 64-byte seed; unavailable for an expanded-only imported key.
    Seed,
    /// Expanded decapsulation key.
    Expanded,
    /// Consistent seed and expanded key, unavailable when the seed is unknown.
    Combined,
}

/// RustCrypto recipient private key; secret components are erased by upstream Drop.
pub struct RustCryptoMlKemPrivateKey {
    algorithm: KeyEncapsulationAlgorithm,
    key: PrivateKey,
}
/// Validated RustCrypto recipient public key.
pub struct RustCryptoMlKemPublicKey {
    algorithm: KeyEncapsulationAlgorithm,
    key: PublicKey,
}

impl core::fmt::Debug for RustCryptoMlKemPrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RustCryptoMlKemPrivateKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}
impl core::fmt::Debug for RustCryptoMlKemPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RustCryptoMlKemPublicKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

fn invalid() -> ProviderError {
    ProviderError::InvalidInput(ProviderInputError::MlKemKey)
}

fn algorithm_identifier(
    algorithm: pkcs8::AlgorithmIdentifierRef<'_>,
) -> Result<KeyEncapsulationAlgorithm, ProviderError> {
    // RFC 9935 section 3: parameters MUST be absent, including ASN.1 NULL.
    // https://www.rfc-editor.org/rfc/rfc9935.html#section-3
    if algorithm.parameters.is_some() {
        return Err(invalid());
    }
    KeyEncapsulationAlgorithm::from_oid(algorithm.oid).ok_or_else(invalid)
}

enum PrivateEncoding<'a> {
    Seed(&'a [u8]),
    Expanded(&'a [u8]),
    Combined { seed: &'a [u8], expanded: &'a [u8] },
}

fn private_choice(bytes: &[u8]) -> Result<PrivateEncoding<'_>, ProviderError> {
    let inner = AnyRef::from_der(bytes).map_err(|_| invalid())?;
    // RFC 9935 section 6: CHOICE is tag-selected; sequence parsing consumes
    // every field, preventing both truncated and surplus key components.
    // https://www.rfc-editor.org/rfc/rfc9935.html#section-6
    match inner.tag() {
        Tag::ContextSpecific {
            constructed: false,
            number: TagNumber(0),
        } => Ok(PrivateEncoding::Seed(inner.value())),
        Tag::OctetString => Ok(PrivateEncoding::Expanded(inner.value())),
        Tag::Sequence => inner
            .sequence(|reader| -> der::Result<_> {
                let seed: &OctetStringRef = reader.decode()?;
                let expanded: &OctetStringRef = reader.decode()?;
                Ok(PrivateEncoding::Combined {
                    seed: seed.as_bytes(),
                    expanded: expanded.as_bytes(),
                })
            })
            .map_err(|_| invalid()),
        _ => Err(invalid()),
    }
}

impl RustCryptoMlKemPrivateKey {
    /// Import a uniformly random 64-byte seed for this parameter set.
    pub fn from_seed(
        algorithm: KeyEncapsulationAlgorithm,
        seed: &[u8],
    ) -> Result<Self, ProviderError> {
        let seed = Zeroizing::new(ml_kem::Seed::try_from(seed).map_err(|_| invalid())?);
        let key = match algorithm {
            KeyEncapsulationAlgorithm::MlKem512 => {
                PrivateKey::K512(ml_kem::DecapsulationKey::from_seed(*seed))
            }
            KeyEncapsulationAlgorithm::MlKem768 => {
                PrivateKey::K768(ml_kem::DecapsulationKey::from_seed(*seed))
            }
            KeyEncapsulationAlgorithm::MlKem1024 => {
                PrivateKey::K1024(ml_kem::DecapsulationKey::from_seed(*seed))
            }
        };
        Ok(Self { algorithm, key })
    }

    /// Generate with the selected provider's CSPRNG, never ambient crate randomness.
    pub fn generate(
        provider: &dyn CryptoProvider,
        algorithm: KeyEncapsulationAlgorithm,
    ) -> Result<Self, ProviderError> {
        provider.require_capability(ProviderCapability::Decapsulate(algorithm))?;
        provider.require_capability(ProviderCapability::Random)?;
        let mut seed = Zeroizing::new([0; 64]);
        provider.fill_random(seed.as_mut())?;
        Self::from_seed(algorithm, seed.as_ref())
    }

    /// Decode every RFC 9935 private-key form; reject mismatched combined keys.
    pub fn from_pkcs8_der(bytes: &[u8]) -> Result<Self, ProviderError> {
        Self::from_pkcs8_der_with_algorithm(bytes, None)
    }

    pub(in crate::provider) fn from_pkcs8_der_with_algorithm(
        bytes: &[u8],
        expected: Option<KeyEncapsulationAlgorithm>,
    ) -> Result<Self, ProviderError> {
        let info = pkcs8::PrivateKeyInfoRef::from_der(bytes).map_err(|_| invalid())?;
        let algorithm = algorithm_identifier(info.algorithm)?;
        if expected.is_some_and(|expected| expected != algorithm) {
            return Err(invalid());
        }
        let key = match private_choice(info.private_key.as_bytes())? {
            PrivateEncoding::Seed(seed) => Self::from_seed(algorithm, seed)?,
            PrivateEncoding::Expanded(expanded) => Self::from_expanded(algorithm, expanded)?,
            PrivateEncoding::Combined { seed, expanded } => {
                let key = Self::from_seed(algorithm, seed)?;
                // RFC 9935 section 8: a consistency failure MUST reject the key.
                // https://www.rfc-editor.org/rfc/rfc9935.html#section-8
                let expected = key.expanded_bytes();
                if !bool::from(expected.as_ref().ct_eq(expanded)) {
                    return Err(invalid());
                }
                key
            }
        };
        if let Some(public) = info.public_key
            && !key.matches_public(public.as_bytes().ok_or_else(invalid)?)
        {
            return Err(invalid());
        }
        Ok(key)
    }

    // The normative encoding explicitly retains expanded keys despite upstream
    // deprecation. These calls are confined to this RFC 9935 adapter, not new crypto.
    #[expect(
        deprecated,
        reason = "RFC 9935 section 6 requires expanded key encoding support"
    )]
    fn from_expanded(
        algorithm: KeyEncapsulationAlgorithm,
        bytes: &[u8],
    ) -> Result<Self, ProviderError> {
        macro_rules! decode {
            ($parameter:ty, $variant:ident) => {{
                let encoded = Zeroizing::new(
                    ml_kem::ExpandedDecapsulationKey::<$parameter>::try_from(bytes)
                        .map_err(|_| invalid())?,
                );
                PrivateKey::$variant(
                    ml_kem::DecapsulationKey::from_expanded(&encoded).map_err(|_| invalid())?,
                )
            }};
        }
        let key = match algorithm {
            KeyEncapsulationAlgorithm::MlKem512 => decode!(ml_kem::MlKem512, K512),
            KeyEncapsulationAlgorithm::MlKem768 => decode!(ml_kem::MlKem768, K768),
            KeyEncapsulationAlgorithm::MlKem1024 => decode!(ml_kem::MlKem1024, K1024),
        };
        Ok(Self { algorithm, key })
    }

    #[expect(
        deprecated,
        reason = "RFC 9935 section 6 requires expanded key encoding support"
    )]
    fn expanded_bytes(&self) -> ExpandedBuffer {
        use ml_kem::ExpandedKeyEncoding;
        macro_rules! encode {
            ($key:expr) => {{
                let encoded = Zeroizing::new($key.to_expanded_bytes());
                let mut buffer = ExpandedBuffer {
                    bytes: Zeroizing::new([0; 3168]),
                    len: encoded.len(),
                };
                buffer.bytes[..encoded.len()].copy_from_slice(&encoded);
                buffer
            }};
        }
        match &self.key {
            PrivateKey::K512(key) => encode!(key),
            PrivateKey::K768(key) => encode!(key),
            PrivateKey::K1024(key) => encode!(key),
        }
    }

    /// Export the requested RFC 9935 form; never invent a missing seed.
    pub fn to_pkcs8_der(
        &self,
        encoding: MlKemPrivateKeyEncoding,
    ) -> Result<pkcs8::SecretDocument, ProviderError> {
        let seed = match &self.key {
            PrivateKey::K512(key) => key.to_seed(),
            PrivateKey::K768(key) => key.to_seed(),
            PrivateKey::K1024(key) => key.to_seed(),
        }
        .map(Zeroizing::new);
        let encode = || -> der::Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(match encoding {
                MlKemPrivateKeyEncoding::Seed => ContextSpecific {
                    tag_number: TagNumber(0),
                    tag_mode: TagMode::Implicit,
                    value: OctetStringRef::new(
                        seed.as_ref().ok_or(der::ErrorKind::Failed)?.as_slice(),
                    )?,
                }
                .to_der()?,
                MlKemPrivateKeyEncoding::Expanded => {
                    OctetStringRef::new(self.expanded_bytes().as_ref())?.to_der()?
                }
                MlKemPrivateKeyEncoding::Combined => {
                    let expanded = self.expanded_bytes();
                    Both {
                        seed: OctetStringRef::new(
                            seed.as_ref().ok_or(der::ErrorKind::Failed)?.as_slice(),
                        )?,
                        expanded: OctetStringRef::new(expanded.as_ref())?,
                    }
                    .to_der()?
                }
            }))
        };
        let inner = encode().map_err(|_| invalid())?;
        let info = pkcs8::PrivateKeyInfoRef::new(
            pkcs8::AlgorithmIdentifierRef {
                oid: self.algorithm.oid(),
                parameters: None,
            },
            OctetStringRef::new(&inner).map_err(|_| invalid())?,
        );
        pkcs8::SecretDocument::encode_msg(&info).map_err(|_| invalid())
    }

    /// Obtain the validated public key without exporting private material.
    pub fn public_key(&self) -> RustCryptoMlKemPublicKey {
        let key = match &self.key {
            PrivateKey::K512(key) => PublicKey::K512(key.encapsulation_key().clone()),
            PrivateKey::K768(key) => PublicKey::K768(key.encapsulation_key().clone()),
            PrivateKey::K1024(key) => PublicKey::K1024(key.encapsulation_key().clone()),
        };
        RustCryptoMlKemPublicKey {
            algorithm: self.algorithm,
            key,
        }
    }

    fn matches_public(&self, bytes: &[u8]) -> bool {
        macro_rules! matches {
            ($key:expr) => {
                bool::from($key.encapsulation_key().to_bytes().as_slice().ct_eq(bytes))
            };
        }
        match &self.key {
            PrivateKey::K512(key) => matches!(key),
            PrivateKey::K768(key) => matches!(key),
            PrivateKey::K1024(key) => matches!(key),
        }
    }

    /// Copy identity directly from the retained public component without cloning it.
    pub fn copy_public(&self, output: &mut [u8]) -> Result<usize, ProviderError> {
        let length = self.algorithm.public_key_len();
        if output.len() < length {
            return Err(invalid());
        }
        match &self.key {
            PrivateKey::K512(key) => {
                output[..length].copy_from_slice(&key.encapsulation_key().to_bytes())
            }
            PrivateKey::K768(key) => {
                output[..length].copy_from_slice(&key.encapsulation_key().to_bytes())
            }
            PrivateKey::K1024(key) => {
                output[..length].copy_from_slice(&key.encapsulation_key().to_bytes())
            }
        }
        Ok(length)
    }
}

struct ExpandedBuffer {
    bytes: Zeroizing<[u8; 3168]>,
    len: usize,
}
impl AsRef<[u8]> for ExpandedBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

#[derive(der::Sequence)]
struct Both<'a> {
    seed: &'a OctetStringRef,
    expanded: &'a OctetStringRef,
}

impl RustCryptoMlKemPublicKey {
    /// Validate raw public coefficients before any encapsulation work.
    pub fn from_bytes(
        algorithm: KeyEncapsulationAlgorithm,
        bytes: &[u8],
    ) -> Result<Self, ProviderError> {
        macro_rules! decode {
            ($parameter:ty, $variant:ident) => {{
                let encoded = ml_kem::Key::<ml_kem::EncapsulationKey<$parameter>>::try_from(bytes)
                    .map_err(|_| invalid())?;
                PublicKey::$variant(ml_kem::EncapsulationKey::new(&encoded).map_err(|_| invalid())?)
            }};
        }
        let key = match algorithm {
            KeyEncapsulationAlgorithm::MlKem512 => decode!(ml_kem::MlKem512, K512),
            KeyEncapsulationAlgorithm::MlKem768 => decode!(ml_kem::MlKem768, K768),
            KeyEncapsulationAlgorithm::MlKem1024 => decode!(ml_kem::MlKem1024, K1024),
        };
        Ok(Self { algorithm, key })
    }

    /// Import RFC 9935 SPKI with absent parameters and an octet-aligned BIT STRING.
    pub fn from_spki_der(bytes: &[u8]) -> Result<Self, ProviderError> {
        Self::from_spki_der_with_algorithm(bytes, None)
    }

    pub(in crate::provider) fn from_spki_der_with_algorithm(
        bytes: &[u8],
        expected: Option<KeyEncapsulationAlgorithm>,
    ) -> Result<Self, ProviderError> {
        let info = pkcs8::SubjectPublicKeyInfoRef::from_der(bytes).map_err(|_| invalid())?;
        let algorithm = algorithm_identifier(info.algorithm)?;
        if expected.is_some_and(|expected| expected != algorithm) {
            return Err(invalid());
        }
        Self::from_bytes(
            algorithm,
            info.subject_public_key.as_bytes().ok_or_else(invalid)?,
        )
    }

    /// Export the raw FIPS 203 encapsulation key.
    pub fn to_bytes(&self) -> Vec<u8> {
        match &self.key {
            PublicKey::K512(key) => key.to_bytes().to_vec(),
            PublicKey::K768(key) => key.to_bytes().to_vec(),
            PublicKey::K1024(key) => key.to_bytes().to_vec(),
        }
    }

    /// Copy the public identity into caller-owned fixed storage without allocating.
    pub fn copy_public(&self, output: &mut [u8]) -> Result<usize, ProviderError> {
        let length = self.algorithm.public_key_len();
        if output.len() < length {
            return Err(invalid());
        }
        match &self.key {
            PublicKey::K512(key) => output[..length].copy_from_slice(&key.to_bytes()),
            PublicKey::K768(key) => output[..length].copy_from_slice(&key.to_bytes()),
            PublicKey::K1024(key) => output[..length].copy_from_slice(&key.to_bytes()),
        }
        Ok(length)
    }

    /// Export RFC 9935 SPKI; no ASN.1 wrapper inside its BIT STRING.
    pub fn to_spki_der(&self) -> Result<pkcs8::Document, ProviderError> {
        macro_rules! encode {
            ($key:expr) => {{
                let bytes = $key.to_bytes();
                let info = pkcs8::SubjectPublicKeyInfoRef {
                    algorithm: pkcs8::AlgorithmIdentifierRef {
                        oid: self.algorithm.oid(),
                        parameters: None,
                    },
                    subject_public_key: BitStringRef::new(0, bytes.as_slice())
                        .map_err(|_| invalid())?,
                };
                pkcs8::Document::encode_msg(&info).map_err(|_| invalid())
            }};
        }
        match &self.key {
            PublicKey::K512(key) => encode!(key),
            PublicKey::K768(key) => encode!(key),
            PublicKey::K1024(key) => encode!(key),
        }
    }
}

impl KeyEncapsulationKey for RustCryptoMlKemPublicKey {
    fn algorithm(&self) -> KeyEncapsulationAlgorithm {
        self.algorithm
    }
    fn encapsulate_with_provider(
        &self,
        provider: &dyn CryptoProvider,
    ) -> Result<EncapsulatedKey, ProviderError> {
        provider.require_capability(ProviderCapability::Random)?;
        let mut randomness = Zeroizing::new(ml_kem::B32::default());
        provider.fill_random(randomness.as_mut())?;
        // FIPS 203 section 7.2: m comes from the selected provider CSPRNG.
        // https://doi.org/10.6028/NIST.FIPS.203
        macro_rules! encapsulate {
            ($key:expr) => {{
                let (ciphertext, secret) = $key.encapsulate_deterministic(&randomness);
                let secret = Zeroizing::new(secret);
                EncapsulatedKey {
                    ciphertext: ciphertext.to_vec(),
                    shared_secret: Zeroizing::new((*secret).into()),
                }
            }};
        }
        Ok(match &self.key {
            PublicKey::K512(key) => encapsulate!(key),
            PublicKey::K768(key) => encapsulate!(key),
            PublicKey::K1024(key) => encapsulate!(key),
        })
    }
}

impl KeyDecapsulationKey for RustCryptoMlKemPrivateKey {
    fn algorithm(&self) -> KeyEncapsulationAlgorithm {
        self.algorithm
    }
    fn decapsulate(&self, ciphertext: &[u8]) -> Result<Zeroizing<[u8; 32]>, ProviderError> {
        // FIPS 203 section 7.3: length errors are public; ciphertext mismatch
        // uses implicit rejection inside the primitive, without a validity bit.
        // https://doi.org/10.6028/NIST.FIPS.203
        macro_rules! decapsulate {
            ($parameter:ty, $key:expr) => {{
                let ciphertext =
                    ml_kem::Ciphertext::<$parameter>::try_from(ciphertext).map_err(|_| {
                        ProviderError::InvalidInput(ProviderInputError::MlKemCiphertext)
                    })?;
                let secret = Zeroizing::new($key.decapsulate(&ciphertext));
                Zeroizing::new((*secret).into())
            }};
        }
        Ok(match &self.key {
            PrivateKey::K512(key) => decapsulate!(ml_kem::MlKem512, key),
            PrivateKey::K768(key) => decapsulate!(ml_kem::MlKem768, key),
            PrivateKey::K1024(key) => decapsulate!(ml_kem::MlKem1024, key),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::RustCryptoProvider;

    const ALGORITHMS: [KeyEncapsulationAlgorithm; 3] = [
        KeyEncapsulationAlgorithm::MlKem512,
        KeyEncapsulationAlgorithm::MlKem768,
        KeyEncapsulationAlgorithm::MlKem1024,
    ];

    #[test]
    fn all_parameter_sets_roundtrip_every_private_encoding() {
        // RFC 9935 section 6 permits every CHOICE branch, not just the preferred seed.
        for algorithm in ALGORITHMS {
            let original =
                RustCryptoMlKemPrivateKey::from_seed(algorithm, &[42; 64]).expect("seed");
            let public = original.public_key();
            let encapsulated = RustCryptoProvider
                .encapsulate_key(&public)
                .expect("encapsulate");
            assert_eq!(encapsulated.ciphertext.len(), algorithm.ciphertext_len());
            for encoding in [
                MlKemPrivateKeyEncoding::Seed,
                MlKemPrivateKeyEncoding::Expanded,
                MlKemPrivateKeyEncoding::Combined,
            ] {
                let der = original.to_pkcs8_der(encoding).expect("encode");
                let decoded =
                    RustCryptoMlKemPrivateKey::from_pkcs8_der(der.as_bytes()).expect("decode");
                assert_eq!(decoded.algorithm(), algorithm);
                assert_eq!(decoded.public_key().to_bytes(), public.to_bytes());
                assert_eq!(
                    *RustCryptoProvider
                        .decapsulate_key(&decoded, &encapsulated.ciphertext)
                        .expect("decapsulate"),
                    *encapsulated.shared_secret
                );
                if encoding == MlKemPrivateKeyEncoding::Expanded {
                    assert!(decoded.to_pkcs8_der(MlKemPrivateKeyEncoding::Seed).is_err());
                    assert!(
                        decoded
                            .to_pkcs8_der(MlKemPrivateKeyEncoding::Combined)
                            .is_err()
                    );
                }
            }
            let der = public.to_spki_der().expect("SPKI");
            assert_eq!(
                RustCryptoMlKemPublicKey::from_spki_der(der.as_bytes())
                    .expect("SPKI decode")
                    .to_bytes(),
                public.to_bytes()
            );
        }
    }

    #[test]
    fn combined_keys_reject_inconsistent_seed() {
        // Keep the expanded key intact but change its seed: import must fail.
        for algorithm in ALGORITHMS {
            let key = RustCryptoMlKemPrivateKey::from_seed(algorithm, &[7; 64]).expect("seed");
            let encoded = key
                .to_pkcs8_der(MlKemPrivateKeyEncoding::Combined)
                .expect("encode");
            let info = pkcs8::PrivateKeyInfoRef::from_der(encoded.as_bytes()).expect("PKCS8");
            let mut inner = Zeroizing::new(info.private_key.as_bytes().to_vec());
            let start = inner
                .windows(64)
                .position(|bytes| bytes == [7; 64])
                .expect("seed offset");
            inner[start] ^= 1;
            let info = pkcs8::PrivateKeyInfoRef::new(
                info.algorithm,
                OctetStringRef::new(&inner).expect("inner"),
            );
            let der = pkcs8::SecretDocument::encode_msg(&info).expect("DER");
            assert!(RustCryptoMlKemPrivateKey::from_pkcs8_der(der.as_bytes()).is_err());
        }
    }

    #[test]
    fn valid_size_invalid_ciphertext_is_implicitly_rejected() {
        // FIPS 203 section 7.3 returns a deterministic fallback secret, never an oracle bit.
        for algorithm in ALGORITHMS {
            let key = RustCryptoMlKemPrivateKey::from_seed(algorithm, &[19; 64]).expect("seed");
            let mut encapsulated = RustCryptoProvider
                .encapsulate_key(&key.public_key())
                .expect("encapsulate");
            encapsulated.ciphertext[0] ^= 1;
            let first = RustCryptoProvider
                .decapsulate_key(&key, &encapsulated.ciphertext)
                .expect("implicit rejection");
            let second = RustCryptoProvider
                .decapsulate_key(&key, &encapsulated.ciphertext)
                .expect("implicit rejection");
            assert_eq!(*first, *second);
            assert_ne!(*first, *encapsulated.shared_secret);
            assert!(
                RustCryptoProvider
                    .decapsulate_key(
                        &key,
                        &encapsulated.ciphertext[..algorithm.ciphertext_len() - 1]
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn key_encoding_rejects_parameters_trailing_data_and_bad_public_coefficients() {
        // Absent means absent: ASN.1 NULL is not an allowed AlgorithmIdentifier parameter.
        for algorithm in ALGORITHMS {
            let key = RustCryptoMlKemPrivateKey::from_seed(algorithm, &[1; 64]).expect("seed");
            let public = key.public_key();
            let encoded = public.to_spki_der().expect("SPKI");
            let info =
                pkcs8::SubjectPublicKeyInfoRef::from_der(encoded.as_bytes()).expect("SPKI decode");
            let info = pkcs8::SubjectPublicKeyInfoRef {
                algorithm: pkcs8::AlgorithmIdentifierRef {
                    oid: algorithm.oid(),
                    parameters: Some(AnyRef::NULL),
                },
                subject_public_key: info.subject_public_key,
            };
            assert!(RustCryptoMlKemPublicKey::from_spki_der(&info.to_der().expect("DER")).is_err());
            let mut trailing = encoded.as_bytes().to_vec();
            trailing.push(0);
            assert!(RustCryptoMlKemPublicKey::from_spki_der(&trailing).is_err());
            let mut raw = public.to_bytes();
            raw[..3].fill(255);
            assert!(RustCryptoMlKemPublicKey::from_bytes(algorithm, &raw).is_err());
            assert!(RustCryptoMlKemPrivateKey::from_seed(algorithm, &[0; 63]).is_err());
        }
    }

    #[test]
    fn expanded_keys_reject_hash_corruption() {
        // FIPS 203 section 7.3 validates the embedded encapsulation-key hash on import.
        for algorithm in ALGORITHMS {
            let key = RustCryptoMlKemPrivateKey::from_seed(algorithm, &[2; 64]).expect("seed");
            let mut expanded = key.expanded_bytes();
            expanded.bytes[expanded.len - 64] ^= 1;
            assert!(
                RustCryptoMlKemPrivateKey::from_expanded(algorithm, expanded.as_ref()).is_err()
            );
        }
    }
}
