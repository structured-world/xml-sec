//! Opaque `RustCrypto` PQ primitives, invoked through `CryptoProvider` only.

use crate::rustcrypto_ml_dsa as ml_dsa;

use super::{PqAlgorithm, SignatureContext, SignatureVerificationError};
#[cfg(feature = "xmldsig-sign")]
use super::{SignatureAlgorithm, SigningKey, SigningKeyError, SigningPublicKeyInfo};
#[cfg(feature = "xmldsig-sign")]
use pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
#[cfg(feature = "xmldsig-sign")]
use signature::Keypair;
#[cfg(feature = "xmldsig-sign")]
use zeroize::Zeroizing;

#[cfg(feature = "xmldsig-sign")]
enum MlPrivateKey<P: ml_dsa::MlDsaParams> {
    Seed(ml_dsa::SigningKey<P>),
    Expanded(Box<ml_dsa::ExpandedSigningKey<P>>, ml_dsa::VerifyingKey<P>),
}

#[cfg(feature = "xmldsig-sign")]
impl<P: ml_dsa::MlDsaParams> MlPrivateKey<P> {
    fn expanded_key(&self) -> &ml_dsa::ExpandedSigningKey<P> {
        match self {
            Self::Seed(key) => key.expanded_key(),
            Self::Expanded(key, _) => key,
        }
    }

    fn verifying_key(&self) -> &ml_dsa::VerifyingKey<P> {
        match self {
            Self::Seed(key) => key.as_ref(),
            Self::Expanded(_, public) => public,
        }
    }
}

#[cfg(feature = "xmldsig-sign")]
impl<P> TryFrom<pkcs8::PrivateKeyInfoRef<'_>> for MlPrivateKey<P>
where
    P: ml_dsa::MlDsaParams
        + pkcs8::spki::AssociatedAlgorithmIdentifier<Params = pkcs8::der::AnyRef<'static>>,
{
    type Error = pkcs8::Error;

    fn try_from(info: pkcs8::PrivateKeyInfoRef<'_>) -> pkcs8::Result<Self> {
        use ctutils::CtEq;
        use pkcs8::der::{AnyRef, Decode, Reader, Tag, TagNumber, Tagged, asn1::OctetStringRef};
        info.algorithm
            .assert_algorithm_oid(P::ALGORITHM_IDENTIFIER.oid)?;
        if info.algorithm.parameters.is_some() {
            return Err(pkcs8::KeyError::Invalid.into());
        }
        let inner = AnyRef::from_der(info.private_key.as_bytes())?;
        // RFC 9881 section 6: CHOICE uses distinct ASN.1 tags, not a length
        // heuristic. AnyRef and sequence readers require complete consumption.
        // https://www.rfc-editor.org/rfc/rfc9881.html#section-6
        let (seed, expanded) = match inner.tag() {
            Tag::ContextSpecific {
                constructed: false,
                number: TagNumber(0),
            } => (Some(inner.value()), None),
            Tag::OctetString => (None, Some(inner.value())),
            Tag::Sequence => inner.sequence(|reader| -> pkcs8::der::Result<_> {
                let seed: &OctetStringRef = reader.decode()?;
                let expanded: &OctetStringRef = reader.decode()?;
                Ok((Some(seed.as_bytes()), Some(expanded.as_bytes())))
            })?,
            _ => return Err(pkcs8::KeyError::Invalid.into()),
        };
        if let Some(seed) = seed {
            let seed =
                Zeroizing::new(ml_dsa::Seed::try_from(seed).map_err(|_| pkcs8::KeyError::Invalid)?);
            let key = ml_dsa::SigningKey::<P>::from_seed(&seed);
            if let Some(expanded) = expanded {
                // RFC 9881 section 8.2: when consistency is checked, mismatch
                // MUST be rejected. Regeneration also validates the packed codes.
                // https://www.rfc-editor.org/rfc/rfc9881.html#section-8.2
                #[allow(deprecated)] // RFC 9881 explicitly supports expanded keys.
                let expected = Zeroizing::new(key.expanded_key().to_expanded());
                if !bool::from(expected.as_slice().ct_eq(expanded)) {
                    return Err(pkcs8::KeyError::Invalid.into());
                }
            }
            Ok(Self::Seed(key))
        } else {
            let expanded = expanded.ok_or(pkcs8::KeyError::Invalid)?;
            let encoded = Zeroizing::new(
                ml_dsa::ExpandedSigningKeyBytes::<P>::try_from(expanded)
                    .map_err(|_| pkcs8::KeyError::Invalid)?,
            );
            let key = ml_dsa::ExpandedSigningKey::<P>::try_from_expanded(&encoded)
                .map_err(|_| pkcs8::KeyError::Invalid)?;
            let public = key.verifying_key();
            Ok(Self::Expanded(Box::new(key), public))
        }
    }
}

#[cfg(feature = "xmldsig-sign")]
impl<P> EncodePrivateKey for MlPrivateKey<P>
where
    P: ml_dsa::MlDsaParams
        + pkcs8::spki::AssociatedAlgorithmIdentifier<Params = pkcs8::der::AnyRef<'static>>,
{
    fn to_pkcs8_der(&self) -> pkcs8::Result<pkcs8::SecretDocument> {
        use pkcs8::der::{
            Encode, TagMode, TagNumber,
            asn1::{ContextSpecific, OctetStringRef},
        };
        // Preserve the information we actually possess: an expanded-only key
        // cannot be exported as a fabricated seed. Every secret staging buffer
        // is zeroizing, including the inner ASN.1 encoding.
        let inner = match self {
            Self::Seed(key) => Zeroizing::new(
                ContextSpecific {
                    tag_mode: TagMode::Implicit,
                    tag_number: TagNumber(0),
                    value: OctetStringRef::new(key.as_seed())?,
                }
                .to_der()?,
            ),
            Self::Expanded(key, _) => {
                #[allow(deprecated)] // RFC 9881 expanded-only representation.
                let expanded = Zeroizing::new(key.to_expanded());
                Zeroizing::new(OctetStringRef::new(&expanded)?.to_der()?)
            }
        };
        let info =
            pkcs8::PrivateKeyInfoRef::new(P::ALGORITHM_IDENTIFIER, OctetStringRef::new(&inner)?);
        pkcs8::SecretDocument::encode_msg(&info).map_err(pkcs8::Error::Asn1)
    }
}

#[cfg(feature = "xmldsig-sign")]
trait PublicBytes {
    fn copy_public(&self, output: &mut [u8; 2592]) -> usize;
}

#[cfg(feature = "xmldsig-sign")]
impl<P: ml_dsa::MlDsaParams> PublicBytes for MlPrivateKey<P> {
    fn copy_public(&self, output: &mut [u8; 2592]) -> usize {
        let encoded = self.verifying_key().encode();
        output[..encoded.len()].copy_from_slice(&encoded);
        encoded.len()
    }
}

#[cfg(feature = "xmldsig-sign")]
impl<P: slh_dsa::ParameterSet> PublicBytes for slh_dsa::SigningKey<P> {
    fn copy_public(&self, output: &mut [u8; 2592]) -> usize {
        let encoded = self.verifying_key().to_bytes();
        output[..encoded.len()].copy_from_slice(&encoded);
        encoded.len()
    }
}

#[cfg(feature = "xmldsig-sign")]
trait ContextSigner {
    fn sign_context(&self, context: &[u8], message: &[u8]) -> Result<Vec<u8>, SigningKeyError>;
}

#[cfg(feature = "xmldsig-sign")]
impl<P: ml_dsa::MlDsaParams> ContextSigner for MlPrivateKey<P> {
    fn sign_context(&self, context: &[u8], message: &[u8]) -> Result<Vec<u8>, SigningKeyError> {
        // FIPS 204 section 5.2, algorithm 2: deterministic signing uses
        // a zero randomizer; context is included by the primitive, not by XML.
        // https://doi.org/10.6028/NIST.FIPS.204
        self.expanded_key()
            .sign_deterministic(message, context)
            .map(|signature| signature.encode().to_vec())
            .map_err(|_| SigningKeyError::InvalidKeyDer)
    }
}

#[cfg(feature = "xmldsig-sign")]
impl<P: slh_dsa::ParameterSet> ContextSigner for slh_dsa::SigningKey<P> {
    fn sign_context(&self, context: &[u8], message: &[u8]) -> Result<Vec<u8>, SigningKeyError> {
        // FIPS 205 section 10.2, algorithm 22 permits deterministic opt_rand.
        // Use stack serialization: upstream to_vec allocates intermediate trees.
        // https://doi.org/10.6028/NIST.FIPS.205
        self.try_sign_with_context(message, context, None)
            .map(|signature| signature.to_bytes().to_vec())
            .map_err(|_| SigningKeyError::InvalidKeyDer)
    }
}

trait ContextVerifier {
    fn verify_context(
        &self,
        context: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, SignatureVerificationError>;
}

impl<P: ml_dsa::MlDsaParams> ContextVerifier for ml_dsa::VerifyingKey<P> {
    fn verify_context(
        &self,
        context: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, SignatureVerificationError> {
        let Ok(signature) = ml_dsa::Signature::<P>::try_from(signature) else {
            return Ok(false);
        };
        Ok(self.verify_with_context(message, context, &signature))
    }
}

impl<P: slh_dsa::ParameterSet> ContextVerifier for slh_dsa::VerifyingKey<P> {
    fn verify_context(
        &self,
        context: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, SignatureVerificationError> {
        let Ok(signature) = slh_dsa::Signature::<P>::try_from(signature) else {
            return Ok(false);
        };
        Ok(self
            .try_verify_with_context(message, context, &signature)
            .is_ok())
    }
}

macro_rules! parameter_sets {
    ($($variant:ident: $signing:ty => $verifying:ty),+ $(,)?) => {
        #[cfg(feature = "xmldsig-sign")]
        enum PrivateKey { $($variant($signing)),+ }

        #[cfg(feature = "xmldsig-sign")]
        impl PostQuantumSigningKey {
            /// Strict PKCS#8 import for the explicitly selected parameter set.
            ///
            /// # Errors
            /// Returns an error for invalid DER, mismatched algorithm or public
            /// key, or parameters forbidden by the selected key format.
            pub fn from_pkcs8_der(algorithm: PqAlgorithm, der: &[u8]) -> Result<Self, SigningKeyError> {
                use pkcs8::der::Decode;
                let info = pkcs8::PrivateKeyInfoRef::from_der(der).map_err(|_| SigningKeyError::InvalidKeyDer)?;
                // RFC 9881 §2 / RFC 9909 §3: NULL is not equivalent to absent.
                // https://www.rfc-editor.org/rfc/rfc9881.html#section-2
                // https://www.rfc-editor.org/rfc/rfc9909.html#section-3
                // The primitive decoders only check OIDs, so enforce this here.
                if info.algorithm.parameters.is_some() || info.algorithm.oid != algorithm.object_oid() { return Err(SigningKeyError::InvalidKeyDer); }
                let key = match algorithm { $(PqAlgorithm::$variant => PrivateKey::$variant(<$signing>::from_pkcs8_der(der).map_err(|_| SigningKeyError::InvalidKeyDer)?)),+ };
                let key = Self { algorithm, key };
                if let Some(public) = info.public_key {
                    let mut derived = [0; 2592];
                    let length = key.copy_public(&mut derived);
                    if public.as_bytes() != Some(&derived[..length]) { return Err(SigningKeyError::InvalidKeyDer); }
                }
                Ok(key)
            }

            /// Export into a zeroizing private-key document, never an ordinary Vec.
            ///
            /// # Errors
            /// Returns an error if the primitive cannot encode the private key.
            pub fn to_pkcs8_der(&self) -> Result<pkcs8::SecretDocument, SigningKeyError> {
                match &self.key { $(PrivateKey::$variant(key) => key.to_pkcs8_der()),+ }.map_err(|_| SigningKeyError::InvalidKeyDer)
            }

            fn public_der(&self) -> Result<pkcs8::Document, SigningKeyError> {
                match &self.key { $(PrivateKey::$variant(key) => key.verifying_key().to_public_key_der()),+ }.map_err(|_| SigningKeyError::PublicKeyEncodingFailed)
            }

            pub(crate) fn copy_public(&self, output: &mut [u8; 2592]) -> usize {
                match &self.key { $(PrivateKey::$variant(key) => key.copy_public(output)),+ }
            }
        }

        pub(crate) fn validate_public_key(algorithm: PqAlgorithm, der: &[u8], session: &super::pkix::CertificateSession) -> Result<(), SignatureVerificationError> {
            with_public_octets(algorithm, der, session, |octets| match algorithm { $(PqAlgorithm::$variant => <$verifying>::from_public_octets(octets).map(|_| ())),+ })?
                .ok_or(SignatureVerificationError::InvalidKeyDer)
        }

        pub(crate) fn verify(algorithm: PqAlgorithm, der: &[u8], context: &SignatureContext, message: &[u8], signature: &[u8], session: &super::pkix::CertificateSession) -> Result<bool, SignatureVerificationError> {
            with_public_octets(algorithm, der, session, |octets| {
                if signature.len() != algorithm.signature_len() { return Some(Ok(false)); }
                match algorithm { $(PqAlgorithm::$variant => <$verifying>::from_public_octets(octets).map(|key| key.verify_context(context.as_bytes(), message, signature))),+ }
            })?
                .ok_or(SignatureVerificationError::InvalidKeyDer)?
        }

        #[cfg(feature = "xmldsig-sign")]
        impl SigningKey for PostQuantumSigningKey {
            fn sign(&self, algorithm: SignatureAlgorithm, message: &[u8]) -> Result<Vec<u8>, SigningKeyError> {
                crate::provider::default_provider().sign(self, algorithm, message)
            }

            fn sign_with_provider(&self, provider: &dyn crate::provider::CryptoProvider, algorithm: SignatureAlgorithm, message: &[u8]) -> Result<Vec<u8>, SigningKeyError> {
                self.sign_with_provider_context(provider, algorithm, &SignatureContext::default(), message)
            }

            fn sign_with_provider_context(&self, _provider: &dyn crate::provider::CryptoProvider, algorithm: SignatureAlgorithm, context: &SignatureContext, message: &[u8]) -> Result<Vec<u8>, SigningKeyError> {
                if algorithm != SignatureAlgorithm::PostQuantum(self.algorithm) { return Err(SigningKeyError::UnsupportedAlgorithm { uri: algorithm.uri().to_owned() }); }
                match &self.key { $(PrivateKey::$variant(key) => key.sign_context(context.as_bytes(), message)),+ }
            }

            fn public_key_info(&self) -> Result<SigningPublicKeyInfo, SigningKeyError> {
                Ok(SigningPublicKeyInfo::PostQuantum { algorithm: self.algorithm, spki_der: self.public_der()?.into_vec() })
            }
        }
    }
}

/// Opaque experimental PQ signing key; built-in primitives zeroize secrets on drop.
#[cfg(feature = "xmldsig-sign")]
pub struct PostQuantumSigningKey {
    algorithm: PqAlgorithm,
    key: PrivateKey,
}

parameter_sets! {
    MlDsa44: MlPrivateKey<ml_dsa::MlDsa44> => ml_dsa::VerifyingKey<ml_dsa::MlDsa44>,
    MlDsa65: MlPrivateKey<ml_dsa::MlDsa65> => ml_dsa::VerifyingKey<ml_dsa::MlDsa65>,
    MlDsa87: MlPrivateKey<ml_dsa::MlDsa87> => ml_dsa::VerifyingKey<ml_dsa::MlDsa87>,
    SlhDsaSha2_128f: slh_dsa::SigningKey<slh_dsa::Sha2_128f> => slh_dsa::VerifyingKey<slh_dsa::Sha2_128f>,
    SlhDsaSha2_128s: slh_dsa::SigningKey<slh_dsa::Sha2_128s> => slh_dsa::VerifyingKey<slh_dsa::Sha2_128s>,
    SlhDsaSha2_192f: slh_dsa::SigningKey<slh_dsa::Sha2_192f> => slh_dsa::VerifyingKey<slh_dsa::Sha2_192f>,
    SlhDsaSha2_192s: slh_dsa::SigningKey<slh_dsa::Sha2_192s> => slh_dsa::VerifyingKey<slh_dsa::Sha2_192s>,
    SlhDsaSha2_256f: slh_dsa::SigningKey<slh_dsa::Sha2_256f> => slh_dsa::VerifyingKey<slh_dsa::Sha2_256f>,
    SlhDsaSha2_256s: slh_dsa::SigningKey<slh_dsa::Sha2_256s> => slh_dsa::VerifyingKey<slh_dsa::Sha2_256s>,
}

/// Hands the raw public key of an `algorithm` SPKI, read by the shared PKIX
/// reader under `session`, to `use_key`; `None` for any other or malformed
/// SPKI. RFC 9881 section 2 / RFC 9909 section 3: the exact OID, parameters
/// absent. <https://www.rfc-editor.org/rfc/rfc9881.html#section-2>
fn with_public_octets<T>(
    algorithm: PqAlgorithm,
    der: &[u8],
    session: &super::pkix::CertificateSession,
    use_key: impl FnOnce(&[u8]) -> Option<T>,
) -> Result<Option<T>, SignatureVerificationError> {
    let read = session.with_public_key_info(der, |info, _| {
        let identifier = info.algorithm();
        Ok(
            if identifier.parameters().is_none()
                && identifier.algorithm().as_bytes() == algorithm.object_oid().as_bytes()
            {
                info.key_octets().and_then(use_key)
            } else {
                None
            },
        )
    });
    match read {
        Ok(value) => Ok(value),
        Err(error) if error.is_resource() => Err(super::signature::key_read_error(session, &error)),
        Err(_) => Ok(None),
    }
}

/// Verifying-key construction from raw public octets (FIPS 204 pkDecode,
/// FIPS 205 PK.seed || PK.root).
trait PublicOctets: Sized {
    fn from_public_octets(octets: &[u8]) -> Option<Self>;
}

impl<P: ml_dsa::MlDsaParams> PublicOctets for ml_dsa::VerifyingKey<P> {
    fn from_public_octets(octets: &[u8]) -> Option<Self> {
        ml_dsa::EncodedVerifyingKey::<P>::try_from(octets)
            .ok()
            .map(|encoded| Self::decode(&encoded))
    }
}

impl<P: slh_dsa::ParameterSet> PublicOctets for slh_dsa::VerifyingKey<P> {
    fn from_public_octets(octets: &[u8]) -> Option<Self> {
        Self::try_from(octets).ok()
    }
}
