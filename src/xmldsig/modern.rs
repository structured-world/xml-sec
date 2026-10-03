//! RustCrypto-owned modern key handles used only behind provider dispatch.

use super::{SignatureAlgorithm, SigningKey, SigningKeyError, SigningPublicKeyInfo};
use pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use sha2::digest::Update;

#[expect(
    clippy::large_enum_variant,
    reason = "fixed-size inline private keys avoid a second secret allocation and indirection"
)]
enum EdDsaPrivateKey {
    Ed25519(ed25519_dalek::SigningKey),
    Ed448(ed448_goldilocks::SigningKey),
}

/// Opaque EdDSA private key. Private bytes are zeroized by the primitive on drop.
pub struct EdDsaSigningKey(EdDsaPrivateKey);

impl EdDsaSigningKey {
    /// Import a strict RFC 8410 PKCS#8 key for the explicitly selected algorithm.
    pub fn from_pkcs8_der(
        algorithm: SignatureAlgorithm,
        der: &[u8],
    ) -> Result<Self, SigningKeyError> {
        let key = match algorithm.eddsa_key_algorithm() {
            Some(SignatureAlgorithm::Ed25519) => EdDsaPrivateKey::Ed25519(
                ed25519_dalek::SigningKey::from_pkcs8_der(der)
                    .map_err(|_| SigningKeyError::InvalidKeyDer)?,
            ),
            Some(SignatureAlgorithm::Ed448) => EdDsaPrivateKey::Ed448(
                ed448_goldilocks::SigningKey::from_pkcs8_der(der)
                    .map_err(|_| SigningKeyError::InvalidKeyDer)?,
            ),
            _ => {
                return Err(SigningKeyError::UnsupportedAlgorithm {
                    uri: algorithm.uri().to_owned(),
                });
            }
        };
        Ok(Self(key))
    }

    /// Export private PKCS#8 DER in a zeroizing secret document.
    pub fn to_pkcs8_der(&self) -> Result<pkcs8::SecretDocument, SigningKeyError> {
        match &self.0 {
            EdDsaPrivateKey::Ed25519(key) => key.to_pkcs8_der(),
            EdDsaPrivateKey::Ed448(key) => key.to_pkcs8_der(),
        }
        .map_err(|_| SigningKeyError::InvalidKeyDer)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        match &self.0 {
            EdDsaPrivateKey::Ed25519(_) => SignatureAlgorithm::Ed25519,
            EdDsaPrivateKey::Ed448(_) => SignatureAlgorithm::Ed448,
        }
    }
}

impl SigningKey for EdDsaSigningKey {
    fn sign_with_provider_context(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: SignatureAlgorithm,
        context: &super::SignatureContext,
        message: &[u8],
    ) -> Result<Vec<u8>, SigningKeyError> {
        if algorithm.eddsa_key_algorithm() != Some(self.algorithm()) {
            return Err(SigningKeyError::UnsupportedAlgorithm {
                uri: algorithm.uri().to_owned(),
            });
        }
        match &self.0 {
            EdDsaPrivateKey::Ed448(key) if algorithm == SignatureAlgorithm::Ed448 => key
                .sign_ctx(context.as_bytes(), message)
                .map(|sig| sig.to_bytes().to_vec())
                .map_err(|_| SigningKeyError::InvalidKeyDer),
            EdDsaPrivateKey::Ed448(key) => {
                use ed448_goldilocks::{PreHasherXof, shake::Shake256};
                key.sign_prehashed::<PreHasherXof<Shake256>>(
                    Some(context.as_bytes()),
                    Shake256::default().chain(message).into(),
                )
                .map(|sig| sig.to_bytes().to_vec())
                .map_err(|_| SigningKeyError::InvalidKeyDer)
            }
            EdDsaPrivateKey::Ed25519(key) if algorithm == SignatureAlgorithm::Ed25519Ctx => {
                Ok(sign_ed25519ctx(key, context, message).to_bytes().to_vec())
            }
            EdDsaPrivateKey::Ed25519(key) if algorithm == SignatureAlgorithm::Ed25519Ph => {
                use sha2::Digest;
                key.sign_prehashed(
                    sha2::Sha512::new_with_prefix(message),
                    Some(context.as_bytes()),
                )
                .map(|sig| sig.to_bytes().to_vec())
                .map_err(|_| SigningKeyError::InvalidKeyDer)
            }
            EdDsaPrivateKey::Ed25519(_) if context.as_bytes().is_empty() => {
                self.sign_with_provider(provider, algorithm, message)
            }
            _ => Err(SigningKeyError::UnsupportedAlgorithm {
                uri: algorithm.uri().to_owned(),
            }),
        }
    }
    fn sign(
        &self,
        algorithm: SignatureAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>, SigningKeyError> {
        crate::provider::default_provider().sign(self, algorithm, message)
    }

    fn sign_with_provider(
        &self,
        _provider: &dyn crate::provider::CryptoProvider,
        algorithm: SignatureAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>, SigningKeyError> {
        if algorithm != self.algorithm() {
            return self.sign_with_provider_context(
                _provider,
                algorithm,
                &super::SignatureContext::default(),
                message,
            );
        }
        // RFC 8032 sections 5.1.6 and 5.2.6 hash internally with different
        // domain separation: https://www.rfc-editor.org/rfc/rfc8032.html#section-5
        // This callback is the opaque key primitive, invoked by CryptoProvider.
        Ok(match &self.0 {
            EdDsaPrivateKey::Ed25519(key) => {
                use signature::Signer;
                key.sign(message).to_bytes().to_vec()
            }
            EdDsaPrivateKey::Ed448(key) => key.sign_raw(message).to_bytes().to_vec(),
        })
    }

    fn public_key_info(&self) -> Result<SigningPublicKeyInfo, SigningKeyError> {
        let public = match &self.0 {
            EdDsaPrivateKey::Ed25519(key) => key.verifying_key().to_public_key_der(),
            EdDsaPrivateKey::Ed448(key) => key.verifying_key().to_public_key_der(),
        }
        .map_err(|_| SigningKeyError::PublicKeyEncodingFailed)?;
        Ok(SigningPublicKeyInfo::EdDsa {
            algorithm: self.algorithm(),
            spki_der: public.into_vec(),
        })
    }
}

pub(crate) fn validate_public_key(
    algorithm: SignatureAlgorithm,
    der: &[u8],
) -> Result<(), super::SignatureVerificationError> {
    if let SignatureAlgorithm::PostQuantum(algorithm) = algorithm {
        #[cfg(feature = "experimental-pq")]
        {
            return super::post_quantum::validate_public_key(algorithm, der);
        }
        #[cfg(not(feature = "experimental-pq"))]
        {
            return Err(super::SignatureVerificationError::UnsupportedAlgorithm {
                uri: algorithm.uri().to_owned(),
            });
        }
    }
    match algorithm.eddsa_key_algorithm() {
        Some(SignatureAlgorithm::Ed25519) => {
            ed25519_dalek::VerifyingKey::from_public_key_der(der).map(|_| ())
        }
        Some(SignatureAlgorithm::Ed448) => {
            ed448_goldilocks::VerifyingKey::from_public_key_der(der).map(|_| ())
        }
        _ => {
            return Err(super::SignatureVerificationError::UnsupportedAlgorithm {
                uri: algorithm.uri().to_owned(),
            });
        }
    }
    .map_err(|_| super::SignatureVerificationError::InvalidKeyDer)
}

pub(crate) fn verify(
    algorithm: SignatureAlgorithm,
    der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, super::SignatureVerificationError> {
    verify_with_context(
        algorithm,
        der,
        &super::SignatureContext::default(),
        message,
        signature,
    )
}

pub(crate) fn verify_with_context(
    algorithm: SignatureAlgorithm,
    der: &[u8],
    context: &super::SignatureContext,
    message: &[u8],
    signature: &[u8],
) -> Result<bool, super::SignatureVerificationError> {
    use super::SignatureVerificationError as Error;
    if let SignatureAlgorithm::PostQuantum(algorithm) = algorithm {
        #[cfg(feature = "experimental-pq")]
        {
            return super::post_quantum::verify(algorithm, der, context, message, signature);
        }
        #[cfg(not(feature = "experimental-pq"))]
        {
            return Err(Error::UnsupportedAlgorithm {
                uri: algorithm.uri().to_owned(),
            });
        }
    }
    match algorithm {
        SignatureAlgorithm::Ed25519
        | SignatureAlgorithm::Ed25519Ctx
        | SignatureAlgorithm::Ed25519Ph => {
            let key = ed25519_dalek::VerifyingKey::from_public_key_der(der)
                .map_err(|_| Error::InvalidKeyDer)?;
            let signature = ed25519_dalek::Signature::try_from(signature)
                .map_err(|_| Error::InvalidSignatureFormat)?;
            Ok(match algorithm {
                SignatureAlgorithm::Ed25519 if context.as_bytes().is_empty() => {
                    key.verify_strict(message, &signature).is_ok()
                }
                SignatureAlgorithm::Ed25519Ctx => {
                    verify_ed25519ctx(&key, context, message, &signature)
                }
                SignatureAlgorithm::Ed25519Ph => {
                    use sha2::Digest;
                    key.verify_prehashed_strict(
                        sha2::Sha512::new_with_prefix(message),
                        Some(context.as_bytes()),
                        &signature,
                    )
                    .is_ok()
                }
                _ => {
                    return Err(Error::UnsupportedAlgorithm {
                        uri: algorithm.uri().to_owned(),
                    });
                }
            })
        }
        SignatureAlgorithm::Ed448 | SignatureAlgorithm::Ed448Ph => {
            let key = ed448_goldilocks::VerifyingKey::from_public_key_der(der)
                .map_err(|_| Error::InvalidKeyDer)?;
            let signature = ed448_goldilocks::Signature::try_from(signature)
                .map_err(|_| Error::InvalidSignatureFormat)?;
            Ok(if algorithm == SignatureAlgorithm::Ed448 {
                key.verify_ctx(&signature, context.as_bytes(), message)
                    .is_ok()
            } else {
                use ed448_goldilocks::{PreHasherXof, shake::Shake256};
                key.verify_prehashed::<PreHasherXof<Shake256>>(
                    &signature,
                    Some(context.as_bytes()),
                    Shake256::default().chain(message).into(),
                )
                .is_ok()
            })
        }
        _ => Err(Error::UnsupportedAlgorithm {
            uri: algorithm.uri().to_owned(),
        }),
    }
}

fn ed25519ctx_hash(context: &super::SignatureContext) -> sha2::Sha512 {
    use sha2::Digest;
    // RFC 8032 sections 2 and 5.1.6: dom2(0, C) precedes both nonce
    // and challenge hashes, never the private-key expansion hash.
    // https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.6
    sha2::Sha512::new_with_prefix(b"SigEd25519 no Ed25519 collisions")
        .chain_update([0, context.as_bytes().len() as u8])
        .chain_update(context.as_bytes())
}

fn sign_ed25519ctx(
    key: &ed25519_dalek::SigningKey,
    context: &super::SignatureContext,
    message: &[u8],
) -> ed25519_dalek::Signature {
    use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};
    use sha2::Digest;
    use zeroize::Zeroizing;
    let expansion = Zeroizing::new(<[u8; 64]>::from(sha2::Sha512::digest(key.as_bytes())));
    let secret = ed25519_dalek::hazmat::ExpandedSecretKey::from_bytes(&expansion);
    let nonce_hash = Zeroizing::new(<[u8; 64]>::from(
        ed25519ctx_hash(context)
            .chain_update(secret.hash_prefix)
            .chain_update(message)
            .finalize(),
    ));
    let nonce = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&nonce_hash));
    let r = EdwardsPoint::mul_base(&nonce).compress().to_bytes();
    let challenge = Scalar::from_bytes_mod_order_wide(
        &ed25519ctx_hash(context)
            .chain_update(r)
            .chain_update(key.verifying_key().as_bytes())
            .chain_update(message)
            .finalize()
            .into(),
    );
    let s = Zeroizing::new(*nonce + challenge * secret.scalar);
    ed25519_dalek::Signature::from_components(r, s.to_bytes())
}

fn verify_ed25519ctx(
    key: &ed25519_dalek::VerifyingKey,
    context: &super::SignatureContext,
    message: &[u8],
    signature: &ed25519_dalek::Signature,
) -> bool {
    use curve25519_dalek::{
        edwards::{CompressedEdwardsY, EdwardsPoint},
        scalar::Scalar,
    };
    use sha2::Digest;
    let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(*signature.s_bytes())) else {
        return false;
    };
    let encoded_r = CompressedEdwardsY(*signature.r_bytes());
    let Some(r) = encoded_r.decompress() else {
        return false;
    };
    // RFC 8032 section 5.1.7 permits the uncofactored equation. Additionally
    // reject small-order points, matching the existing strict Ed25519 key API.
    // https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.7
    if key.is_weak() || r.is_small_order() || r.compress() != encoded_r {
        return false;
    }
    let challenge = Scalar::from_bytes_mod_order_wide(
        &ed25519ctx_hash(context)
            .chain_update(signature.r_bytes())
            .chain_update(key.as_bytes())
            .chain_update(message)
            .finalize()
            .into(),
    );
    EdwardsPoint::vartime_double_scalar_mul_basepoint(&challenge, &(-key.to_edwards()), &s)
        .compress()
        == encoded_r
}
