//! Safe AWS-LC FIPS dispatch. Unsupported mechanisms never use another engine.

use aws_lc_rs::encoding::{AsDer as _, PublicKeyX509Der};
#[cfg(feature = "xmlenc")]
use aws_lc_rs::key_wrap::KeyWrap as _;
use aws_lc_rs::rand::SecureRandom as _;
use aws_lc_rs::signature::KeyPair as _;
#[cfg(feature = "xmlenc")]
use aws_lc_rs::{aead, cipher, key_wrap};
use aws_lc_rs::{digest, rand, signature};

#[cfg(feature = "xmlenc")]
use super::ProviderInputError;
use super::{CryptoProvider, KdfParameters, ProviderCapability, ProviderError};
use crate::xmldsig::{
    DigestAlgorithm, DsigError, SignatureAlgorithm, SigningKey, SigningKeyError, VerifyingKey,
};
#[cfg(feature = "xmlenc")]
use crate::xmlenc::{DataEncryptionAlgorithm, KeyWrapAlgorithm, RsaOaepParameters};

/// Optional native provider linked exclusively to the AWS-LC FIPS module.
///
/// Mechanism availability is not policy permission or a certification claim.
/// The operation's immutable policy still decides whether an algorithm is allowed.
#[derive(Debug, Clone, Copy, Default)]
pub struct AwsLcFipsProvider;

impl AwsLcFipsProvider {
    /// Version string of the linked native module, not an application certification.
    #[must_use]
    pub fn module_version(&self) -> &'static str {
        aws_lc_rs::awslc_version()
    }

    /// AWS-LC's reported FIPS module version, without an approved-service claim.
    #[must_use]
    pub fn fips_module_version(&self) -> Option<u32> {
        aws_lc_rs::fips_version()
    }
}

fn digest_algorithm(algorithm: DigestAlgorithm) -> Option<&'static digest::Algorithm> {
    Some(match algorithm {
        #[cfg(feature = "legacy-algorithms")]
        DigestAlgorithm::Md5 | DigestAlgorithm::Ripemd160 => return None,
        DigestAlgorithm::Sha1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
        DigestAlgorithm::Sha224 => &digest::SHA224,
        DigestAlgorithm::Sha256 => &digest::SHA256,
        DigestAlgorithm::Sha384 => &digest::SHA384,
        DigestAlgorithm::Sha512 => &digest::SHA512,
        DigestAlgorithm::Sha3_256 => &digest::SHA3_256,
        DigestAlgorithm::Sha3_384 => &digest::SHA3_384,
        DigestAlgorithm::Sha3_512 => &digest::SHA3_512,
        DigestAlgorithm::Sha3_224 => return None,
    })
}

struct AwsLcDigest(digest::Context);

impl super::DigestState for AwsLcDigest {
    fn update(&mut self, data: &[u8]) -> Result<(), ProviderError> {
        self.0.update(data);
        Ok(())
    }

    fn finalize(self: Box<Self>) -> Result<Vec<u8>, ProviderError> {
        Ok(self.0.finish().as_ref().to_vec())
    }
}

fn unsupported(capability: ProviderCapability<'_>) -> ProviderError {
    ProviderError::Unsupported {
        operation: capability.operation(),
        algorithm: capability.algorithm().map(str::to_owned),
    }
}

#[cfg(feature = "xmlenc")]
fn initialization(primitive: &'static str) -> ProviderError {
    ProviderError::InvalidInput(ProviderInputError::PrimitiveInitialization(primitive))
}

fn verify_leaf(
    key: &dyn VerifyingKey,
    algorithm: SignatureAlgorithm,
    data: &[u8],
    signature_value: &[u8],
) -> Result<bool, DsigError> {
    let spki = key
        .verification_spki(algorithm)?
        .ok_or_else(|| verification_unsupported(algorithm))?;
    if !key.validate_signature_value(algorithm, signature_value)? {
        return Ok(false);
    }
    let native = verification_algorithm(algorithm, spki, key.ecdsa_encoding())?;
    if let Some(parameters) = algorithm.rsa_pss_parameters() {
        let encoded = super::rsa_pss::encoded_public_key(spki, parameters)
            .ok_or(crate::xmldsig::SignatureVerificationError::InvalidKeyDer)?;
        return Ok(signature::UnparsedPublicKey::new(native, encoded)
            .verify(data, signature_value)
            .is_ok());
    }
    let public = signature::ParsedPublicKey::new(native, spki)
        .map_err(|_| crate::xmldsig::SignatureVerificationError::InvalidKeyDer)?;
    Ok(public.verify_sig(data, signature_value).is_ok())
}

impl CryptoProvider for AwsLcFipsProvider {
    fn verify_with_key_receipt(
        &self,
        key: &dyn VerifyingKey,
        input: super::SignatureVerificationInput<'_>,
        observer: &mut dyn FnMut(super::KeyVerificationEvent<'_>) -> Result<(), DsigError>,
    ) -> Result<bool, DsigError> {
        if !input.context.as_bytes().is_empty() {
            return Err(verification_unsupported(input.algorithm).into());
        }
        self.require_capability(ProviderCapability::Verify(input.algorithm))?;
        super::key_association::observed_leaf(key, observer, &|key| {
            verify_leaf(key, input.algorithm, input.data, input.signature)
        })
    }

    fn associate_verification_key(
        &self,
        actual: &[u8],
        expected: structured_pkix::path::WorkingKey<'_>,
        charge: &dyn Fn(u64) -> Result<(), structured_asn1::memory::MemoryError>,
    ) -> Result<super::KeyAssociation, DsigError> {
        // The official safe AWS API does not expose general parsed-point
        // equality. Unsupported aliases stay Unproven, without software fallback.
        super::key_association::compare(actual, expected, charge)
    }
    fn name(&self) -> &'static str {
        "aws-lc-fips"
    }

    fn import_signing_key(
        &self,
        algorithm: SignatureAlgorithm,
        der: &[u8],
    ) -> Result<Box<dyn SigningKey>, SigningKeyError> {
        Ok(Box::new(AwsLcSigningKey::from_pkcs8_der(algorithm, der)?))
    }

    #[cfg(feature = "xmlenc")]
    fn import_recovery_key(
        &self,
        pkcs8: &[u8],
    ) -> Result<std::sync::Arc<dyn super::KeyRecoveryKey>, ProviderError> {
        Ok(std::sync::Arc::new(AwsLcRsaPrivateKey::from_pkcs8_der(
            pkcs8,
        )?))
    }

    fn supports(&self, capability: ProviderCapability<'_>) -> bool {
        match capability {
            ProviderCapability::Digest(algorithm) => digest_algorithm(algorithm).is_some(),
            ProviderCapability::Random => true,
            ProviderCapability::Sign(algorithm) => signing_supported(algorithm),
            ProviderCapability::Verify(algorithm) => {
                signing_supported(algorithm) || algorithm == SignatureAlgorithm::RsaSha1
            }
            ProviderCapability::VerifyCertificate(algorithm) => {
                certificate_method(algorithm).is_some()
            }
            #[cfg(feature = "xmlenc")]
            ProviderCapability::Encrypt(algorithm) | ProviderCapability::Decrypt(algorithm) => {
                matches!(
                    algorithm,
                    DataEncryptionAlgorithm::Aes128Cbc
                        | DataEncryptionAlgorithm::Aes256Cbc
                        | DataEncryptionAlgorithm::Aes128Gcm
                        | DataEncryptionAlgorithm::Aes256Gcm
                )
            }
            #[cfg(feature = "xmlenc")]
            ProviderCapability::KeyWrap(algorithm) | ProviderCapability::KeyUnwrap(algorithm) => {
                matches!(
                    algorithm,
                    KeyWrapAlgorithm::AesKw128 | KeyWrapAlgorithm::AesKw256
                )
            }
            #[cfg(feature = "xmlenc")]
            ProviderCapability::KeyTransport(parameters)
            | ProviderCapability::KeyRecovery(parameters) => oaep_algorithm(parameters).is_some(),
            _ => false,
        }
    }

    fn fill_random(&self, output: &mut [u8]) -> Result<(), ProviderError> {
        rand::SystemRandom::new()
            .fill(output)
            .map_err(|_| ProviderError::Random("AWS-LC random generation failed".into()))
    }

    fn begin_digest(
        &self,
        algorithm: DigestAlgorithm,
    ) -> Result<Box<dyn super::DigestState + '_>, ProviderError> {
        let native = digest_algorithm(algorithm)
            .ok_or_else(|| unsupported(ProviderCapability::Digest(algorithm)))?;
        Ok(Box::new(AwsLcDigest(digest::Context::new(native))))
    }

    fn sign(
        &self,
        key: &dyn SigningKey,
        algorithm: SignatureAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>, SigningKeyError> {
        self.require_capability(ProviderCapability::Sign(algorithm))?;
        if key.provider_name() != Some(self.name()) {
            return Err(unsupported(ProviderCapability::Sign(algorithm)).into());
        }
        key.sign_with_provider(self, algorithm, data)
    }

    fn verify(
        &self,
        key: &dyn VerifyingKey,
        algorithm: SignatureAlgorithm,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, DsigError> {
        if !self.supports(ProviderCapability::Verify(algorithm)) {
            return Err(verification_unsupported(algorithm).into());
        }
        super::key_association::observed_leaf(key, &mut |_| Ok(()), &|key| {
            verify_leaf(key, algorithm, data, signature)
        })
    }

    fn verify_x509_signature(
        &self,
        algorithm: super::X509SignatureAlgorithm,
        data: &[u8],
        signature: &[u8],
        issuer_spki: &[u8],
    ) -> Result<bool, ProviderError> {
        let method = certificate_method(algorithm)
            .ok_or_else(|| unsupported(ProviderCapability::VerifyCertificate(algorithm)))?;
        // RFC 5758 §3.2: ECDSA certificate signatures use DER, independently
        // of the XMLDSig operation's SignatureValue compatibility encoding.
        // https://www.rfc-editor.org/rfc/rfc5758#section-3.2
        let native = match verification_algorithm(
            method,
            issuer_spki,
            crate::policy::EcdsaSignatureValueEncoding::XmlSecAsn1Der,
        ) {
            Ok(native) => native,
            Err(crate::xmldsig::SignatureVerificationError::UnsupportedAlgorithm { .. }) => {
                return Err(unsupported(ProviderCapability::VerifyCertificate(
                    algorithm,
                )));
            }
            Err(_) => return Ok(false),
        };
        let Ok(public) = signature::ParsedPublicKey::new(native, issuer_spki) else {
            return Ok(false);
        };
        Ok(public.verify_sig(data, signature).is_ok())
    }

    #[cfg(feature = "xmlenc")]
    fn encrypt_data(
        &self,
        algorithm: DataEncryptionAlgorithm,
        key: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        self.require_capability(ProviderCapability::Encrypt(algorithm))?;
        check_key(algorithm.key_len(), key)?;
        match algorithm {
            DataEncryptionAlgorithm::Camellia128Cbc
            | DataEncryptionAlgorithm::Camellia192Cbc
            | DataEncryptionAlgorithm::Camellia256Cbc
            | DataEncryptionAlgorithm::ChaCha20
            | DataEncryptionAlgorithm::ChaCha20Poly1305 => {
                Err(unsupported(ProviderCapability::Encrypt(algorithm)))
            }
            #[cfg(feature = "legacy-algorithms")]
            DataEncryptionAlgorithm::TripleDesCbc
            | DataEncryptionAlgorithm::Aes192Cbc
            | DataEncryptionAlgorithm::Aes192Gcm => {
                Err(unsupported(ProviderCapability::Encrypt(algorithm)))
            }
            DataEncryptionAlgorithm::Aes128Cbc | DataEncryptionAlgorithm::Aes256Cbc => {
                let padding = 16 - plaintext.len() % 16;
                let mut output = vec![0; framed_len(plaintext.len(), 16 + padding)?];
                output[16..16 + plaintext.len()].copy_from_slice(plaintext);
                let last = output.len() - 1;
                self.fill_random(&mut output[16 + plaintext.len()..last])?;
                output[last] = u8::try_from(padding).expect("AES block padding is at most 16");
                // XMLEnc 1.1 §5.2.1 permits arbitrary padding octets except the
                // final length octet; PKCS#7 padding would change that contract.
                // https://www.w3.org/TR/xmlenc-core1/#sec-Block-Encryption
                let encryption = cipher::EncryptingKey::cbc(
                    cipher::UnboundCipherKey::new(cbc_algorithm(algorithm), key)
                        .map_err(|_| initialization("AES-CBC"))?,
                )
                .map_err(|_| initialization("AES-CBC"))?;
                let context = encryption
                    .encrypt(&mut output[16..])
                    .map_err(|_| initialization("AES-CBC"))?;
                let iv: &[u8] = (&context)
                    .try_into()
                    .map_err(|_| initialization("AES-CBC IV"))?;
                output[..16].copy_from_slice(iv);
                Ok(output)
            }
            DataEncryptionAlgorithm::Aes128Gcm | DataEncryptionAlgorithm::Aes256Gcm => {
                let mut nonce = [0; 12];
                self.fill_random(&mut nonce)?;
                let encryption = aead_key(algorithm, key)?;
                let mut output = Vec::with_capacity(framed_len(plaintext.len(), 28)?);
                output.extend_from_slice(&nonce);
                output.extend_from_slice(plaintext);
                let tag = encryption
                    .seal_in_place_separate_tag(
                        aead::Nonce::assume_unique_for_key(nonce),
                        aead::Aad::empty(),
                        &mut output[12..],
                    )
                    .map_err(|_| ProviderError::AuthenticationFailed)?;
                output.extend_from_slice(tag.as_ref());
                Ok(output)
            }
        }
    }

    #[cfg(feature = "xmlenc")]
    fn decrypt_data(
        &self,
        algorithm: DataEncryptionAlgorithm,
        key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        self.require_capability(ProviderCapability::Decrypt(algorithm))?;
        check_key(algorithm.key_len(), key)?;
        match algorithm {
            DataEncryptionAlgorithm::Camellia128Cbc
            | DataEncryptionAlgorithm::Camellia192Cbc
            | DataEncryptionAlgorithm::Camellia256Cbc
            | DataEncryptionAlgorithm::ChaCha20
            | DataEncryptionAlgorithm::ChaCha20Poly1305 => {
                Err(unsupported(ProviderCapability::Decrypt(algorithm)))
            }
            #[cfg(feature = "legacy-algorithms")]
            DataEncryptionAlgorithm::TripleDesCbc
            | DataEncryptionAlgorithm::Aes192Cbc
            | DataEncryptionAlgorithm::Aes192Gcm => {
                Err(unsupported(ProviderCapability::Decrypt(algorithm)))
            }
            DataEncryptionAlgorithm::Aes128Cbc | DataEncryptionAlgorithm::Aes256Cbc => {
                if ciphertext.len() < 32 || !ciphertext.len().is_multiple_of(16) {
                    return Err(ProviderError::InvalidInput(
                        ProviderInputError::AesCbcFraming,
                    ));
                }
                let mut plaintext = ciphertext[16..].to_vec();
                let iv = aws_lc_rs::iv::FixedLength::try_from(&ciphertext[..16])
                    .map_err(|_| initialization("AES-CBC IV"))?;
                cipher::DecryptingKey::cbc(
                    cipher::UnboundCipherKey::new(cbc_algorithm(algorithm), key)
                        .map_err(|_| initialization("AES-CBC"))?,
                )
                .map_err(|_| initialization("AES-CBC"))?
                .decrypt(&mut plaintext, cipher::DecryptionContext::Iv128(iv))
                .map_err(|_| ProviderError::InvalidInput(ProviderInputError::AesCbcCiphertext))?;
                let padding = usize::from(plaintext[plaintext.len() - 1]);
                if !(1..=16).contains(&padding) {
                    return Err(ProviderError::InvalidInput(
                        ProviderInputError::AesCbcCiphertext,
                    ));
                }
                plaintext.truncate(plaintext.len() - padding);
                Ok(plaintext)
            }
            DataEncryptionAlgorithm::Aes128Gcm | DataEncryptionAlgorithm::Aes256Gcm => {
                if ciphertext.len() < 28 {
                    return Err(ProviderError::InvalidInput(
                        ProviderInputError::AesGcmFraming,
                    ));
                }
                let mut nonce = [0; 12];
                nonce.copy_from_slice(&ciphertext[..12]);
                let mut plaintext = ciphertext[12..].to_vec();
                let len = aead_key(algorithm, key)?
                    .open_in_place(
                        aead::Nonce::assume_unique_for_key(nonce),
                        aead::Aad::empty(),
                        &mut plaintext,
                    )
                    .map_err(|_| ProviderError::AuthenticationFailed)?
                    .len();
                plaintext.truncate(len);
                Ok(plaintext)
            }
        }
    }

    #[cfg(feature = "xmlenc")]
    fn wrap_key(
        &self,
        algorithm: KeyWrapAlgorithm,
        kek: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        self.require_capability(ProviderCapability::KeyWrap(algorithm))?;
        check_key(algorithm.key_len(), kek)?;
        if key.len() < 16 || !key.len().is_multiple_of(8) || key.len() > i32::MAX as usize - 8 {
            return Err(ProviderError::InvalidInput(
                ProviderInputError::AesKeyWrapFraming,
            ));
        }
        let mut output = vec![0; key.len() + 8];
        wrapping_key(algorithm, kek)?
            .wrap(key, &mut output)
            .map_err(|_| ProviderError::InvalidInput(ProviderInputError::AesKeyWrapFraming))?;
        Ok(output)
    }

    #[cfg(feature = "xmlenc")]
    fn unwrap_key(
        &self,
        algorithm: KeyWrapAlgorithm,
        kek: &[u8],
        wrapped: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        self.require_capability(ProviderCapability::KeyUnwrap(algorithm))?;
        check_key(algorithm.key_len(), kek)?;
        if wrapped.len() < 24
            || !wrapped.len().is_multiple_of(8)
            || wrapped.len() > i32::MAX as usize
        {
            return Err(ProviderError::InvalidInput(
                ProviderInputError::AesKeyWrapFraming,
            ));
        }
        let mut output = vec![0; wrapped.len() - 8];
        wrapping_key(algorithm, kek)?
            .unwrap(wrapped, &mut output)
            .map_err(|_| ProviderError::AuthenticationFailed)?;
        Ok(output)
    }

    #[cfg(feature = "xmlenc")]
    fn transport_key(
        &self,
        key: &dyn super::KeyTransportKey,
        parameters: &RsaOaepParameters,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        use der::Encode as _;
        self.require_capability(ProviderCapability::KeyTransport(parameters))?;
        let modulus = key.rsa_modulus();
        let exponent = key.rsa_exponent();
        let public = pkcs1::RsaPublicKeyRef {
            modulus: der::asn1::UintRef::new(&modulus)
                .map_err(|_| initialization("RSA public key"))?,
            public_exponent: der::asn1::UintRef::new(&exponent)
                .map_err(|_| initialization("RSA public key"))?,
        }
        .to_der()
        .map_err(|_| initialization("RSA public key"))?;
        let spki = pkcs8::SubjectPublicKeyInfoRef {
            algorithm: pkcs8::AlgorithmIdentifierRef {
                oid: pkcs1::ALGORITHM_OID,
                parameters: Some(der::asn1::AnyRef::NULL),
            },
            subject_public_key: der::asn1::BitStringRef::new(0, &public)
                .map_err(|_| initialization("RSA public key"))?,
        }
        .to_der()
        .map_err(|_| initialization("RSA public key"))?;
        let key = aws_lc_rs::rsa::OaepPublicEncryptingKey::new(
            aws_lc_rs::rsa::PublicEncryptingKey::from_der(&spki)
                .map_err(|_| initialization("RSA-OAEP"))?,
        )
        .map_err(|_| initialization("RSA-OAEP"))?;
        let mut output = vec![0; key.ciphertext_size()];
        key.encrypt(
            oaep_algorithm(parameters).expect("capability checked"),
            plaintext,
            &mut output,
            Some(&parameters.label),
        )
        .map_err(|_| initialization("RSA-OAEP plaintext"))?;
        Ok(output)
    }

    #[cfg(feature = "xmlenc")]
    fn recover_key(
        &self,
        key: &dyn super::KeyRecoveryKey,
        parameters: &RsaOaepParameters,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        self.require_capability(ProviderCapability::KeyRecovery(parameters))?;
        if key.provider_name() != Some(self.name()) {
            return Err(unsupported(ProviderCapability::KeyRecovery(parameters)));
        }
        key.recover_with_provider(self, parameters, ciphertext)
    }

    fn derive_key(
        &self,
        parameters: &KdfParameters<'_>,
        _secret: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        Err(unsupported(ProviderCapability::Kdf(parameters)))
    }
}

#[cfg(feature = "xmlenc")]
fn check_key(expected: usize, key: &[u8]) -> Result<(), ProviderError> {
    if key.len() != expected {
        return Err(ProviderError::InvalidKeySize {
            expected,
            actual: key.len(),
        });
    }
    Ok(())
}

#[cfg(feature = "xmlenc")]
fn framed_len(input: usize, overhead: usize) -> Result<usize, ProviderError> {
    input
        .checked_add(overhead)
        .filter(|len| isize::try_from(*len).is_ok())
        .ok_or_else(|| initialization("ciphertext length"))
}

#[cfg(feature = "xmlenc")]
fn cbc_algorithm(algorithm: DataEncryptionAlgorithm) -> &'static cipher::Algorithm {
    match algorithm {
        DataEncryptionAlgorithm::Aes128Cbc => &cipher::AES_128,
        DataEncryptionAlgorithm::Aes256Cbc => &cipher::AES_256,
        _ => unreachable!("CBC branch selected"),
    }
}

#[cfg(feature = "xmlenc")]
fn aead_key(
    algorithm: DataEncryptionAlgorithm,
    key: &[u8],
) -> Result<aead::LessSafeKey, ProviderError> {
    let algorithm = match algorithm {
        DataEncryptionAlgorithm::Aes128Gcm => &aead::AES_128_GCM,
        DataEncryptionAlgorithm::Aes256Gcm => &aead::AES_256_GCM,
        _ => unreachable!("GCM branch selected"),
    };
    Ok(aead::LessSafeKey::new(
        aead::UnboundKey::new(algorithm, key).map_err(|_| initialization("AES-GCM"))?,
    ))
}

#[cfg(feature = "xmlenc")]
fn wrapping_key(
    algorithm: KeyWrapAlgorithm,
    kek: &[u8],
) -> Result<key_wrap::KeyEncryptionKey<key_wrap::AesBlockCipher>, ProviderError> {
    let cipher = match algorithm {
        KeyWrapAlgorithm::CamelliaKw128
        | KeyWrapAlgorithm::CamelliaKw192
        | KeyWrapAlgorithm::CamelliaKw256
        | KeyWrapAlgorithm::Cbc(_) => {
            return Err(unsupported(ProviderCapability::KeyWrap(algorithm)));
        }
        #[cfg(feature = "legacy-algorithms")]
        KeyWrapAlgorithm::AesKw192 | KeyWrapAlgorithm::TripleDes => {
            return Err(unsupported(ProviderCapability::KeyWrap(algorithm)));
        }
        KeyWrapAlgorithm::AesKw128 => &key_wrap::AES_128,
        KeyWrapAlgorithm::AesKw256 => &key_wrap::AES_256,
    };
    key_wrap::KeyEncryptionKey::new(cipher, kek).map_err(|_| initialization("AES key wrap"))
}

fn signing_supported(algorithm: SignatureAlgorithm) -> bool {
    if let Some(digest) = native_pss_digest(algorithm) {
        return matches!(
            digest,
            DigestAlgorithm::Sha256 | DigestAlgorithm::Sha384 | DigestAlgorithm::Sha512
        );
    }
    matches!(
        algorithm,
        SignatureAlgorithm::RsaSha256
            | SignatureAlgorithm::RsaSha384
            | SignatureAlgorithm::RsaSha512
            | SignatureAlgorithm::EcdsaSha224
            | SignatureAlgorithm::EcdsaSha256
            | SignatureAlgorithm::EcdsaSha384
            | SignatureAlgorithm::EcdsaSha512
            | SignatureAlgorithm::EcdsaSha3_384
            | SignatureAlgorithm::EcdsaSha3_512
    )
}

fn native_pss_digest(algorithm: SignatureAlgorithm) -> Option<DigestAlgorithm> {
    let parameters = algorithm.rsa_pss_parameters()?;
    // AWS-LC's high-level PSS encodings require matching MGF1 and digest-sized salt.
    // This is a provider capability restriction, not an XMLDSig policy default.
    (parameters.digest == parameters.mgf_digest
        && parameters.salt_len == parameters.digest.output_len())
    .then_some(parameters.digest)
}

fn certificate_method(algorithm: super::X509SignatureAlgorithm) -> Option<SignatureAlgorithm> {
    use super::X509SignatureAlgorithm as X;
    use DigestAlgorithm as D;
    use SignatureAlgorithm as A;
    Some(match algorithm {
        X::RsaPkcs1v15(D::Sha1) => A::RsaSha1,
        X::RsaPkcs1v15(D::Sha256) => A::RsaSha256,
        X::RsaPkcs1v15(D::Sha384) => A::RsaSha384,
        X::RsaPkcs1v15(D::Sha512) => A::RsaSha512,
        X::Ecdsa(D::Sha224) => A::EcdsaSha224,
        X::Ecdsa(D::Sha256) => A::EcdsaSha256,
        X::Ecdsa(D::Sha384) => A::EcdsaSha384,
        X::Ecdsa(D::Sha512) => A::EcdsaSha512,
        X::Ecdsa(D::Sha3_384) => A::EcdsaSha3_384,
        X::Ecdsa(D::Sha3_512) => A::EcdsaSha3_512,
        _ => return None,
    })
}

fn verification_unsupported(
    algorithm: SignatureAlgorithm,
) -> crate::xmldsig::SignatureVerificationError {
    crate::xmldsig::SignatureVerificationError::UnsupportedAlgorithm {
        uri: algorithm.uri().into(),
    }
}

fn curve_oid_name(bytes: &[u8]) -> Option<&'static str> {
    match bytes {
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] => Some("1.2.840.10045.3.1.7"),
        [0x2b, 0x81, 0x04, 0x00, 0x22] => Some("1.3.132.0.34"),
        [0x2b, 0x81, 0x04, 0x00, 0x23] => Some("1.3.132.0.35"),
        _ => None,
    }
}

fn spki_curve(spki: &[u8]) -> Result<&'static str, crate::xmldsig::SignatureVerificationError> {
    use crate::xmldsig::pkix::PublicKey;
    use structured_pkix::key::ec::Curve;
    let session =
        crate::xmldsig::pkix::CertificateSession::new(&crate::policy::ResourcePolicy::default());
    match session.read_public_key(spki) {
        Ok(PublicKey::Ec(key)) => match key.curve() {
            Curve::Named(oid) => curve_oid_name(oid.as_bytes()),
            Curve::Implicit | Curve::Specified(_) => None,
        },
        Ok(PublicKey::Rsa(_)) | Err(_) => None,
    }
    .ok_or(crate::xmldsig::SignatureVerificationError::InvalidKeyDer)
}

fn verification_algorithm(
    algorithm: SignatureAlgorithm,
    spki: &[u8],
    encoding: crate::policy::EcdsaSignatureValueEncoding,
) -> Result<&'static dyn signature::VerificationAlgorithm, crate::xmldsig::SignatureVerificationError>
{
    use SignatureAlgorithm as A;
    use signature::{
        ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_FIXED, ECDSA_P384_SHA3_384_ASN1,
        ECDSA_P384_SHA3_384_FIXED, ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_FIXED,
        ECDSA_P521_SHA3_512_ASN1, ECDSA_P521_SHA3_512_FIXED, ECDSA_P521_SHA224_ASN1,
        ECDSA_P521_SHA224_FIXED, ECDSA_P521_SHA256_ASN1, ECDSA_P521_SHA256_FIXED,
        ECDSA_P521_SHA384_ASN1, ECDSA_P521_SHA384_FIXED, ECDSA_P521_SHA512_ASN1,
        ECDSA_P521_SHA512_FIXED, RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
        RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
        RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA384, RSA_PSS_2048_8192_SHA512,
        RsaParameters,
    };
    let rsa: Option<&'static RsaParameters> = match (algorithm, native_pss_digest(algorithm)) {
        (_, Some(DigestAlgorithm::Sha256)) => Some(&RSA_PSS_2048_8192_SHA256),
        (_, Some(DigestAlgorithm::Sha384)) => Some(&RSA_PSS_2048_8192_SHA384),
        (_, Some(DigestAlgorithm::Sha512)) => Some(&RSA_PSS_2048_8192_SHA512),
        (A::RsaSha1, _) => Some(&RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY),
        (A::RsaSha256, _) => Some(&RSA_PKCS1_2048_8192_SHA256),
        (A::RsaSha384, _) => Some(&RSA_PKCS1_2048_8192_SHA384),
        (A::RsaSha512, _) => Some(&RSA_PKCS1_2048_8192_SHA512),
        _ => None,
    };
    if let Some(rsa) = rsa {
        let session = crate::xmldsig::pkix::CertificateSession::new(
            &crate::policy::ResourcePolicy::default(),
        );
        let modulus = session
            .rsa_public_key(spki, algorithm.rsa_pss_parameters())
            .ok_or(crate::xmldsig::SignatureVerificationError::InvalidKeyDer)?
            .modulus();
        // These are the selected native verifier's capabilities, not strength
        // policy. AWS-LC defers this check until verify_sig and uses the same
        // error for a size it cannot handle and a bad signature; distinguish
        // them before dispatch without allocating a native key or bigint.
        // https://docs.rs/aws-lc-rs/1.18.1/aws_lc_rs/signature/struct.RsaParameters.html
        let bits = modulus.bits();
        if bits < u64::from(rsa.min_modulus_len()) || bits > u64::from(rsa.max_modulus_len()) {
            return Err(verification_unsupported(algorithm));
        }
        return Ok(rsa);
    }
    let curve = spki_curve(spki)?;
    let der = encoding == crate::policy::EcdsaSignatureValueEncoding::XmlSecAsn1Der;
    // XMLDSig 1.1 §6.4.3 uses fixed-width r || s; ASN.1 is an explicit
    // compatibility-policy choice, never inferred from attacker-controlled bytes.
    // https://www.w3.org/TR/xmldsig-core1/#sec-ECDSA
    Ok(match (curve, algorithm, der) {
        ("1.2.840.10045.3.1.7", A::EcdsaSha256, false) => &ECDSA_P256_SHA256_FIXED,
        ("1.2.840.10045.3.1.7", A::EcdsaSha256, true) => &ECDSA_P256_SHA256_ASN1,
        ("1.3.132.0.34", A::EcdsaSha384, false) => &ECDSA_P384_SHA384_FIXED,
        ("1.3.132.0.34", A::EcdsaSha384, true) => &ECDSA_P384_SHA384_ASN1,
        ("1.3.132.0.34", A::EcdsaSha3_384, false) => &ECDSA_P384_SHA3_384_FIXED,
        ("1.3.132.0.34", A::EcdsaSha3_384, true) => &ECDSA_P384_SHA3_384_ASN1,
        ("1.3.132.0.35", A::EcdsaSha224, false) => &ECDSA_P521_SHA224_FIXED,
        ("1.3.132.0.35", A::EcdsaSha224, true) => &ECDSA_P521_SHA224_ASN1,
        ("1.3.132.0.35", A::EcdsaSha256, false) => &ECDSA_P521_SHA256_FIXED,
        ("1.3.132.0.35", A::EcdsaSha256, true) => &ECDSA_P521_SHA256_ASN1,
        ("1.3.132.0.35", A::EcdsaSha384, false) => &ECDSA_P521_SHA384_FIXED,
        ("1.3.132.0.35", A::EcdsaSha384, true) => &ECDSA_P521_SHA384_ASN1,
        ("1.3.132.0.35", A::EcdsaSha512, false) => &ECDSA_P521_SHA512_FIXED,
        ("1.3.132.0.35", A::EcdsaSha512, true) => &ECDSA_P521_SHA512_ASN1,
        ("1.3.132.0.35", A::EcdsaSha3_512, false) => &ECDSA_P521_SHA3_512_FIXED,
        ("1.3.132.0.35", A::EcdsaSha3_512, true) => &ECDSA_P521_SHA3_512_ASN1,
        _ => return Err(verification_unsupported(algorithm)),
    })
}

enum NativeSigningKey {
    Rsa(signature::RsaKeyPair),
    Ec(signature::EcdsaKeyPair),
}

/// Native private signing handle. Only public metadata can be exported.
pub struct AwsLcSigningKey {
    key: NativeSigningKey,
    algorithm: SignatureAlgorithm,
    public: crate::xmldsig::SigningPublicKeyInfo,
}

impl AwsLcSigningKey {
    /// Import an unencrypted PKCS#8 key for one exact `XMLDSig` method.
    ///
    /// # Errors
    /// Returns an unsupported-method error, invalid key/curve encoding, or
    /// failure to encode the imported key's public metadata.
    pub fn from_pkcs8_der(
        algorithm: SignatureAlgorithm,
        der: &[u8],
    ) -> Result<Self, SigningKeyError> {
        use SignatureAlgorithm as A;
        if !signing_supported(algorithm) {
            return Err(SigningKeyError::UnsupportedAlgorithm {
                uri: algorithm.uri().into(),
            });
        }
        let (key, spki) = if algorithm.is_rsa() {
            let key = signature::RsaKeyPair::from_pkcs8(der)
                .map_err(|_| SigningKeyError::InvalidKeyDer)?;
            let spki: PublicKeyX509Der<'static> = key
                .public_key()
                .as_der()
                .map_err(|_| SigningKeyError::PublicKeyEncodingFailed)?;
            (NativeSigningKey::Rsa(key), spki.as_ref().to_vec())
        } else {
            use der::Decode as _;
            let info = pkcs8::PrivateKeyInfoRef::from_der(der)
                .map_err(|_| SigningKeyError::InvalidKeyDer)?;
            let curve = info
                .algorithm
                .parameters
                .and_then(|p| p.decode_as::<der::asn1::ObjectIdentifier>().ok())
                .ok_or(SigningKeyError::InvalidKeyDer)?;
            let curve =
                curve_oid_name(curve.as_bytes()).ok_or(SigningKeyError::UnsupportedAlgorithm {
                    uri: algorithm.uri().into(),
                })?;
            let native = match (curve, algorithm) {
                ("1.2.840.10045.3.1.7", A::EcdsaSha256) => {
                    &signature::ECDSA_P256_SHA256_FIXED_SIGNING
                }
                ("1.3.132.0.34", A::EcdsaSha384) => &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                ("1.3.132.0.34", A::EcdsaSha3_384) => &signature::ECDSA_P384_SHA3_384_FIXED_SIGNING,
                ("1.3.132.0.35", A::EcdsaSha224) => &signature::ECDSA_P521_SHA224_FIXED_SIGNING,
                ("1.3.132.0.35", A::EcdsaSha256) => &signature::ECDSA_P521_SHA256_FIXED_SIGNING,
                ("1.3.132.0.35", A::EcdsaSha384) => &signature::ECDSA_P521_SHA384_FIXED_SIGNING,
                ("1.3.132.0.35", A::EcdsaSha512) => &signature::ECDSA_P521_SHA512_FIXED_SIGNING,
                ("1.3.132.0.35", A::EcdsaSha3_512) => &signature::ECDSA_P521_SHA3_512_FIXED_SIGNING,
                _ => {
                    return Err(SigningKeyError::UnsupportedAlgorithm {
                        uri: algorithm.uri().into(),
                    });
                }
            };
            let key = signature::EcdsaKeyPair::from_pkcs8(native, der)
                .map_err(|_| SigningKeyError::InvalidKeyDer)?;
            let spki: PublicKeyX509Der<'static> = key
                .public_key()
                .as_der()
                .map_err(|_| SigningKeyError::PublicKeyEncodingFailed)?;
            (NativeSigningKey::Ec(key), spki.as_ref().to_vec())
        };
        Ok(Self {
            key,
            algorithm,
            public: signing_public_key_info(spki)?,
        })
    }
}

/// Public metadata of a natively generated SPKI, read by the shared PKIX
/// reader; RSA magnitudes carry no sign octet.
fn signing_public_key_info(
    spki: Vec<u8>,
) -> Result<crate::xmldsig::SigningPublicKeyInfo, SigningKeyError> {
    use crate::xmldsig::pkix::PublicKey;
    enum Components {
        Rsa { modulus: Vec<u8>, exponent: Vec<u8> },
        Ec { point: Vec<u8> },
    }
    let components = {
        let session = crate::xmldsig::pkix::CertificateSession::new(
            &crate::policy::ResourcePolicy::default(),
        );
        match session
            .read_public_key(&spki)
            .map_err(|_| SigningKeyError::InvalidPublicKeyInfo)?
        {
            PublicKey::Rsa(rsa) => Components::Rsa {
                modulus: rsa.modulus().as_bytes().to_vec(),
                exponent: rsa.exponent().as_bytes().to_vec(),
            },
            PublicKey::Ec(ec) => Components::Ec {
                point: ec.as_bytes().to_vec(),
            },
        }
    };
    Ok(match components {
        Components::Rsa { modulus, exponent } => crate::xmldsig::SigningPublicKeyInfo::Rsa {
            modulus,
            exponent,
            spki_der: spki,
        },
        Components::Ec { point } => crate::xmldsig::SigningPublicKeyInfo::Ec {
            curve_oid: spki_curve(&spki).map_err(|_| SigningKeyError::InvalidPublicKeyInfo)?,
            public_key: point,
            spki_der: spki,
        },
    })
}

impl SigningKey for AwsLcSigningKey {
    fn provider_name(&self) -> Option<&'static str> {
        Some("aws-lc-fips")
    }
    fn sign(&self, algorithm: SignatureAlgorithm, data: &[u8]) -> Result<Vec<u8>, SigningKeyError> {
        self.sign_with_provider(&AwsLcFipsProvider, algorithm, data)
    }
    fn sign_with_provider(
        &self,
        provider: &dyn CryptoProvider,
        algorithm: SignatureAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>, SigningKeyError> {
        if provider.name() != "aws-lc-fips" || algorithm != self.algorithm {
            return Err(unsupported(ProviderCapability::Sign(algorithm)).into());
        }
        match &self.key {
            NativeSigningKey::Rsa(key) => {
                let encoding = match (algorithm, native_pss_digest(algorithm)) {
                    (_, Some(DigestAlgorithm::Sha256)) => &signature::RSA_PSS_SHA256,
                    (_, Some(DigestAlgorithm::Sha384)) => &signature::RSA_PSS_SHA384,
                    (_, Some(DigestAlgorithm::Sha512)) => &signature::RSA_PSS_SHA512,
                    (SignatureAlgorithm::RsaSha256, _) => &signature::RSA_PKCS1_SHA256,
                    (SignatureAlgorithm::RsaSha384, _) => &signature::RSA_PKCS1_SHA384,
                    (SignatureAlgorithm::RsaSha512, _) => &signature::RSA_PKCS1_SHA512,
                    _ => {
                        return Err(SigningKeyError::UnsupportedAlgorithm {
                            uri: algorithm.uri().into(),
                        });
                    }
                };
                let mut output = vec![0; key.public_modulus_len()];
                key.sign(encoding, &rand::SystemRandom::new(), data, &mut output)
                    .map_err(|_| SigningKeyError::SigningFailed)?;
                Ok(output)
            }
            NativeSigningKey::Ec(key) => key
                .sign(&rand::SystemRandom::new(), data)
                .map(|signature| signature.as_ref().to_vec())
                .map_err(|_| SigningKeyError::SigningFailed),
        }
    }
    fn public_key_info(&self) -> Result<crate::xmldsig::SigningPublicKeyInfo, SigningKeyError> {
        Ok(self.public.clone())
    }
}

#[cfg(feature = "xmlenc")]
fn oaep_algorithm(
    parameters: &RsaOaepParameters,
) -> Option<&'static aws_lc_rs::rsa::OaepAlgorithm> {
    use crate::xmlenc::OaepDigestAlgorithm as D;
    use aws_lc_rs::rsa::{
        OAEP_SHA1_MGF1SHA1, OAEP_SHA256_MGF1SHA256, OAEP_SHA384_MGF1SHA384, OAEP_SHA512_MGF1SHA512,
    };
    if parameters.digest != parameters.mgf_digest {
        return None;
    }
    Some(match parameters.digest {
        D::Sha1 => &OAEP_SHA1_MGF1SHA1,
        D::Sha256 => &OAEP_SHA256_MGF1SHA256,
        D::Sha384 => &OAEP_SHA384_MGF1SHA384,
        D::Sha512 => &OAEP_SHA512_MGF1SHA512,
        // The selected native API exposes only these four paired hashes.
        // Expanded RustCrypto capability must never trigger a software fallback.
        D::Sha224 | D::Sha3_224 | D::Sha3_256 | D::Sha3_384 | D::Sha3_512 => return None,
        #[cfg(feature = "legacy-algorithms")]
        D::Md5 | D::Ripemd160 => return None,
    })
}

/// Native RSA recovery handle without a private-material export API.
#[cfg(feature = "xmlenc")]
pub struct AwsLcRsaPrivateKey {
    key: aws_lc_rs::rsa::OaepPrivateDecryptingKey,
    modulus_bits: usize,
    exponent: Option<u64>,
    ciphertext_len: usize,
    public_spki: Vec<u8>,
}

#[cfg(feature = "xmlenc")]
impl AwsLcRsaPrivateKey {
    /// Import an unencrypted PKCS#8 RSA private key; retain only public metadata.
    ///
    /// # Errors
    /// Returns a provider initialization error if private-key import, public
    /// metadata decoding/encoding or RSA-OAEP handle construction fails.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, ProviderError> {
        let key = aws_lc_rs::rsa::PrivateDecryptingKey::from_pkcs8(der)
            .map_err(|_| initialization("RSA recovery key"))?;
        let public: PublicKeyX509Der<'static> = key
            .public_key()
            .as_der()
            .map_err(|_| initialization("RSA public key"))?;
        let session = crate::xmldsig::pkix::CertificateSession::new(
            &crate::policy::ResourcePolicy::default(),
        );
        let rsa = session
            .rsa_public_key(public.as_ref(), None)
            .ok_or_else(|| initialization("RSA public key"))?;
        let exponent = rsa
            .exponent()
            .as_bytes()
            .iter()
            .try_fold(0_u64, |value, byte| {
                value.checked_mul(256)?.checked_add(u64::from(*byte))
            });
        let modulus_bits = key.key_size_bits();
        let ciphertext_len = key.key_size_bytes();
        Ok(Self {
            key: aws_lc_rs::rsa::OaepPrivateDecryptingKey::new(key)
                .map_err(|_| initialization("RSA-OAEP"))?,
            modulus_bits,
            exponent,
            ciphertext_len,
            public_spki: public.as_ref().to_vec(),
        })
    }
}

#[cfg(feature = "xmlenc")]
impl super::KeyRecoveryKey for AwsLcRsaPrivateKey {
    fn provider_name(&self) -> Option<&'static str> {
        Some("aws-lc-fips")
    }
    fn public_spki(&self) -> Option<&[u8]> {
        Some(&self.public_spki)
    }
    fn rsa_modulus_bits(&self) -> usize {
        self.modulus_bits
    }
    fn rsa_public_exponent(&self) -> Option<u64> {
        self.exponent
    }
    fn ciphertext_len(&self) -> usize {
        self.ciphertext_len
    }
    fn recover_with_provider(
        &self,
        provider: &dyn CryptoProvider,
        parameters: &RsaOaepParameters,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        if provider.name() != "aws-lc-fips" {
            return Err(unsupported(ProviderCapability::KeyRecovery(parameters)));
        }
        let algorithm = oaep_algorithm(parameters)
            .ok_or_else(|| unsupported(ProviderCapability::KeyRecovery(parameters)))?;
        if ciphertext.len() != self.ciphertext_len {
            return Err(initialization("RSA-OAEP ciphertext"));
        }
        let mut output = vec![0; self.ciphertext_len];
        let len = self
            .key
            .decrypt(algorithm, ciphertext, &mut output, Some(&parameters.label))
            .map_err(|_| ProviderError::AuthenticationFailed)?
            .len();
        output.truncate(len);
        Ok(output)
    }
}

#[cfg(test)]
mod tests;
