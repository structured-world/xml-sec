//! Safe AWS-LC FIPS dispatch. Unsupported mechanisms never use another engine.

use aws_lc_rs::encoding::{AsDer as _, PublicKeyX509Der};
#[cfg(feature = "xmlenc")]
use aws_lc_rs::key_wrap::KeyWrap as _;
use aws_lc_rs::rand::SecureRandom as _;
use aws_lc_rs::signature::KeyPair as _;
#[cfg(feature = "xmlenc")]
use aws_lc_rs::{aead, cipher, key_wrap};
use aws_lc_rs::{digest, rand, signature};
use x509_parser::prelude::FromDer as _;
use x509_parser::x509::SubjectPublicKeyInfo;

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
    pub fn module_version(&self) -> &'static str {
        aws_lc_rs::awslc_version()
    }

    /// AWS-LC's reported FIPS module version, without an approved-service claim.
    pub fn fips_module_version(&self) -> Option<u32> {
        aws_lc_rs::fips_version()
    }
}

fn digest_algorithm(algorithm: DigestAlgorithm) -> Option<&'static digest::Algorithm> {
    Some(match algorithm {
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

impl CryptoProvider for AwsLcFipsProvider {
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
            ProviderCapability::Encrypt(_)
            | ProviderCapability::Decrypt(_)
            | ProviderCapability::KeyWrap(_)
            | ProviderCapability::KeyUnwrap(_) => true,
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

    fn digest(&self, algorithm: DigestAlgorithm, data: &[u8]) -> Result<Vec<u8>, ProviderError> {
        let native = digest_algorithm(algorithm)
            .ok_or_else(|| unsupported(ProviderCapability::Digest(algorithm)))?;
        Ok(digest::digest(native, data).as_ref().to_vec())
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
        if let Some(result) = key.verify_candidate_keys(&mut |candidate| {
            self.verify(candidate, algorithm, data, signature)
        })? {
            return Ok(result);
        }
        let spki = key
            .verification_spki(algorithm)?
            .ok_or_else(|| verification_unsupported(algorithm))?;
        if !key.validate_signature_value(algorithm, signature)? {
            return Ok(false);
        }
        let native = verification_algorithm(algorithm, spki, key.ecdsa_encoding())?;
        let public = signature::ParsedPublicKey::new(native, spki)
            .map_err(|_| crate::xmldsig::SignatureVerificationError::InvalidKeyDer)?;
        Ok(public.verify_sig(data, signature).is_ok())
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
        check_key(algorithm.key_len(), key)?;
        match algorithm {
            DataEncryptionAlgorithm::Aes128Cbc | DataEncryptionAlgorithm::Aes256Cbc => {
                let padding = 16 - plaintext.len() % 16;
                let mut output = vec![0; framed_len(plaintext.len(), 16 + padding)?];
                output[16..16 + plaintext.len()].copy_from_slice(plaintext);
                let last = output.len() - 1;
                self.fill_random(&mut output[16 + plaintext.len()..last])?;
                output[last] = padding as u8;
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
        check_key(algorithm.key_len(), key)?;
        match algorithm {
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
        let public = rsa::pkcs1::RsaPublicKey {
            modulus: der::asn1::UintRef::new(&modulus)
                .map_err(|_| initialization("RSA public key"))?,
            public_exponent: der::asn1::UintRef::new(&exponent)
                .map_err(|_| initialization("RSA public key"))?,
        }
        .to_der()
        .map_err(|_| initialization("RSA public key"))?;
        let spki = pkcs8::SubjectPublicKeyInfoRef {
            algorithm: pkcs8::AlgorithmIdentifierRef {
                oid: rsa::pkcs1::ALGORITHM_OID,
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
        .filter(|len| *len <= isize::MAX as usize)
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
        KeyWrapAlgorithm::AesKw128 => &key_wrap::AES_128,
        KeyWrapAlgorithm::AesKw256 => &key_wrap::AES_256,
    };
    key_wrap::KeyEncryptionKey::new(cipher, kek).map_err(|_| initialization("AES key wrap"))
}

fn signing_supported(algorithm: SignatureAlgorithm) -> bool {
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
    let (rest, public) = SubjectPublicKeyInfo::from_der(spki)
        .map_err(|_| crate::xmldsig::SignatureVerificationError::InvalidKeyDer)?;
    if !rest.is_empty()
        || public.algorithm.algorithm.as_bytes() != [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]
    {
        return Err(crate::xmldsig::SignatureVerificationError::InvalidKeyDer);
    }
    public
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.as_oid().ok())
        .and_then(|oid| curve_oid_name(oid.as_bytes()))
        .ok_or(crate::xmldsig::SignatureVerificationError::InvalidKeyDer)
}

fn verification_algorithm(
    algorithm: SignatureAlgorithm,
    spki: &[u8],
    encoding: crate::policy::EcdsaSignatureValueEncoding,
) -> Result<&'static dyn signature::VerificationAlgorithm, crate::xmldsig::SignatureVerificationError>
{
    use SignatureAlgorithm as A;
    use signature::*;
    let rsa: Option<&'static dyn VerificationAlgorithm> = match algorithm {
        A::RsaSha1 => Some(&RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY),
        A::RsaSha256 => Some(&RSA_PKCS1_2048_8192_SHA256),
        A::RsaSha384 => Some(&RSA_PKCS1_2048_8192_SHA384),
        A::RsaSha512 => Some(&RSA_PKCS1_2048_8192_SHA512),
        _ => None,
    };
    if let Some(rsa) = rsa {
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
    /// Import an unencrypted PKCS#8 key for one exact XMLDSig method.
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
        let (key, spki) = if matches!(algorithm, A::RsaSha256 | A::RsaSha384 | A::RsaSha512) {
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
        let (rest, parsed) = SubjectPublicKeyInfo::from_der(&spki)
            .map_err(|_| SigningKeyError::InvalidPublicKeyInfo)?;
        if !rest.is_empty() {
            return Err(SigningKeyError::InvalidPublicKeyInfo);
        }
        let public = match parsed
            .parsed()
            .map_err(|_| SigningKeyError::InvalidPublicKeyInfo)?
        {
            x509_parser::public_key::PublicKey::RSA(rsa) => {
                crate::xmldsig::SigningPublicKeyInfo::Rsa {
                    modulus: rsa
                        .modulus
                        .iter()
                        .copied()
                        .skip_while(|b| *b == 0)
                        .collect(),
                    exponent: rsa
                        .exponent
                        .iter()
                        .copied()
                        .skip_while(|b| *b == 0)
                        .collect(),
                    spki_der: spki,
                }
            }
            x509_parser::public_key::PublicKey::EC(_) => {
                let curve = spki_curve(&spki).map_err(|_| SigningKeyError::InvalidPublicKeyInfo)?;
                let curve_oid = curve;
                crate::xmldsig::SigningPublicKeyInfo::Ec {
                    curve_oid,
                    public_key: parsed.subject_public_key.data.to_vec(),
                    spki_der: spki,
                }
            }
            _ => return Err(SigningKeyError::InvalidPublicKeyInfo),
        };
        Ok(Self {
            key,
            algorithm,
            public,
        })
    }
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
                let encoding = match algorithm {
                    SignatureAlgorithm::RsaSha256 => &signature::RSA_PKCS1_SHA256,
                    SignatureAlgorithm::RsaSha384 => &signature::RSA_PKCS1_SHA384,
                    SignatureAlgorithm::RsaSha512 => &signature::RSA_PKCS1_SHA512,
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
    use aws_lc_rs::rsa::*;
    if parameters.digest != parameters.mgf_digest {
        return None;
    }
    Some(match parameters.digest {
        D::Sha1 => &OAEP_SHA1_MGF1SHA1,
        D::Sha256 => &OAEP_SHA256_MGF1SHA256,
        D::Sha384 => &OAEP_SHA384_MGF1SHA384,
        D::Sha512 => &OAEP_SHA512_MGF1SHA512,
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
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, ProviderError> {
        let key = aws_lc_rs::rsa::PrivateDecryptingKey::from_pkcs8(der)
            .map_err(|_| initialization("RSA recovery key"))?;
        let public: PublicKeyX509Der<'static> = key
            .public_key()
            .as_der()
            .map_err(|_| initialization("RSA public key"))?;
        let (_, spki) = SubjectPublicKeyInfo::from_der(public.as_ref())
            .map_err(|_| initialization("RSA public key"))?;
        let x509_parser::public_key::PublicKey::RSA(rsa) = spki
            .parsed()
            .map_err(|_| initialization("RSA public key"))?
        else {
            return Err(initialization("RSA public key"));
        };
        let exponent = rsa.exponent.iter().try_fold(0_u64, |value, byte| {
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
