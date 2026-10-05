//! Explicit, optional PKCS#11 execution through caller-owned authenticated sessions.
//!
//! The caller loads and initializes the module and authenticates the session.
//! No module search, environment discovery, token initialization or PIN persistence
//! occurs here. One session is serialized across complete primitive operations;
//! independent provider instances can use independent sessions concurrently.

pub use cryptoki;

use std::sync::{Arc, Mutex, MutexGuard};

use crypto_bigint::BoxedUint;
use cryptoki::{
    error::{Error, RvError},
    mechanism::{
        Mechanism, MechanismInfo, MechanismType,
        elliptic_curve::{EcKdf, Ecdh1DeriveParams},
        rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource},
    },
    object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    types::AuthPin,
};
use rsa::{RsaPublicKey, pkcs8::EncodePublicKey, traits::PublicKeyParts};

use super::{
    ContentDecryptionKey, CryptoProvider, ExternalProviderError, KeyAgreementKey,
    KeyAgreementParameters, KeyRecoveryKey, KeyTransportKey, ProviderBinding, ProviderCapability,
    ProviderError, ProviderOperation, RecoveredContentKey, X509SignatureAlgorithm,
};
use crate::{
    xmldsig::{
        DigestAlgorithm, DsigError, SignatureAlgorithm, SigningKey, SigningKeyError,
        SigningPublicKeyInfo, VerifyingKey,
    },
    xmlenc::{DataEncryptionAlgorithm, KeyWrapAlgorithm, OaepDigestAlgorithm, RsaOaepParameters},
};

struct Token {
    session: Mutex<Session>,
    mechanisms: Vec<(MechanismType, MechanismInfo)>,
    random: bool,
    binding: ProviderBinding,
}

impl Token {
    fn session(&self) -> Result<MutexGuard<'_, Session>, ProviderError> {
        self.session
            .lock()
            .map_err(|_| external(ExternalProviderError::Operation))
    }

    fn check_binding(&self, provider: &dyn CryptoProvider) -> Result<(), ProviderError> {
        if provider
            .binding()
            .is_some_and(|binding| self.binding.matches(binding))
        {
            Ok(())
        } else {
            Err(external(ExternalProviderError::Binding))
        }
    }

    fn mechanism(&self, kind: MechanismType, operation: ProviderOperation) -> bool {
        self.mechanisms.iter().any(|(available, info)| {
            *available == kind
                && match operation {
                    ProviderOperation::Digest => info.digest(),
                    ProviderOperation::Sign => info.sign(),
                    ProviderOperation::Verify | ProviderOperation::VerifyCertificate => {
                        info.verify()
                    }
                    ProviderOperation::Encrypt | ProviderOperation::KeyTransport => info.encrypt(),
                    ProviderOperation::Decrypt | ProviderOperation::KeyRecovery => info.decrypt(),
                    ProviderOperation::KeyUnwrap => info.unwrap(),
                    ProviderOperation::KeyWrap => info.wrap(),
                    ProviderOperation::KeyAgreement => info.derive(),
                    _ => false,
                }
        })
    }
}

/// One explicit token/session execution domain. Clones share its session and identity.
#[derive(Clone)]
pub struct Pkcs11Provider(Arc<Token>);

impl std::fmt::Debug for Pkcs11Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs11Provider").finish_non_exhaustive()
    }
}

impl Pkcs11Provider {
    /// Open a session on an explicitly initialized module and slot. Discovering
    /// mechanisms and opening the session through the same module prevents
    /// caller-supplied sessions from being paired with another module's capabilities.
    pub fn new(
        module: &cryptoki::context::Pkcs11,
        slot: cryptoki::slot::Slot,
    ) -> Result<Self, ProviderError> {
        let session = module.open_rw_session(slot).map_err(map_error)?;
        let random = module.get_token_info(slot).map_err(map_error)?.rng();
        let mechanisms = module
            .get_mechanism_list(slot)
            .map_err(map_error)?
            .into_iter()
            .map(|kind| {
                module
                    .get_mechanism_info(slot, kind)
                    .map(|info| (kind, info))
                    .map_err(map_error)
            })
            .collect::<Result<_, _>>()?;
        Ok(Self(Arc::new(Token {
            session: Mutex::new(session),
            mechanisms,
            random,
            binding: ProviderBinding::default(),
        })))
    }

    /// Authenticate explicitly without retaining or displaying the PIN.
    pub fn login(&self, pin: &AuthPin) -> Result<(), ProviderError> {
        self.0
            .session()?
            .login(UserType::User, Some(pin))
            .map_err(map_error)
    }

    /// Resolve one persistent RSA private key by exact binary CKA_ID.
    /// Only public RSA attributes are read; private exponents are never queried.
    pub fn rsa_private_key(&self, id: &[u8]) -> Result<Pkcs11RsaKey, ProviderError> {
        self.rsa_key(id, ObjectClass::PRIVATE_KEY)
    }

    /// Resolve one persistent RSA public key for token-side verification/transport.
    pub fn rsa_public_key(&self, id: &[u8]) -> Result<Pkcs11RsaKey, ProviderError> {
        self.rsa_key(id, ObjectClass::PUBLIC_KEY)
    }

    fn rsa_key(&self, id: &[u8], class: ObjectClass) -> Result<Pkcs11RsaKey, ProviderError> {
        let session = self.0.session()?;
        let object = unique_object(&session, id, class, KeyType::RSA)?;
        let attributes = session
            .get_attributes(
                object,
                &[AttributeType::Modulus, AttributeType::PublicExponent],
            )
            .map_err(map_error)?;
        let modulus = bytes_attribute(&attributes, AttributeType::Modulus)?;
        let exponent = bytes_attribute(&attributes, AttributeType::PublicExponent)?;
        if modulus.is_empty() || exponent.is_empty() {
            return Err(external(ExternalProviderError::Object));
        }
        let public = RsaPublicKey::new(
            BoxedUint::from_be_slice_vartime(modulus),
            BoxedUint::from_be_slice_vartime(exponent),
        )
        .map_err(|_| external(ExternalProviderError::Object))?;
        let modulus = public.n().to_be_bytes_trimmed_vartime().into_vec();
        let exponent = public.e().to_be_bytes_trimmed_vartime().into_vec();
        let spki = public
            .to_public_key_der()
            .map_err(|_| external(ExternalProviderError::Object))?
            .as_bytes()
            .to_vec();
        Ok(Pkcs11RsaKey {
            token: self.0.clone(),
            object,
            modulus,
            exponent,
            spki,
        })
    }

    /// Resolve a non-exportable AES content key or KEK; width is read as metadata.
    pub fn aes_key(&self, id: &[u8]) -> Result<Pkcs11AesKey, ProviderError> {
        let session = self.0.session()?;
        let object = unique_object(&session, id, ObjectClass::SECRET_KEY, KeyType::AES)?;
        let attributes = session
            .get_attributes(object, &[AttributeType::ValueLen])
            .map_err(map_error)?;
        let length = attributes
            .iter()
            .find_map(|attribute| match attribute {
                Attribute::ValueLen(value) => Some(usize::from(*value)),
                _ => None,
            })
            .ok_or(external(ExternalProviderError::Object))?;
        if !matches!(length, 16 | 24 | 32) {
            return Err(external(ExternalProviderError::Object));
        }
        Ok(Pkcs11AesKey {
            token: self.0.clone(),
            object,
            length,
            temporary: false,
        })
    }

    /// Resolve a persistent NIST-curve EC private key for token-side agreement.
    pub fn agreement_key(&self, id: &[u8]) -> Result<Pkcs11AgreementKey, ProviderError> {
        let session = self.0.session()?;
        let object = unique_object(&session, id, ObjectClass::PRIVATE_KEY, KeyType::EC)?;
        let attributes = session
            .get_attributes(object, &[AttributeType::EcParams])
            .map_err(map_error)?;
        let parameters = attributes
            .iter()
            .find_map(|attribute| match attribute {
                Attribute::EcParams(value) => Some(value.as_slice()),
                _ => None,
            })
            .ok_or(external(ExternalProviderError::Object))?;
        let width = match parameters {
            [6, 8, 42, 134, 72, 206, 61, 3, 1, 7] => 32,
            [6, 5, 43, 129, 4, 0, 34] => 48,
            [6, 5, 43, 129, 4, 0, 35] => 66,
            _ => return Err(external(ExternalProviderError::Object)),
        };
        Ok(Pkcs11AgreementKey {
            token: self.0.clone(),
            object,
            width,
        })
    }
}

fn external(reason: ExternalProviderError) -> ProviderError {
    ProviderError::External(reason)
}

fn oaep_error(error: Error, capability: ProviderCapability<'_>) -> ProviderError {
    // Mechanism presence does not advertise every OAEP digest/MGF combination.
    // Modules may reject these parameters at C_EncryptInit/C_DecryptInit.
    match error {
        Error::Pkcs11(
            RvError::ArgumentsBad | RvError::MechanismParamInvalid | RvError::MechanismInvalid,
            _,
        ) => unsupported(capability),
        error => map_error(error),
    }
}

fn map_error(error: Error) -> ProviderError {
    match error {
        Error::Pkcs11(
            RvError::SignatureInvalid
            | RvError::SignatureLenRange
            | RvError::EncryptedDataInvalid
            | RvError::WrappedKeyInvalid,
            _,
        ) => ProviderError::AuthenticationFailed,
        Error::Pkcs11(
            RvError::PinIncorrect
            | RvError::PinLocked
            | RvError::PinExpired
            | RvError::UserNotLoggedIn,
            _,
        ) => external(ExternalProviderError::Credentials),
        Error::Pkcs11(RvError::ObjectHandleInvalid | RvError::KeyHandleInvalid, _) => {
            external(ExternalProviderError::Object)
        }
        Error::Pkcs11(RvError::KeyFunctionNotPermitted, _) => {
            external(ExternalProviderError::Usage)
        }
        Error::Pkcs11(
            RvError::TokenNotPresent
            | RvError::TokenNotRecognized
            | RvError::DeviceRemoved
            | RvError::SessionHandleInvalid,
            _,
        ) => external(ExternalProviderError::Unavailable),
        _ => external(ExternalProviderError::Operation),
    }
}

fn unique_object(
    session: &Session,
    id: &[u8],
    class: ObjectClass,
    key_type: KeyType,
) -> Result<ObjectHandle, ProviderError> {
    if id.is_empty() {
        return Err(external(ExternalProviderError::Object));
    }
    // PKCS#11 Base §5.7 C_FindObjects: CKA_ID is not required to be unique.
    // Reject ambiguity rather than choosing the first token-dependent result.
    // https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html
    let mut objects = session
        .iter_objects_with_cache_size(
            &[
                Attribute::Token(true),
                Attribute::Id(id.to_vec()),
                Attribute::Class(class),
                Attribute::KeyType(key_type),
            ],
            std::num::NonZeroUsize::new(2).expect("nonzero cache size"),
        )
        .map_err(map_error)?;
    let first = objects
        .next()
        .transpose()
        .map_err(map_error)?
        .ok_or(external(ExternalProviderError::Object))?;
    if objects.next().transpose().map_err(map_error)?.is_some() {
        return Err(external(ExternalProviderError::Object));
    }
    Ok(first)
}

fn bytes_attribute(attributes: &[Attribute], kind: AttributeType) -> Result<&[u8], ProviderError> {
    attributes
        .iter()
        .find_map(|attribute| match (kind, attribute) {
            (AttributeType::Modulus, Attribute::Modulus(bytes))
            | (AttributeType::PublicExponent, Attribute::PublicExponent(bytes)) => {
                Some(bytes.as_slice())
            }
            _ => None,
        })
        .ok_or(external(ExternalProviderError::Object))
}

fn require_usage(
    session: &Session,
    object: ObjectHandle,
    kind: AttributeType,
) -> Result<(), ProviderError> {
    let attributes = session.get_attributes(object, &[kind]).map_err(map_error)?;
    let enabled = attributes.iter().any(|attribute| {
        matches!(
            attribute,
            Attribute::Sign(true)
                | Attribute::Verify(true)
                | Attribute::Encrypt(true)
                | Attribute::Decrypt(true)
                | Attribute::Unwrap(true)
                | Attribute::Derive(true)
        )
    });
    if enabled {
        Ok(())
    } else {
        Err(external(ExternalProviderError::Usage))
    }
}

fn signature_mechanism(algorithm: SignatureAlgorithm) -> Option<Mechanism<'static>> {
    match algorithm {
        SignatureAlgorithm::RsaSha1 => Some(Mechanism::Sha1RsaPkcs),
        SignatureAlgorithm::RsaSha224 => Some(Mechanism::Sha224RsaPkcs),
        SignatureAlgorithm::RsaSha256 => Some(Mechanism::Sha256RsaPkcs),
        SignatureAlgorithm::RsaSha384 => Some(Mechanism::Sha384RsaPkcs),
        SignatureAlgorithm::RsaSha512 => Some(Mechanism::Sha512RsaPkcs),
        _ => None,
    }
}

fn digest_mechanism(algorithm: DigestAlgorithm) -> Option<Mechanism<'static>> {
    match algorithm {
        DigestAlgorithm::Sha1 => Some(Mechanism::Sha1),
        DigestAlgorithm::Sha224 => Some(Mechanism::Sha224),
        DigestAlgorithm::Sha256 => Some(Mechanism::Sha256),
        DigestAlgorithm::Sha384 => Some(Mechanism::Sha384),
        DigestAlgorithm::Sha512 => Some(Mechanism::Sha512),
        _ => None,
    }
}

fn oaep(parameters: &RsaOaepParameters) -> Mechanism<'_> {
    let hash = match parameters.digest {
        OaepDigestAlgorithm::Sha1 => MechanismType::SHA1,
        OaepDigestAlgorithm::Sha256 => MechanismType::SHA256,
        OaepDigestAlgorithm::Sha384 => MechanismType::SHA384,
        OaepDigestAlgorithm::Sha512 => MechanismType::SHA512,
    };
    let mgf = match parameters.mgf_digest {
        OaepDigestAlgorithm::Sha1 => PkcsMgfType::MGF1_SHA1,
        OaepDigestAlgorithm::Sha256 => PkcsMgfType::MGF1_SHA256,
        OaepDigestAlgorithm::Sha384 => PkcsMgfType::MGF1_SHA384,
        OaepDigestAlgorithm::Sha512 => PkcsMgfType::MGF1_SHA512,
    };
    // PKCS#11 Current Mechanisms v2.40 §2.1.7 requires NULL source data for
    // an empty OAEP label; a non-null zero-length Rust slice is not equivalent.
    // https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html
    let source = if parameters.label.is_empty() {
        PkcsOaepSource::empty()
    } else {
        PkcsOaepSource::data_specified(&parameters.label)
    };
    Mechanism::RsaPkcsOaep(PkcsOaepParams::new(hash, mgf, source))
}

/// Opaque RSA object. Debug deliberately omits object handles, IDs and token identity.
pub struct Pkcs11RsaKey {
    token: Arc<Token>,
    object: ObjectHandle,
    modulus: Vec<u8>,
    exponent: Vec<u8>,
    spki: Vec<u8>,
}

impl SigningKey for Pkcs11RsaKey {
    fn provider_name(&self) -> Option<&'static str> {
        Some("pkcs11")
    }
    fn sign(&self, algorithm: SignatureAlgorithm, data: &[u8]) -> Result<Vec<u8>, SigningKeyError> {
        self.sign_with_provider(&Pkcs11Provider(self.token.clone()), algorithm, data)
    }
    fn sign_with_provider(
        &self,
        provider: &dyn CryptoProvider,
        algorithm: SignatureAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>, SigningKeyError> {
        self.token.check_binding(provider)?;
        let capability = ProviderCapability::Sign(algorithm);
        provider.require_capability(capability)?;
        let mechanism = signature_mechanism(algorithm).ok_or_else(|| unsupported(capability))?;
        let session = self.token.session()?;
        require_usage(&session, self.object, AttributeType::Sign)?;
        Ok(session
            .sign(&mechanism, self.object, data)
            .map_err(map_error)?)
    }
    fn public_key_info(&self) -> Result<SigningPublicKeyInfo, SigningKeyError> {
        Ok(SigningPublicKeyInfo::Rsa {
            spki_der: self.spki.clone(),
            modulus: self.modulus.clone(),
            exponent: self.exponent.clone(),
        })
    }
}

impl VerifyingKey for Pkcs11RsaKey {
    fn provider_binding(&self) -> Option<&ProviderBinding> {
        Some(&self.token.binding)
    }
    fn validate_policy(&self, policy: &crate::policy::VerificationPolicy) -> Result<(), DsigError> {
        // Reuse the policy's component validator without copying or reparsing SPKI.
        policy
            .key_trust
            .rsa_keys
            .validate_components("verification", &self.modulus, &self.exponent)
            .map(|_| ())
            .map_err(Into::into)
    }
    fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, DsigError> {
        let mechanism = signature_mechanism(algorithm)
            .ok_or_else(|| unsupported(ProviderCapability::Verify(algorithm)))?;
        let session = self.token.session()?;
        require_usage(&session, self.object, AttributeType::Verify)?;
        match session
            .verify(&mechanism, self.object, data, signature)
            .map_err(map_error)
        {
            Ok(()) => Ok(true),
            Err(ProviderError::AuthenticationFailed) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
}

impl KeyTransportKey for Pkcs11RsaKey {
    fn provider_binding(&self) -> Option<&ProviderBinding> {
        Some(&self.token.binding)
    }
    fn rsa_modulus(&self) -> std::borrow::Cow<'_, [u8]> {
        std::borrow::Cow::Borrowed(&self.modulus)
    }
    fn rsa_exponent(&self) -> std::borrow::Cow<'_, [u8]> {
        std::borrow::Cow::Borrowed(&self.exponent)
    }
    fn transport_with_provider(
        &self,
        provider: &dyn CryptoProvider,
        parameters: &RsaOaepParameters,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        self.token.check_binding(provider)?;
        provider.require_capability(ProviderCapability::KeyTransport(parameters))?;
        let session = self.token.session()?;
        require_usage(&session, self.object, AttributeType::Encrypt)?;
        session
            .encrypt(&oaep(parameters), self.object, plaintext)
            .map_err(|error| oaep_error(error, ProviderCapability::KeyTransport(parameters)))
    }
}

impl KeyRecoveryKey for Pkcs11RsaKey {
    fn recover_content_with_provider(
        &self,
        provider: &dyn CryptoProvider,
        parameters: &RsaOaepParameters,
        content_algorithm: DataEncryptionAlgorithm,
        ciphertext: &[u8],
    ) -> Result<RecoveredContentKey, ProviderError> {
        self.token.check_binding(provider)?;
        provider.require_capability(ProviderCapability::KeyRecovery(parameters))?;
        provider.require_capability(ProviderCapability::Decrypt(content_algorithm))?;
        if ciphertext.len() != self.modulus.len() {
            return Err(ProviderError::AuthenticationFailed);
        }
        // PKCS#11 Current Mechanisms §2.8.2, table 47 forbids CKA_VALUE_LEN
        // in AES unwrap templates (footnote 6). SoftHSM does not populate this
        // metadata for RSA unwrap, so it cannot enforce the XMLEnc key width.
        // Use C_Decrypt and a zeroized transient CEK before importing a session
        // object instead; the RSA private material never leaves the token.
        // https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html
        let recovered = self.recover_with_provider(provider, parameters, ciphertext)?;
        let key = import_content_key(&self.token, content_algorithm, recovered)?;
        Ok(RecoveredContentKey::opaque(Arc::new(key)))
    }
    fn provider_name(&self) -> Option<&'static str> {
        Some("pkcs11")
    }
    fn public_spki(&self) -> Option<&[u8]> {
        Some(&self.spki)
    }
    fn rsa_modulus_bits(&self) -> usize {
        self.modulus.len() * 8 - self.modulus[0].leading_zeros() as usize
    }
    fn ciphertext_len(&self) -> usize {
        self.modulus.len()
    }
    fn rsa_public_exponent(&self) -> Option<u64> {
        if self.exponent.len() > 8 {
            return None;
        }
        Some(
            self.exponent
                .iter()
                .fold(0, |value, byte| (value << 8) | u64::from(*byte)),
        )
    }
    fn recover_with_provider(
        &self,
        provider: &dyn CryptoProvider,
        parameters: &RsaOaepParameters,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        self.token.check_binding(provider)?;
        provider.require_capability(ProviderCapability::KeyRecovery(parameters))?;
        let session = self.token.session()?;
        require_usage(&session, self.object, AttributeType::Decrypt)?;
        session
            .decrypt(&oaep(parameters), self.object, ciphertext)
            .map_err(|error| oaep_error(error, ProviderCapability::KeyRecovery(parameters)))
    }
}

fn unsupported(capability: ProviderCapability<'_>) -> ProviderError {
    ProviderError::Unsupported {
        operation: capability.operation(),
        algorithm: capability.algorithm().map(str::to_owned),
    }
}

impl CryptoProvider for Pkcs11Provider {
    fn recover_content_key(
        &self,
        key: &dyn KeyRecoveryKey,
        parameters: &RsaOaepParameters,
        content_algorithm: DataEncryptionAlgorithm,
        ciphertext: &[u8],
    ) -> Result<RecoveredContentKey, ProviderError> {
        if key.provider_name() != Some(self.name()) {
            return Err(external(ExternalProviderError::Binding));
        }
        key.recover_content_with_provider(self, parameters, content_algorithm, ciphertext)
    }
    fn binding(&self) -> Option<&ProviderBinding> {
        Some(&self.0.binding)
    }
    fn name(&self) -> &'static str {
        "pkcs11"
    }
    fn supports(&self, capability: ProviderCapability<'_>) -> bool {
        let kind = match capability {
            ProviderCapability::Digest(algorithm) => {
                digest_mechanism(algorithm).map(|m| m.mechanism_type())
            }
            ProviderCapability::Sign(algorithm) | ProviderCapability::Verify(algorithm) => {
                signature_mechanism(algorithm).map(|m| m.mechanism_type())
            }
            ProviderCapability::KeyTransport(_) | ProviderCapability::KeyRecovery(_) => {
                Some(MechanismType::RSA_PKCS_OAEP)
            }
            ProviderCapability::Decrypt(algorithm) => content_mechanism(algorithm),
            ProviderCapability::KeyUnwrap(algorithm)
                if algorithm.key_kind() == crate::key_manager::SymmetricKeyKind::Aes =>
            {
                Some(MechanismType::AES_KEY_WRAP)
            }
            ProviderCapability::KeyAgreement(parameters)
                if parameters.algorithm == "http://www.w3.org/2009/xmlenc11#ECDH-ES" =>
            {
                Some(MechanismType::ECDH1_DERIVE)
            }
            ProviderCapability::Random => return self.0.random,
            _ => None,
        };
        kind.is_some_and(|kind| self.0.mechanism(kind, capability.operation()))
    }
    fn fill_random(&self, output: &mut [u8]) -> Result<(), ProviderError> {
        self.require_capability(ProviderCapability::Random)?;
        self.0
            .session()?
            .generate_random_slice(output)
            .map_err(map_error)
    }
    fn digest(&self, algorithm: DigestAlgorithm, input: &[u8]) -> Result<Vec<u8>, ProviderError> {
        self.require_capability(ProviderCapability::Digest(algorithm))?;
        let mechanism = digest_mechanism(algorithm)
            .ok_or_else(|| unsupported(ProviderCapability::Digest(algorithm)))?;
        self.0
            .session()?
            .digest(&mechanism, input)
            .map_err(map_error)
    }
    fn sign(
        &self,
        key: &dyn SigningKey,
        algorithm: SignatureAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>, SigningKeyError> {
        self.require_capability(ProviderCapability::Sign(algorithm))?;
        if key.provider_name() != Some(self.name()) {
            return Err(external(ExternalProviderError::Binding).into());
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
        self.require_capability(ProviderCapability::Verify(algorithm))?;
        if let Some(result) = key.verify_candidate_keys(&mut |candidate| {
            self.verify(candidate, algorithm, data, signature)
        })? {
            return Ok(result);
        }
        if !key
            .provider_binding()
            .is_some_and(|binding| binding.matches(&self.0.binding))
        {
            return Err(external(ExternalProviderError::Binding).into());
        }
        key.verify(algorithm, data, signature)
    }
    fn verify_x509_signature(
        &self,
        algorithm: X509SignatureAlgorithm,
        _spki: &[u8],
        _data: &[u8],
        _signature: &[u8],
    ) -> Result<bool, ProviderError> {
        Err(unsupported(ProviderCapability::VerifyCertificate(
            algorithm,
        )))
    }
    fn encrypt_data(
        &self,
        algorithm: DataEncryptionAlgorithm,
        _key: &[u8],
        _plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        Err(unsupported(ProviderCapability::Encrypt(algorithm)))
    }
    fn decrypt_data(
        &self,
        algorithm: DataEncryptionAlgorithm,
        key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        self.require_capability(ProviderCapability::Decrypt(algorithm))?;
        // Reject invalid caller widths before allocating an import workspace.
        if key.len() != algorithm.key_len() {
            return Err(ProviderError::InvalidKeySize {
                expected: algorithm.key_len(),
                actual: key.len(),
            });
        }
        let key = import_content_key(&self.0, algorithm, key.to_vec())?;
        key.decrypt_with_provider(self, algorithm, ciphertext)
    }
    fn decrypt_content_key(
        &self,
        algorithm: DataEncryptionAlgorithm,
        key: &dyn ContentDecryptionKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        self.require_capability(ProviderCapability::Decrypt(algorithm))?;
        if !key.provider_binding().matches(&self.0.binding) {
            return Err(external(ExternalProviderError::Binding));
        }
        key.decrypt_with_provider(self, algorithm, ciphertext)
    }
    fn wrap_key(
        &self,
        algorithm: KeyWrapAlgorithm,
        _kek: &[u8],
        _key: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        Err(unsupported(ProviderCapability::KeyWrap(algorithm)))
    }
    fn unwrap_key(
        &self,
        algorithm: KeyWrapAlgorithm,
        _kek: &[u8],
        _wrapped: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        Err(unsupported(ProviderCapability::KeyUnwrap(algorithm)))
    }
    fn unwrap_content_key(
        &self,
        key: &dyn super::KeyUnwrappingKey,
        algorithm: KeyWrapAlgorithm,
        content_algorithm: DataEncryptionAlgorithm,
        wrapped: &[u8],
    ) -> Result<RecoveredContentKey, ProviderError> {
        self.require_capability(ProviderCapability::KeyUnwrap(algorithm))?;
        if !key.provider_binding().matches(&self.0.binding) {
            return Err(external(ExternalProviderError::Binding));
        }
        key.unwrap_with_provider(self, algorithm, content_algorithm, wrapped)
    }
    fn transport_key(
        &self,
        key: &dyn KeyTransportKey,
        parameters: &RsaOaepParameters,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        if !key
            .provider_binding()
            .is_some_and(|binding| binding.matches(&self.0.binding))
        {
            return Err(external(ExternalProviderError::Binding));
        }
        key.transport_with_provider(self, parameters, plaintext)
    }
    fn recover_key(
        &self,
        key: &dyn KeyRecoveryKey,
        parameters: &RsaOaepParameters,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        if key.provider_name() != Some(self.name()) {
            return Err(external(ExternalProviderError::Binding));
        }
        key.recover_with_provider(self, parameters, ciphertext)
    }
    fn agree_key(
        &self,
        key: &dyn KeyAgreementKey,
        parameters: &KeyAgreementParameters<'_>,
    ) -> Result<Vec<u8>, ProviderError> {
        self.require_capability(ProviderCapability::KeyAgreement(parameters))?;
        if !key
            .provider_binding()
            .is_some_and(|binding| binding.matches(&self.0.binding))
        {
            return Err(external(ExternalProviderError::Binding));
        }
        key.agree(parameters)
    }
    fn derive_key(
        &self,
        parameters: &super::KdfParameters<'_>,
        _secret: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        Err(unsupported(ProviderCapability::Kdf(parameters)))
    }
}

fn content_mechanism(algorithm: DataEncryptionAlgorithm) -> Option<MechanismType> {
    match algorithm {
        DataEncryptionAlgorithm::Aes128Cbc | DataEncryptionAlgorithm::Aes256Cbc => {
            Some(MechanismType::AES_CBC)
        }
        DataEncryptionAlgorithm::Aes128Gcm | DataEncryptionAlgorithm::Aes256Gcm => {
            Some(MechanismType::AES_GCM)
        }
        #[cfg(feature = "legacy-algorithms")]
        DataEncryptionAlgorithm::Aes192Cbc => Some(MechanismType::AES_CBC),
        #[cfg(feature = "legacy-algorithms")]
        DataEncryptionAlgorithm::Aes192Gcm => Some(MechanismType::AES_GCM),
        #[cfg(feature = "legacy-algorithms")]
        DataEncryptionAlgorithm::TripleDesCbc => None,
    }
}

/// Non-exportable AES token object, including session-owned unwrap results.
pub struct Pkcs11AesKey {
    token: Arc<Token>,
    object: ObjectHandle,
    length: usize,
    temporary: bool,
}

fn import_content_key(
    token: &Arc<Token>,
    algorithm: DataEncryptionAlgorithm,
    mut value: Vec<u8>,
) -> Result<Pkcs11AesKey, ProviderError> {
    use zeroize::Zeroize;
    let length = value.len();
    if length != algorithm.key_len() {
        value.zeroize();
        return Err(ProviderError::InvalidKeySize {
            expected: algorithm.key_len(),
            actual: length,
        });
    }
    let mut attributes = [
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Token(false),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Decrypt(true),
        Attribute::Value(value),
    ];
    // Erase the only owned host copy on success, module failure or a poisoned session.
    let result = token
        .session()
        .and_then(|session| session.create_object(&attributes).map_err(map_error));
    if let Attribute::Value(value) = &mut attributes[6] {
        value.zeroize();
    }
    result.map(|object| Pkcs11AesKey {
        token: token.clone(),
        object,
        length,
        temporary: true,
    })
}

impl Drop for Pkcs11AesKey {
    fn drop(&mut self) {
        if self.temporary
            && let Ok(session) = self.token.session()
        {
            let _ = session.destroy_object(self.object);
        }
    }
}

impl ContentDecryptionKey for Pkcs11AesKey {
    fn provider_binding(&self) -> &ProviderBinding {
        &self.token.binding
    }
    fn key_len(&self) -> usize {
        self.length
    }
    fn decrypt_with_provider(
        &self,
        provider: &dyn CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        self.token.check_binding(provider)?;
        provider.require_capability(ProviderCapability::Decrypt(algorithm))?;
        if self.length != algorithm.key_len() {
            return Err(ProviderError::InvalidKeySize {
                expected: algorithm.key_len(),
                actual: self.length,
            });
        }
        let session = self.token.session()?;
        require_usage(&session, self.object, AttributeType::Decrypt)?;
        if content_mechanism(algorithm) == Some(MechanismType::AES_GCM) {
            if ciphertext.len() < 28 {
                return Err(ProviderError::InvalidInput(
                    super::ProviderInputError::AesGcmFraming,
                ));
            }
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&ciphertext[..12]);
            let params = cryptoki::mechanism::aead::GcmParams::new(&mut nonce, &[], 128.into())
                .map_err(map_error)?;
            session
                .decrypt(&Mechanism::AesGcm(params), self.object, &ciphertext[12..])
                .map_err(map_error)
        } else {
            if ciphertext.len() < 32 || !ciphertext.len().is_multiple_of(16) {
                return Err(ProviderError::InvalidInput(
                    super::ProviderInputError::AesCbcFraming,
                ));
            }
            let mut iv = [0u8; 16];
            iv.copy_from_slice(&ciphertext[..16]);
            let mut plaintext = session
                .decrypt(&Mechanism::AesCbc(iv), self.object, &ciphertext[16..])
                .map_err(map_error)?;
            // XMLEnc §5.2.1 permits arbitrary padding bytes; PKCS#7 CBC_PAD is not equivalent.
            // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-AES
            let padding = usize::from(
                *plaintext
                    .last()
                    .ok_or(ProviderError::AuthenticationFailed)?,
            );
            if padding == 0 || padding > 16 || padding > plaintext.len() {
                zeroize::Zeroize::zeroize(&mut plaintext);
                return Err(ProviderError::AuthenticationFailed);
            }
            plaintext.truncate(plaintext.len() - padding);
            Ok(plaintext)
        }
    }
}

impl super::KeyUnwrappingKey for Pkcs11AesKey {
    fn provider_binding(&self) -> &ProviderBinding {
        &self.token.binding
    }
    fn unwrap_with_provider(
        &self,
        provider: &dyn CryptoProvider,
        algorithm: KeyWrapAlgorithm,
        content_algorithm: DataEncryptionAlgorithm,
        wrapped: &[u8],
    ) -> Result<RecoveredContentKey, ProviderError> {
        self.token.check_binding(provider)?;
        provider.require_capability(ProviderCapability::KeyUnwrap(algorithm))?;
        provider.require_capability(ProviderCapability::Decrypt(content_algorithm))?;
        if self.length != algorithm.key_len() {
            return Err(ProviderError::InvalidKeySize {
                expected: algorithm.key_len(),
                actual: self.length,
            });
        }
        if wrapped.len() != content_algorithm.key_len() + 8 {
            return Err(ProviderError::AuthenticationFailed);
        }
        let session = self.token.session()?;
        require_usage(&session, self.object, AttributeType::Unwrap)?;
        // PKCS#11 Base §5.13 C_UnwrapKey defaults CKA_EXTRACTABLE to true.
        // Set it explicitly: the resulting CEK stays in the token until destruction.
        // https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html
        let object = session
            .unwrap_key(
                &Mechanism::AesKeyWrap,
                self.object,
                wrapped,
                &[
                    Attribute::Class(ObjectClass::SECRET_KEY),
                    Attribute::KeyType(KeyType::AES),
                    Attribute::Token(false),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                    Attribute::Decrypt(true),
                ],
            )
            .map_err(map_error)?;
        let key = Pkcs11AesKey {
            token: self.token.clone(),
            object,
            length: content_algorithm.key_len(),
            temporary: true,
        };
        // Release the session before the temporary key's destructor can acquire it.
        drop(session);
        Ok(RecoveredContentKey::opaque(Arc::new(key)))
    }
}

/// Opaque EC base key. Only the derived shared secret, never the private scalar, is returned.
pub struct Pkcs11AgreementKey {
    token: Arc<Token>,
    object: ObjectHandle,
    width: usize,
}

impl KeyAgreementKey for Pkcs11AgreementKey {
    fn provider_binding(&self) -> Option<&ProviderBinding> {
        Some(&self.token.binding)
    }
    fn agree(&self, parameters: &KeyAgreementParameters<'_>) -> Result<Vec<u8>, ProviderError> {
        if parameters.algorithm != "http://www.w3.org/2009/xmlenc11#ECDH-ES" {
            return Err(unsupported(ProviderCapability::KeyAgreement(parameters)));
        }
        // SEC 1 §2.3.3: the adapter accepts uncompressed points only. The token
        // validates curve membership; reject framing before invoking C_DeriveKey.
        // https://www.secg.org/sec1-v2.pdf
        if parameters.peer_public_key.len() != 1 + self.width * 2
            || parameters.peer_public_key[0] != 4
        {
            return Err(external(ExternalProviderError::Object));
        }
        let session = self.token.session()?;
        require_usage(&session, self.object, AttributeType::Derive)?;
        let object = session
            .derive_key(
                &Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(
                    EcKdf::null(),
                    parameters.peer_public_key,
                )),
                self.object,
                &[
                    Attribute::Class(ObjectClass::SECRET_KEY),
                    Attribute::KeyType(KeyType::GENERIC_SECRET),
                    Attribute::Token(false),
                    Attribute::Sensitive(false),
                    Attribute::Extractable(true),
                    Attribute::ValueLen(
                        cryptoki::types::Ulong::try_from(self.width).map_err(map_error)?,
                    ),
                ],
            )
            .map_err(map_error)?;
        let result = session
            .get_attributes(object, &[AttributeType::Value])
            .map_err(map_error);
        let cleanup = session.destroy_object(object).map_err(map_error);
        let mut attributes = result?;
        let mut value = attributes
            .iter_mut()
            .find_map(|attribute| match attribute {
                Attribute::Value(value) => Some(std::mem::take(value)),
                _ => None,
            })
            .ok_or(external(ExternalProviderError::Object))?;
        if let Err(error) = cleanup {
            zeroize::Zeroize::zeroize(&mut value);
            return Err(error);
        }
        if value.len() != self.width {
            zeroize::Zeroize::zeroize(&mut value);
            return Err(external(ExternalProviderError::Operation));
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptoki::context::Function;

    #[test]
    fn external_failures_are_typed_and_redacted() {
        // Module-specific diagnostics must not escape into credential or object errors.
        for (native, expected) in [
            (RvError::PinIncorrect, ExternalProviderError::Credentials),
            (RvError::ObjectHandleInvalid, ExternalProviderError::Object),
            (
                RvError::KeyFunctionNotPermitted,
                ExternalProviderError::Usage,
            ),
            (RvError::TokenNotPresent, ExternalProviderError::Unavailable),
            (RvError::GeneralError, ExternalProviderError::Operation),
        ] {
            let result = map_error(Error::Pkcs11(native, Function::Decrypt));
            assert!(matches!(result, ProviderError::External(actual) if actual == expected));
        }
        assert!(matches!(
            map_error(Error::Pkcs11(
                RvError::EncryptedDataInvalid,
                Function::Decrypt
            )),
            ProviderError::AuthenticationFailed
        ));
    }

    #[test]
    fn oaep_parameter_rejection_never_implies_digest_downgrade() {
        // SoftHSM reports ArgumentsBad for an unsupported SHA-256 OAEP selection.
        let parameters = RsaOaepParameters::default();
        let error = oaep_error(
            Error::Pkcs11(RvError::ArgumentsBad, Function::DecryptInit),
            ProviderCapability::KeyRecovery(&parameters),
        );
        assert!(matches!(
            error,
            ProviderError::Unsupported {
                operation: ProviderOperation::KeyRecovery,
                ..
            }
        ));
    }

    #[test]
    fn binding_clones_keep_identity_but_new_domains_do_not() {
        // Same engine name is not sufficient to move an opaque handle across sessions.
        let binding = ProviderBinding::default();
        assert!(binding.matches(&binding.clone()));
        assert!(!binding.matches(&ProviderBinding::default()));
    }
}
