//! The objects behind the handles, and the safe operations the FFI module
//! calls with already-validated Rust values.
#![forbid(unsafe_code)]

use crate::status::{
    XS_CANONICALIZATION, XS_CONFIGURATION, XS_DOCUMENT, XS_ENCRYPTION, XS_INVALID_ARGUMENT, XS_KEY,
    XS_OPERATION_DISABLED, XS_POLICY, XS_SIGNING, XS_VERIFICATION, XsStatus,
};
use crate::table::Kind;
use parking_lot::{Mutex, RwLock};
use std::sync::Arc;
use xml_sec::api::Operation;
use xml_sec::key_establishment::EncapsulationMechanism;
use xml_sec::key_manager::{KeyInventory, KeyStoreError, KeyUsages, SymmetricKeyKind};
use xml_sec::policy::{
    AlgorithmRole, CompiledPolicies, Instant, ManifestProcessing, PolicyAudit,
    PolicyCompileContext, PolicyDecision, PolicyIdentity, PolicyValidity, PolicyViolation,
    ResourcePolicy, UriRole,
};
use xml_sec::provider::{CryptoProvider, RecoveredContentKey};
use xml_sec::xmldsig::{
    DsigError, DsigStatus, InspectedKeyCandidateBudget, KeyInfo, KeyInfoSource, KeyResolver,
    KeyTrustEvidence, ResolvedVerificationKey, SignatureAlgorithm, SignatureRequirement,
    SigningKey, UriClass, VerificationRequest, VerifyEvidence, VerifyingKey,
};
use xml_sec::xmlenc::{
    AgreementMethod, DataEncryptionAlgorithm, DecryptionKeyResolver, DerivedKey,
    DocumentEncryptionOptions, EncryptedDataBuilder, EncryptedKey, EncryptionRecipient,
    KeyCandidateBudget, KeyEncryptionKeySource, KeyWrapAlgorithm, XmlEncError,
};
use xml_sec::{SharedSecurity, XmlBackend, XmlDocument, XmlDocumentError, XmlSecError};
use xml_sec_config::{Configuration, LoadLimits, PolicyStore, Source};

#[cfg(test)]
mod tests;

/// Why a call failed: the status it returns, the `XS_VIOLATION_*` of a policy
/// refusal (zero otherwise), and the diagnostic its error handle carries.
pub(crate) struct Failure {
    pub(crate) status: XsStatus,
    pub(crate) violation: u32,
    pub(crate) message: String,
}

impl Failure {
    pub(crate) fn new(status: XsStatus, message: impl Into<String>) -> Self {
        Self {
            status,
            violation: 0,
            message: message.into(),
        }
    }

    fn refused(violation: &PolicyViolation, message: String) -> Self {
        Self {
            status: XS_POLICY,
            violation: violation_code(violation),
            message,
        }
    }
}

impl From<XsStatus> for Failure {
    fn from(status: XsStatus) -> Self {
        Self::new(status, status_text(status))
    }
}

impl From<XmlSecError> for Failure {
    fn from(error: XmlSecError) -> Self {
        let message = error.to_string();
        let status = match &error {
            XmlSecError::Policy(violation)
            | XmlSecError::Verification(xml_sec::xmldsig::DsigError::Policy(violation))
            | XmlSecError::Signing(xml_sec::xmldsig::SigningError::Policy(violation))
            | XmlSecError::KeyStore(xml_sec::key_manager::KeyStoreError::Policy(violation))
            | XmlSecError::Encryption(xml_sec::xmlenc::XmlEncError::Policy(violation))
            // The policy-bound parse reports every ceiling of the compiled
            // policy as a typed violation.
            | XmlSecError::Document(XmlDocumentError::Policy(violation)) => {
                return Self::refused(violation, message);
            }
            XmlSecError::OperationDisabled(_) => XS_OPERATION_DISABLED,
            XmlSecError::Document(_) => XS_DOCUMENT,
            XmlSecError::Canonicalization(_) => XS_CANONICALIZATION,
            XmlSecError::Verification(_) => XS_VERIFICATION,
            XmlSecError::Signing(_) => XS_SIGNING,
            XmlSecError::KeyStore(_) => XS_KEY,
            XmlSecError::Encryption(_) => XS_ENCRYPTION,
            _ => crate::status::XS_INTERNAL,
        };
        Self::new(status, message)
    }
}

impl From<xml_sec_config::Error> for Failure {
    fn from(error: xml_sec_config::Error) -> Self {
        let message = error.to_string();
        match &error {
            xml_sec_config::Error::Policy(violation) => Self::refused(violation, message),
            _ => Self::new(XS_CONFIGURATION, message),
        }
    }
}

/// `XS_VIOLATION_RESOURCE_LIMIT`.
const RESOURCE_LIMIT: u32 = 8;

/// The `XS_VIOLATION_*` of `violation`; zero for a kind the header does not name.
pub(crate) fn violation_code(violation: &PolicyViolation) -> u32 {
    match violation {
        PolicyViolation::Configuration { .. } => 1,
        PolicyViolation::ManifestProcessingDisabled => 2,
        PolicyViolation::AttestedDigestForbidden => 3,
        PolicyViolation::SignatureProfile { .. } => 4,
        PolicyViolation::AuthorizationExpired => 5,
        PolicyViolation::Algorithm { .. } => 6,
        PolicyViolation::HmacOutputLength { .. } => 7,
        PolicyViolation::ResourceLimit { .. } | PolicyViolation::ResourceLimitExceeded { .. } => {
            RESOURCE_LIMIT
        }
        PolicyViolation::KdfIterationsOutsideLimit { .. } => 9,
        PolicyViolation::InvalidResourceLimit { .. } => 10,
        PolicyViolation::KeyTrust { .. } => 11,
        PolicyViolation::XmlInput { .. } => 12,
        PolicyViolation::Uri { .. } => 13,
        PolicyViolation::KeySize { .. } => 14,
        PolicyViolation::InvalidKeyMaterial { .. } => 15,
        _ => 0,
    }
}

/// A short description of a status without other detail.
pub(crate) fn status_text(status: XsStatus) -> &'static str {
    match status {
        crate::status::XS_INVALID_ARGUMENT => "invalid argument",
        crate::status::XS_WRONG_HANDLE => "handle names another object type",
        crate::status::XS_STALE_HANDLE => "stale handle",
        crate::status::XS_DESTROYED_HANDLE => "destroyed handle",
        crate::status::XS_BUSY => "object in use",
        crate::status::XS_HANDLE_LIMIT => "handle table full",
        XS_OPERATION_DISABLED => "operation disabled by the compiled policy",
        _ => "operation failed",
    }
}

/// Everything a handle can name.
pub(crate) enum Object {
    Provider(Arc<dyn CryptoProvider>),
    PolicyStore(PolicyStore),
    Policy(Arc<CompiledPolicies>),
    Keys(Arc<Keys>),
    Document(Mutex<XmlDocument>),
    Signer(Signer),
    Verifier(Verifier),
    // Boxed: the builder is several times larger than every other object.
    Encryptor(Box<Encryptor>),
    Decryptor(Decryptor),
    Evidence(VerifyEvidence),
    Audit(Audit),
    Error(Failure),
}

impl Object {
    pub(crate) fn kind(&self) -> Kind {
        match self {
            Self::Provider(_) => Kind::Provider,
            Self::PolicyStore(_) => Kind::PolicyStore,
            Self::Policy(_) => Kind::Policy,
            Self::Keys(_) => Kind::Keys,
            Self::Document(_) => Kind::Document,
            Self::Signer(_) => Kind::Signer,
            Self::Verifier(_) => Kind::Verifier,
            Self::Encryptor(_) => Kind::Encryptor,
            Self::Decryptor(_) => Kind::Decryptor,
            Self::Evidence(_) => Kind::Evidence,
            Self::Audit(_) => Kind::Audit,
            Self::Error(_) => Kind::Error,
        }
    }
}

/// `XS_OPERATION_*`: the operation whose compiled policy applies.
pub(crate) fn operation(value: u32) -> Result<Operation, Failure> {
    Ok(match value {
        1 => Operation::Verify,
        2 => Operation::Sign,
        3 => Operation::Encrypt,
        4 => Operation::Decrypt,
        _ => return Err(Failure::new(XS_INVALID_ARGUMENT, "unknown operation")),
    })
}

fn resources(policies: &CompiledPolicies, operation: Operation) -> Option<&ResourcePolicy> {
    match operation {
        Operation::Verify => policies.verification().map(|policy| &policy.resources),
        Operation::Sign => policies.signing().map(|policy| &policy.resources),
        Operation::Encrypt => policies.encryption().map(|policy| &policy.resources),
        Operation::Decrypt => policies.decryption().map(|policy| &policy.resources),
        _ => None,
    }
}

fn disabled(operation: Operation) -> Failure {
    XmlSecError::OperationDisabled(operation).into()
}

/// A compiled-policy grant the application authenticated.
pub(crate) struct Grant<'a> {
    pub(crate) authorization_id: &'a str,
    pub(crate) authority: &'a str,
    pub(crate) reason: &'a str,
    pub(crate) not_before: (i64, u32),
    pub(crate) expires_at: (i64, u32),
}

fn instant((seconds, nanos): (i64, u32)) -> Result<Instant, Failure> {
    Instant::new(seconds, nanos).ok_or_else(|| Failure::new(XS_INVALID_ARGUMENT, "invalid instant"))
}

/// What a policy store compiles.
pub(crate) struct PolicySource<'a> {
    pub(crate) configuration: &'a str,
    pub(crate) profile: &'a str,
    pub(crate) provider: &'a dyn CryptoProvider,
    pub(crate) context: PolicyCompileContext,
    pub(crate) grant: Option<Grant<'a>>,
}

impl PolicySource<'_> {
    fn publish<T>(
        &self,
        publish: impl FnOnce(Source<'_>) -> Result<T, xml_sec_config::Error>,
    ) -> Result<T, Failure> {
        let configuration = Configuration::from_str(self.configuration, LoadLimits::default())?;
        let authorization = self
            .grant
            .as_ref()
            .map(|grant| {
                Ok::<_, Failure>(PolicyValidity {
                    authorization_id: grant.authorization_id.into(),
                    authority: grant.authority.into(),
                    reason: grant.reason.into(),
                    not_before: instant(grant.not_before)?,
                    expires_at: instant(grant.expires_at)?,
                })
            })
            .transpose()?;
        Ok(publish(Source {
            configuration: &configuration,
            profile: self.profile,
            provider: self.provider,
            context: &self.context,
            authorization,
        })?)
    }

    pub(crate) fn new_store(&self) -> Result<PolicyStore, Failure> {
        self.publish(PolicyStore::new)
    }

    pub(crate) fn replace(&self, store: &PolicyStore) -> Result<(), Failure> {
        self.publish(|source| store.replace(source)).map(drop)
    }
}

/// A key manager, with the resource policy its imports are bounded by and
/// the names it holds, in import order.
pub(crate) struct Keys {
    inventory: RwLock<KeyInventory>,
    resources: ResourcePolicy,
    names: Mutex<Vec<String>>,
}

/// `XS_KEY_USAGE_*` bits, the same values as [`KeyUsages`].
fn usages(bits: u32) -> Result<KeyUsages, Failure> {
    let mut usages: Option<KeyUsages> = None;
    for (bit, usage) in [
        (1, KeyUsages::SIGN),
        (2, KeyUsages::VERIFY),
        (4, KeyUsages::ENCRYPT),
        (8, KeyUsages::DECRYPT),
    ] {
        if bits & bit != 0 {
            usages = Some(usages.map_or(usage, |usages| usages.union(usage)));
        }
    }
    if bits & !0xf != 0 {
        return Err(Failure::new(XS_INVALID_ARGUMENT, "unknown key usage"));
    }
    usages.ok_or_else(|| Failure::new(XS_INVALID_ARGUMENT, "no key usage"))
}

/// The key kinds `XS_SYMMETRIC_*` name.
fn symmetric_kind(value: u32) -> Result<SymmetricKeyKind, Failure> {
    Ok(match value {
        1 => SymmetricKeyKind::Hmac,
        2 => SymmetricKeyKind::Aes,
        3 => SymmetricKeyKind::Camellia,
        4 => SymmetricKeyKind::ChaCha20,
        _ => {
            return Err(Failure::new(
                XS_INVALID_ARGUMENT,
                "unknown symmetric key kind",
            ));
        }
    })
}

fn key_failure(error: xml_sec::key_manager::KeyStoreError) -> Failure {
    XmlSecError::from(error).into()
}

impl Keys {
    pub(crate) fn new(policies: &CompiledPolicies, operation: Operation) -> Result<Self, Failure> {
        Ok(Self::bounded_by(
            resources(policies, operation)
                .ok_or_else(|| disabled(operation))?
                .clone(),
        ))
    }

    fn bounded_by(resources: ResourcePolicy) -> Self {
        Self {
            inventory: RwLock::new(KeyInventory::default()),
            resources,
            names: Mutex::new(Vec::new()),
        }
    }

    /// Record `name` once `imported` succeeded.
    fn named(&self, name: &str, imported: Result<(), Failure>) -> Result<(), Failure> {
        imported?;
        self.names.lock().push(name.to_owned());
        Ok(())
    }

    pub(crate) fn add_private_pem(
        &self,
        name: &str,
        pem: &[u8],
        password: Option<&[u8]>,
        usage_bits: u32,
    ) -> Result<(), Failure> {
        let usages = usages(usage_bits)?;
        let imported = self
            .inventory
            .write()
            .add_private_pem(name, pem, password, usages, &self.resources)
            .map_err(key_failure);
        self.named(name, imported)
    }

    pub(crate) fn add_public_pem(
        &self,
        name: &str,
        pem: &[u8],
        usage_bits: u32,
    ) -> Result<(), Failure> {
        let usages = usages(usage_bits)?;
        let imported = self
            .inventory
            .write()
            .add_public_pem_with_usages(name, pem, usages, &self.resources)
            .map_err(key_failure);
        self.named(name, imported)
    }

    pub(crate) fn add_symmetric(
        &self,
        name: &str,
        kind: u32,
        key: &[u8],
        usage_bits: u32,
    ) -> Result<(), Failure> {
        let (kind, usages) = (symmetric_kind(kind)?, usages(usage_bits)?);
        let imported = self
            .inventory
            .write()
            .add_symmetric(name, kind, key, usages, &self.resources)
            .map_err(key_failure);
        self.named(name, imported)
    }
}

/// An application's key store, asked while an operation resolves one key:
/// given the key names the document gives and the method the key serves, it
/// imports the keys it holds into `keys`. Keys found reach the operation
/// through the same validation, resource policy and trust as any key manager.
pub(crate) trait KeyLookup {
    /// Import the keys matching `names` and `method` into `keys`.
    fn lookup(&self, names: &[&str], method: &str, keys: &Arc<Keys>) -> Result<(), Failure>;
}

/// The key manager every lookup of one operation fills, so the operation's
/// key-import work, material and candidate allowances are counted once for
/// the whole operation; and the first lookup failure, which fails the call.
struct LookupScope<'a> {
    lookup: &'a dyn KeyLookup,
    keys: Mutex<Option<Arc<Keys>>>,
    /// Methods already asked for without a key name.
    unnamed: Mutex<Vec<String>>,
    failure: Mutex<Option<Failure>>,
}

impl<'a> LookupScope<'a> {
    fn new(lookup: &'a dyn KeyLookup) -> Self {
        Self {
            lookup,
            keys: Mutex::new(None),
            unnamed: Mutex::new(Vec::new()),
            failure: Mutex::new(None),
        }
    }

    /// The operation's key manager after asking the lookup for `names`, and
    /// the names that lookup imported. A lookup is asked only for names it
    /// has not imported, and once per method for a request without names, so
    /// a store never imports one key twice; after a failure none is asked.
    fn fill(
        &self,
        names: &[&str],
        method: &str,
        resources: &ResourcePolicy,
    ) -> Option<(Arc<Keys>, Vec<String>)> {
        if self.failure.lock().is_some() {
            return None;
        }
        let keys = Arc::clone(
            self.keys
                .lock()
                .get_or_insert_with(|| Arc::new(Keys::bounded_by(resources.clone()))),
        );
        let (before, missing) = {
            let held = keys.names.lock();
            // A document may repeat a KeyName; each name is asked for once.
            let mut missing: Vec<&str> = Vec::with_capacity(names.len());
            for &name in names {
                if !held.iter().any(|held| held == name) && !missing.contains(&name) {
                    missing.push(name);
                }
            }
            (held.len(), missing)
        };
        let asked = if names.is_empty() {
            let mut unnamed = self.unnamed.lock();
            let asked = unnamed.iter().any(|served| served == method);
            if !asked {
                unnamed.push(method.to_owned());
            }
            asked
        } else {
            missing.is_empty()
        };
        if asked {
            return Some((keys, Vec::new()));
        }
        // No lock of this scope is held while the application runs, so its
        // lookup may import into `keys` and reenter the library.
        if let Err(failure) = self.lookup.lookup(&missing, method, &keys) {
            *self.failure.lock() = Some(failure);
            return None;
        }
        let imported = keys.names.lock()[before..].to_vec();
        Some((keys, imported))
    }

    /// The failure that ends the call, if a lookup failed.
    fn into_failure(self) -> Option<Failure> {
        self.failure.into_inner()
    }
}

/// The `KeyName` values of `key_info`, in document order.
fn key_names(key_info: Option<&KeyInfo>) -> Vec<&str> {
    key_info
        .into_iter()
        .flat_map(|info| &info.sources)
        .filter_map(|source| match source {
            KeyInfoSource::KeyName(name) => Some(name.as_str()),
            _ => None,
        })
        .collect()
}

/// Verification keys from a lookup, resolved by the key-manager rules over
/// what it imported: the document's names select application keys, and its
/// other `KeyInfo` sources go through the policy's X.509 and key-source rules.
struct LookupVerification<'a> {
    scope: LookupScope<'a>,
}

impl KeyResolver for LookupVerification<'_> {
    fn resolve<'k>(
        &'k self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
    ) -> Result<Option<Box<dyn VerifyingKey + 'k>>, DsigError> {
        self.resolve_with_policy_and_provider(
            key_info,
            algorithm,
            &xml_sec::policy::VerificationPolicy::default(),
            xml_sec::provider::default_provider(),
        )
    }

    fn resolve_with_policy_and_provider<'k>(
        &'k self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
        policy: &xml_sec::policy::VerificationPolicy,
        provider: &dyn CryptoProvider,
    ) -> Result<Option<Box<dyn VerifyingKey + 'k>>, DsigError> {
        self.resolve_for_verification(key_info, algorithm, policy, provider)
            .map(|key| key.map(ResolvedVerificationKey::into_key))
    }

    fn resolve_for_verification<'k>(
        &'k self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
        policy: &xml_sec::policy::VerificationPolicy,
        provider: &dyn CryptoProvider,
    ) -> Result<Option<ResolvedVerificationKey<'k>>, DsigError> {
        let mut budget = InspectedKeyCandidateBudget::new(policy);
        self.resolve_for_verification_with_budget(
            key_info,
            algorithm,
            policy,
            provider,
            &mut budget,
        )
    }

    fn resolve_for_verification_with_budget<'k>(
        &'k self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
        policy: &xml_sec::policy::VerificationPolicy,
        provider: &dyn CryptoProvider,
        budget: &mut InspectedKeyCandidateBudget,
    ) -> Result<Option<ResolvedVerificationKey<'k>>, DsigError> {
        let Some((keys, _)) =
            self.scope
                .fill(&key_names(key_info), algorithm.uri(), &policy.resources)
        else {
            return Err(DsigError::InvalidStructure {
                reason: "key lookup failed",
            });
        };
        let inventory = keys.inventory.read();
        inventory
            .verification_resolver()
            .resolve_owned(key_info, algorithm, policy, provider, budget)
    }

    fn consumes_document_key_info(&self) -> bool {
        true
    }
}

/// Decryption keys from a lookup, selected by the document's key name, or by
/// the one key the lookup imported when the document names none. Every
/// resolver method is forwarded, so recipient keys keep the core's
/// acceptance checks.
struct LookupDecryption<'a> {
    scope: LookupScope<'a>,
    /// One resolver per key name and method: a content key and a transport
    /// key without names are different requests.
    resolvers: Mutex<Vec<DecryptionResolution>>,
}

/// A resolved request: its key name and method, and the selected resolver.
type DecryptionResolution = (
    Option<String>,
    String,
    Arc<dyn DecryptionKeyResolver + Send + Sync>,
);

impl LookupDecryption<'_> {
    /// The resolver for the key `name` selects, asking the lookup for it.
    fn resolver(
        &self,
        name: Option<&str>,
        method: &str,
        policy: &xml_sec::policy::DecryptionPolicy,
        provider: &dyn CryptoProvider,
    ) -> Result<Arc<dyn DecryptionKeyResolver + Send + Sync>, XmlEncError> {
        if let Some((_, _, found)) = self
            .resolvers
            .lock()
            .iter()
            .find(|(cached, served, _)| cached.as_deref() == name && served == method)
        {
            return Ok(Arc::clone(found));
        }
        let (keys, imported) = self
            .scope
            .fill(name.as_slice(), method, &policy.resources)
            // A failed lookup ends the operation before any recovered key
            // can decrypt and replace the content.
            .ok_or(XmlEncError::KeyResolverAborted)?;
        let selected = match (name, imported.as_slice()) {
            (Some(name), _) => name.to_owned(),
            (None, [only]) => only.clone(),
            (None, _) => return Err(XmlEncError::KeyNotFound),
        };
        let resolver: Arc<dyn DecryptionKeyResolver + Send + Sync> = keys
            .inventory
            .read()
            .decryption_resolver_with_provider(&selected, policy, provider)
            .map_err(|error| match error {
                // A policy refusal ends the operation; any other selection
                // failure leaves later key sources eligible.
                KeyStoreError::Policy(violation) => XmlEncError::Policy(violation),
                _ => XmlEncError::KeyNotFound,
            })?
            .into();
        self.resolvers.lock().push((
            name.map(str::to_owned),
            method.to_owned(),
            Arc::clone(&resolver),
        ));
        Ok(resolver)
    }
}

impl DecryptionKeyResolver for LookupDecryption<'_> {
    fn resolve_encapsulation_content_keys_with_policy(
        &self,
        provider: &dyn CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        descriptor: &EncapsulationMechanism,
        policy: &xml_sec::policy::DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<RecoveredContentKey>, XmlEncError> {
        self.resolver(None, algorithm.uri(), policy, provider)?
            .resolve_encapsulation_content_keys_with_policy(
                provider, algorithm, descriptor, policy, budget,
            )
    }

    fn resolve_key_encryption_keys_with_policy(
        &self,
        provider: &dyn CryptoProvider,
        algorithm: KeyWrapAlgorithm,
        source: KeyEncryptionKeySource<'_>,
        policy: &xml_sec::policy::DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<RecoveredContentKey>, XmlEncError> {
        // A nested key is asked for under its own name and transport method,
        // the ones the key that unwraps it serves; the outer wrap method still
        // drives the recovery below.
        let (name, method) = match &source {
            KeyEncryptionKeySource::Encrypted(key) => (
                key.key_name.as_deref(),
                key.encryption_method.algorithm.as_str(),
            ),
            _ => (None, algorithm.uri()),
        };
        self.resolver(name, method, policy, provider)?
            .resolve_key_encryption_keys_with_policy(provider, algorithm, source, policy, budget)
    }

    fn resolve_agreement_content_keys_with_policy(
        &self,
        provider: &dyn CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        descriptor: &AgreementMethod,
        policy: &xml_sec::policy::DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<RecoveredContentKey>, XmlEncError> {
        self.resolver(None, algorithm.uri(), policy, provider)?
            .resolve_agreement_content_keys_with_policy(
                provider, algorithm, descriptor, policy, budget,
            )
    }

    fn resolve_derived_content_keys_with_policy(
        &self,
        provider: &dyn CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        descriptor: &DerivedKey,
        policy: &xml_sec::policy::DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<RecoveredContentKey>, XmlEncError> {
        self.resolver(None, algorithm.uri(), policy, provider)?
            .resolve_derived_content_keys_with_policy(
                provider, algorithm, descriptor, policy, budget,
            )
    }

    fn resolve_content_keys_with_policy(
        &self,
        provider: &dyn CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
        policy: &xml_sec::policy::DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<RecoveredContentKey>, XmlEncError> {
        let (name, method) = recipient(encrypted_key, algorithm);
        self.resolver(name, method, policy, provider)?
            .resolve_content_keys_with_policy(provider, algorithm, encrypted_key, policy, budget)
    }

    fn resolve_key_candidates_with_policy(
        &self,
        provider: &dyn CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
        policy: &xml_sec::policy::DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<Vec<u8>>, XmlEncError> {
        let (name, method) = recipient(encrypted_key, algorithm);
        self.resolver(name, method, policy, provider)?
            .resolve_key_candidates_with_policy(provider, algorithm, encrypted_key, policy, budget)
    }

    // A lookup's keys are bounded by the operation's policy, so a resolution
    // without one finds nothing rather than importing unbounded.
    fn resolve_key(
        &self,
        _provider: &dyn CryptoProvider,
        _algorithm: DataEncryptionAlgorithm,
        _encrypted_key: Option<&EncryptedKey>,
    ) -> Result<Vec<u8>, XmlEncError> {
        Err(XmlEncError::KeyNotFound)
    }
}

/// The key name and method a content key's source names: an `EncryptedKey`'s
/// own `KeyName` and transport method, or none and the content method.
fn recipient(
    encrypted_key: Option<&EncryptedKey>,
    algorithm: DataEncryptionAlgorithm,
) -> (Option<&str>, &str) {
    encrypted_key.map_or((None, algorithm.uri()), |key| {
        (
            key.key_name.as_deref(),
            key.encryption_method.algorithm.as_str(),
        )
    })
}

/// Bind `policies` to `provider` once for an operation handle.
pub(crate) fn security(
    policies: &Arc<CompiledPolicies>,
    provider: &Arc<dyn CryptoProvider>,
) -> Result<SharedSecurity, Failure> {
    Ok(SharedSecurity::new(
        Arc::clone(policies),
        Arc::clone(provider),
    )?)
}

/// Parse `xml` under the compiled policy of `operation`. The core checks the
/// policy's byte ceiling before it copies the borrowed input.
pub(crate) fn parse_document(
    policies: &CompiledPolicies,
    operation: Operation,
    xml: &str,
) -> Result<XmlDocument, Failure> {
    let backend = XmlBackend::default();
    let parsed = match operation {
        Operation::Verify => XmlDocument::parse_with_policy_and_backend(
            xml,
            policies.verification().ok_or_else(|| disabled(operation))?,
            backend,
        ),
        Operation::Sign => XmlDocument::parse_with_policy_and_backend(
            xml,
            policies.signing().ok_or_else(|| disabled(operation))?,
            backend,
        ),
        Operation::Encrypt => XmlDocument::parse_with_policy_and_backend(
            xml,
            policies.encryption().ok_or_else(|| disabled(operation))?,
            backend,
        ),
        Operation::Decrypt => XmlDocument::parse_with_policy_and_backend(
            xml,
            policies.decryption().ok_or_else(|| disabled(operation))?,
            backend,
        ),
        _ => return Err(disabled(operation)),
    };
    Ok(parsed.map_err(XmlSecError::from)?)
}

/// A signing operation with its key selected once.
pub(crate) struct Signer {
    security: SharedSecurity,
    key: Box<dyn SigningKey + Send + Sync>,
}

impl Signer {
    pub(crate) fn new(
        security: SharedSecurity,
        keys: &Keys,
        name: &str,
        method: &str,
    ) -> Result<Self, Failure> {
        let algorithm = SignatureAlgorithm::from_uri(method)
            .ok_or_else(|| Failure::new(XS_INVALID_ARGUMENT, "unknown signature method"))?;
        let key = security
            .binding()
            .signing_key(&keys.inventory.read(), name, algorithm)?;
        Ok(Self { security, key })
    }

    /// Fill the document's signature template.
    pub(crate) fn sign(&self, document: &mut XmlDocument) -> Result<PolicyAudit, Failure> {
        Ok(self
            .security
            .binding()
            .signer(&*self.key)?
            .sign_template(document)?)
    }
}

/// A verification operation, with the key manager it resolves keys from.
pub(crate) struct Verifier {
    security: SharedSecurity,
    keys: Option<Arc<Keys>>,
}

/// `XS_REQUIRE_*`: how many signatures must pass.
pub(crate) fn requirement(kind: u32, count: usize) -> Result<SignatureRequirement, Failure> {
    Ok(match kind {
        0 => SignatureRequirement::All,
        1 => SignatureRequirement::AtLeast(count),
        2 => SignatureRequirement::Exactly(count),
        _ => {
            return Err(Failure::new(
                XS_INVALID_ARGUMENT,
                "unknown signature requirement",
            ));
        }
    })
}

impl Verifier {
    pub(crate) fn new(security: SharedSecurity, keys: Option<Arc<Keys>>) -> Self {
        Self { security, keys }
    }

    /// Refuse a request for more expected targets than the policy admits,
    /// before any ID is read or looked up in the document.
    pub(crate) fn check_target_count(&self, count: usize) -> Result<(), Failure> {
        let policy = self
            .security
            .policies()
            .verification()
            .ok_or_else(|| disabled(Operation::Verify))?;
        VerificationRequest::check_target_count(policy, count)
            .map_err(|error| XmlSecError::from(error).into())
    }

    /// Verify `document`, requiring the elements whose ID is in
    /// `expected_ids` to be authenticated. A `lookup` supplies the keys for
    /// this call in place of the verifier's key manager.
    pub(crate) fn verify(
        &self,
        document: &XmlDocument,
        expected_ids: &[&str],
        signatures: SignatureRequirement,
        lookup: Option<&dyn KeyLookup>,
    ) -> Result<VerifyEvidence, Failure> {
        let targets = document.with_view(|view| {
            expected_ids
                .iter()
                .map(|id| {
                    view.node_for_id(id, &[]).ok_or_else(|| {
                        Failure::new(XS_DOCUMENT, "expected target ID not found or ambiguous")
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        })?;
        let request = VerificationRequest {
            expected_targets: &targets,
            signatures,
            ..VerificationRequest::default()
        };
        let binding = self.security.binding();
        let verifier = binding.verifier()?;
        if let Some(lookup) = lookup {
            let resolver = LookupVerification {
                scope: LookupScope::new(lookup),
            };
            let outcome = verifier.key_resolver(&resolver).verify(document, &request);
            // A failed lookup fails the call with its own status, whatever
            // the verification made of the signature it could not resolve.
            if let Some(failure) = resolver.scope.into_failure() {
                return Err(failure);
            }
            return Ok(outcome?);
        }
        Ok(match &self.keys {
            Some(keys) => {
                let inventory = keys.inventory.read();
                let resolver = inventory.verification_resolver();
                verifier
                    .key_resolver(&resolver)
                    .verify(document, &request)?
            }
            None => verifier.verify(document, &request)?,
        })
    }
}

/// An encryption operation for one content algorithm and RSA recipient.
pub(crate) struct Encryptor {
    security: SharedSecurity,
    builder: EncryptedDataBuilder,
}

impl Encryptor {
    pub(crate) fn new(
        security: SharedSecurity,
        keys: &Keys,
        recipient: &str,
        method: &str,
    ) -> Result<Self, Failure> {
        let algorithm = DataEncryptionAlgorithm::from_uri(method)
            .map_err(|_| Failure::new(XS_INVALID_ARGUMENT, "unknown content encryption method"))?;
        let policy = security
            .policies()
            .encryption()
            .ok_or_else(|| disabled(Operation::Encrypt))?;
        let key = keys
            .inventory
            .read()
            .rsa_encryption_key(recipient, policy)
            .map_err(key_failure)?;
        let builder = EncryptedDataBuilder::new(algorithm)
            .add_recipient(EncryptionRecipient::rsa_oaep(key).key_name(recipient));
        Ok(Self { security, builder })
    }

    /// Replace the element with ID `element_id`, or the root, by its encryption.
    pub(crate) fn encrypt(
        &self,
        document: &mut XmlDocument,
        element_id: Option<&str>,
    ) -> Result<PolicyAudit, Failure> {
        Ok(self
            .security
            .binding()
            .encryptor(&self.builder)?
            .encrypt(document, DocumentEncryptionOptions { element_id })?)
    }
}

/// A decryption operation with its recovery key selected once, or none when
/// every call supplies its keys through a lookup.
pub(crate) struct Decryptor {
    security: SharedSecurity,
    resolver: Option<Box<dyn DecryptionKeyResolver + Send + Sync>>,
}

impl Decryptor {
    pub(crate) fn new(
        security: SharedSecurity,
        key: Option<(&Keys, &str)>,
    ) -> Result<Self, Failure> {
        let resolver = key
            .map(|(keys, name)| {
                security
                    .binding()
                    .decryption_key(&keys.inventory.read(), name)
            })
            .transpose()?;
        Ok(Self { security, resolver })
    }

    /// Recover the `EncryptedData` with schema `Id` `id`, or the first one. A
    /// `lookup` supplies the keys for this call in place of the selected key.
    pub(crate) fn decrypt(
        &self,
        document: &mut XmlDocument,
        id: Option<&str>,
        lookup: Option<&dyn KeyLookup>,
    ) -> Result<PolicyAudit, Failure> {
        let binding = self.security.binding();
        if let Some(lookup) = lookup {
            let resolver = LookupDecryption {
                scope: LookupScope::new(lookup),
                resolvers: Mutex::new(Vec::new()),
            };
            let decrypted = binding.decryptor(&resolver)?.decrypt(document, id);
            if let Some(failure) = resolver.scope.into_failure() {
                return Err(failure);
            }
            return Ok(decrypted?);
        }
        let resolver = self.resolver.as_deref().ok_or_else(|| {
            Failure::new(
                XS_INVALID_ARGUMENT,
                "a decryptor without a key needs a key lookup",
            )
        })?;
        Ok(binding.decryptor(resolver)?.decrypt(document, id)?)
    }
}

/// `XS_SIGNATURE_*` outcome and `XS_KEY_TRUST_*` of one evidence entry.
pub(crate) fn signature_outcome(evidence: &VerifyEvidence, index: usize) -> Option<(u32, u32)> {
    let signature = evidence.signatures().get(index)?;
    Some(match signature.result() {
        Ok(result) => (
            if result.status == DsigStatus::Valid {
                1
            } else {
                2
            },
            match result.key_trust {
                KeyTrustEvidence::NotEvaluated => 1,
                KeyTrustEvidence::NotEstablished => 2,
                KeyTrustEvidence::CallerTrusted => 3,
                KeyTrustEvidence::ValidatedX509(_) => 4,
            },
        ),
        Err(_) => (3, 0),
    })
}

/// One decision, in the form the C structure reports it.
pub(crate) struct DecisionView {
    pub(crate) kind: u32,
    pub(crate) role: u32,
    pub(crate) uri_class: u32,
    pub(crate) manifests: u32,
    pub(crate) violation: u32,
    pub(crate) text: String,
}

/// An audit whose text the C side borrows until the handle is destroyed.
pub(crate) struct Audit {
    pub(crate) identity: Option<Arc<PolicyIdentity>>,
    pub(crate) decisions: Vec<DecisionView>,
}

fn algorithm_role(role: AlgorithmRole) -> u32 {
    match role {
        AlgorithmRole::Signature => 1,
        AlgorithmRole::Canonicalization => 2,
        AlgorithmRole::Digest => 3,
        AlgorithmRole::Transform => 4,
        AlgorithmRole::DataEncryption => 5,
        AlgorithmRole::KeyTransport => 6,
        AlgorithmRole::KeyWrap => 7,
        AlgorithmRole::OaepDigest => 8,
        AlgorithmRole::MaskGeneration => 9,
        _ => 0,
    }
}

fn uri_role(role: UriRole) -> u32 {
    match role {
        UriRole::Reference => 1,
        UriRole::ManifestReference => 2,
        UriRole::CipherReference => 3,
        _ => 0,
    }
}

fn uri_class(class: UriClass) -> u32 {
    match class {
        UriClass::Empty => 1,
        UriClass::SameDocument => 2,
        UriClass::External => 3,
    }
}

impl From<&PolicyAudit> for Audit {
    fn from(audit: &PolicyAudit) -> Self {
        let decisions = audit
            .decisions
            .iter()
            .map(|decision| {
                let mut view = DecisionView {
                    kind: 0,
                    role: 0,
                    uri_class: 0,
                    manifests: 0,
                    violation: 0,
                    text: String::new(),
                };
                match decision {
                    PolicyDecision::Algorithm { role, uri } => {
                        (view.kind, view.role) = (1, algorithm_role(*role));
                        view.text.clone_from(uri);
                    }
                    PolicyDecision::Uri { role, class } => {
                        (view.kind, view.role, view.uri_class) =
                            (2, uri_role(*role), uri_class(*class));
                    }
                    PolicyDecision::Manifests(processing) => {
                        view.kind = 3;
                        view.manifests = match processing {
                            ManifestProcessing::Ignore => 1,
                            ManifestProcessing::Process => 2,
                        };
                    }
                    PolicyDecision::Exception {
                        authorization_id, ..
                    } => {
                        view.kind = 4;
                        view.text.clone_from(authorization_id);
                    }
                    PolicyDecision::Rejected(violation) => {
                        (view.kind, view.violation) = (5, violation_code(violation));
                        view.text = violation.to_string();
                    }
                    _ => {}
                }
                view
            })
            .collect();
        Self {
            identity: audit.identity.clone(),
            decisions,
        }
    }
}
