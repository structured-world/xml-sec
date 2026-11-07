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
use xml_sec::key_manager::{KeyInventory, KeyUsages, SymmetricKeyKind};
use xml_sec::policy::{
    AlgorithmRole, CompiledPolicies, Instant, ManifestProcessing, PolicyAudit,
    PolicyCompileContext, PolicyDecision, PolicyIdentity, PolicyValidity, PolicyViolation,
    ResourcePolicy, UriRole,
};
use xml_sec::provider::CryptoProvider;
use xml_sec::xmldsig::{
    DsigStatus, KeyTrustEvidence, SignatureAlgorithm, SignatureRequirement, SigningKey, UriClass,
    VerificationRequest, VerifyEvidence,
};
use xml_sec::xmlenc::{
    DataEncryptionAlgorithm, DecryptionKeyResolver, DocumentEncryptionOptions,
    EncryptedDataBuilder, EncryptionRecipient,
};
use xml_sec::{SharedSecurity, XmlBackend, XmlDocument, XmlDocumentError, XmlSecError};
use xml_sec_config::{Configuration, LoadLimits, PolicyStore, Source};

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
            | XmlSecError::Document(XmlDocumentError::Policy(violation)) => {
                return Self::refused(violation, message);
            }
            // The compiled policy's byte and depth ceilings, reported by the
            // parser with their own variants.
            XmlSecError::Document(
                XmlDocumentError::DocumentTooLarge { .. }
                | XmlDocumentError::DocumentTooDeep { .. },
            ) => {
                return Self {
                    status: XS_POLICY,
                    violation: RESOURCE_LIMIT,
                    message,
                };
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

/// A key manager, with the resource policy its imports are bounded by.
pub(crate) struct Keys {
    inventory: RwLock<KeyInventory>,
    resources: ResourcePolicy,
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
        Ok(Self {
            inventory: RwLock::new(KeyInventory::default()),
            resources: resources(policies, operation)
                .ok_or_else(|| disabled(operation))?
                .clone(),
        })
    }

    pub(crate) fn add_private_pem(
        &self,
        name: &str,
        pem: &[u8],
        password: Option<&[u8]>,
        usage_bits: u32,
    ) -> Result<(), Failure> {
        let usages = usages(usage_bits)?;
        self.inventory
            .write()
            .add_private_pem(name.into(), pem, password, usages, &self.resources)
            .map_err(key_failure)
    }

    pub(crate) fn add_public_pem(
        &self,
        name: &str,
        pem: &[u8],
        usage_bits: u32,
    ) -> Result<(), Failure> {
        let usages = usages(usage_bits)?;
        self.inventory
            .write()
            .add_public_pem_with_usages(name.into(), pem, usages, &self.resources)
            .map_err(key_failure)
    }

    pub(crate) fn add_symmetric(
        &self,
        name: &str,
        kind: u32,
        key: &[u8],
        usage_bits: u32,
    ) -> Result<(), Failure> {
        let (kind, usages) = (symmetric_kind(kind)?, usages(usage_bits)?);
        self.inventory
            .write()
            .add_symmetric(name.into(), kind, key.to_vec(), usages, &self.resources)
            .map_err(key_failure)
    }
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

    /// Verify `document`, requiring the elements whose ID is in
    /// `expected_ids` to be authenticated.
    pub(crate) fn verify(
        &self,
        document: &XmlDocument,
        expected_ids: &[&str],
        signatures: SignatureRequirement,
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

/// A decryption operation with its recovery key selected once.
pub(crate) struct Decryptor {
    security: SharedSecurity,
    resolver: Box<dyn DecryptionKeyResolver + Send + Sync>,
}

impl Decryptor {
    pub(crate) fn new(security: SharedSecurity, keys: &Keys, name: &str) -> Result<Self, Failure> {
        let resolver = security
            .binding()
            .decryption_key(&keys.inventory.read(), name)?;
        Ok(Self { security, resolver })
    }

    /// Recover the `EncryptedData` with schema `Id` `id`, or the first one.
    pub(crate) fn decrypt(
        &self,
        document: &mut XmlDocument,
        id: Option<&str>,
    ) -> Result<PolicyAudit, Failure> {
        Ok(self
            .security
            .binding()
            .decryptor(&*self.resolver)?
            .decrypt(document, id)?)
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
