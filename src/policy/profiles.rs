//! Trusted profile selection and compilation; no configuration discovery or I/O.

use super::*;
use crate::provider::{CryptoProvider, ProviderCapability};

mod composition;
mod constraints;

/// XML Security presets, selected only by trusted application code.
/// These names do not certify full SAML, SOAP or XAdES conformance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyProfile {
    /// Implemented libxmlsec1 mechanisms, with explicit compatibility permission.
    XmlSecCompatible,
    /// Modern signatures, SHA-2/SHA-3 digests and authenticated encryption.
    Modern,
    /// Restricted SAML signatures and explicit authenticated target coverage.
    SecureSaml,
    /// SOAP Security-header signatures and explicit authenticated target coverage.
    WsSecurity,
    /// XML signatures with authenticated, typed SignedProperties references.
    Xades,
    /// Compatibility verification only, requiring expiring authorization.
    LegacyVerify,
}

/// Auditable, caller-authorized exception with an exclusive expiration boundary.
/// The core does not decide who is entitled to grant exceptions; the trusted
/// application authenticates that authority before constructing this value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyValidity {
    /// Application's audit record identifier, unrelated to document content.
    pub authorization_id: String,
    /// Authenticated principal granting the exception.
    pub authority: String,
    /// Non-secret justification retained for audit.
    pub reason: String,
    /// Inclusive beginning of validity.
    pub not_before: SystemTime,
    /// Exclusive expiration; cached policies cannot outlive this boundary.
    pub expires_at: SystemTime,
}

impl PolicyValidity {
    /// Check metadata and the half-open interval against an explicit time.
    pub fn validate_at(&self, now: SystemTime) -> Result<(), PolicyViolation> {
        if self.authorization_id.trim().is_empty()
            || self.authority.trim().is_empty()
            || self.reason.trim().is_empty()
            || self.not_before >= self.expires_at
        {
            return Err(configuration(
                "authorization needs identity, authority, reason and a nonempty validity interval",
            ));
        }
        if now < self.not_before || now >= self.expires_at {
            return Err(PolicyViolation::AuthorizationExpired);
        }
        Ok(())
    }
}

/// Signature-level XML Security constraints, not application protocol semantics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SignatureConstraints {
    /// Generic XMLDSig processing with caller-selected request requirements.
    #[default]
    General,
    /// SAML Core §5.4 signature format and coverage requirements.
    Saml,
    /// WS-Security §8.2 Security-header signature placement and target coverage.
    WsSecurity,
    /// ETSI EN 319 132-1 §4.4.2 SignedProperties protection.
    Xades,
}

/// Editable compilation input. `None` disables an operation; a restrictive
/// layer can disable but never re-enable an operation inherited as disabled.
#[derive(Debug, Clone, Default)]
pub struct PolicySet {
    /// XMLDSig verification policy.
    pub verification: Option<VerificationPolicy>,
    /// XMLDSig signing policy.
    pub signing: Option<SigningPolicy>,
    /// XMLEnc encryption policy.
    #[cfg(feature = "xmlenc")]
    pub encryption: Option<EncryptionPolicy>,
    /// XMLEnc decryption policy.
    #[cfg(feature = "xmlenc")]
    pub decryption: Option<DecryptionPolicy>,
}

/// Caller-owned capabilities promised to operations using the compiled policy.
/// This is a contract, not permission to discover resources. Actual resource
/// maps and target identities must still be supplied to each operation.
pub struct PolicyCompileContext {
    /// Caller guarantees an explicit external-resource map on applicable calls.
    pub external_resources: bool,
    /// Caller uses `verify_request` with nonempty expected target identities.
    pub target_evidence: bool,
}

/// Immutable compiled output. Operation snapshots retain all constraints and
/// authorization metadata when cloned into existing processing contexts.
#[derive(Debug, Clone)]
pub struct CompiledPolicies {
    profile: PolicyProfile,
    policies: PolicySet,
}

impl CompiledPolicies {
    /// Explicit trusted profile identity, not inferred from XML.
    pub const fn profile(&self) -> PolicyProfile {
        self.profile
    }
    /// Borrow the compiled verification snapshot, if enabled.
    pub fn verification(&self) -> Option<&VerificationPolicy> {
        self.policies.verification.as_ref()
    }
    /// Borrow the compiled signing snapshot, if enabled.
    pub fn signing(&self) -> Option<&SigningPolicy> {
        self.policies.signing.as_ref()
    }
    /// Borrow the compiled encryption snapshot, if enabled.
    #[cfg(feature = "xmlenc")]
    pub fn encryption(&self) -> Option<&EncryptionPolicy> {
        self.policies.encryption.as_ref()
    }
    /// Borrow the compiled decryption snapshot, if enabled.
    #[cfg(feature = "xmlenc")]
    pub fn decryption(&self) -> Option<&DecryptionPolicy> {
        self.policies.decryption.as_ref()
    }
}

/// Compose layers in system → application → tenant order. Every ordinary layer
/// intersects the previous snapshot; only `authorize_replacement` can relax it.
pub struct PolicyCompiler<'a> {
    provider: &'a dyn CryptoProvider,
    profile: PolicyProfile,
    policies: PolicySet,
}

impl<'a> PolicyCompiler<'a> {
    /// Construct a named profile using this engine's advertised capabilities.
    /// LegacyVerify requires a valid authorization even before compilation.
    pub fn new(
        profile: PolicyProfile,
        provider: &'a dyn CryptoProvider,
        authorization: Option<PolicyValidity>,
    ) -> Result<Self, PolicyViolation> {
        if profile == PolicyProfile::LegacyVerify && authorization.is_none() {
            return Err(configuration(
                "LegacyVerify requires expiring authorization",
            ));
        }
        if let Some(validity) = &authorization {
            validity.validate_at(SystemTime::now())?;
        }
        let policies = profile_policies(profile, provider, authorization);
        Ok(Self {
            provider,
            profile,
            policies,
        })
    }

    /// Intersect another complete layer without granting any new permission.
    /// `None` operation fields mean disabled, not unspecified inheritance.
    pub fn restrict(mut self, layer: &PolicySet) -> Result<Self, PolicyViolation> {
        self.policies = self.policies.intersect(layer)?;
        Ok(self)
    }

    /// Explicit relaxation path: replace the effective policy and retain the
    /// authenticated grant on every enabled operation. Earlier authorization
    /// lifetimes are intersected, so replacement cannot extend an existing grant.
    pub fn authorize_replacement(
        mut self,
        mut replacement: PolicySet,
        authorization: PolicyValidity,
    ) -> Result<Self, PolicyViolation> {
        authorization.validate_at(SystemTime::now())?;
        replacement.bind_authorization(authorization, &self.policies)?;
        self.policies = replacement;
        Ok(self)
    }

    /// Compile contradictions before parsing, resolver calls or cryptography.
    pub fn compile(
        self,
        context: &PolicyCompileContext,
    ) -> Result<CompiledPolicies, PolicyViolation> {
        self.policies.validate(context, self.provider)?;
        Ok(CompiledPolicies {
            profile: self.profile,
            policies: self.policies,
        })
    }

    /// Inspect a layer input for customization before restrictive composition.
    pub fn policies(&self) -> &PolicySet {
        &self.policies
    }
}

fn configuration(reason: &'static str) -> PolicyViolation {
    PolicyViolation::Configuration { reason }
}

fn profile_policies(
    profile: PolicyProfile,
    provider: &dyn CryptoProvider,
    validity: Option<PolicyValidity>,
) -> PolicySet {
    let compatibility = matches!(
        profile,
        PolicyProfile::XmlSecCompatible | PolicyProfile::LegacyVerify
    );
    let constraints = match profile {
        PolicyProfile::SecureSaml => SignatureConstraints::Saml,
        PolicyProfile::WsSecurity => SignatureConstraints::WsSecurity,
        PolicyProfile::Xades => SignatureConstraints::Xades,
        _ => SignatureConstraints::General,
    };
    let signatures: HashSet<_> = SignatureAlgorithm::ALL
        .into_iter()
        .filter(|a| provider.supports(ProviderCapability::Verify(*a)))
        .filter(|a| {
            compatibility
                || (a.signing_allowed() && a.hmac_output_bits().is_none_or(|bits| bits >= 256))
        })
        .filter(|a| !matches!(a, SignatureAlgorithm::PostQuantum(_)))
        .collect();
    let digests: HashSet<_> = DigestAlgorithm::ALL
        .into_iter()
        .filter(|a| provider.supports(ProviderCapability::Digest(*a)))
        .filter(|a| compatibility || (a.signing_allowed() && a.output_len() >= 32))
        .collect();
    let transforms = if compatibility {
        // libxmlsec1 compiles stylesheets with libxslt; signers and verifiers in this
        // profile must agree with it on the digested output.
        TransformPolicy {
            xslt_prefix_list_semantics: XsltPrefixListSemantics::Libxslt,
            ..TransformPolicy::default()
        }
    } else {
        TransformPolicy {
            allowed_algorithms: Some(
                [
                    "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                    "http://www.w3.org/2001/10/xml-exc-c14n#",
                    "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
                    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
                    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
                    "http://www.w3.org/2006/12/xml-c14n11",
                    "http://www.w3.org/2006/12/xml-c14n11#WithComments",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            ),
            ..TransformPolicy::default()
        }
    };
    let mut verification = VerificationPolicy {
        validity: validity.clone(),
        signature_constraints: constraints,
        signature_algorithms: Some(signatures),
        parameterized_rsa_pss: if compatibility {
            RsaPssPermission::AllSupported
        } else {
            RsaPssPermission::SecureSupported
        },
        digest_algorithms: Some(digests),
        transforms: transforms.clone(),
        ..VerificationPolicy::default()
    };
    verification.key_trust.parameterized_rsa_pss = verification.parameterized_rsa_pss;
    if compatibility {
        verification.key_trust.allowed_legacy_signature_algorithms = verification
            .signature_algorithms
            .clone()
            .unwrap_or_default();
        verification.key_trust.rsa_keys.minimum_modulus_bits = 1024;
        verification.key_trust.dsa_keys.minimum_modulus_bits = 1024;
        verification.hmac.minimum_output_bits = 80;
        verification.transforms.same_document_id_semantics =
            SameDocumentIdSemantics::XmlSecBarename;
    }
    if constraints != SignatureConstraints::General {
        verification.key_sources = KeySourcePolicy {
            preset_key: true,
            key_name: true,
            x509_data: true,
            key_value: false,
            der_encoded_key_value: false,
            key_info_reference: false,
        };
    }
    if constraints == SignatureConstraints::Saml {
        verification.uris.references = UriTypeSet::new(false, true, false);
        verification.transforms.allowed_algorithms = Some(
            [
                "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                "http://www.w3.org/2001/10/xml-exc-c14n#",
                "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        );
    }
    let signing = SigningPolicy {
        validity: validity.clone(),
        signature_constraints: constraints,
        parameterized_rsa_pss: RsaPssPermission::SecureSupported,
        signature_algorithms: Some(
            SignatureAlgorithm::ALL
                .into_iter()
                .filter(|a| a.signing_allowed() && !matches!(a, SignatureAlgorithm::PostQuantum(_)))
                .filter(|a| a.hmac_output_bits().is_none_or(|bits| bits >= 256))
                .filter(|a| provider.supports(ProviderCapability::Sign(*a)))
                .collect(),
        ),
        digest_algorithms: Some(
            DigestAlgorithm::ALL
                .into_iter()
                .filter(|a| a.signing_allowed() && a.output_len() >= 32)
                .filter(|a| provider.supports(ProviderCapability::Digest(*a)))
                .collect(),
        ),
        transforms: if constraints == SignatureConstraints::Saml {
            verification.transforms.clone()
        } else {
            transforms
        },
        uris: if constraints == SignatureConstraints::Saml {
            verification.uris
        } else {
            UriPolicy::default()
        },
        ..SigningPolicy::default()
    };
    let legacy = profile == PolicyProfile::LegacyVerify;
    PolicySet {
        verification: Some(verification),
        signing: (!legacy).then_some(signing),
        #[cfg(feature = "xmlenc")]
        encryption: (!legacy).then(|| encryption_profile(provider, validity.clone())),
        #[cfg(feature = "xmlenc")]
        decryption: (!legacy).then(|| decryption_profile(provider, compatibility, validity)),
    }
}

#[cfg(feature = "xmlenc")]
const MODERN_CONTENT_METHODS: [DataEncryptionAlgorithm; 3] = [
    DataEncryptionAlgorithm::Aes128Gcm,
    DataEncryptionAlgorithm::Aes256Gcm,
    DataEncryptionAlgorithm::ChaCha20Poly1305,
];
#[cfg(feature = "xmlenc")]
const MODERN_WRAP_METHODS: [KeyWrapAlgorithm; 2] =
    [KeyWrapAlgorithm::AesKw128, KeyWrapAlgorithm::AesKw256];
#[cfg(feature = "xmlenc")]
const MODERN_OAEP_DIGESTS: [OaepDigestAlgorithm; 3] = [
    OaepDigestAlgorithm::Sha256,
    OaepDigestAlgorithm::Sha384,
    OaepDigestAlgorithm::Sha512,
];

#[cfg(feature = "xmlenc")]
const COMPATIBLE_CONTENT_METHODS: &[DataEncryptionAlgorithm] = &[
    DataEncryptionAlgorithm::Aes128Cbc,
    DataEncryptionAlgorithm::Aes256Cbc,
    DataEncryptionAlgorithm::Aes128Gcm,
    DataEncryptionAlgorithm::Aes256Gcm,
    DataEncryptionAlgorithm::Camellia128Cbc,
    DataEncryptionAlgorithm::Camellia192Cbc,
    DataEncryptionAlgorithm::Camellia256Cbc,
    DataEncryptionAlgorithm::ChaCha20,
    DataEncryptionAlgorithm::ChaCha20Poly1305,
    #[cfg(feature = "legacy-algorithms")]
    DataEncryptionAlgorithm::TripleDesCbc,
    #[cfg(feature = "legacy-algorithms")]
    DataEncryptionAlgorithm::Aes192Cbc,
    #[cfg(feature = "legacy-algorithms")]
    DataEncryptionAlgorithm::Aes192Gcm,
];
#[cfg(feature = "xmlenc")]
const COMPATIBLE_WRAP_METHODS: &[KeyWrapAlgorithm] = &[
    KeyWrapAlgorithm::AesKw128,
    KeyWrapAlgorithm::AesKw256,
    KeyWrapAlgorithm::CamelliaKw128,
    KeyWrapAlgorithm::CamelliaKw192,
    KeyWrapAlgorithm::CamelliaKw256,
    #[cfg(feature = "legacy-algorithms")]
    KeyWrapAlgorithm::TripleDes,
    #[cfg(feature = "legacy-algorithms")]
    KeyWrapAlgorithm::AesKw192,
];
#[cfg(feature = "xmlenc")]
const COMPATIBLE_TRANSPORT_METHODS: &[KeyTransportAlgorithm] = &[
    KeyTransportAlgorithm::RsaOaepMgf1p,
    KeyTransportAlgorithm::RsaOaep11,
    #[cfg(feature = "legacy-algorithms")]
    KeyTransportAlgorithm::RsaPkcs1v15,
];
#[cfg(feature = "xmlenc")]
const OAEP_MGF_DIGESTS: [OaepDigestAlgorithm; 5] = [
    OaepDigestAlgorithm::Sha1,
    OaepDigestAlgorithm::Sha224,
    OaepDigestAlgorithm::Sha256,
    OaepDigestAlgorithm::Sha384,
    OaepDigestAlgorithm::Sha512,
];

#[cfg(feature = "xmlenc")]
fn encryption_profile(
    provider: &dyn CryptoProvider,
    validity: Option<PolicyValidity>,
) -> EncryptionPolicy {
    EncryptionPolicy {
        validity,
        data_algorithms: Some(
            MODERN_CONTENT_METHODS
                .into_iter()
                .filter(|a| provider.supports(ProviderCapability::Encrypt(*a)))
                .collect(),
        ),
        key_transport_algorithms: Some(HashSet::from([KeyTransportAlgorithm::RsaOaep11])),
        key_wrap_algorithms: Some(
            MODERN_WRAP_METHODS
                .into_iter()
                .filter(|a| provider.supports(ProviderCapability::KeyWrap(*a)))
                .collect(),
        ),
        oaep_digests: Some(HashSet::from(MODERN_OAEP_DIGESTS)),
        ..EncryptionPolicy::default()
    }
}

#[cfg(feature = "xmlenc")]
fn decryption_profile(
    provider: &dyn CryptoProvider,
    compatibility: bool,
    validity: Option<PolicyValidity>,
) -> DecryptionPolicy {
    let content = if compatibility {
        COMPATIBLE_CONTENT_METHODS
    } else {
        &MODERN_CONTENT_METHODS
    };
    let wraps = if compatibility {
        COMPATIBLE_WRAP_METHODS
    } else {
        &MODERN_WRAP_METHODS
    };
    let cbc_methods = if compatibility {
        COMPATIBLE_CONTENT_METHODS
    } else {
        &[]
    };
    let oaep_digests = if compatibility {
        DigestAlgorithm::ALL
            .into_iter()
            .filter(|digest| provider.supports(ProviderCapability::Digest(*digest)))
            .filter_map(|digest| OaepDigestAlgorithm::from_uri(digest.uri()))
            .collect()
    } else {
        HashSet::from(MODERN_OAEP_DIGESTS)
    };
    let transports = if compatibility {
        COMPATIBLE_TRANSPORT_METHODS
            .iter()
            .copied()
            .filter(|method| recovery_method_available(provider, *method, &oaep_digests))
            .collect()
    } else {
        HashSet::from([KeyTransportAlgorithm::RsaOaep11])
    };
    DecryptionPolicy {
        validity,
        data_algorithms: Some(
            content
                .iter()
                .copied()
                .filter(|algorithm| provider.supports(ProviderCapability::Decrypt(*algorithm)))
                .collect(),
        ),
        key_transport_algorithms: Some(transports),
        key_wrap_algorithms: Some(
            wraps
                .iter()
                .copied()
                .chain(
                    cbc_methods
                        .iter()
                        .copied()
                        .filter(|algorithm| algorithm.cbc_block_len().is_some())
                        .map(KeyWrapAlgorithm::Cbc),
                )
                .filter(|algorithm| provider.supports(ProviderCapability::KeyUnwrap(*algorithm)))
                .collect(),
        ),
        oaep_digests: Some(oaep_digests),
        ..DecryptionPolicy::default()
    }
}

#[cfg(feature = "xmlenc")]
fn recovery_method_available(
    provider: &dyn CryptoProvider,
    method: KeyTransportAlgorithm,
    digests: &HashSet<OaepDigestAlgorithm>,
) -> bool {
    #[cfg(feature = "legacy-algorithms")]
    if method == KeyTransportAlgorithm::RsaPkcs1v15 {
        return provider.supports(ProviderCapability::Pkcs1v15Recovery);
    }
    // Admission here identifies an available mechanism; compilation still
    // checks every permitted digest/MGF tuple, never silently dropping a tuple.
    digests.iter().any(|&digest| {
        OAEP_MGF_DIGESTS.into_iter().any(|mgf| {
            digests.contains(&mgf)
                && provider.supports(ProviderCapability::KeyRecovery(
                    &crate::xmlenc::RsaOaepParameters {
                        algorithm: method,
                        digest,
                        mgf_digest: mgf,
                        label: Vec::new(),
                    },
                ))
        })
    })
}
