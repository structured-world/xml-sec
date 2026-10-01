//! Caller-owned, provider-neutral key inventory and xmlsec key-store import.

use std::collections::HashSet;

use base64::Engine as _;
use crypto_bigint::{
    BoxedUint,
    modular::{BoxedMontyForm, BoxedMontyParams},
};
use der::Decode as _;
use dsa::{
    Components as DsaComponents, SigningKey as NativeDsaSigningKey,
    VerifyingKey as DsaVerifyingKey, pkcs8::EncodePrivateKey as _,
};
mod pkcs12_import;
use pkcs12_import::Limits as Pkcs12Limits;
#[cfg(feature = "xmlenc")]
use rsa::pkcs8::DecodePublicKey as _;
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1::{DecodeRsaPrivateKey as _, DecodeRsaPublicKey as _},
    pkcs8::{
        DecodePrivateKey as _, EncodePublicKey as _, EncryptedPrivateKeyInfoRef, PrivateKeyInfoRef,
    },
};
use x509_parser::prelude::{FromDer as _, X509Certificate};
use zeroize::Zeroizing;

#[cfg(feature = "xmlenc")]
use crate::xmldsig::parse::X509PublicKeyInfo;
use crate::{
    XmlBackend, XmlDomNode as Node,
    document::{
        DocumentParseSettings, XmlParseWorkBudget, parse_borrowed_with_settings_and_budget,
    },
    policy::ResourcePolicy,
    xmldsig::keys::InspectedKeyCandidateBudget,
    xmldsig::parse::XMLDSIG11_NS,
    xmldsig::{
        DefaultKeyResolver, DsaSigningKey, DsigError, EcdsaP256SigningKey, EcdsaP384SigningKey,
        EcdsaP521SigningKey, HmacSigningKey, HmacVerificationKey, KeyInfo, KeyInfoSource,
        KeyResolver, KeyResolverConfig, KeyValueInfo, RsaSigningKey, SignatureAlgorithm,
        SigningKey, VerifyingKey, X509DataInfo, parse_key_info, validate_signing_key,
    },
};

const XMLSEC_NS: &str = "http://www.aleksey.com/xmlsec/2002";
const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

fn check_selected_public_material(
    info: &KeyInfo,
    resources: &ResourcePolicy,
) -> Result<usize, DsigError> {
    let mut total = 0_usize;
    for source in &info.sources {
        let mut charge = |length: usize| -> Result<(), DsigError> {
            if length > resources.max_external_resource_bytes {
                return Err(crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
                    maximum: resources.max_external_resource_bytes,
                    actual: length,
                }
                .into());
            }
            total = total.checked_add(length).ok_or({
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                    maximum: resources.max_external_resource_total_bytes,
                    actual: usize::MAX,
                }
            })?;
            if total > resources.max_external_resource_total_bytes {
                return Err(crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                    maximum: resources.max_external_resource_total_bytes,
                    actual: total,
                }
                .into());
            }
            Ok(())
        };
        match source {
            KeyInfoSource::KeyValue(value) => {
                // One selected key is one resource, irrespective of how many
                // XML fields encode it. Bound the complete borrowed payload
                // before resolution materializes its SPKI.
                let lengths = match value {
                    KeyValueInfo::Rsa { modulus, exponent } => {
                        [modulus.len(), exponent.len(), 0, 0]
                    }
                    KeyValueInfo::Dsa { p, q, g, y } => [
                        p.as_ref().map_or(0, Vec::len),
                        q.as_ref().map_or(0, Vec::len),
                        g.as_ref().map_or(0, Vec::len),
                        y.len(),
                    ],
                    KeyValueInfo::Ec {
                        curve_oid,
                        public_key,
                    } => [curve_oid.len(), public_key.len(), 0, 0],
                    KeyValueInfo::InvalidEcKeyValue | KeyValueInfo::Unsupported { .. } => continue,
                };
                let length = lengths.into_iter().try_fold(0_usize, |sum, length| {
                    sum.checked_add(length)
                        .ok_or(crate::policy::PolicyViolation::ResourceLimit {
                            resource: crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
                            maximum: resources.max_external_resource_bytes,
                            actual: usize::MAX,
                        })
                })?;
                charge(length)?;
            }
            KeyInfoSource::DerEncodedKeyValue(bytes) => charge(bytes.len())?,
            KeyInfoSource::X509Data(data) => {
                for certificate in &data.certificates {
                    charge(certificate.len())?;
                }
                for crl in &data.crls {
                    charge(crl.len())?;
                }
            }
            _ => {}
        }
    }
    Ok(total)
}

/// A named secret imported from an xmlsec key store.
pub struct StoredSymmetricKey {
    /// Opaque caller-supplied lookup name.
    pub name: String,
    /// XML Security symmetric-key family.
    pub kind: SymmetricKeyKind,
    /// Secret bytes, zeroized when the inventory is dropped.
    pub bytes: Zeroizing<Vec<u8>>,
    /// Allowed operations.
    pub usages: KeyUsages,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// The secret-key family declared by an xmlsec key store.
pub enum SymmetricKeyKind {
    /// HMAC signing and verification key.
    Hmac,
    /// AES content-encryption key.
    Aes,
    /// Legacy DES key marker; import rejects it until a DES operation exists.
    Des,
}

#[derive(Default)]
/// A caller-owned inventory of imported XML Security key material.
pub struct KeyInventory {
    /// Total XML entries inspected, including unsupported algorithms.
    entry_count: usize,
    /// Supported symmetric keys.
    symmetric_keys: Vec<StoredSymmetricKey>,
    /// Supported public keys.
    public_keys: Vec<StoredPublicKey>,
    /// Private PKCS#8 keys imported from caller-owned byte sources.
    private_keys: Vec<StoredPrivateKey>,
    /// Untrusted certificates available for key lookup or path construction.
    lookup_certificates: Vec<Vec<u8>>,
    /// Explicit caller-trusted certificate anchors.
    trusted_certificates: Vec<Vec<u8>>,
    /// Caller-supplied DER certificate revocation lists.
    crls: Vec<Vec<u8>>,
    material_bytes: usize,
}

/// Candidate inspections shared by named signing lookups in one operation.
#[derive(Default)]
pub struct SigningLookupBudget {
    inspected: usize,
}

/// Operations for which a caller may authorize a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyUsage {
    /// XMLDSig signing.
    Sign,
    /// XMLDSig verification.
    Verify,
    /// XMLEnc encryption or key wrapping.
    Encrypt,
    /// XMLEnc decryption or key unwrapping.
    Decrypt,
}

/// Explicit, immutable allowed-use set for one imported key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyUsages(u8);

impl KeyUsages {
    /// A key usable only for signing.
    pub const SIGN: Self = Self(1);
    /// A key usable only for verification.
    pub const VERIFY: Self = Self(2);
    /// A key usable only for encryption.
    pub const ENCRYPT: Self = Self(4);
    /// A key usable only for decryption.
    pub const DECRYPT: Self = Self(8);

    /// Combine disjoint permissions explicitly.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Test one requested operation.
    #[must_use]
    pub const fn allows(self, usage: KeyUsage) -> bool {
        let bit = match usage {
            KeyUsage::Sign => Self::SIGN.0,
            KeyUsage::Verify => Self::VERIFY.0,
            KeyUsage::Encrypt => Self::ENCRYPT.0,
            KeyUsage::Decrypt => Self::DECRYPT.0,
        };
        self.0 & bit != 0
    }
}

/// Private key encoded as provider-neutral PKCS#8 DER.
pub struct StoredPrivateKey {
    /// Opaque caller-assigned name.
    pub name: String,
    /// Private key bytes; zeroized on drop.
    pub pkcs8_der: Zeroizing<Vec<u8>>,
    /// Allowed operations.
    pub usages: KeyUsages,
    /// Associated certificates, leaf first when a matching leaf exists.
    pub certificate_chain: Vec<Vec<u8>>,
    has_matching_leaf: bool,
}

impl StoredPrivateKey {
    /// Return the chain only when its first certificate matches this private key.
    #[must_use]
    pub fn matching_certificate_chain(&self) -> Option<&[Vec<u8>]> {
        self.has_matching_leaf.then_some(&self.certificate_chain)
    }
}

/// A named public key imported from an xmlsec key store.
pub struct StoredPublicKey {
    /// Opaque caller-supplied lookup name.
    pub name: String,
    /// Parsed XMLDSig key material.
    pub key_info: KeyInfo,
    /// Allowed operations.
    pub usages: KeyUsages,
}

impl StoredPublicKey {
    /// Decode this already-selected RSA recipient without searching the inventory again.
    #[cfg(feature = "xmlenc")]
    pub fn rsa_encryption_key(
        &self,
        policy: &crate::policy::EncryptionPolicy,
    ) -> Result<RsaPublicKey, KeyStoreError> {
        policy.validate()?;
        if !self.usages.allows(KeyUsage::Encrypt) {
            return Err(KeyStoreError::Selection(
                "key is not authorized for encryption",
            ));
        }
        for source in &self.key_info.sources {
            return match source {
                KeyInfoSource::KeyValue(KeyValueInfo::Rsa { modulus, exponent }) => {
                    rsa_recipient_from_components(modulus, exponent, policy)
                }
                KeyInfoSource::DerEncodedKeyValue(der) => {
                    check_encryption_material_size(der.len(), &policy.resources)?;
                    let (rest, spki) = x509_parser::x509::SubjectPublicKeyInfo::from_der(der)
                        .map_err(|_| KeyStoreError::Selection("invalid RSA encryption key"))?;
                    if !rest.is_empty() {
                        return Err(KeyStoreError::Selection("invalid RSA encryption key"));
                    }
                    let x509_parser::public_key::PublicKey::RSA(raw) = spki
                        .parsed()
                        .map_err(|_| KeyStoreError::Selection("invalid RSA encryption key"))?
                    else {
                        return Err(KeyStoreError::Selection(
                            "named key is not an RSA public key",
                        ));
                    };
                    rsa_recipient_preflight(raw.modulus, raw.exponent, policy)?;
                    RsaPublicKey::from_public_key_der(der)
                        .map_err(|_| KeyStoreError::Selection("invalid RSA encryption key"))
                }
                KeyInfoSource::X509Data(data) if data.parsed_certificates.len() == 1 => {
                    if let Some(certificate) = data.certificates.first() {
                        check_encryption_material_size(certificate.len(), &policy.resources)?;
                    }
                    match &data.parsed_certificates[0].public_key {
                        X509PublicKeyInfo::Rsa { modulus, exponent } => {
                            rsa_recipient_from_components(modulus, exponent, policy)
                        }
                        _ => Err(KeyStoreError::Selection("certificate does not contain RSA")),
                    }
                }
                _ => continue,
            };
        }
        Err(KeyStoreError::Selection(
            "named key is not an RSA public key",
        ))
    }
}

/// Policy-aware verification adapter over a caller-owned inventory.
pub struct InventoryVerificationResolver<'a> {
    inventory: &'a KeyInventory,
}

impl<'a> KeyResolver for InventoryVerificationResolver<'a> {
    fn resolve<'k>(
        &'k self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
    ) -> Result<Option<Box<dyn VerifyingKey + 'k>>, DsigError> {
        self.resolve_with_policy_and_provider(
            key_info,
            algorithm,
            &crate::policy::VerificationPolicy::default(),
            crate::provider::default_provider(),
        )
    }

    fn resolve_with_policy<'k>(
        &'k self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
        policy: &crate::policy::VerificationPolicy,
    ) -> Result<Option<Box<dyn VerifyingKey + 'k>>, DsigError> {
        self.resolve_with_policy_and_provider(
            key_info,
            algorithm,
            policy,
            crate::provider::default_provider(),
        )
    }

    fn resolve_with_policy_and_provider<'k>(
        &'k self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
        policy: &crate::policy::VerificationPolicy,
        provider: &dyn crate::provider::CryptoProvider,
    ) -> Result<Option<Box<dyn VerifyingKey + 'k>>, DsigError> {
        policy.validate()?;
        if let Some(info) = key_info {
            crate::xmldsig::keys::validate_key_info_source_permissions(info, policy.key_sources)?;
        }
        let mut candidate: Option<&StoredPublicKey> = None;
        let mut secret_candidate: Option<&StoredSymmetricKey> = None;
        let mut inspected_candidates =
            InspectedKeyCandidateBudget::new(policy.resources.max_key_candidates);
        for name in key_info
            .into_iter()
            .flat_map(|info| &info.sources)
            .filter_map(|source| match source {
                KeyInfoSource::KeyName(name) => Some(name.as_str()),
                _ => None,
            })
        {
            if self.inventory.symmetric_keys.is_empty() && self.inventory.public_keys.is_empty() {
                inspected_candidates.charge()?;
            }
            let mut symmetric_match = None;
            for entry in &self.inventory.symmetric_keys {
                inspected_candidates.charge()?;
                if entry.name == name {
                    symmetric_match = Some(entry);
                    break;
                }
            }
            if let Some(found) = symmetric_match {
                if !found.usages.allows(KeyUsage::Verify) || found.kind != SymmetricKeyKind::Hmac {
                    return Err(DsigError::InvalidStructure {
                        reason: "named key is not authorized for verification",
                    });
                }
                if candidate.is_some()
                    || secret_candidate.is_some_and(|previous| !core::ptr::eq(previous, found))
                {
                    return Err(DsigError::InvalidStructure {
                        reason: "more than one named verification key matches",
                    });
                }
                secret_candidate = Some(found);
                continue;
            }
            let mut public_match = None;
            for entry in &self.inventory.public_keys {
                inspected_candidates.charge()?;
                if entry.name == name {
                    public_match = Some(entry);
                    break;
                }
            }
            if let Some(found) = public_match {
                if !found.usages.allows(KeyUsage::Verify) {
                    return Err(DsigError::InvalidStructure {
                        reason: "named key is not authorized for verification",
                    });
                }
                if secret_candidate.is_some()
                    || candidate.is_some_and(|previous| !core::ptr::eq(previous, found))
                {
                    return Err(DsigError::InvalidStructure {
                        reason: "more than one named verification key matches",
                    });
                }
                candidate = Some(found);
            }
        }
        if let Some(candidate) = secret_candidate {
            if algorithm.hmac_output_bits().is_none() {
                return Err(DsigError::InvalidStructure {
                    reason: "named HMAC key is incompatible with signature method",
                });
            }
            for (resource, maximum) in [
                (
                    crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
                    policy.resources.max_external_resource_bytes,
                ),
                (
                    crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                    policy.resources.max_external_resource_total_bytes,
                ),
            ] {
                if candidate.bytes.len() > maximum {
                    return Err(crate::policy::PolicyViolation::ResourceLimit {
                        resource,
                        maximum,
                        actual: candidate.bytes.len(),
                    }
                    .into());
                }
            }
            let key = HmacVerificationKey::new(candidate.bytes.to_vec()).map_err(|_| {
                DsigError::InvalidStructure {
                    reason: "invalid named HMAC key",
                }
            })?;
            return Ok(Some(Box::new(key)));
        }
        let selected_material_bytes = candidate
            .map(|candidate| check_selected_public_material(&candidate.key_info, &policy.resources))
            .transpose()?
            .unwrap_or(0);
        let selected_info = candidate.map_or(key_info, |entry| Some(&entry.key_info));
        let configured_x509_index = selected_info.and_then(|info| {
            info.sources.iter().position(|source| match source {
                KeyInfoSource::X509Data(data) if data.certificate_chain.is_empty() => {
                    crate::xmldsig::parse::x509_data_has_lookup_identifiers(data)
                }
                KeyInfoSource::X509Data(_) => policy.key_trust.verify_x509_chains,
                _ => false,
            })
        });
        // Try only sources preceding the first configured-X.509 use without
        // inspecting or copying inventory certificates that may never be used.
        if let Some(info) = selected_info
            && let Some(first_x509) = configured_x509_index
            && first_x509 != 0
        {
            let prefix_resolver = DefaultKeyResolver::new(KeyResolverConfig::default());
            let result = prefix_resolver.resolve_prefix_with_candidate_budget(
                info,
                algorithm,
                policy,
                provider,
                &mut inspected_candidates,
                if candidate.is_some() {
                    crate::xmldsig::keys::ResolutionScope::TrustedPrefix(first_x509)
                } else {
                    crate::xmldsig::keys::ResolutionScope::DocumentPrefix(first_x509)
                },
            );
            match result {
                Ok(Some(key)) => return Ok(Some(key)),
                Err(DsigError::Policy(violation)) => return Err(violation.into()),
                _ => {}
            }
        }
        let fallback = if configured_x509_index.is_some() {
            let certificates = self
                .inventory
                .lookup_certificates
                .iter()
                .chain(&self.inventory.trusted_certificates);
            // Selecting a trusted named key substitutes key material, not
            // document revocation evidence. Retain CRLs without importing any
            // document certificate into the trusted candidate's chain.
            let document_crls = key_info
                .filter(|_| {
                    candidate.is_some()
                        && policy.key_trust.check_crls
                        && policy.key_trust.verify_x509_chains
                })
                .into_iter()
                .flat_map(|info| &info.sources)
                .filter_map(|source| match source {
                    KeyInfoSource::X509Data(data) => Some(data.crls.as_slice()),
                    _ => None,
                })
                .flatten();
            let crls = self
                .inventory
                .crls
                .iter()
                .chain(document_crls)
                .filter(|_| policy.key_trust.check_crls && policy.key_trust.verify_x509_chains);
            let mut total = selected_material_bytes;
            for material in certificates.chain(crls.clone()) {
                if material.len() > policy.resources.max_external_resource_bytes {
                    return Err(crate::policy::PolicyViolation::ResourceLimit {
                        resource: crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
                        maximum: policy.resources.max_external_resource_bytes,
                        actual: material.len(),
                    }
                    .into());
                }
                debug_assert!(total <= policy.resources.max_external_resource_total_bytes);
                if material.len() > policy.resources.max_external_resource_total_bytes - total {
                    return Err(crate::policy::PolicyViolation::ResourceLimit {
                        resource: crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                        maximum: policy.resources.max_external_resource_total_bytes,
                        actual: total.saturating_add(material.len()),
                    }
                    .into());
                }
                total += material.len();
            }
            DefaultKeyResolver::new(KeyResolverConfig {
                lookup_certs: self.inventory.lookup_certificates.clone(),
                trusted_certs: self.inventory.trusted_certificates.clone(),
                crls: crls.cloned().collect(),
                ..KeyResolverConfig::default()
            })
        } else {
            DefaultKeyResolver::new(KeyResolverConfig::default())
        };
        if let Some(candidate) = candidate {
            return fallback.resolve_trusted_material_with_candidate_budget(
                &candidate.key_info,
                algorithm,
                policy,
                provider,
                &mut inspected_candidates,
            );
        }
        fallback.resolve_with_candidate_budget(
            key_info,
            algorithm,
            policy,
            provider,
            &mut inspected_candidates,
        )
    }

    fn consumes_document_key_info(&self) -> bool {
        true
    }
}

enum ParsedMaterial {
    Symmetric(SymmetricKeyKind, Zeroizing<Vec<u8>>),
    Public(Option<KeyValueInfo>),
    Dsa(KeyValueInfo, Option<Zeroizing<Vec<u8>>>),
    Unsupported,
}

type ParsedDsaKey = (KeyValueInfo, Option<Zeroizing<Vec<u8>>>);

#[cfg(feature = "xmlenc")]
struct InventoryDirectAes(Zeroizing<Vec<u8>>);

#[cfg(feature = "xmlenc")]
impl crate::xmlenc::DecryptionKeyResolver for InventoryDirectAes {
    fn resolve_key(
        &self,
        _provider: &dyn crate::provider::CryptoProvider,
        algorithm: crate::xmlenc::DataEncryptionAlgorithm,
        encrypted_key: Option<&crate::xmlenc::EncryptedKey>,
    ) -> Result<Vec<u8>, crate::xmlenc::XmlEncError> {
        if encrypted_key.is_some() {
            return Err(crate::xmlenc::XmlEncError::KeyNotFound);
        }
        crate::xmlenc::validate_key_len(algorithm, &self.0)?;
        Ok(self.0.to_vec())
    }

    fn resolve_key_candidates(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: crate::xmlenc::DataEncryptionAlgorithm,
        encrypted_key: Option<&crate::xmlenc::EncryptedKey>,
        budget: &mut crate::xmlenc::KeyCandidateBudget,
    ) -> Result<Vec<Vec<u8>>, crate::xmlenc::XmlEncError> {
        // This inventory entry is a content key, not a transport key.
        // Ineligible recipient paths neither copy it nor consume candidates.
        if encrypted_key.is_some() {
            return Err(crate::xmlenc::XmlEncError::KeyNotFound);
        }
        budget.consume(1)?;
        self.resolve_key(provider, algorithm, None)
            .map(|key| vec![key])
    }
}

#[derive(Debug, thiserror::Error)]
/// Key-store import errors that never include secret material.
pub enum KeyStoreError {
    /// The XML structure or key material was invalid.
    #[error("invalid xmlsec keys.xml: {0}")]
    Invalid(String),
    /// The named key is missing, duplicated, or incompatible with the requested operation.
    #[error("key inventory selection failed: {0}")]
    Selection(&'static str),
    /// The active operation policy rejected the key or its resources.
    #[error("key inventory policy violation: {0}")]
    Policy(#[from] crate::policy::PolicyViolation),
    /// A protected container could not be decoded with the supplied password.
    #[error("protected key container could not be decoded")]
    ProtectedContainer,
}

impl KeyInventory {
    fn retained_material_bytes(&self) -> Result<usize, KeyStoreError> {
        let mut total = 0_usize;
        let mut add = |length: usize| -> Result<(), KeyStoreError> {
            total = total
                .checked_add(length)
                .ok_or(KeyStoreError::Selection("key material size overflow"))?;
            Ok(())
        };
        for key in &self.symmetric_keys {
            add(key.name.len())?;
            add(key.bytes.len())?;
        }
        for key in &self.private_keys {
            add(key.name.len())?;
            add(key.pkcs8_der.len())?;
            for certificate in &key.certificate_chain {
                add(certificate.len())?;
            }
        }
        for key in &self.public_keys {
            add(key.name.len())?;
            for source in &key.key_info.sources {
                match source {
                    KeyInfoSource::KeyName(name) => add(name.len())?,
                    KeyInfoSource::KeyValue(KeyValueInfo::Dsa { p, q, g, y }) => {
                        add(p.as_ref().map_or(0, Vec::len))?;
                        add(q.as_ref().map_or(0, Vec::len))?;
                        add(g.as_ref().map_or(0, Vec::len))?;
                        add(y.len())?;
                    }
                    KeyInfoSource::KeyValue(KeyValueInfo::Rsa { modulus, exponent }) => {
                        add(modulus.len())?;
                        add(exponent.len())?;
                    }
                    KeyInfoSource::KeyValue(KeyValueInfo::Ec {
                        curve_oid,
                        public_key,
                    }) => {
                        add(curve_oid.len())?;
                        add(public_key.len())?;
                    }
                    KeyInfoSource::DerEncodedKeyValue(bytes) => add(bytes.len())?,
                    _ => {}
                }
            }
        }
        for certificate in self
            .lookup_certificates
            .iter()
            .chain(&self.trusted_certificates)
        {
            add(certificate.len())?;
        }
        for crl in &self.crls {
            add(crl.len())?;
        }
        Ok(total)
    }

    /// Number of imported candidates, including unsupported XML entries.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entry_count
    }

    /// Imported symmetric keys, without mutable access to inventory bounds.
    #[must_use]
    pub fn symmetric_keys(&self) -> &[StoredSymmetricKey] {
        &self.symmetric_keys
    }

    /// Imported public keys, without mutable access to inventory bounds.
    #[must_use]
    pub fn public_keys(&self) -> &[StoredPublicKey] {
        &self.public_keys
    }

    /// Imported private keys, without mutable access to inventory bounds.
    #[must_use]
    pub fn private_keys(&self) -> &[StoredPrivateKey] {
        &self.private_keys
    }

    /// Combine two caller-owned imports after checking aggregate bytes,
    /// candidates, and cross-store name collisions before mutating either.
    pub fn extend(
        &mut self,
        mut other: Self,
        resources: &ResourcePolicy,
    ) -> Result<(), KeyStoreError> {
        ensure_resource_policy(resources)?;
        let candidates = self
            .entry_count
            .checked_add(other.entry_count)
            .ok_or(KeyStoreError::Selection("key candidate count overflow"))?;
        if candidates > resources.max_key_candidates {
            return Err(KeyStoreError::Selection("key candidate limit exceeded"));
        }
        let bytes = self
            .material_bytes
            .checked_add(other.material_bytes)
            .ok_or(KeyStoreError::Selection("key material size overflow"))?;
        if bytes > resources.max_external_resource_total_bytes {
            return Err(KeyStoreError::Selection(
                "key material total exceeds resource limit",
            ));
        }
        let mut names = HashSet::new();
        for name in other
            .symmetric_keys
            .iter()
            .map(|entry| entry.name.as_str())
            .chain(other.public_keys.iter().map(|entry| entry.name.as_str()))
            .chain(other.private_keys.iter().map(|entry| entry.name.as_str()))
        {
            names.insert(name);
        }
        if names.iter().any(|name| {
            self.symmetric_keys.iter().any(|entry| entry.name == *name)
                || self.public_keys.iter().any(|entry| entry.name == *name)
                || self.private_keys.iter().any(|entry| entry.name == *name)
        }) {
            return Err(KeyStoreError::Selection("duplicate key name"));
        }
        self.entry_count = candidates;
        self.material_bytes = bytes;
        self.symmetric_keys.append(&mut other.symmetric_keys);
        self.public_keys.append(&mut other.public_keys);
        self.private_keys.append(&mut other.private_keys);
        self.lookup_certificates
            .append(&mut other.lookup_certificates);
        self.trusted_certificates
            .append(&mut other.trusted_certificates);
        self.crls.append(&mut other.crls);
        Ok(())
    }

    /// Select an authorized named RSA recipient from XMLDSig RSAKeyValue or
    /// DER SubjectPublicKeyInfo without introducing an implicit key source.
    #[cfg(feature = "xmlenc")]
    pub fn rsa_encryption_key(
        &self,
        name: &str,
        policy: &crate::policy::EncryptionPolicy,
    ) -> Result<RsaPublicKey, KeyStoreError> {
        policy.validate()?;
        let entry = find_named_entry(
            &self.public_keys,
            name,
            &policy.resources,
            &mut 0,
            |entry| &entry.name,
        )?
        .ok_or(KeyStoreError::Selection("named encryption key not found"))?;
        entry.rsa_encryption_key(policy)
    }

    /// Select a named signer under the operation's immutable policy.
    pub fn signing_key(
        &self,
        name: &str,
        algorithm: SignatureAlgorithm,
        policy: &crate::policy::SigningPolicy,
    ) -> Result<Box<dyn SigningKey>, KeyStoreError> {
        self.signing_key_with_budget(name, algorithm, policy, &mut SigningLookupBudget::default())
    }

    /// Select a named signer while sharing lookup work across caller retries.
    pub fn signing_key_with_budget(
        &self,
        name: &str,
        algorithm: SignatureAlgorithm,
        policy: &crate::policy::SigningPolicy,
        budget: &mut SigningLookupBudget,
    ) -> Result<Box<dyn SigningKey>, KeyStoreError> {
        policy.validate()?;
        if algorithm.hmac_output_bits().is_some() {
            let entry = find_named_entry(
                &self.symmetric_keys,
                name,
                &policy.resources,
                &mut budget.inspected,
                |entry| &entry.name,
            )?
            .ok_or(KeyStoreError::Selection("named signing key not found"))?;
            if entry.kind != SymmetricKeyKind::Hmac || !entry.usages.allows(KeyUsage::Sign) {
                return Err(KeyStoreError::Selection(
                    "key is not authorized for signing",
                ));
            }
            check_operation_material_size(entry.bytes.len(), &policy.resources)?;
            let key = HmacSigningKey::new(entry.bytes.to_vec())
                .map_err(|_| KeyStoreError::Selection("invalid HMAC key"))?;
            validate_signing_key(&key, algorithm, policy).map_err(signing_policy_error)?;
            return Ok(Box::new(key));
        }
        let entry = find_named_entry(
            &self.private_keys,
            name,
            &policy.resources,
            &mut budget.inspected,
            |entry| &entry.name,
        )?
        .ok_or(KeyStoreError::Selection("named signing key not found"))?;
        if !entry.usages.allows(KeyUsage::Sign) {
            return Err(KeyStoreError::Selection(
                "key is not authorized for signing",
            ));
        }
        let der = entry.pkcs8_der.as_slice();
        check_operation_material_size(der.len(), &policy.resources)?;
        if let Ok(info) = PrivateKeyInfoRef::try_from(der)
            && info.algorithm.oid == dsa::OID
        {
            preflight_dsa_pkcs8_components(&info)?;
        }
        let key: Box<dyn SigningKey> = match algorithm {
            SignatureAlgorithm::RsaSha1
            | SignatureAlgorithm::RsaSha224
            | SignatureAlgorithm::RsaSha256
            | SignatureAlgorithm::RsaSha384
            | SignatureAlgorithm::RsaSha512 => Box::new(
                RsaSigningKey::from_pkcs8_der(der)
                    .map_err(|_| KeyStoreError::Selection("incompatible RSA signing key"))?,
            ),
            SignatureAlgorithm::DsaSha1 | SignatureAlgorithm::DsaSha256 => Box::new(
                DsaSigningKey::from_pkcs8_der(der)
                    .map_err(|_| KeyStoreError::Selection("incompatible DSA signing key"))?,
            ),
            SignatureAlgorithm::EcdsaSha1
            | SignatureAlgorithm::EcdsaSha224
            | SignatureAlgorithm::EcdsaSha256
            | SignatureAlgorithm::EcdsaSha384
            | SignatureAlgorithm::EcdsaSha512 => {
                if let Ok(key) = EcdsaP256SigningKey::from_pkcs8_der(der) {
                    Box::new(key)
                } else if let Ok(key) = EcdsaP384SigningKey::from_pkcs8_der(der) {
                    Box::new(key)
                } else {
                    Box::new(
                        EcdsaP521SigningKey::from_pkcs8_der(der)
                            .map_err(|_| KeyStoreError::Selection("incompatible EC signing key"))?,
                    )
                }
            }
            _ => return Err(KeyStoreError::Selection("unsupported signature method")),
        };
        validate_signing_key(key.as_ref(), algorithm, policy).map_err(signing_policy_error)?;
        Ok(key)
    }

    /// Select a named direct AES key or RSA private-key transport resolver.
    #[cfg(feature = "xmlenc")]
    pub fn decryption_resolver(
        &self,
        name: &str,
        policy: &crate::policy::DecryptionPolicy,
    ) -> Result<Box<dyn crate::xmlenc::DecryptionKeyResolver>, KeyStoreError> {
        policy.validate()?;
        let mut visited = 0;
        if let Some(entry) = find_named_entry(
            &self.symmetric_keys,
            name,
            &policy.resources,
            &mut visited,
            |entry| &entry.name,
        )? {
            if entry.kind != SymmetricKeyKind::Aes || !entry.usages.allows(KeyUsage::Decrypt) {
                return Err(KeyStoreError::Selection(
                    "key is not authorized for decryption",
                ));
            }
            check_selected_material_size(entry.bytes.len(), &policy.resources)?;
            return Ok(Box::new(InventoryDirectAes(Zeroizing::new(
                entry.bytes.to_vec(),
            ))));
        }
        let entry = find_named_entry(
            &self.private_keys,
            name,
            &policy.resources,
            &mut visited,
            |entry| &entry.name,
        )?
        .ok_or(KeyStoreError::Selection("named decryption key not found"))?;
        if !entry.usages.allows(KeyUsage::Decrypt) {
            return Err(KeyStoreError::Selection(
                "key is not authorized for decryption",
            ));
        }
        check_selected_material_size(entry.pkcs8_der.len(), &policy.resources)?;
        let key = RsaPrivateKey::from_pkcs8_der(&entry.pkcs8_der)
            .map_err(|_| KeyStoreError::Selection("incompatible RSA decryption key"))?;
        Ok(Box::new(crate::xmlenc::PrivateKeyDecryptor::new(key)))
    }
    /// Build a resolver from this inventory and one immutable key-store snapshot.
    /// Trust anchors are copied once, not on each candidate lookup.
    #[must_use]
    pub fn verification_resolver(&self) -> InventoryVerificationResolver<'_> {
        InventoryVerificationResolver { inventory: self }
    }
    /// Register raw symmetric bytes under a unique name.
    pub fn add_symmetric(
        &mut self,
        name: String,
        kind: SymmetricKeyKind,
        bytes: Vec<u8>,
        usages: KeyUsages,
        resources: &ResourcePolicy,
    ) -> Result<(), KeyStoreError> {
        self.check_new_name(&name, resources)?;
        if bytes.is_empty()
            || bytes.len() > resources.max_external_resource_bytes
            || (kind == SymmetricKeyKind::Aes && !matches!(bytes.len(), 16 | 24 | 32))
        {
            return Err(KeyStoreError::Selection("invalid symmetric key length"));
        }
        let permitted = match kind {
            SymmetricKeyKind::Hmac => KeyUsages::SIGN.union(KeyUsages::VERIFY),
            SymmetricKeyKind::Aes => KeyUsages::ENCRYPT.union(KeyUsages::DECRYPT),
            SymmetricKeyKind::Des => {
                return Err(KeyStoreError::Selection("DES encryption is unsupported"));
            }
        };
        if usages.0 == 0 || usages.0 & !permitted.0 != 0 {
            return Err(KeyStoreError::Selection(
                "symmetric key usage is incompatible",
            ));
        }
        self.reserve_material(named_material_length(&name, bytes.len(), 1)?, resources)?;
        self.symmetric_keys.push(StoredSymmetricKey {
            name,
            kind,
            bytes: Zeroizing::new(bytes),
            usages,
        });
        self.entry_count += 1;
        Ok(())
    }

    /// Register DER SubjectPublicKeyInfo or a complete X.509 certificate.
    /// A certificate is a lookup candidate, never an implicit trust anchor.
    pub fn add_public_der(
        &mut self,
        name: String,
        der: Vec<u8>,
        resources: &ResourcePolicy,
    ) -> Result<(), KeyStoreError> {
        self.add_public_der_inner(name, der, None, resources)
    }

    /// Register public DER with explicit verification/encryption permissions.
    pub fn add_public_der_with_usages(
        &mut self,
        name: String,
        der: Vec<u8>,
        usages: KeyUsages,
        resources: &ResourcePolicy,
    ) -> Result<(), KeyStoreError> {
        self.add_public_der_inner(name, der, Some(usages), resources)
    }

    fn add_public_der_inner(
        &mut self,
        name: String,
        der: Vec<u8>,
        usages: Option<KeyUsages>,
        resources: &ResourcePolicy,
    ) -> Result<(), KeyStoreError> {
        self.check_new_name(&name, resources)?;
        let permitted = KeyUsages::VERIFY.union(KeyUsages::ENCRYPT);
        if usages.is_some_and(|usages| usages.0 == 0 || usages.0 & !permitted.0 != 0) {
            return Err(KeyStoreError::Selection("public key usage is incompatible"));
        }
        if der.len() > resources.max_external_resource_bytes {
            return Err(KeyStoreError::Selection(
                "public key exceeds resource limit",
            ));
        }
        self.check_material_capacity(named_material_length(&name, der.len(), 2)?, resources)?;
        let material_len = der.len();
        let mut key_info = KeyInfo::default();
        key_info.sources.push(KeyInfoSource::KeyName(name.clone()));
        let is_rsa = if let Ok((rest, spki)) =
            x509_parser::x509::SubjectPublicKeyInfo::from_der(&der)
            && rest.is_empty()
            && spki.raw == der
        {
            let is_rsa = crate::xmldsig::keys::supported_parsed_spki_is_rsa(&spki, &der)
                .map_err(|_| KeyStoreError::Selection("unsupported public key algorithm"))?;
            key_info
                .sources
                .push(KeyInfoSource::DerEncodedKeyValue(der));
            is_rsa
        } else {
            let (rest, certificate) = X509Certificate::from_der(&der)
                .map_err(|_| KeyStoreError::Selection("invalid public key or X.509 certificate"))?;
            if !rest.is_empty() {
                return Err(KeyStoreError::Selection("invalid X.509 certificate"));
            }
            let parsed = crate::xmldsig::parse::parse_x509_certificate(&der)
                .map_err(|_| KeyStoreError::Selection("unsupported X.509 certificate key"))?;
            let is_rsa = crate::xmldsig::keys::supported_parsed_spki_is_rsa(
                certificate.public_key(),
                certificate.public_key().raw,
            )
            .map_err(|_| KeyStoreError::Selection("unsupported X.509 certificate key"))?;
            key_info.sources.push(KeyInfoSource::X509Data(X509DataInfo {
                certificates: vec![der],
                parsed_certificates: vec![parsed],
                certificate_chain: vec![0],
                ..X509DataInfo::default()
            }));
            is_rsa
        };
        let usages = usages.unwrap_or(if is_rsa { permitted } else { KeyUsages::VERIFY });
        if usages.allows(KeyUsage::Encrypt) && !is_rsa {
            return Err(KeyStoreError::Selection(
                "only RSA public keys can be used for encryption",
            ));
        }
        self.reserve_material(named_material_length(&name, material_len, 2)?, resources)?;
        self.public_keys.push(StoredPublicKey {
            name,
            key_info,
            usages,
        });
        self.entry_count += 1;
        Ok(())
    }

    /// Import one PEM-encoded public key. RFC 7468 labels select SPKI or
    /// PKCS#1; extra text and multiple armor blocks are rejected.
    pub fn add_public_pem(
        &mut self,
        name: String,
        bytes: &[u8],
        resources: &ResourcePolicy,
    ) -> Result<(), KeyStoreError> {
        self.add_public_pem_inner(name, bytes, None, resources)
    }

    /// Import one PEM public key with explicit verification/encryption permissions.
    pub fn add_public_pem_with_usages(
        &mut self,
        name: String,
        bytes: &[u8],
        usages: KeyUsages,
        resources: &ResourcePolicy,
    ) -> Result<(), KeyStoreError> {
        self.add_public_pem_inner(name, bytes, Some(usages), resources)
    }

    fn add_public_pem_inner(
        &mut self,
        name: String,
        bytes: &[u8],
        usages: Option<KeyUsages>,
        resources: &ResourcePolicy,
    ) -> Result<(), KeyStoreError> {
        ensure_resource_policy(resources)?;
        self.check_new_name(&name, resources)?;
        self.check_material_capacity(named_material_length(&name, bytes.len(), 2)?, resources)?;
        let block = single_pem_block(bytes, resources.max_external_resource_bytes)?;
        let der = match block.tag() {
            "PUBLIC KEY" => block.into_contents(),
            "RSA PUBLIC KEY" => {
                let components = rsa::pkcs1::RsaPublicKey::from_der(block.contents())
                    .map_err(|_| KeyStoreError::Selection("invalid RSA public key"))?;
                crate::xmldsig::keys::bounded_rsa_public_components(
                    components.modulus.as_bytes(),
                    components.public_exponent.as_bytes(),
                )
                .map_err(|_| KeyStoreError::Selection("RSA public key exceeds safety limit"))?;
                RsaPublicKey::from_pkcs1_der(block.contents())
                    .ok()
                    .and_then(|key| key.to_public_key_der().ok())
                    .map(|der| der.as_bytes().to_vec())
                    .ok_or(KeyStoreError::Selection("invalid RSA public key"))?
            }
            _ => return Err(KeyStoreError::Selection("unsupported public PEM label")),
        };
        let previous_total = self.material_bytes;
        let charged_total = self.check_material_capacity(
            named_material_length(&name, bytes.len().max(der.len()), 2)?,
            resources,
        )?;
        self.add_public_der_inner(name, der, usages, resources)?;
        debug_assert!(self.material_bytes >= previous_total);
        self.material_bytes = charged_total;
        Ok(())
    }

    /// Import a DER private key as PKCS#8 (plain or encrypted) or RSA PKCS#1.
    /// Passwords are consulted only for a structurally encrypted container;
    /// a wrong password never retries a plaintext decoder.
    pub fn add_private_der(
        &mut self,
        name: String,
        bytes: &[u8],
        password: Option<&[u8]>,
        usages: KeyUsages,
        resources: &ResourcePolicy,
    ) -> Result<(), KeyStoreError> {
        self.check_new_name(&name, resources)?;
        if bytes.len() > resources.max_external_resource_bytes {
            return Err(KeyStoreError::Selection(
                "private key exceeds resource limit",
            ));
        }
        self.check_material_capacity(named_material_length(&name, bytes.len(), 1)?, resources)?;
        let permitted = KeyUsages::SIGN.union(KeyUsages::DECRYPT);
        if usages.0 == 0 || usages.0 & !permitted.0 != 0 {
            return Err(KeyStoreError::Selection(
                "private key usage is incompatible",
            ));
        }
        let der = if PrivateKeyInfoRef::try_from(bytes).is_ok() {
            Zeroizing::new(bytes.to_vec())
        } else if let Ok(encrypted) = EncryptedPrivateKeyInfoRef::try_from(bytes) {
            enforce_pkcs8_kdf_policy(&encrypted, resources)?;
            let password = password.ok_or(KeyStoreError::ProtectedContainer)?;
            let plain = encrypted
                .decrypt(password)
                .map_err(|_| KeyStoreError::ProtectedContainer)?;
            Zeroizing::new(plain.as_bytes().to_vec())
        } else {
            preflight_rsa_pkcs1_components(bytes)?;
            let rsa = RsaPrivateKey::from_pkcs1_der(bytes)
                .map_err(|_| KeyStoreError::Selection("unsupported private key DER"))?;
            let normalized = rsa
                .to_pkcs8_der()
                .map_err(|_| KeyStoreError::Selection("invalid RSA private key"))?;
            Zeroizing::new(normalized.as_bytes().to_vec())
        };
        if der.len() > resources.max_external_resource_bytes {
            return Err(KeyStoreError::Selection(
                "private key exceeds resource limit",
            ));
        }
        private_key_spki(&der)?;
        if usages.allows(KeyUsage::Decrypt) && RsaPrivateKey::from_pkcs8_der(&der).is_err() {
            return Err(KeyStoreError::Selection(
                "only RSA private keys can be used for decryption",
            ));
        }
        self.reserve_material(
            named_material_length(&name, bytes.len().max(der.len()), 1)?,
            resources,
        )?;
        self.private_keys.push(StoredPrivateKey {
            name,
            pkcs8_der: der,
            usages,
            certificate_chain: Vec::new(),
            has_matching_leaf: false,
        });
        self.entry_count += 1;
        Ok(())
    }

    /// Import private DER using a caller-owned password callback only when
    /// the input is an encrypted PKCS#8 container.
    pub fn add_private_der_with_password_callback<F>(
        &mut self,
        name: String,
        bytes: &[u8],
        password: F,
        usages: KeyUsages,
        resources: &ResourcePolicy,
    ) -> Result<(), KeyStoreError>
    where
        F: FnOnce() -> Option<Zeroizing<Vec<u8>>>,
    {
        self.check_new_name(&name, resources)?;
        if bytes.len() > resources.max_external_resource_bytes {
            return Err(KeyStoreError::Selection(
                "private key exceeds resource limit",
            ));
        }
        self.check_material_capacity(named_material_length(&name, bytes.len(), 1)?, resources)?;
        let secret = if let Ok(encrypted) = EncryptedPrivateKeyInfoRef::try_from(bytes) {
            enforce_pkcs8_kdf_policy(&encrypted, resources)?;
            Some(password().ok_or(KeyStoreError::ProtectedContainer)?)
        } else {
            None
        };
        self.add_private_der(
            name,
            bytes,
            secret.as_deref().map(Vec::as_slice),
            usages,
            resources,
        )
    }

    /// Import one PEM private key, including encrypted PKCS#8. Traditional
    /// OpenSSL PEM encryption is handled at the CLI compatibility boundary.
    pub fn add_private_pem(
        &mut self,
        name: String,
        bytes: &[u8],
        password: Option<&[u8]>,
        usages: KeyUsages,
        resources: &ResourcePolicy,
    ) -> Result<(), KeyStoreError> {
        ensure_resource_policy(resources)?;
        self.check_new_name(&name, resources)?;
        self.check_material_capacity(named_material_length(&name, bytes.len(), 1)?, resources)?;
        let block = single_pem_block(bytes, resources.max_external_resource_bytes)?;
        match block.tag() {
            "PRIVATE KEY" | "ENCRYPTED PRIVATE KEY" | "RSA PRIVATE KEY" => {
                let der = Zeroizing::new(block.into_contents());
                let previous_total = self.material_bytes;
                let name_len = name.len();
                self.add_private_der(name, &der, password, usages, resources)?;
                let retained_len = self.material_bytes - previous_total;
                self.material_bytes =
                    previous_total + name_len + bytes.len().max(retained_len - name_len);
                Ok(())
            }
            _ => Err(KeyStoreError::Selection("unsupported private PEM label")),
        }
    }

    /// Import a bounded PKCS#12 bundle from caller-owned bytes. The key may
    /// sign; RSA keys may also decrypt. A bundle with more than one private
    /// key is rejected rather than assigning names from iteration order.
    pub fn add_pkcs12(
        &mut self,
        name: String,
        bytes: &[u8],
        password: &str,
        resources: &ResourcePolicy,
    ) -> Result<(), KeyStoreError> {
        self.add_pkcs12_inner(
            name,
            bytes,
            password,
            KeyUsages::SIGN.union(KeyUsages::DECRYPT),
            resources,
            true,
        )
    }

    /// Import PKCS#12 using a caller-owned password callback. Its result is
    /// zeroized after decoding and callback failure exposes no diagnostic.
    pub fn add_pkcs12_with_password_callback<F>(
        &mut self,
        name: String,
        bytes: &[u8],
        password: F,
        usages: KeyUsages,
        resources: &ResourcePolicy,
    ) -> Result<(), KeyStoreError>
    where
        F: FnOnce() -> Option<Zeroizing<String>>,
    {
        let limits = self.pkcs12_import_limits(&name, bytes, usages, resources)?;
        let prepared = pkcs12_import::prepare(bytes, &limits)?;
        let secret = password().ok_or(KeyStoreError::ProtectedContainer)?;
        let contents = prepared.decrypt(&secret)?;
        self.add_pkcs12_contents(name, bytes.len(), contents, usages, resources, false)
    }

    /// Import a PKCS#12 bundle with explicit signing/decryption permissions.
    pub fn add_pkcs12_with_usages(
        &mut self,
        name: String,
        bytes: &[u8],
        password: &str,
        usages: KeyUsages,
        resources: &ResourcePolicy,
    ) -> Result<(), KeyStoreError> {
        self.add_pkcs12_inner(name, bytes, password, usages, resources, false)
    }

    fn add_pkcs12_inner(
        &mut self,
        name: String,
        bytes: &[u8],
        password: &str,
        usages: KeyUsages,
        resources: &ResourcePolicy,
        auto_decrypt: bool,
    ) -> Result<(), KeyStoreError> {
        let limits = self.pkcs12_import_limits(&name, bytes, usages, resources)?;
        let contents = pkcs12_import::prepare(bytes, &limits)?.decrypt(password)?;
        self.add_pkcs12_contents(name, bytes.len(), contents, usages, resources, auto_decrypt)
    }

    fn add_pkcs12_contents(
        &mut self,
        name: String,
        encoded_len: usize,
        mut contents: pkcs12_import::Contents,
        mut usages: KeyUsages,
        resources: &ResourcePolicy,
        auto_decrypt: bool,
    ) -> Result<(), KeyStoreError> {
        if contents.private_keys.len() != 1 {
            return Err(KeyStoreError::Selection(
                "PKCS#12 bundle must contain exactly one private key",
            ));
        }
        let private_key = contents
            .private_keys
            .pop()
            .ok_or(KeyStoreError::ProtectedContainer)?;
        let mut certificates = contents.certificates;
        let spki = private_key_spki(private_key.as_ref())?;
        if usages.allows(KeyUsage::Decrypt)
            && RsaPrivateKey::from_pkcs8_der(private_key.as_ref()).is_err()
        {
            if auto_decrypt {
                usages = KeyUsages::SIGN;
            } else {
                return Err(KeyStoreError::Selection(
                    "only RSA private keys can be used for decryption",
                ));
            }
        }
        let mut matching_leaf = None;
        for certificate in &certificates {
            let (rest, parsed) = X509Certificate::from_der(certificate)
                .map_err(|_| KeyStoreError::Selection("invalid certificate in PKCS#12"))?;
            if !rest.is_empty() {
                return Err(KeyStoreError::Selection("invalid certificate in PKCS#12"));
            }
            if parsed.public_key().raw == spki.as_slice() {
                if matching_leaf.is_some_and(|leaf: &[u8]| leaf != certificate.as_slice()) {
                    return Err(KeyStoreError::Selection(
                        "ambiguous certificate for PKCS#12 private key",
                    ));
                }
                // RFC 7292 section 4.2 permits repeated certificate bags.
                // Identical DER is the same leaf, not a second candidate.
                matching_leaf = Some(certificate.as_slice());
            }
        }
        // PKCS#12 may carry unrelated CA certificates. They remain lookup
        // material; only an actual SPKI match is promoted to the leaf slot.
        let has_matching_leaf = matching_leaf.is_some();
        if let Some(leaf) = matching_leaf {
            let position = certificates
                .iter()
                .position(|candidate| candidate == leaf)
                .ok_or(KeyStoreError::ProtectedContainer)?;
            certificates.swap(0, position);
            let mut index = 1;
            while index < certificates.len() {
                if certificates[index] == certificates[0] {
                    certificates.remove(index);
                } else {
                    index += 1;
                }
            }
        }
        let decoded_bytes = certificates
            .iter()
            .try_fold(private_key.len(), |total, cert| {
                total
                    .checked_add(cert.len())
                    .ok_or(KeyStoreError::Selection("key material size overflow"))
            })?;
        let retained_candidates = 1_usize
            .checked_add(certificates.len())
            .ok_or(KeyStoreError::Selection("key candidate count overflow"))?;
        let remaining_candidates = resources.max_key_candidates - self.entry_count;
        if retained_candidates > remaining_candidates {
            return Err(crate::policy::PolicyViolation::ResourceLimitExceeded {
                resource: crate::policy::resource_name::KEY_CANDIDATES,
                maximum: remaining_candidates,
            }
            .into());
        }
        self.reserve_material(
            named_material_length(&name, decoded_bytes.max(encoded_len), 1)?,
            resources,
        )?;
        self.private_keys.push(StoredPrivateKey {
            name,
            pkcs8_der: private_key,
            usages,
            certificate_chain: certificates,
            has_matching_leaf,
        });
        self.entry_count += retained_candidates;
        Ok(())
    }

    fn pkcs12_import_limits(
        &self,
        name: &str,
        bytes: &[u8],
        usages: KeyUsages,
        resources: &ResourcePolicy,
    ) -> Result<Pkcs12Limits, KeyStoreError> {
        self.check_new_name(name, resources)?;
        let permitted = KeyUsages::SIGN.union(KeyUsages::DECRYPT);
        if usages.0 == 0 || usages.0 & !permitted.0 != 0 {
            return Err(KeyStoreError::Selection(
                "private key usage is incompatible",
            ));
        }
        if bytes.len() > resources.max_external_resource_bytes {
            return Err(KeyStoreError::Policy(
                crate::policy::PolicyViolation::ResourceLimitExceeded {
                    resource: crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
                    maximum: resources.max_external_resource_bytes,
                },
            ));
        }
        self.check_material_capacity(named_material_length(name, bytes.len(), 1)?, resources)?;
        let remaining_candidates = resources.max_key_candidates - self.entry_count;
        Ok(Pkcs12Limits {
            resources: resources.clone(),
            candidates: remaining_candidates,
            memory_available: resources.max_external_resource_total_bytes
                - self.material_bytes
                - name.len(),
        })
    }

    fn check_new_name(&self, name: &str, resources: &ResourcePolicy) -> Result<(), KeyStoreError> {
        ensure_resource_policy(resources)?;
        if name.is_empty() || self.entry_count >= resources.max_key_candidates {
            return Err(KeyStoreError::Selection(
                "name or key candidate limit is invalid",
            ));
        }
        if name.len() > resources.max_external_resource_bytes {
            return Err(KeyStoreError::Selection("key name exceeds resource limit"));
        }
        self.check_material_capacity(name.len(), resources)?;
        if self.symmetric_keys.iter().any(|key| key.name == name)
            || self.public_keys.iter().any(|key| key.name == name)
            || self.private_keys.iter().any(|key| key.name == name)
        {
            return Err(KeyStoreError::Selection("duplicate key name"));
        }
        Ok(())
    }

    fn check_material_capacity(
        &self,
        length: usize,
        resources: &ResourcePolicy,
    ) -> Result<usize, KeyStoreError> {
        let total = self
            .material_bytes
            .checked_add(length)
            .ok_or(KeyStoreError::Selection("key material size overflow"))?;
        if total > resources.max_external_resource_total_bytes {
            return Err(KeyStoreError::Selection(
                "key material total exceeds resource limit",
            ));
        }
        Ok(total)
    }

    fn reserve_material(
        &mut self,
        length: usize,
        resources: &ResourcePolicy,
    ) -> Result<(), KeyStoreError> {
        self.material_bytes = self.check_material_capacity(length, resources)?;
        Ok(())
    }

    /// Import a DER certificate as an untrusted lookup candidate or an
    /// explicitly caller-trusted anchor. Parsing alone never grants trust.
    pub fn add_certificate_der(
        &mut self,
        der: Vec<u8>,
        trusted_anchor: bool,
        resources: &ResourcePolicy,
    ) -> Result<(), KeyStoreError> {
        ensure_resource_policy(resources)?;
        if der.len() > resources.max_external_resource_bytes {
            return Err(KeyStoreError::Selection(
                "certificate exceeds resource limit",
            ));
        }
        let (rest, _) = X509Certificate::from_der(&der)
            .map_err(|_| KeyStoreError::Selection("invalid X.509 certificate"))?;
        if !rest.is_empty() {
            return Err(KeyStoreError::Selection("invalid X.509 certificate"));
        }
        if self.entry_count >= resources.max_key_candidates {
            return Err(KeyStoreError::Selection("key candidate limit exceeded"));
        }
        self.reserve_material(der.len(), resources)?;
        if trusted_anchor {
            self.trusted_certificates.push(der);
        } else {
            self.lookup_certificates.push(der);
        }
        self.entry_count += 1;
        Ok(())
    }

    /// Import a DER CRL for policy-controlled revocation checks.
    pub fn add_crl_der(
        &mut self,
        der: Vec<u8>,
        resources: &ResourcePolicy,
    ) -> Result<(), KeyStoreError> {
        ensure_resource_policy(resources)?;
        if der.len() > resources.max_external_resource_bytes {
            return Err(KeyStoreError::Selection("CRL exceeds resource limit"));
        }
        let (rest, _) = x509_parser::revocation_list::CertificateRevocationList::from_der(&der)
            .map_err(|_| KeyStoreError::Selection("invalid X.509 CRL"))?;
        if !rest.is_empty() {
            return Err(KeyStoreError::Selection("invalid X.509 CRL"));
        }
        if self.entry_count >= resources.max_key_candidates {
            return Err(KeyStoreError::Selection("key candidate limit exceeded"));
        }
        self.reserve_material(der.len(), resources)?;
        self.crls.push(der);
        self.entry_count += 1;
        Ok(())
    }
    /// Import caller-owned XML bytes under the operation's XML and resource snapshot.
    pub fn from_xml_bytes<P: crate::document::XmlDocumentPolicy>(
        bytes: &[u8],
        policy: &P,
        backend: XmlBackend,
    ) -> Result<Self, KeyStoreError> {
        let resources = policy.resource_policy();
        ensure_resource_policy(resources)?;
        if bytes.len() > resources.max_external_resource_bytes
            || bytes.len() > resources.max_external_resource_total_bytes
        {
            return Err(KeyStoreError::Selection(
                "XML key store exceeds resource limit",
            ));
        }
        let settings = DocumentParseSettings::from_policy(policy.xml_input_policy(), resources)
            .with_backend(backend);
        let budget = XmlParseWorkBudget::from_resources(resources);
        let text = crate::document::decode_xml_with_budget(
            bytes,
            resources
                .max_xml_document_bytes
                .min(resources.max_external_resource_bytes),
            Some(&budget),
        )
        .map_err(|error| KeyStoreError::Invalid(error.to_string()))?;
        let document = parse_borrowed_with_settings_and_budget(&text, settings, Some(&budget))
            .map_err(|error| KeyStoreError::Invalid(error.to_string()))?;
        let root = document.root_element();
        if !root.has_tag_name((XMLSEC_NS, "Keys")) {
            return Err(KeyStoreError::Invalid("expected xmlsec Keys root".into()));
        }
        let mut names = HashSet::new();
        let mut store = Self::default();
        let mut entry_count = 0_usize;
        for info in root.children().filter(|child| child.is_element()) {
            if !info.has_tag_name((XMLDSIG_NS, "KeyInfo")) {
                return Err(KeyStoreError::Invalid("unexpected child of Keys".into()));
            }
            if entry_count >= resources.max_key_candidates {
                return Err(KeyStoreError::Invalid(
                    "key candidate limit exceeded".into(),
                ));
            }
            entry_count += 1;
            let mut name = None;
            let mut value = None;
            for child in info.children().filter(|child| child.is_element()) {
                if child.has_tag_name((XMLDSIG_NS, "KeyName")) {
                    if name.is_some() {
                        return Err(KeyStoreError::Invalid("duplicate KeyName".into()));
                    }
                    let text = element_text(child)?;
                    if text.is_empty() {
                        return Err(KeyStoreError::Invalid("empty KeyName".into()));
                    }
                    name = Some(text);
                } else if child.has_tag_name((XMLDSIG_NS, "KeyValue")) {
                    if value.is_some() {
                        return Err(KeyStoreError::Invalid("duplicate KeyValue".into()));
                    }
                    let mut values = child.children().filter(|node| node.is_element());
                    let key = values.next().ok_or_else(|| {
                        KeyStoreError::Invalid("KeyValue has no key material".into())
                    })?;
                    if values.next().is_some() {
                        return Err(KeyStoreError::Invalid("ambiguous KeyValue".into()));
                    }
                    let material = if key.has_tag_name((XMLSEC_NS, "HMACKeyValue")) {
                        Some(SymmetricKeyKind::Hmac)
                    } else if key.has_tag_name((XMLSEC_NS, "AESKeyValue")) {
                        Some(SymmetricKeyKind::Aes)
                    } else if key.has_tag_name((XMLSEC_NS, "DESKeyValue")) {
                        Some(SymmetricKeyKind::Des)
                    } else {
                        None
                    };
                    value = Some(if let Some(kind) = material {
                        ParsedMaterial::Symmetric(kind, Zeroizing::new(decode_xml_base64(key)?))
                    } else if key.has_tag_name((XMLDSIG_NS, "DSAKeyValue")) {
                        let (public, private) = parse_xmlsec_dsa_key_value(key)?;
                        ParsedMaterial::Dsa(public, private)
                    } else if key.has_tag_name((XMLDSIG_NS, "RSAKeyValue"))
                        // XMLDSig 1.1 section 4.5.2.3 places ECKeyValue in dsig11:
                        // https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-ECKeyValue
                        || key.has_tag_name((XMLDSIG11_NS, "ECKeyValue"))
                    {
                        ParsedMaterial::Public(None)
                    } else {
                        ParsedMaterial::Unsupported
                    });
                } else {
                    return Err(KeyStoreError::Invalid("unsupported KeyInfo child".into()));
                }
            }
            let name = name.ok_or_else(|| KeyStoreError::Invalid("missing KeyName".into()))?;
            let material =
                value.ok_or_else(|| KeyStoreError::Invalid("missing KeyValue".into()))?;
            if !names.insert(name.clone()) {
                return Err(KeyStoreError::Invalid("duplicate key name".into()));
            }
            match material {
                ParsedMaterial::Symmetric(kind, bytes) => {
                    if bytes.is_empty() {
                        return Err(KeyStoreError::Invalid("empty symmetric key".into()));
                    }
                    if kind == SymmetricKeyKind::Aes && !matches!(bytes.len(), 16 | 24 | 32) {
                        return Err(KeyStoreError::Invalid("invalid AES key length".into()));
                    }
                    let usages = match kind {
                        SymmetricKeyKind::Hmac => KeyUsages::SIGN.union(KeyUsages::VERIFY),
                        SymmetricKeyKind::Aes => KeyUsages::ENCRYPT.union(KeyUsages::DECRYPT),
                        SymmetricKeyKind::Des => {
                            return Err(KeyStoreError::Selection("DES encryption is unsupported"));
                        }
                    };
                    store.symmetric_keys.push(StoredSymmetricKey {
                        name,
                        kind,
                        bytes,
                        usages,
                    });
                }
                ParsedMaterial::Public(manual_value) => {
                    let key_info = if let Some(value) = manual_value {
                        let mut key_info = KeyInfo::default();
                        key_info.sources.push(KeyInfoSource::KeyName(name.clone()));
                        key_info.sources.push(KeyInfoSource::KeyValue(value));
                        key_info
                    } else {
                        parse_key_info(info)
                            .map_err(|error| KeyStoreError::Invalid(error.to_string()))?
                    };
                    let is_rsa = key_info
                        .sources
                        .iter()
                        .find_map(|source| match source {
                            KeyInfoSource::KeyValue(value) => Some(value),
                            _ => None,
                        })
                        .ok_or_else(|| KeyStoreError::Invalid("invalid public KeyValue".into()))?;
                    let is_rsa = crate::xmldsig::keys::supported_key_value_is_rsa(is_rsa)
                        .map_err(|_| KeyStoreError::Invalid("invalid public KeyValue".into()))?;
                    let usages = if is_rsa {
                        KeyUsages::VERIFY.union(KeyUsages::ENCRYPT)
                    } else {
                        KeyUsages::VERIFY
                    };
                    store.public_keys.push(StoredPublicKey {
                        name,
                        key_info,
                        usages,
                    });
                }
                ParsedMaterial::Dsa(public, private) => {
                    // This inventory has no external DSA parameter inheritance;
                    // its stored public tuple must be independently resolvable.
                    crate::xmldsig::keys::supported_key_value_is_rsa(&public)
                        .map_err(|_| KeyStoreError::Invalid("invalid public DSAKeyValue".into()))?;
                    let mut key_info = KeyInfo::default();
                    key_info.sources.push(KeyInfoSource::KeyName(name.clone()));
                    key_info.sources.push(KeyInfoSource::KeyValue(public));
                    if let Some(pkcs8_der) = private {
                        store.private_keys.push(StoredPrivateKey {
                            name: name.clone(),
                            pkcs8_der,
                            usages: KeyUsages::SIGN,
                            certificate_chain: Vec::new(),
                            has_matching_leaf: false,
                        });
                    }
                    store.public_keys.push(StoredPublicKey {
                        name,
                        key_info,
                        usages: KeyUsages::VERIFY,
                    });
                }
                ParsedMaterial::Unsupported => {}
            }
        }
        store.entry_count = entry_count;
        // Decoding can retain both public components and a derived private key.
        // Keep the input charge too, so compact XML never lowers the import budget.
        store.material_bytes = bytes.len().max(store.retained_material_bytes()?);
        if store.material_bytes > resources.max_external_resource_total_bytes {
            return Err(KeyStoreError::Selection(
                "key material total exceeds resource limit",
            ));
        }
        Ok(store)
    }
}

fn check_operation_material_size(
    length: usize,
    resources: &ResourcePolicy,
) -> Result<(), KeyStoreError> {
    if length > resources.max_external_resource_bytes {
        return Err(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
            maximum: resources.max_external_resource_bytes,
            actual: length,
        }
        .into());
    }
    if length > resources.max_external_resource_total_bytes {
        return Err(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
            maximum: resources.max_external_resource_total_bytes,
            actual: length,
        }
        .into());
    }
    Ok(())
}

#[cfg(feature = "xmlenc")]
fn check_selected_material_size(
    length: usize,
    resources: &ResourcePolicy,
) -> Result<(), KeyStoreError> {
    check_operation_material_size(length, resources)
}

#[cfg(feature = "xmlenc")]
fn check_encryption_material_size(
    length: usize,
    resources: &ResourcePolicy,
) -> Result<(), KeyStoreError> {
    check_operation_material_size(length, resources)
}

#[cfg(feature = "xmlenc")]
fn rsa_recipient_preflight(
    modulus: &[u8],
    exponent: &[u8],
    policy: &crate::policy::EncryptionPolicy,
) -> Result<(), KeyStoreError> {
    let combined = modulus
        .len()
        .checked_add(exponent.len())
        .ok_or(KeyStoreError::Selection("encryption key size overflow"))?;
    check_encryption_material_size(combined, &policy.resources)?;
    policy
        .rsa_keys
        .validate_components("encryption", modulus, exponent)?;
    Ok(())
}

#[cfg(feature = "xmlenc")]
fn rsa_recipient_from_components(
    modulus: &[u8],
    exponent: &[u8],
    policy: &crate::policy::EncryptionPolicy,
) -> Result<RsaPublicKey, KeyStoreError> {
    rsa_recipient_preflight(modulus, exponent, policy)?;
    let first_nonzero = modulus
        .iter()
        .position(|byte| *byte != 0)
        .ok_or(KeyStoreError::Selection("invalid RSA encryption key"))?;
    RsaPublicKey::new(
        BoxedUint::from_be_slice_vartime(&modulus[first_nonzero..]),
        BoxedUint::from_be_slice_vartime(exponent),
    )
    .map_err(|_| KeyStoreError::Selection("invalid RSA encryption key"))
}

fn signing_policy_error(error: crate::xmldsig::SigningError) -> KeyStoreError {
    match error {
        crate::xmldsig::SigningError::Policy(violation) => violation.into(),
        _ => KeyStoreError::Selection("signing key violates operation policy"),
    }
}

fn ensure_resource_policy(resources: &ResourcePolicy) -> Result<(), KeyStoreError> {
    resources.validate().map_err(Into::into)
}

fn find_named_entry<'a, T>(
    entries: &'a [T],
    name: &str,
    resources: &ResourcePolicy,
    visited: &mut usize,
    entry_name: impl Fn(&T) -> &str,
) -> Result<Option<&'a T>, KeyStoreError> {
    for entry in entries {
        let next = visited
            .checked_add(1)
            .ok_or(KeyStoreError::Selection("key candidate count overflow"))?;
        resources.validate_key_candidates(next)?;
        *visited = next;
        if entry_name(entry) == name {
            return Ok(Some(entry));
        }
    }
    Ok(None)
}

fn named_material_length(
    name: &str,
    payload: usize,
    retained_names: usize,
) -> Result<usize, KeyStoreError> {
    name.len()
        .checked_mul(retained_names)
        .and_then(|names| names.checked_add(payload))
        .ok_or(KeyStoreError::Selection("key material size overflow"))
}

fn private_key_spki(der: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
    let info = PrivateKeyInfoRef::try_from(der)
        .map_err(|_| KeyStoreError::Selection("unsupported PKCS#12 private key"))?;
    if info.algorithm.oid == rsa::pkcs1::ALGORITHM_OID {
        preflight_rsa_pkcs1_components(info.private_key.as_bytes())?;
    } else if info.algorithm.oid == dsa::OID {
        preflight_dsa_pkcs8_components(&info)?;
    }
    macro_rules! try_key {
        ($key:ty) => {
            if let Ok(key) = <$key>::from_pkcs8_der(der) {
                return key
                    .public_key_info()
                    .ok()
                    .and_then(|info| info.spki_der().map(ToOwned::to_owned))
                    .ok_or(KeyStoreError::Selection("private key has no public key"));
            }
        };
    }
    try_key!(RsaSigningKey);
    try_key!(DsaSigningKey);
    try_key!(EcdsaP256SigningKey);
    try_key!(EcdsaP384SigningKey);
    try_key!(EcdsaP521SigningKey);
    Err(KeyStoreError::Selection("unsupported PKCS#12 private key"))
}

fn preflight_rsa_pkcs1_components(der: &[u8]) -> Result<(), KeyStoreError> {
    let key = rsa::pkcs1::RsaPrivateKey::from_der(der)
        .map_err(|_| KeyStoreError::Selection("invalid RSA private key"))?;
    let modulus = key.modulus.as_bytes();
    let maximum = crate::hard_limits::RSA_MODULUS_BIT_CEILING;
    if modulus.len() > maximum.div_ceil(8)
        || modulus
            .first()
            .is_some_and(|first| modulus.len() * 8 - first.leading_zeros() as usize > maximum)
    {
        return Err(KeyStoreError::Selection("RSA modulus exceeds safety limit"));
    }
    if [
        key.public_exponent,
        key.private_exponent,
        key.prime1,
        key.prime2,
        key.exponent1,
        key.exponent2,
        key.coefficient,
    ]
    .into_iter()
    .any(|component| component.as_bytes().len() > maximum.div_ceil(8))
        || key.other_prime_infos.as_ref().is_some_and(|infos| {
            infos.iter().any(|info| {
                [info.prime, info.exponent, info.coefficient]
                    .into_iter()
                    .any(|component| component.as_bytes().len() > maximum.div_ceil(8))
            })
        })
    {
        return Err(KeyStoreError::Selection(
            "RSA component exceeds safety limit",
        ));
    }
    Ok(())
}

#[derive(der::Sequence)]
struct BorrowedDsaParameters<'a> {
    p: der::asn1::UintRef<'a>,
    q: der::asn1::UintRef<'a>,
    g: der::asn1::UintRef<'a>,
}

fn preflight_dsa_pkcs8_components(info: &PrivateKeyInfoRef<'_>) -> Result<(), KeyStoreError> {
    let parameters = info
        .algorithm
        .parameters
        .as_ref()
        .ok_or(KeyStoreError::Selection("missing DSA parameters"))?
        .decode_as::<BorrowedDsaParameters<'_>>()
        .map_err(|_| KeyStoreError::Selection("invalid DSA parameters"))?;
    let x = der::asn1::UintRef::from_der(info.private_key.as_bytes())
        .map_err(|_| KeyStoreError::Selection("invalid DSA private exponent"))?;
    if [parameters.p, parameters.q, parameters.g, x]
        .into_iter()
        .any(|component| {
            component.as_bytes().len() > crate::hard_limits::DSA_KEY_COMPONENT_BYTE_CEILING
        })
    {
        return Err(KeyStoreError::Selection(
            "DSA component exceeds safety limit",
        ));
    }
    Ok(())
}

fn single_pem_block(bytes: &[u8], maximum: usize) -> Result<pem::Pem, KeyStoreError> {
    if bytes.len() > maximum {
        return Err(KeyStoreError::Selection("PEM key exceeds resource limit"));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| KeyStoreError::Selection("PEM key is not ASCII text"))?
        .trim_matches(|character: char| character.is_ascii_whitespace());
    let block = pem::parse(text).map_err(|_| KeyStoreError::Selection("invalid PEM key"))?;
    let begin = format!("-----BEGIN {}-----", block.tag());
    let end = format!("-----END {}-----", block.tag());
    if !text.starts_with(&begin)
        || !text.ends_with(&end)
        || text.matches(&begin).count() != 1
        || text.matches(&end).count() != 1
    {
        return Err(KeyStoreError::Selection(
            "PEM must contain one complete block",
        ));
    }
    Ok(block)
}

fn enforce_pkcs8_kdf_policy(
    encrypted: &EncryptedPrivateKeyInfoRef<'_>,
    resources: &ResourcePolicy,
) -> Result<(), KeyStoreError> {
    use pkcs8::pkcs5::{EncryptionScheme, pbes2::Kdf};
    // RFC 8018 §6.2 leaves KDF iteration policy to the application. Reject
    // excessive work before decrypting attacker-supplied containers.
    // https://www.rfc-editor.org/rfc/rfc8018#section-6.2
    let EncryptionScheme::Pbes2(params) = &encrypted.encryption_algorithm else {
        return Err(KeyStoreError::ProtectedContainer);
    };
    match &params.kdf {
        Kdf::Pbkdf2(kdf) => {
            if kdf.iteration_count == 0 {
                return Err(KeyStoreError::ProtectedContainer);
            }
            if u64::from(kdf.iteration_count) > resources.max_key_import_kdf_work as u64 {
                return Err(kdf_policy_violation(
                    crate::policy::resource_name::KEY_IMPORT_KDF_WORK,
                    resources.max_key_import_kdf_work,
                    Some(u64::from(kdf.iteration_count)),
                ));
            }
        }
        Kdf::Scrypt(kdf) => {
            enforce_scrypt_kdf_limits(
                kdf.cost_parameter,
                u64::from(kdf.block_size),
                u64::from(kdf.parallelization),
                resources,
            )?;
        }
        _ => return Err(KeyStoreError::ProtectedContainer),
    }
    Ok(())
}

fn enforce_scrypt_kdf_limits(
    n: u64,
    r: u64,
    p: u64,
    resources: &ResourcePolicy,
) -> Result<(), KeyStoreError> {
    if n == 0 || r == 0 || p == 0 {
        return Err(KeyStoreError::ProtectedContainer);
    }
    let work = n.checked_mul(r).and_then(|value| value.checked_mul(p));
    if work.is_none_or(|value| value > resources.max_key_import_kdf_work as u64) {
        return Err(kdf_policy_violation(
            crate::policy::resource_name::KEY_IMPORT_KDF_WORK,
            resources.max_key_import_kdf_work,
            work,
        ));
    }
    // RustCrypto scrypt retains B[p*r] plus V[N*r] and T[r] per parallel
    // worker when its `parallel` feature is unified in a downstream build.
    let memory = n
        .checked_add(2)
        .and_then(|blocks| blocks.checked_mul(p))
        .and_then(|blocks| blocks.checked_mul(r))
        .and_then(|blocks| blocks.checked_mul(128));
    if memory.is_none_or(|value| value > resources.max_key_import_kdf_memory_bytes as u64) {
        return Err(kdf_policy_violation(
            crate::policy::resource_name::KEY_IMPORT_KDF_MEMORY,
            resources.max_key_import_kdf_memory_bytes,
            memory,
        ));
    }
    Ok(())
}

fn kdf_policy_violation(
    resource: &'static str,
    maximum: usize,
    actual: Option<u64>,
) -> KeyStoreError {
    KeyStoreError::Policy(crate::policy::PolicyViolation::ResourceLimit {
        resource,
        maximum,
        actual: actual
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(usize::MAX),
    })
}

fn element_text(node: Node<'_, '_>) -> Result<String, KeyStoreError> {
    let mut text = String::new();
    for child in node.children() {
        if child.is_element() {
            return Err(KeyStoreError::Invalid("unexpected nested element".into()));
        }
        if child.is_text() {
            text.push_str(child.text().unwrap_or_default());
        }
    }
    Ok(text)
}

fn decode_xml_base64(node: Node<'_, '_>) -> Result<Vec<u8>, KeyStoreError> {
    let encoded = element_text(node)?;
    let normalized = encoded
        .bytes()
        .filter(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        .collect::<Vec<_>>();
    base64::engine::general_purpose::STANDARD
        .decode(normalized)
        .map_err(|_| KeyStoreError::Invalid("invalid key base64".into()))
}

fn parse_xmlsec_dsa_key_value(node: Node<'_, '_>) -> Result<ParsedDsaKey, KeyStoreError> {
    let mut p = None;
    let mut q = None;
    let mut g = None;
    let mut y = None;
    let mut seed = None;
    let mut counter = None;
    let mut private_x = None;
    let mut previous_position = None;
    for child in node.children().filter(|child| child.is_element()) {
        let (position, slot) = if child.has_tag_name((XMLDSIG_NS, "P")) {
            (0, Some(&mut p))
        } else if child.has_tag_name((XMLDSIG_NS, "Q")) {
            (1, Some(&mut q))
        } else if child.has_tag_name((XMLDSIG_NS, "G")) {
            (2, Some(&mut g))
        } else if child.has_tag_name((XMLDSIG_NS, "Y")) {
            (4, Some(&mut y))
        } else if child.has_tag_name((XMLSEC_NS, "X")) {
            if private_x.is_some() {
                return Err(KeyStoreError::Invalid("duplicate DSA X".into()));
            }
            // XMLDSig 1.1 §4.5.2.1 has no private X field. libxmlsec's
            // keys.xml adds one before Y; only this store importer accepts it.
            // https://www.w3.org/TR/xmldsig-core1/#sec-DSAKeyValue
            private_x = Some(Zeroizing::new(decode_xml_base64(child)?));
            (3, None)
        } else if child.has_tag_name((XMLDSIG_NS, "J")) {
            (5, None)
        } else if child.has_tag_name((XMLDSIG_NS, "Seed")) {
            (6, Some(&mut seed))
        } else if child.has_tag_name((XMLDSIG_NS, "PgenCounter")) {
            (7, Some(&mut counter))
        } else {
            return Err(KeyStoreError::Invalid(
                "unsupported DSAKeyValue child".into(),
            ));
        };
        // XMLDSig 1.1 §4.5.2.1 defines a sequence, not an unordered set.
        if previous_position.is_some_and(|previous| position <= previous) {
            return Err(KeyStoreError::Invalid(
                "DSA parameters are out of order".into(),
            ));
        }
        previous_position = Some(position);
        if let Some(slot) = slot {
            if slot.replace(decode_xml_base64(child)?).is_some() {
                return Err(KeyStoreError::Invalid("duplicate DSA parameter".into()));
            }
        } else if position == 5 {
            let _ = decode_xml_base64(child)?;
        }
    }
    if p.is_some() != q.is_some() {
        return Err(KeyStoreError::Invalid(
            "DSA P and Q must occur together".into(),
        ));
    }
    if seed.is_some() != counter.is_some() {
        return Err(KeyStoreError::Invalid(
            "DSA Seed and PgenCounter must occur together".into(),
        ));
    }
    if [p.as_ref(), q.as_ref(), g.as_ref(), y.as_ref()]
        .into_iter()
        .flatten()
        .any(|component| component.len() > crate::hard_limits::DSA_KEY_COMPONENT_BYTE_CEILING)
        || private_x.as_ref().is_some_and(|component| {
            component.len() > crate::hard_limits::DSA_KEY_COMPONENT_BYTE_CEILING
        })
    {
        return Err(KeyStoreError::Invalid(
            "DSA component exceeds safety limit".into(),
        ));
    }
    let y = y.ok_or_else(|| KeyStoreError::Invalid("DSAKeyValue requires Y".into()))?;
    let private = if let Some(x) = private_x {
        let (Some(p), Some(q), Some(g)) = (&p, &q, &g) else {
            return Err(KeyStoreError::Invalid(
                "private DSA key requires P, Q, and G".into(),
            ));
        };
        let components = DsaComponents::from_components(
            BoxedUint::from_be_slice_vartime(p),
            BoxedUint::from_be_slice_vartime(q),
            BoxedUint::from_be_slice_vartime(g),
        )
        .map_err(|_| KeyStoreError::Invalid("invalid DSA parameters".into()))?;
        let x_value = BoxedUint::from_be_slice_vartime(&x);
        let monty = BoxedMontyParams::new(components.p().clone());
        let expected_y = BoxedMontyForm::new((**components.g()).clone(), &monty)
            .pow(&x_value)
            .retrieve();
        if expected_y != BoxedUint::from_be_slice_vartime(&y) {
            return Err(KeyStoreError::Invalid(
                "DSA private and public values differ".into(),
            ));
        }
        let public = DsaVerifyingKey::from_components(components, expected_y)
            .map_err(|_| KeyStoreError::Invalid("invalid DSA public key".into()))?;
        let private = NativeDsaSigningKey::from_components(public, x_value)
            .map_err(|_| KeyStoreError::Invalid("invalid DSA private key".into()))?;
        Some(Zeroizing::new(
            private
                .to_pkcs8_der()
                .map_err(|_| KeyStoreError::Invalid("DSA private key encoding failed".into()))?
                .as_bytes()
                .to_vec(),
        ))
    } else {
        None
    };
    Ok((KeyValueInfo::Dsa { p, q, g, y }, private))
}

#[cfg(test)]
mod tests {
    use rand_chacha::{ChaCha8Rng, rand_core::SeedableRng as _};
    use rsa::pkcs1::EncodeRsaPrivateKey as _;

    use super::*;

    fn xml_policy(resources: ResourcePolicy) -> crate::policy::VerificationPolicy {
        crate::policy::VerificationPolicy {
            resources,
            ..crate::policy::VerificationPolicy::default()
        }
    }

    #[test]
    fn imports_donor_pkcs12_and_rejects_wrong_password() {
        // A real upstream PHAOS bundle exercises MAC, password decoding, key
        // association, and certificate import rather than a synthetic ASN.1 stub.
        let bytes = include_bytes!("../tests/fixtures/xmlenc/01-phaos-xmlenc-3/rsa-priv-key.p12");
        let resources = ResourcePolicy::default();
        let mut inventory = KeyInventory::default();
        inventory
            .add_pkcs12("phaos".into(), bytes, "secret", &resources)
            .expect("donor PKCS#12 should import");
        assert_eq!(inventory.private_keys.len(), 1);
        assert!(!inventory.private_keys[0].certificate_chain.is_empty());
        assert!(inventory.private_keys[0].usages.allows(KeyUsage::Sign));

        let mut wrong = KeyInventory::default();
        assert!(matches!(
            wrong.add_pkcs12("phaos".into(), bytes, "wrong", &resources),
            Err(KeyStoreError::ProtectedContainer)
        ));
        assert!(wrong.private_keys.is_empty());

        let oversized = ResourcePolicy {
            max_external_resource_bytes: bytes.len() - 1,
            ..ResourcePolicy::default()
        };
        assert!(matches!(
            KeyInventory::default().add_pkcs12("phaos".into(), bytes, "secret", &oversized),
            Err(KeyStoreError::Policy(
                crate::policy::PolicyViolation::ResourceLimitExceeded {
                    resource: crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
                    maximum,
                }
            )) if maximum == bytes.len() - 1
        ));
    }

    #[test]
    fn pkcs12_kdf_limit_is_a_typed_policy_denial() {
        // A valid protected bundle that exceeds import work is not a bad password.
        let bytes = include_bytes!("../tests/fixtures/xmlenc/01-phaos-xmlenc-3/rsa-priv-key.p12");
        let resources = ResourcePolicy {
            max_key_import_kdf_work: 1,
            ..ResourcePolicy::default()
        };
        assert!(matches!(
            KeyInventory::default().add_pkcs12("phaos".into(), bytes, "secret", &resources),
            Err(KeyStoreError::Policy(
                crate::policy::PolicyViolation::KdfIterationsOutsideLimit { maximum: 1 }
            ))
        ));
        assert!(matches!(
            KeyInventory::default().add_pkcs12(
                "phaos".into(),
                bytes,
                "wrong",
                &ResourcePolicy::default(),
            ),
            Err(KeyStoreError::ProtectedContainer)
        ));
    }

    #[test]
    fn pkcs12_visible_encryption_kdf_is_checked_before_password() {
        // Raising an unencrypted PBES2 iteration count must deny the import
        // before asking for a secret, even when MacData is within the limit.
        let mut bytes =
            include_bytes!("../tests/fixtures/xmlenc/01-phaos-xmlenc-3/rsa-priv-key.p12").to_vec();
        let offset = bytes
            .windows(4)
            .position(|v| v == [2, 2, 8, 0])
            .expect("PBKDF2 iterations");
        bytes[offset + 3] = 1;
        let resources = ResourcePolicy {
            max_key_import_kdf_work: 2048,
            ..ResourcePolicy::default()
        };
        let result = KeyInventory::default().add_pkcs12_with_password_callback(
            "limited".into(),
            &bytes,
            || panic!("visible KDF must be checked first"),
            KeyUsages::SIGN,
            &resources,
        );
        assert!(matches!(result, Err(KeyStoreError::Policy(_))));
    }

    #[test]
    fn pkcs12_content_count_denial_is_not_a_password_error() {
        // AuthenticatedSafe has two content infos; its count is public and
        // must report the candidate policy rather than request a password.
        let bytes = include_bytes!("../tests/fixtures/xmlenc/01-phaos-xmlenc-3/rsa-priv-key.p12");
        let resources = ResourcePolicy {
            max_key_candidates: 1,
            ..ResourcePolicy::default()
        };
        let result = KeyInventory::default().add_pkcs12_with_password_callback(
            "limited".into(),
            bytes,
            || panic!("container limit must be checked first"),
            KeyUsages::SIGN,
            &resources,
        );
        assert!(matches!(
            result,
            Err(KeyStoreError::Policy(
                crate::policy::PolicyViolation::ResourceLimitExceeded {
                    resource: crate::policy::resource_name::KEY_CANDIDATES,
                    maximum: 1,
                }
            ))
        ));
    }

    #[test]
    fn pkcs12_aggregate_kdf_work_preserves_policy_error() {
        // Individual counts fit, but MAC plus PBES2 exceeds one shared budget.
        let resources = ResourcePolicy {
            max_key_import_kdf_work: 3000,
            ..ResourcePolicy::default()
        };
        let bytes = include_bytes!("../tests/fixtures/xmlenc/01-phaos-xmlenc-3/rsa-priv-key.p12");
        assert!(matches!(
            KeyInventory::default().add_pkcs12("limited".into(), bytes, "secret", &resources),
            Err(KeyStoreError::Policy(
                crate::policy::PolicyViolation::ResourceLimitExceeded {
                    resource: crate::policy::resource_name::KEY_IMPORT_KDF_WORK,
                    maximum: 3000,
                }
            ))
        ));
    }

    #[test]
    fn pkcs12_workspace_denial_preserves_policy_error() {
        // KDF workspace denial must not look like a wrong password.
        let resources = ResourcePolicy {
            max_key_import_kdf_memory_bytes: 1,
            ..ResourcePolicy::default()
        };
        let bytes = include_bytes!("../tests/fixtures/xmlenc/01-phaos-xmlenc-3/rsa-priv-key.p12");
        assert!(matches!(
            KeyInventory::default().add_pkcs12("limited".into(), bytes, "secret", &resources),
            Err(KeyStoreError::Policy(
                crate::policy::PolicyViolation::ResourceLimitExceeded {
                    resource: crate::policy::resource_name::KEY_IMPORT_KDF_MEMORY,
                    maximum: 1,
                }
            ))
        ));
    }

    #[test]
    fn pkcs12_temporary_memory_shares_existing_inventory_budget() {
        // Encoded input fits, but decrypted buffers and retained vector slots
        // must not receive a fresh aggregate allowance beside existing keys.
        let resources = ResourcePolicy {
            max_external_resource_bytes: 3000,
            max_external_resource_total_bytes: 5000,
            ..ResourcePolicy::default()
        };
        let mut inventory = KeyInventory::default();
        inventory
            .add_symmetric(
                "hmac".into(),
                SymmetricKeyKind::Hmac,
                vec![1; 2000],
                KeyUsages::SIGN,
                &resources,
            )
            .expect("existing key fits");
        let bytes = include_bytes!("../tests/fixtures/xmlenc/01-phaos-xmlenc-3/rsa-priv-key.p12");
        assert!(matches!(
            inventory.add_pkcs12("bundle".into(), bytes, "secret", &resources),
            Err(KeyStoreError::Policy(
                crate::policy::PolicyViolation::ResourceLimitExceeded {
                    resource: crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                    maximum: 5000
                }
            ))
        ));
        assert_eq!(inventory.symmetric_keys().len(), 1);
        assert!(inventory.private_keys().is_empty());
    }

    #[test]
    fn private_bundle_certificates_do_not_authorize_verification() {
        // A SIGN/DECRYPT-only PKCS#12 bundle must not implicitly make its
        // associated leaf available as a verification lookup candidate.
        let bytes = include_bytes!("../tests/fixtures/xmlenc/01-phaos-xmlenc-3/rsa-priv-key.p12");
        let resources = ResourcePolicy::default();
        let mut inventory = KeyInventory::default();
        inventory
            .add_pkcs12("private".into(), bytes, "secret", &resources)
            .expect("bundle imports");
        let leaf = inventory.private_keys()[0].certificate_chain[0].clone();
        let subject = crate::xmldsig::parse::parse_x509_certificate(&leaf)
            .expect("bundle leaf parses")
            .subject_dn;
        let key_info = KeyInfo {
            sources: vec![KeyInfoSource::X509Data(X509DataInfo {
                subject_names: vec![subject],
                ..X509DataInfo::default()
            })],
        };
        let resolver = inventory.verification_resolver();
        assert!(
            resolver
                .resolve(Some(&key_info), SignatureAlgorithm::RsaSha256)
                .expect("lookup completes")
                .is_none()
        );

        inventory
            .add_certificate_der(leaf, false, &resources)
            .expect("explicit lookup certificate imports");
        assert!(
            inventory
                .verification_resolver()
                .resolve(Some(&key_info), SignatureAlgorithm::RsaSha256)
                .expect("explicit lookup completes")
                .is_some()
        );
    }

    #[test]
    fn stored_signing_keys_obey_operation_material_limits() {
        // An import-time resource policy must not override stricter limits
        // selected for a later signing operation.
        let resources = ResourcePolicy::default();
        let mut inventory = KeyInventory::default();
        inventory
            .add_symmetric(
                "hmac".into(),
                SymmetricKeyKind::Hmac,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                KeyUsages::SIGN,
                &resources,
            )
            .expect("HMAC imports");
        inventory
            .add_private_pem(
                "rsa".into(),
                include_bytes!("../tests/fixtures/keys/rsa/rsa-2048-key.pem"),
                None,
                KeyUsages::SIGN,
                &resources,
            )
            .expect("RSA imports");

        for (name, algorithm, length) in [
            (
                "hmac",
                SignatureAlgorithm::HmacSha256,
                inventory.symmetric_keys[0].bytes.len(),
            ),
            (
                "rsa",
                SignatureAlgorithm::RsaSha256,
                inventory.private_keys[0].pkcs8_der.len(),
            ),
        ] {
            let mut policy = crate::policy::SigningPolicy::default();
            policy.resources.max_external_resource_bytes = length - 1;
            assert!(matches!(
                inventory.signing_key(name, algorithm, &policy),
                Err(KeyStoreError::Policy(
                    crate::policy::PolicyViolation::ResourceLimit {
                        resource: crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
                        maximum,
                        actual,
                    }
                )) if maximum == length - 1 && actual == length
            ));

            policy.resources.max_external_resource_bytes = length;
            policy.resources.max_external_resource_total_bytes = length - 1;
            assert!(matches!(
                inventory.signing_key(name, algorithm, &policy),
                Err(KeyStoreError::Policy(
                    crate::policy::PolicyViolation::ResourceLimit {
                        resource: crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                        maximum,
                        actual,
                    }
                )) if maximum == length - 1 && actual == length
            ));
        }
    }

    #[test]
    fn named_signing_lookup_obeys_active_candidate_budget() {
        // Import limits do not authorize a later operation to scan the full inventory.
        let resources = ResourcePolicy::default();
        let mut inventory = KeyInventory::default();
        for name in ["first", "second"] {
            inventory
                .add_symmetric(
                    name.into(),
                    SymmetricKeyKind::Hmac,
                    vec![0x42; 32],
                    KeyUsages::SIGN,
                    &resources,
                )
                .expect("HMAC imports");
        }
        let mut policy = crate::policy::SigningPolicy::default();
        policy.resources.max_key_candidates = 1;
        assert!(
            inventory
                .signing_key("first", SignatureAlgorithm::HmacSha256, &policy)
                .is_ok()
        );
        assert!(matches!(
            inventory.signing_key("second", SignatureAlgorithm::HmacSha256, &policy),
            Err(KeyStoreError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::KEY_CANDIDATES,
                    ..
                }
            ))
        ));
    }

    #[cfg(feature = "xmlenc")]
    #[test]
    fn named_decryption_lookup_shares_candidate_budget_across_key_kinds() {
        // Scanning a symmetric miss must consume the same operation budget as
        // the subsequent private-key lookup.
        let resources = ResourcePolicy::default();
        let mut inventory = KeyInventory::default();
        inventory
            .add_symmetric(
                "aes".into(),
                SymmetricKeyKind::Aes,
                vec![0x42; 32],
                KeyUsages::DECRYPT,
                &resources,
            )
            .expect("AES imports");
        inventory
            .add_private_pem(
                "rsa".into(),
                include_bytes!("../tests/fixtures/keys/rsa/rsa-2048-key.pem"),
                None,
                KeyUsages::DECRYPT,
                &resources,
            )
            .expect("RSA imports");
        let mut policy = crate::policy::DecryptionPolicy::default();
        policy.resources.max_key_candidates = 1;
        assert!(inventory.decryption_resolver("aes", &policy).is_ok());
        assert!(matches!(
            inventory.decryption_resolver("rsa", &policy),
            Err(KeyStoreError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::KEY_CANDIDATES,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn pkcs12_imports_share_candidate_budget() {
        // A key plus its retained certificate consumes two inventory slots.
        let bundle = include_bytes!("../tests/fixtures/xmlenc/01-phaos-xmlenc-3/rsa-priv-key.p12");
        let resources = ResourcePolicy {
            max_key_candidates: 3,
            ..ResourcePolicy::default()
        };
        let mut inventory = KeyInventory::default();
        inventory
            .add_pkcs12("first".into(), bundle, "secret", &resources)
            .expect("first bundle fits");
        assert_eq!(inventory.entry_count(), 2);
        assert!(
            inventory.private_keys()[0]
                .matching_certificate_chain()
                .is_some()
        );
        assert!(
            inventory
                .add_pkcs12("second".into(), bundle, "secret", &resources)
                .is_err()
        );
    }

    #[test]
    fn pkcs12_input_consumes_aggregate_import_budget() {
        // Repeated containers must charge encoded bytes, even when decoded material is small.
        let bundle = include_bytes!("../tests/fixtures/xmlenc/01-phaos-xmlenc-3/rsa-priv-key.p12");
        let resources = ResourcePolicy::default();
        let mut inventory = KeyInventory::default();
        inventory
            .add_pkcs12("first".into(), bundle, "secret", &resources)
            .expect("first bundle imports");
        assert!(inventory.material_bytes >= bundle.len());
        let limited = ResourcePolicy {
            max_external_resource_total_bytes: bundle.len() * 2 - 1,
            ..resources
        };
        assert!(
            inventory
                .add_pkcs12("second".into(), bundle, "secret", &limited)
                .is_err()
        );
    }

    #[test]
    fn pkcs12_unrelated_ca_does_not_block_private_key() {
        // Generated with OpenSSL from the tracked RSA key and unrelated CA;
        // the CA is lookup material, not a fabricated leaf certificate.
        let bundle = base64::engine::general_purpose::STANDARD
            .decode(
                include_str!("../tests/fixtures/keys/pkcs12/rsa-key-unrelated-ca.p12.b64").trim(),
            )
            .expect("fixture base64 decodes");
        let mut inventory = KeyInventory::default();
        inventory
            .add_pkcs12(
                "ca-only".into(),
                &bundle,
                "secret",
                &ResourcePolicy::default(),
            )
            .expect("unrelated CA must not invalidate the private key");
        assert_eq!(inventory.private_keys.len(), 1);
        assert_eq!(inventory.private_keys[0].certificate_chain.len(), 1);
        assert!(!inventory.private_keys[0].has_matching_leaf);
        assert!(
            inventory
                .signing_key(
                    "ca-only",
                    SignatureAlgorithm::RsaSha256,
                    &crate::policy::SigningPolicy::default(),
                )
                .is_ok()
        );
    }

    #[test]
    fn pkcs12_identical_leaf_bags_are_one_candidate() {
        // OpenSSL exported the same certificate as both the leaf and an extra
        // cert bag; the inventory retains one copy for the matching key.
        let bundle = base64::engine::general_purpose::STANDARD
            .decode(include_str!("../tests/fixtures/keys/pkcs12/rsa-duplicate-leaf.p12.b64").trim())
            .expect("fixture base64 decodes");
        let mut inventory = KeyInventory::default();
        inventory
            .add_pkcs12(
                "duplicate-leaf".into(),
                &bundle,
                "secret",
                &ResourcePolicy::default(),
            )
            .expect("identical leaf bags are not ambiguous");
        assert_eq!(inventory.private_keys[0].certificate_chain.len(), 1);
        assert!(inventory.private_keys[0].has_matching_leaf);
    }

    #[test]
    fn ec_pkcs12_import_is_sign_only() {
        // The convenience importer must not advertise RSA transport for EC.
        let bundle = base64::engine::general_purpose::STANDARD
            .decode(include_str!("../tests/fixtures/keys/pkcs12/ec-key.p12.b64").trim())
            .expect("fixture base64 decodes");
        let resources = ResourcePolicy::default();
        let mut inventory = KeyInventory::default();
        inventory
            .add_pkcs12("ec".into(), &bundle, "secret", &resources)
            .expect("EC signing bundle imports");
        assert!(inventory.private_keys()[0].usages.allows(KeyUsage::Sign));
        assert!(!inventory.private_keys()[0].usages.allows(KeyUsage::Decrypt));
        assert!(
            KeyInventory::default()
                .add_pkcs12_with_usages(
                    "ec".into(),
                    &bundle,
                    "secret",
                    KeyUsages::DECRYPT,
                    &resources,
                )
                .is_err()
        );
    }

    #[test]
    fn password_callback_runs_for_protected_container() {
        // Password delivery is caller-owned and failures must not leak the
        // callback's diagnostic or retry a plaintext decoder.
        let bundle = include_bytes!("../tests/fixtures/xmlenc/01-phaos-xmlenc-3/rsa-priv-key.p12");
        let mut inventory = KeyInventory::default();
        inventory
            .add_pkcs12_with_password_callback(
                "bundle".into(),
                bundle,
                || Some(Zeroizing::new("secret".to_owned())),
                KeyUsages::SIGN,
                &ResourcePolicy::default(),
            )
            .expect("callback password decrypts donor bundle");
        assert!(inventory.private_keys[0].usages.allows(KeyUsage::Sign));
        assert!(matches!(
            KeyInventory::default().add_pkcs12_with_password_callback(
                "bundle".into(),
                bundle,
                || None,
                KeyUsages::SIGN,
                &ResourcePolicy::default(),
            ),
            Err(KeyStoreError::ProtectedContainer)
        ));
        let limited = ResourcePolicy {
            max_external_resource_total_bytes: bundle.len() - 1,
            ..ResourcePolicy::default()
        };
        assert!(matches!(
            KeyInventory::default().add_pkcs12_with_password_callback(
                "bundle".into(),
                bundle,
                || panic!("budget must be checked before password delivery"),
                KeyUsages::SIGN,
                &limited,
            ),
            Err(KeyStoreError::Selection(_))
        ));
        let limited_kdf = ResourcePolicy {
            max_key_import_kdf_work: 1,
            ..ResourcePolicy::default()
        };
        assert!(matches!(
            KeyInventory::default().add_pkcs12_with_password_callback(
                "bundle".into(),
                bundle,
                || panic!("KDF denial must precede password delivery"),
                KeyUsages::SIGN,
                &limited_kdf,
            ),
            Err(KeyStoreError::Policy(
                crate::policy::PolicyViolation::KdfIterationsOutsideLimit { maximum: 1 }
            ))
        ));
        let oversized_bundle = ResourcePolicy {
            max_external_resource_bytes: bundle.len() - 1,
            ..ResourcePolicy::default()
        };
        assert!(matches!(
            KeyInventory::default().add_pkcs12_with_password_callback(
                "bundle".into(),
                bundle,
                || panic!("size denial must precede password delivery"),
                KeyUsages::SIGN,
                &oversized_bundle,
            ),
            Err(KeyStoreError::Policy(
                crate::policy::PolicyViolation::ResourceLimitExceeded {
                    resource: crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
                    maximum,
                }
            )) if maximum == bundle.len() - 1
        ));
    }

    #[test]
    fn pkcs12_callback_preflights_indefinite_outer_ber() {
        // The outer PFX may use BER indefinite length without changing MAC parameters.
        let bundle = include_bytes!("../tests/fixtures/xmlenc/01-phaos-xmlenc-3/rsa-priv-key.p12");
        assert_eq!(bundle[0], 0x30);
        let length_octets = usize::from(bundle[1] & 0x7f);
        assert!(bundle[1] & 0x80 != 0 && length_octets > 0);
        let mut ber = vec![0x30, 0x80];
        ber.extend_from_slice(&bundle[2 + length_octets..]);
        ber.extend_from_slice(&[0, 0]);
        let resources = ResourcePolicy {
            max_key_import_kdf_work: 1,
            ..ResourcePolicy::default()
        };
        assert!(matches!(
            KeyInventory::default().add_pkcs12_with_password_callback(
                "bundle".into(),
                &ber,
                || panic!("BER MAC KDF denial must precede password delivery"),
                KeyUsages::SIGN,
                &resources,
            ),
            Err(KeyStoreError::Policy(
                crate::policy::PolicyViolation::KdfIterationsOutsideLimit { maximum: 1 }
            ))
        ));
    }

    #[test]
    fn donor_xml_store_preserves_private_dsa_material() {
        // xmlsec's non-standard DSA X must be checked against Y, not silently
        // dropped while presenting the named key as usable for signing.
        let bytes = include_bytes!("../tests/fixtures/keys/xmlsec/mixed-keys.xml");
        let inventory = KeyInventory::from_xml_bytes(
            bytes,
            &xml_policy(ResourcePolicy::default()),
            XmlBackend::default(),
        )
        .expect("donor key store should parse");
        let dsa = inventory
            .private_keys
            .iter()
            .find(|entry| entry.name == "test-dsa")
            .expect("DSA private X should be imported");
        assert!(dsa.usages.allows(KeyUsage::Sign));
        assert!(!dsa.usages.allows(KeyUsage::Decrypt));
        assert!(DsaSigningKey::from_pkcs8_der(&dsa.pkcs8_der).is_ok());
        let dsa_public = inventory
            .public_keys()
            .iter()
            .find(|entry| entry.name == "test-dsa")
            .expect("DSA public entry is retained");
        assert_eq!(dsa_public.usages, KeyUsages::VERIFY);
    }

    #[test]
    fn xml_store_charges_retained_decoded_material() {
        // DSA retains public components and a derived private PKCS#8 buffer.
        let source = include_str!("../tests/fixtures/keys/xmlsec/mixed-keys.xml");
        let marker = source.find("<KeyName>test-dsa</KeyName>").expect("DSA key");
        let start = source[..marker].rfind("<KeyInfo").expect("DSA KeyInfo");
        let end =
            marker + source[marker..].find("</KeyInfo>").expect("DSA end") + "</KeyInfo>".len();
        let xml = format!(
            "<Keys xmlns=\"{XMLSEC_NS}\">{}</Keys>",
            source[start..end].replace('\n', "")
        );
        let inventory = KeyInventory::from_xml_bytes(
            xml.as_bytes(),
            &xml_policy(ResourcePolicy::default()),
            XmlBackend::default(),
        )
        .expect("compact DSA store imports");
        let retained = inventory.retained_material_bytes().expect("bounded tally");
        assert_eq!(inventory.material_bytes, xml.len().max(retained));
        assert!(retained >= inventory.private_keys[0].pkcs8_der.len());
    }

    #[test]
    fn xml_store_rejects_empty_symmetric_material() {
        // Empty decoded secrets are invalid at the same boundary as direct imports.
        for kind in ["HMACKeyValue", "AESKeyValue", "DESKeyValue"] {
            let xml = format!(
                "<Keys xmlns=\"{XMLSEC_NS}\"><KeyInfo xmlns=\"{XMLDSIG_NS}\"><KeyName>empty</KeyName><KeyValue><{kind} xmlns=\"{XMLSEC_NS}\"/></KeyValue></KeyInfo></Keys>"
            );
            assert!(
                KeyInventory::from_xml_bytes(
                    xml.as_bytes(),
                    &xml_policy(ResourcePolicy::default()),
                    XmlBackend::default(),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn aes_imports_require_supported_key_widths() {
        // Both direct and XML key stores must reject widths unusable by AES-CBC/GCM.
        let resources = ResourcePolicy::default();
        for length in [1, 15, 17, 23, 25, 31, 33] {
            let mut inventory = KeyInventory::default();
            assert!(
                inventory
                    .add_symmetric(
                        "aes".into(),
                        SymmetricKeyKind::Aes,
                        vec![0; length],
                        KeyUsages::ENCRYPT,
                        &resources,
                    )
                    .is_err()
            );
            let xml = format!(
                "<Keys xmlns=\"{XMLSEC_NS}\"><KeyInfo xmlns=\"{XMLDSIG_NS}\"><KeyName>aes</KeyName><KeyValue><AESKeyValue xmlns=\"{XMLSEC_NS}\">{}</AESKeyValue></KeyValue></KeyInfo></Keys>",
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, vec![0; length])
            );
            assert!(
                KeyInventory::from_xml_bytes(
                    xml.as_bytes(),
                    &xml_policy(resources.clone()),
                    XmlBackend::default(),
                )
                .is_err()
            );
        }
        for length in [16, 24, 32] {
            let mut inventory = KeyInventory::default();
            inventory
                .add_symmetric(
                    "aes".into(),
                    SymmetricKeyKind::Aes,
                    vec![0; length],
                    KeyUsages::ENCRYPT,
                    &resources,
                )
                .expect("AES-128/192/256 key imports");
        }
    }

    #[test]
    fn unsupported_des_material_is_not_authorized() {
        // A parsed legacy DES value must not advertise an operation that the
        // encryption pipeline cannot execute.
        let resources = ResourcePolicy::default();
        let mut inventory = KeyInventory::default();
        assert!(
            inventory
                .add_symmetric(
                    "des".into(),
                    SymmetricKeyKind::Des,
                    vec![0x42; 8],
                    KeyUsages::ENCRYPT,
                    &resources,
                )
                .is_err()
        );
        let xml = format!(
            "<Keys xmlns=\"{XMLSEC_NS}\"><KeyInfo xmlns=\"{XMLDSIG_NS}\"><KeyName>des</KeyName><KeyValue><DESKeyValue xmlns=\"{XMLSEC_NS}\">QkJCQkJCQkI=</DESKeyValue></KeyValue></KeyInfo></Keys>"
        );
        assert!(
            KeyInventory::from_xml_bytes(
                xml.as_bytes(),
                &xml_policy(resources.clone()),
                XmlBackend::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn xml_store_accepts_xmlsig11_ec_key_value() {
        // XMLDSig 1.1 ECKeyValue must be recognized as public material.
        let pem = pem::parse(include_bytes!(
            "../tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem"
        ))
        .expect("EC public PEM decodes");
        let (_, spki) = x509_parser::x509::SubjectPublicKeyInfo::from_der(pem.contents())
            .expect("EC SPKI parses");
        let point =
            base64::engine::general_purpose::STANDARD.encode(spki.subject_public_key.data.as_ref());
        let xml = format!(
            "<Keys xmlns=\"{XMLSEC_NS}\"><KeyInfo xmlns=\"{XMLDSIG_NS}\"><KeyName>ec</KeyName><KeyValue><ECKeyValue xmlns=\"{XMLDSIG11_NS}\"><NamedCurve URI=\"urn:oid:1.2.840.10045.3.1.7\"/><PublicKey>{point}</PublicKey></ECKeyValue></KeyValue></KeyInfo></Keys>"
        );
        let store = KeyInventory::from_xml_bytes(
            xml.as_bytes(),
            &xml_policy(ResourcePolicy::default()),
            XmlBackend::default(),
        )
        .expect("ECKeyValue namespace is supported");
        assert_eq!(store.public_keys().len(), 1);
        assert_eq!(store.public_keys()[0].usages, KeyUsages::VERIFY);
        assert!(
            store.public_keys()[0]
                .key_info
                .sources
                .iter()
                .any(|source| matches!(source, KeyInfoSource::KeyValue(KeyValueInfo::Ec { .. })))
        );
    }

    #[test]
    fn xml_store_rejects_unusable_public_key_values() {
        // Malformed supported public-key material must fail at import, not at verification.
        let cases = [
            "<RSAKeyValue><Modulus></Modulus><Exponent>AQAB</Exponent></RSAKeyValue>",
            "<ECKeyValue xmlns=\"http://www.w3.org/2009/xmldsig11#\"><NamedCurve URI=\"urn:oid:1.2.840.10045.3.1.7\"/><PublicKey>AQ==</PublicKey></ECKeyValue>",
        ];
        for key in cases {
            let xml = format!(
                "<Keys xmlns=\"{XMLSEC_NS}\"><KeyInfo xmlns=\"{XMLDSIG_NS}\"><KeyName>invalid</KeyName><KeyValue>{key}</KeyValue></KeyInfo></Keys>"
            );
            assert!(
                KeyInventory::from_xml_bytes(
                    xml.as_bytes(),
                    &xml_policy(ResourcePolicy::default()),
                    XmlBackend::default(),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn xml_store_enforces_all_parser_resource_limits() {
        // Import must not skip the depth, namespace or cumulative work limits.
        let xml = format!(
            "<Keys xmlns=\"{XMLSEC_NS}\" xmlns:a=\"urn:a\" xmlns:b=\"urn:b\"><KeyInfo xmlns=\"{XMLDSIG_NS}\"><KeyName>key</KeyName><KeyValue><HMACKeyValue xmlns=\"{XMLSEC_NS}\">c2VjcmV0</HMACKeyValue></KeyValue></KeyInfo></Keys>"
        );
        for resources in [
            ResourcePolicy {
                max_xml_depth: 2,
                ..ResourcePolicy::default()
            },
            ResourcePolicy {
                max_xml_namespace_bindings: 1,
                ..ResourcePolicy::default()
            },
            ResourcePolicy {
                max_xml_parse_work_bytes: 1,
                ..ResourcePolicy::default()
            },
        ] {
            assert!(
                KeyInventory::from_xml_bytes(
                    xml.as_bytes(),
                    &xml_policy(resources),
                    XmlBackend::default()
                )
                .is_err(),
                "parser limit must apply to key stores"
            );
        }
    }

    #[test]
    fn xml_store_bounds_source_before_utf16_decode() {
        // The source-byte ceiling must be checked before UTF-16 expansion or parsing.
        let xml = format!("<Keys xmlns=\"{XMLSEC_NS}\"/>");
        let mut bytes = vec![0xff, 0xfe];
        for unit in xml.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let resources = ResourcePolicy {
            max_xml_document_bytes: xml.len() + 1,
            ..ResourcePolicy::default()
        };
        assert!(bytes.len() > resources.max_xml_document_bytes);
        assert!(
            KeyInventory::from_xml_bytes(&bytes, &xml_policy(resources), XmlBackend::default())
                .is_err()
        );
    }

    #[test]
    fn xml_store_uses_operation_xml_policy() {
        // Internal DTD permission must come from the operation snapshot, not
        // an importer-local default that rejects a caller-authorized store.
        let xml = format!(
            "<!DOCTYPE Keys [<!ENTITY key 'named'>]><Keys xmlns=\"{XMLSEC_NS}\"><KeyInfo xmlns=\"{XMLDSIG_NS}\"><KeyName>&key;</KeyName><KeyValue><HMACKeyValue xmlns=\"{XMLSEC_NS}\">c2VjcmV0</HMACKeyValue></KeyValue></KeyInfo></Keys>"
        );
        let denied = crate::policy::VerificationPolicy::default();
        assert!(
            KeyInventory::from_xml_bytes(xml.as_bytes(), &denied, XmlBackend::default()).is_err()
        );
        let mut allowed = denied;
        allowed.xml.allow_internal_dtd = true;
        assert!(
            KeyInventory::from_xml_bytes(xml.as_bytes(), &allowed, XmlBackend::default()).is_ok()
        );
    }

    #[test]
    fn ec_public_key_cannot_authorize_encryption() {
        // EC material can verify signatures but cannot serve as an RSA recipient.
        let resources = ResourcePolicy::default();
        let ec = include_bytes!("../tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem");
        let cert = include_bytes!("../tests/fixtures/keys/ec/ec-prime256v1-cert.pem");
        let mut store = KeyInventory::default();
        store
            .add_public_pem("ec".into(), ec, &resources)
            .expect("EC public key imports");
        assert_eq!(store.public_keys()[0].usages, KeyUsages::VERIFY);
        assert!(
            store
                .add_public_pem_with_usages("ec-encrypt".into(), ec, KeyUsages::ENCRYPT, &resources)
                .is_err()
        );
        let cert_der = pem::parse(cert)
            .expect("EC certificate PEM decodes")
            .into_contents();
        store
            .add_public_der("ec-cert".into(), cert_der.clone(), &resources)
            .expect("EC certificate imports");
        assert_eq!(store.public_keys()[1].usages, KeyUsages::VERIFY);
        assert!(
            store
                .add_public_der_with_usages(
                    "ec-cert-encrypt".into(),
                    cert_der,
                    KeyUsages::ENCRYPT,
                    &resources
                )
                .is_err()
        );
    }

    #[test]
    fn xml_store_rejects_policy_above_absolute_ceiling() {
        // Public imports cannot bypass hard ceilings with an unvalidated policy.
        let resources = ResourcePolicy {
            max_xml_nodes: crate::hard_limits::XML_DOCUMENT_NODE_CEILING as usize + 1,
            ..ResourcePolicy::default()
        };
        let xml = format!("<Keys xmlns=\"{XMLSEC_NS}\"/>");
        assert!(
            KeyInventory::from_xml_bytes(
                xml.as_bytes(),
                &xml_policy(resources.clone()),
                XmlBackend::default(),
            )
            .is_err()
        );
        assert!(
            KeyInventory::default()
                .add_symmetric(
                    "key".into(),
                    SymmetricKeyKind::Hmac,
                    b"secret".to_vec(),
                    KeyUsages::SIGN,
                    &resources,
                )
                .is_err()
        );
    }

    #[test]
    fn ec_private_key_cannot_advertise_rsa_decryption() {
        // Only RSA private material can satisfy the inventory's decrypt API.
        let pem = include_bytes!("../tests/fixtures/keys/ec/ec-prime256v1-key.pem");
        assert!(
            KeyInventory::default()
                .add_private_pem(
                    "ec".into(),
                    pem,
                    None,
                    KeyUsages::DECRYPT,
                    &ResourcePolicy::default(),
                )
                .is_err()
        );
    }

    #[test]
    fn imports_rsa_pkcs1_pem_and_resolves_named_spki() {
        // Traditional RSA import and named public lookup share one inventory,
        // while the resolver still applies the operation's verification policy.
        let private_pem = include_str!("../tests/fixtures/keys/rsa/rsa-2048-key.pem");
        let rsa = RsaPrivateKey::from_pkcs8_pem(private_pem).expect("RSA fixture parses");
        let pkcs1 = rsa.to_pkcs1_der().expect("RSA fixture encodes as PKCS#1");
        let public = rsa
            .to_public_key()
            .to_public_key_der()
            .expect("RSA fixture has SPKI");
        let resources = ResourcePolicy::default();
        let mut inventory = KeyInventory::default();
        inventory
            .add_private_der(
                "key".into(),
                pkcs1.as_bytes(),
                None,
                KeyUsages::SIGN.union(KeyUsages::DECRYPT),
                &resources,
            )
            .expect("PKCS#1 private key imports");
        inventory
            .add_public_der("verify-key".into(), public.as_bytes().to_vec(), &resources)
            .expect("public SPKI imports");
        assert!(inventory.private_keys[0].usages.allows(KeyUsage::Sign));
        let mut info = KeyInfo::default();
        info.sources
            .push(KeyInfoSource::KeyName("verify-key".into()));
        let resolver = inventory.verification_resolver();
        let resolved = resolver
            .resolve(Some(&info), SignatureAlgorithm::RsaSha256)
            .expect("named public key resolves");
        assert!(resolved.is_some());
    }

    #[test]
    fn rejects_unknown_pem_text_and_duplicate_names() {
        // PEM is a single armor block; unrelated trailing data must not be
        // silently skipped by the general-purpose PEM parser.
        let public = include_bytes!("../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
        let mut inventory = KeyInventory::default();
        let resources = ResourcePolicy::default();
        inventory
            .add_public_pem("first".into(), public, &resources)
            .expect("public PEM imports");
        assert!(matches!(
            inventory.add_public_pem("first".into(), public, &resources),
            Err(KeyStoreError::Selection("duplicate key name"))
        ));
        let mut trailing = public.to_vec();
        trailing.extend_from_slice(b"\nnot a key");
        assert!(
            inventory
                .add_public_pem("other".into(), &trailing, &resources)
                .is_err()
        );
    }

    #[test]
    fn rsa_spki_import_rejects_even_public_exponent() {
        // ASN.1 shape alone must not grant verify/encrypt usages to an unusable RSA key.
        let mut der = single_pem_block(
            include_bytes!("../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"),
            ResourcePolicy::default().max_external_resource_bytes,
        )
        .expect("public key fixture")
        .into_contents();
        let exponent = der
            .windows(5)
            .position(|bytes| bytes == [0x02, 0x03, 0x01, 0x00, 0x01])
            .expect("RSA exponent in SPKI");
        der[exponent + 4] = 0;
        assert!(
            KeyInventory::default()
                .add_public_der("invalid".into(), der, &ResourcePolicy::default())
                .is_err()
        );
    }

    #[test]
    fn rsa_public_pkcs1_pem_is_bounded_before_bigint_decode() {
        // The borrowed ASN.1 modulus is checked before RSA allocates integers.
        let modulus = vec![1_u8; crate::hard_limits::RSA_MODULUS_BIT_CEILING.div_ceil(8) + 1];
        let exponent = [1_u8, 0, 1];
        let public = rsa::pkcs1::RsaPublicKey {
            modulus: der::asn1::UintRef::new(&modulus).expect("valid modulus"),
            public_exponent: der::asn1::UintRef::new(&exponent).expect("valid exponent"),
        };
        let pem = pem::encode(&pem::Pem::new(
            "RSA PUBLIC KEY",
            der::Encode::to_der(&public).expect("encodable RSA public key"),
        ));
        assert!(matches!(
            KeyInventory::default().add_public_pem(
                "oversized".into(),
                pem.as_bytes(),
                &ResourcePolicy::default(),
            ),
            Err(KeyStoreError::Selection(
                "RSA public key exceeds safety limit"
            ))
        ));
    }

    #[test]
    fn direct_inventory_names_consume_resource_budget() {
        // Caller-owned names must not bypass per-resource or retained aggregate bounds.
        let resources = ResourcePolicy {
            max_external_resource_bytes: 64,
            max_external_resource_total_bytes: 100,
            ..ResourcePolicy::default()
        };
        let mut inventory = KeyInventory::default();
        assert!(
            inventory
                .add_symmetric(
                    "x".repeat(65),
                    SymmetricKeyKind::Hmac,
                    vec![7; 32],
                    KeyUsages::SIGN,
                    &resources,
                )
                .is_err()
        );
        inventory
            .add_symmetric(
                "a".repeat(40),
                SymmetricKeyKind::Hmac,
                vec![7; 32],
                KeyUsages::SIGN,
                &resources,
            )
            .expect("first named key fits");
        assert!(
            inventory
                .add_symmetric(
                    "b".repeat(40),
                    SymmetricKeyKind::Hmac,
                    vec![8; 32],
                    KeyUsages::SIGN,
                    &resources,
                )
                .is_err()
        );
    }

    #[test]
    fn encrypted_pkcs8_requires_correct_password_without_plaintext_fallback() {
        // Wrong passwords must not retry another format or leave a partial
        // registration in the caller-owned inventory.
        let private_pem = include_str!("../tests/fixtures/keys/rsa/rsa-2048-key.pem");
        let rsa = RsaPrivateKey::from_pkcs8_pem(private_pem).expect("RSA fixture parses");
        let plain = rsa.to_pkcs8_der().expect("RSA fixture encodes as PKCS#8");
        let mut rng = ChaCha8Rng::seed_from_u64(0xA11C_E501);
        let encrypted = PrivateKeyInfoRef::try_from(plain.as_bytes())
            .expect("PKCS#8 reference parses")
            .encrypt_with_rng(&mut rng, b"correct")
            .expect("PKCS#8 fixture encrypts");
        let resources = ResourcePolicy::default();
        let mut inventory = KeyInventory::default();
        let restricted = ResourcePolicy {
            max_key_import_kdf_work: 1,
            ..ResourcePolicy::default()
        };
        assert!(matches!(
            inventory.add_private_der(
                "restricted".into(),
                encrypted.as_bytes(),
                Some(b"correct"),
                KeyUsages::SIGN,
                &restricted,
            ),
            Err(KeyStoreError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::KEY_IMPORT_KDF_WORK,
                    maximum: 1,
                    ..
                }
            ))
        ));
        let callback_calls = std::cell::Cell::new(0);
        assert!(matches!(
            inventory.add_private_der_with_password_callback(
                "restricted-callback".into(),
                encrypted.as_bytes(),
                || {
                    callback_calls.set(callback_calls.get() + 1);
                    Some(Zeroizing::new(b"correct".to_vec()))
                },
                KeyUsages::SIGN,
                &restricted,
            ),
            Err(KeyStoreError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::KEY_IMPORT_KDF_WORK,
                    maximum: 1,
                    ..
                }
            ))
        ));
        assert_eq!(callback_calls.get(), 0);
        assert!(matches!(
            inventory.add_private_der(
                "protected".into(),
                encrypted.as_bytes(),
                Some(b"wrong"),
                KeyUsages::SIGN,
                &resources,
            ),
            Err(KeyStoreError::ProtectedContainer)
        ));
        assert!(inventory.private_keys.is_empty());
        inventory
            .add_private_der(
                "protected".into(),
                encrypted.as_bytes(),
                Some(b"correct"),
                KeyUsages::SIGN,
                &resources,
            )
            .expect("correct password imports encrypted PKCS#8");
        assert_eq!(inventory.private_keys.len(), 1);
        assert!(inventory.material_bytes >= encrypted.as_bytes().len());
        let mut callback_inventory = KeyInventory::default();
        callback_inventory
            .add_private_der_with_password_callback(
                "callback".into(),
                encrypted.as_bytes(),
                || Some(Zeroizing::new(b"correct".to_vec())),
                KeyUsages::SIGN,
                &resources,
            )
            .expect("callback decrypts encrypted PKCS#8");
        callback_inventory
            .add_private_der_with_password_callback(
                "plain".into(),
                plain.as_bytes(),
                || panic!("plaintext PKCS#8 must not request a password"),
                KeyUsages::SIGN,
                &resources,
            )
            .expect("plaintext import ignores password callback");
    }

    #[test]
    fn scrypt_parallel_buffers_are_checked_before_derivation() {
        // N*r fits a tiny limit, but p independent B/V/T workspaces do not.
        let mut resources = ResourcePolicy {
            max_key_import_kdf_work: 10_000,
            max_key_import_kdf_memory_bytes: 4_096,
            ..ResourcePolicy::default()
        };
        assert!(matches!(
            enforce_scrypt_kdf_limits(2, 1, 1_000, &resources),
            Err(KeyStoreError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::KEY_IMPORT_KDF_MEMORY,
                    maximum: 4_096,
                    actual: 512_000,
                }
            ))
        ));
        resources.max_key_import_kdf_memory_bytes = 512_000;
        assert!(enforce_scrypt_kdf_limits(2, 1, 1_000, &resources).is_ok());
    }

    #[test]
    fn named_hmac_resolution_enforces_usage_and_method() {
        // A named secret may verify only when both its usage and the XMLDSig
        // method permit HMAC; the resolver must not fall back to another key.
        let resources = ResourcePolicy::default();
        let mut inventory = KeyInventory::default();
        inventory
            .add_symmetric(
                "verify".into(),
                SymmetricKeyKind::Hmac,
                b"sufficiently-long-hmac-secret".to_vec(),
                KeyUsages::VERIFY,
                &resources,
            )
            .expect("verification HMAC imports");
        inventory
            .add_symmetric(
                "sign-only".into(),
                SymmetricKeyKind::Hmac,
                b"another-hmac-secret".to_vec(),
                KeyUsages::SIGN,
                &resources,
            )
            .expect("sign-only HMAC imports");
        let resolver = inventory.verification_resolver();
        let named = |name: &str| KeyInfo {
            sources: vec![KeyInfoSource::KeyName(name.into())],
            ..KeyInfo::default()
        };
        assert!(
            resolver
                .resolve(Some(&named("verify")), SignatureAlgorithm::HmacSha256)
                .expect("named HMAC resolves")
                .is_some()
        );
        assert!(
            resolver
                .resolve(Some(&named("verify")), SignatureAlgorithm::RsaSha256)
                .is_err()
        );
        assert!(
            resolver
                .resolve(Some(&named("sign-only")), SignatureAlgorithm::HmacSha256)
                .is_err()
        );
    }

    #[test]
    fn named_hmac_resolution_rejects_invalid_policy_snapshot() {
        // Early HMAC resolution must validate the entire snapshot even when
        // the selected key is small and otherwise permitted.
        let mut inventory = KeyInventory::default();
        inventory
            .add_symmetric(
                "verify".into(),
                SymmetricKeyKind::Hmac,
                b"sufficiently-long-hmac-secret".to_vec(),
                KeyUsages::VERIFY,
                &ResourcePolicy::default(),
            )
            .expect("verification HMAC imports");
        let info = KeyInfo {
            sources: vec![KeyInfoSource::KeyName("verify".into())],
            ..KeyInfo::default()
        };
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.resources.max_external_resource_bytes = usize::MAX;
        assert!(matches!(
            inventory.verification_resolver().resolve_with_policy(
                Some(&info),
                SignatureAlgorithm::HmacSha256,
                &policy
            ),
            Err(DsigError::Policy(_))
        ));
    }

    #[test]
    fn named_hmac_resolution_uses_active_resource_limits() {
        // A store imported under a broad policy must not bypass a later,
        // stricter verification snapshot when resolving a named secret.
        let resources = ResourcePolicy::default();
        let secret = b"sufficiently-long-hmac-secret";
        let mut inventory = KeyInventory::default();
        inventory
            .add_symmetric(
                "verify".into(),
                SymmetricKeyKind::Hmac,
                secret.to_vec(),
                KeyUsages::VERIFY,
                &resources,
            )
            .expect("verification HMAC imports");
        let key_info = KeyInfo {
            sources: vec![KeyInfoSource::KeyName("verify".into())],
            ..KeyInfo::default()
        };
        let resolver = inventory.verification_resolver();
        for (resource, aggregate) in [
            (crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES, false),
            (
                crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                true,
            ),
        ] {
            let mut policy = crate::policy::VerificationPolicy::default();
            if aggregate {
                policy.resources.max_external_resource_total_bytes = secret.len() - 1;
            } else {
                policy.resources.max_external_resource_bytes = secret.len() - 1;
            }
            let error = resolver
                .resolve_with_policy(Some(&key_info), SignatureAlgorithm::HmacSha256, &policy)
                .err()
                .expect("active limit must reject stored HMAC material");
            assert!(
                matches!(
                    error,
                    DsigError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                        resource: actual,
                        maximum,
                        actual: size,
                    }) if actual == resource && maximum == secret.len() - 1 && size == secret.len()
                ),
                "{error:?}"
            );
        }
    }

    #[test]
    fn one_named_verification_entry_fits_one_candidate() {
        // A name and the single entry it selects are one lookup, not two.
        let mut inventory = KeyInventory::default();
        let mut policy = crate::policy::VerificationPolicy::default();
        inventory
            .add_symmetric(
                "only".into(),
                SymmetricKeyKind::Hmac,
                b"sufficiently-long-hmac-secret".to_vec(),
                KeyUsages::VERIFY,
                &policy.resources,
            )
            .expect("HMAC imports");
        policy.resources.max_key_candidates = 1;
        let info = KeyInfo {
            sources: vec![KeyInfoSource::KeyName("only".into())],
        };
        assert!(
            inventory
                .verification_resolver()
                .resolve_with_policy(Some(&info), SignatureAlgorithm::HmacSha256, &policy)
                .expect("one lookup fits")
                .is_some()
        );
    }

    #[test]
    fn pem_imports_charge_encoded_input_to_aggregate_budget() {
        // Repeated padded PEM inputs must consume the aggregate work budget
        // even when their decoded DER keys are much smaller.
        let public = include_str!("../tests/fixtures/keys/rsa/rsa-4096-pubkey.pem");
        let private = include_str!("../tests/fixtures/keys/rsa/rsa-4096-key.pem");
        for (pem, is_private) in [(public, false), (private, true)] {
            let padded = format!("{pem}{}", " ".repeat(16 * 1024));
            let resources = ResourcePolicy {
                max_external_resource_bytes: padded.len(),
                max_external_resource_total_bytes: padded.len()
                    + if is_private { 5 } else { 10 }
                    + 1,
                ..ResourcePolicy::default()
            };
            let mut inventory = KeyInventory::default();
            let import = |inventory: &mut KeyInventory, name: &str| {
                if is_private {
                    inventory.add_private_pem(
                        name.into(),
                        padded.as_bytes(),
                        None,
                        KeyUsages::SIGN,
                        &resources,
                    )
                } else {
                    inventory.add_public_pem(name.into(), padded.as_bytes(), &resources)
                }
            };
            import(&mut inventory, "first").expect("first PEM import fits");
            assert!(
                matches!(
                    import(&mut inventory, "second"),
                    Err(KeyStoreError::Selection(
                        "key material total exceeds resource limit"
                    ))
                ),
                "second PEM input must exceed aggregate budget"
            );
        }
    }

    #[test]
    fn repeated_key_name_selects_one_inventory_entry() {
        // XMLDSig 1.1 section 4.5 permits repeated KeyInfo choices; duplicate
        // references to one entry are not two distinct verification keys.
        let resources = ResourcePolicy::default();
        let mut inventory = KeyInventory::default();
        inventory
            .add_symmetric(
                "secret".into(),
                SymmetricKeyKind::Hmac,
                b"sufficiently-long-hmac-secret".to_vec(),
                KeyUsages::VERIFY,
                &resources,
            )
            .expect("HMAC key imports");
        inventory
            .add_symmetric(
                "other-secret".into(),
                SymmetricKeyKind::Hmac,
                b"another-long-hmac-secret".to_vec(),
                KeyUsages::VERIFY,
                &resources,
            )
            .expect("second HMAC key imports");
        inventory
            .add_public_pem(
                "public".into(),
                include_bytes!("../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"),
                &resources,
            )
            .expect("public key imports");
        let resolver = inventory.verification_resolver();
        for (name, algorithm) in [
            ("secret", SignatureAlgorithm::HmacSha256),
            ("public", SignatureAlgorithm::RsaSha256),
        ] {
            let info = KeyInfo {
                sources: vec![
                    KeyInfoSource::KeyName(name.into()),
                    KeyInfoSource::KeyName(name.into()),
                ],
            };
            assert!(resolver.resolve(Some(&info), algorithm).is_ok(), "{name}");
        }
        let distinct = KeyInfo {
            sources: vec![
                KeyInfoSource::KeyName("secret".into()),
                KeyInfoSource::KeyName("other-secret".into()),
            ],
        };
        assert!(
            resolver
                .resolve(Some(&distinct), SignatureAlgorithm::HmacSha256)
                .is_err()
        );
    }

    #[test]
    fn named_lookup_charges_inspected_inventory_entries() {
        // A late KeyName must not bypass a stricter operation candidate limit.
        let mut inventory = KeyInventory::default();
        let resources = ResourcePolicy::default();
        for name in ["first", "second"] {
            inventory
                .add_symmetric(
                    name.into(),
                    SymmetricKeyKind::Hmac,
                    b"sufficiently-long-hmac-secret".to_vec(),
                    KeyUsages::VERIFY,
                    &resources,
                )
                .expect("key imports");
        }
        let key_info = KeyInfo {
            sources: vec![KeyInfoSource::KeyName("second".into())],
            ..KeyInfo::default()
        };
        let policy = crate::policy::VerificationPolicy {
            resources: ResourcePolicy {
                max_key_candidates: 1,
                ..ResourcePolicy::default()
            },
            ..crate::policy::VerificationPolicy::default()
        };
        let resolver = inventory.verification_resolver();
        assert!(
            resolver
                .resolve_with_policy_and_provider(
                    Some(&key_info),
                    SignatureAlgorithm::HmacSha256,
                    &policy,
                    crate::provider::default_provider(),
                )
                .is_err()
        );
    }

    #[test]
    fn private_import_rejects_public_only_usage() {
        // Usage is part of the inventory contract: nonsensical permissions
        // must not survive import and later be interpreted by a resolver.
        let private = include_bytes!("../tests/fixtures/keys/rsa/rsa-2048-key.pem");
        let mut inventory = KeyInventory::default();
        assert!(
            inventory
                .add_private_pem(
                    "wrong-use".into(),
                    private,
                    None,
                    KeyUsages::SIGN.union(KeyUsages::VERIFY),
                    &ResourcePolicy::default(),
                )
                .is_err()
        );
        assert!(inventory.private_keys.is_empty());
    }

    #[test]
    fn normalized_private_key_must_fit_resource_limit() {
        // PKCS#8 wrapping may cross the per-resource ceiling even when PKCS#1 fits.
        let rsa = RsaPrivateKey::from_pkcs8_pem(include_str!(
            "../tests/fixtures/keys/rsa/rsa-2048-key.pem"
        ))
        .expect("RSA fixture parses");
        let pkcs1 = rsa.to_pkcs1_der().expect("PKCS#1 encodes");
        let pkcs8 = rsa.to_pkcs8_der().expect("PKCS#8 encodes");
        assert!(pkcs8.as_bytes().len() > pkcs1.as_bytes().len());
        let resources = ResourcePolicy {
            max_external_resource_bytes: pkcs1.as_bytes().len(),
            ..ResourcePolicy::default()
        };
        let mut inventory = KeyInventory::default();
        assert!(
            inventory
                .add_private_der(
                    "rsa".into(),
                    pkcs1.as_bytes(),
                    None,
                    KeyUsages::SIGN,
                    &resources,
                )
                .is_err()
        );
        assert!(inventory.private_keys.is_empty());
    }

    #[test]
    fn oversized_rsa_components_are_rejected_before_private_key_decode() {
        // PKCS#8 wraps PKCS#1 integers; every component must be checked
        // before RustCrypto allocates big integers or validates CRT arithmetic.
        let pem = include_bytes!("../tests/fixtures/keys/rsa/rsa-2048-key.pem");
        let block = single_pem_block(pem, ResourcePolicy::default().max_external_resource_bytes)
            .expect("fixture PEM");
        let info = PrivateKeyInfoRef::try_from(block.contents()).expect("fixture PKCS#8");
        let original = rsa::pkcs1::RsaPrivateKey::from_der(info.private_key.as_bytes())
            .expect("fixture PKCS#1");
        let oversized_modulus = vec![1_u8; 1025];
        let oversized = rsa::pkcs1::RsaPrivateKey {
            modulus: der::asn1::UintRef::new(&oversized_modulus).expect("positive modulus"),
            public_exponent: original.public_exponent,
            private_exponent: original.private_exponent,
            prime1: original.prime1,
            prime2: original.prime2,
            exponent1: original.exponent1,
            exponent2: original.exponent2,
            coefficient: original.coefficient,
            other_prime_infos: None,
        };
        let pkcs1 = der::Encode::to_der(&oversized).expect("PKCS#1 encodes");
        let octets = der::asn1::OctetStringRef::new(&pkcs1).expect("PKCS#8 octets");
        let pkcs8 = der::Encode::to_der(&PrivateKeyInfoRef::new(rsa::pkcs1::ALGORITHM_ID, octets))
            .expect("PKCS#8 encodes");
        let mut inventory = KeyInventory::default();
        let error = inventory
            .add_private_der(
                "oversized".into(),
                &pkcs8,
                None,
                KeyUsages::SIGN,
                &ResourcePolicy::default(),
            )
            .expect_err("oversized RSA modulus must fail at preflight");
        assert!(error.to_string().contains("safety limit"), "{error}");

        let oversized_exponent = vec![1_u8; 1025];
        let oversized = rsa::pkcs1::RsaPrivateKey {
            modulus: original.modulus,
            public_exponent: original.public_exponent,
            private_exponent: der::asn1::UintRef::new(&oversized_exponent)
                .expect("positive exponent"),
            prime1: original.prime1,
            prime2: original.prime2,
            exponent1: original.exponent1,
            exponent2: original.exponent2,
            coefficient: original.coefficient,
            other_prime_infos: None,
        };
        let pkcs1 = der::Encode::to_der(&oversized).expect("PKCS#1 encodes");
        let error = preflight_rsa_pkcs1_components(&pkcs1)
            .expect_err("oversized private exponent must fail before bigint decoding");
        assert!(error.to_string().contains("safety limit"), "{error}");
    }

    #[test]
    fn named_certificate_import_is_not_a_trust_anchor() {
        // A certificate is usable as a named public-key source but importing
        // it must never grant certificate-chain trust implicitly.
        let pem = include_bytes!("../tests/fixtures/keys/rsa/rsa-4096-cert.pem");
        let certificate =
            single_pem_block(pem, ResourcePolicy::default().max_external_resource_bytes)
                .expect("certificate fixture is one PEM block");
        let mut inventory = KeyInventory::default();
        inventory
            .add_public_der(
                "recipient-cert".into(),
                certificate.contents().to_vec(),
                &ResourcePolicy::default(),
            )
            .expect("named X.509 certificate imports");
        assert!(
            inventory
                .rsa_encryption_key(
                    "recipient-cert",
                    &crate::policy::EncryptionPolicy::default()
                )
                .is_ok()
        );
        let restricted = crate::policy::EncryptionPolicy {
            resources: ResourcePolicy {
                max_external_resource_bytes: 64,
                max_external_resource_total_bytes: 64,
                ..ResourcePolicy::default()
            },
            ..crate::policy::EncryptionPolicy::default()
        };
        assert!(
            inventory
                .rsa_encryption_key("recipient-cert", &restricted)
                .is_err()
        );
        assert!(inventory.trusted_certificates.is_empty());
    }

    #[test]
    fn unsupported_spki_is_rejected_at_import() {
        // A syntactically valid Ed25519 SPKI must not acquire VERIFY usage.
        let mut ed25519_spki = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        ed25519_spki.extend_from_slice(&[1; 32]);
        let mut inventory = KeyInventory::default();
        assert!(
            inventory
                .add_public_der(
                    "unsupported".into(),
                    ed25519_spki,
                    &ResourcePolicy::default()
                )
                .is_err()
        );
        assert!(inventory.public_keys.is_empty());
    }

    #[test]
    fn named_certificate_resolution_preserves_document_crl() {
        // Named inventory selection must preserve document revocation evidence;
        // without it the same chain is valid and resolves successfully.
        use rcgen::{CertificateParams, KeyPair, KeyUsagePurpose, SerialNumber};
        let mut root_params = CertificateParams::new(Vec::new()).expect("root params");
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let root = rcgen::CertifiedIssuer::self_signed(
            root_params,
            KeyPair::generate().expect("root key"),
        )
        .expect("root certificate");
        let mut leaf_params = CertificateParams::new(Vec::new()).expect("leaf params");
        leaf_params.serial_number = Some(SerialNumber::from(42_u64));
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let leaf = leaf_params
            .signed_by(&KeyPair::generate().expect("leaf key"), &root)
            .expect("leaf certificate");
        let now = time::OffsetDateTime::now_utc();
        let crl = rcgen::CertificateRevocationListParams {
            this_update: now - time::Duration::days(1),
            next_update: now + time::Duration::days(1),
            crl_number: SerialNumber::from(1_u64),
            issuing_distribution_point: None,
            revoked_certs: vec![rcgen::RevokedCertParams {
                serial_number: SerialNumber::from(42_u64),
                revocation_time: now - time::Duration::hours(1),
                reason_code: None,
                invalidity_date: None,
            }],
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        }
        .signed_by(&root)
        .expect("signed CRL");
        let resources = ResourcePolicy::default();
        let mut inventory = KeyInventory::default();
        inventory
            .add_public_der("leaf".into(), leaf.der().to_vec(), &resources)
            .expect("leaf imports");
        inventory
            .add_certificate_der(root.der().to_vec(), true, &resources)
            .expect("root imports");
        let policy = crate::policy::VerificationPolicy {
            key_trust: crate::policy::KeyTrustPolicy {
                verify_x509_chains: true,
                check_crls: true,
                verification_time: Some(std::time::SystemTime::now()),
                ..crate::policy::KeyTrustPolicy::default()
            },
            ..crate::policy::VerificationPolicy::default()
        };
        let mut info = KeyInfo {
            sources: vec![KeyInfoSource::KeyName("leaf".into())],
        };
        let resolver = inventory.verification_resolver();
        assert!(
            resolver
                .resolve_with_policy_and_provider(
                    Some(&info),
                    SignatureAlgorithm::EcdsaSha256,
                    &policy,
                    crate::provider::default_provider()
                )
                .expect("unrevoked chain resolves")
                .is_some()
        );
        info.sources.push(KeyInfoSource::X509Data(X509DataInfo {
            crls: vec![crl.der().to_vec()],
            ..X509DataInfo::default()
        }));
        let error = resolver
            .resolve_with_policy_and_provider(
                Some(&info),
                SignatureAlgorithm::EcdsaSha256,
                &policy,
                crate::provider::default_provider(),
            )
            .err()
            .expect("document CRL revokes leaf");
        assert!(
            error
                .to_string()
                .contains("certificate at chain position 0 is revoked"),
            "{error}"
        );
        let mut bounded = policy.clone();
        bounded.resources.max_external_resource_total_bytes =
            leaf.der().len() + root.der().len() + crl.der().len() - 1;
        assert!(matches!(
            resolver.resolve_with_policy_and_provider(
                Some(&info),
                SignatureAlgorithm::EcdsaSha256,
                &bounded,
                crate::provider::default_provider()
            ),
            Err(DsigError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                    ..
                }
            ))
        ));
        bounded.key_trust.check_crls = false;
        assert!(
            resolver
                .resolve_with_policy_and_provider(
                    Some(&info),
                    SignatureAlgorithm::EcdsaSha256,
                    &bounded,
                    crate::provider::default_provider()
                )
                .expect("disabled CRL checks do not load CRLs")
                .is_some()
        );
    }

    #[test]
    fn named_certificate_resolution_enforces_inventory_crl() {
        // A KeyName must not drop caller-supplied revocation evidence.
        fn cert(pem: &[u8]) -> Vec<u8> {
            let text = std::str::from_utf8(pem).expect("fixture is UTF-8");
            let start = text.find("-----BEGIN ").expect("fixture has PEM armor");
            single_pem_block(
                &text.as_bytes()[start..],
                ResourcePolicy::default().max_external_resource_bytes,
            )
            .expect("certificate PEM parses")
            .into_contents()
        }
        let resources = ResourcePolicy::default();
        let mut inventory = KeyInventory::default();
        inventory
            .add_public_der(
                "leaf".into(),
                cert(include_bytes!(
                    "../tests/fixtures/keys/rsa/rsa-2048-cert.pem"
                )),
                &resources,
            )
            .expect("leaf imports");
        for anchor in [
            include_bytes!("../tests/fixtures/keys/ca2cert.pem").as_slice(),
            include_bytes!("../tests/fixtures/keys/cacert.pem").as_slice(),
        ] {
            inventory
                .add_certificate_der(cert(anchor), true, &resources)
                .expect("anchor imports");
        }
        inventory
            .add_crl_der(
                cert(include_bytes!(
                    "../tests/fixtures/keys/rsa/rsa-2048-cert-revoked-crl.pem"
                )),
                &resources,
            )
            .expect("CRL imports");
        let policy = crate::policy::VerificationPolicy {
            key_trust: crate::policy::KeyTrustPolicy {
                verify_x509_chains: true,
                check_crls: true,
                max_x509_chain_depth: 3,
                verification_time: Some(
                    std::time::SystemTime::UNIX_EPOCH
                        + std::time::Duration::from_secs(1_773_964_800),
                ),
                ..crate::policy::KeyTrustPolicy::default()
            },
            ..crate::policy::VerificationPolicy::default()
        };
        let key_info = KeyInfo {
            sources: vec![KeyInfoSource::KeyName("leaf".into())],
            ..KeyInfo::default()
        };
        let error = inventory
            .verification_resolver()
            .resolve_with_policy_and_provider(
                Some(&key_info),
                SignatureAlgorithm::RsaSha256,
                &policy,
                crate::provider::default_provider(),
            )
            .err()
            .expect("revocation evidence must reject this chain");
        assert!(error.to_string().contains("cRLSign"), "{error}");
    }

    #[test]
    fn hmac_resolution_does_not_load_unrelated_certificate_material() {
        // The active snapshot bounds selected material, not unrelated X.509
        // bytes that an HMAC resolver never needs to copy or inspect.
        let mut inventory = KeyInventory::default();
        inventory
            .add_symmetric(
                "hmac".into(),
                SymmetricKeyKind::Hmac,
                b"secret".to_vec(),
                KeyUsages::VERIFY,
                &ResourcePolicy::default(),
            )
            .expect("HMAC imports");
        let pem = include_bytes!("../tests/fixtures/keys/rsa/rsa-2048-cert.pem");
        let certificate =
            single_pem_block(pem, ResourcePolicy::default().max_external_resource_bytes)
                .expect("certificate fixture");
        inventory
            .add_certificate_der(
                certificate.contents().to_vec(),
                true,
                &ResourcePolicy::default(),
            )
            .expect("anchor imports");
        let policy = crate::policy::VerificationPolicy {
            resources: ResourcePolicy {
                max_external_resource_bytes: 64,
                max_external_resource_total_bytes: 64,
                ..ResourcePolicy::default()
            },
            ..crate::policy::VerificationPolicy::default()
        };
        let info = KeyInfo {
            sources: vec![KeyInfoSource::KeyName("hmac".into())],
            ..KeyInfo::default()
        };
        assert!(
            inventory
                .verification_resolver()
                .resolve_with_policy_and_provider(
                    Some(&info),
                    SignatureAlgorithm::HmacSha256,
                    &policy,
                    crate::provider::default_provider(),
                )
                .expect("unrelated certificates cannot consume HMAC budget")
                .is_some()
        );
    }

    #[test]
    fn named_key_resolution_obeys_source_policy() {
        // Inventory lookup is not permission to use a KeyName source that the
        // operation's immutable verification policy has disabled.
        let resources = ResourcePolicy::default();
        let mut inventory = KeyInventory::default();
        inventory
            .add_symmetric(
                "blocked-name".into(),
                SymmetricKeyKind::Hmac,
                b"policy-guarded-hmac-secret".to_vec(),
                KeyUsages::VERIFY,
                &resources,
            )
            .expect("HMAC fixture imports");
        let info = KeyInfo {
            sources: vec![KeyInfoSource::KeyName("blocked-name".into())],
            ..KeyInfo::default()
        };
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.key_sources.key_name = false;
        assert!(
            inventory
                .verification_resolver()
                .resolve_with_policy_and_provider(
                    Some(&info),
                    SignatureAlgorithm::HmacSha256,
                    &policy,
                    crate::provider::default_provider(),
                )
                .is_err()
        );
    }

    #[test]
    fn named_lookup_and_fallback_share_one_candidate_budget() {
        // Finding a named inventory entry and resolving its embedded KeyValue
        // are one verification operation, not two independently budgeted scans.
        let mut inventory = KeyInventory::default();
        inventory.public_keys.push(StoredPublicKey {
            name: "named".into(),
            key_info: KeyInfo {
                sources: vec![
                    KeyInfoSource::KeyName("named".into()),
                    KeyInfoSource::KeyValue(KeyValueInfo::Rsa {
                        modulus: vec![3],
                        exponent: vec![3],
                    }),
                ],
            },
            usages: KeyUsages::VERIFY,
        });
        let info = KeyInfo {
            sources: vec![KeyInfoSource::KeyName("named".into())],
        };
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.resources.max_key_candidates = 1;
        let error = inventory
            .verification_resolver()
            .resolve_with_policy_and_provider(
                Some(&info),
                SignatureAlgorithm::RsaSha256,
                &policy,
                crate::provider::default_provider(),
            )
            .err()
            .expect("delegation must not reset the candidate budget");
        assert!(matches!(
            error,
            DsigError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::KEY_CANDIDATES,
                maximum: 1,
                actual: 2,
            })
        ));
    }

    #[test]
    fn prefix_retry_spends_the_same_candidate_budget() {
        // Unresolved sources preceding X.509 lookup are visited twice, so both
        // passes must charge the same operation budget.
        let mut sources = vec![KeyInfoSource::KeyName("missing".into()); 3];
        sources.push(KeyInfoSource::X509Data(X509DataInfo {
            subject_names: vec!["missing subject".into()],
            ..X509DataInfo::default()
        }));
        let info = KeyInfo { sources };
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.resources.max_key_candidates = 5;
        let error = KeyInventory::default()
            .verification_resolver()
            .resolve_with_policy_and_provider(
                Some(&info),
                SignatureAlgorithm::RsaSha256,
                &policy,
                crate::provider::default_provider(),
            )
            .err()
            .expect("the repeated prefix must exhaust the candidate limit");
        assert!(matches!(
            error,
            DsigError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::KEY_CANDIDATES,
                maximum: 5,
                actual: 6,
            })
        ));
    }

    #[test]
    fn selected_key_value_is_one_resource() {
        // Representation must not split one key into separately bounded
        // components; exact boundaries remain accepted for all KeyValue kinds.
        for value in [
            KeyValueInfo::Rsa {
                modulus: vec![1; 256],
                exponent: vec![1; 3],
            },
            KeyValueInfo::Dsa {
                p: Some(vec![1; 64]),
                q: Some(vec![1; 16]),
                g: Some(vec![1; 64]),
                y: vec![1; 64],
            },
            KeyValueInfo::Ec {
                curve_oid: "1.2.840.10045.3.1.7".into(),
                public_key: vec![1; 65],
            },
        ] {
            let info = KeyInfo {
                sources: vec![KeyInfoSource::KeyValue(value)],
            };
            let size =
                check_selected_public_material(&info, &ResourcePolicy::default()).expect("size");
            let resources = ResourcePolicy {
                max_external_resource_bytes: size,
                ..ResourcePolicy::default()
            };
            assert_eq!(
                check_selected_public_material(&info, &resources).expect("exact limit"),
                size
            );
            let resources = ResourcePolicy {
                max_external_resource_bytes: size - 1,
                ..resources
            };
            assert!(matches!(check_selected_public_material(&info, &resources),
                Err(DsigError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES, actual, ..
                })) if actual == size));
        }
    }

    #[test]
    fn named_verification_bounds_complete_key_value() {
        // A broadly imported XML key must obey the tighter operation snapshot
        // before the resolver constructs an SPKI from its components.
        use rsa::{pkcs8::DecodePublicKey as _, traits::PublicKeyParts as _};
        let public = RsaPublicKey::from_public_key_pem(include_str!(
            "../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"
        ))
        .expect("RSA fixture");
        let modulus = public.n().to_be_bytes_trimmed_vartime();
        let exponent = public.e().to_be_bytes_trimmed_vartime();
        let size = modulus.len() + exponent.len();
        let base64 = base64::engine::general_purpose::STANDARD;
        let xml = format!(
            "<Keys xmlns=\"{XMLSEC_NS}\"><KeyInfo xmlns=\"{XMLDSIG_NS}\"><KeyName>named</KeyName><KeyValue><RSAKeyValue><Modulus>{}</Modulus><Exponent>{}</Exponent></RSAKeyValue></KeyValue></KeyInfo></Keys>",
            base64.encode(modulus),
            base64.encode(exponent)
        );
        let inventory = KeyInventory::from_xml_bytes(
            xml.as_bytes(),
            &xml_policy(ResourcePolicy::default()),
            XmlBackend::default(),
        )
        .expect("broad import");
        let info = KeyInfo {
            sources: vec![KeyInfoSource::KeyName("named".into())],
        };
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.resources.max_external_resource_bytes = size;
        assert!(
            inventory
                .verification_resolver()
                .resolve_with_policy_and_provider(
                    Some(&info),
                    SignatureAlgorithm::RsaSha256,
                    &policy,
                    crate::provider::default_provider()
                )
                .expect("exact complete-key limit")
                .is_some()
        );
        policy.resources.max_external_resource_bytes = size - 1;
        assert!(
            matches!(inventory.verification_resolver().resolve_with_policy_and_provider(Some(&info), SignatureAlgorithm::RsaSha256,
            &policy, crate::provider::default_provider()),
            Err(DsigError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES, actual, ..
            })) if actual == size)
        );
    }

    #[test]
    fn selected_certificate_and_anchors_share_aggregate_budget() {
        // Selected named material and configured trust material are one
        // operation, even though they enter the resolver through separate paths.
        let certificate = single_pem_block(
            include_bytes!("../tests/fixtures/keys/rsa/rsa-2048-cert.pem"),
            ResourcePolicy::default().max_external_resource_bytes,
        )
        .expect("leaf PEM")
        .into_contents();
        let anchor = single_pem_block(
            include_bytes!("../tests/fixtures/keys/rsa/rsa-4096-cert.pem"),
            ResourcePolicy::default().max_external_resource_bytes,
        )
        .expect("anchor PEM")
        .into_contents();
        let mut inventory = KeyInventory::default();
        inventory
            .add_public_der(
                "leaf".into(),
                certificate.clone(),
                &ResourcePolicy::default(),
            )
            .expect("leaf imports");
        inventory
            .add_certificate_der(anchor.clone(), true, &ResourcePolicy::default())
            .expect("anchor imports");
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.key_trust.verify_x509_chains = true;
        policy.resources.max_external_resource_total_bytes = certificate.len() + anchor.len() - 1;
        let info = KeyInfo {
            sources: vec![KeyInfoSource::KeyName("leaf".into())],
        };
        let error = inventory
            .verification_resolver()
            .resolve_with_policy_and_provider(
                Some(&info),
                SignatureAlgorithm::RsaSha256,
                &policy,
                crate::provider::default_provider(),
            )
            .err()
            .expect("combined selected and configured material exceeds the budget");
        assert!(matches!(
            error,
            DsigError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                ..
            })
        ));
    }

    #[test]
    fn named_key_does_not_bypass_other_source_permissions() {
        // Every source in a document KeyInfo is subject to the policy, even
        // when the inventory can resolve its KeyName without the other source.
        let resources = ResourcePolicy::default();
        let mut inventory = KeyInventory::default();
        inventory
            .add_symmetric(
                "named".into(),
                SymmetricKeyKind::Hmac,
                b"verification-secret".to_vec(),
                KeyUsages::VERIFY,
                &resources,
            )
            .expect("HMAC fixture imports");
        let info = KeyInfo {
            sources: vec![
                KeyInfoSource::KeyName("named".into()),
                KeyInfoSource::KeyValue(KeyValueInfo::Rsa {
                    modulus: vec![3],
                    exponent: vec![3],
                }),
            ],
            ..KeyInfo::default()
        };
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.key_sources.key_value = false;
        assert!(
            inventory
                .verification_resolver()
                .resolve_with_policy_and_provider(
                    Some(&info),
                    SignatureAlgorithm::HmacSha256,
                    &policy,
                    crate::provider::default_provider(),
                )
                .is_err()
        );
    }

    #[test]
    fn named_public_key_is_trusted_inventory_material() {
        // A document KeyName must not inherit the source restrictions of the
        // caller-owned public key's internal representation.
        let mut inventory = KeyInventory::default();
        inventory
            .add_public_pem(
                "named".into(),
                include_bytes!("../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"),
                &ResourcePolicy::default(),
            )
            .expect("public key imports");
        let info = KeyInfo {
            sources: vec![KeyInfoSource::KeyName("named".into())],
            ..KeyInfo::default()
        };
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.key_sources.key_value = false;
        policy.key_sources.der_encoded_key_value = false;
        policy.key_sources.x509_data = false;
        assert!(
            inventory
                .verification_resolver()
                .resolve_with_policy_and_provider(
                    Some(&info),
                    SignatureAlgorithm::RsaSha256,
                    &policy,
                    crate::provider::default_provider(),
                )
                .expect("trusted inventory material resolves")
                .is_some()
        );
    }

    #[test]
    fn named_public_key_obeys_current_verification_limits() {
        // A permissive import policy cannot replace a later stricter operation snapshot.
        let mut inventory = KeyInventory::default();
        inventory
            .add_public_pem(
                "named".into(),
                include_bytes!("../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"),
                &ResourcePolicy::default(),
            )
            .expect("public key imports");
        let info = KeyInfo {
            sources: vec![KeyInfoSource::KeyName("named".into())],
        };
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.resources.max_external_resource_bytes = 1;
        assert!(
            inventory
                .verification_resolver()
                .resolve_with_policy(Some(&info), SignatureAlgorithm::RsaSha256, &policy)
                .is_err()
        );
        let certificate = pem::parse(include_bytes!(
            "../tests/fixtures/keys/rsa/rsa-2048-cert.pem"
        ))
        .expect("certificate PEM")
        .into_contents();
        let mut certificate_inventory = KeyInventory::default();
        certificate_inventory
            .add_public_der("named".into(), certificate, &ResourcePolicy::default())
            .expect("certificate imports as a named public key");
        assert!(
            certificate_inventory
                .verification_resolver()
                .resolve_with_policy(Some(&info), SignatureAlgorithm::RsaSha256, &policy)
                .is_err()
        );
    }

    #[test]
    fn unused_certificates_do_not_block_earlier_public_keys() {
        // X.509 lookup bytes are irrelevant when a preceding DER key resolves.
        let mut inventory = KeyInventory::default();
        let certificate = pem::parse(include_bytes!(
            "../tests/fixtures/keys/rsa/rsa-2048-cert.pem"
        ))
        .expect("certificate PEM")
        .into_contents();
        inventory
            .add_certificate_der(certificate, false, &ResourcePolicy::default())
            .expect("certificate imports");
        let public = pem::parse(include_bytes!(
            "../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"
        ))
        .expect("public PEM")
        .into_contents();
        let info = KeyInfo {
            sources: vec![
                KeyInfoSource::DerEncodedKeyValue(public.clone()),
                KeyInfoSource::X509Data(X509DataInfo {
                    subject_names: vec!["unused".into()],
                    ..X509DataInfo::default()
                }),
            ],
        };
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.resources.max_external_resource_bytes = public.len();
        assert!(
            inventory
                .verification_resolver()
                .resolve_with_policy(Some(&info), SignatureAlgorithm::RsaSha256, &policy)
                .expect("earlier public key resolves")
                .is_some()
        );
    }

    #[test]
    fn public_import_rejects_incompatible_usage() {
        // Public material may verify or encrypt, but cannot authorize signing.
        let resources = ResourcePolicy::default();
        let public = include_bytes!("../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
        let mut inventory = KeyInventory::default();
        assert!(
            inventory
                .add_public_pem_with_usages("invalid".into(), public, KeyUsages::SIGN, &resources,)
                .is_err()
        );
        assert_eq!(inventory.entry_count(), 0);
    }

    #[test]
    fn public_certificate_import_rejects_unsupported_key_family() {
        // A syntactically valid certificate cannot advertise verification when
        // none of the supported XMLDSig verifiers can consume its public key.
        let pair =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("Ed25519 key generation");
        let params = rcgen::CertificateParams::new(vec!["example.test".into()])
            .expect("certificate parameters");
        let certificate = params.self_signed(&pair).expect("certificate generation");
        assert!(
            KeyInventory::default()
                .add_public_der(
                    "unsupported".into(),
                    certificate.der().to_vec(),
                    &ResourcePolicy::default()
                )
                .is_err()
        );
    }

    #[cfg(feature = "xmlenc")]
    #[test]
    fn imported_usage_restricts_operation_selection() {
        // Explicit restrictions survive import and are enforced when selecting
        // material for the opposite operation.
        let resources = ResourcePolicy::default();
        let public = include_bytes!("../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
        let bundle = include_bytes!("../tests/fixtures/xmlenc/01-phaos-xmlenc-3/rsa-priv-key.p12");
        let mut inventory = KeyInventory::default();
        inventory
            .add_public_pem_with_usages("verify".into(), public, KeyUsages::VERIFY, &resources)
            .expect("verification-only public key imports");
        assert!(
            inventory
                .rsa_encryption_key("verify", &crate::policy::EncryptionPolicy::default())
                .is_err()
        );
        inventory
            .add_pkcs12_with_usages(
                "decrypt".into(),
                bundle,
                "secret",
                KeyUsages::DECRYPT,
                &resources,
            )
            .expect("decryption-only private key imports");
        assert!(
            inventory
                .signing_key(
                    "decrypt",
                    SignatureAlgorithm::RsaSha256,
                    &crate::policy::SigningPolicy::default(),
                )
                .is_err()
        );
        assert!(
            inventory
                .decryption_resolver("decrypt", &crate::policy::DecryptionPolicy::default())
                .is_ok()
        );
    }

    #[cfg(feature = "xmlenc")]
    #[test]
    fn selected_rsa_recipient_obeys_operation_modulus_policy() {
        // Import permission does not override a stricter encryption snapshot.
        let mut inventory = KeyInventory::default();
        inventory
            .add_public_pem(
                "rsa".into(),
                include_bytes!("../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"),
                &ResourcePolicy::default(),
            )
            .expect("RSA fixture imports");
        let mut policy = crate::policy::EncryptionPolicy::default();
        policy.rsa_keys.minimum_modulus_bits = 4096;
        assert!(matches!(
            inventory.rsa_encryption_key("rsa", &policy),
            Err(KeyStoreError::Policy(
                crate::policy::PolicyViolation::KeySize { .. }
            ))
        ));
        assert!(matches!(
            inventory.public_keys()[0].rsa_encryption_key(&policy),
            Err(KeyStoreError::Policy(
                crate::policy::PolicyViolation::KeySize { .. }
            ))
        ));
    }

    #[test]
    fn inventory_merge_checks_names_and_budget_atomically() {
        // Combining independently parsed stores cannot bypass name or
        // aggregate-material limits, and a rejected merge is atomic.
        let resources = ResourcePolicy::default();
        let mut first = KeyInventory::default();
        first
            .add_symmetric(
                "one".into(),
                SymmetricKeyKind::Hmac,
                b"first-secret".to_vec(),
                KeyUsages::SIGN,
                &resources,
            )
            .expect("first key imports");
        let mut duplicate = KeyInventory::default();
        duplicate
            .add_symmetric(
                "one".into(),
                SymmetricKeyKind::Hmac,
                b"second-secret".to_vec(),
                KeyUsages::VERIFY,
                &resources,
            )
            .expect("independent duplicate imports");
        assert!(matches!(
            first.extend(duplicate, &resources),
            Err(KeyStoreError::Selection("duplicate key name"))
        ));
        assert_eq!(first.entry_count(), 1);
        let mut second = KeyInventory::default();
        second
            .add_symmetric(
                "two".into(),
                SymmetricKeyKind::Hmac,
                b"second-secret".to_vec(),
                KeyUsages::VERIFY,
                &resources,
            )
            .expect("second key imports");
        let constrained = ResourcePolicy {
            max_external_resource_total_bytes: b"first-secret".len(),
            ..ResourcePolicy::default()
        };
        assert!(matches!(
            first.extend(second, &constrained),
            Err(KeyStoreError::Selection(
                "key material total exceeds resource limit"
            ))
        ));
        assert_eq!(first.entry_count(), 1);
    }

    #[test]
    fn public_dsa_store_entries_require_usable_parameters() {
        // The inventory has no implicit parameter inheritance. Do not grant
        // VERIFY to material that its own resolver cannot construct as a key.
        for fields in [
            "<Y>AQ==</Y>",
            "<P/><Q/><G/><Y>AQ==</Y>",
            "<P>AQ==</P><Q>AQ==</Q><G>AQ==</G><Y>AQ==</Y>",
        ] {
            let xml = format!(
                "<Keys xmlns=\"{XMLSEC_NS}\"><KeyInfo xmlns=\"{XMLDSIG_NS}\"><KeyName>dsa</KeyName><KeyValue><DSAKeyValue>{fields}</DSAKeyValue></KeyValue></KeyInfo></Keys>"
            );
            assert!(
                KeyInventory::from_xml_bytes(
                    xml.as_bytes(),
                    &xml_policy(ResourcePolicy::default()),
                    XmlBackend::default()
                )
                .is_err(),
                "accepted unusable DSA: {fields}"
            );
        }
    }

    #[test]
    fn oversized_private_dsa_component_stops_before_big_integer_work() {
        // A bounded XML file can still contain an outsized exponent; reject
        // it before constructing a large modular exponentiation.
        let oversized = base64::engine::general_purpose::STANDARD.encode(vec![1_u8; 513]);
        let xml = format!(
            "<Keys xmlns=\"{XMLSEC_NS}\"><KeyInfo xmlns=\"{XMLDSIG_NS}\"><KeyName>dsa</KeyName><KeyValue><DSAKeyValue><P>{oversized}</P><Q>AQ==</Q><G>AQ==</G><X xmlns=\"{XMLSEC_NS}\">AQ==</X><Y>AQ==</Y></DSAKeyValue></KeyValue></KeyInfo></Keys>"
        );
        assert!(matches!(
            KeyInventory::from_xml_bytes(
                xml.as_bytes(),
                &xml_policy(ResourcePolicy::default()),
                XmlBackend::default(),
            ),
            Err(KeyStoreError::Invalid(message)) if message.contains("safety limit")
        ));
    }

    #[test]
    fn oversized_pkcs8_dsa_parameters_stop_before_key_derivation() {
        // PKCS#8 uses the same component ceiling as xmlsec's DSAKeyValue.
        #[derive(der::Sequence)]
        struct DsaParameters<'a> {
            p: der::asn1::UintRef<'a>,
            q: der::asn1::UintRef<'a>,
            g: der::asn1::UintRef<'a>,
        }
        let oversized = vec![1_u8; crate::hard_limits::DSA_KEY_COMPONENT_BYTE_CEILING + 1];
        let one = [1_u8];
        let parameters = der::Encode::to_der(&DsaParameters {
            p: der::asn1::UintRef::new(&oversized).expect("positive P"),
            q: der::asn1::UintRef::new(&one).expect("positive Q"),
            g: der::asn1::UintRef::new(&one).expect("positive G"),
        })
        .expect("DSA parameters encode");
        let x = der::Encode::to_der(&der::asn1::UintRef::new(&one).expect("positive X"))
            .expect("DSA X encodes");
        let algorithm = rsa::pkcs8::AlgorithmIdentifierRef {
            oid: dsa::OID,
            parameters: Some(der::asn1::AnyRef::from_der(&parameters).expect("parameters")),
        };
        let private = der::asn1::OctetStringRef::new(&x).expect("private octets");
        let pkcs8 = der::Encode::to_der(&PrivateKeyInfoRef::new(algorithm, private))
            .expect("PKCS#8 encodes");
        let mut inventory = KeyInventory::default();
        let error = inventory
            .add_private_der(
                "oversized-dsa".into(),
                &pkcs8,
                None,
                KeyUsages::SIGN,
                &ResourcePolicy::default(),
            )
            .expect_err("oversized DSA parameter must fail preflight");
        assert!(error.to_string().contains("safety limit"), "{error}");
    }

    #[test]
    fn compressed_ec_spki_cannot_acquire_verify_usage() {
        // Import must enforce the same SEC1 profile as signature verification,
        // for every supported curve, rather than grant unusable VERIFY usage.
        for pem in [
            include_bytes!("../tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem").as_slice(),
            include_bytes!("../tests/fixtures/keys/ec/ec-prime384v1-pubkey.pem").as_slice(),
            include_bytes!("../tests/fixtures/keys/ec/ec-prime521v1-pubkey.pem").as_slice(),
        ] {
            let original =
                single_pem_block(pem, ResourcePolicy::default().max_external_resource_bytes)
                    .expect("EC fixture")
                    .into_contents();
            let spki = rsa::pkcs8::SubjectPublicKeyInfoRef::from_der(&original).expect("SPKI");
            let point = spki
                .subject_public_key
                .as_bytes()
                .expect("octet-aligned point");
            let coordinate_len = (point.len() - 1) / 2;
            let mut compressed = vec![2 | (point.last().expect("Y coordinate") & 1)];
            compressed.extend_from_slice(&point[1..=coordinate_len]);
            let encoded = der::Encode::to_der(&rsa::pkcs8::SubjectPublicKeyInfoRef {
                algorithm: spki.algorithm,
                subject_public_key: der::asn1::BitStringRef::from_bytes(&compressed)
                    .expect("point"),
            })
            .expect("compressed SPKI");
            let mut inventory = KeyInventory::default();
            assert!(
                inventory
                    .add_public_der("compressed".into(), encoded, &ResourcePolicy::default())
                    .is_err()
            );
            assert!(inventory.public_keys().is_empty());
            inventory
                .add_public_der("uncompressed".into(), original, &ResourcePolicy::default())
                .expect("supported uncompressed encoding remains usable");
        }
        // A genuinely signed certificate wrapper must not bypass this profile.
        struct CompressedPoint<'a>(&'a [u8], &'static rcgen::SignatureAlgorithm);
        impl rcgen::PublicKeyData for CompressedPoint<'_> {
            fn der_bytes(&self) -> &[u8] {
                self.0
            }
            fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
                self.1
            }
        }
        let mut root_params = rcgen::CertificateParams::new(Vec::new()).expect("root params");
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root = rcgen::CertifiedIssuer::self_signed(
            root_params,
            rcgen::KeyPair::generate().expect("root key"),
        )
        .expect("root certificate");
        for (pem, algorithm) in [
            (
                include_bytes!("../tests/fixtures/keys/ec/ec-prime256v1-cert.pem").as_slice(),
                &rcgen::PKCS_ECDSA_P256_SHA256,
            ),
            (
                include_bytes!("../tests/fixtures/keys/ec/ec-prime384v1-cert.pem").as_slice(),
                &rcgen::PKCS_ECDSA_P384_SHA384,
            ),
        ] {
            let original =
                single_pem_block(pem, ResourcePolicy::default().max_external_resource_bytes)
                    .expect("certificate fixture")
                    .into_contents();
            let (_, certificate) = X509Certificate::from_der(&original).expect("certificate");
            let point = certificate.public_key().subject_public_key.data.as_ref();
            let coordinate_len = (point.len() - 1) / 2;
            let mut compressed = vec![2 | (point.last().expect("Y coordinate") & 1)];
            compressed.extend_from_slice(&point[1..=coordinate_len]);
            let leaf = rcgen::CertificateParams::new(Vec::new())
                .expect("leaf params")
                .signed_by(&CompressedPoint(&compressed, algorithm), &root)
                .expect("signed compressed certificate");
            let encoded = leaf.der().to_vec();
            let mut inventory = KeyInventory::default();
            assert!(
                inventory
                    .add_public_der(
                        "compressed-cert".into(),
                        encoded,
                        &ResourcePolicy::default()
                    )
                    .is_err()
            );
            assert!(inventory.public_keys().is_empty());
            inventory
                .add_public_der(
                    "uncompressed-cert".into(),
                    original,
                    &ResourcePolicy::default(),
                )
                .expect("uncompressed certificate imports");
        }
    }

    #[test]
    fn malformed_ec_point_cannot_acquire_verify_usage() {
        // A supported curve OID does not make an off-curve point usable.
        let block = single_pem_block(
            include_bytes!("../tests/fixtures/keys/ec/ec-prime256v1-pubkey.pem"),
            ResourcePolicy::default().max_external_resource_bytes,
        )
        .expect("EC SPKI fixture");
        let mut der = block.into_contents();
        let last = der.last_mut().expect("point bytes");
        *last ^= 1;
        let mut inventory = KeyInventory::default();
        assert!(
            inventory
                .add_public_der("off-curve".into(), der, &ResourcePolicy::default())
                .is_err()
        );
        assert!(inventory.public_keys().is_empty());
    }

    #[cfg(feature = "xmlenc")]
    #[test]
    fn decryption_policy_rejection_retains_its_type() {
        // An invalid operation snapshot is not a candidate-local key miss.
        let mut policy = crate::policy::DecryptionPolicy::default();
        policy.resources.max_external_resource_bytes = usize::MAX;
        assert!(matches!(
            KeyInventory::default().decryption_resolver("missing", &policy),
            Err(KeyStoreError::Policy(_))
        ));
    }

    #[cfg(feature = "xmlenc")]
    #[test]
    fn inventory_decryption_resolver_enforces_aes_usage_end_to_end() {
        // Inventory authorization is checked before the normal XMLEnc
        // decryptor receives an otherwise valid direct AES content key.
        use crate::xmlenc::{
            DataEncryptionAlgorithm, DecryptContext, DecryptedContent, EncryptedDataBuilder,
        };

        let key = b"0123456789abcdef";
        let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .direct_key(*key)
            .encrypt_binary(b"inventory decrypt payload")
            .expect("AES fixture encrypts");
        let resources = ResourcePolicy::default();
        let mut keys = KeyInventory::default();
        keys.add_symmetric(
            "decrypt".into(),
            SymmetricKeyKind::Aes,
            key.to_vec(),
            KeyUsages::DECRYPT,
            &resources,
        )
        .expect("decrypt key imports");
        let resolver = keys
            .decryption_resolver("decrypt", &crate::policy::DecryptionPolicy::default())
            .expect("decrypt use is allowed");
        let content = DecryptContext::new(resolver.as_ref())
            .decrypt(&encrypted.encrypted_data_xml)
            .expect("inventory key decrypts");
        assert!(
            matches!(content, DecryptedContent::Bytes(bytes) if bytes == b"inventory decrypt payload")
        );

        let mut restricted = KeyInventory::default();
        restricted
            .add_symmetric(
                "encrypt-only".into(),
                SymmetricKeyKind::Aes,
                key.to_vec(),
                KeyUsages::ENCRYPT,
                &resources,
            )
            .expect("encrypt-only key imports");
        assert!(
            restricted
                .decryption_resolver("encrypt-only", &crate::policy::DecryptionPolicy::default())
                .is_err()
        );
    }

    #[cfg(feature = "xmlenc")]
    #[test]
    fn inventory_direct_aes_does_not_consume_recipient_candidates() {
        // A direct AES key is not a wrapping key. Recipient traversal must
        // leave its sole candidate available for the later direct-key path.
        use crate::xmlenc::{
            CipherData, DataEncryptionAlgorithm, EncryptedKey, EncryptionMethod,
            KeyCandidateBudget, KeyTransportAlgorithm, XmlEncError,
        };
        let mut keys = KeyInventory::default();
        keys.add_symmetric(
            "direct".into(),
            SymmetricKeyKind::Aes,
            vec![1; 16],
            KeyUsages::DECRYPT,
            &ResourcePolicy::default(),
        )
        .expect("AES imports");
        let resolver = keys
            .decryption_resolver("direct", &crate::policy::DecryptionPolicy::default())
            .expect("AES resolver");
        let recipient = EncryptedKey {
            id: None,
            recipient: None,
            key_name: None,
            encryption_method: EncryptionMethod {
                algorithm: KeyTransportAlgorithm::RsaOaep11.uri().into(),
                key_size_bits: None,
                oaep_digest: None,
                mgf_algorithm: None,
                oaep_params: None,
            },
            cipher_data: CipherData {
                value: String::new(),
            },
            reference_list: None,
            carried_key_name: None,
        };
        let mut budget = KeyCandidateBudget::with_limit(1);
        let provider = crate::provider::RustCryptoProvider;
        for _ in 0..64 {
            assert!(matches!(
                resolver.resolve_key_candidates(
                    &provider,
                    DataEncryptionAlgorithm::Aes128Gcm,
                    Some(&recipient),
                    &mut budget
                ),
                Err(XmlEncError::KeyNotFound)
            ));
            assert_eq!(budget.remaining(), 1);
        }
        assert_eq!(
            resolver
                .resolve_key_candidates(
                    &provider,
                    DataEncryptionAlgorithm::Aes128Gcm,
                    None,
                    &mut budget
                )
                .expect("one direct candidate"),
            vec![vec![1; 16]]
        );
        assert_eq!(budget.remaining(), 0);
    }

    #[cfg(feature = "xmlenc")]
    #[test]
    fn decryption_selection_checks_operation_limits_before_material_use() {
        // Reusing a broadly imported inventory with a tighter operation
        // snapshot must reject both AES and RSA material before copy/decode.
        let resources = ResourcePolicy::default();
        let mut keys = KeyInventory::default();
        keys.add_symmetric(
            "aes".into(),
            SymmetricKeyKind::Aes,
            vec![0x31; 16],
            KeyUsages::DECRYPT,
            &resources,
        )
        .expect("AES key imports");
        keys.add_private_pem(
            "rsa".into(),
            include_bytes!("../tests/fixtures/keys/rsa/rsa-2048-key.pem"),
            None,
            KeyUsages::DECRYPT,
            &resources,
        )
        .expect("RSA key imports");
        let mut policy = crate::policy::DecryptionPolicy::default();
        policy.resources.max_external_resource_bytes = 8;
        policy.resources.max_external_resource_total_bytes = 8;
        assert!(keys.decryption_resolver("aes", &policy).is_err());
        assert!(keys.decryption_resolver("rsa", &policy).is_err());
    }
}
