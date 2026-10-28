//! Caller-owned, provider-neutral key inventory and xmlsec key-store import.

use alloc::{
    borrow::ToOwned,
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};

use crate::collections::Set;

#[cfg(all(test, feature = "xmldsig-sign"))]
use crate::xmldsig::DsaSigningKey;
#[cfg(all(test, feature = "xmldsig-sign"))]
use base64::Engine as _;
#[cfg(feature = "xmldsig-sign")]
use crypto_bigint::{
    BoxedUint,
    modular::{BoxedMontyForm, BoxedMontyParams},
};
use der::Decode as _;
#[cfg(feature = "xmldsig-sign")]
use dsa::{
    Components as DsaComponents, SigningKey as NativeDsaSigningKey,
    VerifyingKey as DsaVerifyingKey, pkcs8::EncodePrivateKey as _,
};
// Private-key and protected-container import compile only with signing.
#[cfg(feature = "xmldsig-sign")]
mod pkcs12_import;
#[cfg(feature = "xmldsig-sign")]
use crate::rsa_encoding::RsaPrivateKeyEncoding as _;
#[cfg(feature = "xmldsig-sign")]
use pkcs8::{DecodePrivateKey as _, EncryptedPrivateKeyInfoRef, PrivateKeyInfoRef};
#[cfg(feature = "xmldsig-sign")]
use pkcs12_import::Limits as Pkcs12Limits;
#[cfg(feature = "xmldsig-sign")]
use rsa::RsaPrivateKey;
#[cfg(feature = "xmlenc")]
use rsa::RsaPublicKey;
#[cfg(all(test, feature = "xmldsig-sign"))]
use x509_parser::prelude::FromDer as _;
#[cfg(all(test, feature = "xmldsig-sign"))]
use x509_parser::prelude::X509Certificate;
use zeroize::Zeroizing;

#[cfg(feature = "xmlenc")]
use crate::xmldsig::parse::X509PublicKeyInfo;
#[cfg(feature = "xmldsig-sign")]
use crate::xmldsig::{HmacSigningKey, SigningKey, validate_signing_key};
use crate::{
    XmlBackend, XmlDomNode as Node,
    document::{
        DocumentParseSettings, XmlParseWorkBudget, parse_borrowed_with_settings_and_budget,
    },
    policy::ResourcePolicy,
    xmldsig::keys::InspectedKeyCandidateBudget,
    xmldsig::parse::XMLDSIG11_NS,
    xmldsig::{
        DefaultKeyResolver, DsigError, HmacVerificationKey, KeyInfo, KeyInfoSource, KeyResolver,
        KeyResolverConfig, KeyValueInfo, SignatureAlgorithm, VerifyingKey, X509DataInfo,
    },
};

const XMLSEC_NS: &str = "http://www.aleksey.com/xmlsec/2002";
const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

#[derive(Clone, Copy)]
enum PublicDerFormat {
    KeyOrCertificate,
    SubjectPublicKeyInfo,
}

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
                        [modulus.len(), exponent.len(), 0, 0, 0, 0]
                    }
                    KeyValueInfo::Dsa { p, q, g, y } => [
                        p.as_ref().map_or(0, Vec::len),
                        q.as_ref().map_or(0, Vec::len),
                        g.as_ref().map_or(0, Vec::len),
                        y.len(),
                        0,
                        0,
                    ],
                    KeyValueInfo::Dh {
                        p,
                        q,
                        generator,
                        public,
                        seed,
                        pgen_counter,
                    } => [
                        p.as_ref().map_or(0, Vec::len),
                        q.as_ref().map_or(0, Vec::len),
                        generator.as_ref().map_or(0, Vec::len),
                        public.len(),
                        seed.as_ref().map_or(0, Vec::len),
                        pgen_counter.as_ref().map_or(0, Vec::len),
                    ],
                    KeyValueInfo::Ec {
                        curve_oid,
                        public_key,
                    } => [curve_oid.len(), public_key.len(), 0, 0, 0, 0],
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
    /// Camellia content-encryption or wrapping key.
    Camellia,
    /// `ChaCha20` and ChaCha20-Poly1305 256-bit key material.
    ChaCha20,
    /// Three-key TDEA key, available with `legacy-algorithms`.
    Des,
}

impl SymmetricKeyKind {
    /// Whether the compiled mechanism supports this content-key family.
    #[must_use]
    pub fn is_encryption_key(self) -> bool {
        matches!(self, Self::Aes | Self::Camellia | Self::ChaCha20)
            || (cfg!(feature = "legacy-algorithms") && self == Self::Des)
    }

    #[cfg(feature = "xmlenc")]
    fn accepts_algorithm(self, algorithm: crate::xmlenc::DataEncryptionAlgorithm) -> bool {
        self == algorithm.key_kind()
    }
}

fn des_key_usages(bytes: &[u8]) -> Result<KeyUsages, KeyStoreError> {
    if cfg!(feature = "legacy-algorithms") && bytes.len() == 24 {
        Ok(KeyUsages::ENCRYPT.union(KeyUsages::DECRYPT))
    } else {
        Err(KeyStoreError::Selection(
            "unsupported DES key length or mechanism",
        ))
    }
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
    #[cfg(feature = "xmldsig-sign")]
    private_keys: Vec<StoredPrivateKey>,
    /// Untrusted certificates available for key lookup or path construction.
    lookup_certificates: Vec<Vec<u8>>,
    /// Explicit caller-trusted certificate anchors.
    trusted_certificates: Vec<Vec<u8>>,
    /// Caller-supplied DER certificate revocation lists.
    crls: Vec<Vec<u8>>,
    material_bytes: usize,
    /// Password-derivation work reserved by protected-container imports.
    #[cfg(feature = "xmldsig-sign")]
    kdf_work: usize,
}

/// Import session for multiple XML key stores under one operation snapshot.
/// Failed attempts retain their inspection and parser-work charges. Successful
/// stores are moved into the inventory, never cloned.
pub struct XmlKeyStoreImporter<'a, P: crate::document::XmlDocumentPolicy> {
    policy: &'a P,
    backend: XmlBackend,
    parse_work: XmlParseWorkBudget,
    inspected: usize,
    inventory: KeyInventory,
    live_material_bytes: usize,
}

impl<'a, P: crate::document::XmlDocumentPolicy> XmlKeyStoreImporter<'a, P> {
    /// Bind this session to the caller's immutable policy and XML backend.
    ///
    /// # Errors
    /// Returns an invalid resource-policy or initial aggregate-material limit violation.
    pub fn new(policy: &'a P, backend: XmlBackend) -> Result<Self, KeyStoreError> {
        Self::with_live_material(policy, backend, 0)
    }

    /// Bind import accounting to material already retained by the operation.
    /// This is usage, not a second policy limit; it remains live until finish.
    ///
    /// # Errors
    /// Returns invalid resource configuration or an aggregate-material limit
    /// violation when the already-live material exceeds the snapshot's allowance.
    pub fn with_live_material(
        policy: &'a P,
        backend: XmlBackend,
        live_material_bytes: usize,
    ) -> Result<Self, KeyStoreError> {
        ensure_resource_policy(policy.resource_policy())?;
        if live_material_bytes > policy.resource_policy().max_external_resource_total_bytes {
            return Err(import_resource_limit(
                crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                policy.resource_policy().max_external_resource_total_bytes,
            ));
        }
        Ok(Self {
            policy,
            backend,
            parse_work: XmlParseWorkBudget::from_resources(policy.resource_policy()),
            inspected: 0,
            inventory: KeyInventory::default(),
            live_material_bytes,
        })
    }

    /// Import a file without resetting work budgets. Failure leaves stored keys
    /// unchanged, but does not refund work already performed.
    ///
    /// # Errors
    /// Returns XML/key-store format, unsupported material, duplicate-name,
    /// parser-work or material/candidate budget failures.
    pub fn import(&mut self, bytes: &[u8]) -> Result<(), KeyStoreError> {
        let store = KeyInventory::from_xml_bytes_with_budget(
            bytes,
            self.policy,
            self.backend,
            &self.parse_work,
            &mut self.inspected,
            self.inventory
                .material_bytes
                .checked_add(self.live_material_bytes)
                .ok_or_else(|| {
                    import_resource_limit(
                        crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                        self.policy
                            .resource_policy()
                            .max_external_resource_total_bytes,
                    )
                })?,
        )?;
        self.inventory.extend(store, self.policy.resource_policy())
    }

    /// Finish the import session and transfer ownership of the complete inventory.
    #[must_use]
    pub fn finish(self) -> KeyInventory {
        self.inventory
    }
}

/// Candidate inspections shared by named signing lookups in one operation.
#[cfg(feature = "xmldsig-sign")]
#[derive(Default)]
pub struct SigningLookupBudget {
    inspected: usize,
}

/// Operations for which a caller may authorize a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyUsage {
    /// `XMLDSig` signing.
    Sign,
    /// `XMLDSig` verification.
    Verify,
    /// `XMLEnc` encryption or key wrapping.
    Encrypt,
    /// `XMLEnc` decryption or key unwrapping.
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

/// PKCS#8 DER of a stored private key; both forms wipe on drop.
#[cfg(feature = "xmldsig-sign")]
enum PrivateKeyDer {
    Owned(Zeroizing<Vec<u8>>),
    /// A decrypted PKCS#12 key kept in place, with its import memory charge.
    Retained(structured_cms::personal::Plaintext),
}

#[cfg(feature = "xmldsig-sign")]
impl core::ops::Deref for PrivateKeyDer {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Self::Owned(bytes) => bytes,
            Self::Retained(plaintext) => plaintext.as_bytes(),
        }
    }
}

/// Private key encoded as provider-neutral PKCS#8 DER.
#[cfg(feature = "xmldsig-sign")]
pub struct StoredPrivateKey {
    /// Opaque caller-assigned name.
    pub name: String,
    pkcs8_der: PrivateKeyDer,
    /// Allowed operations.
    pub usages: KeyUsages,
    /// Associated certificates, leaf first when a matching leaf exists.
    pub certificate_chain: Vec<Vec<u8>>,
    has_matching_leaf: bool,
}

#[cfg(feature = "xmldsig-sign")]
impl StoredPrivateKey {
    /// Private key bytes as PKCS#8 DER; zeroized on drop.
    #[must_use]
    pub fn pkcs8_der(&self) -> &[u8] {
        &self.pkcs8_der
    }

    /// Import an explicitly selected recipient into the operation's crypto engine.
    ///
    /// # Errors
    /// Returns policy/resource refusal, missing decryption authorization or
    /// the selected provider's decapsulation-key import failure.
    pub fn decapsulation_key(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: crate::provider::KeyEncapsulationAlgorithm,
        policy: &crate::policy::KeyEstablishmentPolicy,
        resources: &ResourcePolicy,
    ) -> Result<Arc<dyn crate::provider::KeyDecapsulationKey>, KeyStoreError> {
        policy.validate()?;
        policy.check_encapsulation(algorithm)?;
        if !self.usages.allows(KeyUsage::Decrypt) {
            return Err(KeyStoreError::Selection(
                "key is not authorized for decapsulation",
            ));
        }
        check_operation_material_size(self.pkcs8_der.len(), resources)?;
        provider
            .import_decapsulation_key(algorithm, &self.pkcs8_der)
            .map_err(KeyStoreError::Provider)
    }

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
    /// Parsed `XMLDSig` key material.
    pub key_info: KeyInfo,
    /// Allowed operations.
    pub usages: KeyUsages,
}

impl StoredPublicKey {
    /// Import one named ML-KEM recipient; document hints never grant permission.
    ///
    /// # Errors
    /// Returns policy/resource refusal, missing encryption authorization or
    /// recipient SPKI, or the selected provider's encapsulation-key import failure.
    pub fn encapsulation_key(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: crate::provider::KeyEncapsulationAlgorithm,
        policy: &crate::policy::KeyEstablishmentPolicy,
        resources: &ResourcePolicy,
    ) -> Result<Arc<dyn crate::provider::KeyEncapsulationKey>, KeyStoreError> {
        policy.validate()?;
        policy.check_encapsulation(algorithm)?;
        if !self.usages.allows(KeyUsage::Encrypt) {
            return Err(KeyStoreError::Selection(
                "key is not authorized for encapsulation",
            ));
        }
        let der = self
            .key_info
            .sources
            .iter()
            .find_map(|source| match source {
                KeyInfoSource::DerEncodedKeyValue(der) => Some(der.as_slice()),
                _ => None,
            })
            .ok_or(KeyStoreError::Selection(
                "recipient requires an ML-KEM SPKI",
            ))?;
        check_operation_material_size(der.len(), resources)?;
        provider
            .import_encapsulation_key(algorithm, der)
            .map_err(KeyStoreError::Provider)
    }

    /// Decode this already-selected RSA recipient without searching the inventory again.
    ///
    /// # Errors
    /// Returns policy/resource refusal, missing encryption authorization,
    /// incompatible key material or invalid RSA public metadata.
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
                    let session = crate::xmldsig::pkix::CertificateSession::new(&policy.resources);
                    if session
                        .spki_algorithm(der)
                        .map_err(|error| match session.error(error) {
                            crate::xmldsig::X509ChainError::Policy(error) => {
                                KeyStoreError::Policy(error)
                            }
                            _ => KeyStoreError::Selection("invalid RSA encryption key"),
                        })?
                        != crate::xmldsig::pkix::SpkiAlgorithm::RsaEncryption
                    {
                        return Err(KeyStoreError::Selection(
                            "named key is not an RSA public key",
                        ));
                    }
                    let raw = session
                        .rsa_public_key(der, None)
                        .map_err(|error| match session.error(error) {
                            crate::xmldsig::X509ChainError::Policy(error) => {
                                KeyStoreError::Policy(error)
                            }
                            _ => KeyStoreError::Selection("invalid RSA encryption key"),
                        })?
                        .ok_or(KeyStoreError::Selection("invalid RSA encryption key"))?;
                    // The shared reader already admitted the SPKI; build the
                    // key from its components instead of parsing it again.
                    rsa_recipient_from_components(
                        raw.modulus().as_bytes(),
                        raw.exponent().as_bytes(),
                        policy,
                    )
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

type NamedVerificationKeys<'a> = (Option<&'a StoredPublicKey>, Option<&'a StoredSymmetricKey>);

impl InventoryVerificationResolver<'_> {
    fn select_named<'k>(
        &'k self,
        key_info: Option<&KeyInfo>,
        inspected_candidates: &mut InspectedKeyCandidateBudget,
    ) -> Result<NamedVerificationKeys<'k>, DsigError> {
        let mut candidate: Option<&StoredPublicKey> = None;
        let mut secret_candidate: Option<&StoredSymmetricKey> = None;
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
        Ok((candidate, secret_candidate))
    }

    fn named_hmac_key(
        candidate: &StoredSymmetricKey,
        algorithm: SignatureAlgorithm,
        resources: &ResourcePolicy,
    ) -> Result<HmacVerificationKey, DsigError> {
        if algorithm.hmac_output_bits().is_none() {
            return Err(DsigError::InvalidStructure {
                reason: "named HMAC key is incompatible with signature method",
            });
        }
        for (resource, maximum) in [
            (
                crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
                resources.max_external_resource_bytes,
            ),
            (
                crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                resources.max_external_resource_total_bytes,
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
        HmacVerificationKey::new(candidate.bytes.to_vec()).map_err(|_| {
            DsigError::InvalidStructure {
                reason: "invalid named HMAC key",
            }
        })
    }

    fn configured_x509_fallback(
        &self,
        key_info: Option<&KeyInfo>,
        trusted_selection: bool,
        selected_material_bytes: usize,
        policy: &crate::policy::VerificationPolicy,
    ) -> Result<DefaultKeyResolver, DsigError> {
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
                trusted_selection
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
            // The owned resolver config and its borrowed inventory/document
            // input coexist. Reserve both payloads before any config clone;
            // this is live-memory policy, not a certificate syntax rule.
            for _ in 0..2 {
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
        }
        Ok(DefaultKeyResolver::new(KeyResolverConfig {
            lookup_certs: self.inventory.lookup_certificates.clone(),
            trusted_certs: self.inventory.trusted_certificates.clone(),
            crls: crls.cloned().collect(),
            ..KeyResolverConfig::default()
        }))
    }
}

impl KeyResolver for InventoryVerificationResolver<'_> {
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
        self.resolve_for_verification(key_info, algorithm, policy, provider)
            .map(|key| key.map(crate::xmldsig::ResolvedVerificationKey::into_key))
    }

    fn resolve_for_verification<'k>(
        &'k self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
        policy: &crate::policy::VerificationPolicy,
        provider: &dyn crate::provider::CryptoProvider,
    ) -> Result<Option<crate::xmldsig::ResolvedVerificationKey<'k>>, DsigError> {
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
        policy: &crate::policy::VerificationPolicy,
        provider: &dyn crate::provider::CryptoProvider,
        inspected_candidates: &mut InspectedKeyCandidateBudget,
    ) -> Result<Option<crate::xmldsig::ResolvedVerificationKey<'k>>, DsigError> {
        policy.validate()?;
        inspected_candidates.bind_policy(policy)?;
        if let Some(info) = key_info {
            crate::xmldsig::keys::validate_key_info_source_permissions(info, policy.key_sources)?;
        }
        let (candidate, secret_candidate) = self.select_named(key_info, inspected_candidates)?;
        if let Some(candidate) = secret_candidate {
            let key = Self::named_hmac_key(candidate, algorithm, &policy.resources)?;
            return Ok(Some(
                crate::xmldsig::ResolvedVerificationKey::CallerTrusted(Box::new(key)),
            ));
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
                KeyInfoSource::X509Data(_) => {
                    policy.key_trust.verify_x509_chains
                        || !self.inventory.trusted_certificates.is_empty()
                }
                _ => false,
            })
        });
        // Try only sources preceding the first configured-X.509 use without
        // inspecting or copying inventory certificates that may never be used.
        let mut prefix_error = None;
        if let Some(info) = selected_info
            && let Some(first_x509) = configured_x509_index
            && first_x509 != 0
        {
            let prefix_resolver = DefaultKeyResolver::new(KeyResolverConfig::default());
            let outcome = prefix_resolver.resolve_sources_with_candidate_budget(
                info,
                algorithm,
                policy,
                provider,
                inspected_candidates,
                if candidate.is_some() {
                    crate::xmldsig::keys::ResolutionScope::TrustedPrefix(first_x509)
                } else {
                    crate::xmldsig::keys::ResolutionScope::DocumentPrefix(first_x509)
                },
            )?;
            if let Some(key) = outcome.key {
                return Ok(Some(key));
            }
            prefix_error = outcome.deferred_error;
        }
        let fallback = if configured_x509_index.is_some() {
            self.configured_x509_fallback(
                key_info,
                candidate.is_some(),
                selected_material_bytes,
                policy,
            )?
        } else {
            DefaultKeyResolver::new(KeyResolverConfig::default())
        };
        if let Some(first_x509) = configured_x509_index
            && let Some(info) = selected_info
        {
            // Resume after the inspected prefix: one budget counts actual
            // work, not a replay caused by attaching configured certificates.
            let mut outcome = fallback.resolve_sources_with_candidate_budget(
                info,
                algorithm,
                policy,
                provider,
                inspected_candidates,
                if candidate.is_some() {
                    crate::xmldsig::keys::ResolutionScope::TrustedSuffix(first_x509)
                } else {
                    crate::xmldsig::keys::ResolutionScope::DocumentSuffix(first_x509)
                },
            )?;
            // Terminal suffix failures have already propagated. On a complete
            // miss, keep the first deferred error in original source order.
            if outcome.key.is_none()
                && let Some(error) = prefix_error
            {
                outcome.deferred_error = Some(error);
            }
            return outcome.finish();
        }
        if let Some(candidate) = candidate {
            return fallback.resolve_trusted_material_with_candidate_budget(
                &candidate.key_info,
                algorithm,
                policy,
                provider,
                inspected_candidates,
            );
        }
        fallback.resolve_with_candidate_budget(
            key_info,
            algorithm,
            policy,
            provider,
            inspected_candidates,
        )
    }

    fn consumes_document_key_info(&self) -> bool {
        true
    }
}

enum ParsedMaterial {
    Symmetric(SymmetricKeyKind, Zeroizing<Vec<u8>>),
    Public(KeyValueInfo),
    PublicDer(Vec<u8>),
    Dsa {
        public: KeyValueInfo,
        /// PKCS#8 form of the store's `X`; a verification-only build keeps none.
        #[cfg(feature = "xmldsig-sign")]
        private: Option<Zeroizing<Vec<u8>>>,
    },
    Unsupported,
}

#[cfg(feature = "xmlenc")]
struct InventoryDirectSymmetric {
    bytes: Zeroizing<Vec<u8>>,
    kind: SymmetricKeyKind,
}

#[cfg(feature = "xmlenc")]
impl crate::xmlenc::DecryptionKeyResolver for InventoryDirectSymmetric {
    fn resolve_key(
        &self,
        _provider: &dyn crate::provider::CryptoProvider,
        algorithm: crate::xmlenc::DataEncryptionAlgorithm,
        encrypted_key: Option<&crate::xmlenc::EncryptedKey>,
    ) -> Result<Vec<u8>, crate::xmlenc::XmlEncError> {
        if encrypted_key.is_some() || !self.kind.accepts_algorithm(algorithm) {
            return Err(crate::xmlenc::XmlEncError::KeyNotFound);
        }
        crate::xmlenc::validate_key_len(algorithm, &self.bytes)?;
        Ok(self.bytes.to_vec())
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

    fn resolve_key_candidates_with_policy(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: crate::xmlenc::DataEncryptionAlgorithm,
        encrypted_key: Option<&crate::xmlenc::EncryptedKey>,
        policy: &crate::policy::DecryptionPolicy,
        budget: &mut crate::xmlenc::KeyCandidateBudget,
    ) -> Result<Vec<Vec<u8>>, crate::xmlenc::XmlEncError> {
        policy.validate()?;
        if encrypted_key.is_some() {
            return Err(crate::xmlenc::XmlEncError::KeyNotFound);
        }
        check_selected_material_size(self.bytes.len(), &policy.resources).map_err(|error| {
            match error {
                KeyStoreError::Policy(violation) => crate::xmlenc::XmlEncError::Policy(violation),
                other => crate::xmlenc::XmlEncError::InvalidStructure(other.to_string()),
            }
        })?;
        self.resolve_key_candidates(provider, algorithm, None, budget)
    }
}

#[derive(Debug, thiserror::Error)]
/// Key-store import errors that never include secret material.
pub enum KeyStoreError {
    /// The selected cryptographic engine failed; do not retry another engine.
    #[error(transparent)]
    Provider(#[from] crate::provider::ProviderError),
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
    /// Work reserved before password derivation, including unsuccessful imports.
    /// An operation importing through temporary inventories must carry this
    /// usage forward rather than resetting its remaining KDF allowance.
    #[cfg(feature = "xmldsig-sign")]
    #[must_use]
    pub fn key_import_kdf_work(&self) -> usize {
        self.kdf_work
    }

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
        #[cfg(feature = "xmldsig-sign")]
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
    #[cfg(feature = "xmldsig-sign")]
    #[must_use]
    pub fn private_keys(&self) -> &[StoredPrivateKey] {
        &self.private_keys
    }

    fn has_key_name(&self, name: &str) -> bool {
        #[cfg(feature = "xmldsig-sign")]
        if self.private_keys.iter().any(|key| key.name == name) {
            return true;
        }
        self.symmetric_keys.iter().any(|key| key.name == name)
            || self.public_keys.iter().any(|key| key.name == name)
    }

    /// Combine two caller-owned imports after checking aggregate bytes,
    /// candidates, KDF work, and cross-store name collisions before mutation.
    ///
    /// # Errors
    /// Returns invalid resource configuration, aggregate byte/candidate/KDF
    /// overflow or exhaustion, or duplicate names, before changing the destination inventory.
    pub fn extend(
        &mut self,
        mut other: Self,
        resources: &ResourcePolicy,
    ) -> Result<(), KeyStoreError> {
        ensure_resource_policy(resources)?;
        #[cfg(feature = "xmldsig-sign")]
        let work = self
            .kdf_work
            .checked_add(other.kdf_work)
            .filter(|work| *work <= resources.max_key_import_kdf_work)
            .ok_or_else(|| {
                import_resource_limit(
                    crate::policy::resource_name::KEY_IMPORT_KDF_WORK,
                    resources.max_key_import_kdf_work,
                )
            })?;
        let candidates = self
            .entry_count
            .checked_add(other.entry_count)
            .ok_or(KeyStoreError::Selection("key candidate count overflow"))?;
        if candidates > resources.max_key_candidates {
            return Err(import_resource_limit(
                crate::policy::resource_name::KEY_CANDIDATES,
                resources.max_key_candidates,
            ));
        }
        let bytes = self
            .material_bytes
            .checked_add(other.material_bytes)
            .ok_or(KeyStoreError::Selection("key material size overflow"))?;
        if bytes > resources.max_external_resource_total_bytes {
            return Err(import_resource_limit(
                crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                resources.max_external_resource_total_bytes,
            ));
        }
        let mut names = Set::new();
        for name in other
            .symmetric_keys
            .iter()
            .map(|entry| entry.name.as_str())
            .chain(other.public_keys.iter().map(|entry| entry.name.as_str()))
        {
            names.insert(name);
        }
        #[cfg(feature = "xmldsig-sign")]
        names.extend(other.private_keys.iter().map(|entry| entry.name.as_str()));
        if names.iter().any(|name| self.has_key_name(name)) {
            return Err(KeyStoreError::Selection("duplicate key name"));
        }
        self.entry_count = candidates;
        self.material_bytes = bytes;
        self.symmetric_keys.append(&mut other.symmetric_keys);
        self.public_keys.append(&mut other.public_keys);
        #[cfg(feature = "xmldsig-sign")]
        {
            self.kdf_work = work;
            self.private_keys.append(&mut other.private_keys);
        }
        self.lookup_certificates
            .append(&mut other.lookup_certificates);
        self.trusted_certificates
            .append(&mut other.trusted_certificates);
        self.crls.append(&mut other.crls);
        Ok(())
    }

    /// Select an authorized named RSA recipient from `XMLDSig` `RSAKeyValue` or
    /// DER `SubjectPublicKeyInfo` without introducing an implicit key source.
    ///
    /// # Errors
    /// Returns invalid policy, lookup/material budget refusal, a missing or
    /// unauthorized recipient, or invalid/incompatible RSA public material.
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
    ///
    /// # Errors
    /// Returns policy/resource refusal, a missing or unauthorized key,
    /// incompatible method/key material or default-provider import failure.
    #[cfg(feature = "xmldsig-sign")]
    pub fn signing_key(
        &self,
        name: &str,
        algorithm: SignatureAlgorithm,
        policy: &crate::policy::SigningPolicy,
    ) -> Result<Box<dyn SigningKey>, KeyStoreError> {
        self.signing_key_with_budget(name, algorithm, policy, &mut SigningLookupBudget::default())
    }

    /// Select a named signer while sharing lookup work across caller retries.
    ///
    /// # Errors
    /// Returns policy or cumulative lookup/material budget refusal, missing
    /// authorization, incompatible key/method metadata or provider import failure.
    #[cfg(feature = "xmldsig-sign")]
    pub fn signing_key_with_budget(
        &self,
        name: &str,
        algorithm: SignatureAlgorithm,
        policy: &crate::policy::SigningPolicy,
        budget: &mut SigningLookupBudget,
    ) -> Result<Box<dyn SigningKey>, KeyStoreError> {
        self.signing_key_with_provider_and_budget(
            name,
            algorithm,
            policy,
            crate::provider::default_provider(),
            budget,
        )
    }

    /// Select an authorized key and import it into the explicitly chosen engine.
    ///
    /// # Errors
    /// Returns policy/resource refusal, an unavailable provider capability,
    /// a missing/unauthorized key or incompatible provider key material.
    #[cfg(feature = "xmldsig-sign")]
    pub fn signing_key_with_provider(
        &self,
        name: &str,
        algorithm: SignatureAlgorithm,
        policy: &crate::policy::SigningPolicy,
        provider: &dyn crate::provider::CryptoProvider,
    ) -> Result<Box<dyn SigningKey>, KeyStoreError> {
        self.signing_key_with_provider_and_budget(
            name,
            algorithm,
            policy,
            provider,
            &mut SigningLookupBudget::default(),
        )
    }

    /// Provider-aware selection sharing the operation's retry budget.
    ///
    /// # Errors
    /// Returns policy, capability or cumulative budget refusal, missing key
    /// authorization, invalid key metadata or selected-provider import failure.
    #[cfg(feature = "xmldsig-sign")]
    pub fn signing_key_with_provider_and_budget(
        &self,
        name: &str,
        algorithm: SignatureAlgorithm,
        policy: &crate::policy::SigningPolicy,
        provider: &dyn crate::provider::CryptoProvider,
        budget: &mut SigningLookupBudget,
    ) -> Result<Box<dyn SigningKey>, KeyStoreError> {
        policy.validate()?;
        policy.check_signature_algorithm(algorithm)?;
        provider
            .require_capability(crate::provider::ProviderCapability::Sign(algorithm))
            .map_err(|_| KeyStoreError::Selection("provider does not support signing method"))?;
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
        let der = entry.pkcs8_der();
        check_operation_material_size(der.len(), &policy.resources)?;
        if let Ok(info) = PrivateKeyInfoRef::try_from(der)
            && info.algorithm.oid == dsa::OID
        {
            preflight_dsa_pkcs8_components(&info)?;
        }
        let key = provider
            .import_signing_key(algorithm, der)
            .map_err(|_| KeyStoreError::Selection("incompatible signing key for provider"))?;
        validate_signing_key(key.as_ref(), algorithm, policy).map_err(signing_policy_error)?;
        Ok(key)
    }

    /// Select a named direct symmetric, RSA transport, or ML-KEM recipient key.
    ///
    /// # Errors
    /// Returns policy/resource refusal, an absent/unauthorized or incompatible
    /// key, or failure importing it into the default provider.
    #[cfg(feature = "xmlenc")]
    pub fn decryption_resolver(
        &self,
        name: &str,
        policy: &crate::policy::DecryptionPolicy,
    ) -> Result<Box<dyn crate::xmlenc::DecryptionKeyResolver>, KeyStoreError> {
        self.decryption_resolver_with_provider(name, policy, crate::provider::default_provider())
    }

    /// Select an authorized recovery key owned by the chosen native engine.
    ///
    /// # Errors
    /// Returns policy, lookup/material budget or usage refusal, absent or
    /// incompatible key material, or the selected engine's key import failure.
    #[cfg(feature = "xmlenc")]
    pub fn decryption_resolver_with_provider(
        &self,
        name: &str,
        policy: &crate::policy::DecryptionPolicy,
        provider: &dyn crate::provider::CryptoProvider,
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
            if !entry.kind.is_encryption_key() || !entry.usages.allows(KeyUsage::Decrypt) {
                return Err(KeyStoreError::Selection(
                    "key is not authorized for decryption",
                ));
            }
            check_selected_material_size(entry.bytes.len(), &policy.resources)?;
            return Ok(Box::new(InventoryDirectSymmetric {
                bytes: Zeroizing::new(entry.bytes.to_vec()),
                kind: entry.kind,
            }));
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
        // Borrow public PKCS#1 components before bigint decoding: import
        // permission is not an exemption from the decryption snapshot.
        let info = PrivateKeyInfoRef::try_from(entry.pkcs8_der())
            .map_err(|_| KeyStoreError::Selection("incompatible RSA decryption key"))?;
        if let Some(algorithm) =
            crate::provider::KeyEncapsulationAlgorithm::from_oid(info.algorithm.oid)
        {
            let key = entry.decapsulation_key(
                provider,
                algorithm,
                &policy.key_establishment,
                &policy.resources,
            )?;
            return Ok(Box::new(
                crate::xmlenc::EncapsulationDecryptor::provider_key(key),
            ));
        }
        let components = pkcs1::RsaPrivateKeyRef::from_der(info.private_key.as_bytes())
            .map_err(|_| KeyStoreError::Selection("incompatible RSA decryption key"))?;
        policy.rsa_keys.validate_components(
            "decryption",
            components.modulus.as_bytes(),
            components.public_exponent.as_bytes(),
        )?;
        let key = provider
            .import_recovery_key(&entry.pkcs8_der)
            .map_err(|_| KeyStoreError::Selection("incompatible RSA decryption key"))?;
        Ok(Box::new(crate::xmlenc::PrivateKeyDecryptor::provider_key(
            key,
        )))
    }
    /// Build a resolver from this inventory and one immutable key-store snapshot.
    /// Trust anchors are copied once, not on each candidate lookup.
    #[must_use]
    pub fn verification_resolver(&self) -> InventoryVerificationResolver<'_> {
        InventoryVerificationResolver { inventory: self }
    }
    /// Register raw symmetric bytes under a unique name.
    ///
    /// # Errors
    /// Returns invalid policy, duplicate names, resource exhaustion, invalid
    /// family-specific key widths or incompatible/empty usage permissions.
    pub fn add_symmetric(
        &mut self,
        name: String,
        kind: SymmetricKeyKind,
        bytes: Vec<u8>,
        usages: KeyUsages,
        resources: &ResourcePolicy,
    ) -> Result<(), KeyStoreError> {
        self.check_new_name(&name, resources)?;
        if bytes.len() > resources.max_external_resource_bytes {
            return Err(import_resource_limit(
                crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
                resources.max_external_resource_bytes,
            ));
        }
        if bytes.is_empty()
            || (matches!(kind, SymmetricKeyKind::Aes | SymmetricKeyKind::Camellia)
                && !matches!(bytes.len(), 16 | 24 | 32))
            || (kind == SymmetricKeyKind::ChaCha20 && bytes.len() != 32)
        {
            return Err(KeyStoreError::Selection("invalid symmetric key length"));
        }
        let permitted = match kind {
            SymmetricKeyKind::Hmac => KeyUsages::SIGN.union(KeyUsages::VERIFY),
            SymmetricKeyKind::Aes | SymmetricKeyKind::Camellia | SymmetricKeyKind::ChaCha20 => {
                KeyUsages::ENCRYPT.union(KeyUsages::DECRYPT)
            }
            SymmetricKeyKind::Des => des_key_usages(&bytes)?,
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

    /// Register DER `SubjectPublicKeyInfo` or a complete X.509 certificate.
    /// A certificate is a lookup candidate, never an implicit trust anchor.
    ///
    /// # Errors
    /// Returns name/resource refusal, unsupported or malformed public material,
    /// or certificate parsing/validation failures.
    pub fn add_public_der(
        &mut self,
        name: String,
        der: Vec<u8>,
        resources: &ResourcePolicy,
    ) -> Result<(), KeyStoreError> {
        self.add_public_der_inner(name, der, None, resources)
    }

    /// Register public DER with explicit verification/encryption permissions.
    ///
    /// # Errors
    /// Returns name/resource refusal, malformed or unsupported public material,
    /// or usage permissions incompatible with the decoded key family.
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
        self.add_public_der_payload(
            name,
            der,
            usages,
            resources,
            PublicDerFormat::KeyOrCertificate,
            &crate::xmldsig::pkix::CertificateSession::new(resources),
        )
    }

    /// Store an RFC 9935 ML-KEM public key, which establishes keys only.
    #[cfg(feature = "experimental-pq")]
    fn add_encapsulation_public_key(
        &mut self,
        name: String,
        der: Vec<u8>,
        usages: Option<KeyUsages>,
        resources: &ResourcePolicy,
    ) -> Result<(), KeyStoreError> {
        crate::provider::RustCryptoMlKemPublicKey::from_spki_der(&der)
            .map_err(|_| KeyStoreError::Selection("invalid ML-KEM public key"))?;
        let usages = usages.unwrap_or(KeyUsages::ENCRYPT);
        if usages != KeyUsages::ENCRYPT {
            return Err(KeyStoreError::Selection(
                "ML-KEM public keys establish keys, not signatures",
            ));
        }
        self.reserve_material(named_material_length(&name, der.len(), 2)?, resources)?;
        self.public_keys.push(StoredPublicKey {
            key_info: KeyInfo {
                sources: vec![
                    KeyInfoSource::KeyName(name.clone()),
                    KeyInfoSource::DerEncodedKeyValue(der),
                ],
                ..KeyInfo::default()
            },
            name,
            usages,
        });
        self.entry_count += 1;
        Ok(())
    }

    fn add_public_der_payload(
        &mut self,
        name: String,
        der: Vec<u8>,
        usages: Option<KeyUsages>,
        resources: &ResourcePolicy,
        format: PublicDerFormat,
        // One import pays every key and certificate it reads from this account.
        session: &crate::xmldsig::pkix::CertificateSession,
    ) -> Result<(), KeyStoreError> {
        self.check_new_name(&name, resources)?;
        let permitted = KeyUsages::VERIFY.union(KeyUsages::ENCRYPT);
        if usages.is_some_and(|usages| usages.0 == 0 || usages.0 & !permitted.0 != 0) {
            return Err(KeyStoreError::Selection("public key usage is incompatible"));
        }
        if der.len() > resources.max_external_resource_bytes {
            return Err(import_resource_limit(
                crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
                resources.max_external_resource_bytes,
            ));
        }
        self.check_material_capacity(named_material_length(&name, der.len(), 2)?, resources)?;
        #[cfg(feature = "experimental-pq")]
        if is_encapsulation_spki(session, &der)? {
            return self.add_encapsulation_public_key(name, der, usages, resources);
        }
        let material_len = der.len();
        let mut key_info = KeyInfo::default();
        key_info.sources.push(KeyInfoSource::KeyName(name.clone()));
        let spki = match session.spki_algorithm(&der) {
            Ok(_) => true,
            // Exhausting the shared import account is not a format fallback.
            Err(error) if error.is_resource() => {
                return Err(certificate_import_error(session.error(error)));
            }
            Err(_) => false,
        };
        let is_rsa = if spki {
            let is_rsa =
                crate::xmldsig::keys::supported_spki_is_rsa(session, &der).map_err(|error| {
                    key_import_error(error, || {
                        KeyStoreError::Selection("unsupported public key algorithm")
                    })
                })?;
            key_info
                .sources
                .push(KeyInfoSource::DerEncodedKeyValue(der));
            is_rsa
        } else {
            if matches!(format, PublicDerFormat::SubjectPublicKeyInfo) {
                // RFC 7468 section 13 identifies PUBLIC KEY as SPKI. Section 2
                // permits reinterpretation, but this label-dispatched API does
                // not: certificate fallback belongs only to generic DER import.
                // https://www.rfc-editor.org/rfc/rfc7468#section-13
                // https://www.rfc-editor.org/rfc/rfc7468#section-2
                return Err(KeyStoreError::Selection("invalid PUBLIC KEY payload"));
            }
            let certificate = session.read(&der).map_err(certificate_import_error)?;
            let parsed = crate::xmldsig::parse::certificate_metadata(&certificate, session)
                .map_err(|error| match error {
                    crate::xmldsig::ParseError::Policy(error) => KeyStoreError::Policy(error),
                    _ => KeyStoreError::Selection("unsupported X.509 certificate key"),
                })?;
            let spki_der = certificate.tbs().public_key().as_bytes();
            let is_rsa = crate::xmldsig::keys::supported_spki_is_rsa(session, spki_der).map_err(
                |error| {
                    key_import_error(error, || {
                        KeyStoreError::Selection("unsupported X.509 certificate key")
                    })
                },
            )?;
            drop(certificate);
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
    /// Aggregate capacity includes retained inventory, the live encoded input,
    /// decoded DER, and any SPKI normalization output before allocation.
    ///
    /// # Errors
    /// Returns invalid or ambiguous PEM framing/labels, name/resource refusal,
    /// unsupported key material or failure decoding/normalizing the public key.
    pub fn add_public_pem(
        &mut self,
        name: String,
        bytes: &[u8],
        resources: &ResourcePolicy,
    ) -> Result<(), KeyStoreError> {
        self.add_public_pem_inner(name, bytes, None, resources)
    }

    /// Import one PEM public key with explicit verification/encryption permissions.
    ///
    /// # Errors
    /// Returns PEM/DER format, name/resource or public-key decoding failures,
    /// including usage permissions incompatible with the key family.
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
        let block = BorrowedPem::parse(bytes, resources.max_external_resource_bytes)?;
        if !matches!(block.label, "PUBLIC KEY" | "RSA PUBLIC KEY") {
            return Err(KeyStoreError::Selection("unsupported public PEM label"));
        }
        self.check_material_capacity(
            named_material_length(
                &name,
                bytes
                    .len()
                    .checked_add(block.decoded_len)
                    .ok_or(KeyStoreError::Selection("key material size overflow"))?,
                2,
            )?,
            resources,
        )?;
        let decoded = block.decode()?;
        let der = match block.label {
            "PUBLIC KEY" => decoded,
            "RSA PUBLIC KEY" => {
                use der::Encode as _;
                let components = pkcs1::RsaPublicKeyRef::from_der(&decoded)
                    .map_err(|_| KeyStoreError::Selection("invalid RSA public key"))?;
                crate::xmldsig::keys::bounded_rsa_public_components(
                    components.modulus.as_bytes(),
                    components.public_exponent.as_bytes(),
                )
                .map_err(|_| KeyStoreError::Selection("RSA public key exceeds safety limit"))?;
                // Wrap borrowed PKCS#1 bytes directly; the final SPKI importer
                // performs native RSA validation once, without an intermediate key.
                let spki = pkcs8::SubjectPublicKeyInfoRef {
                    algorithm: pkcs1::ALGORITHM_ID,
                    subject_public_key: der::asn1::BitStringRef::new(0, &decoded)
                        .map_err(|_| KeyStoreError::Selection("invalid RSA public key"))?,
                };
                let encoded_len = usize::try_from(
                    spki.encoded_len()
                        .map_err(|_| KeyStoreError::Selection("invalid RSA public key"))?,
                )
                .map_err(|_| KeyStoreError::Selection("invalid RSA public key"))?;
                if encoded_len > resources.max_external_resource_bytes {
                    return Err(import_resource_limit(
                        crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
                        resources.max_external_resource_bytes,
                    ));
                }
                self.check_material_capacity(
                    named_material_length(
                        &name,
                        bytes
                            .len()
                            .checked_add(decoded.capacity())
                            .and_then(|total| total.checked_add(encoded_len))
                            .ok_or(KeyStoreError::Selection("key material size overflow"))?,
                        2,
                    )?,
                    resources,
                )?;
                spki.to_der()
                    .map_err(|_| KeyStoreError::Selection("invalid RSA public key"))?
            }
            _ => return Err(KeyStoreError::Selection("unsupported public PEM label")),
        };
        let previous_total = self.material_bytes;
        let charged_total = self.check_material_capacity(
            named_material_length(&name, bytes.len().max(der.len()), 2)?,
            resources,
        )?;
        self.add_public_der_payload(
            name,
            der,
            usages,
            resources,
            PublicDerFormat::SubjectPublicKeyInfo,
            &crate::xmldsig::pkix::CertificateSession::new(resources),
        )?;
        debug_assert!(self.material_bytes >= previous_total);
        self.material_bytes = charged_total;
        Ok(())
    }
}

/// Private-key and protected-container import.
#[cfg(feature = "xmldsig-sign")]
impl KeyInventory {
    /// Import a DER private key as PKCS#8 (plain or encrypted) or RSA PKCS#1.
    /// Passwords are consulted only for a structurally encrypted container;
    /// a wrong password never retries a plaintext decoder.
    ///
    /// # Errors
    /// Returns name/resource or usage refusal, malformed/unsupported private
    /// material, required-password/decryption failures or KDF-budget exhaustion.
    pub fn add_private_der(
        &mut self,
        name: String,
        bytes: &[u8],
        password: Option<&[u8]>,
        usages: KeyUsages,
        resources: &ResourcePolicy,
    ) -> Result<(), KeyStoreError> {
        self.add_private_der_inner(name, bytes, password, usages, resources, 0)
    }

    fn insert_private_der(
        &mut self,
        name: String,
        der: Zeroizing<Vec<u8>>,
        usages: KeyUsages,
        source_len: usize,
        resources: &ResourcePolicy,
    ) -> Result<(), KeyStoreError> {
        if der.len() > resources.max_external_resource_bytes {
            return Err(import_resource_limit(
                crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
                resources.max_external_resource_bytes,
            ));
        }
        let identity = PrivateKeyIdentity::decode(&der)?;
        if usages.allows(KeyUsage::Decrypt) && !identity.can_decrypt() {
            return Err(KeyStoreError::Selection(
                "private key cannot recover encryption keys",
            ));
        }
        #[cfg(feature = "experimental-pq")]
        identity.validate_usages(usages)?;
        drop(identity);
        self.reserve_material(
            named_material_length(&name, source_len.max(der.len()), 1)?,
            resources,
        )?;
        self.private_keys.push(StoredPrivateKey {
            name,
            pkcs8_der: PrivateKeyDer::Owned(der),
            usages,
            certificate_chain: Vec::new(),
            has_matching_leaf: false,
        });
        self.entry_count += 1;
        Ok(())
    }

    fn add_private_der_inner(
        &mut self,
        name: String,
        bytes: &[u8],
        password: Option<&[u8]>,
        usages: KeyUsages,
        resources: &ResourcePolicy,
        live_encoded_bytes: usize,
    ) -> Result<(), KeyStoreError> {
        self.check_new_name(&name, resources)?;
        if bytes.len() > resources.max_external_resource_bytes {
            return Err(import_resource_limit(
                crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
                resources.max_external_resource_bytes,
            ));
        }
        let retained_with_input =
            self.check_material_capacity(named_material_length(&name, bytes.len(), 1)?, resources)?;
        validate_private_key_usages(usages)?;
        // Borrowed input and decoded PEM remain live while an owned output is
        // created. Preflight that peak, not only the final inventory footprint.
        let check_plain_output = |output: usize| {
            if output > resources.max_external_resource_bytes {
                return Err(import_resource_limit(
                    crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
                    resources.max_external_resource_bytes,
                ));
            }
            let live = bytes
                .len()
                .checked_add(live_encoded_bytes)
                .and_then(|live| live.checked_add(output))
                .ok_or_else(|| {
                    import_resource_limit(
                        crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                        resources.max_external_resource_total_bytes,
                    )
                })?;
            self.check_material_capacity(named_material_length(&name, live, 1)?, resources)
        };
        let der = if PrivateKeyInfoRef::try_from(bytes).is_ok() {
            check_plain_output(bytes.len())?;
            Zeroizing::new(bytes.to_vec())
        } else if let Ok(encrypted) = EncryptedPrivateKeyInfoRef::try_from(bytes) {
            // PEM decoding does not end the caller's encoded buffer lifetime.
            // Its bytes coexist with DER and the KDF workspace, not replace DER.
            let kdf_live_bytes = retained_with_input
                .checked_add(live_encoded_bytes)
                .ok_or_else(|| {
                    import_resource_limit(
                        crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                        resources.max_external_resource_total_bytes,
                    )
                })?;
            let remaining = self.remaining_kdf_resources(resources)?;
            enforce_pkcs8_kdf_policy(&encrypted, &remaining, kdf_live_bytes)?;
            let password = password.ok_or(KeyStoreError::ProtectedContainer)?;
            let work =
                enforce_pkcs8_password_policy(&encrypted, password, &remaining, kdf_live_bytes)?;
            self.kdf_work += work;
            // Decrypt in the one preflighted, zeroizing output allocation;
            // SecretDocument followed by to_vec would retain two plaintext copies.
            let mut plain = Zeroizing::new(encrypted.encrypted_data.as_bytes().to_vec());
            let plaintext_len = encrypted
                .encryption_algorithm
                .decrypt_in_place(password, &mut plain)
                .map_err(|_| KeyStoreError::ProtectedContainer)?;
            let plaintext_len = plaintext_len.len();
            plain.truncate(plaintext_len);
            PrivateKeyInfoRef::try_from(plain.as_slice())
                .map_err(|_| KeyStoreError::ProtectedContainer)?;
            plain
        } else {
            use der::Encode as _;
            preflight_rsa_pkcs1_components(bytes)?;
            // RFC 8017 A.1.2 / RFC 5958 section 2: wrap the original PKCS#1
            // octets directly, avoiding bigint re-encoding and two owned DERs.
            // https://www.rfc-editor.org/rfc/rfc5958#section-2
            let normalized = PrivateKeyInfoRef::new(
                pkcs1::ALGORITHM_ID,
                der::asn1::OctetStringRef::new(bytes)
                    .map_err(|_| KeyStoreError::Selection("invalid RSA private key"))?,
            );
            let size = usize::try_from(
                normalized
                    .encoded_len()
                    .map_err(|_| KeyStoreError::Selection("invalid RSA private key"))?,
            )
            .map_err(|_| KeyStoreError::Selection("key material size overflow"))?;
            check_plain_output(size)?;
            let normalized = normalized
                .to_der()
                .map_err(|_| KeyStoreError::Selection("invalid RSA private key"))?;
            Zeroizing::new(normalized)
        };
        self.insert_private_der(name, der, usages, bytes.len(), resources)
    }

    /// Import private DER using a caller-owned password callback only when
    /// the input is an encrypted PKCS#8 container.
    ///
    /// # Errors
    /// Returns preflight policy/name/usage refusal, an absent required password,
    /// decryption/key decoding failure or cumulative KDF/material budget refusal.
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
        validate_private_key_usages(usages)?;
        if bytes.len() > resources.max_external_resource_bytes {
            return Err(import_resource_limit(
                crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
                resources.max_external_resource_bytes,
            ));
        }
        let retained_with_input =
            self.check_material_capacity(named_material_length(&name, bytes.len(), 1)?, resources)?;
        let encrypted = EncryptedPrivateKeyInfoRef::try_from(bytes).ok();
        let secret = if let Some(encrypted) = &encrypted {
            let remaining = self.remaining_kdf_resources(resources)?;
            // Secret acquisition is observable work: use the same remaining
            // allowance as direct import before invoking the caller.
            enforce_pkcs8_kdf_policy(encrypted, &remaining, retained_with_input)?;
            Some(password().ok_or(KeyStoreError::ProtectedContainer)?)
        } else {
            None
        };
        if let Some(secret) = &secret {
            // The callback owns capacity, not only initialized password bytes.
            self.check_material_capacity(
                named_material_length(
                    &name,
                    bytes.len().checked_add(secret.capacity()).ok_or_else(|| {
                        import_resource_limit(
                            crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                            resources.max_external_resource_total_bytes,
                        )
                    })?,
                    1,
                )?,
                resources,
            )?;
            let encrypted = encrypted
                .as_ref()
                .ok_or(KeyStoreError::ProtectedContainer)?;
            enforce_pkcs8_password_policy(
                encrypted,
                secret,
                &self.remaining_kdf_resources(resources)?,
                retained_with_input + secret.capacity() - secret.len(),
            )?;
        }
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
    ///
    /// # Errors
    /// Returns malformed/unsupported PEM or private material, name/resource or
    /// usage refusal, required-password/decryption failure or KDF-budget exhaustion.
    pub fn add_private_pem(
        &mut self,
        name: String,
        bytes: &[u8],
        password: Option<&[u8]>,
        usages: KeyUsages,
        resources: &ResourcePolicy,
    ) -> Result<(), KeyStoreError> {
        enum Payload {
            Plain,
            Encrypted,
            Rsa,
        }

        ensure_resource_policy(resources)?;
        self.check_new_name(&name, resources)?;
        self.check_material_capacity(named_material_length(&name, bytes.len(), 1)?, resources)?;
        let block = BorrowedPem::parse(bytes, resources.max_external_resource_bytes)?;
        validate_private_key_usages(usages)?;
        self.check_material_capacity(
            named_material_length(
                &name,
                bytes
                    .len()
                    .checked_add(block.decoded_len)
                    .ok_or(KeyStoreError::Selection("key material size overflow"))?,
                1,
            )?,
            resources,
        )?;
        let payload = match block.label {
            "PRIVATE KEY" => Payload::Plain,
            "ENCRYPTED PRIVATE KEY" => Payload::Encrypted,
            "RSA PRIVATE KEY" => Payload::Rsa,
            _ => return Err(KeyStoreError::Selection("unsupported private PEM label")),
        };
        let mut der = Zeroizing::new(vec![0; block.decoded_len]);
        block.decode_into(&mut der)?;
        // RFC 7468 sections 10/11 define distinct PKCS#8 labels. Section 2
        // permits reinterpretation, but our protected-key contract forbids it:
        // https://www.rfc-editor.org/rfc/rfc7468#section-2
        match payload {
            Payload::Encrypted => {
                EncryptedPrivateKeyInfoRef::try_from(der.as_slice())
                    .map_err(|_| KeyStoreError::ProtectedContainer)?;
            }
            Payload::Plain => {
                PrivateKeyInfoRef::try_from(der.as_slice())
                    .map_err(|_| KeyStoreError::Selection("invalid PRIVATE KEY payload"))?;
            }
            Payload::Rsa => preflight_rsa_pkcs1_components(&der)?,
        }
        let previous_total = self.material_bytes;
        let name_len = name.len();
        self.add_private_der_inner(name, &der, password, usages, resources, bytes.len())?;
        let retained_len = self.material_bytes - previous_total;
        self.material_bytes = previous_total + name_len + bytes.len().max(retained_len - name_len);
        Ok(())
    }

    /// Import a bounded PKCS#12 bundle from caller-owned bytes. Signing keys
    /// may sign; RSA keys may also decrypt; ML-KEM keys only decapsulate.
    /// A bundle with more than one private
    /// key is rejected rather than assigning names from iteration order.
    ///
    /// # Errors
    /// Returns resource/name refusal, unsupported or unauthenticated protection,
    /// invalid bundle contents, ambiguous private keys or incompatible key usages.
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
    ///
    /// # Errors
    /// Returns preflight resource/name/usage refusal, an absent password,
    /// protection/integrity failure or invalid/ambiguous private bundle contents.
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
        let contents = pkcs12_import::import(bytes, &limits, &mut self.kdf_work, password)?;
        self.add_pkcs12_contents(name, bytes.len(), contents, usages, resources, false)
    }

    /// Import a PKCS#12 bundle with explicit signing/decryption permissions.
    ///
    /// # Errors
    /// Returns resource/name/usage refusal, protection/integrity failure or
    /// invalid, unsupported or ambiguous private bundle contents.
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
        let contents =
            pkcs12_import::import(bytes, &limits, &mut self.kdf_work, || Some(password))?;
        self.add_pkcs12_contents(name, bytes.len(), contents, usages, resources, auto_decrypt)
    }

    fn add_pkcs12_contents(
        &mut self,
        name: String,
        encoded_len: usize,
        contents: pkcs12_import::Contents,
        mut usages: KeyUsages,
        resources: &ResourcePolicy,
        auto_decrypt: bool,
    ) -> Result<(), KeyStoreError> {
        // The importer refuses a second key; a key-less bundle is refused here.
        let private_key = contents.private_key.ok_or(KeyStoreError::Selection(
            "PKCS#12 bundle must contain exactly one private key",
        ))?;
        let mut certificates = contents.certificates;
        let identity = PrivateKeyIdentity::decode(&private_key)?;
        if auto_decrypt {
            usages = identity.automatic_usages();
        } else if usages.allows(KeyUsage::Decrypt) && !identity.can_decrypt() {
            return Err(KeyStoreError::Selection(
                "private key cannot recover encryption keys",
            ));
        }
        #[cfg(feature = "experimental-pq")]
        identity.validate_usages(usages)?;
        let mut matching_leaf = None;
        let session = crate::xmldsig::pkix::CertificateSession::new(resources);
        for certificate in &certificates {
            let parsed = session
                .read(certificate)
                .map_err(certificate_import_error)?;
            if identity.matches_spki(parsed.tbs().public_key().as_bytes()) {
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
        drop(identity);
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
        validate_private_key_usages(usages)?;
        if bytes.len() > resources.max_external_resource_bytes {
            return Err(KeyStoreError::Policy(
                crate::policy::PolicyViolation::ResourceLimitExceeded {
                    resource: crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
                    maximum: resources.max_external_resource_bytes,
                },
            ));
        }
        let retained_with_input =
            self.check_material_capacity(named_material_length(name, bytes.len(), 1)?, resources)?;
        let remaining_candidates = resources.max_key_candidates - self.entry_count;
        Ok(Pkcs12Limits {
            resources: resources.clone(),
            candidates: remaining_candidates,
            // Borrowing the PFX does not end its lifetime during decryption.
            memory_available: resources.max_external_resource_total_bytes - retained_with_input,
        })
    }
}

impl KeyInventory {
    fn check_new_name(&self, name: &str, resources: &ResourcePolicy) -> Result<(), KeyStoreError> {
        ensure_resource_policy(resources)?;
        if name.is_empty() {
            return Err(KeyStoreError::Selection("empty key name"));
        }
        if self.entry_count >= resources.max_key_candidates {
            return Err(import_resource_limit(
                crate::policy::resource_name::KEY_CANDIDATES,
                resources.max_key_candidates,
            ));
        }
        if name.len() > resources.max_external_resource_bytes {
            return Err(import_resource_limit(
                crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
                resources.max_external_resource_bytes,
            ));
        }
        self.check_material_capacity(name.len(), resources)?;
        if self.has_key_name(name) {
            return Err(KeyStoreError::Selection("duplicate key name"));
        }
        Ok(())
    }

    #[cfg(feature = "xmldsig-sign")]
    fn remaining_kdf_resources(
        &self,
        resources: &ResourcePolicy,
    ) -> Result<ResourcePolicy, KeyStoreError> {
        if self.kdf_work > resources.max_key_import_kdf_work {
            return Err(import_resource_limit(
                crate::policy::resource_name::KEY_IMPORT_KDF_WORK,
                resources.max_key_import_kdf_work,
            ));
        }
        let mut remaining = resources.clone();
        remaining.max_key_import_kdf_work -= self.kdf_work;
        Ok(remaining)
    }

    fn check_material_capacity(
        &self,
        length: usize,
        resources: &ResourcePolicy,
    ) -> Result<usize, KeyStoreError> {
        let total = self.material_bytes.checked_add(length).ok_or_else(|| {
            import_resource_limit(
                crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                resources.max_external_resource_total_bytes,
            )
        })?;
        if total > resources.max_external_resource_total_bytes {
            return Err(import_resource_limit(
                crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                resources.max_external_resource_total_bytes,
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
    ///
    /// # Errors
    /// Returns invalid resource configuration, candidate/material budget
    /// exhaustion or invalid certificate encoding/processing.
    pub fn add_certificate_der(
        &mut self,
        der: Vec<u8>,
        trusted_anchor: bool,
        resources: &ResourcePolicy,
    ) -> Result<(), KeyStoreError> {
        let material_bytes = self.preflight_x509_import(&der, resources)?;
        let session = crate::xmldsig::pkix::CertificateSession::new(resources);
        drop(session.read(&der).map_err(certificate_import_error)?);
        self.material_bytes = material_bytes;
        if trusted_anchor {
            self.trusted_certificates.push(der);
        } else {
            self.lookup_certificates.push(der);
        }
        self.entry_count += 1;
        Ok(())
    }

    /// Import a DER CRL for policy-controlled revocation checks.
    ///
    /// # Errors
    /// Returns invalid resource configuration, candidate/material budget
    /// exhaustion or invalid CRL encoding/processing.
    pub fn add_crl_der(
        &mut self,
        der: Vec<u8>,
        resources: &ResourcePolicy,
    ) -> Result<(), KeyStoreError> {
        let material_bytes = self.preflight_x509_import(&der, resources)?;
        let session = crate::xmldsig::pkix::CertificateSession::new(resources);
        drop(session.read_crl(&der).map_err(|error| match error {
            crate::xmldsig::X509ChainError::Policy(error) => KeyStoreError::Policy(error),
            _ => KeyStoreError::Selection("invalid X.509 CRL"),
        })?);
        self.material_bytes = material_bytes;
        self.crls.push(der);
        self.entry_count += 1;
        Ok(())
    }

    fn preflight_x509_import(
        &self,
        der: &[u8],
        resources: &ResourcePolicy,
    ) -> Result<usize, KeyStoreError> {
        // Policy exhaustion is terminal before any candidate-local DER work.
        ensure_resource_policy(resources)?;
        if der.len() > resources.max_external_resource_bytes {
            return Err(import_resource_limit(
                crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
                resources.max_external_resource_bytes,
            ));
        }
        if self.entry_count >= resources.max_key_candidates {
            return Err(import_resource_limit(
                crate::policy::resource_name::KEY_CANDIDATES,
                resources.max_key_candidates,
            ));
        }
        self.check_material_capacity(der.len(), resources)
    }
    /// Import caller-owned XML bytes under the operation's XML and resource snapshot.
    ///
    /// # Errors
    /// Returns malformed XML/key-store structure, parser policy/work refusal,
    /// unsupported/invalid key material or name/material/candidate budget failures.
    pub fn from_xml_bytes<P: crate::document::XmlDocumentPolicy>(
        bytes: &[u8],
        policy: &P,
        backend: XmlBackend,
    ) -> Result<Self, KeyStoreError> {
        let budget = XmlParseWorkBudget::from_resources(policy.resource_policy());
        Self::from_xml_bytes_with_budget(bytes, policy, backend, &budget, &mut 0, 0)
    }

    fn read_xml_store_entry(
        info: Node<'_, '_>,
        material_budget: &mut XmlImportMaterialBudget,
    ) -> Result<(String, ParsedMaterial), KeyStoreError> {
        let mut name = None;
        let mut value = None;
        for child in info.children().filter(Node::is_element) {
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
                let mut values = child.children().filter(Node::is_element);
                let key = values
                    .next()
                    .ok_or_else(|| KeyStoreError::Invalid("KeyValue has no key material".into()))?;
                if values.next().is_some() {
                    return Err(KeyStoreError::Invalid("ambiguous KeyValue".into()));
                }
                let material = if key.has_tag_name((XMLSEC_NS, "HMACKeyValue")) {
                    Some(SymmetricKeyKind::Hmac)
                } else if key.has_tag_name((XMLSEC_NS, "AESKeyValue")) {
                    Some(SymmetricKeyKind::Aes)
                } else if key.has_tag_name((XMLSEC_NS, "CamelliaKeyValue")) {
                    Some(SymmetricKeyKind::Camellia)
                } else if key.has_tag_name((XMLSEC_NS, "ChaCha20KeyValue")) {
                    Some(SymmetricKeyKind::ChaCha20)
                } else if key.has_tag_name((XMLSEC_NS, "DESKeyValue")) {
                    Some(SymmetricKeyKind::Des)
                } else {
                    None
                };
                value = Some(if let Some(kind) = material {
                    ParsedMaterial::Symmetric(kind, decode_xml_base64_secret(key)?)
                } else if key.has_tag_name((XMLDSIG_NS, "DSAKeyValue")) {
                    parse_xmlsec_dsa_key_value(key, material_budget)?
                } else if key.has_tag_name((XMLDSIG_NS, "RSAKeyValue"))
                    // XMLDSig 1.1 section 4.5.2.3 places ECKeyValue in dsig11:
                    // https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-ECKeyValue
                    || key.has_tag_name((XMLDSIG11_NS, "ECKeyValue"))
                {
                    ParsedMaterial::Public(
                        crate::xmldsig::parse::parse_key_value_dispatch(child)
                            .map_err(|error| KeyStoreError::Invalid(error.to_string()))?,
                    )
                } else {
                    ParsedMaterial::Unsupported
                });
            } else if child.has_tag_name((XMLDSIG11_NS, "DEREncodedKeyValue")) {
                // XMLDSig 1.1 §4.5.9: this contains base64 DER SPKI, not PKCS#8.
                // https://www.w3.org/TR/xmldsig-core1/#sec-DEREncodedKeyValue
                if value.is_some() {
                    return Err(KeyStoreError::Invalid("ambiguous key material".into()));
                }
                value = Some(ParsedMaterial::PublicDer(decode_xml_base64(child)?));
            } else {
                return Err(KeyStoreError::Invalid("unsupported KeyInfo child".into()));
            }
        }
        let name = name.ok_or_else(|| KeyStoreError::Invalid("missing KeyName".into()))?;
        let material = value.ok_or_else(|| KeyStoreError::Invalid("missing KeyValue".into()))?;
        Ok((name, material))
    }

    fn insert_xml_material(
        &mut self,
        name: String,
        material: ParsedMaterial,
        resources: &ResourcePolicy,
        session: &crate::xmldsig::pkix::CertificateSession,
    ) -> Result<(), KeyStoreError> {
        match material {
            ParsedMaterial::PublicDer(der) => {
                self.add_public_der_payload(
                    name,
                    der,
                    None,
                    resources,
                    PublicDerFormat::SubjectPublicKeyInfo,
                    session,
                )?;
            }
            ParsedMaterial::Symmetric(kind, bytes) => {
                if bytes.is_empty() {
                    return Err(KeyStoreError::Invalid("empty symmetric key".into()));
                }
                if matches!(kind, SymmetricKeyKind::Aes | SymmetricKeyKind::Camellia)
                    && !matches!(bytes.len(), 16 | 24 | 32)
                {
                    return Err(KeyStoreError::Invalid(
                        "invalid block-cipher key length".into(),
                    ));
                }
                if kind == SymmetricKeyKind::ChaCha20 && bytes.len() != 32 {
                    return Err(KeyStoreError::Invalid(
                        "ChaCha20 requires a 256-bit key".into(),
                    ));
                }
                let usages = match kind {
                    SymmetricKeyKind::Hmac => KeyUsages::SIGN.union(KeyUsages::VERIFY),
                    SymmetricKeyKind::Aes
                    | SymmetricKeyKind::Camellia
                    | SymmetricKeyKind::ChaCha20 => KeyUsages::ENCRYPT.union(KeyUsages::DECRYPT),
                    SymmetricKeyKind::Des => des_key_usages(&bytes)?,
                };
                self.symmetric_keys.push(StoredSymmetricKey {
                    name,
                    kind,
                    bytes,
                    usages,
                });
            }
            ParsedMaterial::Public(value) => {
                let mut key_info = KeyInfo::default();
                key_info.sources.push(KeyInfoSource::KeyName(name.clone()));
                key_info.sources.push(KeyInfoSource::KeyValue(value));
                let is_rsa = key_info
                    .sources
                    .iter()
                    .find_map(|source| match source {
                        KeyInfoSource::KeyValue(value) => Some(value),
                        _ => None,
                    })
                    .ok_or_else(|| KeyStoreError::Invalid("invalid public KeyValue".into()))?;
                let is_rsa = crate::xmldsig::keys::supported_key_value_is_rsa(session, is_rsa)
                    .map_err(|error| {
                        key_import_error(error, || {
                            KeyStoreError::Invalid("invalid public KeyValue".into())
                        })
                    })?;
                let usages = if is_rsa {
                    KeyUsages::VERIFY.union(KeyUsages::ENCRYPT)
                } else {
                    KeyUsages::VERIFY
                };
                self.public_keys.push(StoredPublicKey {
                    name,
                    key_info,
                    usages,
                });
            }
            ParsedMaterial::Dsa {
                public,
                #[cfg(feature = "xmldsig-sign")]
                private,
            } => {
                let key_info = dsa_store_key_info(&name, public, session)?;
                #[cfg(feature = "xmldsig-sign")]
                if let Some(der) = private {
                    self.private_keys.push(StoredPrivateKey {
                        name: name.clone(),
                        pkcs8_der: PrivateKeyDer::Owned(der),
                        usages: KeyUsages::SIGN,
                        certificate_chain: Vec::new(),
                        has_matching_leaf: false,
                    });
                }
                self.public_keys.push(StoredPublicKey {
                    name,
                    key_info,
                    usages: KeyUsages::VERIFY,
                });
            }
            ParsedMaterial::Unsupported => {}
        }
        Ok(())
    }

    fn from_xml_bytes_with_budget<P: crate::document::XmlDocumentPolicy>(
        bytes: &[u8],
        policy: &P,
        backend: XmlBackend,
        budget: &XmlParseWorkBudget,
        inspected: &mut usize,
        live_material: usize,
    ) -> Result<Self, KeyStoreError> {
        let resources = policy.resource_policy();
        ensure_resource_policy(resources)?;
        if bytes.len() > resources.max_external_resource_bytes {
            return Err(import_resource_limit(
                crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
                resources.max_external_resource_bytes,
            ));
        }
        if bytes.len() > resources.max_external_resource_total_bytes - live_material {
            return Err(import_resource_limit(
                crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                resources.max_external_resource_total_bytes,
            ));
        }
        let settings = DocumentParseSettings::from_policy(*policy.xml_input_policy(), resources)
            .with_backend(backend);
        let text = crate::document::decode_xml_with_budget(
            bytes,
            resources
                .max_xml_document_bytes
                .min(resources.max_external_resource_bytes),
            Some(budget),
        )
        .map_err(|error| match error.into_policy_violation(settings) {
            Ok(violation) => KeyStoreError::Policy(violation),
            Err(error) => KeyStoreError::Invalid(error.to_string()),
        })?;
        let document = parse_borrowed_with_settings_and_budget(&text, settings, Some(budget))
            .map_err(|error| match error.into_policy_violation(settings) {
                Ok(violation) => KeyStoreError::Policy(violation),
                Err(error) => KeyStoreError::Invalid(error.to_string()),
            })?;
        let root = document.root_element();
        if !root.has_tag_name((XMLSEC_NS, "Keys")) {
            return Err(KeyStoreError::Invalid("expected xmlsec Keys root".into()));
        }
        let mut material_budget = XmlImportMaterialBudget {
            used: live_material + bytes.len(),
            maximum: resources.max_external_resource_total_bytes,
        };
        let mut names = Set::new();
        let mut store = Self::default();
        let mut entry_count = 0_usize;
        // One account for every public key read while loading this store.
        let session = crate::xmldsig::pkix::CertificateSession::new(resources);
        for info in root.children().filter(Node::is_element) {
            if !info.has_tag_name((XMLDSIG_NS, "KeyInfo")) {
                return Err(KeyStoreError::Invalid("unexpected child of Keys".into()));
            }
            if *inspected >= resources.max_key_candidates {
                return Err(import_resource_limit(
                    crate::policy::resource_name::KEY_CANDIDATES,
                    resources.max_key_candidates,
                ));
            }
            *inspected += 1;
            entry_count += 1;
            preflight_xml_material(info, &mut material_budget)?;
            let (name, material) = Self::read_xml_store_entry(info, &mut material_budget)?;
            if !names.insert(name.clone()) {
                return Err(KeyStoreError::Invalid("duplicate key name".into()));
            }
            store.insert_xml_material(name, material, resources, &session)?;
        }
        store.entry_count = entry_count;
        // Decoding can retain both public components and a derived private key.
        // Keep the input charge too, so compact XML never lowers the import budget.
        store.material_bytes = bytes
            .len()
            .checked_add(store.retained_material_bytes()?)
            .ok_or(KeyStoreError::Selection("key material size overflow"))?;
        if store.material_bytes > resources.max_external_resource_total_bytes - live_material {
            return Err(import_resource_limit(
                crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                resources.max_external_resource_total_bytes,
            ));
        }
        Ok(store)
    }
}

/// Exhausting the import session while reading a key stays a policy violation.
fn key_import_error(
    error: crate::xmldsig::KeyResolutionError,
    otherwise: impl FnOnce() -> KeyStoreError,
) -> KeyStoreError {
    match error {
        crate::xmldsig::KeyResolutionError::Chain(crate::xmldsig::X509ChainError::Policy(
            error,
        )) => KeyStoreError::Policy(error),
        _ => otherwise(),
    }
}

/// The named `KeyInfo` of a store's public DSA tuple, once it resolves alone.
fn dsa_store_key_info(
    name: &str,
    public: KeyValueInfo,
    session: &crate::xmldsig::pkix::CertificateSession,
) -> Result<KeyInfo, KeyStoreError> {
    // This inventory has no external DSA parameter inheritance;
    // its stored public tuple must be independently resolvable.
    crate::xmldsig::keys::supported_key_value_is_rsa(session, &public).map_err(|error| {
        key_import_error(error, || {
            KeyStoreError::Invalid("invalid public DSAKeyValue".into())
        })
    })?;
    let mut key_info = KeyInfo::default();
    key_info
        .sources
        .push(KeyInfoSource::KeyName(name.to_owned()));
    key_info.sources.push(KeyInfoSource::KeyValue(public));
    Ok(key_info)
}

/// Whether DER is an SPKI naming an RFC 9935 ML-KEM parameter set. Exhausting
/// the shared import account is an error, never a format fallback.
#[cfg(feature = "experimental-pq")]
fn is_encapsulation_spki(
    session: &crate::xmldsig::pkix::CertificateSession,
    der: &[u8],
) -> Result<bool, KeyStoreError> {
    match session.with_public_key_info(der, |info, _| {
        Ok(crate::provider::KeyEncapsulationAlgorithm::from_oid_bytes(
            info.algorithm().algorithm().as_bytes(),
        )
        .is_some())
    }) {
        Ok(encapsulation) => Ok(encapsulation),
        Err(error) if error.is_resource() => Err(certificate_import_error(session.error(error))),
        Err(_) => Ok(false),
    }
}

fn certificate_import_error(error: crate::xmldsig::X509ChainError) -> KeyStoreError {
    match error {
        crate::xmldsig::X509ChainError::Policy(error) => KeyStoreError::Policy(error),
        _ => KeyStoreError::Selection("invalid X.509 certificate"),
    }
}

#[cfg(feature = "xmldsig-sign")]
fn validate_private_key_usages(usages: KeyUsages) -> Result<(), KeyStoreError> {
    let permitted = KeyUsages::SIGN.union(KeyUsages::DECRYPT);
    if usages.0 == 0 || usages.0 & !permitted.0 != 0 {
        return Err(KeyStoreError::Selection(
            "private key usage is incompatible",
        ));
    }
    Ok(())
}

fn import_resource_limit(resource: &'static str, maximum: usize) -> KeyStoreError {
    crate::policy::PolicyViolation::ResourceLimitExceeded { resource, maximum }.into()
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

#[cfg(feature = "xmldsig-sign")]
fn signing_policy_error(error: crate::xmldsig::SigningError) -> KeyStoreError {
    match error {
        crate::xmldsig::SigningError::Policy(violation) => violation.into(),
        _ => KeyStoreError::Selection("signing key violates operation policy"),
    }
}

fn ensure_resource_policy(resources: &ResourcePolicy) -> Result<(), KeyStoreError> {
    resources.validate().map_err(Into::into)
}

#[cfg(feature = "xmldsig-sign")]
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

// Public identity stays borrowed (RSA), native (DSA), or stack-sized (EC).
// Import validation must not serialize an unaccounted SPKI beside live input.
#[cfg(feature = "xmldsig-sign")]
#[cfg_attr(
    feature = "experimental-pq",
    expect(
        clippy::large_enum_variant,
        reason = "A transient, wire-bounded 2592-byte public key avoids a heap allocation during identity comparison"
    )
)]
enum PrivateKeyIdentity<'a> {
    Rsa(pkcs1::RsaPrivateKeyRef<'a>),
    #[cfg(feature = "experimental-pq")]
    Encapsulation {
        algorithm: pkcs8::AlgorithmIdentifierRef<'a>,
        public: [u8; 1568],
        length: usize,
    },
    Dsa {
        algorithm: pkcs8::AlgorithmIdentifierRef<'a>,
        key: NativeDsaSigningKey,
    },
    Ec {
        algorithm: pkcs8::AlgorithmIdentifierRef<'a>,
        point: [u8; 133],
        length: usize,
    },
    EdDsa {
        algorithm: pkcs8::AlgorithmIdentifierRef<'a>,
        public: [u8; 57],
        length: usize,
    },
    #[cfg(feature = "experimental-pq")]
    PostQuantum {
        algorithm: pkcs8::AlgorithmIdentifierRef<'a>,
        public: [u8; 2592],
        length: usize,
    },
}

#[cfg(feature = "xmldsig-sign")]
impl<'a> PrivateKeyIdentity<'a> {
    fn automatic_usages(&self) -> KeyUsages {
        match self {
            Self::Rsa(_) => KeyUsages::SIGN.union(KeyUsages::DECRYPT),
            #[cfg(feature = "experimental-pq")]
            Self::Encapsulation { .. } => KeyUsages::DECRYPT,
            _ => KeyUsages::SIGN,
        }
    }

    fn can_decrypt(&self) -> bool {
        match self {
            Self::Rsa(_) => true,
            #[cfg(feature = "experimental-pq")]
            Self::Encapsulation { .. } => true,
            _ => false,
        }
    }

    #[cfg(feature = "experimental-pq")]
    fn validate_usages(&self, usages: KeyUsages) -> Result<(), KeyStoreError> {
        if matches!(self, Self::Encapsulation { .. }) && usages != KeyUsages::DECRYPT {
            return Err(KeyStoreError::Selection(
                "ML-KEM private keys require DECRYPT-only usage",
            ));
        }
        Ok(())
    }

    fn decode(der: &'a [u8]) -> Result<Self, KeyStoreError> {
        let info = PrivateKeyInfoRef::try_from(der)
            .map_err(|_| KeyStoreError::Selection("unsupported PKCS#12 private key"))?;
        #[cfg(feature = "experimental-pq")]
        if crate::provider::KeyEncapsulationAlgorithm::from_oid(info.algorithm.oid).is_some() {
            let key = crate::provider::RustCryptoMlKemPrivateKey::from_pkcs8_der(der)
                .map_err(|_| KeyStoreError::Selection("invalid ML-KEM private key"))?;
            // RFC 9935 sections 4 and 6: bind every private form to the same
            // raw encapsulation-key identity, with absent ASN.1 parameters.
            // https://www.rfc-editor.org/rfc/rfc9935.html#section-6
            let mut public = [0; 1568];
            let length = key
                .copy_public(&mut public)
                .map_err(|_| KeyStoreError::Selection("invalid ML-KEM identity"))?;
            return Ok(Self::Encapsulation {
                algorithm: info.algorithm,
                public,
                length,
            });
        }
        #[cfg(feature = "experimental-pq")]
        if let Some(parameter) =
            crate::xmldsig::PqAlgorithm::from_oid(info.algorithm.oid.as_bytes())
        {
            let key = crate::xmldsig::PostQuantumSigningKey::from_pkcs8_der(parameter, der)
                .map_err(|_| KeyStoreError::Selection("invalid PQ private key"))?;
            // RFC 9881 section 4 / RFC 9909 section 5: identity is the raw
            // public bytes, not a separately allocated ASN.1 serialization.
            let mut public = [0; 2592];
            let length = key.copy_public(&mut public);
            return Ok(Self::PostQuantum {
                algorithm: info.algorithm,
                public,
                length,
            });
        }
        // RFC 8410 sections 3 and 7 require absent parameters and a nested
        // octet string: https://www.rfc-editor.org/rfc/rfc8410.html#section-7
        // Primitive decoding validates that contract before deriving identity.
        if info.algorithm.oid == der::asn1::ObjectIdentifier::new_unwrap("1.3.101.112") {
            let key = ed25519_dalek::SigningKey::from_pkcs8_der(der)
                .map_err(|_| KeyStoreError::Selection("invalid Ed25519 private key"))?;
            let mut public = [0; 57];
            public[..32].copy_from_slice(&key.verifying_key().to_bytes());
            return Ok(Self::EdDsa {
                algorithm: info.algorithm,
                public,
                length: 32,
            });
        }
        if info.algorithm.oid == der::asn1::ObjectIdentifier::new_unwrap("1.3.101.113") {
            let key = ed448_goldilocks::SigningKey::from_pkcs8_der(der)
                .map_err(|_| KeyStoreError::Selection("invalid Ed448 private key"))?;
            return Ok(Self::EdDsa {
                algorithm: info.algorithm,
                public: key.verifying_key().to_bytes(),
                length: 57,
            });
        }
        if info.algorithm.oid == pkcs1::ALGORITHM_OID {
            preflight_rsa_pkcs1_components(info.private_key.as_bytes())?;
            RsaPrivateKey::from_pkcs8_der(der)
                .map_err(|_| KeyStoreError::Selection("invalid RSA private key"))?;
            return pkcs1::RsaPrivateKeyRef::from_der(info.private_key.as_bytes())
                .map(Self::Rsa)
                .map_err(|_| KeyStoreError::Selection("invalid RSA private key"));
        } else if info.algorithm.oid == dsa::OID {
            let algorithm = info.algorithm;
            return crate::xmldsig::sign::decode_dsa_signing_key(info)
                .map(|key| Self::Dsa { algorithm, key })
                .map_err(|_| KeyStoreError::Selection("invalid or oversized DSA private key"));
        }
        macro_rules! try_ec {
            ($key:ty) => {
                if let Ok(key) = <$key>::from_pkcs8_der(der) {
                    use p256::elliptic_curve::sec1::ToSec1Point as _;
                    let encoded = key.public_key().to_sec1_point(false);
                    let bytes = encoded.as_bytes();
                    let mut point = [0; 133];
                    point[..bytes.len()].copy_from_slice(bytes);
                    return Ok(Self::Ec {
                        algorithm: info.algorithm,
                        point,
                        length: bytes.len(),
                    });
                }
            };
        }
        try_ec!(p256::SecretKey);
        try_ec!(p384::SecretKey);
        try_ec!(p521::SecretKey);
        Err(KeyStoreError::Selection("unsupported PKCS#12 private key"))
    }

    fn matches_spki(&self, der: &[u8]) -> bool {
        let Ok(spki) = pkcs8::SubjectPublicKeyInfoRef::from_der(der) else {
            return false;
        };
        let Some(bytes) = spki.subject_public_key.as_bytes() else {
            return false;
        };
        match self {
            #[cfg(feature = "experimental-pq")]
            Self::Encapsulation {
                algorithm,
                public,
                length,
            } => spki.algorithm == *algorithm && bytes == &public[..*length],
            #[cfg(feature = "experimental-pq")]
            Self::PostQuantum {
                algorithm,
                public,
                length,
            } => spki.algorithm == *algorithm && bytes == &public[..*length],
            Self::EdDsa {
                algorithm,
                public,
                length,
            } => spki.algorithm == *algorithm && bytes == &public[..*length],
            Self::Rsa(key) => {
                if spki.algorithm != pkcs1::ALGORITHM_ID {
                    return false;
                }
                let Ok(public) = pkcs1::RsaPublicKeyRef::from_der(bytes) else {
                    return false;
                };
                key.modulus == public.modulus && key.public_exponent == public.public_exponent
            }
            Self::Dsa { algorithm, key } => {
                if spki.algorithm != *algorithm {
                    return false;
                }
                let Ok(y) = der::asn1::UintRef::from_der(bytes) else {
                    return false;
                };
                // Compare native little-endian limbs as a byte iterator, without
                // materializing a second big integer or owned public encoding.
                key.verifying_key()
                    .y()
                    .as_words()
                    .iter()
                    .rev()
                    .flat_map(|word| word.to_be_bytes())
                    .skip_while(|byte| *byte == 0)
                    .eq(y.as_bytes().iter().copied())
            }
            Self::Ec {
                algorithm,
                point,
                length,
            } => spki.algorithm == *algorithm && bytes == &point[..*length],
        }
    }
}

/// Validate borrowed PKCS#1 private components against process-safety ceilings.
///
/// Container adapters must call this before constructing native big integers.
/// This checks ingestion safety, not the operation's RSA algorithm/key policy.
///
/// # Errors
/// Returns malformed RSA DER or an above-ceiling modulus/component width
/// before native bigint decoding.
#[cfg(feature = "xmldsig-sign")]
pub fn preflight_rsa_pkcs1_components(der: &[u8]) -> Result<(), KeyStoreError> {
    let key = pkcs1::RsaPrivateKeyRef::from_der(der)
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

#[cfg(feature = "xmldsig-sign")]
fn preflight_dsa_pkcs8_components(info: &PrivateKeyInfoRef<'_>) -> Result<(), KeyStoreError> {
    crate::xmldsig::sign::preflight_dsa_private_key(info)
        .map_err(|_| KeyStoreError::Selection("invalid or oversized DSA private key"))
}

// Borrow the frame and stream whitespace-separated Base64 into one preflighted
// DER buffer. No normalized Base64 string or owned label/header copies are needed.
struct BorrowedPem<'a> {
    label: &'a str,
    data: &'a str,
    decoded_len: usize,
}

impl<'a> BorrowedPem<'a> {
    fn parse(bytes: &'a [u8], maximum: usize) -> Result<Self, KeyStoreError> {
        if bytes.len() > maximum {
            return Err(import_resource_limit(
                crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
                maximum,
            ));
        }
        let invalid = || KeyStoreError::Selection("invalid PEM key");
        let text = core::str::from_utf8(bytes)
            .map_err(|_| invalid())?
            .trim_matches(|character: char| character.is_ascii_whitespace());
        let (label, rest) = text
            .strip_prefix("-----BEGIN ")
            .and_then(|rest| rest.split_once("-----"))
            .ok_or_else(invalid)?;
        let (payload, end) = rest
            .trim_start_matches([' ', '\t', '\n', '\r'])
            .split_once("-----END ")
            .ok_or_else(invalid)?;
        if end.strip_prefix(label) != Some("-----") || payload.contains("-----BEGIN ") {
            return Err(KeyStoreError::Selection(
                "PEM must contain one complete block",
            ));
        }
        // Preserve the existing importer's optional header and whitespace
        // acceptance without allocating header strings or a stripped body.
        let data = if let Some((headers, data)) = payload
            .split_once("\n\n")
            .or_else(|| payload.split_once("\r\n\r\n"))
        {
            if headers.lines().any(|line| !line.contains(':')) {
                return Err(invalid());
            }
            data
        } else {
            payload
        };
        let mut characters = 0_usize;
        let mut padding = 0_usize;
        for part in data.split_whitespace() {
            for byte in part.bytes() {
                if byte == b'=' {
                    padding += 1;
                } else if padding != 0
                    || !matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/')
                {
                    return Err(invalid());
                }
                characters += 1;
            }
        }
        if !characters.is_multiple_of(4) || padding > 2 {
            return Err(invalid());
        }
        let decoded_len = (characters / 4 * 3)
            .checked_sub(padding)
            .ok_or_else(invalid)?;
        Ok(Self {
            label,
            data,
            decoded_len,
        })
    }

    fn decode(&self) -> Result<Vec<u8>, KeyStoreError> {
        let mut decoded = vec![0; self.decoded_len];
        self.decode_into(&mut decoded)?;
        Ok(decoded)
    }

    fn decode_into(&self, output: &mut [u8]) -> Result<(), KeyStoreError> {
        // `parse` admitted whole quartets with padding only at the end.
        crate::xmldsig::whitespace::decode_base64_into(
            self.data.split_whitespace().flat_map(str::bytes),
            output,
        )
        .map_err(|_| KeyStoreError::Selection("invalid PEM key"))
    }
}

#[cfg(all(test, feature = "xmldsig-sign"))]
fn single_pem_block(bytes: &[u8], maximum: usize) -> Result<pem::Pem, KeyStoreError> {
    if bytes.len() > maximum {
        return Err(import_resource_limit(
            crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
            maximum,
        ));
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

#[cfg(feature = "xmldsig-sign")]
fn enforce_pkcs8_kdf_policy(
    encrypted: &EncryptedPrivateKeyInfoRef<'_>,
    resources: &ResourcePolicy,
    retained_with_input: usize,
) -> Result<usize, KeyStoreError> {
    use pkcs8::pkcs5::{
        EncryptionScheme,
        pbes2::{Kdf, Pbkdf2Prf},
    };
    // RFC 8018 §6.2 leaves KDF iteration policy to the application. Reject
    // excessive work before decrypting attacker-supplied containers.
    // https://www.rfc-editor.org/rfc/rfc8018#section-6.2
    let EncryptionScheme::Pbes2(params) = &encrypted.encryption_algorithm else {
        return Err(KeyStoreError::ProtectedContainer);
    };
    // PBES2 decryption mutates a ciphertext-sized output buffer while the
    // encoded input remains live. Include that capacity before any password
    // callback or KDF, including failed padding/DER decoding.
    let live_with_output =
        retained_with_input.checked_add(encrypted.encrypted_data.as_bytes().len());
    if live_with_output.is_none_or(|total| total > resources.max_external_resource_total_bytes) {
        return Err(kdf_policy_violation(
            crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
            resources.max_external_resource_total_bytes,
            live_with_output.map(|total| total as u64),
        ));
    }
    let live_with_output = live_with_output.ok_or(KeyStoreError::ProtectedContainer)?;
    let work = match &params.kdf {
        Kdf::Pbkdf2(kdf) => {
            if kdf.iteration_count == 0 {
                return Err(KeyStoreError::ProtectedContainer);
            }
            let hash_len = match kdf.prf {
                Pbkdf2Prf::HmacWithSha1 => 20,
                Pbkdf2Prf::HmacWithSha224 => 28,
                Pbkdf2Prf::HmacWithSha256 => 32,
                Pbkdf2Prf::HmacWithSha384 => 48,
                Pbkdf2Prf::HmacWithSha512 => 64,
                _ => return Err(KeyStoreError::ProtectedContainer),
            };
            // RFC 8018 5.2 steps 2-3: every ceil(dkLen/hLen) block runs c
            // PRFs. The cipher determines dkLen, not a caller's KDF hint.
            // https://www.rfc-editor.org/rfc/rfc8018#section-5.2
            let blocks = params.encryption.key_size().div_ceil(hash_len) as u64;
            let work = u64::from(kdf.iteration_count).checked_mul(blocks);
            if work.is_none_or(|work| work > resources.max_key_import_kdf_work as u64) {
                return Err(kdf_policy_violation(
                    crate::policy::resource_name::KEY_IMPORT_KDF_WORK,
                    resources.max_key_import_kdf_work,
                    work,
                ));
            }
            usize::try_from(work.ok_or(KeyStoreError::ProtectedContainer)?)
                .expect("admitted PBKDF2 work fits the usize policy bound")
        }
        Kdf::Scrypt(kdf) => enforce_scrypt_kdf_limits(
            kdf.cost_parameter,
            u64::from(kdf.block_size),
            u64::from(kdf.parallelization),
            resources,
            live_with_output,
        )?,
        _ => return Err(KeyStoreError::ProtectedContainer),
    };
    Ok(work)
}

#[cfg(feature = "xmldsig-sign")]
fn enforce_pkcs8_password_policy(
    encrypted: &EncryptedPrivateKeyInfoRef<'_>,
    password: &[u8],
    resources: &ResourcePolicy,
    live_bytes: usize,
) -> Result<usize, KeyStoreError> {
    if password.len() > resources.max_external_resource_bytes {
        return Err(kdf_policy_violation(
            crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
            resources.max_external_resource_bytes,
            Some(password.len() as u64),
        ));
    }
    let live = live_bytes.checked_add(password.len()).ok_or_else(|| {
        import_resource_limit(
            crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
            resources.max_external_resource_total_bytes,
        )
    })?;
    // Product work accounting: one unit per 64 input bytes conservatively
    // covers password hashing for the supported SHA PRFs, in addition to rounds.
    let hashing_passes = match &encrypted.encryption_algorithm {
        pkcs8::pkcs5::EncryptionScheme::Pbes2(params)
            if matches!(&params.kdf, pkcs8::pkcs5::pbes2::Kdf::Scrypt(_)) =>
        {
            2
        }
        _ => 1,
    };
    // Scrypt initializes password-keyed HMAC both before and after ROMix.
    let password_work = password.len().div_ceil(64) * hashing_passes;
    if password_work > resources.max_key_import_kdf_work {
        return Err(kdf_policy_violation(
            crate::policy::resource_name::KEY_IMPORT_KDF_WORK,
            resources.max_key_import_kdf_work,
            Some(password_work as u64),
        ));
    }
    let mut remaining = resources.clone();
    remaining.max_key_import_kdf_work -= password_work;
    enforce_pkcs8_kdf_policy(encrypted, &remaining, live)
        .map(|work| work + password_work)
        .map_err(|error| match error {
            KeyStoreError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::KEY_IMPORT_KDF_WORK,
                actual,
                ..
            }) => kdf_policy_violation(
                crate::policy::resource_name::KEY_IMPORT_KDF_WORK,
                resources.max_key_import_kdf_work,
                Some(actual.saturating_add(password_work) as u64),
            ),
            error => error,
        })
}

#[cfg(feature = "xmldsig-sign")]
fn enforce_scrypt_kdf_limits(
    n: u64,
    r: u64,
    p: u64,
    resources: &ResourcePolicy,
    retained_with_input: usize,
) -> Result<usize, KeyStoreError> {
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
    // The workspace is live alongside the existing inventory, name and
    // imported container. An independent KDF ceiling cannot waive that peak.
    let total = memory.and_then(|memory| memory.checked_add(retained_with_input as u64));
    if total.is_none_or(|total| total > resources.max_external_resource_total_bytes as u64) {
        return Err(kdf_policy_violation(
            crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
            resources.max_external_resource_total_bytes,
            total,
        ));
    }
    // The work check above proves this value exists and fits the usize ceiling.
    Ok(
        usize::try_from(work.ok_or(KeyStoreError::ProtectedContainer)?)
            .expect("admitted scrypt work fits the usize policy bound"),
    )
}

#[cfg(feature = "xmldsig-sign")]
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
    let length = node
        .children()
        .filter(Node::is_text)
        .filter_map(Node::text)
        .map(str::len)
        .sum();
    let mut text = String::with_capacity(length);
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
    xml_base64_payload(node)?
        .decode()
        .map_err(|reason| KeyStoreError::Invalid(reason.into()))
}

fn decode_xml_base64_secret(node: Node<'_, '_>) -> Result<Zeroizing<Vec<u8>>, KeyStoreError> {
    let payload = xml_base64_payload(node)?;
    // Own the zeroizing guard before decoding: malformed trailing bits can
    // fail after part of the secret has already been written into the buffer.
    let mut output = Zeroizing::new(vec![0; payload.decoded_len]);
    payload
        .decode_into(&mut output)
        .map_err(|reason| KeyStoreError::Invalid(reason.into()))?;
    Ok(output)
}

fn xml_base64_payload<'a, 'input>(
    node: Node<'a, 'input>,
) -> Result<crate::xmldsig::whitespace::XmlBase64Payload<'a, 'input>, KeyStoreError> {
    crate::xmldsig::whitespace::XmlBase64Payload::new(node)
        .map_err(|reason| KeyStoreError::Invalid(reason.into()))
}

struct XmlImportMaterialBudget {
    used: usize,
    maximum: usize,
}

impl XmlImportMaterialBudget {
    fn reserve(&mut self, length: usize) -> Result<(), KeyStoreError> {
        if self.used > self.maximum || length > self.maximum - self.used {
            return Err(import_resource_limit(
                crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                self.maximum,
            ));
        }
        self.used += length;
        Ok(())
    }
}

fn preflight_xml_material(
    info: Node<'_, '_>,
    budget: &mut XmlImportMaterialBudget,
) -> Result<(), KeyStoreError> {
    // The source remains live while decoded entries and cloned names are
    // retained. Charge them before importing any entry, including failed ones.
    let key = info
        .children()
        .find(|child| child.has_tag_name((XMLDSIG_NS, "KeyValue")))
        .and_then(|value| value.children().find(Node::is_element));
    let has_der = info
        .children()
        .any(|child| child.has_tag_name((XMLDSIG11_NS, "DEREncodedKeyValue")));
    let name_copies = match key {
        Some(key) if key.has_tag_name((XMLDSIG_NS, "DSAKeyValue")) => {
            if key
                .children()
                .any(|child| child.has_tag_name((XMLSEC_NS, "X")))
            {
                4
            } else {
                3
            }
        }
        Some(key)
            if key.has_tag_name((XMLDSIG_NS, "RSAKeyValue"))
                || key.has_tag_name((XMLDSIG11_NS, "ECKeyValue")) =>
        {
            3
        }
        _ if has_der => 3,
        _ => 2,
    };
    let uses_shared_public_parser = has_der
        || key.is_some_and(|key| {
            key.has_tag_name((XMLDSIG_NS, "RSAKeyValue"))
                || key.has_tag_name((XMLDSIG11_NS, "ECKeyValue"))
        });
    if uses_shared_public_parser {
        crate::xmldsig::parse::validate_key_info_container(info)
            .map_err(|error| KeyStoreError::Invalid(error.to_string()))?;
    }
    for child in info.children().filter(Node::is_element) {
        if child.has_tag_name((XMLDSIG_NS, "KeyName")) {
            let length = child
                .children()
                .filter(Node::is_text)
                .filter_map(Node::text)
                .try_fold(0_usize, |sum, text| {
                    sum.checked_add(text.len())
                        .ok_or(KeyStoreError::Selection("key material size overflow"))
                })?;
            // Inventory, duplicate-name set, KeyInfo and private DSA name.
            if uses_shared_public_parser && length > crate::xmldsig::parse::MAX_KEY_NAME_TEXT_LEN {
                return Err(KeyStoreError::Invalid(
                    "KeyName exceeds maximum allowed text length".into(),
                ));
            }
            for _ in 0..name_copies {
                budget.reserve(length)?;
            }
        } else if child.has_tag_name((XMLDSIG11_NS, "DEREncodedKeyValue")) {
            let payload = xml_base64_payload(child)?;
            budget.reserve(payload.decoded_len)?;
        } else if child.has_tag_name((XMLDSIG_NS, "KeyValue")) {
            for key in child.children().filter(Node::is_element) {
                if key.has_tag_name((XMLSEC_NS, "HMACKeyValue"))
                    || key.has_tag_name((XMLSEC_NS, "AESKeyValue"))
                    || key.has_tag_name((XMLSEC_NS, "DESKeyValue"))
                {
                    budget.reserve(xml_base64_payload(key)?.decoded_len)?;
                } else if key.has_tag_name((XMLDSIG_NS, "RSAKeyValue"))
                    || key.has_tag_name((XMLDSIG_NS, "DSAKeyValue"))
                    || key.has_tag_name((XMLDSIG11_NS, "ECKeyValue"))
                {
                    for component in key.children().filter(Node::is_element) {
                        if component.has_tag_name((XMLDSIG11_NS, "NamedCurve")) {
                            budget.reserve(component.attribute("URI").map_or(0, str::len))?;
                        } else {
                            budget.reserve(xml_base64_payload(component)?.decoded_len)?;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(feature = "xmldsig-sign")]
fn encode_xmlsec_dsa_private(
    modulus: &[u8],
    order: &[u8],
    generator: &[u8],
    public_value: &[u8],
    secret: &[u8],
    budget: &mut XmlImportMaterialBudget,
) -> Result<Zeroizing<Vec<u8>>, KeyStoreError> {
    use der::Encode as _;

    let components = DsaComponents::from_components(
        BoxedUint::from_be_slice_vartime(modulus),
        BoxedUint::from_be_slice_vartime(order),
        BoxedUint::from_be_slice_vartime(generator),
    )
    .map_err(|_| KeyStoreError::Invalid("invalid DSA parameters".into()))?;
    let x_value = BoxedUint::from_be_slice_vartime(secret);
    let monty = BoxedMontyParams::new(components.p().clone());
    let expected_y = BoxedMontyForm::new((**components.g()).clone(), &monty)
        .pow(&x_value)
        .retrieve();
    if expected_y != BoxedUint::from_be_slice_vartime(public_value) {
        return Err(KeyStoreError::Invalid(
            "DSA private and public values differ".into(),
        ));
    }
    let public = DsaVerifyingKey::from_components(components, expected_y)
        .map_err(|_| KeyStoreError::Invalid("invalid DSA public key".into()))?;
    let private = NativeDsaSigningKey::from_components(public, x_value)
        .map_err(|_| KeyStoreError::Invalid("invalid DSA private key".into()))?;
    // The native encoder owns parameter DER, padded X bytes, X DER and
    // PKCS#8 DER concurrently; the retained copy also exists before return.
    let parameters_len = usize::try_from(
        private
            .verifying_key()
            .components()
            .encoded_len()
            .map_err(|_| KeyStoreError::Invalid("DSA private key encoding failed".into()))?,
    )
    .map_err(|_| KeyStoreError::Selection("key material size overflow"))?;
    let x_bytes_len = usize::try_from(private.x().bits_precision() / 8)
        .map_err(|_| KeyStoreError::Selection("key material size overflow"))?;
    // DER length headers and the PKCS#8 algorithm identifier fit this
    // checked bound: each header is at most 1 tag + 1 count + sizeof(usize).
    let header = 2 + core::mem::size_of::<usize>();
    let x_der_len = x_bytes_len
        .checked_add(header + 1)
        .ok_or(KeyStoreError::Selection("key material size overflow"))?;
    let pkcs8_len = parameters_len
        .checked_add(x_der_len)
        .and_then(|length| length.checked_add(4 * header + 16))
        .ok_or(KeyStoreError::Selection("key material size overflow"))?;
    budget.reserve(parameters_len)?;
    budget.reserve(x_bytes_len)?;
    budget.reserve(x_der_len)?;
    budget.reserve(pkcs8_len)?;
    budget.reserve(pkcs8_len)?;
    Ok(Zeroizing::new(
        private
            .to_pkcs8_der()
            .map_err(|_| KeyStoreError::Invalid("DSA private key encoding failed".into()))?
            .as_bytes()
            .to_vec(),
    ))
}

fn parse_xmlsec_dsa_key_value(
    node: Node<'_, '_>,
    budget: &mut XmlImportMaterialBudget,
) -> Result<ParsedMaterial, KeyStoreError> {
    let mut p = None;
    let mut q = None;
    let mut g = None;
    let mut y = None;
    let mut seed = None;
    let mut counter = None;
    let mut private_x = None;
    let mut previous_position = None;
    for child in node.children().filter(Node::is_element) {
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
            private_x = Some(decode_xml_base64_secret(child)?);
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
    #[cfg(feature = "xmldsig-sign")]
    let private = if let Some(x) = private_x {
        let (Some(p), Some(q), Some(g)) = (&p, &q, &g) else {
            return Err(KeyStoreError::Invalid(
                "private DSA key requires P, Q, and G".into(),
            ));
        };
        Some(encode_xmlsec_dsa_private(p, q, g, &y, &x, budget)?)
    } else {
        None
    };
    // A verification-only inventory keeps the public tuple and wipes X.
    #[cfg(not(feature = "xmldsig-sign"))]
    drop((private_x, budget));
    Ok(ParsedMaterial::Dsa {
        public: KeyValueInfo::Dsa { p, q, g, y },
        #[cfg(feature = "xmldsig-sign")]
        private,
    })
}

// The inventory tests import private keys and select signers.
#[cfg(all(test, feature = "xmldsig-sign"))]
mod tests;
