//! Agreement metadata remains separate from application-owned private keys.

use crate::policy::{KeyAgreementAlgorithm, ResourcePolicy};
use crate::provider::{KdfContext, KdfParameters, KeyAgreementParameters};
use crate::xml::dom::Node;
use crate::xmldsig::parse::{KeyInfo, KeyInfoParsingSession};

use super::parse::{decode_bounded_base64_text, require_element, validate_metadata_len};
use super::types::{XMLDSIG_NS, XMLENC_NS, XMLENC11_NS};
use super::{KeyDerivationMethod, XmlEncError};

/// Public agreement descriptor. Key information is advisory; a document never
/// supplies the application's private handle or chooses its security profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgreementMethod {
    /// Exact agreement mechanism, independently permission checked at execution.
    pub algorithm: KeyAgreementAlgorithm,
    /// Explicit derivation; omission requires application knowledge except for
    /// the legacy DH algorithm, whose derivation is specified by its URI.
    pub method: Option<KeyDerivationMethod>,
    /// Public agreement nonce, retained in the trusted descriptor comparison.
    /// Legacy DH incorporates it directly; explicit KDFs use their own context
    /// fields rather than an undocumented nonce concatenation.
    pub nonce: Vec<u8>,
    /// Optional legacy DH digest. No default digest is guessed.
    pub legacy_digest: Option<String>,
    /// Originator public key or application lookup hints in the original role.
    pub originator: Option<KeyInfo>,
    /// Recipient lookup hints, never permission to substitute a private key.
    pub recipient: Option<KeyInfo>,
}

impl AgreementMethod {
    /// Establish a consuming key with explicitly bound private and peer keys.
    /// The caller validates party identities before invoking this method.
    pub fn derive_key(
        &self,
        consuming_algorithm: &str,
        output_len: usize,
        key: &dyn crate::provider::KeyAgreementKey,
        peer: &[u8],
        provider: &dyn crate::provider::CryptoProvider,
        budget: &mut super::KeyEstablishmentBudget<'_>,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, XmlEncError> {
        let agreement = KeyAgreementParameters {
            algorithm: self.algorithm.uri(),
            peer_public_key: peer,
        };
        let parameters = self.parameters(consuming_algorithm, output_len)?;
        budget.agree_and_derive(provider, key, &agreement, &parameters)
    }

    pub(super) fn parameters<'a>(
        &'a self,
        consuming_algorithm: &'a str,
        output_len: usize,
    ) -> Result<KdfParameters<'a>, XmlEncError> {
        if self.algorithm == KeyAgreementAlgorithm::LegacyDh {
            // XMLEnc 1.1 §5.6.2.2 binds EncryptionMethod's URI, not the
            // agreement URI, and its nonce/decimal consuming key width.
            // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-DHKeyAgreementLegacyKDF
            return Ok(KdfParameters {
                algorithm: self.algorithm.uri(),
                digest: self.legacy_digest.as_deref(),
                salt: &[],
                info: KdfContext::LegacyDh {
                    encryption_algorithm: consuming_algorithm,
                    nonce: &self.nonce,
                },
                iterations: 0,
                output_len,
            });
        }
        // XMLEnc 1.1 sections 5.4.1 and 5.6 define explicit KDF inputs but
        // do not define an additional KA-Nonce-to-OtherInfo concatenation.
        // Preserve the nonce in descriptor identity; applications requiring
        // fresh explicit-KDF output must also vary its declared context/salt.
        // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-ConcatKDF
        // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-Alg-KeyAgreement
        self.method
            .as_ref()
            .ok_or(XmlEncError::MissingRequired(
                "agreement key derivation method",
            ))?
            .parameters(output_len)
    }
}

pub(super) fn parse(
    node: Node<'_, '_>,
    resources: &ResourcePolicy,
    key_info: &mut KeyInfoParsingSession<'_>,
    provider: &dyn crate::provider::CryptoProvider,
) -> Result<AgreementMethod, XmlEncError> {
    require_element(node, XMLENC_NS, "AgreementMethod")?;
    let algorithm = node
        .attribute("Algorithm")
        .ok_or(XmlEncError::MissingRequired("AgreementMethod Algorithm"))?;
    validate_metadata_len(algorithm.len(), resources.max_encryption_metadata_bytes)?;
    let algorithm = KeyAgreementAlgorithm::from_uri(algorithm)
        .ok_or_else(|| XmlEncError::UnsupportedAlgorithm(algorithm.into()))?;
    let mut result = AgreementMethod {
        algorithm,
        method: None,
        nonce: Vec::new(),
        legacy_digest: None,
        originator: None,
        recipient: None,
    };
    let mut phase = 0;
    let mut nonce_seen = false;
    // XMLEnc 1.1 §5.6: AgreementMethodType is mixed=true. Only element
    // sequence is constrained; non-whitespace text is not a schema error.
    // Unlike libxmlsec1 KAMRead, the two KeyInfoType roles are optional.
    // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-Alg-KeyAgreement
    for child in node.children().filter(Node::is_element) {
        match (child.tag_name().namespace(), child.tag_name().name()) {
            (Some(XMLENC_NS), "KA-Nonce") if phase == 0 && !nonce_seen => {
                result.nonce = decode_bounded_base64_text(
                    child,
                    "KA-Nonce",
                    resources.max_encryption_metadata_bytes,
                )?;
                nonce_seen = true;
            }
            (Some(XMLENC11_NS), "KeyDerivationMethod") if phase <= 1 && result.method.is_none() => {
                result.method = Some(super::key_derivation::parse_node(
                    child,
                    resources.max_encryption_metadata_bytes,
                )?);
                phase = 1;
            }
            (Some(XMLDSIG_NS), "DigestMethod") if phase <= 1 && result.legacy_digest.is_none() => {
                if algorithm != KeyAgreementAlgorithm::LegacyDh
                    || child.children().any(|node| node.is_element())
                {
                    return Err(invalid(
                        "DigestMethod is only defined for legacy DH agreement",
                    ));
                }
                let digest = child
                    .attribute("Algorithm")
                    .ok_or(XmlEncError::MissingRequired("DigestMethod Algorithm"))?;
                validate_metadata_len(digest.len(), resources.max_encryption_metadata_bytes)?;
                result.legacy_digest = Some(digest.into());
                phase = 1;
            }
            (Some(XMLENC_NS), "OriginatorKeyInfo") if phase <= 1 => {
                key_info
                    .preflight_agreement_role_candidates(child)
                    .map_err(map_key_info_error)?;
                preflight_role_metadata(child, resources.max_encryption_metadata_bytes)?;
                result.originator = Some(
                    key_info
                        .parse_agreement_role(child, provider)
                        .map_err(map_key_info_error)?,
                );
                phase = 2;
            }
            (Some(XMLENC_NS), "RecipientKeyInfo") if phase <= 2 => {
                key_info
                    .preflight_agreement_role_candidates(child)
                    .map_err(map_key_info_error)?;
                preflight_role_metadata(child, resources.max_encryption_metadata_bytes)?;
                result.recipient = Some(
                    key_info
                        .parse_agreement_role(child, provider)
                        .map_err(map_key_info_error)?,
                );
                phase = 3;
            }
            (Some(namespace), _) if namespace != XMLENC_NS && phase <= 1 => {
                // The schema's ##other extension point permits unrelated
                // metadata. Recognized duplicate parameters must not fall here.
                if child.has_tag_name((XMLENC11_NS, "KeyDerivationMethod"))
                    || child.has_tag_name((XMLDSIG_NS, "DigestMethod"))
                {
                    return Err(invalid("duplicate agreement parameter"));
                }
                phase = 1;
            }
            _ => return Err(invalid("unexpected or unordered AgreementMethod child")),
        }
    }
    if algorithm == KeyAgreementAlgorithm::LegacyDh && result.method.is_some() {
        return Err(invalid("legacy DH URI fixes the derivation algorithm"));
    }
    Ok(result)
}

fn invalid(message: &str) -> XmlEncError {
    XmlEncError::InvalidStructure(message.into())
}

fn preflight_role_metadata(node: Node<'_, '_>, maximum: usize) -> Result<(), XmlEncError> {
    for child in node.descendants().filter(Node::is_element) {
        for attribute in child.attributes() {
            validate_metadata_len(attribute.value().len(), maximum)?;
        }
        if child.children().any(|node| node.is_element()) {
            continue;
        }
        let binary = matches!(
            (child.tag_name().namespace(), child.tag_name().name()),
            (
                Some(XMLDSIG_NS),
                "Modulus"
                    | "Exponent"
                    | "P"
                    | "Q"
                    | "G"
                    | "Y"
                    | "J"
                    | "Seed"
                    | "PgenCounter"
                    | "X509Certificate"
                    | "X509CRL"
                    | "X509SKI",
            ) | (
                Some(XMLENC_NS),
                "P" | "Q" | "Generator" | "Public" | "seed" | "pgenCounter"
            ) | (
                Some(crate::xmldsig::parse::XMLDSIG11_NS),
                "PublicKey" | "DEREncodedKeyValue" | "X509Digest",
            )
        );
        if binary {
            let payload = crate::xmldsig::whitespace::XmlBase64Payload::bounded(
                child,
                usize::MAX,
                usize::MAX,
            )
            .map_err(|_| invalid("invalid agreement key binary metadata"))?;
            validate_metadata_len(payload.decoded_len, maximum)?;
        } else if child.tag_name().namespace() == Some(XMLDSIG_NS)
            && matches!(
                child.tag_name().name(),
                "KeyName" | "X509SubjectName" | "X509IssuerName" | "X509SerialNumber" | "XPath"
            )
        {
            let mut length = 0usize;
            for text in child
                .children()
                .filter(Node::is_text)
                .filter_map(|node| node.text())
            {
                length = length
                    .checked_add(text.len())
                    .ok_or_else(|| invalid("agreement metadata length overflow"))?;
                validate_metadata_len(length, maximum)?;
            }
        }
    }
    Ok(())
}

pub(super) fn validate_role_metadata(info: &KeyInfo, maximum: usize) -> Result<(), XmlEncError> {
    use crate::xmldsig::parse::{KeyInfoSource, KeyValueInfo, RetrievalMethodTransforms};
    let check = |bytes: &[u8]| validate_metadata_len(bytes.len(), maximum);
    let check_optional = |bytes: &Option<Vec<u8>>| check(bytes.as_deref().unwrap_or(&[]));
    for source in &info.sources {
        match source {
            KeyInfoSource::KeyName(value) | KeyInfoSource::KeyInfoReference { uri: value } => {
                check(value.as_bytes())?
            }
            KeyInfoSource::DerEncodedKeyValue(value) => check(value)?,
            KeyInfoSource::KeyValue(value) => match value {
                KeyValueInfo::Dh {
                    p,
                    q,
                    generator,
                    public,
                    seed,
                    pgen_counter,
                } => {
                    for bytes in [p, q, generator, seed, pgen_counter] {
                        check_optional(bytes)?;
                    }
                    check(public)?;
                }
                KeyValueInfo::Dsa { p, q, g, y } => {
                    for bytes in [p, q, g] {
                        check_optional(bytes)?;
                    }
                    check(y)?;
                }
                KeyValueInfo::Rsa { modulus, exponent } => {
                    check(modulus)?;
                    check(exponent)?;
                }
                KeyValueInfo::Ec {
                    curve_oid,
                    public_key,
                } => {
                    check(curve_oid.as_bytes())?;
                    check(public_key)?;
                }
                KeyValueInfo::Unsupported {
                    namespace,
                    local_name,
                } => {
                    if let Some(namespace) = namespace {
                        check(namespace.as_bytes())?;
                    }
                    check(local_name.as_bytes())?;
                }
                KeyValueInfo::InvalidEcKeyValue => {}
            },
            KeyInfoSource::RetrievalMethod {
                uri,
                resource_type,
                transforms,
            } => {
                check(uri.as_bytes())?;
                if let Some(kind) = resource_type {
                    check(kind.as_bytes())?;
                }
                if let RetrievalMethodTransforms::X509DataNodeSetFilter {
                    expression,
                    namespaces,
                } = transforms
                {
                    check(expression.as_bytes())?;
                    for (prefix, uri) in namespaces {
                        check(prefix.as_bytes())?;
                        check(uri.as_bytes())?;
                    }
                }
            }
            KeyInfoSource::X509Data(data) => {
                for bytes in data.certificates.iter().chain(&data.crls).chain(&data.skis) {
                    check(bytes)?;
                }
                for value in &data.subject_names {
                    check(value.as_bytes())?;
                }
                for (issuer, serial) in &data.issuer_serials {
                    check(issuer.as_bytes())?;
                    check(serial.as_bytes())?;
                }
                for (algorithm, bytes) in &data.digests {
                    check(algorithm.as_bytes())?;
                    check(bytes)?;
                }
            }
        }
    }
    Ok(())
}

pub(super) fn map_key_info_error(error: crate::xmldsig::parse::ParseError) -> XmlEncError {
    match error {
        crate::xmldsig::parse::ParseError::Policy(error) => XmlEncError::Policy(error),
        crate::xmldsig::parse::ParseError::Provider(error) => XmlEncError::Provider(error),
        error => invalid(&error.to_string()),
    }
}

/// Bind an expected agreement descriptor and trusted keys to a content cipher.
/// Compare XML parameters before provider work; party/KDF substitutions fail.
pub struct AgreementDecryptor<'a> {
    expected: &'a AgreementMethod,
    key: &'a dyn crate::provider::KeyAgreementKey,
    peer: &'a [u8],
    purpose: AgreementPurpose,
}

enum AgreementPurpose {
    Content(super::DataEncryptionAlgorithm),
    Wrapping(super::KeyWrapAlgorithm),
}

impl<'a> AgreementDecryptor<'a> {
    /// Expectations must come from the application's trusted configuration,
    /// not be copied from the message as a substitute for party validation.
    pub fn content(
        expected: &'a AgreementMethod,
        key: &'a dyn crate::provider::KeyAgreementKey,
        peer: &'a [u8],
        algorithm: super::DataEncryptionAlgorithm,
    ) -> Self {
        Self {
            expected,
            key,
            peer,
            purpose: AgreementPurpose::Content(algorithm),
        }
    }

    /// Bind this agreement to a KEK algorithm instead of a content cipher.
    pub fn wrapping(
        expected: &'a AgreementMethod,
        key: &'a dyn crate::provider::KeyAgreementKey,
        peer: &'a [u8],
        algorithm: super::KeyWrapAlgorithm,
    ) -> Self {
        Self {
            expected,
            key,
            peer,
            purpose: AgreementPurpose::Wrapping(algorithm),
        }
    }

    fn derive(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        uri: &str,
        width: usize,
        policy: &crate::policy::DecryptionPolicy,
        budget: &mut super::KeyCandidateBudget,
    ) -> Result<Vec<crate::provider::RecoveredContentKey>, XmlEncError> {
        let agreement = KeyAgreementParameters {
            algorithm: self.expected.algorithm.uri(),
            peer_public_key: self.peer,
        };
        let parameters = self.expected.parameters(uri, width)?;
        let mut secret =
            budget.agree_and_derive(provider, policy, self.key, &agreement, &parameters)?;
        Ok(vec![crate::provider::RecoveredContentKey::confirmed(
            core::mem::take(&mut *secret),
        )])
    }
}

impl super::DecryptionKeyResolver for AgreementDecryptor<'_> {
    fn resolve_key_encryption_keys_with_policy(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: super::KeyWrapAlgorithm,
        source: super::KeyEncryptionKeySource<'_>,
        policy: &crate::policy::DecryptionPolicy,
        budget: &mut super::KeyCandidateBudget,
    ) -> Result<Vec<crate::provider::RecoveredContentKey>, XmlEncError> {
        let super::KeyEncryptionKeySource::Agreement(descriptor) = source else {
            return Err(XmlEncError::KeyNotFound);
        };
        if !matches!(self.purpose, AgreementPurpose::Wrapping(expected) if expected == algorithm)
            || descriptor != self.expected
        {
            return Err(XmlEncError::KeyNotFound);
        }
        // Reserve the consuming unwrap too, before either expensive primitive.
        budget.require_available(3)?;
        self.derive(
            provider,
            algorithm.uri(),
            algorithm.key_len(),
            policy,
            budget,
        )
    }
    fn resolve_agreement_content_keys_with_policy(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: super::DataEncryptionAlgorithm,
        descriptor: &AgreementMethod,
        policy: &crate::policy::DecryptionPolicy,
        budget: &mut super::KeyCandidateBudget,
    ) -> Result<Vec<crate::provider::RecoveredContentKey>, XmlEncError> {
        if !matches!(self.purpose, AgreementPurpose::Content(expected) if expected == algorithm)
            || descriptor != self.expected
        {
            return Err(XmlEncError::KeyNotFound);
        }
        self.derive(
            provider,
            algorithm.uri(),
            algorithm.key_len(),
            policy,
            budget,
        )
    }

    fn resolve_key(
        &self,
        _provider: &dyn crate::provider::CryptoProvider,
        _algorithm: super::DataEncryptionAlgorithm,
        _encrypted_key: Option<&super::EncryptedKey>,
    ) -> Result<Vec<u8>, XmlEncError> {
        // Raw key resolution cannot assert that transported agreement metadata
        // was checked against the application's expected parties and KDF.
        Err(XmlEncError::KeyNotFound)
    }
}
