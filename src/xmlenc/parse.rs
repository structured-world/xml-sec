//! Strict parsing for the subset of XMLEnc needed by the decryption API.

#[cfg(test)]
use crate::xml::dom::ParsingOptions;
use crate::xml::dom::{Document, Node};
#[cfg(test)]
use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::document::{
    DocumentParseSettings, XmlParseWorkBudget, parse_borrowed_with_settings_and_budget,
};

use super::map_document_error;
use super::types::{
    CipherData, EncryptedData, EncryptedDataType, EncryptedKey, EncryptionMethod,
    MAX_CIPHER_VALUE_BASE64_LEN, ReferenceList, XMLDSIG_NS, XMLENC_NS, XMLENC11_NS, XmlEncError,
};

#[derive(Clone, Copy)]
pub(super) struct ParsingPolicy<'a> {
    key_establishment: &'a crate::policy::KeyEstablishmentPolicy,
    xml: &'a crate::policy::XmlInputPolicy,
    resources: &'a crate::policy::ResourcePolicy,
    uris: Option<&'a crate::policy::UriPolicy>,
    transforms: Option<&'a crate::policy::TransformPolicy>,
}

impl<'a> From<&'a crate::policy::EncryptionPolicy> for ParsingPolicy<'a> {
    fn from(policy: &'a crate::policy::EncryptionPolicy) -> Self {
        Self {
            key_establishment: &policy.key_establishment,
            xml: &policy.xml,
            resources: &policy.resources,
            uris: None,
            transforms: None,
        }
    }
}

impl<'a> From<&'a crate::policy::DecryptionPolicy> for ParsingPolicy<'a> {
    fn from(policy: &'a crate::policy::DecryptionPolicy) -> Self {
        Self {
            key_establishment: &policy.key_establishment,
            xml: &policy.xml,
            resources: &policy.resources,
            uris: Some(&policy.uris),
            transforms: Some(&policy.transforms),
        }
    }
}

struct ParsedKeyInfo {
    encapsulation_methods: Vec<crate::key_establishment::EncapsulationMechanism>,
    source_nodes: Vec<crate::NodeId>,
    key_name: Option<String>,
    encrypted_keys: Vec<EncryptedKey>,
    derived_keys: Vec<super::DerivedKey>,
    agreement_methods: Vec<super::AgreementMethod>,
}

struct SharedKeySourceParseBudget<'a> {
    count: usize,
    retained_cipher_bytes: usize,
    transforms: crate::xmldsig::transforms::XPathSignatureParseBudget,
    key_info: crate::xmldsig::parse::KeyInfoParsingSession<'a>,
    reference_ancestry: Vec<(Option<String>, [u8; 32])>,
}

impl<'a> SharedKeySourceParseBudget<'a> {
    fn new(resources: &'a crate::policy::ResourcePolicy) -> Result<Self, XmlEncError> {
        Ok(Self {
            count: 0,
            retained_cipher_bytes: 0,
            transforms: crate::xmldsig::transforms::XPathSignatureParseBudget::from_resources(
                resources,
            ),
            key_info: crate::xmldsig::parse::KeyInfoParsingSession::new(resources)
                .map_err(super::agreement::map_key_info_error)?,
            reference_ancestry: Vec::new(),
        })
    }
}

struct KeySourceParseBudget<'a, 'doc, 'shared> {
    policy: ParsingPolicy<'a>,
    provider: &'a dyn crate::provider::CryptoProvider,
    shared: &'shared mut SharedKeySourceParseBudget<'a>,
    references: Option<&'a super::CipherReferenceContext<'a>>,
    xml_parse: Option<&'a XmlParseWorkBudget>,
    document_base: Option<String>,
    resolver: Option<crate::xmldsig::uri::UriReferenceResolver<'doc>>,
    registrations: &'a [crate::IdAttributeRegistration],
    ancestry: Vec<crate::NodeId>,
    origins: Vec<Option<crate::NodeId>>,
    encapsulation_values: Vec<Node<'doc, 'doc>>,
    encrypted_key_depth: usize,
    detached: Option<Vec<crate::NodeId>>,
}

impl<'a, 'doc, 'shared> KeySourceParseBudget<'a, 'doc, 'shared> {
    fn resolver(
        &mut self,
        source: Node<'doc, 'doc>,
    ) -> &crate::xmldsig::uri::UriReferenceResolver<'doc> {
        self.resolver.get_or_insert_with(|| {
            crate::xmldsig::uri::UriReferenceResolver::with_id_registrations(
                source.document(),
                self.registrations,
            )
            .with_same_document_id_semantics(
                self.policy.transforms.map_or(Default::default(), |policy| {
                    policy.same_document_id_semantics
                }),
            )
        })
    }

    fn referenced_node(
        &mut self,
        source: Node<'doc, 'doc>,
        uri: &str,
    ) -> Result<Node<'doc, 'doc>, XmlEncError> {
        self.resolver(source)
            .node_for_same_document_reference(uri)?
            .ok_or_else(|| {
                XmlEncError::InvalidStructure(
                    "encryption key reference target is absent or ambiguous".into(),
                )
            })
    }
    fn new(
        policy: ParsingPolicy<'a>,
        registrations: &'a [crate::IdAttributeRegistration],
        provider: &'a dyn crate::provider::CryptoProvider,
        shared: &'shared mut SharedKeySourceParseBudget<'a>,
    ) -> Self {
        Self {
            policy,
            provider,
            shared,
            references: None,
            xml_parse: None,
            document_base: None,
            resolver: None,
            registrations,
            ancestry: Vec::new(),
            origins: Vec::new(),
            encapsulation_values: Vec::new(),
            encrypted_key_depth: 0,
            detached: None,
        }
    }

    fn charge(&mut self, resources: &crate::policy::ResourcePolicy) -> Result<(), XmlEncError> {
        resources.validate_key_candidates(self.shared.count + 1)?;
        self.shared.count += 1;
        Ok(())
    }

    fn charge_recipient(
        &mut self,
        resources: &crate::policy::ResourcePolicy,
        existing: usize,
    ) -> Result<(), XmlEncError> {
        if existing >= resources.max_encryption_recipients {
            return Err(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::ENCRYPTION_RECIPIENTS,
                maximum: resources.max_encryption_recipients,
                actual: existing + 1,
            }
            .into());
        }
        self.charge(resources)
    }
}

/// Parse one `xenc:EncryptedData` document fragment.
pub fn parse_encrypted_data(xml: &str) -> Result<EncryptedData, XmlEncError> {
    parse_encrypted_data_with_policy(xml, &crate::policy::DecryptionPolicy::default())
}

pub(super) fn parse_encrypted_data_with_policy(
    xml: &str,
    policy: &crate::policy::DecryptionPolicy,
) -> Result<EncryptedData, XmlEncError> {
    parse_encrypted_data_with_policy_and_backend(xml, policy, crate::XmlBackend::default())
}

pub(super) fn parse_encrypted_data_with_policy_and_backend(
    xml: &str,
    policy: &crate::policy::DecryptionPolicy,
    backend: crate::XmlBackend,
) -> Result<EncryptedData, XmlEncError> {
    let parse_budget = XmlParseWorkBudget::from_resources(&policy.resources);
    parse_encrypted_data_with_policy_backend_and_budget(xml, policy, backend, &parse_budget)
}

pub(super) fn parse_encrypted_data_with_policy_backend_and_budget(
    xml: &str,
    policy: &crate::policy::DecryptionPolicy,
    backend: crate::XmlBackend,
    parse_budget: &XmlParseWorkBudget,
) -> Result<EncryptedData, XmlEncError> {
    policy.validate()?;
    policy.resources.validate_xml_document_len(xml.len())?;
    let settings =
        DocumentParseSettings::from_policy(&policy.xml, &policy.resources).with_backend(backend);
    let document = parse_borrowed_with_settings_and_budget(xml, settings, Some(parse_budget))
        .map_err(|error| map_document_error(error, settings))?;
    let references = super::CipherReferenceContext::new(policy, None, backend, &[])?;
    parse_encrypted_data_node_with_origins(
        document.root_element(),
        policy.into(),
        false,
        &[],
        crate::provider::default_provider(),
        Some(&references),
        Some(parse_budget),
    )
    .map(|(data, _)| data)
}

/// Parse a selected `xenc:EncryptedData` node under an immutable policy snapshot.
///
/// This is the node-oriented counterpart to [`parse_encrypted_data`]. It lets
/// callers that already parsed a containing document validate the complete
/// encrypted-data structure without serializing the selected subtree and losing
/// namespace declarations inherited from its ancestors. The containing source
/// document is reparsed because [`Node`] does not expose its parser provenance.
pub fn parse_encrypted_data_node_with_policy(
    node: Node<'_, '_>,
    policy: &crate::policy::DecryptionPolicy,
) -> Result<EncryptedData, XmlEncError> {
    parse_encrypted_data_node_with_policy_and_backend(node, policy, crate::XmlBackend::default())
}

/// Parse a selected `xenc:EncryptedData` node with an explicit parser backend.
pub fn parse_encrypted_data_node_with_policy_and_backend(
    node: Node<'_, '_>,
    policy: &crate::policy::DecryptionPolicy,
    backend: crate::XmlBackend,
) -> Result<EncryptedData, XmlEncError> {
    parse_encrypted_data_node_with_context(
        node,
        policy,
        backend,
        crate::provider::default_provider(),
        &[],
    )
}

/// Inspect a selected node using the same provider and ID registrations as decryption.
/// Same-document KeyInfo references are resolved before returning recipient metadata.
pub fn parse_encrypted_data_node_with_context(
    node: Node<'_, '_>,
    policy: &crate::policy::DecryptionPolicy,
    backend: crate::XmlBackend,
    provider: &dyn crate::provider::CryptoProvider,
    id_attributes: &[crate::IdAttributeRegistration],
) -> Result<EncryptedData, XmlEncError> {
    let parse_budget = XmlParseWorkBudget::from_resources(&policy.resources);
    parse_encrypted_data_node_with_context_and_budget(
        node,
        policy,
        &parse_budget,
        backend,
        provider,
        id_attributes,
    )
}

fn parse_encrypted_data_node_with_context_and_budget(
    node: Node<'_, '_>,
    policy: &crate::policy::DecryptionPolicy,
    parse_budget: &XmlParseWorkBudget,
    backend: crate::XmlBackend,
    provider: &dyn crate::provider::CryptoProvider,
    id_attributes: &[crate::IdAttributeRegistration],
) -> Result<EncryptedData, XmlEncError> {
    policy.validate()?;
    let references = super::CipherReferenceContext::new(policy, None, backend, id_attributes)?;
    let policy = ParsingPolicy::from(policy);
    validate_node_document_policy(node, policy, parse_budget, backend)?;
    parse_encrypted_data_node_with_origins(
        node,
        policy,
        false,
        id_attributes,
        provider,
        Some(&references),
        Some(parse_budget),
    )
    .map(|(data, _)| data)
}

/// Immutable descriptor graph with an association-checked recipient location.
/// No key material is copied to record selection; the private location is bound
/// to this graph and cannot become stale through caller mutation.
pub struct EncryptedDataInspection {
    data: EncryptedData,
    recipient: Option<super::decrypt::EncapsulationRecipient>,
}

impl EncryptedDataInspection {
    /// Validated, fully resolved encrypted-data metadata.
    pub fn data(&self) -> &EncryptedData {
        &self.data
    }

    /// Whether decryption must retain the original document's reference and ID
    /// semantics rather than use the standalone typed-descriptor API.
    pub fn requires_document_context(&self) -> bool {
        fn keys_require_context(keys: &[EncryptedKey]) -> bool {
            keys.iter().any(|key| {
                key.reference_list.is_some()
                    || matches!(key.cipher_data, CipherData::Reference { .. })
                    || key
                        .sources
                        .derived_keys
                        .iter()
                        .any(|key| key.reference_list.is_some())
                    || keys_require_context(&key.sources.encrypted_keys)
            })
        }
        // Parsed graphs have the non-configurable KeyInfo depth ceiling. This
        // borrowed traversal allocates nothing and cannot recurse past it.
        matches!(self.data.cipher_data, CipherData::Reference { .. })
            || self
                .data
                .derived_keys
                .iter()
                .any(|key| key.reference_list.is_some())
            || keys_require_context(&self.data.encrypted_keys)
    }

    /// The sole applicable KEM recipient, after encrypted-key association checks.
    pub fn recipient_encapsulation(
        &self,
    ) -> Option<&crate::key_establishment::EncapsulationMechanism> {
        self.recipient
            .as_ref()
            .map(|recipient| recipient.mechanism(&self.data))
    }
}

/// Inspect recipient selection using the same source identities and association
/// predicates as decryption, before loading any caller-provided private key.
pub fn inspect_encrypted_data_node_with_context(
    node: Node<'_, '_>,
    policy: &crate::policy::DecryptionPolicy,
    backend: crate::XmlBackend,
    provider: &dyn crate::provider::CryptoProvider,
    id_attributes: &[crate::IdAttributeRegistration],
) -> Result<EncryptedDataInspection, XmlEncError> {
    let parse_budget = XmlParseWorkBudget::from_resources(&policy.resources);
    policy.validate()?;
    let references = super::CipherReferenceContext::new(policy, None, backend, id_attributes)?;
    validate_node_document_policy(node, policy.into(), &parse_budget, backend)?;
    let (data, origins) = parse_encrypted_data_node_with_origins(
        node,
        policy.into(),
        false,
        id_attributes,
        provider,
        Some(&references),
        Some(&parse_budget),
    )?;
    let bound = references.bind_document(node.document());
    let recipient =
        super::decrypt::select_encapsulation_recipient(&data, &bound, node.id(), &origins, policy)?;
    Ok(EncryptedDataInspection { data, recipient })
}

/// Parse an `xenc:EncryptedData` template under an immutable policy snapshot.
///
/// This applies the complete encrypted-data grammar and metadata limits while
/// permitting empty `CipherValue` placeholders that encryption will replace.
/// Non-empty placeholders must still be well-formed base64. The containing
/// source document is reparsed under this policy before template inspection.
pub fn parse_encrypted_data_template_node_with_policy(
    node: Node<'_, '_>,
    policy: &crate::policy::EncryptionPolicy,
) -> Result<EncryptedData, XmlEncError> {
    parse_encrypted_data_template_node_with_policy_and_backend(
        node,
        policy,
        crate::XmlBackend::default(),
    )
}

/// Parse an `xenc:EncryptedData` template node with an explicit parser backend.
pub fn parse_encrypted_data_template_node_with_policy_and_backend(
    node: Node<'_, '_>,
    policy: &crate::policy::EncryptionPolicy,
    backend: crate::XmlBackend,
) -> Result<EncryptedData, XmlEncError> {
    inspect_encrypted_data_template_node_with_context(
        node,
        policy,
        backend,
        crate::provider::default_provider(),
        &[],
    )
    .map(|template| template.data)
}

/// Validated template metadata and original same-document mutation targets.
/// The borrowed nodes remain bound to the inspected source DOM; they are never
/// inferred from a generated document or from a lexical descendant scan.
pub struct EncryptedDataTemplate<'doc> {
    data: EncryptedData,
    encapsulation_values: Vec<Node<'doc, 'doc>>,
}

impl<'doc> EncryptedDataTemplate<'doc> {
    /// Fully resolved establishment descriptors, bound to the original targets.
    pub fn data(&self) -> &EncryptedData {
        &self.data
    }

    /// Consume inspection when only the descriptor graph is needed.
    pub fn into_data(self) -> EncryptedData {
        self.data
    }

    /// Original CipherValue placeholders in resolved mechanism order.
    pub fn encapsulation_cipher_values(&self) -> &[Node<'doc, 'doc>] {
        &self.encapsulation_values
    }
}

/// Inspect a template with the operation's engine and registered XML IDs.
pub fn inspect_encrypted_data_template_node_with_context<'doc>(
    node: Node<'doc, 'doc>,
    policy: &crate::policy::EncryptionPolicy,
    backend: crate::XmlBackend,
    provider: &dyn crate::provider::CryptoProvider,
    id_attributes: &[crate::IdAttributeRegistration],
) -> Result<EncryptedDataTemplate<'doc>, XmlEncError> {
    let parse_budget = XmlParseWorkBudget::from_resources(&policy.resources);
    policy.validate()?;
    let policy = ParsingPolicy::from(policy);
    validate_node_document_policy(node, policy, &parse_budget, backend)?;
    let (data, _, encapsulation_values) = parse_encrypted_data_node_traced(
        node,
        policy,
        true,
        id_attributes,
        provider,
        None,
        Some(&parse_budget),
    )?;
    Ok(EncryptedDataTemplate {
        data,
        encapsulation_values,
    })
}

fn validate_node_document_policy(
    node: Node<'_, '_>,
    policy: ParsingPolicy<'_>,
    parse_budget: &XmlParseWorkBudget,
    backend: crate::XmlBackend,
) -> Result<(), XmlEncError> {
    parse_policy_document(node.document().input_text(), policy, parse_budget, backend)?;
    Ok(())
}

fn parse_policy_document<'a>(
    xml: &'a str,
    policy: ParsingPolicy<'_>,
    parse_budget: &XmlParseWorkBudget,
    backend: crate::XmlBackend,
) -> Result<Document<'a>, XmlEncError> {
    let settings =
        DocumentParseSettings::from_policy(policy.xml, policy.resources).with_backend(backend);
    parse_borrowed_with_settings_and_budget(xml, settings, Some(parse_budget))
        .map_err(|error| map_document_error(error, settings))
}

pub(super) fn parse_encrypted_data_node_with_origins(
    node: Node<'_, '_>,
    policy: ParsingPolicy<'_>,
    allow_empty_cipher_values: bool,
    registrations: &[crate::IdAttributeRegistration],
    provider: &dyn crate::provider::CryptoProvider,
    references: Option<&super::CipherReferenceContext<'_>>,
    xml_parse: Option<&XmlParseWorkBudget>,
) -> Result<(EncryptedData, Vec<Option<crate::NodeId>>), XmlEncError> {
    parse_encrypted_data_node_traced(
        node,
        policy,
        allow_empty_cipher_values,
        registrations,
        provider,
        references,
        xml_parse,
    )
    .map(|(data, origins, _)| (data, origins))
}

type TracedEncryptedData<'doc> = (
    EncryptedData,
    Vec<Option<crate::NodeId>>,
    Vec<Node<'doc, 'doc>>,
);

fn parse_encrypted_data_node_traced<'doc>(
    node: Node<'doc, 'doc>,
    policy: ParsingPolicy<'_>,
    allow_empty_cipher_values: bool,
    registrations: &[crate::IdAttributeRegistration],
    provider: &dyn crate::provider::CryptoProvider,
    references: Option<&super::CipherReferenceContext<'_>>,
    xml_parse: Option<&XmlParseWorkBudget>,
) -> Result<TracedEncryptedData<'doc>, XmlEncError> {
    require_element(node, XMLENC_NS, "EncryptedData")?;
    let mut shared = SharedKeySourceParseBudget::new(policy.resources)?;
    let mut budget = KeySourceParseBudget::new(policy, registrations, provider, &mut shared);
    budget.references = references;
    budget.xml_parse = xml_parse;
    validate_encrypted_type_attributes(node, policy)?;
    let mut children = element_children(node);
    let encryption_method = parse_encryption_method_with_limit(
        next_required(&mut children, "EncryptionMethod")?,
        policy.resources.max_encryption_metadata_bytes,
    )?;
    if children
        .peek()
        .is_some_and(|child| child.has_tag_name((XMLENC_NS, "EncryptionMethod")))
    {
        return Err(XmlEncError::InvalidStructure(
            "EncryptedData contains more than one direct EncryptionMethod".into(),
        ));
    }

    let key_info_node = match children.peek() {
        Some(child) if child.has_tag_name((XMLDSIG_NS, "KeyInfo")) => {
            Some(next_required(&mut children, "KeyInfo")?)
        }
        _ => None,
    };
    if children
        .peek()
        .is_some_and(|child| child.has_tag_name((XMLDSIG_NS, "KeyInfo")))
    {
        return Err(XmlEncError::InvalidStructure(
            "EncryptedData contains more than one direct KeyInfo".into(),
        ));
    }

    let cipher_data = parse_cipher_data(
        next_required(&mut children, "CipherData")?,
        allow_empty_cipher_values,
        policy,
        &mut budget.shared.transforms,
        &mut budget.shared.retained_cipher_bytes,
    )?;
    consume_encryption_properties(&mut children);
    if children.next().is_some() {
        return Err(XmlEncError::InvalidStructure(
            "EncryptedData has unexpected child after CipherData".into(),
        ));
    }

    // Reject the containing value and policy before indirect KeyInfo processing
    // can resolve resources or execute transforms.
    if let Some(references) = references {
        references.validate_method(&encryption_method, true, provider)?;
        references.preflight_cipher_data(&cipher_data)?;
    }
    let mut key_info = match key_info_node {
        Some(key_info) => {
            parse_key_info(key_info, policy, allow_empty_cipher_values, &mut budget, 0)?
        }
        None => ParsedKeyInfo {
            encapsulation_methods: Vec::new(),
            source_nodes: Vec::new(),
            key_name: None,
            encrypted_keys: Vec::new(),
            derived_keys: Vec::new(),
            agreement_methods: Vec::new(),
        },
    };
    append_detached_keys(
        node,
        &mut key_info,
        policy,
        allow_empty_cipher_values,
        &mut budget,
        0,
    )?;

    let encrypted = EncryptedData {
        encapsulation_methods: key_info.encapsulation_methods,
        id: bounded_attribute(node, "Id", policy)?,
        encrypted_type: parse_encrypted_data_type(node.attribute("Type")),
        key_name: key_info.key_name,
        encryption_method,
        encrypted_keys: key_info.encrypted_keys,
        derived_keys: key_info.derived_keys,
        agreement_methods: key_info.agreement_methods,
        cipher_data,
    };
    validate_encrypted_data_metadata_inner(&encrypted, policy, allow_empty_cipher_values)?;
    Ok((encrypted, budget.origins, budget.encapsulation_values))
}

fn parse_key_info<'doc>(
    node: Node<'doc, 'doc>,
    policy: ParsingPolicy<'_>,
    allow_empty_cipher_values: bool,
    budget: &mut KeySourceParseBudget<'_, 'doc, '_>,
    depth: usize,
) -> Result<ParsedKeyInfo, XmlEncError> {
    require_element(node, XMLDSIG_NS, "KeyInfo")?;
    policy.resources.validate_key_info_reference_depth(depth)?;
    let recipients = node
        .children()
        .filter(|child| child.has_tag_name((XMLENC_NS, "EncryptedKey")))
        .count();
    if recipients > policy.resources.max_encryption_recipients {
        return Err(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::ENCRYPTION_RECIPIENTS,
            maximum: policy.resources.max_encryption_recipients,
            actual: recipients,
        }
        .into());
    }
    if budget.ancestry.contains(&node.id()) {
        return Err(XmlEncError::InvalidStructure(
            "cyclic encryption KeyInfo reference".into(),
        ));
    }
    budget.ancestry.push(node.id());
    let mut key_name = None;
    let mut source_nodes = Vec::new();
    let mut encrypted_keys = Vec::new();
    let mut derived_keys = Vec::new();
    let mut agreement_methods = Vec::new();
    let mut encapsulation_methods = Vec::new();
    for child in node.children().filter(Node::is_element) {
        if child.has_tag_name((
            crate::key_establishment::ENCAPSULATION_NS,
            "EncapsulationMechanism",
        )) {
            budget.charge(policy.resources)?;
            let mechanism =
                crate::key_establishment::parse_encapsulation(child, allow_empty_cipher_values)?;
            policy
                .key_establishment
                .check_encapsulation(mechanism.algorithm)?;
            let bytes = mechanism.ciphertext().len().div_ceil(3) * 4;
            let maximum = policy.resources.max_xml_document_bytes;
            let used = budget.shared.retained_cipher_bytes;
            if used > maximum || bytes > maximum - used {
                return Err(crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::AGGREGATE_ENCRYPTION_CIPHER_VALUE_BYTES,
                    maximum,
                    actual: used.saturating_add(bytes),
                }
                .into());
            }
            budget.shared.retained_cipher_bytes += bytes;
            let info = parse_encapsulation_key_info(mechanism.key_info, budget, depth + 1)?;
            if allow_empty_cipher_values && budget.encrypted_key_depth == 0 {
                budget.encapsulation_values.push(mechanism.cipher_value);
            }
            encapsulation_methods.push(crate::key_establishment::EncapsulationMechanism {
                algorithm: mechanism.algorithm,
                key_info: info,
                ciphertext: mechanism.ciphertext().to_vec(),
            });
            source_nodes.push(child.id());
        } else if child.has_tag_name((XMLDSIG_NS, "KeyName")) {
            if key_name.is_some() {
                return Err(XmlEncError::InvalidStructure(
                    "KeyInfo contains more than one direct KeyName".into(),
                ));
            }
            key_name = Some(parse_key_name(child, policy)?);
        } else if child.has_tag_name((XMLENC_NS, "EncryptedKey")) {
            budget.charge_recipient(policy.resources, encrypted_keys.len())?;
            source_nodes.push(child.id());
            encrypted_keys.push(parse_encrypted_key(
                child,
                policy,
                allow_empty_cipher_values,
                budget,
                depth + 1,
            )?);
        } else if child.has_tag_name((XMLENC11_NS, "DerivedKey")) {
            budget.charge(policy.resources)?;
            source_nodes.push(child.id());
            derived_keys.push(super::derived_key::parse(child, policy.resources)?);
        } else if child.has_tag_name((XMLENC_NS, "AgreementMethod")) {
            budget.charge(policy.resources)?;
            for role in child.children().filter(|node| {
                node.has_tag_name((XMLENC_NS, "OriginatorKeyInfo"))
                    || node.has_tag_name((XMLENC_NS, "RecipientKeyInfo"))
            }) {
                for source in role.children().filter(Node::is_element) {
                    if source.has_tag_name((XMLDSIG_NS, "KeyValue"))
                        || source.has_tag_name((
                            crate::xmldsig::parse::XMLDSIG11_NS,
                            "DEREncodedKeyValue",
                        ))
                    {
                        budget.charge(policy.resources)?;
                    } else if source.has_tag_name((XMLDSIG_NS, "X509Data")) {
                        for _ in source
                            .children()
                            .filter(|node| node.has_tag_name((XMLDSIG_NS, "X509Certificate")))
                        {
                            budget.charge(policy.resources)?;
                        }
                    }
                }
            }
            agreement_methods.push(super::agreement::parse(
                child,
                policy.resources,
                &mut budget.shared.key_info,
                budget.provider,
            )?);
        } else if child.has_tag_name((XMLDSIG_NS, "RetrievalMethod")) {
            // XMLDSig 1.1 section 4.5.3 defines element-only content here.
            // KeyInfo's mixed content must not leak into this child grammar.
            // https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-RetrievalMethod
            if child.children().any(|node| {
                node.is_text()
                    && node.text().is_some_and(|text| {
                        !text
                            .bytes()
                            .all(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
                    })
            }) {
                return Err(XmlEncError::InvalidStructure(
                    "RetrievalMethod contains non-whitespace text".into(),
                ));
            }
            // XMLEnc 1.1 §3.5.3 defines both EncryptedKey and DerivedKey
            // retrieval. An explicit Type must agree with the actual target.
            // Resolve against one ID index and retain the original key node.
            // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-Extensions-to-KeyInfo
            let uri = child
                .attribute("URI")
                .ok_or(XmlEncError::MissingRequired("RetrievalMethod URI"))?;
            validate_metadata_len(uri.len(), policy.resources.max_encryption_metadata_bytes)?;
            let allowed = policy
                .uris
                .map_or(crate::xmldsig::UriTypeSet::SAME_DOCUMENT, |uris| {
                    uris.retrieval_methods
                });
            if !allowed.allows(uri) {
                return Err(crate::policy::PolicyViolation::Algorithm {
                    operation: "encryption key retrieval URI",
                    algorithm: uri.to_owned(),
                }
                .into());
            }
            let mut transform_children = element_children(child);
            let transforms = match transform_children.next() {
                Some(container) if container.has_tag_name((XMLDSIG_NS, "Transforms")) => {
                    if transform_children.next().is_some()
                        || !container.children().any(|node| node.is_element())
                    {
                        return Err(XmlEncError::InvalidStructure(
                            "RetrievalMethod requires one nonempty ds:Transforms container".into(),
                        ));
                    }
                    crate::xmldsig::transforms::parse_reference_transforms_with_budget(
                        container,
                        XMLDSIG_NS,
                        &mut budget.shared.transforms,
                    )?
                }
                Some(_) => {
                    return Err(XmlEncError::InvalidStructure(
                        "unexpected RetrievalMethod child".into(),
                    ));
                }
                None => Vec::new(),
            };
            let declared_type = child.attribute("Type");
            let declared_type = declared_type
                .map(|kind| {
                    validate_metadata_len(
                        kind.len(),
                        policy.resources.max_encryption_metadata_bytes,
                    )?;
                    RetrievedKeyType::parse(kind)
                })
                .transpose()?;
            if !uri.is_empty() && !uri.starts_with('#') || !transforms.is_empty() {
                budget.charge(policy.resources)?;
                match parse_processed_key_reference(
                    child,
                    uri,
                    &transforms,
                    declared_type,
                    allow_empty_cipher_values,
                    budget,
                    depth + 1,
                )? {
                    RetrievedKey::Encrypted(key) => {
                        if encrypted_keys.len() >= policy.resources.max_encryption_recipients {
                            return Err(crate::policy::PolicyViolation::ResourceLimit {
                                resource: crate::policy::resource_name::ENCRYPTION_RECIPIENTS,
                                maximum: policy.resources.max_encryption_recipients,
                                actual: encrypted_keys.len() + 1,
                            }
                            .into());
                        }
                        encrypted_keys.push(key);
                    }
                    RetrievedKey::Derived(key) => derived_keys.push(key),
                }
                continue;
            }
            let target = budget.referenced_node(child, uri)?;
            if let Some(kind) = declared_type {
                kind.validate_target(target)?;
            }
            if target.has_tag_name((XMLENC11_NS, "DerivedKey")) {
                budget.charge(policy.resources)?;
                source_nodes.push(target.id());
                derived_keys.push(super::derived_key::parse(target, policy.resources)?);
                continue;
            }
            budget.charge_recipient(policy.resources, encrypted_keys.len())?;
            source_nodes.push(target.id());
            encrypted_keys.push(parse_encrypted_key(
                target,
                policy,
                allow_empty_cipher_values,
                budget,
                depth + 1,
            )?);
        } else if child.has_tag_name((crate::xmldsig::parse::XMLDSIG11_NS, "KeyInfoReference")) {
            // XMLDSig 1.1 §4.5.10 requires a KeyInfo target, without
            // RetrievalMethod transforms. The same recursion budget and
            // ancestry track indirect and embedded encryption sources.
            // https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-KeyInfoReference
            let uri = child
                .attribute("URI")
                .ok_or(XmlEncError::MissingRequired("KeyInfoReference URI"))?;
            validate_metadata_len(uri.len(), policy.resources.max_encryption_metadata_bytes)?;
            if child.children().any(|node| {
                node.is_element()
                    || node.is_text()
                        && node.text().is_some_and(|text| {
                            !text
                                .bytes()
                                .all(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
                        })
            }) {
                return Err(XmlEncError::InvalidStructure(
                    "KeyInfoReference must be empty".into(),
                ));
            }
            let allowed = policy
                .uris
                .map_or(crate::xmldsig::UriTypeSet::SAME_DOCUMENT, |uris| {
                    uris.key_info_references
                });
            if !allowed.allows(uri) {
                return Err(crate::policy::PolicyViolation::Algorithm {
                    operation: "encryption KeyInfo reference URI",
                    algorithm: uri.to_owned(),
                }
                .into());
            }
            budget.charge(policy.resources)?;
            let target = budget.referenced_node(child, uri)?;
            let info =
                parse_key_info(target, policy, allow_empty_cipher_values, budget, depth + 1)?;
            if let Some(name) = info.key_name {
                if key_name.is_some() {
                    return Err(XmlEncError::InvalidStructure(
                        "indirect KeyInfo contains conflicting KeyName".into(),
                    ));
                }
                key_name = Some(name);
            }
            if encrypted_keys.len() + info.encrypted_keys.len()
                > policy.resources.max_encryption_recipients
            {
                return Err(crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::ENCRYPTION_RECIPIENTS,
                    maximum: policy.resources.max_encryption_recipients,
                    actual: encrypted_keys.len() + info.encrypted_keys.len(),
                }
                .into());
            }
            encrypted_keys.extend(info.encrypted_keys);
            source_nodes.extend(info.source_nodes);
            derived_keys.extend(info.derived_keys);
            agreement_methods.extend(info.agreement_methods);
            encapsulation_methods.extend(info.encapsulation_methods);
        }
    }
    budget.ancestry.pop();
    Ok(ParsedKeyInfo {
        encapsulation_methods,
        source_nodes,
        key_name,
        encrypted_keys,
        derived_keys,
        agreement_methods,
    })
}

fn parse_encapsulation_key_info<'doc>(
    node: Node<'doc, 'doc>,
    budget: &mut KeySourceParseBudget<'_, 'doc, '_>,
    depth: usize,
) -> Result<crate::xmldsig::parse::KeyInfo, XmlEncError> {
    use crate::xmldsig::parse::KeyInfoSource;
    budget
        .policy
        .resources
        .validate_key_info_reference_depth(depth)?;
    if budget.ancestry.contains(&node.id()) {
        return Err(XmlEncError::InvalidStructure(
            "cyclic encryption KeyInfo reference".into(),
        ));
    }
    budget.ancestry.push(node.id());
    let mut info = budget
        .shared
        .key_info
        .parse_with_provider_and_document_base(
            node,
            budget.provider,
            budget.document_base.as_deref(),
        )
        .map_err(super::agreement::map_key_info_error)?;
    if info
        .sources
        .iter()
        .any(|source| matches!(source, KeyInfoSource::KeyInfoReference { .. }))
    {
        let mut sources = Vec::new();
        for source in std::mem::take(&mut info.sources) {
            if let KeyInfoSource::KeyInfoReference { uri } = source {
                // XMLDSig 1.1 §4.5.10 also applies inside the mechanism's KeyInfo.
                // Resolve before recipient selection, sharing ancestry and work.
                // https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-KeyInfoReference
                let allowed = budget
                    .policy
                    .uris
                    .map_or(crate::xmldsig::UriTypeSet::SAME_DOCUMENT, |uris| {
                        uris.key_info_references
                    });
                if !allowed.allows(&uri) {
                    return Err(crate::policy::PolicyViolation::Uri {
                        operation: "encryption KeyInfoReference",
                        reason: "URI class is disabled",
                    }
                    .into());
                }
                budget.charge(budget.policy.resources)?;
                budget
                    .policy
                    .resources
                    .validate_key_info_reference_depth(depth + 1)?;
                let referenced = if uri.is_empty() || uri.starts_with('#') {
                    let target = budget.referenced_node(node, &uri)?;
                    parse_encapsulation_key_info(target, budget, depth + 1)?
                } else {
                    let resource = uri
                        .split_once('#')
                        .map_or(uri.as_str(), |(resource, _)| resource);
                    let fragment = &uri[resource.len()..];
                    with_processed_key_reference(
                        node,
                        resource,
                        allowed,
                        &[],
                        budget,
                        |root, child| {
                            let target = if fragment.is_empty() || fragment == "#" {
                                root
                            } else {
                                child.referenced_node(root, fragment)?
                            };
                            // §4.5.10 requires KeyInfo, not arbitrary retrieved key data.
                            require_element(target, XMLDSIG_NS, "KeyInfo")?;
                            parse_encapsulation_key_info(target, child, depth + 1)
                        },
                    )?
                };
                sources.extend(referenced.sources);
            } else {
                sources.push(source);
            }
        }
        info.sources = sources;
    }
    budget.ancestry.pop();
    Ok(info)
}

enum RetrievedKey {
    Encrypted(EncryptedKey),
    Derived(super::DerivedKey),
}

#[derive(Clone, Copy)]
enum RetrievedKeyType {
    Encrypted,
    Derived,
}

impl RetrievedKeyType {
    fn parse(uri: &str) -> Result<Self, XmlEncError> {
        // XMLEnc 1.1 §3.5.2 specifies the xmlenc11 identifier, while §3.5.3
        // prints xmlenc. Accept the latter as an interoperability alias; both
        // still require an xenc11:DerivedKey target, including after transforms.
        // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-DerivedKey
        // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-RetrievalMethod
        match uri {
            "http://www.w3.org/2001/04/xmlenc#EncryptedKey" => Ok(Self::Encrypted),
            "http://www.w3.org/2009/xmlenc11#DerivedKey"
            | "http://www.w3.org/2001/04/xmlenc#DerivedKey" => Ok(Self::Derived),
            _ => Err(XmlEncError::InvalidStructure(
                "unsupported encryption RetrievalMethod Type".into(),
            )),
        }
    }

    fn validate_target(self, node: Node<'_, '_>) -> Result<(), XmlEncError> {
        let (namespace, tag) = match self {
            Self::Encrypted => (XMLENC_NS, "EncryptedKey"),
            Self::Derived => (XMLENC11_NS, "DerivedKey"),
        };
        if node.has_tag_name((namespace, tag)) {
            Ok(())
        } else {
            Err(XmlEncError::InvalidStructure(format!(
                "RetrievalMethod Type disagrees with {tag} target"
            )))
        }
    }
}

fn parse_processed_key_reference(
    source: Node<'_, '_>,
    uri: &str,
    transforms: &[crate::xmldsig::transforms::Transform],
    declared_type: Option<RetrievedKeyType>,
    allow_empty: bool,
    budget: &mut KeySourceParseBudget<'_, '_, '_>,
    depth: usize,
) -> Result<RetrievedKey, XmlEncError> {
    budget
        .policy
        .resources
        .validate_key_info_reference_depth(depth)?;
    let allowed = budget
        .policy
        .uris
        .map_or(crate::xmldsig::UriTypeSet::SAME_DOCUMENT, |uris| {
            uris.retrieval_methods
        });
    with_processed_key_reference(
        source,
        uri,
        allowed,
        transforms,
        budget,
        |target, child_budget| {
            if let Some(kind) = declared_type {
                kind.validate_target(target)?;
            }
            if target.has_tag_name((XMLENC11_NS, "DerivedKey")) {
                return Ok(RetrievedKey::Derived(super::derived_key::parse(
                    target,
                    child_budget.policy.resources,
                )?));
            }
            let mut key = parse_encrypted_key(
                target,
                child_budget.policy,
                allow_empty,
                child_budget,
                depth,
            )?;
            let context = child_budget
                .references
                .expect("processed reference context");
            let parse = child_budget
                .xml_parse
                .expect("processed reference parse budget");
            let bound = context
                .bind_document_with_base(target.document(), child_budget.document_base.as_deref());
            let mut origins = child_budget.origins.iter();
            super::decrypt::resolve_nested_cipher_references(
                core::slice::from_mut(&mut key),
                target.document(),
                &mut origins,
                &bound,
                parse,
            )?;
            if origins.next().is_some() {
                return Err(XmlEncError::OperationPlan(
                    "unused processed key origin".into(),
                ));
            }
            Ok(RetrievedKey::Encrypted(key))
        },
    )
}

fn with_processed_key_reference<T>(
    source: Node<'_, '_>,
    uri: &str,
    allowed_uris: crate::xmldsig::UriTypeSet,
    transforms: &[crate::xmldsig::transforms::Transform],
    budget: &mut KeySourceParseBudget<'_, '_, '_>,
    consume: impl for<'doc> FnOnce(
        Node<'doc, 'doc>,
        &mut KeySourceParseBudget<'_, 'doc, '_>,
    ) -> Result<T, XmlEncError>,
) -> Result<T, XmlEncError> {
    use sha2::Digest as _;
    let policy = budget.policy;
    let context = budget.references.ok_or_else(|| {
        XmlEncError::InvalidStructure(
            "processed key retrieval requires an operation resource context".into(),
        )
    })?;
    let parse = budget
        .xml_parse
        .ok_or_else(|| XmlEncError::OperationPlan("missing key resource parse budget".into()))?;
    let (bytes, base) = context.resolve_key_reference(
        source,
        uri,
        allowed_uris,
        transforms,
        budget.document_base.as_deref(),
        parse,
    )?;
    policy.resources.validate_xml_document_len(bytes.len())?;
    // Equality is over the selected, bounded result, never a phase-local node
    // handle or a scan/hash of every unused caller resource.
    let fingerprint: [u8; 32] = sha2::Sha256::digest(&bytes).into();
    if budget
        .shared
        .reference_ancestry
        .iter()
        .any(|(identity, hash)| identity == &base && hash == &fingerprint)
    {
        return Err(XmlEncError::InvalidStructure(
            "cyclic processed encryption key reference".into(),
        ));
    }
    budget
        .shared
        .reference_ancestry
        .push((base.clone(), fingerprint));
    let settings = DocumentParseSettings::from_policy(policy.xml, policy.resources)
        .with_backend(context.backend());
    let xml = crate::document::decode_xml_with_budget(
        &bytes,
        policy.resources.max_xml_document_bytes,
        Some(parse),
    )
    .map_err(|error| map_document_error(error, settings))?;
    let document = parse_policy_document(&xml, policy, parse, context.backend())?;
    let mut child_budget = KeySourceParseBudget::new(
        budget.policy,
        budget.registrations,
        budget.provider,
        &mut *budget.shared,
    );
    child_budget.references = Some(context);
    child_budget.xml_parse = Some(parse);
    child_budget.document_base = base;
    let result = consume(document.root_element(), &mut child_budget)?;
    budget
        .origins
        .extend(child_budget.origins.iter().map(|_| None));
    budget.shared.reference_ancestry.pop();
    Ok(result)
}

fn append_detached_keys<'doc>(
    node: Node<'doc, 'doc>,
    info: &mut ParsedKeyInfo,
    policy: ParsingPolicy<'_>,
    allow_empty_cipher_values: bool,
    budget: &mut KeySourceParseBudget<'_, 'doc, '_>,
    depth: usize,
) -> Result<(), XmlEncError> {
    // XMLEnc §§3.5.1, 3.5.2 and 3.6 bind detached transports/derivations to either
    // encrypted-object class. Inventory node IDs once, not the document once
    // per recursive key. Original nodes retain namespaces and provenance.
    // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-ReferenceList
    if budget.detached.is_none() {
        let mut candidates = Vec::new();
        let maximum = policy.resources.effective_xml_nodes() as usize;
        for (index, candidate) in node.document().descendants().enumerate() {
            // Inventory is bounded document work, not candidate execution.
            // Gate the scan before retaining any additional node identities.
            if index >= maximum {
                return Err(crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_NODES,
                    maximum,
                    actual: index + 1,
                }
                .into());
            }
            if candidate.has_tag_name((XMLENC_NS, "EncryptedKey"))
                || candidate.has_tag_name((XMLENC11_NS, "DerivedKey"))
            {
                candidates.push(candidate.id());
            }
        }
        budget.detached = Some(candidates);
    }
    let count = budget
        .detached
        .as_ref()
        .expect("inventory initialized")
        .len();
    for index in 0..count {
        let id = budget.detached.as_ref().expect("inventory initialized")[index];
        let candidate = node
            .document()
            .get_node(id)
            .expect("inventory belongs to this document");
        let derived = candidate.has_tag_name((XMLENC11_NS, "DerivedKey"));
        let named = info.key_name.as_deref().is_some_and(|expected| {
            candidate
                .children()
                .find(|child| {
                    child.has_tag_name(if derived {
                        (XMLENC11_NS, "DerivedKeyName")
                    } else {
                        (XMLENC_NS, "CarriedKeyName")
                    })
                })
                .is_some_and(|label| {
                    !label.children().any(|child| child.is_element())
                        && label
                            .children()
                            .filter_map(|child| child.text())
                            .flat_map(str::bytes)
                            .eq(expected.bytes())
                })
        });
        let mut referenced = false;
        for list in candidate
            .children()
            .filter(|child| child.has_tag_name((XMLENC_NS, "ReferenceList")))
        {
            let data_target = node.has_tag_name((XMLENC_NS, "EncryptedData"));
            // Association is a borrowed, allocation-free prefilter, not full
            // validation of every key in the document. Errors in unrelated
            // metadata cannot invalidate the selected encrypted object.
            for child in list.children() {
                if !child.has_tag_name((
                    XMLENC_NS,
                    if data_target {
                        "DataReference"
                    } else {
                        "KeyReference"
                    },
                )) {
                    continue;
                }
                let Some(uri) = child.attribute("URI") else {
                    continue;
                };
                if !uri.is_empty() && !uri.starts_with('#') {
                    continue;
                }
                if uri.len() > policy.resources.max_encryption_metadata_bytes {
                    continue;
                }
                if budget
                    .resolver(node)
                    .same_document_reference_targets(uri, node.id())
                {
                    referenced = true;
                    break;
                }
            }
            if referenced {
                break;
            }
        }
        if !named && !referenced {
            continue;
        }
        // Once associated, validate the entire list, including malformed
        // siblings and URI grammar, before parsing or resolving key sources.
        for list in candidate
            .children()
            .filter(|child| child.has_tag_name((XMLENC_NS, "ReferenceList")))
        {
            visit_reference_list(list, policy.resources, |_, uri| {
                if uri.is_empty() || uri.starts_with('#') {
                    budget
                        .resolver(candidate)
                        .node_for_same_document_reference(uri)?;
                }
                Ok(())
            })?;
        }
        if budget.ancestry.contains(&id) {
            return Err(XmlEncError::InvalidStructure(
                "cyclic detached EncryptedKey association".into(),
            ));
        }
        if info.source_nodes.contains(&id) {
            continue;
        }
        if derived {
            budget.charge(policy.resources)?;
            info.source_nodes.push(id);
            info.derived_keys
                .push(super::derived_key::parse(candidate, policy.resources)?);
            continue;
        }
        budget.charge_recipient(policy.resources, info.encrypted_keys.len())?;
        info.source_nodes.push(id);
        info.encrypted_keys.push(parse_encrypted_key(
            candidate,
            policy,
            allow_empty_cipher_values,
            budget,
            depth + 1,
        )?);
    }
    Ok(())
}

fn parse_encrypted_key<'doc>(
    node: Node<'doc, 'doc>,
    policy: ParsingPolicy<'_>,
    allow_empty_cipher_values: bool,
    budget: &mut KeySourceParseBudget<'_, 'doc, '_>,
    depth: usize,
) -> Result<EncryptedKey, XmlEncError> {
    require_element(node, XMLENC_NS, "EncryptedKey")?;
    // XMLEnc §3.5 allows EncryptedKey inside another key's KeyInfo. The
    // product indirection ceiling bounds both parsing and execution stacks.
    // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-Extensions-to-KeyInfo
    policy.resources.validate_key_info_reference_depth(depth)?;
    if budget.ancestry.contains(&node.id()) {
        return Err(XmlEncError::InvalidStructure(
            "cyclic EncryptedKey reference".into(),
        ));
    }
    budget.ancestry.push(node.id());
    budget.origins.push(Some(node.id()));
    budget.encrypted_key_depth += 1;
    validate_encrypted_type_attributes(node, policy)?;
    let mut children = element_children(node);
    let encryption_method = parse_encryption_method_with_limit(
        next_required(&mut children, "EncryptionMethod")?,
        policy.resources.max_encryption_metadata_bytes,
    )?;
    if children
        .peek()
        .is_some_and(|child| child.has_tag_name((XMLENC_NS, "EncryptionMethod")))
    {
        return Err(XmlEncError::InvalidStructure(
            "EncryptedKey contains more than one direct EncryptionMethod".into(),
        ));
    }
    let key_info_node = if children
        .peek()
        .is_some_and(|child| child.has_tag_name((XMLDSIG_NS, "KeyInfo")))
    {
        Some(next_required(&mut children, "KeyInfo")?)
    } else {
        None
    };
    if children
        .peek()
        .is_some_and(|child| child.has_tag_name((XMLDSIG_NS, "KeyInfo")))
    {
        return Err(XmlEncError::InvalidStructure(
            "EncryptedKey contains more than one direct KeyInfo".into(),
        ));
    }
    let cipher_data = parse_cipher_data(
        next_required(&mut children, "CipherData")?,
        allow_empty_cipher_values,
        policy,
        &mut budget.shared.transforms,
        &mut budget.shared.retained_cipher_bytes,
    )?;
    consume_encryption_properties(&mut children);
    let reference_list = if children
        .peek()
        .is_some_and(|child| child.has_tag_name((XMLENC_NS, "ReferenceList")))
    {
        Some(parse_reference_list(
            next_required(&mut children, "ReferenceList")?,
            policy,
        )?)
    } else {
        None
    };
    let carried_key_name = if children
        .peek()
        .is_some_and(|child| child.has_tag_name((XMLENC_NS, "CarriedKeyName")))
    {
        Some(parse_carried_key_name(
            next_required(&mut children, "CarriedKeyName")?,
            policy,
        )?)
    } else {
        None
    };
    if children.next().is_some() {
        return Err(XmlEncError::InvalidStructure(
            "EncryptedKey has unexpected child after CipherData".into(),
        ));
    }
    if let Some(references) = budget.references {
        // Unsupported unused recipients remain skippable. Preflight a key
        // method here only when its key source would initiate indirect work.
        if key_info_node.is_some_and(|info| {
            info.descendants().any(|child| {
                child.has_tag_name((XMLDSIG_NS, "RetrievalMethod"))
                    || child.has_tag_name((crate::xmldsig::parse::XMLDSIG11_NS, "KeyInfoReference"))
            })
        }) {
            references.validate_method(&encryption_method, false, budget.provider)?;
        }
        references.preflight_cipher_data(&cipher_data)?;
    }
    let mut key_info = match key_info_node {
        Some(key_info) => Some(parse_key_info(
            key_info,
            policy,
            allow_empty_cipher_values,
            budget,
            depth,
        )?),
        None => None,
    };
    let info = key_info.get_or_insert_with(|| ParsedKeyInfo {
        encapsulation_methods: Vec::new(),
        source_nodes: Vec::new(),
        key_name: None,
        encrypted_keys: Vec::new(),
        derived_keys: Vec::new(),
        agreement_methods: Vec::new(),
    });
    append_detached_keys(node, info, policy, allow_empty_cipher_values, budget, depth)?;
    budget.ancestry.pop();
    budget.encrypted_key_depth -= 1;
    Ok(EncryptedKey {
        sources: key_info
            .as_mut()
            .map(|info| super::EncryptionKeySources {
                encapsulation_methods: core::mem::take(&mut info.encapsulation_methods),
                encrypted_keys: core::mem::take(&mut info.encrypted_keys),
                derived_keys: core::mem::take(&mut info.derived_keys),
                agreement_methods: core::mem::take(&mut info.agreement_methods),
            })
            .unwrap_or_default(),
        id: bounded_attribute(node, "Id", policy)?,
        recipient: bounded_attribute(node, "Recipient", policy)?,
        key_name: key_info.and_then(|info| info.key_name),
        encryption_method,
        cipher_data,
        reference_list,
        carried_key_name,
    })
}

fn parse_carried_key_name(
    node: Node<'_, '_>,
    policy: ParsingPolicy<'_>,
) -> Result<String, XmlEncError> {
    require_element(node, XMLENC_NS, "CarriedKeyName")?;
    let value = bounded_simple_text(node, "CarriedKeyName", policy)?;
    if value.is_empty() {
        return Err(XmlEncError::InvalidStructure(
            "CarriedKeyName is empty".into(),
        ));
    }
    Ok(value)
}

fn parse_key_name(node: Node<'_, '_>, policy: ParsingPolicy<'_>) -> Result<String, XmlEncError> {
    let value = bounded_simple_text(node, "KeyName", policy)?;
    if value.is_empty() {
        return Err(XmlEncError::InvalidStructure("KeyName is empty".into()));
    }
    Ok(value)
}

fn parse_reference_list(
    node: Node<'_, '_>,
    policy: ParsingPolicy<'_>,
) -> Result<ReferenceList, XmlEncError> {
    parse_reference_list_with_resources(node, policy.resources)
}

pub(super) fn parse_reference_list_with_resources(
    node: Node<'_, '_>,
    resources: &crate::policy::ResourcePolicy,
) -> Result<ReferenceList, XmlEncError> {
    require_element(node, XMLENC_NS, "ReferenceList")?;
    let mut data_references = Vec::new();
    let mut key_references = Vec::new();
    visit_reference_list(node, resources, |data_reference, uri| {
        if data_reference {
            data_references.push(uri.to_owned());
        } else {
            key_references.push(uri.to_owned());
        }
        Ok(())
    })?;
    Ok(ReferenceList {
        data_references,
        key_references,
    })
}

fn visit_reference_list(
    node: Node<'_, '_>,
    resources: &crate::policy::ResourcePolicy,
    mut visit: impl FnMut(bool, &str) -> Result<(), XmlEncError>,
) -> Result<(), XmlEncError> {
    require_element(node, XMLENC_NS, "ReferenceList")?;
    let mut count = 0;
    // XMLEnc 1.1 §3.6: an element-only choice of DataReference/KeyReference;
    // URI is required, but its anyURI type does not require a nonempty value.
    // Validate the choice before allocating its URI or consulting a resolver.
    // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-ReferenceList
    for child in node.children() {
        if child.is_text()
            && child.text().is_some_and(|text| {
                !text
                    .bytes()
                    .all(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
            })
        {
            return Err(XmlEncError::InvalidStructure(
                "ReferenceList contains character data".into(),
            ));
        }
        if !child.is_element() {
            continue;
        }
        let data_reference = match (child.tag_name().namespace(), child.tag_name().name()) {
            (Some(XMLENC_NS), "DataReference") => true,
            (Some(XMLENC_NS), "KeyReference") => false,
            _ => {
                return Err(XmlEncError::InvalidStructure(format!(
                    "unsupported ReferenceList child {}",
                    child.tag_name().name(),
                )));
            }
        };
        count += 1;
        if count > resources.max_references {
            return Err(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::ENCRYPTION_REFERENCES,
                maximum: resources.max_references,
                actual: count,
            }
            .into());
        }
        let uri = child
            .attribute("URI")
            .ok_or(XmlEncError::MissingRequired("Reference URI attribute"))?;
        validate_metadata_len(uri.len(), resources.max_encryption_metadata_bytes)?;
        visit(data_reference, uri)?;
    }
    if count == 0 {
        return Err(XmlEncError::InvalidStructure(
            "ReferenceList must contain at least one reference".into(),
        ));
    }
    Ok(())
}

fn consume_encryption_properties<'a, I>(children: &mut std::iter::Peekable<I>)
where
    I: Iterator<Item = Node<'a, 'a>>,
{
    if children
        .peek()
        .is_some_and(|child| child.has_tag_name((XMLENC_NS, "EncryptionProperties")))
    {
        let _ = children.next();
    }
}

#[cfg(test)]
fn parse_encryption_method(node: Node<'_, '_>) -> Result<EncryptionMethod, XmlEncError> {
    parse_encryption_method_with_limit(node, crate::hard_limits::ENCRYPTION_METADATA_BYTE_CEILING)
}

fn parse_encryption_method_with_limit(
    node: Node<'_, '_>,
    metadata_limit: usize,
) -> Result<EncryptionMethod, XmlEncError> {
    require_element(node, XMLENC_NS, "EncryptionMethod")?;
    let algorithm = node
        .attribute("Algorithm")
        .ok_or(XmlEncError::MissingRequired(
            "EncryptionMethod Algorithm attribute",
        ))?;
    validate_metadata_len(algorithm.len(), metadata_limit)?;
    let algorithm = algorithm.to_owned();

    let mut oaep_digest = None;
    let mut mgf_algorithm = None;
    let mut oaep_params = None;
    let mut key_size_bits = None;
    for child in node.children().filter(Node::is_element) {
        match (child.tag_name().namespace(), child.tag_name().name()) {
            (Some(XMLENC_NS), "KeySize")
                if key_size_bits.is_none()
                    && oaep_params.is_none()
                    && oaep_digest.is_none()
                    && mgf_algorithm.is_none() =>
            {
                key_size_bits = Some(parse_key_size(child, metadata_limit)?);
            }
            (Some(XMLENC_NS), "OAEPparams") if oaep_params.is_none() => {
                oaep_params = Some(decode_bounded_base64_text(
                    child,
                    "OAEPparams",
                    metadata_limit,
                )?);
            }
            (Some(XMLDSIG_NS), "DigestMethod") if oaep_digest.is_none() => {
                let digest = child
                    .attribute("Algorithm")
                    .ok_or(XmlEncError::MissingRequired(
                        "DigestMethod Algorithm attribute",
                    ))?;
                validate_metadata_len(digest.len(), metadata_limit)?;
                oaep_digest = Some(digest.to_owned());
            }
            (Some(XMLENC11_NS), "MGF") if mgf_algorithm.is_none() => {
                let mgf = child
                    .attribute("Algorithm")
                    .ok_or(XmlEncError::MissingRequired("MGF Algorithm attribute"))?;
                validate_metadata_len(mgf.len(), metadata_limit)?;
                mgf_algorithm = Some(mgf.to_owned());
            }
            _ => {
                return Err(XmlEncError::InvalidStructure(format!(
                    "unsupported EncryptionMethod child {}",
                    child.tag_name().name()
                )));
            }
        }
    }

    let method = EncryptionMethod {
        algorithm,
        key_size_bits,
        oaep_digest,
        mgf_algorithm,
        oaep_params,
    };
    method.validate_structure()?;
    Ok(method)
}

fn parse_key_size(node: Node<'_, '_>, metadata_limit: usize) -> Result<usize, XmlEncError> {
    let value = bounded_simple_text_with_limit(node, "KeySize", metadata_limit)?;
    let value = value.trim();
    let bits = value
        .parse::<usize>()
        .map_err(|_| XmlEncError::InvalidStructure("KeySize must be a positive integer".into()))?;
    if bits == 0 {
        return Err(XmlEncError::InvalidStructure(
            "KeySize must be a positive integer".into(),
        ));
    }
    Ok(bits)
}

fn parse_cipher_data(
    node: Node<'_, '_>,
    allow_empty: bool,
    policy: ParsingPolicy<'_>,
    transform_budget: &mut crate::xmldsig::transforms::XPathSignatureParseBudget,
    retained_cipher_bytes: &mut usize,
) -> Result<CipherData, XmlEncError> {
    require_element(node, XMLENC_NS, "CipherData")?;
    let mut children = element_children(node);
    let value = next_required(&mut children, "CipherValue")?;
    if children.next().is_some() {
        return Err(XmlEncError::InvalidStructure(
            "CipherData must contain exactly one CipherValue or CipherReference".into(),
        ));
    }
    // XMLEnc 1.1 section 3.3 defines a choice, not two optional siblings.
    // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-CipherData
    if value.has_tag_name((XMLENC_NS, "CipherReference")) {
        let (uri, transforms) =
            super::cipher_reference::parse_reference(value, policy.resources, transform_budget)?;
        return Ok(CipherData::Reference {
            uri: uri.to_owned(),
            transforms,
        });
    }
    require_element(value, XMLENC_NS, "CipherValue")?;
    // XSD 1.0 section 3.2.16 permits only XML whitespace in base64Binary.
    // Borrow text across comments/CDATA; validate before retaining one buffer.
    // https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#base64Binary
    let payload = crate::xmldsig::whitespace::XmlBase64Payload::bounded(
        value,
        usize::MAX,
        MAX_CIPHER_VALUE_BASE64_LEN,
    )
    .map_err(|reason| {
        if reason == "unexpected nested element" {
            XmlEncError::InvalidStructure("CipherValue must not contain element children".into())
        } else {
            XmlEncError::Base64(format!("CipherValue: {reason}"))
        }
    })?;
    if payload.normalized_len == 0 && !allow_empty {
        return Err(XmlEncError::Base64("CipherValue is empty".into()));
    }
    let maximum = policy.resources.max_xml_document_bytes;
    if payload.normalized_len > maximum - *retained_cipher_bytes {
        return Err(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::AGGREGATE_ENCRYPTION_CIPHER_VALUE_BYTES,
            maximum,
            actual: retained_cipher_bytes.saturating_add(payload.normalized_len),
        }
        .into());
    }
    *retained_cipher_bytes += payload.normalized_len;
    Ok(CipherData::Value {
        value: payload
            .normalized()
            .map_err(|reason| XmlEncError::Base64(format!("CipherValue: {reason}")))?,
    })
}

fn bounded_simple_text(
    node: Node<'_, '_>,
    field: &'static str,
    policy: ParsingPolicy<'_>,
) -> Result<String, XmlEncError> {
    bounded_simple_text_with_limit(node, field, policy.resources.max_encryption_metadata_bytes)
}

pub(super) fn bounded_simple_text_with_limit(
    node: Node<'_, '_>,
    field: &'static str,
    maximum: usize,
) -> Result<String, XmlEncError> {
    if node.children().any(|child| child.is_element()) {
        return Err(XmlEncError::InvalidStructure(format!(
            "{field} must not contain element children"
        )));
    }
    let mut value = String::new();
    for text in node
        .children()
        .filter(Node::is_text)
        .filter_map(|child| child.text())
    {
        let actual = value.len().saturating_add(text.len());
        validate_metadata_len(actual, maximum)?;
        value.push_str(text);
    }
    Ok(value)
}

fn bounded_attribute(
    node: Node<'_, '_>,
    attribute: &str,
    policy: ParsingPolicy<'_>,
) -> Result<Option<String>, XmlEncError> {
    let Some(value) = node.attribute(attribute) else {
        return Ok(None);
    };
    validate_metadata_len(value.len(), policy.resources.max_encryption_metadata_bytes)?;
    Ok(Some(value.to_owned()))
}

pub(super) fn validate_metadata_len(actual: usize, maximum: usize) -> Result<(), XmlEncError> {
    if actual <= maximum {
        Ok(())
    } else {
        Err(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::ENCRYPTION_METADATA_BYTES,
            maximum,
            actual,
        }
        .into())
    }
}

pub(super) fn validate_encrypted_data_metadata<'a>(
    encrypted: &EncryptedData,
    policy: impl Into<ParsingPolicy<'a>>,
) -> Result<(), XmlEncError> {
    let policy = policy.into();
    validate_encrypted_data_metadata_inner(encrypted, policy, false)
}

fn validate_encrypted_data_metadata_inner(
    encrypted: &EncryptedData,
    policy: ParsingPolicy<'_>,
    template: bool,
) -> Result<(), XmlEncError> {
    let maximum = policy.resources.max_encryption_metadata_bytes;
    let validate = |value: Option<&str>| validate_metadata_len(value.map_or(0, str::len), maximum);
    validate(encrypted.id.as_deref())?;
    if let Some(encrypted_type) = encrypted.encrypted_type.as_ref() {
        let value = match encrypted_type {
            EncryptedDataType::Element => "http://www.w3.org/2001/04/xmlenc#Element",
            EncryptedDataType::Content => "http://www.w3.org/2001/04/xmlenc#Content",
            EncryptedDataType::Other(value) => value,
        };
        validate(Some(value))?;
    }
    validate(encrypted.key_name.as_deref())?;
    validate_encryption_method_metadata(&encrypted.encryption_method, maximum)?;
    validate_key_sources(
        &encrypted.encrypted_keys,
        &encrypted.derived_keys,
        &encrypted.agreement_methods,
        &encrypted.encapsulation_methods,
        KeySourceValidation { policy, template },
        0,
        &mut 0,
    )
}

#[derive(Clone, Copy)]
struct KeySourceValidation<'a> {
    policy: ParsingPolicy<'a>,
    template: bool,
}

fn validate_key_sources(
    keys: &[EncryptedKey],
    derived: &[super::DerivedKey],
    agreements: &[super::AgreementMethod],
    encapsulations: &[crate::key_establishment::EncapsulationMechanism],
    validation: KeySourceValidation<'_>,
    depth: usize,
    count: &mut usize,
) -> Result<(), XmlEncError> {
    let KeySourceValidation { policy, template } = validation;
    policy.resources.validate_key_info_reference_depth(depth)?;
    let actual = count
        .saturating_add(keys.len())
        .saturating_add(derived.len())
        .saturating_add(agreements.len());
    let actual = actual.saturating_add(encapsulations.len());
    policy.resources.validate_key_candidates(actual)?;
    *count = actual;
    let maximum = policy.resources.max_encryption_metadata_bytes;
    let validate = |value: Option<&str>| validate_metadata_len(value.map_or(0, str::len), maximum);
    for descriptor in encapsulations {
        policy
            .key_establishment
            .check_encapsulation(descriptor.algorithm)?;
        if descriptor.ciphertext.len() != descriptor.algorithm.ciphertext_len()
            && !(template && descriptor.ciphertext.is_empty())
        {
            return Err(crate::key_establishment::KeyEstablishmentError::Structure(
                "ciphertext size does not match Algorithm",
            )
            .into());
        }
        super::agreement::validate_role_metadata(&descriptor.key_info, maximum)?;
        *count = count.saturating_add(descriptor.key_info.sources.len());
        policy.resources.validate_key_candidates(*count)?;
    }
    for descriptor in agreements {
        validate(Some(descriptor.algorithm.uri()))?;
        validate(descriptor.legacy_digest.as_deref())?;
        validate_metadata_len(descriptor.nonce.len(), maximum)?;
        for role in descriptor.originator.iter().chain(&descriptor.recipient) {
            super::agreement::validate_role_metadata(role, maximum)?;
            *count = count.saturating_add(role.embedded_candidate_count());
            policy.resources.validate_key_candidates(*count)?;
        }
        if let Some(method) = &descriptor.method {
            method.validate_metadata(maximum)?;
        }
    }
    for descriptor in derived {
        validate(descriptor.id.as_deref())?;
        validate(descriptor.recipient.as_deref())?;
        validate(descriptor.key_type.as_deref())?;
        validate(descriptor.derived_key_name.as_deref())?;
        validate(descriptor.master_key_name.as_deref())?;
        if let Some(method) = &descriptor.method {
            method.validate_metadata(maximum)?;
        }
        if let Some(list) = &descriptor.reference_list {
            validate_reference_list(list, policy.resources)?;
        }
    }
    for key in keys {
        validate(key.id.as_deref())?;
        validate(key.recipient.as_deref())?;
        validate(key.key_name.as_deref())?;
        validate(key.carried_key_name.as_deref())?;
        validate_encryption_method_metadata(&key.encryption_method, maximum)?;
        if let Some(references) = key.reference_list.as_ref() {
            validate_reference_list(references, policy.resources)?;
        }
        validate_key_sources(
            &key.sources.encrypted_keys,
            &key.sources.derived_keys,
            &key.sources.agreement_methods,
            &key.sources.encapsulation_methods,
            validation,
            depth + 1,
            count,
        )?;
    }
    Ok(())
}

fn validate_reference_list(
    references: &ReferenceList,
    resources: &crate::policy::ResourcePolicy,
) -> Result<(), XmlEncError> {
    let count = references
        .data_references
        .len()
        .saturating_add(references.key_references.len());
    if count > resources.max_references {
        return Err(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::ENCRYPTION_REFERENCES,
            maximum: resources.max_references,
            actual: count,
        }
        .into());
    }
    if count == 0 {
        return Err(XmlEncError::InvalidStructure(
            "ReferenceList must contain at least one reference".into(),
        ));
    }
    for uri in references
        .data_references
        .iter()
        .chain(&references.key_references)
    {
        validate_metadata_len(uri.len(), resources.max_encryption_metadata_bytes)?;
    }
    Ok(())
}

fn validate_encryption_method_metadata(
    method: &EncryptionMethod,
    maximum: usize,
) -> Result<(), XmlEncError> {
    validate_metadata_len(method.algorithm.len(), maximum)?;
    if let Some(value) = method.oaep_digest.as_deref() {
        validate_metadata_len(value.len(), maximum)?;
    }
    if let Some(value) = method.mgf_algorithm.as_deref() {
        validate_metadata_len(value.len(), maximum)?;
    }
    if let Some(value) = method.oaep_params.as_deref() {
        validate_metadata_len(value.len(), maximum)?;
    }
    Ok(())
}

fn validate_encrypted_type_attributes(
    node: Node<'_, '_>,
    policy: ParsingPolicy<'_>,
) -> Result<(), XmlEncError> {
    // Both EncryptedData and EncryptedKey derive these attributes from the XML
    // Encryption EncryptedType schema. Template mutation preserves attributes
    // that are not represented in the cryptographic model, so bound them here.
    for attribute in ["Id", "Recipient", "Type", "MimeType", "Encoding"] {
        if let Some(value) = node.attribute(attribute) {
            validate_metadata_len(value.len(), policy.resources.max_encryption_metadata_bytes)?;
        }
    }
    Ok(())
}

fn parse_encrypted_data_type(value: Option<&str>) -> Option<EncryptedDataType> {
    value.map(|value| match value {
        "http://www.w3.org/2001/04/xmlenc#Element" => EncryptedDataType::Element,
        "http://www.w3.org/2001/04/xmlenc#Content" => EncryptedDataType::Content,
        other => EncryptedDataType::Other(other.to_owned()),
    })
}

pub(super) fn decode_bounded_base64_text(
    node: Node<'_, '_>,
    field: &'static str,
    maximum: usize,
) -> Result<Vec<u8>, XmlEncError> {
    if node.children().any(|child| child.is_element()) {
        return Err(XmlEncError::InvalidStructure(format!(
            "{field} must not contain element children"
        )));
    }
    let encoded_limit = maximum.div_ceil(3).saturating_mul(4);
    // XSD Datatypes 1.0 §3.2.16 permits only XML whitespace in base64Binary.
    // Borrow fragmented text; reject size before allocating the exact output.
    // https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#base64Binary
    let payload =
        crate::xmldsig::whitespace::XmlBase64Payload::bounded(node, usize::MAX, encoded_limit)
            .map_err(|reason| {
                if reason == "maximum allowed base64 length" {
                    XmlEncError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                        resource: crate::policy::resource_name::ENCRYPTION_METADATA_BYTES,
                        maximum,
                        actual: maximum.saturating_add(1),
                    })
                } else {
                    XmlEncError::Base64(format!("{field}: {reason}"))
                }
            })?;
    validate_metadata_len(payload.decoded_len, maximum)?;
    payload
        .decode()
        .map_err(|reason| XmlEncError::Base64(format!("{field}: {reason}")))
}

#[cfg(test)]
fn normalize_base64(value: &str) -> Result<String, XmlEncError> {
    // Exercise the production node parser, not a second normalization algorithm.
    let xml =
        format!("<CipherData xmlns='{XMLENC_NS}'><CipherValue>{value}</CipherValue></CipherData>");
    let document = Document::parse(&xml).expect("base64 test text forms XML");
    let policy = crate::policy::DecryptionPolicy::default();
    let mut budget =
        crate::xmldsig::transforms::XPathSignatureParseBudget::from_resources(&policy.resources);
    let CipherData::Value { value } = parse_cipher_data(
        document.root_element(),
        false,
        (&policy).into(),
        &mut budget,
        &mut 0,
    )?
    else {
        unreachable!("inline fixture")
    };
    Ok(value)
}

pub(super) fn require_element(
    node: Node<'_, '_>,
    namespace: &str,
    name: &str,
) -> Result<(), XmlEncError> {
    if node.has_tag_name((namespace, name)) {
        Ok(())
    } else {
        Err(XmlEncError::InvalidStructure(format!(
            "expected {{{namespace}}}{name}"
        )))
    }
}

fn element_children<'a>(
    node: Node<'a, 'a>,
) -> std::iter::Peekable<impl Iterator<Item = Node<'a, 'a>>> {
    node.children().filter(Node::is_element).peekable()
}

fn next_required<'a, I>(
    children: &mut std::iter::Peekable<I>,
    expected: &'static str,
) -> Result<Node<'a, 'a>, XmlEncError>
where
    I: Iterator<Item = Node<'a, 'a>>,
{
    children
        .next()
        .ok_or(XmlEncError::MissingRequired(expected))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &str = "<xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"/><xenc:CipherData><xenc:CipherValue> YWJj\nZA== </xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>";

    #[test]
    fn parses_supported_encrypted_data_and_normalizes_cipher_value() {
        // XML base64 permits line wrapping, but the retained value must be canonical.
        let parsed = parse_encrypted_data(DATA).expect("valid XMLEnc data must parse");
        assert_eq!(parsed.cipher_data.inline_value(), Some("YWJjZA=="));
        assert_eq!(parsed.encrypted_type, Some(EncryptedDataType::Element));
    }

    #[cfg(feature = "xml-backend-differential")]
    #[test]
    fn node_revalidation_uses_the_operation_backend() {
        // A node selected from an operation-scoped document must not silently
        // switch to the build default when its containing XML is revalidated.
        let backend = crate::XmlBackend::Roxmltree;
        let document = Document::parse_with_backend(DATA, backend).expect("test XML must parse");
        let expected_work = DATA.len() * 3;
        let resources = crate::policy::ResourcePolicy {
            max_xml_parse_work_bytes: expected_work,
            ..crate::policy::ResourcePolicy::default()
        };
        let policy = crate::policy::DecryptionPolicy {
            resources: resources.clone(),
            ..crate::policy::DecryptionPolicy::default()
        };
        let budget = XmlParseWorkBudget::from_resources(&resources);

        parse_encrypted_data_node_with_context_and_budget(
            document.root_element(),
            &policy,
            &budget,
            backend,
            crate::provider::default_provider(),
            &[],
        )
        .expect("node revalidation must retain the selected backend");
        assert_eq!(budget.consumed(), expected_work);

        parse_encrypted_data_node_with_policy_and_backend(
            document.root_element(),
            &policy,
            backend,
        )
        .expect("public decryption parser must retain the selected backend");
        let encryption_policy = crate::policy::EncryptionPolicy {
            resources,
            ..crate::policy::EncryptionPolicy::default()
        };
        parse_encrypted_data_template_node_with_policy_and_backend(
            document.root_element(),
            &encryption_policy,
            backend,
        )
        .expect("public template parser must retain the selected backend");
    }

    #[test]
    fn node_parsers_enforce_the_containing_document_byte_limit() {
        // A caller-selected node retains its complete source document. Passing a
        // small subtree must not bypass the operation's document-byte ceiling.
        let containing = format!("<root>{}<payload/></root>", DATA);
        let document = Document::parse(&containing).expect("containing document must parse");
        let encrypted_data = document
            .descendants()
            .find(|node| node.has_tag_name((XMLENC_NS, "EncryptedData")))
            .expect("selected EncryptedData");
        let resources = crate::policy::ResourcePolicy {
            max_xml_document_bytes: DATA.len(),
            ..crate::policy::ResourcePolicy::default()
        };
        let decryption = crate::policy::DecryptionPolicy {
            resources: resources.clone(),
            ..crate::policy::DecryptionPolicy::default()
        };
        let encryption = crate::policy::EncryptionPolicy {
            resources,
            ..crate::policy::EncryptionPolicy::default()
        };

        for result in [
            parse_encrypted_data_node_with_policy(encrypted_data, &decryption),
            parse_encrypted_data_template_node_with_policy(encrypted_data, &encryption),
        ] {
            assert!(matches!(
                result,
                Err(XmlEncError::Policy(
                    crate::policy::PolicyViolation::ResourceLimit {
                        resource: crate::policy::resource_name::XML_DOCUMENT,
                        ..
                    }
                ))
            ));
        }
    }

    #[test]
    fn node_parsers_enforce_the_containing_document_node_limit() {
        // A selected EncryptedData subtree must not hide sibling nodes from the
        // immutable resource policy supplied for the containing document.
        let containing = format!("<root>{}<payload/></root>", DATA);
        let document = Document::parse(&containing).expect("containing document must parse");
        let encrypted_data = document
            .descendants()
            .find(|node| node.has_tag_name((XMLENC_NS, "EncryptedData")))
            .expect("selected EncryptedData");
        let actual_nodes = document.root().descendants().count();
        let resources = crate::policy::ResourcePolicy {
            max_xml_nodes: actual_nodes - 1,
            ..crate::policy::ResourcePolicy::default()
        };
        let decryption = crate::policy::DecryptionPolicy {
            resources: resources.clone(),
            ..crate::policy::DecryptionPolicy::default()
        };
        let encryption = crate::policy::EncryptionPolicy {
            resources,
            ..crate::policy::EncryptionPolicy::default()
        };

        for result in [
            parse_encrypted_data_node_with_policy(encrypted_data, &decryption),
            parse_encrypted_data_template_node_with_policy(encrypted_data, &encryption),
        ] {
            assert!(matches!(
                result,
                Err(XmlEncError::Policy(
                    crate::policy::PolicyViolation::ResourceLimit {
                        resource: "XML nodes",
                        maximum,
                        actual,
                    }
                )) if maximum == actual_nodes - 1 && actual == actual_nodes
            ));
        }

        let exact_resources = crate::policy::ResourcePolicy {
            max_xml_nodes: actual_nodes,
            ..crate::policy::ResourcePolicy::default()
        };
        let exact_policy = crate::policy::DecryptionPolicy {
            resources: exact_resources,
            ..crate::policy::DecryptionPolicy::default()
        };
        parse_encrypted_data_node_with_policy(encrypted_data, &exact_policy)
            .expect("a document exactly at the node ceiling must parse");
    }

    #[test]
    fn policy_parsers_enforce_the_complete_document_depth() {
        // Both borrowed-node entry points revalidate the containing document;
        // selecting a shallow EncryptedData subtree must not hide deep ancestors.
        let containing = format!("<outer><inner>{DATA}</inner></outer>");
        let document = Document::parse(&containing).expect("containing document must parse");
        let encrypted_data = document
            .descendants()
            .find(|node| node.has_tag_name((XMLENC_NS, "EncryptedData")))
            .expect("selected EncryptedData");
        let actual_depth = encrypted_data
            .document()
            .descendants()
            .filter(|node| node.is_element())
            .map(|node| {
                node.ancestors()
                    .filter(|ancestor| ancestor.is_element())
                    .count()
            })
            .max()
            .expect("fixture has elements");
        let resources = crate::policy::ResourcePolicy {
            max_xml_depth: actual_depth - 1,
            ..crate::policy::ResourcePolicy::default()
        };
        let decryption = crate::policy::DecryptionPolicy {
            resources: resources.clone(),
            ..crate::policy::DecryptionPolicy::default()
        };
        let encryption = crate::policy::EncryptionPolicy {
            resources,
            ..crate::policy::EncryptionPolicy::default()
        };

        for result in [
            parse_encrypted_data_node_with_policy(encrypted_data, &decryption),
            parse_encrypted_data_template_node_with_policy(encrypted_data, &encryption),
        ] {
            assert!(matches!(
                result,
                Err(XmlEncError::Policy(
                    crate::policy::PolicyViolation::ResourceLimit {
                        resource: crate::policy::resource_name::XML_DEPTH,
                        maximum,
                        actual,
                    }
                )) if maximum == actual_depth - 1 && actual == actual_depth
            ));
        }
    }

    #[test]
    fn node_parsers_revalidate_the_containing_documents_dtd_policy() {
        // Node parse provenance is not available through roxmltree. Both public
        // entry points must therefore validate the source document themselves.
        let containing = format!(
            r#"<!DOCTYPE root [<!ENTITY marker "allowed">]><root>{DATA}<payload>&marker;</payload></root>"#
        );
        let document = Document::parse_with_options(
            &containing,
            ParsingOptions {
                allow_dtd: true,
                ..ParsingOptions::default()
            },
        )
        .expect("the caller can parse a document under a more permissive policy");
        let encrypted_data = document
            .descendants()
            .find(|node| node.has_tag_name((XMLENC_NS, "EncryptedData")))
            .expect("selected EncryptedData");

        for result in [
            parse_encrypted_data_node_with_policy(
                encrypted_data,
                &crate::policy::DecryptionPolicy::default(),
            ),
            parse_encrypted_data_template_node_with_policy(
                encrypted_data,
                &crate::policy::EncryptionPolicy::default(),
            ),
        ] {
            assert!(matches!(result, Err(XmlEncError::XmlParse(_))));
        }

        let mut decryption_allowed = crate::policy::DecryptionPolicy::default();
        decryption_allowed.xml.allow_internal_dtd = true;
        parse_encrypted_data_node_with_policy(encrypted_data, &decryption_allowed)
            .expect("explicitly permitted internal DTD must remain accepted");
        let mut encryption_allowed = crate::policy::EncryptionPolicy::default();
        encryption_allowed.xml.allow_internal_dtd = true;
        parse_encrypted_data_template_node_with_policy(encrypted_data, &encryption_allowed)
            .expect("template parsing must share the same explicit DTD policy");
    }

    #[test]
    fn template_parser_rejects_nonempty_invalid_cipher_values() {
        // Empty placeholders are intentional template slots, but every nonempty
        // direct or recipient value must already satisfy the base64Binary syntax.
        let invalid_direct = DATA.replace(" YWJj\nZA== ", "!!!!");
        let invalid_recipient = format!(
            "<xenc:EncryptedData xmlns:xenc=\"{XMLENC_NS}\" xmlns:ds=\"{XMLDSIG_NS}\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"/><ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"/><xenc:CipherData><xenc:CipherValue>!!!!</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedData>"
        );
        for xml in [&invalid_direct, &invalid_recipient] {
            let document = Document::parse(xml).expect("template must be well-formed XML");
            assert!(matches!(
                parse_encrypted_data_template_node_with_policy(
                    document.root_element(),
                    &crate::policy::EncryptionPolicy::default(),
                ),
                Err(XmlEncError::Base64(_))
            ));
        }

        let empty = DATA.replace(" YWJj\nZA== ", "");
        let document = Document::parse(&empty).expect("empty template must be XML");
        parse_encrypted_data_template_node_with_policy(
            document.root_element(),
            &crate::policy::EncryptionPolicy::default(),
        )
        .expect("an explicit empty template placeholder remains valid");
    }

    #[test]
    fn parses_cipher_reference_without_performing_retrieval() {
        // Parsing the source descriptor grants no URI permission or I/O.
        let xml = "<xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"/><xenc:CipherData><xenc:CipherReference URI=\"https://attacker.invalid/key\"/></xenc:CipherData></xenc:EncryptedData>";
        assert!(
            matches!(parse_encrypted_data(xml).expect("reference descriptor").cipher_data,
            CipherData::Reference { ref uri, .. } if uri == "https://attacker.invalid/key")
        );
    }

    #[test]
    fn joins_comment_split_cipher_text_and_rejects_element_children() {
        // Comments may split XML character data, but elements would change the
        // CipherValue schema and must not be silently ignored.
        let split = DATA.replace("YWJj\nZA==", "YW<!-- split -->Jj\nZA==");
        let parsed = parse_encrypted_data(&split).expect("comment-split base64 must parse");
        assert_eq!(parsed.cipher_data.inline_value(), Some("YWJjZA=="));

        let nested = DATA.replace("YWJj\nZA==", "YW<xenc:Unexpected/>JjZA==");
        assert!(matches!(
            parse_encrypted_data(&nested),
            Err(XmlEncError::InvalidStructure(_))
        ));
    }

    #[test]
    fn rejects_wrong_namespaces_and_retains_recipient_keys() {
        // Local names alone are insufficient: accepting lookalike namespaces would
        // let an attacker change the data model interpreted by the decryptor.
        let wrong_namespace = DATA.replace(XMLENC_NS, "urn:not-xmlenc");
        assert!(matches!(
            parse_encrypted_data(&wrong_namespace),
            Err(XmlEncError::InvalidStructure(_))
        ));

        let encrypted_key = |recipient: &str| {
            format!(
                "<xenc:EncryptedKey Recipient=\"{recipient}\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#kw-aes128\"/><xenc:CipherData><xenc:CipherValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>"
            )
        };
        let recipients = format!(
            "<xenc:EncryptedData xmlns:xenc=\"{XMLENC_NS}\" xmlns:ds=\"{XMLDSIG_NS}\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"/><ds:KeyInfo>{}{}</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>",
            encrypted_key("alice"),
            encrypted_key("bob")
        );
        let parsed = parse_encrypted_data(&recipients).expect("recipient keys must parse");
        assert_eq!(
            parsed
                .encrypted_keys
                .iter()
                .filter_map(|key| key.recipient.as_deref())
                .collect::<Vec<_>>(),
            ["alice", "bob"]
        );
    }

    /// Known agreement metadata parses independently of execution permission;
    /// unknown mechanisms retain their exact URI and missing algorithms fail.
    #[test]
    fn rejects_unsupported_key_agreement_explicitly() {
        let xml = format!(
            r#"<xenc:EncryptedData xmlns:xenc="{XMLENC_NS}" xmlns:ds="{XMLDSIG_NS}"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/><ds:KeyInfo><xenc:AgreementMethod Algorithm="http://www.w3.org/2001/04/xmlenc#dh"/></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>"#
        );
        let parsed = parse_encrypted_data(&xml).expect("legacy DH descriptor parses");
        assert_eq!(
            parsed.agreement_methods[0].algorithm,
            crate::policy::KeyAgreementAlgorithm::LegacyDh
        );
        let unknown = xml.replace(
            "http://www.w3.org/2001/04/xmlenc#dh",
            "urn:unknown:agreement",
        );
        assert!(matches!(
            parse_encrypted_data(&unknown),
            Err(XmlEncError::UnsupportedAlgorithm(uri))
                if uri == "urn:unknown:agreement"
        ));

        let missing_algorithm =
            xml.replace(" Algorithm=\"http://www.w3.org/2001/04/xmlenc#dh\"", "");
        assert!(matches!(
            parse_encrypted_data(&missing_algorithm),
            Err(XmlEncError::MissingRequired("AgreementMethod Algorithm"))
        ));
    }

    /// Multiple supported mechanisms remain independent ordered candidates.
    #[test]
    fn retains_supported_key_candidates_alongside_unsupported_agreement() {
        // Parsing legacy DH does not discard an independent wrapped recipient.
        let xml = format!(
            r#"<xenc:EncryptedData xmlns:xenc="{XMLENC_NS}" xmlns:ds="{XMLDSIG_NS}"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/><ds:KeyInfo><xenc:AgreementMethod Algorithm="http://www.w3.org/2001/04/xmlenc#dh"/><ds:KeyName>content-key</ds:KeyName><xenc:EncryptedKey Recipient="alice"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#kw-aes128"/><xenc:CipherData><xenc:CipherValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>"#
        );

        let parsed = parse_encrypted_data(&xml)
            .expect("a supported key candidate must take precedence over agreement fallback");
        assert_eq!(parsed.key_name.as_deref(), Some("content-key"));
        assert_eq!(parsed.encrypted_keys.len(), 1);
        assert_eq!(parsed.agreement_methods.len(), 1);
        assert_eq!(parsed.encrypted_keys[0].recipient.as_deref(), Some("alice"));
    }

    #[test]
    fn rejects_missing_algorithm_and_duplicate_oaep_parameters() {
        // Algorithm selection and OAEP parameter cardinality are security-sensitive,
        // so malformed declarations must not fall back to implicit behavior.
        let missing_algorithm = DATA.replace(
            " Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"",
            "",
        );
        assert!(matches!(
            parse_encrypted_data(&missing_algorithm),
            Err(XmlEncError::MissingRequired(_))
        ));

        let duplicate_oaep = format!(
            "<xenc:EncryptedData xmlns:xenc=\"{XMLENC_NS}\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"><xenc:OAEPparams>YQ==</xenc:OAEPparams><xenc:OAEPparams>Yg==</xenc:OAEPparams></xenc:EncryptionMethod><xenc:CipherData><xenc:CipherValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>"
        );
        assert!(matches!(
            parse_encrypted_data(&duplicate_oaep),
            Err(XmlEncError::InvalidStructure(_))
        ));

        let oaep_on_aes = DATA.replace(
            "/><xenc:CipherData>",
            "><xenc:OAEPparams>YQ==</xenc:OAEPparams></xenc:EncryptionMethod><xenc:CipherData>",
        );
        assert!(matches!(
            parse_encrypted_data(&oaep_on_aes),
            Err(XmlEncError::InvalidStructure(_))
        ));
    }

    #[test]
    fn accepts_empty_oaep_params_as_an_explicit_empty_label() {
        // base64Binary permits an empty lexical value. Preserve presence separately
        // from absence because RSA-OAEP treats both as the same empty label bytes.
        for params in ["", " \n\t "] {
            let xml = format!(
                "<xenc:EncryptionMethod xmlns:xenc=\"{XMLENC_NS}\" Algorithm=\"http://www.w3.org/2009/xmlenc11#rsa-oaep\"><xenc:OAEPparams>{params}</xenc:OAEPparams></xenc:EncryptionMethod>"
            );
            let document = Document::parse(&xml).expect("test method must be XML");
            let parsed = parse_encryption_method(document.root_element())
                .expect("empty OAEPparams must decode as an empty label");
            assert_eq!(parsed.oaep_params, Some(Vec::new()));
        }

        assert!(matches!(
            normalize_base64(" \n\t "),
            Err(XmlEncError::Base64(_))
        ));
    }

    #[test]
    fn bounds_oaep_parameters_before_base64_allocation() {
        // OAEP labels are retained as decoded metadata. The parser must cap the
        // normalized lexical form before either String or decoded Vec can grow.
        let xml = format!(
            "<xenc:EncryptionMethod xmlns:xenc=\"{XMLENC_NS}\" Algorithm=\"http://www.w3.org/2009/xmlenc11#rsa-oaep\"><xenc:OAEPparams>{}</xenc:OAEPparams></xenc:EncryptionMethod>",
            STANDARD.encode([0_u8; 65])
        );
        let document = Document::parse(&xml).expect("test method must be XML");

        assert!(matches!(
            parse_encryption_method_with_limit(document.root_element(), 64),
            Err(XmlEncError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::ENCRYPTION_METADATA_BYTES,
                    maximum: 64,
                    actual: 65,
                }
            ))
        ));
    }

    #[test]
    fn validates_explicit_key_size_for_supported_aes_methods() {
        // KeySize is valid for every EncryptionMethod, but fixed-size AES URIs
        // must reject a declaration that disagrees with the algorithm.
        for (algorithm, bits) in [
            ("http://www.w3.org/2001/04/xmlenc#aes128-cbc", 128),
            ("http://www.w3.org/2001/04/xmlenc#aes256-cbc", 256),
            ("http://www.w3.org/2009/xmlenc11#aes128-gcm", 128),
            ("http://www.w3.org/2009/xmlenc11#aes256-gcm", 256),
            ("http://www.w3.org/2001/04/xmlenc#kw-aes128", 128),
            ("http://www.w3.org/2001/04/xmlenc#kw-aes256", 256),
        ] {
            let xml = format!(
                "<xenc:EncryptionMethod xmlns:xenc=\"{XMLENC_NS}\" Algorithm=\"{algorithm}\"><xenc:KeySize>{bits}</xenc:KeySize></xenc:EncryptionMethod>"
            );
            let document = Document::parse(&xml).expect("test method must be XML");
            let parsed = parse_encryption_method(document.root_element())
                .expect("matching AES KeySize must parse");
            assert_eq!(parsed.key_size_bits, Some(bits));

            let inconsistent = xml.replace(&format!(">{bits}<"), ">192<");
            let document = Document::parse(&inconsistent).expect("test method must be XML");
            assert!(matches!(
                parse_encryption_method(document.root_element()),
                Err(XmlEncError::InvalidStructure(_))
            ));
        }

        for key_size in ["128.0", "", "128</xenc:KeySize><xenc:KeySize>128"] {
            let xml = format!(
                "<xenc:EncryptionMethod xmlns:xenc=\"{XMLENC_NS}\" Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"><xenc:KeySize>{key_size}</xenc:KeySize></xenc:EncryptionMethod>"
            );
            let document = Document::parse(&xml).expect("test method must be XML");
            assert!(matches!(
                parse_encryption_method(document.root_element()),
                Err(XmlEncError::InvalidStructure(_))
            ));
        }
    }

    #[test]
    fn key_size_text_is_bounded_before_integer_parsing() {
        // Leading zeroes keep the numeric value valid while making the lexical
        // form arbitrarily large; enforce the metadata budget before parsing.
        let key_size = format!("{}128", "0".repeat(65));
        let xml = format!(
            "<xenc:EncryptionMethod xmlns:xenc=\"{XMLENC_NS}\" Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"><xenc:KeySize>{key_size}</xenc:KeySize></xenc:EncryptionMethod>"
        );
        let document = Document::parse(&xml).expect("test method must be XML");

        assert!(matches!(
            parse_encryption_method_with_limit(document.root_element(), 64),
            Err(XmlEncError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::ENCRYPTION_METADATA_BYTES,
                    maximum: 64,
                    actual: 68,
                }
            ))
        ));
    }

    #[test]
    fn retains_key_names_and_encrypted_key_reference_list() {
        // Key selection and reference metadata must survive parsing even though
        // sibling-key dereferencing remains the caller's responsibility.
        let xml = format!(
            r##"<xenc:EncryptedData xmlns:xenc="{XMLENC_NS}" xmlns:ds="{XMLDSIG_NS}" Id="data-1"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><ds:KeyName>content-key</ds:KeyName><xenc:EncryptedKey Id="key-1" Recipient="alice"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#kw-aes128"/><ds:KeyInfo><ds:X509Data/><ds:KeyName>wrapping-key</ds:KeyName></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</xenc:CipherValue></xenc:CipherData><xenc:ReferenceList><xenc:DataReference URI="#data-1"/><xenc:KeyReference URI="#key-2"/></xenc:ReferenceList></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>"##
        );
        let parsed = parse_encrypted_data(&xml).expect("complete key metadata must parse");
        assert_eq!(parsed.key_name.as_deref(), Some("content-key"));
        let encrypted_key = parsed
            .encrypted_keys
            .first()
            .expect("embedded key must be retained");
        assert_eq!(encrypted_key.key_name.as_deref(), Some("wrapping-key"));
        let references = encrypted_key
            .reference_list
            .as_ref()
            .expect("reference list must be retained");
        assert_eq!(references.data_references, ["#data-1"]);
        assert_eq!(references.key_references, ["#key-2"]);
    }

    #[test]
    fn preserves_key_identifier_whitespace() {
        // Key identifiers use exact string matching. Leading and trailing XML
        // character data must not be normalized into a different key identity.
        let xml = format!(
            r#"<xenc:EncryptedData xmlns:xenc="{XMLENC_NS}" xmlns:ds="{XMLDSIG_NS}"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><ds:KeyName> content-key </ds:KeyName><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#kw-aes128"/><ds:KeyInfo><ds:KeyName> wrapping-key </ds:KeyName></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</xenc:CipherValue></xenc:CipherData><xenc:CarriedKeyName> transported-key </xenc:CarriedKeyName></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>"#
        );
        let parsed = parse_encrypted_data(&xml).expect("key metadata must parse");
        assert_eq!(parsed.key_name.as_deref(), Some(" content-key "));
        let encrypted_key = parsed
            .encrypted_keys
            .first()
            .expect("embedded key must be retained");
        assert_eq!(encrypted_key.key_name.as_deref(), Some(" wrapping-key "));
        assert_eq!(
            encrypted_key.carried_key_name.as_deref(),
            Some(" transported-key ")
        );
    }

    #[test]
    fn accepts_one_carried_key_name_and_rejects_duplicates() {
        // CarriedKeyName is optional transported-key metadata after ReferenceList;
        // accepting more than one would violate EncryptedKey's content model.
        let xml = format!(
            r##"<xenc:EncryptedData xmlns:xenc="{XMLENC_NS}" xmlns:ds="{XMLDSIG_NS}"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#kw-aes128"/><xenc:CipherData><xenc:CipherValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</xenc:CipherValue></xenc:CipherData><xenc:ReferenceList><xenc:DataReference URI="#data-1"/></xenc:ReferenceList><xenc:CarriedKeyName>transported-key</xenc:CarriedKeyName></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>"##
        );
        let parsed = parse_encrypted_data(&xml).expect("one CarriedKeyName must parse");
        assert_eq!(
            parsed
                .encrypted_keys
                .first()
                .expect("embedded key must be retained")
                .carried_key_name
                .as_deref(),
            Some("transported-key")
        );

        let duplicate = xml.replace(
            "</xenc:EncryptedKey>",
            "<xenc:CarriedKeyName>duplicate</xenc:CarriedKeyName></xenc:EncryptedKey>",
        );
        assert!(matches!(
            parse_encrypted_data(&duplicate),
            Err(XmlEncError::InvalidStructure(_))
        ));
    }

    #[test]
    fn accepts_encrypted_key_key_info_without_key_name() {
        // Certificates are valid EncryptedKey KeyInfo content; absence of a
        // direct KeyName must not reject RSA-backed interoperability vectors.
        let xml = format!(
            r#"<xenc:EncryptedData xmlns:xenc="{XMLENC_NS}" xmlns:ds="{XMLDSIG_NS}"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/><ds:KeyInfo><ds:X509Data><ds:X509Certificate>YQ==</ds:X509Certificate></ds:X509Data></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>YQ==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>YQ==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>"#
        );
        let parsed = parse_encrypted_data(&xml).expect("certificate-only KeyInfo must parse");
        assert_eq!(
            parsed
                .encrypted_keys
                .first()
                .expect("embedded key must be retained")
                .key_name
                .as_deref(),
            None
        );
    }

    #[test]
    fn rejects_malformed_encrypted_key_reference_lists() {
        // ReferenceList entries are security-sensitive associations: empty lists,
        // absent URIs, and foreign children must fail rather than be ignored.
        let template = format!(
            r#"<xenc:EncryptedData xmlns:xenc="{XMLENC_NS}" xmlns:ds="{XMLDSIG_NS}"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#kw-aes128"/><xenc:CipherData><xenc:CipherValue>YQ==</xenc:CipherValue></xenc:CipherData>{{reference_list}}</xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>YQ==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>"#
        );
        for malformed in [
            "<xenc:ReferenceList/>",
            "<xenc:ReferenceList><xenc:DataReference/></xenc:ReferenceList>",
            "<xenc:ReferenceList><xenc:Unexpected URI=\"#data\"/></xenc:ReferenceList>",
        ] {
            let xml = template.replace("{reference_list}", malformed);
            assert!(
                parse_encrypted_data(&xml).is_err(),
                "malformed list must fail: {malformed}"
            );
        }
    }

    #[test]
    fn bounds_normalized_cipher_value_before_decode() {
        // The public document ceiling rejects an over-ceiling inline value
        // before its text can be retained or decoded by CipherData parsing.
        let oversized = "A".repeat(MAX_CIPHER_VALUE_BASE64_LEN + 1);
        let xml = DATA.replace("YWJj\nZA==", &oversized);
        assert!(matches!(
            parse_encrypted_data(&xml),
            Err(XmlEncError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_DOCUMENT,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn policy_bounds_copied_encryption_metadata() {
        // Every retained metadata field must be rejected before it can bypass
        // the configured per-field ceiling through the XML parser entry point.
        let policy = crate::policy::DecryptionPolicy {
            resources: crate::policy::ResourcePolicy {
                max_encryption_metadata_bytes: 64,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::DecryptionPolicy::default()
        };
        let oversized = "x".repeat(65);
        for xml in [
            DATA.replace("<xenc:EncryptedData ", &format!("<xenc:EncryptedData Id=\"{oversized}\" ")),
            DATA.replace(
                "<xenc:EncryptedData ",
                &format!("<xenc:EncryptedData MimeType=\"{oversized}\" "),
            ),
            DATA.replace(
                "<xenc:EncryptedData ",
                &format!("<xenc:EncryptedData Encoding=\"{oversized}\" "),
            ),
            DATA.replace(
                "<xenc:CipherData>",
                &format!("<ds:KeyInfo xmlns:ds=\"{XMLDSIG_NS}\"><ds:KeyName>{oversized}</ds:KeyName></ds:KeyInfo><xenc:CipherData>"),
            ),
        ] {
            assert!(matches!(
                parse_encrypted_data_with_policy(&xml, &policy),
                Err(XmlEncError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                    maximum: 64,
                    actual: 65,
                    ..
                }))
            ));
        }
    }

    #[test]
    fn policy_bounds_common_encrypted_type_metadata_on_nested_keys() {
        // EncryptedKey inherits Type, MimeType, and Encoding from EncryptedType.
        // Even though the key model does not retain them, both parse entry points
        // must reject oversized values before a template can preserve them.
        let resources = crate::policy::ResourcePolicy {
            max_encryption_metadata_bytes: 64,
            ..crate::policy::ResourcePolicy::default()
        };
        let decryption = crate::policy::DecryptionPolicy {
            resources: resources.clone(),
            ..crate::policy::DecryptionPolicy::default()
        };
        let encryption = crate::policy::EncryptionPolicy {
            resources,
            ..crate::policy::EncryptionPolicy::default()
        };
        let oversized = "x".repeat(65);

        for attribute in ["Type", "MimeType", "Encoding"] {
            let xml = format!(
                r#"<xenc:EncryptedData xmlns:xenc="{XMLENC_NS}" xmlns:ds="{XMLDSIG_NS}"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><xenc:EncryptedKey {attribute}="{oversized}"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#kw-aes128"/><xenc:CipherData><xenc:CipherValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>"#
            );
            assert!(matches!(
                parse_encrypted_data_with_policy(&xml, &decryption),
                Err(XmlEncError::Policy(
                    crate::policy::PolicyViolation::ResourceLimit {
                        resource: "encryption metadata bytes",
                        maximum: 64,
                        actual: 65,
                    }
                ))
            ));

            let document = Document::parse(&xml).expect("test template must be XML");
            assert!(matches!(
                parse_encrypted_data_template_node_with_policy(
                    document.root_element(),
                    &encryption,
                ),
                Err(XmlEncError::Policy(
                    crate::policy::PolicyViolation::ResourceLimit {
                        resource: "encryption metadata bytes",
                        maximum: 64,
                        actual: 65,
                    }
                ))
            ));
        }
    }

    #[test]
    fn rejects_non_ascii_base64_before_it_can_cross_the_byte_bound() {
        // Base64 is ASCII-only. Rejecting Unicode before insertion also prevents a
        // multi-byte scalar from jumping from below the byte limit to above it.
        assert!(matches!(
            normalize_base64("YWJjéA=="),
            Err(XmlEncError::Base64(_))
        ));

        // At an admitted document size the production lexical preflight
        // rejects Unicode, including immediately after a full quartet.
        assert!(matches!(
            normalize_base64("AAAAé"),
            Err(XmlEncError::Base64(_))
        ));
    }
}
