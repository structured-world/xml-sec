//! Strict parsing for the subset of XMLEnc needed by the decryption API.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use roxmltree::{Document, Node, ParsingOptions};

use crate::document::XmlParseWorkBudget;

use super::types::{
    CipherData, EncryptedData, EncryptedDataType, EncryptedKey, EncryptionMethod,
    MAX_CIPHER_VALUE_BASE64_LEN, ReferenceList, XMLDSIG_NS, XMLENC_NS, XMLENC11_NS, XmlEncError,
};

#[derive(Clone, Copy)]
pub(super) struct ParsingPolicy<'a> {
    xml: &'a crate::policy::XmlInputPolicy,
    resources: &'a crate::policy::ResourcePolicy,
}

impl<'a> From<&'a crate::policy::EncryptionPolicy> for ParsingPolicy<'a> {
    fn from(policy: &'a crate::policy::EncryptionPolicy) -> Self {
        Self {
            xml: &policy.xml,
            resources: &policy.resources,
        }
    }
}

impl<'a> From<&'a crate::policy::DecryptionPolicy> for ParsingPolicy<'a> {
    fn from(policy: &'a crate::policy::DecryptionPolicy) -> Self {
        Self {
            xml: &policy.xml,
            resources: &policy.resources,
        }
    }
}

struct ParsedKeyInfo {
    key_name: Option<String>,
    encrypted_keys: Vec<EncryptedKey>,
}

/// Parse one `xenc:EncryptedData` document fragment.
pub fn parse_encrypted_data(xml: &str) -> Result<EncryptedData, XmlEncError> {
    parse_encrypted_data_with_policy(xml, &crate::policy::DecryptionPolicy::default())
}

pub(super) fn parse_encrypted_data_with_policy(
    xml: &str,
    policy: &crate::policy::DecryptionPolicy,
) -> Result<EncryptedData, XmlEncError> {
    policy.validate()?;
    policy.resources.validate_xml_document_len(xml.len())?;
    let parse_budget = XmlParseWorkBudget::from_resources(&policy.resources);
    parse_budget.charge_policy(xml.len())?;
    let document = Document::parse_with_options(
        xml,
        ParsingOptions {
            allow_dtd: policy.xml.allow_internal_dtd,
            nodes_limit: policy.resources.effective_xml_nodes(),
            entity_resolver: None,
        },
    )?;
    parse_encrypted_data_node(document.root_element(), policy.into(), false)
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
    let parse_budget = XmlParseWorkBudget::from_resources(&policy.resources);
    parse_encrypted_data_node_with_policy_and_budget(node, policy, &parse_budget)
}

pub(super) fn parse_encrypted_data_node_with_policy_and_budget(
    node: Node<'_, '_>,
    policy: &crate::policy::DecryptionPolicy,
    parse_budget: &XmlParseWorkBudget,
) -> Result<EncryptedData, XmlEncError> {
    policy.validate()?;
    let policy = ParsingPolicy::from(policy);
    validate_node_document_policy(node, policy, parse_budget)?;
    parse_encrypted_data_node(node, policy, false)
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
    let parse_budget = XmlParseWorkBudget::from_resources(&policy.resources);
    policy.validate()?;
    let policy = ParsingPolicy::from(policy);
    validate_node_document_policy(node, policy, &parse_budget)?;
    parse_encrypted_data_node(node, policy, true)
}

fn validate_node_document_policy(
    node: Node<'_, '_>,
    policy: ParsingPolicy<'_>,
    parse_budget: &XmlParseWorkBudget,
) -> Result<(), XmlEncError> {
    let resources = &policy.resources;
    resources
        .validate_xml_document_len(node.document().input_text().len())
        .map_err(XmlEncError::from)?;
    let actual = node.document().root().descendants().count();
    if actual > resources.max_xml_nodes {
        return Err(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::XML_NODES,
            maximum: resources.max_xml_nodes,
            actual,
        }
        .into());
    }
    parse_budget.charge_policy(node.document().input_text().len())?;
    Document::parse_with_options(
        node.document().input_text(),
        ParsingOptions {
            allow_dtd: policy.xml.allow_internal_dtd,
            nodes_limit: resources.effective_xml_nodes(),
            entity_resolver: None,
        },
    )?;
    Ok(())
}

fn parse_encrypted_data_node(
    node: Node<'_, '_>,
    policy: ParsingPolicy<'_>,
    allow_empty_cipher_values: bool,
) -> Result<EncryptedData, XmlEncError> {
    require_element(node, XMLENC_NS, "EncryptedData")?;
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

    let key_info = match children.peek() {
        Some(child) if child.has_tag_name((XMLDSIG_NS, "KeyInfo")) => parse_key_info(
            next_required(&mut children, "KeyInfo")?,
            policy,
            allow_empty_cipher_values,
        )?,
        _ => ParsedKeyInfo {
            key_name: None,
            encrypted_keys: Vec::new(),
        },
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
    )?;
    consume_encryption_properties(&mut children);
    if children.next().is_some() {
        return Err(XmlEncError::InvalidStructure(
            "EncryptedData has unexpected child after CipherData".into(),
        ));
    }

    let encrypted = EncryptedData {
        id: bounded_attribute(node, "Id", policy)?,
        encrypted_type: parse_encrypted_data_type(node.attribute("Type")),
        key_name: key_info.key_name,
        encryption_method,
        encrypted_keys: key_info.encrypted_keys,
        cipher_data,
    };
    validate_encrypted_data_metadata(&encrypted, policy)?;
    Ok(encrypted)
}

fn parse_key_info(
    node: Node<'_, '_>,
    policy: ParsingPolicy<'_>,
    allow_empty_cipher_values: bool,
) -> Result<ParsedKeyInfo, XmlEncError> {
    require_element(node, XMLDSIG_NS, "KeyInfo")?;
    let mut key_name = None;
    let mut encrypted_keys = Vec::new();
    let mut unsupported_agreement = None;
    for child in node.children().filter(Node::is_element) {
        if child.has_tag_name((XMLDSIG_NS, "KeyName")) {
            if key_name.is_some() {
                return Err(XmlEncError::InvalidStructure(
                    "KeyInfo contains more than one direct KeyName".into(),
                ));
            }
            key_name = Some(parse_key_name(child, policy)?);
        } else if child.has_tag_name((XMLENC_NS, "EncryptedKey")) {
            if encrypted_keys.len() == policy.resources.max_encryption_recipients {
                return Err(crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::ENCRYPTION_RECIPIENTS,
                    maximum: policy.resources.max_encryption_recipients,
                    actual: encrypted_keys.len() + 1,
                }
                .into());
            }
            encrypted_keys.push(parse_encrypted_key(
                child,
                policy,
                allow_empty_cipher_values,
            )?);
        } else if child.has_tag_name((XMLENC_NS, "AgreementMethod")) {
            // Agreement methods require a separate key-derivation trust boundary.
            // Keep the URI as a fallback error while allowing another advertised
            // key candidate to be selected by the caller's resolver.
            let algorithm = child
                .attribute("Algorithm")
                .ok_or(XmlEncError::MissingRequired(
                    "AgreementMethod Algorithm attribute",
                ))?;
            validate_metadata_len(
                algorithm.len(),
                policy.resources.max_encryption_metadata_bytes,
            )?;
            unsupported_agreement.get_or_insert_with(|| algorithm.to_owned());
        }
    }
    if key_name.is_none()
        && encrypted_keys.is_empty()
        && let Some(algorithm) = unsupported_agreement
    {
        return Err(XmlEncError::UnsupportedAlgorithm(algorithm));
    }
    Ok(ParsedKeyInfo {
        key_name,
        encrypted_keys,
    })
}

fn parse_encrypted_key(
    node: Node<'_, '_>,
    policy: ParsingPolicy<'_>,
    allow_empty_cipher_values: bool,
) -> Result<EncryptedKey, XmlEncError> {
    require_element(node, XMLENC_NS, "EncryptedKey")?;
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
    let key_name = if children
        .peek()
        .is_some_and(|child| child.has_tag_name((XMLDSIG_NS, "KeyInfo")))
    {
        parse_key_name_hint(next_required(&mut children, "KeyInfo")?, policy)?
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
    Ok(EncryptedKey {
        id: bounded_attribute(node, "Id", policy)?,
        recipient: bounded_attribute(node, "Recipient", policy)?,
        key_name,
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

fn parse_key_name_hint(
    node: Node<'_, '_>,
    policy: ParsingPolicy<'_>,
) -> Result<Option<String>, XmlEncError> {
    require_element(node, XMLDSIG_NS, "KeyInfo")?;
    let mut key_names = node
        .children()
        .filter(|child| child.has_tag_name((XMLDSIG_NS, "KeyName")));
    let Some(key_name) = key_names.next() else {
        return Ok(None);
    };
    if key_names.next().is_some() {
        return Err(XmlEncError::InvalidStructure(
            "EncryptedKey KeyInfo contains more than one direct KeyName".into(),
        ));
    }
    parse_key_name(key_name, policy).map(Some)
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
    require_element(node, XMLENC_NS, "ReferenceList")?;
    let mut data_references = Vec::new();
    let mut key_references = Vec::new();
    for child in node.children().filter(Node::is_element) {
        let uri = child
            .attribute("URI")
            .filter(|uri| !uri.is_empty())
            .ok_or(XmlEncError::MissingRequired("Reference URI attribute"))?;
        validate_metadata_len(uri.len(), policy.resources.max_encryption_metadata_bytes)?;
        let uri = uri.to_owned();
        match (child.tag_name().namespace(), child.tag_name().name()) {
            (Some(XMLENC_NS), "DataReference") => data_references.push(uri),
            (Some(XMLENC_NS), "KeyReference") => key_references.push(uri),
            _ => {
                return Err(XmlEncError::InvalidStructure(format!(
                    "unsupported ReferenceList child {}",
                    child.tag_name().name()
                )));
            }
        }
    }
    if data_references.is_empty() && key_references.is_empty() {
        return Err(XmlEncError::InvalidStructure(
            "ReferenceList must contain at least one reference".into(),
        ));
    }
    Ok(ReferenceList {
        data_references,
        key_references,
    })
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
                oaep_params = Some(decode_bounded_base64_text(child, metadata_limit)?);
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

fn parse_cipher_data(node: Node<'_, '_>, allow_empty: bool) -> Result<CipherData, XmlEncError> {
    require_element(node, XMLENC_NS, "CipherData")?;
    let mut children = element_children(node);
    let value = next_required(&mut children, "CipherValue")?;
    require_element(value, XMLENC_NS, "CipherValue")?;
    if children.next().is_some() {
        return Err(XmlEncError::InvalidStructure(
            "CipherData must contain exactly one CipherValue".into(),
        ));
    }
    Ok(CipherData {
        value: normalize_base64_with_empty(&simple_text(value, "CipherValue")?, allow_empty)?,
    })
}

fn simple_text(node: Node<'_, '_>, element_name: &str) -> Result<String, XmlEncError> {
    if node.children().any(|child| child.is_element()) {
        return Err(XmlEncError::InvalidStructure(format!(
            "{element_name} must not contain element children"
        )));
    }
    Ok(node
        .children()
        .filter(Node::is_text)
        .filter_map(|child| child.text())
        .collect())
}

fn bounded_simple_text(
    node: Node<'_, '_>,
    field: &'static str,
    policy: ParsingPolicy<'_>,
) -> Result<String, XmlEncError> {
    bounded_simple_text_with_limit(node, field, policy.resources.max_encryption_metadata_bytes)
}

fn bounded_simple_text_with_limit(
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

fn validate_metadata_len(actual: usize, maximum: usize) -> Result<(), XmlEncError> {
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
    for key in &encrypted.encrypted_keys {
        validate(key.id.as_deref())?;
        validate(key.recipient.as_deref())?;
        validate(key.key_name.as_deref())?;
        validate(key.carried_key_name.as_deref())?;
        validate_encryption_method_metadata(&key.encryption_method, maximum)?;
        if let Some(references) = key.reference_list.as_ref() {
            for uri in references
                .data_references
                .iter()
                .chain(&references.key_references)
            {
                validate(Some(uri))?;
            }
        }
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
    bounded_attribute(node, "Type", policy)?;
    bounded_attribute(node, "MimeType", policy)?;
    bounded_attribute(node, "Encoding", policy)?;
    Ok(())
}

fn parse_encrypted_data_type(value: Option<&str>) -> Option<EncryptedDataType> {
    value.map(|value| match value {
        "http://www.w3.org/2001/04/xmlenc#Element" => EncryptedDataType::Element,
        "http://www.w3.org/2001/04/xmlenc#Content" => EncryptedDataType::Content,
        other => EncryptedDataType::Other(other.to_owned()),
    })
}

fn decode_bounded_base64_text(node: Node<'_, '_>, maximum: usize) -> Result<Vec<u8>, XmlEncError> {
    if node.children().any(|child| child.is_element()) {
        return Err(XmlEncError::InvalidStructure(
            "OAEPparams must not contain element children".into(),
        ));
    }
    let encoded_limit = maximum.div_ceil(3).saturating_mul(4);
    let mut normalized = String::with_capacity(encoded_limit);
    for character in node
        .children()
        .filter(Node::is_text)
        .filter_map(|child| child.text())
        .flat_map(str::chars)
    {
        if !character.is_ascii() {
            return Err(XmlEncError::Base64(
                "OAEPparams contains non-ASCII data".into(),
            ));
        }
        if !character.is_ascii_whitespace() {
            if normalized.len() == encoded_limit {
                return Err(crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::ENCRYPTION_METADATA_BYTES,
                    maximum,
                    actual: maximum.saturating_add(1),
                }
                .into());
            }
            normalized.push(character);
        }
    }
    let decoded = STANDARD
        .decode(normalized)
        .map_err(|error| XmlEncError::Base64(error.to_string()))?;
    validate_metadata_len(decoded.len(), maximum)?;
    Ok(decoded)
}

fn normalize_base64_with_empty(value: &str, allow_empty: bool) -> Result<String, XmlEncError> {
    let mut normalized = String::with_capacity(value.len().min(MAX_CIPHER_VALUE_BASE64_LEN));
    for character in value.chars() {
        if !character.is_ascii() {
            return Err(XmlEncError::Base64(
                "CipherValue contains non-ASCII data".into(),
            ));
        }
        if !character.is_ascii_whitespace() {
            if normalized.len() == MAX_CIPHER_VALUE_BASE64_LEN {
                return Err(XmlEncError::Base64(format!(
                    "CipherValue exceeds {MAX_CIPHER_VALUE_BASE64_LEN}-byte limit"
                )));
            }
            normalized.push(character);
        }
    }
    if normalized.is_empty() && !allow_empty {
        return Err(XmlEncError::Base64("CipherValue is empty".into()));
    }
    if !normalized.is_empty() {
        STANDARD
            .decode(&normalized)
            .map_err(|error| XmlEncError::Base64(error.to_string()))?;
    }
    Ok(normalized)
}

#[cfg(test)]
fn normalize_base64(value: &str) -> Result<String, XmlEncError> {
    normalize_base64_with_empty(value, false)
}

fn require_element(node: Node<'_, '_>, namespace: &str, name: &str) -> Result<(), XmlEncError> {
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
        assert_eq!(parsed.cipher_data.value, "YWJjZA==");
        assert_eq!(parsed.encrypted_type, Some(EncryptedDataType::Element));
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
    fn rejects_cipher_reference_and_trailing_children() {
        // External CipherReference retrieval would cross a caller-controlled trust boundary.
        let xml = "<xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"/><xenc:CipherData><xenc:CipherReference URI=\"https://attacker.invalid/key\"/></xenc:CipherData></xenc:EncryptedData>";
        assert!(
            parse_encrypted_data(xml).is_err(),
            "CipherReference must fail closed"
        );
    }

    #[test]
    fn joins_comment_split_cipher_text_and_rejects_element_children() {
        // Comments may split XML character data, but elements would change the
        // CipherValue schema and must not be silently ignored.
        let split = DATA.replace("YWJj\nZA==", "YW<!-- split -->Jj\nZA==");
        let parsed = parse_encrypted_data(&split).expect("comment-split base64 must parse");
        assert_eq!(parsed.cipher_data.value, "YWJjZA==");

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

    /// Verifies that a lone unsupported agreement reports its algorithm URI.
    #[test]
    fn rejects_unsupported_key_agreement_explicitly() {
        // AgreementMethod is outside the supported secure profile. Reporting its
        // URI avoids misclassifying a present but unsupported key as missing.
        let xml = format!(
            r#"<xenc:EncryptedData xmlns:xenc="{XMLENC_NS}" xmlns:ds="{XMLDSIG_NS}"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/><ds:KeyInfo><xenc:AgreementMethod Algorithm="http://www.w3.org/2001/04/xmlenc#dh"/></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>"#
        );
        assert!(matches!(
            parse_encrypted_data(&xml),
            Err(XmlEncError::UnsupportedAlgorithm(uri))
                if uri == "http://www.w3.org/2001/04/xmlenc#dh"
        ));

        let missing_algorithm =
            xml.replace(" Algorithm=\"http://www.w3.org/2001/04/xmlenc#dh\"", "");
        assert!(matches!(
            parse_encrypted_data(&missing_algorithm),
            Err(XmlEncError::MissingRequired(
                "AgreementMethod Algorithm attribute"
            ))
        ));
    }

    /// Verifies that unsupported agreement metadata does not hide usable keys.
    #[test]
    fn retains_supported_key_candidates_alongside_unsupported_agreement() {
        // Multi-recipient KeyInfo may advertise an unsupported agreement method
        // before a key candidate that the configured resolver can actually use.
        let xml = format!(
            r#"<xenc:EncryptedData xmlns:xenc="{XMLENC_NS}" xmlns:ds="{XMLDSIG_NS}"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/><ds:KeyInfo><xenc:AgreementMethod Algorithm="http://www.w3.org/2001/04/xmlenc#dh"/><ds:KeyName>content-key</ds:KeyName><xenc:EncryptedKey Recipient="alice"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#kw-aes128"/><xenc:CipherData><xenc:CipherValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>"#
        );

        let parsed = parse_encrypted_data(&xml)
            .expect("a supported key candidate must take precedence over agreement fallback");
        assert_eq!(parsed.key_name.as_deref(), Some("content-key"));
        assert_eq!(parsed.encrypted_keys.len(), 1);
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
        // The bound applies after XML whitespace removal and before base64 allocates
        // its decoded output, preventing oversized transient allocations.
        let oversized = "A".repeat(MAX_CIPHER_VALUE_BASE64_LEN + 1);
        assert!(matches!(
            normalize_base64(&oversized),
            Err(XmlEncError::Base64(_))
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

        let mut boundary = "A".repeat(MAX_CIPHER_VALUE_BASE64_LEN - 1);
        boundary.push('é');
        assert!(matches!(
            normalize_base64(&boundary),
            Err(XmlEncError::Base64(_))
        ));
    }
}
