//! Strict parsing for the subset of XMLEnc needed by the decryption API.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use roxmltree::{Document, Node};

use super::types::{
    CipherData, EncryptedData, EncryptedDataType, EncryptedKey, EncryptionMethod,
    MAX_CIPHER_VALUE_BASE64_LEN, ReferenceList, XMLDSIG_NS, XMLENC_NS, XMLENC11_NS, XmlEncError,
};

struct ParsedKeyInfo {
    key_name: Option<String>,
    encrypted_keys: Vec<EncryptedKey>,
}

/// Parse one `xenc:EncryptedData` document fragment.
pub fn parse_encrypted_data(xml: &str) -> Result<EncryptedData, XmlEncError> {
    let document = Document::parse(xml)?;
    parse_encrypted_data_node(document.root_element())
}

pub(super) fn parse_encrypted_data_node(node: Node<'_, '_>) -> Result<EncryptedData, XmlEncError> {
    require_element(node, XMLENC_NS, "EncryptedData")?;
    let mut children = element_children(node);
    let encryption_method =
        parse_encryption_method(next_required(&mut children, "EncryptionMethod")?)?;

    let key_info = match children.peek() {
        Some(child) if child.has_tag_name((XMLDSIG_NS, "KeyInfo")) => {
            parse_key_info(next_required(&mut children, "KeyInfo")?)?
        }
        _ => ParsedKeyInfo {
            key_name: None,
            encrypted_keys: Vec::new(),
        },
    };

    let cipher_data = parse_cipher_data(next_required(&mut children, "CipherData")?)?;
    consume_encryption_properties(&mut children);
    if children.next().is_some() {
        return Err(XmlEncError::InvalidStructure(
            "EncryptedData has unexpected child after CipherData".into(),
        ));
    }

    Ok(EncryptedData {
        id: node.attribute("Id").map(str::to_owned),
        encrypted_type: parse_type(node.attribute("Type")),
        key_name: key_info.key_name,
        encryption_method,
        encrypted_keys: key_info.encrypted_keys,
        cipher_data,
    })
}

fn parse_key_info(node: Node<'_, '_>) -> Result<ParsedKeyInfo, XmlEncError> {
    require_element(node, XMLDSIG_NS, "KeyInfo")?;
    let mut key_name = None;
    let mut encrypted_keys = Vec::new();
    for child in node.children().filter(Node::is_element) {
        if child.has_tag_name((XMLDSIG_NS, "KeyName")) {
            if key_name.is_some() {
                return Err(XmlEncError::InvalidStructure(
                    "KeyInfo contains more than one direct KeyName".into(),
                ));
            }
            key_name = Some(parse_key_name(child)?);
        } else if child.has_tag_name((XMLENC_NS, "EncryptedKey")) {
            encrypted_keys.push(parse_encrypted_key(child)?);
        }
    }
    Ok(ParsedKeyInfo {
        key_name,
        encrypted_keys,
    })
}

fn parse_encrypted_key(node: Node<'_, '_>) -> Result<EncryptedKey, XmlEncError> {
    require_element(node, XMLENC_NS, "EncryptedKey")?;
    let mut children = element_children(node);
    let encryption_method =
        parse_encryption_method(next_required(&mut children, "EncryptionMethod")?)?;
    let key_name = if children
        .peek()
        .is_some_and(|child| child.has_tag_name((XMLDSIG_NS, "KeyInfo")))
    {
        parse_key_name_hint(next_required(&mut children, "KeyInfo")?)?
    } else {
        None
    };
    let cipher_data = parse_cipher_data(next_required(&mut children, "CipherData")?)?;
    consume_encryption_properties(&mut children);
    let reference_list = if children
        .peek()
        .is_some_and(|child| child.has_tag_name((XMLENC_NS, "ReferenceList")))
    {
        Some(parse_reference_list(next_required(
            &mut children,
            "ReferenceList",
        )?)?)
    } else {
        None
    };
    let carried_key_name = if children
        .peek()
        .is_some_and(|child| child.has_tag_name((XMLENC_NS, "CarriedKeyName")))
    {
        Some(parse_carried_key_name(next_required(
            &mut children,
            "CarriedKeyName",
        )?)?)
    } else {
        None
    };
    if children.next().is_some() {
        return Err(XmlEncError::InvalidStructure(
            "EncryptedKey has unexpected child after CipherData".into(),
        ));
    }
    Ok(EncryptedKey {
        id: node.attribute("Id").map(str::to_owned),
        recipient: node.attribute("Recipient").map(str::to_owned),
        key_name,
        encryption_method,
        cipher_data,
        reference_list,
        carried_key_name,
    })
}

fn parse_carried_key_name(node: Node<'_, '_>) -> Result<String, XmlEncError> {
    require_element(node, XMLENC_NS, "CarriedKeyName")?;
    let value = simple_text(node, "CarriedKeyName")?;
    if value.is_empty() {
        return Err(XmlEncError::InvalidStructure(
            "CarriedKeyName is empty".into(),
        ));
    }
    Ok(value)
}

fn parse_key_name_hint(node: Node<'_, '_>) -> Result<Option<String>, XmlEncError> {
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
    parse_key_name(key_name).map(Some)
}

fn parse_key_name(node: Node<'_, '_>) -> Result<String, XmlEncError> {
    let value = simple_text(node, "KeyName")?;
    if value.is_empty() {
        return Err(XmlEncError::InvalidStructure("KeyName is empty".into()));
    }
    Ok(value)
}

fn parse_reference_list(node: Node<'_, '_>) -> Result<ReferenceList, XmlEncError> {
    require_element(node, XMLENC_NS, "ReferenceList")?;
    let mut data_references = Vec::new();
    let mut key_references = Vec::new();
    for child in node.children().filter(Node::is_element) {
        let uri = child
            .attribute("URI")
            .filter(|uri| !uri.is_empty())
            .ok_or(XmlEncError::MissingRequired("Reference URI attribute"))?
            .to_owned();
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

fn parse_encryption_method(node: Node<'_, '_>) -> Result<EncryptionMethod, XmlEncError> {
    require_element(node, XMLENC_NS, "EncryptionMethod")?;
    let algorithm = node
        .attribute("Algorithm")
        .ok_or(XmlEncError::MissingRequired(
            "EncryptionMethod Algorithm attribute",
        ))?
        .to_owned();

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
                key_size_bits = Some(parse_key_size(child)?);
            }
            (Some(XMLENC_NS), "OAEPparams") if oaep_params.is_none() => {
                oaep_params = Some(decode_base64_text(&simple_text(child, "OAEPparams")?)?);
            }
            (Some(XMLDSIG_NS), "DigestMethod") if oaep_digest.is_none() => {
                oaep_digest = Some(
                    child
                        .attribute("Algorithm")
                        .ok_or(XmlEncError::MissingRequired(
                            "DigestMethod Algorithm attribute",
                        ))?
                        .to_owned(),
                );
            }
            (Some(XMLENC11_NS), "MGF") if mgf_algorithm.is_none() => {
                mgf_algorithm = Some(
                    child
                        .attribute("Algorithm")
                        .ok_or(XmlEncError::MissingRequired("MGF Algorithm attribute"))?
                        .to_owned(),
                );
            }
            _ => {
                return Err(XmlEncError::InvalidStructure(format!(
                    "unsupported EncryptionMethod child {}",
                    child.tag_name().name()
                )));
            }
        }
    }

    let is_legacy_oaep = algorithm == "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
    let is_oaep11 = algorithm == "http://www.w3.org/2009/xmlenc11#rsa-oaep";
    if (oaep_params.is_some() || oaep_digest.is_some() || mgf_algorithm.is_some())
        && !is_legacy_oaep
        && !is_oaep11
    {
        return Err(XmlEncError::InvalidStructure(
            "OAEP parameters are only valid for RSA-OAEP EncryptionMethod".into(),
        ));
    }
    if mgf_algorithm.is_some() && !is_oaep11 {
        return Err(XmlEncError::InvalidStructure(
            "MGF is only valid for XML Encryption 1.1 RSA-OAEP".into(),
        ));
    }
    if let (Some(actual), Some(expected)) = (key_size_bits, fixed_aes_key_size(&algorithm))
        && actual != expected
    {
        return Err(XmlEncError::InvalidStructure(format!(
            "EncryptionMethod {algorithm} requires KeySize {expected}, got {actual}"
        )));
    }

    Ok(EncryptionMethod {
        algorithm,
        key_size_bits,
        oaep_digest,
        mgf_algorithm,
        oaep_params,
    })
}

fn parse_key_size(node: Node<'_, '_>) -> Result<usize, XmlEncError> {
    let value = simple_text(node, "KeySize")?;
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

fn fixed_aes_key_size(algorithm: &str) -> Option<usize> {
    match algorithm {
        "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
        | "http://www.w3.org/2009/xmlenc11#aes128-gcm"
        | "http://www.w3.org/2001/04/xmlenc#kw-aes128" => Some(128),
        "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
        | "http://www.w3.org/2009/xmlenc11#aes256-gcm"
        | "http://www.w3.org/2001/04/xmlenc#kw-aes256" => Some(256),
        _ => None,
    }
}

fn parse_cipher_data(node: Node<'_, '_>) -> Result<CipherData, XmlEncError> {
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
        value: normalize_base64(&simple_text(value, "CipherValue")?)?,
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

fn parse_type(value: Option<&str>) -> Option<EncryptedDataType> {
    match value {
        None => None,
        Some("http://www.w3.org/2001/04/xmlenc#Element") => Some(EncryptedDataType::Element),
        Some("http://www.w3.org/2001/04/xmlenc#Content") => Some(EncryptedDataType::Content),
        Some(other) => Some(EncryptedDataType::Other(other.to_owned())),
    }
}

fn decode_base64_text(value: &str) -> Result<Vec<u8>, XmlEncError> {
    let normalized = normalize_base64_with_empty(value, true)?;
    STANDARD
        .decode(normalized)
        .map_err(|error| XmlEncError::Base64(error.to_string()))
}

/// Normalize XML base64 whitespace while applying a pre-allocation bound.
pub(super) fn normalize_base64(value: &str) -> Result<String, XmlEncError> {
    normalize_base64_with_empty(value, false)
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
    Ok(normalized)
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

        let encrypted_key = |recipient: &str| format!(
            "<xenc:EncryptedKey Recipient=\"{recipient}\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#kw-aes128\"/><xenc:CipherData><xenc:CipherValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>"
        );
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
