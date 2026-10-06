//! Source-aware DerivedKey processing without implicit master-key discovery.

use crate::xml::dom::Node;

use super::parse::{bounded_simple_text_with_limit, validate_metadata_len};
use super::{
    KeyDerivationMethod, XmlEncError,
    types::{XMLENC_NS, XMLENC11_NS},
};

/// Public descriptor transported by XML Encryption 1.1 DerivedKey.
/// It contains no private material and never selects a permissive policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedKey {
    /// Optional method; omission requires an explicit method in request context.
    pub method: Option<KeyDerivationMethod>,
    /// Optional name of the derived key, distinct from the master key name.
    pub derived_key_name: Option<String>,
    /// Optional master-key association. Names are whitespace significant.
    pub master_key_name: Option<String>,
    /// Optional recipient association, supplied to the application resolver.
    pub recipient: Option<String>,
    /// Optional identifier of this descriptor in its source document.
    pub id: Option<String>,
    /// Optional type hint; it never overrides the consuming algorithm's width.
    pub key_type: Option<String>,
    /// Optional association with consuming encrypted objects.
    pub reference_list: Option<super::ReferenceList>,
}

pub(super) fn parse(
    node: Node<'_, '_>,
    resources: &crate::policy::ResourcePolicy,
) -> Result<DerivedKey, XmlEncError> {
    let maximum = resources.max_encryption_metadata_bytes;
    super::parse::require_element(node, XMLENC11_NS, "DerivedKey")?;
    let attribute = |name| -> Result<_, XmlEncError> {
        let value = node.attribute(name);
        if let Some(value) = value {
            validate_metadata_len(value.len(), maximum)?;
        }
        Ok(value.map(str::to_owned))
    };
    for child in node.children() {
        if child.is_text()
            && child.text().is_some_and(|text| {
                !text
                    .bytes()
                    .all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
            })
        {
            return Err(XmlEncError::InvalidStructure(
                "DerivedKey contains character data".into(),
            ));
        }
    }
    let mut children = node.children().filter(Node::is_element).peekable();
    let method = if children
        .peek()
        .is_some_and(|child| child.has_tag_name((XMLENC11_NS, "KeyDerivationMethod")))
    {
        Some(super::key_derivation::parse_node(
            children.next().expect("peeked child"),
            maximum,
        )?)
    } else {
        None
    };
    let reference_list = if children
        .peek()
        .is_some_and(|child| child.has_tag_name((XMLENC_NS, "ReferenceList")))
    {
        Some(super::parse::parse_reference_list_with_resources(
            children.next().expect("peeked child"),
            resources,
        )?)
    } else {
        None
    };
    let mut name = |tag| -> Result<_, XmlEncError> {
        if children
            .peek()
            .is_some_and(|child| child.has_tag_name((XMLENC11_NS, tag)))
        {
            Ok(Some(bounded_simple_text_with_limit(
                children.next().expect("peeked child"),
                tag,
                maximum,
            )?))
        } else {
            Ok(None)
        }
    };
    // XMLEnc 1.1 §3.5.2: optional fields have this sequence, and missing
    // method/master information must be known by the recipient, not invented.
    // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-DerivedKey
    let derived_key_name = name("DerivedKeyName")?;
    let master_key_name = name("MasterKeyName")?;
    if children.next().is_some() {
        return Err(XmlEncError::InvalidStructure(
            "unexpected or unordered DerivedKey child".into(),
        ));
    }
    Ok(DerivedKey {
        method,
        derived_key_name,
        master_key_name,
        reference_list,
        recipient: attribute("Recipient")?,
        id: attribute("Id")?,
        key_type: attribute("Type")?,
    })
}
