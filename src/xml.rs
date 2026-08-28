//! Shared XML lexical invariants used before serialization.

pub mod dom;

#[cfg(any(feature = "xmldsig", test))]
use std::collections::{HashMap, HashSet, hash_map::Entry};

#[cfg(any(feature = "xmldsig", test))]
use crate::xml::dom::Document;
use crate::xml::dom::Node;

#[cfg(feature = "xmldsig")]
use crate::xml::dom::NodeId;

/// Default ID attribute names shared by XMLDSig and XMLEnc selection.
#[cfg(any(feature = "xmldsig", test))]
const DEFAULT_ID_ATTRS: &[&str] = &["ID", "Id", "id"];

/// Caller-declared XML ID attribute registration.
///
/// Registrations are request context rather than security policy. A global
/// registration applies an attribute local name to every element; a scoped
/// registration applies to one element local name in either any namespace or
/// one exact namespace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdAttributeRegistration {
    attribute_local_name: String,
    element_scope: IdAttributeElementScope,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum IdAttributeElementScope {
    AnyElement,
    AnyNamespace {
        local_name: String,
    },
    ExpandedName {
        local_name: String,
        namespace: Option<String>,
    },
}

impl IdAttributeRegistration {
    /// Register an attribute local name as an ID on every element.
    #[must_use]
    pub fn global(attribute_local_name: impl Into<String>) -> Self {
        Self {
            attribute_local_name: attribute_local_name.into(),
            element_scope: IdAttributeElementScope::AnyElement,
        }
    }

    /// Register an attribute as an ID on a local element name in any namespace.
    ///
    /// This models libxmlsec1's unqualified `--id-attr` element-name contract.
    #[must_use]
    pub fn scoped_any_namespace(
        attribute_local_name: impl Into<String>,
        element_local_name: impl Into<String>,
    ) -> Self {
        Self {
            attribute_local_name: attribute_local_name.into(),
            element_scope: IdAttributeElementScope::AnyNamespace {
                local_name: element_local_name.into(),
            },
        }
    }

    /// Register an attribute as an ID only on matching elements.
    ///
    /// `element_namespace` is the namespace URI, not an XML prefix. `None`
    /// matches only elements without a namespace.
    #[must_use]
    pub fn scoped(
        attribute_local_name: impl Into<String>,
        element_local_name: impl Into<String>,
        element_namespace: Option<&str>,
    ) -> Self {
        Self {
            attribute_local_name: attribute_local_name.into(),
            element_scope: IdAttributeElementScope::ExpandedName {
                local_name: element_local_name.into(),
                namespace: element_namespace.map(str::to_owned),
            },
        }
    }

    #[cfg(any(feature = "xmldsig", test))]
    fn matches(&self, node: Node<'_, '_>, attribute_name: &str) -> bool {
        self.attribute_local_name == attribute_name && self.matches_node(node)
    }

    pub(crate) fn attribute_local_name(&self) -> &str {
        &self.attribute_local_name
    }

    pub(crate) fn matches_node(&self, node: Node<'_, '_>) -> bool {
        match &self.element_scope {
            IdAttributeElementScope::AnyElement => true,
            IdAttributeElementScope::AnyNamespace { local_name } => {
                node.tag_name().name() == local_name
            }
            IdAttributeElementScope::ExpandedName {
                local_name,
                namespace,
            } => {
                node.tag_name().name() == local_name
                    && node.tag_name().namespace() == namespace.as_deref()
            }
        }
    }
}

/// Duplicate-safe index of XML ID attributes in one parsed document.
#[cfg(any(feature = "xmldsig", test))]
pub(crate) struct XmlIdIndex<'a> {
    nodes: HashMap<&'a str, Node<'a, 'a>>,
}

#[cfg(any(feature = "xmldsig", test))]
impl<'a> XmlIdIndex<'a> {
    /// Index standard ID spellings plus caller-declared registrations.
    pub(crate) fn with_registrations(
        document: &'a Document<'a>,
        registrations: &[IdAttributeRegistration],
    ) -> Self {
        let mut nodes = HashMap::new();
        let mut duplicates = HashSet::new();
        for node in document.descendants().filter(Node::is_element) {
            // ID registration is local-name based: qualified profile attributes
            // such as wsu:Id and xml:id participate alongside unqualified Id.
            for value in node
                .attributes()
                .filter(|attribute| {
                    DEFAULT_ID_ATTRS.contains(&attribute.name())
                        || registrations
                            .iter()
                            .any(|registration| registration.matches(node, attribute.name()))
                })
                .map(|attribute| attribute.value())
            {
                if duplicates.contains(value) {
                    continue;
                }
                match nodes.entry(value) {
                    Entry::Vacant(entry) => {
                        entry.insert(node);
                    }
                    Entry::Occupied(entry) if entry.get().id() != node.id() => {
                        entry.remove();
                        duplicates.insert(value);
                    }
                    Entry::Occupied(_) => {}
                }
            }
        }
        Self { nodes }
    }

    #[cfg(feature = "xmldsig")]
    pub(crate) fn contains(&self, id: &str) -> bool {
        self.nodes.contains_key(id)
    }

    #[cfg(feature = "xmldsig")]
    pub(crate) fn node_id(&self, id: &str) -> Option<NodeId> {
        self.nodes.get(id).map(|node| node.id())
    }

    pub(crate) fn node(&self, id: &str) -> Option<Node<'a, 'a>> {
        self.nodes.get(id).copied()
    }

    #[cfg(feature = "xmldsig")]
    pub(crate) fn len(&self) -> usize {
        self.nodes.len()
    }
}

/// Return whether a Unicode scalar is permitted by XML 1.0 Fifth Edition [2].
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) fn is_xml_1_0_character(character: char) -> bool {
    // Rust `char` cannot represent the surrogate range between D7FF and E000,
    // but the split keeps that exclusion explicit alongside XML's upper bound.
    matches!(
        character,
        '\u{9}'
            | '\u{A}'
            | '\u{D}'
            | '\u{20}'..='\u{D7FF}'
            | '\u{E000}'..='\u{FFFD}'
            | '\u{10000}'..='\u{10FFFF}'
    )
}

/// Return whether a string is an XML 1.0 NCName.
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) fn is_xml_ncname(value: &str) -> bool {
    if value.is_empty() || value.contains(':') {
        return false;
    }

    // Delegate the complete Unicode Name grammar to the selected backend
    // instead of maintaining a partial ASCII approximation.
    dom::Document::parse(&format!("<{value}/>"))
        .is_ok_and(|document| document.root_element().tag_name().name() == value)
}

#[cfg(test)]
mod tests {
    use crate::xml::dom::{Document, ParsingOptions};

    use super::{IdAttributeRegistration, XmlIdIndex};
    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    use super::{is_xml_1_0_character, is_xml_ncname};

    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    #[test]
    fn xml_1_0_character_boundaries_match_production_two() {
        // Exercise each explicit singleton/range boundary in XML 1.0 [2].
        for character in [
            '\u{9}',
            '\u{A}',
            '\u{D}',
            '\u{20}',
            '\u{D7FF}',
            '\u{E000}',
            '\u{FFFD}',
            '\u{10000}',
            '\u{10FFFF}',
        ] {
            assert!(is_xml_1_0_character(character), "{character:?}");
        }
        for character in [
            '\0', '\u{1}', '\u{B}', '\u{C}', '\u{E}', '\u{1F}', '\u{FFFE}', '\u{FFFF}',
        ] {
            assert!(!is_xml_1_0_character(character), "{character:?}");
        }
    }

    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    #[test]
    fn ncname_validation_uses_the_xml_unicode_grammar() {
        for valid in ["id", "_private", "Δοκιμή"] {
            assert!(is_xml_ncname(valid), "{valid:?}");
        }
        for invalid in ["", "1leading", "bad id", "qualified:name"] {
            assert!(!is_xml_ncname(invalid), "{invalid:?}");
        }
    }

    #[test]
    fn id_index_rejects_duplicate_values_but_not_duplicate_attributes_on_one_node() {
        // Ambiguous IDs must fail closed across every consumer, while one node
        // carrying equivalent ID spellings still denotes one stable target.
        let document = Document::parse(
            r#"<root><one ID="same" Id="same"/><two id="duplicate"/><three ID="duplicate"/></root>"#,
        )
        .expect("ID index fixture must be valid XML");
        let index = XmlIdIndex::with_registrations(&document, &[]);

        assert_eq!(
            index.node("same").map(|node| node.tag_name().name()),
            Some("one")
        );
        assert!(index.node("duplicate").is_none());
    }

    #[test]
    fn id_index_matches_supported_local_names_in_any_namespace() {
        // ID registration is defined by local attribute name. Common security
        // profiles qualify Id with wsu or xml, but the target remains the same.
        let document = Document::parse(
            r#"<root xmlns:wsu="urn:wsu"><one wsu:Id="wsu-target"/><two xml:id="xml-target"/></root>"#,
        )
        .expect("namespaced ID fixture must parse");
        let index = XmlIdIndex::with_registrations(&document, &[]);

        assert_eq!(
            index.node("wsu-target").map(|node| node.tag_name().name()),
            Some("one")
        );
        assert_eq!(
            index.node("xml-target").map(|node| node.tag_name().name()),
            Some("two")
        );
    }

    #[test]
    fn id_registration_distinguishes_any_and_exact_element_namespaces() {
        // Donor --id-attr without a namespace matches the local element name
        // everywhere, while the public scoped API retains exact-name matching.
        let document = Document::parse(
            r#"<root xmlns:n="urn:item"><item Token="plain"/><n:item Token="namespaced"/></root>"#,
        )
        .expect("scope fixture must parse");

        let any_namespace = XmlIdIndex::with_registrations(
            &document,
            &[IdAttributeRegistration::scoped_any_namespace(
                "Token", "item",
            )],
        );
        assert!(any_namespace.node("plain").is_some());
        assert!(any_namespace.node("namespaced").is_some());

        let no_namespace = XmlIdIndex::with_registrations(
            &document,
            &[IdAttributeRegistration::scoped("Token", "item", None)],
        );
        assert!(no_namespace.node("plain").is_some());
        assert!(no_namespace.node("namespaced").is_none());

        let exact_namespace = XmlIdIndex::with_registrations(
            &document,
            &[IdAttributeRegistration::scoped(
                "Token",
                "item",
                Some("urn:item"),
            )],
        );
        assert!(exact_namespace.node("plain").is_none());
        assert!(exact_namespace.node("namespaced").is_some());
    }

    #[test]
    fn dtd_id_declarations_do_not_replace_request_registration() {
        // Internal-DTD policy controls parsing only. The owned Rust tree does
        // not expose DTD attribute types, so custom IDs remain request context.
        let document = Document::parse_with_options(
            "<!DOCTYPE root [<!ATTLIST item Token ID #REQUIRED>]><root><item Token=\"target\"/></root>",
            ParsingOptions {
                allow_dtd: true,
                ..ParsingOptions::default()
            },
        )
        .expect("bounded internal DTD fixture must parse");

        let implicit = XmlIdIndex::with_registrations(&document, &[]);
        assert!(implicit.node("target").is_none());

        let registered =
            XmlIdIndex::with_registrations(&document, &[IdAttributeRegistration::global("Token")]);
        assert_eq!(
            registered.node("target").map(|node| node.tag_name().name()),
            Some("item")
        );
    }
}
