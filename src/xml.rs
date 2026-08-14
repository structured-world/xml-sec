//! Shared XML lexical invariants used before serialization.

use std::collections::{HashMap, HashSet, hash_map::Entry};

use roxmltree::{Document, Node};

#[cfg(feature = "xmldsig")]
use roxmltree::NodeId;

/// Default ID attribute names shared by XMLDSig and XMLEnc selection.
const DEFAULT_ID_ATTRS: &[&str] = &["ID", "Id", "id"];

/// Duplicate-safe index of XML ID attributes in one parsed document.
pub(crate) struct XmlIdIndex<'a> {
    nodes: HashMap<&'a str, Node<'a, 'a>>,
}

impl<'a> XmlIdIndex<'a> {
    /// Index the standard `ID`, `Id`, and `id` spellings.
    #[cfg(any(feature = "xmlenc", test))]
    pub(crate) fn new(document: &'a Document<'a>) -> Self {
        Self::with_extra_attrs(document, &[])
    }

    /// Index standard ID spellings plus caller-declared local attribute names.
    pub(crate) fn with_extra_attrs(document: &'a Document<'a>, extra_attrs: &[&str]) -> Self {
        let mut names = DEFAULT_ID_ATTRS.to_vec();
        for name in extra_attrs {
            if !names.contains(name) {
                names.push(name);
            }
        }

        let mut nodes = HashMap::new();
        let mut duplicates = HashSet::new();
        for node in document.descendants().filter(Node::is_element) {
            for name in &names {
                let Some(value) = node.attribute(*name) else {
                    continue;
                };
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
        self.nodes.get(id).map(Node::id)
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
pub(crate) fn is_xml_ncname(value: &str) -> bool {
    if value.is_empty() || value.contains(':') {
        return false;
    }

    // Delegate the complete Unicode Name grammar to the parser used by the
    // rest of the crate instead of maintaining a partial ASCII approximation.
    roxmltree::Document::parse(&format!("<{value}/>"))
        .is_ok_and(|document| document.root_element().tag_name().name() == value)
}

#[cfg(test)]
mod tests {
    use roxmltree::Document;

    use super::{XmlIdIndex, is_xml_1_0_character, is_xml_ncname};

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
        let index = XmlIdIndex::new(&document);

        assert!(index.contains("same"));
        assert!(!index.contains("duplicate"));
        assert_eq!(index.len(), 1);
    }
}
