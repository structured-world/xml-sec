//! Shared XML lexical invariants used before serialization.

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
    use super::{is_xml_1_0_character, is_xml_ncname};

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
}
