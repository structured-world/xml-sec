use super::*;

const CEILING: usize = crate::hard_limits::XML_ENTITY_EXPANSION_CEILING as usize;

fn backends() -> Vec<XmlBackend> {
    vec![
        #[cfg(feature = "xml-backend-xmloxide")]
        XmlBackend::Xmloxide,
        #[cfg(feature = "xml-backend-roxmltree")]
        XmlBackend::Roxmltree,
    ]
}

fn parse(xml: String, backend: XmlBackend) -> Result<XmlDocument, XmlDocumentError> {
    let settings = DocumentParseSettings::new(
        true,
        crate::hard_limits::XML_DOCUMENT_NODE_CEILING,
        crate::hard_limits::XML_DOCUMENT_BYTE_CEILING,
    )
    .with_backend(backend);
    XmlDocument::parse_with_settings(xml, settings)
}

#[test]
fn predefined_and_character_references_do_not_consume_the_entity_ceiling() {
    // The ceiling bounds substitutions of declared general entities. A predefined or
    // character reference expands nothing: it takes at least four input bytes for one
    // character, so the document byte ceiling already bounds it.
    let references = "&amp;&#13;&#x41;&lt;".repeat(CEILING);
    let xml = format!(r#"<r a="{references}">{references}</r>"#);
    for backend in backends() {
        parse(xml.clone(), backend).unwrap_or_else(|error| panic!("{backend:?}: {error:?}"));
    }
}

#[test]
fn predefined_references_inside_replacement_text_are_not_charged() {
    // Replacement text of one declared entity may hold many predefined references;
    // only the declared entity itself is a substitution.
    let replacement = "&#38;amp;".repeat(CEILING + 1);
    let xml = format!(r#"<!DOCTYPE r [<!ENTITY e "{replacement}">]><r>&e;</r>"#);
    for backend in backends() {
        parse(xml.clone(), backend).unwrap_or_else(|error| panic!("{backend:?}: {error:?}"));
    }
}

#[cfg(feature = "xml-backend-xmloxide")]
#[test]
fn tolerated_undeclared_references_are_not_charged() {
    // With an external subset an undeclared reference is tolerated and expands
    // nothing, so only the declared entity around it is a substitution: each use of
    // `e` costs one expansion, not two, in content and attributes alike.
    let uses = CEILING / 2 + 1;
    let wrapped = "&e;".repeat(uses);
    let bare = "&missing;".repeat(CEILING + 1);
    let subset = r#"<!DOCTYPE r SYSTEM "urn:absent" [<!ENTITY e "&missing;">]>"#;
    for xml in [
        format!("{subset}<r>{wrapped}</r>"),
        format!(r#"{subset}<r a="{wrapped}"/>"#),
        format!("{subset}<r>{bare}</r>"),
    ] {
        parse(xml.clone(), XmlBackend::Xmloxide)
            .unwrap_or_else(|error| panic!("{error:?}: {}", &xml[..80]));
    }
}

#[test]
fn declared_entity_references_still_reach_the_ceiling() {
    // The accounting for declared entities is unchanged, in content and attributes.
    let references = "&e;".repeat(CEILING + 1);
    for xml in [
        format!(r#"<!DOCTYPE r [<!ENTITY e "x">]><r>{references}</r>"#),
        format!(r#"<!DOCTYPE r [<!ENTITY e "x">]><r a="{references}"/>"#),
    ] {
        for backend in backends() {
            let error = parse(xml.clone(), backend)
                .err()
                .unwrap_or_else(|| panic!("{backend:?}: the ceiling was not enforced"));
            assert!(
                error.to_string().contains("entity expansion"),
                "{backend:?}: {error}"
            );
        }
    }
}

#[test]
fn a_parse_without_an_operation_still_reaches_the_expansion_work_ceiling() {
    // A parse outside any operation has no parse-work budget, so the absolute
    // expansion-work ceiling is its only bound on replacement text traversed. Recording
    // the work a document cost must not lift that ceiling.
    let maximum = crate::hard_limits::XML_ENTITY_EXPANSION_WORK_BYTE_CEILING;
    let replacement = "x".repeat(1024 * 1024);
    let uses = maximum / replacement.len() + 1;
    let references = "<a>&e;</a>".repeat(uses);
    let xml = format!(r#"<!DOCTYPE r [<!ENTITY e "{replacement}">]><r>{references}</r>"#);
    for backend in backends() {
        let error = parse(xml.clone(), backend)
            .err()
            .unwrap_or_else(|| panic!("{backend:?}: the ceiling was not enforced"));
        assert!(
            matches!(
                error,
                XmlDocumentError::Parse(ParseError::EntityExpansionWorkLimitReached {
                    maximum: reported,
                    ..
                }) if reported == maximum
            ),
            "{backend:?}: {error:?}"
        );
    }
}
