#![cfg(feature = "xmldsig")]

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
use structured_asn1::{Encoding, Limits, Parser};
use xml_sec::{
    document::XmlDocument,
    xmldsig::extension::{BooleanAttribute, ScalarError, boolean_attribute},
};

#[test]
fn boolean_attribute_preserves_presence_and_exact_schema_lexical_space() {
    // Absence is not false; XML whitespace collapse accepts the four schema
    // literals but never case folding, embedded whitespace or Unicode spaces.
    for (lexical, expected) in [
        (None, BooleanAttribute::Absent),
        (Some("true"), BooleanAttribute::Value(true)),
        (Some("false"), BooleanAttribute::Value(false)),
        (Some("1"), BooleanAttribute::Value(true)),
        (Some("0"), BooleanAttribute::Value(false)),
        (Some(" &#x9;true&#xD;&#xA; "), BooleanAttribute::Value(true)),
        (Some(""), BooleanAttribute::Malformed),
        (Some("TRUE"), BooleanAttribute::Malformed),
        (Some("tr ue"), BooleanAttribute::Malformed),
        (Some("&#xA0;true"), BooleanAttribute::Malformed),
        (Some("2"), BooleanAttribute::Malformed),
    ] {
        let attr = lexical.map_or(String::new(), |value| format!(" value=\"{value}\""));
        let document = XmlDocument::parse(format!("<root Id=\"root\"{attr}/>")).unwrap();
        let work = Memory::new(Arc::new(MemoryAccount::new(0, 10000)));
        document.with_view(|view| {
            let root = view.node_for_id("root", &[]).unwrap();
            assert_eq!(
                boolean_attribute(view, root, None, "value", &work).unwrap(),
                expected
            );
        });
    }
}

#[test]
fn boolean_attribute_matches_expanded_name_and_rejects_foreign_nodes() {
    // A same-local-name attribute in another namespace cannot replace the
    // selected attribute; identities remain bound to their original document.
    let document = XmlDocument::parse(
        "<root Id=\"root\" xmlns:p=\"urn:property\" value=\"false\" p:value=\"true\"/>",
    )
    .unwrap();
    let other = XmlDocument::parse("<root Id=\"root\" value=\"true\"/>").unwrap();
    let work = Memory::new(Arc::new(MemoryAccount::new(0, 10000)));
    let foreign = other.with_view(|view| view.node_for_id("root", &[]).unwrap());
    document.with_view(|view| {
        let root = view.node_for_id("root", &[]).unwrap();
        assert_eq!(
            boolean_attribute(view, root, None, "value", &work).unwrap(),
            BooleanAttribute::Value(false)
        );
        assert_eq!(
            boolean_attribute(view, root, Some("urn:property"), "value", &work).unwrap(),
            BooleanAttribute::Value(true)
        );
        assert!(matches!(
            boolean_attribute(view, foreign, None, "value", &work),
            Err(ScalarError::Document(_))
        ));
    });
}

#[test]
fn boolean_attribute_refuses_exhausted_work_before_attribute_scan() {
    // Already parsed input does not make future schema scans free. This reader
    // needs no heap allowance but must use the caller's live work account.
    let document = XmlDocument::parse("<root Id=\"root\" value=\"true\"/>").unwrap();
    let work = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
    document.with_view(|view| {
        let root = view.node_for_id("root", &[]).unwrap();
        assert!(matches!(
            boolean_attribute(view, root, None, "value", &work),
            Err(ScalarError::Resource(MemoryError::WorkExceeded))
        ));
    });
}

#[test]
fn boolean_attribute_preserves_parser_and_aggregate_work_ceilings() {
    // Either live ceiling can stop a repeated read. Passing borrowed Execution
    // must not erase its parser ceiling or create a new aggregate account.
    let document = XmlDocument::parse("<root Id=\"root\" value=\"true\"/>").unwrap();
    for (parser_work, aggregate_work) in [(19, 10000), (10000, 19)] {
        let memory = Memory::new(Arc::new(MemoryAccount::new(0, aggregate_work)));
        let parser = Parser::new(
            Encoding::Der,
            Limits {
                max_work: parser_work,
                ..Limits::default()
            },
            memory,
        );
        let reader = parser.read(&[], 0).unwrap();
        let work = reader.execution();
        document.with_view(|view| {
            let root = view.node_for_id("root", &[]).unwrap();
            assert_eq!(
                boolean_attribute(view, root, None, "value", &work).unwrap(),
                BooleanAttribute::Value(true)
            );
            assert!(matches!(
                boolean_attribute(view, root, None, "value", &work),
                Err(ScalarError::Resource(MemoryError::WorkExceeded))
            ));
        });
    }
}
