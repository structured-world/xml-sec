#[test]
fn xml_version_requires_digits_after_the_period() {
    // The scanner implements the XML 1.0 character and grammar contract only.
    assert!(
        super::Scanner::new("<?xml version='1.'?><r/>")
            .next_event()
            .is_err()
    );
    assert!(
        super::Scanner::new("<?xml version='1.0'?><r/>")
            .next_event()
            .is_ok()
    );
}

#[test]
fn scanner_rejects_xml_11_until_character_rules_are_version_aware() {
    // Accepting an XML version means applying that version's complete character model.
    assert!(
        super::Scanner::new("<?xml version='1.1'?><r>&#x1;</r>")
            .next_event()
            .is_err()
    );
}
use super::*;

#[test]
fn scanner_groups_start_tags_and_splits_references() {
    let xml = "<p xmlns='urn:test' a='x&amp;y'>a&amp;&#x62;<![CDATA[c]]></p>";
    let mut scanner = Scanner::new(xml);
    let events = std::iter::from_fn(|| scanner.next_event().transpose())
        .collect::<Result<Vec<_>, _>>()
        .expect("fixture must scan");
    assert!(matches!(&events[0], Event::Start(tag) if tag.attributes.len() == 2));
    assert!(matches!(&events[1], Event::Text { text: "a", .. }));
    assert!(matches!(&events[2], Event::Reference { name: "amp", .. }));
    assert!(matches!(&events[3], Event::Reference { name: "#x62", .. }));
    assert!(matches!(&events[4], Event::CData { text: "c", .. }));
    assert!(matches!(&events[5], Event::End { .. }));
}

#[test]
fn scanner_streams_dense_reference_runs_without_buffering_events() {
    // One borrowed lexical event must be produced per pull. A source-sized reference run
    // cannot amplify into an event queue before the consumer sees its first reference.
    let xml = format!("<root>{}</root>", "&amp;".repeat(4096));
    let mut scanner = Scanner::new(&xml);
    assert!(matches!(
        scanner.next_event().expect("scan root start"),
        Some(Event::Start(_))
    ));
    assert!(matches!(
        scanner.next_event().expect("scan first reference"),
        Some(Event::Reference { name: "amp", .. })
    ));
    assert_eq!(
        scanner.pending_text.as_ref().map(|pending| pending.offset),
        Some("&amp;".len()),
        "the scanner retains only a cursor into the source token"
    );
    assert_eq!(
        std::iter::from_fn(|| scanner.next_event().transpose())
            .collect::<Result<Vec<_>, _>>()
            .expect("remaining references scan")
            .len(),
        4096
    );
}

#[test]
fn scanner_rejects_unterminated_references_in_character_data() {
    // XML 1.0 productions [66]-[68] require every reference opened by `&` to end with `;`.
    // https://www.w3.org/TR/xml/#NT-Reference
    for xml in ["<root>AT&T</root>", "<root>&bad</root>"] {
        let mut scanner = Scanner::new(xml);
        let result =
            std::iter::from_fn(|| scanner.next_event().transpose()).collect::<Result<Vec<_>, _>>();
        assert!(result.is_err(), "accepted {xml}");
    }
}

#[test]
fn scanner_keeps_the_internal_subset_as_one_doctype_event() {
    // DTD comments and declarations are not document-tree nodes. Keeping
    // them inside one event prevents semantic sidecars from diverging.
    let xml = r#"<!DOCTYPE root [<!-- <fake/> --><!ENTITY value "ok">]><root/>"#;
    let mut scanner = Scanner::new(xml);
    assert!(matches!(
        scanner.next_event().expect("scan DTD"),
        Some(Event::DocType { .. })
    ));
    assert!(matches!(
        scanner.next_event().expect("scan root"),
        Some(Event::Empty(_))
    ));
    assert!(scanner.next_event().expect("scan EOF").is_none());
}

#[test]
fn scanner_rejects_empty_and_repeated_prefix_components() {
    // The tokenizer exposes split names but accepts these malformed QName
    // spellings, so the shared lexical contract must reject them itself.
    for xml in ["<:root/>", "<root: />", "<a:b:c/>"] {
        assert!(Scanner::new(xml).next_event().is_err(), "accepted {xml}");
    }
}

#[test]
fn scanner_preserves_non_ascii_name_start_characters() {
    // XML 1.0 production [4] admits U+1680 as NameStartChar; it is not markup whitespace.
    // https://www.w3.org/TR/xml/#NT-NameStartChar
    let Some(Event::Empty(tag)) = Scanner::new("<\u{1680}/>")
        .next_event()
        .expect("valid non-ASCII name scans")
    else {
        panic!("empty element must produce one empty-tag event");
    };
    assert_eq!(tag.name.local(), "\u{1680}");
}

#[test]
fn scanner_rejects_duplicate_lexical_attributes() {
    // Namespace declarations are attributes under XML Namespaces 1.0 and
    // may not be repeated even though they do not enter the XPath axis.
    for xml in [
        "<root xmlns='urn:first' xmlns='urn:second'/>",
        "<root xmlns:p='urn:first' xmlns:p='urn:second'/>",
        "<root value='first' value='second'/>",
    ] {
        assert!(Scanner::new(xml).next_event().is_err(), "accepted {xml}");
    }
}

#[test]
fn scanner_validates_wide_attributes_without_changing_source_order() {
    use core::fmt::Write as _;

    // Wide tags use the allocation-free sorted duplicate check. Restoring source order is part
    // of the public lexical event contract and keeps downstream namespace processing stable.
    let mut attributes = String::new();
    for index in (0..4096).rev() {
        write!(attributes, " a{index}='{index}'").expect("String formatting cannot fail");
    }
    let xml = format!("<root{attributes}/>");
    let Some(Event::Empty(tag)) = Scanner::new(&xml)
        .next_event()
        .expect("wide start tag scans")
    else {
        panic!("wide empty element must produce one empty-tag event");
    };
    assert_eq!(tag.attributes.len(), 4096);
    assert_eq!(tag.attributes[0].name.local(), "a4095");
    assert_eq!(tag.attributes[4095].name.local(), "a0");

    let mut unique = String::new();
    for index in 0..4096 {
        write!(unique, " a{index}='x'").expect("String formatting cannot fail");
    }
    let duplicate = format!("<root{unique} a0='duplicate'/>");
    assert!(Scanner::new(&duplicate).next_event().is_err());
}

#[test]
fn writer_escapes_text_and_attributes_by_context() {
    let mut writer = Writer::new(Vec::new());
    writer
        .start("p", [("a", "<&\"")])
        .expect("start tag must serialize");
    writer.text("<&\"").expect("text must serialize");
    writer.end("p").expect("end tag must serialize");
    assert_eq!(
        String::from_utf8(writer.into_inner()).expect("writer emits UTF-8"),
        "<p a=\"&lt;&amp;&quot;\">&lt;&amp;\"</p>"
    );
}

#[test]
fn escaped_lengths_match_the_escaped_output() {
    // A size limit is checked against these lengths before the escaped copy
    // exists, so they must equal the output byte for byte, including next to
    // multi-byte characters and for the attribute-only references.
    for value in [
        "",
        "plain",
        "a < b & c > d",
        "\u{1680}&\u{10FFFF}<",
        "tab\tline\nreturn\r\"quote\"",
    ] {
        assert_eq!(
            escaped_text_len(value),
            Some(escape_text(value).len()),
            "{value:?}"
        );
        assert_eq!(
            escaped_attribute_len(value),
            Some(escape_attribute(value).len()),
            "{value:?}"
        );
    }
}

#[test]
fn writer_preserves_normalized_whitespace_across_reparse() {
    // Literal XML whitespace is normalized differently in character data
    // and attributes, so numeric references preserve the semantic value.
    let mut writer = Writer::new(Vec::new());
    writer
        .empty("root", [("value", "tab\tline\nreturn\r")])
        .expect("empty tag must serialize");
    assert_eq!(
        String::from_utf8(writer.into_inner()).expect("writer emits UTF-8"),
        "<root value=\"tab&#9;line&#10;return&#13;\"/>"
    );

    let mut writer = Writer::new(Vec::new());
    writer.text("line\rbreak\n").expect("text must serialize");
    assert_eq!(
        String::from_utf8(writer.into_inner()).expect("writer emits UTF-8"),
        "line&#13;break\n"
    );
}

#[test]
fn writer_rejects_invalid_element_and_attribute_qnames() {
    for name in ["", ":root", "root:", "a:b:c", "root><injected"] {
        let mut writer = Writer::new(Vec::new());
        assert!(
            writer.empty(name, []).is_err(),
            "accepted element name {name:?}"
        );
    }

    let mut writer = Writer::new(Vec::new());
    assert!(writer.empty("root", [("a:b:c", "value")]).is_err());
    let mut writer = Writer::new(Vec::new());
    assert!(writer.end("root><injected").is_err());
}

#[test]
fn writer_rejects_orphan_and_mismatched_end_tags_without_mutation() {
    // XML 1.0 section 3.1 requires every end-tag to match its open start-tag. Rejection must
    // happen before output or stack mutation so the caller can still close the open element.
    let mut orphan = Writer::new(Vec::new());
    assert!(orphan.end("root").is_err());
    assert_eq!(orphan.into_inner(), [] as [u8; 0]);

    let mut writer = Writer::new(Vec::new());
    writer.start("root", []).expect("root opens");
    writer.start("child", []).expect("child opens");
    assert!(writer.end("root").is_err());
    writer.end("child").expect("mismatch preserves child frame");
    writer.end("root").expect("root closes after child");
    assert_eq!(writer.into_inner(), b"<root><child></child></root>");
}

#[test]
fn numeric_character_references_follow_the_exact_xml_grammar() {
    for valid in ["65", "x41", "x10FFFF"] {
        let reference = format!("&#{valid};");
        assert!(decode_references(&reference).is_ok(), "rejected {valid}");
    }
    for malformed in ["", "x", "+65", "-1", "X41", "x+41", " 65"] {
        let reference = format!("&#{malformed};");
        assert!(
            decode_references(&reference).is_err(),
            "accepted {malformed}"
        );
    }
}

#[test]
fn writer_rejects_duplicate_attributes_before_emitting_markup() {
    // XML 1.0 section 3.1 forbids an attribute name from appearing more than once in the
    // same start-tag: https://www.w3.org/TR/xml/#sec-starttags
    let mut writer = Writer::new(Vec::new());
    assert!(
        writer
            .empty("root", [("id", "one"), ("id", "two")])
            .is_err()
    );
    assert_eq!(writer.into_inner(), [] as [u8; 0]);
}

#[test]
fn writer_rejects_duplicate_expanded_attribute_names() {
    // Namespaces in XML 1.0 section 6.3 makes expanded names, not lexical prefixes, unique.
    // https://www.w3.org/TR/xml-names/#uniqAttrs
    let mut writer = Writer::new(Vec::new());
    assert!(
        writer
            .empty(
                "root",
                [
                    ("xmlns:a", "urn:shared"),
                    ("xmlns:b", "urn:shared"),
                    ("a:id", "one"),
                    ("b:id", "two"),
                ],
            )
            .is_err()
    );
    assert_eq!(writer.into_inner(), [] as [u8; 0]);

    let mut writer = Writer::new(Vec::new());
    writer
        .empty(
            "root",
            [
                ("xmlns:a", "urn:first"),
                ("xmlns:b", "urn:second"),
                ("a:id", "one"),
                ("b:id", "two"),
            ],
        )
        .expect("different expanded names remain legal");
}

#[test]
fn writer_rejects_invalid_element_namespace_bindings_before_output() {
    // Namespaces in XML 1.0 sections 3 and 5 reserve xml/xmlns and require every other
    // element prefix to be declared: https://www.w3.org/TR/xml-names/#ns-decl and
    // https://www.w3.org/TR/xml-names/#ns-using
    for (name, attributes) in [
        ("p:root", Vec::new()),
        ("root", vec![("xmlns:xml", "urn:wrong")]),
        ("root", vec![("xmlns:xmlns", "urn:wrong")]),
    ] {
        let mut writer = Writer::new(Vec::new());
        assert!(writer.empty(name, attributes).is_err(), "accepted {name}");
        assert_eq!(writer.into_inner(), [] as [u8; 0]);
    }

    let mut writer = Writer::new(Vec::new());
    writer
        .empty("p:root", [("xmlns:p", "urn:bound")])
        .expect("a same-tag namespace declaration binds the element prefix");

    let mut writer = Writer::new(Vec::new());
    writer
        .start("root", [("xmlns:p", "urn:bound")])
        .expect("parent namespace declaration is valid");
    writer
        .empty("p:child", [])
        .expect("an inherited namespace declaration binds the child prefix");
}

#[test]
fn writer_rejects_characters_forbidden_by_xml_1_0() {
    let mut writer = Writer::new(Vec::new());
    assert!(writer.text("before\0after").is_err());
    assert_eq!(writer.into_inner(), [] as [u8; 0]);

    let mut writer = Writer::new(Vec::new());
    assert!(
        writer
            .empty("root", [("value", "before\u{1}after")])
            .is_err()
    );
}
