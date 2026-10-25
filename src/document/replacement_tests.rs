use super::*;

fn target_of(document: &XmlDocument) -> NodeIdentity {
    document.with_view(|view| view.node_for_id("target", &[]).expect("target is indexed"))
}

/// Replace the `ID="target"` element and return the committed serialization.
fn replaced(xml: &str, replacement: &str, fragment: bool) -> Result<String, XmlDocumentError> {
    let mut document = XmlDocument::parse(xml).expect("fixture must parse");
    let target = target_of(&document);
    let result = if fragment {
        document.replace_node_with_fragment(target, replacement)
    } else {
        document.replace_element(target, replacement)
    };
    match result {
        Ok(()) => {
            assert_eq!(document.generation(), 1);
            Ok(document.as_xml().to_owned())
        }
        Err(error) => {
            assert_eq!(
                document.as_xml(),
                xml,
                "a refused replacement must not commit"
            );
            assert_eq!(document.generation(), 0);
            Err(error)
        }
    }
}

#[test]
fn element_replacement_accepts_one_element_with_markup_around_it() {
    // Whitespace, comments and processing instructions may surround the one
    // element, even when the whitespace folds into the neighbouring text.
    assert_eq!(
        replaced(
            r#"<r>a<t ID="target"/>b</r>"#,
            " <!--c--> <x/> <?p d?> ",
            false
        )
        .expect("one element is a valid replacement"),
        "<r>a <!--c--> <x/> <?p d?> b</r>"
    );
    assert_eq!(
        replaced(r#"<t ID="target"/>"#, " <x/> ", false).expect("document element"),
        " <x/> "
    );
}

#[test]
fn element_replacement_reads_folded_whitespace_by_value() {
    // Whitespace written as a character reference or CDATA section is still
    // whitespace when it folds into the neighbouring text.
    for (replacement, expected) in [
        ("&#32;<x/>", "<r>a&#32;<x/>b</r>"),
        ("<![CDATA[ ]]><x/>", "<r>a<![CDATA[ ]]><x/>b</r>"),
        ("<x/>&#x9;", "<r>a<x/>&#x9;b</r>"),
    ] {
        assert_eq!(
            replaced(r#"<r>a<t ID="target"/>b</r>"#, replacement, false)
                .unwrap_or_else(|error| panic!("{replacement:?}: {error:?}")),
            expected
        );
    }
}

#[test]
fn element_replacement_rejects_other_shapes() {
    // An Element replacement is exactly one element: no sibling element, no
    // character data, nothing that closes or reopens an ancestor.
    let xml = r#"<root><p>k<t ID="target"/><![CDATA[c]]></p></root>"#;
    for replacement in [
        "<x/><y/>",
        "text<x/>",
        "<x/>&#65;",
        "",
        "<x/></p><p>",
        "<x/><![CDATA[",
        "<!--c-->",
    ] {
        assert!(
            replaced(xml, replacement, false).is_err(),
            "{replacement:?} must be refused"
        );
    }
}

#[test]
fn fragment_replacement_merges_with_neighbouring_text() {
    // Content replacement may contribute character data that folds into the
    // text around the replaced node.
    assert_eq!(
        replaced(
            r#"<r>a<t ID="target"/>b</r>"#,
            "mid &amp; <![CDATA[<c>]]><x/>",
            true
        )
        .expect("well-formed content is a valid replacement"),
        "<r>amid &amp; <![CDATA[<c>]]><x/>b</r>"
    );
    assert_eq!(
        replaced(r#"<r>a<t ID="target"/>b</r>"#, "", true).expect("empty content"),
        "<r>ab</r>"
    );
}

#[test]
fn fragment_replacement_cannot_absorb_its_neighbours() {
    // A token opened by the replacement must not be closed by markup that
    // follows it: each candidate below is well-formed as a whole document,
    // but rewrites a node outside the replaced range.
    for (xml, replacement) in [
        (
            r#"<r><p><t ID="target"/><![CDATA[k]]></p></r>"#,
            "<x/><![CDATA[",
        ),
        (r#"<r><p><t ID="target"/><?q?></p></r>"#, "<?pi "),
        (r#"<r><p><t ID="target"/>;x</p></r>"#, "&amp"),
        (r#"<r><p><t ID="target"/></p><p/></r>"#, "</p><p>"),
        (r#"<r><p><t ID="target"/><y/></p></r>"#, "<z>"),
    ] {
        assert!(
            replaced(xml, replacement, true).is_err(),
            "{replacement:?} in {xml:?} must be refused"
        );
    }
}
