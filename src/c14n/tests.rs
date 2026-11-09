use super::*;

#[cfg(feature = "xmldsig")]
fn subtree_bytes(document: &Document, apex: Node<'_, '_>, algorithm: &C14nAlgorithm) -> Vec<u8> {
    let mut output = Vec::new();
    canonicalize_visible_to_writer_bounded(
        document,
        Some(&SubtreeVisibility { apex }),
        algorithm,
        usize::MAX,
        &xml_base::XmlBaseResolutionBudget::default(),
        &mut output,
        0,
    )
    .expect("subtree canonicalization");
    output
}

#[cfg(feature = "xmldsig")]
#[test]
fn walking_from_the_apex_matches_filtering_the_whole_document() {
    // SignedInfo starts at its own element. Ancestors still supply in-scope
    // namespaces and inherited xml:* attributes, in every mode.
    let xml = r#"<r xmlns="urn:d" xmlns:p="urn:p" xmlns:q="urn:q" xml:lang="en" xml:base="http://a/b/"><!--c-->text<p:s xml:space="preserve" q:a="1" b="2"><p:i xml:base="c/">t</p:i><!--in--><?pi x?></p:s><p:after/></r>"#;
    let document = Document::parse(xml).expect("parse");
    let apex = document.root_element().first_element_child().expect("apex");
    let subtree: Vec<_> = apex.descendants().map(Node::id).collect();
    for mode in [
        C14nMode::Inclusive1_0,
        C14nMode::Inclusive1_1,
        C14nMode::Exclusive1_0,
    ] {
        for comments in [false, true] {
            let algorithm = C14nAlgorithm::new(mode, comments);
            let mut filtered = Vec::new();
            canonicalize(
                &document,
                Some(&|node| subtree.contains(&node.id())),
                &algorithm,
                &mut filtered,
            )
            .expect("filtered canonicalization");
            assert_eq!(subtree_bytes(&document, apex, &algorithm), filtered);
        }
    }
}

#[cfg(feature = "xmldsig")]
#[test]
fn relative_namespace_outside_the_apex_still_fails() {
    // Canonical XML 1.0 §2.3 refuses the document, not just the subset, so
    // starting at the apex must not skip a binding declared elsewhere.
    let document = Document::parse("<r><a/><b xmlns:p='relative'><c/></b></r>").expect("parse");
    let apex = document.root_element().first_element_child().expect("apex");
    let algorithm = C14nAlgorithm::new(C14nMode::Exclusive1_0, false);
    let mut output = Vec::new();
    let result = canonicalize_visible_to_writer_bounded(
        &document,
        Some(&SubtreeVisibility { apex }),
        &algorithm,
        usize::MAX,
        &xml_base::XmlBaseResolutionBudget::default(),
        &mut output,
        0,
    );
    assert!(matches!(result, Err(C14nError::RelativeNamespace)));
}

/// A selection by element name, attribute name and namespace prefix, which
/// fails to judge elements named `unknown`.
#[cfg(all(feature = "external-tree", feature = "xmldsig"))]
struct ByName;

#[cfg(all(feature = "external-tree", feature = "xmldsig"))]
impl SelectedNodes for ByName {
    fn node(&self, node: Node<'_, '_>) -> Option<bool> {
        if node.has_tag_name("unknown") {
            return None;
        }
        Some(
            !node.has_tag_name("drop")
                && node
                    .parent()
                    .is_none_or(|parent| !parent.has_tag_name("drop")),
        )
    }

    fn attribute(
        &self,
        _owner: Node<'_, '_>,
        _namespace: Option<&str>,
        local_name: &str,
    ) -> Option<bool> {
        Some(local_name != "hidden")
    }

    fn namespace(&self, _owner: Node<'_, '_>, prefix: &str, _uri: &str) -> Option<bool> {
        Some(prefix != "p")
    }
}

#[cfg(all(feature = "external-tree", feature = "xmldsig"))]
#[test]
fn selected_nodes_choose_elements_attributes_and_namespaces_independently() {
    // An external node set can select an element without one of its
    // attributes or namespace nodes; each is asked for separately, and a node
    // the selection cannot judge fails the canonicalization instead of being
    // guessed.
    let document = crate::XmlDocument::parse(
        r#"<r xmlns:p="urn:p" a="1" hidden="2"><keep p:x="3">t</keep><drop>gone</drop></r>"#
            .to_owned(),
    )
    .expect("parse");
    let resources = crate::policy::ResourcePolicy::default();
    let algorithm = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
    let mut output = Vec::new();
    document
        .with_view(|view| canonicalize_selected(view, &ByName, &algorithm, &resources, &mut output))
        .expect("selected canonicalization");
    assert_eq!(
        String::from_utf8(output).expect("UTF-8"),
        r#"<r a="1"><keep p:x="3">t</keep></r>"#
    );
    let unknown = crate::XmlDocument::parse("<r><unknown/></r>".to_owned()).expect("parse");
    let mut output = Vec::new();
    let result = unknown.with_view(|view| {
        canonicalize_selected(view, &ByName, &algorithm, &resources, &mut output)
    });
    assert!(matches!(result, Err(C14nError::InvalidNode)));
}

#[test]
fn from_uri_roundtrip() {
    let uris = [
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
        "http://www.w3.org/2006/12/xml-c14n11",
        "http://www.w3.org/2006/12/xml-c14n11#WithComments",
        "http://www.w3.org/2001/10/xml-exc-c14n#",
        "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
    ];
    for uri in uris {
        let algo = C14nAlgorithm::from_uri(uri).expect(uri);
        assert_eq!(algo.uri(), uri);
    }
}

#[test]
fn unknown_uri_returns_none() {
    assert!(C14nAlgorithm::from_uri("http://example.com/unknown").is_none());
}

#[test]
fn prefix_list_parsing() {
    let algo =
        C14nAlgorithm::new(C14nMode::Exclusive1_0, false).with_prefix_list("foo bar #default baz");
    assert!(algo.inclusive_prefixes.contains("foo"));
    assert!(algo.inclusive_prefixes.contains("bar"));
    assert!(algo.inclusive_prefixes.contains("baz"));
    assert!(algo.inclusive_prefixes.contains("")); // #default → ""
    assert_eq!(algo.inclusive_prefixes.len(), 4);
}

#[test]
fn canonicalize_xml_basic() {
    let xml = b"<root b=\"2\" a=\"1\"><empty/></root>";
    let algo = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
    let result = canonicalize_xml(xml, &algo).expect("c14n");
    assert_eq!(
        String::from_utf8(result).expect("utf8"),
        r#"<root a="1" b="2"><empty></empty></root>"#
    );
}

#[test]
fn canonicalize_xml_rejects_input_above_the_document_byte_ceiling_before_parsing() {
    // The convenience parser accepts untrusted bytes, so allocation bounds
    // must apply before UTF-8 or XML parsing can inspect the payload.
    let xml = vec![b' '; crate::hard_limits::XML_DOCUMENT_BYTE_CEILING + 1];
    let Err(error) = canonicalize_xml(&xml, &C14nAlgorithm::new(C14nMode::Inclusive1_0, false))
    else {
        panic!("oversized canonicalization input must be rejected");
    };
    assert!(matches!(
        error,
        C14nError::Parse(message)
            if message.contains("exceeds maximum XML document size")
    ));
}

#[test]
fn canonicalize_xml_rejects_input_above_the_document_node_ceiling() {
    // A compact document can otherwise force an effectively unbounded
    // parser-node allocation despite staying below the byte ceiling.
    let children = "<n/>".repeat(crate::hard_limits::XML_DOCUMENT_NODE_CEILING as usize);
    let xml = format!("<root>{children}</root>");
    let Err(error) = canonicalize_xml(
        xml.as_bytes(),
        &C14nAlgorithm::new(C14nMode::Inclusive1_0, false),
    ) else {
        panic!("excessive canonicalization nodes must be rejected");
    };
    assert!(matches!(
        error,
        C14nError::Parse(message) if message.contains("nodes limit reached")
    ));
}

#[test]
fn canonicalize_xml_rejects_input_above_the_document_depth_ceiling() {
    // The convenience parser is a public untrusted-input boundary, so the
    // absolute depth ceiling must apply before recursive C14N traversal.
    let depth = crate::hard_limits::XML_DOCUMENT_DEPTH_CEILING + 1;
    let xml = format!("{}{}", "<n>".repeat(depth), "</n>".repeat(depth));

    let error = canonicalize_xml(
        xml.as_bytes(),
        &C14nAlgorithm::new(C14nMode::Inclusive1_0, false),
    )
    .expect_err("over-depth canonicalization input must be rejected");

    assert!(matches!(
        error,
        C14nError::Parse(message) if message.contains("maximum element depth")
    ));
}

#[test]
fn canonicalize_xml_does_not_enable_dtd_or_external_entity_resolution() {
    // Whole-document C14N is a convenience API, not an implicit opt-in to
    // DTD parsing or external resource access.
    let xml = b"<!DOCTYPE root [<!ENTITY value 'expanded'>]><root>&value;</root>";
    let error = canonicalize_xml(xml, &C14nAlgorithm::new(C14nMode::Inclusive1_0, false))
        .expect_err("DTD input must remain disabled");
    assert!(matches!(
        error,
        C14nError::Parse(message) if message.contains("DTD detected")
    ));
}

#[test]
fn c14n_1_1_basic() {
    // C14N 1.1 serialization is identical to 1.0 for full documents.
    let xml = b"<root b=\"2\" a=\"1\"><empty/></root>";
    let algo = C14nAlgorithm::new(C14nMode::Inclusive1_1, false);
    let result = canonicalize_xml(xml, &algo).expect("c14n 1.1");
    assert_eq!(
        String::from_utf8(result).expect("utf8"),
        r#"<root a="1" b="2"><empty></empty></root>"#
    );
}

#[test]
fn c14n_1_1_with_comments() {
    let xml = b"<root><!-- comment -->text</root>";
    let algo = C14nAlgorithm::new(C14nMode::Inclusive1_1, true);
    let result = canonicalize_xml(xml, &algo).expect("c14n 1.1 with comments");
    assert_eq!(
        String::from_utf8(result).expect("utf8"),
        "<root><!-- comment -->text</root>"
    );
}

#[test]
fn c14n_1_1_without_comments() {
    let xml = b"<root><!-- comment -->text</root>";
    let algo = C14nAlgorithm::new(C14nMode::Inclusive1_1, false);
    let result = canonicalize_xml(xml, &algo).expect("c14n 1.1 without comments");
    assert_eq!(
        String::from_utf8(result).expect("utf8"),
        "<root>text</root>"
    );
}

#[test]
fn c14n_1_1_namespaces() {
    // C14N 1.1 renders all in-scope namespaces like 1.0.
    let xml = b"<root xmlns:a=\"http://a\" xmlns:b=\"http://b\"><child/></root>";
    let algo_10 = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
    let algo_11 = C14nAlgorithm::new(C14nMode::Inclusive1_1, false);
    let result_10 = canonicalize_xml(xml, &algo_10).expect("1.0");
    let result_11 = canonicalize_xml(xml, &algo_11).expect("1.1");
    // For full documents, 1.0 and 1.1 produce identical output.
    assert_eq!(result_10, result_11);
}

#[test]
fn c14n_1_1_xml_id_is_not_inherited_in_subset() {
    // C14N 1.1 explicitly excludes xml:id from simple inheritable
    // attributes, so omitting its owner must also omit the attribute.
    use crate::xml::dom::Document;
    use std::collections::HashSet;

    let xml = r#"<root xml:id="r1"><child>text</child></root>"#;
    let doc = Document::parse(xml).expect("parse");
    let child = doc.root_element().first_element_child().expect("child");

    // Build subset: child + its descendants, excluding root
    let mut ids = HashSet::new();
    let mut stack = vec![child];
    while let Some(n) = stack.pop() {
        ids.insert(n.id());
        for c in n.children() {
            stack.push(c);
        }
    }
    let pred = move |n: crate::xml::dom::Node| ids.contains(&n.id());

    let algo = C14nAlgorithm::new(C14nMode::Inclusive1_1, false);
    let mut out = Vec::new();
    canonicalize(&doc, Some(&pred), &algo, &mut out).expect("c14n 1.1 subset");
    let result = String::from_utf8(out).expect("utf8");

    assert!(
        !result.contains(r#"xml:id="r1""#),
        "xml:id must not be inherited in C14N 1.1 subset; got: {result}"
    );
}

#[test]
fn c14n_1_0_xml_id_is_inherited_in_subset() {
    // C14N 1.0 predates the C14N 1.1 xml:id exception, so xml:id follows
    // the general xml:* apex inheritance rule in a document subset.
    use crate::xml::dom::Document;
    use std::collections::HashSet;

    let xml = r#"<root xml:id="r1"><child>text</child></root>"#;
    let doc = Document::parse(xml).expect("parse");
    let child = doc.root_element().first_element_child().expect("child");
    let ids = child
        .descendants()
        .map(crate::xml::dom::Node::id)
        .collect::<HashSet<_>>();
    let pred = move |node: crate::xml::dom::Node| ids.contains(&node.id());

    let algo = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
    let mut out = Vec::new();
    canonicalize(&doc, Some(&pred), &algo, &mut out).expect("c14n 1.0 subset");

    assert_eq!(
        String::from_utf8(out).expect("utf8"),
        r#"<child xml:id="r1">text</child>"#
    );
}

#[test]
fn bounded_canonicalization_stops_before_exceeding_the_limit() {
    // XMLDSig applies a signature-wide output ceiling. The serializer must
    // stop at that ceiling instead of allocating the complete hostile value
    // and rejecting it only after serialization has finished.
    let xml = format!("<root>{}</root>", "x".repeat(4_096));
    let document = Document::parse(&xml).expect("fixed XML must parse");
    let algorithm = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
    let mut output = Vec::new();

    let error = canonicalize_with_visibility_and_position_bounded(
        &document,
        None,
        &algorithm,
        None,
        64,
        &mut output,
    )
    .expect_err("canonicalization must stop at the caller's byte ceiling");

    assert!(is_output_limit_error(&error));
    assert!(
        output.len() <= 64,
        "bounded output grew to {} bytes",
        output.len()
    );
}

#[test]
fn c14n_1_1_bounds_inherited_xml_base_components() {
    // C14N 1.1 subset fixup walks ancestors outside the selected node set.
    // Bounding that walk prevents deeply nested xml:base chains from
    // multiplying URI-resolution work during canonicalization.
    let mut xml = String::new();
    for _ in 0..=crate::hard_limits::XML_BASE_COMPONENT_CEILING {
        xml.push_str(r#"<n xml:base="segment/">"#);
    }
    xml.push_str("<leaf/>");
    for _ in 0..=crate::hard_limits::XML_BASE_COMPONENT_CEILING {
        xml.push_str("</n>");
    }
    let document = Document::parse(&xml).expect("fixed XML must parse");
    let leaf = document
        .descendants()
        .find(|node| node.has_tag_name("leaf"))
        .expect("leaf");
    let visible = |node: Node<'_, '_>| node == leaf;
    let algorithm = C14nAlgorithm::new(C14nMode::Inclusive1_1, false);
    let mut output = Vec::new();

    let error = canonicalize_with_visibility(
        &document,
        Some(&ClosureVisibility {
            predicate: &visible,
        }),
        &algorithm,
        &mut output,
    )
    .expect_err("C14N must reject an overlong inherited xml:base chain");

    assert!(
        error.to_string().contains("XML Base"),
        "unexpected C14N error: {error}"
    );
}

#[test]
fn unbounded_output_preserves_the_callers_xml_base_budget() {
    // Output capacity and XML Base work are independent limits. Omitting
    // an output ceiling must not replace the caller's XML Base policy.
    let document =
        Document::parse(r#"<root xml:base="one/"><parent xml:base="two/"><leaf/></parent></root>"#)
            .unwrap();
    let leaf = document
        .descendants()
        .find(|node| node.has_tag_name("leaf"))
        .unwrap();
    let visible = |node: Node<'_, '_>| node == leaf;
    let budget = xml_base::XmlBaseResolutionBudget::with_limits(1, usize::MAX);
    let algorithm = C14nAlgorithm::new(C14nMode::Inclusive1_1, false);
    let mut output = Vec::new();

    let error = canonicalize_with_visibility_and_position_impl(
        &document,
        Some(&ClosureVisibility {
            predicate: &visible,
        }),
        &algorithm,
        None,
        None,
        Some(&budget),
        &mut output,
    )
    .expect_err("the caller's component ceiling must survive unbounded dispatch");

    assert!(matches!(
        error,
        C14nError::XmlBaseComponentsTooLarge { max: 1, actual: 2 }
    ));
}
