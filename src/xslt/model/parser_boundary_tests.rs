use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Arc;

use super::{
    Attribute, Document, EntityExpansionMeter, Error, ExpandedName, Namespace, NodeKind, Result,
    doctype_span, expand_document_entities, expand_entity_references,
    expand_parameter_entity_references, internal_general_entities, namespace_for, namespace_index,
    normalize_predefined_entity_declaration, parser_workspace_bytes, prepare_xml_frontend_bounded,
    set_namespace,
};
use crate::budget::{
    ENTITY_EXPANSION_BYTE_CEILING, ENTITY_EXPANSION_DEPTH_CEILING, Meter, ParseWork,
};
use crate::{BudgetKind, ExecutionBudget, ParseBudget};

fn nested_xml(depth: usize, leaf: &str) -> String {
    format!("{}{}{}", "<n>".repeat(depth), leaf, "</n>".repeat(depth))
}

#[test]
fn fragment_xml_id_index_is_preflighted_before_mutation() {
    let mut document = Document::empty(None);
    document.push(
        document.root(),
        NodeKind::Element {
            name: ExpandedName::new(None::<String>, "item"),
            prefix: None,
            attributes: vec![Attribute {
                name: ExpandedName::new(Some("http://www.w3.org/XML/1998/namespace"), "id"),
                prefix: Some("xml".into()),
                value: " target ".into(),
            }],
            namespaces: Arc::new(Vec::new()),
        },
        None,
    );
    let mut meter = Meter::new(
        ExecutionBudget {
            source_bytes: usize::MAX,
            external_documents: usize::MAX,
            recursion_depth: usize::MAX,
            xpath_evaluations: usize::MAX,
            xpath_operations: usize::MAX,
            extension_operations: usize::MAX,
            pattern_evaluations: usize::MAX,
            template_applications: usize::MAX,
            sort_comparisons: usize::MAX,
            key_entries: usize::MAX,
            result_nodes: usize::MAX,
            serialized_bytes: usize::MAX,
            messages: usize::MAX,
            owned_bytes: 0,
        },
        0,
    )
    .expect("zero-byte meter initializes");

    assert!(matches!(
        document.finalize_xml_ids(&mut meter),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
    assert_eq!(document.ids().count(), 0);
}

#[test]
fn subtree_copy_stack_crosses_the_execution_owned_bytes_gate() {
    // The copied nodes and remap are retained separately by the caller; this test isolates
    // the additional DFS stack that exists only while a wide subtree is being copied.
    let source = Document::parse("<root><a/><b/><c/><d/><e/></root>", None).expect("source parses");
    let source_root = source
        .node(source.root())
        .and_then(|root| root.children.first())
        .copied()
        .expect("source has a document element");
    let mut target = Document::empty(None);
    let mut mapping = HashMap::new();
    let mut meter = Meter::new(
        ExecutionBudget {
            source_bytes: usize::MAX,
            external_documents: usize::MAX,
            recursion_depth: usize::MAX,
            xpath_evaluations: usize::MAX,
            xpath_operations: usize::MAX,
            extension_operations: usize::MAX,
            pattern_evaluations: usize::MAX,
            template_applications: usize::MAX,
            sort_comparisons: usize::MAX,
            key_entries: usize::MAX,
            result_nodes: usize::MAX,
            serialized_bytes: usize::MAX,
            messages: usize::MAX,
            owned_bytes: 0,
        },
        0,
    )
    .expect("zero-byte meter initializes");

    assert!(matches!(
        target.append_subtree_from(
            target.root(),
            &source,
            source_root,
            &mut mapping,
            &mut meter,
        ),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
}

fn parse_tree_with_oracle_stack(xml: &str, base_uri: Option<&str>) -> Result<Document> {
    let xml = xml.to_owned();
    let base_uri = base_uri.map(str::to_owned);
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(move || Document::parse_tree(&xml, base_uri.as_deref()))
        .expect("parser oracle thread starts")
        .join()
        .expect("parser oracle thread does not panic")
}

#[test]
fn xinclude_entity_merge_accepts_duplicates_and_rejects_conflicts() {
    // XInclude 1.0 section 4.5.1 collapses duplicate entity metadata but makes a
    // same-name, different-identity entity fatal.
    // https://www.w3.org/TR/xinclude/#unparsed-entities
    let mut output = Document::empty(None);
    output
        .register_unparsed_entity("logo", "memory:logo.png")
        .expect("result entity registers");
    let mut duplicate = Document::empty(None);
    duplicate
        .register_unparsed_entity("logo", "memory:logo.png")
        .expect("duplicate source entity registers");
    output
        .merge_unparsed_entities_from(&duplicate, output.root())
        .expect("identical entity metadata coalesces");

    let mut conflicting = Document::empty(None);
    conflicting
        .register_unparsed_entity("logo", "memory:other.png")
        .expect("conflicting source entity registers");
    assert!(
        output
            .merge_unparsed_entities_from(&conflicting, output.root())
            .is_err()
    );
}

#[test]
fn oracle_and_iterative_parsers_have_identical_boundary_semantics() {
    // Attacker-controlled depth must not select a different namespace, ID, or node model.
    for depth in (62..=66).chain(126..=130) {
        let xml = nested_xml(
            depth,
            r#"<p:leaf xmlns:p="urn:leaf" xml:id="target" p:value="ok">text</p:leaf>"#,
        );
        let tree = parse_tree_with_oracle_stack(&xml, Some("memory:source.xml"))
            .expect("tree parser accepts boundary document");
        let iterative = Document::parse_iterative(&xml, Some("memory:source.xml"))
            .expect("iterative parser accepts boundary document");
        assert_eq!(tree, iterative, "parser models differ at depth {depth}");
    }
}

#[test]
fn nested_elements_share_unchanged_namespace_scopes() {
    let document = Document::parse(
        r#"<root xmlns:p="urn:test"><first><second/></first></root>"#,
        None,
    )
    .expect("nested namespace document parses");
    let scopes = document.nodes.iter().filter_map(|node| match &node.kind {
        NodeKind::Element { namespaces, .. } => Some(namespaces),
        _ => None,
    });
    let scopes = scopes.collect::<Vec<_>>();
    assert_eq!(scopes.len(), 3);
    assert!(Arc::ptr_eq(scopes[0], scopes[1]));
    assert!(Arc::ptr_eq(scopes[1], scopes[2]));
}

#[test]
fn empty_xml_base_preserves_a_path_like_document_uri() {
    // RFC 3986 empty references retain the current document path while
    // removing its fragment; treating the base as a directory moves it.
    let document = Document::parse(
        r#"<root xml:base=""><child/></root>"#,
        Some("/tmp/styles/main.xml#source"),
    )
    .expect("path-like base parses");
    let root = document
        .nodes()
        .find_map(|(_, node)| matches!(node.kind, super::NodeKind::Element { .. }).then_some(node))
        .expect("document element exists");
    assert_eq!(root.base_uri.as_deref(), Some("/tmp/styles/main.xml"));
}

#[test]
fn defaulted_xml_base_recomputes_the_complete_subtree() {
    // XML Base section 3 permits xml:base to be supplied by defaulting, and section 4.2
    // applies it to the owning element and descendants.
    // https://www.w3.org/TR/xmlbase/#syntax
    // https://www.w3.org/TR/xmlbase/#granularity
    let mut document = Document::parse(
        r#"<root><child xml:base="nested/"><leaf/></child><sibling/></root>"#,
        Some("https://example.test/original/source.xml"),
    )
    .expect("source document parses");
    let element = |document: &Document, local: &str| {
        document
            .nodes()
            .find_map(|(id, node)| match &node.kind {
                NodeKind::Element { name, .. } if name.local == local => Some(id),
                _ => None,
            })
            .expect("named element exists")
    };
    let root = element(&document, "root");
    document
        .add_default_attribute(
            root,
            Attribute {
                name: ExpandedName::new(Some(super::XML_NS), "base"),
                prefix: Some("xml".into()),
                value: "../default/".into(),
            },
        )
        .expect("trusted defaulted xml:base is applied");

    let base = |local| {
        document
            .node(element(&document, local))
            .and_then(|node| node.base_uri.as_deref())
    };
    assert_eq!(base("root"), Some("https://example.test/default/"));
    assert_eq!(base("child"), Some("https://example.test/default/nested/"));
    assert_eq!(base("leaf"), Some("https://example.test/default/nested/"));
    assert_eq!(base("sibling"), Some("https://example.test/default/"));
}

#[test]
fn oracle_and_iterative_parsers_coalesce_adjacent_character_data() {
    // Tokenizer event boundaries are not XPath text-node boundaries: text, references and
    // CDATA in one character-data run must project as one semantic text node.
    for depth in 126..=130 {
        let xml = nested_xml(depth, "<leaf>a&amp;b&#x21;<![CDATA[c]]>d</leaf>");
        let tree = parse_tree_with_oracle_stack(&xml, None)
            .expect("tree parser accepts adjacent character data");
        let iterative = Document::parse_iterative(&xml, None)
            .expect("iterative parser accepts adjacent character data");
        assert_eq!(tree, iterative, "text projection differs at depth {depth}");
    }
}

#[test]
fn iterative_parser_excludes_the_pi_separator_from_data() {
    // XML's mandatory S between PITarget and data is syntax, not part of
    // the processing-instruction value exposed by the semantic model.
    let document = Document::parse_iterative("<root><?target   value ?></root>", None)
        .expect("processing instruction parses");
    let value = document.nodes().find_map(|(_, node)| match &node.kind {
        super::NodeKind::ProcessingInstruction { value, .. } => value.as_deref(),
        _ => None,
    });
    assert_eq!(value, Some("value "));
}

#[test]
fn iterative_parser_bounds_entity_references_across_the_document() {
    // Sibling references share one expansion allowance; resetting the
    // counter per sibling makes total expanded output attacker-controlled.
    let body = format!("<leaf>{}</leaf>", "&e;".repeat(256));
    let xml = format!(r#"<!DOCTYPE n [<!ENTITY e "x">]>{}"#, nested_xml(65, &body));

    let budget = ParseBudget::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        255,
        usize::MAX,
        usize::MAX,
    );
    assert!(matches!(
        Document::parse_with_budget(&xml, None, budget),
        Err(Error::Budget {
            kind: BudgetKind::EntityReferences,
            limit: 255,
            actual: 256,
        })
    ));
}

#[test]
fn general_entities_cannot_supply_or_follow_the_document_element() {
    // XML 1.0 production [1] requires one literal document element surrounded only by
    // prolog and Misc; entity references are content and cannot occupy either outer region.
    // https://www.w3.org/TR/xml/#sec-well-formed
    for malformed in [
        r#"<!DOCTYPE root [<!ENTITY root "<root/>">]>&root;"#,
        r#"<!DOCTYPE root [<!ENTITY empty "">]><root/>&empty;"#,
    ] {
        assert!(
            matches!(Document::parse(malformed, None), Err(Error::Xml(_))),
            "outer entity reference must remain malformed: {malformed}"
        );
    }

    let valid = Document::parse(
        r#"<!DOCTYPE root [<!ENTITY child "<child>ok</child>">]><root>&child;</root>"#,
        None,
    )
    .expect("an entity in document content remains valid");
    assert_eq!(valid.string_value(valid.root()), "ok");
}

#[test]
fn entity_replacement_normalizes_character_references_before_parsing() {
    // XML 1.0 section 4.5 expands character references when constructing replacement
    // text, so an encoded '<' can introduce markup when the entity is referenced.
    let document = Document::parse(r#"<!DOCTYPE r [<!ENTITY e "&#60;a/>">]><r>&e;</r>"#, None)
        .expect("replacement markup is well formed");
    assert_eq!(document.string_value(document.root()), "");
    assert!(document.nodes().any(|(_, node)| matches!(&node.kind,
        super::NodeKind::Element { name, .. } if name.local == "a")));
}

#[test]
fn internal_entity_values_reject_parameter_references() {
    // XML 1.0 section 2.8 WFC PEs in Internal Subset forbids references inside
    // declarations, including EntityValue, before any expansion erases their origin.
    for xml in [
        r#"<!DOCTYPE r [<!ENTITY % p "x"><!ENTITY e "%p;">]><r>&e;</r>"#,
        r#"<!DOCTYPE r [<!ENTITY % p "x"><!ENTITY % q "%p;">]><r/>"#,
    ] {
        assert!(
            matches!(Document::parse(xml, None), Err(Error::Xml(_))),
            "{xml}"
        );
    }
}

#[test]
fn general_entity_markup_is_balanced_within_each_replacement() {
    // XML 1.0 section 4.3.2 requires every referenced internal general entity replacement
    // to match `content`; a tag cannot begin in one entity and end in another.
    // https://www.w3.org/TR/xml/#wf-entities
    for malformed in [
        r#"<!DOCTYPE root [<!ENTITY e "</root>">]><root>&e;"#,
        r#"<!DOCTYPE root [<!ENTITY e "<child>">]><root>&e;</child></root>"#,
    ] {
        assert!(
            matches!(Document::parse(malformed, None), Err(Error::Xml(_))),
            "cross-entity markup must remain malformed: {malformed}"
        );
    }

    let valid = Document::parse(
        r#"<!DOCTYPE root [<!ENTITY e "<child>ok</child>">]><root>&e;</root>"#,
        None,
    )
    .expect("balanced replacement content parses");
    assert_eq!(valid.string_value(valid.root()), "ok");
}

#[test]
fn parse_budget_controls_entity_reference_occurrences() {
    // XML 1.0 section 4.1 defines reference syntax but no occurrence ceiling; this is a
    // caller-selected resource limit rather than malformed XML.
    // https://www.w3.org/TR/xml/#sec-references
    let xml = format!(
        r#"<!DOCTYPE root [<!ENTITY e "x">]><root>{}</root>"#,
        "&e;".repeat(256)
    );
    let constrained = ParseBudget::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        255,
        usize::MAX,
        usize::MAX,
    );
    assert!(matches!(
        Document::parse_with_budget(&xml, None, constrained),
        Err(Error::Budget {
            kind: BudgetKind::EntityReferences,
            limit: 255,
            actual: 256,
        })
    ));

    let admitted = ParseBudget::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        256,
        usize::MAX,
        usize::MAX,
    );
    Document::parse_with_budget(&xml, None, admitted)
        .expect("the caller-selected reference limit admits its exact boundary");
}

#[test]
fn parse_budget_bounds_entity_expansion_bytes() {
    // XML 1.0 section 4.4.2 defines replacement-text inclusion but no byte ceiling, so the
    // caller's typed resource budget must bound the materialized expansion.
    // https://www.w3.org/TR/xml/#included
    let xml =
        r#"<!DOCTYPE root [<!ENTITY a "0123456789"><!ENTITY b "&a;&a;&a;&a;">]><root>&b;</root>"#;
    let budget = ParseBudget::new(xml.len(), usize::MAX, usize::MAX, usize::MAX, 1, usize::MAX);
    assert!(matches!(
        Document::parse_with_budget(xml, None, budget),
        Err(Error::Budget {
            kind: BudgetKind::EntityExpansionBytes,
            limit: 1,
            actual,
        }) if actual > 1
    ));

    let admitted = ParseBudget::new(
        xml.len(),
        usize::MAX,
        usize::MAX,
        usize::MAX,
        ENTITY_EXPANSION_BYTE_CEILING,
        usize::MAX,
    );
    Document::parse_with_budget(xml, None, admitted)
        .expect("a sufficient entity-expansion budget admits the same document");
}

#[test]
fn parse_budget_controls_entity_expansion_depth() {
    // XML 1.0 section 4.4.2 requires included replacement text to be processed in place and
    // defines no fixed nesting ceiling; recursion is therefore a caller-selected budget.
    // https://www.w3.org/TR/xml/#included
    let declarations = (0..12)
        .map(|depth| {
            let replacement = if depth == 11 {
                "expanded".to_owned()
            } else {
                format!("&e{};", depth + 1)
            };
            format!(r#"<!ENTITY e{depth} "{replacement}">"#)
        })
        .collect::<String>();
    let xml = format!("<!DOCTYPE root [{declarations}]><root>&e0;</root>");
    let constrained = ParseBudget::new(
        usize::MAX,
        usize::MAX,
        11,
        usize::MAX,
        usize::MAX,
        usize::MAX,
    );
    assert!(matches!(
        Document::parse_with_budget(&xml, None, constrained),
        Err(Error::Budget {
            kind: BudgetKind::RecursionDepth,
            limit: 11,
            actual: 12,
        })
    ));

    let admitted = ParseBudget::new(
        usize::MAX,
        usize::MAX,
        12,
        usize::MAX,
        usize::MAX,
        usize::MAX,
    );
    let document = Document::parse_with_budget(&xml, None, admitted)
        .expect("the caller-selected depth admits the entity chain");
    assert_eq!(document.string_value(document.root()), "expanded");
}

#[test]
fn parse_budget_controls_namespace_scope_materialization() {
    // Namespaces in XML 1.0 section 6.1 defines scope but no storage ceiling; the parser must
    // classify its allocation guard as caller-selected resource policy.
    // https://www.w3.org/TR/xml-names/#scoping
    let xml = "<root xmlns:p='urn:p'><p:child/></root>";
    let mut exact_limit = 0;
    loop {
        let candidate = ParseBudget::new(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            usize::MAX,
            usize::MAX,
            exact_limit,
        );
        match Document::parse_with_budget(xml, None, candidate) {
            Ok(_) => break,
            Err(Error::Budget {
                kind: BudgetKind::NamespaceScopeBytes,
                actual,
                ..
            }) => {
                assert!(actual > exact_limit);
                exact_limit = actual;
            }
            Err(_) => panic!("namespace storage must use the typed parse-budget contract"),
        }
    }
    let below_boundary = ParseBudget::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        usize::MAX,
        usize::MAX,
        exact_limit - 1,
    );
    assert!(matches!(
        Document::parse_with_budget(xml, None, below_boundary),
        Err(Error::Budget {
            kind: BudgetKind::NamespaceScopeBytes,
            actual,
            ..
        }) if actual == exact_limit
    ));

    let admitted = ParseBudget::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        usize::MAX,
        usize::MAX,
        exact_limit,
    );
    Document::parse_with_budget(xml, None, admitted)
        .expect("the caller-selected namespace limit admits its exact boundary");
}

#[test]
fn iterative_parser_registers_dtd_declared_id_attributes() {
    // XML 1.0 section 3.3.1 assigns ID semantics to attributes declared with type ID;
    // XPath id() must therefore resolve them without caller-supplied metadata.
    // https://www.w3.org/TR/xml/#sec-attribute-types
    let document = Document::parse_iterative(
        r#"<!DOCTYPE root [<!ATTLIST item key ID #REQUIRED>]><root><item key="target"/></root>"#,
        None,
    )
    .expect("DTD-declared ID parses");
    let owner = document
        .nodes()
        .find_map(|(id, node)| match &node.kind {
            NodeKind::Element { name, .. } if name.local == "item" => Some(id),
            _ => None,
        })
        .expect("ID owner exists");

    assert!(
        document
            .ids()
            .any(|(value, root, registered_owner)| value == "target"
                && root == document.root()
                && registered_owner == owner)
    );
}

#[test]
fn iterative_parser_does_not_enforce_dtd_id_validity() {
    // XML 1.0 sections 3.3.1 and 5.1 make the ID Name rule a validity constraint, not a
    // well-formedness constraint required of this non-validating parser.
    // https://www.w3.org/TR/xml/#id
    // https://www.w3.org/TR/xml/#proc-types
    let document = Document::parse_iterative(
        r#"<!DOCTYPE r [<!ATTLIST r id ID #IMPLIED>]><r id="1bad"/>"#,
        None,
    )
    .expect("a non-validating parser accepts a validity-constraint violation");

    assert!(document.ids().any(|(value, _, _)| value == "1bad"));
}

#[test]
fn iterative_parser_coalesces_dtd_and_xml_id_registration() {
    // xml:id 1.0 section 4 gives xml:id ID semantics independently of the DTD. If the DTD
    // declares that same attribute as ID, both mechanisms identify one attribute rather than
    // two competing IDs: https://www.w3.org/TR/xml-id/#processing
    let document = Document::parse_iterative(
        r#"<!DOCTYPE root [<!ATTLIST item xml:id ID #REQUIRED>]><root><item xml:id="target"/></root>"#,
        None,
    )
    .expect("the same xml:id registration is idempotent");

    assert_eq!(
        document
            .ids()
            .filter(|(value, _, _)| *value == "target")
            .count(),
        1
    );

    let error = Document::parse_iterative(
        r#"<!DOCTYPE root [<!ATTLIST item xml:id ID #REQUIRED>]><root><item xml:id="same"/><item xml:id="same"/></root>"#,
        None,
    )
    .expect_err("the same ID on distinct owners remains invalid");
    assert!(error.to_string().contains("duplicate XML ID"));
}

#[test]
fn defaulted_xml_id_is_processed_atomically() {
    // xml:id 1.0 section 4 applies to attributes added to the infoset by default and requires
    // normalization before ID assignment: https://www.w3.org/TR/xml-id/#processing
    let mut document =
        Document::parse("<root><first/><second/></root>", None).expect("source document parses");
    let elements = document
        .nodes()
        .filter_map(|(id, node)| match &node.kind {
            NodeKind::Element { name, .. } if name.local != "root" => Some(id),
            _ => None,
        })
        .collect::<Vec<_>>();
    let [first, second] = elements.as_slice() else {
        panic!("two child elements exist");
    };
    let (first, second) = (*first, *second);
    let xml_id = |value: &str| Attribute {
        name: ExpandedName::new(Some("http://www.w3.org/XML/1998/namespace"), "id"),
        prefix: Some("xml".into()),
        value: value.into(),
    };

    document
        .add_default_attribute(first, xml_id("  target  "))
        .expect("defaulted xml:id is accepted");
    assert!(document.ids().any(|(value, root, owner)| value == "target"
        && root == document.root()
        && owner == first));
    let first_attributes = match &document.node(first).expect("first remains present").kind {
        NodeKind::Element { attributes, .. } => attributes,
        _ => panic!("first remains an element"),
    };
    assert_eq!(first_attributes[0].value, "target");

    let invalid = document
        .add_default_attribute(second, xml_id("not valid"))
        .expect_err("invalid defaulted xml:id is rejected");
    assert!(invalid.to_string().contains("NCName"));
    let duplicate = document
        .add_default_attribute(second, xml_id("target"))
        .expect_err("duplicate defaulted xml:id is rejected");
    assert!(duplicate.to_string().contains("duplicate XML ID"));
    let second_attributes = match &document.node(second).expect("second remains present").kind {
        NodeKind::Element { attributes, .. } => attributes,
        _ => panic!("second remains an element"),
    };
    assert!(second_attributes.is_empty(), "failed additions are atomic");
}

#[test]
fn iterative_parser_does_not_enforce_dtd_id_uniqueness() {
    // XML 1.0 sections 3.3.1 and 5.1 make ID uniqueness a validity constraint that this
    // non-validating parser must not turn into a fatal well-formedness error.
    // https://www.w3.org/TR/xml/#id
    // https://www.w3.org/TR/xml/#proc-types
    let document = Document::parse_iterative(
        r#"<!DOCTYPE root [<!ATTLIST item key ID #REQUIRED>]><root><item key="same"/><item key="same"/></root>"#,
        None,
    )
    .expect("duplicate DTD-declared ID values remain parseable");

    assert_eq!(
        document
            .ids()
            .filter(|(value, _, _)| *value == "same")
            .count(),
        1,
        "the deterministic ID index keeps its first declaration"
    );
}

#[test]
fn iterative_parser_does_not_enforce_one_dtd_id_per_element_type() {
    // XML 1.0 sections 3.3.1 and 5.1 classify the one-ID-per-element-type rule as validity,
    // while both declarations still provide ID typing to a non-validating processor.
    // https://www.w3.org/TR/xml/#one-id-per-el
    // https://www.w3.org/TR/xml/#proc-types
    let document = Document::parse_iterative(
        r#"<!DOCTYPE root [<!ATTLIST item first ID #IMPLIED second ID #IMPLIED>]><root><item first="one" second="two"/></root>"#,
        None,
    )
    .expect("multiple DTD-declared ID attributes remain parseable");

    assert!(document.ids().any(|(value, _, _)| value == "one"));
    assert!(document.ids().any(|(value, _, _)| value == "two"));
}

#[test]
fn iterative_parser_bounds_aggregate_text_entity_expansion_bytes() {
    // A bounded reference count is insufficient when each permitted
    // reference materializes a large replacement into document text.
    let replacement = "x".repeat(70_000);
    let body = "&large;".repeat(255);
    let xml = format!("<!DOCTYPE root [<!ENTITY large \"{replacement}\">]><root>{body}</root>");

    let error = Document::parse_iterative(&xml, None)
        .expect_err("aggregate expanded text must remain bounded");
    assert!(matches!(error, crate::Error::Budget { .. }));
}

#[test]
fn iterative_parser_bounds_aggregate_attribute_entity_expansion_bytes() {
    // Attribute expansion happens after the document-level lexical pass
    // and must consume the same document-wide materialization budget.
    let replacement = "x".repeat(70_000);
    let mut attributes = String::new();
    for index in 0..255 {
        write!(attributes, " a{index}=\"&large;\"")
            .expect("writing attributes to String cannot fail");
    }
    let xml = format!("<!DOCTYPE root [<!ENTITY large \"{replacement}\">]><root{attributes}/>");

    let error = Document::parse_iterative(&xml, None)
        .expect_err("aggregate expanded attributes must remain bounded");
    assert!(matches!(error, crate::Error::Budget { .. }));
}

#[test]
fn oracle_and_iterative_parsers_reject_the_same_boundary_malformations() {
    // Namespace and document-well-formedness failures cannot depend on document depth.
    for depth in (62..=66).chain(126..=130) {
        for leaf in [
            "<p:leaf/>",
            "<p:a:b xmlns:p=\"urn:p\"/>",
            "<:leaf/>",
            "<leaf:/>",
            "<leaf p:a:b=\"x\" xmlns:p=\"urn:p\"/>",
            "<leaf xmlns:a=\"urn:u\" xmlns:b=\"urn:u\" a:x=\"1\" b:x=\"2\"/>",
            "<leaf xmlns:xml=\"urn:wrong\"/>",
            "<leaf xmlns:p=\"\"/>",
            "<leaf>&#0;</leaf>",
            "<leaf>&#x1;</leaf>",
        ] {
            let xml = nested_xml(depth, leaf);
            let tree_ok = parse_tree_with_oracle_stack(&xml, None).is_ok();
            let iterative_ok = Document::parse_iterative(&xml, None).is_ok();
            assert!(
                !tree_ok,
                "tree parser accepted malformed input at depth {depth}: {leaf}"
            );
            assert_eq!(
                tree_ok, iterative_ok,
                "parser acceptance differs at depth {depth} for {leaf}"
            );
        }
    }
}

#[test]
fn iterative_parser_rejects_mismatched_closing_names() {
    // Deep documents select the iterative parser, which must enforce the
    // same lexical element nesting invariant as the regular parser.
    let xml = nested_xml(65, "<expected></different>");
    assert!(parse_tree_with_oracle_stack(&xml, None).is_err());
    assert!(
        Document::parse_iterative(&xml, None).is_err(),
        "iterative parser accepted a mismatched closing element"
    );
}

#[test]
fn iterative_parser_expands_entities_inside_attribute_value_context() {
    // Entity replacement text is interpreted inside the attribute value;
    // a quote in that text must not terminate the source-level delimiter.
    let xml = r#"<!DOCTYPE root [<!ENTITY quote "'">]><root value='&quote;'/>"#;
    let iterative = Document::parse_iterative(xml, None)
        .expect("iterative parser must preserve attribute quoting");
    let value = iterative.nodes().find_map(|(_, node)| match &node.kind {
        super::NodeKind::Element { attributes, .. } => attributes
            .iter()
            .find(|attribute| attribute.name.local == "value")
            .map(|attribute| attribute.value.as_str()),
        _ => None,
    });
    assert_eq!(value, Some("'"));
}

#[test]
fn oracle_and_iterative_parsers_reject_misplaced_and_duplicate_doctypes() {
    // Document depth must not make invalid prolog structure acceptable.
    let deep_document = nested_xml(65, "<leaf/>");
    for xml in [
        format!("<!DOCTYPE n><!DOCTYPE n>{deep_document}"),
        nested_xml(65, "<!DOCTYPE leaf><leaf/>"),
    ] {
        assert!(
            parse_tree_with_oracle_stack(&xml, None).is_err(),
            "tree parser accepted malformed doctype placement"
        );
        assert!(
            Document::parse_iterative(&xml, None).is_err(),
            "iterative parser accepted malformed doctype placement"
        );
    }
}

#[test]
fn every_parser_accepts_a_doctype_for_another_document_element() {
    // XML 1.0 section 2.8 defines the name match as a validity constraint; section 5.1 does
    // not require a non-validating processor to enforce it.
    let shallow = "<!DOCTYPE expected><actual/>";
    Document::parse(shallow, None).expect("shallow non-validating parse accepts the document");
    Document::parse_iterative(shallow, None)
        .expect("iterative non-validating parse accepts the document");

    let deep = format!("<!DOCTYPE expected>{}", nested_xml(130, "<actual/>"));
    Document::parse(&deep, None).expect("deep dispatch accepts the validity-only mismatch");
    Document::parse_iterative(&deep, None)
        .expect("iterative parser accepts the validity-only mismatch");
}

#[test]
fn parser_paths_count_xml_line_endings_identically() {
    // XML 1.0 section 2.11 normalizes CR, CRLF, and LF to one logical line ending.
    for separator in ["\n", "\r", "\r\n"] {
        let xml = format!("<root>{separator}<child/></root>");
        for document in [
            Document::parse_tree(&xml, None).expect("tree parser accepts line ending"),
            Document::parse_iterative(&xml, None).expect("iterative parser accepts line ending"),
        ] {
            let child = document
                .nodes()
                .find_map(|(_, node)| match &node.kind {
                    NodeKind::Element { name, .. } if name.local == "child" => Some(node),
                    _ => None,
                })
                .expect("child exists");
            assert_eq!(child.source_line, Some(2), "separator {separator:?}");
        }
    }
}

#[test]
fn doctype_discovery_is_limited_to_the_document_prolog() {
    // Lexical lookalikes in comments and character data are not declarations.
    for xml in [
        "<!-- <!DOCTYPE fake [<!ENTITY e 'bad'>]> --><root/>",
        "<root><![CDATA[<!DOCTYPE fake [<!ENTITY e 'bad'>]>]]></root>",
    ] {
        assert_eq!(doctype_span(xml).expect("doctype scan succeeds"), None);
        Document::parse_iterative(xml, None).expect("document parses without a doctype");
    }
}

#[test]
fn dtd_processing_instructions_cannot_declare_entities() {
    // Processing-instruction content is a protected DTD region. Markup-shaped text inside it
    // must not become a declaration consumed by the entity-expansion pass.
    let xml = r#"<!DOCTYPE r [<?pi <!ENTITY e "evil">?>]><r>&e;</r>"#;
    assert!(Document::parse_iterative(xml, None).is_err());
}

#[test]
fn external_identifier_brackets_do_not_form_an_internal_subset() {
    // XML 1.0 only permits the internal subset after the external identifier, outside its
    // quoted SystemLiteral: https://www.w3.org/TR/xml/#NT-doctypedecl
    let xml = r#"<!DOCTYPE r SYSTEM "[<!ENTITY e 'ok'>]"><r>&e;</r>"#;
    assert!(Document::parse_iterative(xml, None).is_err());
}

#[test]
fn unused_entity_definitions_reject_invalid_grammar() {
    // XML 1.0 [70]-[74]: unused declarations still need a complete EntityDef/PEDef.
    for declaration in [
        "<!ENTITY e BOGUS>",
        "<!ENTITY % e BOGUS>",
        "<!ENTITY e 'value' BOGUS>",
        "<!ENTITY e 'value' NDATA notation>",
    ] {
        let xml = format!("<!DOCTYPE root [{declaration}]><root/>");
        assert!(
            Document::parse(&xml, None).is_err(),
            "accepted {declaration}"
        );
        assert!(
            Document::parse_iterative(&xml, None).is_err(),
            "iterative accepted {declaration}"
        );
        assert!(
            super::collect_internal_entity_declarations(
                declaration,
                &mut EntityExpansionMeter::new(ENTITY_EXPANSION_BYTE_CEILING),
            )
            .is_err(),
            "preprocessor accepted {declaration}"
        );
    }
}

#[test]
fn unused_entity_graphs_obey_well_formedness() {
    // XML 1.0 section 4.1 applies Entity Declared and No Recursion to unused declarations.
    for subset in [
        "<!ENTITY a '&missing;'>",
        "<!ENTITY a '&a;'>",
        "<!ENTITY a '&b;'><!ENTITY b '&a;'>",
    ] {
        let xml = format!("<!DOCTYPE root [{subset}]><root/>");
        assert!(Document::parse(&xml, None).is_err(), "accepted {subset}");
    }
    // Forward references between general entities are legal; unused text is not expanded.
    Document::parse(
        "<!DOCTYPE root [<!ENTITY a '&b;'><!ENTITY b 'ok'>]><root/>",
        None,
    )
    .expect("acyclic forward reference is valid");
    Document::parse(
        "<!DOCTYPE root SYSTEM 'memory:external.dtd' [<!ENTITY a '&external;'>]><root/>",
        None,
    )
    .expect("non-validating processor need not read an external declaration");
    assert!(Document::parse("<?xml version='1.0' standalone='yes'?><!DOCTYPE root SYSTEM 'memory:external.dtd' [<!ENTITY a '&external;'>]><root/>", None).is_err());
    Document::parse("<!DOCTYPE root [<!ENTITY a '&amp;missing;'>]><root/>", None)
        .expect("escaped ampersand does not declare a dependency");
}

#[test]
fn external_entity_system_literals_reject_fragment_identifiers() {
    // XML 1.0 section 4.2.2 makes a fragment identifier in a system identifier an error:
    // https://www.w3.org/TR/xml/#sec-external-ent
    for declaration in [
        r#"<!ENTITY logo SYSTEM "image.bin#part" NDATA png>"#,
        r#"<!ENTITY logo PUBLIC "image" "image.bin#part" NDATA png>"#,
        r#"<!NOTATION png SYSTEM "image.bin#part">"#,
        r#"<!NOTATION png PUBLIC "image" "image.bin#part">"#,
    ] {
        let xml = format!("<!DOCTYPE root [{declaration}]><root/>");
        assert!(Document::parse(&xml, None).is_err());
        assert!(Document::parse_iterative(&xml, None).is_err());
    }

    let valid = r#"<!DOCTYPE root [<!NOTATION png SYSTEM "image/png"><!ENTITY logo SYSTEM "image.bin" NDATA png>]><root/>"#;
    Document::parse(valid, None).expect("fragment-free system identifier is valid");
    Document::parse_iterative(valid, None)
        .expect("fragment-free system identifier is valid in the iterative parser");
}

#[test]
fn unparsed_entities_accept_empty_system_literals() {
    // XML 1.0 production [11] permits an empty SystemLiteral. Both parser paths must retain
    // that empty URI as unparsed-entity metadata instead of rejecting the document.
    // https://www.w3.org/TR/xml/#NT-SystemLiteral
    let xml = r#"<!DOCTYPE root [<!NOTATION png SYSTEM "image/png"><!ENTITY logo SYSTEM "" NDATA png>]><root/>"#;
    for document in [
        Document::parse(xml, None).expect("empty system identifier is well-formed"),
        Document::parse_iterative(xml, None)
            .expect("iterative parser accepts an empty system identifier"),
    ] {
        assert_eq!(
            document
                .unparsed_entities()
                .map(|(name, uri, _)| (name, uri))
                .collect::<Vec<_>>(),
            vec![("logo", "")]
        );
    }
}

#[test]
fn duplicate_entity_declarations_retain_the_first_binding() {
    // XML binds the first declaration of an entity; later declarations neither replace it
    // nor make an otherwise well-formed document invalid.
    let document = Document::parse_iterative(
        r#"<!DOCTYPE r [<!ENTITY e "first"><!ENTITY e "second">]><r>&e;</r>"#,
        None,
    )
    .expect("duplicate entity declarations are well-formed");
    assert_eq!(document.string_value(document.root()), "first");
}

#[test]
fn rejected_unparsed_entity_registration_preserves_the_first_binding() {
    // A failed public mutation must leave the accepted document metadata unchanged.
    let mut document = Document::parse_iterative("<root/>", None).expect("document parses");
    document
        .register_unparsed_entity("logo", "memory:first")
        .expect("first entity is accepted");
    let error = document
        .register_unparsed_entity("logo", "memory:rejected")
        .expect_err("duplicate entity is rejected");
    assert!(matches!(error, super::Error::Xml(message) if message.contains("duplicate")));
    assert_eq!(
        document
            .unparsed_entities()
            .map(|(name, uri, _)| (name, uri))
            .collect::<Vec<_>>(),
        vec![("logo", "memory:first")]
    );
}

#[test]
fn internal_dtd_declaration_boundaries_are_enforced() {
    // XML 1.0 productions [52] and [71] permit an empty ATTLIST but require S before each
    // attribute definition and before NDATA.
    // https://www.w3.org/TR/xml/#NT-AttlistDecl
    // https://www.w3.org/TR/xml/#NT-GEDecl
    Document::parse_iterative("<!DOCTYPE r [<!ATTLIST r>]><r/>", None)
        .expect("an empty ATTLIST is well-formed");
    for malformed in [
        r#"<!DOCTYPE r [<!ATTLIST r a CDATA "x"b CDATA "y">]><r/>"#,
        r#"<!DOCTYPE r [<!ENTITY logo SYSTEM "logo.png"NDATA png>]><r/>"#,
    ] {
        Document::parse_iterative(malformed, None)
            .expect_err("missing DTD declaration whitespace must be rejected");
    }
}

#[test]
fn every_attlist_default_validates_reference_grammar() {
    // XML 1.0 production [10] applies while parsing the declaration, regardless of whether
    // an explicit attribute later prevents the default from being used.
    // https://www.w3.org/TR/xml/#NT-AttValue
    for malformed in [
        r#"<!DOCTYPE r [<!ATTLIST r a CDATA "&broken">]><r a="explicit"/>"#,
        r#"<!DOCTYPE r [<!ATTLIST unused a CDATA "&#x110000;">]><r/>"#,
    ] {
        Document::parse_iterative(malformed, None)
            .expect_err("malformed unused ATTLIST defaults must be rejected");
    }
}

#[test]
fn internal_dtd_enumerations_follow_xml_token_grammar() {
    for valid in [
        r#"<!DOCTYPE r [<!ATTLIST r mode (1 | a:b | x-y) "1">]><r/>"#,
        r#"<!DOCTYPE r [<!ATTLIST r format NOTATION (png | jpeg) "png">]><r/>"#,
    ] {
        Document::parse_iterative(valid, None)
            .expect("well-formed enumeration tokens must be accepted");
    }

    for malformed in [
        r#"<!DOCTYPE r [<!ATTLIST r mode () "a">]><r/>"#,
        r#"<!DOCTYPE r [<!ATTLIST r mode ( ) "a">]><r/>"#,
        r#"<!DOCTYPE r [<!ATTLIST r mode (a||b) "a">]><r/>"#,
        r#"<!DOCTYPE r [<!ATTLIST r mode (|a) "a">]><r/>"#,
        r#"<!DOCTYPE r [<!ATTLIST r mode (a|) "a">]><r/>"#,
        r#"<!DOCTYPE r [<!ATTLIST r mode (a b) "a">]><r/>"#,
        r#"<!DOCTYPE r [<!ATTLIST r format NOTATION (png||jpeg) "png">]><r/>"#,
        r#"<!DOCTYPE r [<!ATTLIST r format NOTATION (1png|jpeg) "jpeg">]><r/>"#,
    ] {
        Document::parse_iterative(malformed, None)
            .expect_err("malformed enumeration grammar must be rejected");
    }
}

#[test]
fn internal_dtd_markup_declarations_follow_xml_grammar() {
    for valid in [
        r#"<!DOCTYPE r [<!ELEMENT r (head, (body | note)*, tail?)>]><r/>"#,
        r#"<!DOCTYPE r [<!ELEMENT r (#PCDATA | item)*>]><r/>"#,
        r#"<!DOCTYPE r [<!NOTATION png SYSTEM "image/png">]><r/>"#,
        r#"<!DOCTYPE r [<!NOTATION png PUBLIC "image/png">]><r/>"#,
        r#"<!DOCTYPE r [<!NOTATION png PUBLIC "image/png" "png.viewer">]><r/>"#,
        r#"<!DOCTYPE r [<!ENTITY e "parameter &amp; &#37;">]><r>&e;</r>"#,
    ] {
        Document::parse_iterative(valid, None)
            .expect("well-formed markup declaration must be accepted");
    }

    for malformed in [
        r#"<!DOCTYPE r [<!ELEMENT r (a||b)>]><r/>"#,
        // PE references within internal declarations violate XML 1.0 section 2.8.
        r#"<!DOCTYPE r [<!ENTITY % p "parameter"><!ENTITY e "%p; &amp; &#37;">]><r>&e;</r>"#,
        r#"<!DOCTYPE r [<!ELEMENT r (a,b|c)>]><r/>"#,
        r#"<!DOCTYPE r [<!ELEMENT r (#PCDATA|item)>]><r/>"#,
        r#"<!DOCTYPE r [<!ELEMENT r EMPTY extra>]><r/>"#,
        r#"<!DOCTYPE r [<!NOTATION png SYSTEM>]><r/>"#,
        r#"<!DOCTYPE r [<!NOTATION png PUBLIC "image/png" extra>]><r/>"#,
        r#"<!DOCTYPE r [<!ENTITY e PUBLIC "[bad" "urn:example">]><r/>"#,
        r#"<!DOCTYPE r [<!ENTITY e "%">]><r>&e;</r>"#,
        r#"<!DOCTYPE r [<!ENTITY e "&bad">]><r>&e;</r>"#,
        r#"<!DOCTYPE r [<!UNKNOWN r ANY>]><r/>"#,
    ] {
        Document::parse_iterative(malformed, None)
            .expect_err("malformed markup declaration must be rejected");
    }
}

#[test]
fn element_children_groups_follow_choice_and_sequence_grammar() {
    for valid in [
        r#"<!DOCTYPE r [<!ELEMENT r (a)>]><r/>"#,
        r#"<!DOCTYPE r [<!ELEMENT r (a?)>]><r/>"#,
        r#"<!DOCTYPE r [<!ELEMENT r ((a,b))>]><r/>"#,
        r#"<!DOCTYPE r [<!ELEMENT r (a,b)>]><r/>"#,
        r#"<!DOCTYPE r [<!ELEMENT r (a|b)>]><r/>"#,
    ] {
        Document::parse_iterative(valid, None)
            .expect("single-particle sequences and multi-particle groups remain valid");
    }

    for malformed in [
        r#"<!DOCTYPE r [<!ELEMENT r ()>]><r/>"#,
        r#"<!DOCTYPE r [<!ELEMENT r (|a)>]><r/>"#,
        r#"<!DOCTYPE r [<!ELEMENT r (a|)>]><r/>"#,
        r#"<!DOCTYPE r [<!ELEMENT r (a,)>]><r/>"#,
    ] {
        Document::parse_iterative(malformed, None)
            .expect_err("incomplete choice and sequence groups must be rejected");
    }
}

#[test]
fn parameter_attributes_and_duplicate_unparsed_entities_keep_xml_semantics() {
    // Parameter entities can contribute declarations, while XML 1.0 section 4.2 binds the
    // first general-entity declaration and ignores later duplicates.
    // https://www.w3.org/TR/xml/#sec-entity-decl
    let document = Document::parse_iterative(
        r#"<!DOCTYPE r [
              <!ENTITY % attrs '<!ATTLIST r status NMTOKENS "  ready   now  ">'>
              %attrs;
              <!NOTATION png SYSTEM "image/png">
              <!ENTITY logo SYSTEM "first.png" NDATA png>
              <!ENTITY logo SYSTEM "second.png" NDATA png>
            ]><r/>"#,
        Some("https://example.test/source.xml"),
    )
    .expect("parameter-provided attributes and duplicate entities parse");
    let status = document.nodes().find_map(|(_, node)| match &node.kind {
        super::NodeKind::Element { attributes, .. } => attributes
            .iter()
            .find(|attribute| attribute.name.local == "status")
            .map(|attribute| attribute.value.as_str()),
        _ => None,
    });
    assert_eq!(status, Some("ready now"));
    assert_eq!(
        document
            .unparsed_entities()
            .map(|(name, uri, _)| (name, uri))
            .collect::<Vec<_>>(),
        vec![("logo", "https://example.test/first.png")]
    );
}

#[test]
fn predefined_entity_redeclarations_preserve_xml_builtins() {
    // XML permits only the normative replacement forms for predefined entities. A malformed
    // declaration must not replace a builtin before the document reaches the XML parser.
    for invalid in [
        r#"<!DOCTYPE r [<!ENTITY amp "evil">]><r>&amp;</r>"#,
        r#"<!DOCTYPE r [<!ENTITY amp "&#38;">]><r>&amp;</r>"#,
        r#"<!DOCTYPE r [<!ENTITY lt "&#60;">]><r>&lt;</r>"#,
    ] {
        assert!(Document::parse_iterative(invalid, None).is_err());
    }

    let valid = r#"<!DOCTYPE r [
            <!ENTITY amp "&#38;#38;">
            <!ENTITY apos "&#39;">
            <!ENTITY gt "&#62;">
            <!ENTITY lt "&#38;#60;">
            <!ENTITY quot "&#34;">
        ]><r>&amp;&lt;&gt;&apos;&quot;</r>"#;
    let document = Document::parse_iterative(valid, None)
        .expect("normative predefined-entity redeclarations remain well-formed");
    assert_eq!(document.string_value(document.root()), "&<>'\"");
}

#[test]
fn predefined_amp_and_lt_require_double_escaped_declarations() {
    // XML 1.0 requires the replacement text for amp and lt to remain a character reference
    // after the declaration's first entity-replacement pass.
    assert!(normalize_predefined_entity_declaration("amp", "&#38;").is_err());
    assert!(normalize_predefined_entity_declaration("lt", "&#60;").is_err());
    assert_eq!(
        normalize_predefined_entity_declaration("amp", "&#38;#38;")
            .expect("normative amp declaration"),
        "&#38;"
    );
    assert_eq!(
        normalize_predefined_entity_declaration("lt", "&#38;#60;")
            .expect("normative lt declaration"),
        "&#60;"
    );
}

#[test]
fn internal_parameter_entities_contribute_markup_declarations() {
    // Parameter entities in the internal subset can expand to declarations consumed by the
    // document. The parser must process that declaration before resolving general entities.
    let xml = r#"<!DOCTYPE r [<!ENTITY % defs '<!ENTITY e "ok">'> %defs;]><r>&e;</r>"#;
    let mut references = 0;
    let mut meter = EntityExpansionMeter::new(ENTITY_EXPANSION_BYTE_CEILING);
    let (prepared, declarations) = internal_general_entities(xml, &mut references, &mut meter)
        .expect("parameter entity subset is prepared");
    assert_eq!(prepared, r#"<!DOCTYPE r [ <!ENTITY e "ok">]><r>&e;</r>"#);
    assert_eq!(
        declarations.general.get("e").map(String::as_str),
        Some("ok")
    );

    let document =
        Document::parse_iterative(xml, None).expect("parameter entity declaration expands");
    assert_eq!(document.string_value(document.root()), "ok");
}

#[test]
fn staged_parameter_entities_contribute_markup_declarations() {
    // XML 1.0 sections 4.4.8 and 4.5 allow replacement text to contribute declarations;
    // every newly exposed parameter declaration must therefore join the same bounded pass.
    // https://www.w3.org/TR/xml/#included-in-literal
    let xml = r#"<!DOCTYPE r [<!ENTITY % first '<!ENTITY &#37; second "<!ENTITY e &#39;ok&#39;>">'> %first; %second;]><r>&e;</r>"#;
    let document =
        Document::parse_iterative(xml, None).expect("staged parameter entity declarations expand");
    assert_eq!(document.string_value(document.root()), "ok");
}

#[test]
fn malformed_parameter_entity_declarations_are_not_stripped() {
    // A declaration may be removed from the subset only after the complete PEDecl grammar
    // has been recognized; otherwise preprocessing can hide malformed XML from the parser.
    for malformed in [
        r#"<!DOCTYPE r [<!ENTITY % p "x" BOGUS>]><r/>"#,
        r#"<!DOCTYPE r [<!ENTITY % p "x &broken">]><r/>"#,
        r#"<!DOCTYPE r [<!ENTITY % p "x %broken">]><r/>"#,
        r#"<!DOCTYPE r [<!ENTITY % p "&#0;">]><r/>"#,
        r#"<!DOCTYPE r [<!ENTITY e "&#+65;">]><r>&e;</r>"#,
        r#"<!DOCTYPE r [<!ENTITY e "&#X41;">]><r>&e;</r>"#,
        "<!DOCTYPE r [<!ENTITY % p \"x\"\u{000b}>]><r/>",
        "<!DOCTYPE r [<!ENTITY % p \"x\"\u{000c}>]><r/>",
    ] {
        assert!(Document::parse_iterative(malformed, None).is_err());
    }

    Document::parse_iterative("<!DOCTYPE r [<!ENTITY % p \"x\" \t\r\n>]><r/>", None)
        .expect("XML S before the declaration terminator remains valid");
}

#[test]
fn undeclared_parameter_entity_references_are_rejected() {
    // XML 1.0 section 4.1 requires every parameter-entity reference to name a declared
    // entity; preprocessing must not leave an unknown reference for the DTD scanner to hide.
    // https://www.w3.org/TR/xml/#wf-entdeclared
    let error = Document::parse_iterative("<!DOCTYPE r [%missing;]><r/>", None)
        .expect_err("an undeclared parameter entity is not well-formed XML");
    assert!(
        matches!(&error, Error::Xml(message) if message.contains("parameter entity")),
        "unexpected rejection: {error:?}"
    );
    Document::parse_iterative(
        "<!DOCTYPE r [<!ENTITY % declared '<!ELEMENT r EMPTY>'>%declared;]><r/>",
        None,
    )
    .expect("a declared parameter entity remains valid");
}

#[test]
fn undeclared_entities_in_unused_attribute_defaults_are_rejected() {
    // XML 1.0 section 4.1 applies the Entity Declared well-formedness constraint to entity
    // references in every declared default, whether or not an element uses that attribute.
    // https://www.w3.org/TR/xml/#wf-entdeclared
    let error = Document::parse_iterative(
        r#"<!DOCTYPE r [<!ATTLIST unused value CDATA "&missing;">]><r/>"#,
        None,
    )
    .expect_err("an undeclared entity in an unused default is not well-formed XML");
    assert!(
        matches!(&error, Error::Xml(message) if message.contains("undeclared entity")),
        "unexpected rejection: {error:?}"
    );

    Document::parse_iterative(
        r#"<!DOCTYPE r [<!ENTITY declared "ok"><!ATTLIST unused value CDATA "&declared;">]><r/>"#,
        None,
    )
    .expect("a forward-resolved default entity remains valid");
}

#[test]
fn external_entities_are_rejected_transitively_in_attribute_defaults() {
    // XML 1.0 Fifth Edition section 3.1 forbids direct and indirect external entity
    // references in attribute values, including defaults that are never applied.
    // https://www.w3.org/TR/2008/REC-xml-20081126/#NoExternalRefs
    let xml = r#"<!DOCTYPE r [<!ENTITY ext SYSTEM "external.txt"><!ENTITY middle "&ext;"><!ENTITY outer "&middle;"><!ATTLIST unused value CDATA "&outer;">]><r/>"#;
    let error = Document::parse_iterative(xml, None)
        .expect_err("attribute defaults must not reach parsed external entities indirectly");
    assert!(
        matches!(&error, Error::Xml(message) if message.contains("external entity")),
        "unexpected rejection: {error:?}"
    );
}

#[test]
fn external_subset_may_declare_unused_attribute_default_entities() {
    // XML 1.0 Fifth Edition section 4.1 does not require a non-validating processor to read
    // the external subset unless standalone="yes"; an undeclared reference may therefore be
    // supplied externally: https://www.w3.org/TR/2008/REC-xml-20081126/#wf-entdeclared
    Document::parse_iterative(
        r#"<!DOCTYPE r SYSTEM "memory:external.dtd" [<!ATTLIST unused value CDATA "&external;">]><r/>"#,
        None,
    )
    .expect("a non-standalone document may rely on an external entity declaration");

    for xml in [
        r#"<!DOCTYPE r [<!ATTLIST unused value CDATA "&external;">]><r/>"#,
        r#"<?xml version="1.0" standalone="yes"?><!DOCTYPE r SYSTEM "memory:external.dtd" [<!ATTLIST unused value CDATA "&external;">]><r/>"#,
    ] {
        Document::parse_iterative(xml, None)
            .expect_err("the entity declaration is required without the external exception");
    }
}

#[test]
fn parameter_entity_expansion_enforces_recursive_aggregate_limits() {
    // Parameter entities share the bounded expansion path used by document entities: cycles,
    // aggregate references, and materialized bytes must all fail before parser allocation.
    let recursive = HashMap::from([("loop".into(), "%loop;".into())]);
    assert!(
        expand_parameter_entity_references(
            "%loop;",
            &recursive,
            &[],
            0,
            &mut 0,
            &mut EntityExpansionMeter::new(ENTITY_EXPANSION_BYTE_CEILING),
        )
        .is_err()
    );

    let leaf = HashMap::from([("leaf".into(), "x".into())]);
    let references = "%leaf;".repeat(256);
    assert!(matches!(
        expand_parameter_entity_references(
            &references,
            &leaf,
            &[],
            0,
            &mut 0,
            &mut EntityExpansionMeter::with_reference_limit(ENTITY_EXPANSION_BYTE_CEILING, 255,),
        ),
        Err(Error::Budget {
            kind: BudgetKind::EntityReferences,
            limit: 255,
            actual: 256,
        })
    ));
    assert!(
        expand_parameter_entity_references(
            "%leaf;",
            &leaf,
            &[],
            0,
            &mut 0,
            &mut EntityExpansionMeter::new(0),
        )
        .is_err()
    );
}

#[test]
fn attribute_normalization_preserves_referenced_whitespace() {
    // Literal XML whitespace normalizes to spaces, while character references append their
    // referenced scalar after normalization and therefore retain tab/newline characters.
    let document = Document::parse_iterative("<r a=\"\t&#x9;&#xA;&#xD;\"/>", None)
        .expect("attribute whitespace parses");
    let value = document
        .nodes()
        .find_map(|(_, node)| match &node.kind {
            super::NodeKind::Element { attributes, .. } => {
                attributes.first().map(|attribute| attribute.value.as_str())
            }
            _ => None,
        })
        .expect("attribute exists");
    assert_eq!(value, " \t\n\r");
}

#[test]
fn entity_expansion_accepts_source_bounded_long_names() {
    // XML 1.0 productions [4], [5], [68], and [69] impose no lexical byte ceiling on Name.
    // https://www.w3.org/TR/xml/#NT-Name
    let name = format!("entity{}", "a".repeat(1_025));
    let source = format!("&{name};");
    let entities = HashMap::from([(name.clone(), "expanded".into())]);
    assert_eq!(
        expand_entity_references(
            &source,
            &entities,
            0,
            &mut 0,
            &mut EntityExpansionMeter::new(ENTITY_EXPANSION_BYTE_CEILING),
        )
        .expect("source-bounded entity scan succeeds"),
        "expanded"
    );

    let parameter_source = format!("%{name};");
    assert_eq!(
        expand_parameter_entity_references(
            &parameter_source,
            &entities,
            &[],
            0,
            &mut 0,
            &mut EntityExpansionMeter::new(ENTITY_EXPANSION_BYTE_CEILING),
        )
        .expect("source-bounded parameter entity scan succeeds"),
        "expanded"
    );

    let general_xml = format!("<!DOCTYPE r [<!ENTITY {name} 'expanded'>]><r>&{name};</r>");
    let general = Document::parse_iterative(&general_xml, None)
        .expect("a long general entity name remains valid XML");
    assert_eq!(general.string_value(general.root()), "expanded");

    let parameter_xml = format!("<!DOCTYPE r [<!ENTITY % {name} ' '> %{name};]><r>expanded</r>");
    let parameter = Document::parse_iterative(&parameter_xml, None)
        .expect("a long parameter entity name remains valid XML");
    assert_eq!(parameter.string_value(parameter.root()), "expanded");
}

#[test]
fn frontend_preserves_declared_attribute_normalization() {
    // XML 1.0 section 3.3.3: tokenized values collapse spaces, while character
    // references in CDATA defaults retain their referenced whitespace.
    for (xml, expected) in [
        (
            r#"<!DOCTYPE r [<!ATTLIST r a NMTOKENS #IMPLIED>]><r a="  one   two  "/>"#,
            "one two",
        ),
        (
            r#"<!DOCTYPE r [<!ATTLIST r a CDATA "&#9;&#10;&#13;">]><r/>"#,
            "\t\n\r",
        ),
    ] {
        let prepared =
            super::prepare_xml_frontend_bounded(xml, 100_000, 64, &mut ParseWork::new(usize::MAX))
                .expect("DTD preprocessing succeeds");
        let document = roxmltree::Document::parse(&prepared).expect("prepared XML parses");
        assert_eq!(document.root_element().attribute("a"), Some(expected));
    }
}

#[test]
fn unused_entity_declarations_keep_the_source_borrowed() {
    // Declaring an entity must not force a full document or attribute copy when no
    // replacement is required on the parsed path.
    let xml = "<!DOCTYPE root [<!ENTITY unused 'value'>]><root plain='text'/>";
    let entities = HashMap::from([("unused".to_owned(), "value".to_owned())]);
    let mut references = 0;
    let mut meter = EntityExpansionMeter::new(ENTITY_EXPANSION_BYTE_CEILING);
    assert!(matches!(
        expand_document_entities(xml, &entities, &mut references, &mut meter)
            .expect("unused declaration is accepted"),
        std::borrow::Cow::Borrowed(_)
    ));
    assert!(matches!(
        expand_entity_references("text", &entities, 0, &mut references, &mut meter,)
            .expect("plain attribute is accepted"),
        std::borrow::Cow::Borrowed(_)
    ));
}

#[test]
fn shallow_and_iterative_frontends_expand_explicit_attribute_entities_identically() {
    // XML 1.0 section 3.3.3 requires general entity replacement while normalizing every
    // explicit attribute value: https://www.w3.org/TR/xml/#AVNormalize
    let xml = r#"<!DOCTYPE root [<!ENTITY quoted '&quot;value&quot;'>]><root attr="&quoted;"/>"#;
    let shallow = Document::parse(xml, None).expect("shallow frontend expands the entity");
    let iterative =
        Document::parse_iterative(xml, None).expect("iterative frontend expands the entity");
    assert_eq!(shallow, iterative);
    let root = shallow
        .node(shallow.root())
        .expect("document root exists")
        .children[0];
    let NodeKind::Element { attributes, .. } = &shallow.node(root).expect("element exists").kind
    else {
        panic!("document child is an element");
    };
    assert_eq!(attributes[0].value, "\"value\"");

    let prepared = prepare_xml_frontend_bounded(
        xml,
        ENTITY_EXPANSION_BYTE_CEILING,
        ENTITY_EXPANSION_DEPTH_CEILING,
        &mut ParseWork::new(usize::MAX),
    )
    .expect("roxmltree frontend preparation expands the entity");
    let parsed = roxmltree::Document::parse(&prepared).expect("prepared XML parses");
    assert_eq!(parsed.root_element().attribute("attr"), Some("\"value\""));
}

#[test]
fn unterminated_entity_names_with_utf8_remain_borrowed() {
    // Source-bounded scanning stops only at lexical delimiters and never slices through a
    // multibyte scalar when an entity reference is unterminated.
    let source = format!("&{}é", "a".repeat(1_022));
    let entities = HashMap::from([("x".to_owned(), "expanded".to_owned())]);
    assert_eq!(
        expand_entity_references(
            &source,
            &entities,
            0,
            &mut 0,
            &mut EntityExpansionMeter::new(ENTITY_EXPANSION_BYTE_CEILING),
        )
        .expect("bounded entity scan succeeds"),
        source
    );
}

#[test]
fn wide_string_value_traversal_preserves_document_order() {
    // A wide element must not require a sibling-sized DFS frontier merely to find the text
    // nodes that contribute its XPath string-value.
    let mut document = Document::empty(None);
    let root = document.push(
        document.root(),
        NodeKind::Element {
            name: ExpandedName::new(None::<String>, "root"),
            prefix: None,
            attributes: Vec::new(),
            namespaces: Arc::new(Vec::new()),
        },
        None,
    );
    for _ in 0..4_096 {
        document.push(
            root,
            NodeKind::Element {
                name: ExpandedName::new(None::<String>, "empty"),
                prefix: None,
                attributes: Vec::new(),
                namespaces: Arc::new(Vec::new()),
            },
            None,
        );
    }
    document.push(
        root,
        NodeKind::Text {
            value: "tail".into(),
            disable_output_escaping: false,
        },
        None,
    );

    assert_eq!(document.string_value(root), "tail");
}

#[test]
fn bounded_parse_rejects_source_before_building_the_tree() {
    // A caller-selected source limit is enforced before entity expansion or arena growth.
    let error = Document::parse_with_budget(
        "<root/>",
        None,
        ParseBudget::new(
            6,
            usize::MAX,
            usize::MAX,
            usize::MAX,
            usize::MAX,
            usize::MAX,
        ),
    )
    .expect_err("oversized source must be rejected");
    assert!(matches!(
        error,
        Error::Budget {
            kind: BudgetKind::SourceBytes,
            limit: 6,
            actual: 7,
        }
    ));
}

#[test]
fn parser_workspace_bound_covers_wide_retained_documents() {
    // External-resource parsing reserves this bound before scanning. A wide start tag is the
    // adversarial shape where attribute-vector and semantic-arena storage dominate input size.
    let attributes = (0..4096)
        .map(|index| format!(" a{index}='x'"))
        .collect::<String>();
    let xml = format!("<root{attributes}/>");
    let document = Document::parse(&xml, None).expect("wide document parses");
    assert!(parser_workspace_bytes(&xml) >= document.estimated_owned_bytes());
}

#[test]
fn owned_estimate_counts_retained_capacity_past_logical_lengths() {
    // External-document accounting must retain the actual backing stores after parsing, even
    // when allocator growth leaves most of a container unused.
    let mut document = Document::empty(None);
    document.nodes.reserve_exact(16);
    document.logical_roots.reserve_exact(8);
    document.nodes[0].children.reserve_exact(4);

    let clone_bytes = document.estimated_clone_bytes();
    assert!(document.estimated_owned_bytes() > clone_bytes);
}

#[test]
fn namespace_index_preserves_order_while_overriding_bindings() {
    // QName lookup needs constant-time prefix selection without changing namespace-node order.
    let mut namespaces = Arc::new(vec![
        Namespace {
            prefix: Some("a".into()),
            uri: "urn:old".into(),
        },
        Namespace {
            prefix: None,
            uri: "urn:default".into(),
        },
    ]);
    let mut index = namespace_index(&namespaces);
    set_namespace(
        &mut namespaces,
        &mut index,
        Some("a".into()),
        "urn:new".into(),
    );
    set_namespace(
        &mut namespaces,
        &mut index,
        Some("b".into()),
        "urn:added".into(),
    );

    assert_eq!(
        namespaces
            .iter()
            .map(|namespace| (namespace.prefix.as_deref(), namespace.uri.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (Some("a"), "urn:new"),
            (None, "urn:default"),
            (Some("b"), "urn:added"),
        ]
    );
    assert_eq!(
        namespace_for(&namespaces, &index, Some("a")).as_deref(),
        Some("urn:new")
    );
}

#[test]
fn bounded_parse_rejects_node_and_depth_growth() {
    // The synthetic root counts as one node; each XML element must reserve its slot before
    // materializing attributes, namespace state, or arena storage.
    assert!(matches!(
        Document::parse_with_budget(
            "<root><child/></root>",
            None,
            ParseBudget::new(
                usize::MAX,
                2,
                usize::MAX,
                usize::MAX,
                usize::MAX,
                usize::MAX,
            ),
        ),
        Err(Error::Budget {
            kind: BudgetKind::SourceNodes,
            limit: 2,
            actual: 3,
        })
    ));
    assert!(matches!(
        Document::parse_with_budget(
            "<root><child/></root>",
            None,
            ParseBudget::new(
                usize::MAX,
                usize::MAX,
                1,
                usize::MAX,
                usize::MAX,
                usize::MAX,
            ),
        ),
        Err(Error::Budget {
            kind: BudgetKind::RecursionDepth,
            limit: 1,
            actual: 2,
        })
    ));
}

#[test]
fn bounded_byte_parse_limits_decoded_output() {
    // UTF-16 input can expand after decoding; the decoded source budget remains authoritative.
    let mut bytes = vec![0xff, 0xfe];
    for unit in "<r>é</r>".encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    assert!(matches!(
        Document::parse_bytes_with_budget(
            &bytes,
            None,
            ParseBudget::new(
                8,
                usize::MAX,
                usize::MAX,
                usize::MAX,
                usize::MAX,
                usize::MAX,
            ),
        ),
        Err(Error::Budget {
            kind: BudgetKind::SourceBytes,
            limit: 8,
            actual,
        }) if actual > 8
    ));
}
