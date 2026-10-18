use super::{Value, format_xpath_number};
use crate::{Document, NodeKind, NodeReference};

#[test]
fn public_node_set_string_conversion_uses_document_order() {
    // Public callers may construct node sets in any vector order; XPath conversion must not
    // let that storage order override the document's first node.
    let document = Document::parse("<root><first>one</first><second>two</second></root>", None)
        .expect("document parses");
    let elements = document
        .nodes()
        .filter_map(|(id, node)| matches!(node.kind, NodeKind::Element { .. }).then_some(id))
        .collect::<Vec<_>>();
    let value = Value::NodeSet(vec![
        NodeReference::Node(elements[2]),
        NodeReference::Node(elements[1]),
    ]);
    assert_eq!(value.into_string(&document), "one");
}

#[test]
fn xpath_non_finite_numbers_keep_their_lexical_forms() {
    assert_eq!(format_xpath_number(f64::NAN), "NaN");
    assert_eq!(format_xpath_number(f64::INFINITY), "Infinity");
    assert_eq!(format_xpath_number(f64::NEG_INFINITY), "-Infinity");
}

#[test]
fn xpath_finite_numbers_do_not_lose_significant_digits() {
    assert_eq!(format_xpath_number(59.999_999_999_99), "59.99999999999");
    assert_eq!(format_xpath_number(0.000_01), "0.00001");
    assert_eq!(
        format_xpath_number(0.640_000_000_000_000_1),
        "0.6400000000000001"
    );
    assert_eq!(
        format_xpath_number(95_012.388_419_899_99),
        "95012.38841989999"
    );
    assert_eq!(format_xpath_number(285_311_670_611.0), "285311670611");
}
