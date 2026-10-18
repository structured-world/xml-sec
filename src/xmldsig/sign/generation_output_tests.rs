use super::*;
use crate::xmldsig::transforms::transform_chain_produces_binary;

#[test]
fn relationship_output_classifiers_agree() {
    // Both generation preflight and the typed executor classify the
    // algorithm's output, independently of subsequent chain validation.
    assert!(generation_chain_produces_binary(
        false,
        &[super::super::RELATIONSHIP_TRANSFORM_URI]
    ));
    assert!(transform_chain_produces_binary(
        false,
        &[Transform::Relationship(vec![])]
    ));
}

#[cfg(feature = "xslt")]
#[test]
fn xslt_output_classifiers_agree() {
    // XSLT serializes its result tree, so a terminal XSLT step needs no implicit C14N.
    assert!(generation_chain_produces_binary(
        false,
        &[super::super::XSLT_TRANSFORM_URI]
    ));
    let stylesheet = crate::xmldsig::XsltStylesheet::new(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"/>"#,
    )
    .expect("empty stylesheet is valid markup");
    assert!(transform_chain_produces_binary(
        false,
        &[Transform::Xslt(stylesheet)]
    ));
}
