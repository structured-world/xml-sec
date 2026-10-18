use super::super::{
    Transform, TransformData, TransformError, TransformExecutionBudget, TransformOptions,
    execute_transforms_with_options_and_budget,
};
use super::XsltStylesheet;
use crate::policy::{PolicyViolation, ResourcePolicy, resource_name};
use crate::xml::dom::Document;

const XSL: &str = "http://www.w3.org/1999/XSL/Transform";

fn stylesheet(body: &str) -> XsltStylesheet {
    XsltStylesheet::new(format!(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="{XSL}">{body}</xsl:stylesheet>"#
    ))
    .expect("test stylesheet is valid markup")
}

fn run(
    budget: &TransformExecutionBudget,
    stylesheet: &XsltStylesheet,
    input: &[u8],
) -> Result<Vec<u8>, TransformError> {
    let signature = Document::parse("<Signature/>").expect("fixed XML parses");
    execute_transforms_with_options_and_budget(
        signature.root_element(),
        TransformData::Binary(input.to_vec()),
        &[Transform::Xslt(stylesheet.clone())],
        TransformOptions::default(),
        budget,
    )
}

#[test]
fn unresolved_references_respect_scopes_inside_the_stylesheet() {
    // Only prefixes used where no element of the stylesheet declares them are inherited.
    // Axes, quoted literals and inner redeclarations are not references to inherit.
    let markup = concat!(
        r#"<xsl:stylesheet version="1.0" exclude-result-prefixes="foo #default">"#,
        r#"<xsl:template match="ds:Object[@a='q:x']" mode="child::m"><out/>"#,
        r#"<inner xmlns:in="urn:in" in:attr="{in:f()}"/><in:x xmlns:in="urn:other"/>"#,
        r#"</xsl:template></xsl:stylesheet>"#
    );
    let (name, mut unresolved) = super::unresolved_references(markup).expect("markup scans");
    assert_eq!(name, "xsl:stylesheet".len());
    unresolved.sort();
    assert_eq!(
        unresolved,
        [
            None,
            Some("ds".into()),
            Some("foo".into()),
            Some("xsl".into())
        ]
    );
}

#[test]
fn every_parser_pass_is_charged_to_the_operation() {
    // The stylesheet is preflighted, then read by three compiler passes; the input is
    // decoded, preflighted and scanned once. Charging each text once per operation let a
    // caller-selected parse-work limit be exceeded several times over.
    let stylesheet = stylesheet(r#"<xsl:template match="/"><out/></xsl:template>"#);
    let input = b"<doc><item>a</item></doc>";
    let charged = 4 * stylesheet.source().len() + 3 * input.len();
    let budget = TransformExecutionBudget::from_resources(&ResourcePolicy::default());
    run(&budget, &stylesheet, input).expect("transform succeeds");
    assert_eq!(budget.xml_parse_work().consumed(), charged);

    let short = TransformExecutionBudget::from_resources(&ResourcePolicy {
        max_xml_parse_work_bytes: charged - 1,
        ..ResourcePolicy::default()
    });
    let error = run(&short, &stylesheet, input).expect_err("one byte short");
    assert!(
        matches!(
            error,
            TransformError::Policy(PolicyViolation::ResourceLimit {
                resource: resource_name::XML_PARSE_WORK_BYTES,
                ..
            })
        ),
        "{error:?}"
    );
}

#[test]
fn input_namespace_bindings_follow_the_operation_policy() {
    // C14N and XPath refuse transform output with more active bindings than the policy
    // allows; the XSLT input parser must apply the same limit.
    let budget = TransformExecutionBudget::from_resources(&ResourcePolicy {
        max_xml_namespace_bindings: 1,
        ..ResourcePolicy::default()
    });
    let error = run(
        &budget,
        &stylesheet(r#"<xsl:template match="/"><out/></xsl:template>"#),
        br#"<root xmlns:a="urn:a" xmlns:b="urn:b"/>"#,
    )
    .expect_err("two bindings exceed the limit of one");
    assert!(
        matches!(
            error,
            TransformError::Policy(PolicyViolation::ResourceLimit {
                resource: resource_name::XML_NAMESPACE_BINDINGS,
                maximum: 1,
                actual: 2,
            })
        ),
        "{error:?}"
    );
}

#[test]
fn input_octets_are_bounded_before_decoding() {
    // max_xml_document_bytes bounds the octets received; UTF-16 input occupies twice the
    // bytes of the UTF-8 text it decodes to.
    let text = format!("<doc>{}</doc>", "a".repeat(400));
    let mut input = vec![0xff, 0xfe];
    for unit in text.encode_utf16() {
        input.extend_from_slice(&unit.to_le_bytes());
    }
    let maximum = text.len() + 100;
    assert!(input.len() > maximum);
    let budget = TransformExecutionBudget::from_resources(&ResourcePolicy {
        max_xml_document_bytes: maximum,
        ..ResourcePolicy::default()
    });
    let error = run(
        &budget,
        &stylesheet(r#"<xsl:template match="/"><out/></xsl:template>"#),
        &input,
    )
    .expect_err("the encoded input exceeds the document limit");
    assert!(
        matches!(
            error,
            TransformError::Policy(PolicyViolation::ResourceLimit {
                resource: resource_name::XML_DOCUMENT,
                maximum: refused,
                actual,
            }) if refused == maximum && actual == input.len()
        ),
        "{error:?}"
    );
}

#[test]
fn the_parsed_input_shares_the_workspace() {
    // Twenty thousand empty elements take about eighty kilobytes of text and several
    // megabytes as a tree. The workspace bounds the tree while it is built, not only the
    // execution that follows it: the refusal comes when the tree's growth crosses the
    // limit (one doubling of its arena at most), not after the whole tree exists.
    let input = format!("<root>{}</root>", "<n/>".repeat(20_000));
    let budget = TransformExecutionBudget::from_resources(&ResourcePolicy {
        max_xslt_workspace_bytes: 256 * 1024,
        ..ResourcePolicy::default()
    });
    let error = run(
        &budget,
        &stylesheet(r#"<xsl:template match="/"><out/></xsl:template>"#),
        input.as_bytes(),
    )
    .expect_err("the tree exceeds the workspace");
    assert!(
        matches!(
            error,
            TransformError::Policy(PolicyViolation::ResourceLimit {
                resource: resource_name::XSLT_WORKSPACE_BYTES,
                maximum: 262_144,
                actual,
            }) if actual <= 2 * 262_144
        ),
        "{error:?}"
    );
}

#[test]
fn failed_executions_consume_the_shared_allowance() {
    // A Manifest keeps verifying after one reference fails. Work a failed execution did
    // must leave the operation's allowance, or each failing reference spends it anew.
    // Each execution creates five result nodes per input element: 4000 of the 6000 the
    // allowance admits, while every other kind of work stays well below it.
    let input = format!("<root>{}</root>", "<n/>".repeat(800));
    let budget = TransformExecutionBudget::from_resources(&ResourcePolicy {
        max_xslt_work: 6000,
        ..ResourcePolicy::default()
    });
    let copy = r#"<xsl:for-each select="/root/n"><x/><x/><x/><x/><x/></xsl:for-each>"#;
    let failing = stylesheet(&format!(
        r#"<xsl:template match="/"><out>{copy}<xsl:message terminate="yes">stop</xsl:message></out></xsl:template>"#
    ));
    let error = run(&budget, &failing, input.as_bytes()).expect_err("the stylesheet terminates");
    assert!(matches!(error, TransformError::Xslt(_)), "{error:?}");

    let copying = stylesheet(&format!(
        r#"<xsl:template match="/"><out>{copy}</out></xsl:template>"#
    ));
    let error = run(&budget, &copying, input.as_bytes())
        .expect_err("the first execution already spent most of the allowance");
    assert!(
        matches!(
            error,
            TransformError::Policy(PolicyViolation::ResourceLimit {
                resource: resource_name::XSLT_WORK,
                maximum: 6000,
                ..
            })
        ),
        "{error:?}"
    );
}
