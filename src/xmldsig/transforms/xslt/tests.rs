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
fn stylesheets_are_serialized_from_the_parsed_tree() {
    // The stylesheet compiles from the tree: references are replaced, the declarations
    // written on its elements stay where they are, and every binding in scope at the
    // `<Transform>` that its element does not make itself is kept apart for insertion.
    let xml = concat!(
        r#"<root xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:p="urn:p">"#,
        r#"<Transform xmlns="urn:default"><xsl:stylesheet version="1.0" xmlns:in="urn:in">"#,
        r#"<xsl:template match="/"><out a="&#112;&lt;&#9;">x&amp;y<!--c--></out>"#,
        r#"<inner xmlns="" b="1"/></xsl:template></xsl:stylesheet></Transform></root>"#
    );
    let document = Document::parse(xml).expect("fixed XML parses");
    let transform = document
        .root_element()
        .first_child()
        .expect("the Transform element");
    let parsed = super::ParsedStylesheet::from_transform(transform).expect("a stylesheet");
    assert_eq!(
        parsed.document,
        concat!(
            r#"<xsl:stylesheet xmlns:in="urn:in" version="1.0"><xsl:template match="/">"#,
            r#"<out a="p&lt;&#9;">x&amp;y<!--c--></out><inner xmlns="" b="1"/>"#,
            r#"</xsl:template></xsl:stylesheet>"#
        )
    );
    assert_eq!(parsed.at, "<xsl:stylesheet".len());
    let mut inherited = parsed
        .inherited
        .split(' ')
        .filter(|declaration| !declaration.is_empty())
        .collect::<Vec<_>>();
    inherited.sort_unstable();
    assert_eq!(
        inherited,
        [
            r#"xmlns:p="urn:p""#,
            r#"xmlns:xsl="http://www.w3.org/1999/XSL/Transform""#,
            r#"xmlns="urn:default""#
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
            }) if actual > 262_144 && actual <= 2 * 262_144
        ),
        "{error:?}"
    );
}

#[test]
fn workspace_refusals_report_what_every_stage_holds() {
    // Execution receives the workspace less the compiled stylesheet and the parsed
    // input. When it is refused, the reported total includes what those stages hold,
    // so it exceeds the workspace limit it names.
    use crate::xslt::{CompileBudget, Compiler, Document as Tree, NoResolver, ParseBudget};
    let stylesheet = stylesheet(r#"<xsl:template match="/"><out/></xsl:template>"#);
    let input = format!("<root>{}</root>", "a".repeat(4096));
    let compiled = Compiler::new(
        std::sync::Arc::new(NoResolver),
        CompileBudget::new(usize::MAX, 0, 64, usize::MAX),
    )
    .compile(stylesheet.source(), None)
    .expect("stylesheet compiles")
    .retained_bytes();
    let unbounded = ParseBudget::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        usize::MAX,
        usize::MAX,
        usize::MAX,
    );
    let tree = Tree::parse_with_budget(&input, None, unbounded.with_owned_bytes(usize::MAX))
        .expect("input parses")
        .retained_bytes();
    // Execution first holds a copy of the input text, which this workspace cannot fit.
    let workspace = compiled + tree + input.len() / 2;
    let budget = TransformExecutionBudget::from_resources(&ResourcePolicy {
        max_xslt_workspace_bytes: workspace,
        ..ResourcePolicy::default()
    });
    let error = run(&budget, &stylesheet, input.as_bytes()).expect_err("execution is refused");
    assert!(
        matches!(
            error,
            TransformError::Policy(PolicyViolation::ResourceLimit {
                resource: resource_name::XSLT_WORKSPACE_BYTES,
                maximum,
                actual,
            }) if maximum == workspace && actual > workspace
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
