use super::super::{
    Transform, TransformData, TransformError, TransformExecutionBudget, TransformOptions,
    execute_transforms_with_options_and_budget,
};
use super::XsltStylesheet;
use crate::policy::{PolicyViolation, ResourcePolicy, resource_name};
use crate::xml::dom::Document;

const XSL: &str = "http://www.w3.org/1999/XSL/Transform";

#[test]
fn replay_output_copy_obeys_xslt_workspace_peak() {
    // Escaping expands a compact result tree into a large serialized buffer.
    // Replay must admit that buffer and its accounted copy together, even when
    // the general query account has ample room after the engine trees drop.
    use structured_asn1::memory::{Memory, MemoryAccount};
    let sheet = XsltStylesheet::new(format!(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="{XSL}" xmlns:s="http://exslt.org/strings" exclude-result-prefixes="s"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><out><xsl:value-of select="s:padding(90000, '&amp;')"/></out></xsl:template></xsl:stylesheet>"#
    ))
    .expect("valid amplification stylesheet");
    let native =
        run(&TransformExecutionBudget::default(), &sheet, b"<doc/>").expect("native execution");
    let peak = native.capacity() + native.len();
    let expected = native.clone();
    drop(native);
    for limit in [peak - 1, peak] {
        let resources = ResourcePolicy {
            max_xslt_workspace_bytes: limit,
            ..Default::default()
        };
        run(
            &TransformExecutionBudget::from_resources(&resources),
            &sheet,
            b"<doc/>",
        )
        .expect("the engine itself fits below the copy peak");
        let budget = TransformExecutionBudget::from_resources(&resources);
        let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(1 << 26, 1 << 28)));
        let result = super::execute::<_, crate::xml::dom::storage::Native>(
            super::XsltParameter::Stylesheet(&sheet),
            b"<doc/>",
            crate::policy::XsltStylesheetSemantics::Specification,
            false,
            &budget,
            budget.xml_parse_work(),
            &crate::c14n::scratch::Accounted(&memory),
        );
        if limit < peak {
            assert!(
                result.is_err(),
                "replay admitted both copies above the XSLT workspace"
            );
            assert!(
                matches!(
                    result,
                    Err(TransformError::Policy(PolicyViolation::ResourceLimit {
                        resource: resource_name::XSLT_WORKSPACE_BYTES, maximum, actual,
                    })) if maximum == limit && actual == peak
                ),
                "replay must refuse the simultaneous output copies"
            );
        } else {
            match result.expect("exact copy peak fits") {
                super::ExecutionData::Accounted(bytes) => assert_eq!(&*bytes, &expected),
                _ => panic!("expected accounted replay output"),
            }
        }
        assert_eq!(memory.used(), 0, "all temporary output charges released");
    }
}

#[test]
fn replay_accepts_referenced_whitespace_beside_stylesheet() {
    // The in-place query path must apply the same root-node model as native
    // stylesheet capture, without emitting a character reference outside root.
    let xml = format!(
        r#"<Transform>&#13;<xsl:stylesheet xmlns:xsl="{XSL}" version="1.0"><xsl:template match="/"><out/></xsl:template></xsl:stylesheet>&#13;</Transform>"#
    );
    let document = Document::parse(&xml).expect("accepted Transform whitespace");
    query_run_with(
        super::XsltParameter::Transform(document.root_element()),
        b"<doc/>",
        1 << 24,
        1 << 28,
    )
    .outcome
    .expect("replay ignores root-level whitespace");
}

#[test]
fn transcoded_input_refuses_growth_before_consuming_the_document() {
    // Native decoding must not materialize a document-sized allocation before
    // discovering that only a much smaller XSLT workspace is permitted.
    let sheet = stylesheet(r#"<xsl:template match="/"><out/></xsl:template>"#);
    let text = format!("<doc>{}</doc>", "x".repeat(1 << 20));
    let mut input = vec![0xff, 0xfe];
    for unit in text.encode_utf16() {
        input.extend_from_slice(&unit.to_le_bytes());
    }
    let limit = 1 << 16;
    let budget = TransformExecutionBudget::from_resources(&ResourcePolicy {
        max_xslt_workspace_bytes: limit,
        ..Default::default()
    });
    let error = run(&budget, &sheet, &input).expect_err("decode exceeds workspace");
    assert!(
        matches!(error, TransformError::Policy(PolicyViolation::ResourceLimit {
        resource: resource_name::XSLT_WORKSPACE_BYTES, maximum, actual
    }) if maximum == limit && actual <= 2 * limit),
        "{error:?}"
    );
}

#[test]
fn in_place_stylesheet_preserves_document_siblings() {
    // XSLT 1.0 section 12.1: document('') observes the stylesheet document,
    // including accepted top-level processing instructions and comments.
    let xml = format!(
        r#"<Transform><?before alpha?><!--one--><xsl:stylesheet version="1.0" xmlns:xsl="{XSL}"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="concat(count(document('')/processing-instruction()), ':', count(document('')/comment()))"/></xsl:template></xsl:stylesheet><!--two--><?after beta?></Transform>"#
    );
    let document = Document::parse(&xml).expect("stylesheet siblings are well-formed XML");
    for semantics in [
        crate::policy::XsltStylesheetSemantics::Specification,
        crate::policy::XsltStylesheetSemantics::Libxmlsec1,
    ] {
        let budget = TransformExecutionBudget::default();
        let result = super::execute::<_, crate::xml::dom::storage::Native>(
            super::XsltParameter::Transform(document.root_element()),
            b"<doc/>",
            semantics,
            false,
            &budget,
            budget.xml_parse_work(),
            &crate::c14n::scratch::Native,
        )
        .expect("both semantics execute the complete stylesheet document");
        let super::ExecutionData::NativeBinary(bytes) = result else {
            panic!("expected bytes")
        };
        assert_eq!(bytes, b"2:2", "{semantics:?}");
    }
}

#[test]
fn entity_child_does_not_hide_repeated_namespace_declarations() {
    // XML 1.0 section 4.4.2 includes entity replacement children without
    // moving the containing start tag into that entity's source range.
    for backend in [
        #[cfg(feature = "xml-backend-roxmltree")]
        crate::XmlBackend::Roxmltree,
        #[cfg(feature = "xml-backend-xmloxide")]
        crate::XmlBackend::Xmloxide,
    ] {
        for child in ["<!--comment-->", "&comment;"] {
            let xml = format!(
                r#"<!DOCTYPE Transform [<!ENTITY comment "<!--comment-->">]><Transform xmlns:xsl="{XSL}"><xsl:stylesheet version="1.0" xmlns:xsl="{XSL}" xmlns:m="urn:meta" m:note="a > b">{child}<xsl:template match="/"><out/></xsl:template></xsl:stylesheet></Transform>"#
            );
            let document = Document::parse_with_options_and_backend(
                &xml,
                crate::xml::dom::ParsingOptions {
                    allow_dtd: true,
                    ..Default::default()
                },
                backend,
            )
            .expect("entity fixture parses");
            let parsed = super::ParsedStylesheet::from_transform(
                document.root_element(),
                usize::MAX,
                super::Inheritance::Omit,
                &mut super::unmetered,
            )
            .expect("stylesheet serializes");
            assert!(
                parsed.document.contains(&format!(r#"xmlns:xsl="{XSL}""#)),
                "{backend:?}: {child}"
            );
            crate::xslt::Compiler::new(
                std::sync::Arc::new(crate::xslt::NoResolver),
                crate::xslt::CompileBudget::new(1 << 20, 0, 64, 1 << 24),
            )
            .compile(&parsed.document, None)
            .expect("explicit stylesheet namespace survives");
        }
    }
}

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
    let parsed = super::ParsedStylesheet::from_transform(
        transform,
        usize::MAX,
        super::Inheritance::Separate,
        &mut super::unmetered,
    )
    .expect("a stylesheet");
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
fn stylesheet_serialization_stays_within_the_workspace() {
    // A stylesheet serialized from a parsed `<Transform>` is text in the workspace. It is
    // refused before its allocation would exceed the bytes granted, not after a full copy.
    let body = "<xsl:template match=\"/\"><out>x</out></xsl:template>".repeat(100);
    let xml = format!(
        r#"<Transform><xsl:stylesheet version="1.0" xmlns:xsl="{XSL}">{body}</xsl:stylesheet></Transform>"#
    );
    let document = Document::parse(&xml).expect("fixed XML parses");
    let transform = document.root_element();
    let serialize = |limit| {
        super::ParsedStylesheet::from_transform(
            transform,
            limit,
            super::Inheritance::Inline,
            &mut super::unmetered,
        )
    };
    let full = serialize(usize::MAX).expect("a stylesheet").document.len();
    let limit = full / 2;
    match serialize(limit) {
        Err(super::Unavailable::Exceeds(needed)) => assert!(needed > limit && needed <= full),
        _ => panic!("half the serialized size is refused"),
    }

    let mut text = super::Bounded::new(limit);
    while text.push_str("<a/>").is_ok() {}
    assert!(
        text.text.capacity() <= limit,
        "capacity {} over {limit}",
        text.text.capacity()
    );
}

#[test]
fn stylesheet_growth_admits_old_and_new_blocks() {
    // Reallocation may move a buffer: its replacement must fit while the old
    // allocation is still live, not merely after realloc releases it.
    let mut text = super::Bounded::new(100);
    text.push_str(&"a".repeat(60))
        .expect("first allocation fits");
    assert!(
        text.push_str(&"b".repeat(20)).is_err(),
        "growth hides its old live block"
    );
    assert_eq!(text.text.len(), 60);
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

/// What one transform did inside a query.
struct QueryRun {
    outcome: Result<(), TransformError>,
    /// Engine work the operation allowance admitted.
    executed: usize,
    /// Work the query paid.
    paid: usize,
    /// Parse work the operation was charged.
    scanned: usize,
}

/// Run `stylesheet` in a query with `remaining` work units and `memory` bytes left.
fn query_run(
    stylesheet: &XsltStylesheet,
    input: &[u8],
    remaining: usize,
    memory: usize,
) -> QueryRun {
    query_run_with(
        super::XsltParameter::Stylesheet(stylesheet),
        input,
        remaining,
        memory,
    )
}

/// [`query_run`] for any stylesheet parameter.
fn query_run_with(
    parameter: super::XsltParameter<'_>,
    input: &[u8],
    remaining: usize,
    memory: usize,
) -> QueryRun {
    use structured_asn1::memory::{Memory, MemoryAccount};
    let budget = TransformExecutionBudget::from_resources(&ResourcePolicy::default());
    let work = Memory::new(std::sync::Arc::new(MemoryAccount::new(memory, 1 << 26)));
    work.charge_work((work.work_remaining() - remaining) as u64)
        .expect("leave the remainder");
    let before = work.work_used();
    let scratch = crate::c14n::scratch::Accounted(&work);
    let outcome = super::execute::<_, crate::xml::dom::storage::Native>(
        parameter,
        input,
        crate::policy::XsltStylesheetSemantics::Specification,
        false,
        &budget,
        budget.xml_parse_work(),
        &scratch,
    )
    .map(drop);
    QueryRun {
        outcome,
        executed: super::WORK_KINDS
            .into_iter()
            .map(|kind| budget.xslt.work_used(kind))
            .sum(),
        paid: work.work_used() - before,
        scanned: budget.xml_parse_work().consumed(),
    }
}

/// [`query_run`] with ample memory; returns the outcome, the executed and the paid work.
fn run_in_query(
    stylesheet: &XsltStylesheet,
    input: &[u8],
    remaining: usize,
) -> (Result<(), TransformError>, usize, usize) {
    let run = query_run(stylesheet, input, remaining, 1 << 26);
    (run.outcome, run.executed, run.paid)
}

#[test]
fn adapter_scans_are_paid_by_the_query_before_they_run() {
    // The adapter checks the stylesheet and the input against the XML input policy in
    // its own lexical passes. A query with the work to decode the input but not to scan
    // it is refused before any lexical pass runs: only decoding is charged.
    use structured_asn1::memory::MemoryError;
    let sheet = stylesheet(r#"<xsl:template match="/"><out/></xsl:template>"#);
    let input = b"<doc/>";
    let run = query_run(&sheet, input, 10, 1 << 26);
    assert!(
        matches!(
            run.outcome,
            Err(TransformError::C14n(
                crate::c14n::C14nError::SharedExecution(MemoryError::WorkExceeded)
            ))
        ),
        "{:?}",
        run.outcome
    );
    assert_eq!(
        run.scanned,
        input.len(),
        "a text was scanned before it was paid for"
    );
}

#[test]
fn stylesheet_serialization_is_paid_before_it_runs() {
    // A stylesheet read from its `<Transform>` is serialized from the tree, and each of its
    // elements compares its in-scope bindings with its parent's. Many bindings and many
    // elements make that walk far more work than the text it writes, so a query without
    // the work is refused during the walk instead of paying only for the text afterwards.
    use structured_asn1::memory::MemoryError;
    let declarations: String = (0..100)
        .map(|index| format!(r#" xmlns:p{index}="urn:p{index}""#))
        .collect();
    let templates: String = (0..150)
        .map(|index| format!(r#"<xsl:template name="t{index}"/>"#))
        .collect();
    let xml = format!(
        r#"<root{declarations}><Transform><xsl:stylesheet version="1.0" xmlns:xsl="{XSL}">{templates}</xsl:stylesheet></Transform></root>"#
    );
    let document = Document::parse(&xml).expect("fixed XML parses");
    let transform = super::XsltParameter::Transform(
        document
            .root_element()
            .first_child()
            .expect("the Transform element"),
    );
    query_run_with(transform, b"<doc/>", 1 << 26, 1 << 26)
        .outcome
        .expect("an ample remainder admits the transform");

    // About a hundred comparisons per binding of each of 151 elements, and a few
    // thousand units of text.
    let remaining = 1 << 19;
    let run = query_run_with(transform, b"<doc/>", remaining, 1 << 26);
    assert!(
        matches!(
            run.outcome,
            Err(TransformError::C14n(
                crate::c14n::C14nError::SharedExecution(MemoryError::WorkExceeded)
            ))
        ),
        "{:?}",
        run.outcome
    );
    assert!(run.paid <= remaining);
}

#[test]
fn native_stylesheet_capture_obeys_operation_work() {
    // Namespace fan-out during native parameter capture must be refused before
    // serialization, even though this path has no replay query account.
    let declarations: String = (0..100)
        .map(|index| format!(r#" xmlns:p{index}="urn:p{index}""#))
        .collect();
    let templates = "<xsl:template match=\"/\"><out/></xsl:template>";
    let xml = format!(
        r#"<ds:Transforms xmlns:ds="{}"{declarations}><ds:Transform Algorithm="{}"><xsl:stylesheet version="1.0" xmlns:xsl="{XSL}">{templates}</xsl:stylesheet></ds:Transform></ds:Transforms>"#,
        super::super::XMLDSIG_NS,
        super::super::XSLT_TRANSFORM_URI,
    );
    let document = Document::parse(&xml).expect("fixed XML parses");
    let resources = ResourcePolicy {
        max_xslt_work: 1000,
        ..Default::default()
    };
    let mut parse = super::super::XPathSignatureParseBudget::from_resources(&resources);
    let result = super::super::parse_transforms_with_budget(document.root_element(), &mut parse);
    assert!(
        matches!(
            result,
            Err(TransformError::Policy(PolicyViolation::ResourceLimit {
                resource: resource_name::XSLT_WORK,
                ..
            }))
        ),
        "{result:?}"
    );
}

#[test]
fn each_input_scan_is_paid_before_it_runs() {
    // Without DTDs the input is scanned twice before the engine parses it: once for a
    // document type declaration and once against the XML input policy. A query with the
    // work to decode it and scan it one and a half times is refused before the second
    // scan, so the policy preflight never charges the operation.
    use structured_asn1::memory::MemoryError;
    let sheet = stylesheet(r#"<xsl:template match="/"><out/></xsl:template>"#);
    let input = format!("<!--{}--><doc/>", "a".repeat(100_000));
    let length = input.len();
    // Decoding admits the octets and then validates them: two input lengths.
    let run = query_run(&sheet, input.as_bytes(), 3 * length + length / 2, 1 << 26);
    assert!(
        matches!(
            run.outcome,
            Err(TransformError::C14n(
                crate::c14n::C14nError::SharedExecution(MemoryError::WorkExceeded)
            ))
        ),
        "{:?}",
        run.outcome
    );
    assert_eq!(
        run.scanned, length,
        "the second scan ran before it was paid for"
    );
}

#[test]
fn stylesheet_preflight_stops_at_the_current_query_remainder() {
    // Namespace bookkeeping is part of the current query, not just the later
    // compiler pass. The namespace-heavy preflight must exhaust the query
    // before the compiler's three additional text scans can be admitted.
    let sheet = stylesheet(&format!(
        "<xsl:template match=\"/\"><out {} /></xsl:template>",
        (0..1000)
            .map(|i| format!("xmlns:p{i}=\"urn:{i}\""))
            .collect::<Vec<_>>()
            .join(" ")
    ));
    let run = query_run(&sheet, b"<doc/>", 4 * sheet.source().len() + 1024, 1 << 26);
    assert!(run.outcome.is_err(), "the query cannot afford preflight");
    assert_eq!(run.executed, 0);
    assert!(
        run.scanned < 2 * sheet.source().len(),
        "stylesheet preflight ran without query admission: {}, paid {}, outcome {:?}",
        run.scanned,
        run.paid,
        run.outcome
    );
}

#[test]
fn entity_preflight_stops_at_the_current_query_remainder() {
    // A compact DTD can multiply preflight scans before the engine is entered.
    // Exhausting this query must stop that expansion, not merely the later parse.
    use structured_asn1::memory::{Memory, MemoryAccount};
    let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(1 << 26, 25_000)));
    let scratch = crate::c14n::scratch::Accounted(&memory);
    let budget = TransformExecutionBudget::default();
    let sheet = stylesheet(r#"<xsl:template match="/"><out/></xsl:template>"#);
    let input = format!(
        "<!DOCTYPE doc [<!ENTITY e '{}'>]><doc>{}</doc>",
        "x".repeat(2000),
        "&e;".repeat(100)
    );
    let result = super::execute::<_, crate::xml::dom::storage::Native>(
        super::XsltParameter::Stylesheet(&sheet),
        input.as_bytes(),
        crate::policy::XsltStylesheetSemantics::Specification,
        true,
        &budget,
        budget.xml_parse_work(),
        &scratch,
    );
    assert!(
        result.is_err(),
        "the current query cannot afford expanded input"
    );
    assert!(
        budget.xml_parse_work().consumed() < 100_000,
        "preflight traversed the expansion before query admission: {}",
        budget.xml_parse_work().consumed()
    );
}

#[test]
fn decoded_input_is_admitted_before_the_workspace() {
    // A query whose memory is no more than the workspace limit still decodes UTF-16
    // input: decoding takes what it needs first and the workspace gets the rest, instead
    // of the workspace taking everything and decoding being refused.
    let text = "<doc><item>a</item></doc>";
    let mut input = vec![0xff, 0xfe];
    for unit in text.encode_utf16() {
        input.extend_from_slice(&unit.to_le_bytes());
    }
    let memory = 1 << 20;
    assert!(memory <= ResourcePolicy::default().max_xslt_workspace_bytes);
    let sheet = stylesheet(
        r#"<xsl:template match="/"><out><xsl:value-of select="//item"/></out></xsl:template>"#,
    );
    let run = query_run(&sheet, &input, 1 << 24, memory);
    run.outcome
        .expect("the decoded input and the transform fit the query");
}

#[test]
fn inherited_xml_space_preserves_stylesheet_whitespace() {
    // XSLT 1.0 section 3.4 keeps a whitespace-only text node of the stylesheet when an
    // ancestor element has xml:space="preserve"; the stylesheet's ancestors in the signed
    // document count. libxmlsec1 compiles the element alone and strips it.
    let xml = format!(
        concat!(
            r#"<root xml:space="preserve"><Transform><xsl:stylesheet version="1.0" xmlns:xsl="{xsl}">"#,
            r#"<xsl:template match="/"><out><xsl:value-of select="'a'"/> <xsl:value-of select="'b'"/>"#,
            r#"</out></xsl:template></xsl:stylesheet></Transform></root>"#
        ),
        xsl = XSL
    );
    let document = Document::parse(&xml).expect("fixed XML parses");
    let transform = document
        .root_element()
        .first_child()
        .expect("the Transform element");
    let output = |semantics| {
        let budget = TransformExecutionBudget::from_resources(&ResourcePolicy::default());
        match super::execute::<_, crate::xml::dom::storage::Native>(
            super::XsltParameter::Transform(transform),
            b"<doc/>",
            semantics,
            false,
            &budget,
            budget.xml_parse_work(),
            &crate::c14n::scratch::Native,
        )
        .expect("the transform runs")
        {
            super::super::ExecutionData::NativeBinary(bytes) => {
                String::from_utf8(bytes).expect("serialized output is UTF-8")
            }
            _ => panic!("XSLT output is binary"),
        }
    };
    assert_eq!(
        output(crate::policy::XsltStylesheetSemantics::Specification),
        "<?xml version=\"1.0\"?>\n<out>a b</out>\n"
    );
    assert_eq!(
        output(crate::policy::XsltStylesheetSemantics::Libxmlsec1),
        "<?xml version=\"1.0\"?>\n<out>ab</out>\n"
    );
}

#[test]
fn query_work_bounds_the_engine_while_it_runs() {
    // A query replaying a reference may have little work left. The engine must stop
    // when it crosses that remainder, not after doing all the work the policy allows;
    // parsing the stylesheet and the input is paid from the same remainder first.
    // The stylesheet evaluates a test per input element and writes almost nothing, so
    // nearly all the work the query pays for a successful run is the engine's.
    use structured_asn1::memory::MemoryError;
    let input = format!("<root>{}</root>", "<n/>".repeat(2000));
    let scanning = stylesheet(
        r#"<xsl:template match="/"><out><xsl:for-each select="/root/n"><xsl:if test="@a"><x/></xsl:if></xsl:for-each></out></xsl:template>"#,
    );
    let (outcome, ample, paid) = run_in_query(&scanning, input.as_bytes(), 1 << 24);
    outcome.expect("an ample remainder admits the transform");
    assert!(ample > 4000);
    // Everything but the execution, plus a hundred units for it.
    let remaining = paid - ample + 100;
    let (outcome, executed, paid) = run_in_query(&scanning, input.as_bytes(), remaining);
    assert!(
        matches!(
            outcome,
            Err(TransformError::C14n(
                crate::c14n::C14nError::SharedExecution(MemoryError::WorkExceeded)
            ))
        ),
        "{outcome:?}"
    );
    // The hundred units, and what the successful run paid after execution, which this
    // run never reaches.
    assert!(
        executed < ample / 10,
        "the engine ran {executed} of {ample} units past the query"
    );
    assert!(paid <= remaining);

    // Too little for the parser passes: refused before any execution.
    let (outcome, executed, _) = run_in_query(&scanning, input.as_bytes(), 10);
    assert!(
        matches!(
            outcome,
            Err(TransformError::C14n(
                crate::c14n::C14nError::SharedExecution(MemoryError::WorkExceeded)
            ))
        ),
        "{outcome:?}"
    );
    assert_eq!(executed, 0);
}

#[test]
fn the_parsed_input_is_charged_to_the_workspace_once() {
    // The adapter holds the compiled stylesheet and the parsed input, counted in the
    // workspace. The engine opens its owned-byte count with the input's text length,
    // which that held tree already covers, so the workspace needs the held bytes plus
    // what execution needs beyond its opening charge, not that charge a second time.
    use crate::xslt::{
        CompileBudget, Compiler, Document as Tree, ExecutionEnvironment, ExecutionOptions,
        NoResolver, Parameters, ParseBudget,
    };
    let sheet = stylesheet(r#"<xsl:template match="/"><out/></xsl:template>"#);
    let input = format!("<root>{}</root>", "a".repeat(65_536));
    let compiled = Compiler::new(
        std::sync::Arc::new(NoResolver),
        CompileBudget::new(usize::MAX, 0, 64, usize::MAX),
    )
    .compile(sheet.source(), None)
    .expect("stylesheet compiles");
    let unbounded = ParseBudget::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        usize::MAX,
        usize::MAX,
        usize::MAX,
    );
    let tree = Tree::parse_with_budget(&input, None, unbounded.with_owned_bytes(usize::MAX))
        .expect("input parses");
    let allowance = super::Allowance::new(&ResourcePolicy::default());
    let executes = |owned: usize| {
        compiled
            .execute_with_environment(
                &tree,
                &Parameters::new(),
                ExecutionEnvironment::new(std::sync::Arc::new(NoResolver)),
                ExecutionOptions {
                    budget: allowance.execution_budget(owned),
                    initial_mode: None,
                    initial_template: None,
                },
            )
            .is_ok()
    };
    // The least owned-byte budget the engine runs this execution in.
    let (mut refused, mut admitted) = (0, 1 << 24);
    while admitted - refused > 1 {
        let middle = refused + (admitted - refused) / 2;
        if executes(middle) {
            admitted = middle;
        } else {
            refused = middle;
        }
    }
    let held = compiled.retained_bytes() + tree.retained_bytes();
    let exact = held + admitted - tree.source_bytes();
    let workspace = |bytes| {
        TransformExecutionBudget::from_resources(&ResourcePolicy {
            max_xslt_workspace_bytes: bytes,
            ..ResourcePolicy::default()
        })
    };
    run(&workspace(exact), &sheet, input.as_bytes()).expect("the transform fits its workspace");
    assert!(run(&workspace(exact - 1), &sheet, input.as_bytes()).is_err());
}

#[test]
fn parsed_stylesheet_copies_count_against_the_workspace() {
    // A stylesheet parsed from a signature keeps its markup and its serialization for
    // the whole transform. With the least workspace in which the same markup given to
    // `XsltStylesheet::new` runs, the parsed one, which holds those copies, is refused.
    let filler = "x".repeat(32 * 1024);
    let body = format!(
        r#"<xsl:variable name="v" select="'{filler}'"/><xsl:template match="/"><out/></xsl:template>"#
    );
    let given = stylesheet(&body);
    let xml = format!(
        concat!(
            r#"<Transforms xmlns="http://www.w3.org/2000/09/xmldsig#">"#,
            r#"<Transform Algorithm="{xslt}">{markup}</Transform></Transforms>"#
        ),
        xslt = super::super::XSLT_TRANSFORM_URI,
        markup = given.source()
    );
    let document = Document::parse(&xml).expect("fixed XML parses");
    let parsed = match super::super::parse_transforms(document.root_element())
        .expect("the transform parses")
        .pop()
    {
        Some(Transform::Xslt(stylesheet)) => stylesheet,
        _ => panic!("one XSLT transform"),
    };
    let workspace = |bytes| {
        TransformExecutionBudget::from_resources(&ResourcePolicy {
            max_xslt_workspace_bytes: bytes,
            ..ResourcePolicy::default()
        })
    };
    let input = b"<doc/>";
    let (mut refused, mut admitted) = (0, 1 << 24);
    while admitted - refused > 1 {
        let middle = refused + (admitted - refused) / 2;
        if run(&workspace(middle), &given, input).is_ok() {
            admitted = middle;
        } else {
            refused = middle;
        }
    }
    // Room for serialization to differ from the given markup, far less than the
    // two copies of the filler the parsed stylesheet holds.
    let error = run(&workspace(admitted + 4096), &parsed, input)
        .expect_err("the parsed copies do not fit beside the transform");
    assert!(
        matches!(
            error,
            TransformError::Policy(PolicyViolation::ResourceLimit {
                resource: resource_name::XSLT_WORKSPACE_BYTES,
                ..
            })
        ),
        "{error:?}"
    );
}

#[test]
fn compatibility_serialization_holds_no_inherited_declarations() {
    // Under libxmlsec1 semantics a stylesheet read from its `<Transform>` keeps only
    // what it declares itself, so the bindings of its ancestors are neither written nor
    // counted against the workspace.
    let declarations: String = (0..64)
        .map(|index| format!(r#" xmlns:p{index}="urn:{}""#, "x".repeat(64)))
        .collect();
    let xml = format!(
        r#"<root{declarations}><Transform><xsl:stylesheet version="1.0" xmlns:xsl="{XSL}"/></Transform></root>"#
    );
    let document = Document::parse(&xml).expect("fixed XML parses");
    let transform = document
        .root_element()
        .first_child()
        .expect("the Transform element");
    let serialize = |limit, inheritance| {
        super::ParsedStylesheet::from_transform(
            transform,
            limit,
            inheritance,
            &mut super::unmetered,
        )
    };
    let own = serialize(usize::MAX, super::Inheritance::Omit)
        .expect("a stylesheet")
        .document
        .len();
    // The old and replacement buffer may coexist during growth. This covers
    // that peak but remains far smaller than the inherited declarations.
    let workspace = 2 * own;
    assert!(
        serialize(workspace, super::Inheritance::Omit).is_ok(),
        "the stylesheet's own text fits"
    );
    assert!(matches!(
        serialize(workspace, super::Inheritance::Inline),
        Err(super::Unavailable::Exceeds(_))
    ));
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
