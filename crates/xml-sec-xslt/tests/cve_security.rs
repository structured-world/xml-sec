//! Semantic counterparts of documented native XSLT security defects.
use std::sync::Arc;
use xml_sec_xslt::{
    CompileBudget, Compiler, Document, ExecutionBudget, ExecutionOptions, NoResolver, Parameters,
};

fn compile(text: &str) -> xml_sec_xslt::Result<xml_sec_xslt::Stylesheet> {
    Compiler::new(
        Arc::new(NoResolver),
        CompileBudget::new(1 << 20, 8, 128, 8 << 20),
    )
    .compile(text, None)
}

fn options() -> ExecutionOptions {
    ExecutionOptions {
        initial_mode: None,
        initial_template: None,
        budget: ExecutionBudget {
            source_bytes: 1 << 20,
            external_documents: 8,
            recursion_depth: 128,
            xpath_evaluations: 100_000,
            xpath_operations: 1_000_000,
            extension_operations: 1_000_000,
            pattern_evaluations: 100_000,
            template_applications: 100_000,
            sort_comparisons: 100_000,
            key_entries: 10_000,
            result_nodes: 100_000,
            serialized_bytes: 1 << 20,
            messages: 100,
            owned_bytes: 16 << 20,
        },
    }
}

fn run(sheet: &str, xml: &str) -> Vec<u8> {
    compile(sheet)
        .unwrap()
        .execute(
            &Document::parse(xml, None).unwrap(),
            &Parameters::new(),
            Arc::new(NoResolver),
            options(),
        )
        .unwrap()
        .serialized
        .bytes
}

fn text_sheet(body: &str) -> String {
    format!(
        "<xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform' version='1.0'><xsl:output method='text'/><xsl:template match='/'>{body}</xsl:template></xsl:stylesheet>"
    )
}

#[test]
fn cve_2011_1202_generated_ids_are_stable_node_ids_not_addresses() {
    // The original defect leaked heap addresses. Independent compilations and
    // trees must produce the same deterministic identifier for this position.
    // Namespace-node results also exercise the early-release defect identified
    // by Chromium review 10823168 (CVE-2012-2870).
    for path in ["/*", "/*/namespace::p"] {
        let sheet = text_sheet(&format!("<xsl:value-of select='generate-id({path})'/>"));
        let expected = run(&sheet, "<r xmlns:p='urn:p'/>");
        assert!(!expected.is_empty());
        for _ in 0..16 {
            assert_eq!(run(&sheet, "<r xmlns:p='urn:p'/>"), expected);
        }
    }
}

#[test]
fn cve_2012_2870_bad_id_key_patterns_cannot_resume_compilation() {
    // The second fixing diff returns immediately after an id/key parse error
    // instead of continuing with a partly built match. These are semantic
    // counterparts; neither Chromium fixing diff supplies an exploit file.
    for pattern in [
        "id(1)/a",
        "key(&quot;k&quot;)/a",
        "unknown(&quot;x&quot;)/a",
    ] {
        let sheet = format!(
            "<xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform' version='1.0'><xsl:template match='{pattern}'/></xsl:stylesheet>"
        );
        assert_eq!(
            compile(&sheet).unwrap_err().kind(),
            xml_sec_xslt::ErrorKind::Static
        );
    }
    compile("<xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform' version='1.0'><xsl:template match='id(&quot;x&quot;)/a'/></xsl:stylesheet>").unwrap();
}

#[test]
fn cve_2012_6139_empty_key_match_is_a_static_error() {
    // xsltAddKey dereferenced an empty compiled match. A bad declaration must
    // fail compilation, not produce a partly usable stylesheet.
    let bad = "<xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform' version='1.0'><xsl:key name='k' match='' use='.'/></xsl:stylesheet>";
    assert_eq!(
        compile(bad).unwrap_err().kind(),
        xml_sec_xslt::ErrorKind::Static
    );
    let good = bad.replace("match=''", "match='item'");
    compile(&good).unwrap();
}

#[test]
fn cve_2021_30560_stripping_does_not_invalidate_held_source_nodes() {
    // The libxslt fix stopped deleting source nodes during apply-templates.
    // A variable holding the original node set must remain usable afterward.
    let sheet = "<xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform' version='1.0'><xsl:strip-space elements='*'/><xsl:output method='text'/><xsl:template match='/'><xsl:variable name='held' select='/*/node()'/><xsl:apply-templates select='/*'/><xsl:value-of select='count($held)'/></xsl:template><xsl:template match='r'><xsl:apply-templates/></xsl:template></xsl:stylesheet>";
    assert_eq!(run(sheet, "<r>  <a>A</a>  <b>B</b>  </r>"), b"AB2");
}

#[test]
fn cve_2024_55549_excluded_namespace_lifetime_survives_local_redeclaration() {
    // Excluded URI metadata must outlive compile-time namespace nodes; this
    // checks exact namespace fixup, not just absence of a memory fault.
    let sheet = "<xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform' xmlns:p='urn:outer' exclude-result-prefixes='p' version='1.0'><xsl:output omit-xml-declaration='yes'/><xsl:template match='/'><out><child xmlns:p='urn:inner' xsl:exclude-result-prefixes='p'/></out></xsl:template></xsl:stylesheet>";
    assert_eq!(run(sheet, "<r/>"), b"<out><child/></out>\n");
}

#[test]
fn cve_2025_24855_nested_sort_and_number_restore_xpath_context() {
    // Sort and number evaluate nested XPath, but later operations still use
    // the current source node rather than a stale temporary context.
    let sheet = text_sheet(
        "<xsl:for-each select='r/i'><xsl:sort select='@v' data-type='number'/><xsl:number value='@v' format='1'/><xsl:value-of select='name()'/><xsl:text>;</xsl:text></xsl:for-each>",
    );
    assert_eq!(run(&sheet, "<r><i v='2'/><i v='1'/></r>"), b"1i;2i;");
}

#[test]
fn cve_2019_13118_grouping_preserves_a_multibyte_separator() {
    // Native grouping used a too-narrow type for character/length. Four-byte
    // UTF-8 grouping must neither truncate nor expose uninitialized bytes.
    assert_eq!(
        run(
            &text_sheet("<xsl:number value='1234567' grouping-separator='💠' grouping-size='3'/>"),
            "<r/>"
        ),
        "1💠234💠567".as_bytes()
    );
}

#[test]
fn cve_2019_13117_number_format_empty_and_punctuation_are_initialized() {
    // Format-token edge paths must have deterministic values, not stack bytes.
    for format in ["", ".", "()", "1"] {
        let sheet = text_sheet(&format!("<xsl:number value='12' format='{format}'/>"));
        let expected: &[u8] = match format {
            "." => b".12.",
            "()" => b"()12()",
            _ => b"12",
        };
        assert_eq!(run(&sheet, "<r/>"), expected, "{format}");
    }
}

#[test]
fn cve_2008_2935_long_rc4_roundtrip_is_not_a_native_fixed_buffer() {
    // The legacy EXSLT capability is preserved, with a long result whose full
    // bytes are checked. It is not used for product key custody or randomness.
    let body = format!(
        "<xsl:variable name='plain' select=\"'{}'\"/><xsl:value-of select='crypto:rc4_decrypt(\"key\",crypto:rc4_encrypt(\"key\",$plain))'/>",
        "x".repeat(4096)
    );
    let sheet = text_sheet(&body).replace(
        "version='1.0'",
        "xmlns:crypto='http://exslt.org/crypto' version='1.0'",
    );
    assert_eq!(run(&sheet, "<r/>"), vec![b'x'; 4096]);
}

#[test]
fn cve_2016_1684_large_roman_number_uses_bounded_decimal_conversion() {
    // The native overflow involved iteration proportional to a huge Roman
    // numeral. This documented compatibility range falls back to decimal.
    assert_eq!(
        run(
            &text_sheet(
                "<xsl:number value='12' format='i'/><xsl:text>|</xsl:text><xsl:number value='2147483648' format='i'/>"
            ),
            "<r/>"
        ),
        b"xii|2147483648"
    );
}

#[test]
fn cve_2016_1683_namespace_node_numbering_has_no_element_cast() {
    // Namespace nodes have no element payload. Both numbering traversals
    // must retain their XPath identity instead of interpreting raw node fields.
    let sheet = text_sheet(
        "<xsl:for-each select='r/namespace::p'><xsl:number level='multiple'/><xsl:text>|</xsl:text><xsl:number level='any'/></xsl:for-each>",
    );
    assert_eq!(run(&sheet, "<r xmlns:p='urn:p'/>"), b"1|1");
}

#[test]
fn cve_2019_18197_adjacent_text_copy_retains_all_bytes() {
    // Copy text from different source nodes repeatedly, exercising the native
    // text-coalescing lifetime boundary without relying on allocator reuse.
    let sheet = text_sheet(
        "<xsl:for-each select='r/*'><xsl:copy-of select='text()'/><xsl:value-of select='text()'/></xsl:for-each>",
    );
    assert_eq!(
        run(&sheet, "<r><a>alpha</a><b>beta</b><c>gamma</c></r>"),
        b"alphaalphabetabetagammagamma"
    );
}

#[test]
fn cve_2025_7424_stylesheet_as_source_does_not_share_scratch_metadata() {
    // The same document bytes can be used for stylesheet and source roles;
    // compiled instructions must not overwrite the source tree's node fields.
    let sheet = text_sheet("<xsl:value-of select='count(//xsl:template)'/>");
    assert_eq!(run(&sheet, &sheet), b"1");
}

#[test]
fn cve_2025_7425_key_queries_on_temporary_trees_keep_independent_indexes() {
    // Native atype corruption occurred when keys were built for temporary
    // trees. Repeated queries must leave the retained tree and index intact.
    let sheet = "<xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform' xmlns:exsl='http://exslt.org/common' version='1.0'><xsl:output method='text'/><xsl:key name='k' match='i' use='@id'/><xsl:template match='/'><xsl:variable name='tree'><i id='a'>ok</i></xsl:variable><xsl:for-each select='exsl:node-set($tree)'><xsl:value-of select='key(\"k\",\"a\")'/><xsl:value-of select='key(\"k\",\"a\")'/></xsl:for-each></xsl:template></xsl:stylesheet>";
    assert_eq!(run(sheet, "<r/>"), b"okok");
}

#[test]
fn cve_2025_27113_explicit_child_axis_matches_default_axis() {
    // The fixing pattern.c source corrects the opcode for explicit child::.
    // Equivalent patterns must select the same node, without a raw-node cast.
    let plain = text_sheet("<xsl:apply-templates select='r/a'/>").replace(
        "</xsl:stylesheet>",
        "<xsl:template match='r/a'>ok</xsl:template></xsl:stylesheet>",
    );
    let explicit = plain.replace("match='r/a'", "match='child::r/child::a'");
    assert_eq!(run(&plain, "<r><a/></r>"), b"ok");
    assert_eq!(run(&explicit, "<r><a/></r>"), b"ok");
}

#[test]
fn cve_2008_1767_long_patterns_are_admitted_before_compilation() {
    // A bounded analogue: do not allocate thousands of native match steps
    // before checking the supplied stylesheet-byte budget. A flat path's
    // length is not XML nesting depth, so use the input admission dimension.
    let pattern = "a/".repeat(300) + "a";
    let sheet = format!(
        "<xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform' version='1.0'><xsl:template match='{pattern}'/></xsl:stylesheet>"
    );
    let compiler = Compiler::new(
        Arc::new(NoResolver),
        CompileBudget::new(256, 8, 128, 8 << 20),
    );
    assert_eq!(
        compiler.compile(&sheet, None).unwrap_err().kind(),
        xml_sec_xslt::ErrorKind::Budget
    );
    compiler
        .compile(&sheet.replace(&pattern, "a/a"), None)
        .unwrap();
}

#[test]
fn upstream_document_read_cannot_bypass_caller_authority() {
    // Original upstream security input: refusal must precede acquisition and
    // must not be recovered as an empty document() result.
    struct Denied;
    impl xml_sec_xslt::Resolver for Denied {
        fn authorize(&self, access: xml_sec_xslt::ResourceAccess<'_>) -> xml_sec_xslt::Result<()> {
            Err(access.denied(xml_sec_xslt::AccessDenialReason::NotGranted))
        }
        fn resolve(
            &self,
            _: xml_sec_xslt::ResolveRequest<'_>,
        ) -> xml_sec_xslt::Result<xml_sec_xslt::ResolvedResource> {
            panic!("permission denial must precede acquisition")
        }
    }
    let sheet =
        include_str!("../../../tests/fixtures/security/libxslt/tests/security/load_document.xsl");
    let source = include_str!("../../../tests/fixtures/security/libxslt/tests/security/input.xml");
    let error = compile(sheet)
        .unwrap()
        .execute(
            &Document::parse(source, None).unwrap(),
            &Parameters::new(),
            Arc::new(Denied),
            options(),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        xml_sec_xslt::Error::ResourceAccessDenied { .. }
    ));
}

#[test]
fn upstream_secondary_output_is_returned_not_written() {
    // The original libxslt-only xsl:document instruction is a static error.
    // The supported XT equivalent returns bytes, never filesystem authority.
    let sheet =
        include_str!("../../../tests/fixtures/security/libxslt/tests/security/write_output.xsl");
    let source = include_str!("../../../tests/fixtures/security/libxslt/tests/security/input.xml");
    assert_eq!(
        compile(sheet).unwrap_err().kind(),
        xml_sec_xslt::ErrorKind::Static
    );
    let supported = sheet.replace("<xsl:stylesheet ", "<xsl:stylesheet xmlns:xt=\"http://www.jclark.com/xt\" extension-element-prefixes=\"xt\" ")
        .replace("xsl:document", "xt:document");
    let mut parameters = Parameters::new();
    parameters.insert(
        xml_sec_xslt::ExpandedName::new(None::<String>, "output"),
        xml_sec_xslt::Value::String("urn:xml-sec:secondary-output".into()),
    );
    let result = compile(&supported)
        .unwrap()
        .execute(
            &Document::parse(source, None).unwrap(),
            &parameters,
            Arc::new(NoResolver),
            options(),
        )
        .unwrap();
    assert_eq!(result.secondary_outputs.len(), 1);
    assert_eq!(
        result.secondary_outputs[0].serialized.bytes,
        b"<?xml version=\"1.0\"?>\n<result>written</result>\n"
    );
    assert_eq!(
        result.serialized.bytes,
        b"<?xml version=\"1.0\"?>\n<done/>\n"
    );
}
