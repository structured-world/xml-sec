use std::sync::Arc;
use std::{collections::HashMap, sync::Mutex};

use pretty_assertions::assert_eq;
use xml_sec_xslt::{
    BudgetKind, CompileBudget, Compiler, Document, Error, ExecutionBudget, ExecutionOptions,
    NoResolver, NodeReference, Parameters, ResolvePurpose, ResolvedResource, Resolver,
    ResourceIdentity, Value,
};

fn compile(source: &str) -> xml_sec_xslt::Stylesheet {
    Compiler::new(
        Arc::new(NoResolver),
        CompileBudget::new(1 << 20, 16, 256, 4 << 20),
    )
    .compile(source, Some("memory:main.xsl"))
    .expect("test stylesheet must compile")
}

fn execution_budget(source_bytes: usize) -> ExecutionBudget {
    ExecutionBudget {
        source_bytes,
        external_documents: 8,
        recursion_depth: 256,
        xpath_evaluations: 100_000,
        template_applications: 100_000,
        sort_comparisons: 100_000,
        key_entries: 100_000,
        result_nodes: 100_000,
        serialized_bytes: 1 << 20,
        messages: 100,
        owned_bytes: 8 << 20,
    }
}

fn execute(stylesheet: &str, source: &str) -> String {
    let result = compile(stylesheet)
        .execute(
            &Document::parse(source, Some("memory:source.xml")).expect("source must parse"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1 << 20),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("transformation must succeed");
    String::from_utf8(result.serialized.bytes).expect("test output is UTF-8")
}

#[test]
fn identity_transform_preserves_elements_attributes_and_namespaces() {
    // This is the transform shape embedded in the XMLDSig interoperability corpus.
    let stylesheet = r#"
      <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
        <xsl:output omit-xml-declaration="yes"/>
        <xsl:template match="@*|node()">
          <xsl:copy><xsl:apply-templates select="@*|node()"/></xsl:copy>
        </xsl:template>
      </xsl:stylesheet>"#;
    assert_eq!(
        execute(
            stylesheet,
            r#"<p:r xmlns:p="urn:test" a="1">x<!--c--></p:r>"#
        ),
        "<p:r xmlns:p=\"urn:test\" a=\"1\">x<!--c--></p:r>\n",
    );
}

#[test]
fn templates_modes_parameters_sort_keys_and_numbering_compose() {
    // Exercises cross-feature dynamic context: mode, params, key(), sort and numbering.
    let stylesheet = r#"
      <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
        <xsl:output omit-xml-declaration="yes"/>
        <xsl:key name="by-id" match="item" use="@id"/>
        <xsl:template match="/"><out><xsl:apply-templates select="root/item" mode="m"><xsl:sort select="@name" case-order="upper-first"/><xsl:with-param name="suffix" select="'!'"/></xsl:apply-templates><xsl:value-of select="key('by-id', 'b')/@name"/></out></xsl:template>
        <xsl:template match="item" mode="m"><xsl:param name="suffix"/><xsl:number level="single" format="A"/><xsl:value-of select="$suffix"/></xsl:template>
      </xsl:stylesheet>"#;
    assert_eq!(
        execute(
            stylesheet,
            r#"<root><item id="b" name="z"/><item id="a" name="A"/></root>"#
        ),
        "<out>B!A!z</out>\n",
    );
}

#[test]
fn whitespace_aliases_and_decimal_formats_affect_results() {
    // Top-level declarations must be execution semantics rather than compiler metadata.
    let stylesheet = r#"
      <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:old="urn:old" xmlns:new="urn:new">
        <xsl:output omit-xml-declaration="yes"/>
        <xsl:strip-space elements="*"/>
        <xsl:namespace-alias stylesheet-prefix="old" result-prefix="new"/>
        <xsl:decimal-format name="d" decimal-separator="," grouping-separator="."/>
        <xsl:template match="/"><old:r><xsl:value-of select="count(root/text())"/><xsl:text>|</xsl:text><xsl:value-of select="format-number(1234.5, '#.##0,00', 'd')"/></old:r></xsl:template>
      </xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<root>  <item/>\n</root>"),
        "<old:r xmlns:old=\"urn:new\" xmlns:new=\"urn:new\">0|1.234,50</old:r>\n",
    );
}

#[test]
fn malformed_stylesheet_and_budget_exhaustion_are_typed() {
    // Static and resource failures must remain distinguishable to callers.
    let error = Compiler::new(Arc::new(NoResolver), CompileBudget::new(4096, 0, 64, 4096))
        .compile("<stylesheet/>", None)
        .expect_err("literal result stylesheet without xsl:version must fail");
    assert!(matches!(error, Error::Static(_)));

    let error = Compiler::new(Arc::new(NoResolver), CompileBudget::new(8, 0, 64, 64))
        .compile("<xsl:stylesheet/>", None)
        .expect_err("stylesheet bytes must be bounded before parsing");
    assert!(matches!(
        error,
        Error::Budget {
            kind: BudgetKind::StylesheetBytes,
            ..
        }
    ));

    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><out/></xsl:template></xsl:stylesheet>"#,
    );
    let error = stylesheet
        .execute(
            &Document::parse("<root/>", None).expect("source must parse"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: ExecutionBudget {
                    source_bytes: 1,
                    external_documents: 0,
                    recursion_depth: 1,
                    xpath_evaluations: 1,
                    template_applications: 1,
                    sort_comparisons: 1,
                    key_entries: 1,
                    result_nodes: 1,
                    serialized_bytes: 1,
                    messages: 0,
                    owned_bytes: 1,
                },
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect_err("source budget must fail before execution");
    assert!(matches!(
        error,
        Error::Budget {
            kind: BudgetKind::SourceBytes,
            ..
        }
    ));
}

#[derive(Default)]
struct MemoryResolver {
    resources: Mutex<HashMap<String, String>>,
}

impl Resolver for MemoryResolver {
    fn resolve(
        &self,
        uri: &str,
        _base_uri: Option<&str>,
        _purpose: ResolvePurpose,
    ) -> xml_sec_xslt::Result<ResolvedResource> {
        let bytes = self
            .resources
            .lock()
            .expect("test resolver mutex is not poisoned")
            .get(uri)
            .cloned()
            .ok_or_else(|| Error::Resolver {
                uri: uri.into(),
                message: "missing test resource".into(),
            })?;
        Ok(ResolvedResource {
            canonical_uri: format!("memory:{uri}"),
            identity: ResourceIdentity(uri.into()),
            bytes: bytes.into_bytes(),
            media_type: Some("application/xslt+xml".into()),
            encoding: Some("UTF-8".into()),
        })
    }
}

#[test]
fn import_precedence_overrides_but_include_keeps_equal_precedence() {
    // Imports are weaker than the importing module; includes are textual and therefore equal.
    let resolver = Arc::new(MemoryResolver::default());
    resolver.resources.lock().expect("test resolver mutex is not poisoned").insert(
        "base.xsl".into(),
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><base/></xsl:template></xsl:stylesheet>"#.into(),
    );
    let stylesheet = Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
        .compile(r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:import href="base.xsl"/><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><local/></xsl:template></xsl:stylesheet>"#, Some("memory:main.xsl"))
        .expect("import graph must compile");
    let included = Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:include href="base.xsl"/><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><included-after/></xsl:template></xsl:stylesheet>"#,
        Some("memory:main.xsl"),
    )
    .expect("include graph must compile");
    let included_output = included
        .execute(
            &Document::parse("<root/>", None).expect("source must parse"),
            &Parameters::new(),
            resolver.clone(),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("included transform must execute");
    assert_eq!(
        String::from_utf8(included_output.serialized.bytes).expect("UTF-8 output"),
        "<included-after/>\n"
    );
    let output = stylesheet
        .execute(
            &Document::parse("<root/>", None).expect("source must parse"),
            &Parameters::new(),
            resolver,
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("transform must execute");
    assert_eq!(
        String::from_utf8(output.serialized.bytes).expect("UTF-8 output"),
        "<local/>\n"
    );
}

#[test]
fn serializer_honors_doctype_cdata_html_and_text_contracts() {
    // Serializer method selection changes exact transform bytes, not only presentation.
    let xml = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes" doctype-system="result.dtd" cdata-section-elements="script"/><xsl:template match="/"><doc><script><xsl:text>if (a &lt; b) x = ']]&gt;';</xsl:text></script></doc></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(xml, "<source/>"),
        "<!DOCTYPE doc SYSTEM \"result.dtd\"><doc><script><![CDATA[if (a < b) x = ']]><![CDATA[>';]]></script></doc>\n",
    );

    let html = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><html><body><br/><script>if (a &lt; b) x++;</script></body></html></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(html, "<source/>"),
        "<html>\n  <body>\n    <br>\n    <script>if (a < b) x++;</script>\n  </body>\n</html>\n",
    );

    let text = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><ignored>A<xsl:value-of select="'&lt;B'"/></ignored></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(text, "<source/>"), "A<B");
}

#[test]
fn xslt_introspection_functions_report_engine_capabilities() {
    // XSLT-defined functions must override the underlying XPath library's surface.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="system-property('xsl:version')"/><xsl:text>|</xsl:text><xsl:value-of select="element-available('xsl:for-each')"/><xsl:text>|</xsl:text><xsl:value-of select="function-available('key')"/><xsl:text>|</xsl:text><xsl:value-of select="generate-id(/*) = generate-id(/*)"/><xsl:text>|</xsl:text><xsl:value-of select="generate-id(/*) != generate-id(/*/@*)"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<source id=\"x\"/>"),
        "1|true|true|true|true",
    );
}

#[test]
fn invalid_instruction_order_and_late_attributes_fail_closed() {
    // Invalid sequence constructors must not be silently normalized by the engine.
    let invalid = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="1"/><xsl:param name="late"/></xsl:template></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(Arc::new(NoResolver), CompileBudget::new(4096, 0, 256, 4096),)
            .compile(invalid, None),
        Err(Error::Static(_))
    ));

    let late_attribute = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><out><xsl:text>child</xsl:text><xsl:attribute name="late">value</xsl:attribute></out></xsl:template></xsl:stylesheet>"#;
    let stylesheet = compile(late_attribute);
    let result = stylesheet.execute(
        &Document::parse("<source/>", None).expect("source must parse"),
        &Parameters::new(),
        Arc::new(NoResolver),
        ExecutionOptions {
            budget: execution_budget(4096),
            initial_mode: None,
            initial_template: None,
        },
    );
    assert!(matches!(result, Err(Error::Dynamic(_))));
}

#[test]
fn control_flow_computed_nodes_and_messages_share_the_current_context() {
    // Named templates retain the caller context while all result constructors compose.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><xsl:for-each select="root/item"><xsl:call-template name="emit"/></xsl:for-each></xsl:template><xsl:template name="emit"><xsl:message>seen:<xsl:value-of select="@id"/></xsl:message><xsl:element name="row"><xsl:attribute name="id"><xsl:value-of select="@id"/></xsl:attribute><xsl:choose><xsl:when test="@enabled='yes'"><xsl:copy-of select="node()"/></xsl:when><xsl:otherwise><xsl:comment>disabled</xsl:comment></xsl:otherwise></xsl:choose><xsl:processing-instruction name="done">ok</xsl:processing-instruction></xsl:element></xsl:template></xsl:stylesheet>"#;
    let result = compile(stylesheet)
        .execute(
            &Document::parse(
                "<root><item id=\"a\" enabled=\"yes\">A</item><item id=\"b\"/></root>",
                None,
            )
            .expect("source must parse"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(4096),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("transform must execute");
    assert_eq!(
        String::from_utf8(result.serialized.bytes).expect("UTF-8 output"),
        "<row id=\"a\">A<?done ok?></row><row id=\"b\"><!--disabled--><?done ok?></row>\n"
    );
    assert_eq!(
        result
            .messages
            .iter()
            .map(|message| message.content.as_str())
            .collect::<Vec<_>>(),
        ["seen:a", "seen:b"]
    );
}

#[test]
fn attribute_sets_variables_and_multiple_numbering_compose() {
    // Attribute-set expansion and multi-level numbering must use one variable scope.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes"/><xsl:attribute-set name="base"><xsl:attribute name="class">entry</xsl:attribute></xsl:attribute-set><xsl:template match="/"><out><xsl:apply-templates select="book/chapter/section"/></out></xsl:template><xsl:template match="section"><xsl:variable name="label">S<xsl:value-of select="@id"/></xsl:variable><xsl:element name="item" use-attribute-sets="base"><xsl:attribute name="label"><xsl:value-of select="$label"/></xsl:attribute><xsl:number level="multiple" count="chapter|section" format="1"/></xsl:element></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(
            stylesheet,
            "<book><chapter><section id=\"x\"/><section id=\"y\"/></chapter></book>"
        ),
        "<out><item class=\"entry\" label=\"Sx\">1.1</item><item class=\"entry\" label=\"Sy\">1.2</item></out>\n"
    );
}

#[test]
fn terminating_messages_and_attribute_set_cycles_are_typed_failures() {
    // Execution and static graph errors retain distinct deterministic categories.
    let terminating = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:message terminate="yes">stop</xsl:message></xsl:template></xsl:stylesheet>"#;
    let result = compile(terminating).execute(
        &Document::parse("<source/>", None).expect("source must parse"),
        &Parameters::new(),
        Arc::new(NoResolver),
        ExecutionOptions {
            budget: execution_budget(1024),
            initial_mode: None,
            initial_template: None,
        },
    );
    assert!(matches!(result, Err(Error::Dynamic(_))));

    let cycle = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:attribute-set name="a" use-attribute-sets="b"/><xsl:attribute-set name="b" use-attribute-sets="a"/><xsl:template match="/"><out xsl:use-attribute-sets="a"/></xsl:template></xsl:stylesheet>"#;
    let result = compile(cycle).execute(
        &Document::parse("<source/>", None).expect("source must parse"),
        &Parameters::new(),
        Arc::new(NoResolver),
        ExecutionOptions {
            budget: execution_budget(1024),
            initial_mode: None,
            initial_template: None,
        },
    );
    assert!(matches!(result, Err(Error::Static(_))));
}

#[test]
fn result_tree_fragments_preserve_nodes_and_global_dependencies_are_order_independent() {
    // RTF content is a temporary tree, and global bindings form a dependency graph.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes"/><xsl:variable name="later" select="$base"/><xsl:variable name="base" select="'ok'"/><xsl:template match="/"><xsl:variable name="fragment"><b><xsl:value-of select="$later"/></b><xsl:comment>kept</xsl:comment><xsl:processing-instruction name="done">yes</xsl:processing-instruction></xsl:variable><out><xsl:copy-of select="$fragment"/></out></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<source/>"),
        "<out><b>ok</b><!--kept--><?done yes?></out>\n"
    );

    let cycle = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:variable name="a" select="$b"/><xsl:variable name="b" select="$a"/><xsl:template match="/"/></xsl:stylesheet>"#;
    let result = compile(cycle).execute(
        &Document::parse("<source/>", None).expect("source must parse"),
        &Parameters::new(),
        Arc::new(NoResolver),
        ExecutionOptions {
            budget: execution_budget(1024),
            initial_mode: None,
            initial_template: None,
        },
    );
    assert!(matches!(result, Err(Error::Dynamic(_))));
}

#[test]
fn static_xpath_and_template_conflicts_are_resolved_during_compilation() {
    // Invalid expressions are static errors and union branches retain their own priority.
    let malformed = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="["/></xsl:template></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(Arc::new(NoResolver), CompileBudget::new(4096, 0, 256, 4096),)
            .compile(malformed, None),
        Err(Error::Static(_))
    ));

    let union = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><xsl:apply-templates select="bar"/></xsl:template><xsl:template match="foo|*"><wild/></xsl:template><xsl:template match="bar"><specific/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(union, "<bar/>"), "<specific/>\n");
}

#[test]
fn stylesheet_static_context_is_module_and_instruction_local() {
    // Comments do not end the parameter prologue, and computed names use stylesheet bindings.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:p="urn:p"><xsl:output omit-xml-declaration="yes" exclude-result-prefixes="p"/><xsl:template match="/"><!--documented--><xsl:param name="v" select="'ok'"/><xsl:element name="p:out"><xsl:attribute name="p:value"><xsl:value-of select="$v"/></xsl:attribute></xsl:element></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<source/>"),
        "<p:out xmlns:p=\"urn:p\" p:value=\"ok\"/>\n"
    );
}

#[test]
fn whitespace_rules_honor_namespaces_specificity_and_inherited_xml_space() {
    // Import precedence and NameTest priority apply before declaration order; xml:space inherits.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:n="urn:n"><xsl:output method="text"/><xsl:strip-space elements="*"/><xsl:preserve-space elements="n:keep"/><xsl:template match="/"><xsl:value-of select="count(n:root/text())"/><xsl:text>|</xsl:text><xsl:value-of select="count(n:root/n:keep/text())"/><xsl:text>|</xsl:text><xsl:value-of select="count(n:root/n:drop/n:child/text())"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(
            stylesheet,
            r#"<n:root xmlns:n="urn:n">  <n:keep>  </n:keep><n:drop xml:space="preserve"><n:child>  </n:child></n:drop></n:root>"#,
        ),
        "0|1|1"
    );
}

#[test]
fn xpath_context_keeps_predicate_positions_and_all_node_kinds() {
    // XSLT outer context and XPath predicate context must not overwrite one another.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:for-each select="root/item"><xsl:value-of select="position()"/><xsl:text>:</xsl:text><xsl:value-of select="count(child[position() &lt; 2])"/><xsl:text>|</xsl:text></xsl:for-each><xsl:for-each select="root/@*"><xsl:variable name="a" select="."/><xsl:value-of select="name(current())"/><xsl:text>=</xsl:text><xsl:value-of select="$a"/></xsl:for-each></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(
            stylesheet,
            r#"<root id="r"><item><child/><child/></item><item><child/></item></root>"#,
        ),
        "1:1|2:1|id=r"
    );
}

#[test]
fn sorting_uses_avts_case_order_and_xpath_number_grammar() {
    // Sort metadata is dynamic, case order is directional, and exponent text is NaN.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:param name="direction" select="'descending'"/><xsl:template match="/"><xsl:for-each select="root/case"><xsl:sort select="." case-order="upper-first"/><xsl:value-of select="."/></xsl:for-each><xsl:text>|</xsl:text><xsl:for-each select="root/number"><xsl:sort select="@v" data-type="number" order="{$direction}"/><xsl:value-of select="@id"/></xsl:for-each></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(
            stylesheet,
            r#"<root><case>a</case><case>A</case><number id="bad" v="1e2"/><number id="good" v="2"/></root>"#,
        ),
        "Aa|goodbad"
    );
}

#[test]
fn numbering_parses_tokens_widths_and_unicode_decimal_patterns() {
    // Number formatting must preserve token separators, widths, and UTF-8 boundaries.
    let stylesheet = r##"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:decimal-format name="arabic" zero-digit="٠" digit="#"/><xsl:template match="/"><xsl:number value="1" format="001"/><xsl:text>|</xsl:text><xsl:number value="2" format="1."/><xsl:text>|</xsl:text><xsl:apply-templates select="book/chapter/section"/></xsl:template><xsl:template match="section"><xsl:number level="multiple" count="chapter|section" format="A.1"/><xsl:text>|</xsl:text><xsl:value-of select="format-number(12, '٠٠', 'arabic')"/></xsl:template></xsl:stylesheet>"##;
    assert_eq!(
        execute(stylesheet, "<book><chapter><section/></chapter></book>"),
        "001|2.|A.1|١٢"
    );
}

#[test]
fn serializer_preserves_mixed_content_and_method_detection() {
    // Pretty printing cannot change text, and leading non-elements do not hide the root element.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output indent="yes" omit-xml-declaration="yes"/><xsl:template match="/"><xsl:comment>lead</xsl:comment><html><body><p>Hello<b>world</b>!</p><br/></body></html></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<source/>"),
        "<!--lead--><html>\n  <body>\n    <p>Hello<b>world</b>!</p>\n    <br>\n  </body>\n</html>\n"
    );

    let public_only = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes" doctype-public="public-id"/><xsl:template match="/"><root/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(public_only, "<source/>"), "<root/>\n");
}

#[test]
fn serializer_encodes_xml_fallbacks_and_utf16_consistently() {
    // Declared encodings must match bytes and preserve representable XML via character references.
    let latin = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output encoding="ISO-8859-1"/><xsl:template match="/"><root>€</root></xsl:template></xsl:stylesheet>"#;
    let latin = compile(latin)
        .execute(
            &Document::parse("<source/>", None).expect("source must parse"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("numeric fallback must serialize");
    assert!(String::from_utf8_lossy(&latin.serialized.bytes).contains("&#8364;"));

    let utf16 = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output encoding="UTF-16"/><xsl:template match="/"><root>ok</root></xsl:template></xsl:stylesheet>"#;
    let utf16 = compile(utf16)
        .execute(
            &Document::parse("<source/>", None).expect("source must parse"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("UTF-16 must serialize");
    assert!(utf16.serialized.bytes.starts_with(&[0xFF, 0xFE]));
    let decoded = String::from_utf16(
        &utf16.serialized.bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>(),
    )
    .expect("UTF-16 output must decode");
    assert!(decoded.contains("encoding=\"UTF-16\""));
}

#[test]
fn xslt_capability_and_include_contracts_match_execution() {
    // Advertised functions and textual include precedence are executable contracts.
    let available = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="function-available('current')"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(available, "<source/>"), "true");

    let resolver = Arc::new(MemoryResolver::default());
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert(
            "included.xsl".into(),
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><included/></xsl:template></xsl:stylesheet>"#.into(),
        );
    let stylesheet = Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
        .compile(r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:include href="included.xsl"/><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><local/></xsl:template></xsl:stylesheet>"#, Some("memory:main.xsl"))
        .expect("include graph must compile");
    let output = stylesheet
        .execute(
            &Document::parse("<root/>", None).expect("source must parse"),
            &Parameters::new(),
            resolver,
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("included transform must execute");
    assert_eq!(
        String::from_utf8(output.serialized.bytes).expect("UTF-8 output"),
        "<local/>\n"
    );
}

#[derive(Default)]
struct ContextResolver {
    calls: Mutex<Vec<(String, Option<String>, ResolvePurpose)>>,
    resources: Mutex<HashMap<(String, Option<String>), ResolvedResource>>,
}

impl Resolver for ContextResolver {
    fn resolve(
        &self,
        uri: &str,
        base_uri: Option<&str>,
        purpose: ResolvePurpose,
    ) -> xml_sec_xslt::Result<ResolvedResource> {
        let key = (uri.to_owned(), base_uri.map(str::to_owned));
        self.calls
            .lock()
            .expect("test resolver mutex is not poisoned")
            .push((key.0.clone(), key.1.clone(), purpose));
        self.resources
            .lock()
            .expect("test resolver mutex is not poisoned")
            .get(&key)
            .cloned()
            .ok_or_else(|| Error::Resolver {
                uri: uri.into(),
                message: format!("missing test resource at base {base_uri:?}"),
            })
    }
}

#[test]
fn module_resolution_honors_xml_base_and_resource_identity() {
    // Nested xml:base participates in resolver requests, and one identity cannot change bytes.
    let resolver = Arc::new(ContextResolver::default());
    let include = r#"<xsl:stylesheet version="1.0" xml:base="../shared/" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:include href="leaf.xsl"/></xsl:stylesheet>"#;
    let leaf = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><leaf/></xsl:template></xsl:stylesheet>"#;
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert(
            (
                "included.xsl".into(),
                Some("https://example.test/root/styles/".into()),
            ),
            ResolvedResource {
                canonical_uri: "https://example.test/root/styles/included.xsl".into(),
                identity: ResourceIdentity("included".into()),
                bytes: include.as_bytes().to_vec(),
                media_type: None,
                encoding: Some("UTF-8".into()),
            },
        );
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert(
            (
                "leaf.xsl".into(),
                Some("https://example.test/root/shared/".into()),
            ),
            ResolvedResource {
                canonical_uri: "https://example.test/root/shared/leaf.xsl".into(),
                identity: ResourceIdentity("leaf".into()),
                bytes: leaf.as_bytes().to_vec(),
                media_type: None,
                encoding: Some("UTF-8".into()),
            },
        );
    Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 8, 32, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xml:base="styles/" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:include href="included.xsl"/></xsl:stylesheet>"#,
        Some("https://example.test/root/main.xsl"),
    )
    .expect("xml:base-aware include graph must compile");
    let calls = resolver
        .calls
        .lock()
        .expect("test resolver mutex is not poisoned");
    assert_eq!(
        calls[0].1.as_deref(),
        Some("https://example.test/root/styles/")
    );
    assert_eq!(
        calls[1].1.as_deref(),
        Some("https://example.test/root/shared/")
    );

    let stale = Arc::new(ContextResolver::default());
    let main_base = Some("https://example.test/main.xsl".into());
    let empty =
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"/>"#;
    for (href, body) in [("a.xsl", empty), ("b.xsl", leaf)] {
        stale
            .resources
            .lock()
            .expect("test resolver mutex is not poisoned")
            .insert(
                (href.into(), main_base.clone()),
                ResolvedResource {
                    canonical_uri: format!("https://example.test/{href}"),
                    identity: ResourceIdentity("same-resource".into()),
                    bytes: body.as_bytes().to_vec(),
                    media_type: None,
                    encoding: Some("UTF-8".into()),
                },
            );
    }
    let error = Compiler::new(stale, CompileBudget::new(1 << 20, 8, 32, 1 << 20))
        .compile(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:include href="a.xsl"/><xsl:include href="b.xsl"/></xsl:stylesheet>"#,
            Some("https://example.test/main.xsl"),
        )
        .expect_err("one resource identity cannot resolve to different bytes");
    assert!(matches!(error, Error::StaleResource { .. }), "{error:?}");
}

#[test]
fn recursion_and_output_budgets_gate_work_before_growth() {
    // Compile recursion, source copying, and rendered output each enforce their own ceiling.
    let nested = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:if test="true()"><xsl:if test="true()"><xsl:if test="true()"><out/></xsl:if></xsl:if></xsl:if></xsl:template></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(Arc::new(NoResolver), CompileBudget::new(4096, 0, 3, 4096))
            .compile(nested, None),
        Err(Error::Budget {
            kind: BudgetKind::RecursionDepth,
            ..
        })
    ));

    let identity = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:copy-of select="."/></xsl:template></xsl:stylesheet>"#,
    );
    let source = Document::parse("<a><b><c><d/></c></b></a>", None).expect("source must parse");
    let mut budget = execution_budget(1024);
    budget.recursion_depth = 3;
    assert!(matches!(
        identity.execute(
            &source,
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
        ),
        Err(Error::Budget {
            kind: BudgetKind::RecursionDepth,
            ..
        })
    ));

    let large = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><out>0123456789</out></xsl:template></xsl:stylesheet>"#,
    );
    let mut budget = execution_budget(1024);
    budget.serialized_bytes = 8;
    assert!(matches!(
        large.execute(
            &Document::parse("<source/>", None).expect("source must parse"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
        ),
        Err(Error::Budget {
            kind: BudgetKind::SerializedBytes,
            ..
        })
    ));
}

#[test]
fn semantic_projection_preserves_cdata_and_public_node_kinds() {
    // Normalization removes parser-node alignment assumptions without losing XPath node kinds.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="root/text()"/><xsl:text>|</xsl:text><xsl:value-of select="root/@id"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<root id=\"r\"><![CDATA[value]]></root>"),
        "value|r"
    );

    let document = Document::parse("<root id=\"r\"/>", None).expect("source must parse");
    let attribute = Value::NodeSet(vec![NodeReference::Attribute {
        owner: xml_sec_xslt::NodeId(1),
        index: 0,
    }]);
    assert_eq!(attribute.into_string(&document), "r");
}

#[test]
fn namespaces_fallbacks_and_xml_characters_fail_or_emit_by_contract() {
    // Namespace exclusions affect only unused bindings, and malformed fallback remains static.
    let excluded = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:unused="urn:unused" xmlns:used="urn:used" exclude-result-prefixes="unused used"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><used:out/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(excluded, "<source/>"),
        "<used:out xmlns:used=\"urn:used\"/>\n"
    );

    let fallback = r#"<xsl:stylesheet version="2.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:future><xsl:fallback><xsl:value-of select="["/></xsl:fallback></xsl:future></xsl:template></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(Arc::new(NoResolver), CompileBudget::new(4096, 0, 32, 4096))
            .compile(fallback, None),
        Err(Error::Static(_))
    ));

    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:param name="value"/><xsl:template match="/"><xsl:value-of select="$value"/></xsl:template></xsl:stylesheet>"#,
    );
    let mut parameters = Parameters::new();
    parameters.insert(
        xml_sec_xslt::ExpandedName::new(None::<String>, "value"),
        Value::String("\u{1}".into()),
    );
    assert!(matches!(
        stylesheet.execute(
            &Document::parse("<source/>", None).expect("source must parse"),
            &parameters,
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        ),
        Err(Error::Serialization(_))
    ));
}
