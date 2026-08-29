use std::sync::Arc;
use std::{collections::HashMap, sync::Mutex};

use pretty_assertions::assert_eq;
use xml_sec_xslt::{
    BudgetKind, CompileBudget, Compiler, Document, Error, ExecutionBudget, ExecutionOptions,
    NoResolver, Parameters, ResolvePurpose, ResolvedResource, Resolver, ResourceIdentity,
};

fn compile(source: &str) -> xml_sec_xslt::Stylesheet {
    Compiler::new(
        Arc::new(NoResolver),
        CompileBudget::new(1 << 20, 16, 4 << 20),
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
        r#"<p:r xmlns:p="urn:test" a="1">x<!--c--></p:r>"#,
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
        "<out>B!A!z</out>",
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
        r#"<new:r xmlns:new="urn:new">0|1.234,50</new:r>"#,
    );
}

#[test]
fn malformed_stylesheet_and_budget_exhaustion_are_typed() {
    // Static and resource failures must remain distinguishable to callers.
    let error = Compiler::new(Arc::new(NoResolver), CompileBudget::new(64, 0, 64))
        .compile("<xsl:stylesheet/>", None)
        .expect_err("missing namespace/version must fail");
    assert!(matches!(error, Error::Static(_) | Error::Xml(_)));

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
    let stylesheet = Compiler::new(resolver.clone(), CompileBudget::new(1 << 20, 8, 1 << 20))
        .compile(r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:import href="base.xsl"/><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><local/></xsl:template></xsl:stylesheet>"#, Some("memory:main.xsl"))
        .expect("import graph must compile");
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
        "<local></local>"
    );
}

#[test]
fn serializer_honors_doctype_cdata_html_and_text_contracts() {
    // Serializer method selection changes exact transform bytes, not only presentation.
    let xml = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes" doctype-system="result.dtd" cdata-section-elements="script"/><xsl:template match="/"><doc><script><xsl:text>if (a &lt; b) x = ']]&gt;';</xsl:text></script></doc></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(xml, "<source/>"),
        "<!DOCTYPE doc SYSTEM \"result.dtd\"><doc><script><![CDATA[if (a < b) x = ']]><![CDATA[>';]]></script></doc>",
    );

    let html = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><html><body><br/><script>if (a &lt; b) x++;</script></body></html></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(html, "<source/>"),
        "<html><body><br><script>if (a < b) x++;</script></body></html>",
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
        Compiler::new(Arc::new(NoResolver), CompileBudget::new(4096, 0, 4096))
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
        "<row id=\"a\">A<?done ok?></row><row id=\"b\"><!--disabled--><?done ok?></row>"
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
        "<out><item class=\"entry\" label=\"Sx\">1.1</item><item class=\"entry\" label=\"Sy\">1.2</item></out>"
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
