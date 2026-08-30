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
fn ancestor_attribute_nodesets_do_not_leak_from_siblings() {
    // A node-set variable must contain attributes from the context ancestry only;
    // a prior changed sibling must not activate inherited diff markup.
    let stylesheet = r#"
      <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
        <xsl:output omit-xml-declaration="yes"/>
        <xsl:template match="/"><out><xsl:apply-templates select="root/item/label"/></out></xsl:template>
        <xsl:template match="item/label">
          <xsl:variable name="diffval" select="ancestor-or-self::*/@diff"/>
          <label count="{count($diffval)}" value="{$diffval}">
            <xsl:if test="$diffval != ''"><marked/></xsl:if>
            <xsl:value-of select="."/>
          </label>
        </xsl:template>
      </xsl:stylesheet>"#;
    assert_eq!(
        execute(
            stylesheet,
            r#"<root><item diff="add"><label>changed</label></item><item><label>may</label></item></root>"#,
        ),
        "<out><label count=\"1\" value=\"add\"><marked/>changed</label><label count=\"0\" value=\"\">may</label></out>\n",
    );
}

#[test]
fn arithmetic_on_a_variable_nodeset_path_uses_xpath_semantics() {
    // A variable-rooted location path is not a variable name; the generic XPath
    // evaluator must select the attribute before numeric coercion.
    let stylesheet = r#"
      <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
        <xsl:output omit-xml-declaration="yes"/>
        <xsl:template match="/">
          <xsl:variable name="colspec" select="table/colspec"/>
          <out><xsl:value-of select="$colspec/@colnum + 1"/></out>
        </xsl:template>
      </xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, r#"<table><colspec colnum="2"/></table>"#),
        "<out>3</out>\n",
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

#[test]
fn namespace_name_validation_matches_xslt_1_0_compatibility() {
    // Legacy XSLT 1.0 stylesheets may use relative namespace names, while a
    // fragment-only name cannot identify an expanded XSLT QName.
    compile(
        r#"<xsl:stylesheet version="1.0"
             xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
             xmlns:local="data_local_to_this_file">
             <xsl:template match="/"><local:result/></xsl:template>
           </xsl:stylesheet>"#,
    );

    let error = Compiler::new(
        Arc::new(NoResolver),
        CompileBudget::new(1 << 20, 16, 256, 4 << 20),
    )
    .compile(
        r##"<xsl:stylesheet version="1.0"
             xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
             xmlns:local="#fragment">
             <xsl:variable name="local:value" select="1"/>
           </xsl:stylesheet>"##,
        Some("memory:fragment-namespace.xsl"),
    )
    .expect_err("fragment-only namespace names must be rejected");
    assert!(matches!(error, Error::Static(_)));
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
fn document_function_resolves_dynamic_uris_without_cross_document_leaks() {
    // External trees share stable semantic node identities, but ordinary absolute
    // paths remain confined to the logical document of the current context node.
    let resolver = Arc::new(MemoryResolver::default());
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert(
            "external.xml".into(),
            "<catalog><item>external</item></catalog>".into(),
        );
    let stylesheet = Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="count(//item)"/><xsl:text>|</xsl:text><xsl:value-of select="count(document(/*/@href))"/><xsl:text>|</xsl:text><xsl:value-of select="count(document(/*/@href)/catalog)"/><xsl:text>|</xsl:text><xsl:value-of select="document(/*/@href)/catalog/item"/></xsl:template></xsl:stylesheet>"#,
        Some("memory:main.xsl"),
    )
    .expect("stylesheet compiles");
    let output = stylesheet
        .execute(
            &Document::parse(
                "<source href=\"external.xml\"><item>primary</item></source>",
                Some("memory:source.xml"),
            )
            .expect("source parses"),
            &Parameters::new(),
            resolver,
            ExecutionOptions {
                budget: execution_budget(1 << 20),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("external document resolves");
    assert_eq!(output.serialized.bytes, b"1|1|1|external");
}

#[test]
fn document_function_uses_node_module_and_explicit_base_uris() {
    // XSLT 1.0 assigns node-set URI references their originating node base,
    // scalar references their stylesheet module base, and the optional second
    // argument overrides either without collapsing equal hrefs in the cache.
    let resolver = Arc::new(ContextResolver::default());
    let mut resources = resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned");
    let imported = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template name="imported"><xsl:value-of select="document('module.xml')/doc"/></xsl:template></xsl:stylesheet>"#;
    for (href, base, canonical, identity, body) in [
        (
            "imported.xsl",
            "https://example.test/styles/main.xsl",
            "https://example.test/modules/imported.xsl",
            "imported",
            imported,
        ),
        (
            "module.xml",
            "https://example.test/modules/imported.xsl",
            "https://example.test/modules/module.xml",
            "module-doc",
            "<doc>module</doc>",
        ),
        (
            "same.xml",
            "https://example.test/source/a/",
            "https://example.test/source/a/same.xml",
            "same-a",
            "<doc>A</doc>",
        ),
        (
            "same.xml",
            "https://example.test/source/b/",
            "https://example.test/source/b/same.xml",
            "same-b",
            "<doc>B</doc>",
        ),
        (
            "override.xml",
            "https://example.test/source/b/",
            "https://example.test/source/b/override.xml",
            "override-b",
            "<doc>override</doc>",
        ),
    ] {
        resources.insert(
            (href.into(), Some(base.into())),
            ResolvedResource {
                canonical_uri: canonical.into(),
                identity: ResourceIdentity(identity.into()),
                bytes: body.as_bytes().to_vec(),
                media_type: None,
                encoding: Some("UTF-8".into()),
            },
        );
    }
    drop(resources);

    let stylesheet = Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:import href="imported.xsl"/><xsl:output method="text"/><xsl:template match="/"><xsl:for-each select="root/item"><xsl:value-of select="document(@href)/doc"/></xsl:for-each><xsl:text>|</xsl:text><xsl:value-of select="document('override.xml', root/item[2])/doc"/><xsl:text>|</xsl:text><xsl:call-template name="imported"/></xsl:template></xsl:stylesheet>"#,
        Some("https://example.test/styles/main.xsl"),
    )
    .expect("stylesheet graph compiles");
    let source = Document::parse(
        r#"<root xml:base="https://example.test/source/"><item xml:base="a/" href="same.xml"/><item xml:base="b/" href="same.xml"/></root>"#,
        Some("https://example.test/source/input.xml"),
    )
    .expect("source parses");
    let result = stylesheet
        .execute(
            &source,
            &Parameters::new(),
            resolver.clone(),
            ExecutionOptions {
                budget: execution_budget(1 << 20),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("all document bases resolve");
    assert_eq!(result.serialized.bytes, b"AB|override|module");

    let calls = resolver
        .calls
        .lock()
        .expect("test resolver mutex is not poisoned");
    assert!(calls.iter().any(|(href, base, purpose)| {
        href == "same.xml"
            && base.as_deref() == Some("https://example.test/source/a/")
            && *purpose == ResolvePurpose::Document
    }));
    assert!(calls.iter().any(|(href, base, purpose)| {
        href == "same.xml"
            && base.as_deref() == Some("https://example.test/source/b/")
            && *purpose == ResolvePurpose::Document
    }));
    assert!(calls.iter().any(|(href, base, purpose)| {
        href == "module.xml"
            && base.as_deref() == Some("https://example.test/modules/imported.xsl")
            && *purpose == ResolvePurpose::Document
    }));
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
        "<!DOCTYPE doc SYSTEM \"result.dtd\">\n<doc><script><![CDATA[if (a < b) x = ']]]]><![CDATA[>';]]></script></doc>\n",
    );

    let html = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><html><body><br/><script>if (a &lt; b) x++;</script></body></html></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(html, "<source/>"),
        "<html>\n  <body>\n    <br>\n    <script>if (a < b) x++;</script>\n  </body>\n</html>\n",
    );

    let text = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><ignored>A<xsl:value-of select="'&lt;B'"/></ignored></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(text, "<source/>"), "A<B");

    let lexical = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="xml" indent="no" omit-xml-declaration="yes"/><xsl:template match="/"><doc><xsl:text>&#13;</xsl:text></doc></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(lexical, "<source/>"), "<doc>&#13;</doc>");

    let html_pi = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="html" indent="no"/><xsl:template match="/"><xsl:processing-instruction name="php">Success</xsl:processing-instruction></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(html_pi, "<source/>"), "<?php Success>");

    let html_meta = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="html" indent="no"/><xsl:template match="/"><html><head/></html></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(html_meta, "<source/>"),
        r#"<html><head><meta charset="UTF-8"></head></html>"#
    );

    let xhtml = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns="http://www.w3.org/1999/xhtml"><xsl:output method="xml" omit-xml-declaration="yes" indent="no"/><xsl:template match="/"><html><link/></html></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(xhtml, "<source/>"),
        r#"<html xmlns="http://www.w3.org/1999/xhtml"><link/></html>"#
    );
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

    let unbound_prefix = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="*[missing:name]"/></xsl:template></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(Arc::new(NoResolver), CompileBudget::new(4096, 0, 256, 4096),)
            .compile(unbound_prefix, None),
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
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:for-each select="root/item"><xsl:value-of select="position()"/><xsl:text>:</xsl:text><xsl:value-of select="count(child[position() &lt; 2])"/><xsl:text>|</xsl:text></xsl:for-each><xsl:value-of select="name(/*)"/><xsl:text>:</xsl:text><xsl:value-of select="local-name(/*)"/><xsl:text>:</xsl:text><xsl:value-of select="namespace-uri(/*)"/><xsl:text>|</xsl:text><xsl:for-each select="root/@*"><xsl:variable name="a" select="."/><xsl:value-of select="name(current())"/><xsl:text>=</xsl:text><xsl:value-of select="$a"/></xsl:for-each></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(
            stylesheet,
            r#"<root id="r"><item><child/><child/></item><item><child/></item></root>"#,
        ),
        "1:1|2:1|root:root:|id=r"
    );

    let default_namespace = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:d="urn:default"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="name(/d:doc)"/><xsl:text>:</xsl:text><xsl:value-of select="local-name(/d:doc)"/><xsl:text>:</xsl:text><xsl:value-of select="namespace-uri(/d:doc)"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(default_namespace, r#"<doc xmlns="urn:default"/>"#),
        "doc:doc:urn:default"
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

    let lexical_numbers = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="285311670611"/><xsl:text>|</xsl:text><xsl:value-of select="95012.38841989999"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(lexical_numbers, "<source/>"),
        "285311670611|95012.3884199"
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

    let undeclared = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns="urn:parent"><xsl:output omit-xml-declaration="yes" indent="no"/><xsl:template match="/"><parent><xsl:copy-of select="/*/*"/></parent></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(undeclared, "<source><child/></source>"),
        r#"<parent xmlns="urn:parent"><child xmlns=""/></parent>"#
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

#[test]
fn xpath_accepts_whitespace_before_function_arguments() {
    // XPath permits whitespace between a function QName and its argument list even
    // though the underlying parser requires lexical normalization.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="concat ('a', 'b')"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "ab");
}

#[test]
fn xpath_document_root_and_inherited_language_use_xslt_context() {
    // A root-only path inside a function call must address the current logical
    // document, and lang() must walk inherited xml:lang declarations.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="string-length(generate-id(/))"/><xsl:text>|</xsl:text><xsl:apply-templates select="root/item"/></xsl:template><xsl:template match="item"><xsl:value-of select="lang('en')"/><xsl:text>|</xsl:text><xsl:value-of select="lang('de')"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, r#"<root xml:lang="en-GB"><item/></root>"#),
        "3|true|false"
    );
}

#[test]
fn stylesheet_defined_exslt_functions_preserve_xpath_values() {
    // Function calls must retain numeric and result-tree-fragment types across
    // recursion instead of degrading every extension result to a string.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:func="http://exslt.org/functions" xmlns:f="urn:functions" extension-element-prefixes="func"><xsl:output omit-xml-declaration="yes" indent="no"/><func:function name="f:sum"><xsl:param name="n"/><xsl:param name="step" select="1"/><xsl:choose><xsl:when test="$n &gt; 0"><func:result select="$n + f:sum($n - $step, $step)"/></xsl:when><xsl:otherwise><func:result select="0"/></xsl:otherwise></xsl:choose></func:function><func:function name="f:tree"><func:result><answer><xsl:value-of select="f:sum(3)"/></answer></func:result></func:function><xsl:template match="/"><xsl:copy-of select="f:tree()"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "<answer>6</answer>");
}

#[test]
fn exslt_node_set_preserves_nested_parameter_fragments() {
    // A fragment copied through xsl:with-param must retain element identity when a
    // second temporary tree filters it and converts it back with exsl:node-set().
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:exsl="http://exslt.org/common" exclude-result-prefixes="exsl"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><xsl:apply-templates select="source"><xsl:with-param name="selection"><xsl:copy-of select="source/forms"/></xsl:with-param></xsl:apply-templates></xsl:template><xsl:template match="source"><xsl:param name="selection"/><xsl:variable name="filtered"><paradigm><xsl:copy-of select="exsl:node-set($selection)/forms/form[@id='b']"/></paradigm></xsl:variable><out><xsl:copy-of select="exsl:node-set($filtered)/paradigm/form"/></out></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(
            stylesheet,
            "<source><forms><form id=\"a\"/><form id=\"b\"/></forms></source>"
        ),
        "<out><form id=\"b\"/></out>\n"
    );
}

#[test]
fn exslt_node_set_preserves_large_filtered_parameter_fragments() {
    // The libxslt node-set.5/.6 stylesheets repeatedly pass copied source
    // subtrees as RTF parameters. Materialization must preserve descendants
    // and predicate evaluation before the recursive templates run.
    let stylesheet = r#"
      <xsl:stylesheet version="1.0"
        xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
        xmlns:exsl="http://exslt.org/common"
        exclude-result-prefixes="exsl">
        <xsl:output method="text"/>
        <xsl:template match="document">
          <xsl:variable name="selection"><xsl:copy-of select="/document/paradigm"/></xsl:variable>
          <xsl:value-of select="count(exsl:node-set($selection)/paradigm/form)"/>
          <xsl:text>|</xsl:text>
          <xsl:value-of select="count(exsl:node-set($selection)/paradigm/form[attribute[@name='caste' and @value='Brahmin']])"/>
        </xsl:template>
      </xsl:stylesheet>"#;
    let source = include_str!("fixtures/libxslt-1.1.45/upstream/tests/exslt/common/node-set.6.xml");
    assert_eq!(execute(stylesheet, source), "24|12");
}

#[test]
fn exslt_function_contract_is_rejected_statically() {
    // func:result is an instruction, not a top-level declaration or a general
    // extension fallback, and select/content are mutually exclusive.
    let outside = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:func="http://exslt.org/functions" extension-element-prefixes="func"><xsl:template match="/"><func:result select="1"/></xsl:template></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(Arc::new(NoResolver), CompileBudget::new(4096, 0, 32, 4096))
            .compile(outside, None),
        Err(Error::Static(_))
    ));

    let mixed = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:func="http://exslt.org/functions" xmlns:f="urn:functions" extension-element-prefixes="func"><func:function name="f:bad"><func:result select="1">content</func:result></func:function></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(Arc::new(NoResolver), CompileBudget::new(4096, 0, 32, 4096))
            .compile(mixed, None),
        Err(Error::Static(_))
    ));
}

#[test]
fn match_patterns_preserve_predicate_context() {
    // Predicates in match patterns keep the candidate node as their context;
    // positional sibling steps must not be evaluated against the document wrapper.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes" indent="no"/><xsl:template match="/"><out><xsl:apply-templates select="table/row"/></out></xsl:template><xsl:template match="row" priority="-1"><row/></xsl:template><xsl:template match="row[id mod 3 = 2][following-sibling::row[4]/firstname='Bob']"><crazy/></xsl:template></xsl:stylesheet>"#;
    let source = "<table><row><id>1</id></row><row><id>2</id></row><row/><row/><row/><row><firstname>Bob</firstname></row></table>";
    let selection = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="count(//row[id mod 3 = 2][following-sibling::row[4]/firstname='Bob'])"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(selection, source), "1");
    assert_eq!(
        execute(stylesheet, source),
        "<out><row/><crazy/><row/><row/><row/><row/></out>"
    );
}

#[test]
fn self_axis_preserves_node_sets_through_template_parameters() {
    // self::* and self::text() are axes, not boolean node-kind tests. Values
    // stored in variables must retain node identity when passed to templates.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><xsl:apply-templates select="root"/></xsl:template><xsl:template match="root"><xsl:variable name="element" select="self::*"/><xsl:variable name="text" select="text()/self::text()"/><xsl:call-template name="emit"><xsl:with-param name="element" select="$element"/><xsl:with-param name="text" select="$text"/></xsl:call-template></xsl:template><xsl:template name="emit"><xsl:param name="element"/><xsl:param name="text"/><out><xsl:copy-of select="$element/@id"/><xsl:value-of select="$text"/></out></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<root id=\"kept\">content</root>"),
        "<out id=\"kept\">content</out>\n"
    );
}

#[test]
fn recursive_named_templates_accumulate_result_tree_fragment_parameters() {
    // DocBook uses this shape to indent method signatures. The RTF accumulator
    // must remain string-coercible across every recursive call.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:variable name="decl"><xsl:text>abc</xsl:text></xsl:variable><xsl:call-template name="repeat"><xsl:with-param name="string">&#160;</xsl:with-param><xsl:with-param name="count" select="string-length($decl)"/></xsl:call-template></xsl:template><xsl:template name="repeat"><xsl:param name="string"/><xsl:param name="count" select="0"/><xsl:param name="result"/><xsl:choose><xsl:when test="$count &gt; 0"><xsl:call-template name="repeat"><xsl:with-param name="string" select="$string"/><xsl:with-param name="count" select="$count - 1"/><xsl:with-param name="result"><xsl:value-of select="$result"/><xsl:value-of select="$string"/></xsl:with-param></xsl:call-template></xsl:when><xsl:otherwise><xsl:value-of select="$result"/></xsl:otherwise></xsl:choose></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<root/>"), "\u{a0}\u{a0}\u{a0}");
}

#[test]
fn html_uri_serialization_drops_only_leading_xml_whitespace() {
    // Match libxslt's HTML serializer: leading XML whitespace is ignored,
    // while interior and trailing URI spaces are percent-encoded.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="html" omit-xml-declaration="yes"/><xsl:template match="/"><a href="  a b  ">x</a></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<root/>"),
        "<a href=\"a%20b%20%20\">x</a>\n"
    );
}

#[test]
fn imported_predicate_templates_override_base_templates() {
    // A higher-precedence imported module must be able to suppress nodes that
    // a lower-precedence generic template would otherwise copy.
    assert_eq!(
        execute(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><out><xsl:apply-templates/></out></xsl:template><xsl:template match="*"><xsl:copy><xsl:apply-templates/></xsl:copy></xsl:template><xsl:template match="*[@diff='del']"/></xsl:stylesheet>"#,
            "<root><old diff=\"del\">gone</old><kept>here</kept></root>",
        ),
        "<out><root><kept>here</kept></root></out>\n"
    );
    let resolver = Arc::new(MemoryResolver::default());
    resolver.resources.lock().expect("test resolver mutex is not poisoned").insert(
        "base.xsl".into(),
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><out><xsl:apply-templates/></out></xsl:template><xsl:template match="*"><xsl:copy><xsl:apply-templates/></xsl:copy></xsl:template></xsl:stylesheet>"#.into(),
    );
    let stylesheet = Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:import href="base.xsl"/><xsl:output omit-xml-declaration="yes"/><xsl:template match="*[@diff='del']"/></xsl:stylesheet>"#,
        Some("memory:main.xsl"),
    )
    .expect("imported predicate stylesheet compiles");
    let result = stylesheet
        .execute(
            &Document::parse(
                "<root><old diff=\"del\">gone</old><kept>here</kept></root>",
                None,
            )
            .expect("source parses"),
            &Parameters::new(),
            resolver,
            ExecutionOptions {
                budget: execution_budget(1 << 20),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("transformation succeeds");
    assert_eq!(
        result.serialized.bytes,
        b"<out><root><kept>here</kept></root></out>\n"
    );
}

#[test]
fn include_keeps_equal_precedence_and_document_order() {
    // Includes are textual expansion: the later local declaration wins at equal precedence.
    let resolver = Arc::new(MemoryResolver::default());
    resolver.resources.lock().expect("test resolver mutex is not poisoned").insert(
        "base.xsl".into(),
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><base/></xsl:template></xsl:stylesheet>"#.into(),
    );
    let stylesheet = Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:include href="base.xsl"/><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><local/></xsl:template></xsl:stylesheet>"#,
        Some("memory:main.xsl"),
    )
    .expect("included stylesheet compiles");
    let output = stylesheet
        .execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &Parameters::new(),
            resolver,
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("included stylesheet executes");
    assert_eq!(output.serialized.bytes, b"<local/>\n");
}

#[test]
fn whitespace_and_variable_scopes_follow_xslt_lexical_rules() {
    // NBSP is character data, nested variables do not leak, and undeclared caller values are ignored.
    let whitespace = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:strip-space elements="*"/><xsl:template match="/"><xsl:value-of select="string-length(root)"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(whitespace, "<root>\u{a0}</root>"), "1");

    let scope = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:if test="true()"><xsl:variable name="v" select="'inner'"/></xsl:if><xsl:value-of select="$v"/></xsl:template></xsl:stylesheet>"#;
    let scope_error = compile(scope)
        .execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect_err("out-of-scope variable must not resolve to the nested binding");
    assert!(
        matches!(scope_error, Error::Dynamic(ref message) if message.contains("unknown variable")),
        "{scope_error:?}"
    );

    let globals = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:variable name="y" select="$x"/><xsl:variable name="x" select="'fixed'"/><xsl:template match="/"><xsl:value-of select="$y"/></xsl:template></xsl:stylesheet>"#;
    let mut parameters = Parameters::new();
    parameters.insert(
        xml_sec_xslt::ExpandedName::new(None::<String>, "x"),
        Value::String("caller".into()),
    );
    let output = compile(globals)
        .execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &parameters,
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("undeclared caller parameter is ignored");
    assert_eq!(output.serialized.bytes, b"fixed");
}

#[test]
fn compiler_rejects_invalid_instruction_content_and_accounts_for_ir() {
    // Static content models fail during compilation, and retained IR consumes owned-byte budget.
    let invalid_text = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:text>before<xsl:value-of select="."/>after</xsl:text></xsl:template></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(Arc::new(NoResolver), CompileBudget::new(4096, 0, 32, 4096))
            .compile(invalid_text, None),
        Err(Error::Static(_))
    ));

    let retained = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:a="urn:a" xmlns:b="urn:b"><xsl:template match="/"><out><xsl:value-of select="concat('retained-expression-', name(/*))"/></out></xsl:template></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(Arc::new(NoResolver), CompileBudget::new(4096, 0, 32, 8))
            .compile(retained, None),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
}

#[test]
fn parser_preserves_base_and_lexical_names_across_depths() {
    // Semantic projection must apply xml:base, retain attribute prefixes, and reject unbound names.
    let document = Document::parse(
        r#"<root xml:base="sub/"><item xmlns:a="urn:x" xmlns:b="urn:x" b:value="1"/></root>"#,
        Some("https://example.test/source.xml"),
    )
    .expect("source parses");
    let item = document.node(xml_sec_xslt::NodeId(2)).expect("item exists");
    assert_eq!(item.base_uri.as_deref(), Some("https://example.test/sub/"));
    let xml_sec_xslt::NodeKind::Element { attributes, .. } = &item.kind else {
        panic!("item is an element");
    };
    assert_eq!(attributes[0].prefix.as_deref(), Some("b"));

    let mut malformed = String::new();
    for _ in 0..129 {
        malformed.push_str("<n>");
    }
    malformed.push_str("<p:item/>");
    for _ in 0..129 {
        malformed.push_str("</n>");
    }
    assert!(matches!(
        Document::parse(&malformed, None),
        Err(Error::Xml(_))
    ));
}

#[test]
fn serializer_applies_html_and_xml11_output_rules() {
    // HTML boolean attributes are minimized and XML 1.1 restricted controls use references.
    let html = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="html" omit-xml-declaration="yes"/><xsl:template match="/"><input checked="checked"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(html, "<source/>"), "<input checked>\n");

    let xml11 = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output version="1.1" omit-xml-declaration="yes"/><xsl:param name="value"/><xsl:template match="/"><out><xsl:value-of select="$value"/></out></xsl:template></xsl:stylesheet>"#;
    let mut parameters = Parameters::new();
    parameters.insert(
        xml_sec_xslt::ExpandedName::new(None::<String>, "value"),
        Value::String("\u{1}".into()),
    );
    let output = compile(xml11)
        .execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &parameters,
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("restricted XML 1.1 character serializes as a reference");
    assert_eq!(output.serialized.bytes, b"<out>&#x1;</out>\n");

    for stylesheet in [
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output version="1.1" omit-xml-declaration="yes" cdata-section-elements="out"/><xsl:param name="value"/><xsl:template match="/"><out><xsl:value-of select="$value"/></out></xsl:template></xsl:stylesheet>"#,
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output version="1.1" omit-xml-declaration="yes"/><xsl:param name="value"/><xsl:template match="/"><out><xsl:value-of select="$value" disable-output-escaping="yes"/></out></xsl:template></xsl:stylesheet>"#,
    ] {
        let output = compile(stylesheet)
            .execute(
                &Document::parse("<source/>", None).expect("source parses"),
                &parameters,
                Arc::new(NoResolver),
                ExecutionOptions {
                    budget: execution_budget(1024),
                    initial_mode: None,
                    initial_template: None,
                },
            )
            .expect("all XML text serialization paths preserve restricted controls");
        assert!(
            String::from_utf8(output.serialized.bytes)
                .expect("UTF-8 output")
                .contains("&#x1;")
        );
    }

    let comment = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output version="1.1"/><xsl:param name="value"/><xsl:template match="/"><xsl:comment><xsl:value-of select="$value"/></xsl:comment></xsl:template></xsl:stylesheet>"#;
    assert!(matches!(
        compile(comment).execute(
            &Document::parse("<source/>", None).expect("source parses"),
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

#[test]
fn computed_processing_instruction_targets_are_ncnames() {
    // A PI target is an NCName, not merely a string without a colon.
    for target in ["1invalid", "a b"] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:processing-instruction name="{target}">value</xsl:processing-instruction></xsl:template></xsl:stylesheet>"#
        );
        assert!(matches!(
            compile(&stylesheet).execute(
                &Document::parse("<source/>", None).expect("source parses"),
                &Parameters::new(),
                Arc::new(NoResolver),
                ExecutionOptions {
                    budget: execution_budget(1024),
                    initial_mode: None,
                    initial_template: None,
                },
            ),
            Err(Error::Dynamic(_))
        ));
    }
}

#[test]
fn xpath_numbers_use_decimal_not_exponent_notation() {
    // XPath 1.0 string conversion never emits scientific notation for finite values.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="285311670611"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "285311670611");
}

#[test]
fn execution_budgets_abort_sorting_and_charge_result_payloads() {
    // Comparison and owned-byte ceilings gate work while it is performed, not after allocation.
    let sorter = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><out><xsl:for-each select="root/item"><xsl:sort select="@v"/><xsl:value-of select="@v"/></xsl:for-each></out></xsl:template></xsl:stylesheet>"#,
    );
    let source = Document::parse(
        "<root><item v=\"c\"/><item v=\"b\"/><item v=\"a\"/></root>",
        None,
    )
    .expect("source parses");
    let mut budget = execution_budget(1024);
    budget.sort_comparisons = 0;
    assert!(matches!(
        sorter.execute(
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
            kind: BudgetKind::SortComparisons,
            ..
        })
    ));

    let payload = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:param name="name"/><xsl:template match="/"><xsl:element name="{$name}"/></xsl:template></xsl:stylesheet>"#,
    );
    let source = Document::parse("<s/>", None).expect("source parses");
    let mut parameters = Parameters::new();
    parameters.insert(
        xml_sec_xslt::ExpandedName::new(None::<String>, "name"),
        Value::String(format!("n{}", "x".repeat(512))),
    );
    let mut budget = execution_budget(1024);
    budget.owned_bytes = 128;
    assert!(matches!(
        payload.execute(
            &source,
            &parameters,
            Arc::new(NoResolver),
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
        ),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
}

#[test]
fn xinclude_fallback_never_swallows_security_budget_failures() {
    // Fallback handles resource availability, not operation-wide budget exhaustion.
    let resolver = Arc::new(MemoryResolver::default());
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert("included.xml".into(), "<included/>".into());
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:copy-of select="."/></xsl:template></xsl:stylesheet>"#,
    );
    let source = Document::parse(
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="included.xml"><xi:fallback><fallback/></xi:fallback></xi:include></root>"#,
        Some("memory:source.xml"),
    )
    .expect("source parses");
    let mut budget = execution_budget(1024);
    budget.external_documents = 0;
    assert!(matches!(
        stylesheet.execute_with_source_processing(
            &source,
            &Parameters::new(),
            resolver,
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
            xml_sec_xslt::SourceProcessing::XInclude,
        ),
        Err(Error::Budget {
            kind: BudgetKind::ExternalDocuments,
            ..
        })
    ));

    let stale = Arc::new(ContextResolver::default());
    for (href, body) in [("a.xml", "<a/>"), ("b.xml", "<b/>")] {
        stale
            .resources
            .lock()
            .expect("test resolver mutex is not poisoned")
            .insert(
                (href.into(), Some("memory:source.xml".into())),
                ResolvedResource {
                    canonical_uri: format!("memory:{href}"),
                    identity: ResourceIdentity("changing-xinclude".into()),
                    bytes: body.as_bytes().to_vec(),
                    media_type: Some("application/xml".into()),
                    encoding: Some("UTF-8".into()),
                },
            );
    }
    let source = Document::parse(
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="a.xml"><xi:fallback><fallback-a/></xi:fallback></xi:include><xi:include href="b.xml"><xi:fallback><fallback-b/></xi:fallback></xi:include></root>"#,
        Some("memory:source.xml"),
    )
    .expect("source parses");
    assert!(matches!(
        stylesheet.execute_with_source_processing(
            &source,
            &Parameters::new(),
            stale,
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
            xml_sec_xslt::SourceProcessing::XInclude,
        ),
        Err(Error::StaleResource { .. })
    ));
}
