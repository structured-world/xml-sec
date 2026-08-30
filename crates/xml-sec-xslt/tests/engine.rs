use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{collections::HashMap, sync::Mutex};

use pretty_assertions::assert_eq;
use xml_sec_xslt::{
    BudgetKind, CompileBudget, Compiler, Document, Error, ExecutionBudget, ExecutionOptions,
    ExpandedName, NoResolver, NodeReference, Parameters, ResolvePurpose, ResolvedResource,
    Resolver, ResourceIdentity, Value,
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
fn built_in_template_rules_do_not_forward_parameters() {
    // A parameter targets only the selected template; an intervening built-in rule must not
    // accidentally pass it to explicit templates selected for that rule's children.
    let stylesheet = r#"
      <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
        <xsl:output method="text"/>
        <xsl:template match="/"><xsl:apply-templates select="wrapper"><xsl:with-param name="value" select="'forwarded'"/></xsl:apply-templates></xsl:template>
        <xsl:template match="leaf"><xsl:param name="value" select="'default'"/><xsl:value-of select="$value"/></xsl:template>
      </xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<wrapper><leaf/></wrapper>"), "default");
}

#[test]
fn computed_names_require_lexical_qnames() {
    // Invalid dynamic names must fail before malformed element or attribute markup reaches the
    // serializer; both unprefixed and prefixed QName parts use NCName validation.
    for instruction in [
        r#"<xsl:element name="1invalid"/>"#,
        r#"<xsl:attribute name="p:a b" namespace="urn:test">value</xsl:attribute>"#,
    ] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><out>{instruction}</out></xsl:template></xsl:stylesheet>"#
        );
        let error = compile(&stylesheet)
            .execute(
                &Document::parse("<root/>", None).expect("source must parse"),
                &Parameters::new(),
                Arc::new(NoResolver),
                ExecutionOptions {
                    budget: execution_budget(1 << 20),
                    initial_mode: None,
                    initial_template: None,
                },
            )
            .expect_err("invalid computed QName must fail");
        assert!(matches!(error, Error::Dynamic(message) if message.contains("computed QName")));
    }
}

#[test]
fn result_tree_fragments_require_explicit_nodeset_conversion() {
    // XSLT 1.0 content-created variables are RTFs: direct path navigation is a dynamic error,
    // while exsl:node-set is the explicit operation that exposes their nodes.
    let invalid = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:variable name="fragment"><item/></xsl:variable><xsl:copy-of select="$fragment/item"/></xsl:template></xsl:stylesheet>"#;
    let error = compile(invalid)
        .execute(
            &Document::parse("<root/>", None).expect("source must parse"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1 << 20),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect_err("an RTF must not support direct path navigation");
    assert!(matches!(error, Error::Dynamic(_)));

    let explicit = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:exsl="http://exslt.org/common" exclude-result-prefixes="exsl"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><xsl:variable name="fragment"><item/></xsl:variable><xsl:copy-of select="exsl:node-set($fragment)/item"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(explicit, "<root/>"), "<item/>\n");
}

#[test]
fn doctype_uses_the_first_element_qualified_name() {
    // Prolog nodes do not replace the document element, and a prefixed root requires the same
    // qualified name in both the DOCTYPE and serialized start tag.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:p="urn:test"><xsl:output omit-xml-declaration="yes" doctype-system="result.dtd"/><xsl:template match="/"><xsl:comment>before</xsl:comment><p:root/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<source/>"),
        "<!--before--><!DOCTYPE p:root SYSTEM \"result.dtd\">\n<p:root xmlns:p=\"urn:test\"/>\n"
    );
}

#[test]
fn instruction_specific_attributes_are_rejected() {
    // Known attributes on the wrong instruction are static errors rather than silently ignored
    // behavior that makes a malformed stylesheet appear valid.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="." terminate="yes"/></xsl:template></xsl:stylesheet>"#;
    let error = Compiler::new(
        Arc::new(NoResolver),
        CompileBudget::new(1 << 20, 16, 256, 4 << 20),
    )
    .compile(stylesheet, None)
    .expect_err("misplaced known XSLT attribute must fail");
    assert!(matches!(error, Error::Static(message) if message.contains("does not permit")));
}

#[test]
fn external_parameter_payload_is_owned_byte_metered() {
    // Caller-owned parameter strings are cloned into the persistent global scope, so their
    // payload must be rejected before the clone can bypass a tight execution-owned-byte limit.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:param name="payload"/><xsl:template match="/"><out/></xsl:template></xsl:stylesheet>"#,
    );
    let mut parameters = Parameters::new();
    parameters.insert(
        ExpandedName::new(None::<String>, "payload"),
        Value::String("x".repeat(1024)),
    );
    let mut budget = execution_budget(1 << 20);
    budget.owned_bytes = 64;
    let error = stylesheet
        .execute(
            &Document::parse("<r/>", None).expect("source must parse"),
            &parameters,
            Arc::new(NoResolver),
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect_err("external parameter clone must be metered");
    assert!(matches!(
        error,
        Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        }
    ));
}

#[test]
fn number_empty_boundary_and_exceptional_values_follow_xslt() {
    // Empty sequences emit no formatting punctuation, level-any excludes its from boundary,
    // and exceptional explicit values bypass numbering tokens entirely.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:apply-templates select="section/section/item"/><xsl:text>|</xsl:text><xsl:number count="missing" format="(1)"/><xsl:text>|</xsl:text><xsl:number value="0" format="001"/><xsl:text>|</xsl:text><xsl:number value="1 div 0" format="001"/></xsl:template><xsl:template match="item"><xsl:number level="any" count="section|item" from="section"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<section><section><item/></section></section>"),
        "1||0|Infinity"
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
        "<new:r xmlns:new=\"urn:new\">0|1.234,50</new:r>\n",
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
fn stylesheet_xml_space_controls_literal_whitespace() {
    // xml:space applies to stylesheet text nodes too; nested `default` resumes stripping.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><out xml:space="preserve"> <kept> </kept><reset xml:space="default"> </reset> </out></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<source/>"),
        "<out xml:space=\"preserve\"> <kept> </kept><reset xml:space=\"default\"/> </out>\n"
    );
}

#[test]
fn forward_compatible_instruction_requires_an_actual_fallback() {
    // Forward-compatible processing suppresses unknown instructions only through xsl:fallback.
    let missing = r#"<xsl:stylesheet version="2.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:future/></xsl:template></xsl:stylesheet>"#;
    let error = compile(missing)
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
        .expect_err("unknown instruction without fallback must fail dynamically");
    assert!(matches!(error, Error::Unsupported(message) if message.contains("no xsl:fallback")));

    let present = r#"<xsl:stylesheet version="2.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:future><xsl:fallback>fallback</xsl:fallback></xsl:future></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(present, "<source/>"), "fallback");
}

#[test]
fn deferred_globals_do_not_repeat_observable_work() {
    // Dependency ordering must precede execution so retry cannot duplicate messages or outputs.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xt="http://www.jclark.com/xt" extension-element-prefixes="xt"><xsl:output method="text"/><xsl:variable name="dependent"><xsl:message>once</xsl:message><xt:document href="memory:once.xml" method="text">once</xt:document><xsl:value-of select="$later"/></xsl:variable><xsl:variable name="later" select="'ok'"/><xsl:template match="/"><xsl:value-of select="$dependent"/></xsl:template></xsl:stylesheet>"#;
    let result = compile(stylesheet)
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
        .expect("ordered globals execute");
    assert_eq!(result.messages.len(), 1);
    assert_eq!(result.secondary_outputs.len(), 1);
}

#[test]
fn included_module_document_is_retained_for_document_empty_uri() {
    // document('') is the stylesheet module containing the expression, not always the principal.
    #[derive(Default)]
    struct ModuleResolver {
        calls: Mutex<Vec<ResolvePurpose>>,
    }
    impl Resolver for ModuleResolver {
        fn resolve(
            &self,
            uri: &str,
            _base_uri: Option<&str>,
            purpose: ResolvePurpose,
        ) -> xml_sec_xslt::Result<ResolvedResource> {
            self.calls.lock().expect("calls lock").push(purpose);
            assert_eq!(uri, "module.xsl");
            Ok(ResolvedResource {
                canonical_uri: "memory:module.xsl".into(),
                identity: ResourceIdentity("module".into()),
                bytes: br#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><marker>module</marker><xsl:template name="read"><xsl:value-of select="document('')/*/marker"/></xsl:template></xsl:stylesheet>"#.to_vec(),
                media_type: Some("application/xslt+xml".into()),
                encoding: Some("UTF-8".into()),
            })
        }
    }
    let resolver = Arc::new(ModuleResolver::default());
    let stylesheet = Compiler::new(
        Arc::clone(&resolver),
        CompileBudget::new(1 << 20, 8, 256, 4 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:include href="module.xsl"/><xsl:template match="/"><xsl:call-template name="read"/></xsl:template></xsl:stylesheet>"#,
        Some("memory:main.xsl"),
    )
    .expect("stylesheet graph compiles");
    resolver.calls.lock().expect("calls lock").clear();
    let output = stylesheet
        .execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &Parameters::new(),
            Arc::clone(&resolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("retained module document resolves without runtime I/O");
    assert_eq!(output.serialized.bytes, b"module");
    assert!(resolver.calls.lock().expect("calls lock").is_empty());
}

#[test]
fn xpath_fast_paths_preserve_xpath_node_and_space_semantics() {
    // Absolute paths after word operators are operands, and normalize-space uses XML whitespace.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="count(/root)=1 and /root/item"/><xsl:text>|</xsl:text><xsl:value-of select="false() or /root/item"/><xsl:text>|</xsl:text><xsl:value-of select="normalize-space(.)"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<root><item/> a\u{a0}b \t c </root>"),
        "true|true|a\u{a0}b c"
    );
}

#[test]
fn adjacent_result_text_nodes_coalesce_without_crossing_doe_boundaries() {
    // XPath sees one adjacent text node, while differing disable-output-escaping is metadata boundary.
    let coalesced = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:exsl="http://exslt.org/common"><xsl:output method="text"/><xsl:template match="/"><xsl:variable name="fragment"><xsl:text>a</xsl:text><xsl:text>b</xsl:text></xsl:variable><xsl:value-of select="count(exsl:node-set($fragment)/text())"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(coalesced, "<source/>"), "1");

    let separated = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:exsl="http://exslt.org/common"><xsl:output method="text"/><xsl:template match="/"><xsl:variable name="fragment"><xsl:text>a</xsl:text><xsl:text disable-output-escaping="yes">b</xsl:text></xsl:variable><xsl:value-of select="count(exsl:node-set($fragment)/text())"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(separated, "<source/>"), "2");
}

#[test]
fn direct_nodeset_parameters_are_normalized_to_document_order() {
    // Caller vector order is not XPath node-set order.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes"/><xsl:param name="nodes"/><xsl:template match="/"><out first="{$nodes}"><xsl:copy-of select="$nodes"/></out></xsl:template></xsl:stylesheet>"#,
    );
    let document = Document::parse("<root><item>first</item><item>second</item></root>", None)
        .expect("source parses");
    let mut parameters = Parameters::new();
    parameters.insert(
        ExpandedName::new(None::<String>, "nodes"),
        Value::NodeSet(vec![
            NodeReference::Node(xml_sec_xslt::NodeId(4)),
            NodeReference::Node(xml_sec_xslt::NodeId(2)),
        ]),
    );
    let output = stylesheet
        .execute(
            &document,
            &parameters,
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("node-set parameter executes");
    assert_eq!(
        output.serialized.bytes,
        b"<out first=\"first\"><item>first</item><item>second</item></out>\n"
    );
}

#[test]
fn every_xpath_dispatch_consumes_exactly_one_evaluation() {
    // Optimized expressions are still logical XPath evaluations and generic dispatch is not double charged.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template name="run"><xsl:value-of select="."/></xsl:template></xsl:stylesheet>"#,
    );
    let mut budget = execution_budget(1024);
    budget.xpath_evaluations = 0;
    let error = stylesheet
        .execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: Some(ExpandedName::new(None::<String>, "run")),
            },
        )
        .expect_err("optimized XPath must consume budget");
    assert!(matches!(
        error,
        Error::Budget {
            kind: BudgetKind::XPathEvaluations,
            ..
        }
    ));

    let generic = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template name="run"><xsl:value-of select="1 + 1"/></xsl:template></xsl:stylesheet>"#,
    );
    budget.xpath_evaluations = 1;
    let output = generic
        .execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: Some(ExpandedName::new(None::<String>, "run")),
            },
        )
        .expect("generic expression consumes one evaluation");
    assert_eq!(output.serialized.bytes, b"2");
}

#[test]
fn optimized_attribute_pattern_trims_grammar_whitespace() {
    // Whitespace around `=` belongs to the predicate grammar, not the attribute QName.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:apply-templates select="root/item"/></xsl:template><xsl:template match="item[@id = 'wanted']">yes</xsl:template><xsl:template match="item">no</xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(
            stylesheet,
            "<root><item id=\"wanted\"/><item id=\"other\"/></root>"
        ),
        "yesno"
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
        "285311670611|95012.38841989999"
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

#[test]
fn missing_document_resolution_consumes_the_external_document_budget() {
    // A failed resolver attempt is still attacker-controlled external work.
    struct MissingResolver;
    impl Resolver for MissingResolver {
        fn resolve(
            &self,
            uri: &str,
            _base_uri: Option<&str>,
            _purpose: ResolvePurpose,
        ) -> xml_sec_xslt::Result<ResolvedResource> {
            Err(Error::ResourceNotFound { uri: uri.into() })
        }
    }
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="document('missing.xml')"/></xsl:template></xsl:stylesheet>"#,
    );
    let mut budget = execution_budget(1024);
    budget.external_documents = 0;
    assert!(matches!(
        stylesheet.execute(
            &Document::parse("<source/>", Some("memory:source.xml")).expect("source parses"),
            &Parameters::new(),
            Arc::new(MissingResolver),
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
        ),
        Err(Error::Budget {
            kind: BudgetKind::ExternalDocuments,
            ..
        })
    ));
}

#[test]
fn xslt_capability_queries_require_expanded_names_and_cover_registered_exslt() {
    // Capability discovery reports the exact expanded name of executable functions/elements.
    let stylesheet = r#"<xsl:stylesheet version="1.0"
        xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
        xmlns:exsl="http://exslt.org/common"
        xmlns:str="http://exslt.org/strings"
        xmlns:math="http://exslt.org/math">
        <xsl:output method="text"/>
        <xsl:template match="/"><xsl:value-of select="element-available('if')"/><xsl:text>|</xsl:text><xsl:value-of select="element-available('xsl:if')"/><xsl:text>|</xsl:text><xsl:value-of select="function-available('exsl:node-set')"/><xsl:text>|</xsl:text><xsl:value-of select="function-available('str:encode-uri')"/><xsl:text>|</xsl:text><xsl:value-of select="function-available('math:max')"/></xsl:template>
    </xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<source/>"),
        "false|true|true|true|true"
    );
}

#[test]
fn html_raw_text_rules_do_not_apply_to_foreign_namespaces() {
    // HTML raw-text elements are no-namespace HTML names, not arbitrary equal local names.
    let stylesheet = r#"<xsl:stylesheet version="1.0"
        xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:f="urn:foreign">
        <xsl:output method="html" omit-xml-declaration="yes"/>
        <xsl:template match="/"><html><f:script><xsl:text>&lt;</xsl:text></f:script><script><xsl:text>&lt;</xsl:text></script></html></xsl:template>
    </xsl:stylesheet>"#;
    let output = execute(stylesheet, "<source/>");
    assert!(output.contains("<f:script>&lt;</f:script>"));
    assert!(output.contains("<script><</script>"));
}

#[test]
fn format_number_treats_question_mark_as_an_ordinary_literal() {
    // Only the decimal-format's configured per-mille character scales the value.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="format-number(1, '?0')"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "?1");
}

struct EncodedStylesheetResolver;

impl Resolver for EncodedStylesheetResolver {
    fn resolve(
        &self,
        uri: &str,
        _base_uri: Option<&str>,
        purpose: ResolvePurpose,
    ) -> xml_sec_xslt::Result<ResolvedResource> {
        assert_eq!(uri, "latin1.xsl");
        assert_eq!(purpose, ResolvePurpose::Include);
        let source = b"<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"><xsl:template name=\"word\"><xsl:text>caf\xe9</xsl:text></xsl:template></xsl:stylesheet>";
        Ok(ResolvedResource {
            canonical_uri: "memory:latin1.xsl".into(),
            identity: ResourceIdentity("latin1.xsl".into()),
            bytes: source.to_vec(),
            media_type: Some("application/xslt+xml".into()),
            encoding: Some("ISO-8859-1".into()),
        })
    }
}

#[test]
fn imported_stylesheets_honor_resolver_encoding_metadata() {
    // Included XML modules use the resolver's authoritative byte encoding metadata.
    let resolver = Arc::new(EncodedStylesheetResolver);
    let stylesheet = Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:include href="latin1.xsl"/><xsl:output method="text"/><xsl:template match="/"><xsl:call-template name="word"/></xsl:template></xsl:stylesheet>"#,
        Some("memory:main.xsl"),
    )
    .expect("Latin-1 include compiles");
    let result = stylesheet
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
        .expect("stylesheet executes");
    assert_eq!(result.serialized.bytes, "caf\u{e9}".as_bytes());
}

#[test]
fn exslt_decode_uri_honors_the_requested_encoding() {
    // Percent-decoded octets are interpreted using the caller's declared character encoding.
    let stylesheet = r#"<xsl:stylesheet version="1.0"
        xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:str="http://exslt.org/strings">
        <xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="str:decode-uri('%E9', 'ISO-8859-1')"/></xsl:template>
    </xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "\u{e9}");

    let unsupported = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:str="http://exslt.org/strings"><xsl:template match="/"><xsl:value-of select="str:decode-uri('%E9', 'not-an-encoding')"/></xsl:template></xsl:stylesheet>"#,
    );
    assert!(matches!(
        unsupported.execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        ),
        Err(Error::Dynamic(message)) if message.contains("unknown encoding")
    ));
}

#[test]
fn keys_index_full_attribute_axis_patterns() {
    // Candidate enumeration must include attributes for the unabbreviated XPath axis spelling.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:key name="attrs" match="attribute::*" use="."/><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="count(key('attrs', 'needle'))"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source value=\"needle\"/>"), "1");
}

#[test]
fn retained_dynamic_xpath_expressions_consume_owned_memory_budget() {
    // Distinct attacker-controlled dynamic expressions cannot grow the execution cache for free.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:dyn="http://exslt.org/dynamic"><xsl:template match="/"><xsl:for-each select="root/item"><xsl:value-of select="dyn:evaluate(@expr)"/></xsl:for-each></xsl:template></xsl:stylesheet>"#,
    );
    let source_with = |expression: &dyn Fn(usize) -> String| {
        let expressions = (0..64)
            .map(|index| format!(r#"<item expr="{}"/>"#, expression(index)))
            .collect::<String>();
        Document::parse(&format!("<root>{expressions}</root>"), None).expect("source parses")
    };
    let mut budget = execution_budget(1 << 20);
    budget.owned_bytes = 128 << 10;
    stylesheet
        .execute(
            &source_with(&|_| "1 + 1".into()),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("one cached dynamic expression stays within the budget");
    assert!(matches!(
        stylesheet.execute(
            &source_with(&|index| format!("{index} + {}1", "1 + ".repeat(64))),
            &Parameters::new(),
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
fn xpath_document_scanner_ignores_calls_inside_string_literals() {
    // Literal text that resembles document() must never cross the resolver boundary.
    let resolver = Arc::new(ContextResolver::default());
    let stylesheet = Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="'document(&quot;secret.xml&quot;)'"/></xsl:template></xsl:stylesheet>"#,
        Some("memory:main.xsl"),
    )
    .expect("stylesheet compiles");
    let output = stylesheet
        .execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &Parameters::new(),
            resolver.clone(),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("literal expression executes");
    assert_eq!(output.serialized.bytes, b"document(\"secret.xml\")");
    assert!(
        resolver
            .calls
            .lock()
            .expect("test resolver mutex is not poisoned")
            .is_empty()
    );
}

#[test]
fn computed_elements_require_bound_prefixes() {
    // A lexical prefix without a namespace binding cannot form a result-tree QName.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:element name="p:item"/></xsl:template></xsl:stylesheet>"#,
    );
    assert!(matches!(
        stylesheet.execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        ),
        Err(Error::Dynamic(message)) if message.contains("unbound") && message.contains('p')
    ));
}

#[test]
fn unicode_variable_names_preserve_result_tree_fragments() {
    // XML NCNames are Unicode; the direct-value path must retain fragment node identity.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><xsl:variable name="é"><kept/></xsl:variable><out><xsl:copy-of select="$é"/></out></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "<out><kept/></out>\n");
}

#[test]
fn processing_instruction_strips_leading_xml_whitespace() {
    // XSLT strips leading PI data whitespace before the serializer adds one separator.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><xsl:processing-instruction name="p"><xsl:text>  value</xsl:text></xsl:processing-instruction></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "<?p value?>\n");
}

#[derive(Default)]
struct IncludeChainResolver {
    calls: Mutex<usize>,
}

impl Resolver for IncludeChainResolver {
    fn resolve(
        &self,
        uri: &str,
        _base_uri: Option<&str>,
        purpose: ResolvePurpose,
    ) -> xml_sec_xslt::Result<ResolvedResource> {
        assert_eq!(purpose, ResolvePurpose::Include);
        *self
            .calls
            .lock()
            .expect("test resolver mutex is not poisoned") += 1;
        let index = uri
            .strip_prefix("level-")
            .and_then(|value| value.strip_suffix(".xsl"))
            .and_then(|value| value.parse::<usize>().ok())
            .expect("chain URI contains a level");
        let next = index + 1;
        let source = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:include href="level-{next}.xsl"/></xsl:stylesheet>"#
        );
        Ok(ResolvedResource {
            canonical_uri: format!("memory:{uri}"),
            identity: ResourceIdentity(uri.into()),
            bytes: source.into_bytes(),
            media_type: Some("application/xslt+xml".into()),
            encoding: Some("UTF-8".into()),
        })
    }
}

#[test]
fn include_import_scan_checks_recursion_before_resolving_the_next_module() {
    // Compile depth bounds resolver work as well as the later declaration traversal.
    let resolver = Arc::new(IncludeChainResolver::default());
    let error = Compiler::new(resolver.clone(), CompileBudget::new(1 << 20, 32, 3, 1 << 20))
        .compile(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:include href="level-1.xsl"/></xsl:stylesheet>"#,
            Some("memory:main.xsl"),
        )
        .expect_err("include chain must stop at the compile recursion limit");
    assert!(matches!(
        error,
        Error::Budget {
            kind: BudgetKind::RecursionDepth,
            ..
        }
    ));
    assert_eq!(
        *resolver
            .calls
            .lock()
            .expect("test resolver mutex is not poisoned"),
        2,
        "the over-limit module must not be resolved"
    );
}

#[test]
fn attribute_set_dependencies_obey_execution_recursion_budget() {
    // Acyclic dependency chains must not bypass the native-stack recursion gate.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:attribute-set name="a" use-attribute-sets="b"/><xsl:attribute-set name="b" use-attribute-sets="c"/><xsl:attribute-set name="c" use-attribute-sets="d"/><xsl:attribute-set name="d"><xsl:attribute name="ok">yes</xsl:attribute></xsl:attribute-set><xsl:template match="/"><out xsl:use-attribute-sets="a"/></xsl:template></xsl:stylesheet>"#,
    );
    let mut budget = execution_budget(1024);
    budget.recursion_depth = 3;
    assert!(matches!(
        stylesheet.execute(
            &Document::parse("<source/>", None).expect("source parses"),
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
}

#[test]
fn evaluated_sort_order_rejects_unknown_values() {
    // Invalid AVT results are dynamic errors, never an implicit ascending fallback.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:param name="order" select="'sideways'"/><xsl:template match="/"><xsl:for-each select="root/item"><xsl:sort order="{$order}"/><xsl:value-of select="."/></xsl:for-each></xsl:template></xsl:stylesheet>"#,
    );
    assert!(matches!(
        stylesheet.execute(
            &Document::parse("<root><item>b</item><item>a</item></root>", None)
                .expect("source parses"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        ),
        Err(Error::Dynamic(message)) if message.contains("xsl:sort") && message.contains("order")
    ));
}

#[test]
fn computed_names_normalize_an_explicit_empty_namespace() {
    // An empty namespace URI removes the lexical prefix; retaining it would serialize an
    // undeclarable `xmlns:p=""` binding and change the expanded-name contract.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:p="urn:source"><xsl:output omit-xml-declaration="yes" indent="no"/><xsl:template match="/"><xsl:element name="p:out" namespace=""><xsl:attribute name="p:value" namespace="">ok</xsl:attribute></xsl:element></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "<out value=\"ok\"/>");
}

#[test]
fn html_boolean_minimization_requires_unnamespaced_names() {
    // HTML boolean shorthand applies to HTML attributes only, never to foreign expanded names.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:x="urn:foreign"><xsl:output method="html" indent="no"/><xsl:template match="/"><html><input x:checked="checked"/><x:input checked="checked"/></html></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<source/>"),
        "<html xmlns:x=\"urn:foreign\"><input x:checked=\"checked\"><x:input checked=\"checked\"></x:input></html>"
    );
}

#[test]
fn evaluated_sort_data_type_rejects_unknown_values() {
    // XSLT defines exactly text and number; an unknown AVT result is not a text fallback.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:param name="kind" select="'binary'"/><xsl:template match="/"><xsl:for-each select="root/item"><xsl:sort data-type="{$kind}"/></xsl:for-each></xsl:template></xsl:stylesheet>"#,
    );
    let error = stylesheet
        .execute(
            &Document::parse("<root><item/></root>", None).expect("source parses"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect_err("unsupported sort data type must fail");
    assert!(
        matches!(error, Error::Dynamic(message) if message.contains("data-type") && message.contains("binary"))
    );
}

#[test]
fn zero_argument_exslt_date_components_use_the_current_datetime() {
    // Zero-argument EXSLT date component functions operate on the current local date/time.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:date="http://exslt.org/dates-and-times"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="date:year()"/><xsl:text>|</xsl:text><xsl:value-of select="date:month-in-year()"/><xsl:text>|</xsl:text><xsl:value-of select="date:hour-in-day()"/></xsl:template></xsl:stylesheet>"#;
    let output = execute(stylesheet, "<source/>");
    let values = output
        .split('|')
        .map(|value| value.parse::<u32>().expect("current component is numeric"))
        .collect::<Vec<_>>();
    assert!((1970..=9999).contains(&values[0]));
    assert!((1..=12).contains(&values[1]));
    assert!(values[2] <= 23);
}

#[derive(Default)]
struct CountingResolver {
    calls: AtomicUsize,
    resources: Mutex<HashMap<String, String>>,
}

impl Resolver for CountingResolver {
    fn resolve(
        &self,
        uri: &str,
        _base_uri: Option<&str>,
        _purpose: ResolvePurpose,
    ) -> xml_sec_xslt::Result<ResolvedResource> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let bytes = self
            .resources
            .lock()
            .expect("test resolver mutex is not poisoned")
            .get(uri)
            .cloned()
            .ok_or_else(|| Error::ResourceNotFound { uri: uri.into() })?;
        Ok(ResolvedResource {
            canonical_uri: format!("memory:{uri}"),
            identity: ResourceIdentity(uri.into()),
            bytes: bytes.into_bytes(),
            media_type: Some("application/xml".into()),
            encoding: Some("UTF-8".into()),
        })
    }
}

#[test]
fn imported_stylesheets_share_the_cumulative_stylesheet_byte_budget() {
    // The graph limit covers principal and imported bytes, even when retained-memory allows both.
    let resolver = Arc::new(CountingResolver::default());
    resolver.resources.lock().expect("resolver mutex").insert(
        "included.xsl".into(),
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template name="included"/></xsl:stylesheet>"#.into(),
    );
    let principal = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:include href="included.xsl"/></xsl:stylesheet>"#;
    let error = Compiler::new(
        resolver,
        CompileBudget::new(principal.len() + 1, 8, 256, 1 << 20),
    )
    .compile(principal, Some("memory:main.xsl"))
    .expect_err("module graph exceeds cumulative stylesheet bytes");
    assert!(matches!(
        error,
        Error::Budget {
            kind: BudgetKind::StylesheetBytes,
            ..
        }
    ));
}

#[test]
fn xinclude_budget_is_checked_before_resolver_access() {
    // A denied external-document operation must not cross the resolver trust boundary.
    let resolver = Arc::new(CountingResolver::default());
    resolver
        .resources
        .lock()
        .expect("resolver mutex")
        .insert("included.xml".into(), "<included/>".into());
    let source = Document::parse(
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="included.xml"/></root>"#,
        Some("memory:source.xml"),
    )
    .expect("source parses");
    let mut budget = execution_budget(1024);
    budget.external_documents = 0;
    assert!(matches!(
        compile(r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"/></xsl:stylesheet>"#)
            .execute_with_source_processing(
                &source,
                &Parameters::new(),
                resolver.clone(),
                ExecutionOptions { budget, initial_mode: None, initial_template: None },
                xml_sec_xslt::SourceProcessing::XInclude,
            ),
        Err(Error::Budget { kind: BudgetKind::ExternalDocuments, .. })
    ));
    assert_eq!(resolver.calls.load(Ordering::Relaxed), 0);
}

#[test]
fn document_fragments_share_one_physical_resource_cache_entry() {
    // Fragment selectors identify views of one fetched document, not separate resources.
    let resolver = Arc::new(CountingResolver::default());
    resolver
        .resources
        .lock()
        .expect("resolver mutex")
        .insert("external.xml".into(), "<doc/>".into());
    let stylesheet = Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="count(document('external.xml')/doc | document('external.xml#xpointer(/doc)'))"/></xsl:template></xsl:stylesheet>"#,
        Some("memory:main.xsl"),
    )
    .expect("stylesheet compiles");
    let result = stylesheet
        .execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &Parameters::new(),
            resolver.clone(),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("document views resolve");
    assert_eq!(result.serialized.bytes, b"1");
    assert_eq!(resolver.calls.load(Ordering::Relaxed), 1);
}

#[test]
fn doctype_is_emitted_immediately_before_the_document_element() {
    // Top-level comments and processing instructions precede the document type declaration.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes" doctype-system="result.dtd"/><xsl:template match="/"><xsl:comment>before</xsl:comment><xsl:processing-instruction name="before">value</xsl:processing-instruction><root/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<source/>"),
        "<!--before--><?before value?><!DOCTYPE root SYSTEM \"result.dtd\">\n<root/>\n"
    );
}

#[test]
fn selected_local_variable_values_are_retained_memory_metered() {
    // A selected string remains owned by the lexical scope and must consume retained memory.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:variable name="payload" select="concat('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')"/></xsl:template></xsl:stylesheet>"#,
    );
    let mut budget = execution_budget(1024);
    budget.owned_bytes = 32;
    assert!(matches!(
        stylesheet.execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None
            },
        ),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
}

#[test]
fn supported_secondary_output_does_not_execute_fallback() {
    // xsl:fallback belongs only to unsupported extension execution.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xt="http://www.jclark.com/xt" extension-element-prefixes="xt"><xsl:template match="/"><xt:document href="memory:out.xml"><kept/><xsl:fallback><bad/></xsl:fallback></xt:document></xsl:template></xsl:stylesheet>"#,
    );
    let result = stylesheet
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
        .expect("secondary output executes");
    assert_eq!(
        result.secondary_outputs[0].serialized.bytes,
        b"<?xml version=\"1.0\"?>\n<kept/>\n"
    );
}

#[test]
fn default_processing_instruction_numbering_matches_the_target() {
    // The default count pattern for a PI is processing-instruction(target), not every PI.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:apply-templates select="root/processing-instruction()"/></xsl:template><xsl:template match="processing-instruction()"><xsl:value-of select="name()"/><xsl:text>:</xsl:text><xsl:number/><xsl:text>|</xsl:text></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<root><?a one?><?b two?><?a three?></root>"),
        "a:1|b:1|a:2|"
    );
}

#[test]
fn copied_namespace_nodes_preserve_existing_result_qnames() {
    // Namespace fixup may rename a copied binding, but it must never retarget the owner QName.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:p="urn:result"><xsl:output omit-xml-declaration="yes" indent="no"/><xsl:template match="/"><p:out><xsl:copy-of select="root/namespace::p"/></p:out></xsl:template></xsl:stylesheet>"#;
    let output = execute(stylesheet, r#"<root xmlns:p="urn:source"/>"#);
    let parsed = roxmltree::Document::parse(&output).expect("result remains namespace-well-formed");
    assert_eq!(
        parsed.root_element().tag_name().namespace(),
        Some("urn:result")
    );
    assert!(
        parsed
            .root_element()
            .namespaces()
            .any(|namespace| namespace.uri() == "urn:source")
    );
}

#[test]
fn deep_streaming_parser_enforces_single_document_element() {
    // The deep parser must enforce XML document grammar rather than accept fragments.
    let nested = format!("{}x{}", "<n>".repeat(129), "</n>".repeat(129));
    for malformed in [
        format!("{nested}<second/>"),
        format!("top-level{nested}"),
        format!("{nested}top-level"),
    ] {
        assert!(matches!(
            Document::parse(&malformed, None),
            Err(Error::Xml(_))
        ));
    }
}

#[test]
fn following_and_preceding_axes_stay_inside_the_logical_document() {
    // Projection siblings include stylesheet/external trees and are not XPath-visible documents.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:for-each select="root/item[last()]"><xsl:value-of select="count(following::*)"/><xsl:text>|</xsl:text><xsl:value-of select="count(preceding::*)"/></xsl:for-each></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<root><before/><item/></root>"), "0|1");
}

#[test]
fn whitespace_rules_apply_to_every_loaded_source_document() {
    // strip-space is a stylesheet-wide rule and must run after both document() loading and
    // XInclude expansion, not only on the principal source passed to execute().
    let resolver = Arc::new(CountingResolver::default());
    resolver.resources.lock().expect("resolver mutex").insert(
        "external.xml".into(),
        "<external>  <item/>  </external>".into(),
    );
    let stylesheet = Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:strip-space elements="*"/><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="count(document('external.xml')/external/text())"/></xsl:template></xsl:stylesheet>"#,
        Some("memory:main.xsl"),
    )
    .expect("stylesheet compiles");
    let result = stylesheet
        .execute(
            &Document::parse("<source/>", Some("memory:source.xml")).expect("source parses"),
            &Parameters::new(),
            resolver.clone(),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("external document transforms");
    assert_eq!(result.serialized.bytes, b"0");

    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:strip-space elements="*"/><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="count(root/external/text())"/></xsl:template></xsl:stylesheet>"#,
    );
    let source = Document::parse(
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="external.xml"/></root>"#,
        Some("memory:source.xml"),
    )
    .expect("source parses");
    let result = stylesheet
        .execute_with_source_processing(
            &source,
            &Parameters::new(),
            resolver,
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
            xml_sec_xslt::SourceProcessing::XInclude,
        )
        .expect("expanded source transforms");
    assert_eq!(result.serialized.bytes, b"0");
}

#[test]
fn built_in_template_rules_consume_supplied_parameters_in_fragments() {
    // The built-in element rule is equivalent to apply-templates without with-param.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:variable name="fragment"><xsl:apply-templates select="root/wrapper"><xsl:with-param name="value" select="'supplied'"/></xsl:apply-templates></xsl:variable><xsl:value-of select="$fragment"/></xsl:template><xsl:template match="leaf"><xsl:param name="value" select="'default'"/><xsl:value-of select="$value"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<root><wrapper><leaf/></wrapper></root>"),
        "default"
    );
}

#[test]
fn html_uri_escaping_uses_element_attribute_pairs_and_expanded_names() {
    // URI escaping applies only to the pairs listed by the XSLT HTML output contract.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:x="urn:foreign"><xsl:output method="html" indent="no"/><xsl:template match="/"><html><div href="é"/><foo src="é"/><a href="é" x:href="é"/></html></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<source/>"),
        "<html xmlns:x=\"urn:foreign\"><div href=\"é\"></div><foo src=\"é\"></foo><a href=\"%C3%A9\" x:href=\"é\"></a></html>"
    );
}

#[test]
fn for_each_honors_inherited_stylesheet_xml_space() {
    // The specialized sort/body parser must preserve the same stylesheet text nodes as the
    // general sequence compiler.
    let preserved = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:for-each select="/" xml:space="preserve"> </xsl:for-each><xsl:text>|</xsl:text></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(preserved, "<source/>"), " |");
    let stripped = preserved.replace(" xml:space=\"preserve\"", "");
    assert_eq!(execute(&stripped, "<source/>"), "|");
}

#[test]
fn computed_attributes_reject_reserved_namespace_names() {
    // Namespace declarations are namespace nodes, never attributes constructed by xsl:attribute.
    for (name, namespace) in [
        ("xmlns", None),
        ("value", Some("http://www.w3.org/2000/xmlns/")),
    ] {
        let namespace = namespace.map_or_else(String::new, |uri| format!(" namespace=\"{uri}\""));
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><out><xsl:attribute name="{name}"{namespace}>value</xsl:attribute></out></xsl:template></xsl:stylesheet>"#
        );
        let error = compile(&stylesheet)
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
            .expect_err("reserved computed attribute must fail");
        assert!(matches!(error, Error::Dynamic(message) if message.contains("namespace")));
    }
}

#[test]
fn xsl_number_level_is_validated_during_compilation() {
    // Literal enum errors are static even when dynamic control flow never executes the node.
    let invalid = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:if test="false()"><xsl:number level="sideways"/></xsl:if></xsl:template></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(Arc::new(NoResolver), CompileBudget::new(4096, 0, 32, 4096))
            .compile(invalid, None),
        Err(Error::Static(message)) if message.contains("xsl:number") && message.contains("level")
    ));
    for level in ["single", "multiple", "any"] {
        let valid = invalid.replace("sideways", level);
        Compiler::new(Arc::new(NoResolver), CompileBudget::new(4096, 0, 32, 4096))
            .compile(&valid, None)
            .expect("defined xsl:number level compiles");
    }
}

#[test]
fn text_output_rejects_characters_unrepresentable_in_its_encoding() {
    // Character references are markup and cannot preserve a character in method=text output.
    let text = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text" encoding="ISO-8859-1"/><xsl:template match="/">€</xsl:template></xsl:stylesheet>"#,
    );
    assert!(matches!(
        text.execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        ),
        Err(Error::Serialization(message)) if message.contains("ISO-8859-1") && message.contains('€')
    ));
    let xml = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="xml" encoding="ISO-8859-1" omit-xml-declaration="yes"/><xsl:template match="/"><out>€</out></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(xml, "<source/>"), "<out>&#8364;</out>\n");
}

#[test]
fn optimized_translate_uses_the_first_duplicate_mapping() {
    // XPath translate() assigns each source character by its first position in the map string.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:param name="from" select="'aa'"/><xsl:param name="to" select="'xy'"/><xsl:template match="/"><xsl:apply-templates select="root/item"/></xsl:template><xsl:template match="item"><xsl:value-of select="translate(., $from, $to)"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<root><item>a</item></root>"), "x");
}

#[test]
fn deep_streaming_parser_rejects_reserved_namespace_rebindings() {
    // The depth fallback parser must enforce the same Namespaces in XML constraints as roxmltree.
    for declaration in [
        "xmlns:xml=\"urn:wrong\"",
        "xmlns:p=\"http://www.w3.org/XML/1998/namespace\"",
        "xmlns:xmlns=\"urn:wrong\"",
        "xmlns:p=\"http://www.w3.org/2000/xmlns/\"",
    ] {
        let xml = format!(
            "{}<leaf {declaration}/>{}",
            "<n>".repeat(129),
            "</n>".repeat(129)
        );
        assert!(matches!(Document::parse(&xml, None), Err(Error::Xml(_))));
    }
    let valid = format!(
        "{}<leaf xml:lang=\"en\"/>{}",
        "<n>".repeat(129),
        "</n>".repeat(129)
    );
    Document::parse(&valid, None).expect("reserved xml binding remains implicitly available");
}

#[test]
fn doctype_identifiers_use_a_safe_literal_delimiter() {
    // A system identifier containing one quote kind uses the other; two kinds cannot form an
    // XML external identifier literal and must fail rather than emitting malformed markup.
    let quoted = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes" doctype-system="a&quot;b"/><xsl:template match="/"><root/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(quoted, "<source/>"),
        "<!DOCTYPE root SYSTEM 'a\"b'>\n<root/>\n"
    );
    let impossible = quoted.replace("a&quot;b", "a&quot;b&apos;c");
    let error = compile(&impossible)
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
        .expect_err("unquotable system identifier must fail");
    assert!(
        matches!(error, Error::Serialization(message) if message.contains("system identifier"))
    );
}

#[test]
fn global_dependencies_follow_called_named_templates() {
    // A global's value may depend on a later global through a named template call.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:variable name="first"><xsl:call-template name="build"/></xsl:variable><xsl:variable name="later" select="'ready'"/><xsl:template name="build"><xsl:value-of select="$later"/></xsl:template><xsl:template match="/"><xsl:value-of select="$first"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "ready");
}

#[test]
fn computed_names_enforce_reserved_prefix_namespace_pairs() {
    // Reserved lexical prefixes are remapped without changing the requested expanded name.
    for (instruction, namespace, local, attribute) in [
        (
            r#"<xsl:element name="xml:node" namespace="urn:not-xml"/>"#,
            "urn:not-xml",
            "node",
            false,
        ),
        (
            r#"<xsl:element name="xmlns:node" namespace="urn:any"/>"#,
            "urn:any",
            "node",
            false,
        ),
        (
            r#"<out><xsl:attribute name="xml:value" namespace="urn:not-xml">x</xsl:attribute></out>"#,
            "urn:not-xml",
            "value",
            true,
        ),
    ] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/">{instruction}</xsl:template></xsl:stylesheet>"#
        );
        let output = execute(&stylesheet, "<source/>");
        let parsed =
            roxmltree::Document::parse(&output).expect("computed output is namespace-valid");
        let root = parsed.root_element();
        let name = if attribute {
            root.attributes()
                .find(|candidate| candidate.name() == local)
                .expect("computed attribute exists")
                .name()
        } else {
            root.tag_name().name()
        };
        let actual_namespace = if attribute {
            root.attributes()
                .find(|candidate| candidate.name() == local)
                .and_then(|candidate| candidate.namespace())
        } else {
            root.tag_name().namespace()
        };
        assert_eq!(name, local);
        assert_eq!(actual_namespace, Some(namespace));
    }
    let forbidden = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><out><xsl:attribute name="value" namespace="http://www.w3.org/2000/xmlns/">x</xsl:attribute></out></xsl:template></xsl:stylesheet>"#;
    assert!(matches!(
        compile(forbidden).execute(
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
    let remapped = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><xsl:element name="p:node" namespace="http://www.w3.org/XML/1998/namespace"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(remapped, "<source/>"), "<xml:node/>\n");
}

#[test]
fn deep_streaming_parser_rejects_duplicate_expanded_attributes() {
    // Namespace aliases cannot bypass XML's uniqueness rule in the depth fallback parser.
    let xml = format!(
        "{}<leaf xmlns:a=\"urn:u\" xmlns:b=\"urn:u\" a:x=\"1\" b:x=\"2\"/>{}",
        "<n>".repeat(129),
        "</n>".repeat(129)
    );
    assert!(matches!(Document::parse(&xml, None), Err(Error::Xml(_))));
}

#[test]
fn literal_result_elements_honor_local_excluded_prefixes() {
    // xsl:exclude-result-prefixes applies where it is declared on a literal result element.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><out xmlns:p="urn:unused" xsl:exclude-result-prefixes="p"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "<out/>\n");
}

#[test]
fn logical_document_roots_hide_projection_parents_for_every_axis_form() {
    // The private package wrapper is never an XPath parent or ancestor of a document root.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="count(parent::node())"/><xsl:text>|</xsl:text><xsl:value-of select="count(ancestor::node())"/><xsl:text>|</xsl:text><xsl:value-of select="count(..)"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "0|0|0");
}

#[test]
fn empty_result_tree_fragments_are_true_singleton_root_node_sets() {
    // XSLT boolean conversion observes the fragment root even when it has no children.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:variable name="empty"><xsl:if test="false()"><never/></xsl:if></xsl:variable><xsl:template match="/"><xsl:if test="$empty">direct</xsl:if><xsl:text>|</xsl:text><xsl:value-of select="boolean($empty)"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "direct|true");
    assert!(Value::ResultTreeFragment(Document::empty(None)).into_boolean());
}

#[test]
fn function_available_advertises_document() {
    // Capability introspection must agree with the registered XSLT document() function.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="function-available('document')"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "true");
}

#[test]
fn key_indexes_charge_retained_values_to_owned_bytes() {
    // Key-entry count alone must not permit unbounded copies of large distinct use values.
    let value = "x".repeat(64 * 1024);
    let source_xml = format!("<root><item code=\"{value}\"/></root>");
    let source = Document::parse(&source_xml, None).expect("large key source parses");
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:key name="by-code" match="item" use="@code"/><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="count(key('by-code', root/item/@code))"/></xsl:template></xsl:stylesheet>"#,
    );
    let mut budget = execution_budget(source_xml.len());
    budget.owned_bytes = 180 * 1024;
    assert!(matches!(
        stylesheet.execute(
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
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
}

#[test]
fn scalar_fast_paths_resolve_prefixed_variables() {
    // Optimized scalar expressions use the same expanded variable names as general XPath.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:p="urn:params"><xsl:output method="text"/><xsl:param name="p:n" select="2"/><xsl:param name="p:text" select="'ok'"/><xsl:template match="/"><xsl:value-of select="$p:n + 1"/><xsl:text>|</xsl:text><xsl:value-of select="string-length($p:text) &gt; 0"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "3|true");
}

#[test]
fn processing_instruction_pattern_priority_ignores_xpath_whitespace() {
    // Equivalent PI target patterns have equal default priority, so later stylesheet order wins.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:apply-templates select="root/processing-instruction()"/></xsl:template><xsl:template match="processing-instruction ('target')">early</xsl:template><xsl:template match="processing-instruction('target')">late</xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<root><?target value?></root>"), "late");
}

#[test]
fn xpath_number_strings_preserve_distinguishable_f64_digits() {
    // XPath string conversion must not collapse distinct IEEE-754 values before serialization.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="1.2345678901234567"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "1.2345678901234567");
}

#[test]
fn deep_streaming_parser_expands_internal_general_entities() {
    // The depth-safe parser must retain the same internal-entity semantics as the normal parser.
    let xml = format!(
        "<!DOCTYPE n [<!ENTITY nested \"ok\"><!ENTITY value \"<leaf attr='&nested;'>&nested;</leaf>\">]>{}&value;{}",
        "<n>".repeat(129),
        "</n>".repeat(129)
    );
    let document = Document::parse(&xml, None).expect("deep document with internal entity parses");
    let result = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="//leaf/@attr"/><xsl:text>|</xsl:text><xsl:value-of select="//leaf"/></xsl:template></xsl:stylesheet>"#,
    )
    .execute(
        &document,
        &Parameters::new(),
        Arc::new(NoResolver),
        ExecutionOptions {
            budget: execution_budget(xml.len()),
            initial_mode: None,
            initial_template: None,
        },
    )
    .expect("deep entity document transforms");
    assert_eq!(result.serialized.bytes, b"ok|ok");

    let cyclic = format!(
        "<!DOCTYPE n [<!ENTITY a \"&b;\"><!ENTITY b \"&a;\">]>{}&a;{}",
        "<n>".repeat(129),
        "</n>".repeat(129)
    );
    assert!(matches!(Document::parse(&cyclic, None), Err(Error::Xml(_))));
}

struct CanonicalIdentityResolver {
    calls: AtomicUsize,
}

impl Resolver for CanonicalIdentityResolver {
    fn resolve(
        &self,
        _uri: &str,
        _base_uri: Option<&str>,
        _purpose: ResolvePurpose,
    ) -> xml_sec_xslt::Result<ResolvedResource> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(ResolvedResource {
            canonical_uri: "memory:canonical.xml".into(),
            identity: ResourceIdentity("canonical-document".into()),
            bytes: b"<doc/>".to_vec(),
            media_type: Some("application/xml".into()),
            encoding: Some("UTF-8".into()),
        })
    }
}

#[test]
fn document_function_coalesces_lexical_aliases_by_resource_identity() {
    // Resolver provenance, not lexical href spelling, defines external document identity.
    let resolver = Arc::new(CanonicalIdentityResolver {
        calls: AtomicUsize::new(0),
    });
    let stylesheet = Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="count(document('doc.xml')/doc | document('./doc.xml')/doc)"/></xsl:template></xsl:stylesheet>"#,
        Some("memory:main.xsl"),
    )
    .expect("stylesheet compiles");
    let result = stylesheet
        .execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &Parameters::new(),
            resolver.clone(),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("canonical document aliases resolve");
    assert_eq!(result.serialized.bytes, b"1");
    assert_eq!(resolver.calls.load(Ordering::Relaxed), 2);
}

#[test]
fn namespace_alias_uses_the_declared_result_prefix() {
    // The alias chooses both the result namespace URI and its lexical output prefix.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:old="urn:old" xmlns:new="urn:new"><xsl:namespace-alias stylesheet-prefix="old" result-prefix="new"/><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><old:result/></xsl:template></xsl:stylesheet>"#;
    let output = execute(stylesheet, "<source/>");
    assert!(output.starts_with("<new:result"), "{output}");
    assert!(output.contains("xmlns:new=\"urn:new\""), "{output}");
}

#[test]
fn explicit_axis_node_tests_keep_their_default_priority() {
    // Explicit child/attribute axes are priority-equivalent to their abbreviated node tests.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:apply-templates select="root/foo | root/foo/@id"/></xsl:template><xsl:template match="foo">element-specific|</xsl:template><xsl:template match="child::node()">element-generic|</xsl:template><xsl:template match="@id">attribute-specific|</xsl:template><xsl:template match="attribute::node()">attribute-generic|</xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<root><foo id=\"x\"/></root>"),
        "element-specific|attribute-specific|"
    );
}

#[test]
fn xpath_string_to_number_rejects_non_xpath_lexical_forms() {
    // XPath 1.0 accepts decimal syntax only, not Rust's leading-plus or exponent forms.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="number('+1')"/><xsl:text>|</xsl:text><xsl:value-of select="number('1e2')"/><xsl:text>|</xsl:text><xsl:value-of select="number('1.5')"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "NaN|NaN|1.5");
}

#[test]
fn computed_names_accept_the_complete_xml_name_start_range() {
    // U+200C is an XML 1.0 NameStartChar even though Rust does not classify it alphabetically.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><xsl:element name="&#x200C;result"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "<\u{200c}result/>\n");
}

#[test]
fn relational_nodeset_comparisons_are_existential() {
    // Every nodeset member participates; the first node in document order is not privileged.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="root/n &lt; 5"/><xsl:text>|</xsl:text><xsl:value-of select="root/n &lt; root/limit"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(
            stylesheet,
            "<root><n>10</n><n>1</n><limit>0</limit><limit>5</limit></root>"
        ),
        "true|true"
    );
}

#[test]
fn fractional_numeric_predicates_do_not_select_truncated_positions() {
    // A numeric predicate matches only exact context position equality.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="count(root/item[1.5])"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<root><item/><item/></root>"), "0");
}

#[test]
fn level_any_numbering_counts_attributes_on_preceding_elements() {
    // Attribute document order includes attributes of elements preceding the current owner.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:apply-templates select="root/*/@id"/></xsl:template><xsl:template match="@id"><xsl:number level="any" count="@id"/><xsl:text>|</xsl:text></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<root><a id=\"x\"/><b id=\"y\"/></root>"),
        "1|2|"
    );
}

#[test]
fn retained_node_paths_consume_the_execution_memory_budget() {
    // Deep documents retain ancestor paths for cross-model identity; that quadratic storage must
    // remain inside the same OwnedBytes boundary as the semantic and XPath projections.
    let source_xml = format!("{}text{}", "<n>".repeat(220), "</n>".repeat(220));
    let source = Document::parse(&source_xml, None).expect("deep source parses");
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"/></xsl:stylesheet>"#,
    );
    let mut budget = execution_budget(source_xml.len());
    budget.owned_bytes = 512 * 1024;
    assert!(matches!(
        stylesheet.execute(
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
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
}

#[test]
fn named_templates_preserve_the_callers_current_template_rule() {
    // apply-imports inside a named template continues from the matched caller's import
    // precedence, not from the named template declaration's precedence.
    let resolver = Arc::new(MemoryResolver::default());
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert(
            "base.xsl".into(),
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:call-template name="bridge"/></xsl:template></xsl:stylesheet>"#.into(),
        );
    let stylesheet = Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:import href="base.xsl"/><xsl:output method="text"/><xsl:template name="bridge"><xsl:apply-imports/></xsl:template></xsl:stylesheet>"#,
        Some("memory:main.xsl"),
    )
    .expect("cross-precedence named template compiles");
    let result = stylesheet
        .execute(
            &Document::parse("<source>ok</source>", None).expect("source parses"),
            &Parameters::new(),
            resolver,
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("named call preserves the current matched rule");
    assert_eq!(result.serialized.bytes, b"ok");

    let no_current_rule = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template name="bridge"><xsl:apply-imports/></xsl:template><xsl:template match="/">wrong</xsl:template></xsl:stylesheet>"#,
    );
    assert!(matches!(
        no_current_rule.execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: Some(ExpandedName::new(None::<String>, "bridge")),
            },
        ),
        Err(Error::Dynamic(message)) if message.contains("current template rule")
    ));
}

#[test]
fn duplicate_with_param_bindings_are_static_errors() {
    // One invocation cannot assign two values to the same expanded parameter name.
    for invocation in [
        r#"<xsl:apply-templates><xsl:with-param name="value" select="1"/><xsl:with-param name="value" select="2"/></xsl:apply-templates>"#,
        r#"<xsl:call-template name="target"><xsl:with-param name="value" select="1"/><xsl:with-param name="value" select="2"/></xsl:call-template>"#,
    ] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/">{invocation}</xsl:template><xsl:template name="target"/></xsl:stylesheet>"#
        );
        assert!(matches!(
            Compiler::new(
                Arc::new(NoResolver),
                CompileBudget::new(1 << 20, 8, 256, 1 << 20),
            )
            .compile(&stylesheet, None),
            Err(Error::Static(message)) if message.contains("duplicate xsl:with-param")
        ));
    }
}

#[test]
fn retained_pattern_match_sets_consume_the_execution_memory_budget() {
    // Distinct complex patterns may each select the whole source, but their retained cache sets
    // cannot multiply memory beyond the operation's OwnedBytes limit.
    let templates = (1..=120)
        .map(|index| format!(r#"<xsl:template match="item[position() &gt;= 1][{index} &gt; 0]"/>"#))
        .collect::<String>();
    let stylesheet = compile(&format!(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">{templates}<xsl:template match="/"><xsl:apply-templates select="root/item"/></xsl:template></xsl:stylesheet>"#
    ));
    let source_xml = format!("<root>{}</root>", "<item/>".repeat(800));
    let source = Document::parse(&source_xml, None).expect("broad-pattern source parses");
    let mut budget = execution_budget(source_xml.len());
    budget.owned_bytes = 4 << 20;
    assert!(matches!(
        stylesheet.execute(
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
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
}

#[test]
fn document_function_resolves_xml_shorthand_pointers() {
    // A bare fragment is an XPointer shorthand pointer and resolves through the imported
    // document's typed ID index rather than being parsed as an XPath expression.
    let resolver = Arc::new(MemoryResolver::default());
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert(
            "external.xml".into(),
            r#"<doc><item xml:id="target">selected</item></doc>"#.into(),
        );
    let stylesheet = Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="document('external.xml#target')"/><xsl:text>|</xsl:text><xsl:value-of select="count(document('external.xml#missing'))"/></xsl:template></xsl:stylesheet>"#,
        Some("memory:main.xsl"),
    )
    .expect("shorthand-pointer stylesheet compiles");
    let result = stylesheet
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
        .expect("shorthand pointers resolve through XML IDs");
    assert_eq!(result.serialized.bytes, b"selected|0");
}

#[test]
fn format_number_honors_apostrophe_quoted_literals() {
    // DecimalFormat quotes remove syntax from enclosed symbols; doubled apostrophes emit one
    // literal apostrophe without changing the active numeric subpattern.
    let stylesheet = r##"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="format-number(12, &quot;'#'0&quot;)"/><xsl:text>|</xsl:text><xsl:value-of select="format-number(12, &quot;'%'0&quot;)"/><xsl:text>|</xsl:text><xsl:value-of select="format-number(12, &quot;''0&quot;)"/></xsl:template></xsl:stylesheet>"##;
    assert_eq!(execute(stylesheet, "<source/>"), "#12|%12|'12");
}

#[test]
fn exslt_padding_is_metered_before_result_allocation() {
    // A scalar consumer must not let str:padding allocate a large temporary string before the
    // operation's OwnedBytes budget sees the requested result.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:str="http://exslt.org/strings"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="string-length(str:padding(1048576, 'é'))"/></xsl:template></xsl:stylesheet>"#,
    );
    let mut budget = execution_budget(1024);
    budget.owned_bytes = 256 * 1024;
    assert!(matches!(
        stylesheet.execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &Parameters::new(),
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
fn namespace_generate_ids_are_stable_and_injective() {
    // Lexically different namespace prefixes must never collide through mixed raw/hex encoding.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="generate-id(root/namespace::*[name() = 'C3A9']) != generate-id(root/namespace::*[name() = 'é'])"/><xsl:text>|</xsl:text><xsl:value-of select="generate-id(root/namespace::*[name() = 'é']) = generate-id(root/namespace::*[name() = 'é'])"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(
            stylesheet,
            r#"<root xmlns:C3A9="urn:ascii" xmlns:é="urn:utf8"/>"#
        ),
        "true|true"
    );
}

#[test]
fn exslt_replace_is_metered_before_multiplicative_expansion() {
    // The replacement result can be the product of two individually bounded strings. The
    // execution budget must reject that product before the result String reserves its capacity.
    let replacement = "y".repeat(32 * 1024);
    let stylesheet = compile(&format!(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:str="http://exslt.org/strings"><xsl:output method="text"/><xsl:variable name="replacement">{replacement}</xsl:variable><xsl:template match="/"><xsl:value-of select="str:replace(string(.), 'x', $replacement)"/></xsl:template></xsl:stylesheet>"#
    ));
    let source_xml = format!("<source>{}</source>", "x".repeat(1024));
    let mut budget = execution_budget(source_xml.len());
    budget.owned_bytes = 256 * 1024;
    assert!(matches!(
        stylesheet.execute(
            &Document::parse(&source_xml, None).expect("source parses"),
            &Parameters::new(),
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
fn standalone_fallback_is_a_static_error() {
    // xsl:fallback is meaningful only as a direct child of an extension instruction.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:fallback><out/></xsl:fallback></xsl:template></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(1 << 20, 8, 256, 1 << 20),
        )
        .compile(stylesheet, None),
        Err(Error::Static(message)) if message.contains("extension instruction")
    ));
}

#[test]
fn instruction_value_capture_rejects_non_text_nodes() {
    // XSLT does not flatten forbidden element descendants into attribute, comment, or PI values.
    for instruction in [
        r#"<out><xsl:attribute name="value"><bad>attribute</bad></xsl:attribute></out>"#,
        r#"<xsl:comment><bad>comment</bad></xsl:comment>"#,
        r#"<xsl:processing-instruction name="target"><bad>pi</bad></xsl:processing-instruction>"#,
    ] {
        let stylesheet = compile(&format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/">{instruction}</xsl:template></xsl:stylesheet>"#
        ));
        assert!(matches!(
            stylesheet.execute(
                &Document::parse("<source/>", None).expect("source parses"),
                &Parameters::new(),
                Arc::new(NoResolver),
                ExecutionOptions {
                    budget: execution_budget(1024),
                    initial_mode: None,
                    initial_template: None,
                },
            ),
            Err(Error::Dynamic(message)) if message.contains("text nodes")
        ));
    }
}

#[test]
fn child_axis_fast_path_preserves_union_precedence() {
    // `|` binds below `/`: the text() operand remains relative to the original context node.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:for-each select="root"><xsl:for-each select="a/*|text()"><xsl:value-of select="name()"/><xsl:text>:</xsl:text><xsl:value-of select="."/><xsl:text>|</xsl:text></xsl:for-each></xsl:for-each></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<root>outer<a>inner<b>B</b></a></root>"),
        ":outer|b:B|"
    );
}

#[test]
fn empty_xslt_instructions_reject_content() {
    // Instructions with an EMPTY content model may contain formatting whitespace, but no
    // executable child or non-whitespace character data.
    for instruction in [
        r#"<xsl:value-of select="1"><bad/></xsl:value-of>"#,
        r#"<xsl:copy-of select=".">content</xsl:copy-of>"#,
        r#"<xsl:number><bad/></xsl:number>"#,
        r#"<xsl:apply-templates><xsl:sort select="."><bad/></xsl:sort></xsl:apply-templates>"#,
    ] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/">{instruction}</xsl:template></xsl:stylesheet>"#
        );
        assert!(matches!(
            Compiler::new(
                Arc::new(NoResolver),
                CompileBudget::new(1 << 20, 8, 256, 1 << 20),
            )
            .compile(&stylesheet, None),
            Err(Error::Static(message)) if message.contains("must be empty")
        ));
    }

    compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="1">
        </xsl:value-of><xsl:copy-of select="."> </xsl:copy-of><xsl:number> </xsl:number><xsl:apply-templates><xsl:sort select="."> </xsl:sort></xsl:apply-templates></xsl:template></xsl:stylesheet>"#,
    );
}
