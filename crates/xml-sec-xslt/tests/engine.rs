use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{collections::HashMap, sync::Mutex};

use pretty_assertions::assert_eq;
use xml_sec_xslt::{
    BudgetKind, Clock, CompileBudget, Compiler, Document, Error, ExecutionBudget,
    ExecutionEnvironment, ExecutionOptions, ExpandedName, ExtensionPolicy, FixedClock, NoResolver,
    NodeKind, NodeReference, Parameters, ResolvePurpose, ResolvedResource, Resolver,
    ResourceIdentity, SourceProcessing, Value,
};

fn node_id_at(document: &Document, index: usize) -> xml_sec_xslt::NodeId {
    document
        .nodes()
        .nth(index)
        .map(|(id, _)| id)
        .expect("document contains the requested arena node")
}

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
        pattern_evaluations: 100_000_000,
        template_applications: 100_000,
        sort_comparisons: 100_000,
        key_entries: 100_000,
        result_nodes: 100_000,
        serialized_bytes: 1 << 20,
        messages: 100,
        owned_bytes: 8 << 20,
    }
}

fn minimum_execution_owned_bytes(
    stylesheet: &xml_sec_xslt::Stylesheet,
    initial_template: &str,
) -> usize {
    minimum_execution_owned_bytes_with_parameters(stylesheet, initial_template, &Parameters::new())
}

fn minimum_execution_owned_bytes_with_parameters(
    stylesheet: &xml_sec_xslt::Stylesheet,
    initial_template: &str,
    parameters: &Parameters,
) -> usize {
    let source = Document::parse("<source/>", None).expect("source parses");
    let succeeds = |owned_bytes| {
        let mut budget = execution_budget(1024);
        budget.messages = usize::MAX;
        budget.owned_bytes = owned_bytes;
        stylesheet
            .execute(
                &source,
                parameters,
                Arc::new(NoResolver),
                ExecutionOptions {
                    budget,
                    initial_mode: None,
                    initial_template: Some(ExpandedName::new(None::<String>, initial_template)),
                },
            )
            .is_ok()
    };
    let mut rejected = 0;
    let mut accepted = 1;
    while !succeeds(accepted) {
        rejected = accepted;
        accepted *= 2;
    }
    while rejected + 1 < accepted {
        let candidate = rejected + (accepted - rejected) / 2;
        if succeeds(candidate) {
            accepted = candidate;
        } else {
            rejected = candidate;
        }
    }
    accepted
}

fn minimum_execution_owned_bytes_for_source(
    stylesheet: &xml_sec_xslt::Stylesheet,
    source: &Document,
    source_bytes: usize,
) -> usize {
    let succeeds = |owned_bytes| {
        let mut budget = execution_budget(source_bytes);
        budget.owned_bytes = owned_bytes;
        stylesheet
            .execute(
                source,
                &Parameters::new(),
                Arc::new(NoResolver),
                ExecutionOptions {
                    budget,
                    initial_mode: None,
                    initial_template: None,
                },
            )
            .is_ok()
    };
    let mut rejected = 0;
    let mut accepted = 1;
    while !succeeds(accepted) {
        rejected = accepted;
        accepted *= 2;
    }
    while rejected + 1 < accepted {
        let candidate = rejected + (accepted - rejected) / 2;
        if succeeds(candidate) {
            accepted = candidate;
        } else {
            rejected = candidate;
        }
    }
    accepted
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
fn compound_key_name_expression_builds_the_runtime_selected_index() {
    // XPath 1.0 converts the complete first argument to a string before key lookup; matching
    // outer quotes do not make a compound expression one lexical string literal.
    let stylesheet = r#"
      <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
        <xsl:key name="true" match="item" use="@id"/>
        <xsl:output method="text"/>
        <xsl:template match="/"><xsl:value-of select="key('a' or 'b', 'wanted')"/></xsl:template>
      </xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, r#"<root><item id="wanted">found</item></root>"#),
        "found"
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
fn result_tree_fragments_preserve_binding_and_xml_base_uris() {
    // XSLT 1.0 assigns a temporary tree the variable-binding element's base URI, while xml:base
    // on a constructed descendant refines that inherited base for document() resolution.
    let resolver = Arc::new(ContextResolver::default());
    let imported = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:exsl="http://exslt.org/common"><xsl:template name="read"><xsl:variable name="fragment" xml:base="fragments/"><item xml:base="nested/"/></xsl:variable><xsl:value-of select="document('root.xml', exsl:node-set($fragment))/doc"/><xsl:text>|</xsl:text><xsl:value-of select="document('item.xml', exsl:node-set($fragment)/item)/doc"/></xsl:template></xsl:stylesheet>"#;
    for (href, base, canonical, identity, body) in [
        (
            "imported.xsl",
            "https://example.test/styles/main.xsl",
            "https://example.test/modules/imported.xsl",
            "imported-rtf-base",
            imported,
        ),
        (
            "root.xml",
            "https://example.test/modules/fragments/",
            "https://example.test/modules/fragments/root.xml",
            "rtf-root-document",
            "<doc>root</doc>",
        ),
        (
            "item.xml",
            "https://example.test/modules/fragments/nested/",
            "https://example.test/modules/fragments/nested/item.xml",
            "rtf-item-document",
            "<doc>item</doc>",
        ),
    ] {
        resolver
            .resources
            .lock()
            .expect("test resolver mutex is not poisoned")
            .insert(
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
    let stylesheet = Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:import href="imported.xsl"/><xsl:output method="text"/><xsl:template match="/"><xsl:call-template name="read"/></xsl:template></xsl:stylesheet>"#,
        Some("https://example.test/styles/main.xsl"),
    )
    .expect("stylesheet graph compiles");
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
        .expect("fragment-relative documents resolve");
    assert_eq!(result.serialized.bytes, b"root|item");
}

#[test]
fn constructed_elements_preserve_their_instruction_base_uri() {
    // XSLT 1.0 section 3.2 assigns a node the base URI of the stylesheet instruction that
    // creates it, even when an imported template writes into a caller-owned temporary tree.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#base-uri
    let resolver = Arc::new(ContextResolver::default());
    for (href, base, canonical, identity, body) in [
        (
            "imported.xsl",
            "https://example.test/styles/main.xsl",
            "https://example.test/modules/imported.xsl",
            "instruction-base-module",
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template name="emit"><item/></xsl:template></xsl:stylesheet>"#,
        ),
        (
            "data.xml",
            "https://example.test/modules/imported.xsl",
            "https://example.test/modules/data.xml",
            "instruction-base-data",
            "<doc>module</doc>",
        ),
    ] {
        resolver
            .resources
            .lock()
            .expect("test resolver mutex is not poisoned")
            .insert(
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
    let stylesheet = Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:exsl="http://exslt.org/common"><xsl:import href="imported.xsl"/><xsl:output method="text"/><xsl:template match="/"><xsl:variable name="tree"><xsl:call-template name="emit"/></xsl:variable><xsl:value-of select="document('data.xml', exsl:node-set($tree)/item)/doc"/></xsl:template></xsl:stylesheet>"#,
        Some("https://example.test/styles/main.xsl"),
    )
    .expect("stylesheet graph compiles");
    let output = stylesheet
        .execute(
            &Document::parse("<root/>", None).expect("source parses"),
            &Parameters::new(),
            resolver,
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("instruction-relative document resolves");

    assert_eq!(output.serialized.bytes, b"module");
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
fn html_doctype_uses_the_html_name_for_a_non_html_root() {
    // XSLT 1.0 section 16.2 fixes the HTML output DOCTYPE name independently of the result root.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#section-HTML-Output-Method
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="html" doctype-system="result.dtd" indent="no"/><xsl:template match="/"><custom/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<source/>"),
        "<!DOCTYPE html SYSTEM \"result.dtd\">\n<custom></custom>"
    );
}

#[test]
fn text_output_ignores_doctype_properties() {
    // XSLT 1.0 section 16.3 emits only result-tree text-node string-values; DOCTYPE properties
    // are not applicable to the text method.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#output
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text" doctype-system="ignored.dtd"/><xsl:template match="/"><root>payload</root></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "payload");
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
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:apply-templates select="section/section/item"/><xsl:text>|</xsl:text><xsl:number count="missing" format="(1)"/><xsl:text>|</xsl:text><xsl:number value="0" format="001"/><xsl:text>|</xsl:text><xsl:number value="-2" format="001"/><xsl:text>|</xsl:text><xsl:number value="0 div 0" format="001"/><xsl:text>|</xsl:text><xsl:number value="1 div 0" format="001"/></xsl:template><xsl:template match="item"><xsl:number level="any" count="section|item" from="section"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<section><section><item/></section></section>"),
        "1||0|-2|NaN|Infinity"
    );
}

#[test]
fn rtf_order_compares_every_node_selected_from_current() {
    // XPath node-set equality examines every RHS node, so a value present only after the first
    // selected child must still match the corresponding temporary-tree element name.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:exsl="http://exslt.org/common"><xsl:output method="text"/><xsl:template match="/"><xsl:apply-templates select="item"/></xsl:template><xsl:template match="item"><xsl:variable name="fragment"><a/><b/></xsl:variable><xsl:value-of select="count(exsl:node-set($fragment)/*[name() = current()/x]/preceding-sibling::*)"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<item><x>z</x><x>b</x></item>"), "1");
}

#[test]
fn rtf_order_fast_path_requires_the_exslt_common_namespace() {
    // XPath resolves function QNames through the expression's namespace context; a lexical
    // `exsl` prefix bound elsewhere must not acquire EXSLT semantics.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:exsl="urn:not-exslt"><xsl:output method="text"/><xsl:template match="/"><xsl:variable name="fragment"><a/><b/></xsl:variable><xsl:value-of select="count(exsl:node-set($fragment)/*[name() = name(current())]/preceding-sibling::*)"/></xsl:template></xsl:stylesheet>"#;
    assert!(matches!(
        compile(stylesheet).execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        ),
        Err(Error::Unsupported(message)) if message.contains("node-set")
    ));
}

#[test]
fn copied_namespaces_consume_result_node_budget() {
    // XPath 1.0 section 5.4 models each in-scope binding as a namespace node. Inserting one new
    // result binding must therefore consume the same node ceiling as elements and attributes.
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#namespace-nodes
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><out><xsl:copy-of select="/root/namespace::p"/></out></xsl:template></xsl:stylesheet>"#,
    );
    let source = Document::parse(r#"<root xmlns:p="urn:p"/>"#, None).expect("source parses");
    let mut budget = execution_budget(1024);
    budget.result_nodes = 1;
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
            kind: BudgetKind::ResultNodes,
            limit: 1,
            actual: 2,
        })
    ));
}

#[test]
fn copied_elements_charge_embedded_attribute_and_namespace_nodes() {
    // XPath 1.0 sections 5.2 and 5.4 model attributes and namespaces as nodes even though the
    // result arena stores them inside an element. Copying an element must charge the element, its
    // attribute, and both explicit and implicit namespace nodes before cloning retained data.
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#data-model
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:copy-of select="/root"/></xsl:template></xsl:stylesheet>"#,
    );
    let source = Document::parse(r#"<root xmlns:p="urn:p" id="1"/>"#, None).expect("source parses");
    let mut budget = execution_budget(1024);
    budget.result_nodes = 2;
    let error = stylesheet
        .execute(
            &source,
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect_err("embedded attributes and namespaces exceed two result nodes");
    assert!(
        matches!(
            &error,
            Error::Budget {
                kind: BudgetKind::ResultNodes,
                limit: 2,
                actual: 4,
            }
        ),
        "unexpected rejection: {error:?}"
    );
}

#[test]
fn generated_attribute_namespaces_consume_result_node_budget() {
    // Namespace fixup creates a real XPath namespace node in addition to the result element and
    // attribute, so the generated binding must consume the shared result-node budget.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><root><xsl:attribute name="p:id" namespace="urn:p">1</xsl:attribute></root></xsl:template></xsl:stylesheet>"#,
    );
    let source = Document::parse("<source/>", None).expect("source parses");
    let mut budget = execution_budget(1024);
    budget.result_nodes = 2;
    let error = stylesheet
        .execute(
            &source,
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect_err("element, generated namespace, and attribute exceed two result nodes");
    assert!(matches!(
        error,
        Error::Budget {
            kind: BudgetKind::ResultNodes,
            limit: 2,
            actual: 3,
        }
    ));
}

#[test]
fn level_any_numbering_resets_at_preceding_non_ancestor_boundary() {
    // The `from` boundary for level-any numbering is the most recent matching node in document
    // order, not only a matching ancestor of the node being numbered.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:apply-templates select="root/item[last()]"/></xsl:template><xsl:template match="item"><xsl:number level="any" count="item" from="reset"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<root><item/><reset/><item/></root>"),
        "1"
    );
    assert_eq!(execute(stylesheet, "<root><item/><item/></root>"), "2");
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
fn equal_precedence_decimal_formats_merge_explicit_properties() {
    // XSLT 1.0 section 12.3 merges declarations with the same name and precedence
    // property by property; defaults must not conflict with separately declared values.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#format-number
    let stylesheet = r#"
      <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
        <xsl:output method="text"/>
        <xsl:decimal-format name="d" infinity="Inf"/>
        <xsl:decimal-format name="d" NaN="Not a Number"/>
        <xsl:template match="/">
          <xsl:value-of select="format-number(1 div 0, '0', 'd')"/>
          <xsl:text>|</xsl:text>
          <xsl:value-of select="format-number(0 div 0, '0', 'd')"/>
        </xsl:template>
      </xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<root/>"), "Inf|Not a Number");

    let conflict = r#"
      <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
        <xsl:decimal-format name="d" infinity="Inf"/>
        <xsl:decimal-format name="d" infinity="Infinite"/>
      </xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(1 << 20, 0, 64, 1 << 20),
        )
            .compile(conflict, None),
        Err(Error::Static(message)) if message.contains("conflicting xsl:decimal-format")
    ));
}

#[test]
fn malformed_stylesheet_and_budget_exhaustion_are_typed() {
    // Static and resource failures must remain distinguishable to callers.
    let error = Compiler::new(Arc::new(NoResolver), CompileBudget::new(4096, 0, 64, 4096))
        .compile("<stylesheet/>", None)
        .expect_err("literal result stylesheet without xsl:version must fail");
    assert!(matches!(error, Error::Static(_)));

    let error = Compiler::new(
        Arc::new(NoResolver),
        CompileBudget::new(1 << 20, 0, 64, 1 << 20),
    )
    .compile(
        r#"<xsl:template xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xsl:version="1.0" match="/"/>"#,
        None,
    )
    .expect_err("an XSLT instruction cannot be a simplified stylesheet root");
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
                    pattern_evaluations: 1,
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
fn xinclude_preserves_xpath_text_node_boundaries() {
    // XPath 1.0 section 5.7 requires maximal text nodes even when XInclude inserts character
    // information items between text already present in the source infoset.
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#section-Text-Nodes
    let resolver = Arc::new(ContextResolver::default());
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert(
            ("value.txt".into(), Some("memory:source.xml".into())),
            ResolvedResource {
                canonical_uri: "memory:value.txt".into(),
                identity: ResourceIdentity("xinclude-text-boundary".into()),
                bytes: b"included".to_vec(),
                media_type: Some("text/plain".into()),
                encoding: Some("UTF-8".into()),
            },
        );
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="count(root/text())"/><xsl:text>|</xsl:text><xsl:value-of select="root"/></xsl:template></xsl:stylesheet>"#,
    );
    let source = Document::parse(
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude">before<xi:include href="value.txt" parse="text"/>after</root>"#,
        Some("memory:source.xml"),
    )
    .expect("XInclude source parses");
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
            SourceProcessing::XInclude,
        )
        .expect("text inclusion succeeds");
    assert_eq!(result.serialized.bytes, b"1|beforeincludedafter");
}

#[test]
fn xinclude_preserves_principal_unparsed_entities() {
    // XInclude 1.0 section 4.5.1 preserves unparsed-entity metadata in the result infoset;
    // enabling XInclude must not erase metadata when the source contains no include element.
    // https://www.w3.org/TR/xinclude/#unparsed-entities
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="unparsed-entity-uri('logo')"/></xsl:template></xsl:stylesheet>"#,
    );
    let mut source =
        Document::parse("<root/>", Some("memory:source.xml")).expect("source document parses");
    source
        .register_unparsed_entity("logo", "memory:logo.png")
        .expect("entity metadata registers");
    let result = stylesheet
        .execute_with_source_processing(
            &source,
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
            SourceProcessing::XInclude,
        )
        .expect("XInclude projection preserves document metadata");
    assert_eq!(result.serialized.bytes, b"memory:logo.png");
}

#[test]
fn internal_dtd_defaults_and_unparsed_entities_reach_xpath() {
    // XML 1.0 sections 3.3.2 and 4.2.2 require internal attribute defaults and unparsed
    // entity metadata to reach the document information set consumed by XSLT.
    // https://www.w3.org/TR/xml/#AVNormalize
    // https://www.w3.org/TR/xml/#sec-external-ent
    let stylesheet = r#"<xsl:stylesheet version="1.0"
        xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
        <xsl:output method="text"/>
        <xsl:template match="/">
          <xsl:value-of select="/root/@status"/>
          <xsl:text>|</xsl:text>
          <xsl:value-of select="/root/@tokens"/>
          <xsl:text>|</xsl:text>
          <xsl:value-of select="unparsed-entity-uri('logo')"/>
          <xsl:text>|</xsl:text>
          <xsl:value-of select="unparsed-entity-uri('public-logo')"/>
        </xsl:template>
      </xsl:stylesheet>"#;
    let source = r#"<!DOCTYPE root [
      <!ENTITY word "ok">
      <!ATTLIST root status CDATA "&word;" tokens NMTOKENS "  alpha   beta  ">
      <!ENTITY logo SYSTEM "logo.png" NDATA png>
      <!ENTITY public-logo PUBLIC "-//EXAMPLE//IMAGE" "public.png" NDATA png>
    ]><root/>"#;
    let stylesheet = compile(stylesheet);
    let source = Document::parse(source, Some("https://example.test/input/source.xml"))
        .expect("source with internal DTD declarations parses");
    let result = stylesheet
        .execute(
            &source,
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1 << 20),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("DTD metadata is available to XPath");
    assert_eq!(
        result.serialized.bytes,
        b"ok|alpha beta|https://example.test/input/logo.png|https://example.test/input/public.png"
    );

    let explicit = r#"<!DOCTYPE root [
      <!ATTLIST root status CDATA "default" tokens NMTOKENS "default">
    ]><root status="explicit" tokens="  gamma   delta  "/>"#;
    let explicit = Document::parse(explicit, None).expect("explicit attributes parse");
    let result = stylesheet
        .execute(
            &explicit,
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1 << 20),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("explicit attributes override DTD defaults");
    assert_eq!(result.serialized.bytes, b"explicit|gamma delta||");
}

#[test]
fn empty_unparsed_entity_system_identifier_reaches_xpath() {
    // XML 1.0 production [11] permits an empty SystemLiteral, and XSLT 1.0 section 12.4
    // exposes that exact URI through unparsed-entity-uri().
    // https://www.w3.org/TR/xml/#NT-SystemLiteral
    // https://www.w3.org/TR/1999/REC-xslt-19991116#function-unparsed-entity-uri
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="unparsed-entity-uri('logo')"/></xsl:template></xsl:stylesheet>"#,
    );
    let source = Document::parse(
        r#"<!DOCTYPE root [<!NOTATION png SYSTEM "image/png"><!ENTITY logo SYSTEM "" NDATA png>]><root/>"#,
        None,
    )
    .expect("empty system identifier is well-formed");
    let result = stylesheet
        .execute(
            &source,
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(4096),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("empty unparsed-entity URI remains XPath-visible");
    assert!(result.serialized.bytes.is_empty());
}

#[test]
fn compile_owned_bytes_counts_empty_instruction_structure() {
    // Empty literal-result elements retain DOM nodes, instruction variants, and child vectors even
    // though their lexical payload is tiny. CompileBudget must bound that structure, not just text.
    let elements = "<a/>".repeat(2_000);
    let stylesheet = format!(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/">{elements}</xsl:template></xsl:stylesheet>"#
    );
    let error = Compiler::new(
        Arc::new(NoResolver),
        CompileBudget::new(stylesheet.len(), 0, 256, 256 * 1024),
    )
    .compile(&stylesheet, None)
    .expect_err("retained instruction structure must exceed the owned-byte budget");
    assert!(matches!(
        error,
        Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        }
    ));
}

#[test]
fn namespace_name_validation_matches_xslt_1_0_compatibility() {
    // XSLT 1.0 uses the XML Namespaces 1.0 definition, which permits relative URI references;
    // RFC 2396 section 4 classifies a fragment-only reference as relative as well.
    // https://www.w3.org/TR/REC-xml-names/#ns-decl
    // https://www.rfc-editor.org/rfc/rfc2396#section-4
    compile(
        r#"<xsl:stylesheet version="1.0"
             xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
             xmlns:local="data_local_to_this_file">
             <xsl:template match="/"><local:result/></xsl:template>
           </xsl:stylesheet>"#,
    );

    let stylesheet = compile(
        r##"<xsl:stylesheet version="1.0"
             xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
             xmlns:local="#fragment">
             <xsl:variable name="local:value" select="'accepted'"/>
             <xsl:template match="/"><xsl:value-of select="$local:value"/></xsl:template>
           </xsl:stylesheet>"##,
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
        .expect("fragment namespace variable executes");
    assert_eq!(
        result.serialized.bytes,
        b"<?xml version=\"1.0\"?>\naccepted\n"
    );
}

#[test]
fn stylesheet_uses_internal_dtd_attribute_defaults() {
    // XML 1.0 section 3.3.2 requires defaulted attributes to be reported to the application.
    // https://www.w3.org/TR/xml/#sec-attr-defaults
    let stylesheet = r#"<!DOCTYPE xsl:stylesheet [
      <!ATTLIST xsl:stylesheet version CDATA "1.0">
      <!ATTLIST xsl:output method CDATA "text">
    ]><xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output/><xsl:template match="/">defaulted</xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "defaulted");

    let explicit = stylesheet.replace("<xsl:output/>", "<xsl:output method=\"xml\"/>");
    assert!(execute(&explicit, "<source/>").starts_with("<?xml"));
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
fn empty_document_uri_from_an_external_tree_returns_that_tree() {
    // XSLT 1.0 section 12.1 makes a zero-length URI refer to the document that supplies its base;
    // a nested document() call must not send that URI back through the external resolver.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#document
    let resolver = Arc::new(MemoryResolver::default());
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert(
            "external.xml".into(),
            "<doc origin=\"external\"><uri/></doc>".into(),
        );
    let stylesheet = Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="document(document('external.xml')/doc/uri)/doc/@origin"/></xsl:template></xsl:stylesheet>"#,
        Some("memory:main.xsl"),
    )
    .expect("stylesheet compiles");
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
        .expect("external document owns its empty-URI alias");
    assert_eq!(output.serialized.bytes, b"external");
}

#[test]
fn external_document_paths_and_axes_use_the_dynamic_document_root() {
    // XPath 1.0 sections 2.1 and 2.2 bind absolute paths and document-order axes to the
    // document containing the current predicate or axis context node.
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#location-paths
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#axes
    let resolver = Arc::new(MemoryResolver::default());
    resolver.resources.lock().expect("resolver mutex").insert(
        "external.xml".into(),
        "<external><flag/><item>selected</item><a>before</a><b>after</b></external>".into(),
    );
    let stylesheet = Compiler::new(
        Arc::clone(&resolver),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="count(document('external.xml')/external/item[/external/flag])"/><xsl:text>|</xsl:text><xsl:value-of select="document('external.xml')/external/a/following::b"/><xsl:text>|</xsl:text><xsl:value-of select="document('external.xml')/external/b/preceding::a"/></xsl:template></xsl:stylesheet>"#,
        Some("memory:main.xsl"),
    )
    .expect("stylesheet compiles");
    let result = stylesheet
        .execute(
            &Document::parse("<source/>", Some("memory:source.xml")).expect("source parses"),
            &Parameters::new(),
            resolver,
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("external document paths evaluate");
    assert_eq!(result.serialized.bytes, b"1|after|before");
}

#[test]
fn key_uses_the_dynamic_document_index() {
    // XSLT 1.0 section 12.2 binds key() to the document containing the context node,
    // including trees loaded by document().
    // https://www.w3.org/TR/1999/REC-xslt-19991116#key
    let resolver = Arc::new(MemoryResolver::default());
    resolver.resources.lock().expect("resolver mutex").insert(
        "external.xml".into(),
        r#"<external><item id="wanted">external</item></external>"#.into(),
    );
    let stylesheet = Compiler::new(
        Arc::clone(&resolver),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:key name="by-id" match="item" use="@id"/><xsl:template match="/"><xsl:apply-templates select="document('external.xml')/external"/></xsl:template><xsl:template match="external"><xsl:value-of select="key('by-id', 'wanted')"/></xsl:template></xsl:stylesheet>"#,
        Some("memory:main.xsl"),
    )
    .expect("stylesheet compiles");
    let result = stylesheet
        .execute(
            &Document::parse("<source/>", Some("memory:source.xml")).expect("source parses"),
            &Parameters::new(),
            resolver,
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("dynamic document functions evaluate");
    assert_eq!(result.serialized.bytes, b"external");
}

#[test]
fn document_function_uses_the_actual_predicate_candidate_context() {
    // Each predicate candidate supplies its own @href to document(), not the outer root context.
    let resolver = Arc::new(MemoryResolver::default());
    let mut resources = resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned");
    resources.insert("empty.xml".into(), "<empty/>".into());
    resources.insert("match.xml".into(), "<doc/>".into());
    drop(resources);
    let stylesheet = Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="count(root/item[document(@href)/doc])"/></xsl:template></xsl:stylesheet>"#,
        Some("memory:main.xsl"),
    )
    .expect("stylesheet compiles");
    let result = stylesheet
        .execute(
            &Document::parse(
                r#"<root><item href="empty.xml"/><item href="match.xml"/></root>"#,
                Some("memory:source.xml"),
            )
            .expect("source parses"),
            &Parameters::new(),
            resolver,
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("predicate document calls resolve");
    assert_eq!(
        String::from_utf8(result.serialized.bytes).expect("UTF-8 output"),
        "1"
    );
}

#[test]
fn id_function_uses_the_predicate_context_document() {
    // XPath 1.0 section 4.1 resolves id() in the document containing the dynamic context node.
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#function-id
    let resolver = Arc::new(MemoryResolver::default());
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert(
            "external.xml".into(),
            r#"<external xml:id="target" value="external"/>"#.into(),
        );
    let stylesheet = Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="document('external.xml')/*[generate-id(id('target')) = generate-id(.)]/@value"/></xsl:template></xsl:stylesheet>"#,
        Some("memory:main.xsl"),
    )
    .expect("stylesheet compiles");
    let result = stylesheet
        .execute(
            &Document::parse(
                r#"<source xml:id="target" value="principal"/>"#,
                Some("memory:source.xml"),
            )
            .expect("source parses"),
            &Parameters::new(),
            resolver,
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("external id lookup executes");

    assert_eq!(result.serialized.bytes, b"external");
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
fn document_function_preserves_an_explicitly_missing_base_uri() {
    // Supplying a second-argument node with no base is distinct from omitting that argument;
    // the stylesheet module base must not silently replace the explicit absence.
    let resolver = Arc::new(ContextResolver::default());
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert(
            ("relative.xml".into(), None),
            ResolvedResource {
                canonical_uri: "memory:relative.xml".into(),
                identity: ResourceIdentity("relative-without-base".into()),
                bytes: b"<doc>resolved without base</doc>".to_vec(),
                media_type: Some("application/xml".into()),
                encoding: Some("UTF-8".into()),
            },
        );
    let stylesheet = Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="document('relative.xml', root/base)/doc"/></xsl:template></xsl:stylesheet>"#,
        Some("memory:main.xsl"),
    )
    .expect("stylesheet compiles");
    let output = stylesheet
        .execute(
            &Document::parse("<root><base/></root>", None).expect("source parses"),
            &Parameters::new(),
            resolver.clone(),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("explicitly absent base resolves without fallback");
    assert_eq!(output.serialized.bytes, b"resolved without base");
    assert!(
        resolver
            .calls
            .lock()
            .expect("test resolver mutex is not poisoned")
            .iter()
            .any(|(href, base, purpose)| href == "relative.xml"
                && base.is_none()
                && *purpose == ResolvePurpose::Document)
    );
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
    let default_xml = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><root/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(default_xml, "<source/>"),
        "<?xml version=\"1.0\"?>\n<root/>\n"
    );
    let explicit_utf8 = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output encoding="UTF-8"/><xsl:template match="/"><root/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(explicit_utf8, "<source/>"),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root/>\n"
    );

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

    // XSLT 1.0 section 16.2 recommends generated content-type metadata. The pinned libxslt
    // contract uses HTML5 syntax and replaces its legacy equivalent, while unrelated metadata
    // remains intact.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#section-HTML-Output-Method
    let existing_html_meta = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="html" indent="no"/><xsl:template match="/"><html><head><meta http-equiv="Content-Type" content="text/plain; charset=ISO-8859-1" data-owner="caller"/></head></html></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(existing_html_meta, "<source/>"),
        r#"<html><head><meta charset="UTF-8"></head></html>"#,
    );
    let existing_charset_meta = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="html" indent="no"/><xsl:template match="/"><html><head><meta charset="ISO-8859-1" data-owner="caller"/></head></html></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(existing_charset_meta, "<source/>"),
        r#"<html><head><meta charset="UTF-8"><meta charset="ISO-8859-1" data-owner="caller"></head></html>"#,
    );

    let foreign_head = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:f="urn:foreign"><xsl:output method="html" indent="no"/><xsl:template match="/"><f:head><f:meta charset="kept"/></f:head></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(foreign_head, "<source/>"),
        r#"<f:head xmlns:f="urn:foreign"><f:meta charset="kept"></f:meta></f:head>"#
    );

    let legacy_html_namespace = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="html" indent="no"/><xsl:template match="/"><head xmlns="http://www.w3.org/TR/REC-html40"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(legacy_html_namespace, "<source/>"),
        r#"<head xmlns="http://www.w3.org/TR/REC-html40"><meta charset="UTF-8"></head>"#
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
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(4096, 0, 256, 64 * 1024),
        )
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
fn scalar_arithmetic_fast_path_preserves_variable_types() {
    // XPath number(boolean) is 1 or 0; converting through "true" would incorrectly produce NaN.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:param name="flag"/><xsl:template match="/"><xsl:value-of select="$flag + 1"/></xsl:template></xsl:stylesheet>"#,
    );
    for (flag, expected) in [(true, "2"), (false, "1")] {
        let mut parameters = Parameters::new();
        parameters.insert(
            ExpandedName::new(None::<String>, "flag"),
            Value::Boolean(flag),
        );
        let result = stylesheet
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
            .expect("typed arithmetic succeeds");
        assert_eq!(
            String::from_utf8(result.serialized.bytes).expect("UTF-8 output"),
            expected
        );
    }
}

#[test]
fn result_tree_fragment_preceding_sibling_count_uses_the_full_node_set() {
    // The union of preceding siblings for repeated matches is determined by the last match.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:exsl="http://exslt.org/common"><xsl:output method="text"/><xsl:template match="/"><xsl:variable name="fragment"><a/><b/><a/></xsl:variable><xsl:value-of select="count(exsl:node-set($fragment)/*[name() = 'a']/preceding-sibling::*)"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "2");
}

#[test]
fn result_tree_fragment_order_fast_path_accounts_for_target_strings() {
    // Source string-values retained for the optimized RTF ordering predicate are temporary but
    // simultaneously live, so their complete payload must increase the peak OwnedBytes budget.
    let payload = "target".repeat(16 * 1024);
    let source_xml = format!("<source><target>{payload}</target></source>");
    let source = Document::parse(&source_xml, None).expect("source parses");
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:exsl="http://exslt.org/common"><xsl:output method="text"/><xsl:template name="baseline"><xsl:variable name="fragment"><a/><b/></xsl:variable><xsl:value-of select="count(exsl:node-set($fragment)/*)"/></xsl:template><xsl:template name="targets"><xsl:variable name="fragment"><a/><b/></xsl:variable><xsl:value-of select="count(exsl:node-set($fragment)/*[name() = current()/source/target]/preceding-sibling::*)"/></xsl:template></xsl:stylesheet>"#,
    );
    let minimum = |initial_template: &str| {
        let succeeds = |owned_bytes| {
            let mut budget = execution_budget(source_xml.len());
            budget.owned_bytes = owned_bytes;
            stylesheet
                .execute(
                    &source,
                    &Parameters::new(),
                    Arc::new(NoResolver),
                    ExecutionOptions {
                        budget,
                        initial_mode: None,
                        initial_template: Some(ExpandedName::new(None::<String>, initial_template)),
                    },
                )
                .is_ok()
        };
        let mut rejected = 0;
        let mut accepted = 1;
        while !succeeds(accepted) {
            rejected = accepted;
            accepted *= 2;
        }
        while rejected + 1 < accepted {
            let candidate = rejected + (accepted - rejected) / 2;
            if succeeds(candidate) {
                accepted = candidate;
            } else {
                rejected = candidate;
            }
        }
        accepted
    };
    let baseline = minimum("baseline");
    let targets = minimum("targets");
    assert!(
        targets + 16 * 1024 >= baseline + payload.len(),
        "baseline={baseline}, targets={targets}, payload={}",
        payload.len()
    );
}

#[test]
fn empty_result_tree_fragment_remains_truthy_in_generic_xpath() {
    // XSLT 1.0 RTF boolean conversion is true even when its constructed root has no children.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:variable name="fragment"><xsl:if test="false()">unreachable</xsl:if></xsl:variable><xsl:value-of select="not($fragment)"/><xsl:text>|</xsl:text><xsl:value-of select="string($fragment)"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "false|");
}

#[test]
fn exslt_padding_uses_each_predicate_candidate_context() {
    // Extension arguments inside predicates must be evaluated for each candidate node.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:str="http://exslt.org/strings"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="count(root/item[str:padding(@width, 'x') = 'xx'])"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(
            stylesheet,
            "<root><item width=\"1\"/><item width=\"2\"/></root>"
        ),
        "1"
    );
}

#[test]
fn exslt_tokenize_defaults_to_all_xml_whitespace() {
    // Omitted str:tokenize delimiters are XML S; str:split retains its separate space default.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:str="http://exslt.org/strings"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="count(str:tokenize(concat('a', '&#10;', 'b', '&#9;', 'c', '&#13;', 'd')))"/><xsl:text>|</xsl:text><xsl:value-of select="count(str:split(concat('a', '&#10;', 'b')))"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "4|1");
}

#[test]
fn execution_environment_controls_exslt_current_time() {
    // Ambient clock access is explicit and can be fixed or prohibited for security transforms.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:date="http://exslt.org/dates-and-times"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="date:year()"/></xsl:template></xsl:stylesheet>"#,
    );
    let fixed = time::OffsetDateTime::from_unix_timestamp(0).expect("Unix epoch is valid");
    let result = stylesheet
        .execute_with_environment(
            &Document::parse("<source/>", None).expect("source parses"),
            &Parameters::new(),
            ExecutionEnvironment::new(Arc::new(NoResolver))
                .with_clock(Arc::new(FixedClock::new(fixed))),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("fixed operation time is available");
    assert_eq!(
        String::from_utf8(result.serialized.bytes).expect("UTF-8 output"),
        "1970"
    );

    let error = stylesheet
        .execute_with_environment(
            &Document::parse("<source/>", None).expect("source parses"),
            &Parameters::new(),
            ExecutionEnvironment::new(Arc::new(NoResolver))
                .with_extension_policy(ExtensionPolicy::Deterministic),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect_err("deterministic policy rejects ambient current time");
    assert!(matches!(
        error,
        Error::Dynamic(message) if message.contains("disabled") && message.contains("extension policy")
    ));
}

#[test]
fn exslt_current_time_rejects_non_xsd_timezone_offsets() {
    // XML Schema 1.0 Part 2 section 3.2.7.3 permits only minute-aligned offsets through +/-14:00.
    // https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime-timezones
    #[derive(Debug)]
    struct InvalidOffsetClock(time::UtcOffset);

    impl Clock for InvalidOffsetClock {
        fn now_local(&self) -> xml_sec_xslt::Result<time::OffsetDateTime> {
            Ok(time::OffsetDateTime::UNIX_EPOCH.to_offset(self.0))
        }
    }

    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:date="http://exslt.org/dates-and-times"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="date:date-time()"/></xsl:template></xsl:stylesheet>"#,
    );
    let source = Document::parse("<source/>", None).expect("source parses");
    for offset in [
        time::UtcOffset::from_hms(15, 0, 0).expect("test offset is representable"),
        time::UtcOffset::from_hms(1, 2, 3).expect("test offset is representable"),
    ] {
        let error = stylesheet
            .execute_with_environment(
                &source,
                &Parameters::new(),
                ExecutionEnvironment::new(Arc::new(NoResolver))
                    .with_clock(Arc::new(InvalidOffsetClock(offset))),
                ExecutionOptions {
                    budget: execution_budget(1024),
                    initial_mode: None,
                    initial_template: None,
                },
            )
            .expect_err("non-XSD timezone offset must be rejected");
        assert!(
            matches!(error, Error::Dynamic(message) if message.contains("timezone offset") && message.contains("XML Schema"))
        );
    }
}

#[test]
fn zero_argument_exslt_seconds_uses_the_execution_clock_and_policy() {
    // EXSLT date:seconds defines an omitted argument as the current local date-time, so the
    // operation must use the configured clock and reject ambient time in deterministic mode.
    // https://exslt.github.io/date/functions/seconds/date.seconds.html
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:date="http://exslt.org/dates-and-times"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="date:seconds()"/></xsl:template></xsl:stylesheet>"#,
    );
    let source = Document::parse("<source/>", None).expect("source parses");
    let fixed = time::OffsetDateTime::from_unix_timestamp(0).expect("Unix epoch is valid");
    let result = stylesheet
        .execute_with_environment(
            &source,
            &Parameters::new(),
            ExecutionEnvironment::new(Arc::new(NoResolver))
                .with_clock(Arc::new(FixedClock::new(fixed))),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("fixed operation time is available");
    assert_eq!(result.serialized.bytes, b"0");

    let error = stylesheet
        .execute_with_environment(
            &source,
            &Parameters::new(),
            ExecutionEnvironment::new(Arc::new(NoResolver))
                .with_extension_policy(ExtensionPolicy::Deterministic),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect_err("deterministic execution rejects current-time access");
    assert!(
        matches!(error, Error::Dynamic(message) if message.contains("execution extension policy"))
    );
}

#[test]
fn zero_argument_exslt_duration_uses_the_execution_clock_and_policy() {
    // EXSLT date:duration defines its omitted argument as date:seconds(), so both functions must
    // share the configured operation clock and deterministic-policy gate.
    // https://exslt.github.io/date/functions/duration/date.duration.html
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:date="http://exslt.org/dates-and-times"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="date:duration()"/></xsl:template></xsl:stylesheet>"#,
    );
    let source = Document::parse("<source/>", None).expect("source parses");
    let fixed = time::OffsetDateTime::from_unix_timestamp(86_400).expect("test time is valid");
    let result = stylesheet
        .execute_with_environment(
            &source,
            &Parameters::new(),
            ExecutionEnvironment::new(Arc::new(NoResolver))
                .with_clock(Arc::new(FixedClock::new(fixed))),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("fixed operation time is available");
    assert_eq!(result.serialized.bytes, b"P1D");

    let error = stylesheet
        .execute_with_environment(
            &source,
            &Parameters::new(),
            ExecutionEnvironment::new(Arc::new(NoResolver))
                .with_extension_policy(ExtensionPolicy::Deterministic),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect_err("deterministic execution rejects current-time access");
    assert!(
        matches!(error, Error::Dynamic(message) if message.contains("execution extension policy"))
    );
}

#[test]
fn exslt_date_arithmetic_normalizes_common_precision_before_calculation() {
    // EXSLT date:difference truncates both operands to the least-specific input before subtraction.
    // https://exslt.github.io/date/functions/difference/date.difference.1.html
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:date="http://exslt.org/dates-and-times"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="date:difference('2001', '2000-02')"/><xsl:text>|</xsl:text><xsl:value-of select="date:difference('2000-02', '2001')"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "-P1Y|P1Y");
}

#[test]
fn exslt_add_promotes_a_year_when_lower_order_components_are_added() {
    // EXSLT date:add promotes gYear to gYearMonth before applying any non-year component.
    // https://exslt.github.io/date/functions/add/date.add.2.html
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:date="http://exslt.org/dates-and-times"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="date:add('2000', 'P1M')"/><xsl:text>|</xsl:text><xsl:value-of select="date:add('2000', 'P13M')"/><xsl:text>|</xsl:text><xsl:value-of select="date:add('2000', '-P1M')"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "2000-02|2001-02|1999-12");
}

#[test]
fn compound_substring_length_uses_the_general_xpath_evaluator() {
    // The specialized path is valid only for `$QName * number`; compound arithmetic must retain
    // XPath 1.0 operator precedence in the general evaluator.
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#section-String-Functions
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:param name="x" select="2"/><xsl:param name="y" select="1"/><xsl:template match="/"><xsl:value-of select="substring ('abcdef', 0, $x + $y * 2)"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "abc");
}

#[test]
fn compound_substring_variables_use_the_general_xpath_evaluator() {
    // Scalar fast paths may capture only a lexical variable QName. XPath operators in either
    // captured operand must fall through so the general evaluator preserves XPath 1.0 semantics.
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#section-String-Functions
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:param name="x" select="2"/><xsl:param name="y" select="3"/><xsl:param name="left" select="/root/left"/><xsl:param name="right" select="/root/right"/><xsl:param name="prefix" select="/root/prefix"/><xsl:param name="other" select="/root/other"/><xsl:template match="/"><xsl:value-of select="substring-before($x + $y, '5')"/><xsl:text>|</xsl:text><xsl:value-of select="substring($left | $right, string-length($prefix)+1)"/><xsl:text>|</xsl:text><xsl:value-of select="substring($left, string-length($prefix | $other)+1)"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(
            stylesheet,
            "<root><left>abcd</left><right>ignored</right><prefix>x</prefix><other>yy</other></root>"
        ),
        "|bcd|bcd"
    );
}

#[test]
fn compound_substring_delimiter_uses_the_general_xpath_evaluator() {
    // The optimized delimiter must be one XPath Literal token. Treating a compound expression
    // with matching outer quotes as that token changes its boolean-to-string conversion.
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#NT-Literal
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:param name="value" select="&quot;xxa' or 'byy&quot;"/><xsl:template match="/"><xsl:value-of select="substring-before($value, 'a' or 'b')"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "");
}

#[test]
fn two_argument_substring_handles_negative_infinity_without_an_upper_bound() {
    // XPath 1.0 section 4.2 defines the two-argument form by positions at or after the rounded
    // start; it has no synthetic upper bound that can become NaN through infinity arithmetic.
    // https://www.w3.org/TR/1999/REC-xpath-19991116#function-substring
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="substring('abc', -1 div 0)"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "abc");
}

#[test]
fn exslt_durations_allow_fractional_syntax_only_for_seconds() {
    // XML Schema 1.0 erratum E2-23 requires digits after a decimal point, but libxslt accepts a
    // trailing point in seconds. Preserve that pinned-oracle exception without accepting decimal
    // spellings for any other duration component.
    // https://www.w3.org/2001/05/xmlschema-errata#e2-23
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:date="http://exslt.org/dates-and-times"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="date:add-duration('P1.0Y', 'P1Y')"/><xsl:text>|</xsl:text><xsl:value-of select="date:add-duration('P1.0M', 'P1M')"/><xsl:text>|</xsl:text><xsl:value-of select="date:add-duration('P1.0D', 'P1D')"/><xsl:text>|</xsl:text><xsl:value-of select="date:add-duration('PT1.0H', 'PT1H')"/><xsl:text>|</xsl:text><xsl:value-of select="date:add-duration('PT1.0M', 'PT1M')"/><xsl:text>|</xsl:text><xsl:value-of select="date:add-duration('PT1.S', 'PT1S')"/><xsl:text>|</xsl:text><xsl:value-of select="date:add-duration('PT0.5S', 'PT0.5S')"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "|||||PT2S|PT1S");
}

#[test]
fn exslt_duration_arithmetic_rejects_unrenderable_results() {
    // All duration-producing operations must fail closed instead of exposing Rust's saturating
    // float-to-integer cast as a plausible duration value.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:date="http://exslt.org/dates-and-times"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="date:add-duration('PT1000000000000000000000000000000S', 'PT1S')"/><xsl:text>|</xsl:text><xsl:value-of select="date:sum(/root/duration)"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(
            stylesheet,
            "<root><duration>PT1000000000000000000000000000000S</duration></root>"
        ),
        "|"
    );
}

#[test]
fn exslt_current_date_functions_share_the_execution_clock_and_policy() {
    // Core EXSLT current-date functions must be discoverable and use the same controlled clock
    // as zero-argument component functions; deterministic execution rejects ambient time access.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:date="http://exslt.org/dates-and-times"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="function-available('date:date-time')"/><xsl:text>|</xsl:text><xsl:value-of select="function-available('date:date')"/><xsl:text>|</xsl:text><xsl:value-of select="date:date-time()"/><xsl:text>|</xsl:text><xsl:value-of select="date:date()"/></xsl:template></xsl:stylesheet>"#,
    );
    let fixed = time::OffsetDateTime::from_unix_timestamp(0).expect("Unix epoch is valid");
    let source = Document::parse("<source/>", None).expect("source parses");
    let result = stylesheet
        .execute_with_environment(
            &source,
            &Parameters::new(),
            ExecutionEnvironment::new(Arc::new(NoResolver))
                .with_clock(Arc::new(FixedClock::new(fixed))),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("fixed current-date functions execute");
    assert_eq!(
        String::from_utf8(result.serialized.bytes).expect("UTF-8 output"),
        "true|true|1970-01-01T00:00:00+00:00|1970-01-01Z"
    );

    let error = stylesheet
        .execute_with_environment(
            &source,
            &Parameters::new(),
            ExecutionEnvironment::new(Arc::new(NoResolver))
                .with_extension_policy(ExtensionPolicy::Deterministic),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect_err("deterministic execution rejects current-date functions");
    assert!(
        matches!(error, Error::Dynamic(message) if message.contains("execution extension policy"))
    );
}

#[test]
fn exslt_clock_years_use_xml_schema_numbering() {
    // `time` exposes astronomical years, while XML Schema has no year zero.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:date="http://exslt.org/dates-and-times"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="date:date-time()"/><xsl:text>|</xsl:text><xsl:value-of select="date:date()"/></xsl:template></xsl:stylesheet>"#,
    );
    let source = Document::parse("<source/>", None).expect("source parses");
    for (astronomical_year, schema_year) in [(0, "-0001"), (-1, "-0002")] {
        let fixed = time::Date::from_calendar_date(astronomical_year, time::Month::January, 1)
            .expect("test year is representable")
            .midnight()
            .assume_utc();
        let result = stylesheet
            .execute_with_environment(
                &source,
                &Parameters::new(),
                ExecutionEnvironment::new(Arc::new(NoResolver))
                    .with_clock(Arc::new(FixedClock::new(fixed))),
                ExecutionOptions {
                    budget: execution_budget(1024),
                    initial_mode: None,
                    initial_template: None,
                },
            )
            .expect("fixed pre-Common-Era time executes");
        assert_eq!(
            String::from_utf8(result.serialized.bytes).expect("UTF-8 output"),
            format!("{schema_year}-01-01T00:00:00+00:00|{schema_year}-01-01Z")
        );
    }
}

#[test]
fn optimized_addition_distinguishes_xpath_names_from_numbers() {
    // Rust accepts `NaN` as a float, but XPath parses it as a child-name test.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:apply-templates select="root"/></xsl:template><xsl:template match="root"><xsl:variable name="x" select="1"/><xsl:value-of select="$x + NaN"/><xsl:text>|</xsl:text><xsl:value-of select="substring ('abcdef', 0, $x * NaN)"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<root><NaN>5</NaN></root>"), "6|abcd");
}

#[test]
fn xpath_normalization_rejects_non_xml_whitespace() {
    // NBSP is an XML character but not XPath whitespace and must not repair invalid syntax.
    for stylesheet in [
        "<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"><xsl:template match=\"/\"><xsl:value-of select=\"count\u{a0}(*)\"/></xsl:template></xsl:stylesheet>",
        "<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"><xsl:template match=\"/\"><xsl:value-of select=\"/\u{a0}\"/></xsl:template></xsl:stylesheet>",
    ] {
        assert!(matches!(
            Compiler::new(
                Arc::new(NoResolver),
                CompileBudget::new(4096, 0, 32, 64 * 1024),
            )
                .compile(stylesheet, None),
            Err(Error::Static(message)) if message.contains("invalid XPath")
        ));
    }
}

#[test]
fn standard_stylesheets_reject_top_level_character_data() {
    // XSLT 1.0 section 2.2 strips top-level XML whitespace but does not permit other character
    // data among declarations: https://www.w3.org/TR/1999/REC-xslt-19991116#stylesheet-element
    let malformed = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">payload<xsl:template match="/"/></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(4096, 0, 32, 64 * 1024),
        )
            .compile(malformed, None),
        Err(Error::Static(message)) if message.contains("stylesheet top level")
    ));

    compile(
        "<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\">\n\t<xsl:template match=\"/\"/>\r\n</xsl:stylesheet>",
    );
}

#[test]
fn top_level_declarations_reject_unknown_unqualified_attributes() {
    // Every standard declaration has a closed XSLT 1.0 attribute contract.
    let declarations = [
        r#"<xsl:template match="/" bogus="yes"/>"#,
        r#"<xsl:variable name="value" bogus="yes"/>"#,
        r#"<xsl:output bogus="yes"/>"#,
        r#"<xsl:strip-space elements="*" bogus="yes"/>"#,
        r#"<xsl:key name="key" match="*" use="." bogus="yes"/>"#,
        r#"<xsl:decimal-format bogus="yes"/>"#,
        r##"<xsl:namespace-alias stylesheet-prefix="#default" result-prefix="#default" bogus="yes"/>"##,
        r#"<xsl:attribute-set name="set" bogus="yes"/>"#,
        r#"<func:function name="f:test" bogus="yes"><func:result select="1"/></func:function>"#,
        r#"<xsl:include href="memory:included.xsl" bogus="yes"/>"#,
        r#"<xsl:import href="memory:imported.xsl" bogus="yes"/>"#,
    ];
    for declaration in declarations {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:func="http://exslt.org/functions" xmlns:f="urn:functions" extension-element-prefixes="func">{declaration}</xsl:stylesheet>"#
        );
        assert!(matches!(
            Compiler::new(
                Arc::new(NoResolver),
                CompileBudget::new(4096, 0, 32, 64 * 1024),
            )
                .compile(&stylesheet, None),
            Err(Error::Static(message)) if message.contains("bogus")
        ));
    }

    let root_typo = r#"<xsl:stylesheet version="1.0" bogus="yes" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"/>"#;
    assert!(matches!(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(4096, 0, 32, 64 * 1024),
        )
            .compile(root_typo, None),
        Err(Error::Static(message)) if message.contains("bogus")
    ));

    compile(
        r#"<xsl:stylesheet version="2.0" bogus="yes" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/" future-option="yes"/></xsl:stylesheet>"#,
    );
}

#[test]
fn exslt_function_results_are_enforced_on_executed_paths() {
    // EXSLT func:result v3 distinguishes static placement rules from the number of results
    // instantiated at runtime: https://exslt.github.io/func/result/
    let conditional = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:func="http://exslt.org/functions" xmlns:f="urn:functions" extension-element-prefixes="func"><xsl:output method="text"/><func:function name="f:choose"><xsl:param name="condition"/><xsl:if test="$condition"><func:result select="'yes'"/></xsl:if><xsl:if test="not($condition)"><func:result select="'no'"/></xsl:if></func:function><xsl:template match="/"><xsl:value-of select="f:choose(true())"/><xsl:text>|</xsl:text><xsl:value-of select="f:choose(false())"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(conditional, "<source/>"), "yes|no");

    let duplicate = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:func="http://exslt.org/functions" xmlns:f="urn:functions" extension-element-prefixes="func"><func:function name="f:bad"><xsl:param name="condition"/><xsl:if test="$condition"><func:result select="1"/></xsl:if><func:result select="2"/></func:function><xsl:template match="/"><xsl:value-of select="f:bad(true())"/></xsl:template></xsl:stylesheet>"#,
    );
    assert!(matches!(
        duplicate.execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        ),
        Err(Error::Dynamic(message)) if message.contains("more than one result")
    ));

    let trailing_result = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:func="http://exslt.org/functions" xmlns:f="urn:functions" extension-element-prefixes="func"><func:function name="f:bad"><func:result select="1"/><func:result select="2"/></func:function></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(4096, 0, 32, 16 * 1024),
        )
        .compile(trailing_result, None),
        Err(Error::Static(message)) if message.contains("only be followed")
    ));

    for invalid in [
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:func="http://exslt.org/functions" xmlns:f="urn:functions" extension-element-prefixes="func"><func:function name="f:bad"><func:result><func:result select="2"/></func:result></func:function></xsl:stylesheet>"#,
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:func="http://exslt.org/functions" xmlns:f="urn:functions" extension-element-prefixes="func"><func:function name="f:bad"><xsl:variable name="value"><func:result select="2"/></xsl:variable></func:function></xsl:stylesheet>"#,
    ] {
        assert!(matches!(
            Compiler::new(
                Arc::new(NoResolver),
                CompileBudget::new(4096, 0, 32, 16 * 1024),
            )
            .compile(invalid, None),
            Err(Error::Static(_))
        ));
    }

    let fallback = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:func="http://exslt.org/functions" xmlns:f="urn:functions" extension-element-prefixes="func"><xsl:output method="text"/><func:function name="f:value"><func:result select="'ok'"/><xsl:fallback><xsl:text>ignored</xsl:text></xsl:fallback></func:function><xsl:template match="/"><xsl:value-of select="f:value()"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(fallback, "<source/>"), "ok");

    // EXSLT func:function "Function Results" defines no result as the empty string and generated
    // result nodes as errors: https://exslt.github.io/func/elements/function/index.html
    let no_result = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:func="http://exslt.org/functions" xmlns:f="urn:functions" extension-element-prefixes="func"><xsl:output method="text"/><func:function name="f:empty"/><xsl:template match="/"><xsl:value-of select="concat('[', f:empty(), ']')"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(no_result, "<source/>"), "[]");

    let generated_nodes = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:func="http://exslt.org/functions" xmlns:f="urn:functions" extension-element-prefixes="func"><func:function name="f:bad"><generated/></func:function><xsl:template match="/"><xsl:value-of select="f:bad()"/></xsl:template></xsl:stylesheet>"#,
    );
    assert!(matches!(
        generated_nodes.execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        ),
        Err(Error::Dynamic(message)) if message.contains("generated result nodes")
    ));
}

#[test]
fn exslt_function_names_require_a_namespace() {
    // EXSLT func:function requires a non-null namespace so a stylesheet function cannot replace
    // an XPath core function: https://exslt.github.io/func/elements/function/index.html
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:func="http://exslt.org/functions" extension-element-prefixes="func"><func:function name="concat"><func:result select="'shadowed'"/></func:function></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(4096, 0, 32, 64 * 1024),
        )
        .compile(stylesheet, None),
        Err(Error::Static(message)) if message.contains("namespace")
    ));
}

#[test]
fn built_in_template_rule_ignores_namespace_nodes() {
    // XSLT's built-in text rule copies attributes and text only; selected namespace nodes are
    // silent unless an explicit template handles them.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:apply-templates select="/*/namespace::*"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, r#"<root xmlns:p="urn:visible"/>"#), "");
}

#[test]
fn namespace_node_name_returns_its_prefix() {
    // XPath 1.0 section 4.1 defines name() for a namespace node as its namespace prefix.
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#function-name
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:for-each select="/*/namespace::*[name()='p']"><xsl:value-of select="concat('&lt;',name(.),'&gt;')"/></xsl:for-each></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, r#"<root xmlns:p="urn:visible"/>"#),
        "<p>"
    );
}

#[test]
fn stylesheet_functions_use_each_predicate_candidate_context() {
    // XPath 1.0 section 2.4 evaluates predicates with each candidate as the context node; a
    // stylesheet-defined function call inside that predicate must observe the same dynamic node.
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#predicates
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:func="http://exslt.org/functions" xmlns:f="urn:functions" extension-element-prefixes="func"><xsl:output method="text"/><func:function name="f:kept"><xsl:param name="candidate"/><func:result select="$candidate/@keep = 'yes'"/></func:function><xsl:template match="/"><xsl:for-each select="/*/item[f:kept(.)]"><xsl:value-of select="@id"/></xsl:for-each></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(
            stylesheet,
            r#"<root><item id="a" keep="no"/><item id="b" keep="yes"/></root>"#,
        ),
        "b"
    );
}

#[test]
fn stylesheet_functions_keep_context_inside_prepared_extension_arguments() {
    // Extension-call preparation must use the same stylesheet-function continuation as the outer
    // XPath evaluation; otherwise nesting changes the dynamic context or rejects a valid call.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:func="http://exslt.org/functions" xmlns:exsl="http://exslt.org/common" xmlns:f="urn:functions" extension-element-prefixes="func"><xsl:output method="text"/><func:function name="f:value"><xsl:param name="candidate"/><func:result select="$candidate/@id"/></func:function><xsl:template match="/"><xsl:for-each select="/*/item"><xsl:value-of select="concat(exsl:object-type(f:value(.)), ':', f:value(.))"/><xsl:text>;</xsl:text></xsl:for-each></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, r#"<root><item id="a"/><item id="b"/></root>"#,),
        "node-set:a;node-set:b;"
    );
}

#[test]
fn stylesheet_function_continuations_meter_retained_results() {
    // Each suspended call result survives the next XPath replay. Aggregate retained values must
    // consume OwnedBytes even when the final XPath result is only a boolean.
    let calls = std::iter::repeat_n("string-length(f:value(.)) > 0", 16)
        .collect::<Vec<_>>()
        .join(" and ");
    let stylesheet = compile(&format!(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:func="http://exslt.org/functions" xmlns:f="urn:functions" extension-element-prefixes="func"><xsl:output method="text"/><func:function name="f:value"><xsl:param name="candidate"/><func:result select="string($candidate)"/></func:function><xsl:template match="/"><xsl:value-of select="{calls}"/></xsl:template></xsl:stylesheet>"#,
    ));
    let source = format!("<source>{}</source>", "x".repeat(32 * 1024));
    let mut budget = execution_budget(source.len());
    budget.owned_bytes = 512 * 1024;
    assert!(matches!(
        stylesheet.execute(
            &Document::parse(&source, None).expect("source parses"),
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
fn built_in_template_rule_ignores_namespace_nodes_in_captured_fragments() {
    // Capturing output must not select a separate built-in-rule implementation: XSLT 1.0 section
    // 5.8 defines no built-in rule that emits namespace-node string values.
    // https://www.w3.org/TR/xslt-10/#built-in-rule
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:variable name="captured"><xsl:apply-templates select="/*/namespace::*"/></xsl:variable><xsl:value-of select="$captured"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, r#"<root xmlns:p="urn:visible"/>"#), "");
}

#[test]
fn inert_exslt_function_does_not_exclude_its_name_namespace() {
    // EXSLT declarations become instructions only when their namespace is designated through
    // extension-element-prefixes. Foreign top-level data must not affect namespace copying.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#extension
    let stylesheet = r#"<xsl:stylesheet version="1.0"
        xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
        xmlns:func="http://exslt.org/functions" xmlns:f="urn:functions"
        xmlns:exsl="http://exslt.org/common">
      <xsl:output method="text"/>
      <func:function name="f:inert"/>
      <xsl:template match="/">
        <xsl:variable name="tree"><out/></xsl:variable>
        <xsl:value-of select="count(exsl:node-set($tree)/out/namespace::*[name()='f'])"/>
      </xsl:template>
    </xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "1");

    let active = stylesheet.replace(
        "xmlns:exsl=",
        "extension-element-prefixes=\"func\" xmlns:exsl=",
    );
    assert_eq!(execute(&active, "<source/>"), "0");
}

#[test]
fn built_in_template_traversal_does_not_use_the_native_stack() {
    // Source depth is attacker-controlled and may legitimately exceed the native call stack when
    // the caller explicitly grants a matching recursion budget. Built-in rules must use the same
    // iterative task machine as explicit template rules.
    let depth = 4_096usize;
    let mut source = String::with_capacity(depth.saturating_mul(7).saturating_add(4));
    source.extend(std::iter::repeat_n("<n>", depth));
    source.push_str("text");
    source.extend(std::iter::repeat_n("</n>", depth));
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/></xsl:stylesheet>"#,
    );
    let mut budget = execution_budget(source.len());
    budget.recursion_depth = depth + 2;
    budget.template_applications = depth + 2;
    budget.owned_bytes = 512 * 1024 * 1024;
    let output = stylesheet
        .execute(
            &Document::parse(&source, None).expect("deep source parses iteratively"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("built-in traversal remains iterative");
    assert_eq!(output.serialized.bytes, b"text");
}

#[test]
fn copy_of_source_traversal_does_not_use_the_native_stack() {
    // xsl:copy-of must honor a deliberately large recursion budget without mapping source depth
    // onto the process stack.
    let depth = 8_192usize;
    let mut source = String::with_capacity(depth.saturating_mul(7));
    source.extend(std::iter::repeat_n("<n>", depth));
    source.extend(std::iter::repeat_n("</n>", depth));
    let mut expected = String::with_capacity(source.len());
    expected.extend(std::iter::repeat_n("<n>", depth - 1));
    expected.push_str("<n/>");
    expected.extend(std::iter::repeat_n("</n>", depth - 1));
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes" indent="no"/><xsl:template match="/"><xsl:copy-of select="."/></xsl:template></xsl:stylesheet>"#,
    );
    let mut budget = execution_budget(source.len());
    budget.recursion_depth = depth + 2;
    budget.result_nodes = depth.saturating_mul(3);
    budget.owned_bytes = 2 * 1024 * 1024 * 1024;
    budget.serialized_bytes = source.len() + 1;
    let output = stylesheet
        .execute(
            &Document::parse(&source, None).expect("deep source parses iteratively"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("copy-of traversal remains iterative");
    assert_eq!(
        output.serialized.bytes.len(),
        expected.len(),
        "copy-of must preserve the complete deep source"
    );
    assert_eq!(output.serialized.bytes, expected.as_bytes());
}

#[test]
fn exslt_set_boundaries_must_belong_to_the_first_node_set() {
    // EXSLT explicitly returns an empty set when the first node in the boundary set is absent
    // from the first argument; an empty boundary set instead returns the complete first set.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:set="http://exslt.org/sets"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="count(set:leading(/root/a | /root/b | /root/c, /root/h))"/><xsl:text>|</xsl:text><xsl:value-of select="count(set:trailing(/root/d | /root/e | /root/f, /root/a))"/><xsl:text>|</xsl:text><xsl:value-of select="count(set:leading(/root/*, /root/missing))"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<root><a/><b/><c/><d/><e/><f/><h/></root>"),
        "0|0|7"
    );
}

#[test]
fn named_templates_consume_template_application_budget() {
    // Initial and nested named-template calls are executable template applications.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template name="entry"><xsl:call-template name="nested"/></xsl:template><xsl:template name="nested"/></xsl:stylesheet>"#,
    );
    let mut budget = execution_budget(1024);
    budget.template_applications = 1;
    let error = stylesheet
        .execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: Some(ExpandedName::new(None::<String>, "entry")),
            },
        )
        .expect_err("the second named-template application exceeds the budget");
    assert!(matches!(
        error,
        Error::Budget {
            kind: BudgetKind::TemplateApplications,
            limit: 1,
            actual: 2,
        }
    ));
}

#[test]
fn message_content_preserves_constructed_xml_fragments() {
    // xsl:message instantiates a template into a fragment rather than accepting text only.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:message><detail code="E"><xsl:text>failed</xsl:text><xsl:comment>kept</xsl:comment><xsl:processing-instruction name="hint">retry</xsl:processing-instruction></detail></xsl:message></xsl:template></xsl:stylesheet>"#,
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
        .expect("constructed message succeeds");
    assert_eq!(
        result.messages[0].content,
        r#"<detail code="E">failed<!--kept--><?hint retry?></detail>"#
    );
}

#[test]
fn sequential_messages_release_temporary_fragment_memory() {
    // Message strings remain in TransformResult, but each constructed fragment dies after
    // serialization and must not accumulate against the peak-live OwnedBytes ceiling.
    let payload = "x".repeat(4096);
    let messages = format!("<xsl:message><detail>{payload}</detail></xsl:message>").repeat(32);
    let stylesheet = compile(&format!(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/">{messages}</xsl:template></xsl:stylesheet>"#
    ));
    let mut budget = execution_budget(1024);
    budget.messages = 32;
    budget.owned_bytes = 1 << 20;
    let result = stylesheet
        .execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("temporary message fragments remain below the peak-memory ceiling");
    assert_eq!(result.messages.len(), 32);
}

#[test]
fn retained_empty_messages_consume_owned_bytes() {
    // Empty message payloads still retain one Message entry apiece in TransformResult.
    let count = 64;
    let messages = "<xsl:message/>".repeat(count);
    let stylesheet = compile(&format!(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template name="baseline"/><xsl:template name="messages">{messages}</xsl:template></xsl:stylesheet>"#
    ));
    assert!(
        minimum_execution_owned_bytes(&stylesheet, "messages")
            >= minimum_execution_owned_bytes(&stylesheet, "baseline")
                + count * std::mem::size_of::<xml_sec_xslt::Message>()
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
    let result = Compiler::new(
        Arc::new(NoResolver),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(cycle, None);
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
fn unreachable_global_content_does_not_create_a_dependency_cycle() {
    // Global dependencies arise only from expressions that execution reaches. A variable in a
    // false instruction branch must not form a cycle with the global being initialized.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:variable name="a"><xsl:if test="false()"><xsl:value-of select="$b"/></xsl:if><xsl:text>ok</xsl:text></xsl:variable><xsl:variable name="b" select="$a"/><xsl:template match="/"><xsl:value-of select="$b"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "ok");
}

#[test]
fn static_xpath_and_template_conflicts_are_resolved_during_compilation() {
    // Invalid expressions are static errors and union branches retain their own priority.
    let malformed = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="["/></xsl:template></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(4096, 0, 256, 64 * 1024),
        )
        .compile(malformed, None),
        Err(Error::Static(_))
    ));

    let unbound_prefix = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="*[missing:name]"/></xsl:template></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(4096, 0, 256, 64 * 1024),
        )
        .compile(unbound_prefix, None),
        Err(Error::Static(_))
    ));

    for wildcard in [
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="missing:*"/></xsl:template></xsl:stylesheet>"#,
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="missing:*"/></xsl:stylesheet>"#,
    ] {
        assert!(matches!(
            Compiler::new(
                Arc::new(NoResolver),
                CompileBudget::new(4096, 0, 256, 64 * 1024),
            )
            .compile(wildcard, None),
            Err(Error::Static(_))
        ));
    }

    let union = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><xsl:apply-templates select="bar"/></xsl:template><xsl:template match="foo|*"><wild/></xsl:template><xsl:template match="bar"><specific/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(union, "<bar/>"), "<specific/>\n");
}

#[test]
fn stylesheet_static_context_is_module_and_instruction_local() {
    // Comments do not end the parameter prologue, and computed names use stylesheet bindings.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:p="urn:p" exclude-result-prefixes="p"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><!--documented--><xsl:param name="v" select="'ok'"/><xsl:element name="p:out"><xsl:attribute name="p:value"><xsl:value-of select="$v"/></xsl:attribute></xsl:element></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<source/>"),
        "<p:out xmlns:p=\"urn:p\" p:value=\"ok\"/>\n"
    );
}

#[test]
fn whitespace_rules_honor_namespaces_specificity_and_inherited_xml_space() {
    // Import precedence and NameTest priority apply before declaration order. XSLT 1.0 section
    // 3.4 independently preserves whitespace beneath inherited xml:space="preserve".
    // https://www.w3.org/TR/1999/REC-xslt-19991116#strip
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
fn whitespace_rules_reject_malformed_qname_name_tests() {
    // XSLT 1.0 section 3.4 permits QName, prefix:* and * only; malformed tokens must not install
    // inert rules that silently hide stylesheet errors.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#strip
    for token in ["p:item:extra", ":item", "item:", "p:"] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:p="urn:p"><xsl:strip-space elements="{token}"/></xsl:stylesheet>"#
        );
        assert!(matches!(
            Compiler::new(
                Arc::new(NoResolver),
                CompileBudget::new(4096, 0, 32, 64 * 1024),
            )
                .compile(&stylesheet, None),
            Err(Error::Static(message)) if message.contains("whitespace") || message.contains("name test")
        ));
    }

    compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:p="urn:p"><xsl:strip-space elements="* p:* p:item"/></xsl:stylesheet>"#,
    );
}

#[test]
fn whitespace_rules_reject_empty_name_test_lists() {
    // XSLT 1.0 section 3.4 declares `elements` as required NMTOKENS, which cannot be an
    // empty or whitespace-only list.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#strip
    for elements in ["", " \t\r\n "] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:strip-space elements="{elements}"/></xsl:stylesheet>"#
        );
        let result = Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(4096, 0, 32, 64 * 1024),
        )
        .compile(&stylesheet, None);
        assert!(
            matches!(
                &result,
                Err(Error::Static(message)) if message.contains("elements") && message.contains("name test")
            ),
            "unexpected compile result: {result:?}"
        );
    }
}

#[test]
fn whitespace_declarations_reject_content() {
    // XSLT 1.0 section 3.4 declares both whitespace instructions EMPTY; accepting content
    // would silently discard stylesheet logic instead of reporting a static error.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#strip
    for instruction in [
        r#"<xsl:strip-space elements="*">text</xsl:strip-space>"#,
        r#"<xsl:preserve-space elements="*"><foreign/></xsl:preserve-space>"#,
    ] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">{instruction}</xsl:stylesheet>"#
        );
        assert!(
            Compiler::new(Arc::new(NoResolver), CompileBudget::new(4096, 0, 32, 4096))
                .compile(&stylesheet, None)
                .is_err()
        );
    }
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
fn empty_instructions_honor_inherited_stylesheet_xml_space() {
    // XSLT 1.0 sections 3.4 and 7.2 make preserved stylesheet whitespace a text node. It is
    // therefore content, not ignorable indentation, inside instructions required to be empty.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#strip
    // https://www.w3.org/TR/1999/REC-xslt-19991116#value-of
    let preserved = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/" xml:space="preserve"><xsl:value-of select="." > </xsl:value-of></xsl:template></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(4096, 0, 32, 64 * 1024),
        )
            .compile(preserved, None),
        Err(Error::Static(message)) if message.contains("xsl:value-of must be empty")
    ));

    let indentation = preserved.replace(" xml:space=\"preserve\"", "");
    Compiler::new(
        Arc::new(NoResolver),
        CompileBudget::new(4096, 0, 32, 64 * 1024),
    )
    .compile(&indentation, None)
    .expect("ordinary XML whitespace remains ignorable indentation");
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
                bytes: br#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:meta="urn:metadata"><meta:marker>module</meta:marker><xsl:template name="read"><xsl:value-of select="document('')/*/meta:marker"/></xsl:template></xsl:stylesheet>"#.to_vec(),
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
            NodeReference::Node(node_id_at(&document, 4)),
            NodeReference::Node(node_id_at(&document, 2)),
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
fn nodeset_parameters_reject_foreign_document_references() {
    // Arena indices are document-local. A cached parameter from another source must never alias
    // a same-numbered node in the document used for this transformation.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:param name="node"/><xsl:template match="/"><xsl:value-of select="$node"/></xsl:template></xsl:stylesheet>"#,
    );
    let foreign =
        Document::parse("<root><item>foreign</item></root>", None).expect("foreign source parses");
    let source =
        Document::parse("<root><item>local</item></root>", None).expect("principal source parses");
    let mut parameters = Parameters::new();
    parameters.insert(
        ExpandedName::new(None::<String>, "node"),
        Value::NodeSet(vec![NodeReference::Node(
            foreign
                .nodes()
                .find_map(|(id, node)| {
                    matches!(node.kind, NodeKind::Element { ref name, .. } if name.local == "item")
                        .then_some(id)
                })
                .expect("foreign item exists"),
        )]),
    );

    let error = stylesheet
        .execute(
            &source,
            &parameters,
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect_err("foreign node-set parameter is rejected");
    assert!(error.to_string().contains("foreign document"));
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
fn optimized_node_selections_consume_xpath_evaluation_budget() {
    // Fast paths are implementation details: apply-templates and for-each selections must
    // consume the same logical XPath budget as expressions handled by the generic evaluator.
    for instruction in [
        r#"<xsl:apply-templates select="node()"/>"#,
        r#"<xsl:for-each select="@*"><xsl:value-of select="."/></xsl:for-each>"#,
    ] {
        let stylesheet = compile(&format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><out>{instruction}</out></xsl:template></xsl:stylesheet>"#,
        ));
        let mut budget = execution_budget(1024);
        budget.xpath_evaluations = 0;

        let error = stylesheet
            .execute(
                &Document::parse("<source key=\"value\"/>", None).expect("source parses"),
                &Parameters::new(),
                Arc::new(NoResolver),
                ExecutionOptions {
                    budget,
                    initial_mode: None,
                    initial_template: None,
                },
            )
            .expect_err("optimized node selection must consume XPath budget");

        assert!(matches!(
            error,
            Error::Budget {
                kind: BudgetKind::XPathEvaluations,
                ..
            }
        ));
    }
}

#[test]
fn complex_match_patterns_consume_xpath_evaluation_budget() {
    // The apply-templates selection and the generic predicate match are two XPath evaluations.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:apply-templates select="root/item"/></xsl:template><xsl:template match="item[position() = 1]">hit</xsl:template></xsl:stylesheet>"#,
    );
    let mut budget = execution_budget(4096);
    budget.xpath_evaluations = 1;
    let error = stylesheet
        .execute(
            &Document::parse("<root><item/></root>", None).expect("source parses"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect_err("generic match evaluation must consume budget");

    assert!(matches!(
        error,
        Error::Budget {
            kind: BudgetKind::XPathEvaluations,
            ..
        }
    ));
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
fn sorting_rejects_unknown_case_order_values() {
    // case-order is an AVT, but every evaluated value still has the XSLT two-value contract.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:for-each select="root/item"><xsl:sort case-order="sideways"/><xsl:value-of select="."/></xsl:for-each></xsl:template></xsl:stylesheet>"#,
    );
    let source = Document::parse("<root><item>a</item></root>", None).expect("source parses");
    let error = stylesheet
        .execute(
            &source,
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect_err("unknown case-order must fail");
    assert!(matches!(error, Error::Dynamic(message) if message.contains("case-order")));
}

#[test]
fn number_rejects_multi_character_grouping_separator() {
    // Empty disables grouping in the pinned libxslt contract; multiple characters are malformed.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:number value="1234" grouping-separator=".." grouping-size="3"/></xsl:template></xsl:stylesheet>"#,
    );
    let source = Document::parse("<root/>", None).expect("source parses");
    let error = stylesheet
        .execute(
            &source,
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect_err("malformed grouping-separator must fail");
    assert!(matches!(error, Error::Dynamic(message) if message.contains("grouping-separator")));
}

#[test]
fn number_converts_grouping_size_through_xpath_number_semantics() {
    // XSLT 1.0 sections 7.7 and 7.7.1 define grouping-size as a numeric AVT used by decimal
    // numbering. libxslt accepts decimal spellings and truncates fractional group widths.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#number
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:number value="1234567" grouping-separator="," grouping-size="3.0"/><xsl:text>|</xsl:text><xsl:number value="1234567" grouping-separator="," grouping-size="2.6"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "1,234,567|1,23,45,67");
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
fn numbering_preserves_punctuation_and_groups_only_decimal_tokens() {
    // XSLT 1.0 section 7.7.1 retains a leading punctuation token when it supplies the default
    // format token, while grouping-separator/grouping-size apply only to decimal formatting.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#convert
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:number value="27" format="("/><xsl:text>|</xsl:text><xsl:number value="27" format="A" grouping-separator="," grouping-size="1"/><xsl:text>|</xsl:text><xsl:number value="9" format="I" grouping-separator="," grouping-size="1"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "(27|AA|IX");
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
fn html_indentation_preserves_preformatted_content() {
    // XSLT 1.0 section 16.2 permits indentation only when it does not change rendering;
    // whitespace inserted into preformatted or raw-text HTML content is therefore forbidden.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#section-HTML-Output-Method
    for element in ["pre", "textarea", "script", "style"] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="html" indent="yes"/><xsl:template match="/"><{element}><span>x</span></{element}></xsl:template></xsl:stylesheet>"#
        );
        assert_eq!(
            execute(&stylesheet, "<source/>"),
            format!("<{element}><span>x</span></{element}>\n")
        );
    }
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
fn explicit_utf16_endianness_omits_the_byte_order_mark() {
    // RFC 2781 section 3.3 forbids a BOM when the charset label fixes the byte order.
    // https://www.rfc-editor.org/rfc/rfc2781.html#section-3.3
    for (encoding, prefix) in [("UTF-16LE", [0x3c, 0x00]), ("UTF-16BE", [0x00, 0x3c])] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output encoding="{encoding}"/><xsl:template match="/"><root>ok</root></xsl:template></xsl:stylesheet>"#,
        );
        let output = compile(&stylesheet)
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
            .expect("explicit-endian UTF-16 must serialize");

        assert_eq!(&output.serialized.bytes[..2], &prefix, "{encoding}");
    }
}

#[test]
fn serializer_preserves_iana_latin1_alias_semantics() {
    // Every IANA alias names ISO-8859-1, so none may inherit encoding_rs's WHATWG
    // Windows-1252 behavior and emit an undeclared 0x80 byte for U+20AC.
    // https://www.iana.org/assignments/character-sets/character-sets.xhtml
    for alias in [
        "ISO_8859-1:1987",
        "iso-ir-100",
        "ISO_8859-1",
        "ISO-8859-1",
        "latin1",
        "l1",
        "IBM819",
        "CP819",
        "csISOLatin1",
    ] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output encoding="{alias}" omit-xml-declaration="yes"/><xsl:template match="/"><out>€</out></xsl:template></xsl:stylesheet>"#,
        );
        assert_eq!(
            execute(&stylesheet, "<source/>"),
            "<out>&#8364;</out>\n",
            "alias {alias} must retain ISO-8859-1 semantics",
        );
    }
}

#[test]
fn serializer_canonicalizes_iana_aliases_in_xml_declarations() {
    // XML 1.0 section 4.3.3 restricts declaration encoding names to EncName. A registered
    // alias may contain other punctuation, so the declaration must use its canonical name.
    // https://www.w3.org/TR/xml/#charencoding
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output encoding="ISO_8859-1:1987"/><xsl:template match="/"><out>café</out></xsl:template></xsl:stylesheet>"#,
    );
    let output = stylesheet
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
        .expect("registered alias serializes");

    assert!(
        output
            .serialized
            .bytes
            .starts_with(b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>")
    );
    assert!(output.serialized.bytes.ends_with(b"<out>caf\xe9</out>\n"));
}

#[test]
fn serializer_canonicalizes_ascii_aliases_for_xml_round_trips() {
    // XSLT 1.0 section 16.1 requires the declaration to identify the encoding actually used.
    // Canonical US-ASCII keeps every supported IANA alias parseable by the shared XML decoder.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#output
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output encoding="iso-ir-6"/><xsl:template match="/"><out>ASCII</out></xsl:template></xsl:stylesheet>"#,
    );
    let output = stylesheet
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
        .expect("ASCII alias serializes");

    assert!(
        output
            .serialized
            .bytes
            .starts_with(b"<?xml version=\"1.0\" encoding=\"US-ASCII\"?>")
    );
    xml_sec_xml_input::decode_xml(&output.serialized.bytes, None)
        .expect("serialized ASCII output decodes as XML");
}

#[test]
fn serializer_preserves_strict_iana_single_byte_semantics() {
    // XML 1.0 section 4.3.3 requires registered charset names to retain their IANA
    // repertoire rather than the wider WHATWG Windows mappings.
    // https://www.w3.org/TR/xml/#charencoding
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text" encoding="ISO-8859-9"/><xsl:template match="/">Ğı</xsl:template></xsl:stylesheet>"#,
    );
    let output = stylesheet
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
        .expect("registered repertoire serializes");
    assert_eq!(output.serialized.bytes, [0xD0, 0xFD]);

    let unrepresentable = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text" encoding="ISO-8859-9"/><xsl:template match="/">€</xsl:template></xsl:stylesheet>"#,
    );
    assert!(
        unrepresentable
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
            .is_err()
    );
}

#[test]
fn serializer_rejects_iana_labels_redirected_to_windows_code_pages() {
    // XML 1.0 section 4.3.3 requires an encoding declaration to name the actual
    // character encoding; WHATWG aliases must not silently change IANA semantics.
    // https://www.w3.org/TR/xml/#charencoding
    let iana = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text" encoding="ISO-8859-2"/><xsl:template match="/">€</xsl:template></xsl:stylesheet>"#,
    );
    assert!(
        iana.execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .is_err()
    );

    let windows = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text" encoding="Windows-1250"/><xsl:template match="/">€</xsl:template></xsl:stylesheet>"#,
    );
    let output = windows
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
        .expect("explicit Windows encoding serializes");
    assert_eq!(output.serialized.bytes, [0x80]);
}

#[test]
fn us_ascii_output_is_strict_for_markup_and_text() {
    // WHATWG label aliases must not silently widen XSLT's declared US-ASCII output contract.
    let xml = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output encoding="US-ASCII" omit-xml-declaration="yes"/><xsl:template match="/"><root>€</root></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(xml, "<source/>"), "<root>&#8364;</root>\n");

    let text = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text" encoding="US-ASCII"/><xsl:template match="/">€</xsl:template></xsl:stylesheet>"#,
    );
    let error = text
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
        .expect_err("non-ASCII text cannot be emitted as US-ASCII");
    assert!(matches!(error, Error::Serialization(message) if message.contains("US-ASCII")));
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
fn lower_precedence_attribute_sets_keep_equal_precedence_ordering() {
    // A principal declaration protects only the attributes it defines; later imported
    // declarations at the same precedence still override earlier imported declarations.
    let resolver = Arc::new(ContextResolver::default());
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert(
            (
                "imported.xsl".into(),
                Some("memory:principal.xsl".into()),
            ),
            ResolvedResource {
                canonical_uri: "memory:imported.xsl".into(),
                identity: ResourceIdentity("imported-attribute-sets".into()),
                bytes: br#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:attribute-set name="shared"><xsl:attribute name="x">old</xsl:attribute></xsl:attribute-set><xsl:attribute-set name="shared"><xsl:attribute name="x">new</xsl:attribute></xsl:attribute-set></xsl:stylesheet>"#.to_vec(),
                media_type: Some("application/xml".into()),
                encoding: Some("UTF-8".into()),
            },
        );
    let stylesheet = Compiler::new(resolver, CompileBudget::new(1 << 20, 8, 32, 1 << 20))
        .compile(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:import href="imported.xsl"/><xsl:output omit-xml-declaration="yes"/><xsl:attribute-set name="shared"><xsl:attribute name="y">principal</xsl:attribute></xsl:attribute-set><xsl:template match="/"><out xsl:use-attribute-sets="shared"/></xsl:template></xsl:stylesheet>"#,
            Some("memory:principal.xsl"),
        )
        .expect("stylesheet compiles");
    let result = stylesheet
        .execute(
            &Document::parse("<root/>", None).expect("source parses"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("stylesheet executes");
    assert_eq!(
        String::from_utf8(result.serialized.bytes).expect("UTF-8 output"),
        "<out y=\"principal\" x=\"new\"/>\n"
    );
}

#[test]
fn document_cache_identity_includes_parse_provenance() {
    // Caller identities are stable only when bytes, decoding metadata, and canonical base agree.
    let resolver = Arc::new(ContextResolver::default());
    for (href, canonical_uri, encoding) in [
        ("a.xml", "memory:first.xml", "UTF-8"),
        ("b.xml", "memory:second.xml", "windows-1252"),
    ] {
        resolver
            .resources
            .lock()
            .expect("test resolver mutex is not poisoned")
            .insert(
                (href.into(), Some("memory:principal.xsl".into())),
                ResolvedResource {
                    canonical_uri: canonical_uri.into(),
                    identity: ResourceIdentity("shared-document-identity".into()),
                    bytes: b"<doc/>".to_vec(),
                    media_type: Some("application/xml".into()),
                    encoding: Some(encoding.into()),
                },
            );
    }
    let stylesheet = Compiler::new(
        Arc::new(NoResolver),
        CompileBudget::new(1 << 20, 8, 32, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><out><xsl:copy-of select="document('a.xml')"/><xsl:copy-of select="document('b.xml')"/></out></xsl:template></xsl:stylesheet>"#,
        Some("memory:principal.xsl"),
    )
    .expect("stylesheet compiles");
    let error = stylesheet
        .execute(
            &Document::parse("<root/>", None).expect("source parses"),
            &Parameters::new(),
            resolver,
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect_err("changed parse provenance must invalidate a resource identity");
    assert!(matches!(error, Error::StaleResource { .. }), "{error:?}");
}

#[test]
fn recursion_and_output_budgets_gate_work_before_growth() {
    // Compile recursion, source copying, and rendered output each enforce their own ceiling.
    let nested = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:if test="true()"><xsl:if test="true()"><xsl:if test="true()"><out/></xsl:if></xsl:if></xsl:if></xsl:template></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(4096, 0, 3, 16 * 1024),
        )
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
        owner: node_id_at(&document, 1),
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
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(4096, 0, 32, 16 * 1024),
        )
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
fn excluded_namespace_alias_is_not_restored_by_a_used_uri() {
    // XSLT 1.0 section 7.1.1 requires the literal QName's actual prefix, not every in-scope alias
    // for the same URI; exclude-result-prefixes must still remove an unused alias.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#literal-result-element
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:a="urn:x" xmlns:b="urn:x" exclude-result-prefixes="b"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><a:out/></xsl:template></xsl:stylesheet>"#;

    assert_eq!(
        execute(stylesheet, "<source/>"),
        "<a:out xmlns:a=\"urn:x\"/>\n"
    );
}

#[test]
fn result_tree_container_capacity_consumes_owned_memory_budget() {
    // Empty result elements still retain arena Nodes and parent child slots. A payload-only meter
    // lets the result tree exceed OwnedBytes whenever ResultNodes is configured independently.
    let stylesheet = |body: &str| {
        compile(&format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><out><xsl:for-each select="/source/i">{body}</xsl:for-each></out></xsl:template></xsl:stylesheet>"#
        ))
    };
    let source_xml = format!("<source>{}</source>", "<i/>".repeat(128));
    let source = Document::parse(&source_xml, None).expect("source parses");
    let minimum = |stylesheet: &xml_sec_xslt::Stylesheet| {
        let succeeds = |owned_bytes| {
            let mut budget = execution_budget(source_xml.len());
            budget.owned_bytes = owned_bytes;
            stylesheet
                .execute(
                    &source,
                    &Parameters::new(),
                    Arc::new(NoResolver),
                    ExecutionOptions {
                        budget,
                        initial_mode: None,
                        initial_template: None,
                    },
                )
                .is_ok()
        };
        let mut rejected = 0;
        let mut accepted = 1;
        while !succeeds(accepted) {
            rejected = accepted;
            accepted *= 2;
        }
        while rejected + 1 < accepted {
            let candidate = rejected + (accepted - rejected) / 2;
            if succeeds(candidate) {
                accepted = candidate;
            } else {
                rejected = candidate;
            }
        }
        accepted
    };
    let empty = minimum(&stylesheet(""));
    let elements = minimum(&stylesheet("<a/>"));

    assert!(
        elements >= empty + 8 * 1024,
        "128 retained nodes and child slots added only {} metered bytes",
        elements.saturating_sub(empty)
    );
}

#[test]
fn xpath_accepts_whitespace_before_function_arguments() {
    // XPath permits whitespace between a function QName and its argument list even
    // though the underlying parser requires lexical normalization.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="concat ('a', 'b')"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "ab");
}

#[test]
fn for_each_context_functions_accept_xpath_whitespace() {
    // The XSLT outer iteration context must be preserved for every legal
    // whitespace spelling of the zero-argument XPath context functions.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:for-each select="source/item"><xsl:value-of select="position &#x9;( )"/><xsl:text>/</xsl:text><xsl:value-of select="last&#xA;(&#xD;)"/><xsl:text>;</xsl:text></xsl:for-each></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<source><item/><item/></source>"),
        "1/2;2/2;"
    );
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
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(4096, 0, 32, 64 * 1024),
        )
        .compile(outside, None),
        Err(Error::Static(_))
    ));

    let mixed = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:func="http://exslt.org/functions" xmlns:f="urn:functions" extension-element-prefixes="func"><func:function name="f:bad"><func:result select="1">content</func:result></func:function></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(4096, 0, 32, 64 * 1024),
        )
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
fn include_accepts_a_simplified_stylesheet_module() {
    // XSLT 1.0 permits a literal result element carrying xsl:version to act as a stylesheet
    // module, including when that module is reached through xsl:include.
    let resolver = Arc::new(MemoryResolver::default());
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert(
            "literal.xsl".into(),
            r#"<included xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:value-of select="/*/@value"/></included>"#.into(),
        );
    let stylesheet = Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes"/><xsl:include href="literal.xsl"/></xsl:stylesheet>"#,
        Some("memory:main.xsl"),
    )
    .expect("simplified included stylesheet compiles");
    let output = stylesheet
        .execute(
            &Document::parse("<source value=\"ok\"/>", None).expect("source parses"),
            &Parameters::new(),
            resolver,
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("simplified included stylesheet executes");
    assert_eq!(output.serialized.bytes, b"<included>ok</included>\n");
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

    let combining_name = "a\u{0300}";
    let unicode_dependency = format!(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:variable name="dependent" select="${combining_name}"/><xsl:variable name="{combining_name}" select="'combined'"/><xsl:template match="/"><xsl:value-of select="$dependent"/></xsl:template></xsl:stylesheet>"#
    );
    assert_eq!(execute(&unicode_dependency, "<source/>"), "combined");
}

#[test]
fn undeclared_node_set_parameters_are_ignored_before_provenance_validation() {
    // XSLT 1.0 section 11.4 defines only top-level xsl:param as stylesheet parameters and leaves
    // the passing mechanism unspecified; this API ignores entries with no effective declaration.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/">ok</xsl:template></xsl:stylesheet>"#,
    );
    let source = Document::parse("<source/>", None).expect("source parses");
    let foreign = Document::parse("<foreign/>", None).expect("foreign document parses");
    let mut parameters = Parameters::new();
    parameters.insert(
        ExpandedName::new(None::<String>, "unused"),
        Value::NodeSet(vec![NodeReference::Node(foreign.root())]),
    );

    let output = stylesheet
        .execute(
            &source,
            &parameters,
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("an undeclared caller parameter is ignored");
    assert_eq!(output.serialized.bytes, b"ok");

    let declared = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:param name="unused"/><xsl:template match="/"/></xsl:stylesheet>"#,
    );
    let error = declared
        .execute(
            &source,
            &parameters,
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect_err("a bound node-set parameter must belong to the source document");
    assert!(
        matches!(error, Error::Dynamic(ref message) if message.contains("foreign document")),
        "{error:?}"
    );
}

#[test]
fn compiler_rejects_invalid_instruction_content_and_accounts_for_ir() {
    // Static content models fail during compilation, and retained IR consumes owned-byte budget.
    let invalid_text = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:text>before<xsl:value-of select="."/>after</xsl:text></xsl:template></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(4096, 0, 32, 16 * 1024),
        )
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
fn stylesheet_content_models_distinguish_ignorable_nodes_from_character_data() {
    // Comments and processing instructions are absent from the stylesheet's sequence
    // constructor, while child instructions in xsl:text and character data in an attribute set
    // remain static errors.
    let text = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:text>a<!-- note --><?trace ignored?>b</xsl:text></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(text, "<source/>"), "ab");

    let invalid_attribute_set = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:attribute-set name="attrs">invalid<xsl:attribute name="a">v</xsl:attribute></xsl:attribute-set></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(4096, 0, 32, 64 * 1024),
        )
        .compile(invalid_attribute_set, None),
        Err(Error::Static(_))
    ));

    let ignorable_attribute_set = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:attribute-set name="attrs"> <!-- note --> <?trace ignored?> <xsl:attribute name="a">v</xsl:attribute> </xsl:attribute-set><xsl:template match="/"><out xsl:use-attribute-sets="attrs"/></xsl:template></xsl:stylesheet>"#;
    compile(ignorable_attribute_set);
}

#[test]
fn parser_preserves_base_and_lexical_names_across_depths() {
    // Semantic projection must apply xml:base, retain attribute prefixes, and reject unbound names.
    let document = Document::parse(
        r#"<root xml:base="sub/"><item xmlns:a="urn:x" xmlns:b="urn:x" b:value="1"/></root>"#,
        Some("https://example.test/source.xml"),
    )
    .expect("source parses");
    let item = document
        .node(node_id_at(&document, 2))
        .expect("item exists");
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
fn iterative_parser_preserves_xpath_namespace_and_id_behavior_at_depth_boundaries() {
    // Historically significant depth boundaries must feed XPath identical leaf semantics.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:p="urn:leaf"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="count(//p:leaf)"/><xsl:text>|</xsl:text><xsl:value-of select="count(id('target'))"/><xsl:text>|</xsl:text><xsl:value-of select="//p:leaf/@p:value"/></xsl:template></xsl:stylesheet>"#,
    );
    for depth in (62..=66).chain(126..=130) {
        let source = format!(
            "{}{}{}",
            "<n>".repeat(depth),
            r#"<p:leaf xmlns:p="urn:leaf" xml:id="target" p:value="ok"/>"#,
            "</n>".repeat(depth)
        );
        let result = stylesheet
            .execute(
                &Document::parse(&source, Some("memory:source.xml"))
                    .expect("boundary source parses"),
                &Parameters::new(),
                Arc::new(NoResolver),
                ExecutionOptions {
                    budget: execution_budget(source.len()),
                    initial_mode: None,
                    initial_template: None,
                },
            )
            .expect("boundary source transforms");
        assert_eq!(
            String::from_utf8(result.serialized.bytes).expect("UTF-8 output"),
            "1|1|ok",
            "XPath behavior differs at depth {depth}"
        );
    }
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
fn numeric_sort_workspace_is_metered_before_allocation() {
    // Numeric keys have no string payload, but their structural vectors and merge buffers are
    // still attacker-sized execution-owned allocations.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:for-each select="root/item"><xsl:sort select="@a" data-type="number"/><xsl:sort select="@b" data-type="number"/><xsl:value-of select="@a"/></xsl:for-each></xsl:template></xsl:stylesheet>"#,
    );
    let xml = format!(
        "<root>{}</root>",
        (0..1024)
            .map(|index| format!(r#"<item a="{index}" b="{}"/>"#, 1024 - index))
            .collect::<String>()
    );
    let source = Document::parse(&xml, None).expect("source parses");
    let mut budget = execution_budget(xml.len());
    budget.owned_bytes = 2_200_000;
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
fn xinclude_text_encoding_errors_activate_fallback() {
    // XInclude 1.0 section 4.3.3 classifies malformed acquired byte sequences as resource
    // errors, so fallback applies; successfully decoded XML-forbidden characters remain fatal.
    // https://www.w3.org/TR/xinclude/#text_included
    let resolver = Arc::new(ContextResolver::default());
    for (href, encoding, bytes) in [
        ("invalid-utf8.txt", "UTF-8", vec![0xFF]),
        ("truncated-utf16.txt", "UTF-16LE", vec![0x41]),
    ] {
        resolver
            .resources
            .lock()
            .expect("test resolver mutex is not poisoned")
            .insert(
                (href.into(), Some("memory:source.xml".into())),
                ResolvedResource {
                    canonical_uri: format!("memory:{href}"),
                    identity: ResourceIdentity(href.into()),
                    bytes,
                    media_type: Some("text/plain".into()),
                    encoding: Some(encoding.into()),
                },
            );
    }
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="root"/></xsl:template></xsl:stylesheet>"#,
    );
    for href in ["invalid-utf8.txt", "truncated-utf16.txt"] {
        let source = Document::parse(
            &format!(
                r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="{href}" parse="text"><xi:fallback>fallback</xi:fallback></xi:include></root>"#
            ),
            Some("memory:source.xml"),
        )
        .expect("XInclude source parses");
        let result = stylesheet
            .execute_with_source_processing(
                &source,
                &Parameters::new(),
                resolver.clone(),
                ExecutionOptions {
                    budget: execution_budget(1024),
                    initial_mode: None,
                    initial_template: None,
                },
                SourceProcessing::XInclude,
            )
            .expect("encoding resource errors activate fallback");
        assert_eq!(result.serialized.bytes, b"fallback");
    }

    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert(
            ("forbidden.txt".into(), Some("memory:source.xml".into())),
            ResolvedResource {
                canonical_uri: "memory:forbidden.txt".into(),
                identity: ResourceIdentity("forbidden.txt".into()),
                bytes: vec![0x01],
                media_type: Some("text/plain".into()),
                encoding: Some("UTF-8".into()),
            },
        );
    let source = Document::parse(
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="forbidden.txt" parse="text"><xi:fallback>wrong</xi:fallback></xi:include></root>"#,
        Some("memory:source.xml"),
    )
    .expect("XInclude source parses");
    assert!(matches!(
        stylesheet.execute_with_source_processing(
            &source,
            &Parameters::new(),
            resolver,
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
            SourceProcessing::XInclude,
        ),
        Err(Error::Xml(message)) if message.contains("forbidden XML character")
    ));
}

#[test]
fn xinclude_fallback_handles_only_resource_errors() {
    // XInclude 1.0 makes invalid syntax fatal; fallback must not turn malformed instructions into
    // data, while selection failures are resource errors under section 4.2.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:copy-of select="."/></xsl:template></xsl:stylesheet>"#,
    );
    for source in [
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="missing.xml" parse="invalid"><xi:fallback><wrong/></xi:fallback></xi:include></root>"#,
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="missing.xml#fragment"><xi:fallback><wrong/></xi:fallback></xi:include></root>"#,
    ] {
        let error = stylesheet
            .execute_with_source_processing(
                &Document::parse(source, Some("memory:source.xml")).expect("source parses"),
                &Parameters::new(),
                Arc::new(NoResolver),
                ExecutionOptions {
                    budget: execution_budget(1024),
                    initial_mode: None,
                    initial_template: None,
                },
                SourceProcessing::XInclude,
            )
            .expect_err("fatal XInclude errors must bypass fallback");
        assert!(matches!(error, Error::Xml(_) | Error::Unsupported(_)));
    }

    let source = Document::parse(
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="unused.xml" xpointer="element(/1)"><xi:fallback><selected/></xi:fallback></xi:include></root>"#,
        Some("memory:source.xml"),
    )
    .expect("source parses");
    let result = stylesheet
        .execute_with_source_processing(
            &source,
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
            SourceProcessing::XInclude,
        )
        .expect("an unavailable XPointer selection activates fallback");
    assert_eq!(
        String::from_utf8(result.serialized.bytes).expect("result is UTF-8"),
        "<?xml version=\"1.0\"?>\n<root xmlns:xi=\"http://www.w3.org/2001/XInclude\"><selected/></root>\n"
    );

    let source = Document::parse(
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="unused.xml" xpointer="element(/1)"/></root>"#,
        Some("memory:source.xml"),
    )
    .expect("source parses");
    assert!(matches!(
        stylesheet.execute_with_source_processing(
            &source,
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
            SourceProcessing::XInclude,
        ),
        Err(Error::Resolver { uri, message })
            if uri == "unused.xml"
                && message == "external resource access is not configured"
    ));

    let resolver = Arc::new(MemoryResolver::default());
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert("malformed.xml".into(), "<unclosed>".into());
    let source = Document::parse(
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="malformed.xml"><xi:fallback><wrong/></xi:fallback></xi:include></root>"#,
        Some("memory:source.xml"),
    )
    .expect("source parses");
    let error = stylesheet
        .execute_with_source_processing(
            &source,
            &Parameters::new(),
            resolver,
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
            SourceProcessing::XInclude,
        )
        .expect_err("non-well-formed included XML is fatal before fallback");
    assert!(matches!(error, Error::Xml(_)));
}

#[test]
fn xinclude_preserves_acquired_and_fallback_language() {
    // XInclude 1.0 section 4.5.7 requires top-level included items to retain the language they
    // had before insertion, including an explicit empty fixup that blocks new inheritance.
    // https://www.w3.org/TR/xinclude/#language
    let resolver = Arc::new(MemoryResolver::default());
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert("included.xml".into(), "<included/>".into());
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="root/included/@xml:lang"/><xsl:text>|</xsl:text><xsl:value-of select="boolean(root/included[lang('fr')])"/><xsl:text>|</xsl:text><xsl:value-of select="root/fallback/@xml:lang"/><xsl:text>|</xsl:text><xsl:value-of select="boolean(root/fallback[lang('de')])"/></xsl:template></xsl:stylesheet>"#,
    );
    let source = Document::parse(
        r#"<root xml:lang="fr" xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="included.xml"/><xi:include href="missing.xml"><xi:fallback xml:lang="de"><fallback/></xi:fallback></xi:include></root>"#,
        Some("memory:source.xml"),
    )
    .expect("source parses");
    let result = stylesheet
        .execute_with_source_processing(
            &source,
            &Parameters::new(),
            resolver,
            ExecutionOptions {
                budget: execution_budget(4096),
                initial_mode: None,
                initial_template: None,
            },
            SourceProcessing::XInclude,
        )
        .expect("XInclude language fixup succeeds");
    assert_eq!(result.serialized.bytes, b"|false|de|true");
}

#[test]
fn xinclude_text_strips_encoding_signatures() {
    // XInclude 1.0 section 4.3.3 requires an encoding signature to be interpreted and removed
    // before the text resource is included in the document.
    // https://www.w3.org/TR/xinclude/#text_included
    let resolver = Arc::new(ContextResolver::default());
    for (href, encoding, bytes) in [
        (
            "utf8.txt",
            "UTF-8",
            [b"\xEF\xBB\xBF".as_slice(), "alpha".as_bytes()].concat(),
        ),
        (
            "utf16le.txt",
            "UTF-16LE",
            [0xFEFF_u16]
                .into_iter()
                .chain("beta".encode_utf16())
                .flat_map(u16::to_le_bytes)
                .collect(),
        ),
        (
            "utf16be.txt",
            "UTF-16",
            [0xFEFF_u16]
                .into_iter()
                .chain("gamma".encode_utf16())
                .flat_map(u16::to_be_bytes)
                .collect(),
        ),
    ] {
        resolver
            .resources
            .lock()
            .expect("test resolver mutex is not poisoned")
            .insert(
                (href.into(), Some("memory:source.xml".into())),
                ResolvedResource {
                    canonical_uri: format!("memory:{href}"),
                    identity: ResourceIdentity(href.into()),
                    bytes,
                    media_type: Some("text/plain".into()),
                    encoding: Some(encoding.into()),
                },
            );
    }

    for (href, bytes) in [
        (
            "utf16-signature.txt",
            [0xFEFF_u16]
                .into_iter()
                .chain("delta".encode_utf16())
                .flat_map(u16::to_le_bytes)
                .collect(),
        ),
        (
            "utf32-signature.txt",
            [0xFF, 0xFE, 0x00, 0x00]
                .into_iter()
                .chain(
                    "epsilon"
                        .chars()
                        .flat_map(|character| u32::from(character).to_le_bytes()),
                )
                .collect(),
        ),
    ] {
        resolver
            .resources
            .lock()
            .expect("test resolver mutex is not poisoned")
            .insert(
                (href.into(), Some("memory:source.xml".into())),
                ResolvedResource {
                    canonical_uri: format!("memory:{href}"),
                    identity: ResourceIdentity(href.into()),
                    bytes,
                    media_type: Some("text/plain".into()),
                    encoding: None,
                },
            );
    }
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="root"/></xsl:template></xsl:stylesheet>"#,
    );
    for (href, expected) in [
        ("utf8.txt", "alpha"),
        ("utf16le.txt", "beta"),
        ("utf16be.txt", "gamma"),
        ("utf16-signature.txt", "delta"),
        ("utf32-signature.txt", "epsilon"),
    ] {
        let source = Document::parse(
            &format!(
                r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="{href}" parse="text"/></root>"#
            ),
            Some("memory:source.xml"),
        )
        .expect("XInclude source parses");
        let result = stylesheet
            .execute_with_source_processing(
                &source,
                &Parameters::new(),
                resolver.clone(),
                ExecutionOptions {
                    budget: execution_budget(1024),
                    initial_mode: None,
                    initial_template: None,
                },
                SourceProcessing::XInclude,
            )
            .expect("encoding signature is removed from included text");
        assert_eq!(result.serialized.bytes, expected.as_bytes());
    }

    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert(
            ("bomless.txt".into(), Some("memory:source.xml".into())),
            ResolvedResource {
                canonical_uri: "memory:bomless.txt".into(),
                identity: ResourceIdentity("bomless.txt".into()),
                bytes: "ambiguous"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect(),
                media_type: Some("text/plain".into()),
                encoding: Some("UTF-16".into()),
            },
        );
    let source = Document::parse(
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="bomless.txt" parse="text"/></root>"#,
        Some("memory:source.xml"),
    )
    .expect("XInclude source parses");
    assert!(
        stylesheet
            .execute_with_source_processing(
                &source,
                &Parameters::new(),
                resolver,
                ExecutionOptions {
                    budget: execution_budget(1024),
                    initial_mode: None,
                    initial_template: None,
                },
                SourceProcessing::XInclude,
            )
            .is_err()
    );
}

#[test]
fn xinclude_element_scheme_selects_only_the_addressed_element() {
    // XInclude 1.0 section 4.2.2 requires support for the XPointer Framework element() scheme.
    // Child sequence numbers count element children, and an ID may anchor the sequence.
    // https://www.w3.org/TR/xinclude/#fragment
    let resolver = Arc::new(MemoryResolver::default());
    resolver.resources.lock().expect("resolver mutex").insert(
        "included.xml".into(),
        r#"<doc><first/><second xml:id="anchor"><leaf/></second><outside xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="must-not-resolve.xml"/></outside></doc>"#.into(),
    );
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><xsl:copy-of select="."/></xsl:template></xsl:stylesheet>"#,
    );

    for (pointer, expected) in [
        ("element(/1/2/1)", "<leaf/>"),
        ("element(anchor/1)", "<leaf/>"),
        ("anchor", "<second xml:id=\"anchor\"><leaf/></second>"),
        ("unknown(a(b)) element(/1/1)", "<first/>"),
    ] {
        let source = Document::parse(
            &format!(
                r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="included.xml" xpointer="{pointer}"/></root>"#
            ),
            Some("memory:source.xml"),
        )
        .expect("source parses");
        let result = stylesheet
            .execute_with_source_processing(
                &source,
                &Parameters::new(),
                resolver.clone(),
                ExecutionOptions {
                    budget: execution_budget(4096),
                    initial_mode: None,
                    initial_template: None,
                },
                SourceProcessing::XInclude,
            )
            .expect("required element() scheme selects a subresource");
        let output = String::from_utf8(result.serialized.bytes).expect("result is UTF-8");
        assert!(
            output.contains(expected),
            "unexpected selection for {pointer}: {output}"
        );
        assert!(!output.contains("must-not-resolve"));
    }

    let source = Document::parse(
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="included.xml" xpointer="element(/1/9)"><xi:fallback><fallback/></xi:fallback></xi:include></root>"#,
        Some("memory:source.xml"),
    )
    .expect("source parses");
    let result = stylesheet
        .execute_with_source_processing(
            &source,
            &Parameters::new(),
            resolver,
            ExecutionOptions {
                budget: execution_budget(4096),
                initial_mode: None,
                initial_template: None,
            },
            SourceProcessing::XInclude,
        )
        .expect("an empty element() selection activates fallback");
    assert!(
        String::from_utf8(result.serialized.bytes)
            .expect("result is UTF-8")
            .contains("<fallback/>")
    );
}

#[test]
fn xinclude_empty_href_selects_the_source_document_without_resolution() {
    // XInclude 1.0 section 3.1 defines an absent href as the containing document. The selection
    // therefore stays inside the current document and must not consume resolver capability.
    // https://www.w3.org/TR/xinclude/#include_element
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="count(root/selected)"/></xsl:template></xsl:stylesheet>"#,
    );
    let source = Document::parse(
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><selected/><xi:include xpointer="element(/1/1)"/></root>"#,
        Some("memory:source.xml"),
    )
    .expect("same-document XInclude source parses");

    let result = stylesheet
        .execute_with_source_processing(
            &source,
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(4096),
                initial_mode: None,
                initial_template: None,
            },
            SourceProcessing::XInclude,
        )
        .expect("same-document XPointer resolves without an external resolver");
    assert_eq!(result.serialized.bytes, b"2");

    let recursive = Document::parse(
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><selected/><xi:include href="" xpointer="element(/1/2)"/></root>"#,
        Some("memory:source.xml"),
    )
    .expect("recursive same-document XInclude source parses");
    assert!(matches!(
        stylesheet.execute_with_source_processing(
            &recursive,
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(4096),
                initial_mode: None,
                initial_template: None,
            },
            SourceProcessing::XInclude,
        ),
        Err(Error::Xml(message)) if message.contains("same-document cycle")
    ));
}

#[test]
fn xinclude_element_scheme_budgets_only_the_selected_projection() {
    // The acquired resource must be parsed in full, but XInclude 1.0 section 4.2.2 adds only the
    // selected subresource to the result. Unselected payload must not be charged as a second copy.
    // https://www.w3.org/TR/xinclude/#fragment
    let resolver = Arc::new(MemoryResolver::default());
    let unselected = "x".repeat(256 * 1024);
    resolver.resources.lock().expect("resolver mutex").insert(
        "included.xml".into(),
        format!(r#"<doc><selected/><unselected>{unselected}</unselected></doc>"#),
    );
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><xsl:copy-of select="."/></xsl:template></xsl:stylesheet>"#,
    );
    let source = Document::parse(
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="included.xml" xpointer="element(/1/1)"/></root>"#,
        Some("memory:source.xml"),
    )
    .expect("source parses");
    let mut budget = execution_budget(512 * 1024);
    // The full acquired document needs transient parser workspace. This allowance still leaves
    // insufficient room to retain the unselected 256 KiB payload as an additional projection.
    budget.owned_bytes = 1200 * 1024;
    let result = stylesheet
        .execute_with_source_processing(
            &source,
            &Parameters::new(),
            resolver,
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
            SourceProcessing::XInclude,
        )
        .expect("an unselected sibling must not consume projection budget");
    assert!(
        String::from_utf8(result.serialized.bytes)
            .expect("result is UTF-8")
            .contains("<selected/>")
    );
}

#[test]
fn xinclude_fallback_releases_failed_xpointer_parse_storage() {
    // A supported pointer that selects nothing is a recoverable resource error. Repeated fallback
    // must reuse the same peak allocation allowance rather than accumulate already-dropped parses.
    let resolver = Arc::new(MemoryResolver::default());
    resolver.resources.lock().expect("resolver mutex").insert(
        "included.xml".into(),
        format!("<doc><payload>{}</payload></doc>", "x".repeat(512 * 1024)),
    );
    let includes = r#"<xi:include href="included.xml" xpointer="element(/1/9)"><xi:fallback><fallback/></xi:fallback></xi:include>"#.repeat(4);
    let source_xml =
        format!(r#"<root xmlns:xi="http://www.w3.org/2001/XInclude">{includes}</root>"#);
    let source =
        Document::parse(&source_xml, Some("memory:source.xml")).expect("XInclude source parses");
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="count(root/fallback)"/></xsl:template></xsl:stylesheet>"#,
    );
    let mut budget = execution_budget(source_xml.len());
    budget.external_documents = 4;
    budget.owned_bytes = 2_200 * 1024;

    let result = stylesheet
        .execute_with_source_processing(
            &source,
            &Parameters::new(),
            resolver,
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
            SourceProcessing::XInclude,
        )
        .expect("recoverable XPointer parses release their temporary reservations");
    assert_eq!(result.serialized.bytes, b"4");
}

#[test]
fn xinclude_fragment_href_is_rejected_before_resolver_access() {
    // XInclude 1.0 section 3.1 makes any fragment identifier in href a fatal error, including an
    // empty fragment, and therefore it must not cross the resolver boundary.
    // https://www.w3.org/TR/xinclude/#include_element
    let resolver = Arc::new(CountingResolver::default());
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"/></xsl:stylesheet>"#,
    );
    for href in ["included.xml#fragment", "included.xml#"] {
        let source = Document::parse(
            &format!(
                r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="{href}"/></root>"#
            ),
            Some("memory:source.xml"),
        )
        .expect("source parses before XInclude validation");
        let error = stylesheet
            .execute_with_source_processing(
                &source,
                &Parameters::new(),
                resolver.clone(),
                ExecutionOptions {
                    budget: execution_budget(1024),
                    initial_mode: None,
                    initial_template: None,
                },
                SourceProcessing::XInclude,
            )
            .expect_err("fragment-bearing XInclude href must be fatal");
        assert!(matches!(error, Error::Xml(message) if message.contains("fragment")));
    }
    assert_eq!(resolver.calls.load(Ordering::Relaxed), 0);
}

#[test]
fn xinclude_rejects_multiple_fallback_children() {
    // XInclude 1.0 section 3.1 permits at most one xi:fallback child. This is a syntax
    // constraint, so a resource failure must not turn a malformed include into a successful
    // fallback: https://www.w3.org/TR/xinclude/#syntax
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:copy-of select="."/></xsl:template></xsl:stylesheet>"#,
    );
    let source = Document::parse(
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="missing.xml"><xi:fallback><first/></xi:fallback><xi:fallback><second/></xi:fallback></xi:include></root>"#,
        Some("memory:source.xml"),
    )
    .expect("source parses before XInclude validation");

    let error = stylesheet
        .execute_with_source_processing(
            &source,
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
            SourceProcessing::XInclude,
        )
        .expect_err("multiple xi:fallback children are a fatal syntax error");
    assert!(matches!(
        error,
        Error::Xml(message) if message.contains("at most one xi:fallback")
    ));
}

#[test]
fn xinclude_rejects_fallback_outside_include_before_resolution() {
    // XInclude 1.0 section 3.1 permits xi:fallback only as a direct child of xi:include; a
    // malformed source must fail before any external capability is invoked.
    // https://www.w3.org/TR/xinclude/#syntax
    let resolver = Arc::new(CountingResolver::default());
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"/></xsl:stylesheet>"#,
    );
    let source = Document::parse(
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:fallback><xi:include href="never.xml"/></xi:fallback></root>"#,
        Some("memory:source.xml"),
    )
    .expect("source parses before XInclude validation");
    let error = stylesheet
        .execute_with_source_processing(
            &source,
            &Parameters::new(),
            resolver.clone(),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
            SourceProcessing::XInclude,
        )
        .expect_err("standalone xi:fallback is invalid");
    assert!(matches!(error, Error::Xml(message) if message.contains("direct child")));
    assert_eq!(resolver.calls.load(Ordering::Relaxed), 0);
}

#[test]
fn xinclude_distinguishes_extension_content_from_reserved_children() {
    // XInclude 1.0 section 3.1 permits local and foreign-namespace extension children but
    // reserves XInclude-namespace children other than xi:fallback.
    // https://www.w3.org/TR/xinclude/#syntax
    let resolver = Arc::new(MemoryResolver::default());
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert("included.xml".into(), "<included/>".into());
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><xsl:copy-of select="."/></xsl:template></xsl:stylesheet>"#,
    );
    let source = Document::parse(
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="included.xml"><extension/><foreign:metadata xmlns:foreign="urn:extension"/></xi:include></root>"#,
        Some("memory:source.xml"),
    )
    .expect("extension-bearing source parses");
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
            SourceProcessing::XInclude,
        )
        .expect("permitted extension children do not invalidate inclusion");
    assert_eq!(
        String::from_utf8(result.serialized.bytes).unwrap(),
        "<root xmlns:xi=\"http://www.w3.org/2001/XInclude\"><included/></root>\n"
    );

    let source = Document::parse(
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="missing.xml"><xi:include href="nested.xml"/></xi:include></root>"#,
        Some("memory:source.xml"),
    )
    .expect("reserved-child source parses before XInclude validation");
    assert!(matches!(
        stylesheet.execute_with_source_processing(
            &source,
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
            SourceProcessing::XInclude,
        ),
        Err(Error::Xml(message)) if message.contains("XInclude namespace child")
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

#[test]
fn format_number_localizes_generated_digits_without_rewriting_literals() {
    // zero-digit localizes numeric output only; quoted affix digits and a digit-shaped grouping
    // separator are literal decimal-format characters and must remain byte-for-byte unchanged.
    let stylesheet = r##"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:decimal-format name="arabic" zero-digit="٠" digit="#" grouping-separator="2"/><xsl:template match="/"><xsl:value-of select="format-number(1, &quot;'2'٠'3'&quot;, 'arabic')"/><xsl:text>|</xsl:text><xsl:value-of select="format-number(1234, '٠2٠٠٠', 'arabic')"/></xsl:template></xsl:stylesheet>"##;
    assert_eq!(execute(stylesheet, "<source/>"), "2١3|١2٢٣٤");
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

    let strict_iana = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:str="http://exslt.org/strings"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="str:decode-uri('%80', 'ISO-8859-9')"/><xsl:text>|</xsl:text><xsl:value-of select="str:decode-uri('%80', 'windows-1254')"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(strict_iana, "<source/>"), "\u{80}|€");

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
fn exslt_decode_uri_returns_empty_for_malformed_percent_escapes() {
    // EXSLT str:decode-uri returns the empty string when `%` is not followed by exactly two
    // hexadecimal digits; malformed suffixes must not leak through as literal text.
    // https://exslt.github.io/str/functions/decode-uri/index.html
    for value in ["%", "%A", "%ZZ", "%41%ZZ"] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:str="http://exslt.org/strings"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="str:decode-uri('{value}')"/></xsl:template></xsl:stylesheet>"#
        );
        assert_eq!(execute(&stylesheet, "<source/>"), "");
    }
    assert_eq!(
        execute(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:str="http://exslt.org/strings"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="str:decode-uri('%41')"/></xsl:template></xsl:stylesheet>"#,
            "<source/>",
        ),
        "A"
    );
}

#[test]
fn exslt_encode_uri_honors_the_optional_encoding() {
    // The current EXSLT contract accepts an optional encoding and percent-encodes the
    // resulting octets rather than always encoding the source as UTF-8.
    // https://exslt.github.io/str/functions/encode-uri/index.html
    let stylesheet = r#"<xsl:stylesheet version="1.0"
        xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
        xmlns:str="http://exslt.org/strings">
        <xsl:output method="text"/>
        <xsl:template match="/">
          <xsl:value-of select="str:encode-uri('é', true())"/>
          <xsl:text>|</xsl:text>
          <xsl:value-of select="str:encode-uri('é', true(), 'ISO-8859-1')"/>
        </xsl:template>
      </xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "%C3%A9|%E9");

    let unsupported = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:str="http://exslt.org/strings"><xsl:template match="/"><xsl:value-of select="str:encode-uri('é', true(), 'not-an-encoding')"/></xsl:template></xsl:stylesheet>"#,
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

    // EXSLT specifies an empty string when the requested encoding cannot represent a character.
    // Cover both the built-in single-byte registry and the encoding_rs path.
    // https://exslt.github.io/str/functions/encode-uri/index.html
    for (value, encoding) in [("€", "ISO-8859-1"), ("漢", "windows-1252")] {
        assert_eq!(
            execute(
                &format!(
                    r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:str="http://exslt.org/strings"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="str:encode-uri('{value}', true(), '{encoding}')"/></xsl:template></xsl:stylesheet>"#
                ),
                "<source/>",
            ),
            ""
        );
    }
}

#[test]
fn undeclared_unicode_ncname_prefix_is_a_static_error() {
    // XML Names permits combining marks after the first prefix character; namespace validation
    // must not defer such an unbound prefix until the expression happens to execute.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="ṕ:item"/></xsl:template></xsl:stylesheet>"#;
    let error = Compiler::new(
        Arc::new(NoResolver),
        CompileBudget::new(1 << 20, 16, 256, 4 << 20),
    )
    .compile(stylesheet, Some("memory:main.xsl"))
    .expect_err("the Unicode prefix is not bound");
    assert!(matches!(error, Error::Static(message) if message.contains("ṕ")));

    let declared = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:ṕ="urn:unicode"><xsl:template match="/"><xsl:value-of select="ṕ:item"/></xsl:template></xsl:stylesheet>"#;
    Compiler::new(
        Arc::new(NoResolver),
        CompileBudget::new(1 << 20, 16, 256, 4 << 20),
    )
    .compile(declared, Some("memory:main.xsl"))
    .expect("the declared Unicode prefix is valid");
}

#[test]
fn xpath_function_whitespace_accepts_complete_unicode_ncnames() {
    // XPath 1.0 section 3.7 permits XML whitespace before `(`, while FunctionName is a QName and
    // therefore admits combining NCName characters: https://www.w3.org/TR/1999/REC-xpath-19991116/#exprlex
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:func="http://exslt.org/functions" xmlns:f="urn:functions" extension-element-prefixes="func"><xsl:output method="text"/><func:function name="f:á"><func:result select="'ok'"/></func:function><xsl:template match="/"><xsl:value-of select="f:á ()"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "ok");
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
    let repeated_expression = format!("{}1", "1 + ".repeat(64));
    let mut budget = execution_budget(1 << 20);
    // Leave room for one retained AST and the concurrently live adapter workspace. Distinct
    // expressions must still exhaust this budget through retained cache growth.
    budget.owned_bytes = 512 << 10;
    stylesheet
        .execute(
            &source_with(&|_| repeated_expression.clone()),
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
            &source_with(&|index| format!("{index} + {repeated_expression}")),
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
fn unbounded_compile_policy_cannot_exceed_the_native_stack_ceiling() {
    // Resolver-controlled module depth must terminate with a typed budget error even when caller
    // policy is effectively unbounded; otherwise the host stack becomes the accidental limit.
    let resolver = Arc::new(IncludeChainResolver::default());
    let error = Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 1024, usize::MAX, 16 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:include href="level-1.xsl"/></xsl:stylesheet>"#,
        Some("memory:main.xsl"),
    )
    .expect_err("absolute compile ceiling must stop the include chain");
    assert!(matches!(
        error,
        Error::Budget {
            kind: BudgetKind::RecursionDepth,
            limit: 256,
            actual: 257,
        }
    ));
    assert_eq!(
        *resolver
            .calls
            .lock()
            .expect("test resolver mutex is not poisoned"),
        255,
        "the over-ceiling module must not cross the resolver boundary"
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
fn forward_compatible_sort_ignores_invalid_optional_values() {
    // XSLT 1.0 section 2.5 ignores optional attributes whose values are unknown to a 1.0
    // processor when forwards-compatible processing is active.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#forwards
    let stylesheet = r#"<xsl:stylesheet version="2.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:for-each select="root/order"><xsl:sort order="future"/><xsl:value-of select="."/></xsl:for-each><xsl:text>|</xsl:text><xsl:for-each select="root/data"><xsl:sort data-type="future"/><xsl:value-of select="."/></xsl:for-each><xsl:text>|</xsl:text><xsl:for-each select="root/case"><xsl:sort case-order="future"/><xsl:value-of select="."/></xsl:for-each><xsl:text>|</xsl:text><xsl:for-each select="root/lang"><xsl:sort lang="!"/><xsl:value-of select="."/></xsl:for-each></xsl:template></xsl:stylesheet>"#;

    assert_eq!(
        execute(
            stylesheet,
            "<root><order>b</order><order>a</order><data>2</data><data>10</data><case>b</case><case>a</case><lang>b</lang><lang>a</lang></root>",
        ),
        "ab|102|ab|ab"
    );
}

#[test]
fn forward_compatible_output_ignores_invalid_optional_booleans() {
    // XSLT 1.0 section 2.5 ignores unsupported optional attribute values in
    // forward-compatible mode, while the same values remain errors in strict mode.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#forwards
    for attribute in [
        r#"omit-xml-declaration="future""#,
        r#"standalone="future""#,
        r#"indent="future""#,
    ] {
        let strict = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output {attribute}/></xsl:stylesheet>"#
        );
        let compiler = || {
            Compiler::new(
                Arc::new(NoResolver),
                CompileBudget::new(16 * 1024, 0, 32, 16 * 1024),
            )
        };
        assert!(compiler().compile(&strict, None).is_err());

        let compatible = strict.replacen("version=\"1.0\"", "version=\"2.0\"", 1);
        compiler()
            .compile(&compatible, None)
            .expect("forward-compatible optional output values are ignored");
    }
}

#[test]
fn forward_compatible_value_of_ignores_invalid_optional_boolean() {
    // XSLT 1.0 section 2.5 ignores unsupported optional values in forward-compatible mode.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#forwards
    let strict = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="." disable-output-escaping="future"/></xsl:template></xsl:stylesheet>"#;
    assert!(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(16 * 1024, 0, 32, 16 * 1024),
        )
        .compile(strict, None)
        .is_err()
    );
    assert_eq!(
        execute(&strict.replacen("1.0", "2.0", 1), "<source>ok</source>"),
        "<?xml version=\"1.0\"?>\nok\n"
    );
}

#[test]
fn decimal_format_rejects_child_content() {
    // XSLT 1.0 section 12.3 declares xsl:decimal-format EMPTY.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#format-number
    for content in ["<foreign/>", "text"] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:decimal-format>{content}</xsl:decimal-format></xsl:stylesheet>"#
        );
        assert!(
            Compiler::new(
                Arc::new(NoResolver),
                CompileBudget::new(16 * 1024, 0, 32, 16 * 1024),
            )
            .compile(&stylesheet, None)
            .is_err()
        );
    }
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
fn imported_stylesheets_charge_retained_semantic_documents_before_projection() {
    // Imported bytes, decoded source, and the retained parser-neutral document are distinct
    // allocations; a budget covering only the byte and source copies must reject the module.
    let resolver = Arc::new(CountingResolver::default());
    let payload = "x".repeat(8 * 1024);
    resolver.resources.lock().expect("resolver mutex").insert(
        "included.xsl".into(),
        format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:variable name="payload" select="'{payload}'"/></xsl:stylesheet>"#
        ),
    );
    let principal = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:include href="included.xsl"/></xsl:stylesheet>"#;
    let error = Compiler::new(resolver, CompileBudget::new(1 << 20, 8, 256, 20 * 1024))
        .compile(principal, Some("memory:main.xsl"))
        .expect_err("retained imported document exceeds owned-byte budget");
    assert!(matches!(
        error,
        Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        }
    ));
}

#[test]
fn imported_stylesheets_charge_retained_resolver_metadata() {
    // Resolver-controlled metadata remains live in compilation caches independently of the tiny
    // stylesheet payload and must therefore cross the same owned-memory gate.
    struct MetadataResolver;

    impl Resolver for MetadataResolver {
        fn resolve(
            &self,
            _uri: &str,
            _base_uri: Option<&str>,
            _purpose: ResolvePurpose,
        ) -> xml_sec_xslt::Result<ResolvedResource> {
            let large = "m".repeat(2 << 20);
            Ok(ResolvedResource {
                canonical_uri: "memory:included.xsl".into(),
                identity: ResourceIdentity(large.clone()),
                bytes: br#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"/>"#.to_vec(),
                media_type: Some(large),
                encoding: Some("UTF-8".into()),
            })
        }
    }

    let principal = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:include href="included.xsl"/></xsl:stylesheet>"#;
    let error = Compiler::new(
        Arc::new(MetadataResolver),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(principal, Some("memory:main.xsl"))
    .expect_err("retained resolver metadata exceeds owned-byte budget");
    assert!(
        matches!(
            error,
            Error::Budget {
                kind: BudgetKind::OwnedBytes,
                ..
            }
        ),
        "expected owned-memory rejection, got {error:?}"
    );
}

#[test]
fn runtime_resource_caches_charge_resolver_metadata_before_retaining_it() {
    // Both document() and XInclude retain resolver provenance for stale-resource detection. Tiny
    // XML payloads with oversized metadata must fail the owned-memory gate before cache insertion.
    struct MetadataResolver;

    impl Resolver for MetadataResolver {
        fn resolve(
            &self,
            _uri: &str,
            _base_uri: Option<&str>,
            _purpose: ResolvePurpose,
        ) -> xml_sec_xslt::Result<ResolvedResource> {
            let metadata = "m".repeat(2 << 20);
            Ok(ResolvedResource {
                canonical_uri: "memory:document.xml".into(),
                identity: ResourceIdentity(metadata.clone()),
                bytes: b"<document/>".to_vec(),
                media_type: Some(metadata),
                encoding: Some("UTF-8".into()),
            })
        }
    }

    let mut budget = execution_budget(1 << 20);
    budget.owned_bytes = 1 << 20;
    let options = ExecutionOptions {
        budget,
        initial_mode: None,
        initial_template: None,
    };
    let document_stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:copy-of select="document('document.xml')"/></xsl:template></xsl:stylesheet>"#,
    );
    let source = Document::parse("<source/>", Some("memory:source.xml")).expect("source parses");
    assert!(matches!(
        document_stylesheet.execute(
            &source,
            &Parameters::new(),
            Arc::new(MetadataResolver),
            options.clone(),
        ),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));

    let include_stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:copy-of select="."/></xsl:template></xsl:stylesheet>"#,
    );
    let include_source = Document::parse(
        r#"<source xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="document.xml"/></source>"#,
        Some("memory:source.xml"),
    )
    .expect("XInclude source parses");
    assert!(matches!(
        include_stylesheet.execute_with_source_processing(
            &include_source,
            &Parameters::new(),
            Arc::new(MetadataResolver),
            options,
            SourceProcessing::XInclude,
        ),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
}

#[test]
fn included_stylesheets_decode_each_retained_source_once() {
    // Import discovery and declaration compilation revisit an included module, but one retained
    // decoded source must serve every pass instead of consuming the cumulative owned-byte budget.
    let resolver = Arc::new(CountingResolver::default());
    let payload = "x".repeat(64 * 1024);
    resolver.resources.lock().expect("resolver mutex").insert(
        "included.xsl".into(),
        format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:variable name="payload" select="'{payload}'"/></xsl:stylesheet>"#
        ),
    );
    let principal = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:include href="included.xsl"/></xsl:stylesheet>"#;
    Compiler::new(resolver, CompileBudget::new(1 << 20, 8, 256, 450 * 1024))
        .compile(principal, Some("memory:main.xsl"))
        .expect("one retained module decode fits the owned-byte budget");
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
fn xinclude_native_recursion_has_an_absolute_safety_ceiling() {
    // A caller budget may be intentionally permissive, but resolver-controlled nesting must not
    // turn that policy choice into unbounded native stack growth.
    let resolver = Arc::new(CountingResolver::default());
    {
        let mut resources = resolver.resources.lock().expect("resolver mutex");
        for depth in 0..300 {
            resources.insert(
                format!("{depth}.xml"),
                format!(
                    r#"<node xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="{}.xml"/></node>"#,
                    depth + 1
                ),
            );
        }
        resources.insert("300.xml".into(), "<leaf/>".into());
    }
    let source = Document::parse(
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="0.xml"/></root>"#,
        Some("memory:source.xml"),
    )
    .expect("source parses");
    let mut budget = execution_budget(1024);
    budget.external_documents = 512;
    budget.recursion_depth = 512;
    budget.owned_bytes = 64 << 20;
    assert!(matches!(
        compile(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"/></xsl:stylesheet>"#,
        )
        .execute_with_source_processing(
            &source,
            &Parameters::new(),
            resolver,
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
            SourceProcessing::XInclude,
        ),
        Err(Error::Budget {
            kind: BudgetKind::RecursionDepth,
            ..
        })
    ));
}

#[test]
fn xinclude_clone_budget_is_checked_before_resolver_access() {
    // The principal XInclude projection and its remap workspace are retained allocations. A
    // budget that cannot hold them must fail before any include crosses the resolver boundary.
    let resolver = Arc::new(CountingResolver::default());
    resolver
        .resources
        .lock()
        .expect("resolver mutex")
        .insert("included.xml".into(), "<included/>".into());
    let payload = "x".repeat(8 * 1024);
    let source_xml = format!(
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><payload>{payload}</payload><xi:include href="included.xml"/></root>"#
    );
    let source = Document::parse(&source_xml, Some("memory:source.xml")).expect("source parses");
    let mut budget = execution_budget(source_xml.len());
    budget.owned_bytes = source_xml.len() + 1024;
    let error = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"/></xsl:stylesheet>"#,
    )
    .execute_with_source_processing(
        &source,
        &Parameters::new(),
        resolver.clone(),
        ExecutionOptions {
            budget,
            initial_mode: None,
            initial_template: None,
        },
        SourceProcessing::XInclude,
    )
    .expect_err("XInclude projection exceeds retained-memory budget");
    assert!(matches!(
        error,
        Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        }
    ));
    assert_eq!(resolver.calls.load(Ordering::Relaxed), 0);
}

#[test]
fn sequential_xincludes_release_temporary_projection_memory() {
    // OwnedBytes is a peak-live-memory ceiling. Included documents and remap workspaces die after
    // each subtree is copied, so sequential inclusions must not accumulate their reservations.
    let resolver = Arc::new(CountingResolver::default());
    resolver
        .resources
        .lock()
        .expect("resolver mutex")
        .insert("included.xml".into(), "<included/>".into());
    let source_xml = format!(
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude">{}</root>"#,
        r#"<xi:include href="included.xml"/>"#.repeat(64)
    );
    let source = Document::parse(&source_xml, Some("memory:source.xml")).expect("source parses");
    let mut budget = execution_budget(source_xml.len());
    budget.external_documents = 64;
    // Includes the conservative SXD arena/container estimate and the shared namespace arenas
    // retained by the projected nodes, while remaining far below the aggregate footprint that
    // retaining 64 complete parsed/projection temporaries would require.
    budget.owned_bytes = 208 * 1024;
    compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"/></xsl:stylesheet>"#,
    )
    .execute_with_source_processing(
        &source,
        &Parameters::new(),
        resolver,
        ExecutionOptions {
            budget,
            initial_mode: None,
            initial_template: None,
        },
        SourceProcessing::XInclude,
    )
    .expect("sequential XInclude temporaries remain below the peak-memory ceiling");
}

#[test]
fn supplied_global_parameter_respects_the_preallocation_budget() {
    // Caller values are already owned by Parameters. Retaining a global binding must reject its
    // second copy against OwnedBytes before the execution path duplicates the payload.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:param name="payload"/><xsl:template match="/"/></xsl:stylesheet>"#,
    );
    let source = Document::parse("<source/>", None).expect("source parses");
    let mut parameters = Parameters::new();
    parameters.insert(
        ExpandedName::new(None::<String>, "payload"),
        Value::String("x".repeat(16 * 1024)),
    );
    let mut budget = execution_budget(1024);
    budget.owned_bytes = 8 * 1024;
    assert!(matches!(
        stylesheet.execute(
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
fn xpath_scope_snapshot_counts_toward_peak_owned_memory() {
    // Generic XPath evaluation temporarily owns both its visible-variable snapshot and the
    // evaluator's value copy. Their simultaneous peak must be rejected before either copy can
    // move the operation above its OwnedBytes ceiling.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:param name="payload"/><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="concat($payload, '')"/></xsl:template></xsl:stylesheet>"#,
    );
    let source = Document::parse("<source/>", None).expect("source parses");
    let mut parameters = Parameters::new();
    parameters.insert(
        ExpandedName::new(None::<String>, "payload"),
        Value::String("x".repeat(256 * 1024)),
    );
    let mut budget = execution_budget(1024);
    budget.owned_bytes = 700 * 1024;
    assert!(matches!(
        stylesheet.execute(
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
fn prepared_extension_calls_borrow_the_visible_variable_snapshot() {
    // Rewriting an extension call may add generated bindings, but must not deep-clone every
    // unrelated visible value after the caller has already materialized and charged the snapshot.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:exsl="http://exslt.org/common">
          <xsl:param name="payload"/>
          <xsl:output method="text"/>
          <xsl:template name="baseline"><xsl:value-of select="string-length($payload)"/></xsl:template>
          <xsl:template name="extension"><xsl:value-of select="exsl:object-type($payload)"/></xsl:template>
        </xsl:stylesheet>"#,
    );
    let mut parameters = Parameters::new();
    parameters.insert(
        ExpandedName::new(None::<String>, "payload"),
        Value::String("x".repeat(256 * 1024)),
    );
    let baseline =
        minimum_execution_owned_bytes_with_parameters(&stylesheet, "baseline", &parameters);
    let extension =
        minimum_execution_owned_bytes_with_parameters(&stylesheet, "extension", &parameters);
    assert!(
        extension <= baseline.saturating_add(16 * 1024),
        "extension rewrite required {extension} bytes versus {baseline} for the baseline"
    );
}

#[test]
fn value_of_transfers_owned_xpath_string_without_transient_copies() {
    // The evaluated concat result can move directly into a new text node. The execution must not
    // require simultaneous source, conversion, and result-tree copies of the same string.
    let payload = "x".repeat(256 * 1024);
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="concat(/source, '')"/></xsl:template></xsl:stylesheet>"#,
    );
    let source_xml = format!("<source>{payload}</source>");
    let mut budget = execution_budget(source_xml.len());
    budget.owned_bytes = 2 * 1024 * 1024;
    let result = stylesheet
        .execute(
            &Document::parse(&source_xml, None).expect("source parses"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("owned XPath string transfers within the peak-memory ceiling");
    assert_eq!(result.serialized.bytes.len(), payload.len());
}

#[test]
fn adjacent_value_of_accounts_for_the_owned_string_while_coalescing_text() {
    // Adjacent XSLT text nodes coalesce. The owned XPath string remains live while it is copied
    // into the existing result node, so both allocations must fit the peak-memory ceiling.
    let payload = "x".repeat(256 * 1024);
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:text>prefix</xsl:text><xsl:value-of select="concat(/source, '')"/></xsl:template></xsl:stylesheet>"#,
    );
    let source_xml = format!("<source>{payload}</source>");
    let mut budget = execution_budget(source_xml.len());
    budget.owned_bytes = 5 * 256 * 1024;
    let error = stylesheet
        .execute(
            &Document::parse(&source_xml, None).expect("source parses"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect_err("coalescing must account for the live owned XPath buffer");
    assert!(matches!(
        error,
        Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        }
    ));
}

#[test]
fn sequential_local_scopes_release_retained_binding_memory() {
    // OwnedBytes is a peak-live-memory ceiling. A for-each binding dies after its iteration, so
    // identical sequential locals must not be accumulated as if all iterations remained live.
    let payload = "x".repeat(32 * 1024);
    let stylesheet = compile(&format!(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:for-each select="root/item"><xsl:variable name="payload" select="'{payload}'"/></xsl:for-each></xsl:template></xsl:stylesheet>"#
    ));
    let source_xml = format!("<root>{}</root>", "<item/>".repeat(64));
    let source = Document::parse(&source_xml, None).expect("source parses");
    let mut budget = execution_budget(1024);
    budget.owned_bytes = 6 * 1024 * 1024;
    stylesheet
        .execute(
            &source,
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("sequential local bindings remain below the peak-memory ceiling");
}

#[test]
fn sequential_sorts_release_transient_workspace() {
    // OwnedBytes is a peak-live-memory ceiling. Each inner sort completes before the next outer
    // iteration, so structural workspace and text collation keys must not accumulate.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:for-each select="root/group"><xsl:apply-templates select="/root/item"><xsl:sort select="."/></xsl:apply-templates></xsl:for-each></xsl:template><xsl:template match="item"/></xsl:stylesheet>"#,
    );
    let item = format!("<item>{}</item>", "x".repeat(128));
    let source_xml = format!("<root>{}{}</root>", "<group/>".repeat(64), item.repeat(16));
    let source = Document::parse(&source_xml, None).expect("source parses");
    let mut budget = execution_budget(source_xml.len());
    budget.owned_bytes = 256 * 1024;
    stylesheet
        .execute(
            &source,
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("sequential sorts remain below the peak-memory ceiling");
}

#[test]
fn repeated_attribute_overrides_release_replaced_storage() {
    // XSLT 1.0 section 7.1.3 makes the last attribute with an expanded name win. Replaced values
    // are no longer live result-tree storage and therefore must not accumulate against the peak
    // OwnedBytes ceiling: https://www.w3.org/TR/1999/REC-xslt-19991116#creating-attributes
    let payload = "x".repeat(32 * 1024);
    let attributes = (0..64)
        .map(|_| r#"<xsl:attribute name="value"><xsl:value-of select="/source"/></xsl:attribute>"#)
        .collect::<String>();
    let stylesheet = compile(&format!(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><result>{attributes}</result></xsl:template></xsl:stylesheet>"#
    ));
    let source_xml = format!("<source>{payload}</source>");
    let source = Document::parse(&source_xml, None).expect("source parses");
    let mut budget = execution_budget(source_xml.len());
    budget.owned_bytes = 768 * 1024;
    let result = stylesheet
        .execute(
            &source,
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("only the final attribute value remains live");
    assert!(
        String::from_utf8(result.serialized.bytes)
            .expect("UTF-8 output")
            .contains(&payload)
    );
}

#[test]
fn repeated_namespace_overrides_release_replaced_storage() {
    // Namespace nodes with the same prefix replace one another on a result element. Only the
    // final URI remains live, so prior bindings must not accumulate against OwnedBytes.
    let copies = r#"<xsl:copy-of select="root/item/namespace::*[name() = 'p']"/>"#.repeat(4);
    let stylesheet = compile(&format!(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><result>{copies}</result></xsl:template></xsl:stylesheet>"#,
    ));
    let payload = "x".repeat(4 * 1024);
    let items = (0..64)
        .map(|index| format!(r#"<item xmlns:p="urn:{index}:{payload}"/>"#))
        .collect::<String>();
    let source_xml = format!("<root>{items}</root>");
    let source = Document::parse(&source_xml, None).expect("source parses");
    let mut budget = execution_budget(source_xml.len());
    budget.owned_bytes = 2 << 20;
    let result = stylesheet
        .execute(
            &source,
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("only the final namespace binding remains live");
    let output = String::from_utf8(result.serialized.bytes).expect("UTF-8 output");
    assert!(output.contains("xmlns:p=\"urn:63:"));
}

#[test]
fn xpath_sessions_do_not_clone_retained_result_tree_fragments() {
    // The retained RTF and its XPath string projection fit together. Registering a second owned
    // tree in the generic XPath session would cross this operation ceiling.
    let payload = "x".repeat(128 * 1024);
    let stylesheet = compile(&format!(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:variable name="payload"><xsl:text>{payload}</xsl:text></xsl:variable><xsl:if test="contains($payload, 'missing')">unexpected</xsl:if></xsl:template></xsl:stylesheet>"#
    ));
    let mut budget = execution_budget(1024);
    budget.owned_bytes = 576 * 1024;
    let result = stylesheet
        .execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("borrowed RTF session remains inside the allocation gate");
    assert!(result.serialized.bytes.is_empty());
}

#[test]
fn generic_xpath_accounts_for_result_tree_fragment_projections() {
    // A generic XPath context owns an SXD string projection for every in-scope RTF. The duplicate
    // must fit beside the retained fragment even when the expression never reads that variable.
    let payload = "x".repeat(64 * 1024);
    let stylesheet = compile(&format!(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template name="baseline"><xsl:variable name="payload"><xsl:text>{payload}</xsl:text></xsl:variable></xsl:template><xsl:template name="xpath"><xsl:variable name="payload"><xsl:text>{payload}</xsl:text></xsl:variable><xsl:if test="1 + 1 = 2"/></xsl:template></xsl:stylesheet>"#
    ));

    let baseline = minimum_execution_owned_bytes(&stylesheet, "baseline");
    let xpath = minimum_execution_owned_bytes(&stylesheet, "xpath");
    assert!(
        xpath >= baseline + payload.len(),
        "the SXD projection of every in-scope RTF must fit the peak-memory budget"
    );
}

#[test]
fn generate_id_cache_is_charged_to_retained_owned_memory() {
    // Deep node paths make generate-id's retained identity cache grow quadratically even when
    // the XPath result is one number; the cache must remain inside the operation memory budget.
    let mut source_xml = String::new();
    for _ in 0..192 {
        source_xml.push_str("<n>");
    }
    for _ in 0..192 {
        source_xml.push_str("</n>");
    }
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="count(//*[generate-id(.)])"/></xsl:template></xsl:stylesheet>"#,
    );
    let mut budget = execution_budget(source_xml.len());
    budget.recursion_depth = 512;
    budget.owned_bytes = 1408 * 1024;
    let result = stylesheet.execute(
        &Document::parse(&source_xml, None).expect("deep source parses"),
        &Parameters::new(),
        Arc::new(NoResolver),
        ExecutionOptions {
            budget,
            initial_mode: None,
            initial_template: None,
        },
    );
    assert!(matches!(
        result,
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
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
fn core_concat_maps_preallocation_rejection_to_the_owned_bytes_budget() {
    // The XPath fork must reject the aggregate concat reservation before constructing it, while
    // the public engine preserves the typed operation-budget error.
    let arguments = std::iter::repeat_n("string(/*)", 64)
        .collect::<Vec<_>>()
        .join(",");
    let stylesheet = compile(&format!(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="concat({arguments})"/></xsl:template></xsl:stylesheet>"#
    ));
    let source_xml = format!("<source>{}</source>", "x".repeat(16 * 1024));
    let mut budget = execution_budget(source_xml.len());
    budget.owned_bytes = source_xml.len() + (128 * 1024);
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
fn xpath_extension_string_coercions_reserve_their_peak_memory() {
    // Node-set coercion materializes the selected node's complete string-value. Functions that
    // return only a boolean or an empty URI must still reserve that temporary before allocating it.
    let payload = "a".repeat(64 * 1024);
    let source_xml = format!("<source>{payload}</source>");
    let source = Document::parse(&source_xml, None).expect("large source parses");
    let baseline = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"/></xsl:stylesheet>"#,
    );
    let unparsed = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:if test="unparsed-entity-uri(/*) = ''"/></xsl:template></xsl:stylesheet>"#,
    );
    let compatibility = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:lib="http://xmlsoft.org/XSLT/"><xsl:template match="/"><xsl:if test="lib:test(/*) = ''"/></xsl:template></xsl:stylesheet>"#,
    );
    let capability = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:if test="function-available(/*)"/></xsl:template></xsl:stylesheet>"#,
    );

    let baseline_bytes =
        minimum_execution_owned_bytes_for_source(&baseline, &source, source_xml.len());
    for stylesheet in [&unparsed, &compatibility, &capability] {
        assert!(
            minimum_execution_owned_bytes_for_source(stylesheet, &source, source_xml.len())
                >= baseline_bytes.saturating_add(payload.len()),
            "string coercion must fit beside the retained source"
        );
    }
}

#[test]
fn template_candidate_scans_are_bounded_as_pattern_work() {
    // Selection scans are attacker-controlled work even when every cheap mode/name check rejects.
    let decoys = (0..64)
        .map(|index| format!(r#"<xsl:template match="decoy-{index}" mode="unused"/>"#))
        .collect::<String>();
    let stylesheet = compile(&format!(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">{decoys}<xsl:template match="/"/></xsl:stylesheet>"#
    ));
    let mut budget = execution_budget(1024);
    budget.pattern_evaluations = 0;
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
            kind: BudgetKind::PatternEvaluations,
            ..
        })
    ));
}

#[test]
fn normalize_space_fast_path_preflights_its_output_allocation() {
    // The optimized normalize-space path consumes attacker-controlled source text. It must honor
    // the same OwnedBytes preallocation contract as the general XPath implementation without
    // reserving discarded whitespace. This mostly-whitespace value therefore fits the budget.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="source"><xsl:value-of select="normalize-space(.)"/></xsl:template></xsl:stylesheet>"#,
    );
    let payload = format!("{}word{}", " ".repeat(64 * 1024), " ".repeat(64 * 1024));
    let source_xml = format!("<source>{payload}</source>");
    let mut budget = execution_budget(source_xml.len());
    budget.owned_bytes = source_xml.len().saturating_mul(4);
    let output = stylesheet
        .execute(
            &Document::parse(&source_xml, None).expect("source parses"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("discarded whitespace is not reserved as result storage");
    assert_eq!(output.serialized.bytes, b"word");

    // A result that retains the attacker-controlled payload must fail before reserving it.
    let source_xml = format!("<source>{}</source>", "x".repeat(128 * 1024));
    let mut budget = execution_budget(source_xml.len());
    budget.owned_bytes = source_xml.len().saturating_mul(4);
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
fn translate_preflights_all_transient_workspace() {
    // The canonical XPath implementation must reserve its source conversion, replacement index,
    // and worst-case UTF-8 result before any attacker-sized workspace is allocated.
    let payload = "a".repeat(128 * 1024);
    let source_xml = format!("<source><value>{payload}</value></source>");
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:param name="from" select="'a'"/><xsl:param name="to" select="'b'"/><xsl:template match="source"><xsl:value-of select="translate(value, $from, $to)"/></xsl:template></xsl:stylesheet>"#,
    );
    let mut budget = execution_budget(source_xml.len());
    budget.owned_bytes = 1024 * 1024;
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
fn attribute_value_templates_preflight_transient_growth() {
    // Repeating source-derived text in an AVT must be bounded before the combined allocation.
    let value = "x".repeat(32 * 1024);
    let source_xml = format!("<source value=\"{value}\"/>");
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><out value="{/*/@value}{/*/@value}"/></xsl:template></xsl:stylesheet>"#,
    );
    let mut budget = execution_budget(source_xml.len());
    budget.owned_bytes = source_xml.len() + value.len() + 4096;
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
fn retained_secondary_output_uris_share_the_owned_byte_budget() {
    // Each URI remains live in TransformResult, so repeated large AVT values must accumulate
    // against OwnedBytes instead of being treated as independent temporary strings.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xt="http://www.jclark.com/xt" extension-element-prefixes="xt"><xsl:template match="/"><xt:document href="{concat(string(/source), '1')}" method="text"/><xt:document href="{concat(string(/source), '2')}" method="text"/><xt:document href="{concat(string(/source), '3')}" method="text"/><xt:document href="{concat(string(/source), '4')}" method="text"/></xsl:template></xsl:stylesheet>"#,
    );
    let payload = "u".repeat(128 * 1024);
    let source_xml = format!("<source>{payload}</source>");
    let source = Document::parse(&source_xml, None).expect("source parses");
    let mut budget = execution_budget(1 << 20);
    budget.owned_bytes = 700 * 1024;
    let error = stylesheet
        .execute(
            &source,
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect_err("retained output URIs must exhaust the aggregate owned-byte budget");
    assert!(matches!(
        error,
        Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        }
    ));
}

#[test]
fn dynamic_secondary_output_metadata_consumes_owned_bytes() {
    // The AVT result is copied into the transient output definition and then into the retained
    // SerializedOutput metadata, so both simultaneously live copies belong to the peak budget.
    let payload = "m".repeat(64 * 1024);
    let stylesheet = compile(&format!(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xt="http://www.jclark.com/xt" extension-element-prefixes="xt"><xsl:template name="baseline"><xt:document href="memory:out" method="text"/></xsl:template><xsl:template name="metadata"><xt:document href="memory:out" method="text" media-type="{payload}"/></xsl:template></xsl:stylesheet>"#
    ));
    let baseline_bytes = minimum_execution_owned_bytes(&stylesheet, "baseline");
    let metadata_bytes = minimum_execution_owned_bytes(&stylesheet, "metadata");
    assert!(
        metadata_bytes >= baseline_bytes + payload.len() + payload.len() / 2,
        "baseline={baseline_bytes}, metadata={metadata_bytes}, payload={}",
        payload.len()
    );
}

#[test]
fn sequential_secondary_outputs_release_temporary_fragment_memory() {
    // Serialized secondary outputs remain live, but their source fragments are temporary and
    // must not accumulate against the peak-live OwnedBytes ceiling.
    let payload = "x".repeat(4096);
    let outputs = (0..32)
        .map(|index| {
            format!(
                r#"<xt:document href="memory:{index}.xml"><detail>{payload}</detail></xt:document>"#
            )
        })
        .collect::<String>();
    let stylesheet = compile(&format!(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xt="http://www.jclark.com/xt" extension-element-prefixes="xt"><xsl:template match="/">{outputs}</xsl:template></xsl:stylesheet>"#
    ));
    let mut budget = execution_budget(1024);
    budget.owned_bytes = 1 << 20;
    let result = stylesheet
        .execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("temporary secondary-output fragments remain below the peak-memory ceiling");
    assert_eq!(result.secondary_outputs.len(), 32);
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
fn optimized_preceding_comment_uses_xpath_xml_whitespace() {
    // normalize-space() removes only XML S characters; NBSP remains non-empty and therefore
    // prevents an earlier comment from satisfying the optimized sibling expression.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:apply-templates select="root/target"/></xsl:template><xsl:template match="target"><xsl:apply-templates select="preceding-sibling::node()[normalize-space()][1][self::comment()]"/></xsl:template><xsl:template match="comment()">found</xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<root><!--kept-->   <target/></root>"),
        "found"
    );
    assert_eq!(
        execute(stylesheet, "<root><!--older-->\u{a0}<target/></root>"),
        ""
    );
}

#[test]
fn namespace_axis_excludes_default_namespace_undeclarations() {
    // xmlns="" is retained in the semantic tree for serialization, but XPath 1.0 exposes no
    // namespace node for a prefix whose in-scope namespace URI is empty.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="count(/*/*/namespace::*)"/></xsl:template></xsl:stylesheet>"#;
    let source = Document::parse(r#"<root xmlns="urn:outer"><child xmlns=""/></root>"#, None)
        .expect("source parses");
    let NodeKind::Element { namespaces, .. } = &source
        .node(node_id_at(&source, 2))
        .expect("child exists")
        .kind
    else {
        panic!("child is an element");
    };
    assert_eq!(
        namespaces
            .iter()
            .filter(|namespace| !namespace.uri.is_empty())
            .map(|namespace| (namespace.prefix.as_deref(), namespace.uri.as_str()))
            .collect::<Vec<_>>(),
        vec![(Some("xml"), "http://www.w3.org/XML/1998/namespace")]
    );
    assert_eq!(
        execute(
            stylesheet,
            r#"<root xmlns="urn:outer"><child xmlns=""/></root>"#
        ),
        "1"
    );
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
    // https://www.w3.org/TR/1999/REC-xslt-19991116#section-HTML-Output-Method
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:x="urn:foreign"><xsl:output method="html" indent="no"/><xsl:template match="/"><html><head profile="é path"/><body background="é path"><div href="é"/><foo src="é"/><a href="é path" x:href="é"/><object archive="é" classid="é" codebase="é" data="é"/></body></html></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<source/>"),
        "<html xmlns:x=\"urn:foreign\"><head profile=\"%C3%A9 path\"><meta charset=\"UTF-8\"></head><body background=\"%C3%A9 path\"><div href=\"é\"></div><foo src=\"é\"></foo><a href=\"%C3%A9%20path\" x:href=\"é\"></a><object archive=\"%C3%A9\" classid=\"%C3%A9\" codebase=\"%C3%A9\" data=\"%C3%A9\"></object></body></html>"
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
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(4096, 0, 32, 16 * 1024),
        )
        .compile(invalid, None),
        Err(Error::Static(message)) if message.contains("xsl:number") && message.contains("level")
    ));
    for level in ["single", "multiple", "any"] {
        let valid = invalid.replace("sideways", level);
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(4096, 0, 32, 16 * 1024),
        )
        .compile(&valid, None)
        .expect("defined xsl:number level compiles");
    }

    let forward = r#"<xsl:stylesheet version="2.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:apply-templates select="root/item[2]"/></xsl:template><xsl:template match="item"><xsl:number level="future-level"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(forward, "<root><item/><item/></root>"), "2");
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
fn xml_output_rejects_unsupported_declaration_versions() {
    // The serializer implements XML 1.0 and 1.1 character rules only; it must not emit a
    // declaration for an unknown version while silently validating the result as XML 1.0.
    for version in ["", "2.0"] {
        let stylesheet = compile(&format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="xml" version="{version}"/><xsl:template match="/"><out/></xsl:template></xsl:stylesheet>"#
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
            Err(Error::Serialization(message))
                if message.contains("XML output version") && message.contains(version)
        ));
    }
}

#[test]
fn optimized_translate_uses_the_first_duplicate_mapping() {
    // XPath translate() assigns by source position, then keeps only the first mapping for a
    // duplicate source character; the duplicate still consumes its target position.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:param name="from" select="'abac'"/><xsl:param name="to" select="'WXYZ'"/><xsl:template match="/"><xsl:apply-templates select="root/item"/></xsl:template><xsl:template match="item"><xsl:value-of select="translate(., $from, $to)"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<root><item>ac</item></root>"), "WZ");
}

#[test]
fn optimized_relative_paths_return_an_attribute_owner_for_parent_axis() {
    // XPath defines an attribute's parent as its owner element; the optimized translate path
    // must not skip to the owner's parent and include ancestor text in the string value.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:param name="from" select="'owner'"/><xsl:param name="to" select="'OWNER'"/><xsl:template match="/"><xsl:apply-templates select="root/item"/></xsl:template><xsl:template match="item"><xsl:value-of select="translate(@code/.., $from, $to)"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(
            stylesheet,
            "<root>ancestor<item code=\"x\">owner</item></root>"
        ),
        "OWNER"
    );
}

#[test]
fn temporary_result_trees_isolate_attribute_insertion_state() {
    // An attribute-set insertion cursor belongs to the outer element; nested variable trees start
    // with an independent empty attribute sequence and must not inherit that cursor.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes"/><xsl:attribute-set name="attrs"><xsl:attribute name="first">one</xsl:attribute><xsl:attribute name="second"><xsl:variable name="fragment"><tmp><xsl:attribute name="nested">x</xsl:attribute></tmp></xsl:variable><xsl:value-of select="$fragment"/></xsl:attribute></xsl:attribute-set><xsl:template match="/"><out existing="yes" xsl:use-attribute-sets="attrs"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<source/>"),
        "<out first=\"one\" second=\"\" existing=\"yes\"/>\n"
    );
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
fn xml_doctype_rejects_fragmented_system_identifiers() {
    // XML 1.0 section 4.2.2 makes a fragment identifier in a SystemLiteral an error:
    // https://www.w3.org/TR/xml/#sec-external-ent
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes" doctype-system="schema.dtd#part"/><xsl:template match="/"><root/></xsl:template></xsl:stylesheet>"#;
    assert!(matches!(
        compile(stylesheet).execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        ),
        Err(Error::Serialization(message))
            if message.contains("system identifier") && message.contains("fragment")
    ));
}

#[test]
fn exslt_token_arguments_count_temporary_string_values() {
    // Both node-set conversions remain live while str:split builds its token document. Their
    // complete peak footprint must cross OwnedBytes even when the delimiter consumes all input.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:str="http://exslt.org/strings"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="count(str:split(/root, /root))"/></xsl:template></xsl:stylesheet>"#,
    );
    let payload = "x".repeat(1 << 20);
    let source_xml = format!("<root>{payload}</root>");
    let source = Document::parse(&source_xml, None).expect("source parses");
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
fn xml_doctype_rejects_invalid_public_identifier_characters() {
    // XML output must never serialize a PUBLIC literal outside the XML PubidChar grammar.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes" doctype-public="bad&lt;id" doctype-system="result.dtd"/><xsl:template match="/"><root/></xsl:template></xsl:stylesheet>"#;
    assert!(matches!(
        compile(stylesheet).execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        ),
        Err(Error::Serialization(message)) if message.contains("public identifier")
    ));
    let valid = stylesheet.replace("bad&lt;id", "-//W3C//DTD XHTML 1.0 Strict//EN");
    assert!(execute(&valid, "<source/>").contains("PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\""));
}

#[test]
fn global_dependencies_follow_called_named_templates() {
    // A global's value may depend on a later global through a named template call.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:variable name="first"><xsl:call-template name="build"/></xsl:variable><xsl:variable name="later" select="'ready'"/><xsl:template name="build"><xsl:value-of select="$later"/></xsl:template><xsl:template match="/"><xsl:value-of select="$first"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "ready");
}

#[test]
fn supplied_template_parameters_skip_unreachable_default_dependencies() {
    // A supplied parameter prevents its default from being evaluated, so that unreachable
    // expression must not create a false cycle back to the global that calls the template.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:variable name="value"><xsl:call-template name="build"><xsl:with-param name="input" select="'ready'"/></xsl:call-template></xsl:variable><xsl:template name="build"><xsl:param name="input" select="$value"/><xsl:value-of select="$input"/></xsl:template><xsl:template match="/"><xsl:value-of select="$value"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "ready");
}

#[test]
fn unsupplied_template_parameters_preserve_default_dependencies() {
    // The same default remains reachable when no with-param overrides it and must order globals.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:variable name="value"><xsl:call-template name="build"/></xsl:variable><xsl:variable name="later" select="'ready'"/><xsl:template name="build"><xsl:param name="input" select="$later"/><xsl:value-of select="$input"/></xsl:template><xsl:template match="/"><xsl:value-of select="$value"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "ready");
}

#[test]
fn global_dependencies_follow_reachable_exslt_functions() {
    // Function bodies belong to the reachable dependency graph. Recursive calls must terminate
    // collection while preserving references to globals declared later in stylesheet order.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:func="http://exslt.org/functions" xmlns:f="urn:functions" extension-element-prefixes="func"><xsl:output method="text"/><xsl:variable name="first" select="f:build(1)"/><xsl:variable name="later" select="'ready'"/><func:function name="f:build"><xsl:param name="remaining"/><xsl:choose><xsl:when test="$remaining &gt; 0"><func:result select="f:build($remaining - 1)"/></xsl:when><xsl:otherwise><func:result select="$later"/></xsl:otherwise></xsl:choose></func:function><xsl:template match="/"><xsl:value-of select="$first"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "ready");
}

#[test]
fn local_bindings_cannot_shadow_still_visible_template_variables() {
    // A local binding remains visible to following siblings and descendants, but bindings in a
    // completed child scope and top-level globals may legally reuse the same expanded name.
    for body in [
        r#"<xsl:variable name="value" select="1"/><xsl:variable name="value" select="2"/>"#,
        r#"<xsl:param name="value"/><xsl:variable name="value" select="2"/>"#,
        r#"<xsl:variable name="value" select="1"/><xsl:if test="true()"><xsl:variable name="value" select="2"/></xsl:if>"#,
    ] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/">{body}</xsl:template></xsl:stylesheet>"#
        );
        assert!(matches!(
            Compiler::new(
                Arc::new(NoResolver),
                CompileBudget::new(1 << 20, 8, 256, 1 << 20),
            )
            .compile(&stylesheet, Some("memory:shadow.xsl")),
            Err(Error::Static(message)) if message.contains("shadows")
        ));
    }

    compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:variable name="value" select="'global'"/><xsl:template match="/"><xsl:if test="true()"><xsl:variable name="value" select="'first scope'"/></xsl:if><xsl:if test="true()"><xsl:variable name="value" select="'second scope'"/></xsl:if><xsl:variable name="value" select="'local'"/></xsl:template></xsl:stylesheet>"#,
    );
}

#[test]
fn global_dependencies_follow_only_selectable_apply_templates() {
    // Named-only and different-mode templates cannot participate in this dispatch, so their
    // global references must not create a false dependency cycle.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes"/><xsl:variable name="first"><xsl:apply-templates select="/" mode="selected"/></xsl:variable><xsl:variable name="later" select="$first"/><xsl:template name="named-only"><xsl:value-of select="$later"/></xsl:template><xsl:template match="/" mode="other"><xsl:value-of select="$later"/></xsl:template><xsl:template match="/" mode="selected"><ready/></xsl:template><xsl:template match="/"><xsl:copy-of select="$first"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "<ready/>\n");
}

#[test]
fn global_dependencies_follow_nested_attribute_sets_on_all_consumers() {
    // Every instruction that applies an attribute set must defer its global until expressions in
    // nested sets can read globals declared later in stylesheet order.
    for body in [
        r#"<literal xsl:use-attribute-sets="outer"/>"#,
        r#"<xsl:element name="computed" use-attribute-sets="outer"/>"#,
        r#"<xsl:for-each select="/*"><xsl:copy use-attribute-sets="outer"/></xsl:for-each>"#,
    ] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:exsl="http://exslt.org/common"><xsl:output method="text"/><xsl:attribute-set name="outer" use-attribute-sets="inner"/><xsl:attribute-set name="inner"><xsl:attribute name="state"><xsl:value-of select="$later"/></xsl:attribute></xsl:attribute-set><xsl:variable name="first">{body}</xsl:variable><xsl:variable name="later" select="'ready'"/><xsl:template match="/"><xsl:value-of select="exsl:node-set($first)/*/@state"/></xsl:template></xsl:stylesheet>"#
        );
        assert_eq!(execute(&stylesheet, "<source/>"), "ready");
    }
}

#[test]
fn computed_elements_use_the_default_and_prefixed_static_namespaces() {
    // Unlike xsl:attribute, XSLT 1.0 expands an unprefixed xsl:element name through the default
    // namespace in scope on the instruction; explicit prefixes use the same static context.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns="urn:stylesheet" xmlns:p="urn:result" xmlns:r="urn:wrapper"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><r:wrapper><xsl:element name="out"/><xsl:element name="p:out"/></r:wrapper></xsl:template></xsl:stylesheet>"#;
    let output = execute(stylesheet, "<source/>");
    let output = Document::parse(&output, None).expect("serialized result parses");
    let names = output
        .nodes()
        .filter_map(|(_, node)| match &node.kind {
            xml_sec_xslt::NodeKind::Element { name, .. } if name.local == "out" => {
                Some(name.namespace.as_deref())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(names, [Some("urn:stylesheet"), Some("urn:result")]);
}

#[test]
fn key_patterns_use_the_parsed_attribute_axis() {
    // XML whitespace around the axis separator is grammatical and must not hide attribute
    // candidates from the key index builder.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:key name="by-id" match="attribute :: id" use="."/><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="count(key('by-id', 'needle'))"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<root id=\"needle\"/>"), "1");
}

#[test]
fn xinclude_preserves_principal_and_included_id_metadata() {
    // XInclude projection must remap caller-supplied typed IDs and XML IDs into the completed
    // logical document rather than rebuilding only node kinds.
    let resolver = Arc::new(ContextResolver::default());
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert(
            ("included.xml".into(), Some("memory:source.xml".into())),
            ResolvedResource {
                canonical_uri: "memory:included.xml".into(),
                identity: ResourceIdentity("included".into()),
                bytes: br#"<included xml:id="included-id"/>"#.to_vec(),
                media_type: Some("application/xml".into()),
                encoding: None,
            },
        );
    let mut source = Document::parse(
        r#"<root custom-id="principal-id" xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="included.xml"/></root>"#,
        Some("memory:source.xml"),
    )
    .expect("source parses");
    let owner = source
        .nodes()
        .find_map(|(id, node)| matches!(&node.kind, xml_sec_xslt::NodeKind::Element { name, .. } if name.local == "root").then_some(id))
        .expect("root element exists");
    source
        .mark_id_attribute(owner, 0)
        .expect("caller ID metadata is valid");
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="count(id('principal-id'))"/><xsl:text>|</xsl:text><xsl:value-of select="count(id('included-id'))"/></xsl:template></xsl:stylesheet>"#,
    );
    let result = stylesheet
        .execute_with_source_processing(
            &source,
            &Parameters::new(),
            resolver,
            ExecutionOptions {
                budget: execution_budget(4096),
                initial_mode: None,
                initial_template: None,
            },
            xml_sec_xslt::SourceProcessing::XInclude,
        )
        .expect("XInclude transform succeeds");
    assert_eq!(result.serialized.bytes, b"1|1");
}

#[test]
fn xpath_id_splits_arguments_only_on_xml_whitespace() {
    // VT and FF are ASCII whitespace but not XML S, so they remain part of an unmatched ID token.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:param name="ids"/><xsl:template match="/"><xsl:value-of select="count(id($ids))"/></xsl:template></xsl:stylesheet>"#,
    );
    let source = Document::parse(r#"<root xml:id="known-id"/>"#, None).expect("source parses");
    for (value, expected) in [
        ("\u{000b}known-id", b"0".as_slice()),
        ("\u{000c}known-id", b"0".as_slice()),
        ("\tknown-id\r\n", b"1".as_slice()),
    ] {
        let mut parameters = Parameters::new();
        parameters.insert(
            ExpandedName::new(None::<String>, "ids"),
            Value::String(value.into()),
        );
        let result = stylesheet
            .execute(
                &source,
                &parameters,
                Arc::new(NoResolver),
                ExecutionOptions {
                    budget: execution_budget(1024),
                    initial_mode: None,
                    initial_template: None,
                },
            )
            .expect("id lookup executes");
        assert_eq!(result.serialized.bytes, expected, "argument {value:?}");
    }
}

#[test]
fn rejected_duplicate_typed_id_preserves_the_registered_owner() {
    // Duplicate registration must not replace the accepted owner before returning its error;
    // subsequent XPath id() lookup must retain the document's last valid ID index state.
    let mut source = Document::parse(
        r#"<root><first custom-id="same"/><second custom-id="same"/></root>"#,
        Some("memory:source.xml"),
    )
    .expect("source parses");
    let first = source
        .nodes()
        .find_map(|(id, node)| match &node.kind {
            NodeKind::Element { name, .. } if name.local == "first" => Some(id),
            _ => None,
        })
        .expect("first ID owner exists");
    let second = source
        .nodes()
        .find_map(|(id, node)| match &node.kind {
            NodeKind::Element { name, .. } if name.local == "second" => Some(id),
            _ => None,
        })
        .expect("second ID owner exists");
    source
        .mark_id_attribute(first, 0)
        .expect("first typed ID is accepted");
    let error = source
        .mark_id_attribute(second, 0)
        .expect_err("duplicate typed ID is rejected");
    assert!(matches!(error, Error::Xml(message) if message.contains("duplicate XML ID")));

    let result = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="name(id('same'))"/></xsl:template></xsl:stylesheet>"#,
    )
    .execute(
        &source,
        &Parameters::new(),
        Arc::new(NoResolver),
        ExecutionOptions {
            budget: execution_budget(1024),
            initial_mode: None,
            initial_template: None,
        },
    )
    .expect("lookup after rejected registration succeeds");
    assert_eq!(result.serialized.bytes, b"first");
}

#[derive(Default)]
struct ByteResolver {
    resources: Mutex<HashMap<String, Vec<u8>>>,
}

impl Resolver for ByteResolver {
    fn resolve(
        &self,
        uri: &str,
        _base_uri: Option<&str>,
        _purpose: ResolvePurpose,
    ) -> xml_sec_xslt::Result<ResolvedResource> {
        Ok(ResolvedResource {
            canonical_uri: format!("memory:{uri}"),
            identity: ResourceIdentity(uri.into()),
            bytes: self
                .resources
                .lock()
                .expect("test resolver mutex is not poisoned")
                .get(uri)
                .cloned()
                .ok_or_else(|| Error::Resolver {
                    uri: uri.into(),
                    message: "missing byte resource".into(),
                })?,
            media_type: Some("application/xml".into()),
            encoding: None,
        })
    }
}

#[test]
fn external_xml_autodetects_declared_and_initial_encodings() {
    // Resolver metadata is optional for XML resources: declarations and the XML initial-byte
    // patterns remain authoritative when callers return raw bytes.
    let resolver = Arc::new(ByteResolver::default());
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert(
            "latin1.xsl".into(),
            b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"><xsl:output method=\"text\"/><xsl:template match=\"/\">caf\xe9</xsl:template></xsl:stylesheet>".to_vec(),
        );
    let principal = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:import href="latin1.xsl"/></xsl:stylesheet>"#;
    let stylesheet = Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(principal, Some("memory:main.xsl"))
    .expect("declared Latin-1 stylesheet compiles");
    let result = stylesheet
        .execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &Parameters::new(),
            resolver,
            ExecutionOptions {
                budget: execution_budget(4096),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("encoded stylesheet executes");
    assert_eq!(result.serialized.bytes, "café".as_bytes());
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
fn computed_names_reject_unbound_xmlns_prefix() {
    // XSLT 1.0 sections 7.1.2 and 7.1.3 require a QName prefix to resolve through the namespace
    // declarations in scope when no namespace AVT supplies the expanded name.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#creating-elements-with-xsl-element
    for instruction in [
        r#"<xsl:element name="xmlns:item"/>"#,
        r#"<out><xsl:attribute name="xmlns:item">value</xsl:attribute></out>"#,
    ] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/">{instruction}</xsl:template></xsl:stylesheet>"#
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
            .expect_err("an unbound reserved prefix must not be discarded");
        assert!(matches!(error, Error::Dynamic(message) if message.contains("xmlns")));
    }
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
    // The private package wrapper is never a relative of a logical document root.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="count(parent::node())"/><xsl:text>|</xsl:text><xsl:value-of select="count(ancestor::node())"/><xsl:text>|</xsl:text><xsl:value-of select="count(..)"/><xsl:text>|</xsl:text><xsl:value-of select="count(following-sibling::node())"/><xsl:text>|</xsl:text><xsl:value-of select="count(preceding-sibling::node())"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "0|0|0|0|0");
}

#[test]
fn empty_result_tree_fragments_are_true_singleton_root_node_sets() {
    // XSLT boolean conversion observes the fragment root even when it has no children.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:variable name="empty"><xsl:if test="false()"><never/></xsl:if></xsl:variable><xsl:template match="/"><xsl:if test="$empty">direct</xsl:if><xsl:text>|</xsl:text><xsl:value-of select="boolean($empty)"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "direct|true");
    assert!(Value::ResultTreeFragment(Arc::new(Document::empty(None))).into_boolean());
}

#[test]
fn result_tree_fragment_clones_share_document_storage() {
    // Variable snapshots and XPath continuation sessions clone Value handles frequently; the
    // immutable temporary tree itself must remain single-allocation shared storage.
    let value = Value::ResultTreeFragment(Arc::new(
        Document::parse("<temporary><payload/></temporary>", None).expect("fragment parses"),
    ));
    let cloned = value.clone();
    let (Value::ResultTreeFragment(original), Value::ResultTreeFragment(cloned)) = (value, cloned)
    else {
        panic!("both values retain result-tree fragments");
    };
    assert!(Arc::ptr_eq(&original, &cloned));
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
fn default_namespace_alias_does_not_qualify_unprefixed_attributes() {
    // Namespaces in XML 1.0 section 6.2 excludes unprefixed attributes from the default namespace,
    // so aliasing the default element namespace cannot qualify a literal unprefixed attribute.
    // https://www.w3.org/TR/REC-xml-names/#defaulting
    let stylesheet = r##"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:r="urn:result"><xsl:namespace-alias stylesheet-prefix="#default" result-prefix="r"/><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><out attribute="value"/></xsl:template></xsl:stylesheet>"##;
    assert_eq!(
        execute(stylesheet, "<source/>"),
        "<r:out xmlns:r=\"urn:result\" attribute=\"value\"/>\n"
    );
}

#[test]
fn namespace_alias_preserves_the_element_binding_across_import_conflicts() {
    // The aliased element QName owns its chosen prefix. A same-prefix namespace copied from the
    // importing module must be renamed rather than changing the element's expanded name.
    let resolver = Arc::new(ContextResolver::default());
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert(
            (
                "imported.xsl".into(),
                Some("https://example.test/main.xsl".into()),
            ),
            ResolvedResource {
                canonical_uri: "https://example.test/imported.xsl".into(),
                identity: ResourceIdentity("namespace-alias-import".into()),
                bytes: br#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:old="urn:old" xmlns:new="urn:aliased"><xsl:namespace-alias stylesheet-prefix="old" result-prefix="new"/></xsl:stylesheet>"#.to_vec(),
                media_type: None,
                encoding: Some("UTF-8".into()),
            },
        );
    let stylesheet = Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:old="urn:old" xmlns:new="urn:principal"><xsl:import href="imported.xsl"/><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><xsl:variable name="fragment"><old:item/></xsl:variable><xsl:copy-of select="$fragment"/></xsl:template></xsl:stylesheet>"#,
        Some("https://example.test/main.xsl"),
    )
    .expect("stylesheet graph compiles");
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
        .expect("namespace alias executes");
    let text = String::from_utf8(output.serialized.bytes).expect("result is UTF-8");
    assert!(text.starts_with("<new:item"), "{text}");
    assert!(text.contains("xmlns:new=\"urn:aliased\""), "{text}");
    assert!(text.contains("urn:principal"), "{text}");
}

#[test]
fn protected_attribute_sets_do_not_leak_losing_namespaces() {
    // A lower-precedence declaration with the same expanded name is ignored atomically, including
    // namespace fixup that would otherwise leave an observable namespace node behind.
    let resolver = Arc::new(ContextResolver::default());
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert(
            (
                "imported.xsl".into(),
                Some("https://example.test/main.xsl".into()),
            ),
            ResolvedResource {
                canonical_uri: "https://example.test/imported.xsl".into(),
                identity: ResourceIdentity("attribute-set-import".into()),
                bytes: br#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:q="urn:value"><xsl:attribute-set name="attrs"><xsl:attribute name="q:value">loser</xsl:attribute></xsl:attribute-set></xsl:stylesheet>"#.to_vec(),
                media_type: None,
                encoding: Some("UTF-8".into()),
            },
        );
    let stylesheet = Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:p="urn:value" xmlns:exsl="http://exslt.org/common"><xsl:import href="imported.xsl"/><xsl:output method="text"/><xsl:attribute-set name="attrs"><xsl:attribute name="p:value">winner</xsl:attribute></xsl:attribute-set><xsl:template match="/"><xsl:variable name="tree"><item xsl:use-attribute-sets="attrs"/></xsl:variable><xsl:value-of select="count(exsl:node-set($tree)/item/namespace::*[name()='q'])"/><xsl:text>|</xsl:text><xsl:value-of select="exsl:node-set($tree)/item/@p:value"/></xsl:template></xsl:stylesheet>"#,
        Some("https://example.test/main.xsl"),
    )
    .expect("stylesheet graph compiles");
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
        .expect("attribute sets execute");
    assert_eq!(output.serialized.bytes, b"0|winner");
}

#[test]
fn automatic_xml_id_registration_normalizes_the_attribute_value() {
    // xml:id normalization must update both the ID index and the XPath-visible attribute value.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="id('target')/@xml:id"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(
            stylesheet,
            r#"<root><item xml:id="  target&#x20; "/></root>"#
        ),
        "target"
    );
}

#[test]
fn dtd_declared_ids_are_available_to_xpath_id() {
    // XML 1.0 section 3.3.1 gives declared ID attributes document-wide identity semantics;
    // XPath 1.0 section 4.1 requires id() to use that typed identity information.
    // https://www.w3.org/TR/xml/#sec-attribute-types
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#function-id
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="id('target')/@name"/></xsl:template></xsl:stylesheet>"#,
    );
    let source = Document::parse(
        r#"<!DOCTYPE root [<!ATTLIST item key ID #REQUIRED>]><root><item key="target" name="found"/></root>"#,
        None,
    )
    .expect("DTD-declared ID source parses");

    let result = stylesheet
        .execute(
            &source,
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("XPath id() resolves the DTD-declared ID");
    assert_eq!(result.serialized.bytes, b"found");
}

#[test]
fn captured_result_fragments_register_normalized_xml_ids() {
    // xml:id processing applies to temporary trees before exsl:node-set() exposes them to XPath.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:exsl="http://exslt.org/common"><xsl:output method="text"/><xsl:template match="/"><xsl:variable name="tree"><root><item xml:id="  target  ">found</item></root></xsl:variable><xsl:for-each select="exsl:node-set($tree)/*"><xsl:value-of select="id('target')"/></xsl:for-each></xsl:template></xsl:stylesheet>"#;

    assert_eq!(execute(stylesheet, "<source/>"), "found");
}

#[test]
fn captured_result_fragments_reject_invalid_or_duplicate_xml_ids() {
    // Temporary trees have the same xml:id well-formedness and uniqueness contract as parsed
    // documents; invalid fragments must fail before exsl:node-set() can expose them.
    for body in [
        r#"<root><item><xsl:attribute name="xml:id" namespace="http://www.w3.org/XML/1998/namespace">not valid</xsl:attribute></item></root>"#,
        r#"<root><first><xsl:attribute name="xml:id" namespace="http://www.w3.org/XML/1998/namespace">same</xsl:attribute></first><second><xsl:attribute name="xml:id" namespace="http://www.w3.org/XML/1998/namespace">same</xsl:attribute></second></root>"#,
    ] {
        let stylesheet = compile(&format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:exsl="http://exslt.org/common"><xsl:template match="/"><xsl:variable name="tree">{body}</xsl:variable><xsl:value-of select="count(exsl:node-set($tree)/*)"/></xsl:template></xsl:stylesheet>"#
        ));
        let source = Document::parse("<source/>", None).expect("source parses");
        let error = stylesheet
            .execute(
                &source,
                &Parameters::new(),
                Arc::new(NoResolver),
                ExecutionOptions {
                    budget: execution_budget(1024),
                    initial_mode: None,
                    initial_template: None,
                },
            )
            .expect_err("invalid fragment xml:id is rejected");
        assert!(matches!(error, Error::Xml(_)), "{error:?}");
    }
}

#[test]
fn automatic_xml_id_registration_rejects_non_ncname_values() {
    // xml:id 1.0 section 4 requires the normalized value to be an NCName before registration.
    // https://www.w3.org/TR/xml-id/#processing
    for value in ["two ids", "1leading", "prefix:name"] {
        let source = format!(r#"<root xml:id="{value}"/>"#);
        assert!(matches!(
            Document::parse(&source, None),
            Err(Error::Xml(message)) if message.contains("xml:id") && message.contains("NCName")
        ));
    }
    Document::parse(r#"<root xml:id=" имя "/>"#, None)
        .expect("a normalized Unicode NCName remains a valid xml:id");
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
fn node_tests_allow_xpath_whitespace_before_the_closing_parenthesis() {
    // XPath 1.0 section 3.7 permits ExprWhitespace between grammar tokens, including here.
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#exprlex
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:apply-templates select="root/node()"/></xsl:template><xsl:template match="node( )">generic</xsl:template><xsl:template match="text( )">text</xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<root>value</root>"), "text");
}

#[test]
fn complex_namespace_wildcard_patterns_use_complex_default_priority() {
    // XSLT 1.0 section 5.5 assigns 0.5 to patterns other than the listed single-step forms.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#conflict
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:p="urn:test"><xsl:output method="text"/><xsl:template match="/"><xsl:apply-templates select="foo/p:bar"/></xsl:template><xsl:template match="foo/p:*">path</xsl:template><xsl:template match="p:bar">name</xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, r#"<foo xmlns:p="urn:test"><p:bar/></foo>"#),
        "path"
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
fn level_any_numbering_excludes_attributes_on_preceding_elements() {
    // XSLT 1.0 section 7.7 excludes attribute and namespace nodes before the current node from
    // level="any": https://www.w3.org/TR/1999/REC-xslt-19991116#number
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:apply-templates select="root/*/@id"/></xsl:template><xsl:template match="@id"><xsl:number level="any" count="@id"/><xsl:text>|</xsl:text></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<root><a id=\"x\"/><b id=\"y\"/></root>"),
        "1|1|"
    );
}

#[test]
fn apply_templates_retains_selected_nodes_inside_owned_memory_budget() {
    // Both templates run over the same source tree; selecting every child must additionally retain
    // the pending batch inside the operation-owned memory ceiling.
    let mode = format!("m:{}", "x".repeat(1024));
    let stylesheet = compile(&format!(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:m="urn:mode"><xsl:template name="one"><xsl:apply-templates select="/*/*[1]" mode="{mode}"/></xsl:template><xsl:template name="many"><xsl:apply-templates select="/*/*" mode="{mode}"/></xsl:template><xsl:template name="for-one"><xsl:for-each select="/*/*[1]"/></xsl:template><xsl:template name="for-many"><xsl:for-each select="/*/*"/></xsl:template><xsl:template match="item" mode="{mode}"/></xsl:stylesheet>"#,
    ));
    let source_xml = format!("<root>{}</root>", "<item/>".repeat(256));
    let source = Document::parse(&source_xml, None).expect("source parses");
    let minimum = |initial_template: &str| {
        let succeeds = |owned_bytes| {
            let mut budget = execution_budget(source_xml.len());
            budget.owned_bytes = owned_bytes;
            stylesheet
                .execute(
                    &source,
                    &Parameters::new(),
                    Arc::new(NoResolver),
                    ExecutionOptions {
                        budget,
                        initial_mode: None,
                        initial_template: Some(ExpandedName::new(None::<String>, initial_template)),
                    },
                )
                .is_ok()
        };
        let mut rejected = 0;
        let mut accepted = 1;
        while !succeeds(accepted) {
            rejected = accepted;
            accepted *= 2;
        }
        while rejected + 1 < accepted {
            let candidate = rejected + (accepted - rejected) / 2;
            if succeeds(candidate) {
                accepted = candidate;
            } else {
                rejected = candidate;
            }
        }
        accepted
    };
    let one = minimum("one");
    let many = minimum("many");
    assert!(
        many >= one + 128 * std::mem::size_of::<NodeReference>(),
        "one={one}, many={many}"
    );
    let for_one = minimum("for-one");
    let for_many = minimum("for-many");
    assert!(
        for_many >= for_one + 128 * std::mem::size_of::<NodeReference>(),
        "for_one={for_one}, for_many={for_many}"
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
fn generic_large_nodeset_projection_preserves_deep_document_order() {
    // More than 64 selected nodes exercises the generic projection path. Deep source paths must
    // not be duplicated into a second quadratic identity set while preserving document order.
    let depth = 192;
    let source_xml = format!("{}text{}", "<n>".repeat(depth), "</n>".repeat(depth));
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:for-each select="//*"><xsl:value-of select="position()"/><xsl:text>|</xsl:text></xsl:for-each></xsl:template></xsl:stylesheet>"#,
    );
    let result = stylesheet
        .execute(
            &Document::parse(&source_xml, None).expect("deep source parses"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(source_xml.len()),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("large node-set projects within the execution budget");
    let output = String::from_utf8(result.serialized.bytes).expect("text output is UTF-8");

    assert!(output.starts_with("1|2|3|"));
    assert!(output.ends_with(&format!("{depth}|")));
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
fn duplicate_template_parameters_are_static_errors() {
    // XSLT 1.0 section 11.5 forbids one local binding from shadowing another local binding;
    // duplicate leading parameters therefore fail before either default can execute.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#local-variables
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:a="urn:param" xmlns:b="urn:param"><xsl:template match="/"><xsl:param name="a:value" select="1"/><xsl:param name="b:value" select="2"/></xsl:template></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(1 << 20, 8, 256, 1 << 20),
        )
        .compile(stylesheet, None),
        Err(Error::Static(message)) if message.contains("shadows")
    ));
}

#[test]
fn forward_compatible_all_prefix_value_is_ignored_consistently() {
    // XSLT 1.0 section 2.5 ignores an optional attribute whose value is not allowed by 1.0;
    // extension classification must not reinterpret the ignored XSLT 2.0 #all token.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#forwards
    let stylesheet = r##"<xsl:stylesheet version="2.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:app="urn:app" extension-element-prefixes="#all"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><app:result/></xsl:template></xsl:stylesheet>"##;
    assert_eq!(
        execute(stylesheet, "<source/>"),
        r#"<app:result xmlns:app="urn:app"/>"#.to_owned() + "\n",
    );
}

#[test]
fn strict_namespace_prefix_lists_require_at_least_one_token() {
    // XSLT 1.0 sections 7.1.1 and 14.1 define these values as token lists, not optional empty
    // strings: https://www.w3.org/TR/1999/REC-xslt-19991116#literal-result-element
    for attribute in ["exclude-result-prefixes", "extension-element-prefixes"] {
        for value in ["", " \t\r\n "] {
            let stylesheet = format!(
                r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" {attribute}="{value}"/>"#,
            );
            assert!(matches!(
                Compiler::new(
                    Arc::new(NoResolver),
                    CompileBudget::new(1 << 20, 8, 256, 1 << 20),
                )
                .compile(&stylesheet, None),
                Err(Error::Static(message)) if message.contains(attribute) && message.contains("token")
            ));
        }
    }
}

#[test]
fn included_modules_validate_namespace_prefix_attributes() {
    // XSLT 1.0 section 2.6.1 treats an included module exactly like its declarations were
    // written at the include site, so an unbound prefix cannot evade principal-root validation.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#include
    let resolver = Arc::new(MemoryResolver::default());
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert(
            "invalid.xsl".into(),
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" exclude-result-prefixes="missing"/>"#.into(),
        );
    let error = Compiler::new(resolver, CompileBudget::new(1 << 20, 8, 256, 1 << 20))
        .compile(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:include href="invalid.xsl"/></xsl:stylesheet>"#,
            Some("memory:main.xsl"),
        )
        .expect_err("unbound included-module prefix must be rejected");
    assert!(matches!(error, Error::Static(message) if message.contains("not bound")));
}

#[test]
fn unused_attribute_set_cycles_are_static_errors() {
    // XSLT 1.0 section 7.1.4 makes direct or indirect self-use erroneous independently of
    // runtime reachability, so the complete declaration graph must be checked at compile time.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#attribute-sets
    for declarations in [
        r#"<xsl:attribute-set name="a" use-attribute-sets="a"/>"#,
        r#"<xsl:attribute-set name="a" use-attribute-sets="b"/><xsl:attribute-set name="b" use-attribute-sets="a"/>"#,
    ] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">{declarations}<xsl:template match="/"><out/></xsl:template></xsl:stylesheet>"#,
        );
        assert!(matches!(
            Compiler::new(
                Arc::new(NoResolver),
                CompileBudget::new(1 << 20, 8, 256, 1 << 20),
            )
            .compile(&stylesheet, None),
            Err(Error::Static(message)) if message.contains("attribute-set cycle")
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
fn document_function_decodes_uri_escaped_shorthand_pointers() {
    // XPointer Framework appendix B encodes pointer characters as UTF-8 percent escapes;
    // shorthand validation and ID lookup operate on the decoded pointer.
    // https://www.w3.org/TR/xptr-framework/#escaping
    let resolver = Arc::new(MemoryResolver::default());
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert(
            "external.xml".into(),
            r#"<doc><item xml:id="café">selected</item></doc>"#.into(),
        );
    let stylesheet = Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="document('external.xml#caf%C3%A9')"/></xsl:template></xsl:stylesheet>"#,
        Some("memory:main.xsl"),
    )
    .expect("escaped shorthand-pointer stylesheet compiles");
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
        .expect("escaped shorthand pointer resolves through the decoded XML ID");
    assert_eq!(result.serialized.bytes, b"selected");

    for fragment in ["bad%", "%GG", "%FF"] {
        let stylesheet = Compiler::new(
            resolver.clone(),
            CompileBudget::new(1 << 20, 8, 256, 1 << 20),
        )
        .compile(
            &format!(
                r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="document('external.xml#{fragment}')"/></xsl:template></xsl:stylesheet>"#
            ),
            Some("memory:main.xsl"),
        )
        .expect("malformed fragment remains a runtime URI error");
        assert!(matches!(
            stylesheet.execute(
                &Document::parse("<source/>", None).expect("source parses"),
                &Parameters::new(),
                resolver.clone(),
                ExecutionOptions {
                    budget: execution_budget(1024),
                    initial_mode: None,
                    initial_template: None,
                },
            ),
            Err(Error::Unsupported(message)) if message.contains("document fragment")
        ));
    }
}

#[test]
fn format_number_handles_fraction_precision_beyond_f64_decimal_exponents() {
    // XSLT 1.0 section 12.3 delegates picture precision to DecimalFormat; a valid high-precision
    // picture must not turn a finite value into NaN through an overflowing scale factor.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#format-number
    let picture = format!("0.{}", "#".repeat(309));
    let stylesheet = format!(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="format-number(1, '{picture}')"/></xsl:template></xsl:stylesheet>"#,
    );
    assert_eq!(execute(&stylesheet, "<source/>"), "1");
}

#[test]
fn format_number_keeps_large_finite_parameters_finite() {
    // XSLT 1.0 section 12.3 delegates formatting to DecimalFormat; intermediate rounding must not
    // turn a finite input into infinity: https://www.w3.org/TR/1999/REC-xslt-19991116#format-number
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:param name="value"/><xsl:template match="/"><xsl:value-of select="format-number($value, '0.0')"/></xsl:template></xsl:stylesheet>"#,
    );
    let mut parameters = Parameters::new();
    parameters.insert(
        ExpandedName::new(None::<String>, "value"),
        Value::Number(1e308),
    );
    let output = stylesheet
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
        .expect("finite value formats");
    let output = String::from_utf8(output.serialized.bytes).expect("text output is UTF-8");
    assert!(!output.to_ascii_lowercase().contains("inf"), "{output}");
    assert!(output.ends_with(".0"), "{output}");
}

#[test]
fn format_number_matches_libxslt_midpoint_rounding() {
    // XSLT 1.0 section 12.3 standardizes the JDK 1.1 picture syntax but leaves rounding
    // controllable by other XPath facilities. The pinned libxslt oracle rounds these ties up.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#format-number
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="format-number(1.25, '0.0')"/><xsl:text>|</xsl:text><xsl:value-of select="format-number(1.35, '0.0')"/><xsl:text>|</xsl:text><xsl:value-of select="format-number(-1.25, '0.0')"/><xsl:text>|</xsl:text><xsl:value-of select="format-number(0.0125, '0.0%')"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "1.3|1.4|-1.3|1.3%");
}

#[test]
fn format_number_suppresses_only_a_rounded_zero_integer() {
    // DecimalFormat applies the picture to the rounded result. Omitting the optional leading
    // zero must not erase an integer produced when rounding crosses the unit boundary.
    assert_eq!(
        execute(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="format-number(0.999, '.00')"/><xsl:text>|</xsl:text><xsl:value-of select="format-number(0.125, '.00')"/></xsl:template></xsl:stylesheet>"#,
            "<source/>",
        ),
        "1.00|.13",
    );
}

#[test]
fn format_number_honors_apostrophe_quoted_literals() {
    // DecimalFormat quotes remove syntax from enclosed symbols; doubled apostrophes emit one
    // literal apostrophe without changing the active numeric subpattern.
    let stylesheet = r##"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="format-number(12, &quot;'#'0&quot;)"/><xsl:text>|</xsl:text><xsl:value-of select="format-number(12, &quot;'%'0&quot;)"/><xsl:text>|</xsl:text><xsl:value-of select="format-number(12, &quot;''0&quot;)"/></xsl:template></xsl:stylesheet>"##;
    assert_eq!(execute(stylesheet, "<source/>"), "#12|%12|'12");
}

#[test]
fn format_number_uses_negative_affixes_with_the_positive_numeric_shape() {
    // XSLT 1.0 section 12.3 delegates picture semantics to DecimalFormat, whose negative
    // subpattern contributes only affixes; its numeric shape is ignored.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#format-number
    assert_eq!(
        execute(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="format-number(-1, '0;(00)')"/></xsl:template></xsl:stylesheet>"#,
            "<source/>",
        ),
        "(1)",
    );
}

#[test]
fn format_number_rejects_malformed_picture_grammar() {
    // XSLT 1.0 section 12.3 delegates the localized picture grammar to DecimalFormat: each
    // subpattern has at most one decimal separator and a picture has at most positive and
    // negative subpatterns. Quoted syntax remains literal.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#format-number
    for picture in ["0.0.0", "0;0;0"] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="format-number(1, '{picture}')"/></xsl:template></xsl:stylesheet>"#,
        );
        assert!(
            compile(&stylesheet)
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
                .is_err(),
            "malformed picture {picture:?} must fail",
        );
    }

    assert_eq!(
        execute(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="format-number(1, &quot;'0.0'0.0&quot;)"/><xsl:text>|</xsl:text><xsl:value-of select="format-number(1, '.')"/></xsl:template></xsl:stylesheet>"#,
            "<source/>",
        ),
        "0.01.0|1.",
    );
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

#[test]
fn key_declarations_reject_child_content() {
    // XSLT 1.0 section 12.2 defines xsl:key with an EMPTY content model.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#key
    for content in ["<bad/>", "preserved"] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:key name="key" match="*" use=".">{content}</xsl:key></xsl:stylesheet>"#
        );
        assert!(matches!(
            Compiler::new(
                Arc::new(NoResolver),
                CompileBudget::new(4096, 0, 32, 64 * 1024),
            )
            .compile(&stylesheet, None),
            Err(Error::Static(message)) if message.contains("xsl:key must be empty")
        ));
    }

    compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:key name="key" match="*" use=".">
        </xsl:key></xsl:stylesheet>"#,
    );
}

#[test]
fn choose_rejects_non_whitespace_character_data_between_branches() {
    // xsl:choose has an element-only content model; text cannot be ignored just because valid
    // xsl:when children are also present.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:choose>unexpected<xsl:when test="true()"><out/></xsl:when></xsl:choose></xsl:template></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(1 << 20, 8, 256, 1 << 20),
        )
        .compile(stylesheet, None),
        Err(Error::Static(message)) if message.contains("xsl:choose")
    ));
}

#[test]
fn choose_rejects_whitespace_preserved_by_xml_space() {
    // XSLT 1.0 sections 3.4 and 9.2 strip ordinary stylesheet whitespace, but xml:space keeps
    // this text node and xsl:choose's element-only content model must then reject it.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#strip
    let preserved = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:choose xml:space="preserve"> <xsl:when test="true()"/></xsl:choose></xsl:template></xsl:stylesheet>"#;
    let error = Compiler::new(
        Arc::new(NoResolver),
        CompileBudget::new(1 << 20, 0, 32, 1 << 20),
    )
    .compile(preserved, None)
    .expect_err("preserved character data must violate xsl:choose's content model");
    assert!(
        matches!(&error, Error::Static(message) if message.contains("xsl:choose")),
        "{error:?}"
    );

    compile(&preserved.replace(" xml:space=\"preserve\"", ""));
}

#[test]
fn strict_compiler_preserves_xpath_and_stylesheet_whitespace_grammars() {
    // XPath 1.0 section 3.7 admits only XML S around tokens; NBSP inside an AVT expression is
    // therefore syntax, not trim-able layout: https://www.w3.org/TR/1999/REC-xpath-19991116#exprlex
    let non_xml_xpath_space = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><out value="{&#160;/&#160;}"/></xsl:template></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(4096, 0, 32, 64 * 1024),
        )
        .compile(non_xml_xpath_space, None),
        Err(Error::Static(_))
    ));

    // XSLT 1.0 sections 3.4 and 6 leave xml:space-preserved text in the stylesheet tree, where it
    // violates call-template's `(xsl:with-param)*` content model.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#named-templates
    let preserved_call = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template name="target"/><xsl:template match="/"><xsl:call-template name="target" xml:space="preserve"> </xsl:call-template></xsl:template></xsl:stylesheet>"#;
    let error = Compiler::new(
        Arc::new(NoResolver),
        CompileBudget::new(4096, 0, 32, 64 * 1024),
    )
    .compile(preserved_call, None)
    .expect_err("preserved call-template text must violate its content model");
    assert!(
        matches!(&error, Error::Static(message) if message.contains("call-template")),
        "{error:?}"
    );
    compile(&preserved_call.replace(" xml:space=\"preserve\"", ""));
}

#[test]
fn strict_compiler_validates_extension_fallback_attributes() {
    // XSLT 1.0 sections 2.1 and 15 permit foreign namespaced attributes on XSLT elements but the
    // xsl:fallback syntax declares no unqualified attributes.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#fallback
    let invalid = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:ext="urn:missing" extension-element-prefixes="ext"><xsl:template match="/"><ext:instruction><xsl:fallback bogus="value"/></ext:instruction></xsl:template></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(4096, 0, 32, 64 * 1024),
        )
            .compile(invalid, None),
        Err(Error::Static(message)) if message.contains("xsl:fallback") && message.contains("bogus")
    ));

    compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:ext="urn:missing" xmlns:meta="urn:meta" extension-element-prefixes="ext"><xsl:template match="/"><ext:instruction><xsl:fallback meta:hint="value"/></ext:instruction></xsl:template></xsl:stylesheet>"#,
    );
}

#[test]
fn compiler_merges_output_and_namespace_alias_by_precedence() {
    // XSLT 1.0 sections 16 and 7.1.1 define highest-import-precedence selection and permit
    // recovery from equal-precedence conflicts by selecting the last declaration.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#output
    let output_conflict = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="xml"/><xsl:output method="html"/></xsl:stylesheet>"#;
    assert_eq!(
        compile(output_conflict).output_definition().method,
        xml_sec_xslt::OutputMethod::Html
    );
    compile(&output_conflict.replace("method=\"html\"", "method=\"xml\""));

    let alias_conflict = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:source="urn:source" xmlns:a="urn:a" xmlns:b="urn:b"><xsl:namespace-alias stylesheet-prefix="source" result-prefix="a"/><xsl:namespace-alias stylesheet-prefix="source" result-prefix="b"/></xsl:stylesheet>"#;
    compile(alias_conflict);
    compile(&alias_conflict.replace("result-prefix=\"b\"", "result-prefix=\"a\""));
    compile(&alias_conflict.replace("urn:b", "urn:a"));

    let resolver = Arc::new(ContextResolver::default());
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert(
            (
                "lower.xsl".into(),
                Some("https://example.test/main.xsl".into()),
            ),
            ResolvedResource {
                canonical_uri: "https://example.test/lower.xsl".into(),
                identity: ResourceIdentity("output-alias-precedence".into()),
                bytes: br#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:source="urn:source" xmlns:low="urn:low"><xsl:output method="html"/><xsl:namespace-alias stylesheet-prefix="source" result-prefix="low"/></xsl:stylesheet>"#.to_vec(),
                media_type: None,
                encoding: Some("UTF-8".into()),
            },
        );
    let stylesheet = Compiler::new(
        resolver,
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:source="urn:source" xmlns:high="urn:high"><xsl:import href="lower.xsl"/><xsl:output method="xml"/><xsl:namespace-alias stylesheet-prefix="source" result-prefix="high"/><xsl:template match="/"><source:result/></xsl:template></xsl:stylesheet>"#,
        Some("https://example.test/main.xsl"),
    )
    .expect("higher-precedence output and alias declarations override imports");
    assert_eq!(
        stylesheet.output_definition().method,
        xml_sec_xslt::OutputMethod::Xml
    );
}

#[test]
fn output_declarations_obey_content_and_forward_compatibility_rules() {
    // XSLT 1.0 sections 2.5 and 16 require unsupported optional values to be ignored only
    // during forward-compatible processing, while xsl:output itself has EMPTY content.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#forwards
    // https://www.w3.org/TR/1999/REC-xslt-19991116#output
    let strict = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="future" omit-xml-declaration="yes"/></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(4096, 0, 32, 64 * 1024),
        )
            .compile(strict, None),
        Err(Error::Static(message)) if message.contains("output method")
    ));

    let forward = strict.replace("version=\"1.0\"", "version=\"2.0\"");
    let output = compile(&forward).output_definition().clone();
    assert_eq!(output.method, xml_sec_xslt::OutputMethod::Xml);
    assert!(output.omit_xml_declaration);

    for content in ["unexpected", "<xsl:text>unexpected</xsl:text>"] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output>{content}</xsl:output></xsl:stylesheet>"#
        );
        assert!(matches!(
            Compiler::new(
                Arc::new(NoResolver),
                CompileBudget::new(4096, 0, 32, 64 * 1024),
            )
                .compile(&stylesheet, None),
            Err(Error::Static(message)) if message.contains("xsl:output") && message.contains("empty")
        ));
    }
}

#[test]
fn compiler_unions_cdata_output_names_across_import_precedence() {
    // XSLT 1.0 section 16 explicitly unions cdata-section-elements across every xsl:output;
    // unlike scalar output properties, lower-import-precedence values remain effective.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#output
    let resolver = Arc::new(ContextResolver::default());
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert(
            (
                "lower.xsl".into(),
                Some("https://example.test/main.xsl".into()),
            ),
            ResolvedResource {
                canonical_uri: "https://example.test/lower.xsl".into(),
                identity: ResourceIdentity("cdata-output-precedence".into()),
                bytes: br#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output cdata-section-elements="low"/></xsl:stylesheet>"#.to_vec(),
                media_type: None,
                encoding: Some("UTF-8".into()),
            },
        );
    let stylesheet = Compiler::new(
        resolver,
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:import href="lower.xsl"/><xsl:output cdata-section-elements="high"/></xsl:stylesheet>"#,
        Some("https://example.test/main.xsl"),
    )
    .expect("CDATA output names from imported stylesheets must remain effective");

    assert_eq!(
        stylesheet.output_definition().cdata_section_elements,
        [
            ExpandedName::new(None::<String>, "low"),
            ExpandedName::new(None::<String>, "high"),
        ]
        .into_iter()
        .collect()
    );
}

#[test]
fn apply_templates_rejects_non_whitespace_character_data() {
    // Character data is not part of the xsl:apply-templates content model and must not vanish.
    let invalid = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:apply-templates>unexpected</xsl:apply-templates></xsl:template></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(4096, 0, 32, 64 * 1024),
        )
            .compile(invalid, None),
        Err(Error::Static(message)) if message.contains("apply-templates")
    ));

    compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:apply-templates>
            <!-- inert stylesheet annotation -->
            <?annotation retained-by-source?>
            <xsl:sort select="."/>
            <xsl:with-param name="value" select="1"/>
        </xsl:apply-templates></xsl:template></xsl:stylesheet>"#,
    );
}

#[test]
fn match_pattern_current_uses_the_candidate_as_outer_context() {
    // current() in a match predicate is bound to the node being tested, not the logical root used
    // to search for pattern candidates.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:apply-templates select="root/group/item"/></xsl:template><xsl:template match="item[@id = current()/../@ref]"><xsl:value-of select="@id"/></xsl:template><xsl:template match="item">miss</xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(
            stylesheet,
            r#"<root><group ref="selected"><item id="other"/><item id="selected"/></group></root>"#,
        ),
        "missselected"
    );
}

#[test]
fn match_pattern_fast_path_trims_xml_whitespace_before_predicates() {
    // XSLT Pattern permits ExprWhitespace around predicate boundaries; the optimized matcher
    // must preserve the same node test as the general XPath path.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:apply-templates select="root/item"/></xsl:template><xsl:template match="item [@kind='selected']">hit</xsl:template><xsl:template match="item">miss</xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(
            stylesheet,
            r#"<root><item kind="selected"/><item kind="other"/></root>"#,
        ),
        "hitmiss"
    );
}

#[test]
fn absolute_match_fast_path_trims_xml_whitespace_around_separators() {
    // XSLT 1.0 section 5.2 permits ExprWhitespace within a Pattern. The absolute-path fast path
    // must compare normalized node tests without allocating replacement strings.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#patterns
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:apply-templates select="root/item"/></xsl:template><xsl:template match="/ root / item">hit</xsl:template><xsl:template match="item">miss</xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<root><item/></root>"), "hit");
}

#[test]
fn internal_xpath_prefixes_do_not_shadow_stylesheet_namespaces() {
    // Engine-generated variables require private namespace bindings, but legal caller prefixes
    // with the old internal-looking spellings remain part of the stylesheet's static context.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:str="http://exslt.org/strings" xmlns:__xml_sec_ctx="urn:caller:context" xmlns:__xml_sec_ext="urn:caller:extension" xmlns:caller_ctx="urn:structured-world:xml-sec:xslt:context" xmlns:caller_ext="urn:structured-world:xml-sec:xslt:extensions"><xsl:output method="text"/><xsl:param name="caller_ctx:position" select="'caller-position'"/><xsl:param name="caller_ext:value0" select="'caller-value'"/><xsl:template match="/"><xsl:for-each select="//__xml_sec_ctx:item"><xsl:value-of select="concat(., ':', position(), '/', last(), ':', $caller_ctx:position)"/></xsl:for-each><xsl:text>|</xsl:text><xsl:value-of select="concat(//__xml_sec_ext:item, ':', str:replace('a', 'a', 'x'), ':', $caller_ext:value0)"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(
            stylesheet,
            r#"<root xmlns:c="urn:caller:context" xmlns:e="urn:caller:extension"><c:item>left</c:item><e:item>right</e:item></root>"#,
        ),
        "left:1/1:caller-position|right:x:caller-value"
    );
}

#[test]
fn xslt_10_patterns_reject_variable_references_statically() {
    // XSLT 1.0 forbids VariableReference in match patterns; it is not a runtime scope lookup.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:variable name="kind" select="'item'"/><xsl:template match="*[$kind = name()]"/></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(4096, 0, 32, 64 * 1024),
        )
            .compile(stylesheet, None),
        Err(Error::Static(message)) if message.contains("variable") && message.contains("match")
    ));
}

#[test]
fn xslt_10_patterns_reject_general_xpath_expressions_statically() {
    // A match attribute uses the restricted Pattern grammar, not the general XPath Expr grammar.
    for pattern in [
        "item + 1",
        "count(item)",
        "item and other",
        "(item)",
        "id('a' or 'b')",
        "key('a' or 'b', 'x')",
    ] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="{pattern}"/></xsl:stylesheet>"#
        );
        assert!(matches!(
            Compiler::new(
                Arc::new(NoResolver),
                CompileBudget::new(4096, 0, 32, 64 * 1024),
            )
                .compile(&stylesheet, None),
            Err(Error::Static(message)) if message.contains("match pattern")
        ));
    }

    compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="item | @id | child :: branch/leaf[@active='yes'] | id ('root')//value | key ('kind', 'x')/entry | processing-instruction ('target')"/></xsl:stylesheet>"#,
    );

    let invalid_axis = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="child::@id"/></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(4096, 0, 32, 64 * 1024),
        )
            .compile(invalid_axis, None),
        Err(Error::Static(message)) if message.contains("match pattern")
    ));
}

#[test]
fn attribute_patterns_accept_xpath_expression_whitespace_after_the_axis() {
    // XSLT 1.0 section 5.2 permits ExprWhitespace around Pattern tokens, including after the
    // abbreviated attribute axis. The optimized matcher must normalize the same grammar.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#patterns
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:apply-templates select="root/@id"/></xsl:template><xsl:template match="@ id">hit</xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<root id=\"value\"/>"), "hit");
}

#[test]
fn match_patterns_trim_only_xml_whitespace() {
    // XPath 1.0 permits only XML S around tokens; Unicode whitespace is not a grammar separator.
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#exprlex
    let invalid = "<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"><xsl:template match=\"\u{a0}/\u{a0}\"/></xsl:stylesheet>";
    assert!(matches!(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(4096, 0, 32, 64 * 1024),
        )
            .compile(invalid, None),
        Err(Error::Static(message)) if message.contains("match pattern")
    ));

    compile(
        "<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"><xsl:template match=\"\t / \r\n\"/></xsl:stylesheet>",
    );
}

#[test]
fn instruction_attributes_follow_strict_and_forward_compatible_rules() {
    // Strict XSLT 1.0 rejects instruction and literal-result typos but ignores foreign extension
    // attributes; forward-compatible processing ignores unknown XSLT attributes.
    let typo = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of selct="."/></xsl:template></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(4096, 0, 32, 64 * 1024),
        )
            .compile(typo, None),
        Err(Error::Static(message)) if message.contains("selct")
    ));
    compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:vendor="urn:vendor"><xsl:template match="/"><xsl:value-of select="." vendor:hint="yes"/></xsl:template></xsl:stylesheet>"#,
    );
    compile(
        r#"<xsl:stylesheet version="2.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="." future-option="yes"/></xsl:template></xsl:stylesheet>"#,
    );

    let literal_typo = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><out xsl:bogus="yes"/></xsl:template></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(4096, 0, 32, 64 * 1024),
        )
            .compile(literal_typo, None),
        Err(Error::Static(message)) if message.contains("bogus")
    ));

    let forward_literal = r#"<xsl:stylesheet version="2.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><out xsl:bogus="yes"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(forward_literal, "<source/>"), "<out/>\n");
}

#[test]
fn exclude_result_prefixes_rejects_xslt_20_all_token_in_strict_mode() {
    // XSLT 1.0 section 7.1.1 permits only QName tokens and #default. In forward-compatible
    // processing, section 2.5 requires the unsupported attribute value to be ignored as a whole.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#literal-result-element
    // https://www.w3.org/TR/1999/REC-xslt-19991116#forwards
    let strict = r##"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:p="urn:p" exclude-result-prefixes="#all"><xsl:template match="/"/></xsl:stylesheet>"##;
    assert!(matches!(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(4096, 0, 32, 64 * 1024),
        )
            .compile(strict, None),
        Err(Error::Static(message)) if message.contains("#all")
    ));

    let forward = r##"<xsl:stylesheet version="2.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><out xmlns:p="urn:p" xsl:exclude-result-prefixes="p #all"/></xsl:template></xsl:stylesheet>"##;
    assert_eq!(execute(forward, "<source/>"), "<out xmlns:p=\"urn:p\"/>\n");
}

#[test]
fn inherited_prefix_lists_use_the_declaring_ancestors_compatibility_mode() {
    // XSLT 1.0 section 2.5 applies forward-compatible processing where the unsupported
    // attribute occurs; a strict descendant cannot reinterpret its ancestor's attribute.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#forwards
    for attribute in ["exclude-result-prefixes", "extension-element-prefixes"] {
        let stylesheet = format!(
            r##"<xsl:stylesheet version="2.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" {attribute}="#all"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><out xsl:version="1.0"/></xsl:template></xsl:stylesheet>"##
        );
        assert_eq!(execute(&stylesheet, "<source/>"), "<out/>\n");
    }
}

#[test]
fn latin1_xml_serialization_distinguishes_markup_from_character_data() {
    // Character references preserve text and attributes, while XML names cannot contain them.
    let data = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output encoding="ISO-8859-1" omit-xml-declaration="yes"/><xsl:template match="/"><out value="€">€</out></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(data, "<source/>"),
        "<out value=\"&#8364;\">&#8364;</out>\n"
    );

    let name = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output encoding="ISO-8859-1"/><xsl:template match="/"><xsl:element name="λ"/></xsl:template></xsl:stylesheet>"#;
    assert!(matches!(
        compile(name).execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        ),
        Err(Error::Serialization(message)) if message.contains("name") && message.contains('λ')
    ));
}

#[test]
fn latin1_cdata_reopens_around_unrepresentable_characters() {
    // A character reference is markup, so an unencodable CDATA character must close the section.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output encoding="ISO-8859-1" omit-xml-declaration="yes" cdata-section-elements="out"/><xsl:template match="/"><out>a€b</out></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<source/>"),
        "<out><![CDATA[a]]>&#8364;<![CDATA[b]]></out>\n"
    );
}

#[test]
fn cdata_carriage_return_round_trips_as_a_character_reference() {
    // XML 1.0 section 2.11 normalizes literal carriage returns even inside CDATA, so the
    // serializer must leave CDATA to preserve the result-tree character across reparsing.
    // https://www.w3.org/TR/xml/#sec-line-ends
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes" cdata-section-elements="out"/><xsl:template match="/"><out>a&#13;b</out></xsl:template></xsl:stylesheet>"#;
    let serialized = execute(stylesheet, "<source/>");
    assert_eq!(serialized, "<out><![CDATA[a]]>&#13;<![CDATA[b]]></out>\n");
    let reparsed = Document::parse(&serialized, None).expect("CDATA result reparses");
    let text = reparsed
        .nodes()
        .find_map(|(_, node)| match &node.kind {
            NodeKind::Text { value, .. } => Some(value.as_str()),
            _ => None,
        })
        .expect("result retains text");
    assert_eq!(text, "a\rb");
}

#[test]
fn encode_uri_charges_expansion_before_constructing_it() {
    // Percent encoding can triple UTF-8 input and must be rejected at the allocation boundary.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:str="http://exslt.org/strings"><xsl:output method="text"/><xsl:param name="value"/><xsl:template match="/"><xsl:value-of select="str:encode-uri($value, true())"/></xsl:template></xsl:stylesheet>"#,
    );
    let value = "€".repeat(4096);
    let mut parameters = Parameters::new();
    parameters.insert(
        ExpandedName::new(None::<String>, "value"),
        Value::String(value),
    );
    let mut budget = execution_budget(1024);
    budget.owned_bytes = 64 * 1024;
    assert!(matches!(
        stylesheet.execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &parameters,
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
fn decode_uri_charges_octets_and_transcoded_output_before_allocating() {
    // Decoding retains both the percent-decoded octets and transcoded UTF-8 output during the
    // call, so a tight budget must reject the operation before either large buffer is built.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:str="http://exslt.org/strings"><xsl:output method="text"/><xsl:param name="value"/><xsl:template match="/"><xsl:value-of select="str:decode-uri($value)"/></xsl:template></xsl:stylesheet>"#,
    );
    let mut parameters = Parameters::new();
    parameters.insert(
        ExpandedName::new(None::<String>, "value"),
        Value::String("%41".repeat(16 * 1024)),
    );
    let mut budget = execution_budget(1024);
    budget.owned_bytes = 104 * 1024;
    assert!(matches!(
        stylesheet.execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &parameters,
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
fn capability_queries_distinguish_instructions_and_declarations() {
    // XSLT 1.0 element-available reports executable instructions, not top-level declarations.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:exsl="http://exslt.org/common"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="element-available('xsl:decimal-format')"/><xsl:text>|</xsl:text><xsl:value-of select="exsl:object-type(system-property('xsl:version'))"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "false|number");
}

#[test]
fn element_available_preserves_libxslt_structural_child_compatibility() {
    // XSLT 1.0 section 15 describes instruction names, while libxslt also advertises these
    // executable structural children. The compatibility engine intentionally matches libxslt.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#element-available
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="element-available('xsl:if')"/><xsl:text>|</xsl:text><xsl:value-of select="element-available('xsl:when')"/><xsl:text>|</xsl:text><xsl:value-of select="element-available('xsl:otherwise')"/><xsl:text>|</xsl:text><xsl:value-of select="element-available('xsl:sort')"/><xsl:text>|</xsl:text><xsl:value-of select="element-available('xsl:with-param')"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "true|true|true|true|true");
}

#[test]
fn quoted_key_text_does_not_prepare_key_indexes() {
    // Function-like text inside an XPath string literal cannot trigger key construction.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:key name="all" match="*" use="name()"/><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="'key('"/></xsl:template></xsl:stylesheet>"#,
    );
    let mut budget = execution_budget(1024);
    budget.key_entries = 0;
    let result = stylesheet
        .execute(
            &Document::parse("<root><item/></root>", None).expect("source parses"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("quoted text does not build keys");
    assert_eq!(result.serialized.bytes, b"key(");
}

#[test]
fn key_index_traversal_accounts_for_its_wide_pending_stack() {
    // A no-match key produces no retained entries, but traversing a wide logical document still
    // requires a temporary DFS frontier that must count toward peak OwnedBytes.
    let source_xml = format!("<root>{}</root>", "<item/>".repeat(4_096));
    let source = Document::parse(&source_xml, None).expect("wide source parses");
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:key name="none" match="missing" use="."/><xsl:output method="text"/><xsl:template name="baseline">ok</xsl:template><xsl:template name="key"><xsl:value-of select="count(key('none', 'x'))"/></xsl:template></xsl:stylesheet>"#,
    );
    let minimum = |template: &str| {
        let succeeds = |owned_bytes| {
            let mut budget = execution_budget(source_xml.len());
            budget.owned_bytes = owned_bytes;
            stylesheet
                .execute(
                    &source,
                    &Parameters::new(),
                    Arc::new(NoResolver),
                    ExecutionOptions {
                        budget,
                        initial_mode: None,
                        initial_template: Some(ExpandedName::new(None::<String>, template)),
                    },
                )
                .is_ok()
        };
        let mut rejected = 0;
        let mut accepted = 1;
        while !succeeds(accepted) {
            rejected = accepted;
            accepted *= 2;
        }
        while rejected + 1 < accepted {
            let candidate = rejected + (accepted - rejected) / 2;
            if succeeds(candidate) {
                accepted = candidate;
            } else {
                rejected = candidate;
            }
        }
        accepted
    };
    let baseline = minimum("baseline");
    let keyed = minimum("key");
    assert!(
        keyed + 4 * 1024 >= baseline + 4_096 * std::mem::size_of::<xml_sec_xslt::NodeId>(),
        "baseline={baseline}, keyed={keyed}"
    );
}

#[test]
fn empty_key_build_markers_consume_owned_memory_budget() {
    // A dynamic key name builds every declaration. Even declarations with no matching nodes
    // retain one completed-build identity and must therefore consume aggregate OwnedBytes.
    let declarations = (0..128)
        .map(|index| format!(r#"<xsl:key name="key-{index}" match="missing" use="."/>"#))
        .collect::<String>();
    let stylesheet = compile(&format!(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">{declarations}<xsl:param name="requested" select="'absent'"/><xsl:output method="text"/><xsl:template name="baseline">ok</xsl:template><xsl:template name="keys"><xsl:value-of select="count(key($requested, 'x'))"/></xsl:template></xsl:stylesheet>"#,
    ));
    let baseline = minimum_execution_owned_bytes(&stylesheet, "baseline");
    let keyed = minimum_execution_owned_bytes(&stylesheet, "keys");

    assert!(
        keyed >= baseline + 128 * std::mem::size_of::<(ExpandedName, xml_sec_xslt::NodeId)>(),
        "baseline={baseline}, keyed={keyed}"
    );
}

#[test]
fn dynamic_map_preserves_boolean_lexical_values() {
    // EXSLT dyn:map scalar nodes use XPath's true/false lexical representation.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:dyn="http://exslt.org/dynamic"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="dyn:map(root/item, '. = 2')[1]"/><xsl:text>|</xsl:text><xsl:value-of select="dyn:map(root/item, '. = 2')[2]"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<root><item>1</item><item>2</item></root>"),
        "false|true"
    );
}

#[test]
fn exslt_functions_do_not_inherit_a_current_template_rule() {
    // A function call has no current template rule, so apply-imports in its body is a dynamic
    // error rather than a dispatch into an unrelated lower-precedence template.
    let resolver = Arc::new(MemoryResolver::default());
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert(
            "base.xsl".into(),
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><base/></xsl:template></xsl:stylesheet>"#.into(),
        );
    let stylesheet = Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:func="http://exslt.org/functions" xmlns:f="urn:functions" extension-element-prefixes="func"><xsl:import href="base.xsl"/><func:function name="f:test"><xsl:apply-imports/><func:result select="'done'"/></func:function><xsl:template match="/"><xsl:value-of select="f:test()"/></xsl:template></xsl:stylesheet>"#,
        Some("memory:main.xsl"),
    )
    .expect("function stylesheet compiles");
    assert!(matches!(
        stylesheet.execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &Parameters::new(),
            resolver,
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        ),
        Err(Error::Dynamic(message)) if message.contains("current template rule")
    ));
}

#[test]
fn xpath_numbers_accept_a_trailing_decimal_point() {
    // XPath Number admits a decimal point with no following digits when integer digits exist.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:param name="value" select="'5.'"/><xsl:template match="/"><xsl:value-of select="number($value)"/><xsl:text>|</xsl:text><xsl:value-of select="$value + 1"/><xsl:text>|</xsl:text><xsl:value-of select="number('.5')"/><xsl:text>|</xsl:text><xsl:value-of select="number('-.5')"/><xsl:text>|</xsl:text><xsl:value-of select="number('5..')"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "5|6|0.5|-0.5|NaN");
}

#[test]
fn capability_queries_do_not_advertise_unimplemented_debug_instruction() {
    // Conditional stylesheets must not select an extension instruction the engine cannot run.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:libxslt="http://xmlsoft.org/XSLT/namespace"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="element-available('libxslt:debug')"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "false");
}

#[test]
fn key_declarations_reject_forbidden_static_dependencies() {
    // Invalid key declarations are static errors even when no key() call ever builds the index.
    for (match_pattern, use_expression) in [
        ("item", "$value"),
        ("item", "key('other', @id)"),
        ("item[key('other', @id)]", "@id"),
    ] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:key name="invalid" match="{match_pattern}" use="{use_expression}"/><xsl:template match="/"/></xsl:stylesheet>"#
        );
        assert!(matches!(
            Compiler::new(
                Arc::new(NoResolver),
                CompileBudget::new(1 << 20, 8, 256, 1 << 20),
            )
            .compile(&stylesheet, Some("memory:key.xsl")),
            Err(Error::Static(_))
        ));
    }
}

#[test]
fn template_priority_uses_the_xpath_number_grammar() {
    // Host-language float extensions and non-finite values are not XSLT Priority values.
    for value in ["1e2", "NaN", "inf", "+1"] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="*" priority="{value}"/></xsl:stylesheet>"#
        );
        assert!(matches!(
            Compiler::new(
                Arc::new(NoResolver),
                CompileBudget::new(1 << 20, 8, 256, 1 << 20),
            )
            .compile(&stylesheet, Some("memory:priority.xsl")),
            Err(Error::Static(_))
        ));
    }
    compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="*" priority="5."/><xsl:template match="item" priority="-.5"/></xsl:stylesheet>"#,
    );
}

#[test]
fn decimal_formats_enforce_character_invariants() {
    // Syntax characters must be distinct and zero-digit must identify value zero in a Unicode
    // decimal digit family.
    for attributes in [
        "decimal-separator=\".\" grouping-separator=\".\"",
        "zero-digit=\"A\"",
        "zero-digit=\"١\"",
    ] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:decimal-format {attributes}/></xsl:stylesheet>"#
        );
        assert!(matches!(
            Compiler::new(
                Arc::new(NoResolver),
                CompileBudget::new(1 << 20, 8, 256, 1 << 20),
            )
            .compile(&stylesheet, Some("memory:decimal-format.xsl")),
            Err(Error::Static(_))
        ));
    }
    compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:decimal-format zero-digit="٠"/></xsl:stylesheet>"#,
    );
}

#[test]
fn encode_uri_escapes_every_reserved_character_when_requested() {
    // RFC 2396 section 2.2 does not classify the fragment delimiter as reserved, so EXSLT
    // encodes `#` under both flag modes instead of changing the resulting URI's semantics.
    // https://www.rfc-editor.org/rfc/rfc2396#section-2.2
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:str="http://exslt.org/strings"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="str:encode-uri(';/?:@&amp;=+$,[]#', true())"/><xsl:text>|</xsl:text><xsl:value-of select="str:encode-uri(';/?:@&amp;=+$,[]#', false())"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<source/>"),
        "%3B%2F%3F%3A%40%26%3D%2B%24%2C%5B%5D%23|;/?:@&=+$,%5B%5D%23"
    );
}

#[test]
fn dynamic_map_propagates_resource_budget_failures() {
    // Per-node dynamic-expression recovery must never turn an exceeded resource boundary into a
    // successful transformation or retry it for the remaining input nodes.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:dyn="http://exslt.org/dynamic"><xsl:param name="expression"/><xsl:template match="/"><xsl:value-of select="dyn:map(root/item, $expression)"/></xsl:template></xsl:stylesheet>"#,
    );
    let mut parameters = Parameters::new();
    parameters.insert(
        ExpandedName::new(None::<String>, "expression"),
        Value::String(format!("'{}'", "x".repeat(70_000))),
    );
    let budget = execution_budget(1024);
    assert!(matches!(
        stylesheet.execute(
            &Document::parse("<root><item/><item/><item/></root>", None).expect("source parses"),
            &parameters,
            Arc::new(NoResolver),
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
        ),
        Err(Error::Budget { .. })
    ));
}

#[test]
fn dynamic_map_assigns_positions_in_document_order() {
    // Union operand/hash order cannot affect the dynamic context position or scalar result order.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:dyn="http://exslt.org/dynamic"><xsl:output method="text"/><xsl:template match="/"><xsl:for-each select="dyn:map(root/item[@id='c'] | root/item[@id='a'] | root/item[@id='b'], 'concat(@id, position())')"><xsl:value-of select="."/><xsl:text>|</xsl:text></xsl:for-each></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(
            stylesheet,
            "<root><item id=\"a\"/><item id=\"b\"/><item id=\"c\"/></root>"
        ),
        "a1|b2|c3|"
    );
}

#[test]
fn dynamic_qnames_require_complete_qname_grammar() {
    // Runtime key and decimal-format names must reject extra colons and invalid NCNames.
    for select in [
        "key('p:a:b', 'x')",
        "format-number(1, '0', 'p:a:b')",
        "key('1bad', 'x')",
    ] {
        let stylesheet = compile(&format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:p="urn:p"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="{select}"/></xsl:template></xsl:stylesheet>"#
        ));
        assert!(matches!(
            stylesheet.execute(
                &Document::parse("<source/>", None).expect("source parses"),
                &Parameters::new(), Arc::new(NoResolver),
                ExecutionOptions { budget: execution_budget(1024), initial_mode: None, initial_template: None },
            ),
            Err(Error::Dynamic(message)) if message.contains("QName")
        ));
    }
}

#[test]
fn format_number_applies_affixes_and_negative_subpatterns_to_infinity() {
    // Infinity substitutes for the numeric portion after the selected subpattern is parsed.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="format-number(1 div 0, 'P0S')"/><xsl:text>|</xsl:text><xsl:value-of select="format-number(-1 div 0, 'P0S;N0Z')"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "PInfinityS|NInfinityZ");
}

#[test]
fn format_number_uses_configured_infinity_after_multiplier_overflow() {
    // XSLT 1.0 section 12.3 delegates percent/per-mille scaling and infinity symbols to
    // DecimalFormat; overflow of the adjusted number must retain those configured affixes.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#format-number
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:decimal-format infinity="OVER"/><xsl:param name="value"/><xsl:template match="/"><xsl:value-of select="format-number($value, 'P0%S;N0%Z')"/></xsl:template></xsl:stylesheet>"#,
    );
    let mut parameters = Parameters::new();
    parameters.insert(
        ExpandedName::new(None::<String>, "value"),
        Value::Number(-1e308),
    );
    let output = stylesheet
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
        .expect("overflowed multiplier formats as infinity");
    assert_eq!(output.serialized.bytes, b"NOVER%Z");
}

#[test]
fn stripped_source_nodes_remap_external_nodeset_parameters() {
    // Whitespace compaction changes NodeIds; caller node, attribute and namespace handles follow it.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:strip-space elements="*"/><xsl:output method="text"/><xsl:param name="node"/><xsl:param name="attr"/><xsl:param name="namespace"/><xsl:param name="removed"/><xsl:template match="/"><xsl:value-of select="$node"/><xsl:text>|</xsl:text><xsl:value-of select="$attr"/><xsl:text>|</xsl:text><xsl:value-of select="$namespace"/><xsl:text>|</xsl:text><xsl:value-of select="count($removed)"/></xsl:template></xsl:stylesheet>"#,
    );
    let source = Document::parse(
        "<root>  <item xmlns:p=\"urn:kept\" id=\"kept\">value</item></root>",
        None,
    )
    .expect("source parses");
    let mut parameters = Parameters::new();
    parameters.insert(
        ExpandedName::new(None::<String>, "node"),
        Value::NodeSet(vec![NodeReference::Node(node_id_at(&source, 3))]),
    );
    parameters.insert(
        ExpandedName::new(None::<String>, "attr"),
        Value::NodeSet(vec![NodeReference::Attribute {
            owner: node_id_at(&source, 3),
            index: 0,
        }]),
    );
    parameters.insert(
        ExpandedName::new(None::<String>, "namespace"),
        Value::NodeSet(vec![NodeReference::Namespace {
            owner: node_id_at(&source, 3),
            index: 1,
        }]),
    );
    parameters.insert(
        ExpandedName::new(None::<String>, "removed"),
        Value::NodeSet(vec![NodeReference::Node(node_id_at(&source, 2))]),
    );
    let result = stylesheet
        .execute(
            &source,
            &parameters,
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("compacted parameter nodes remain valid");
    assert_eq!(result.serialized.bytes, b"value|kept|urn:kept|0");
}

#[test]
fn arithmetic_fast_path_uses_xpath_number_grammar() {
    // Parameter arithmetic must reject exponent and leading-plus forms just like number().
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:param name="value"/><xsl:template match="/"><xsl:value-of select="$value + 1"/></xsl:template></xsl:stylesheet>"#,
    );
    for (value, expected) in [("1e2", "NaN"), ("+1", "NaN"), ("-1.5", "-0.5")] {
        let mut parameters = Parameters::new();
        parameters.insert(
            ExpandedName::new(None::<String>, "value"),
            Value::String(value.into()),
        );
        let result = stylesheet
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
            .expect("arithmetic executes");
        assert_eq!(
            String::from_utf8(result.serialized.bytes).expect("UTF-8"),
            expected
        );
    }
}

#[test]
fn text_output_allows_non_xml_characters_without_adding_markup_rules() {
    // The text method emits text-node data directly; XML character validity belongs to XML output.
    let text = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:str="http://exslt.org/strings"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="str:decode-uri('%01')"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(text, "<source/>").as_bytes(), b"\x01");

    let xml = text.replace(
        "method=\"text\"",
        "method=\"xml\" omit-xml-declaration=\"yes\"",
    );
    assert!(matches!(
        compile(&xml).execute(
            &Document::parse("<source/>", None).expect("source parses"), &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions { budget: execution_budget(1024), initial_mode: None, initial_template: None },
        ),
        Err(Error::Serialization(message)) if message.contains("XML")
    ));
}

#[test]
fn call_template_rejects_non_whitespace_character_data() {
    // call-template has a with-param-only content model; text must not disappear during filtering.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:call-template name="target">unexpected</xsl:call-template></xsl:template><xsl:template name="target"/></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(4096, 0, 32, 16 * 1024),
        )
            .compile(stylesheet, None),
        Err(Error::Static(message)) if message.contains("call-template")
    ));
}

#[test]
fn disable_output_escaping_is_not_absorbed_into_cdata() {
    // DOE creates a serialization boundary even inside an element selected for CDATA output.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output omit-xml-declaration="yes" cdata-section-elements="out"/><xsl:template match="/"><out>before<xsl:text disable-output-escaping="yes">&lt;raw/&gt;</xsl:text>after</out></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<source/>"),
        "<out><![CDATA[before]]><raw/><![CDATA[after]]></out>\n"
    );
}

#[test]
fn stylesheet_versions_use_numeric_xslt_semantics() {
    // The version attribute is an XSLT Number, so equivalent lexical forms remain strict 1.0.
    for version in ["1", "1.00"] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="{version}" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/">ok</xsl:template></xsl:stylesheet>"#
        );
        assert_eq!(execute(&stylesheet, "<source/>"), "ok");
    }
}

#[test]
fn stylesheet_versions_reject_non_xpath_number_spellings() {
    // XSLT 1.0 sections 2.2 and 2.3 use XPath's Number production for stylesheet versions;
    // XPath 1.0 section 3.7 excludes signs, exponents, and surrounding whitespace.
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#exprlex
    for version in ["+1.0", "1e1", " 1.0", "1.0 ", "1.0.0"] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="{version}" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"/></xsl:stylesheet>"#
        );
        assert!(matches!(
            Compiler::new(
                Arc::new(NoResolver),
                CompileBudget::new(4096, 0, 32, 64 * 1024),
            )
                .compile(&stylesheet, None),
            Err(Error::Static(message)) if message.contains("XSLT version")
        ));
    }
}

#[test]
fn literal_result_stylesheet_versions_use_numeric_xslt_semantics() {
    // Equivalent lexical forms of XSLT 1.0 must not enable forward-compatible processing.
    let stylesheet = r#"<out xsl:version="1.00" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:future><xsl:fallback>fallback</xsl:fallback></xsl:future></out>"#;
    assert!(matches!(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(4096, 0, 32, 64 * 1024),
        )
            .compile(stylesheet, None),
        Err(Error::Static(message)) if message.contains("unknown XSLT instruction")
    ));
}

#[test]
fn byte_entry_points_share_strict_non_utf8_xml_decoding() {
    // Stylesheet and source byte APIs use one decoder before their distinct
    // compiler and runtime semantic paths.
    let stylesheet = b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"><xsl:output method=\"text\"/><xsl:template match=\"/\"><xsl:value-of select=\"root\"/></xsl:template></xsl:stylesheet>";
    let compiled = Compiler::new(
        Arc::new(NoResolver),
        CompileBudget::new(4096, 0, 32, 16 * 1024),
    )
    .compile_bytes(stylesheet, None)
    .expect("Latin-1 stylesheet bytes compile");
    let source = b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><root>caf\xe9</root>";
    let document = Document::parse_bytes(source, None).expect("Latin-1 source bytes parse");
    let result = compiled
        .execute(
            &document,
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(4096),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("decoded source transforms");
    assert_eq!(result.serialized.bytes, b"caf\xc3\xa9");

    let utf32 = |source: &str, little_endian: bool| {
        let mut bytes = if little_endian {
            vec![0xFF, 0xFE, 0x00, 0x00]
        } else {
            vec![0x00, 0x00, 0xFE, 0xFF]
        };
        bytes.extend(source.chars().flat_map(|character| {
            let scalar = u32::from(character);
            if little_endian {
                scalar.to_le_bytes()
            } else {
                scalar.to_be_bytes()
            }
        }));
        bytes
    };
    let stylesheet = utf32(
        r#"<?xml version="1.0" encoding="UTF-32"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="root"/></xsl:template></xsl:stylesheet>"#,
        false,
    );
    let compiled = Compiler::new(
        Arc::new(NoResolver),
        CompileBudget::new(4096, 0, 32, 16 * 1024),
    )
    .compile_bytes(&stylesheet, None)
    .expect("UTF-32BE stylesheet bytes compile");
    let declarationless = utf32("<root>lambda</root>", true);
    assert!(matches!(
        Document::parse_bytes(&declarationless, None),
        Err(Error::Xml(message)) if message.contains("encoding declaration")
    ));
    let source = utf32(
        r#"<?xml version="1.0" encoding="UTF-32"?><root>lambda</root>"#,
        true,
    );
    let document = Document::parse_bytes(&source, None).expect("UTF-32LE source bytes parse");
    let result = compiled
        .execute(
            &document,
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(4096),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("UTF-32 input transforms");
    assert_eq!(result.serialized.bytes, b"lambda");
}

#[test]
fn decoded_stylesheet_workspace_is_bounded_before_parsing() {
    // A transcoded stylesheet is live throughout compilation, so OwnedBytes must reject its
    // materialization before parser work can observe malformed trailing content.
    let mut stylesheet = b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>".to_vec();
    stylesheet.extend(std::iter::repeat_n(0xe9, 1024));
    assert!(matches!(
        Compiler::new(Arc::new(NoResolver), CompileBudget::new(4096, 0, 32, 128),)
            .compile_bytes(&stylesheet, None),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
}

#[test]
fn literal_extension_attributes_do_not_change_instruction_semantics() {
    // An unqualified attribute on a literal result element is copied, not interpreted as XSLT.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:e="urn:extension"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><out extension-element-prefixes="e"><e:item/></out></xsl:template></xsl:stylesheet>"#;
    let output = execute(stylesheet, "<source/>");
    assert!(
        output.contains("extension-element-prefixes=\"e\""),
        "{output}"
    );
    assert!(output.contains("<e:item"), "{output}");
}

#[test]
fn unbound_default_namespace_alias_produces_an_unqualified_name() {
    // The result prefix has its own namespace lookup; it must not inherit the source alias URI.
    let stylesheet = r##"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:old="urn:old"><xsl:namespace-alias stylesheet-prefix="old" result-prefix="#default"/><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><old:result/></xsl:template></xsl:stylesheet>"##;
    assert_eq!(execute(stylesheet, "<source/>"), "<result/>\n");
}

#[test]
fn for_each_clears_the_current_template_rule() {
    // XSLT 1.0 makes apply-imports an error while a for-each body is instantiated.
    let resolver = Arc::new(MemoryResolver::default());
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert(
            "base.xsl".into(),
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="item">wrong</xsl:template></xsl:stylesheet>"#.into(),
        );
    let stylesheet = Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:import href="base.xsl"/><xsl:template match="/"><xsl:for-each select="root/item"><xsl:apply-imports/></xsl:for-each></xsl:template></xsl:stylesheet>"#,
        Some("memory:main.xsl"),
    )
    .expect("stylesheet compiles");
    assert!(matches!(
        stylesheet.execute(
            &Document::parse("<root><item/></root>", None).expect("source parses"),
            &Parameters::new(),
            resolver,
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        ),
        Err(Error::Dynamic(message)) if message.contains("current template rule")
    ));
}

#[test]
fn captured_for_each_clears_the_current_template_rule() {
    // Captured instruction bodies must enforce the same current-rule semantics as normal output.
    let resolver = Arc::new(MemoryResolver::default());
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert(
            "base.xsl".into(),
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="item">wrong</xsl:template></xsl:stylesheet>"#.into(),
        );
    let stylesheet = Compiler::new(
        resolver.clone(),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:import href="base.xsl"/><xsl:template match="/"><xsl:message><xsl:for-each select="root/item"><xsl:apply-imports/></xsl:for-each></xsl:message></xsl:template></xsl:stylesheet>"#,
        Some("memory:main.xsl"),
    )
    .expect("stylesheet compiles");
    assert!(matches!(
        stylesheet.execute(
            &Document::parse("<root><item/></root>", None).expect("source parses"),
            &Parameters::new(),
            resolver,
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
        ),
        Err(Error::Dynamic(message)) if message.contains("current template rule")
    ));
}

#[test]
fn multiplication_can_precede_an_absolute_location_path() {
    // Multiplication is an operator here, while the star in the second expression is a node test.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="2 * /root/n"/><xsl:text>|</xsl:text><xsl:value-of select="count(/root/*/leaf)"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(stylesheet, "<root><n>3</n><branch><leaf/></branch></root>"),
        "6|1"
    );
}

#[test]
fn xinclude_expansion_precedes_whitespace_classification() {
    // Fallback children are classified under their post-expansion parent, not xi:fallback.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xi="http://www.w3.org/2001/XInclude"><xsl:strip-space elements="xi:fallback"/><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="string-length(destination/text())"/></xsl:template></xsl:stylesheet>"#,
    );
    let result = stylesheet
        .execute_with_source_processing(
            &Document::parse(
                r#"<destination xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="missing.xml"><xi:fallback> </xi:fallback></xi:include></destination>"#,
                Some("memory:source.xml"),
            )
            .expect("source parses"),
            &Parameters::new(),
            Arc::new(MemoryResolver::default()),
            ExecutionOptions {
                budget: execution_budget(4096),
                initial_mode: None,
                initial_template: None,
            },
            SourceProcessing::XInclude,
        )
        .expect("fallback executes");
    assert_eq!(result.serialized.bytes, b"1");
}

#[test]
fn xinclude_remaps_caller_nodeset_parameters() {
    // Caller handles identify the principal source before XInclude inserts the resolved subtree.
    let resolver = Arc::new(MemoryResolver::default());
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert(
            "included.xml".into(),
            "<included><extra/></included>".into(),
        );
    let source = Document::parse(
        r#"<root xmlns:p="urn:p" xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="included.xml"/><target id="v">ok</target></root>"#,
        Some("memory:source.xml"),
    )
    .expect("source parses");
    let target = source
        .nodes()
        .find_map(|(id, node)| match &node.kind {
            NodeKind::Element { name, .. } if name.local == "target" => Some(id),
            _ => None,
        })
        .expect("target exists");
    let namespace_index = match &source.node(target).expect("target exists").kind {
        NodeKind::Element { namespaces, .. } => namespaces
            .iter()
            .position(|namespace| namespace.prefix.as_deref() == Some("p"))
            .expect("p namespace is in scope"),
        _ => unreachable!("target is an element"),
    };
    let mut parameters = Parameters::new();
    parameters.insert(
        ExpandedName::new(None::<String>, "root"),
        Value::NodeSet(vec![NodeReference::Node(source.root())]),
    );
    parameters.insert(
        ExpandedName::new(None::<String>, "node"),
        Value::NodeSet(vec![NodeReference::Node(target)]),
    );
    parameters.insert(
        ExpandedName::new(None::<String>, "attribute"),
        Value::NodeSet(vec![NodeReference::Attribute {
            owner: target,
            index: 0,
        }]),
    );
    parameters.insert(
        ExpandedName::new(None::<String>, "namespace"),
        Value::NodeSet(vec![NodeReference::Namespace {
            owner: target,
            index: namespace_index,
        }]),
    );
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:param name="root"/><xsl:param name="node"/><xsl:param name="attribute"/><xsl:param name="namespace"/><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="count($root)"/><xsl:text>|</xsl:text><xsl:value-of select="$node"/><xsl:text>|</xsl:text><xsl:value-of select="$attribute"/><xsl:text>|</xsl:text><xsl:value-of select="$namespace"/></xsl:template></xsl:stylesheet>"#,
    );
    let result = stylesheet
        .execute_with_source_processing(
            &source,
            &parameters,
            resolver,
            ExecutionOptions {
                budget: execution_budget(4096),
                initial_mode: None,
                initial_template: None,
            },
            SourceProcessing::XInclude,
        )
        .expect("XInclude parameter remapping executes");
    assert_eq!(result.serialized.bytes, b"1|ok|v|urn:p");
}

struct EncodedDocumentResolver {
    bytes: Vec<u8>,
    encoding: Option<String>,
}

impl Resolver for EncodedDocumentResolver {
    fn resolve(
        &self,
        uri: &str,
        _base_uri: Option<&str>,
        purpose: ResolvePurpose,
    ) -> xml_sec_xslt::Result<ResolvedResource> {
        assert_eq!(uri, "encoded.xml");
        assert_eq!(purpose, ResolvePurpose::Document);
        Ok(ResolvedResource {
            canonical_uri: "memory:encoded.xml".into(),
            identity: ResourceIdentity("encoded.xml".into()),
            bytes: self.bytes.clone(),
            media_type: Some("application/xml".into()),
            encoding: self.encoding.clone(),
        })
    }
}

#[test]
fn document_function_decodes_non_utf8_resources() {
    // document() follows resolver metadata, XML declarations, BOMs and UTF-16 initial patterns.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="document('encoded.xml')/root"/></xsl:template></xsl:stylesheet>"#,
    );
    let latin1 = b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><root>caf\xe9</root>".to_vec();
    let utf16le = [0xff, 0xfe]
        .into_iter()
        .chain(
            "<?xml version=\"1.0\"?><root>λ</root>"
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        )
        .collect::<Vec<_>>();
    let utf16be = [0xfe, 0xff]
        .into_iter()
        .chain(
            "<?xml version=\"1.0\"?><root>Ж</root>"
                .encode_utf16()
                .flat_map(u16::to_be_bytes),
        )
        .collect::<Vec<_>>();
    for (bytes, encoding, expected) in [
        (latin1, None, "café"),
        (utf16le, None, "λ"),
        (utf16be, None, "Ж"),
        (
            b"<root>caf\xe9</root>".to_vec(),
            Some("ISO-8859-1".into()),
            "café",
        ),
    ] {
        let result = stylesheet
            .execute(
                &Document::parse("<source/>", None).expect("source parses"),
                &Parameters::new(),
                Arc::new(EncodedDocumentResolver { bytes, encoding }),
                ExecutionOptions {
                    budget: execution_budget(4096),
                    initial_mode: None,
                    initial_template: None,
                },
            )
            .expect("encoded document executes");
        assert_eq!(result.serialized.bytes, expected.as_bytes());
    }
}

#[test]
fn document_function_rejects_invalid_resource_encodings() {
    // Resolver metadata is authoritative, but unsupported labels and malformed bytes never decode
    // lossily or fall back to UTF-8.
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="document('encoded.xml')"/></xsl:template></xsl:stylesheet>"#,
    );
    for (bytes, encoding) in [
        (b"<root>\xff</root>".to_vec(), Some("UTF-8".into())),
        (b"<root/>".to_vec(), Some("X-UNKNOWN".into())),
    ] {
        assert!(matches!(
            stylesheet.execute(
                &Document::parse("<source/>", None).expect("source parses"),
                &Parameters::new(),
                Arc::new(EncodedDocumentResolver { bytes, encoding }),
                ExecutionOptions {
                    budget: execution_budget(4096),
                    initial_mode: None,
                    initial_template: None,
                },
            ),
            Err(Error::Xml(_))
        ));
    }
}

#[test]
fn decoded_external_document_is_bounded_before_xml_parsing() {
    // Latin-1 can expand when retained as UTF-8; budget exhaustion must win before XML parsing.
    let mut bytes = b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><root>".to_vec();
    bytes.extend(std::iter::repeat_n(0xe9, 65_536));
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="document('encoded.xml')"/></xsl:template></xsl:stylesheet>"#,
    );
    let mut budget = execution_budget(4096);
    budget.owned_bytes = 100_000;
    assert!(matches!(
        stylesheet.execute(
            &Document::parse("<source/>", None).expect("source parses"),
            &Parameters::new(),
            Arc::new(EncodedDocumentResolver {
                bytes,
                encoding: None,
            }),
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
fn equal_precedence_global_bindings_are_static_errors() {
    // Imported declarations may be overridden, but declarations in one precedence stratum may
    // not silently select either value.
    for declarations in [
        r#"<xsl:variable name="value" select="'old'"/><xsl:variable name="value" select="'new'"/>"#,
        r#"<xsl:param name="value" select="'old'"/><xsl:variable name="value" select="'new'"/>"#,
        r#"<xsl:variable name="value" select="'old'"/><xsl:param name="value" select="'new'"/>"#,
    ] {
        let source = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">{declarations}<xsl:template match="/"/></xsl:stylesheet>"#
        );
        assert!(matches!(
            Compiler::new(
                Arc::new(NoResolver),
                CompileBudget::new(4096, 0, 256, 16 * 1024),
            )
            .compile(&source, None),
            Err(Error::Static(message)) if message.contains("duplicate global variable")
        ));
    }
}

#[test]
fn undefined_attribute_sets_fail_on_every_consumer() {
    // Literal, computed, and copied elements must share the same static missing-definition
    // contract, even when their containing instruction would be unreachable at execution time.
    for body in [
        r#"<out xsl:use-attribute-sets="missing"/>"#,
        r#"<xsl:element name="out" use-attribute-sets="missing"/>"#,
        r#"<xsl:for-each select="/*"><xsl:copy use-attribute-sets="missing"/></xsl:for-each>"#,
    ] {
        let source = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/">{body}</xsl:template></xsl:stylesheet>"#
        );
        let error = Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(1 << 20, 16, 256, 4 << 20),
        )
        .compile(&source, Some("memory:main.xsl"))
        .expect_err("undefined attribute-set must fail during compilation");
        assert!(
            matches!(error, Error::Static(message) if message.contains("undefined attribute-set") && message.contains("missing"))
        );
    }
}

#[test]
fn cdata_output_names_use_the_default_namespace_only_when_bound() {
    // Unlike ordinary XSLT QName attributes, cdata-section-elements explicitly inherits the
    // xsl:output default namespace. Prefixed names still use their own bindings.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns="urn:default" xmlns:p="urn:prefixed"><xsl:output omit-xml-declaration="yes" indent="no" cdata-section-elements="out p:out"/><xsl:template match="/"><wrapper><xsl:element name="out" namespace="">plain</xsl:element><out>default</out><p:out>prefixed</p:out></wrapper></xsl:template></xsl:stylesheet>"#;
    let output = execute(stylesheet, "<source/>");
    assert!(output.contains(r#"<out xmlns="">plain</out>"#));
    assert!(output.contains("<out><![CDATA[default]]></out>"));
    assert!(output.contains("<p:out><![CDATA[prefixed]]></p:out>"));
}

#[test]
fn grouped_numbering_is_rejected_before_exceeding_owned_memory() {
    // An untrusted dynamic format can make the formatted integer much wider than its value. The
    // operation must reject the final grouped width before allocating that result.
    let format = "0".repeat(4096);
    let stylesheet = compile(&format!(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:number value="1" format="{format}" grouping-separator="," grouping-size="1"/></xsl:template></xsl:stylesheet>"#
    ));
    let mut budget = execution_budget(1024);
    budget.owned_bytes = 4096;
    let error = stylesheet
        .execute(
            &Document::parse("<root/>", None).expect("source parses"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget,
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect_err("grouped output must cross the allocation gate");
    assert!(matches!(
        error,
        Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        }
    ));
}

#[test]
fn wide_sibling_numbering_does_not_require_a_copied_sibling_set() {
    // xsl:number can scan the retained source children directly; the number of siblings must not
    // impose a second SourceNode-sized allocation on the peak OwnedBytes budget.
    let source_xml = format!("<root>{}</root>", "<item/>".repeat(4_096));
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template name="baseline"><xsl:apply-templates select="root/item[last()]" mode="baseline"/></xsl:template><xsl:template name="number"><xsl:apply-templates select="root/item[last()]" mode="number"/></xsl:template><xsl:template match="item" mode="baseline">4096</xsl:template><xsl:template match="item" mode="number"><xsl:number/></xsl:template></xsl:stylesheet>"#,
    );
    let source = Document::parse(&source_xml, None).expect("wide source parses");
    let minimum = |initial_template: &str| {
        let succeeds = |owned_bytes| {
            let mut budget = execution_budget(source_xml.len());
            budget.owned_bytes = owned_bytes;
            stylesheet
                .execute(
                    &source,
                    &Parameters::new(),
                    Arc::new(NoResolver),
                    ExecutionOptions {
                        budget,
                        initial_mode: None,
                        initial_template: Some(ExpandedName::new(None::<String>, initial_template)),
                    },
                )
                .is_ok()
        };
        let mut rejected = 0;
        let mut accepted = 1;
        while !succeeds(accepted) {
            rejected = accepted;
            accepted *= 2;
        }
        while rejected + 1 < accepted {
            let candidate = rejected + (accepted - rejected) / 2;
            if succeeds(candidate) {
                accepted = candidate;
            } else {
                rejected = candidate;
            }
        }
        accepted
    };
    let baseline = minimum("baseline");
    let numbering = minimum("number");
    assert!(
        numbering <= baseline + 8 * 1024,
        "baseline={baseline}, numbering={numbering}"
    );
}

#[test]
fn number_letter_value_rejects_invalid_evaluated_values_in_strict_mode() {
    // XSLT 1.0 section 7.7 permits only alphabetic and traditional after AVT evaluation.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#number
    for letter_value in ["bogus", "{$choice}"] {
        let stylesheet = compile(&format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:param name="choice" select="'bogus'"/><xsl:output method="text"/><xsl:template match="/"><xsl:number value="1" format="A" letter-value="{letter_value}"/></xsl:template></xsl:stylesheet>"#
        ));
        let error = stylesheet
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
            .expect_err("invalid letter-value must be rejected");
        assert!(matches!(
            error,
            Error::Dynamic(message) if message.contains("letter-value") && message.contains("bogus")
        ));
    }

    for letter_value in ["alphabetic", "traditional"] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:number value="1" format="A" letter-value="{letter_value}"/></xsl:template></xsl:stylesheet>"#
        );
        assert!(!execute(&stylesheet, "<source/>").is_empty());
    }
}

#[test]
fn explicit_latin_format_tokens_remain_alphabetic_with_traditional_letter_value() {
    // XSLT 1.0 section 7.7.1 defines the exact A/a sequences; letter-value disambiguates other
    // language-specific tokens and cannot turn these explicit tokens into decimal numbering.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#convert
    for (format, expected) in [("A", "AA"), ("a", "aa")] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:number value="27" format="{format}" letter-value="traditional"/></xsl:template></xsl:stylesheet>"#
        );
        assert_eq!(execute(&stylesheet, "<source/>"), expected);
    }
}

#[test]
fn alphabetic_and_roman_numbering_do_not_narrow_large_xpath_numbers() {
    // XSLT 1.0 section 7.7 rounds the XPath Number before formatting; converting that value to a
    // platform integer must not collapse distinct finite inputs: https://www.w3.org/TR/1999/REC-xslt-19991116#number
    for (format, expected_1e20, expected_1e30) in [
        ("A", "ANGWJIRSMASUFQV", "AXDQVMMXOILDPAOLPKLIKN"),
        ("a", "angwjirsmasufqv", "axdqvmmxoildpaolpklikn"),
        (
            "I",
            "100000000000000000000",
            "1000000000000000000000000000000",
        ),
        (
            "i",
            "100000000000000000000",
            "1000000000000000000000000000000",
        ),
    ] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:param name="value"/><xsl:template match="/"><xsl:number value="$value" format="{format}"/></xsl:template></xsl:stylesheet>"#,
        );
        let stylesheet = compile(&stylesheet);
        let execute_value = |value| {
            let mut parameters = Parameters::new();
            parameters.insert(
                ExpandedName::new(None::<String>, "value"),
                Value::Number(value),
            );
            let result = stylesheet
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
                .expect("large finite number formats");
            String::from_utf8(result.serialized.bytes).expect("text output is UTF-8")
        };
        assert_eq!(execute_value(1e20), expected_1e20);
        assert_eq!(execute_value(1e30), expected_1e30);
    }
}

#[test]
fn undesignated_exslt_function_declarations_remain_inert() {
    // XSLT 1.0 section 2.2 ignores foreign top-level data, and EXSLT Functions requires its
    // namespace to be designated as an extension: https://exslt.github.io/func/#namespace
    compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:func="http://exslt.org/functions"><func:function/><xsl:template match="/"/></xsl:stylesheet>"#,
    );
}

#[test]
fn number_letter_value_is_ignored_in_forward_compatible_mode() {
    // XSLT 1.0 section 2.5 requires an invalid optional attribute value to be ignored while
    // forwards-compatible processing is active.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#forwards
    let stylesheet = r#"<xsl:stylesheet version="2.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:number value="1" format="A" letter-value="bogus"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "A");
}

#[test]
fn content_created_bindings_preserve_the_current_template_rule() {
    // Binding sequence constructors execute in their containing template context, so each legal
    // form must preserve the current rule used by xsl:apply-imports.
    for main in [
        r#"<xsl:template match="/"><xsl:variable name="value"><xsl:apply-imports/></xsl:variable><xsl:value-of select="$value"/></xsl:template>"#,
        r#"<xsl:template match="/"><xsl:param name="value"><xsl:apply-imports/></xsl:param><xsl:value-of select="$value"/></xsl:template>"#,
        r#"<xsl:template match="/"><xsl:call-template name="bridge"><xsl:with-param name="value"><xsl:apply-imports/></xsl:with-param></xsl:call-template></xsl:template><xsl:template name="bridge"><xsl:param name="value"/><xsl:value-of select="$value"/></xsl:template>"#,
    ] {
        let resolver = Arc::new(MemoryResolver::default());
        resolver
            .resources
            .lock()
            .expect("test resolver mutex is not poisoned")
            .insert(
                "base.xsl".into(),
                r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/">base</xsl:template></xsl:stylesheet>"#.into(),
            );
        let stylesheet = Compiler::new(
            Arc::clone(&resolver),
            CompileBudget::new(1 << 20, 8, 256, 1 << 20),
        )
        .compile(
            &format!(
                r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:import href="base.xsl"/><xsl:output method="text"/>{main}</xsl:stylesheet>"#
            ),
            Some("memory:main.xsl"),
        )
        .expect("binding stylesheet compiles");
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
            .expect("binding content preserves the current matched rule");
        assert_eq!(result.serialized.bytes, b"base");
    }
}

#[test]
fn attribute_sets_preserve_the_current_template_rule() {
    // XSLT 1.0 section 7.1.4 makes use-attribute-sets equivalent to inserting the set's
    // xsl:attribute instructions at the start of the caller's sequence constructor.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#attribute-sets
    let resolver = Arc::new(MemoryResolver::default());
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert(
            "base.xsl".into(),
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:text>base</xsl:text></xsl:template></xsl:stylesheet>"#.into(),
        );
    let stylesheet = Compiler::new(
        Arc::clone(&resolver),
        CompileBudget::new(1 << 20, 8, 256, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:import href="base.xsl"/><xsl:output omit-xml-declaration="yes"/><xsl:attribute-set name="attrs"><xsl:attribute name="value"><xsl:apply-imports/></xsl:attribute></xsl:attribute-set><xsl:template match="/"><out xsl:use-attribute-sets="attrs"/></xsl:template></xsl:stylesheet>"#,
        Some("memory:main.xsl"),
    )
    .expect("attribute-set stylesheet compiles");
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
        .expect("attribute-set content retains the matched template rule");
    assert_eq!(result.serialized.bytes, b"<out value=\"base\"/>\n");
}

#[test]
fn xinclude_text_rejects_characters_forbidden_by_xml() {
    // Successful byte decoding is not sufficient: parse="text" still contributes XML character
    // information items and must reject U+0000 before mutating the semantic document.
    let resolver = Arc::new(MemoryResolver::default());
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert("invalid.txt".into(), "left\0right".into());
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="."/></xsl:template></xsl:stylesheet>"#,
    );
    let source = Document::parse(
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="invalid.txt" parse="text"/></root>"#,
        Some("memory:source.xml"),
    )
    .expect("source parses");
    let error = stylesheet
        .execute_with_source_processing(
            &source,
            &Parameters::new(),
            resolver,
            ExecutionOptions {
                budget: execution_budget(1024),
                initial_mode: None,
                initial_template: None,
            },
            SourceProcessing::XInclude,
        )
        .expect_err("forbidden XML characters must fail inclusion");
    assert!(matches!(error, Error::Xml(message) if message.contains("XML character")));
}

#[test]
fn xinclude_text_validates_after_non_utf8_decoding() {
    // Character validation applies to decoded Unicode, not raw octets; a valid Latin-1 resource
    // must remain usable while forbidden decoded scalar values fail in the companion test.
    let resolver = Arc::new(ByteResolver::default());
    resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned")
        .insert("latin1.txt".into(), b"caf\xe9".to_vec());
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="."/></xsl:template></xsl:stylesheet>"#,
    );
    let source = Document::parse(
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="latin1.txt" parse="text" encoding="ISO-8859-1"/></root>"#,
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
            SourceProcessing::XInclude,
        )
        .expect("valid decoded XInclude text transforms");
    assert_eq!(result.serialized.bytes, "café".as_bytes());
}

#[test]
fn html_output_ignores_xml_cdata_section_settings() {
    // cdata-section-elements belongs to the XML output method; HTML must escape text according
    // to HTML syntax instead of emitting a bogus CDATA construct.
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="html" indent="no" cdata-section-elements="div"/><xsl:template match="/"><div>a&lt;b</div></xsl:template></xsl:stylesheet>"#;
    let output = execute(stylesheet, "<source/>");
    assert_eq!(output, "<div>a&lt;b</div>");
    assert!(!output.contains("<![CDATA["));
}

#[test]
fn exslt_replace_preserves_libxslt_node_set_string_compatibility() {
    // The current EXSLT text specifies replacement nodes, but libxslt implements the earlier
    // contract by using each node's XPath string-value. Drop-in compatibility takes precedence.
    // https://exslt.github.io/str/functions/replace/index.html
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:str="http://exslt.org/strings" exclude-result-prefixes="str"><xsl:output omit-xml-declaration="yes"/><xsl:template match="/"><out><xsl:copy-of select="str:replace('abc', root/search, root/replacement/node())"/></out></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(
            stylesheet,
            "<root><search>a</search><search>b</search><search>c</search><replacement><mark id=\"kept\">R</mark><!--kept--><?kept value?></replacement></root>",
        ),
        "<out>Rkeptvalue</out>\n",
    );
}

#[test]
fn exslt_replace_applies_empty_searches_after_nonempty_matches() {
    // EXSLT requires empty search strings to insert their replacement between characters while
    // longer nonempty searches retain priority.
    // https://exslt.github.io/str/functions/replace/index.html
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:str="http://exslt.org/strings"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="str:replace('abc', root/search, root/replacement)"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(
            stylesheet,
            "<root><search>a</search><search/><replacement>X</replacement><replacement>-</replacement></root>",
        ),
        "Xb-c",
    );
}

#[test]
fn exslt_replace_pairs_node_sets_in_document_order() {
    // EXSLT str:replace pairs node-set arguments in document order, independently of the
    // hash iteration order used by the underlying XPath implementation.
    // https://exslt.github.io/str/functions/replace/index.html
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:str="http://exslt.org/strings"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="str:replace('ab', root/search, root/replacement)"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(
        execute(
            stylesheet,
            "<root><search>b</search><search>a</search><replacement>B</replacement><replacement>A</replacement></root>",
        ),
        "AB",
    );
}

#[test]
fn exslt_replace_reserves_node_set_string_materialization() {
    // Search and replacement string-values remain live together while pairing, so both lists
    // must cross the operation-owned-memory gate before their payloads are allocated.
    let payload = "x".repeat(32 * 1024);
    let source = Document::parse(
        &format!("<root><search>{payload}</search><replacement>{payload}</replacement></root>"),
        Some("memory:source.xml"),
    )
    .expect("source parses");
    let literal = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:str="http://exslt.org/strings"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="str:replace('', '', '')"/></xsl:template></xsl:stylesheet>"#,
    );
    let succeeds = |stylesheet: &xml_sec_xslt::Stylesheet, owned_bytes| {
        let mut budget = execution_budget(1 << 20);
        budget.owned_bytes = owned_bytes;
        stylesheet
            .execute(
                &source,
                &Parameters::new(),
                Arc::new(NoResolver),
                ExecutionOptions {
                    budget,
                    initial_mode: None,
                    initial_template: None,
                },
            )
            .is_ok()
    };
    let mut rejected = 0;
    let mut accepted = 1;
    while !succeeds(&literal, accepted) {
        rejected = accepted;
        accepted *= 2;
    }
    while rejected + 1 < accepted {
        let candidate = rejected + (accepted - rejected) / 2;
        if succeeds(&literal, candidate) {
            accepted = candidate;
        } else {
            rejected = candidate;
        }
    }
    let nodes = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:str="http://exslt.org/strings"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="str:replace('', root/search, root/replacement)"/></xsl:template></xsl:stylesheet>"#,
    );
    let mut budget = execution_budget(1 << 20);
    budget.owned_bytes = accepted + 4096;

    assert!(matches!(
        nodes.execute(
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
fn include_position_blocks_later_imports_but_not_earlier_imports() {
    // XSLT 1.0 section 2.6.2 requires imports before every other element child, explicitly
    // including xsl:include, after included imports have been hoisted.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#import
    let resolver = Arc::new(MemoryResolver::default());
    let mut resources = resolver
        .resources
        .lock()
        .expect("test resolver mutex is not poisoned");
    resources.insert(
        "empty.xsl".into(),
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"/>"#
            .into(),
    );
    resources.insert(
        "base.xsl".into(),
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"/></xsl:stylesheet>"#.into(),
    );
    drop(resources);

    let compiler = Compiler::new(resolver, CompileBudget::new(1 << 20, 8, 256, 1 << 20));
    let invalid = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:include href="empty.xsl"/><xsl:import href="base.xsl"/></xsl:stylesheet>"#;
    assert!(matches!(
        compiler.compile(invalid, Some("memory:main.xsl")),
        Err(Error::Static(message)) if message.contains("xsl:import")
    ));

    let valid = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:import href="base.xsl"/><xsl:include href="empty.xsl"/></xsl:stylesheet>"#;
    compiler
        .compile(valid, Some("memory:main.xsl"))
        .expect("leading import followed by include is valid");
}

#[test]
fn top_level_extensions_require_a_namespace() {
    // XSLT 1.0 section 2.2 permits non-XSLT top-level elements only when their expanded name
    // has a non-null namespace URI. Unqualified elements must not disappear silently.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#stylesheet-element
    let invalid = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><bogus/></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(1 << 20, 0, 32, 1 << 20),
        )
        .compile(invalid, Some("memory:main.xsl")),
        Err(Error::Static(message)) if message.contains("namespace")
    ));

    let valid = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:ext="urn:extension"><ext:metadata/></xsl:stylesheet>"#;
    Compiler::new(
        Arc::new(NoResolver),
        CompileBudget::new(1 << 20, 0, 32, 1 << 20),
    )
    .compile(valid, Some("memory:main.xsl"))
    .expect("namespaced top-level extensions remain valid");

    let forward = r#"<xsl:stylesheet version="2.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><future-declaration/></xsl:stylesheet>"#;
    Compiler::new(
        Arc::new(NoResolver),
        CompileBudget::new(1 << 20, 0, 32, 1 << 20),
    )
    .compile(forward, Some("memory:main.xsl"))
    .expect("forward-compatible processing ignores unknown top-level elements");
}

#[test]
fn empty_top_level_declarations_reject_child_content() {
    // XSLT 1.0 element syntax gives namespace-alias an EMPTY content model. Both element
    // children and whitespace preserved by xml:space violate that model.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#namespace-alias
    for declaration in [
        r#"<xsl:namespace-alias stylesheet-prefix="xsl" result-prefix="xsl"><child/></xsl:namespace-alias>"#,
        r#"<xsl:namespace-alias stylesheet-prefix="xsl" result-prefix="xsl" xml:space="preserve"> </xsl:namespace-alias>"#,
    ] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">{declaration}</xsl:stylesheet>"#
        );
        assert!(matches!(
            Compiler::new(
                Arc::new(NoResolver),
                CompileBudget::new(1 << 20, 0, 32, 1 << 20),
            )
            .compile(&stylesheet, Some("memory:main.xsl")),
            Err(Error::Static(message)) if message.contains("namespace-alias") && message.contains("empty")
        ));
    }
}

#[test]
fn include_and_import_validate_content_before_resolving() {
    struct CountingResolver(AtomicUsize);

    impl Resolver for CountingResolver {
        fn resolve(
            &self,
            uri: &str,
            _base_uri: Option<&str>,
            _purpose: ResolvePurpose,
        ) -> xml_sec_xslt::Result<ResolvedResource> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(Error::Resolver {
                uri: uri.into(),
                message: "resolver must not be reached".into(),
            })
        }
    }

    // XSLT 1.0 sections 2.6.1, 2.6.2 and 18 define include/import as EMPTY. Static
    // validation must precede external-resource side effects.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#include
    let resolver = Arc::new(CountingResolver(AtomicUsize::new(0)));
    for declaration in [
        r#"<xsl:include href="module.xsl"><child/></xsl:include>"#,
        r#"<xsl:import href="module.xsl"><child/></xsl:import>"#,
    ] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">{declaration}</xsl:stylesheet>"#
        );
        assert!(matches!(
            Compiler::new(
                Arc::clone(&resolver),
                CompileBudget::new(1 << 20, 8, 32, 1 << 20),
            )
            .compile(&stylesheet, Some("memory:main.xsl")),
            Err(Error::Static(message)) if message.contains("empty")
        ));
    }
    assert_eq!(resolver.0.load(Ordering::SeqCst), 0);
}

#[test]
fn named_only_templates_reject_mode() {
    // XSLT 1.0 section 5.7 states that xsl:template without match must not have mode.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#modes
    let invalid = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template name="named" mode="m"/></xsl:stylesheet>"#;
    assert!(matches!(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(1 << 20, 0, 32, 1 << 20),
        )
        .compile(invalid, Some("memory:main.xsl")),
        Err(Error::Static(message)) if message.contains("mode") && message.contains("match")
    ));
}

#[test]
fn named_only_templates_allow_priority_without_affecting_named_dispatch() {
    // XSLT 1.0 section 6 says match, mode, and priority do not affect invocation through
    // xsl:call-template. Unlike mode, the specification does not prohibit priority without match.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#named-templates
    let stylesheet = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template name="named" priority="1"><xsl:text>called</xsl:text></xsl:template><xsl:template match="/"><xsl:call-template name="named"/></xsl:template></xsl:stylesheet>"#;
    assert_eq!(execute(stylesheet, "<source/>"), "called");
}

#[test]
fn string_length_variable_fast_path_accepts_xpath_whitespace() {
    // XPath 1.0 section 3.7 permits XML S between tokens. The shortcut must resolve the same
    // variable as the generic evaluator for every permitted whitespace character.
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#exprlex
    for whitespace in [" ", "&#9;", "&#10;", "&#13;"] {
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:param name="value" select="'present'"/><xsl:template match="/"><xsl:value-of select="string-length($value{whitespace}) &gt; 0"/></xsl:template></xsl:stylesheet>"#
        );
        assert_eq!(execute(&stylesheet, "<source/>"), "true");
    }
}

#[test]
fn empty_document_uris_preserve_their_logical_document_origin() {
    // XSLT 1.0 section 12.1 resolves a zero-length URI to the document that supplies its base.
    // Source-relative requests and the omitted-argument stylesheet default must not collide.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#document
    let stylesheet = compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:meta="urn:metadata"><meta:marker>stylesheet</meta:marker><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="document('', /)/source/@origin"/><xsl:text>|</xsl:text><xsl:value-of select="document(/source/uri)/source/@origin"/><xsl:text>|</xsl:text><xsl:value-of select="document('')/*/meta:marker"/></xsl:template></xsl:stylesheet>"#,
    );
    let result = stylesheet
        .execute(
            &Document::parse(
                r#"<source origin="source"><uri/></source>"#,
                Some("memory:source.xml"),
            )
            .expect("source parses"),
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: execution_budget(1 << 20),
                initial_mode: None,
                initial_template: None,
            },
        )
        .expect("empty document URIs resolve without external access");
    assert_eq!(result.serialized.bytes, b"source|source|stylesheet");
}
