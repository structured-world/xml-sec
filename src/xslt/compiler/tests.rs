use super::*;

#[test]
fn principal_base_uri_copy_is_charged_by_retained_capacity() {
    let budget = CompileBudget::new(4096, 0, 32, 4096);
    let mut state = CompileState::new(budget, 0);
    let uri = "memory:principal/".repeat(32);

    let retained = clone_compile_string(Some(&uri), &mut state)
        .expect("principal URI fits the compiler budget")
        .expect("principal URI is retained");

    assert_eq!(retained, uri);
    assert_eq!(state.owned_bytes, retained.capacity());
}

#[test]
fn active_module_stack_is_bounded_before_growth() {
    let slot_bytes = std::mem::size_of::<ActiveResource>();
    let budget = CompileBudget::new(4096, 0, 32, slot_bytes * 4 - 1);
    let compiler = Compiler::new(Arc::new(crate::NoResolver), budget);
    let mut state = CompileState::new(budget, 0);
    let entered = Cell::new(false);

    let error = compiler
        .enter_module(
            StylesheetDocumentId(1),
            "memory:module.xsl",
            None,
            &mut state,
            |_| {
                entered.set(true);
                Ok(())
            },
        )
        .expect_err("active module storage must cross the compile-owned budget first");

    assert!(!entered.get());
    assert!(matches!(
        error,
        Error::Budget {
            kind: BudgetKind::OwnedBytes,
            actual,
            ..
        } if actual == slot_bytes * 4
    ));
}

#[test]
fn xpath_diagnostics_reserve_the_exact_formatted_length() {
    // Prefix diagnostics preserve their text when it fits and fail before formatting otherwise.
    let source = "missing:item";
    let expected = "XPath expression `missing:item` uses unbound namespace prefix `missing`";
    let retained = std::cell::Cell::new(0);
    for limit in [expected.len() - 1, expected.len()] {
        let workspace = CompileWorkspace {
            limit,
            occupied: 0,
            retained: &retained,
        };
        let error = validate_xpath_prefixes(source, &[], workspace)
            .expect_err("unbound prefix produces a static or budget error");
        if limit == expected.len() {
            assert!(matches!(error, Error::Static(message) if message == expected));
        } else {
            assert!(matches!(error, Error::Budget { actual, .. } if actual == expected.len()));
        }
    }
}

#[test]
fn xpath_parser_diagnostic_accounts_for_owned_token_and_escaping() {
    // Debug escaping expands a token. Measure the rendered diagnostic, not source length,
    // and keep the unexpected token's string charged until formatting finishes.
    let source = "f(1 'a\nb')";
    let error = sxd_xpath_no_unsafe::Factory::new()
        .build(source)
        .expect_err("missing argument separator leaves an unexpected literal token");
    assert_eq!(error.owned_bytes(), 3);
    let message = format!("invalid XPath expression `{source}`: {error}");
    let required = message.len() + error.owned_bytes();
    let retained = Cell::new(0);
    let workspace = CompileWorkspace {
        limit: required - 1,
        occupied: 0,
        retained: &retained,
    };
    assert!(
        matches!(workspace.parser_error(error.clone(), source, false),
        Error::Budget { actual, .. } if actual == required)
    );
    let workspace = CompileWorkspace {
        limit: required,
        ..workspace
    };
    assert!(matches!(workspace.parser_error(error, source, false),
        Error::Static(actual) if actual == message));
}

#[test]
fn xpath_namespace_copies_and_reference_conversion_are_charged() {
    // Each pattern owns a namespace copy. References duplicate namespace strings, but dedup
    // frees duplicates before the Vec-to-Arc overlap and retained charge are calculated.
    let document = roxmltree::Document::parse(r#"<root xmlns:p="urn:namespace"/>"#)
        .expect("namespace accounting fixture parses");
    let node = document.root_element();
    let retained = Cell::new(0);
    let workspace = CompileWorkspace {
        limit: 16_384,
        occupied: 0,
        retained: &retained,
    };
    let namespaces = namespaces(node);
    let copy_bytes = namespaces.capacity() * std::mem::size_of::<(String, String)>()
        + namespaces
            .iter()
            .map(|(prefix, uri)| prefix.capacity() + uri.capacity())
            .sum::<usize>();
    assert_eq!(
        namespace_copy_bytes(node, false, workspace)
            .expect("namespace copy size fits the workspace"),
        copy_bytes
    );
    let first = Pattern::new("p:a", node, workspace).expect("first pattern and namespace copy fit");
    let second = Pattern::new("p:b", node, workspace)
        .expect("second pattern and namespace copy fit alongside the first");
    assert_eq!(
        retained.get(),
        2 * copy_bytes + first.source.capacity() + second.source.capacity()
    );

    let names = [("p".to_owned(), "urn:namespace".to_owned())];
    let unit = std::mem::size_of::<ExpandedName>();
    let payload = "urn:namespace".len() + 1;
    let arc = 2 * unit + 2 * std::mem::size_of::<usize>();
    let peak = (3 * unit + 3 * payload).max(3 * unit + 2 * payload + arc);
    for limit in [peak - 1, peak] {
        let retained = Cell::new(0);
        let workspace = CompileWorkspace {
            limit,
            occupied: 0,
            retained: &retained,
        };
        let result = referenced_variables_bounded("$p:a + $p:a + $p:b", &names, workspace);
        if limit == peak {
            assert_eq!(
                result.expect("exact reference-conversion peak fits").len(),
                2
            );
            assert_eq!(retained.get(), arc + 2 * payload);
        } else {
            assert!(matches!(result, Err(Error::Budget { actual, .. }) if actual == peak));
        }
    }
}

#[test]
fn included_literal_reuses_future_source_storage_during_validation() {
    // Import discovery and compilation share one decode. The validation literal and retained
    // expression source are not live together and must not require a seventh payload copy.
    let payload = "x".repeat(64 * 1024);
    let module = format!(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:variable name="payload" select="'{payload}'"/></xsl:stylesheet>"#
    );
    let principal = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:include href="module.xsl"/></xsl:stylesheet>"#;
    Compiler::new(
        Arc::new(RepeatedIncludeResolver {
            module: module.into_bytes(),
            encoding: None,
        }),
        CompileBudget::new(1 << 20, 8, 256, 450 * 1024),
    )
    .compile(principal, Some("memory:main.xsl"))
    .expect("one decoded source and nonoverlapping XPath storage fit");
}

#[test]
fn xpath_source_credit_is_limited_to_its_borrowed_attribute_slice() {
    // Equal text is not proof of precharged storage. Generated defaults and independent
    // strings cannot borrow another attribute's reservation, even if their values match.
    let document = roxmltree::Document::parse(r#"<root select="'payload'"/>"#)
        .expect("source-credit fixture parses");
    let node = document.root_element();
    let source = node
        .attribute("select")
        .expect("fixture has a select attribute");
    let retained = Cell::new(0);
    let workspace = CompileWorkspace {
        limit: 4096,
        occupied: source.len(),
        retained: &retained,
    };
    assert_eq!(workspace.pending_source(source, node).occupied, 0);
    assert_eq!(workspace.pending_source(&source[1..8], node).occupied, 2);
    let independent = source.to_owned();
    assert_eq!(
        workspace.pending_source(&independent, node).occupied,
        source.len()
    );
    assert_eq!(
        workspace.pending_source("node()", node).occupied,
        source.len()
    );
}

#[test]
fn xpath_prefix_scan_preserves_unicode_axes_and_literals() {
    // Byte offsets must remain UTF-8 boundaries; axes and quoted colons are not prefixes.
    let retained = Cell::new(0);
    let workspace = CompileWorkspace {
        limit: 4096,
        occupied: 0,
        retained: &retained,
    };
    let namespaces = vec![("\u{3c0}".into(), "urn:test".into())];
    for source in [
        "child::\u{3c0}:item/@xml:lang",
        "\u{3c0}:*",
        "concat('missing:name', \"other:*\")",
    ] {
        validate_xpath_prefixes(source, &namespaces, workspace)
            .expect("bound prefixes are accepted");
    }
    let source = "child::\u{3bb}:item";
    assert!(matches!(
        validate_xpath_prefixes(source, &namespaces, workspace),
        Err(Error::Static(message)) if message == format!(
            "XPath expression `{source}` uses unbound namespace prefix `\u{3bb}`"
        )
    ));
}

#[test]
fn xpath_normalization_preserves_tokens_and_bounds_capacity() {
    // Preserve literals and non-XML whitespace while adapting axes, calls and wildcards.
    for (source, expected) in [
        ("child \t:: \n\u{3c0}:item", "child::\u{3c0}:item"),
        ("count \r( * )", "count( child::* )"),
        ("f(*, *, ' * :: ( ')", "f(child::*, child::*, ' * :: ( ')"),
        ("2 * 3", "2 * 3"),
        ("f\u{a0}(*)", "f\u{a0}(child::*)"),
    ] {
        let normalized = normalize_xpath_for_sxd(source);
        assert_eq!(normalized.as_ref(), expected);
        if let Cow::Owned(output) = normalized {
            assert_eq!(output.capacity(), expected.len());
        }
    }
    for source in ["\u{3c0}:item", "' * :: ( '", "2 * 3"] {
        assert!(matches!(normalize_xpath_for_sxd(source), Cow::Borrowed(_)));
    }
}

#[test]
fn large_literal_attributes_do_not_reserve_xpath_grammar_workspace() {
    // Neither a literal AVT nor one quoted XPath literal represents a million AST nodes.
    let payload = "x".repeat(1 << 20);
    for value in [payload.clone(), format!("{{'{payload}'}}")] {
        let xml = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><out value="{value}"/></xsl:template></xsl:stylesheet>"#
        );
        Compiler::new(
            Arc::new(crate::NoResolver),
            CompileBudget::new(2 << 20, 0, 32, 32 << 20),
        )
        .compile(&xml, None)
        .expect("literal storage fits without fictitious grammar work");
    }
}

#[test]
fn small_compile_budgets_preserve_static_error_contracts() {
    // This previously failed at the speculative module reservation before syntax checking.
    let xml = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:apply-templates>invalid</xsl:apply-templates></xsl:template></xsl:stylesheet>"#;
    assert!(
        matches!(Compiler::new(Arc::new(crate::NoResolver), CompileBudget::new(4096, 0, 32, 16_384)).compile(xml, None), Err(Error::Static(message)) if message == "xsl:apply-templates accepts only xsl:sort and xsl:with-param")
    );
}

#[test]
fn xpath_compile_workspace_precedes_validation_and_is_released() {
    // Actual token/AST allocations, not a module estimate, must cross the allocation gate.
    let retained = Cell::new(0);
    let workspace = CompileWorkspace {
        limit: 128,
        occupied: 128,
        retained: &retained,
    };
    assert!(matches!(
        workspace.parse_xpath("'payload'", "'payload'", false),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            limit: 128,
            actual: 135
        })
    ));
    let workspace = CompileWorkspace {
        limit: 4096,
        occupied: 128,
        retained: &retained,
    };
    for _ in 0..100 {
        workspace
            .parse_xpath("'payload'", "'payload'", false)
            .expect("dropped AST releases its allowance");
        assert!(matches!(
            workspace.parse_xpath("1 +", "1 +", false),
            Err(Error::Static(_))
        ));
    }
    assert_eq!(workspace.occupied, 128);
}

#[test]
fn xpath_compile_workspace_covers_patterns_keys_and_avts() {
    // Direct Pattern/Expression constructors and context-based AVTs must share the gate.
    for body in [
        r#"<xsl:template match="child :: item[count( * )]"/>"#,
        r#"<xsl:key name="k" match="item" use="count( * )"/>"#,
        r#"<xsl:template match="/"><out value="{count( * )}"/></xsl:template>"#,
        r#"<xsl:template match="/"><xsl:number count="child :: item"/></xsl:template>"#,
    ] {
        let xml = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">{body}</xsl:stylesheet>"#
        );
        let document = roxmltree::Document::parse(&xml).expect("XML parses");
        let required =
            parser_workspace_bytes(&xml) + estimate_compiled_owned_bytes(&document, None);
        assert!(matches!(
            Compiler::new(
                Arc::new(crate::NoResolver),
                CompileBudget::new(xml.len(), 0, 32, required),
            ).compile(&xml, None),
            Err(Error::Budget { kind: BudgetKind::OwnedBytes, actual, .. })
                if actual > required
        ));
        Compiler::new(
            Arc::new(crate::NoResolver),
            CompileBudget::new(xml.len(), 0, 32, 4 << 20),
        )
        .compile(&xml, None)
        .expect("the same source compiles with sufficient workspace");
    }
}

struct RepeatedIncludeResolver {
    module: Vec<u8>,
    encoding: Option<String>,
}

struct FragmentModuleResolver {
    module: Vec<u8>,
}

impl Resolver for RepeatedIncludeResolver {
    fn authorize(&self, _: crate::ResourceAccess<'_>) -> Result<()> {
        // This fixture has a permanent grant for its immutable in-memory module.
        Ok(())
    }
    fn resolve(&self, request: crate::ResolveRequest<'_>) -> Result<ResolvedResource> {
        let crate::ResolveRequest { uri, purpose, .. } = request;
        assert_eq!(uri, "module.xsl");
        assert_eq!(purpose, ResolvePurpose::Include);
        Ok(ResolvedResource {
            canonical_uri: "memory:module.xsl".into(),
            identity: ResourceIdentity("repeated-module".into()),
            bytes: self.module.clone(),
            media_type: Some("application/xslt+xml".into()),
            encoding: self.encoding.clone(),
        })
    }
}

impl Resolver for FragmentModuleResolver {
    fn authorize(&self, _: crate::ResourceAccess<'_>) -> Result<()> {
        // Fragment variants share the same permanently authorized fixture bytes.
        Ok(())
    }
    fn resolve(&self, request: crate::ResolveRequest<'_>) -> Result<ResolvedResource> {
        assert_eq!(request.uri, "module.xml");
        assert!(matches!(
            request.purpose,
            ResolvePurpose::Include | ResolvePurpose::Import
        ));
        Ok(ResolvedResource {
            canonical_uri: "memory:module.xml".into(),
            identity: ResourceIdentity("fragment-module".into()),
            bytes: self.module.clone(),
            media_type: Some("application/xml".into()),
            encoding: Some("UTF-8".into()),
        })
    }
}

fn embedded_stylesheet_module(ids: (&str, &str)) -> Vec<u8> {
    format!(
        r#"<bundle xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:stylesheet id="{}" version="1.0"><xsl:template name="ignored"/></xsl:stylesheet><xsl:stylesheet id="{}" version="1.0"><xsl:template name="selected"/></xsl:stylesheet></bundle>"#,
        ids.0, ids.1
    )
    .into_bytes()
}

#[test]
fn many_distinct_local_bindings_compile_with_one_scope_index() {
    // A wide lexical scope must use the incremental binding index rather than rescanning all
    // preceding siblings for every declaration.
    let mut body = String::new();
    for index in 0..2_048 {
        use std::fmt::Write as _;
        write!(body, r#"<xsl:variable name="v{index}" select="{index}"/>"#)
            .expect("writing to a String succeeds");
    }
    let stylesheet = format!(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/">{body}</xsl:template></xsl:stylesheet>"#
    );

    Compiler::new(
        Arc::new(crate::NoResolver),
        CompileBudget::new(8 << 20, 4, 32, 16 << 20),
    )
    .compile(&stylesheet, None)
    .expect("distinct bindings compile without repeated sibling scans");
}

#[test]
fn local_binding_index_reserves_and_releases_compile_workspace() {
    // The temporary scope index is attacker-controlled compiler state and must remain charged
    // for exactly the lifetime of the shared index.
    let retained = Cell::new(0usize);
    let workspace = CompileWorkspace {
        limit: usize::MAX,
        occupied: 0,
        retained: &retained,
    };
    let document = roxmltree::Document::parse(
        r#"<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><xsl:template match="/"><xsl:variable name="value"/></xsl:template></xsl:stylesheet>"#,
    )
    .expect("stylesheet parses");
    let variable = document
        .descendants()
        .find(|node| node.has_tag_name((XSLT_NS, "variable")))
        .expect("variable exists");
    let context = CompileContext::new(
        false,
        1,
        16,
        None,
        StylesheetDocumentId::PRINCIPAL,
        workspace,
        UnboundPrefixLists::Reject,
    )
    .expect("compile context is valid");

    context
        .register_local_binding(variable, &ExpandedName::new(None::<String>, "value"))
        .expect("binding index fits the workspace");
    assert!(retained.get() > 0, "the live index must reserve workspace");
    drop(context);
    assert_eq!(retained.get(), 0, "dropping the index releases workspace");

    let constrained_retained = Cell::new(0usize);
    let constrained = CompileWorkspace {
        limit: 0,
        occupied: 0,
        retained: &constrained_retained,
    };
    let context = CompileContext::new(
        false,
        1,
        16,
        None,
        StylesheetDocumentId::PRINCIPAL,
        constrained,
        UnboundPrefixLists::Reject,
    )
    .expect("empty compile context fits");
    assert!(matches!(
        context.register_local_binding(variable, &ExpandedName::new(None::<String>, "value")),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
    assert_eq!(constrained_retained.get(), 0);
}

#[test]
fn include_and_import_select_the_referenced_embedded_stylesheet() {
    // XSLT 1.0 sections 2.6 and 2.7 make the fragment identify an embedded stylesheet;
    // fetching the containing XML resource must not compile its document element instead.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#embedded
    for instruction in ["include", "import"] {
        let principal = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:{instruction} href="module.xml#target"/></xsl:stylesheet>"#
        );
        let stylesheet = Compiler::new(
            Arc::new(FragmentModuleResolver {
                module: embedded_stylesheet_module(("other", "target")),
            }),
            CompileBudget::new(1 << 20, 4, 16, 1 << 20),
        )
        .compile(&principal, Some("memory:main.xsl"))
        .expect("fragment-targeted module compiles");

        assert!(
            stylesheet
                .named_template_index
                .contains_key(&ExpandedName::new(None::<String>, "selected"))
        );
        assert!(
            !stylesheet
                .named_template_index
                .contains_key(&ExpandedName::new(None::<String>, "ignored"))
        );
    }
}

#[test]
fn fragment_only_include_and_import_use_the_current_document() {
    // XSLT 1.0 sections 2.6 and 2.7 allow a fragment to select an embedded stylesheet
    // in the current resource without another resolver request.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#embedded
    for instruction in ["include", "import"] {
        let principal = format!(
            r##"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:ext="urn:ext"><xsl:{instruction} href="#target"/><ext:modules><xsl:stylesheet id="target" version="1.0"><xsl:template name="selected"/></xsl:stylesheet></ext:modules></xsl:stylesheet>"##
        );
        let stylesheet = Compiler::new(
            Arc::new(crate::NoResolver),
            CompileBudget::new(1 << 20, 4, 16, 1 << 20),
        )
        .compile(&principal, Some("memory:main.xsl"))
        .expect("fragment-only module compiles without a resolver");
        assert!(
            stylesheet
                .named_template_index
                .contains_key(&ExpandedName::new(None::<String>, "selected"))
        );
    }
}

#[test]
fn fragment_only_reference_inside_external_module_uses_its_document() {
    let principal = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:include href="module.xml#a"/></xsl:stylesheet>"#;
    let module = br##"<bundle xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:stylesheet id="a" version="1.0"><xsl:include href="#b"/></xsl:stylesheet><xsl:stylesheet id="b" version="1.0"><xsl:template name="selected"/></xsl:stylesheet></bundle>"##;
    let stylesheet = Compiler::new(
        Arc::new(FragmentModuleResolver {
            module: module.to_vec(),
        }),
        CompileBudget::new(1 << 20, 4, 16, 1 << 20),
    )
    .compile(principal, Some("memory:main.xsl"))
    .expect("fragment-only reference stays within the external module document");
    assert!(
        stylesheet
            .named_template_index
            .contains_key(&ExpandedName::new(None::<String>, "selected"))
    );
}

#[test]
fn fragment_only_module_uses_declared_id_in_principal_document() {
    // XML 1.0 section 3.3.1 gives the declared attribute ID semantics; the
    // frontend's attribute-name fallback must not be the only lookup path.
    let principal = r##"<!DOCTYPE xsl:stylesheet [
            <!ATTLIST xsl:stylesheet ext:module-key ID #IMPLIED>
        ]>
        <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:ext="urn:ext">
          <xsl:include href="#target"/>
          <ext:modules><xsl:stylesheet ext:module-key="target" version="1.0">
            <xsl:template name="selected"/>
          </xsl:stylesheet></ext:modules>
        </xsl:stylesheet>"##;
    let stylesheet = Compiler::new(
        Arc::new(crate::NoResolver),
        CompileBudget::new(1 << 20, 4, 16, 1 << 20),
    )
    .compile(principal, Some("memory:main.xsl"))
    .expect("DTD-declared ID selects a local embedded module");
    assert!(
        stylesheet
            .named_template_index
            .contains_key(&ExpandedName::new(None::<String>, "selected"))
    );
}

#[test]
fn fragment_only_modules_obey_cycle_and_import_limits() {
    let principal = r##"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:ext="urn:ext"><xsl:include href="#a"/><ext:modules><xsl:stylesheet id="a" version="1.0"><xsl:include href="#b"/></xsl:stylesheet><xsl:stylesheet id="b" version="1.0"><xsl:include href="#a"/></xsl:stylesheet></ext:modules></xsl:stylesheet>"##;
    let error = Compiler::new(
        Arc::new(crate::NoResolver),
        CompileBudget::new(1 << 20, 8, 16, 1 << 20),
    )
    .compile(principal, Some("memory:main.xsl"))
    .expect_err("local fragment cycle is rejected");
    assert!(error.to_string().contains("cycle"), "{error}");

    let error = Compiler::new(
        Arc::new(crate::NoResolver),
        CompileBudget::new(1 << 20, 1, 8, 1 << 20),
    )
    .compile(principal, Some("memory:main.xsl"))
    .expect_err("local fragment expansion obeys the module limit");
    assert!(
        matches!(
            error,
            Error::Budget {
                kind: BudgetKind::ImportedModules,
                ..
            }
        ),
        "{error}"
    );
}

#[test]
fn fragment_only_include_counts_once_across_compilation_phases() {
    let principal = r##"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:ext="urn:ext"><xsl:include href="#a"/><ext:modules><xsl:stylesheet id="a" version="1.0"><xsl:template name="selected"/></xsl:stylesheet></ext:modules></xsl:stylesheet>"##;
    Compiler::new(
        Arc::new(crate::NoResolver),
        CompileBudget::new(1 << 20, 1, 8, 1 << 20),
    )
    .compile(principal, Some("memory:main.xsl"))
    .expect("one local include counts as one module across both phases");
}

#[test]
fn embedded_modules_charge_only_additional_ir_copies() {
    // The source-document estimate already covers each embedded node once. A second
    // include retains another IR copy and must consume additional owned-byte budget.
    let templates = (0..32)
        .map(|index| format!(r#"<xsl:template match="item[{index}]"><out/></xsl:template>"#))
        .collect::<String>();
    let local = |includes: &str| {
        format!(
            r##"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:ext="urn:ext">{includes}<ext:modules><xsl:stylesheet id="target" version="1.0">{templates}</xsl:stylesheet></ext:modules></xsl:stylesheet>"##
        )
    };
    let one = local(r##"<xsl:include href="#target"/>"##);
    let two = local(r##"<xsl:include href="#target"/><xsl:include href="#target"/>"##);
    let baseline = local("");
    let min_baseline = minimum_owned_compile_budget(|limit| {
        Compiler::new(
            Arc::new(crate::NoResolver),
            CompileBudget::new(1 << 20, 4, 16, limit),
        )
        .compile(&baseline, Some("memory:main.xsl"))
    });
    let min_local = minimum_owned_compile_budget(|limit| {
        Compiler::new(
            Arc::new(crate::NoResolver),
            CompileBudget::new(1 << 20, 4, 16, limit),
        )
        .compile(&one, Some("memory:main.xsl"))
    });
    let min_repeated = minimum_owned_compile_budget(|limit| {
        Compiler::new(
            Arc::new(crate::NoResolver),
            CompileBudget::new(1 << 20, 4, 16, limit),
        )
        .compile(&two, Some("memory:main.xsl"))
    });
    let source = roxmltree::Document::parse(&one).expect("test stylesheet parses");
    let embedded = source
        .descendants()
        .find(|node| node.attribute("id") == Some("target"))
        .expect("embedded module exists");
    let additional_ir =
        estimate_compiled_owned_bytes_for_nodes(embedded.descendants(), Some("memory:main.xsl"));
    assert!(
        min_local - min_baseline < additional_ir / 2,
        "embedded include needs {min_local} owned bytes, unreferenced source needs {min_baseline}, IR estimate {additional_ir}"
    );
    assert!(
        min_repeated >= min_local + additional_ir / 2,
        "repeated include needs {min_repeated} owned bytes, first needs {min_local}, extra IR estimate {additional_ir}"
    );
}

fn minimum_owned_compile_budget(mut compile: impl FnMut(usize) -> Result<Stylesheet>) -> usize {
    let mut failing = 0;
    let mut passing = 1 << 20;
    compile(passing).expect("stylesheet compiles with ample owned-byte budget");
    while failing + 1 < passing {
        let limit = failing + (passing - failing) / 2;
        match compile(limit) {
            Ok(_) => passing = limit,
            Err(Error::Budget {
                kind: BudgetKind::OwnedBytes,
                ..
            }) => failing = limit,
            Err(error) => panic!("unexpected compilation error at budget {limit}: {error}"),
        }
    }
    passing
}

#[test]
fn embedded_stylesheet_cycles_are_keyed_by_selected_fragment() {
    // XSLT 1.0 section 2.7 permits multiple embedded stylesheet modules in one resource.
    // Distinct fragments may include each other, but returning to an active fragment is a
    // cycle. https://www.w3.org/TR/1999/REC-xslt-19991116#embedded
    let principal = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:include href="module.xml#a"/></xsl:stylesheet>"#;
    let acyclic = br#"<bundle xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:stylesheet id="a" version="1.0"><xsl:include href="module.xml#b"/><xsl:template name="a"/></xsl:stylesheet><xsl:stylesheet id="b" version="1.0"><xsl:template name="b"/></xsl:stylesheet></bundle>"#;
    let stylesheet = Compiler::new(
        Arc::new(FragmentModuleResolver {
            module: acyclic.to_vec(),
        }),
        CompileBudget::new(1 << 20, 4, 16, 1 << 20),
    )
    .compile(principal, Some("memory:main.xsl"))
    .expect("distinct embedded modules in one resource are acyclic");
    assert!(
        stylesheet
            .named_template_index
            .contains_key(&ExpandedName::new(None::<String>, "b"))
    );

    let cyclic = br#"<bundle xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:stylesheet id="a" version="1.0"><xsl:include href="module.xml#b"/></xsl:stylesheet><xsl:stylesheet id="b" version="1.0"><xsl:include href="module.xml#a"/></xsl:stylesheet></bundle>"#;
    let error = Compiler::new(
        Arc::new(FragmentModuleResolver {
            module: cyclic.to_vec(),
        }),
        CompileBudget::new(1 << 20, 4, 16, 1 << 20),
    )
    .compile(principal, Some("memory:main.xsl"))
    .expect_err("returning to the active embedded module is a cycle");
    assert!(matches!(error, Error::Static(message) if message.contains("cycle")));
}

#[test]
fn include_and_import_resolve_normalized_xml_id_fragments() {
    // xml:id 1.0 section 4 assigns ID type after ID whitespace normalization, so embedded
    // stylesheet lookup must not depend on an unqualified compatibility `id` attribute.
    // https://www.w3.org/TR/2005/REC-xml-id-20050909/#processing
    for instruction in ["include", "import"] {
        let principal = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:{instruction} href="module.xml#target"/></xsl:stylesheet>"#
        );
        let module = br#"<bundle xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:stylesheet xml:id="  target  " version="1.0"><xsl:template name="selected"/></xsl:stylesheet></bundle>"#.to_vec();
        let stylesheet = Compiler::new(
            Arc::new(FragmentModuleResolver { module }),
            CompileBudget::new(1 << 20, 4, 16, 1 << 20),
        )
        .compile(&principal, Some("memory:main.xsl"))
        .expect("normalized xml:id identifies the embedded stylesheet");

        assert!(
            stylesheet
                .named_template_index
                .contains_key(&ExpandedName::new(None::<String>, "selected"))
        );
    }
}

#[test]
fn include_and_import_resolve_dtd_declared_id_fragments() {
    // XML 1.0 section 3.3.1 assigns ID semantics through the declared attribute type,
    // independently of the attribute's lexical name. XPointer shorthand then selects the
    // element carrying that ID. https://www.w3.org/TR/xml/#id
    // https://www.w3.org/TR/2003/REC-xptr-framework-20030325/#shorthand
    for instruction in ["include", "import"] {
        let principal = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:{instruction} href="module.xml#target"/></xsl:stylesheet>"#
        );
        let module = br#"<!DOCTYPE bundle [
                <!ATTLIST xsl:stylesheet ext:module-key ID #IMPLIED>
            ]>
            <bundle xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                    xmlns:ext="urn:example:module-metadata">
                <xsl:stylesheet ext:module-key="target" version="1.0">
                    <xsl:template name="selected"/>
                </xsl:stylesheet>
            </bundle>"#
            .to_vec();
        let stylesheet = Compiler::new(
            Arc::new(FragmentModuleResolver { module }),
            CompileBudget::new(1 << 20, 4, 16, 1 << 20),
        )
        .compile(&principal, Some("memory:main.xsl"))
        .expect("a DTD-declared ID identifies the embedded stylesheet");

        assert!(
            stylesheet
                .named_template_index
                .contains_key(&ExpandedName::new(None::<String>, "selected"))
        );
    }
}

#[test]
fn include_and_import_decode_utf8_embedded_stylesheet_fragments() {
    // XPointer Framework appendix B encodes non-ASCII pointer characters as UTF-8 octets;
    // module selection must compare the decoded identifier.
    // https://www.w3.org/TR/2003/REC-xptr-framework-20030325/#escaping
    for instruction in ["include", "import"] {
        let principal = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:{instruction} href="module.xml#caf%C3%A9"/></xsl:stylesheet>"#
        );
        let stylesheet = Compiler::new(
            Arc::new(FragmentModuleResolver {
                module: embedded_stylesheet_module(("other", "café")),
            }),
            CompileBudget::new(1 << 20, 4, 16, 1 << 20),
        )
        .compile(&principal, Some("memory:main.xsl"))
        .expect("percent-encoded UTF-8 fragment selects the embedded stylesheet");

        assert!(
            stylesheet
                .named_template_index
                .contains_key(&ExpandedName::new(None::<String>, "selected"))
        );
    }
}

#[test]
fn stylesheet_module_fragments_reject_malformed_percent_encoding() {
    for (fragment, expected) in [
        ("truncated%", "truncated percent escape"),
        ("incomplete%C3%", "truncated percent escape"),
        ("invalid%GG", "invalid percent escape"),
        ("%FF", "not valid UTF-8"),
    ] {
        let principal = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:include href="module.xml#{fragment}"/></xsl:stylesheet>"#
        );
        let error = Compiler::new(
            Arc::new(FragmentModuleResolver {
                module: embedded_stylesheet_module(("other", "target")),
            }),
            CompileBudget::new(1 << 20, 4, 16, 1 << 20),
        )
        .compile(&principal, Some("memory:main.xsl"))
        .expect_err("malformed fragment must be rejected");
        assert!(
            error.to_string().contains(expected),
            "fragment {fragment:?} returned unexpected error: {error}"
        );
    }
}

#[test]
fn stylesheet_fragment_must_identify_one_unique_element() {
    let compile = |module, fragment| {
        Compiler::new(
            Arc::new(FragmentModuleResolver { module }),
            CompileBudget::new(1 << 20, 4, 16, 1 << 20),
        )
        .compile(
            &format!(
                r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:include href="module.xml#{fragment}"/></xsl:stylesheet>"#
            ),
            Some("memory:main.xsl"),
        )
    };

    assert!(matches!(
        compile(embedded_stylesheet_module(("other", "target")), "missing"),
        Err(Error::Static(message)) if message.contains("does not identify")
    ));
    assert!(matches!(
        compile(embedded_stylesheet_module(("same", "same")), "same"),
        Err(Error::Static(message)) if message.contains("not unique")
    ));
    assert!(matches!(
        compile(
            br#"<bundle xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:stylesheet id="same" version="1.0"/><xsl:stylesheet xml:id="same" version="1.0"/></bundle>"#.to_vec(),
            "same"
        ),
        Err(Error::Static(message)) if message.contains("not unique")
    ));
    assert!(matches!(
        compile(
            br#"<bundle><not-a-stylesheet id="target"/></bundle>"#.to_vec(),
            "target"
        ),
        Err(Error::Static(message)) if message.contains("does not identify xsl:stylesheet")
    ));
}

#[test]
fn frontend_workspace_accounts_for_every_parser_arena() {
    // roxmltree preallocates node and attribute vectors from lexical delimiters and retains
    // depth/namespace workspaces while parsing. The preflight must dominate all of them.
    let xml = r#"<root xmlns:p="urn:test" a="value"><p:child/></root>"#;
    let node_slots = xml.bytes().filter(|byte| *byte == b'<').count();
    let attribute_slots = xml.bytes().filter(|byte| *byte == b'=').count();
    let lexical_only = xml.len();
    let nodes_only = lexical_only.saturating_add(node_slots);
    let attributes_only = nodes_only.saturating_add(attribute_slots);

    assert!(parser_workspace_bytes(xml) > attributes_only);
}

#[test]
fn compiled_stylesheets_share_the_function_lookup_index() {
    // Function declarations are immutable compiled state; executions must not rebuild or clone
    // their lookup keys under the operation budget.
    let stylesheet = Compiler::new(
        Arc::new(crate::NoResolver),
        CompileBudget::new(1 << 20, 0, 32, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:func="http://exslt.org/functions" xmlns:f="urn:functions" extension-element-prefixes="func"><func:function name="f:value"><func:result select="'ok'"/></func:function></xsl:stylesheet>"#,
        None,
    )
    .expect("function stylesheet compiles");
    let cloned = stylesheet.clone();

    assert!(
        stylesheet
            .function_names
            .contains(&ExpandedName::new(Some("urn:functions"), "value"))
    );
    assert!(Arc::ptr_eq(
        &stylesheet.function_names,
        &cloned.function_names
    ));
}

#[test]
fn compiled_stylesheets_index_unique_keys_and_named_templates() {
    // Runtime dispatch must borrow declarations from immutable compiled state instead of
    // rebuilding owned name collections for every key() or xsl:call-template invocation.
    let stylesheet = Compiler::new(
        Arc::new(crate::NoResolver),
        CompileBudget::new(1 << 20, 0, 32, 1 << 20),
    )
    .compile(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:key name="a" match="a" use="."/><xsl:key name="a" match="b" use="."/><xsl:key name="b" match="b" use="."/><xsl:template name="target"/><xsl:template match="/"/></xsl:stylesheet>"#,
        None,
    )
    .expect("indexed stylesheet compiles");
    let cloned = stylesheet.clone();

    assert_eq!(stylesheet.key_name_indices.as_ref(), &[0, 2]);
    let target = ExpandedName::new(None::<String>, "target");
    assert_eq!(
        stylesheet.templates[*stylesheet
            .named_template_index
            .get(&target)
            .expect("named template is indexed")]
        .name
        .as_ref(),
        Some(&target)
    );
    assert!(Arc::ptr_eq(
        &stylesheet.named_template_index,
        &cloned.named_template_index
    ));
    assert!(Arc::ptr_eq(
        &stylesheet.key_name_indices,
        &cloned.key_name_indices
    ));
}

#[test]
fn expressions_on_one_node_share_their_namespace_snapshot() {
    // A literal result element can contain many AVTs. Sharing one immutable static namespace
    // context prevents retained memory from growing as expressions times namespaces.
    let source = r#"<root xmlns:p="urn:namespace"/>"#;
    let document = roxmltree::Document::parse(source).expect("stylesheet fragment parses");
    let root = document.root_element();
    let retained = Cell::new(0);
    let context = CompileContext::new(
        false,
        0,
        8,
        Some("memory:shared-base/"),
        StylesheetDocumentId::PRINCIPAL,
        CompileWorkspace {
            limit: 16_384,
            occupied: 0,
            retained: &retained,
        },
        UnboundPrefixLists::Reject,
    )
    .expect("context is valid");
    let first = context
        .expression("p:first", root)
        .expect("expression compiles");
    let second = context
        .expression("p:second", root)
        .expect("expression compiles");

    assert!(Arc::ptr_eq(&first.namespaces, &second.namespaces));
    assert!(Arc::ptr_eq(
        first
            .static_base_uri
            .as_ref()
            .expect("base URI is retained"),
        second
            .static_base_uri
            .as_ref()
            .expect("base URI is retained"),
    ));
}

#[test]
fn decoded_workspace_uses_live_string_capacity() {
    let mut decoded = String::with_capacity(4_096);
    decoded.push_str("<xsl:stylesheet/>");
    let capacity = decoded.capacity();

    let (decoded, workspace) = classify_decoded_workspace(Cow::Owned(decoded));
    assert_eq!(workspace, capacity);
    assert_eq!(decoded.as_ref(), "<xsl:stylesheet/>");

    let (decoded, workspace) = classify_decoded_workspace(Cow::Borrowed("<x/>"));
    assert_eq!(workspace, 0);
    assert_eq!(decoded.as_ref(), "<x/>");
}

#[test]
fn repeated_includes_charge_each_retained_declaration_expansion() {
    // XSLT 1.0 section 2.6.1 instantiates included declarations at every include point. A
    // cached source document therefore cannot make repeated compiled IR free.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#include
    let body = "x".repeat(32 * 1_024);
    let module = format!(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="item"><out>{body}</out></xsl:template></xsl:stylesheet>"#
    );
    let includes = r#"<xsl:include href="module.xsl"/>"#.repeat(32);
    let principal = format!(
        r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">{includes}</xsl:stylesheet>"#
    );
    let compiler = Compiler::new(
        Arc::new(RepeatedIncludeResolver {
            module: module.into_bytes(),
            encoding: Some("UTF-8".into()),
        }),
        CompileBudget::new(1 << 20, 64, 16, 768 * 1_024),
    );

    assert!(matches!(
        compiler.compile(&principal, Some("memory:main.xsl")),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
}

#[test]
fn imported_modules_apply_stylesheet_budget_after_decoding() {
    // A single-byte source encoding can expand in UTF-8. The compiled stylesheet budget
    // measures the decoded XML consumed by the parser, not only resolver wire bytes.
    let prefix = br#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><out>"#;
    let suffix = b"</out></xsl:template></xsl:stylesheet>";
    let mut module = Vec::from(prefix.as_slice());
    module.extend(std::iter::repeat_n(0xe9, 64));
    module.extend_from_slice(suffix);
    let principal = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:include href="module.xsl"/></xsl:stylesheet>"#;
    let raw_total = principal.len() + module.len();
    let compiler = Compiler::new(
        Arc::new(RepeatedIncludeResolver {
            module,
            encoding: Some("windows-1252".into()),
        }),
        CompileBudget::new(raw_total, 1, 4, usize::MAX),
    );

    assert!(matches!(
        compiler.compile(principal, Some("memory:main.xsl")),
        Err(Error::Budget {
            kind: BudgetKind::StylesheetBytes,
            limit,
            actual,
        }) if limit == raw_total && actual > limit
    ));
}

#[test]
fn frontend_workspace_is_rejected_before_parsing() {
    // A malformed input must still report the exhausted allocation gate first: the frontend
    // parser is not allowed to allocate merely to discover a later syntax error.
    let xml = "<stylesheet>";
    let required = parser_workspace_bytes(xml);
    let mut state = CompileState::new(CompileBudget::new(xml.len(), 0, 1, required - 1), xml.len());

    assert!(matches!(
        with_frontend_document(xml, &mut state, |_document, _state| Ok(())),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            actual,
            ..
        }) if actual == required
    ));
}

#[test]
fn frontend_workspace_preflights_internal_entity_expansion() {
    // The compiler must account for the entity-expanded source before constructing the
    // frontend DOM; otherwise a short lexical input can allocate far beyond owned_bytes.
    let replacement = "x".repeat(1_024);
    let references = "&payload;".repeat(64);
    let xml = format!(
        r#"<!DOCTYPE xsl:stylesheet [<!ENTITY payload "{replacement}">]><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><out>{references}</out></xsl:template></xsl:stylesheet>"#
    );
    let lexical_workspace = parser_workspace_bytes(&xml);
    let mut state = CompileState::new(
        CompileBudget::new(xml.len(), 0, 8, lexical_workspace + replacement.len()),
        xml.len(),
    );

    assert!(matches!(
        with_frontend_document(&xml, &mut state, |_document, _state| Ok(())),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
}

#[test]
fn semantic_projection_reserves_the_second_parser_workspace() {
    // The semantic parse overlaps retained compile state, so its transient arena must fit the
    // remaining peak budget rather than relying on the earlier frontend parse reservation.
    let xml = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"/></xsl:stylesheet>"#;
    let parsed = roxmltree::Document::parse(xml).expect("test stylesheet parses");
    let retained = xml
        .len()
        .saturating_add(estimate_compiled_owned_bytes(&parsed, None));
    let parser_workspace = parser_workspace_bytes(xml);
    let mut state = CompileState::new(
        CompileBudget::new(
            xml.len(),
            0,
            8,
            retained.saturating_add(parser_workspace).saturating_sub(1),
        ),
        xml.len(),
    );

    assert!(matches!(
        parse_semantic_document_metered(xml, None, &mut state),
        Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            ..
        })
    ));
}
