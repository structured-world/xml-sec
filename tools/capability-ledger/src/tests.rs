use super::*;

fn evidence() -> BTreeMap<String, Evidence> {
    BTreeMap::from([(
        "test".into(),
        Evidence {
            test: "capability_ledger::test".into(),
            description: "classification evidence".into(),
        },
    )])
}

fn rule(id: &str, kinds: &[&str], name_regex: Option<&str>) -> Rule {
    Rule {
        id: id.into(),
        kinds: kinds.iter().map(|kind| (*kind).into()).collect(),
        name_regex: name_regex.map(str::to_owned),
        source_regex: None,
        outcome: Outcome::Planned,
        rationale: "not implemented".into(),
        evidence: "test".into(),
    }
}

#[test]
fn behavior_evidence_requires_an_exact_test_declaration() {
    // A renamed test whose new name extends the old one, or a comment that
    // retains the old spelling, must not keep stale ledger evidence alive.
    let source = "// fn expected\n#[test]\nfn expected_for_case() {}\n";
    assert!(
        !contains_test_declaration(source, "expected").expect("test declaration matching must run")
    );
}

#[test]
fn behavior_evidence_finds_tests_after_rust_comments() {
    // Rust comments are item trivia and may legally separate an attribute
    // from the function to which it applies.
    let source =
        "#[test]\n// rationale\n/* more\n * /* nested */ rationale\n */\nfn expected() {}\n";
    assert!(
        contains_test_declaration(source, "expected").expect("test declaration matching must run")
    );
}

#[test]
fn behavior_evidence_ignores_test_syntax_inside_raw_strings() {
    let source = "const FIXTURE: &str = r#\"\n#[test]\nfn expected() {}\n\"#;\n";
    assert!(
        !contains_test_declaration(source, "expected").expect("test declaration matching must run")
    );
}

#[test]
fn behavior_evidence_rejects_disabled_or_conditional_tests() {
    for source in [
        "#[test]\n#[ignore]\nfn expected() {}\n",
        "#[test]\n#[should_panic]\nfn expected() {}\n",
        "#[test]\n#[cfg(any())]\nfn expected() {}\n",
        "#[test]\n#[cfg_attr(all(), ignore)]\nfn expected() {}\n",
    ] {
        assert!(
            !contains_test_declaration(source, "expected")
                .expect("test declaration matching must run"),
            "disabled or conditional test must not certify evidence: {source}"
        );
    }
}

#[test]
fn behavior_evidence_rejects_conditionally_compiled_source_files() {
    for source in [
        "#![cfg(feature = \"optional\")]\n#[test]\nfn expected() {}\n",
        "#![cfg_attr(all(), cfg(any()))]\n#[test]\nfn expected() {}\n",
    ] {
        assert!(
            !contains_test_declaration(source, "expected")
                .expect("test declaration matching must run"),
            "conditional source file must not certify evidence: {source}"
        );
    }
}

#[test]
fn behavior_evidence_allows_an_unconditional_source_file() {
    let source = "#![allow(dead_code)]\n#[test]\nfn expected() {}\n";
    assert!(
        contains_test_declaration(source, "expected").expect("test declaration matching must run")
    );
}

#[test]
fn behavior_evidence_finds_unconditional_tests_in_nested_modules() {
    let source = "mod nested {\n    #[test]\n    fn expected() {}\n}\n";
    assert!(
        contains_test_declaration(source, "expected").expect("test declaration matching must run")
    );
}

#[test]
fn behavior_evidence_rejects_ambiguous_test_names() {
    // A stale assertion must not be kept alive by an unrelated test with
    // the same leaf name in a different module.
    let source = "mod first {\n    #[test]\n    fn expected() {}\n}\n\
                      mod second {\n    #[test]\n    fn expected() {}\n}\n";
    assert!(
        !contains_test_declaration(source, "expected").expect("test declaration matching must run")
    );
}

#[test]
fn behavior_evidence_rejects_tests_in_conditional_modules() {
    for module_attribute in [
        "#[cfg(feature = \"optional\")]",
        "#[cfg(any())]",
        "#[cfg_attr(all(), cfg(any()))]",
    ] {
        let source =
            format!("{module_attribute}\nmod nested {{\n    #[test]\n    fn expected() {{}}\n}}\n");
        assert!(
            !contains_test_declaration(&source, "expected")
                .expect("test declaration matching must run"),
            "conditional module must not certify evidence: {source}"
        );
    }
}

#[test]
fn behavior_evidence_allows_the_test_harness_module_condition() {
    let source = "#[cfg(test)]\nmod tests {\n    #[test]\n    fn expected() {}\n}\n";
    assert!(
        contains_test_declaration(source, "expected").expect("test declaration matching must run")
    );
}

#[test]
fn behavior_evidence_rejects_an_exact_duplicate_assertion() {
    let assertion = BehaviorTest {
        file: "tests/behavioral_compatibility.rs".into(),
        test: "c_boundary_behaviors_are_explicitly_planned".into(),
        description: "same assertion".into(),
    };
    let evidence = BTreeMap::from([(
        "duplicate".into(),
        BehaviorEvidence {
            positive: vec![assertion.clone()],
            negative: vec![assertion],
        },
    )]);

    let error = validate_behavior_evidence(&evidence)
        .expect_err("identical assertions must not represent both outcomes");
    assert!(error.contains("duplicate"), "{error}");
}

#[test]
fn behavior_evidence_rejects_duplicates_within_each_polarity() {
    let positive = BehaviorTest {
        file: "src/tests.rs".into(),
        test: "behavior_evidence_rejects_duplicates_within_each_polarity".into(),
        description: "positive assertion".into(),
    };
    let negative = BehaviorTest {
        file: "src/tests.rs".into(),
        test: "behavior_evidence_allows_paired_assertions_from_one_test".into(),
        description: "negative assertion".into(),
    };

    for (duplicate_positive, duplicate_negative) in [(true, false), (false, true)] {
        let evidence = BTreeMap::from([(
            "duplicate-polarity".into(),
            BehaviorEvidence {
                positive: if duplicate_positive {
                    vec![positive.clone(), positive.clone()]
                } else {
                    vec![positive.clone()]
                },
                negative: if duplicate_negative {
                    vec![negative.clone(), negative.clone()]
                } else {
                    vec![negative.clone()]
                },
            },
        )]);

        let error = validate_behavior_evidence(&evidence)
            .expect_err("one polarity must not repeat an identical assertion");
        assert!(error.contains("duplicate"), "{error}");
    }
}

#[test]
fn behavior_evidence_allows_paired_assertions_from_one_test() {
    let assertion = BehaviorTest {
        file: "src/tests.rs".into(),
        test: "behavior_evidence_allows_paired_assertions_from_one_test".into(),
        description: "acceptance outcome".into(),
    };
    let evidence = BTreeMap::from([(
        "differential".into(),
        BehaviorEvidence {
            positive: vec![assertion.clone()],
            negative: vec![BehaviorTest {
                description: "rejection outcome".into(),
                ..assertion
            }],
        },
    )]);

    validate_behavior_evidence(&evidence)
        .expect("one differential test may prove distinct paired assertions");
}

#[test]
fn behavior_evidence_rejects_unreferenced_entries() {
    let evidence = BTreeMap::from([(
        "orphan".into(),
        BehaviorEvidence {
            positive: Vec::new(),
            negative: Vec::new(),
        },
    )]);
    let referenced = BTreeSet::new();

    let error = validate_behavior_evidence_references(&evidence, &referenced)
        .expect_err("orphan evidence must not reach the generated ledger");
    assert!(error.contains("orphan"), "{error}");
}

#[test]
fn resolves_adjacent_literals_and_upstream_prefix_macros() {
    // Experimental 1.3.13 URIs concatenate a private namespace macro and suffix.
    let macros = BTreeMap::from([(
        "XMLSEC_EXPERIMENTAL".into(),
        "https://example.test/algorithms#".into(),
    )]);
    assert_eq!(
        resolve_c_string_expression(r#"XMLSEC_EXPERIMENTAL "ml-dsa" "-44""#, &macros)
            .expect("expression must resolve"),
        "https://example.test/algorithms#ml-dsa-44"
    );
}

#[test]
fn rejects_unresolved_uri_macros() {
    // Silent macro loss would omit the newest upstream algorithm families.
    let error = resolve_c_string_expression("XMLSEC_UNKNOWN \"suffix\"", &BTreeMap::new())
        .expect_err("unknown macro must fail");
    assert!(error.contains("XMLSEC_UNKNOWN"));
}

#[test]
fn rejects_unparsed_uri_expression_tokens() {
    // A partially parsed expression would publish a truncated URI as donor truth.
    let macros = BTreeMap::from([("XMLSEC_PREFIX".into(), "urn:test:".into())]);
    for expression in [
        "XMLSEC_PREFIX lowercase \"suffix\"",
        "XMLSEC_PREFIX \"suffix\" trailing",
    ] {
        let error = resolve_c_string_expression(expression, &macros)
            .expect_err("every expression byte must be recognized");
        assert!(error.contains("unparsed"), "{error}");
    }
}

#[test]
fn installed_header_assignment_stops_without_a_continuation() {
    // A later distribution entry must not become a public header accidentally.
    let content = "inc_HEADERS = public.h\nEXTRA_DIST = private.h\n";
    let mut headers = BTreeSet::new();
    collect_installed_headers(content, Path::new("backend"), &mut headers);
    assert_eq!(
        headers,
        BTreeSet::from(["include/xmlsec/backend/public.h".into()])
    );
}

#[test]
fn cli_exit_statuses_are_derived_from_donor_control_flow() {
    // Evidence lines must follow the donor statements instead of generator constants.
    let content = r"int main(void) {
    int res = 1;
    if(command == xmlSecAppCommandUnknown) {
        xmlSecAppPrintUsage();
        res = 0;
        goto done;
    }
    /* sucecss! */
    res = 0;
done:
    return(res);
}";
    let entries = extract_cli_exit_statuses(content).expect("fixture must be recognized");
    assert_eq!(
        entries
            .iter()
            .map(|entry| (entry.name.as_str(), entry.line, entry.exit_code))
            .collect::<Vec<_>>(),
        vec![
            ("success", 9, Some(0)),
            ("unknown-command", 5, Some(0)),
            ("failure", 2, Some(1)),
        ]
    );

    let error = extract_cli_exit_statuses(&content.replace("/* sucecss! */", "/* done */"))
        .expect_err("missing semantic marker must fail closed");
    assert!(error.contains("success"), "{error}");
}

#[test]
fn required_test_runners_fail_closed() {
    // A renamed donor runner must disappear only through an explicit baseline update.
    let directory = env::temp_dir().join(format!(
        "xml-sec-ledger-runner-drift-{}",
        std::process::id()
    ));
    if directory.exists() {
        fs::remove_dir_all(&directory).expect("stale runner fixture must be removable");
    }
    fs::create_dir_all(&directory).expect("runner fixture must be creatable");
    for script in ["testDSig.sh", "testEnc.sh", "testKeys.sh"] {
        fs::write(directory.join(script), "#!/bin/sh\n").expect("runner fixture must be writable");
    }
    let error =
        required_test_runner_items(&directory).expect_err("a missing required runner must fail");
    assert!(error.contains("testRes.sh"), "{error}");
    fs::remove_dir_all(directory).expect("runner fixture must be removable");
}

#[test]
fn first_matching_rule_wins() {
    // Ordered rules allow a precise supported subset before a planned fallback.
    let ledger = classify(
        vec![
            item(
                "algorithm-uri",
                "supported",
                "strings.c",
                1,
                "urn:supported",
            ),
            item("algorithm-uri", "future", "strings.c", 2, "urn:future"),
        ],
        RulesFile {
            schema_version: 1,
            evidence: evidence(),
            rules: vec![
                rule("supported", &["algorithm-uri"], Some("^supported$")),
                rule("fallback", &["algorithm-uri"], None),
            ],
        },
    )
    .expect("both ordered rules must classify at least one item");
    assert_eq!(ledger.items[0].classification, "supported");
    assert_eq!(ledger.items[1].classification, "fallback");
    assert_eq!(ledger.classifications.len(), 2);
}

#[test]
fn rejects_items_without_a_classification() {
    // New upstream categories cannot disappear from the generated baseline.
    let error = classify(
        vec![item("new-kind", "new-item", "new.h", 1, "new")],
        RulesFile {
            schema_version: 1,
            evidence: evidence(),
            rules: vec![rule("headers", &["header"], None)],
        },
    )
    .expect_err("unclassified item must fail");
    assert!(error.contains("matched no classification rule"));
}

#[test]
fn rejects_rules_that_no_longer_match_upstream() {
    // Stale allowlist entries must be reviewed instead of silently surviving upgrades.
    let error = classify(
        vec![item("header", "current.h", "current.h", 1, "header")],
        RulesFile {
            schema_version: 1,
            evidence: evidence(),
            rules: vec![
                rule("current", &["header"], None),
                rule("removed", &["algorithm-uri"], None),
            ],
        },
    )
    .expect_err("unused rule must fail");
    assert!(error.contains("removed"));
}

#[test]
fn export_parser_ignores_return_type_and_calling_convention() {
    // Exported symbol identity comes from the declarator, not macro-like prefixes.
    assert_eq!(
        exported_name("XMLSEC_EXPORT int XMLSEC_CALL xmlSecInit(void);").as_deref(),
        Some("xmlSecInit")
    );
    assert_eq!(
        exported_name("XMLSEC_EXPORT_VAR const xmlChar xmlSecNameId[];").as_deref(),
        Some("xmlSecNameId")
    );
}

#[test]
fn export_parser_selects_the_outer_function_declarator() {
    // Nested callback types and trailing annotations are not exported symbols.
    assert_eq!(
        exported_name("XMLSEC_EXPORT int XMLSEC_CALL xmlSecRegister(int (*callback)(void *ctx));")
            .as_deref(),
        Some("xmlSecRegister")
    );
    assert_eq!(
        exported_name("XMLSEC_EXPORT int XMLSEC_CALL xmlSecInit(void) XMLSEC_API(1);").as_deref(),
        Some("xmlSecInit")
    );
    assert_eq!(
        exported_name("XMLSEC_DEPRECATED(1) XMLSEC_EXPORT int XMLSEC_CALL xmlSecInit(void);")
            .as_deref(),
        Some("xmlSecInit")
    );
}

#[test]
fn declaration_collector_ignores_semicolons_in_comments_and_literals() {
    // Documentation entities and examples must not truncate a public declaration.
    let lines = [
        "typedef enum {",
        "    value = 0, /* compares as value &lt; limit; */",
        "    other = 1 /* example: \"done;\" */",
        "} xmlSecExample;",
    ];
    let (declaration, end) = collect_declaration(&lines, 0).expect("enum must parse");
    assert_eq!(end, 3);
    assert!(declaration.contains("xmlSecExample;"));
}

#[test]
fn macro_collector_preserves_the_complete_definition() {
    // A continuation-body change must produce a generated ledger diff.
    let lines = [
        "#define xmlSecAssert(condition) \\",
        "    do { \\",
        "        check(condition); \\",
        "    } while(0)",
        "#define xmlSecNext 1",
    ];
    let (definition, end) = collect_macro_definition(&lines, 0);
    assert_eq!(end, 3);
    assert!(definition.contains("check(condition)"));
    assert!(!definition.contains("xmlSecNext"));
}

#[test]
fn typedef_parser_extracts_public_alias_declarators() {
    // Scalar, pointer, and inline-layout aliases are separate public C names.
    assert_eq!(
        typedef_aliases("typedef size_t xmlSecSize;"),
        vec!["xmlSecSize"]
    );
    assert_eq!(
        typedef_aliases("typedef struct _xmlSecKey xmlSecKey, *xmlSecKeyPtr;"),
        vec!["xmlSecKey", "xmlSecKeyPtr"]
    );
    assert_eq!(
        typedef_aliases("typedef struct { int member; } xmlSecInline, *xmlSecInlinePtr;"),
        vec!["xmlSecInline", "xmlSecInlinePtr"]
    );
}

#[test]
fn build_define_parser_only_accepts_compiler_definitions() {
    // Configure shell variables are not part of the public preprocessor surface,
    // while every XMLSEC_* compiler token is part of the donor build contract.
    let content = r#"XMLSEC_CRYPTO_CFLAGS=\"-I/example\"
XMLSEC_CRYPTO_DISABLED_LIST=\"openssl\"
CFLAGS=\"$CFLAGS -DXMLSEC_NO_DES -DXMLSEC_CRYPTO_OPENSSL=1\"
XMLSEC_DEFINES=\"$XMLSEC_DEFINES -DXMLSEC_STATIC=1 -DXMLSEC_DL_LIBLTDL=1\"
OPENSSL_CFLAGS=\"$OPENSSL_CFLAGS -DXMLSEC_OPENSSL3_ENGINES=1\"
MSCRYPTO_CFLAGS=\"$MSCRYPTO_CFLAGS -DXMLSEC_CUSTOM_CRYPT32=1\""#;
    let entries = extract_build_defines_from_content(content);
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        vec![
            "XMLSEC_NO_DES",
            "XMLSEC_CRYPTO_OPENSSL",
            "XMLSEC_STATIC",
            "XMLSEC_DL_LIBLTDL",
            "XMLSEC_OPENSSL3_ENGINES",
            "XMLSEC_CUSTOM_CRYPT32",
        ]
    );
}

#[test]
fn normalization_preserves_c_literal_bytes() {
    // Whitespace trivia may collapse, but bytes inside C literals are semantic.
    assert_eq!(
        normalize_c("#define VALUE   \" \"\n  \"  \"").unwrap(),
        "#define VALUE \" \" \"  \""
    );
    assert_ne!(
        normalize_c("#define VALUE \" \"").unwrap(),
        normalize_c("#define VALUE \"  \"").unwrap()
    );
}

#[test]
fn c_normalization_removes_comments_but_preserves_literal_markers() {
    // Donor comments are trivia, while identical bytes inside literals are public data.
    assert_eq!(
        normalize_c(
            "int value /* owner's note */ = call(\"/*kept*/\", '//'); // tail \\\ndiscarded\n;"
        )
        .unwrap(),
        "int value = call(\"/*kept*/\", '//'); ;"
    );
}

#[test]
fn c_normalization_rejects_unterminated_lexical_states() {
    // Truncated donor input must fail generation rather than enter the baseline.
    for malformed in ["int x; /*", "const char *x = \"unterminated", "int x = '"] {
        assert!(normalize_c(malformed).is_err(), "{malformed:?}");
    }
}

#[test]
fn preprocessor_conditions_preserve_nested_branch_history() {
    // Availability evidence includes both the selected branch and alternatives passed over.
    let conditions = preprocessor_conditions(
            "#ifdef XMLSEC_FEATURE\n#if XMLSEC_BACKEND\nint first;\n#elif XMLSEC_FALLBACK\nint second;\n#else\nint third;\n#endif\n#endif\n",
        )
        .expect("balanced conditions must parse");
    assert_eq!(
        conditions[2],
        ["#ifdef XMLSEC_FEATURE", "#if XMLSEC_BACKEND"]
    );
    assert_eq!(
        conditions[4],
        [
            "#ifdef XMLSEC_FEATURE",
            "#if XMLSEC_BACKEND",
            "#elif XMLSEC_FALLBACK",
        ]
    );
    assert_eq!(
        conditions[6],
        [
            "#ifdef XMLSEC_FEATURE",
            "#if XMLSEC_BACKEND",
            "#elif XMLSEC_FALLBACK",
            "#else",
        ]
    );
}

#[test]
fn preprocessor_conditions_reject_malformed_branching() {
    // A damaged donor guard stack must fail generation instead of losing availability data.
    for malformed in ["#else\n", "#if A\n#else\n#elif B\n#endif\n", "#if A\n"] {
        assert!(preprocessor_conditions(malformed).is_err(), "{malformed:?}");
    }
}

#[test]
fn availability_spans_normalize_repeated_item_conditions() {
    // One source span replaces repeated per-item arrays without covering unguarded entries.
    let mut guarded_a = item("macro", "A", "public.h", 10, "A");
    guarded_a.conditions = vec!["#ifndef XMLSEC_NO_A".into()];
    let mut guarded_b = item("macro", "B", "public.h", 20, "B");
    guarded_b.conditions = guarded_a.conditions.clone();
    let unguarded = item("macro", "C", "public.h", 30, "C");
    let mut guarded_d = item("macro", "D", "public.h", 40, "D");
    guarded_d.conditions = guarded_a.conditions.clone();

    let spans = availability_spans(&[guarded_a, guarded_b, unguarded, guarded_d])
        .expect("consistent item conditions must normalize");
    assert_eq!(spans.len(), 2);
    assert_eq!((spans[0].start_line, spans[0].end_line), (10, 20));
    assert_eq!((spans[1].start_line, spans[1].end_line), (40, 40));
}

#[test]
fn cli_option_parser_preserves_the_typed_option_contract() {
    // Name, aliases, help syntax, topic, type, and flags must drift together.
    let content = r#"static xmlSecAppCmdLineParam outputParam = {
    xmlSecAppCmdLineTopicAll,
    "--output",
    "-o",
    "--output <filename>\n\twrite result to file",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};"#;
    let options = extract_cli_options_from_content(content).expect("option must parse");
    assert_eq!(options.len(), 1);
    assert_eq!(options[0].name, "--output");
    assert!(options[0].detail.contains("\"-o\""));
    assert!(options[0].detail.contains("<filename>"));
    assert!(
        options[0]
            .detail
            .contains("xmlSecAppCmdLineParamTypeString")
    );
}

#[test]
fn deduplication_preserves_conditional_macro_variants() {
    // Alternative preprocessor branches are separate donor surface locations.
    let entries = deduplicate_surface(vec![
        item("macro", "XMLSEC_EXPORT", "exports.h", 41, "dllexport"),
        item("macro", "XMLSEC_EXPORT", "exports.h", 48, "dllimport"),
    ]);
    assert_eq!(entries.len(), 2);
}

#[test]
fn registry_predicate_covers_lifecycle_lookup_and_registration() {
    // Registry compatibility includes the complete public ID-list lifecycle.
    for name in [
        "xmlSecKeyDataIdsGet",
        "xmlSecKeyDataIdsGetEnabled",
        "xmlSecKeyDataIdsInit",
        "xmlSecKeyDataIdsShutdown",
        "xmlSecKeyDataIdsRegisterDefault",
        "xmlSecKeyDataIdsRegister",
        "xmlSecKeyDataIdsRegisterDisabled",
        "xmlSecTransformIdsGet",
        "xmlSecTransformIdsInit",
        "xmlSecTransformIdsShutdown",
        "xmlSecTransformIdsRegisterDefault",
        "xmlSecTransformIdsRegister",
        "xmlSecIORegisterCallbacks",
    ] {
        assert!(is_registry_api(name), "{name}");
    }
    assert!(!is_registry_api("xmlSecTransformGetName"));
}

#[test]
fn class_id_detection_uses_the_complete_macro_definition() {
    // Backend class IDs commonly put GetKlass() on a continuation line.
    assert!(is_class_id_macro(
        "xmlSecGCryptTransformAes128CbcId",
        "#define xmlSecGCryptTransformAes128CbcId \\\n             xmlSecGCryptTransformAes128CbcGetKlass()"
    ));
    assert!(is_class_id_macro(
        "xmlSecTransformAes128CbcId",
        "#define xmlSecTransformAes128CbcId xmlSecGCryptTransformAes128CbcId"
    ));
    assert!(!is_class_id_macro(
        "xmlSecKeyCheckId",
        "#define xmlSecKeyCheckId(key, keyId) ((key)->id == (keyId))"
    ));
}

#[test]
fn configured_header_substitutes_pinned_version_values() {
    // Installed header details must represent configure output, not @...@ tokens.
    let configure = r#"AC_INIT([xmlsec1],[1.3.13],[https://example.invalid])
XMLSEC_VERSION_MAJOR=$(echo $PACKAGE_VERSION | cut -d. -f1)
XMLSEC_VERSION_MINOR=$(echo $PACKAGE_VERSION | cut -d. -f2)
XMLSEC_VERSION_SUBMINOR=$(echo $PACKAGE_VERSION | cut -d. -f3)
XMLSEC_VERSION="$PACKAGE_VERSION"
XMLSEC_VERSION_CURRENT=$((10000 * XMLSEC_VERSION_MAJOR + 100 * XMLSEC_VERSION_MINOR + XMLSEC_VERSION_SUBMINOR))
XMLSEC_VERSION_INFO="${XMLSEC_VERSION_CURRENT}:0:0""#;
    let rendered = render_configured_header(
            "#define XMLSEC_VERSION \"@XMLSEC_VERSION@\"\n#define XMLSEC_VERSION_INFO \"@XMLSEC_VERSION_INFO@\"\n",
            configure,
        )
        .expect("known substitutions must render");
    assert!(rendered.contains("\"1.3.13\""));
    assert!(rendered.contains("\"10313:0:0\""));

    let error = render_configured_header("@UNKNOWN_VALUE@", configure)
        .expect_err("unknown substitutions must fail closed");
    assert!(error.contains("UNKNOWN_VALUE"), "{error}");
}

#[test]
fn donor_snapshot_ignores_tracked_and_generated_worktree_changes() {
    // Extraction is commit-based: configure/build output and local edits in
    // the caller's checkout must neither contaminate nor block the ledger.
    let directory =
        env::temp_dir().join(format!("xml-sec-ledger-dirty-donor-{}", std::process::id()));
    if directory.exists() {
        fs::remove_dir_all(&directory).expect("stale donor fixture must be removable");
    }
    fs::create_dir_all(&directory).expect("fixture must be creatable");
    fs::write(directory.join("tracked.h"), "original\n").expect("fixture must be writable");
    fs::write(directory.join(".gitignore"), "generated/\n")
        .expect("ignore fixture must be writable");
    assert!(
        Command::new("git")
            .arg("init")
            .arg(&directory)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .args([
                "-C",
                directory.to_str().unwrap(),
                "add",
                ".gitignore",
                "tracked.h"
            ])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .args([
                "-c",
                "user.name=Capability Ledger Test",
                "-c",
                "user.email=ledger@example.invalid",
                "-C",
                directory.to_str().unwrap(),
                "commit",
                "-m",
                "test fixture"
            ])
            .status()
            .unwrap()
            .success()
    );
    fs::create_dir_all(directory.join("generated")).expect("ignored fixture must be creatable");
    fs::write(directory.join("generated/header.h"), "generated\n")
        .expect("ignored fixture must be writable");
    fs::write(directory.join("tracked.h"), "modified\n").expect("fixture must be writable");
    let commit = Command::new("git")
        .args(["-C", directory.to_str().unwrap(), "rev-parse", "HEAD"])
        .output()
        .unwrap();
    let commit = String::from_utf8(commit.stdout).unwrap();
    let snapshot = snapshot_donor(&directory, commit.trim())
        .expect("dirty caller checkout must produce an immutable commit snapshot");
    assert_eq!(
        fs::read_to_string(snapshot.path().join("tracked.h")).unwrap(),
        "original\n"
    );
    assert!(!snapshot.path().join("generated").exists());
    assert_eq!(
        fs::read_to_string(directory.join("tracked.h")).unwrap(),
        "modified\n"
    );
    assert!(directory.join("generated/header.h").exists());
    fs::remove_dir_all(directory).expect("donor fixture must be removable");
}

#[test]
fn donor_clone_terminates_options_before_caller_paths() {
    // Caller-controlled paths must follow `--` so a leading dash cannot become a Git option.
    let command = donor_clone_command(Path::new("-donor"), Path::new("snapshot"));
    let args: Vec<_> = command
        .get_args()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect();

    assert_eq!(
        args,
        [
            "clone",
            "--quiet",
            "--no-checkout",
            "--",
            "-donor",
            "snapshot"
        ]
    );
}

#[test]
fn rejects_a_different_donor_commit() {
    // A version-shaped checkout at another Git object must not regenerate the baseline.
    let directory =
        env::temp_dir().join(format!("xml-sec-ledger-donor-drift-{}", std::process::id()));
    if directory.exists() {
        fs::remove_dir_all(&directory).expect("stale donor test directory must be removable");
    }
    fs::create_dir_all(&directory).expect("donor test directory must be creatable");
    fs::write(
        directory.join("configure.ac"),
        "AC_INIT([xmlsec1],[1.3.13])\n",
    )
    .expect("donor version fixture must be writable");
    assert!(
        Command::new("git")
            .arg("init")
            .arg(&directory)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .args(["-C", directory.to_str().unwrap(), "add", "configure.ac"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .args([
                "-c",
                "user.name=Capability Ledger Test",
                "-c",
                "user.email=ledger@example.invalid",
                "-C",
                directory.to_str().unwrap(),
                "commit",
                "-m",
                "test fixture",
            ])
            .status()
            .unwrap()
            .success()
    );

    let error = verify_donor(&directory).expect_err("different donor commit must fail");
    assert!(error.contains("revision mismatch"));
    fs::remove_dir_all(directory).expect("donor test directory must be removable");
}
