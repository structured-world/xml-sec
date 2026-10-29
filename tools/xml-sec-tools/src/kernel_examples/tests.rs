use super::{declares_main, extract, render};

#[test]
fn examples_keep_hidden_lines_and_compile_only_semantics() {
    // Hidden `# ` lines are part of the program; `no_run` stays compile-only,
    // and a non-Rust fence is neither rewritten nor extracted.
    let input = "/// ```\n/// # let a = 2;\n/// assert_eq!(a, 2);\n/// ```\n/// ```text\n/// not Rust\n/// ```\n/// ```no_run\n/// unreachable!();\n/// ```\n";
    let (rewritten, examples) = extract(input, "sample.rs").unwrap();
    assert_eq!(examples.len(), 2);
    assert_eq!(examples[0].body, "let a = 2;\nassert_eq!(a, 2);");
    assert!(!examples[0].no_run);
    assert!(examples[1].no_run);
    assert!(rewritten.starts_with("/// ```text,xml-sec-example\n"));
    // Importing an already imported source changes nothing.
    let (again, roundtrip) = extract(&rewritten, "sample.rs").unwrap();
    assert_eq!(again, rewritten);
    assert_eq!(roundtrip, examples);
}

#[test]
fn documented_item_cfg_gates_only_its_own_examples() {
    // An example of a `std`-only item must not compile where the item is absent,
    // and the gate must not leak to the next documented item.
    let input = "/// ```\n/// f();\n/// ```\n#[cfg(feature = \"std\")]\n#[must_use]\npub fn f() {}\n/// ```\n/// g();\n/// ```\npub fn g() {}\n";
    let (_, examples) = extract(input, "gated.rs").unwrap();
    assert_eq!(examples[0].cfgs, ["cfg(feature = \"std\")"]);
    assert_eq!(examples[1].cfgs, Vec::<String>::new());
    let tests = render("xmloxide", &[("gated.rs".into(), examples)]).unwrap();
    assert!(tests.contains("#[cfg(feature = \"std\")]\n#[test]\nfn gated_rs_example_1()"));
    assert!(tests.contains("\n#[test]\nfn gated_rs_example_2()"));
}

#[test]
fn malformed_documentation_is_rejected_with_its_location() {
    for (input, error) in [
        ("/// ```\n/// x\n", "f.rs: unclosed documentation fence"),
        (
            "/// ```\nfn x() {}\n",
            "f.rs:2: documentation fence escaped its comment",
        ),
        (
            "/// ```\n/// ```rust\n",
            "f.rs:2: unterminated documentation fence",
        ),
        (
            "/// ```ignore\n/// ```\n",
            "f.rs:1: unsupported executable example ignore",
        ),
        (
            "/// ```\n/// fn main() {}\n/// ```\n",
            "f.rs:2: explicit main needs a harness adapter",
        ),
    ] {
        assert_eq!(extract(input, "f.rs").unwrap_err(), error, "{input:?}");
    }
}

#[test]
fn only_a_main_function_declaration_needs_an_adapter() {
    assert!(declares_main("fn main() {"));
    assert!(declares_main("pub fn  main ()"));
    assert!(!declares_main("fn mainline()"));
    assert!(!declares_main("defn main()"));
    assert!(!declares_main("fnmain()"));
}
