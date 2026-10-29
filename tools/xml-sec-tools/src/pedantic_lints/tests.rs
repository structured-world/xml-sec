use super::{Clippy, EXEMPT, forbidden_lints, list_problems, parse_lint_help, suppressions};
use crate::test_support::read;
use std::collections::BTreeSet;
use std::process::Command;

fn help(pedantic: &[&str], others: &[&str]) -> String {
    let mut lines: Vec<String> = pedantic
        .iter()
        .chain(others)
        .map(|name| {
            format!(
                "   clippy::{}  allow    some meaning",
                name.replace('_', "-")
            )
        })
        .collect();
    let members: Vec<String> = pedantic
        .iter()
        .map(|name| format!("clippy::{}", name.replace('_', "-")))
        .collect();
    lines.push(format!("clippy::pedantic  {}", members.join(", ")));
    lines.join("\n")
}

fn toolchain(name: &str, pedantic: &[&str], others: &[&str]) -> Clippy {
    parse_lint_help(name, &help(pedantic, others)).unwrap()
}

fn set(lints: &[&str]) -> BTreeSet<String> {
    lints.iter().map(|&lint| lint.to_owned()).collect()
}

#[test]
fn clippy_lint_help_yields_the_pedantic_group_and_every_known_lint() {
    // Both sets drive the comparison; dashes and the `clippy::` path are normalized.
    let parsed = toolchain("t", &["similar_names", "cast_lossless"], &["unwrap_used"]);
    assert_eq!(parsed.pedantic, set(&["cast_lossless", "similar_names"]));
    assert_eq!(
        parsed.known,
        set(&["cast_lossless", "similar_names", "unwrap_used"])
    );
    assert!(
        parse_lint_help("t", "no groups here")
            .unwrap_err()
            .contains("no pedantic group")
    );
}

#[test]
fn the_manifest_table_yields_only_forbidden_clippy_lints() {
    // Other levels and other tables do not count as forbidden.
    let forbidden = forbidden_lints(
        "[workspace.lints.clippy]\npedantic = { level = \"warn\", priority = -1 }\na_lint = \"forbid\"\nb_lint = \"deny\"\n[profile.dev]\nc_lint = \"forbid\"\n",
    )
    .unwrap();
    assert_eq!(forbidden, set(&["a_lint"]));
    assert!(
        forbidden_lints(&read("Cargo.toml"))
            .unwrap()
            .contains("similar_names")
    );
}

#[test]
fn a_pedantic_lint_missing_from_the_forbid_list_is_reported() {
    // A new pedantic lint known to every toolchain must be forbidden or exempt.
    let toolchains = [
        toolchain("old", &["a", "b"], &[]),
        toolchain("new", &["a", "b"], &[]),
    ];
    assert_eq!(
        list_problems(&set(&["a"]), &toolchains),
        [
            "pedantic b of clippy old is neither forbidden nor exempt",
            "pedantic b of clippy new is neither forbidden nor exempt"
        ]
    );
}

#[test]
fn a_lint_one_toolchain_does_not_know_is_neither_required_nor_allowed() {
    // Listing it would fail that toolchain's lint run as an unknown lint.
    let toolchains = [
        toolchain("old", &["a", "renamed"], &[]),
        toolchain("new", &["a", "added"], &[]),
    ];
    assert_eq!(
        list_problems(&set(&["a"]), &toolchains),
        Vec::<String>::new()
    );
    assert_eq!(
        list_problems(&set(&["a", "added"]), &toolchains),
        ["added is forbidden but unknown to clippy old"]
    );
}

#[test]
fn exempt_lints_are_neither_required_nor_forbidden_and_non_pedantic_names_are_refused() {
    // The exemption is explicit, and the list cannot grow beyond the group.
    let exempt = EXEMPT[0].0;
    let toolchains = [toolchain("only", &["a", exempt], &["unwrap_used"])];
    assert_eq!(
        list_problems(&set(&["a"]), &toolchains),
        Vec::<String>::new()
    );
    assert_eq!(
        list_problems(&set(&["a", exempt]), &toolchains),
        [format!("{exempt} is exempt and must not be forbidden")]
    );
    assert_eq!(
        list_problems(&set(&["a", "unwrap_used"]), &toolchains),
        ["unwrap_used is forbidden but pedantic in no toolchain"]
    );
}

#[test]
fn sources_may_not_suppress_an_exempt_lint_or_the_whole_pedantic_group() {
    // Ordinary allows and lint names inside messages are not suppressions.
    let text = [
        "#[allow(clippy::used_underscore_binding)]",
        "fn a() {}",
        "#[cfg_attr(test, expect(clippy::used_underscore_binding, reason = \"x\"))]",
        "fn b() {}",
        "#![allow(clippy::pedantic)]",
        "#[allow(clippy::unwrap_used)]",
        "fn c() { value.expect(\"clippy::pedantic is fine in a message\"); }",
    ]
    .join("\n");
    assert_eq!(
        suppressions("lib.rs", &text),
        [
            "lib.rs:1: allow(clippy::used_underscore_binding)",
            "lib.rs:3: expect(clippy::used_underscore_binding, reason = \"x\")",
            "lib.rs:5: allow(clippy::pedantic)",
        ]
    );
}

#[test]
fn attribute_text_inside_strings_and_comments_is_not_a_suppression() {
    // Test fixtures and documentation quote attributes; only real ones count,
    // and a real one after quoted text keeps its line and reason.
    let text = [
        r##"let fixture = "#![allow(clippy::pedantic)]";"##,
        r##"let raw = r#"#[allow(clippy::used_underscore_binding)] "quoted" "#;"##,
        "// #[allow(clippy::pedantic)]",
        "/* #[allow(clippy::pedantic)] /* nested */ still a comment */",
        "let quote = '\"'; let lifetime: &'static str = \"\\\"#[allow(clippy::pedantic)]\";",
        "#[expect(clippy::pedantic, reason = \"real\")]",
    ]
    .join("\n");
    assert_eq!(
        suppressions("lib.rs", &text),
        ["lib.rs:6: expect(clippy::pedantic, reason = \"real\")"]
    );
}

fn located(found: &[String]) -> Vec<String> {
    found
        .iter()
        .map(|found| found.split(':').take(2).collect::<Vec<_>>().join(":"))
        .collect()
}

#[test]
fn a_reason_string_with_parentheses_or_quotes_does_not_hide_a_suppression() {
    // Clippy accepts these attributes, so the scanner must see past quoted text.
    let text = [
        "#[allow(clippy::used_underscore_binding, reason = \"compatibility (upstream)\")]",
        "#[expect(clippy::pedantic, reason = \"see \\\"foo()\\\" here\")]",
        "#[allow(clippy::unwrap_used, reason = \"not clippy::pedantic, nor clippy::used_underscore_binding\")]",
    ]
    .join("\n");
    assert_eq!(
        located(&suppressions("lib.rs", &text)),
        ["lib.rs:1", "lib.rs:2"]
    );
}

#[test]
fn whitespace_around_the_path_separator_does_not_hide_a_suppression() {
    // Rust tokenizes `clippy :: pedantic` as the same lint path as `clippy::pedantic`.
    let text = [
        "#[allow(clippy :: used_underscore_binding)]",
        "#![expect(clippy::\n  pedantic)]",
        "#[allow(clippy :: unwrap_used)]",
    ]
    .join("\n");
    assert_eq!(
        located(&suppressions("lib.rs", &text)),
        ["lib.rs:1", "lib.rs:2"]
    );
}

#[test]
fn a_local_allow_of_any_forbidden_pedantic_lint_fails_the_lint_gate() {
    // The workspace lint table, applied to a crate that allows every listed lint
    // locally, must make clippy fail with E0453 for each of them; without the
    // allows the same crate passes, so the failure is the forbid and nothing else.
    let manifest = read("Cargo.toml");
    let forbidden = forbidden_lints(&manifest).unwrap();
    assert!(forbidden.contains("cast_possible_truncation"));
    let start = manifest.find("[workspace.lints.clippy]").unwrap();
    let table: Vec<&str> = manifest[start..]
        .lines()
        .skip(1)
        .take_while(|line| !line.starts_with('['))
        .collect();
    let lints = format!("[lints.clippy]\n{}\n", table.join("\n"));
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir(directory.path().join("src")).unwrap();
    let clippy = |source: &str, table: &str| {
        std::fs::write(
            directory.path().join("Cargo.toml"),
            format!("[package]\nname = \"pedantic-probe\"\nversion = \"0.0.0\"\nedition = \"2024\"\npublish = false\n\n[workspace]\n\n{table}"),
        )
        .unwrap();
        std::fs::write(directory.path().join("src/lib.rs"), source).unwrap();
        Command::new("cargo")
            .args(["clippy", "--quiet", "--", "-D", "warnings"])
            .current_dir(directory.path())
            .env_remove("CARGO_TARGET_DIR")
            .output()
            .unwrap()
    };
    // Forbidding only the group is not enough: rustc lets a member allow
    // override it with a forbidden_lint_groups warning, and the lint is silenced.
    let truncating = "//! Probe.\n#[allow(clippy::cast_possible_truncation)]\n#[must_use]\npub fn narrow(value: u64) -> u8 { value as u8 }\n";
    let group_only = clippy(
        truncating,
        "[lints.clippy]\npedantic = { level = \"forbid\", priority = -1 }\n",
    );
    assert!(
        group_only.status.success(),
        "{}",
        String::from_utf8_lossy(&group_only.stderr)
    );
    assert!(!clippy(truncating, &lints).status.success());
    let clean = clippy("//! Probe.\n", &lints);
    assert!(
        clean.status.success(),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );
    let names: Vec<String> = forbidden
        .iter()
        .map(|name| format!("clippy::{name}"))
        .collect();
    let allowed = clippy(
        &format!(
            "//! Probe.\n#[allow({})]\npub fn probe() {{}}\n",
            names.join(", ")
        ),
        &lints,
    );
    assert!(!allowed.status.success());
    let stderr = String::from_utf8_lossy(&allowed.stderr);
    for name in &forbidden {
        let pattern = regex::Regex::new(&format!(
            r"E0453.*allow\(clippy::{name}\) incompatible with previous forbid"
        ))
        .unwrap();
        assert!(pattern.is_match(&stderr), "{name}");
    }
}
