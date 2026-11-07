use super::{
    FIPS_ONLY, HEADER, Library, Mode, build_step, declared, host, library, symbol_mismatch,
    test_step,
};
use crate::test_support::read;
use std::collections::BTreeSet;
use std::path::PathBuf;

fn names(list: &[&str]) -> BTreeSet<String> {
    list.iter().map(|&name| name.to_owned()).collect()
}

#[test]
fn the_host_comes_from_the_compiler_report() {
    // The programs are built for the triple the library was built for.
    let report = "rustc 1.99.0\nbinary: rustc\nhost: x86_64-unknown-linux-gnu\nrelease: 1.99.0\n";
    assert_eq!(host(report).unwrap(), "x86_64-unknown-linux-gnu");
    assert!(host("rustc 1.99.0\n").is_err());
}

#[test]
fn the_library_is_the_one_cargo_names_for_the_crate() {
    // Diagnostics, other crates and the build-finished line are skipped; a
    // fresh artifact is reported like a rebuilt one.
    let messages = [
        r#"{"reason":"compiler-artifact","target":{"name":"xml_sec"},"filenames":["/t/libxml_sec.rlib"]}"#,
        "not json",
        r#"{"reason":"compiler-artifact","target":{"name":"xml_sec_capi"},"fresh":true,"filenames":["/t/debug/libxml_sec_capi.rlib","/t/debug/libxml_sec_capi.so","/t/debug/libxml_sec_capi.a"]}"#,
        r#"{"reason":"build-finished","success":true}"#,
    ]
    .join("\n");
    let found = library(&messages, ".so").unwrap();
    assert_eq!(
        found,
        Library {
            shared: PathBuf::from("/t/debug/libxml_sec_capi.so"),
            import: None,
        }
    );
    assert_eq!(found.directory(), PathBuf::from("/t/debug"));
    let windows = r#"{"reason":"compiler-artifact","target":{"name":"xml_sec_capi"},"filenames":["C:/t/xml_sec_capi.dll","C:/t/xml_sec_capi.dll.lib","C:/t/xml_sec_capi.lib"]}"#;
    assert_eq!(
        library(windows, ".dll").unwrap().import,
        Some(PathBuf::from("C:/t/xml_sec_capi.dll.lib"))
    );
    assert!(library(&messages, ".dylib").is_err());
    assert!(library(r#"{"reason":"build-finished","success":true}"#, ".so").is_err());
}

#[test]
fn declarations_are_functions_before_their_parameter_lists() {
    // Return and parameter types share the prefix but are not functions, and
    // comments and macros declare nothing.
    let header = "/* see xs_abi_version() */\n\
                  #define XS_X(a) a\n\
                  xs_status xs_one(XsBytes a, xs_status *b);\n\
                  uint32_t xs_two(void); xs_status xs_three(\n\
                  \x20   XsError error);\n";
    assert_eq!(declared(header), names(&["xs_one", "xs_three", "xs_two"]));
    let real = declared(&read(HEADER));
    for name in [
        "xs_abi_version",
        "xs_sign",
        "xs_buffer_free",
        "xs_error_destroy",
        FIPS_ONLY,
    ] {
        assert!(real.contains(name), "{name}");
    }
    assert!(!real.contains("xs_status"));
}

#[test]
fn exports_and_declarations_must_match_except_the_optional_engine() {
    // An undeclared export is ABI nobody can call correctly; a declared
    // function the library lacks fails only at a caller's link time.
    let declared = names(&["xs_a", "xs_b", FIPS_ONLY]);
    assert_eq!(symbol_mismatch(&declared, &names(&["xs_a", "xs_b"])), None);
    assert_eq!(
        symbol_mismatch(&declared, &names(&["xs_a", "xs_b", FIPS_ONLY])),
        None
    );
    assert!(symbol_mismatch(&declared, &names(&["xs_a"])).is_some_and(|m| m.contains("xs_b")));
    assert!(
        symbol_mismatch(&declared, &names(&["xs_a", "xs_b", "xs_c"]))
            .is_some_and(|m| m.contains("xs_c"))
    );
}

#[test]
fn the_sanitized_build_keeps_the_callers_flags_and_names_its_target() {
    // The sanitizer applies to the target only, never to build scripts, and
    // adds to the caller's flags rather than replacing them.
    let plain = build_step(Mode::Plain, "x86_64-unknown-linux-gnu", Some("-Dwarnings"));
    assert_eq!(plain.program, "cargo");
    assert_eq!(
        plain.args,
        [
            "build",
            "-p",
            "xml-sec-capi",
            "--lib",
            "--message-format=json-render-diagnostics"
        ]
    );
    assert_eq!(plain.env.len(), 0);
    let sanitized = build_step(
        Mode::Sanitized,
        "x86_64-unknown-linux-gnu",
        Some("-Dwarnings"),
    );
    assert_eq!(sanitized.args[0], "+nightly");
    assert!(
        sanitized
            .args
            .ends_with(&["--target".to_owned(), "x86_64-unknown-linux-gnu".to_owned()])
    );
    assert_eq!(
        sanitized.env,
        [(
            "RUSTFLAGS".to_owned(),
            "-Dwarnings -Zsanitizer=address".to_owned()
        )]
    );
    let tests = test_step("aarch64-apple-darwin", None);
    assert_eq!(
        tests.args,
        [
            "+nightly",
            "nextest",
            "run",
            "-p",
            "xml-sec-capi",
            "--target",
            "aarch64-apple-darwin"
        ]
    );
    assert_eq!(
        tests.env,
        [("RUSTFLAGS".to_owned(), "-Zsanitizer=address".to_owned())]
    );
}
