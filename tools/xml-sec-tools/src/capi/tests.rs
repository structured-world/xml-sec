use super::{
    FIPS_ONLY, HEADER, Library, Mode, Target, build_step, declared, declared_with,
    first_difference, host, layout_program, library, symbol_mismatch, targets, template_defines,
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
    let found = library(&messages, Target::Clean, ".so").unwrap();
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
        library(windows, Target::Clean, ".dll").unwrap().import,
        Some(PathBuf::from("C:/t/xml_sec_capi.dll.lib"))
    );
    assert!(library(&messages, Target::Clean, ".dylib").is_err());
    assert!(
        library(
            r#"{"reason":"build-finished","success":true}"#,
            Target::Clean,
            ".so"
        )
        .is_err()
    );
    // The bridge's build also reports the clean library it depends on; only
    // its own artifact is the bridge.
    let bridge = [
        messages.as_str(),
        r#"{"reason":"compiler-artifact","target":{"name":"xml_sec_libxml2"},"filenames":["/t/debug/libxml_sec_libxml2.rlib","/t/debug/libxml_sec_libxml2.so"]}"#,
    ]
    .join("\n");
    assert_eq!(
        library(&bridge, Target::Libxml2, ".so").unwrap().shared,
        PathBuf::from("/t/debug/libxml_sec_libxml2.so")
    );
    assert!(library(&messages, Target::Libxml2, ".so").is_err());
}

#[test]
fn the_tree_library_declares_the_clean_api_its_entry_point_and_the_tree() {
    // The tree library reexports the clean C API, so its exports are checked
    // against the clean header, its own and the tree functions' header, and
    // its programs include their directories.
    let headers = Target::Libxml2.headers();
    assert_eq!(headers[0], HEADER);
    let entry = declared(&read(headers[1]));
    assert!(entry.contains("xs_tree_document"));
    assert!(!declared(&read(HEADER)).contains("xs_tree_document"));
    let tree = declared(&read(headers[2]));
    assert!(tree.contains("xsReadMemory") && tree.contains("xsFree"));
    assert_eq!(Target::Libxml2.includes().len(), 2);
    // Nothing is resolved at run time, so it is qualified on every platform.
    assert!(targets().contains(&Target::Libxml2));
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

/// A libxmlsec1 declaration whose parameter list starts on the line after
/// the name still declares that name.
#[test]
fn a_parameter_list_on_the_next_line_declares_the_name() {
    let header = "XMLSEC_EXPORT void              xmlSecOneEnableOutput\n\
                  \x20                                                (int enabled);\n\
                  XMLSEC_EXPORT int xmlSecTwo (void);\n";
    assert_eq!(
        declared_with(header, "xmlSec"),
        names(&["xmlSecOneEnableOutput", "xmlSecTwo"])
    );
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
fn libxmlsec1_declarations_are_found_across_alignment_spaces() {
    // libxmlsec1 aligns names and parameter lists with spaces; function
    // pointer typedefs and macros are not exported functions.
    let header = "XMLSEC_EXPORT xmlSecBufferPtr   xmlSecBufferCreate              (xmlSecSize size);\n\
                  typedef int (*xmlSecTransformInitializeMethod) (xmlSecTransformPtr t);\n\
                  #define xmlSecTransformIsValid(t) ((t) != NULL)\n\
                  XMLSEC_EXPORT int xmlSecInit(void);\n";
    assert_eq!(
        declared_with(header, "xmlSec"),
        names(&["xmlSecBufferCreate", "xmlSecInit"])
    );
    let real = declared_with(
        &read("crates/xml-sec-xmlsec1/include/xmlsec/transforms.h"),
        "xmlSec",
    );
    for name in [
        "xmlSecTransformCtxCreate",
        "xmlSecTransformPushBin",
        "xmlSecTransformIdsGet",
    ] {
        assert!(real.contains(name), "{name}");
    }
}

#[test]
fn exported_variables_are_declarations_too() {
    // The string constants are data exports; a function prototype is not a
    // variable.
    let header = "XMLSEC_EXPORT_VAR const xmlChar xmlSecNs[];\n\
                  XMLSEC_EXPORT_VAR int xmlSecFlag;\n\
                  XMLSEC_EXPORT int xmlSecInit(void);\n";
    assert_eq!(
        super::declared_variables(header, "xmlSec"),
        names(&["xmlSecFlag", "xmlSecNs"])
    );
    let real = super::declared_variables(
        &read("crates/xml-sec-xmlsec1/include/xmlsec/strings.h"),
        "xmlSec",
    );
    assert!(real.contains("xmlSecDSigNs"));
    assert!(real.contains("xmlSecNameBase64"));
}

#[test]
fn the_template_defines_are_what_a_consumer_compiles_with() {
    // Only the `-D` flags of the Cflags line; the include path is the
    // installation's and differs between the oracle and the library.
    let template = "Name: x\nCflags: -DA=1 -D__F__=__func__ -I${includedir}\nLibs: -lx\n";
    assert_eq!(
        template_defines(template).unwrap(),
        ["-DA=1", "-D__F__=__func__"]
    );
    assert!(template_defines("Name: x\n").is_err());
    let real = template_defines(&read("crates/xml-sec-xmlsec1/xml-sec-xmlsec1.pc.in")).unwrap();
    assert!(real.contains(&"-DXMLSEC_CRYPTO_DYNAMIC_LOADING=1".to_owned()));
}

#[test]
fn the_layout_program_prints_every_baseline_record() {
    // One line per structure, field and enumerator of the baseline, so both
    // builds print comparable records and a field the headers lack fails to
    // compile rather than being skipped.
    let baseline = r#"{"structs":[{"name":"_S","fields":[{"name":"a"},{"name":"b"}]}],
        "enums":[{"name":"E","values":[{"name":"eOne"}]}]}"#;
    let program = layout_program(baseline).unwrap();
    assert!(program.starts_with("#define XMLSEC_PRIVATE 1\n"));
    assert!(program.contains("sizeof(struct _S), alignof(struct _S)"));
    assert!(program.contains("offsetof(struct _S, a)"));
    assert!(program.contains("offsetof(struct _S, b)"));
    assert!(program.contains("(int)eOne"));
    assert!(layout_program("{}").is_err());
    let real = layout_program(&read(
        "compatibility/libxmlsec1-1.3.13-abi-linux-x86_64.json",
    ))
    .unwrap();
    assert!(real.contains("offsetof(struct _xmlSecTransformCtx, enabledTransforms)"));
}

#[test]
fn differences_name_the_first_differing_line() {
    // A missing or extra line is a difference, as is a changed one.
    assert_eq!(first_difference("a\nb\n", "a\nb\n"), None);
    assert!(first_difference("a\nb\n", "a\nc\n").is_some_and(|d| d.starts_with("line 2")));
    assert!(first_difference("a\n", "a\nb\n").is_some_and(|d| d.contains("None")));
    assert!(first_difference("a\nb\n", "a\n").is_some_and(|d| d.starts_with("line 2")));
}

#[test]
fn the_sanitized_build_keeps_the_callers_flags_and_names_its_target() {
    // The sanitizer applies to the target only, never to build scripts, and
    // adds to the caller's flags rather than replacing them.
    let plain = build_step(
        Target::Clean,
        Mode::Plain,
        "x86_64-unknown-linux-gnu",
        Some("-Dwarnings"),
    );
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
        Target::Clean,
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
    let mut expected = vec!["+nightly", "nextest", "run"];
    for target in targets() {
        expected.extend(["-p", target.package()]);
    }
    // The libxmlsec1-compatible library's tests run wherever the bridge's do.
    if targets().contains(&Target::Libxml2) {
        expected.extend(["-p", Target::Xmlsec1.package()]);
    }
    expected.extend(["--target", "aarch64-apple-darwin"]);
    assert_eq!(tests.args, expected);
    assert_eq!(
        tests.env,
        [("RUSTFLAGS".to_owned(), "-Zsanitizer=address".to_owned())]
    );
}
