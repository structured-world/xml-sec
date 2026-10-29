use super::{build_step, check_module};
use std::path::Path;

/// A module exporting each `(name, value)` as a function returning `value`.
fn module(exports: &[(&str, u8)]) -> Vec<u8> {
    let count = u8::try_from(exports.len()).unwrap();
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    // One type: no parameters, one i32 result; every function has it.
    bytes.extend([0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f]);
    bytes.extend([0x03, count + 1, count]);
    bytes.extend(std::iter::repeat_n(0x00, exports.len()));
    let mut section = vec![count];
    for (index, (name, _)) in exports.iter().enumerate() {
        section.push(u8::try_from(name.len()).unwrap());
        section.extend(name.bytes());
        section.extend([0x00, u8::try_from(index).unwrap()]);
    }
    bytes.extend([0x07, u8::try_from(section.len()).unwrap()]);
    bytes.extend(section);
    // Bodies: no locals, i32.const value, end.
    bytes.extend([0x0a, 5 * count + 1, count]);
    for (_, value) in exports {
        bytes.extend([0x04, 0x00, 0x41, *value, 0x0b]);
    }
    bytes
}

const BOTH: [&str; 2] = ["xml_sec_wasm_smoke", "xml_sec_wasm_verify"];

#[test]
fn both_compiled_exports_must_report_success() {
    // The check is each export's own answer, not that the module loaded.
    assert!(check_module(&module(&[(BOTH[0], 1), (BOTH[1], 1)])).is_ok());
    let error = check_module(&module(&[(BOTH[0], 0), (BOTH[1], 1)])).unwrap_err();
    assert!(error.contains("canonicalization"), "{error}");
    let error = check_module(&module(&[(BOTH[0], 1), (BOTH[1], 0)])).unwrap_err();
    assert!(error.contains("XMLDSig verification"), "{error}");
}

#[test]
fn a_module_without_an_export_fails() {
    // A renamed or stripped export cannot pass as an executed check.
    let error = check_module(&module(&[(BOTH[0], 1)])).unwrap_err();
    assert!(error.contains("xml_sec_wasm_verify"), "{error}");
    let error = check_module(&module(&[(BOTH[1], 1)])).unwrap_err();
    assert!(error.contains("xml_sec_wasm_smoke"), "{error}");
    assert!(check_module(b"not wasm").is_err());
}

#[test]
fn the_smoke_consumer_builds_for_the_bare_webassembly_target() {
    // The executed module is the wasm32-unknown-unknown build of the consumer.
    let step = build_step(Path::new("/target/wasm-smoke"));
    assert_eq!(step.program, "cargo");
    for expected in [
        "tests/wasm-smoke/Cargo.toml",
        "/target/wasm-smoke",
        "wasm32-unknown-unknown",
    ] {
        assert!(step.args.iter().any(|arg| arg == expected), "{expected}");
    }
}
