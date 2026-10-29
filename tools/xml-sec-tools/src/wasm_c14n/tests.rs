use super::{build_step, execute};
use std::path::Path;

/// A module exporting `name` as a function that returns the constant `value`.
fn module(name: &str, value: u8) -> Vec<u8> {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    // One type: no parameters, one i32 result; one function of that type.
    bytes.extend([0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f]);
    bytes.extend([0x03, 0x02, 0x01, 0x00]);
    let name_length = u8::try_from(name.len()).unwrap();
    bytes.extend([0x07, name_length + 4, 0x01, name_length]);
    bytes.extend(name.bytes());
    bytes.extend([0x00, 0x00]);
    // Body: no locals, i32.const value, end.
    bytes.extend([0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, value, 0x0b]);
    bytes
}

#[test]
fn the_compiled_export_decides_the_result() {
    // The check is the module's own answer, not that it loaded.
    assert_eq!(execute(&module("xml_sec_wasm_smoke", 1)).unwrap(), 1);
    assert_eq!(execute(&module("xml_sec_wasm_smoke", 0)).unwrap(), 0);
}

#[test]
fn a_module_without_the_smoke_export_fails() {
    // A renamed or stripped export cannot pass as an executed check.
    let error = execute(&module("other_export", 1)).unwrap_err();
    assert!(error.contains("xml_sec_wasm_smoke"), "{error}");
    assert!(execute(b"not wasm").is_err());
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
