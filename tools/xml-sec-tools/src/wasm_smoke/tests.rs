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

const ALL: [&str; 4] = [
    "xml_sec_wasm_smoke",
    "xml_sec_wasm_verify",
    "xml_sec_wasm_cms",
    "xml_sec_wasm_xades",
];

/// A module where the export at `failing`, if any, reports failure.
fn answering(failing: Option<usize>) -> Vec<u8> {
    let exports = [0, 1, 2, 3].map(|index| (ALL[index], u8::from(Some(index) != failing)));
    module(&exports)
}

#[test]
fn every_compiled_export_must_report_success() {
    // The check is each export's own answer, not that the module loaded.
    assert!(check_module(&answering(None)).is_ok());
    for (index, failure) in [
        "canonicalization",
        "XMLDSig verification",
        "CMS timestamp",
        "XAdES B-LTA",
    ]
    .into_iter()
    .enumerate()
    {
        let error = check_module(&answering(Some(index))).unwrap_err();
        assert!(error.contains(failure), "{error}");
    }
}

#[test]
fn a_module_without_an_export_fails() {
    // A renamed or stripped export cannot pass as an executed check.
    for missing in ALL {
        let exports: Vec<_> = ALL
            .into_iter()
            .filter(|&name| name != missing)
            .map(|name| (name, 1))
            .collect();
        let error = check_module(&module(&exports)).unwrap_err();
        assert!(error.contains(missing), "{error}");
    }
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
