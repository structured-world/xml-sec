//! Executable qualification of the existing WASM C14N-only product path.
//! This separate consumer excludes native-only development dependencies.

use xml_sec::c14n::{C14nAlgorithm, C14nMode, canonicalize_xml};

/// Called in the compiled WASM module, not a native substitute.
#[unsafe(no_mangle)]
pub extern "C" fn xml_sec_wasm_smoke() -> u32 {
    let algorithm = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
    match canonicalize_xml(b"<root b=\"2\" a=\"1\"><empty/></root>", &algorithm) {
        Ok(bytes) if bytes == b"<root a=\"1\" b=\"2\"><empty></empty></root>" => 1,
        _ => 0,
    }
}
