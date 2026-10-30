//! `wasm-smoke`: builds the WebAssembly consumer and executes its C14N,
//! signature verification and CMS timestamp paths, so the check is a run of
//! the compiled module rather than a successful compilation.

use crate::repo::{Failure, Run, Step, System, require, root};
use std::path::Path;

#[cfg(test)]
mod tests;

/// Each export, the failure it reports when it does not return 1, and the
/// line printed when it does.
const EXPORTS: [(&str, &str, &str); 3] = [
    (
        "xml_sec_wasm_smoke",
        "WASM canonicalization must produce exact expected bytes",
        "WASM C14N execution passed",
    ),
    (
        "xml_sec_wasm_verify",
        "WASM XMLDSig verification must accept the signed response and reject tampering",
        "WASM XMLDSig verification passed",
    ),
    (
        "xml_sec_wasm_cms",
        "WASM CMS timestamp check must accept the token and reject tampering",
        "WASM CMS timestamp check passed",
    ),
];

/// The build of the smoke consumer for `wasm32-unknown-unknown`.
pub(crate) fn build_step(target: &Path) -> Step {
    Step::new(
        "WebAssembly smoke build",
        "cargo",
        &[
            "build",
            "--manifest-path",
            "tests/wasm-smoke/Cargo.toml",
            "--target-dir",
            &target.display().to_string(),
            "--target",
            "wasm32-unknown-unknown",
        ],
    )
}

/// Instantiates `module` without imports and calls every export on that one
/// instance; the first one that does not return 1 is the failure.
pub(crate) fn check_module(module: &[u8]) -> Result<(), String> {
    let engine = wasmi::Engine::default();
    let module =
        wasmi::Module::new(&engine, module).map_err(|error| format!("load module: {error}"))?;
    let mut store = wasmi::Store::new(&engine, ());
    let instance = wasmi::Linker::<()>::new(&engine)
        .instantiate_and_start(&mut store, &module)
        .map_err(|error| format!("instantiate module: {error}"))?;
    for (export, failure, passed) in EXPORTS {
        let function = instance
            .get_typed_func::<(), u32>(&store, export)
            .map_err(|error| format!("{export}: {error}"))?;
        let result = function
            .call(&mut store, ())
            .map_err(|error| format!("{export}: {error}"))?;
        if result != 1 {
            return Err(failure.to_owned());
        }
        println!("{passed}");
    }
    Ok(())
}

pub(crate) fn check(run: &mut impl Run) -> Result<(), Failure> {
    let target = root().join("target/wasm-smoke");
    require(run.status(&build_step(&target))?)?;
    let module = target.join("wasm32-unknown-unknown/debug/xml_sec_wasm_smoke.wasm");
    let bytes = std::fs::read(&module).map_err(|error| format!("{}: {error}", module.display()))?;
    Ok(check_module(&bytes)?)
}

pub(crate) fn run(mut args: impl Iterator<Item = String>) -> Result<(), Failure> {
    if args.next().is_some() {
        return Err("usage: wasm-smoke".into());
    }
    check(&mut System)
}
