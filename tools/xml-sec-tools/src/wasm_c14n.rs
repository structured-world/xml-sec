//! `wasm-c14n`: builds the WebAssembly C14N consumer and executes it, so the
//! check is a run of the compiled module rather than a successful compilation.

use crate::repo::{Failure, Run, Step, System, require, root};
use std::path::Path;

#[cfg(test)]
mod tests;

const EXPORT: &str = "xml_sec_wasm_smoke";

/// The build of the smoke consumer for `wasm32-unknown-unknown`.
pub(crate) fn build_step(target: &Path) -> Step {
    Step::new(
        "WebAssembly C14N build",
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

/// The interpreter's stack: its unoptimized build, which `cargo run` uses,
/// needs more for the smoke module than a main thread provides.
const INTERPRETER_STACK: usize = 64 << 20;

/// Instantiates `module` without imports and returns its smoke export's result.
pub(crate) fn execute(module: &[u8]) -> Result<u32, String> {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .stack_size(INTERPRETER_STACK)
            .spawn_scoped(scope, || interpret(module))
            .map_err(|error| format!("start interpreter: {error}"))?
            .join()
            .map_err(|_| "the interpreter panicked".to_owned())?
    })
}

fn interpret(module: &[u8]) -> Result<u32, String> {
    let engine = wasmi::Engine::default();
    let module =
        wasmi::Module::new(&engine, module).map_err(|error| format!("load module: {error}"))?;
    let mut store = wasmi::Store::new(&engine, ());
    let instance = wasmi::Linker::<()>::new(&engine)
        .instantiate_and_start(&mut store, &module)
        .map_err(|error| format!("instantiate module: {error}"))?;
    let smoke = instance
        .get_typed_func::<(), u32>(&store, EXPORT)
        .map_err(|error| format!("{EXPORT}: {error}"))?;
    smoke
        .call(&mut store, ())
        .map_err(|error| format!("{EXPORT}: {error}"))
}

pub(crate) fn check(run: &mut impl Run) -> Result<(), Failure> {
    let target = root().join("target/wasm-smoke");
    require(run.status(&build_step(&target))?)?;
    let module = target.join("wasm32-unknown-unknown/debug/xml_sec_wasm_smoke.wasm");
    let bytes = std::fs::read(&module).map_err(|error| format!("{}: {error}", module.display()))?;
    if execute(&bytes)? != 1 {
        return Err("WASM canonicalization must produce exact expected bytes".into());
    }
    println!("WASM C14N execution passed");
    Ok(())
}

pub(crate) fn run(mut args: impl Iterator<Item = String>) -> Result<(), Failure> {
    if args.next().is_some() {
        return Err("usage: wasm-c14n".into());
    }
    check(&mut System)
}
