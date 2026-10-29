//! `bench-dashboard COMPARISON_DIR NEW_SITE_DIR`: the published dashboard of
//! one complete comparison run.

use super::{read_json, write_json};
use crate::repo::{Failure, root};
use serde_json::Value;
use std::path::Path;

/// CLI: 5 payload shapes x 3 sizes x 4 operations x 4 engines, plus 4
/// workloads x 3 sizes x 2 operations x 4 engines. An engine without the
/// capability has an unsupported entry.
pub(crate) const EXPECTED_CLI: usize = 240 + 96;
/// Library: 4 workloads x 3 sizes x 2 operations x 2 boundaries x 3 engines.
pub(crate) const EXPECTED_LIBRARY: usize = 144;

fn results(report: &Value) -> &[Value] {
    report["results"].as_array().map_or(&[], Vec::as_slice)
}

/// Refuses a partial run: missing engines must never appear as zeros.
pub(crate) fn check(report: &Value, library: &Value, build: &Value) -> Result<(), String> {
    // The next run's regression report needs this run's build identity as its baseline.
    if build["schema"] != 1 {
        return Err("Expected build identity schema 1".into());
    }
    if report["schema"] != 2 || results(report).len() != EXPECTED_CLI {
        return Err(format!("Expected all {EXPECTED_CLI} command-line entries"));
    }
    if library["schema"] != 1 || results(library).len() != EXPECTED_LIBRARY {
        return Err(format!("Expected all {EXPECTED_LIBRARY} library entries"));
    }
    let measured = |entry: &Value| {
        entry["repetitions"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    };
    let unsupported = |entry: &Value| match &entry["unsupported"] {
        Value::Null | Value::Bool(false) => false,
        Value::String(text) => !text.is_empty(),
        _ => true,
    };
    if results(report)
        .iter()
        .chain(results(library))
        .any(|entry| !unsupported(entry) && !measured(entry))
    {
        return Err("A supported entry has no measurements".into());
    }
    Ok(())
}

/// Builds the site from `input` into the new directory `output`.
pub(crate) fn build(input: &Path, output: &Path, assets: &Path) -> Result<(), String> {
    let mut report = read_json(&input.join("comparison.json"))?;
    let library = read_json(&input.join("library.json"))?;
    let build = read_json(&input.join("build.json"))?;
    check(&report, &library, &build)?;
    // Runtime absolute paths are useful locally, not public dashboard content.
    for entry in report["results"].as_array_mut().into_iter().flatten() {
        if let Some(entry) = entry.as_object_mut() {
            entry.remove("commands");
        }
    }
    std::fs::create_dir(output).map_err(|error| format!("create {}: {error}", output.display()))?;
    for file in ["index.html", "app.js", "style.css"] {
        std::fs::copy(assets.join(file), output.join(file))
            .map_err(|error| format!("{file}: {error}"))?;
    }
    write_json(&output.join("comparison.json"), &report)?;
    write_json(&output.join("library.json"), &library)?;
    write_json(&output.join("build.json"), &build)?;
    // Published with the run that produced it; a run without a report publishes none.
    for file in ["regression.json", "regression.md"] {
        let source = input.join(file);
        if source.exists() {
            std::fs::copy(&source, output.join(file))
                .map_err(|error| format!("{file}: {error}"))?;
        }
    }
    Ok(())
}

pub(crate) fn run(args: impl Iterator<Item = String>) -> Result<(), Failure> {
    let args: Vec<String> = args.collect();
    let [input, output] = args.as_slice() else {
        return Err("Usage: bench-dashboard COMPARISON_DIR NEW_SITE_DIR".into());
    };
    build(
        Path::new(input),
        Path::new(output),
        &root().join("benchmarks/dashboard"),
    )?;
    Ok(())
}
