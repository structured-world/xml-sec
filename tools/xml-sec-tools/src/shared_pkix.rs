//! `shared-pkix`: checks the alloc graphs of the released shared mechanisms
//! independently. The `XMLDSig` workspace activates std and cannot qualify its
//! shared dependencies' `no_std` path.

use crate::repo::{Failure, Run, Step, System, require, root};
use serde_json::Value;
use std::path::Path;

#[cfg(test)]
mod tests;

/// The mechanisms that must resolve as one registry generation.
const SHARED: [&str; 5] = [
    "structured-asn1",
    "structured-cms",
    "structured-ltv",
    "structured-pkix",
    "structured-xades",
];

/// The entry points whose alloc graphs cover every shared mechanism.
const ENTRY_POINTS: [&str; 2] = ["structured-pkix", "structured-xades"];

const TARGETS: [&str; 2] = ["thumbv7em-none-eabihf", "wasm32-unknown-unknown"];

/// The manifests of the entry points, from `cargo metadata` output, once
/// the whole shared graph is one coordinated registry generation.
pub(crate) fn manifests(metadata: &Value) -> Result<Vec<String>, String> {
    let refusal = || "expected one coordinated registry ASN1/PKIX/CMS/LTV/XAdES graph".to_owned();
    let shared: Vec<&Value> = metadata
        .get("packages")
        .and_then(Value::as_array)
        .ok_or_else(refusal)?
        .iter()
        .filter(|package| {
            package
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| SHARED.contains(&name))
        })
        .collect();
    let field =
        |package: &Value, name: &str| package.get(name).and_then(Value::as_str).map(str::to_owned);
    let mut names: Vec<String> = shared
        .iter()
        .filter_map(|package| field(package, "name"))
        .collect();
    names.sort();
    let versions: std::collections::BTreeSet<Option<String>> = shared
        .iter()
        .map(|package| field(package, "version"))
        .collect();
    let registry = shared.iter().all(|package| {
        field(package, "source").is_some_and(|source| source.starts_with("registry+"))
    });
    if names != SHARED || versions.len() != 1 || !registry {
        return Err(refusal());
    }
    let manifests: Vec<String> = shared
        .iter()
        .filter(|package| {
            field(package, "name").is_some_and(|name| ENTRY_POINTS.contains(&name.as_str()))
        })
        .filter_map(|package| field(package, "manifest_path"))
        .collect();
    for manifest in &manifests {
        if !published(manifest) {
            return Err("shared qualification requires published registry packages".into());
        }
    }
    Ok(manifests)
}

/// Whether `manifest` is `.../registry/src/<index>/<entry point>-<version>/Cargo.toml`.
fn published(manifest: &str) -> bool {
    let parts: Vec<&str> = manifest.rsplit('/').collect();
    matches!(parts.as_slice(), ["Cargo.toml", package, _, "src", "registry", ..]
        if ENTRY_POINTS.iter().any(|name| package.strip_prefix(name).is_some_and(|rest| rest.starts_with('-'))))
}

/// One locked alloc-only check per entry point and target.
pub(crate) fn checks(manifests: &[String], target_dir: &Path) -> Vec<Step> {
    let target_dir = target_dir.display().to_string();
    manifests
        .iter()
        .flat_map(|manifest| {
            let target_dir = &target_dir;
            TARGETS.iter().map(move |target| {
                Step::new(
                    format!("{manifest} {target}"),
                    "cargo",
                    &[
                        "check",
                        "--manifest-path",
                        manifest,
                        "--locked",
                        "--no-default-features",
                        "--features",
                        "alloc",
                        "--target",
                        target,
                        "--target-dir",
                        target_dir,
                    ],
                )
            })
        })
        .collect()
}

/// Discovers the shared graph, then checks every entry point and target.
pub(crate) fn execute(runner: &mut impl Run) -> Result<(), Failure> {
    let root = root();
    // Discovery also resolves a fresh checkout's ignored workspace lockfile;
    // the registry-package checks below remain locked.
    let metadata = Step::new(
        "metadata",
        "cargo",
        &[
            "metadata",
            "--manifest-path",
            &root.join("Cargo.toml").display().to_string(),
            "--format-version",
            "1",
        ],
    );
    let (status, output) = runner.stdout(&metadata)?;
    require(status)?;
    let metadata: Value =
        serde_json::from_str(&output).map_err(|error| format!("parse cargo metadata: {error}"))?;
    for check in checks(
        &manifests(&metadata)?,
        &root.join("target/shared-pkix-alloc"),
    ) {
        require(runner.status(&check)?)?;
    }
    Ok(())
}

pub(crate) fn run(mut args: impl Iterator<Item = String>) -> Result<(), Failure> {
    if args.next().is_some() {
        return Err("usage: xml-sec-tools shared-pkix".into());
    }
    execute(&mut System)
}
