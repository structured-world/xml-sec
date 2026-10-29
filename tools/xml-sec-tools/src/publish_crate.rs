//! `publish-crate PACKAGE`: publishes a workspace package once. crates.io can
//! accept an immutable upload before Cargo stops waiting for the sparse index,
//! so visibility, not the publish command's status, decides the outcome and a
//! rerun never uploads the same version again.

use crate::repo::{Failure, Run, Step, System};
use serde_json::Value;
use std::time::Duration;

#[cfg(test)]
mod tests;

const ATTEMPTS: u32 = 30;
const INTERVAL: Duration = Duration::from_secs(10);

/// The version of workspace package `package` in `cargo metadata` output.
pub(crate) fn version(metadata: &Value, package: &str) -> Option<String> {
    metadata["packages"]
        .as_array()?
        .iter()
        .find(|candidate| candidate["name"] == package)?["version"]
        .as_str()
        .map(str::to_owned)
}

/// Whether `package@version` is visible on crates.io. Without an explicit
/// registry Cargo resolves the checked-out workspace package and reports an
/// unpublished release as available.
fn published(run: &mut impl Run, package: &str, version: &str) -> Result<bool, String> {
    let query = Step::new(
        "registry lookup",
        "cargo",
        &[
            "info",
            "--registry",
            "crates-io",
            &format!("{package}@{version}"),
        ],
    );
    Ok(run.combined(&query)?.0.success())
}

pub(crate) fn execute(
    run: &mut impl Run,
    package: &str,
    mut wait: impl FnMut(),
) -> Result<(), Failure> {
    let metadata = Step::new(
        "workspace metadata",
        "cargo",
        &["metadata", "--no-deps", "--format-version", "1"],
    );
    let (status, text) = run.stdout(&metadata)?;
    crate::repo::require(status)?;
    let metadata: Value =
        serde_json::from_str(&text).map_err(|error| format!("cargo metadata: {error}"))?;
    let version = version(&metadata, package)
        .ok_or_else(|| format!("workspace package {package} was not found"))?;
    if published(run, package, &version)? {
        println!("{package} {version} is already published");
        return Ok(());
    }
    let uploaded = run
        .status(&Step::new("publish", "cargo", &["publish", "-p", package]))?
        .success();
    for attempt in 1..=ATTEMPTS {
        if published(run, package, &version)? {
            if !uploaded {
                println!("{package} {version} became visible after the publish command failed");
            }
            return Ok(());
        }
        println!("{package} {version} is not visible yet (attempt {attempt}/{ATTEMPTS})");
        wait();
    }
    Err(format!("{package} {version} was not published").into())
}

pub(crate) fn run(args: impl Iterator<Item = String>) -> Result<(), Failure> {
    let args: Vec<String> = args.collect();
    let [package] = args.as_slice() else {
        return Err("usage: publish-crate PACKAGE".into());
    };
    execute(&mut System, package, || std::thread::sleep(INTERVAL))
}
