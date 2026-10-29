//! The build identity a regression report requires to match between two
//! comparison runs: toolchain, C compiler, overriding environment, applying
//! Cargo configuration files and the runner's recorded selections.

use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(test)]
mod tests;

/// Environment that changes what Cargo or the C compiler build, beyond the manifest.
pub(crate) fn overrides_build(name: &str) -> bool {
    let prefixed = |prefix: &str| {
        name.strip_prefix(prefix).is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        })
    };
    matches!(
        name,
        "RUSTFLAGS"
            | "RUSTDOCFLAGS"
            | "CARGO_ENCODED_RUSTFLAGS"
            | "CARGO_INCREMENTAL"
            | "CC"
            | "CFLAGS"
            | "RUSTC"
            | "RUSTC_WRAPPER"
    ) || ["CARGO_BUILD_", "CARGO_PROFILE_", "CARGO_TARGET_"]
        .into_iter()
        .any(prefixed)
}

/// The first line a tool prints about its version.
fn version(program: &str, args: &[&str]) -> Result<String, String> {
    let failed = || {
        format!(
            "cannot record the build identity: {program} {} failed",
            args.join(" ")
        )
    };
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|_| failed())?;
    if !output.status.success() {
        return Err(failed());
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned())
}

/// Every Cargo configuration file Cargo would read from `directory`, highest
/// precedence first, each with its place (levels above the run directory, or
/// `CARGO_HOME`) so swapping contents between places changes the identity.
pub(crate) fn cargo_configs(directory: &Path, cargo_home: &Path) -> Result<Vec<Value>, String> {
    let mut candidates: Vec<(PathBuf, Value)> = Vec::new();
    let start = std::path::absolute(directory).map_err(|error| error.to_string())?;
    for (levels, current) in start.ancestors().enumerate() {
        for file in ["config.toml", "config"] {
            candidates.push((
                current.join(".cargo").join(file),
                json!({ "location": "directory", "levels": levels, "file": file }),
            ));
        }
    }
    for file in ["config.toml", "config"] {
        candidates.push((
            cargo_home.join(file),
            json!({ "location": "cargo_home", "file": file }),
        ));
    }
    // Cargo reads a CARGO_HOME that is also an ancestor's `.cargo` once, at the ancestor's place.
    let mut seen = std::collections::BTreeSet::new();
    let mut configs = Vec::new();
    for (path, role) in candidates {
        if !seen.insert(path.clone()) || !path.exists() {
            continue;
        }
        let mut entry = role;
        entry["sha256"] = Value::from(super::digest_file(&path)?);
        configs.push(entry);
    }
    Ok(configs)
}

/// The identity object; fails when a required part cannot be recorded.
pub(crate) fn build_identity(
    selections: &[(String, String)],
    environment: &[(String, String)],
    directory: &Path,
) -> Result<Value, String> {
    let mut overrides: Vec<&(String, String)> = environment
        .iter()
        .filter(|(name, _)| overrides_build(name))
        .collect();
    overrides.sort();
    let overrides: Map<String, Value> = overrides
        .into_iter()
        .map(|(name, value)| (name.clone(), Value::from(value.clone())))
        .collect();
    let cargo_home = environment
        .iter()
        .find(|(name, _)| name == "CARGO_HOME")
        .map(|(_, value)| PathBuf::from(value))
        .or_else(|| std::env::home_dir().map(|home| home.join(".cargo")))
        .ok_or("cannot record the build identity: no CARGO_HOME")?;
    let selections: Map<String, Value> = selections
        .iter()
        .map(|(name, value)| (name.clone(), Value::from(value.clone())))
        .collect();
    Ok(json!({
        "schema": 1,
        "profile": "release",
        "rustc": version("rustc", &["-V"])?,
        "cc": version("cc", &["--version"])?,
        "environment": overrides,
        "cargo_configs": cargo_configs(directory, &cargo_home)?,
        "selections": selections,
    }))
}

/// `bench-identity NAME=VALUE...`: prints the identity of a build made from
/// the current directory with the given selections.
pub(crate) fn run(args: impl Iterator<Item = String>) -> Result<(), crate::repo::Failure> {
    let args: Vec<String> = args.collect();
    let environment: Vec<(String, String)> = std::env::vars().collect();
    let directory = std::env::current_dir().map_err(|error| error.to_string())?;
    let identity = build_identity(&selections(&args)?, &environment, &directory)?;
    println!("{identity}");
    Ok(())
}

/// `NAME=VALUE` selections, in order.
pub(crate) fn selections(args: &[String]) -> Result<Vec<(String, String)>, String> {
    args.iter()
        .map(|argument| match argument.split_once('=') {
            Some((name, value)) if !name.is_empty() => Ok((name.to_owned(), value.to_owned())),
            _ => Err(format!(
                "Usage: bench-identity NAME=VALUE..., got {argument}"
            )),
        })
        .collect()
}
