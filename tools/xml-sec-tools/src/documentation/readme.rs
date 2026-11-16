//! `documentation readme [--write]`: keeps the `xml-sec` dependency
//! declarations users copy from the documentation on the release line of the
//! package version in `Cargo.toml`. Release automation raises that version
//! and runs `--write` on the release branch; CI runs the check.

use crate::publish_crate::version;
use crate::repo::{Failure, Run, Step, System, require, root};
use regex::Regex;
use serde_json::Value;
use std::path::{Path, PathBuf};

#[cfg(test)]
mod tests;

const PACKAGE: &str = "xml-sec";

/// The requirement a user writes for `version`: the minor line below 1.0,
/// where Cargo treats each minor release as incompatible, the major line
/// from 1.0 on.
pub(crate) fn requirement(version: &str) -> Result<String, String> {
    let number = |part: Option<&str>| part.and_then(|part| part.parse::<u64>().ok());
    let mut parts = version.split('.');
    let (Some(major), Some(minor)) = (number(parts.next()), number(parts.next())) else {
        return Err(format!(
            "{PACKAGE} version {version} has no numeric major and minor"
        ));
    };
    Ok(if major == 0 {
        format!("0.{minor}")
    } else {
        major.to_string()
    })
}

/// A declaration whose requirement differs from the release line.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Stale {
    /// 1-based line of the declaration.
    pub(crate) line: usize,
    pub(crate) found: String,
}

/// `text` with every `xml-sec` version requirement set to `wanted`, and the
/// declarations that differed. Both `xml-sec = "…"` and the table form with
/// a `version` key count; path-only declarations and other packages do not.
pub(crate) fn align(text: &str, wanted: &str) -> (String, Vec<Stale>) {
    let declaration =
        Regex::new(r#"^(\s*xml-sec\s*=\s*(?:\{[^}\n]*?\bversion\s*=\s*)?")([^"\n]*)""#)
            .expect("the declaration pattern is valid");
    let mut stale = Vec::new();
    let mut aligned = String::with_capacity(text.len());
    for (index, line) in text.split_inclusive('\n').enumerate() {
        match declaration.captures(line) {
            Some(found) if &found[2] != wanted => {
                let requirement = found.get(2).expect("the pattern has two groups");
                stale.push(Stale {
                    line: index + 1,
                    found: requirement.as_str().to_owned(),
                });
                aligned.push_str(&line[..requirement.start()]);
                aligned.push_str(wanted);
                aligned.push_str(&line[requirement.end()..]);
            }
            _ => aligned.push_str(line),
        }
    }
    (aligned, stale)
}

/// The Markdown a user reads before adding the dependency: the root README,
/// every guide under `docs`, and each crate's README.
pub(crate) fn documents(base: &Path) -> Result<Vec<PathBuf>, String> {
    fn guides(directory: &Path, found: &mut Vec<PathBuf>) -> Result<(), String> {
        let entries = std::fs::read_dir(directory)
            .map_err(|error| format!("{}: {error}", directory.display()))?;
        for entry in entries {
            let path = entry
                .map_err(|error| format!("{}: {error}", directory.display()))?
                .path();
            if path.is_dir() {
                guides(&path, found)?;
            } else if path.extension().is_some_and(|extension| extension == "md") {
                found.push(path);
            }
        }
        Ok(())
    }
    let mut found = vec![base.join("README.md")];
    guides(&base.join("docs"), &mut found)?;
    let crates = base.join("crates");
    let entries =
        std::fs::read_dir(&crates).map_err(|error| format!("{}: {error}", crates.display()))?;
    for entry in entries {
        let readme = entry
            .map_err(|error| format!("{}: {error}", crates.display()))?
            .path()
            .join("README.md");
        if readme.is_file() {
            found.push(readme);
        }
    }
    found.sort();
    Ok(found)
}

fn package_version(run: &mut impl Run) -> Result<String, Failure> {
    let metadata = Step::new(
        "workspace metadata",
        "cargo",
        &["metadata", "--no-deps", "--format-version", "1"],
    );
    let (status, text) = run.stdout(&metadata)?;
    require(status)?;
    let metadata: Value =
        serde_json::from_str(&text).map_err(|error| format!("cargo metadata: {error}"))?;
    Ok(version(&metadata, PACKAGE)
        .ok_or_else(|| format!("workspace package {PACKAGE} was not found"))?)
}

/// Checks the documents under `base` against `wanted`, or rewrites them
/// when `write` is set.
pub(crate) fn execute(base: &Path, wanted: &str, write: bool) -> Result<(), Failure> {
    let mut report = Vec::new();
    for file in documents(base)? {
        let text = std::fs::read_to_string(&file)
            .map_err(|error| format!("{}: {error}", file.display()))?;
        let (aligned, stale) = align(&text, wanted);
        if stale.is_empty() {
            continue;
        }
        let name = file
            .strip_prefix(base)
            .unwrap_or(&file)
            .display()
            .to_string();
        if write {
            std::fs::write(&file, aligned).map_err(|error| format!("{name}: {error}"))?;
            println!(
                "{name}: {} {PACKAGE} declaration(s) now require {wanted}",
                stale.len()
            );
        } else {
            report.extend(stale.iter().map(|stale| {
                format!(
                    "{name}:{}: {PACKAGE} {} where the release line is {wanted}",
                    stale.line, stale.found
                )
            }));
        }
    }
    if report.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{}\nrun `cargo run -p xml-sec-tools -- documentation readme --write`",
            report.join("\n")
        )
        .into())
    }
}

pub(crate) fn run(write: bool) -> Result<(), Failure> {
    let wanted = requirement(&package_version(&mut System)?)?;
    execute(&root(), &wanted, write)
}
