//! `xades check --output DIR`: the mandatory live corpus check. Every actual
//! output stays in a fresh run directory; reference data is never updated.

use super::package::{Evidence, tracked, walk};
use super::{Corpus, absolute, compare, digest, line, read, write_json, xml};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Every `expected-*.bin` below `directory`, relative to it.
fn goldens(directory: &Path) -> Result<BTreeSet<PathBuf>, String> {
    let mut files = Vec::new();
    walk(directory, &mut files)?;
    Ok(files
        .into_iter()
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    // Goldens are written by this tool with exactly this name form.
                    name.strip_prefix("expected-")
                        .and_then(|rest| rest.strip_suffix(".bin"))
                        .is_some()
                })
        })
        .filter_map(|path| path.strip_prefix(directory).ok().map(Path::to_owned))
        .collect())
}

/// Every independently captured octet vector must be produced again
/// identically, empty vectors included; returns how many were compared.
pub(crate) fn check_goldens(expected: &Path, actual: &Path) -> Result<usize, String> {
    let (wanted, produced) = (goldens(expected)?, goldens(actual)?);
    if wanted.is_empty() || wanted != produced {
        let names = |set: BTreeSet<&PathBuf>| {
            set.iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
        };
        return Err(format!(
            "golden inventory mismatch: missing={:?}, extra={:?}",
            names(wanted.difference(&produced).collect()),
            names(produced.difference(&wanted).collect())
        ));
    }
    let report = actual.join("golden-comparison.json");
    let mut comparisons = Vec::new();
    for path in &wanted {
        let comparison = compare(&read(&expected.join(path))?, &read(&actual.join(path))?);
        // The message repeats the failed comparison; a match needs no copy.
        let failure = (comparison["status"] != "verified").then(|| {
            let detail = Value::Object(comparison.clone());
            format!("golden mismatch: {}: {detail}", path.display())
        });
        let mut result = serde_json::Map::new();
        result.insert("file".into(), path.display().to_string().into());
        result.extend(comparison);
        comparisons.push(Value::Object(result));
        if let Some(failure) = failure {
            write_json(&report, &Value::Array(comparisons))?;
            return Err(failure);
        }
    }
    write_json(&report, &Value::Array(comparisons))?;
    Ok(wanted.len())
}

/// A live summary must state exactly the retained conclusions.
pub(crate) fn check_expectations(expected: &Path, actual: &Path) -> Result<(), String> {
    let parse = |path: &Path| -> Result<Value, String> {
        serde_json::from_str(&xml::read(path)?)
            .map_err(|error| format!("{}: {error}", path.display()))
    };
    if parse(expected)? != parse(actual)? {
        return Err(format!(
            "DSS expectation mismatch: {}; inspect {}",
            expected.display(),
            actual.display()
        ));
    }
    Ok(())
}

/// Rejects unreviewed assets and stale corpus hashes, independently of
/// packaging. `tracked` lists the corpus paths Git tracks.
pub(crate) fn check_inventory(
    root: &Path,
    package: &Path,
    tracked: &[String],
) -> Result<(), String> {
    let evidence = Evidence::load(package)?;
    for path in tracked {
        if !evidence.includes(&root.join(path)) {
            return Err(format!(
                "run artifact or undeclared corpus file tracked by Git: {path}"
            ));
        }
    }
    let mut inventory = std::collections::BTreeMap::new();
    for line in xml::read(&package.join("SHA256SUMS"))?.lines() {
        let (expected, path) = line
            .split_once("  ")
            .ok_or_else(|| format!("malformed inventory line: {line}"))?;
        if inventory
            .insert(path.to_owned(), expected.to_owned())
            .is_some()
        {
            return Err(format!("duplicate corpus inventory entry: {path}"));
        }
    }
    let files = evidence.files()?;
    let declared: BTreeSet<String> = files
        .iter()
        .filter_map(|file| {
            file.strip_prefix(root)
                .ok()
                .map(|path| path.display().to_string())
        })
        .collect();
    if declared != inventory.keys().cloned().collect::<BTreeSet<String>>() {
        return Err("corpus inventory differs from declared assets; refresh explicitly".into());
    }
    for file in files {
        let path = file
            .strip_prefix(root)
            .map_err(|error| error.to_string())?
            .display()
            .to_string();
        if file.is_symlink() || inventory.get(&path) != Some(&digest(&read(&file)?)) {
            return Err(format!("corpus checksum mismatch: {path}"));
        }
    }
    Ok(())
}

/// The corpus paths Git tracks.
fn execute(corpus: &Corpus, output: &Path) -> Result<(), String> {
    if output.exists() {
        return Err("select a fresh output directory".into());
    }
    std::fs::create_dir_all(output)
        .map_err(|error| format!("create {}: {error}", output.display()))?;
    let package = corpus.package();
    check_inventory(
        &corpus.root,
        &package,
        &tracked(&corpus.root, "interop/xades")?,
    )?;
    let harness = line(&[
        &"cargo",
        &"nextest",
        &"run",
        &"-p",
        &"xml-sec-tools",
        &"xades",
    ]);
    corpus.require(&harness, &output.join("harness"))?;
    let failures = super::corpus::run_all(corpus, &output.join("xmldsig"))?;
    if !failures.is_empty() {
        return Err(format!(
            "live corpus check failed: {}; inspect {}",
            failures.join(", "),
            output.display()
        ));
    }
    let mut count = check_goldens(&package.join("results"), &output.join("xmldsig"))?;
    super::dss::execute(corpus, &output.join("dss"))?;
    check_expectations(
        &package.join("dss-evidence/expectations.json"),
        &output.join("dss/summary.json"),
    )?;
    let binding = output.join("binding");
    super::binding::execute(corpus, &binding, false)?;
    count += check_goldens(&package.join("dss-investigation"), &binding)?;
    check_expectations(
        &package.join("dss-investigation/expectations.json"),
        &binding.join("summary.json"),
    )?;
    super::binding::execute(corpus, &binding, true)?;
    check_expectations(
        &package.join("dss-investigation/strict-policy-expectations.json"),
        &binding.join("strict-policy-summary.json"),
    )?;
    println!(
        "verified: live XMLDSig/XAdES, {count} independent octet vectors, DSS and strict-policy expectations"
    );
    Ok(())
}

pub(crate) fn run(corpus: &Corpus, args: &[String]) -> Result<(), crate::repo::Failure> {
    match args {
        [flag, output] if flag == "--output" => Ok(execute(corpus, &absolute(output)?)?),
        _ => Err("usage: xades check --output DIR".into()),
    }
}
