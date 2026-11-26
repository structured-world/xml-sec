//! `xades dss-catalogue [--results DIR]`: every signature and extension test
//! class of EU DSS's `dss-xades`, at the tag of the current DSS release, is
//! classified once in `interop/xades/dss-catalogue.json` as covered by named
//! harness cases, unsupported for a named capability, or not applicable for a
//! named reason. The check fails on a class the release has and the catalogue
//! does not list, on a listed class the release no longer has, and on a case,
//! capability or reason the catalogue does not know.

use super::{Corpus, absolute, line, write_json, xml};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::Path;

#[cfg(test)]
mod tests;

/// Where the test classes live in the DSS tree.
const ROOT: &str = "dss-xades/src/test/java/eu/europa/esig/dss/xades/";

/// The test directories classified, below [`ROOT`].
const DIRECTORIES: [&str; 2] = ["signature", "extension"];

/// The statuses a class takes, each with the catalogue section naming its
/// value; `covered` names cases instead.
const STATUSES: [(&str, Option<&str>); 3] = [
    ("covered", None),
    ("unsupported", Some("capabilities")),
    ("not-applicable", Some("reasons")),
];

/// The test classes among the files of a release tree, as catalogue keys:
/// the path below [`ROOT`] without `.java`, for each `JUnit` class (a file
/// ending in `Test.java`) that is not an abstract base.
pub(crate) fn test_classes(files: &[String]) -> Vec<String> {
    let mut classes: Vec<String> = files
        .iter()
        .filter_map(|path| path.strip_prefix(ROOT))
        .filter(|path| path.ends_with("Test.java"))
        .filter(|path| {
            !path
                .rsplit('/')
                .next()
                .is_some_and(|name| name.starts_with("Abstract"))
        })
        .map(|path| path.trim_end_matches(".java").to_owned())
        .collect();
    classes.sort();
    classes
}

/// Every harness case a catalogue entry may name.
pub(crate) fn known_cases() -> BTreeSet<String> {
    let lifecycle = super::lifecycle::cases()
        .into_iter()
        .map(|case| format!("lifecycle/{}", case.name()));
    let created = super::creation::CASES
        .iter()
        .map(|case| format!("creation/{}", case.name));
    let forms = super::creation::FORMS
        .iter()
        .map(|form| format!("dss-form/{}", form.name));
    lifecycle.chain(created).chain(forms).collect()
}

/// Every way `catalogue` fails to classify exactly `classes` with known
/// `cases`, capabilities and reasons.
pub(crate) fn problems(
    catalogue: &Value,
    classes: &[String],
    cases: &BTreeSet<String>,
) -> Vec<String> {
    let mut found = Vec::new();
    let Some(entries) = catalogue["classes"].as_object() else {
        return vec!["the catalogue has no classes object".into()];
    };
    for class in classes {
        if !entries.contains_key(class) {
            found.push(format!("{class}: not in the catalogue"));
        }
    }
    let mut used = BTreeSet::new();
    for (class, entry) in entries {
        if !classes.contains(class) {
            found.push(format!("{class}: not a test class of the release"));
        }
        let statuses: Vec<&str> = STATUSES
            .iter()
            .map(|(status, _)| *status)
            .filter(|status| !entry[*status].is_null())
            .collect();
        let [status] = statuses[..] else {
            found.push(format!(
                "{class}: {} statuses, one expected",
                statuses.len()
            ));
            continue;
        };
        if entry.as_object().is_some_and(|fields| fields.len() != 1) {
            found.push(format!("{class}: fields beside its status"));
        }
        // One name, or several: a class may lack more than one capability.
        let named: Vec<&str> = match &entry[status] {
            Value::String(name) => vec![name.as_str()],
            Value::Array(names) => names.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        if named.is_empty() {
            found.push(format!("{class}: {status} names nothing"));
        }
        let section = STATUSES
            .iter()
            .find_map(|(name, section)| (*name == status).then_some(*section))
            .flatten();
        for name in named {
            // A definition is known only with a description that says why.
            let known = section.map_or_else(
                || cases.contains(name),
                |section| {
                    catalogue[section][name]
                        .as_str()
                        .is_some_and(|description| !description.trim().is_empty())
                },
            );
            if !known {
                found.push(format!("{class}: {status} names unknown {name:?}"));
            }
            if let Some(section) = section {
                used.insert((section.to_owned(), name.to_owned()));
            }
        }
    }
    // A capability or reason no class names describes nothing.
    for (_, section) in STATUSES {
        let Some(section) = section else { continue };
        for key in catalogue[section]
            .as_object()
            .into_iter()
            .flatten()
            .map(|(key, _)| key)
        {
            if !used.contains(&(section.to_owned(), key.clone())) {
                found.push(format!("{section}: {key:?} is named by no class"));
            }
        }
    }
    found
}

/// How many classes take each status.
pub(crate) fn counts(catalogue: &Value) -> Value {
    let entries = catalogue["classes"].as_object();
    let count = |status: &str| {
        entries
            .into_iter()
            .flatten()
            .filter(|(_, entry)| !entry[status].is_null())
            .count()
    };
    json!({
        "covered": count("covered"),
        "unsupported": count("unsupported"),
        "not-applicable": count("not-applicable"),
    })
}

/// Lists the release's test classes and checks the catalogue against them.
fn execute(corpus: &Corpus, results: &Path) -> Result<(), String> {
    if results.exists() {
        return Err("results already exist; select a fresh --results directory".into());
    }
    std::fs::create_dir_all(results).map_err(|error| error.to_string())?;
    let release = super::dss::resolve(corpus, results)?;
    let (checkout, commit) = super::upstream::fetch(corpus, &release.dss, results)?;
    // The tree objects of the release hold every path; the blobs stay unfetched.
    let mut listing = line(&[
        &"git",
        &"-C",
        &checkout,
        &"ls-tree",
        &"-r",
        &"-z",
        &"--full-tree",
        &commit,
        &"--",
    ]);
    listing.extend(
        DIRECTORIES
            .iter()
            .map(|directory| format!("{ROOT}{directory}").into()),
    );
    let run = corpus.require(&listing, &results.join("tests-tree"))?;
    let classes = test_classes(&super::upstream::regular_files(&run.stdout)?);
    let path = corpus.package().join("dss-catalogue.json");
    let catalogue: Value = serde_json::from_str(&xml::read(&path)?)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let found = problems(&catalogue, &classes, &known_cases());
    write_json(
        &results.join("summary.json"),
        &json!({
            "dss": release.dss,
            "commit": commit,
            "classes": classes.len(),
            "counts": counts(&catalogue),
            "problems": found,
        }),
    )?;
    if !found.is_empty() {
        return Err(format!(
            "{} does not classify the DSS {} test classes:\n{}",
            path.display(),
            release.dss,
            found.join("\n")
        ));
    }
    println!(
        "EU DSS {}: {} signature and extension test classes classified ({})",
        release.dss,
        classes.len(),
        counts(&catalogue)
    );
    Ok(())
}

pub(crate) fn run(corpus: &Corpus, args: &[String]) -> Result<(), crate::repo::Failure> {
    let mut results = corpus.root.join("target/xades-dss-catalogue");
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--results" => results = absolute(args.next().ok_or("--results needs a directory")?)?,
            _ => return Err("usage: xades dss-catalogue [--results DIR]".into()),
        }
    }
    Ok(execute(corpus, &results)?)
}
