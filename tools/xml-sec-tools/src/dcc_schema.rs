//! `dcc-schema`: validates the PTB Digital Calibration Certificate corpus
//! against the DCC schema PTB publishes now. The schema and every schema it
//! imports are read from PTB when the command runs; no copy is kept, so a new
//! schema release fails the check until the corpus follows it.

use crate::repo::{Failure, Run, Step, System, require, root};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[cfg(test)]
mod tests;

/// The current DCC schema release, at PTB's unversioned address.
pub(crate) const SCHEMA: &str = "https://www.ptb.de/dcc/dcc.xsd";
/// The committed corpus documents, relative to the repository root.
pub(crate) const CORPUS: &str = "tests/fixtures/xmldsig/dcc";
const XML_SCHEMA: &str = "http://www.w3.org/2001/XMLSchema";

/// The `schemaLocation` of every `xs:import` and `xs:include` of `xsd`.
pub(crate) fn imports(xsd: &str) -> Result<Vec<String>, String> {
    let document = xml_sec::XmlDomDocument::parse(xsd).map_err(|error| error.to_string())?;
    Ok(document
        .root_element()
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(XML_SCHEMA)
                && matches!(node.tag_name().name(), "import" | "include")
        })
        .filter_map(|node| node.attribute("schemaLocation").map(str::to_owned))
        .collect())
}

/// `location` as an absolute URL, read relative to the schema at `base`.
pub(crate) fn resolve(base: &str, location: &str) -> String {
    if location.contains("://") {
        return location.to_owned();
    }
    let directory = base.rfind('/').map_or(base, |end| &base[..=end]);
    format!("{directory}{location}")
}

/// `xsd` with the quoted `schemaLocation` value `from` replaced by `to`.
pub(crate) fn relocate(xsd: &str, from: &str, to: &str) -> Result<String, String> {
    for quote in ['"', '\''] {
        let old = format!("schemaLocation={quote}{from}{quote}");
        if xsd.contains(&old) {
            return Ok(xsd.replace(&old, &format!("schemaLocation={quote}{to}{quote}")));
        }
    }
    Err(format!(
        "schemaLocation {from} is not written as a plain attribute"
    ))
}

fn download(url: &str, output: &Path) -> Step {
    let output = output.display().to_string();
    Step::new(
        format!("fetch {url}"),
        "curl",
        &[
            "--fail",
            "--location",
            "--retry",
            "2",
            "--connect-timeout",
            "20",
            "--max-time",
            "120",
            "--silent",
            "--show-error",
            url,
            "-o",
            &output,
        ],
    )
}

/// Reads `schema` and everything it imports into `directory`, each schema
/// pointing at the local copies of its imports. Returns the local entry schema.
pub(crate) fn fetch(
    run: &mut impl Run,
    schema: &str,
    directory: &Path,
) -> Result<PathBuf, Failure> {
    let mut names = BTreeMap::new();
    let mut pending = vec![schema.to_owned()];
    names.insert(schema.to_owned(), "schema-0.xsd".to_owned());
    while let Some(url) = pending.pop() {
        let local = directory.join(&names[&url]);
        require(run.status(&download(&url, &local))?)?;
        let mut text = std::fs::read_to_string(&local)
            .map_err(|error| format!("{}: {error}", local.display()))?;
        for location in imports(&text).map_err(|error| format!("{url}: {error}"))? {
            let absolute = resolve(&url, &location);
            let next = names.len();
            let name = names
                .entry(absolute.clone())
                .or_insert_with(|| {
                    pending.push(absolute.clone());
                    format!("schema-{next}.xsd")
                })
                .clone();
            text = relocate(&text, &location, &name)?;
        }
        std::fs::write(&local, text).map_err(|error| format!("{}: {error}", local.display()))?;
    }
    Ok(directory.join(&names[schema]))
}

/// The corpus documents, in name order.
pub(crate) fn corpus(directory: &Path) -> Result<Vec<PathBuf>, String> {
    let mut documents: Vec<PathBuf> = std::fs::read_dir(directory)
        .map_err(|error| format!("{}: {error}", directory.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "xml"))
        .collect();
    documents.sort();
    if documents.is_empty() {
        return Err(format!("{} holds no corpus document", directory.display()));
    }
    Ok(documents)
}

/// Validates every corpus document against the local entry schema.
pub(crate) fn validate(
    run: &mut impl Run,
    schema: &Path,
    documents: &[PathBuf],
) -> Result<(), Failure> {
    let schema = schema.display().to_string();
    let documents: Vec<String> = documents
        .iter()
        .map(|path| path.display().to_string())
        .collect();
    let mut args = vec!["--nonet", "--noout", "--schema", schema.as_str()];
    args.extend(documents.iter().map(String::as_str));
    require(run.status(&Step::new(
        "validate the DCC corpus against the current PTB schema",
        "xmllint",
        &args,
    ))?)
}

pub(crate) fn run(mut args: impl Iterator<Item = String>) -> Result<(), Failure> {
    if args.next().is_some() {
        return Err("usage: dcc-schema".into());
    }
    let directory = tempfile::tempdir().map_err(|error| error.to_string())?;
    let schema = fetch(&mut System, SCHEMA, directory.path())?;
    validate(&mut System, &schema, &corpus(&root().join(CORPUS))?)
}
