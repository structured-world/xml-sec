//! `dcc-schema`: validates the PTB Digital Calibration Certificate corpus
//! against the DCC schema PTB publishes now. The schema and every schema it
//! imports are read from PTB when the command runs; no copy is kept, so a new
//! schema release fails the check until the corpus follows it.

use crate::repo::{Failure, Run, Step, System, require, root};
use std::collections::BTreeMap;
use std::ops::Range;
use std::path::{Path, PathBuf};

#[cfg(test)]
mod tests;

/// The current DCC schema release, at PTB's unversioned address.
pub(crate) const SCHEMA: &str = "https://www.ptb.de/dcc/dcc.xsd";
/// The committed corpus documents, relative to the repository root.
pub(crate) const CORPUS: &str = "tests/fixtures/xmldsig/dcc";
const XML_SCHEMA: &str = "http://www.w3.org/2001/XMLSchema";

/// One schema an `xs:import` or `xs:include` names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Import {
    /// The parsed `schemaLocation` value.
    pub(crate) location: String,
    /// The source bytes of that value, between its quotes.
    pub(crate) value: Range<usize>,
}

/// The `schemaLocation` of every `xs:import` and `xs:include` of `xsd`.
pub(crate) fn imports(xsd: &str) -> Result<Vec<Import>, String> {
    let document = xml_sec::XmlDomDocument::parse(xsd).map_err(|error| error.to_string())?;
    document
        .root_element()
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(XML_SCHEMA)
                && matches!(node.tag_name().name(), "import" | "include")
        })
        .filter_map(|node| {
            let location = node.attribute("schemaLocation")?.to_owned();
            Some(location_value(xsd, node.range().start).map(|value| Import { location, value }))
        })
        .collect()
}

const fn is_xml_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

/// The source range of the unprefixed `schemaLocation` value in the start tag
/// at `start`, read with the attribute grammar of XML 1.0 section 3.1:
/// whitespace may surround `=` and either quote may delimit the value.
fn location_value(xsd: &str, start: usize) -> Result<Range<usize>, String> {
    let bytes = xsd.as_bytes();
    let malformed = || format!("malformed start tag at byte {start}");
    let mut at = start + 1;
    while at < bytes.len() && !is_xml_space(bytes[at]) && !matches!(bytes[at], b'/' | b'>') {
        at += 1;
    }
    loop {
        while at < bytes.len() && is_xml_space(bytes[at]) {
            at += 1;
        }
        match bytes.get(at) {
            Some(b'/' | b'>') | None => {
                return Err(format!(
                    "no schemaLocation in the start tag at byte {start}"
                ));
            }
            Some(_) => {}
        }
        let name_start = at;
        while at < bytes.len() && !is_xml_space(bytes[at]) && bytes[at] != b'=' {
            at += 1;
        }
        let name = &xsd[name_start..at];
        while at < bytes.len() && is_xml_space(bytes[at]) {
            at += 1;
        }
        if bytes.get(at) != Some(&b'=') {
            return Err(malformed());
        }
        at += 1;
        while at < bytes.len() && is_xml_space(bytes[at]) {
            at += 1;
        }
        let quote = *bytes
            .get(at)
            .filter(|quote| matches!(quote, b'"' | b'\''))
            .ok_or_else(malformed)?;
        let value_start = at + 1;
        let value_end = value_start
            + xsd[value_start..]
                .bytes()
                .position(|byte| byte == quote)
                .ok_or_else(malformed)?;
        if name == "schemaLocation" {
            return Ok(value_start..value_end);
        }
        at = value_end + 1;
    }
}

/// `xsd` with each import's location value replaced by `local(location)`.
pub(crate) fn relocate(
    xsd: &str,
    imports: &[Import],
    mut local: impl FnMut(&str) -> String,
) -> String {
    let mut ordered: Vec<&Import> = imports.iter().collect();
    ordered.sort_by_key(|import| import.value.start);
    let mut output = String::with_capacity(xsd.len());
    let mut copied = 0;
    for import in ordered {
        output.push_str(&xsd[copied..import.value.start]);
        output.push_str(&local(&import.location));
        copied = import.value.end;
    }
    output.push_str(&xsd[copied..]);
    output
}

/// The length of the scheme of `uri` and its colon, if it has one
/// (RFC 3986 section 3.1).
fn scheme_length(uri: &str) -> Option<usize> {
    let colon = uri.find(':')?;
    let scheme = &uri[..colon];
    (scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
    .then_some(colon + 1)
}

/// RFC 3986 section 5.2.4: `path` without its `.` and `..` segments.
fn remove_dot_segments(path: &str) -> String {
    let mut output: Vec<&str> = Vec::new();
    let segments: Vec<&str> = path.split('/').collect();
    for (index, segment) in segments.iter().enumerate() {
        let last = index + 1 == segments.len();
        match *segment {
            "." => {
                if last {
                    output.push("");
                }
            }
            ".." => {
                if output.len() > 1 {
                    output.pop();
                }
                if last {
                    output.push("");
                }
            }
            segment => output.push(segment),
        }
    }
    output.join("/")
}

/// `location`, a URI reference, resolved against the schema at `base`
/// (RFC 3986 section 5.2.2), as XSD 1.0 Part 1 section 4.2.3 reads it.
pub(crate) fn resolve(base: &str, location: &str) -> String {
    if scheme_length(location).is_some() {
        return location.to_owned();
    }
    let scheme = &base[..scheme_length(base).unwrap_or(0)];
    if location.starts_with("//") {
        return format!("{scheme}{location}");
    }
    let hierarchy = &base[scheme.len()..];
    let (authority, base_path) = match hierarchy.strip_prefix("//") {
        Some(rest) => {
            let end = rest.find('/').unwrap_or(rest.len());
            (&hierarchy[..end + 2], &rest[end..])
        }
        None => ("", hierarchy),
    };
    let base_path = &base_path[..base_path.find(['?', '#']).unwrap_or(base_path.len())];
    let split = location.find(['?', '#']).unwrap_or(location.len());
    let (path, suffix) = location.split_at(split);
    let merged = if path.starts_with('/') {
        path.to_owned()
    } else {
        let directory = base_path.rfind('/').map_or("/", |end| &base_path[..=end]);
        format!("{directory}{path}")
    };
    format!(
        "{scheme}{authority}{}{suffix}",
        remove_dot_segments(&merged)
    )
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
            "--write-out",
            "%{url_effective}",
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
        // RFC 3986 section 5.1.3: the base of a schema is the URI it was
        // finally retrieved from, after the redirects curl followed.
        let (status, retrieved) = run.stdout(&download(&url, &local))?;
        require(status)?;
        if retrieved.is_empty() {
            return Err(format!("{url}: curl reported no retrieved URL").into());
        }
        let base = retrieved.as_str();
        let text = std::fs::read_to_string(&local)
            .map_err(|error| format!("{}: {error}", local.display()))?;
        let found = imports(&text).map_err(|error| format!("{url}: {error}"))?;
        let text = relocate(&text, &found, |location| {
            let absolute = resolve(base, location);
            let next = names.len();
            names
                .entry(absolute.clone())
                .or_insert_with(|| {
                    pending.push(absolute);
                    format!("schema-{next}.xsd")
                })
                .clone()
        });
        std::fs::write(&local, text).map_err(|error| format!("{}: {error}", local.display()))?;
    }
    Ok(directory.join(&names[schema]))
}

/// The corpus documents, in name order.
pub(crate) fn corpus(directory: &Path) -> Result<Vec<PathBuf>, String> {
    let unreadable = |error: std::io::Error| format!("{}: {error}", directory.display());
    let mut documents = Vec::new();
    // An entry that cannot be read fails the check: validating part of the
    // corpus is not validating the corpus.
    for entry in std::fs::read_dir(directory).map_err(unreadable)? {
        let path = entry.map_err(unreadable)?.path();
        if path.extension().is_some_and(|extension| extension == "xml") {
            documents.push(path);
        }
    }
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
