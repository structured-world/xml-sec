//! `security-corpus check|report|import LIBXML2_SOURCE DATA_DIR LIBXSLT_SOURCE`:
//! the pinned upstream security corpus, the advisory inventory and the
//! explicit per-advisory dispositions.

use crate::repo::{Failure, root};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[cfg(test)]
mod tests;

const XML_COMMIT: &str = "c79c9612fcc77b06b0d16f35fd363d938bdbbf5e";
const XSLT_COMMIT: &str = "81cbfb53bb1bc034853058ff896203d108b663cc";
const SAML_COMMIT: &str = "46578df0695269a16f1c94171f1429873f90ed99";
const XML_PATHS: [&str; 7] = [
    "test/errors",
    "test/errors10",
    "test/recurse",
    "test/XPath",
    "test/valid/766956.xml",
    "test/valid/dtds/766956.dtd",
    "Copyright",
];
const XSLT_PATHS: [&str; 6] = [
    "Copyright",
    "tests/security/input.xml",
    "tests/security/load_document.xsl",
    "tests/security/write_output.xsl",
    "tests/security/xinclude_doc.xml",
    "tests/security/secret.xml",
];
const SAML_PATHS: [&str; 4] = [
    "LICENSE",
    "tests/xmlsec1-keydata/signed-assertion-random-embedded-cert.xml",
    "tests/xmlsec1-keydata/signed-assertion-with-hmac.xml",
    "tests/xmlsec1-keydata/signed-response-with-hmac.xml",
];
const NVD_PRODUCTS: [&str; 6] = [
    "libxml2",
    "libxslt",
    "xmlsec",
    "libxml",
    "cpe-libxml2",
    "cpe-libxslt",
];

fn destination() -> PathBuf {
    root().join("tests/fixtures/security")
}

/// An advisory record or a disposition, in its written field order.
pub(crate) type Row = Map<String, Value>;
/// Dispositions by advisory identifier.
pub(crate) type Table = BTreeMap<String, Row>;

pub(crate) fn sha256(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        hex.push(char::from(HEX[usize::from(byte >> 4)]));
        hex.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    hex
}

/// A corpus path that cannot escape its pinned root.
pub(crate) fn safe_path(path: &str) -> Result<&str, String> {
    let safe = !path.is_empty()
        && !path.contains('\\')
        && !path.starts_with('/')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..");
    if safe {
        Ok(path)
    } else {
        Err(format!("unsafe corpus path: {path}"))
    }
}

/// The record of `id`, created on first sight, with `product` and `source`
/// added to its contributing searches.
fn entry<'a>(
    rows: &'a mut BTreeMap<String, Row>,
    id: &str,
    product: &str,
    source: &str,
) -> Result<&'a mut Row, String> {
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    let mut parts = id.split('-');
    let valid = parts.next() == Some("CVE")
        && parts
            .next()
            .is_some_and(|year| year.len() == 4 && digits(year))
        && parts.next().is_some_and(digits)
        && parts.next().is_none();
    if !valid {
        return Err(format!("not an advisory identifier: {id}"));
    }
    let row = rows.entry(id.to_owned()).or_insert_with(|| {
        let mut row = Map::new();
        row.insert("id".into(), json!(id));
        for field in ["products", "sources", "references"] {
            row.insert(field.into(), json!([]));
        }
        row
    });
    for (field, value) in [("products", product), ("sources", source)] {
        let list = row[field].as_array_mut().expect("a list field");
        if !list.iter().any(|item| item == value) {
            list.push(json!(value));
        }
    }
    Ok(row)
}

/// The advisory records of the NVD searches (`product -> response`, in query
/// order) and the Debian tracker, merged by identifier and sorted.
pub(crate) fn inventory(nvd: &[(String, Value)], debian: &Value) -> Result<Vec<Value>, String> {
    let mut rows: BTreeMap<String, Row> = BTreeMap::new();
    for (product, data) in nvd {
        let vulnerabilities = data["vulnerabilities"]
            .as_array()
            .ok_or("NVD response without vulnerabilities")?;
        let total = data.get("totalResults").and_then(Value::as_u64);
        if total.is_some_and(|total| usize::try_from(total).ok() != Some(vulnerabilities.len())) {
            return Err("all NVD pages must be present".into());
        }
        for vulnerability in vulnerabilities {
            let cve = &vulnerability["cve"];
            let id = cve["id"]
                .as_str()
                .ok_or("NVD record without an identifier")?;
            let product = product.strip_prefix("cpe-").unwrap_or(product);
            let row = entry(&mut rows, id, product, "nvd")?;
            let description = cve["descriptions"]
                .as_array()
                .and_then(|values| values.iter().find(|value| value["lang"] == "en"))
                .and_then(|value| value["value"].as_str())
                .ok_or_else(|| format!("{id}: no English description"))?;
            row.insert("description".into(), json!(description));
            row.insert("published".into(), cve["published"].clone());
            row.insert("status".into(), cve["vulnStatus"].clone());
            let mut references: Vec<String> = row["references"]
                .as_array()
                .into_iter()
                .flatten()
                .chain(
                    cve["references"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .map(|value| &value["url"]),
                )
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
            references.sort();
            references.dedup();
            row.insert("references".into(), json!(references));
        }
    }
    for product in ["libxml2", "libxslt", "xmlsec1"] {
        let Some(records) = debian.get(product).and_then(Value::as_object) else {
            continue;
        };
        for (id, value) in records.iter().filter(|(id, _)| id.starts_with("CVE-")) {
            let product = if product == "xmlsec1" {
                "xmlsec"
            } else {
                product
            };
            let row = entry(&mut rows, id, product, "debian")?;
            if row.get("description").is_none_or(Value::is_null)
                && let Some(description) = value.get("description").filter(|value| !value.is_null())
            {
                row.insert("description".into(), description.clone());
            }
        }
    }
    Ok(rows.into_values().map(Value::Object).collect())
}

/// The reviewed disposition of each advisory identifier.
pub(crate) fn disposition_table(groups: &Value) -> Result<Table, String> {
    let mut by_id = BTreeMap::new();
    for group in groups.as_array().ok_or("dispositions must be a list")? {
        let mut disposition = group
            .as_object()
            .ok_or("a disposition must be an object")?
            .clone();
        let ids = disposition
            .remove("ids")
            .ok_or("a disposition without identifiers")?;
        for id in ids.as_array().ok_or("identifiers must be a list")? {
            let id = id.as_str().ok_or("identifiers must be strings")?;
            if by_id.insert(id.to_owned(), disposition.clone()).is_some() {
                return Err(format!("duplicate disposition: {id}"));
            }
        }
    }
    Ok(by_id)
}

/// The records of `data` with their dispositions, refusing any unclassified one.
fn classified<'a>(data: &'a Value, table: &'a Table) -> Result<Vec<(&'a Value, &'a Row)>, String> {
    data["records"]
        .as_array()
        .ok_or("advisory snapshot without records")?
        .iter()
        .map(|row| {
            let id = row["id"].as_str().unwrap_or_default();
            table
                .get(id)
                .map(|disposition| (row, disposition))
                .ok_or_else(|| format!("every advisory needs an explicit disposition: {id}"))
        })
        .collect()
}

/// The machine-readable audit, bound to the complete advisory snapshot.
pub(crate) fn audit(data: &Value, table: &Table) -> Result<String, String> {
    let snapshot = serde_json::to_string(data).map_err(|error| error.to_string())?;
    let records: Vec<Value> = classified(data, table)?
        .into_iter()
        .map(|(row, disposition)| {
            let mut record = Map::new();
            record.insert("id".into(), row["id"].clone());
            record.extend(disposition.clone());
            Value::Object(record)
        })
        .collect();
    let audit = json!({ "advisorySha256": sha256(snapshot.as_bytes()), "records": records });
    let text = serde_json::to_string_pretty(&audit).map_err(|error| error.to_string())?;
    Ok(format!("{text}\n"))
}

fn text<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field].as_str().unwrap_or_default()
}

/// Replaces every run of whitespace with one space, keeping the ends.
pub(crate) fn collapse_whitespace(text: &str) -> String {
    let mut collapsed = String::with_capacity(text.len());
    let mut in_space = false;
    for c in text.chars() {
        if c.is_whitespace() || c == '\u{feff}' {
            if !in_space {
                collapsed.push(' ');
            }
            in_space = true;
        } else {
            collapsed.push(c);
            in_space = false;
        }
    }
    collapsed
}

/// The generated inventory page.
pub(crate) fn report(
    data: &Value,
    table: &BTreeMap<String, Map<String, Value>>,
) -> Result<String, String> {
    let rows = classified(data, table)?;
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for (_, disposition) in &rows {
        *counts
            .entry(disposition["status"].as_str().unwrap_or_default())
            .or_default() += 1;
    }
    let mut lines: Vec<String> = [
        "# CVE Inventory",
        "",
        "Generated by `cargo run -p xml-sec-tools -- security-corpus report`; see [audit scope and methods](cve-audit.md).",
        "",
    ]
    .map(String::from)
    .to_vec();
    lines.push(format!(
        "Snapshot: {}. This is a source-scoped inventory, not a claim that every CVE is reproduced.",
        text(data, "auditedAt")
    ));
    lines.push(String::new());
    lines.extend(
        counts
            .iter()
            .map(|(status, count)| format!("- {status}: {count}")),
    );
    lines.extend(
        [
            "",
            "## Unqualified Public Triggers",
            "",
            "The following records remain unresolved as individual reproductions. Public descriptions/references",
            "were retained, but no exact trigger was qualified. This does not prove that no public data exists,",
            "and does not mean non-applicability or successful security coverage.",
            "",
        ]
        .map(String::from),
    );
    for (row, disposition) in &rows {
        if disposition["status"] == "insufficient-public-detail" {
            let id = text(row, "id");
            let description = collapse_whitespace(text(row, "description"));
            lines.push(format!(
                "- [{id}](https://nvd.nist.gov/vuln/detail/{id}): {description}"
            ));
        }
    }
    lines.extend(
        [
            "",
            "## Per-Advisory Disposition",
            "",
            "Reasons and source references are in the [machine-readable audit](../tests/fixtures/security/audit.json)",
            "and [advisory snapshot](../tests/fixtures/security/advisories.json).",
            "",
            "| Advisory | Search products | Disposition | Mechanism / evidence |",
            "| --- | --- | --- | --- |",
        ]
        .map(String::from),
    );
    for (row, disposition) in &rows {
        let id = text(row, "id");
        let products: Vec<&str> = row["products"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let evidence = disposition["evidence"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let link = if evidence.starts_with("https://") {
            evidence
        } else {
            format!("../{evidence}")
        };
        lines.push(format!(
            "| [{id}](https://nvd.nist.gov/vuln/detail/{id}) | {} | {} | [{}]({link}) |",
            products.join(", "),
            disposition["status"].as_str().unwrap_or_default(),
            disposition["mechanism"].as_str().unwrap_or_default(),
        ));
    }
    lines.push(String::new());
    Ok(lines.join("\n"))
}

/// Every file below `directory`, as sorted `/`-separated relative paths.
fn files(directory: &Path) -> Result<Vec<String>, String> {
    let mut found = Vec::new();
    let mut pending = vec![(directory.to_path_buf(), String::new())];
    while let Some((directory, prefix)) = pending.pop() {
        let entries = std::fs::read_dir(&directory)
            .map_err(|error| format!("read {}: {error}", directory.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| error.to_string())?;
            let path = format!("{prefix}{}", entry.file_name().to_string_lossy());
            if entry
                .file_type()
                .map_err(|error| error.to_string())?
                .is_dir()
            {
                pending.push((entry.path(), format!("{path}/")));
            } else {
                found.push(path);
            }
        }
    }
    found.sort();
    Ok(found)
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))
}

fn read_text(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|error| format!("read {}: {error}", path.display()))
}

fn json_file(path: &Path) -> Result<Value, String> {
    serde_json::from_str(&read_text(path)?)
        .map_err(|error| format!("parse {}: {error}", path.display()))
}

fn table() -> Result<BTreeMap<String, Map<String, Value>>, String> {
    disposition_table(&json_file(&destination().join("dispositions.json"))?)
}

/// Verifies one manifest (`digest\tpath[\tsource]` lines) against its directory.
fn verify_manifest(manifest: &str, directory: &str, columns: usize) -> Result<Vec<String>, String> {
    let destination = destination();
    let mut paths = Vec::new();
    for line in read_text(&destination.join(manifest))?.trim().lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != columns {
            return Err(format!("{manifest}: malformed line: {line}"));
        }
        let path = safe_path(fields[1])?;
        if columns == 3
            && !fields[2].starts_with(&format!(
                "https://raw.githubusercontent.com/IdentityPython/pysaml2/{SAML_COMMIT}/"
            ))
        {
            return Err(format!("{manifest}: unpinned source: {}", fields[2]));
        }
        if sha256(&read(&destination.join(directory).join(path))?) != fields[0] {
            return Err(format!("{manifest}: digest mismatch: {path}"));
        }
        paths.push(path.to_owned());
    }
    paths.sort();
    if files(&destination.join(directory))? != paths {
        return Err(format!("{directory}: missing or unlisted payloads"));
    }
    Ok(paths)
}

pub(crate) fn check() -> Result<String, String> {
    let destination = destination();
    let upstream = verify_manifest("files.tsv", "libxml2", 2)?;
    let data = json_file(&destination.join("advisories.json"))?;
    if data["xmlCommit"] != XML_COMMIT || data["xsltCommit"] != XSLT_COMMIT {
        return Err("the advisory snapshot names different upstream commits".into());
    }
    verify_manifest("xslt-files.tsv", "libxslt", 2)?;
    verify_manifest("pysaml2-files.tsv", "pysaml2", 3)?;
    let table = table()?;
    let records = data["records"]
        .as_array()
        .ok_or("advisory snapshot without records")?;
    let ids: std::collections::BTreeSet<&str> = records
        .iter()
        .filter_map(|row| row["id"].as_str())
        .collect();
    if ids.len() != records.len() {
        return Err("duplicate advisory records".into());
    }
    for (_, disposition) in classified(&data, &table)? {
        let evidence = disposition["evidence"].as_str().unwrap_or_default();
        if !evidence.starts_with("https://") {
            read(&root().join(safe_path(evidence)?))?;
        }
    }
    if read_text(&destination.join("audit.json"))? != audit(&data, &table)? {
        return Err("stale audit report".into());
    }
    if read_text(&root().join("docs/cve-inventory.md"))? != report(&data, &table)? {
        return Err("stale inventory report".into());
    }
    Ok(format!(
        "{} advisory records; {} upstream files verified",
        records.len(),
        upstream.len()
    ))
}

fn regenerate() -> Result<(), String> {
    let destination = destination();
    let data = json_file(&destination.join("advisories.json"))?;
    let table = table()?;
    std::fs::write(destination.join("audit.json"), audit(&data, &table)?)
        .map_err(|error| error.to_string())?;
    std::fs::write(root().join("docs/cve-inventory.md"), report(&data, &table)?)
        .map_err(|error| error.to_string())
}

/// Runs `program` and returns its stdout; `input` is written to its stdin.
fn output(program: &str, args: &[&str], input: Option<&[u8]>) -> Result<Vec<u8>, String> {
    let mut child = Command::new(program)
        .args(args)
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|error| format!("{program}: {error}"))?;
    if let (Some(input), Some(mut stdin)) = (input, child.stdin.take()) {
        std::io::Write::write_all(&mut stdin, input)
            .map_err(|error| format!("{program}: {error}"))?;
    }
    let result = child
        .wait_with_output()
        .map_err(|error| format!("{program}: {error}"))?;
    if result.status.success() {
        Ok(result.stdout)
    } else {
        Err(format!(
            "{program} {}: {}",
            args.join(" "),
            crate::repo::describe(result.status)
        ))
    }
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    std::fs::write(path, bytes).map_err(|error| format!("write {}: {error}", path.display()))
}

fn manifest(lines: &[String]) -> String {
    format!("{}\n", lines.join("\n"))
}

fn import(source: &Path, data_dir: &Path, xslt_source: &Path) -> Result<(), String> {
    let destination = destination();
    let temp = tempfile::Builder::new()
        .prefix("xml-security-corpus-")
        .tempdir()
        .map_err(|error| error.to_string())?;
    let source = source.display().to_string();
    let mut archive_args = vec!["-C", &source, "archive", XML_COMMIT];
    archive_args.extend(XML_PATHS);
    let archive = output("git", &archive_args, None)?;
    let temp_path = temp.path().display().to_string();
    output("tar", &["-xf", "-", "-C", &temp_path], Some(&archive))?;
    let mut upstream = Vec::new();
    for path in files(temp.path())? {
        let bytes = read(&temp.path().join(&path))?;
        write(&destination.join("libxml2").join(&path), &bytes)?;
        upstream.push(format!("{}\t{path}", sha256(&bytes)));
    }
    write(
        &destination.join("files.tsv"),
        manifest(&upstream).as_bytes(),
    )?;
    let xslt_source = xslt_source.display().to_string();
    let mut xslt = Vec::new();
    for path in XSLT_PATHS {
        let bytes = output(
            "git",
            &["-C", &xslt_source, "show", &format!("{XSLT_COMMIT}:{path}")],
            None,
        )?;
        write(&destination.join("libxslt").join(path), &bytes)?;
        xslt.push(format!("{}\t{path}", sha256(&bytes)));
    }
    write(
        &destination.join("xslt-files.tsv"),
        manifest(&xslt).as_bytes(),
    )?;
    let mut saml = Vec::new();
    for path in SAML_PATHS {
        let url = format!(
            "https://raw.githubusercontent.com/IdentityPython/pysaml2/{SAML_COMMIT}/{path}"
        );
        let bytes = output(
            "curl",
            &["--fail", "--silent", "--show-error", "--location", &url],
            None,
        )?;
        write(&destination.join("pysaml2").join(path), &bytes)?;
        saml.push(format!("{}\t{path}\t{url}", sha256(&bytes)));
    }
    write(
        &destination.join("pysaml2-files.tsv"),
        manifest(&saml).as_bytes(),
    )?;
    let mut nvd = Vec::new();
    let mut queries = Map::new();
    for product in NVD_PRODUCTS {
        let bytes = read(&data_dir.join(format!("xml-sec-nvd-{product}.json")))?;
        let data: Value = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        let selector = match product.strip_prefix("cpe-") {
            Some(product) => format!("virtualMatchString=cpe:2.3:a:xmlsoft:{product}"),
            None => format!("keywordSearch={product}"),
        };
        queries.insert(
            product.into(),
            json!({
                "selector": selector,
                "timestamp": data["timestamp"],
                "totalResults": data["totalResults"],
                "sha256": sha256(&bytes),
            }),
        );
        nvd.push((product.to_owned(), data));
    }
    let debian_bytes = read(&data_dir.join("xml-sec-cve-tracker.json"))?;
    let debian: Value = serde_json::from_slice(&debian_bytes).map_err(|error| error.to_string())?;
    let advisories = json!({
        "auditedAt": "2026-10-22",
        "sources": {
            "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "debian": "https://security-tracker.debian.org/tracker/data/json",
            "debianSha256": sha256(&debian_bytes),
            "queries": queries,
        },
        "xmlCommit": XML_COMMIT,
        "xsltCommit": XSLT_COMMIT,
        "records": inventory(&nvd, &debian)?,
    });
    let text = serde_json::to_string_pretty(&advisories).map_err(|error| error.to_string())?;
    write(
        &destination.join("advisories.json"),
        format!("{text}\n").as_bytes(),
    )
}

pub(crate) fn run(mut args: impl Iterator<Item = String>) -> Result<(), Failure> {
    match args.next().as_deref() {
        Some("check") => println!("{}", check()?),
        Some("report") => regenerate()?,
        Some("import") => {
            let (Some(source), Some(data), Some(xslt)) = (args.next(), args.next(), args.next())
            else {
                return Err("import LIBXML2_SOURCE NVD_AND_DEBIAN_DIRECTORY LIBXSLT_SOURCE".into());
            };
            let absolute =
                |path: &str| std::path::absolute(path).map_err(|error| format!("{path}: {error}"));
            import(&absolute(&source)?, &absolute(&data)?, &absolute(&xslt)?)?;
        }
        _ => return Err("usage: xml-sec-tools security-corpus check|report|import ...".into()),
    }
    Ok(())
}
