//! `xades dss [--results DIR] [--summarize]`: builds a pinned local EU DSS
//! probe and keeps its independent profile reports. Maven downloads public
//! build dependencies; validation reads only local corpus inputs.

use super::{Corpus, absolute, line, read, write_json, xml};
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};

const MAVEN: &str = "3.9.12";

/// The cases DSS validates. The deliberate external-URI fixtures are never
/// given to another validator.
pub(crate) const CASES: [&str; 9] = [
    "enveloped-control",
    "filter2-subtract",
    "filter2-sequence",
    "c14n11-reference",
    "c14n11-signedinfo",
    "empty-result",
    "baseline-wrong-target",
    "baseline-untyped-signed-properties",
    "baseline-certificate-digest-mismatch",
];

/// The pinned Maven and its repository, outside the corpus.
pub(crate) fn tools(corpus: &Corpus) -> PathBuf {
    corpus.root.join(".tools/xades-dss")
}

pub(crate) fn maven(corpus: &Corpus) -> PathBuf {
    tools(corpus).join(format!("apache-maven-{MAVEN}/bin/mvn"))
}

/// The probe classes and their resolved dependency classpath.
pub(crate) fn classpath(corpus: &Corpus) -> Result<String, String> {
    let resolved = xml::read(&tools(corpus).join("classpath.txt"))?;
    Ok(format!(
        "{}:{}",
        corpus.root.join("target/xades-dss/classes").display(),
        resolved.trim()
    ))
}

/// What a DSS report shows about `XAdES` profile binding. EN 319 102-1 V1.4.1
/// §§5.2.2, 5.2.3.4: base-format FC does not attest `XAdES` profile
/// conformance, and ISC must match the actual signer.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf>
pub(crate) fn profile_binding(name: &str, row: &Map<String, Value>) -> Option<Value> {
    let verdict = |ok: bool| if ok { "verified" } else { "failed" };
    let row = |field: &str| row.get(field).unwrap_or(&Value::Null);
    match name {
        "baseline-wrong-target" => Some(json!({
            "status": "not run or blocked",
            "reason": "FC and format labels do not attest Target binding; see dss-investigation",
        })),
        "baseline-certificate-digest-mismatch" => {
            let refused = row("conclusions")["ISC"] == "INDETERMINATE"
                && row("subindications")["ISC"] == "NO_SIGNING_CERTIFICATE_FOUND";
            Some(json!({
                "status": verdict(refused),
                "reason": "root-only CertDigest must not identify the leaf signing certificate",
            }))
        }
        "baseline-untyped-signed-properties" => Some(json!({
            "status": verdict(*row("reported_format") == "XAdES-BES"),
            "reason": "format classification only; not full profile validation",
        })),
        _ => None,
    }
}

fn optional(text: Option<String>) -> Value {
    text.map_or(Value::Null, Value::from)
}

/// The conclusions DSS reached for one case.
fn summary_row(logs: &Path, name: &str) -> Result<Value, String> {
    let folder = logs.join(name);
    let simple_text = xml::read(&folder.join("simple.xml"))?;
    let diagnostic_text = xml::read(&folder.join("diagnostic.xml"))?;
    let detailed_text = xml::read(&folder.join("detailed.xml"))?;
    let simple_document = xml::parse(&simple_text, "simple report")?;
    let diagnostic_document = xml::parse(&diagnostic_text, "diagnostic report")?;
    let detailed_document = xml::parse(&detailed_text, "detailed report")?;
    let simple = xml::child(simple_document.root_element(), "Signature")
        .ok_or("simple report without a Signature")?;
    let signature = xml::find(
        diagnostic_document.root_element(),
        "Signatures",
        "Signature",
    )
    .ok_or("diagnostic report without a Signature")?;
    let blocks = xml::signature_blocks(detailed_document.root_element())
        .ok_or("detailed report without signature building blocks")?;
    let matchers: Vec<Value> = xml::elements(signature)
        .filter(|node| node.tag_name().name() == "DigestMatchers")
        .flat_map(xml::elements)
        .filter(|node| node.tag_name().name() == "DigestMatcher")
        .map(|matcher| {
            json!({
                "uri": matcher.attribute("uri"),
                "found": optional(xml::text_at(matcher, &["DataFound"])),
                "intact": optional(xml::text_at(matcher, &["DataIntact"])),
            })
        })
        .collect();
    let mut row = Map::new();
    row.insert("name".into(), name.into());
    row.insert(
        "reported_format".into(),
        simple.attribute("SignatureFormat").into(),
    );
    row.insert(
        "indication".into(),
        optional(xml::text_at(simple, &["Indication"])),
    );
    row.insert(
        "subindication".into(),
        optional(xml::text_at(simple, &["SubIndication"])),
    );
    row.insert(
        "signature_intact".into(),
        optional(xml::text_at(
            signature,
            &["BasicSignature", "SignatureIntact"],
        )),
    );
    let intact = row["signature_intact"] == "true"
        && matchers.len() == 2
        && matchers.iter().all(|matcher| matcher["intact"] == "true");
    row.insert("digest_matchers".into(), Value::Array(matchers));
    row.insert(
        "conclusions".into(),
        Value::Object(xml::conclusions(blocks, "Indication")),
    );
    row.insert(
        "subindications".into(),
        Value::Object(xml::conclusions(blocks, "SubIndication")),
    );
    row.insert(
        "crypto_status".into(),
        if intact { "verified" } else { "failed" }.into(),
    );
    if let Some(observation) = profile_binding(name, &row) {
        row.insert("profile_binding".into(), observation);
    }
    Ok(Value::Object(row))
}

/// Reads the retained reports of every case into `summary.json`.
pub(crate) fn summarize(logs: &Path) -> Result<Vec<Value>, String> {
    let summary = CASES
        .iter()
        .map(|name| summary_row(logs, name))
        .collect::<Result<Vec<Value>, String>>()?;
    write_json(&logs.join("summary.json"), &Value::Array(summary.clone()))?;
    Ok(summary)
}

/// Downloads and checks the pinned Maven distribution once.
fn bootstrap(corpus: &Corpus, logs: &Path) -> Result<(), String> {
    use sha2::Digest as _;
    let tools = tools(corpus);
    let archive = tools.join("maven.tar.gz");
    let url = format!(
        "https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/{MAVEN}/apache-maven-{MAVEN}-bin.tar.gz"
    );
    let curl = |extra: &[&dyn AsRef<std::ffi::OsStr>]| {
        let mut args = line(&[&"curl", &"--fail", &"--silent", &"--show-error"]);
        args.extend(line(extra));
        args
    };
    corpus.require(
        &curl(&[&"--output", &archive, &url]),
        &logs.join("download"),
    )?;
    let published = corpus.require(
        &curl(&[&format!("{url}.sha512")]),
        &logs.join("download-sha512"),
    )?;
    let published = String::from_utf8_lossy(&published.stdout);
    let expected = published.split_whitespace().next().unwrap_or_default();
    if super::hex(&sha2::Sha512::digest(read(&archive)?)) != expected {
        return Err("Maven distribution SHA-512 mismatch".into());
    }
    let file = std::fs::File::open(&archive).map_err(|error| error.to_string())?;
    // Unpacking refuses entries that would land outside `tools`.
    tar::Archive::new(flate2::read::GzDecoder::new(file))
        .unpack(&tools)
        .map_err(|error| format!("unpack Maven: {error}"))
}

/// Builds the probe and validates every case with DSS.
pub(crate) fn execute(corpus: &Corpus, logs: &Path) -> Result<(), String> {
    if logs.exists() {
        return Err("results already exist; select a fresh --results directory".into());
    }
    let tools = tools(corpus);
    std::fs::create_dir_all(&tools).map_err(|error| error.to_string())?;
    std::fs::create_dir_all(logs).map_err(|error| error.to_string())?;
    let mvn = maven(corpus);
    if !mvn.exists() {
        bootstrap(corpus, logs)?;
    }
    let package = corpus.package();
    // Build output stays under target, so the repository's cargo clean removes it.
    let mut maven = line(&[
        &mvn,
        &"-B",
        &"-f",
        &package.join("dss/pom.xml"),
        &format!("-Dmaven.repo.local={}", tools.join("repository").display()),
    ]);
    let mut build = maven.clone();
    build.extend(line(&[
        &"compile",
        &"dependency:build-classpath",
        &format!(
            "-Dmdep.outputFile={}",
            tools.join("classpath.txt").display()
        ),
    ]));
    corpus.require(&build, &logs.join("build"))?;
    corpus.require(&line(&[&mvn, &"-v"]), &logs.join("versions"))?;
    maven.extend(line(&[
        &"dependency:tree",
        &"-DoutputType=json",
        &format!("-DoutputFile={}", logs.join("dependencies.json").display()),
    ]));
    corpus.require(&maven, &logs.join("dependencies"))?;
    let cases: Value = serde_json::from_str(&xml::read(&package.join("cases.json"))?)
        .map_err(|error| error.to_string())?;
    let classpath = classpath(corpus)?;
    for name in CASES {
        let file = cases
            .as_array()
            .into_iter()
            .flatten()
            .find(|case| case["name"] == name)
            .and_then(|case| case["file"].as_str())
            .ok_or_else(|| format!("no corpus case {name}"))?;
        let probe = line(&[
            &"java",
            &"-cp",
            &classpath,
            &"Probe",
            &package.join(file),
            &package.join("fixtures/baseline/root.der"),
            &logs.join(name),
        ]);
        corpus.require(&probe, &logs.join(format!("{name}-run")))?;
    }
    if summarize(logs)?
        .iter()
        .any(|row| row["crypto_status"] != "verified")
    {
        return Err("DSS cryptographic control failed; inspect retained reports".into());
    }
    println!(
        "EU DSS 6.5.1: {} local profile reports saved to {}",
        CASES.len(),
        logs.display()
    );
    Ok(())
}

pub(crate) fn run(corpus: &Corpus, args: &[String]) -> Result<(), crate::repo::Failure> {
    let mut logs = corpus.root.join("target/xades-dss-results");
    let mut only_summarize = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--summarize" => only_summarize = true,
            "--results" => logs = absolute(args.next().ok_or("--results needs a directory")?)?,
            _ => return Err("usage: xades dss [--results DIR] [--summarize]".into()),
        }
    }
    if only_summarize {
        summarize(&logs)?;
        return Ok(());
    }
    Ok(execute(corpus, &logs)?)
}
