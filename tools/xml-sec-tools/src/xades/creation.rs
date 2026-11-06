//! `xades creation [--results DIR]`: EU DSS's independent reading of the B-B
//! signatures xml-sec creates. The `create_probe` example signs every packaging
//! mode with the creation fixtures; DSS must classify each signature as
//! XAdES-BASELINE-B, find it cryptographically intact with every reference
//! found and intact, and identify the signing certificate.

use super::{Corpus, absolute, line, xml};
use serde_json::{Map, Value, json};
use std::path::Path;

#[cfg(test)]
mod tests;

/// Each created document and how many signatures DSS must report in it.
pub(crate) const CASES: [(&str, usize); 6] = [
    ("enveloped", 1),
    ("enveloping", 1),
    ("internally-detached", 1),
    ("detached", 1),
    ("parallel", 2),
    // The countersignature is a signature of its own in DSS's reports.
    ("countersigned", 2),
];

/// The instant the probe assesses at, inside every creation certificate.
const TIME: &str = "1800000000";

/// What DSS concluded on one created document, and why it does not qualify.
pub(crate) fn assess(
    case: &str,
    signatures: usize,
    output: &str,
    reports: &Path,
) -> Result<Value, String> {
    let mut problems = Vec::new();
    // LevelProbe prints one line per signature it found.
    let lines: Vec<&str> = output
        .lines()
        .filter(|line| line.contains(" format="))
        .collect();
    if lines.len() != signatures {
        problems.push(format!(
            "{} signatures reported, {signatures} expected",
            lines.len()
        ));
    }
    for line in &lines {
        if !line.contains(" format=XAdES-BASELINE-B ") {
            problems.push(format!("not XAdES-BASELINE-B: {line}"));
        }
    }
    let diagnostic_text = xml::read(&reports.join("diagnostic.xml"))?;
    let diagnostic = xml::parse(&diagnostic_text, "diagnostic report")?;
    let mut intact = Vec::new();
    for signature in xml::below(diagnostic.root_element(), "Signature", None)
        .filter(|node| xml::child(*node, "BasicSignature").is_some())
    {
        let id = signature.attribute("Id").unwrap_or_default();
        let signature_intact = xml::text_at(signature, &["BasicSignature", "SignatureIntact"])
            .as_deref()
            == Some("true");
        let matchers: Vec<(String, bool)> = xml::below(signature, "DigestMatcher", None)
            .map(|matcher| {
                let true_at = |field| xml::text_at(matcher, &[field]).as_deref() == Some("true");
                (
                    matcher.attribute("uri").unwrap_or_default().to_owned(),
                    true_at("DataFound") && true_at("DataIntact"),
                )
            })
            .collect();
        if !signature_intact {
            problems.push(format!("{id}: signature value not intact"));
        }
        for (uri, ok) in &matchers {
            if !ok {
                problems.push(format!("{id}: reference {uri:?} not found or not intact"));
            }
        }
        intact.push(
            json!({ "id": id, "signature_intact": signature_intact, "references": matchers.len() }),
        );
    }
    let detailed_text = xml::read(&reports.join("detailed.xml"))?;
    let detailed = xml::parse(&detailed_text, "detailed report")?;
    let mut blocks = Vec::new();
    // DSS validates a countersignature in a block of its own type.
    for block in xml::below(detailed.root_element(), "BasicBuildingBlocks", None).filter(|block| {
        matches!(
            block.attribute("Type"),
            Some("SIGNATURE" | "COUNTER_SIGNATURE")
        )
    }) {
        let conclusions = xml::conclusions(block, "Indication");
        // EN 319 102-1 V1.4.1 §5.2.3: identification of the signing
        // certificate; §5.2.7: cryptographic verification.
        for (name, required) in [("ISC", "PASSED"), ("CV", "PASSED")] {
            if conclusions.get(name).and_then(Value::as_str) != Some(required) {
                problems.push(format!(
                    "{}: {name} is {:?}",
                    block.attribute("Id").unwrap_or_default(),
                    conclusions.get(name)
                ));
            }
        }
        blocks.push(Value::Object(conclusions));
    }
    if blocks.len() != signatures {
        problems.push(format!(
            "{} signature blocks, {signatures} expected",
            blocks.len()
        ));
    }
    let mut row = Map::new();
    row.insert("name".into(), case.into());
    row.insert(
        "reported".into(),
        lines.iter().map(|line| Value::from(*line)).collect(),
    );
    row.insert("signatures".into(), Value::Array(intact));
    row.insert("conclusions".into(), Value::Array(blocks));
    row.insert(
        "problems".into(),
        problems
            .iter()
            .map(|problem| Value::from(problem.as_str()))
            .collect(),
    );
    Ok(Value::Object(row))
}

/// Creates every case, validates it with DSS and keeps the reports.
pub(crate) fn execute(corpus: &Corpus, results: &Path) -> Result<(), String> {
    if results.exists() {
        return Err("results already exist; select a fresh --results directory".into());
    }
    std::fs::create_dir_all(results).map_err(|error| error.to_string())?;
    let fixtures = corpus
        .root
        .join("crates/xml-sec-xades/tests/fixtures/creation");
    let signed = results.join("signed");
    corpus.require(
        &line(&[
            &"cargo",
            &"run",
            &"-q",
            &"-p",
            &"xml-sec-xades",
            &"--features",
            &"produce",
            &"--example",
            &"create_probe",
            &"--",
            &fixtures,
            &signed,
        ]),
        &results.join("create"),
    )?;
    super::dss::build(corpus, results)?;
    let classpath = super::dss::classpath(corpus)?;
    let mut summary = Vec::new();
    for (case, signatures) in CASES {
        let reports = results.join(case);
        let mut probe = line(&[
            &"java",
            &"-cp",
            &classpath,
            &"LevelProbe",
            &signed.join(format!("{case}.xml")),
            &fixtures.join("root.der"),
            &TIME,
            &reports,
        ]);
        if case == "detached" {
            probe.push(signed.join("detached.txt").into());
        }
        let run = corpus.require(&probe, &results.join(format!("{case}-run")))?;
        let output = String::from_utf8_lossy(&run.stdout).into_owned();
        print!("{output}");
        summary.push(assess(case, signatures, &output, &reports)?);
    }
    super::write_json(
        &results.join("summary.json"),
        &Value::Array(summary.clone()),
    )?;
    let failed: Vec<&Value> = summary
        .iter()
        .filter(|row| {
            row["problems"]
                .as_array()
                .is_some_and(|problems| !problems.is_empty())
        })
        .collect();
    if !failed.is_empty() {
        return Err(format!(
            "DSS does not accept the created signatures: {}",
            Value::Array(failed.into_iter().cloned().collect())
        ));
    }
    println!(
        "EU DSS: {} created documents validated, reports saved to {}",
        CASES.len(),
        results.display()
    );
    Ok(())
}

pub(crate) fn run(corpus: &Corpus, args: &[String]) -> Result<(), crate::repo::Failure> {
    let mut results = corpus.root.join("target/xades-creation-results");
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--results" => results = absolute(args.next().ok_or("--results needs a directory")?)?,
            _ => return Err("usage: xades creation [--results DIR]".into()),
        }
    }
    Ok(execute(corpus, &results)?)
}
