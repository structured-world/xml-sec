//! `xades creation [--results DIR]`: EU DSS's independent reading of the
//! signatures xml-sec creates and augments. The `create_probe` example signs
//! every packaging mode with the creation fixtures, and `augment_probe` adds a
//! TSA token to a B-B signature with the augmentation fixtures, the CRLs and
//! OCSP response of the level fixtures to their B-T signature, from its own
//! B-T signature and CRLs, an archive timestamp and its renewal, and to the
//! level fixtures' B-LT `Manifest` signature an archive timestamp over a
//! `RenewedDigestsV2` of its detached object. DSS must
//! classify each signature at its expected level, find it cryptographically
//! intact with every reference found and intact, identify the signing
//! certificate and find every timestamp intact over its message imprint.

use super::{Corpus, absolute, line, xml};
use serde_json::{Map, Value, json};
use std::path::Path;

#[cfg(test)]
mod tests;

/// One created document and what DSS must report in it.
#[derive(Clone, Copy)]
pub(crate) struct Case {
    pub(crate) name: &'static str,
    /// Signatures, a countersignature counting as one of its own.
    pub(crate) signatures: usize,
    /// The baseline format of every signature.
    pub(crate) format: &'static str,
    /// Timestamp tokens.
    pub(crate) timestamps: usize,
    /// The fixture directory the document was created with.
    pub(crate) fixtures: &'static str,
}

const fn created(name: &'static str, signatures: usize) -> Case {
    Case {
        name,
        signatures,
        format: "XAdES-BASELINE-B",
        timestamps: 0,
        fixtures: "creation",
    }
}

pub(crate) const CASES: [Case; 11] = [
    created("enveloped", 1),
    created("enveloping", 1),
    created("internally-detached", 1),
    created("detached", 1),
    created("parallel", 2),
    created("countersigned", 2),
    Case {
        name: "b-t",
        signatures: 1,
        format: "XAdES-BASELINE-T",
        timestamps: 1,
        fixtures: "augmentation",
    },
    Case {
        name: "b-lt",
        signatures: 1,
        format: "XAdES-BASELINE-LT",
        timestamps: 1,
        fixtures: "levels",
    },
    Case {
        name: "b-lta",
        signatures: 1,
        format: "XAdES-BASELINE-LTA",
        timestamps: 2,
        fixtures: "augmentation",
    },
    Case {
        name: "b-lta-renewed",
        signatures: 1,
        format: "XAdES-BASELINE-LTA",
        timestamps: 3,
        fixtures: "augmentation",
    },
    // DSS does not process RenewedDigestsV2; the archive's imprint covers it.
    Case {
        name: "b-lta-manifest",
        signatures: 1,
        format: "XAdES-BASELINE-LTA",
        timestamps: 2,
        fixtures: "levels",
    },
];

/// The instant the probe assesses at, inside every creation certificate.
const TIME: &str = "1800000000";

/// Whether the diagnostic report has `expected` timestamps, each intact over
/// its message imprint (RFC 3161 §2.4.2).
fn tokens(diagnostic: xml::Node<'_, '_>, expected: usize, problems: &mut Vec<String>) {
    let mut found = 0;
    for timestamp in xml::below(diagnostic, "Timestamp", None)
        .filter(|node| xml::child(*node, "BasicSignature").is_some())
    {
        found += 1;
        let id = timestamp.attribute("Id").unwrap_or_default();
        if xml::text_at(timestamp, &["BasicSignature", "SignatureIntact"]).as_deref()
            != Some("true")
        {
            problems.push(format!("{id}: timestamp signature not intact"));
        }
        for matcher in xml::below(timestamp, "DigestMatcher", None) {
            let true_at = |field| xml::text_at(matcher, &[field]).as_deref() == Some("true");
            if !(true_at("DataFound") && true_at("DataIntact")) {
                problems.push(format!("{id}: message imprint not found or not intact"));
            }
        }
    }
    if found != expected {
        problems.push(format!("{found} timestamps, {expected} expected"));
    }
}

/// What DSS concluded on one created document, and why it does not qualify.
pub(crate) fn assess(case: &Case, output: &str, reports: &Path) -> Result<Value, String> {
    let Case {
        name,
        signatures,
        format,
        timestamps,
        ..
    } = *case;
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
        if !line.contains(&format!(" format={format} ")) {
            problems.push(format!("not {format}: {line}"));
        }
    }
    let diagnostic_text = xml::read(&reports.join("diagnostic.xml"))?;
    let diagnostic = xml::parse(&diagnostic_text, "diagnostic report")?;
    tokens(diagnostic.root_element(), timestamps, &mut problems);
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
    row.insert("name".into(), name.into());
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
    let fixtures = corpus.root.join("crates/xml-sec-xades/tests/fixtures");
    let signed = results.join("signed");
    for (example, action, directory) in [
        ("create_probe", None, "creation"),
        ("augment_probe", Some("complete"), "augmentation"),
        ("augment_probe", Some("extend"), "levels"),
        ("augment_probe", Some("archive"), "augmentation"),
        ("augment_probe", Some("renew"), "levels"),
    ] {
        let mut probe = line(&[
            &"cargo",
            &"run",
            &"-q",
            &"-p",
            &"xml-sec-xades",
            &"--features",
            &"produce",
            &"--example",
            &example,
            &"--",
        ]);
        probe.extend(action.map(Into::into));
        probe.extend(line(&[&fixtures.join(directory), &signed]));
        corpus.require(&probe, &results.join(example))?;
    }
    super::dss::build(corpus, results)?;
    let classpath = super::dss::classpath(corpus)?;
    let mut summary = Vec::new();
    for case in &CASES {
        let reports = results.join(case.name);
        let mut probe = line(&[
            &"java",
            &"-cp",
            &classpath,
            &"LevelProbe",
            &signed.join(format!("{}.xml", case.name)),
            &fixtures.join(case.fixtures).join("root.der"),
            &TIME,
            &reports,
        ]);
        match case.name {
            "detached" => probe.push(signed.join("detached.txt").into()),
            // The object its signed Manifest names.
            "b-lta-manifest" => probe.push(fixtures.join("levels/detached.txt").into()),
            _ => {}
        }
        let run = corpus.require(&probe, &results.join(format!("{}-run", case.name)))?;
        let output = String::from_utf8_lossy(&run.stdout).into_owned();
        print!("{output}");
        summary.push(assess(case, &output, &reports)?);
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
