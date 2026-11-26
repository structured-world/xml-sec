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
//! In the other direction DSS (`FormProbe`) makes the signature forms its own
//! tests make with the creation fixtures' signer, and `level_probe` must find
//! every signature of each valid at XAdES-BASELINE-B.

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

pub(crate) const CASES: [Case; 25] = [
    created("enveloped", 1),
    created("enveloping", 1),
    created("internally-detached", 1),
    created("detached", 1),
    created("parallel", 2),
    created("countersigned", 2),
    created("countersigned-nested", 3),
    created("detached-multiple", 1),
    created("inclusive", 1),
    created("prefixes", 1),
    created("empty-prefix", 1),
    created("placement-first-child", 1),
    created("placement-before", 1),
    created("signed-key-info", 1),
    // References the caller composes (`DataObject::Reference`).
    created("reference-filter2", 1),
    created("reference-xpath", 1),
    created("reference-by-id", 1),
    created("reference-comments", 1),
    created("object-base64", 1),
    created("reference-xslt", 1),
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

/// One signature form EU DSS makes as its signature tests make it, and the
/// signatures xml-sec must find in it, a countersignature counting as one of
/// its own.
#[derive(Clone, Copy)]
pub(crate) struct Form {
    pub(crate) name: &'static str,
    pub(crate) signatures: usize,
}

pub(crate) const FORMS: [Form; 6] = [
    Form {
        name: "parallel",
        signatures: 2,
    },
    Form {
        name: "countersigned",
        signatures: 2,
    },
    Form {
        name: "countersigned-nested",
        signatures: 3,
    },
    Form {
        name: "detached-multiple",
        signatures: 1,
    },
    Form {
        name: "inclusive",
        signatures: 1,
    },
    Form {
        name: "pretty-print",
        signatures: 1,
    },
];

/// The document every enveloped DSS form signs, and the detached files.
const FORM_DOCUMENT: &str = "<Document><Data Id=\"payload\">Form payload</Data></Document>";
const FORM_DETACHED: [(&str, &str); 2] = [
    ("detached.txt", "Detached payload\n"),
    ("detached-2.txt", "Second detached payload\n"),
];

/// The detached files a case's references name.
fn detached_files(name: &str) -> &'static [&'static str] {
    match name {
        "detached" => &["detached.txt"],
        "detached-multiple" => &["detached.txt", "detached-2.txt"],
        _ => &[],
    }
}

/// Why xml-sec's reading of a DSS form does not qualify: every signature
/// `level_probe` reports must be valid and meet XAdES-BASELINE-B.
pub(crate) fn assess_form(form: &Form, output: &str) -> Value {
    let reports: Vec<Value> = output
        .split("signature: ")
        .skip(1)
        .map(|chunk| super::lifecycle::xml_sec_outcome(&format!("signature: {chunk}")))
        .collect();
    let mut problems = Vec::new();
    if reports.len() != form.signatures {
        problems.push(format!(
            "{} signatures reported, {} expected",
            reports.len(),
            form.signatures
        ));
    }
    for (index, report) in reports.iter().enumerate() {
        if report["crypto"] != "Valid" || report["structure"] != "met" {
            problems.push(format!("signature {index}: {report}"));
        }
    }
    json!({ "name": form.name, "signatures": reports, "problems": problems })
}

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
            &"produce,xslt",
            &"--example",
            &example,
            &"--",
        ]);
        probe.extend(action.map(Into::into));
        probe.extend(line(&[&fixtures.join(directory), &signed]));
        corpus.require(&probe, &results.join(example))?;
    }
    let classpath = super::dss::build(corpus, results)?.classpath;
    let mut summary = Vec::new();
    for case in &CASES {
        let reports = results.join(case.name);
        let mut probe = super::dss::java(
            &classpath,
            "LevelProbe",
            &[
                &signed.join(format!("{}.xml", case.name)),
                &fixtures.join(case.fixtures).join("root.der"),
                &TIME,
                &reports,
            ],
        );
        for file in detached_files(case.name) {
            probe.push(signed.join(file).into());
        }
        // The object its signed Manifest names.
        if case.name == "b-lta-manifest" {
            probe.push(fixtures.join("levels/detached.txt").into());
        }
        let run = corpus.require(&probe, &results.join(format!("{}-run", case.name)))?;
        let output = String::from_utf8_lossy(&run.stdout).into_owned();
        print!("{output}");
        summary.push(assess(case, &output, &reports)?);
    }
    summary.extend(forms(
        corpus,
        results,
        &classpath,
        &fixtures.join("creation"),
    )?);
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
            "the other implementation does not accept a created document (DSS for xml-sec's, xml-sec for DSS's forms under dss-forms): {}",
            Value::Array(failed.into_iter().cloned().collect())
        ));
    }
    println!(
        "EU DSS: {} created documents validated, xml-sec: {} DSS forms validated, reports saved to {}",
        CASES.len(),
        FORMS.len(),
        results.display()
    );
    Ok(())
}

/// DSS makes every form with the creation fixtures' signer, and xml-sec
/// validates each signature at B-B against the fixtures' root.
fn forms(
    corpus: &Corpus,
    results: &Path,
    classpath: &str,
    fixtures: &Path,
) -> Result<Vec<Value>, String> {
    let work = results.join("dss-forms");
    std::fs::create_dir_all(&work).map_err(|error| error.to_string())?;
    let write = |name: &str, content: &[u8]| {
        std::fs::write(work.join(name), content).map_err(|error| format!("write {name}: {error}"))
    };
    write("document.xml", FORM_DOCUMENT.as_bytes())?;
    for (name, content) in FORM_DETACHED {
        write(name, content.as_bytes())?;
    }
    // DSS takes the signer as a PKCS#12 store with its chain.
    for certificate in ["signer", "intermediate"] {
        corpus.require(
            &line(&[
                &corpus.openssl,
                &"x509",
                &"-inform",
                &"DER",
                &"-in",
                &fixtures.join(format!("{certificate}.der")),
                &"-out",
                &work.join(format!("{certificate}.pem")),
            ]),
            &work.join(format!("{certificate}-pem")),
        )?;
    }
    let store = work.join("signer.p12");
    corpus.require(
        &line(&[
            &corpus.openssl,
            &"pkcs12",
            &"-export",
            &"-inkey",
            &fixtures.join("signer.key"),
            &"-in",
            &work.join("signer.pem"),
            &"-certfile",
            &work.join("intermediate.pem"),
            &"-name",
            &"signer",
            &"-passout",
            &"pass:dss",
            &"-out",
            &store,
        ]),
        &work.join("signer-p12"),
    )?;
    let level_probe = line(&[
        &"cargo",
        &"run",
        &"-q",
        &"-p",
        &"xml-sec-xades",
        &"--features",
        &"produce",
        &"--example",
        &"level_probe",
        &"--",
    ]);
    let mut rows = Vec::new();
    for form in &FORMS {
        let document = work.join(format!("{}.xml", form.name));
        let probe = super::dss::java(
            classpath,
            "FormProbe",
            &[&store, &form.name, &work, &TIME, &document],
        );
        corpus.require(&probe, &work.join(format!("{}-dss", form.name)))?;
        let mut validate = level_probe.clone();
        validate.extend(line(&[&document, &fixtures.join("root.der"), &TIME, &"b"]));
        for file in detached_files(form.name) {
            validate.extend(line(&[&"--detached", &work.join(file)]));
        }
        let run = corpus.require(&validate, &work.join(format!("{}-xml-sec", form.name)))?;
        let output = String::from_utf8_lossy(&run.stdout).into_owned();
        print!("{output}");
        rows.push(assess_form(form, &output));
    }
    Ok(rows)
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
