//! `xades dss-corpus [--results DIR] [--record]`: EU DSS's own `XAdES` test
//! corpus, validated by DSS and by `xml-sec-xades` under the strict `Xades`
//! policy profile, compared per ETSI EN 319 102-1 building block.
//!
//! The corpus is every XML file of `dss-xades/src/test/resources` and of
//! `dss-cookbook/src/test/resources/signature-pool`, read from the tag of the
//! DSS release the probes are built against. Both validators receive the same
//! conditions, derived from each input: the trust anchors are the
//! certificates where the chains the document carries end, and the time is
//! [`INSTANT`]. When none of the document's signatures reaches a validated
//! path at that instant and the document carries no timestamp, a second pair
//! of runs takes its claimed signing time, labelled `signing-time`.
//!
//! `interop/xades/dss-corpus/expectations.json` holds the reviewed
//! classification of every input; a run that observes another comparison,
//! or an input it does not list, fails. `--record` writes the observations
//! for review instead, keeping the reviewed classes and reasons of inputs
//! whose comparison did not change.

use super::{Build, Corpus, absolute, line, write_json, xml};
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};

mod dss_policy;
#[cfg(test)]
mod tests;

/// The fixed validation instant of the first pass, 2027-01-15T08:00:00Z.
pub(crate) const INSTANT: i64 = 1_800_000_000;

/// The DSS source directories whose XML files form the corpus.
const SOURCES: [&str; 2] = [
    "dss-xades/src/test/resources",
    "dss-cookbook/src/test/resources/signature-pool",
];

/// The `XAdES` profiles the corpus runs under, widest last: a result label and
/// the probe's profile name.
pub(crate) const PROFILES: [(&str, &str); 3] = [
    ("strict", "xades"),
    ("extended", "xades-extended"),
    ("conformant", "xades-conformant"),
];

/// Whether `rows` hold at least one signature and `side` reads `value` for
/// `block` in every one of them.
pub(crate) fn every_block(rows: &[Value], block: &str, side: &str, value: &str) -> bool {
    !rows.is_empty() && rows.iter().all(|row| row["blocks"][block][side] == value)
}

/// The building blocks compared, in report order.
pub(crate) const BLOCKS: [&str; 6] = ["FC", "ISC", "CV", "XCV", "SAV", "TIMESTAMPS"];

/// Classes a reviewed difference may take; each needs a reason.
const REVIEWED: [&str; 4] = [
    "normative-difference",
    "policy-refusal",
    "unsupported",
    "dss-deviation",
];

fn expectations_path(corpus: &Corpus) -> PathBuf {
    corpus.package().join("dss-corpus/expectations.json")
}

/// The sparse checkout of the corpus at the DSS tag `release`, under the
/// repository's tool directory, and the commit that tag names.
fn fetch(corpus: &Corpus, release: &str, logs: &Path) -> Result<(PathBuf, String), String> {
    let checkout = super::dss::tools(corpus).join(format!("corpus-{release}"));
    if !checkout.join(".git").exists() {
        corpus.require(
            &line(&[
                &"git",
                &"clone",
                &"--depth",
                &"1",
                &"--filter=blob:none",
                &"--sparse",
                &"--branch",
                &release,
                &"https://github.com/esig/dss.git",
                &checkout,
            ]),
            &logs.join("corpus-clone"),
        )?;
    }
    let mut sparse = line(&[&"git", &"-C", &checkout, &"sparse-checkout", &"set"]);
    sparse.extend(SOURCES.iter().map(Into::into));
    corpus.require(&sparse, &logs.join("corpus-sparse"))?;
    let head = corpus.require(
        &line(&[&"git", &"-C", &checkout, &"rev-parse", &"HEAD"]),
        &logs.join("corpus-commit"),
    )?;
    Ok((
        checkout,
        String::from_utf8_lossy(&head.stdout).trim().to_owned(),
    ))
}

/// Every XML file below the corpus sources, by its path inside the checkout.
fn inputs(checkout: &Path) -> Result<Vec<String>, String> {
    let mut found = Vec::new();
    let mut pending: Vec<PathBuf> = SOURCES.iter().map(|source| checkout.join(source)).collect();
    while let Some(directory) = pending.pop() {
        let entries = std::fs::read_dir(&directory)
            .map_err(|error| format!("read {}: {error}", directory.display()))?;
        for entry in entries {
            let path = entry.map_err(|error| error.to_string())?.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "xml") {
                let relative = path
                    .strip_prefix(checkout)
                    .map_err(|error| error.to_string())?;
                found.push(relative.to_string_lossy().into_owned());
            }
        }
    }
    found.sort();
    Ok(found)
}

/// A directory name for an input path.
fn slug(input: &str) -> String {
    input.replace(['/', '\\'], "__")
}

/// The indication of a DSS building block, or `absent`.
fn indication(block: Option<xml::Node<'_, '_>>) -> String {
    block
        .and_then(|block| xml::text_at(block, &["Conclusion", "Indication"]))
        .unwrap_or_else(|| "absent".into())
}

/// The worst of `indications`: FAILED over INDETERMINATE over PASSED, `none`
/// when there are none.
fn worst(indications: &[String]) -> String {
    for level in ["FAILED", "INDETERMINATE", "absent", "PASSED"] {
        if indications.iter().any(|indication| indication == level) {
            return level.into();
        }
    }
    "none".into()
}

/// One signature of a DSS report: its token, the `Id` of its `ds:Signature`,
/// the indication of each compared block and the overall indication and
/// sub-indication of the simple report.
pub(crate) fn dss_signatures(
    diagnostic: &str,
    detailed: &str,
    simple: &str,
) -> Result<Vec<Value>, String> {
    let diagnostic = xml::parse(diagnostic, "diagnostic report")?;
    let detailed = xml::parse(detailed, "detailed report")?;
    let simple = xml::parse(simple, "simple report")?;
    let overall = |token: &str| {
        let signature = xml::elements(simple.root_element()).find(|node| {
            node.tag_name().name() == "Signature" && node.attribute("Id") == Some(token)
        });
        json!({
            "indication": signature.and_then(|node| xml::text_at(node, &["Indication"])),
            "sub": signature.and_then(|node| xml::text_at(node, &["SubIndication"])),
        })
    };
    let blocks = |token: &str, kind: &str| {
        xml::below(detailed.root_element(), "BasicBuildingBlocks", None)
            .filter(move |node| {
                node.attribute("Type") == Some(kind) && node.attribute("Id") == Some(token)
            })
            .collect::<Vec<_>>()
    };
    let mut found = Vec::new();
    let signatures = xml::below(diagnostic.root_element(), "Signatures", None)
        .flat_map(xml::elements)
        .filter(|node| node.tag_name().name() == "Signature");
    for signature in signatures {
        let token = signature.attribute("Id").unwrap_or_default().to_owned();
        let own = blocks(&token, "SIGNATURE");
        let mut row = Map::new();
        for name in ["FC", "ISC", "CV", "XCV", "SAV"] {
            let block = own.first().and_then(|block| xml::child(*block, name));
            row.insert(name.into(), indication(block).into());
        }
        let stamps: Vec<String> = xml::below(diagnostic.root_element(), "Timestamp", None)
            .filter(|stamp| {
                xml::below(*stamp, "TimestampedObject", None).any(|object| {
                    object.attribute("Category") == Some("SIGNATURE")
                        && object.attribute("Token") == Some(token.as_str())
                })
            })
            .map(|stamp| {
                let id = stamp.attribute("Id").unwrap_or_default();
                let blocks = blocks(id, "TIMESTAMP");
                let conclusion = blocks.first().copied();
                indication(conclusion)
            })
            .collect();
        row.insert("TIMESTAMPS".into(), worst(&stamps).into());
        found.push(json!({
            "token": token,
            "id": xml::text_at(signature, &["DAIdentifier"]),
            "blocks": row,
            "overall": overall(&token),
        }));
    }
    Ok(found)
}

/// Whether a refusal of the strict profile concerns `XAdES` structure (format
/// checking) rather than an algorithm or transform (acceptability).
fn structural(detail: &str) -> bool {
    [
        "XAdES",
        "SignedProperties",
        "QualifyingProperties",
        "Signature requires",
    ]
    .iter()
    .any(|word| detail.contains(word))
}

fn verdict(value: &str, detail: impl Into<String>) -> Value {
    json!({ "verdict": value, "detail": detail.into() })
}

/// The block verdicts of one signature's facts: `pass`, `fail` or
/// `not-reached`, each with the fact it reads. `stamped` says whether the
/// document carries a timestamp at all.
pub(crate) fn our_blocks(facts: &Value, stamped: bool) -> Map<String, Value> {
    let mut blocks = Map::new();
    for name in BLOCKS {
        blocks.insert(name.into(), verdict("not-reached", ""));
    }
    if !stamped {
        blocks.insert("TIMESTAMPS".into(), verdict("none", ""));
    }
    let verification = &facts["verification"];
    if let Some(error) = verification["error"].as_str() {
        let detail = verification["detail"].as_str().unwrap_or_default();
        let block = match error {
            "Policy" if structural(detail) => "FC",
            "Policy" => "SAV",
            _ => "XCV",
        };
        blocks.insert(block.into(), verdict("fail", format!("{error}: {detail}")));
        return blocks;
    }
    let references_valid = verification["references"]
        .as_array()
        .is_some_and(|references| references.iter().all(|status| status == "Valid"));
    let intact = verification["status"] == "Valid" && references_valid;
    blocks.insert(
        "CV".into(),
        verdict(
            if intact { "pass" } else { "fail" },
            format!("status {}", verification["status"]),
        ),
    );
    let trusted = verification["trust"] == "ValidatedX509";
    blocks.insert(
        "XCV".into(),
        verdict(
            if trusted { "pass" } else { "fail" },
            format!("trust {}", verification["trust"]),
        ),
    );
    let basic = &facts["basic"];
    if let Some(bound) = basic["bound"].as_bool() {
        blocks.insert(
            "FC".into(),
            verdict("pass", "qualifying properties prepared"),
        );
        blocks.insert(
            "ISC".into(),
            verdict(
                if bound { "pass" } else { "fail" },
                "signing certificate binding",
            ),
        );
        let met = basic["assessed"].as_bool().unwrap_or(false);
        blocks.insert(
            "SAV".into(),
            verdict(if met { "pass" } else { "fail" }, "B-B requirements"),
        );
    } else if let Some(negative) = basic["negative"].as_str() {
        let block = match negative {
            "Hashes" => "SAV",
            "Timestamp" => "TIMESTAMPS",
            "Path" | "CounterKey" | "Status" => "XCV",
            _ => "FC",
        };
        blocks.insert(
            "FC".into(),
            verdict("pass", "qualifying properties prepared"),
        );
        blocks.insert(
            block.into(),
            verdict("fail", basic["detail"].as_str().unwrap_or_default()),
        );
    } else if let Some(error) = basic["error"].as_str() {
        blocks.insert(
            "FC".into(),
            verdict(
                "fail",
                format!("{error}: {}", basic["detail"].as_str().unwrap_or_default()),
            ),
        );
    }
    if stamped {
        let timestamped = &facts["timestamped"];
        let (value, detail) = match timestamped["assessed"].as_bool() {
            Some(true) => ("pass", "B-T requirements".to_owned()),
            Some(false) => ("fail", "B-T requirements unmet".to_owned()),
            None => (
                "fail",
                format!(
                    "{}{}",
                    timestamped["negative"].as_str().unwrap_or_default(),
                    timestamped["error"].as_str().unwrap_or_default()
                ),
            ),
        };
        if !timestamped.is_null() {
            blocks.insert("TIMESTAMPS".into(), verdict(value, detail));
        }
    }
    blocks
}

/// Whether a DSS indication and one of our verdicts say the same thing.
fn agrees(dss: &str, ours: &str) -> bool {
    match ours {
        "pass" => dss == "PASSED",
        "fail" => dss == "FAILED" || dss == "INDETERMINATE",
        "none" => dss == "none",
        _ => false,
    }
}

/// The per-block comparison of one input: one entry per signature, matched by
/// the `Id` of its `ds:Signature`, or by position when an `Id` is missing.
pub(crate) fn compare(dss: &[Value], ours: &[Value], stamped: bool) -> Vec<Value> {
    let mut rows = Vec::new();
    for (index, signature) in dss.iter().enumerate() {
        let id = signature["id"].as_str();
        let matched = ours
            .iter()
            .find(|facts| id.is_some() && facts["id"].as_str() == id)
            .or_else(|| ours.get(index).filter(|_| id.is_none()));
        let mine = matched.map_or_else(Map::new, |facts| our_blocks(facts, stamped));
        let mut blocks = Map::new();
        for name in BLOCKS {
            let theirs = signature["blocks"][name].as_str().unwrap_or("absent");
            let verdict = mine
                .get(name)
                .and_then(|verdict| verdict["verdict"].as_str())
                .unwrap_or("absent");
            blocks.insert(
                name.into(),
                json!({ "dss": theirs, "ours": verdict, "agrees": agrees(theirs, verdict) }),
            );
        }
        rows.push(json!({ "id": id, "matched": matched.is_some(), "blocks": blocks }));
    }
    rows
}

/// The comparison a reviewer classifies: per signature, each block as
/// `DSS/ours`.
pub(crate) fn observed(rows: &[Value]) -> Value {
    Value::Array(
        rows.iter()
            .map(|row| {
                let blocks: Map<String, Value> = BLOCKS
                    .iter()
                    .map(|name| {
                        let block = &row["blocks"][*name];
                        (
                            (*name).to_owned(),
                            format!(
                                "{}/{}",
                                block["dss"].as_str().unwrap_or_default(),
                                block["ours"].as_str().unwrap_or_default()
                            )
                            .into(),
                        )
                    })
                    .collect();
                Value::Object(blocks)
            })
            .collect(),
    )
}

/// The class a comparison takes without review: every block agrees, both
/// sides found no signature, or the document carries no anchor.
pub(crate) fn automatic_class(rows: &[Value], dss_error: bool, anchors: u64) -> &'static str {
    if dss_error && rows.is_empty() {
        return "not-a-signature";
    }
    if anchors == 0 {
        return "no-usable-anchor";
    }
    let all = !rows.is_empty()
        && rows.iter().all(|row| {
            row["matched"] == true
                && BLOCKS
                    .iter()
                    .all(|name| row["blocks"][*name]["agrees"] == true)
        });
    if all { "agreement" } else { "unreviewed" }
}

/// One validation pass of both implementations at `at` over `cases`.
struct Pass<'a> {
    corpus: &'a Corpus,
    probe: &'a Path,
    classpath: &'a str,
    label: &'a str,
    /// The DSS validation policy of each profile, by its result label.
    policies: &'a Path,
}

/// Writes the DSS validation policy of every profile into `directory`: the
/// release's default policy with the profile's cryptographic constraints.
fn write_policies(
    corpus: &Corpus,
    probe: &Path,
    release: &str,
    directory: &Path,
) -> Result<(), String> {
    let jar = super::dss::tools(corpus)
        .join("repository/eu/europa/ec/joinup/sd-dss/dss-policy-jaxb")
        .join(release)
        .join(format!("dss-policy-jaxb-{release}.jar"));
    std::fs::create_dir_all(directory).map_err(|error| error.to_string())?;
    let template = corpus.require(
        &line(&[&"unzip", &"-p", &jar, &"policy/constraint.xml"]),
        &directory.join("template"),
    )?;
    let template = String::from_utf8(template.stdout).map_err(|error| error.to_string())?;
    for (label, profile) in PROFILES {
        let probe_run = corpus.require(
            &line(&[&probe, &"constraints", &profile]),
            &directory.join(format!("{label}-constraints")),
        )?;
        let constraints: Value =
            serde_json::from_slice(&probe_run.stdout).map_err(|error| error.to_string())?;
        super::write(
            &directory.join(format!("{label}.xml")),
            dss_policy::policy(&template, &constraints)?,
        )?;
    }
    Ok(())
}

impl Pass<'_> {
    /// Validates every `(name, input, directory, at)`: the probe's facts and
    /// DSS's reports (or its refusal) under each profile land in the case's
    /// directory for this pass.
    fn run(&self, cases: &[(String, PathBuf, PathBuf, i64)], logs: &Path) -> Result<(), String> {
        use std::fmt::Write as _;
        let mut manifest = String::new();
        for (name, input, directory, at) in cases {
            let output = directory.join(self.label);
            std::fs::create_dir_all(&output).map_err(|error| error.to_string())?;
            write!(
                manifest,
                "{name}\t{}\t{at}\t{}",
                input.display(),
                directory.join("anchors").display(),
            )
            .map_err(|error| error.to_string())?;
            for (label, _) in PROFILES {
                write!(
                    manifest,
                    "\t{}\t{}",
                    self.policies.join(format!("{label}.xml")).display(),
                    output.join(label).join("dss").display()
                )
                .map_err(|error| error.to_string())?;
            }
            manifest.push('\n');
            for (label, profile) in PROFILES {
                let directory_of_profile = output.join(label);
                std::fs::create_dir_all(&directory_of_profile)
                    .map_err(|error| error.to_string())?;
                let probe = self.corpus.command(
                    &line(&[
                        &self.probe,
                        &"facts",
                        input,
                        &directory.join("anchors"),
                        &at.to_string(),
                        &profile,
                    ]),
                    &directory_of_profile.join("facts"),
                )?;
                // A probe that fails on an input, a panic included, is a
                // finding about xml-sec: it stays in the facts instead of
                // ending the run.
                let facts = if probe.success() {
                    probe.stdout
                } else {
                    json!({ "probe": { "code": probe.code, "stderr": String::from_utf8_lossy(&probe.stderr) } })
                        .to_string()
                        .into_bytes()
                };
                super::write(&directory_of_profile.join("facts.json"), facts)?;
            }
        }
        let file = logs.join(format!("{}-manifest.tsv", self.label));
        super::write(&file, manifest)?;
        self.corpus.require(
            &line(&[&"java", &"-cp", &self.classpath, &"CorpusProbe", &file]),
            &logs.join(format!("{}-dss", self.label)),
        )?;
        Ok(())
    }
}

/// Reads one pass of one case under the profile `label` into its comparison
/// rows, whether DSS refused the input, and our facts.
fn pass_rows(
    directory: &Path,
    label: &str,
    stamped: bool,
) -> Result<(Vec<Value>, bool, Value), String> {
    let dss = directory.join(label).join("dss");
    let facts: Value = serde_json::from_str(&xml::read(&directory.join(label).join("facts.json"))?)
        .map_err(|error| error.to_string())?;
    let ours = facts["signatures"].as_array().cloned().unwrap_or_default();
    if dss.join("error.txt").exists() {
        // DSS read no signature: each of ours stands against an absent one.
        let absent: Vec<Value> = ours
            .iter()
            .map(|facts| json!({ "id": facts["id"], "blocks": {} }))
            .collect();
        return Ok((compare(&absent, &ours, stamped), true, facts));
    }
    let signatures = dss_signatures(
        &xml::read(&dss.join("diagnostic.xml"))?,
        &xml::read(&dss.join("detailed.xml"))?,
        &xml::read(&dss.join("simple.xml"))?,
    )?;
    Ok((compare(&signatures, &ours, stamped), false, facts))
}

/// Whether no signature of a pass reached a validated path.
fn unvalidated(facts: &Value) -> bool {
    facts["signatures"].as_array().is_some_and(|signatures| {
        !signatures.is_empty()
            && signatures
                .iter()
                .all(|signature| signature["verification"]["trust"] != "ValidatedX509")
    })
}

/// A corpus input: its name, path, result directory and validation time.
type Case = (String, PathBuf, PathBuf, i64);

/// Every input of `checkout` with its directory under `results`, and the
/// conditions the probe derives from it.
fn conditions_of(
    corpus: &Corpus,
    probe: &Path,
    checkout: &Path,
    results: &Path,
) -> Result<(Vec<Case>, Map<String, Value>), String> {
    let mut cases = Vec::new();
    let mut conditions = Map::new();
    for input in inputs(checkout)? {
        let directory = results.join("cases").join(slug(&input));
        let path = checkout.join(&input);
        let anchors = directory.join("anchors");
        std::fs::create_dir_all(&anchors).map_err(|error| error.to_string())?;
        let probe_run = corpus.command(
            &line(&[&probe, &"conditions", &path, &anchors]),
            &directory.join("conditions"),
        )?;
        // An input the probe cannot even read for conditions has no anchors;
        // the failure stays visible in its conditions.
        let found: Value = if probe_run.success() {
            serde_json::from_slice(&probe_run.stdout).map_err(|error| error.to_string())?
        } else {
            json!({
                "anchors": 0,
                "timestamps": false,
                "probe": String::from_utf8_lossy(&probe_run.stderr),
            })
        };
        cases.push((input.clone(), path, directory, INSTANT));
        conditions.insert(input, found);
    }
    Ok((cases, conditions))
}

/// Every case's comparison in each pass it took part in.
fn observations(
    cases: &[Case],
    conditions: &Map<String, Value>,
) -> Result<Map<String, Value>, String> {
    let mut observations = Map::new();
    for (name, _, directory, _) in cases {
        let found = &conditions[name];
        let stamped = found["timestamps"] == true;
        let anchors = found["anchors"].as_u64().unwrap_or(0);
        let mut row = Map::new();
        for label in ["instant", "signing-time"] {
            let pass = directory.join(label);
            if !pass.exists() {
                continue;
            }
            for (profile, _) in PROFILES {
                let (rows, dss_error, facts) = pass_rows(&pass, profile, stamped)?;
                row.insert(
                    format!("{label}/{profile}"),
                    json!({
                        "observed": observed(&rows),
                        "class": automatic_class(&rows, dss_error, anchors),
                        "intact": every_block(&rows, "CV", "ours", "pass"),
                        "trusted": every_block(&rows, "XCV", "ours", "pass")
                            && facts["signatures"].as_array().is_some_and(|s| !s.is_empty()),
                        "dss_intact": every_block(&rows, "CV", "dss", "PASSED"),
                    }),
                );
            }
        }
        observations.insert(name.clone(), Value::Object(row));
    }
    Ok(observations)
}

/// Runs both passes and checks or records every case's comparison.
fn execute(corpus: &Corpus, results: &Path, record: bool) -> Result<(), String> {
    if results.exists() {
        return Err("results already exist; select a fresh --results directory".into());
    }
    std::fs::create_dir_all(results).map_err(|error| error.to_string())?;
    let release = super::dss::build(corpus, &results.join("dss-build"))?;
    let (checkout, commit) = fetch(corpus, &release.dss, results)?;
    let probe = corpus.build_example(
        "corpus_probe",
        &[],
        Build::Dev,
        &results.join("corpus-probe-build"),
    )?;
    let classpath = super::dss::classpath(corpus)?;
    let policies = results.join("policies");
    write_policies(corpus, &probe, &release.dss, &policies)?;
    let (cases, conditions) = conditions_of(corpus, &probe, &checkout, results)?;
    let pass = |label| Pass {
        corpus,
        probe: &probe,
        classpath: &classpath,
        label,
        policies: &policies,
    };
    pass("instant").run(&cases, results)?;
    let mut later = Vec::new();
    for (name, path, directory, _) in &cases {
        let found = &conditions[name];
        // The widest profile decides: a strict refusal is policy, not time.
        let facts: Value = serde_json::from_str(&xml::read(
            &directory
                .join("instant")
                .join("conformant")
                .join("facts.json"),
        )?)
        .map_err(|error| error.to_string())?;
        if let Some(time) = found["signing_time"].as_i64()
            && found["timestamps"] == false
            && unvalidated(&facts)
        {
            later.push((name.clone(), path.clone(), directory.clone(), time));
        }
    }
    if !later.is_empty() {
        pass("signing-time").run(&later, results)?;
    }
    let observations = observations(&cases, &conditions)?;
    let summary = json!({
        "dss": release.dss,
        "corpus_commit": commit,
        "instant": INSTANT,
        "cases": observations,
    });
    write_json(&results.join("summary.json"), &summary)?;
    let path = expectations_path(corpus);
    if record {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let expectations = recorded(&summary, &path);
        write_json(&path, &expectations)?;
        return super::write(&report_path(corpus), report(&expectations));
    }
    let expected: Value = serde_json::from_str(&xml::read(&path)?)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let mut found = differences(&expected, &summary);
    if xml::read(&report_path(corpus)).ok() != Some(report(&expected)) {
        found.push("docs/eu-dss-corpus.md is not the report of the expectations".into());
    }
    if !found.is_empty() {
        return Err(format!(
            "DSS corpus comparison differs from {}:\n{}",
            path.display(),
            found.join("\n")
        ));
    }
    println!(
        "EU DSS {} corpus ({commit}): {} inputs match their reviewed classification",
        release.dss,
        observations.len()
    );
    Ok(())
}

/// The published result of a recorded comparison: per pass and profile, how
/// many corpus inputs each implementation finds intact, how many xml-sec
/// also trusts, how many agree with DSS on every block, and the classes.
pub(crate) fn report(expectations: &Value) -> String {
    use std::fmt::Write as _;
    let mut text = String::from(
        "# EU DSS XAdES corpus\n\n\
         Generated by `cargo run -p xml-sec-tools -- xades dss-corpus --record`; \
         CI fails when a run differs from it.\n\n",
    );
    writeln!(
        text,
        "EU DSS {}, every XML input of `dss-xades/src/test/resources` and \
         `dss-cookbook/src/test/resources/signature-pool` at its release tag. \
         Both validators get the same trust anchors (where each chain the \
         document carries ends) and the same time ({} Unix seconds; a second \
         pass at the claimed signing time when no signature reaches a \
         validated path and the document carries no timestamp).\n",
        expectations["dss"].as_str().unwrap_or("?"),
        expectations["instant"],
    )
    .expect("writing to a String cannot fail");
    text.push_str(
        "An input is *intact* when every signature's value and references \
         verify (DSS building block CV), *trusted* when xml-sec also validated \
         the signer's path, and in *agreement* when every compared block \
         (FC, ISC, CV, XCV, SAV, timestamps) reaches the same conclusion.\n",
    );
    for pass in ["instant", "signing-time"] {
        let mut rows = Vec::new();
        for (profile, name) in PROFILES {
            let label = format!("{pass}/{profile}");
            let entries: Vec<&Value> = expectations["cases"]
                .as_object()
                .into_iter()
                .flatten()
                .filter_map(|(_, passes)| passes.get(&label))
                .collect();
            if entries.is_empty() {
                continue;
            }
            let count = |field: &str| entries.iter().filter(|entry| entry[field] == true).count();
            let mut classes = std::collections::BTreeMap::<String, usize>::new();
            for entry in &entries {
                *classes
                    .entry(entry["class"].as_str().unwrap_or("?").to_owned())
                    .or_default() += 1;
            }
            let classes: Vec<String> = classes
                .iter()
                .map(|(class, count)| format!("{class} {count}"))
                .collect();
            rows.push(format!(
                "| `{name}` | {} | {} | {} | {} | {} | {} |",
                entries.len(),
                count("dss_intact"),
                count("intact"),
                count("trusted"),
                classes
                    .iter()
                    .find(|class| class.starts_with("agreement "))
                    .map_or("0", |class| &class["agreement ".len()..]),
                classes.join(", "),
            ));
        }
        if rows.is_empty() {
            continue;
        }
        writeln!(
            text,
            "\n## Pass `{pass}`\n\n\
             | Profile | Inputs | DSS intact | xml-sec intact | xml-sec trusted | Agreement | Classes |\n\
             | --- | --- | --- | --- | --- | --- | --- |"
        )
        .expect("writing to a String cannot fail");
        for row in rows {
            text.push_str(&row);
            text.push('\n');
        }
    }
    text
}

/// Where the published result lives.
fn report_path(corpus: &Corpus) -> PathBuf {
    corpus.root.join("docs/eu-dss-corpus.md")
}

/// `summary` as expectations, keeping the reviewed class and reason of every
/// pass whose observed comparison is unchanged in `previous`.
pub(crate) fn recorded(summary: &Value, previous: &Path) -> Value {
    let previous: Value = xml::read(previous)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or(Value::Null);
    let mut cases = Map::new();
    for (name, passes) in summary["cases"].as_object().into_iter().flatten() {
        let mut row = Map::new();
        for (label, pass) in passes.as_object().into_iter().flatten() {
            let old = &previous["cases"][name][label];
            let mut entry = pass.clone();
            if old["observed"] == pass["observed"] && !old["reason"].is_null() {
                entry["class"] = old["class"].clone();
                entry["reason"] = old["reason"].clone();
            }
            row.insert(label.clone(), entry);
        }
        cases.insert(name.clone(), Value::Object(row));
    }
    json!({ "dss": summary["dss"], "instant": summary["instant"], "cases": cases })
}

/// Every way `summary` differs from the reviewed `expected` classification.
pub(crate) fn differences(expected: &Value, summary: &Value) -> Vec<String> {
    let mut found = Vec::new();
    let reviewed = &expected["cases"];
    for (name, passes) in summary["cases"].as_object().into_iter().flatten() {
        for (label, pass) in passes.as_object().into_iter().flatten() {
            let entry = &reviewed[name][label];
            if entry.is_null() {
                found.push(format!("{name} {label}: not in the expectations"));
                continue;
            }
            if entry["observed"] != pass["observed"] {
                found.push(format!(
                    "{name} {label}: observed {} where {} is expected",
                    pass["observed"], entry["observed"]
                ));
                continue;
            }
            let class = entry["class"].as_str().unwrap_or_default();
            let automatic = pass["class"].as_str().unwrap_or_default();
            let reasoned = entry["reason"]
                .as_str()
                .is_some_and(|reason| !reason.is_empty());
            // An automatic class stands on its own, except the one that says
            // nobody has reviewed the difference yet.
            let automatic_holds = class == automatic && automatic != "unreviewed";
            let review_holds = REVIEWED.contains(&class) && reasoned;
            if !(automatic_holds || review_holds) {
                found.push(format!(
                    "{name} {label}: class {class} needs a reviewed class with a reason"
                ));
            }
        }
    }
    for (name, passes) in reviewed.as_object().into_iter().flatten() {
        for label in passes
            .as_object()
            .into_iter()
            .flatten()
            .map(|(label, _)| label)
        {
            if summary["cases"][name][label].is_null() {
                found.push(format!("{name} {label}: expected but not run"));
            }
        }
    }
    found
}

pub(crate) fn run(corpus: &Corpus, args: &[String]) -> Result<(), crate::repo::Failure> {
    let mut results = corpus.root.join("target/xades-dss-corpus");
    let mut record = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--record" => record = true,
            "--results" => {
                results = absolute(args.next().ok_or("--results needs a directory")?)?;
            }
            _ => return Err("usage: xades dss-corpus [--results DIR] [--record]".into()),
        }
    }
    Ok(execute(corpus, &results, record)?)
}
