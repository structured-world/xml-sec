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
//! `interop/xades/dss-corpus/expectations.json` holds the classification of
//! every input; a run that observes another comparison, or an input it does
//! not list, fails. `interop/xades/dss-corpus/reviews.json` holds the reviews
//! of differences, each for one input's overall comparison, so one review
//! covers every pass and profile that observes it. `--record` writes the
//! observations with the reviews that apply instead of checking them.

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

fn reviews_path(corpus: &Corpus) -> PathBuf {
    corpus.package().join("dss-corpus/reviews.json")
}

/// The reviews of differences, by input; none when the file is absent.
fn read_reviews(path: &Path) -> Result<Value, String> {
    if !path.exists() {
        return Ok(json!({}));
    }
    serde_json::from_str(&xml::read(path)?).map_err(|error| format!("{}: {error}", path.display()))
}

/// The overall comparison of each signature of one pass's observation.
fn overall_of(observed: &Value) -> Value {
    Value::Array(
        observed
            .as_array()
            .into_iter()
            .flatten()
            .map(|row| row["OVERALL"].clone())
            .collect(),
    )
}

/// The review of input `name` written for the overall comparison `observed`
/// shows.
fn review_for<'r>(reviews: &'r Value, name: &str, observed: &Value) -> Option<&'r Value> {
    let overall = overall_of(observed);
    reviews[name]
        .as_array()?
        .iter()
        .find(|review| review["overall"] == overall)
}

/// `pass` as an expectation: a difference nobody classified automatically
/// takes the class and reason of the review written for it.
fn applied(pass: &Value, review: Option<&Value>) -> Value {
    let mut entry = pass.clone();
    if pass["class"] == "unreviewed"
        && let Some(review) = review
    {
        entry["class"] = review["class"].clone();
        entry["reason"] = review["reason"].clone();
    }
    entry
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
/// A signature only xml-sec reads stands against an absent one.
pub(crate) fn compare(dss: &[Value], ours: &[Value], stamped: bool) -> Vec<Value> {
    let mut rows = Vec::new();
    let mut paired = vec![false; ours.len()];
    for (index, signature) in dss.iter().enumerate() {
        let id = signature["id"].as_str();
        let position = ours
            .iter()
            .position(|facts| id.is_some() && facts["id"].as_str() == id)
            .or_else(|| (id.is_none() && index < ours.len()).then_some(index));
        if let Some(position) = position {
            paired[position] = true;
        }
        rows.push(row(
            signature,
            position.map(|position| &ours[position]),
            stamped,
        ));
    }
    for (facts, _) in ours.iter().zip(&paired).filter(|(_, paired)| !**paired) {
        let absent = json!({ "id": facts["id"], "blocks": {} });
        let mut row = row(&absent, Some(facts), stamped);
        row["matched"] = false.into();
        row["overall"]["indication"] = false.into();
        row["overall"]["agrees"] = false.into();
        rows.push(row);
    }
    rows
}

/// The comparison of one DSS signature with its counterpart, if any.
fn row(signature: &Value, matched: Option<&Value>, stamped: bool) -> Value {
    let mine = matched.map_or_else(Map::new, |facts| our_blocks(facts, stamped));
    let spelled = |value: &Value| {
        format!(
            "{}:{}",
            value["indication"].as_str().unwrap_or("absent"),
            value["sub"].as_str().unwrap_or("-")
        )
    };
    let theirs = &signature["overall"];
    let ours = matched.map_or(Value::Null, |facts| facts["etsi"].clone());
    let overall = json!({
        "dss": spelled(theirs),
        "ours": spelled(&ours),
        "indication": matched.is_some() && theirs["indication"] == ours["indication"],
        "agrees": matched.is_some() && spelled(theirs) == spelled(&ours),
    });
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
    json!({
        "id": signature["id"],
        "matched": matched.is_some(),
        "blocks": blocks,
        "overall": overall,
    })
}

/// The comparison a reviewer classifies: per signature, each block as
/// `DSS/ours`.
pub(crate) fn observed(rows: &[Value]) -> Value {
    Value::Array(
        rows.iter()
            .map(|row| {
                let mut blocks: Map<String, Value> = BLOCKS
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
                blocks.insert(
                    "OVERALL".into(),
                    format!(
                        "{}/{}",
                        row["overall"]["dss"].as_str().unwrap_or_default(),
                        row["overall"]["ours"].as_str().unwrap_or_default()
                    )
                    .into(),
                );
                Value::Object(blocks)
            })
            .collect(),
    )
}

/// The class a comparison takes without review: every signature reaches
/// DSS's overall indication and sub-indication (the building blocks are the
/// diagnosis of a difference, not the verdict), neither side found a
/// signature, or the document carries no anchor.
pub(crate) fn automatic_class(rows: &[Value], anchors: u64) -> &'static str {
    if rows.is_empty() {
        return "not-a-signature";
    }
    if anchors == 0 {
        return "no-usable-anchor";
    }
    if every_overall(rows, "agrees") {
        "agreement"
    } else {
        "unreviewed"
    }
}

/// Whether `rows` hold at least one signature and every one's overall
/// comparison has `field` set.
pub(crate) fn every_overall(rows: &[Value], field: &str) -> bool {
    !rows.is_empty()
        && rows
            .iter()
            .all(|row| row["matched"] == true && row["overall"][field] == true)
}

/// Whether every signature of `rows` reads `TOTAL_PASSED` on `side`.
fn every_passed(rows: &[Value], side: &str) -> bool {
    !rows.is_empty()
        && rows.iter().all(|row| {
            row["overall"][side]
                .as_str()
                .is_some_and(|value| value.starts_with("TOTAL_PASSED"))
        })
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
/// rows and our facts.
fn pass_rows(directory: &Path, label: &str, stamped: bool) -> Result<(Vec<Value>, Value), String> {
    let dss = directory.join(label).join("dss");
    let facts: Value = serde_json::from_str(&xml::read(&directory.join(label).join("facts.json"))?)
        .map_err(|error| error.to_string())?;
    let ours = facts["signatures"].as_array().cloned().unwrap_or_default();
    // DSS refusing the input read no signature: each of ours stands against
    // an absent one.
    let signatures = if dss.join("error.txt").exists() {
        Vec::new()
    } else {
        dss_signatures(
            &xml::read(&dss.join("diagnostic.xml"))?,
            &xml::read(&dss.join("detailed.xml"))?,
            &xml::read(&dss.join("simple.xml"))?,
        )?
    };
    Ok((compare(&signatures, &ours, stamped), facts))
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

/// Until when each signature of `facts` keeps passing (the probe's
/// `valid_until`, Unix seconds, `null` for one that does not pass now or
/// that no certificate bounds), when any signature has such a time.
pub(crate) fn horizons(facts: &Value) -> Option<Value> {
    let horizons: Vec<Value> = facts["signatures"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|signature| signature["etsi"]["valid_until"].clone())
        .collect();
    horizons
        .iter()
        .any(|horizon| !horizon.is_null())
        .then(|| Value::Array(horizons))
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
                let (rows, facts) = pass_rows(&pass, profile, stamped)?;
                let mut entry = json!({
                    "observed": observed(&rows),
                    "class": automatic_class(&rows, anchors),
                    "passed": every_passed(&rows, "ours")
                        && facts["signatures"].as_array().is_some_and(|s| !s.is_empty()),
                    "dss_passed": every_passed(&rows, "dss"),
                    "indication": every_overall(&rows, "indication"),
                });
                if let Some(horizons) = horizons(&facts) {
                    entry["valid_until"] = horizons;
                }
                row.insert(format!("{label}/{profile}"), entry);
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
    let reviews = read_reviews(&reviews_path(corpus))?;
    if record {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let expectations = recorded(&summary, &reviews);
        write_json(&path, &expectations)?;
        return super::write(&report_path(corpus), report(&expectations));
    }
    let expected: Value = serde_json::from_str(&xml::read(&path)?)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let mut found = differences(&expected, &summary, &reviews);
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
        "Each profile's DSS run uses DSS's own default policy with every \
         cryptographic constraint replaced by the profile's. An input *passes* \
         when every signature reaches TOTAL_PASSED (ETSI EN 319 102-1 V1.4.1: \
         DSS's simple report, and the shared EN 319 102-1 process over \
         xml-sec's facts); it is in *agreement* when every signature reaches \
         DSS's indication and sub-indication. Each other input carries a \
         reviewed class with the clause it rests on.\n\n\
         For every signature xml-sec passes, the expectations record until \
         when it keeps passing (`valid_until`, Unix seconds): the last \
         certificate validity bound past which the same process, over the \
         evidence the document carries, still reaches TOTAL_PASSED.\n",
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
                count("dss_passed"),
                count("passed"),
                count("indication"),
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
             | Profile | Inputs | DSS passes | xml-sec passes | Same indication | Agreement | Classes |\n\
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

/// `summary` as expectations, each pass with the review written for it.
pub(crate) fn recorded(summary: &Value, reviews: &Value) -> Value {
    let mut cases = Map::new();
    for (name, passes) in summary["cases"].as_object().into_iter().flatten() {
        let mut row = Map::new();
        for (label, pass) in passes.as_object().into_iter().flatten() {
            let review = review_for(reviews, name, &pass["observed"]);
            row.insert(label.clone(), applied(pass, review));
        }
        cases.insert(name.clone(), Value::Object(row));
    }
    json!({ "dss": summary["dss"], "instant": summary["instant"], "cases": cases })
}

/// Every review that no pass of its input observes any more.
fn stale_reviews(summary: &Value, reviews: &Value) -> Vec<String> {
    let mut found = Vec::new();
    for (name, list) in reviews.as_object().into_iter().flatten() {
        for review in list.as_array().into_iter().flatten() {
            let observed = summary["cases"][name]
                .as_object()
                .into_iter()
                .flatten()
                .any(|(_, pass)| overall_of(&pass["observed"]) == review["overall"]);
            if !observed {
                found.push(format!(
                    "{name}: the review of {} matches no observation",
                    review["overall"]
                ));
            }
        }
    }
    found
}

/// Every way `summary` differs from the `expected` classification recorded
/// with `reviews`.
pub(crate) fn differences(expected: &Value, summary: &Value, reviews: &Value) -> Vec<String> {
    let mut found = stale_reviews(summary, reviews);
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
            if entry["valid_until"] != pass["valid_until"] {
                found.push(format!(
                    "{name} {label}: valid until {} where {} is expected",
                    pass["valid_until"], entry["valid_until"]
                ));
                continue;
            }
            let current = applied(pass, review_for(reviews, name, &pass["observed"]));
            if entry["class"] != current["class"] || entry["reason"] != current["reason"] {
                found.push(format!(
                    "{name} {label}: the expectations were not recorded with the reviews"
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
