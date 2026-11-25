//! `xades dss-corpus [--results DIR] [--record]`: EU DSS's own `XAdES` test
//! corpus, validated by DSS and by `xml-sec-xades` under the strict `Xades`
//! policy profile, compared per ETSI EN 319 102-1 building block.
//!
//! The corpus is every XML file (`.xml` and `.xades`) of
//! `dss-xades/src/test/resources` and of
//! `dss-cookbook/src/test/resources/signature-pool`, read from the tag of the
//! DSS release the probes are built against. Both validators receive the same
//! conditions, derived from each input: the trust anchors are the topmost
//! certificates of the signer chains the document carries, and the time is
//! [`INSTANT`]. Under each profile whose run reached no validated path for any
//! of the document's signatures at that instant and found no timestamp token
//! over a signature value that proves its existence, a second pair of runs
//! takes its claimed signing time, labelled `signing-time`.
//!
//! `interop/xades/dss-corpus/expectations.json` holds the classification of
//! every input; a run that observes another comparison, or an input it does
//! not list, fails. The DSS release and corpus commit it names are its
//! provenance. `interop/xades/dss-corpus/reviews.json` holds the reviews of
//! differences, each for one input's comparison, so one review covers every
//! pass and profile that observes it. `--record` writes the observations with
//! the reviews that apply instead of checking them.

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

/// The review of input `name` written for `observed`: its overall pair, and
/// the block results the review lists as the ones it explains. The same
/// overall pair over other block results is a difference it never covered.
fn review_for<'r>(reviews: &'r Value, name: &str, observed: &Value) -> Option<&'r Value> {
    let overall = overall_of(observed);
    reviews[name].as_array()?.iter().find(|review| {
        review["overall"] == overall
            && review["observed"]
                .as_array()
                .is_some_and(|approved| approved.contains(observed))
    })
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
    let text = |run: super::Logged| String::from_utf8_lossy(&run.stdout).trim().to_owned();
    let head = text(corpus.require(
        &line(&[&"git", &"-C", &checkout, &"rev-parse", &"HEAD"]),
        &logs.join("corpus-commit"),
    )?);
    let tagged = text(corpus.require(
        &line(&[
            &"git",
            &"-C",
            &checkout,
            &"rev-parse",
            &"--verify",
            &format!("refs/tags/{release}^{{commit}}"),
        ]),
        &logs.join("corpus-tag"),
    )?);
    let changes = text(corpus.require(
        &line(&[&"git", &"-C", &checkout, &"status", &"--porcelain"]),
        &logs.join("corpus-status"),
    )?);
    checkout_matches(&checkout, release, &head, &tagged, &changes)?;
    Ok((checkout, head))
}

/// Whether a cached corpus checkout still holds the inputs of `release`: its
/// `head` is the commit the tag names (`tagged`) and the work tree has no
/// `changes`. A reused checkout is otherwise run under the wrong name.
pub(crate) fn checkout_matches(
    checkout: &Path,
    release: &str,
    head: &str,
    tagged: &str,
    changes: &str,
) -> Result<(), String> {
    let refresh = || format!("remove {} to fetch the corpus again", checkout.display());
    if head != tagged {
        return Err(format!(
            "the corpus checkout is at {head}, not at DSS {release} ({tagged}); {}",
            refresh()
        ));
    }
    if !changes.is_empty() {
        return Err(format!(
            "the corpus checkout of DSS {release} has local changes; {}",
            refresh()
        ));
    }
    Ok(())
}

/// Every XML file below the corpus sources (`.xml`, and `.xades` as DSS
/// names some signatures), by its path inside the checkout.
fn inputs(checkout: &Path) -> Result<Vec<String>, String> {
    let mut found = Vec::new();
    let mut pending: Vec<PathBuf> = SOURCES.iter().map(|source| checkout.join(source)).collect();
    while let Some(directory) = pending.pop() {
        let entries = std::fs::read_dir(&directory)
            .map_err(|error| format!("read {}: {error}", directory.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| format!("read {}: {error}", directory.display()))?;
            let path = entry.path();
            // The entry's own type, not its target's: a symlinked directory is
            // an alias whose files the walk already lists, or a cycle.
            let kind = entry
                .file_type()
                .map_err(|error| format!("read {}: {error}", path.display()))?;
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file()
                && path
                    .extension()
                    .is_some_and(|extension| extension == "xml" || extension == "xades")
            {
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

/// A directory name for an input path, distinct for distinct paths: `_` is
/// escaped before the separators take its place, so the encoding reverses.
pub(crate) fn slug(input: &str) -> String {
    let mut name = String::with_capacity(input.len());
    for character in input.chars() {
        match character {
            '_' => name.push_str("_u"),
            '/' => name.push_str("_s"),
            '\\' => name.push_str("_b"),
            other => name.push(other),
        }
    }
    name
}

/// The conclusion of a DSS building block as `INDICATION` or
/// `INDICATION:SUB_INDICATION`, or `absent`: the sub-indication says why a
/// block did not pass (EN 319 102-1 V1.4.1 clause 5.1.3), so a change of it
/// is a change of the block's result.
fn indication(block: Option<xml::Node<'_, '_>>) -> String {
    let Some(indication) =
        block.and_then(|block| xml::text_at(block, &["Conclusion", "Indication"]))
    else {
        return "absent".into();
    };
    match block.and_then(|block| xml::text_at(block, &["Conclusion", "SubIndication"])) {
        Some(sub) => format!("{indication}:{sub}"),
        None => indication,
    }
}

/// The indication part of a block conclusion [`indication`] spelled.
fn main_indication(conclusion: &str) -> &str {
    conclusion.split(':').next().unwrap_or_default()
}

/// The worst of `conclusions`, FAILED over INDETERMINATE over PASSED, with
/// its sub-indication; `none` when there are none.
fn worst(conclusions: &[String]) -> String {
    for level in ["FAILED", "INDETERMINATE", "absent", "PASSED"] {
        if let Some(found) = conclusions
            .iter()
            .find(|conclusion| main_indication(conclusion) == level)
        {
            return found.clone();
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
        // DSS attaches each token to the signature that carries it through
        // FoundTimestamps, whatever the token stamps: a RefsOnlyTimeStamp
        // covers no SIGNATURE object, yet it is this signature's.
        let stamps: Vec<String> = xml::below(signature, "FoundTimestamp", None)
            .filter_map(|found| found.attribute("Timestamp"))
            .map(|id| indication(blocks(id, "TIMESTAMP").first().copied()))
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

/// The building block whose result an ETSI decision's sub-indication is
/// (EN 319 102-1 V1.4.1 clauses 5.2.2 to 5.2.8, Table 6): none for one that
/// is no finding about the signature (`CUSTOM`) or that no block names alone.
fn decision_block(decision: &Value) -> Option<&'static str> {
    match decision["sub"].as_str()? {
        "FORMAT_FAILURE" => Some("FC"),
        "NO_SIGNING_CERTIFICATE_FOUND" => Some("ISC"),
        "SIGNED_DATA_NOT_FOUND" | "HASH_FAILURE" | "SIG_CRYPTO_FAILURE" => Some("CV"),
        "SIG_CONSTRAINTS_FAILURE"
        | "CRYPTO_CONSTRAINTS_FAILURE"
        | "CRYPTO_CONSTRAINTS_FAILURE_NO_POE" => Some("SAV"),
        "NO_CERTIFICATE_CHAIN_FOUND"
        | "CERTIFICATE_CHAIN_GENERAL_FAILURE"
        | "CHAIN_CONSTRAINTS_FAILURE"
        | "REVOKED_NO_POE"
        | "REVOKED_CA_NO_POE"
        | "REVOKED"
        | "OUT_OF_BOUNDS_NO_POE"
        | "OUT_OF_BOUNDS_NOT_REVOKED"
        | "REVOCATION_OUT_OF_BOUNDS_NO_POE"
        | "NOT_YET_VALID"
        | "TRY_LATER" => Some("XCV"),
        _ => None,
    }
}

/// An ETSI conclusion as a DSS block spells it, `INDICATION[:SUB_INDICATION]`:
/// a signature's `TOTAL_PASSED` and `TOTAL_FAILED` are a block's `PASSED` and
/// `FAILED` (EN 319 102-1 V1.4.1 clause 5.1.3, Table 5).
fn block_conclusion(indication: &str, sub: Option<&str>) -> String {
    let indication = match indication {
        "TOTAL_PASSED" => "PASSED",
        "TOTAL_FAILED" => "FAILED",
        other => other,
    };
    match sub {
        Some(sub) => format!("{indication}:{sub}"),
        None => indication.to_owned(),
    }
}

/// The conclusion of the ETSI decision in `etsi` for the block it names.
fn decision_conclusion(etsi: &Value) -> String {
    block_conclusion(
        etsi["indication"].as_str().unwrap_or_default(),
        etsi["sub"].as_str(),
    )
}

fn verdict(value: &str, detail: impl Into<String>) -> Value {
    json!({ "verdict": value, "detail": detail.into() })
}

/// The block verdicts of one signature's facts: `pass`, `fail` or
/// `not-reached`, each with the fact it reads, or the ETSI conclusion where
/// the facts have one: the block the ETSI decision names carries that
/// decision's conclusion, TIMESTAMPS the worst of its tokens'. TIMESTAMPS is
/// `none` for a signature that carries no timestamp.
pub(crate) fn our_blocks(facts: &Value) -> Map<String, Value> {
    let mut blocks = Map::new();
    for name in BLOCKS {
        blocks.insert(name.into(), verdict("not-reached", ""));
    }
    if facts["declared_timestamps"].as_u64().unwrap_or(0) == 0 {
        blocks.insert("TIMESTAMPS".into(), verdict("none", ""));
    } else if let Some(timestamps) = timestamp_block(&facts["timestamps"]) {
        blocks.insert("TIMESTAMPS".into(), timestamps);
    }
    let verification = &facts["verification"];
    if let Some(error) = verification["error"].as_str() {
        let detail = verification["detail"].as_str().unwrap_or_default();
        // The block of the ETSI decision the probe reports for the same
        // signature, so both producers read one decision; a refusal that is
        // no finding about the signature fails no block.
        if let Some(block) = decision_block(&facts["etsi"]) {
            blocks.insert(
                block.into(),
                verdict(
                    &decision_conclusion(&facts["etsi"]),
                    format!("{error}: {detail}"),
                ),
            );
        }
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
    basic_blocks(facts, &mut blocks);
    // The block the ETSI decision over the same facts names as the one that
    // ended it did not pass, whatever a narrower fact read, and concluded as
    // that decision did: a path the verification validated still fails X.509
    // validation without the members' statuses (EN 319 102-1 V1.4.1 clause
    // 5.2.6.4 step 4).
    if facts["etsi"]["indication"] != "TOTAL_PASSED"
        && let Some(block) = decision_block(&facts["etsi"])
        && matches!(blocks[block]["verdict"].as_str(), Some("pass" | "fail"))
    {
        let detail = format!(
            "ETSI decision over {}",
            blocks[block]["detail"].as_str().unwrap_or_default()
        );
        blocks.insert(
            block.into(),
            verdict(&decision_conclusion(&facts["etsi"]), detail),
        );
    }
    blocks
}

/// `detail` with each `NodeIdentity { ... }` written `N`, so its shape reads
/// the same for every node.
fn node_free(detail: &str) -> String {
    let mut shape = String::with_capacity(detail.len());
    let mut rest = detail;
    while let Some(start) = rest.find("NodeIdentity {") {
        shape.push_str(&rest[..start]);
        shape.push('N');
        rest = rest[start..]
            .find('}')
            .map_or("", |end| &rest[start + end + 1..]);
    }
    shape.push_str(rest);
    shape
}

/// The FC, ISC and SAV verdicts of one signature's basic facts.
fn basic_blocks(facts: &Value, blocks: &mut Map<String, Value>) {
    // A TS 101 903 V1.2.2 signature has BES facts in place of EN 319 132-1
    // B-B ones: they decide whether its signing certificate is protected.
    let bes = &facts["ts101903_bes"];
    let basic = if bes.is_null() { &facts["basic"] } else { bes };
    if let Some(met) = bes["assessed"].as_bool() {
        blocks.insert(
            "FC".into(),
            verdict("pass", "TS 101 903 V1.2.2 properties prepared"),
        );
        for block in ["ISC", "SAV"] {
            blocks.insert(
                block.into(),
                verdict(
                    if met { "pass" } else { "fail" },
                    "TS 101 903 V1.2.2 BES requirements",
                ),
            );
        }
    } else if let Some(bound) = basic["bound"].as_bool() {
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
        let detail = basic["detail"].as_str().unwrap_or_default();
        // A requirement of the baseline profile (EN 319 132-1 V1.3.1 clause
        // 6.3: no excluded property, a format for every object (k), MimeType
        // (Table 2), one token per SignatureTimeStamp (n), where clause 5.3
        // admits more; and clause 4.5's explicit timestamp canonicalization
        // method, which clause 6.3 builds the levels on, where TS 101 903
        // had a default) breaks no XAdES format: the
        // profile's rules are signature acceptance (EN 319 102-1 V1.4.1
        // clause 5.2.2 NOTE, 5.2.8). A signature whose value did not verify
        // stops B-B, and CV already reports it. Every other refusal is the
        // format's.
        let baseline = [
            "Prepare(Property(Forbidden",
            "Prepare(Format(Missing {",
            "Prepare(Format(Format(Property(Missing { parent: N, local: \"MimeType\"",
            "Prepare(Timestamp(Missing { node: N, local: \"CanonicalizationMethod\"",
        ];
        let shape = node_free(detail);
        let repeated_token = shape.starts_with("Prepare(Timestamp(Duplicate {")
            && basic["duplicate"] == "EncapsulatedTimeStamp";
        let block = if repeated_token || baseline.iter().any(|prefix| shape.starts_with(prefix)) {
            "SAV"
        } else if detail.starts_with("Prepare(Binding(Signature") {
            return;
        } else {
            "FC"
        };
        blocks.insert(block.into(), verdict("fail", format!("{error}: {detail}")));
    }
}

/// The TIMESTAMPS verdict over each of a signature's tokens, the scope DSS
/// reports: every token's own timestamp validation at the validation time
/// (EN 319 102-1 V1.4.1 clause 5.4), archive and validation-data tokens
/// included. One that failed or stayed indeterminate concludes the block
/// with its conclusion, FAILED over INDETERMINATE as DSS takes the worst;
/// one the process could not judge leaves it not reached; none when the
/// facts carry no per-token decision.
fn timestamp_block(tokens: &Value) -> Option<Value> {
    let tokens = tokens.as_array()?;
    let mut unjudged = 0;
    let mut worst: Option<(&Value, &str)> = None;
    for token in tokens {
        match token["current"]["indication"].as_str() {
            None => unjudged += 1,
            Some("PASSED") => {}
            Some(indication) => {
                if worst.is_none_or(|(_, known)| known != "FAILED" && indication == "FAILED") {
                    worst = Some((token, indication));
                }
            }
        }
    }
    if let Some((token, indication)) = worst {
        return Some(verdict(
            &block_conclusion(indication, token["current"]["sub"].as_str()),
            format!("{} token", token["role"].as_str().unwrap_or_default()),
        ));
    }
    if unjudged > 0 {
        return Some(verdict(
            "not-reached",
            format!("{unjudged} of {} tokens not judged", tokens.len()),
        ));
    }
    Some(verdict("pass", format!("{} tokens", tokens.len())))
}

/// Whether a DSS block conclusion and one of our verdicts say the same
/// thing: an ETSI conclusion of ours only the same conclusion, indication and
/// sub-indication (EN 319 102-1 V1.4.1 clause 5.1.3); a bare `fail`, where
/// our facts have no conclusion, any that did not pass.
fn agrees(dss: &str, ours: &str) -> bool {
    match ours {
        "pass" => main_indication(dss) == "PASSED",
        "fail" => matches!(main_indication(dss), "FAILED" | "INDETERMINATE"),
        "none" => dss == "none",
        "not-reached" | "absent" => false,
        conclusion => dss == conclusion,
    }
}

/// Whether both validators reached a block: neither side lacks it and ours
/// did not stop before it.
fn reached(dss: &str, ours: &str) -> bool {
    dss != "absent" && ours != "absent" && ours != "not-reached"
}

/// The per-block comparison of one input: one entry per signature, matched by
/// the `Id` of its `ds:Signature`, or by position when an `Id` is missing.
/// A signature only xml-sec reads stands against an absent one.
pub(crate) fn compare(dss: &[Value], ours: &[Value]) -> Vec<Value> {
    let mut paired = vec![false; ours.len()];
    // Every Id both sides carry is paired first, so a position never takes a
    // signature an Id names.
    let mut counterpart: Vec<Option<usize>> = dss
        .iter()
        .map(|signature| {
            let id = signature["id"].as_str()?;
            let position = (0..ours.len())
                .find(|&position| !paired[position] && ours[position]["id"].as_str() == Some(id))?;
            paired[position] = true;
            Some(position)
        })
        .collect();
    // Then by position, where at most one side has an Id: two different Ids
    // name two different signatures.
    for (index, signature) in dss.iter().enumerate() {
        let free = index < ours.len() && !paired[index] && counterpart[index].is_none();
        let ids = (
            signature["id"].as_str(),
            ours.get(index).and_then(|facts| facts["id"].as_str()),
        );
        if free && !matches!(ids, (Some(theirs), Some(mine)) if theirs != mine) {
            paired[index] = true;
            counterpart[index] = Some(index);
        }
    }
    let mut rows: Vec<Value> = dss
        .iter()
        .zip(&counterpart)
        .map(|(signature, position)| row(signature, position.map(|position| &ours[position])))
        .collect();
    for (facts, _) in ours.iter().zip(&paired).filter(|(_, paired)| !**paired) {
        let absent = json!({ "id": facts["id"], "blocks": {} });
        let mut row = row(&absent, Some(facts));
        row["matched"] = false.into();
        row["overall"]["indication"] = false.into();
        row["overall"]["agrees"] = false.into();
        rows.push(row);
    }
    rows
}

/// The comparison of one DSS signature with its counterpart, if any.
fn row(signature: &Value, matched: Option<&Value>) -> Value {
    let mine = matched.map_or_else(Map::new, our_blocks);
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
            json!({
                "dss": theirs,
                "ours": verdict,
                "agrees": agrees(theirs, verdict),
                "reached": reached(theirs, verdict),
            }),
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
/// DSS's overall indication and sub-indication and agrees on every building
/// block both validators reached, neither side found a signature, or the
/// document carries no anchor. A block one side did not reach stays in the
/// observation, which the check compares, but needs no review: xml-sec's
/// facts stop at the first refusal where DSS goes on.
pub(crate) fn automatic_class(rows: &[Value], anchors: u64) -> &'static str {
    if rows.is_empty() {
        return "not-a-signature";
    }
    if anchors == 0 {
        return "no-usable-anchor";
    }
    let blocks_agree = rows.iter().all(|row| {
        BLOCKS.iter().all(|name| {
            let block = &row["blocks"][*name];
            block["reached"] != true || block["agrees"] == true
        })
    });
    if every_overall(rows, "agrees") && blocks_agree {
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

/// Whether `side` read at least one signature of `rows` and every one it
/// read reaches `TOTAL_PASSED`. A row only the other side reads stands
/// against an absent signature: it decides agreement, not this side's pass.
fn every_passed(rows: &[Value], side: &str) -> bool {
    let mut read = rows
        .iter()
        .filter_map(|row| row["overall"][side].as_str())
        .filter(|value| !value.starts_with("absent"))
        .peekable();
    read.peek().is_some() && read.all(|value| value.starts_with("TOTAL_PASSED"))
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

/// `text` as one field of the DSS probe's manifest, whose fields are
/// tab-separated on one line each: a tab or a line break inside it would
/// split it, so it is refused.
pub(crate) fn manifest_field(text: &str) -> Result<&str, String> {
    if text.contains(['\t', '\n', '\r']) {
        return Err(format!(
            "{text:?} contains a tab or a line break, which the DSS manifest cannot carry"
        ));
    }
    Ok(text)
}

impl Pass<'_> {
    /// Validates every `(name, input, directory, at)` under each of its
    /// profiles: the probe's facts and DSS's reports (or its refusal) land in
    /// the case's directory for this pass.
    fn run(&self, cases: &[(&Case, Vec<(&str, &str)>)], logs: &Path) -> Result<(), String> {
        use std::fmt::Write as _;
        // Every line first, so a field the manifest cannot carry stops the
        // pass before either validator runs.
        let mut manifest = String::new();
        for ((name, input, directory, at), profiles) in cases {
            let output = directory.join(self.label);
            write!(
                manifest,
                "{}\t{}\t{at}\t{}",
                manifest_field(name)?,
                manifest_field(&input.to_string_lossy())?,
                manifest_field(&directory.join("anchors").to_string_lossy())?,
            )
            .map_err(|error| error.to_string())?;
            for (label, _) in profiles {
                write!(
                    manifest,
                    "\t{}\t{}",
                    manifest_field(&self.policies.join(format!("{label}.xml")).to_string_lossy())?,
                    manifest_field(&output.join(label).join("dss").to_string_lossy())?,
                )
                .map_err(|error| error.to_string())?;
            }
            manifest.push('\n');
        }
        for ((_, input, directory, at), profiles) in cases {
            let output = directory.join(self.label);
            std::fs::create_dir_all(&output).map_err(|error| error.to_string())?;
            for (label, profile) in profiles {
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
fn pass_rows(directory: &Path, label: &str) -> Result<(Vec<Value>, Value), String> {
    let dss = directory.join(label).join("dss");
    let mut facts: Value =
        serde_json::from_str(&xml::read(&directory.join(label).join("facts.json"))?)
            .map_err(|error| error.to_string())?;
    let ours = facts["signatures"].as_array().cloned().unwrap_or_default();
    // DSS refusing the input read no signature: each of ours stands against
    // an absent one. DSS failing after it read the input is a failed run,
    // kept with the facts for the check.
    let signatures = if dss.join("refused.txt").exists() {
        Vec::new()
    } else if dss.join("error.txt").exists() {
        facts["dss_error"] = xml::read(&dss.join("error.txt"))?.into();
        Vec::new()
    } else {
        dss_signatures(
            &xml::read(&dss.join("diagnostic.xml"))?,
            &xml::read(&dss.join("detailed.xml"))?,
            &xml::read(&dss.join("simple.xml"))?,
        )?
    };
    Ok((compare(&signatures, &ours), facts))
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

/// Whether a pass established a proof of existence for any signature: one
/// of its tokens over the signature value passed its own validation at the
/// validation time (EN 319 102-1 V1.4.1 clause 5.4). A token that is present
/// but rejected, unjudged or merely written in the text proves nothing; a
/// content timestamp proves the signed data existed (EN 319 132-1 section
/// 5.2.8) and a references-only one stamps the references, neither the
/// signature.
pub(crate) fn proves_existence(facts: &Value) -> bool {
    facts["signatures"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|signature| signature["timestamps"].as_array().into_iter().flatten())
        .any(|token| {
            matches!(
                token["role"].as_str(),
                Some("Signature" | "SignatureAndReferences" | "Archive")
            ) && token["current"]["indication"] == "PASSED"
        })
}

/// The profiles, of `facts` by result label, that take the signing-time
/// pass: each whose own signatures reach no validated path and whose own
/// tokens prove no existence. A profile refuses an expired signer by
/// checking validity over time, so its own facts decide, not a wider
/// profile's.
pub(crate) fn signing_time_profiles<'a>(facts: &[(&'a str, &Value)]) -> Vec<&'a str> {
    facts
        .iter()
        .filter(|(_, facts)| !proves_existence(facts) && unvalidated(facts))
        .map(|(label, _)| *label)
        .collect()
}

/// Whether `recompared` holds every case, pass and profile `saved` lists:
/// one whose artifacts are gone would otherwise drop out of the rewritten
/// summary and be recorded away.
pub(crate) fn complete(saved: &Value, recompared: &Value) -> Result<(), String> {
    let mut missing = Vec::new();
    for (name, passes) in saved["cases"].as_object().into_iter().flatten() {
        for (label, _) in passes.as_object().into_iter().flatten() {
            if recompared["cases"][name][label].is_null() {
                missing.push(format!("{name} {label}"));
            }
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "the saved run lists passes whose artifacts are gone:\n{}",
            missing.join("\n")
        ))
    }
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

/// What one pass of one input under one profile observes: the comparison
/// `rows` against DSS and our `facts`, for an input with these `conditions`.
pub(crate) fn observation(rows: &[Value], facts: &Value, conditions: &Value) -> Value {
    let anchors = conditions["anchors"].as_u64().unwrap_or(0);
    let mut entry = json!({
        "observed": observed(rows),
        "class": automatic_class(rows, anchors),
        "passed": every_passed(rows, "ours")
            && facts["signatures"].as_array().is_some_and(|s| !s.is_empty()),
        "dss_passed": every_passed(rows, "dss"),
        "indication": every_overall(rows, "indication"),
    });
    if let Some(horizons) = horizons(facts) {
        entry["valid_until"] = horizons;
    }
    // A failed run of either validator reads no signature, as an unsigned
    // input does; the failure is kept so the check can tell the two apart.
    let mut failures = Vec::new();
    if !conditions["probe"].is_null() {
        failures.push("the conditions probe failed".to_owned());
    }
    if !facts["probe"].is_null() {
        failures.push(format!(
            "the probe failed with code {}",
            facts["probe"]["code"]
        ));
    }
    if let Some(error) = facts["dss_error"].as_str() {
        failures.push(format!(
            "DSS failed: {}",
            error.lines().next().unwrap_or_default()
        ));
    }
    if !failures.is_empty() {
        entry["failures"] = failures.into();
    }
    entry
}

/// Every failed run of `pass`, each a defect of the comparison that no
/// review or recording can accept.
fn failures(pass: &Value) -> impl Iterator<Item = &str> {
    pass["failures"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}

/// Whether `summary` may be recorded: no pass of it failed to run.
pub(crate) fn recordable(summary: &Value) -> Result<(), String> {
    let mut found = Vec::new();
    for (name, passes) in summary["cases"].as_object().into_iter().flatten() {
        for (label, pass) in passes.as_object().into_iter().flatten() {
            found.extend(failures(pass).map(|failure| format!("{name} {label}: {failure}")));
        }
    }
    if found.is_empty() {
        Ok(())
    } else {
        Err(format!("the run cannot be recorded:\n{}", found.join("\n")))
    }
}

/// Every case's comparison in each pass it took part in.
fn observations(
    cases: &[Case],
    conditions: &Map<String, Value>,
) -> Result<Map<String, Value>, String> {
    let mut observations = Map::new();
    for (name, _, directory, _) in cases {
        let found = &conditions[name];
        let mut row = Map::new();
        for label in ["instant", "signing-time"] {
            let pass = directory.join(label);
            if !pass.exists() {
                continue;
            }
            // A profile whose own facts called for no signing-time pass did
            // not take it.
            for (profile, _) in PROFILES {
                if !pass.join(profile).exists() {
                    continue;
                }
                let (rows, facts) = pass_rows(&pass, profile)?;
                row.insert(
                    format!("{label}/{profile}"),
                    observation(&rows, &facts, found),
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
    // Every case path of the DSS manifest lies below it.
    manifest_field(&results.to_string_lossy())?;
    std::fs::create_dir_all(results).map_err(|error| error.to_string())?;
    let super::dss::Built { release, classpath } =
        super::dss::build(corpus, &results.join("dss-build"))?;
    let (checkout, commit) = fetch(corpus, &release.dss, results)?;
    let probe = corpus.build_example(
        "corpus_probe",
        &[],
        Build::Dev,
        &results.join("corpus-probe-build"),
    )?;
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
    let every: Vec<(&Case, Vec<(&str, &str)>)> =
        cases.iter().map(|case| (case, PROFILES.to_vec())).collect();
    pass("instant").run(&every, results)?;
    let mut later: Vec<Case> = Vec::new();
    let mut due = Vec::new();
    for (name, path, directory, _) in &cases {
        let Some(time) = conditions[name]["signing_time"].as_i64() else {
            continue;
        };
        let mut facts = Vec::new();
        for (label, _) in PROFILES {
            let read: Value = serde_json::from_str(&xml::read(
                &directory.join("instant").join(label).join("facts.json"),
            )?)
            .map_err(|error| error.to_string())?;
            facts.push((label, read));
        }
        let borrowed: Vec<(&str, &Value)> =
            facts.iter().map(|(label, facts)| (*label, facts)).collect();
        let labels = signing_time_profiles(&borrowed);
        if !labels.is_empty() {
            later.push((name.clone(), path.clone(), directory.clone(), time));
            due.push(
                PROFILES
                    .into_iter()
                    .filter(|(label, _)| labels.contains(label))
                    .collect::<Vec<_>>(),
            );
        }
    }
    if !later.is_empty() {
        let pairs: Vec<(&Case, Vec<(&str, &str)>)> = later.iter().zip(due).collect();
        pass("signing-time").run(&pairs, results)?;
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
        // Before either reviewed file is replaced.
        recordable(&summary)?;
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
         Generated by `cargo run -p xml-sec-tools -- xades dss-corpus --record \
         --results <directory>`, where the results directory must not exist \
         yet; CI fails when a run differs from it.\n\n",
    );
    writeln!(
        text,
        "Recorded with EU DSS {}, every XML input (`.xml` and `.xades`) of \
         `dss-xades/src/test/resources` and \
         `dss-cookbook/src/test/resources/signature-pool` at its release tag. \
         Both validators get the same trust anchors (the topmost certificate \
         of each signer chain the document carries) and the same time ({} \
         Unix seconds; a second pass at the claimed signing time under each \
         profile whose own run reached no validated path for any signature \
         and found no timestamp token over a signature value that proves its \
         existence).\n",
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
         DSS's indication and sub-indication and every building block both \
         validators reached says the same, with the same indication and \
         sub-indication wherever xml-sec's facts conclude the block. Two \
         classes come before that rule: *not-a-signature* when neither side \
         reads a signature, and *no-usable-anchor* when the document carries \
         no certificate a chain ends at, whatever the indications. \
         *agreement*, *not-a-signature* and *no-usable-anchor* are automatic; \
         every other input carries a reviewed class (normative-difference, \
         policy-refusal, unsupported, dss-deviation) with its reason: the \
         clause it rests on, or for a policy refusal the deployment rationale \
         of the profile.\n\n\
         For every signature xml-sec passes, the expectations record until \
         when it keeps passing (`valid_until`, Unix seconds): the first \
         certificate validity bound past which the same process, over the \
         evidence the document carries, no longer reaches TOTAL_PASSED. A \
         signature that passes past every bound has none, and a pass where \
         no signature has one lists no `valid_until`.\n",
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
    json!({
        "dss": summary["dss"],
        "corpus_commit": summary["corpus_commit"],
        "instant": summary["instant"],
        "cases": cases,
    })
}

/// `reviews` without the reviews no pass of `summary` observes, the ones the
/// check reports as matching no observation.
pub(crate) fn pruned(summary: &Value, reviews: &Value) -> Value {
    let mut kept = Map::new();
    for (name, list) in reviews.as_object().into_iter().flatten() {
        let live: Vec<Value> = list
            .as_array()
            .into_iter()
            .flatten()
            .filter(|review| {
                summary["cases"][name]
                    .as_object()
                    .into_iter()
                    .flatten()
                    .any(|(_, pass)| {
                        review_for(&json!({ name: [review] }), name, &pass["observed"]).is_some()
                    })
            })
            .cloned()
            .collect();
        if !live.is_empty() {
            kept.insert(name.clone(), Value::Array(live));
        }
    }
    Value::Object(kept)
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
                .any(|(_, pass)| {
                    review_for(&json!({ name: [review] }), name, &pass["observed"]).is_some()
                });
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
    // The release and the corpus commit resolve at run time and are the
    // provenance of the recording, not a condition of it: a new release that
    // observes every input as recorded passes, and its new or changed inputs
    // fail below. The validation instant is a condition of every observation.
    if expected["instant"] != summary["instant"] {
        found.push(format!(
            "the run validated at {} where the expectations record {}",
            summary["instant"], expected["instant"]
        ));
    }
    let reviewed = &expected["cases"];
    for (name, passes) in summary["cases"].as_object().into_iter().flatten() {
        for (label, pass) in passes.as_object().into_iter().flatten() {
            // A failed run is a defect of the comparison, never a
            // classification a review or a recording can accept.
            let before = found.len();
            found.extend(failures(pass).map(|failure| format!("{name} {label}: {failure}")));
            if found.len() > before {
                continue;
            }
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

/// Whether one signature's block result `old` concludes as `new` does, in
/// the observation whose overall comparison is `overall`: both sides the
/// same, or our bare `fail` where the new form spells a conclusion that says
/// no more than the old one did. That is the conclusion of the ETSI decision
/// the overall comparison already shows, at the block that decision names,
/// or DSS's own conclusion at a block that agreed then and agrees now.
fn same_conclusion(name: &str, old: &str, new: &str, overall: &str) -> bool {
    if old == new {
        return true;
    }
    let (Some((old_dss, old_ours)), Some((new_dss, new_ours))) =
        (old.split_once('/'), new.split_once('/'))
    else {
        return false;
    };
    if old_dss != new_dss || old_ours != "fail" {
        return false;
    }
    let ours = overall.split_once('/').map_or("", |(_, ours)| ours);
    let (indication, sub) = ours.split_once(':').unwrap_or((ours, "-"));
    let sub = (sub != "-").then_some(sub);
    let decided = decision_block(&json!({ "sub": sub })) == Some(name)
        && new_ours == block_conclusion(indication, sub);
    decided || (agrees(old_dss, old_ours) && agrees(new_dss, new_ours))
}

/// Whether the observation `new` of one pass holds the conclusions `old`
/// held: every signature's overall comparison and every block's result.
fn same_conclusions(old: &Value, new: &Value) -> bool {
    let (Some(old), Some(new)) = (old.as_array(), new.as_array()) else {
        return false;
    };
    old.len() == new.len()
        && old.iter().zip(new).all(|(old, new)| {
            let overall = old["OVERALL"].as_str().unwrap_or_default();
            old["OVERALL"] == new["OVERALL"]
                && BLOCKS.iter().all(|name| {
                    same_conclusion(
                        name,
                        old[*name].as_str().unwrap_or_default(),
                        new[*name].as_str().unwrap_or_default(),
                        overall,
                    )
                })
        })
}

/// Each review of `reviews` moved onto the observations of `summary`: a
/// review that explained a pass of the `previous` expectations explains the
/// same pass now when every conclusion it explained is unchanged, whatever
/// form the block results took ([`same_conclusions`]). A review whose passes
/// now observe another conclusion, overall or of any block, is kept as it
/// was, for the check to report and a reviewer to write again.
pub(crate) fn carried(previous: &Value, summary: &Value, reviews: &Value) -> Value {
    let mut moved = Map::new();
    for (name, list) in reviews.as_object().into_iter().flatten() {
        let mut kept = Vec::new();
        for review in list.as_array().into_iter().flatten() {
            let mut observed: Vec<Value> = Vec::new();
            for (label, pass) in previous["cases"][name].as_object().into_iter().flatten() {
                let explained = review["observed"]
                    .as_array()
                    .is_some_and(|approved| approved.contains(&pass["observed"]));
                let now = &summary["cases"][name][label]["observed"];
                if explained
                    && !now.is_null()
                    && overall_of(now) == review["overall"]
                    && same_conclusions(&pass["observed"], now)
                    && !observed.contains(now)
                {
                    observed.push(now.clone());
                }
            }
            let mut review = review.clone();
            if !observed.is_empty() {
                review["observed"] = Value::Array(observed);
            }
            kept.push(review);
        }
        moved.insert(name.clone(), Value::Array(kept));
    }
    Value::Object(moved)
}

/// The summary of the completed run in `results`, compared again from the
/// facts and reports it kept: the comparison reads them as it does now.
fn recompared(results: &Path) -> Result<Value, String> {
    let mut summary: Value = serde_json::from_str(&xml::read(&results.join("summary.json"))?)
        .map_err(|error| error.to_string())?;
    let mut cases = Vec::new();
    let mut conditions = Map::new();
    for name in summary["cases"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(name, _)| name)
    {
        let directory = results.join("cases").join(slug(name));
        let written = xml::read(&directory.join("conditions.stdout"))?;
        // A conditions probe that failed wrote no JSON; its run records why.
        let found = serde_json::from_str(&written).unwrap_or_else(|_| {
            json!({
                "anchors": 0,
                "probe": xml::read(&directory.join("conditions.stderr")).unwrap_or_default(),
            })
        });
        cases.push((name.clone(), PathBuf::new(), directory, INSTANT));
        conditions.insert(name.clone(), found);
    }
    let saved = summary.clone();
    summary["cases"] = Value::Object(observations(&cases, &conditions)?);
    // Before the saved summary is replaced.
    complete(&saved, &summary)?;
    write_json(&results.join("summary.json"), &summary)?;
    Ok(summary)
}

/// `reviews` with one more review of input `name`, of `class` for `reason`,
/// over each pass of `summary` that no review explains yet, one review per
/// overall comparison those passes observe; only the passes `labels` names
/// when it names any.
pub(crate) fn reviewed(
    summary: &Value,
    reviews: &Value,
    name: &str,
    class: &str,
    reason: &str,
    labels: &[&str],
) -> Result<Value, String> {
    if !REVIEWED.contains(&class) || reason.trim().is_empty() {
        return Err(format!(
            "a review takes one of {} and a reason",
            REVIEWED.join(", ")
        ));
    }
    let passes = summary["cases"][name]
        .as_object()
        .ok_or_else(|| format!("{name} is not in the run"))?;
    let mut groups: Vec<(Value, Vec<Value>)> = Vec::new();
    for (label, pass) in passes {
        if pass["class"] != "unreviewed"
            || review_for(reviews, name, &pass["observed"]).is_some()
            || !(labels.is_empty() || labels.contains(&label.as_str()))
        {
            continue;
        }
        let overall = overall_of(&pass["observed"]);
        match groups.iter_mut().find(|(known, _)| *known == overall) {
            Some((_, observed)) if !observed.contains(&pass["observed"]) => {
                observed.push(pass["observed"].clone());
            }
            Some(_) => {}
            None => groups.push((overall, vec![pass["observed"].clone()])),
        }
    }
    if groups.is_empty() {
        return Err(format!("{name} has no difference left to review"));
    }
    let mut reviews = reviews.clone();
    if reviews[name].is_null() {
        reviews[name] = json!([]);
    }
    let list = reviews[name]
        .as_array_mut()
        .ok_or_else(|| format!("the reviews of {name} are not a list"))?;
    for (overall, observed) in groups {
        list.push(json!({
            "overall": overall,
            "observed": observed,
            "class": class,
            "reason": reason,
        }));
    }
    Ok(reviews)
}

/// Adds a review of `name` to the reviews and records the expectations of
/// the completed run in `results` with them.
fn review(
    corpus: &Corpus,
    results: &Path,
    name: &str,
    class: &str,
    reason: &str,
    labels: &[&str],
) -> Result<(), String> {
    let summary: Value = serde_json::from_str(&xml::read(&results.join("summary.json"))?)
        .map_err(|error| error.to_string())?;
    recordable(&summary)?;
    let reviews = reviewed(
        &summary,
        &read_reviews(&reviews_path(corpus))?,
        name,
        class,
        reason,
        labels,
    )?;
    write_json(&reviews_path(corpus), &reviews)?;
    let expectations = recorded(&summary, &reviews);
    write_json(&expectations_path(corpus), &expectations)?;
    super::write(&report_path(corpus), report(&expectations))
}

/// Drops the reviews the completed run in `results` observes no more and
/// records the expectations with the rest.
fn prune(corpus: &Corpus, results: &Path) -> Result<(), String> {
    let summary: Value = serde_json::from_str(&xml::read(&results.join("summary.json"))?)
        .map_err(|error| error.to_string())?;
    recordable(&summary)?;
    let reviews = pruned(&summary, &read_reviews(&reviews_path(corpus))?);
    write_json(&reviews_path(corpus), &reviews)?;
    let expectations = recorded(&summary, &reviews);
    write_json(&expectations_path(corpus), &expectations)?;
    super::write(&report_path(corpus), report(&expectations))
}

/// Rewrites the reviews and the expectations from the completed run in
/// `results`, compared again, the committed reviews carried from the
/// committed expectations.
fn carry(corpus: &Corpus, results: &Path) -> Result<(), String> {
    let summary = recompared(results)?;
    recordable(&summary)?;
    // Both from the commit, so carrying again starts where the first did.
    let committed = |path: &Path, log: &str| -> Result<Value, String> {
        let relative = path
            .strip_prefix(&corpus.root)
            .map_err(|error| error.to_string())?;
        let shown = corpus.require(
            &line(&[
                &"git",
                &"-C",
                &corpus.root,
                &"show",
                &format!("HEAD:{}", relative.display()),
            ]),
            &results.join(log),
        )?;
        serde_json::from_slice(&shown.stdout).map_err(|error| error.to_string())
    };
    let path = expectations_path(corpus);
    let previous = committed(&path, "committed-expectations")?;
    let reviews = carried(
        &previous,
        &summary,
        &committed(&reviews_path(corpus), "committed-reviews")?,
    );
    write_json(&reviews_path(corpus), &reviews)?;
    let expectations = recorded(&summary, &reviews);
    write_json(&path, &expectations)?;
    super::write(&report_path(corpus), report(&expectations))
}

pub(crate) fn run(corpus: &Corpus, args: &[String]) -> Result<(), crate::repo::Failure> {
    let usage = "usage: xades dss-corpus [--results DIR] [--record] \
         | xades dss-corpus --carry-reviews DIR \
         | xades dss-corpus --prune-reviews DIR \
         | xades dss-corpus --review DIR INPUT CLASS REASON [PASS...]";
    let mut results = corpus.root.join("target/xades-dss-corpus");
    let mut record = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--record" => record = true,
            "--results" => {
                results = absolute(args.next().ok_or("--results needs a directory")?)?;
            }
            "--review" => {
                let rest: Vec<&str> = args.by_ref().map(String::as_str).collect();
                let [completed, name, class, reason, ref labels @ ..] = rest[..] else {
                    return Err(usage.into());
                };
                return Ok(review(
                    corpus,
                    &absolute(completed)?,
                    name,
                    class,
                    reason,
                    labels,
                )?);
            }
            "--prune-reviews" => {
                let completed = absolute(args.next().ok_or("--prune-reviews needs a directory")?)?;
                if args.next().is_some() {
                    return Err(usage.into());
                }
                return Ok(prune(corpus, &completed)?);
            }
            "--carry-reviews" => {
                let completed = absolute(args.next().ok_or("--carry-reviews needs a directory")?)?;
                if args.next().is_some() {
                    return Err(usage.into());
                }
                return Ok(carry(corpus, &completed)?);
            }
            _ => return Err(usage.into()),
        }
    }
    Ok(execute(corpus, &results, record)?)
}
