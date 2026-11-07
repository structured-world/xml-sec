//! One baseline level of every signature of a document, through the public API.
//!
//! `level_probe XML ANCHOR_DER UNIX_TIME b|t|lt|lta [ACCURACY_SECONDS [cms]]
//! [--detached FILE]`, where `ANCHOR_DER` may be `-` to anchor where each
//! chain the document carries ends, `ACCURACY_SECONDS` states that accuracy
//! for the policy of every token the document carries, and `FILE` supplies the
//! detached object a reference names by the file's name. The anchor and the
//! accuracy are interoperability settings for test corpora, never a trust
//! decision. `--samples N` times `N` runs from the serialized document to the
//! levels (see `timing`).

#[path = "support/timing.rs"]
mod timing;
#[path = "support/tokens.rs"]
mod tokens;

use std::collections::BTreeMap;
use std::sync::Arc;

use structured_asn1::Parser;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_pkix::Certificate;
use structured_pkix::temporal::LeapTable;
use xml_sec::XmlDocument;
use xml_sec::policy::{Instant, TimestampTokenEncoding, VerificationPolicy};
use xml_sec::xmldsig::{
    DefaultKeyResolver, KeyResolverConfig, UriTypeSet, VerificationRequest, VerifyContext,
    with_verified_request,
};
use xml_sec_xades::{ConfiguredResponder, Inputs, Requirements, validate};

/// Where the chain of `certificate` ends among `pool`: it is self-issued, or
/// `pool` holds no other certificate naming its issuer.
fn terminal(certificate: &[u8], pool: &[Vec<u8>]) -> bool {
    let account = Memory::new(Arc::new(MemoryAccount::new(1 << 24, 1 << 28)));
    let parser = Parser::der(account.clone());
    let Ok(parsed) = Certificate::read(&parser, certificate, 0) else {
        return false;
    };
    let issuer = parsed.tbs().issuer();
    let names = |other: &Certificate<'_>| {
        other
            .tbs()
            .subject()
            .matches(issuer, &account)
            .unwrap_or(false)
    };
    names(&parsed)
        || !pool
            .iter()
            .filter(|other| other.as_slice() != certificate)
            .filter_map(|other| Certificate::read(&parser, other, 0).ok())
            .any(|other| names(&other))
}

/// The `--detached FILE` object, by its file name, taken out of `args`.
fn detached(
    args: &mut Vec<String>,
) -> Result<BTreeMap<String, Vec<u8>>, Box<dyn std::error::Error>> {
    let mut resources = BTreeMap::new();
    if let Some(flag) = args.iter().position(|arg| arg == "--detached") {
        let path = args.get(flag + 1).ok_or("--detached needs a file")?.clone();
        let name = std::path::Path::new(&path)
            .file_name()
            .ok_or("--detached needs a file")?
            .to_string_lossy()
            .into_owned();
        resources.insert(name, std::fs::read(&path)?);
        args.drain(flag..flag + 2);
    }
    Ok(resources)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args: Vec<String> = std::env::args().collect();
    let samples = timing::sampling(&mut args)?;
    let resources = detached(&mut args)?;
    let [_, xml, anchor, at, level, rest @ ..] = &args[..] else {
        return Err("usage: level_probe XML ANCHOR_DER|- UNIX_TIME b|t|lt|lta [ACCURACY_SECONDS [cms]] [--detached FILE]".into());
    };
    let seconds: Option<u64> = rest.first().map(|value| value.parse()).transpose()?;
    let timestamp_token_encoding = match rest.get(1) {
        Some(profile) if profile == "cms" => TimestampTokenEncoding::Ber,
        _ => TimestampTokenEncoding::Declared,
    };
    let requirements = match level.as_str() {
        "b" => Requirements::Basic,
        "t" => Requirements::Timestamped,
        "lt" => Requirements::LongTerm,
        "lta" => Requirements::Archival,
        _ => return Err("the level is b, t, lt or lta".into()),
    };
    let text = std::fs::read_to_string(xml)?;
    let Material {
        carried,
        mut authorities,
        pool,
        anchors,
    } = Material::read(&text, anchor)?;
    let resolver = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: anchors.clone(),
        ..KeyResolverConfig::default()
    });
    let mut policy = VerificationPolicy::default();
    policy.key_trust.verify_x509_chains = true;
    policy.key_trust.verification_time = Instant::new(at.parse()?, 0);
    policy.timestamp_token_encoding = timestamp_token_encoding;
    if !resources.is_empty() {
        policy.uris.references = UriTypeSet::ALL;
    }
    let context = VerifyContext::new().policy(policy).key_resolver(&resolver);
    let request = VerificationRequest {
        external_resources: (!resources.is_empty()).then_some(&resources),
        ..VerificationRequest::default()
    };
    let utc = LeapTable::new(-2_208_988_800, 4_102_444_800, &[])
        .map_err(|error| format!("UTC coverage: {error:?}"))?;
    let references: Vec<&[u8]> = anchors.iter().map(Vec::as_slice).collect();
    let others: Vec<&[u8]> = carried.iter().map(Vec::as_slice).collect();
    if seconds.is_none() {
        authorities.clear();
    }
    let mut responders = Vec::new();
    if seconds.is_some() {
        for responder in &pool {
            for issuer in &pool {
                responders.push(ConfiguredResponder { responder, issuer });
            }
        }
    }
    let accuracies = tokens::stated(&authorities, seconds.unwrap_or_default())?;
    let inputs = Inputs {
        requirements,
        anchors: &references,
        certificates: &others,
        utc: &utc,
        accuracies: &accuracies,
        responders: &responders,
        crls: &[],
        responses: &[],
    };
    // The verification and the level of every signature, as report lines.
    let levels = |account: &Memory| -> Result<String, String> {
        let document = XmlDocument::parse(text.as_str()).map_err(|error| error.to_string())?;
        let mut lines = Vec::new();
        with_verified_request(&document, &context, &request, account, |session| {
            for entry in session.evidence().signatures() {
                let status = entry.result().as_ref().map(|r| r.status);
                let outcome = validate(&session, entry.identity(), &inputs, |level| {
                    level.all_requirements_met()
                });
                lines.push(format!("signature: {status:?}\nlevel: {outcome:?}\n"));
            }
            Ok(())
        })
        .map_err(|error| error.to_string())?;
        Ok(lines.concat())
    };
    Ok(emit(
        samples,
        &format!("validate-{level}"),
        text.len(),
        levels,
    )?)
}

/// What a document carries for its own validation, and the anchors chosen.
struct Material {
    carried: Vec<Vec<u8>>,
    authorities: Vec<tokens::Authority>,
    /// Every certificate the document and its tokens carry, once.
    pool: Vec<Vec<u8>>,
    anchors: Vec<Vec<u8>>,
}

impl Material {
    /// `ANCHOR_DER`, or with `-` where each carried chain ends.
    fn read(text: &str, anchor: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let carried = tokens::values(text, "X509Certificate");
        let authorities = tokens::token_authorities(text, &carried)?;
        let mut pool = carried.clone();
        pool.extend(
            authorities
                .iter()
                .map(|(certificate, _)| certificate.clone()),
        );
        pool.sort();
        pool.dedup();
        let anchors: Vec<Vec<u8>> = if anchor == "-" {
            pool.iter()
                .filter(|c| terminal(c, &pool))
                .cloned()
                .collect()
        } else {
            vec![std::fs::read(anchor)?]
        };
        Ok(Self {
            carried,
            authorities,
            pool,
            anchors,
        })
    }
}

/// Prints the report lines of one run of `levels`, or with `samples` times
/// it and prints the measurement after them.
fn emit(
    samples: Option<timing::Sampling>,
    operation: &str,
    input_bytes: usize,
    mut levels: impl FnMut(&Memory) -> Result<String, String>,
) -> Result<(), String> {
    let account = || Memory::new(Arc::new(MemoryAccount::new(1 << 27, 1 << 33)));
    let Some(samples) = samples else {
        print!("{}", levels(&account())?);
        return Ok(());
    };
    let measurement = timing::measure(
        samples,
        || Ok::<_, String>(account()),
        |work| levels(&work),
        |lines| Some(lines.clone().into_bytes()),
    )?;
    print!(
        "{}",
        String::from_utf8_lossy(measurement.output.as_deref().unwrap_or_default())
    );
    println!("{}", timing::report(operation, input_bytes, &measurement));
    Ok(())
}
