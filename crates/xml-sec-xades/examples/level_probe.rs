//! One baseline level of every signature of a document, through the public API.
//!
//! `level_probe XML ANCHOR_DER UNIX_TIME b|t|lt|lta [ACCURACY_SECONDS]`, where
//! `ANCHOR_DER` may be `-` to anchor where each chain the document carries ends,
//! and `ACCURACY_SECONDS` states that accuracy for the policy
//! of every token the document carries. Both are interoperability settings for
//! test corpora, never a trust decision.

use std::convert::Infallible;
use std::sync::Arc;

use base64::Engine as _;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Oid, Parser};
use structured_cms::timestamp::{Accuracy, PolicyAccuracy, Token};
use structured_pkix::Certificate;
use structured_pkix::temporal::LeapTable;
use xml_sec::XmlDocument;
use xml_sec::policy::{Instant, VerificationPolicy};
use xml_sec::xmldsig::{
    DefaultKeyResolver, KeyResolverConfig, VerificationRequest, VerifyContext,
    with_verified_request,
};
use xml_sec_xades::{
    AuthorityAccuracy, ConfiguredResponder, Inputs, Requirements, TokenProfile, validate,
};

/// Every base64 value between `open` and `close` in the source text.
fn values(text: &str, tag: &str) -> Vec<Vec<u8>> {
    let mut found = Vec::new();
    for (start, _) in text.match_indices(tag) {
        let closing = text[..start]
            .rfind('<')
            .is_some_and(|tag| text[tag..].starts_with("</"));
        let Some(open) = text[start..].find('>').filter(|_| !closing) else {
            continue;
        };
        let body = start + open + 1;
        let Some(end) = text[body..].find('<') else {
            continue;
        };
        let compact: String = text[body..body + end]
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect();
        if let Ok(value) = base64::engine::general_purpose::STANDARD.decode(compact) {
            found.push(value);
        }
    }
    found
}

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

/// A DER certificate and a token's encoded policy identifier.
type Authority = (Vec<u8>, Vec<u8>);

/// Each certificate a token or the document carries, with the token's policy.
fn token_authorities(text: &str, carried: &[Vec<u8>]) -> Result<Vec<Authority>, String> {
    let mut found = Vec::new();
    for token in values(text, "EncapsulatedTimeStamp") {
        let parser = Parser::ber(Memory::new(Arc::new(MemoryAccount::new(1 << 24, 1 << 28))));
        let token = Token::read(&parser, &token, 0).map_err(|error| format!("{error:?}"))?;
        let parent = parser.read(&[], 0).map_err(|error| format!("{error:?}"))?;
        let policy = token
            .with_info(&parent, |info, _, _| {
                Ok::<_, Infallible>(info.policy().as_bytes().to_vec())
            })
            .map_err(|error| format!("{error:?}"))?;
        let own = token.message().certificates().iter();
        for certificate in own.map(|parsed| parsed.as_bytes().to_vec()) {
            found.push((certificate, policy.clone()));
        }
        for certificate in carried {
            found.push((certificate.clone(), policy.clone()));
        }
    }
    Ok(found)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let [_, xml, anchor, at, level, rest @ ..] = &args[..] else {
        return Err(
            "usage: level_probe XML ANCHOR_DER|- UNIX_TIME b|t|lt|lta [ACCURACY_SECONDS [cms]]"
                .into(),
        );
    };
    let seconds = rest.first().map(|value| value.parse()).transpose()?;
    let token_profile = match rest.get(1) {
        Some(profile) if profile == "cms" => TokenProfile::Cms,
        _ => TokenProfile::Etsi,
    };
    let requirements = match level.as_str() {
        "b" => Requirements::Basic,
        "t" => Requirements::Timestamped,
        "lt" => Requirements::LongTerm,
        "lta" => Requirements::Archival,
        _ => return Err("the level is b, t, lt or lta".into()),
    };
    let text = std::fs::read_to_string(xml)?;
    let carried = values(&text, "X509Certificate");
    let mut authorities = token_authorities(&text, &carried)?;
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
    let resolver = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: anchors.clone(),
        ..KeyResolverConfig::default()
    });
    let mut policy = VerificationPolicy::default();
    policy.key_trust.verify_x509_chains = true;
    policy.key_trust.verification_time = Instant::new(at.parse()?, 0);
    let context = VerifyContext::new().policy(policy).key_resolver(&resolver);
    let document = XmlDocument::parse(text.as_str())?;
    let request = VerificationRequest::default();
    let account = Memory::new(Arc::new(MemoryAccount::new(1 << 27, 1 << 33)));
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
    let mut accuracies = Vec::with_capacity(authorities.len());
    for (authority, policy) in &authorities {
        let accuracy = Accuracy::new(seconds.unwrap_or_default(), 0, 0);
        accuracies.push(AuthorityAccuracy {
            authority,
            stated: PolicyAccuracy::new(Oid::from_bytes(policy), accuracy)
                .map_err(|error| error.to_string())?,
        });
    }
    with_verified_request(&document, &context, &request, &account, |session| {
        for entry in session.evidence().signatures() {
            println!("signature: {:?}", entry.result().as_ref().map(|r| r.status));
            let inputs = Inputs {
                requirements,
                token_profile,
                anchors: &references,
                certificates: &others,
                utc: &utc,
                accuracies: &accuracies,
                responders: &responders,
                crls: &[],
                responses: &[],
            };
            let outcome = validate(&session, entry.identity(), &inputs, |level| {
                level.all_requirements_met()
            });
            println!("level: {outcome:?}");
        }
        Ok(())
    })?;
    Ok(())
}
