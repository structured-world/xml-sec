//! B-T and B-LT augmentation through the public API, for the augmentation
//! fixtures and independent validation. Every assessment runs at Unix time
//! 1800000000 against `FIXTURES/root.der`.
//!
//! `request` and `complete` create the enveloped B-B signature `sig` with
//! `FIXTURES/signer.key` and the `signer.der`/`intermediate.der` chain.
//!
//! `augment_probe request FIXTURES OUTPUT` writes its timestamp requests to
//! `OUTPUT`: `request.tsq` with a nonce, `request-policy.tsq` that also asks
//! for a policy, and `request-no-nonce.tsq` without a nonce.
//!
//! `augment_probe complete FIXTURES OUTPUT` completes `request.tsq` with
//! `FIXTURES/response.tsr` and writes the B-T document `OUTPUT/b-t.xml`.
//!
//! `augment_probe extend LEVELS OUTPUT` adds validation data to the B-T
//! signature of `LEVELS/b-t.xml`, from the level fixtures: the CRLs and OCSP
//! response OpenSSL issued for its PKI, as `LEVELS/b-lt.xml` carries them. It
//! writes the B-LT document `OUTPUT/b-lt.xml`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use structured_asn1::Oid;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_pkix::algorithm::digest::Algorithm;
use structured_pkix::temporal::LeapTable;
use xml_sec::XmlDocument;
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::policy::{Instant, SigningPolicy, VerificationPolicy};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, KeyResolverConfig, RsaSigningKey, SignatureAlgorithm,
    UriTypeSet, VerificationRequest, VerifyContext,
};
use xml_sec_xades::{
    Assessment, Completion, DataObject, Envelope, Inputs, PendingTimestamp, Request, Requirements,
    Signer, TimestampRequest, ValidationData, add_validation_data, complete_timestamp, create,
    request_timestamp,
};

const DOCUMENT: &str = "<Document><Data Id=\"payload\">Augmented payload</Data></Document>";
const TIME: &str = "2026-10-18T12:00:00Z";
/// The nonce every request with one carries.
const NONCE: &[u8] = &[0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71];
/// `1.3.6.1.4.1.13762.4`, a policy the test TSA does not issue under.
const OTHER_POLICY: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xeb, 0x42, 0x04];

fn read(directory: &Path, name: &str) -> Result<Vec<u8>, String> {
    std::fs::read(directory.join(name)).map_err(|error| format!("read {name}: {error}"))
}

/// The verification of every assessment: chains to `root` at the fixed instant.
fn verification() -> VerificationPolicy {
    let mut verification = VerificationPolicy::default();
    verification.key_trust.verify_x509_chains = true;
    verification.key_trust.verification_time = Instant::new(1_800_000_000, 0);
    verification
}

fn utc() -> Result<LeapTable<'static>, String> {
    LeapTable::new(-2_208_988_800, 4_102_444_800, &[])
        .map_err(|error| format!("UTC coverage: {error:?}"))
}

fn main() -> Result<(), String> {
    let mut args = std::env::args_os().skip(1);
    let usage = "usage: augment_probe request|complete|extend FIXTURES OUTPUT";
    let (Some(action), Some(fixtures), Some(output), None) =
        (args.next(), args.next(), args.next(), args.next())
    else {
        return Err(usage.into());
    };
    let (fixtures, output) = (PathBuf::from(fixtures), PathBuf::from(output));
    std::fs::create_dir_all(&output).map_err(|error| error.to_string())?;
    if action.to_str() == Some("extend") {
        return extend(&fixtures, &output);
    }
    let root = read(&fixtures, "root.der")?;
    let intermediate = read(&fixtures, "intermediate.der")?;
    let signer_der = read(&fixtures, "signer.der")?;
    let key_pem = String::from_utf8(read(&fixtures, "signer.key")?)
        .map_err(|error| format!("signer.key: {error}"))?;
    let key = RsaSigningKey::from_pkcs8_pem(&key_pem).map_err(|error| error.to_string())?;
    let mut signing = SigningPolicy::default();
    signing.uris.references = UriTypeSet::ALL;
    let chain: [&[u8]; 2] = [&signer_der, &intermediate];
    let signer = Signer {
        key: &key,
        provider: xml_sec::provider::default_provider(),
        policy: &signing,
        chain: &chain,
        method: SignatureAlgorithm::RsaSha256,
        digest: DigestAlgorithm::Sha256,
        canonicalization: C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
    };
    let resolver = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: vec![root.clone()],
        ..KeyResolverConfig::default()
    });
    let context = VerifyContext::new()
        .policy(verification())
        .key_resolver(&resolver);
    let request = VerificationRequest::default();
    let assessment = Assessment {
        context: &context,
        request: &request,
        certificates: &[&root],
    };
    let work = Memory::new(Arc::new(MemoryAccount::new(1 << 26, 1 << 30)));
    let mut document = created(&signer, &assessment, &work)?;
    let timestamp = |policy, nonce| TimestampRequest {
        signature: "sig",
        digest: Algorithm::Sha256,
        policy,
        nonce,
        id_attributes: &[],
    };
    let write = |name: &str, bytes: &[u8]| {
        std::fs::write(output.join(name), bytes).map_err(|error| format!("{name}: {error}"))
    };
    let pending = request_timestamp(&document, &timestamp(None, Some(NONCE)), &assessment, &work)
        .map_err(|error| format!("request: {error}"))?;
    match action.to_str() {
        Some("request") => {
            write("request.tsq", pending.request())?;
            for (name, policy, nonce) in [
                (
                    "request-policy.tsq",
                    Some(Oid::from_bytes(OTHER_POLICY)),
                    Some(NONCE),
                ),
                ("request-no-nonce.tsq", None, None),
            ] {
                let variant =
                    request_timestamp(&document, &timestamp(policy, nonce), &assessment, &work)
                        .map_err(|error| format!("{name}: {error}"))?;
                write(name, variant.request())?;
            }
        }
        Some("complete") => {
            let response = read(&fixtures, "response.tsr")?;
            complete(
                &mut document,
                &pending,
                &response,
                &assessment,
                [&root, &intermediate],
                &work,
            )?;
            write("b-t.xml", document.as_xml().as_bytes())?;
        }
        _ => return Err(usage.into()),
    }
    Ok(())
}

/// The B-B signature `sig` over the whole document.
fn created(
    signer: &Signer<'_>,
    assessment: &Assessment<'_, '_>,
    work: &Memory,
) -> Result<XmlDocument, String> {
    let mut document = XmlDocument::parse(DOCUMENT).map_err(|error| error.to_string())?;
    create(
        &mut document,
        signer,
        Request {
            id: "sig",
            signing_time: TIME,
            objects: vec![DataObject::Document {
                mime_type: "text/xml",
                envelope: Envelope::Enveloped,
            }],
            parent: None,
            resources: None,
            id_attributes: &[],
        },
        assessment,
        work,
    )
    .map_err(|error| format!("create: {error}"))?;
    Ok(document)
}

/// Add the token of `response` and require B-T, with the TSA's path ending
/// at `root` through `intermediate`.
fn complete(
    document: &mut XmlDocument,
    pending: &PendingTimestamp,
    response: &[u8],
    assessment: &Assessment<'_, '_>,
    [root, intermediate]: [&[u8]; 2],
    work: &Memory,
) -> Result<(), String> {
    let utc = utc()?;
    let inputs = Inputs {
        requirements: Requirements::Timestamped,
        anchors: &[root],
        certificates: &[intermediate],
        utc: &utc,
        accuracies: &[],
        responders: &[],
        crls: &[],
        responses: &[],
    };
    let completion = Completion {
        assessment,
        inputs: &inputs,
        window: None,
        id_attributes: &[],
    };
    complete_timestamp(document, pending, response, &completion, work)
        .map_err(|error| format!("complete: {error}"))
}

/// The DER of every distinct `xades:{local}` value of `xml`, in document order.
fn values(xml: &str, local: &str) -> Result<Vec<Vec<u8>>, String> {
    let (open, close) = (format!("<xades:{local}>"), format!("</xades:{local}>"));
    let mut values: Vec<Vec<u8>> = Vec::new();
    for (start, _) in xml.match_indices(&open) {
        let start = start + open.len();
        let end = start
            + xml[start..]
                .find(&close)
                .ok_or_else(|| format!("unterminated {local}"))?;
        let value = STANDARD
            .decode(&xml[start..end])
            .map_err(|error| format!("{local}: {error}"))?;
        if !values.contains(&value) {
            values.push(value);
        }
    }
    Ok(values)
}

/// Add the issued CRLs and OCSP response to the B-T level fixture and require B-LT.
fn extend(levels: &Path, output: &Path) -> Result<(), String> {
    let text = |name: &str| {
        String::from_utf8(read(levels, name)?).map_err(|error| format!("{name}: {error}"))
    };
    let root = read(levels, "root.der")?;
    let issued = text("b-lt.xml")?;
    let crls = values(&issued, "EncapsulatedCRLValue")?;
    let responses = values(&issued, "EncapsulatedOCSPValue")?;
    let crls: Vec<&[u8]> = crls.iter().map(Vec::as_slice).collect();
    let responses: Vec<&[u8]> = responses.iter().map(Vec::as_slice).collect();
    let mut document = XmlDocument::parse(&text("b-t.xml")?).map_err(|error| error.to_string())?;
    let resolver = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: vec![root.clone()],
        ..KeyResolverConfig::default()
    });
    let context = VerifyContext::new()
        .policy(verification())
        .key_resolver(&resolver);
    let request = VerificationRequest::default();
    let utc = utc()?;
    let work = Memory::new(Arc::new(MemoryAccount::new(1 << 26, 1 << 30)));
    add_validation_data(
        &mut document,
        &ValidationData {
            signature: "sig",
            assessment: &Assessment {
                context: &context,
                request: &request,
                certificates: &[],
            },
            inputs: &Inputs {
                requirements: Requirements::LongTerm,
                anchors: &[&root],
                certificates: &[],
                utc: &utc,
                accuracies: &[],
                responders: &[],
                crls: &crls,
                responses: &responses,
            },
            id_attributes: &[],
        },
        &work,
    )
    .map_err(|error| format!("extend: {error}"))?;
    std::fs::write(output.join("b-lt.xml"), document.as_xml())
        .map_err(|error| format!("b-lt.xml: {error}"))
}
