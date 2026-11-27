//! B-T, B-LT and B-LTA augmentation through the public API, for the
//! augmentation fixtures and independent validation. Every assessment runs at
//! Unix time 1800000000 against `FIXTURES/root.der`.
//!
//! Every action but `extend` creates the enveloped B-B signature `sig` with
//! `FIXTURES/signer.key` and the `signer.der`/`intermediate.der` chain.
//!
//! `augment_probe request FIXTURES OUTPUT` writes its timestamp requests to
//! `OUTPUT`: `request.tsq` with a nonce, `request-policy.tsq` that also asks
//! for a policy, and `request-no-nonce.tsq` without a nonce.
//!
//! `augment_probe content-request FIXTURES OUTPUT` writes the content
//! timestamp requests of a new signature: `content-all.tsq` and
//! `content-individual.tsq`, and `content-changing.tsq` of a signature whose
//! reference covers its own qualifying properties, and `signature.tsq`, the
//! signature timestamp request of the B-B signature `sig`. `augment_probe content
//! FIXTURES OUTPUT` completes the first two with `FIXTURES/content-all.tsr`
//! and `FIXTURES/content-individual.tsr` and writes the signature as
//! `OUTPUT/content-timestamps.xml`.
//!
//! `augment_probe refresh FIXTURES OUTPUT`, over the content fixtures,
//! completes `signature.tsq` with `FIXTURES/signature.tsr`, adds the first
//! generation of CRLs and refreshes the B-LT signature with the next, written
//! as `OUTPUT/b-lt-refreshed.xml`.
//!
//! `augment_probe x-request|a-request|extended FIXTURES OUTPUT`, over the
//! content fixtures, completes `signature.tsq` with `FIXTURES/signature.tsr`
//! and takes the B-T signature through the TS 101 903 levels: `x-request`
//! writes `OUTPUT/x.tsq`, `a-request` completes it with `FIXTURES/x.tsr` and
//! writes `OUTPUT/a.tsq`, and `extended` completes both and writes
//! `OUTPUT/c.xml`, `x.xml`, `xl.xml` and `a.xml`.
//!
//! `augment_probe seal-signature-request|seal-request|seal|parallel-request|
//! parallel FIXTURES OUTPUT`, over the content fixtures, creates `sig`
//! excluding every signature from what it signs: `seal-signature-request`
//! writes its signature timestamp request `OUTPUT/seal-signature.tsq`; the
//! others complete it with `FIXTURES/seal-signature.tsr`, add the first
//! generation of CRLs and seal the B-LT signature with an evidence record:
//! `seal-request` writes `OUTPUT/seal.tsq`, `seal` completes it with
//! `FIXTURES/seal.tsr` and writes `OUTPUT/e-ers.xml`, `parallel-request`
//! writes the request of a parallel record `OUTPUT/parallel.tsq`, and
//! `parallel` completes it with `FIXTURES/parallel.tsr`, writes
//! `OUTPUT/e-ers-parallel.xml`, adds the parallel B-B signature `sig2` and
//! writes `OUTPUT/e-ers-signed.xml`.
//!
//! `augment_probe historical-request FIXTURES OUTPUT` creates `sig` in the
//! TS 103 171 profile of V1.3.2 and writes its signature timestamp request
//! `OUTPUT/historical.tsq`; `historical` completes it with
//! `FIXTURES/historical.tsr` and writes `OUTPUT/t-pre-en.xml`;
//! `historical-lt` then adds its validation values and writes
//! `OUTPUT/lt-pre-en.xml`. The same actions suffixed `-v111` or `-v122` do
//! this in the ETSI TS 101 903 V1.1.1 or V1.2.2 vocabulary, with
//! `historical-v111.tsq`/`.tsr` or `historical-v122.tsq`/`.tsr`, writing
//! `t-v111.xml` and `lt-v111.xml` or `t-v122.xml` and `lt-v122.xml`.
//! `pre-en-x-request`, `pre-en-a-request`, `pre-en-a2-request`,
//! `pre-en-lta-request` and `pre-en-levels` take the TS 103 171 signature on
//! through the TS 101 903 levels in the names of V1.3.2, as
//! `extended_levels::pre_en_levels` says. `prefixed-request-v111` and
//! `prefixed-v111` do the signature timestamp of a V1.1.1 signature whose
//! canonicalization names an `InclusiveNamespaces` `PrefixList`, with
//! `prefixed-v111.tsq`/`.tsr`, writing `t-v111-prefixed.xml`.
//!
//! `augment_probe complete FIXTURES OUTPUT` completes `request.tsq` with
//! `FIXTURES/response.tsr` and writes the B-T document `OUTPUT/b-t.xml`.
//!
//! The archive actions continue from that B-T document: they add the CRLs
//! `FIXTURES/root.crl` and `FIXTURES/intermediate.crl` and request the first
//! archive timestamp. `archive-request` writes `OUTPUT/archive.tsq`;
//! otherwise `FIXTURES/archive.tsr` completes it and the renewal is
//! requested, which `renewal-request` writes as `OUTPUT/renewal.tsq`.
//! `archive` completes both and writes `OUTPUT/b-lta.xml` and
//! `OUTPUT/b-lta-renewed.xml`.
//!
//! `augment_probe extend LEVELS OUTPUT` adds validation data to the B-T
//! signature of `LEVELS/b-t.xml`, from the level fixtures: the CRLs and OCSP
//! response OpenSSL issued for its PKI, as `LEVELS/b-lt.xml` carries them. It
//! writes the B-LT document `OUTPUT/b-lt.xml`.
//!
//! `augment_probe renew-request LEVELS OUTPUT` requests an archive timestamp
//! of the B-LT `Manifest` signature `LEVELS/b-lt-manifest.xml` with a SHA-512
//! renewal of its detached object `LEVELS/detached.txt`, written as
//! `OUTPUT/renew.tsq`. `augment_probe renew LEVELS OUTPUT` completes it with
//! `LEVELS/renew.tsr` and writes the B-LTA document `OUTPUT/b-lta-manifest.xml`.

#[path = "support/extended_levels.rs"]
mod extended_levels;
#[path = "support/sealing.rs"]
mod sealing;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use structured_asn1::Oid;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_pkix::algorithm::digest::Algorithm;
use structured_pkix::temporal::LeapTable;
use xml_sec::XmlDocument;
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::policy::{
    Instant, ManifestProcessing, SigningPolicy, VerificationPolicy, XadesSyntax,
};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, KeyResolverConfig, RsaSigningKey, SignatureAlgorithm,
    Transform, UriTypeSet, VerificationRequest, VerifyContext, XPathExpression,
};
use xml_sec_xades::properties::Profile;
use xml_sec_xades::{
    Assessment, Completion, ContentEvidence, ContentScope, ContentTimestamp, DataAdded, DataObject,
    DigestRenewal, Envelope, Inputs, PendingTimestamp, Request, Requirements, Signer,
    TimestampRequest, ValidationData, add_validation_data, complete_timestamp, create,
    refresh_validation_data, request_archive_timestamp, request_archive_timestamp_with_renewal,
    request_content_timestamps, request_timestamp,
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
    // The historical actions name their vocabulary; the policy reads it.
    verification.xades_syntax = XadesSyntax::WithHistoricalVocabularies;
    verification
}

fn utc() -> Result<LeapTable<'static>, String> {
    LeapTable::new(-2_208_988_800, 4_102_444_800, &[])
        .map_err(|error| format!("UTC coverage: {error:?}"))
}

fn main() -> Result<(), String> {
    let mut args = std::env::args_os().skip(1);
    let usage = "usage: augment_probe request|content-request|content|content-lta-request|content-lta-archive-request|content-lta|refresh|x-request|a-request|extended|pre-en-x-request|pre-en-a-request|pre-en-a2-request|pre-en-lta-request|pre-en-levels|prefixed-request-v111|prefixed-v111|seal-signature-request|seal-request|seal|parallel-request|parallel|complete|archive-request|renewal-request|archive|extend|renew-request|renew FIXTURES OUTPUT";
    let (Some(action), Some(fixtures), Some(output), None) =
        (args.next(), args.next(), args.next(), args.next())
    else {
        return Err(usage.into());
    };
    let (fixtures, output) = (PathBuf::from(fixtures), PathBuf::from(output));
    std::fs::create_dir_all(&output).map_err(|error| error.to_string())?;
    match action.to_str() {
        Some("extend") => return extend(&fixtures, &output),
        Some("renew-request") => return renew(&fixtures, &output, false),
        Some("renew") => return renew(&fixtures, &output, true),
        _ => {}
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
        prefixes: xml_sec_xades::Prefixes::default(),
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
    match action.to_str() {
        Some("content-request") => return content_requests(&signer, &assessment, &output, &work),
        Some("content") => {
            return content(
                &signer,
                &assessment,
                (&fixtures, &output),
                &intermediate,
                &work,
            );
        }
        Some(step @ ("content-lta-request" | "content-lta-archive-request" | "content-lta")) => {
            return content_lta(
                step,
                (&signer, &assessment),
                (&fixtures, &output),
                [&root, &intermediate],
                &work,
            );
        }
        _ => {}
    }
    let action = action.to_str().ok_or(usage)?;
    augmented(
        action,
        (&signer, &assessment),
        (&fixtures, &output),
        [&root, &intermediate],
        &work,
    )
    .map_err(|error| {
        if error.is_empty() {
            usage.into()
        } else {
            error
        }
    })
}

/// The actions `extended_levels::pre_en_levels` takes.
const PRE_EN_LEVELS: [&str; 5] = [
    "pre-en-x-request",
    "pre-en-a-request",
    "pre-en-a2-request",
    "pre-en-lta-request",
    "pre-en-levels",
];

/// The B-B signature `sig`, its timestamp requests, or its augmentation the
/// `action` names; an unknown action is an empty error.
fn augmented(
    action: &str,
    (signer, assessment): (&Signer<'_>, &Assessment<'_, '_>),
    (fixtures, output): (&Path, &Path),
    pki: [&[u8]; 2],
    work: &Memory,
) -> Result<(), String> {
    let write = |name: &str, bytes: &[u8]| {
        std::fs::write(output.join(name), bytes).map_err(|error| format!("{name}: {error}"))
    };
    let (step, profile) = match action.rsplit_once('-') {
        Some((step, "v111")) => (step, Profile::V111),
        Some((step, "v122")) => (step, Profile::V122),
        _ => (action, Profile::PreEn),
    };
    if matches!(step, "historical-request" | "historical" | "historical-lt") {
        let document = created_in(signer, assessment, Some(profile), Envelope::Enveloped, work)?;
        return extended_levels::historical(
            document,
            (profile, step),
            assessment,
            fixtures,
            pki,
            &write,
            work,
        );
    }
    if matches!(step, "prefixed-request" | "prefixed") {
        return prefixed(
            (signer, assessment),
            (step, profile),
            fixtures,
            pki,
            &write,
            work,
        );
    }
    if PRE_EN_LEVELS.contains(&action) {
        let document = created_in(
            signer,
            assessment,
            Some(Profile::PreEn),
            Envelope::Enveloped,
            work,
        )?;
        return extended_levels::pre_en_levels(
            document, action, assessment, fixtures, pki, &write, work,
        );
    }
    if matches!(
        action,
        "seal-signature-request" | "seal-request" | "seal" | "parallel-request" | "parallel"
    ) {
        return sealed((signer, assessment), fixtures, pki, action, &write, work);
    }
    let mut document = created(signer, assessment, work)?;
    let pending = request_timestamp(&document, &timestamp(None, Some(NONCE)), assessment, work)
        .map_err(|error| format!("request: {error}"))?;
    match action {
        "request" => {
            write("request.tsq", pending.request())?;
            requests(&document, assessment, &write, work)?;
        }
        "complete" | "archive-request" | "renewal-request" | "archive" | "refresh"
        | "x-request" | "x" | "a-request" | "a2-request" | "extended" => {
            // The content fixtures answer the same request as `signature.tsr`.
            let answer = if matches!(
                action,
                "refresh" | "x-request" | "x" | "a-request" | "a2-request" | "extended"
            ) {
                "signature.tsr"
            } else {
                "response.tsr"
            };
            let response = read(fixtures, answer)?;
            complete(&mut document, &pending, &response, assessment, pki, work)?;
            match action {
                "complete" => write("b-t.xml", document.as_xml().as_bytes())?,
                "refresh" => {
                    refreshed(&mut document, assessment, fixtures, pki, work)?;
                    write("b-lt-refreshed.xml", document.as_xml().as_bytes())?;
                }
                "x-request" | "x" | "a-request" | "a2-request" | "extended" => {
                    extended_levels::levels(
                        &mut document,
                        assessment,
                        fixtures,
                        pki,
                        action,
                        &write,
                        work,
                    )?;
                }
                _ => archived(
                    &mut document,
                    assessment,
                    fixtures,
                    pki,
                    action,
                    &write,
                    work,
                )?,
            }
        }
        _ => return Err(String::new()),
    }
    Ok(())
}

/// The signature `sig` in the vocabulary of `profile`, its canonicalization
/// naming the `InclusiveNamespaces` `PrefixList` `ds`: `prefixed-request` writes
/// its signature timestamp request `prefixed-<suffix>.tsq`, `prefixed`
/// completes it with `FIXTURES/prefixed-<suffix>.tsr` and writes
/// `t-<suffix>-prefixed.xml`.
fn prefixed(
    (signer, assessment): (&Signer<'_>, &Assessment<'_, '_>),
    (step, profile): (&str, Profile),
    fixtures: &Path,
    pki: [&[u8]; 2],
    write: &impl Fn(&str, &[u8]) -> Result<(), String>,
    work: &Memory,
) -> Result<(), String> {
    let (_, _, suffix) = extended_levels::historical_names(profile);
    let created = created_in(signer, assessment, Some(profile), Envelope::Enveloped, work)?;
    // This library's creation writes no SignedInfo method parameters, so the
    // signature is signed again from a template that names them.
    let resigned = xml_sec::xmldsig::SignContext::new(signer.key)
        .provider(signer.provider)
        .policy(signer.policy.clone())
        .sign_template(&prefixed_template(created.as_xml())?)
        .map_err(|error| format!("prefixed signature: {error}"))?
        .output;
    let mut document = XmlDocument::parse(&resigned).map_err(|error| error.to_string())?;
    let request = TimestampRequest {
        signature: "sig",
        digest: Algorithm::Sha256,
        policy: None,
        nonce: Some(extended_levels::NONCE),
        id_attributes: &[],
    };
    let pending =
        xml_sec_xades::request_historical_timestamp(&document, &request, profile, assessment, work)
            .map_err(|error| format!("prefixed request: {error}"))?;
    if step == "prefixed-request" {
        return write(&format!("prefixed-{suffix}.tsq"), pending.request());
    }
    let response = read(fixtures, &format!("prefixed-{suffix}.tsr"))?;
    complete(&mut document, &pending, &response, assessment, pki, work)?;
    write(
        &format!("t-{suffix}-prefixed.xml"),
        document.as_xml().as_bytes(),
    )
}

/// `xml` with its `SignedInfo` canonicalization naming the
/// `InclusiveNamespaces` `PrefixList` `ds` and every digest and signature
/// value emptied, a template to sign again.
fn prefixed_template(xml: &str) -> Result<String, String> {
    const METHOD: &str =
        "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>";
    const PREFIXED: &str = "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"><ec:InclusiveNamespaces xmlns:ec=\"http://www.w3.org/2001/10/xml-exc-c14n#\" PrefixList=\"ds\"/></ds:CanonicalizationMethod>";
    if !xml.contains(METHOD) {
        return Err("no exclusive SignedInfo method".into());
    }
    let mut template = xml.replacen(METHOD, PREFIXED, 1);
    for (open, close) in [
        ("<ds:DigestValue>", "</ds:DigestValue>"),
        (
            "<ds:SignatureValue Id=\"sig-value\">",
            "</ds:SignatureValue>",
        ),
    ] {
        let mut from = 0;
        while let Some(start) = template[from..].find(open).map(|at| from + at + open.len()) {
            let end = start
                + template[start..]
                    .find(close)
                    .ok_or_else(|| format!("unterminated {open}"))?;
            template.replace_range(start..end, "");
            from = start;
        }
    }
    Ok(template)
}

/// A `SignatureTimeStamp` request for `sig` with this policy and nonce.
fn timestamp(
    policy: Option<Oid<'static>>,
    nonce: Option<&'static [u8]>,
) -> TimestampRequest<'static> {
    TimestampRequest {
        signature: "sig",
        digest: Algorithm::Sha256,
        policy,
        nonce,
        id_attributes: &[],
    }
}

/// The request variants beside `request.tsq`: one also asking for a policy,
/// one without a nonce.
fn requests(
    document: &XmlDocument,
    assessment: &Assessment<'_, '_>,
    write: &impl Fn(&str, &[u8]) -> Result<(), String>,
    work: &Memory,
) -> Result<(), String> {
    for (name, policy, nonce) in [
        (
            "request-policy.tsq",
            Some(Oid::from_bytes(OTHER_POLICY)),
            Some(NONCE),
        ),
        ("request-no-nonce.tsq", None, None),
    ] {
        let variant = request_timestamp(document, &timestamp(policy, nonce), assessment, work)
            .map_err(|error| format!("{name}: {error}"))?;
        write(name, variant.request())?;
    }
    Ok(())
}

/// From the B-T document: the CRLs of both CAs, the first archive timestamp
/// and its renewal, each completed with the fixture response to its request.
/// `action` stops at the request it names, or writes both archived documents.
fn archived(
    document: &mut XmlDocument,
    assessment: &Assessment<'_, '_>,
    fixtures: &Path,
    [root, intermediate]: [&[u8]; 2],
    action: &str,
    write: &impl Fn(&str, &[u8]) -> Result<(), String>,
    work: &Memory,
) -> Result<(), String> {
    let (root_crl, intermediate_crl) = (
        read(fixtures, "root.crl")?,
        read(fixtures, "intermediate.crl")?,
    );
    let crls: [&[u8]; 2] = [&root_crl, &intermediate_crl];
    let utc = utc()?;
    let (anchors, certificates) = ([root], [intermediate]);
    let inputs = |requirements| Inputs {
        requirements,
        anchors: &anchors,
        certificates: &certificates,
        utc: &utc,
        accuracies: &[],
        responders: &[],
        crls: &crls,
        responses: &[],
    };
    let request = TimestampRequest {
        signature: "sig",
        digest: Algorithm::Sha256,
        policy: None,
        nonce: Some(NONCE),
        id_attributes: &[],
    };
    for (requirements, query, response, archived) in [
        (
            Requirements::LongTerm,
            "archive",
            "archive.tsr",
            "b-lta.xml",
        ),
        (
            Requirements::Archival,
            "renewal",
            "renewal.tsr",
            "b-lta-renewed.xml",
        ),
    ] {
        // The next archive covers the validation data of every earlier token.
        add_validation_data(
            document,
            &ValidationData {
                signature: "sig",
                assessment,
                inputs: &inputs(requirements),
                id_attributes: &[],
            },
            work,
        )
        .map_err(|error| format!("{query} validation data: {error}"))?;
        let pending =
            request_archive_timestamp(document, &request, assessment, &inputs(requirements), work)
                .map_err(|error| format!("{query} request: {error}"))?;
        if action == format!("{query}-request") {
            return write(&format!("{query}.tsq"), pending.request());
        }
        let completion = Completion {
            assessment,
            inputs: &inputs(Requirements::Archival),
            window: None,
            id_attributes: &[],
        };
        complete_timestamp(
            document,
            &pending,
            &read(fixtures, response)?,
            &completion,
            work,
        )
        .map_err(|error| format!("{query} completion: {error}"))?;
        write(archived, document.as_xml().as_bytes())?;
    }
    Ok(())
}

/// The content timestamps the creation tests complete: one over every data
/// object and one over the payload element alone, each with a nonce.
const STAMPS: [ContentTimestamp<'static>; 2] = [
    ContentTimestamp {
        scope: ContentScope::All,
        digest: Algorithm::Sha256,
        policy: None,
        nonce: Some(NONCE),
        response: None,
    },
    ContentTimestamp {
        // Include order differs from reference order (EN 319 132-1 §5.2.8.3).
        scope: ContentScope::Individual(&["#sig-reference-1", "#sig-reference-0"]),
        digest: Algorithm::Sha256,
        policy: None,
        nonce: Some(NONCE),
        response: None,
    },
];

/// `XPath` that keeps the signature's qualifying properties in a whole-document
/// reference while leaving out what signing fills in.
const CHANGING: &str =
    "not(ancestor-or-self::ds:SignedInfo or ancestor-or-self::ds:SignatureValue)";

/// The content timestamp requests of a signature `sig` over the document
/// without signatures and its payload element (`content-all.tsq`,
/// `content-individual.tsq`), and of one whose reference covers its own
/// qualifying properties, which the timestamp then changes
/// (`content-changing.tsq`).
fn content_requests(
    signer: &Signer<'_>,
    assessment: &Assessment<'_, '_>,
    output: &Path,
    work: &Memory,
) -> Result<(), String> {
    let objects = vec![
        DataObject::Document {
            mime_type: "text/xml",
            envelope: Envelope::ExcludingSignatures,
        },
        DataObject::Element {
            id: "payload",
            mime_type: "text/xml",
        },
    ];
    let changing = vec![DataObject::Reference {
        uri: "",
        transforms: vec![
            Transform::XPath(XPathExpression::new(CHANGING).with_namespace("ds", DS)),
            Transform::C14n(C14nAlgorithm::new(C14nMode::Exclusive1_0, false)),
        ],
        mime_type: "text/xml",
    }];
    for (objects, stamps, names) in [
        (
            objects,
            &STAMPS[..],
            &["content-all.tsq", "content-individual.tsq"][..],
        ),
        (changing, &STAMPS[..1], &["content-changing.tsq"][..]),
    ] {
        let mut document = XmlDocument::parse(DOCUMENT).map_err(|error| error.to_string())?;
        let request = Request {
            id: "sig",
            signing_time: TIME,
            objects,
            placement: xml_sec_xades::Placement::DocumentEnd,
            resources: None,
            id_attributes: &[],
            properties: xml_sec_xades::properties::Properties {
                content_timestamps: stamps,
                ..xml_sec_xades::properties::Properties::default()
            },
        };
        let requests =
            request_content_timestamps(&mut document, signer, &request, assessment, work)
                .map_err(|error| format!("content request: {error}"))?;
        for (name, bytes) in names.iter().zip(requests.iter()) {
            std::fs::write(output.join(name), bytes).map_err(|error| format!("{name}: {error}"))?;
        }
    }
    // The B-B signature the refresh tests take to B-T and B-LT.
    let document = created(signer, assessment, work)?;
    let pending = request_timestamp(&document, &timestamp(None, Some(NONCE)), assessment, work)
        .map_err(|error| format!("signature request: {error}"))?;
    std::fs::write(output.join("signature.tsq"), pending.request())
        .map_err(|error| format!("signature.tsq: {error}"))
}

const DS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// The signatures of `content-all.tsq` and `content-individual.tsq`,
/// created with `FIXTURES/content-all.tsr` and `FIXTURES/content-individual.tsr`
/// and written as `OUTPUT/content-timestamps.xml`, and the one carrying the
/// first token twice, as `OUTPUT/content-repeated.xml`: equal requests take
/// the same response.
fn content(
    signer: &Signer<'_>,
    assessment: &Assessment<'_, '_>,
    (fixtures, output): (&Path, &Path),
    intermediate: &[u8],
    work: &Memory,
) -> Result<(), String> {
    let (all, individual) = (
        read(fixtures, "content-all.tsr")?,
        read(fixtures, "content-individual.tsr")?,
    );
    let answered = |stamp: ContentTimestamp<'static>, response| ContentTimestamp {
        response: Some(response),
        ..stamp
    };
    let utc = utc()?;
    let certificates = [intermediate];
    for (name, stamps) in [
        (
            "content-timestamps",
            [answered(STAMPS[0], &all), answered(STAMPS[1], &individual)],
        ),
        (
            "content-repeated",
            [answered(STAMPS[0], &all), answered(STAMPS[0], &all)],
        ),
    ] {
        let mut document = XmlDocument::parse(DOCUMENT).map_err(|error| error.to_string())?;
        let request = Request {
            id: "sig",
            signing_time: TIME,
            objects: vec![
                DataObject::Document {
                    mime_type: "text/xml",
                    envelope: Envelope::ExcludingSignatures,
                },
                DataObject::Element {
                    id: "payload",
                    mime_type: "text/xml",
                },
            ],
            placement: xml_sec_xades::Placement::DocumentEnd,
            resources: None,
            id_attributes: &[],
            properties: xml_sec_xades::properties::Properties {
                content_timestamps: &stamps,
                content_evidence: Some(ContentEvidence {
                    certificates: &certificates,
                    utc: &utc,
                    accuracies: &[],
                    window: None,
                }),
                ..xml_sec_xades::properties::Properties::default()
            },
        };
        create(&mut document, signer, request, assessment, work)
            .map_err(|error| format!("{name}: {error}"))?;
        std::fs::write(output.join(format!("{name}.xml")), document.as_xml())
            .map_err(|error| format!("{name}.xml: {error}"))?;
    }
    Ok(())
}

/// The explicit policy `content-lta` signs and stores.
const LTA_POLICY: &[u8] = b"<Policy xmlns=\"urn:policy\">Sign</Policy>";

/// A signature with both content timestamps, an explicit policy and its
/// embedded store, taken to B-LTA: its signature timestamp request is
/// written as `OUTPUT/content-lta-signature.tsq` for `content-lta-request`;
/// answered by `FIXTURES/content-lta-signature.tsr`, the B-T document is
/// written as `OUTPUT/content-t.xml`, the CRLs of both CAs are
/// added and the archive timestamp request written as
/// `OUTPUT/content-lta-archive.tsq` for `content-lta-archive-request`; for
/// `content-lta`, `FIXTURES/content-lta-archive.tsr` completes it and the
/// document is written as `OUTPUT/content-lta.xml`.
fn content_lta(
    step: &str,
    (signer, assessment): (&Signer<'_>, &Assessment<'_, '_>),
    (fixtures, output): (&Path, &Path),
    [root, intermediate]: [&[u8]; 2],
    work: &Memory,
) -> Result<(), String> {
    let write = |name: &str, bytes: &[u8]| {
        std::fs::write(output.join(name), bytes).map_err(|error| format!("{name}: {error}"))
    };
    let utc = utc()?;
    let (anchors, certificates) = ([root], [intermediate]);
    let mut document = content_lta_signed(signer, assessment, fixtures, intermediate, work)?;
    let pending = request_timestamp(&document, &timestamp(None, Some(NONCE)), assessment, work)
        .map_err(|error| format!("content-lta signature request: {error}"))?;
    if step == "content-lta-request" {
        return write("content-lta-signature.tsq", pending.request());
    }
    complete(
        &mut document,
        &pending,
        &read(fixtures, "content-lta-signature.tsr")?,
        assessment,
        [root, intermediate],
        work,
    )?;
    // The same signature at B-T, before its validation data.
    write("content-t.xml", document.as_xml().as_bytes())?;
    let lists = [
        read(fixtures, "root.crl")?,
        read(fixtures, "intermediate.crl")?,
    ];
    let crls: [&[u8]; 2] = [&lists[0], &lists[1]];
    let inputs = |requirements| Inputs {
        requirements,
        anchors: &anchors,
        certificates: &certificates,
        utc: &utc,
        accuracies: &[],
        responders: &[],
        crls: &crls,
        responses: &[],
    };
    add_validation_data(
        &mut document,
        &ValidationData {
            signature: "sig",
            assessment,
            inputs: &inputs(Requirements::LongTerm),
            id_attributes: &[],
        },
        work,
    )
    .map_err(|error| format!("content-lta validation data: {error}"))?;
    let archive = request_archive_timestamp(
        &document,
        &timestamp(None, Some(NONCE)),
        assessment,
        &inputs(Requirements::LongTerm),
        work,
    )
    .map_err(|error| format!("content-lta archive request: {error}"))?;
    if step == "content-lta-archive-request" {
        return write("content-lta-archive.tsq", archive.request());
    }
    complete_timestamp(
        &mut document,
        &archive,
        &read(fixtures, "content-lta-archive.tsr")?,
        &Completion {
            assessment,
            inputs: &inputs(Requirements::Archival),
            window: None,
            id_attributes: &[],
        },
        work,
    )
    .map_err(|error| format!("content-lta archive completion: {error}"))?;
    write("content-lta.xml", document.as_xml().as_bytes())
}

/// The B-B signature of `content-lta`.
fn content_lta_signed(
    signer: &Signer<'_>,
    assessment: &Assessment<'_, '_>,
    fixtures: &Path,
    intermediate: &[u8],
    work: &Memory,
) -> Result<XmlDocument, String> {
    use xml_sec_xades::properties::{
        ExplicitPolicy, Identifier, Policy, PolicyDocument, PolicyStore, PolicyTransform,
        Properties, SignaturePolicy,
    };
    let (all, individual) = (
        read(fixtures, "content-all.tsr")?,
        read(fixtures, "content-individual.tsr")?,
    );
    let stamps = [
        ContentTimestamp {
            response: Some(&all),
            ..STAMPS[0]
        },
        ContentTimestamp {
            response: Some(&individual),
            ..STAMPS[1]
        },
    ];
    let utc = utc()?;
    let certificates = [intermediate];
    let identifier = |uri| Identifier {
        uri,
        qualifier: None,
        description: None,
        documentation: &[],
    };
    let mut document = XmlDocument::parse(DOCUMENT).map_err(|error| error.to_string())?;
    let request = Request {
        id: "sig",
        signing_time: TIME,
        objects: vec![
            DataObject::Document {
                mime_type: "text/xml",
                envelope: Envelope::ExcludingSignatures,
            },
            DataObject::Element {
                id: "payload",
                mime_type: "text/xml",
            },
        ],
        placement: xml_sec_xades::Placement::DocumentEnd,
        resources: None,
        id_attributes: &[],
        properties: Properties {
            policy: Some(Policy::Document(SignaturePolicy::Explicit(
                ExplicitPolicy {
                    identifier: identifier("urn:oid:1.3.6.1.4.1.13762.3.1"),
                    document: LTA_POLICY,
                    digest_method: DigestAlgorithm::Sha256.uri(),
                    transform: PolicyTransform::None,
                    qualifiers: &[],
                },
            ))),
            policy_store: Some(PolicyStore {
                specification: identifier("urn:oid:1.3.6.1.4.1.13762.3.2"),
                document: PolicyDocument::Embedded,
            }),
            content_timestamps: &stamps,
            content_evidence: Some(ContentEvidence {
                certificates: &certificates,
                utc: &utc,
                accuracies: &[],
                window: None,
            }),
            ..Properties::default()
        },
    };
    create(&mut document, signer, request, assessment, work)
        .map_err(|error| format!("content-lta: {error}"))?;
    Ok(document)
}

/// The CRLs `FIXTURES/root.crl` and `FIXTURES/intermediate.crl` added to the
/// B-T document, then the next generation `root-next.crl` and
/// `intermediate-next.crl` added by a refresh of the B-LT signature.
fn refreshed(
    document: &mut XmlDocument,
    assessment: &Assessment<'_, '_>,
    fixtures: &Path,
    [root, intermediate]: [&[u8]; 2],
    work: &Memory,
) -> Result<(), String> {
    let utc = utc()?;
    let (anchors, certificates) = ([root], [intermediate]);
    for (names, refresh) in [
        (["root.crl", "intermediate.crl"], false),
        (["root-next.crl", "intermediate-next.crl"], true),
    ] {
        let lists = [read(fixtures, names[0])?, read(fixtures, names[1])?];
        let crls: [&[u8]; 2] = [&lists[0], &lists[1]];
        let inputs = Inputs {
            requirements: Requirements::LongTerm,
            anchors: &anchors,
            certificates: &certificates,
            utc: &utc,
            accuracies: &[],
            responders: &[],
            crls: &crls,
            responses: &[],
        };
        let data = ValidationData {
            signature: "sig",
            assessment,
            inputs: &inputs,
            id_attributes: &[],
        };
        let added = if refresh {
            refresh_validation_data(document, &data, work)
        } else {
            add_validation_data(document, &data, work)
        }
        .map_err(|error| format!("{}: {error}", names[0]))?;
        if added != DataAdded::Published {
            return Err(format!("{}: nothing was added", names[0]));
        }
    }
    Ok(())
}

/// The B-B signature `sig` over the whole document.
fn created(
    signer: &Signer<'_>,
    assessment: &Assessment<'_, '_>,
    work: &Memory,
) -> Result<XmlDocument, String> {
    created_in(signer, assessment, None, Envelope::Enveloped, work)
}

/// The B-T signature `sig`, excluding every signature from what it signs,
/// taken to B-LT and sealed by evidence records as `action` says; `parallel`
/// also adds the parallel B-B signature `sig2`, written as
/// `OUTPUT/e-ers-signed.xml`.
fn sealed(
    (signer, assessment): (&Signer<'_>, &Assessment<'_, '_>),
    fixtures: &Path,
    pki: [&[u8]; 2],
    action: &str,
    write: &impl Fn(&str, &[u8]) -> Result<(), String>,
    work: &Memory,
) -> Result<(), String> {
    let mut document = created_in(
        signer,
        assessment,
        None,
        Envelope::ExcludingSignatures,
        work,
    )?;
    let pending = request_timestamp(&document, &timestamp(None, Some(NONCE)), assessment, work)
        .map_err(|error| format!("request: {error}"))?;
    if action == "seal-signature-request" {
        return write("seal-signature.tsq", pending.request());
    }
    let response = read(fixtures, "seal-signature.tsr")?;
    complete(&mut document, &pending, &response, assessment, pki, work)?;
    sealing::sealed(
        &mut document,
        assessment,
        fixtures,
        pki,
        action,
        write,
        work,
    )?;
    if action != "parallel" {
        return Ok(());
    }
    create(
        &mut document,
        signer,
        Request {
            id: "sig2",
            signing_time: TIME,
            objects: vec![DataObject::Document {
                mime_type: "text/xml",
                envelope: Envelope::ExcludingSignatures,
            }],
            placement: xml_sec_xades::Placement::DocumentEnd,
            resources: None,
            id_attributes: &[],
            properties: xml_sec_xades::properties::Properties::default(),
        },
        assessment,
        work,
    )
    .map_err(|error| format!("parallel signature: {error}"))?;
    write("e-ers-signed.xml", document.as_xml().as_bytes())
}

/// [`created`] in the `historical` vocabulary, if any, with `envelope`.
fn created_in(
    signer: &Signer<'_>,
    assessment: &Assessment<'_, '_>,
    historical: Option<Profile>,
    envelope: Envelope,
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
                envelope,
            }],
            placement: xml_sec_xades::Placement::DocumentEnd,
            resources: None,
            id_attributes: &[],
            properties: xml_sec_xades::properties::Properties {
                historical,
                // TS 101 903 V1.1.1 §7.2.3 makes SignaturePolicyIdentifier
                // mandatory; an implied policy satisfies it.
                policy: (historical == Some(Profile::V111)).then_some(
                    xml_sec_xades::properties::Policy::Document(
                        xml_sec_xades::properties::SignaturePolicy::Implied,
                    ),
                ),
                ..xml_sec_xades::properties::Properties::default()
            },
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
        let value = structured_base64::STANDARD
            .decode(&xml.as_bytes()[start..end])
            .map_err(|error| format!("{local}: {error}"))?;
        if !values.contains(&value) {
            values.push(value);
        }
    }
    Ok(values)
}

/// Archive the `Manifest` signature of the level fixtures with a SHA-512
/// renewal of its SHA-256 detached object; `complete` adds the TSA's response
/// and requires B-LTA, otherwise the request is written.
fn renew(levels: &Path, output: &Path, complete: bool) -> Result<(), String> {
    let root = read(levels, "root.der")?;
    let resources = BTreeMap::from([("detached.txt".to_owned(), read(levels, "detached.txt")?)]);
    let text = String::from_utf8(read(levels, "b-lt-manifest.xml")?)
        .map_err(|error| format!("b-lt-manifest.xml: {error}"))?;
    let mut document = XmlDocument::parse(&text).map_err(|error| error.to_string())?;
    let resolver = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: vec![root.clone()],
        ..KeyResolverConfig::default()
    });
    let mut policy = verification();
    policy.uris.references = UriTypeSet::ALL;
    // The renewed objects are those of an authenticated Manifest.
    policy.manifest_processing = ManifestProcessing::Process;
    let context = VerifyContext::new().policy(policy).key_resolver(&resolver);
    let request = VerificationRequest {
        external_resources: Some(&resources),
        ..VerificationRequest::default()
    };
    let assessment = Assessment {
        context: &context,
        request: &request,
        certificates: &[],
    };
    let utc = utc()?;
    let anchors: [&[u8]; 1] = [&root];
    let inputs = |requirements| Inputs {
        requirements,
        anchors: &anchors,
        certificates: &[],
        utc: &utc,
        accuracies: &[],
        responders: &[],
        crls: &[],
        responses: &[],
    };
    let work = Memory::new(Arc::new(MemoryAccount::new(1 << 26, 1 << 30)));
    let pending = request_archive_timestamp_with_renewal(
        &mut document,
        &TimestampRequest {
            signature: "sig",
            digest: Algorithm::Sha256,
            policy: None,
            nonce: Some(NONCE),
            id_attributes: &[],
        },
        &DigestRenewal {
            method: "http://www.w3.org/2001/04/xmlenc#sha512",
            references: &["detached-object"],
        },
        &assessment,
        &inputs(Requirements::LongTerm),
        &work,
    )
    .map_err(|error| format!("renewal request: {error}"))?;
    if !complete {
        return std::fs::write(output.join("renew.tsq"), pending.request())
            .map_err(|error| format!("renew.tsq: {error}"));
    }
    complete_timestamp(
        &mut document,
        &pending,
        &read(levels, "renew.tsr")?,
        &Completion {
            assessment: &assessment,
            inputs: &inputs(Requirements::Archival),
            window: None,
            id_attributes: &[],
        },
        &work,
    )
    .map_err(|error| format!("renewal completion: {error}"))?;
    std::fs::write(output.join("b-lta-manifest.xml"), document.as_xml())
        .map_err(|error| format!("b-lta-manifest.xml: {error}"))
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
