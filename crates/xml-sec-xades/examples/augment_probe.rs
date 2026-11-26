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
//! reference covers its own qualifying properties. `augment_probe content
//! FIXTURES OUTPUT` completes the first two with `FIXTURES/content-all.tsr`
//! and `FIXTURES/content-individual.tsr` and writes the signature as
//! `OUTPUT/content-timestamps.xml`.
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

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use structured_asn1::Oid;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_pkix::algorithm::digest::Algorithm;
use structured_pkix::temporal::LeapTable;
use xml_sec::XmlDocument;
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::policy::{Instant, ManifestProcessing, SigningPolicy, VerificationPolicy};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, KeyResolverConfig, RsaSigningKey, SignatureAlgorithm,
    Transform, UriTypeSet, VerificationRequest, VerifyContext, XPathExpression,
};
use xml_sec_xades::{
    Assessment, Completion, ContentEvidence, ContentScope, ContentTimestamp, DataObject,
    DigestRenewal, Envelope, Inputs, PendingTimestamp, Request, Requirements, Signer,
    TimestampRequest, ValidationData, add_validation_data, complete_timestamp, create,
    request_archive_timestamp, request_archive_timestamp_with_renewal, request_content_timestamps,
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
    let usage = "usage: augment_probe request|content-request|content|complete|archive-request|renewal-request|archive|extend|renew-request|renew FIXTURES OUTPUT";
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
        _ => {}
    }
    let mut document = created(&signer, &assessment, &work)?;
    let write = |name: &str, bytes: &[u8]| {
        std::fs::write(output.join(name), bytes).map_err(|error| format!("{name}: {error}"))
    };
    let pending = request_timestamp(&document, &timestamp(None, Some(NONCE)), &assessment, &work)
        .map_err(|error| format!("request: {error}"))?;
    match action.to_str() {
        Some("request") => {
            write("request.tsq", pending.request())?;
            requests(&document, &assessment, &write, &work)?;
        }
        Some(action @ ("complete" | "archive-request" | "renewal-request" | "archive")) => {
            let response = read(&fixtures, "response.tsr")?;
            complete(
                &mut document,
                &pending,
                &response,
                &assessment,
                [&root, &intermediate],
                &work,
            )?;
            if action == "complete" {
                write("b-t.xml", document.as_xml().as_bytes())?;
            } else {
                archived(
                    &mut document,
                    &assessment,
                    &fixtures,
                    [&root, &intermediate],
                    action,
                    &write,
                    &work,
                )?;
            }
        }
        _ => return Err(usage.into()),
    }
    Ok(())
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
    Ok(())
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
            placement: xml_sec_xades::Placement::DocumentEnd,
            resources: None,
            id_attributes: &[],
            properties: xml_sec_xades::properties::Properties::default(),
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
