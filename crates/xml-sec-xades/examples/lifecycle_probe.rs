//! The lifecycle steps xml-sec takes in a bidirectional qualification with
//! another implementation, one step per run so the other side can validate
//! each result.
//!
//! `lifecycle_probe create rsa|ec PACKAGING PKI DATA SIGNING_TIME AT OUTPUT`
//! creates the B-B signature `sig` with `PKI/signer.key` (PKCS#8) and the
//! `signer.der`/`issuer.der` chain. `PACKAGING` is `enveloped`, `enveloping`,
//! `internally-detached` or `detached`; a detached reference names `DATA` by
//! its file name. `SIGNING_TIME` is the `SigningTime` value, and the result is
//! assessed against `PKI/root.der` at Unix time `AT`.
//!
//! `lifecycle_probe augment t|lt|lta|renew PKI EVIDENCE AT INPUT OUTPUT
//! [--detached FILE] [--accuracy SECONDS] [--ber] -- TSA...` takes the first signature
//! of `INPUT` one step further: a signature timestamp, the validation data of
//! B-LT, the first archive timestamp, or the next archive over a B-LTA
//! signature. `EVIDENCE` holds the DER certificates (`*.cer`), CRLs (`*.crl`)
//! and OCSP responses (`*.ocsp`) the caller supplies. The TSA command runs
//! with `{request}` and `{response}` replaced by the request it must answer
//! and the file the response goes to. `SECONDS` states the accuracy of tokens
//! that omit it, as the corpus's interoperability setting (RFC 3161 §2.4.2).
//! `--ber` reads unmarked tokens as RFC 5652 BER rather than DER.

#[path = "support/tokens.rs"]
mod tokens;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use structured_asn1::memory::{Memory, MemoryAccount};
use structured_pkix::algorithm::digest::Algorithm;
use structured_pkix::temporal::LeapTable;
use xml_sec::XmlDocument;
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::policy::{Instant, SigningPolicy, TimestampTokenEncoding, VerificationPolicy};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, EcdsaP256SigningKey, KeyResolverConfig, ObjectContent,
    RsaSigningKey, SignatureAlgorithm, SigningKey, UriTypeSet, VerificationRequest, VerifyContext,
};
use xml_sec_xades::{
    Assessment, Completion, DataObject, Envelope, Inputs, Request, Requirements, Signer,
    TimestampRequest, ValidationData, add_validation_data, complete_timestamp, create,
    request_archive_timestamp, request_timestamp,
};

const DOCUMENT: &str = "<Document><Data Id=\"payload\">Lifecycle payload</Data></Document>";
/// The nonce of every request.
const NONCE: &[u8] = &[0x1d, 0x2e, 0x3f, 0x40, 0x51, 0x62, 0x73, 0x84];

fn read(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))
}

fn file_name(path: &Path) -> Result<String, String> {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .ok_or_else(|| format!("{} names no file", path.display()))
}

fn work() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 27, 1 << 33)))
}

/// The verification of every assessment: chains to `root` at `at`.
fn verification(at: i64, detached: bool, encoding: TimestampTokenEncoding) -> VerificationPolicy {
    let mut policy = VerificationPolicy::default();
    policy.key_trust.verify_x509_chains = true;
    policy.key_trust.verification_time = Instant::new(at, 0);
    policy.timestamp_token_encoding = encoding;
    if detached {
        policy.uris.references = UriTypeSet::ALL;
    }
    policy
}

/// The `Id` of the first element of `text` named `Signature`, prefixed or not.
fn signature_id(text: &str) -> Option<&str> {
    let mut rest = text;
    while let Some(start) = rest.find('<') {
        let tag = &rest[start + 1..];
        let end = tag.find('>')?;
        let name_end = tag
            .find(|c: char| c.is_ascii_whitespace() || c == '>' || c == '/')
            .unwrap_or(end);
        let name = &tag[..name_end];
        if name.rsplit(':').next() == Some("Signature") {
            let attributes = &tag[name_end..end];
            let value = attributes.split_once(" Id=\"")?.1;
            return value.split_once('"').map(|(id, _)| id);
        }
        rest = &tag[end..];
    }
    None
}

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("create") => created(&args[1..]),
        Some("augment") => augment(&args[1..]),
        _ => Err("usage: lifecycle_probe create ... | augment ...".into()),
    }
}

fn created(args: &[String]) -> Result<(), String> {
    let [algorithm, packaging, pki, data, signing_time, at, output] = args else {
        return Err(
            "usage: lifecycle_probe create rsa|ec PACKAGING PKI DATA SIGNING_TIME AT OUTPUT".into(),
        );
    };
    let pki = PathBuf::from(pki);
    let data = PathBuf::from(data);
    let at: i64 = at.parse().map_err(|error| format!("AT: {error}"))?;
    let root = read(&pki.join("root.der"))?;
    let signer_der = read(&pki.join("signer.der"))?;
    let issuer = read(&pki.join("issuer.der"))?;
    let key_pem = String::from_utf8(read(&pki.join("signer.key"))?)
        .map_err(|error| format!("signer.key: {error}"))?;
    let (key, method): (Box<dyn SigningKey>, _) = match algorithm.as_str() {
        "rsa" => (
            Box::new(RsaSigningKey::from_pkcs8_pem(&key_pem).map_err(|error| error.to_string())?),
            SignatureAlgorithm::RsaSha256,
        ),
        "ec" => (
            Box::new(
                EcdsaP256SigningKey::from_pkcs8_pem(&key_pem).map_err(|error| error.to_string())?,
            ),
            SignatureAlgorithm::EcdsaSha256,
        ),
        _ => return Err("the algorithm is rsa or ec".into()),
    };
    let uri = file_name(&data)?;
    let object = match packaging.as_str() {
        "enveloped" => DataObject::Document {
            mime_type: "text/xml",
            envelope: Envelope::Enveloped,
        },
        "enveloping" => DataObject::Enveloping {
            content: ObjectContent::Text("Lifecycle enveloping text".to_owned()),
            mime_type: "text/plain",
        },
        "internally-detached" => DataObject::Element {
            id: "payload",
            mime_type: "text/xml",
        },
        "detached" => DataObject::Detached {
            uri: &uri,
            mime_type: "text/plain",
        },
        _ => return Err(format!("unknown packaging {packaging}")),
    };
    let mut signing = SigningPolicy::default();
    signing.uris.references = UriTypeSet::ALL;
    let chain: [&[u8]; 2] = [&signer_der, &issuer];
    let signer = Signer {
        key: key.as_ref(),
        provider: xml_sec::provider::default_provider(),
        policy: &signing,
        chain: &chain,
        method,
        digest: DigestAlgorithm::Sha256,
        canonicalization: C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
    };
    let resolver = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: vec![root.clone()],
        ..KeyResolverConfig::default()
    });
    let context = VerifyContext::new()
        .policy(verification(at, true, TimestampTokenEncoding::Declared))
        .key_resolver(&resolver);
    let resources = BTreeMap::from([(uri.clone(), read(&data)?)]);
    let request = VerificationRequest {
        external_resources: Some(&resources),
        ..VerificationRequest::default()
    };
    let assessment = Assessment {
        context: &context,
        request: &request,
        certificates: &[&root],
    };
    let mut document = XmlDocument::parse(DOCUMENT).map_err(|error| error.to_string())?;
    create(
        &mut document,
        &signer,
        Request {
            id: "sig",
            signing_time,
            objects: vec![object],
            parent: None,
            resources: Some(&resources),
            id_attributes: &[],
        },
        &assessment,
        &work(),
    )
    .map_err(|error| format!("create: {error}"))?;
    std::fs::write(output, document.as_xml()).map_err(|error| format!("{output}: {error}"))
}

/// The caller's evidence: every file of `directory` by its extension.
struct Evidence {
    certificates: Vec<Vec<u8>>,
    crls: Vec<Vec<u8>>,
    responses: Vec<Vec<u8>>,
}

impl Evidence {
    fn read(directory: &Path) -> Result<Self, String> {
        let mut evidence = Self {
            certificates: Vec::new(),
            crls: Vec::new(),
            responses: Vec::new(),
        };
        let mut files: Vec<PathBuf> = std::fs::read_dir(directory)
            .map_err(|error| format!("{}: {error}", directory.display()))?
            .map(|entry| {
                entry
                    .map(|entry| entry.path())
                    .map_err(|error| error.to_string())
            })
            .collect::<Result<_, _>>()?;
        files.sort();
        for file in files {
            let target = match file.extension().and_then(|extension| extension.to_str()) {
                Some("cer") => &mut evidence.certificates,
                Some("crl") => &mut evidence.crls,
                Some("ocsp") => &mut evidence.responses,
                _ => continue,
            };
            target.push(read(&file)?);
        }
        Ok(evidence)
    }
}

/// The TSA's response to `request`, through the caller's command.
fn exchange(command: &[String], request: &[u8], output: &Path) -> Result<Vec<u8>, String> {
    let (query, reply) = (output.with_extension("tsq"), output.with_extension("tsr"));
    std::fs::write(&query, request).map_err(|error| format!("{}: {error}", query.display()))?;
    let substitute = |arg: &String| match arg.as_str() {
        "{request}" => query.display().to_string(),
        "{response}" => reply.display().to_string(),
        _ => arg.clone(),
    };
    let [program, args @ ..] = command else {
        return Err("no TSA command".into());
    };
    let status = std::process::Command::new(program)
        .args(args.iter().map(substitute))
        .status()
        .map_err(|error| format!("{program}: {error}"))?;
    if !status.success() {
        return Err(format!("TSA command failed: {status}"));
    }
    read(&reply)
}

/// One augmentation step's inputs, borrowed from the run.
struct Stepper<'a> {
    signature: &'a str,
    assessment: &'a Assessment<'a, 'a>,
    anchors: &'a [&'a [u8]],
    certificates: &'a [&'a [u8]],
    crls: &'a [&'a [u8]],
    responses: &'a [&'a [u8]],
    accuracies: &'a [xml_sec_xades::AuthorityAccuracy<'a>],
    utc: &'a LeapTable<'a>,
    tsa: &'a [String],
    output: &'a Path,
    work: Memory,
}

impl Stepper<'_> {
    fn inputs(&self, requirements: Requirements) -> Inputs<'_> {
        Inputs {
            requirements,
            anchors: self.anchors,
            certificates: self.certificates,
            utc: self.utc,
            accuracies: self.accuracies,
            responders: &[],
            crls: self.crls,
            responses: self.responses,
        }
    }

    fn timestamp(&self) -> TimestampRequest<'_> {
        TimestampRequest {
            signature: self.signature,
            digest: Algorithm::Sha256,
            policy: None,
            nonce: Some(NONCE),
            id_attributes: &[],
        }
    }

    /// Completes `pending` with the TSA's response, requiring `requirements`.
    fn complete(
        &self,
        document: &mut XmlDocument,
        pending: &xml_sec_xades::PendingTimestamp,
        requirements: Requirements,
    ) -> Result<(), String> {
        let response = exchange(self.tsa, pending.request(), self.output)?;
        complete_timestamp(
            document,
            pending,
            &response,
            &Completion {
                assessment: self.assessment,
                inputs: &self.inputs(requirements),
                window: None,
                id_attributes: &[],
            },
            &self.work,
        )
        .map_err(|error| format!("completion: {error}"))
    }

    fn validation_data(
        &self,
        document: &mut XmlDocument,
        requirements: Requirements,
    ) -> Result<(), String> {
        let added = add_validation_data(
            document,
            &ValidationData {
                signature: self.signature,
                assessment: self.assessment,
                inputs: &self.inputs(requirements),
                id_attributes: &[],
            },
            &self.work,
        )
        .map_err(|error| format!("validation data: {error}"))?;
        println!("validation data: {added:?}");
        Ok(())
    }

    fn advance(&self, document: &mut XmlDocument, step: &str) -> Result<(), String> {
        match step {
            "t" => {
                let pending =
                    request_timestamp(document, &self.timestamp(), self.assessment, &self.work)
                        .map_err(|error| format!("request: {error}"))?;
                self.complete(document, &pending, Requirements::Timestamped)
            }
            "lt" => self.validation_data(document, Requirements::LongTerm),
            "lta" | "renew" => {
                // A first archive needs B-LT; a renewal keeps B-LTA.
                let requirements = if step == "lta" {
                    Requirements::LongTerm
                } else {
                    Requirements::Archival
                };
                self.validation_data(document, requirements)?;
                let pending = request_archive_timestamp(
                    document,
                    &self.timestamp(),
                    self.assessment,
                    &self.inputs(requirements),
                    &self.work,
                )
                .map_err(|error| format!("archive request: {error}"))?;
                self.complete(document, &pending, Requirements::Archival)
            }
            _ => Err(format!("unknown step {step}")),
        }
    }
}

fn augment(args: &[String]) -> Result<(), String> {
    let usage = "usage: lifecycle_probe augment t|lt|lta|renew PKI EVIDENCE AT INPUT OUTPUT [--detached FILE] [--accuracy SECONDS] [--ber] -- TSA...";
    let split = args.iter().position(|arg| arg == "--").ok_or(usage)?;
    let (mut options, tsa) = (args[..split].to_vec(), &args[split + 1..]);
    let encoding = match options.iter().position(|arg| arg == "--ber") {
        Some(index) => {
            options.remove(index);
            TimestampTokenEncoding::Ber
        }
        None => TimestampTokenEncoding::Declared,
    };
    let mut resources = BTreeMap::new();
    let mut seconds = None;
    for flag in ["--detached", "--accuracy"] {
        if let Some(index) = options.iter().position(|arg| arg == flag) {
            let value = options.get(index + 1).ok_or(usage)?.clone();
            if flag == "--detached" {
                let path = PathBuf::from(&value);
                resources.insert(file_name(&path)?, read(&path)?);
            } else {
                seconds = Some(value.parse::<u64>().map_err(|error| error.to_string())?);
            }
            options.drain(index..index + 2);
        }
    }
    let [step, pki, evidence, at, input, output] = options.as_slice() else {
        return Err(usage.into());
    };
    let at: i64 = at.parse().map_err(|error| format!("AT: {error}"))?;
    let output = PathBuf::from(output);
    let root = read(&Path::new(pki).join("root.der"))?;
    let evidence = Evidence::read(Path::new(evidence))?;
    let text = String::from_utf8(read(Path::new(input))?).map_err(|error| error.to_string())?;
    let signature = signature_id(&text).ok_or("the document has no signature with an Id")?;
    let carried = tokens::values(&text, "X509Certificate");
    let authorities = if seconds.is_some() {
        tokens::token_authorities(&text, &carried)?
    } else {
        Vec::new()
    };
    let accuracies = tokens::stated(&authorities, seconds.unwrap_or_default())?;
    let mut document = XmlDocument::parse(&text).map_err(|error| error.to_string())?;
    let resolver = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: vec![root.clone()],
        ..KeyResolverConfig::default()
    });
    let context = VerifyContext::new()
        .policy(verification(at, !resources.is_empty(), encoding))
        .key_resolver(&resolver);
    let request = VerificationRequest {
        external_resources: (!resources.is_empty()).then_some(&resources),
        ..VerificationRequest::default()
    };
    let assessment = Assessment {
        context: &context,
        request: &request,
        certificates: &[&root],
    };
    let utc = LeapTable::new(-2_208_988_800, 4_102_444_800, &[])
        .map_err(|error| format!("UTC coverage: {error:?}"))?;
    let anchors: [&[u8]; 1] = [&root];
    let certificates: Vec<&[u8]> = evidence.certificates.iter().map(Vec::as_slice).collect();
    let crls: Vec<&[u8]> = evidence.crls.iter().map(Vec::as_slice).collect();
    let responses: Vec<&[u8]> = evidence.responses.iter().map(Vec::as_slice).collect();
    Stepper {
        signature,
        assessment: &assessment,
        anchors: &anchors,
        certificates: &certificates,
        crls: &crls,
        responses: &responses,
        accuracies: &accuracies,
        utc: &utc,
        tsa,
        output: &output,
        work: work(),
    }
    .advance(&mut document, step)?;
    std::fs::write(&output, document.as_xml())
        .map_err(|error| format!("{}: {error}", output.display()))?;
    println!("augmented {step}");
    Ok(())
}
