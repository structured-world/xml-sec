//! The lifecycle steps xml-sec takes in a bidirectional qualification with
//! another implementation, one step per run so the other side can validate
//! each result, and the harness that times the same steps.
//!
//! `lifecycle_probe create rsa|ec PACKAGING PKI DATA SIGNING_TIME AT OUTPUT`
//! creates the B-B signature `sig` with `PKI/signer.key` (PKCS#8) and the
//! `signer.der`/`issuer.der` chain. `PACKAGING` is `enveloped`, `enveloping`,
//! `internally-detached` or `detached`; a detached reference names `DATA` by
//! its file name. `SIGNING_TIME` is the `SigningTime` value, and the result is
//! assessed against `PKI/root.der` at Unix time `AT`.
//!
//! `lifecycle_probe augment t|lt|lta|renew PKI EVIDENCE AT INPUT OUTPUT
//! [--detached FILE] [--accuracy SECONDS] [--ber] [--tokens DIR] -- [TSA...]`
//! takes the first signature of `INPUT` one step further: a signature
//! timestamp, the validation data of B-LT, the first archive timestamp, or the
//! next archive over a B-LTA signature. `EVIDENCE` holds the DER certificates
//! (`*.cer`), CRLs (`*.crl`) and OCSP responses (`*.ocsp`) the caller supplies.
//! The TSA command runs with `{request}` and `{response}` replaced by the
//! request it must answer and the file the response goes to. `SECONDS` states
//! the accuracy of tokens that omit it, as the corpus's interoperability
//! setting (RFC 3161 §2.4.2). `--ber` reads unmarked tokens as RFC 5652 BER
//! rather than DER. `--tokens DIR` keeps each exchange as `N.tsq`/`N.tsr`: a
//! recorded response answers the identical request again, and without a TSA
//! command an unrecorded request is refused, so a timed run never acquires.
//!
//! `--samples N` on either command times `N` runs from the serialized input to
//! the serialized output, after the first run and warmups (see `timing`). It
//! takes no TSA command: every run replays the tokens a previous run recorded.

#[path = "support/timing.rs"]
mod timing;
#[path = "support/tokens.rs"]
mod tokens;

use std::borrow::Cow;
use std::cell::Cell;
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

fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|error| format!("{}: {error}", path.display()))
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
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let samples = timing::sampling(&mut args)?;
    match args.first().map(String::as_str) {
        Some("create") => created(&args[1..], samples),
        Some("augment") => augment(&args[1..], samples),
        _ => Err("usage: lifecycle_probe create ... | augment ... [--samples N]".into()),
    }
}

/// Runs `operation` once and writes its result to `output`, or, given
/// `samples`, times it and prints the report as well.
fn run(
    name: &str,
    input_bytes: usize,
    samples: Option<timing::Sampling>,
    output: &Path,
    mut operation: impl FnMut(&Memory) -> Result<String, String>,
) -> Result<(), String> {
    let Some(samples) = samples else {
        return write(output, operation(&work())?.as_bytes());
    };
    let measurement = timing::measure(
        samples,
        || Ok::<_, String>(work()),
        |work| operation(&work),
        |text| Some(text.clone().into_bytes()),
    )?;
    write(output, measurement.output.as_deref().unwrap_or_default())?;
    println!("{}", timing::report(name, input_bytes, &measurement));
    Ok(())
}

/// The signer's key of `algorithm` from its PKCS#8 `pem`, and its method.
fn signing_key(
    algorithm: &str,
    pem: &str,
) -> Result<(Box<dyn SigningKey>, SignatureAlgorithm), String> {
    Ok(match algorithm {
        "rsa" => (
            Box::new(RsaSigningKey::from_pkcs8_pem(pem).map_err(|error| error.to_string())?),
            SignatureAlgorithm::RsaSha256,
        ),
        "ec" => (
            Box::new(EcdsaP256SigningKey::from_pkcs8_pem(pem).map_err(|error| error.to_string())?),
            SignatureAlgorithm::EcdsaSha256,
        ),
        _ => return Err("the algorithm is rsa or ec".into()),
    })
}

/// The signed data object of `packaging`; a detached one is named `uri`.
fn data_object<'a>(packaging: &str, uri: &'a str) -> Result<DataObject<'a>, String> {
    Ok(match packaging {
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
            uri,
            mime_type: "text/plain",
        },
        _ => return Err(format!("unknown packaging {packaging}")),
    })
}

fn created(args: &[String], samples: Option<timing::Sampling>) -> Result<(), String> {
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
    let (key, method) = signing_key(algorithm, &key_pem)?;
    let uri = file_name(&data)?;
    data_object(packaging, &uri)?;
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
    run(
        "create",
        DOCUMENT.len(),
        samples,
        Path::new(output),
        |work| {
            let mut document = XmlDocument::parse(DOCUMENT).map_err(|error| error.to_string())?;
            create(
                &mut document,
                &signer,
                Request {
                    id: "sig",
                    signing_time,
                    objects: vec![data_object(packaging, &uri)?],
                    parent: None,
                    resources: Some(&resources),
                    id_attributes: &[],
                },
                &assessment,
                work,
            )
            .map_err(|error| format!("create: {error}"))?;
            Ok(document.into_xml())
        },
    )
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

/// The caller-owned TSA: its command, and the recorded exchanges of `tokens`.
struct Tsa<'a> {
    command: &'a [String],
    tokens: Option<&'a Path>,
    /// The exchanges `tokens` holds, read before any run so that a timed run
    /// replays them from memory: request and response by ordinal.
    recorded: Vec<(Vec<u8>, Vec<u8>)>,
    /// Where the command's request and response files go.
    scratch: &'a Path,
    /// The ordinal of the next exchange of the current run.
    next: Cell<usize>,
}

impl<'a> Tsa<'a> {
    fn new(
        command: &'a [String],
        tokens: Option<&'a Path>,
        scratch: &'a Path,
    ) -> Result<Self, String> {
        let mut recorded = Vec::new();
        if let Some(tokens) = tokens {
            std::fs::create_dir_all(tokens)
                .map_err(|error| format!("{}: {error}", tokens.display()))?;
            while tokens.join(format!("{}.tsr", recorded.len())).exists() {
                let ordinal = recorded.len();
                recorded.push((
                    read(&tokens.join(format!("{ordinal}.tsq")))?,
                    read(&tokens.join(format!("{ordinal}.tsr")))?,
                ));
            }
        }
        Ok(Self {
            command,
            tokens,
            recorded,
            scratch,
            next: Cell::new(0),
        })
    }

    /// The response to `request`: recorded for this exchange, or acquired and
    /// recorded.
    fn respond(&self, request: &[u8]) -> Result<Cow<'_, [u8]>, String> {
        let ordinal = self.next.replace(self.next.get() + 1);
        if let Some((query, reply)) = self.recorded.get(ordinal) {
            if query.as_slice() != request {
                return Err(format!(
                    "the request differs from recorded exchange {ordinal}"
                ));
            }
            return Ok(Cow::Borrowed(reply));
        }
        let response = self.acquire(request)?;
        if let Some(tokens) = self.tokens {
            write(&tokens.join(format!("{ordinal}.tsq")), request)?;
            write(&tokens.join(format!("{ordinal}.tsr")), &response)?;
        }
        Ok(Cow::Owned(response))
    }

    /// The TSA's response to `request`, through the caller's command.
    fn acquire(&self, request: &[u8]) -> Result<Vec<u8>, String> {
        let [program, args @ ..] = self.command else {
            return Err(
                "no recorded response and no TSA command: this run acquires nothing".into(),
            );
        };
        let (query, reply) = (
            self.scratch.with_extension("tsq"),
            self.scratch.with_extension("tsr"),
        );
        write(&query, request)?;
        let substitute = |arg: &String| match arg.as_str() {
            "{request}" => query.display().to_string(),
            "{response}" => reply.display().to_string(),
            _ => arg.clone(),
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
    tsa: &'a Tsa<'a>,
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
        work: &Memory,
    ) -> Result<(), String> {
        let response = self.tsa.respond(pending.request())?;
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
            work,
        )
        .map_err(|error| format!("completion: {error}"))
    }

    fn validation_data(
        &self,
        document: &mut XmlDocument,
        requirements: Requirements,
        work: &Memory,
    ) -> Result<(), String> {
        add_validation_data(
            document,
            &ValidationData {
                signature: self.signature,
                assessment: self.assessment,
                inputs: &self.inputs(requirements),
                id_attributes: &[],
            },
            work,
        )
        .map_err(|error| format!("validation data: {error}"))?;
        Ok(())
    }

    fn advance(&self, document: &mut XmlDocument, step: &str, work: &Memory) -> Result<(), String> {
        // Every run makes the same exchanges in the same order.
        self.tsa.next.set(0);
        match step {
            "t" => {
                let pending = request_timestamp(document, &self.timestamp(), self.assessment, work)
                    .map_err(|error| format!("request: {error}"))?;
                self.complete(document, &pending, Requirements::Timestamped, work)
            }
            "lt" => self.validation_data(document, Requirements::LongTerm, work),
            "lta" | "renew" => {
                // A first archive needs B-LT; a renewal keeps B-LTA.
                let requirements = if step == "lta" {
                    Requirements::LongTerm
                } else {
                    Requirements::Archival
                };
                self.validation_data(document, requirements, work)?;
                let pending = request_archive_timestamp(
                    document,
                    &self.timestamp(),
                    self.assessment,
                    &self.inputs(requirements),
                    work,
                )
                .map_err(|error| format!("archive request: {error}"))?;
                self.complete(document, &pending, Requirements::Archival, work)
            }
            _ => Err(format!("unknown step {step}")),
        }
    }
}

const AUGMENT: &str = "usage: lifecycle_probe augment t|lt|lta|renew PKI EVIDENCE AT INPUT OUTPUT [--detached FILE] [--accuracy SECONDS] [--ber] [--tokens DIR] -- [TSA...]";

/// The options of `augment`, taken out of its arguments.
struct Options {
    encoding: TimestampTokenEncoding,
    resources: BTreeMap<String, Vec<u8>>,
    seconds: Option<u64>,
    tokens: Option<PathBuf>,
    /// The positional arguments left.
    positional: Vec<String>,
}

impl Options {
    fn take(mut options: Vec<String>) -> Result<Self, String> {
        let encoding = match options.iter().position(|arg| arg == "--ber") {
            Some(index) => {
                options.remove(index);
                TimestampTokenEncoding::Ber
            }
            None => TimestampTokenEncoding::Declared,
        };
        let mut taken = Self {
            encoding,
            resources: BTreeMap::new(),
            seconds: None,
            tokens: None,
            positional: Vec::new(),
        };
        for flag in ["--detached", "--accuracy", "--tokens"] {
            if let Some(index) = options.iter().position(|arg| arg == flag) {
                let value = options.get(index + 1).ok_or(AUGMENT)?.clone();
                match flag {
                    "--detached" => {
                        let path = PathBuf::from(&value);
                        taken.resources.insert(file_name(&path)?, read(&path)?);
                    }
                    "--accuracy" => {
                        taken.seconds =
                            Some(value.parse::<u64>().map_err(|error| error.to_string())?);
                    }
                    _ => taken.tokens = Some(PathBuf::from(value)),
                }
                options.drain(index..index + 2);
            }
        }
        taken.positional = options;
        Ok(taken)
    }
}

fn augment(args: &[String], samples: Option<timing::Sampling>) -> Result<(), String> {
    let split = args.iter().position(|arg| arg == "--").ok_or(AUGMENT)?;
    let command = &args[split + 1..];
    if samples.is_some() && !command.is_empty() {
        return Err(
            "--samples replays recorded tokens: record them first, without --samples".into(),
        );
    }
    let Options {
        encoding,
        resources,
        seconds,
        tokens,
        positional,
    } = Options::take(args[..split].to_vec())?;
    let [step, pki, evidence, at, input, output] = positional.as_slice() else {
        return Err(AUGMENT.into());
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
    let tsa = Tsa::new(command, tokens.as_deref(), &output)?;
    let stepper = Stepper {
        signature,
        assessment: &assessment,
        anchors: &anchors,
        certificates: &certificates,
        crls: &crls,
        responses: &responses,
        accuracies: &accuracies,
        utc: &utc,
        tsa: &tsa,
    };
    run(
        &format!("augment-{step}"),
        text.len(),
        samples,
        &output,
        |work| {
            let mut document = XmlDocument::parse(&text).map_err(|error| error.to_string())?;
            stepper.advance(&mut document, step, work)?;
            Ok(document.into_xml())
        },
    )?;
    // A measurement's report stays the last line.
    if samples.is_none() {
        println!("augmented {step}");
    }
    Ok(())
}
