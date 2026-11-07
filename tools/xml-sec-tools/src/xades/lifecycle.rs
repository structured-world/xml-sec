//! `xades lifecycle [--results DIR] [--record]`: the `XAdES` lifecycle across
//! xml-sec and EU DSS in both directions. One implementation creates a B-B
//! signature; the other takes it to B-T, B-LT and B-LTA, validating nothing
//! itself; the first validates every step and then renews the archive, which
//! the second validates. Every step is validated by the implementation that
//! did not make it, and every later document must keep the signature's
//! `SignedInfo` and `SignatureValue` byte for byte.
//!
//! The PKI is issued for the run by OpenSSL: a root, an issuing CA, RSA and
//! ECDSA P-256 signers, one TSA both implementations sign tokens with, and a
//! delegated OCSP responder. Evidence is issued after the signature timestamp
//! it must follow: CRLs only, the signer's and TSA's status by OCSP, or a CRL
//! that revokes the signer. Nothing is fetched.
//!
//! The outcome of every step is compared with `lifecycle/expectations.json`,
//! where structure, cryptographic status, evidence and trust are separate
//! fields and every normative difference carries its explanation. `--record`
//! writes the observed outcomes there instead, for review.

use super::fixtures::Generator;
use super::levels::{CERTIFICATES, Levels};
use super::{Build, Corpus, absolute, line, read, write, write_json, xml};
use serde_json::{Map, Value, json};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use xml_sec::c14n::{C14nAlgorithm, C14nMode, canonicalize};

mod bench;
#[cfg(test)]
mod tests;

/// Which implementation makes a step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Actor {
    XmlSec,
    Dss,
}

impl Actor {
    fn name(self) -> &'static str {
        match self {
            Self::XmlSec => "xml-sec",
            Self::Dss => "dss",
        }
    }

    fn other(self) -> Self {
        match self {
            Self::XmlSec => Self::Dss,
            Self::Dss => Self::XmlSec,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Packaging {
    Enveloped,
    Enveloping,
    InternallyDetached,
    Detached,
}

impl Packaging {
    const ALL: [Self; 4] = [
        Self::Enveloped,
        Self::Enveloping,
        Self::InternallyDetached,
        Self::Detached,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Enveloped => "enveloped",
            Self::Enveloping => "enveloping",
            Self::InternallyDetached => "internally-detached",
            Self::Detached => "detached",
        }
    }

    /// DSS's `SignaturePackaging` constant.
    fn dss(self) -> &'static str {
        match self {
            Self::Enveloped => "ENVELOPED",
            Self::Enveloping => "ENVELOPING",
            Self::InternallyDetached => "INTERNALLY_DETACHED",
            Self::Detached => "DETACHED",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Algorithm {
    Rsa,
    Ec,
}

impl Algorithm {
    fn name(self) -> &'static str {
        match self {
            Self::Rsa => "rsa",
            Self::Ec => "ec",
        }
    }

    /// The certificate and key names of the signer in the run's PKI.
    fn signer(self) -> &'static str {
        match self {
            Self::Rsa => "signer",
            Self::Ec => "signer-ec",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Evidence {
    /// CRLs of both CAs.
    Crl,
    /// The signer's and the TSA's status by delegated OCSP, the CA's by CRL.
    Ocsp,
    /// The issuing CA's CRL lists the signer as revoked.
    Revoked,
}

impl Evidence {
    fn name(self) -> &'static str {
        match self {
            Self::Crl => "crl",
            Self::Ocsp => "ocsp",
            Self::Revoked => "revoked",
        }
    }
}

/// One lifecycle: who starts it, over what, with which evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Case {
    pub(crate) first: Actor,
    pub(crate) packaging: Packaging,
    pub(crate) algorithm: Algorithm,
    pub(crate) evidence: Evidence,
}

impl Case {
    pub(crate) fn name(self) -> String {
        format!(
            "{}-first-{}-{}-{}",
            self.first.name(),
            self.packaging.name(),
            self.algorithm.name(),
            self.evidence.name()
        )
    }

    /// The steps in order, each with the implementation that makes it.
    pub(crate) fn steps(self) -> [(&'static str, Actor); 5] {
        let (first, second) = (self.first, self.first.other());
        [
            ("b", first),
            ("t", second),
            ("lt", second),
            ("lta", second),
            ("renew", first),
        ]
    }
}

/// Every lifecycle: each packaging and signer with CRL and with OCSP
/// evidence, and one revoked signer, in both directions.
pub(crate) fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for first in [Actor::XmlSec, Actor::Dss] {
        for packaging in Packaging::ALL {
            for algorithm in [Algorithm::Rsa, Algorithm::Ec] {
                for evidence in [Evidence::Crl, Evidence::Ocsp] {
                    cases.push(Case {
                        first,
                        packaging,
                        algorithm,
                        evidence,
                    });
                }
            }
        }
        cases.push(Case {
            first,
            packaging: Packaging::Enveloped,
            algorithm: Algorithm::Rsa,
            evidence: Evidence::Revoked,
        });
    }
    cases
}

/// The level a step's result is validated at.
fn level(step: &str) -> &'static str {
    match step {
        "b" => "b",
        "t" => "t",
        "lt" => "lt",
        _ => "lta",
    }
}

/// The text of the first element whose local name is `local`, start tag to
/// end tag, as the document holds it.
pub(crate) fn element<'a>(text: &'a str, local: &str) -> Option<&'a str> {
    let mut offset = 0;
    while let Some(found) = text[offset..].find('<') {
        let start = offset + found;
        let tag = &text[start + 1..];
        let name_end = tag.find(|c: char| c.is_ascii_whitespace() || c == '>' || c == '/')?;
        let name = &tag[..name_end];
        if name.rsplit(':').next() == Some(local) && !name.starts_with('/') {
            let close = format!("</{name}>");
            let end = text[start..].find(&close)? + start + close.len();
            return Some(&text[start..end]);
        }
        offset = start + 1;
    }
    None
}

/// The exclusive canonical form of every property of the first
/// `UnsignedSignatureProperties` of `text`, in document order. An archive
/// timestamp covers this form (EN 319 132-1 §5.5.2), so a serializer may drop
/// a redundant namespace declaration without changing what it covers.
fn unsigned_properties(text: &str) -> Result<Vec<Vec<u8>>, String> {
    let document = xml::parse(text, "lifecycle document")?;
    let Some(properties) = document
        .root_element()
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == "UnsignedSignatureProperties")
    else {
        return Ok(Vec::new());
    };
    let algorithm = C14nAlgorithm::new(C14nMode::Exclusive1_0, false);
    properties
        .children()
        .filter(xml::Node::is_element)
        .map(|property| {
            let within = |node: xml::Node<'_, '_>| {
                node.id() == property.id()
                    || node
                        .ancestors()
                        .any(|ancestor| ancestor.id() == property.id())
            };
            let mut canonical = Vec::new();
            canonicalize(&document, Some(&within), &algorithm, &mut canonical)
                .map_err(|error| format!("canonicalize an unsigned property: {error}"))?;
            Ok(canonical)
        })
        .collect()
}

/// Whether `later` keeps the signature of `created` byte for byte and every
/// unsigned property of `previous` canonically unchanged and in place: a step
/// only appends properties.
pub(crate) fn preserved(created: &str, previous: &str, later: &str) -> Result<bool, String> {
    let signature = ["SignedInfo", "SignatureValue"].iter().all(|local| {
        element(created, local).is_some_and(|bytes| element(later, local) == Some(bytes))
    });
    if !signature {
        return Ok(false);
    }
    let earlier = unsigned_properties(previous)?;
    Ok(unsigned_properties(later)?.starts_with(&earlier))
}

/// What xml-sec's `level_probe` reports, reduced to the compared fields: the
/// `XMLDSig` status of the first signature and whether the level is met, or
/// the outcome that stopped it.
pub(crate) fn xml_sec_outcome(output: &str) -> Value {
    let field = |prefix: &str| {
        output
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .map(str::trim)
    };
    let signature = field("signature: ").map(|status| {
        status
            .trim_start_matches("Ok(")
            .trim_end_matches(')')
            .to_owned()
    });
    let structure = field("level: ").map(|level| {
        if level.contains("Assessed(true)") {
            "met".to_owned()
        } else if level.contains("Assessed(false)") {
            "unmet".to_owned()
        } else {
            // The variant that stopped validation, without its details.
            let inner = level.trim_start_matches("Ok(").trim_start_matches("Err(");
            inner
                .split(|c: char| !c.is_ascii_alphanumeric())
                .next()
                .unwrap_or_default()
                .to_owned()
        }
    });
    json!({
        "crypto": signature,
        "structure": structure,
        // xml-sec reports statuses; whether they are usable is the caller's
        // reading, so there is no trust verdict to compare.
        "trust": "not assessed",
    })
}

/// What DSS's `LevelProbe` reports, reduced to the compared fields.
pub(crate) fn dss_outcome(output: &str, reports: &Path) -> Result<Value, String> {
    let line = output
        .lines()
        .find(|line| line.contains(" format="))
        .ok_or("DSS reported no signature")?;
    let field = |name: &str| {
        line.split(' ')
            .find_map(|word| word.strip_prefix(&format!("{name}=")))
            .map(str::to_owned)
    };
    let diagnostic_text = xml::read(&reports.join("diagnostic.xml"))?;
    let diagnostic = xml::parse(&diagnostic_text, "diagnostic report")?;
    let root = diagnostic.root_element();
    let signature = xml::below(root, "Signature", None)
        .find(|node| xml::child(*node, "BasicSignature").is_some())
        .ok_or("diagnostic report without a signature")?;
    let intact = |node: xml::Node<'_, '_>| {
        xml::text_at(node, &["BasicSignature", "SignatureIntact"]).as_deref() == Some("true")
            && xml::below(node, "DigestMatcher", None).all(|matcher| {
                let true_at = |field| xml::text_at(matcher, &[field]).as_deref() == Some("true");
                true_at("DataFound") && true_at("DataIntact")
            })
    };
    let timestamps: Vec<bool> = xml::below(root, "Timestamp", None)
        .filter(|node| xml::child(*node, "BasicSignature").is_some())
        .map(intact)
        .collect();
    let revocations = xml::below(root, "Revocation", None)
        .filter(|node| xml::child(*node, "BasicSignature").is_some())
        .count();
    Ok(json!({
        "crypto": if intact(signature) { "intact" } else { "broken" },
        "structure": field("format"),
        "evidence": {
            "timestamps": timestamps.len(),
            "timestamps_intact": timestamps.iter().all(|ok| *ok),
            "revocations": revocations,
        },
        "trust": format!(
            "{}/{}",
            field("indication").unwrap_or_default(),
            field("subindication").unwrap_or_default()
        ),
    }))
}

/// The fields of `expected` that `observed` does not repeat.
pub(crate) fn deviations(expected: &Value, observed: &Value, path: &str, found: &mut Vec<String>) {
    match expected {
        Value::Object(fields) => {
            for (name, value) in fields {
                // Explanations are for the reader, not compared.
                if name == "note" {
                    continue;
                }
                deviations(value, &observed[name], &format!("{path}.{name}"), found);
            }
        }
        _ if expected != observed => {
            found.push(format!("{path}: expected {expected}, got {observed}"));
        }
        _ => {}
    }
}

/// Why a step was not made: the refusal `AugmentProbe` states, the exception
/// a Java probe threw or the error a Rust probe returned, never a stack frame,
/// and without the run's certificate hashes, node identities or offsets, so
/// the same refusal reads the same over a fresh PKI.
pub(crate) fn refusal(stdout: &str, stderr: &str) -> String {
    let reason = stdout
        .lines()
        .find_map(|line| line.strip_prefix("refused "))
        .or_else(|| {
            stderr.lines().find_map(|line| {
                line.split_once("Exception in thread \"main\" ")
                    .map(|(_, exception)| exception)
                    .or_else(|| line.strip_prefix("Error: "))
            })
        })
        .or_else(|| stderr.lines().rfind(|line| !line.trim().is_empty()))
        .unwrap_or_default();
    // A Rust `Debug` payload opens with `(` right after a capitalized variant
    // name or before one; a parenthesis in prose, as in "certificate(s)", stays.
    let payload = reason
        .match_indices('(')
        .find(|&(at, _)| {
            let word = reason[..at]
                .rsplit(|c: char| !c.is_ascii_alphanumeric())
                .next()
                .unwrap_or_default();
            word.starts_with(|c: char| c.is_ascii_uppercase())
                || reason[at + 1..].starts_with(|c: char| c.is_ascii_uppercase())
        })
        .map(|(at, _)| at);
    let end = [" [", " {"]
        .iter()
        .filter_map(|cut| reason.find(cut))
        .chain(payload)
        .min()
        .unwrap_or(reason.len());
    reason[..end]
        .trim_matches(|c: char| c == '"' || c.is_whitespace())
        .to_owned()
}

/// The run's clock in Unix seconds.
fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|error| error.to_string())
}

/// `seconds` as an `xs:dateTime` in UTC.
fn date_time(seconds: u64) -> String {
    let formatted = crate::bench::format_timestamp(Duration::from_secs(seconds));
    format!("{}Z", &formatted[..19])
}

/// One step of one lifecycle and where its files go.
#[derive(Clone, Copy)]
struct Step<'p> {
    case: Case,
    name: &'static str,
    actor: Actor,
    directory: &'p Path,
    evidence: &'p Path,
}

impl Step<'_> {
    fn output(&self) -> PathBuf {
        self.directory.join(format!("{}.xml", self.name))
    }

    /// Where `actor`'s command logs and reports for this step go.
    fn log(&self, actor: Actor) -> PathBuf {
        self.directory
            .join(format!("{}-{}", self.name, actor.name()))
    }
}

/// Executables and paths every lifecycle shares.
struct Run<'a> {
    corpus: &'a Corpus,
    results: PathBuf,
    pki: PathBuf,
    classpath: String,
    lifecycle_probe: PathBuf,
    level_probe: PathBuf,
    /// The validation instant of every step, after every token of the run.
    at: u64,
}

const TSA_CONFIG: &str = "[tsa]\ndefault_tsa=lifecycle\n[lifecycle]\nserial=PKI/tsa.serial\ncrypto_device=builtin\nsigner_cert=PKI/tsa.pem\nsigner_key=PKI/tsa.key\nsigner_digest=sha256\ndefault_policy=1.3.6.1.4.1.13762.3\ndigests=sha256\naccuracy=secs:1\nclock_precision_digits=0\nordering=no\ntsa_name=no\ness_cert_id_chain=no\ness_cert_id_alg=sha256\n";

/// DSS signs an internally detached document through its root's `Id`.
const DATA: &str =
    "<Document Id=\"document\"><Data Id=\"payload\">Lifecycle payload</Data></Document>";
const DETACHED: &str = "Lifecycle detached payload\n";

impl Run<'_> {
    fn levels(&self) -> Generator {
        Generator {
            xmlsec: self.corpus.xmlsec.clone(),
            openssl: self.corpus.openssl.clone(),
            work: self.pki.clone(),
            output: self.pki.clone(),
            units: 0,
        }
    }

    /// Issues `name.pem` from `name.csr` with `extensions` and a CRL
    /// distribution point (RFC 5280 §4.2.1.13) for `issuer`'s CRL. DSS looks
    /// a certificate's CRL up only through that point; the URI is never
    /// fetched, the run supplies the CRL.
    fn certify(
        &self,
        generator: &Generator,
        name: &str,
        issuer: &str,
        extensions: &str,
    ) -> Result<(), String> {
        let file = format!("{name}.ext");
        write(
            &self.pki.join(&file),
            format!("{extensions}crlDistributionPoints=URI:http://crl.invalid/{issuer}.crl\n"),
        )?;
        generator.openssl(&[
            "x509",
            "-req",
            "-in",
            &format!("{name}.csr"),
            "-CA",
            &format!("{issuer}.pem"),
            "-CAkey",
            &format!("{issuer}.key"),
            "-out",
            &format!("{name}.pem"),
            "-not_before",
            super::fixtures::NOT_BEFORE,
            "-not_after",
            super::fixtures::NOT_AFTER,
            "-extfile",
            &file,
        ])
    }

    /// The PKI, the signers' key directories and PKCS#12 stores, the TSA and
    /// the data every signature covers.
    fn issue(&self) -> Result<(), String> {
        std::fs::create_dir_all(&self.pki).map_err(|error| error.to_string())?;
        let generator = self.levels();
        let levels = Levels {
            generator: &generator,
        };
        levels.issue()?;
        generator.openssl(&[
            "req",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            "signer-ec.key",
            "-out",
            "signer-ec.csr",
            "-subj",
            "/CN=xml-sec XAdES Lifecycle EC Signer",
        ])?;
        // The CAs first: a certificate is signed by its issuer's final key.
        for (name, issuer, _, extensions) in CERTIFICATES {
            if name != "outsider" {
                self.certify(&generator, name, issuer, extensions)?;
            }
        }
        let (_, issuer, _, extensions) = CERTIFICATES[1];
        self.certify(&generator, "signer-ec", issuer, extensions)?;
        let mut chain = read(&self.pki.join("issuer.pem"))?;
        chain.extend(read(&self.pki.join("root.pem"))?);
        write(&self.pki.join("chain.pem"), chain)?;
        for (name, alias) in [
            ("signer", "signer"),
            ("signer-ec", "signer"),
            ("tsa", "tsa"),
        ] {
            generator.openssl(&[
                "pkcs12",
                "-export",
                "-inkey",
                &format!("{name}.key"),
                "-in",
                &format!("{name}.pem"),
                "-certfile",
                "chain.pem",
                "-name",
                alias,
                "-passout",
                "pass:dss",
                "-out",
                &format!("{name}.p12"),
            ])?;
        }
        for algorithm in [Algorithm::Rsa, Algorithm::Ec] {
            let directory = self.pki.join(algorithm.name());
            std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
            let signer = algorithm.signer();
            write(&directory.join("signer.der"), generator.der(signer)?)?;
            write(
                &directory.join("signer.key"),
                read(&self.pki.join(format!("{signer}.key")))?,
            )?;
            for certificate in ["issuer", "root"] {
                write(
                    &directory.join(format!("{certificate}.der")),
                    generator.der(certificate)?,
                )?;
            }
        }
        write(&self.pki.join("root.der"), generator.der("root")?)?;
        write(&self.pki.join("tsa.serial"), "01\n")?;
        let pki = self.pki.display().to_string();
        write(&self.pki.join("tsa.cnf"), TSA_CONFIG.replace("PKI", &pki))?;
        write(&self.pki.join("data.xml"), DATA)?;
        write(&self.pki.join("detached.txt"), DETACHED)
    }

    /// The evidence of `case`, issued now: after every token it must follow.
    fn evidence(&self, case: Case, directory: &Path) -> Result<(), String> {
        std::fs::create_dir_all(directory).map_err(|error| error.to_string())?;
        let generator = self.levels();
        let levels = Levels {
            generator: &generator,
        };
        write(&directory.join("issuer.cer"), generator.der("issuer")?)?;
        write(&directory.join("root.crl"), levels.crl("root")?)?;
        let signer = case.algorithm.signer();
        match case.evidence {
            Evidence::Crl => write(&directory.join("issuer.crl"), levels.crl("issuer")?),
            Evidence::Ocsp => {
                write(
                    &directory.join("responder.cer"),
                    generator.der("responder")?,
                )?;
                write(&directory.join("signer.ocsp"), levels.ocsp(signer, false)?)?;
                write(&directory.join("tsa.ocsp"), levels.ocsp("tsa", false)?)
            }
            Evidence::Revoked => write(
                &directory.join("issuer.crl"),
                levels.crl_revoking("issuer", signer)?,
            ),
        }
    }

    fn data(&self, case: Case) -> PathBuf {
        self.pki.join(match case.packaging {
            Packaging::Detached => "detached.txt",
            _ => "data.xml",
        })
    }

    /// The detached object a validator or augmenter needs, if any.
    fn detached(&self, case: Case) -> Option<PathBuf> {
        (case.packaging == Packaging::Detached).then(|| self.pki.join("detached.txt"))
    }

    fn java(&self, class: &str) -> Vec<OsString> {
        line(&[&"java", &"-cp", &self.classpath, &class])
    }

    /// Makes `step` from `input` into its output. A refusal is an outcome,
    /// not a run failure.
    fn make(&self, step: &Step<'_>, input: Option<&Path>) -> Result<Value, String> {
        let args = self.command(step, input, now()?)?;
        let run = self.corpus.command(&args, &step.log(step.actor))?;
        if run.success() && step.output().exists() {
            return Ok(json!("made"));
        }
        Ok(
            json!({ "refused": refusal(&String::from_utf8_lossy(&run.stdout), &String::from_utf8_lossy(&run.stderr)) }),
        )
    }

    /// The command that makes `step` at Unix time `time`.
    fn command(
        &self,
        step: &Step<'_>,
        input: Option<&Path>,
        time: u64,
    ) -> Result<Vec<OsString>, String> {
        let Step {
            case,
            name: step_name,
            actor,
            evidence,
            ..
        } = *step;
        let output = step.output();
        Ok(match (actor, step_name) {
            (Actor::XmlSec, "b") => {
                let mut args = line(&[
                    &self.lifecycle_probe,
                    &"create",
                    &case.algorithm.name(),
                    &case.packaging.name(),
                    &self.pki.join(case.algorithm.name()),
                    &self.data(case),
                    &date_time(time),
                    &self.at.to_string(),
                ]);
                args.push(output.clone().into_os_string());
                args
            }
            (Actor::Dss, "b") => {
                let mut args = self.java("SignProbe");
                args.extend(line(&[
                    &self.pki.join(format!("{}.p12", case.algorithm.signer())),
                    &case.packaging.dss(),
                    &self.data(case),
                    &time.to_string(),
                    &output,
                ]));
                args
            }
            (Actor::XmlSec, step) => {
                let input = input.ok_or("no input to augment")?;
                let mut args = line(&[
                    &self.lifecycle_probe,
                    &"augment",
                    &step,
                    &self.pki,
                    &evidence,
                    &self.at.to_string(),
                    &input,
                    &output,
                    &"--accuracy",
                    &"1",
                ]);
                if let Some(detached) = self.detached(case) {
                    args.extend(line(&[&"--detached", &detached]));
                }
                // xml-sec renews only over DSS's tokens, whose unsorted
                // certificate SET OF is not DER; the caller reads them as BER.
                if case.first == Actor::XmlSec {
                    args.push("--ber".into());
                }
                args.extend(line(&[
                    &"--",
                    &self.corpus.openssl,
                    &"ts",
                    &"-reply",
                    &"-config",
                    &self.pki.join("tsa.cnf"),
                    &"-queryfile",
                    &"{request}",
                    &"-out",
                    &"{response}",
                ]));
                args
            }
            (Actor::Dss, step) => {
                let input = input.ok_or("no input to augment")?;
                let level = match step {
                    "t" => "T",
                    "lt" => "LT",
                    _ => "LTA",
                };
                let mut args = self.java("AugmentProbe");
                args.extend(line(&[
                    &input,
                    &output,
                    &level,
                    &self.pki.join("root.der"),
                    &self.pki.join("tsa.p12"),
                    &time.to_string(),
                    &evidence,
                ]));
                args.extend(self.detached(case).map(Into::into));
                args
            }
        })
    }

    /// The other implementation's reading of the output of `step` at its level.
    fn validate(&self, step: &Step<'_>) -> Result<Value, String> {
        let (case, document) = (step.case, step.output());
        let validator = step.actor.other();
        let reports = step.log(validator);
        let log = reports.with_extension("log");
        match validator {
            Actor::Dss => {
                let mut args = self.java("LevelProbe");
                args.extend(line(&[
                    &document,
                    &self.pki.join("root.der"),
                    &self.at.to_string(),
                    &reports,
                ]));
                args.extend(self.detached(case).map(Into::into));
                let run = self.corpus.require(&args, &log)?;
                dss_outcome(&String::from_utf8_lossy(&run.stdout), &reports)
            }
            Actor::XmlSec => {
                let mut outcome = self.xml_sec_reading(step, false, &log)?;
                // The same document with unmarked tokens read as BER: the
                // two readings differ only for a token that is not DER.
                let ber = self.xml_sec_reading(step, true, &reports.with_extension("ber"))?;
                outcome["structure_ber"] = ber["structure"].clone();
                Ok(outcome)
            }
        }
    }

    /// xml-sec's reading of the output of `step`, with unmarked tokens read
    /// as DER or, with `ber`, as RFC 5652 BER.
    fn xml_sec_reading(&self, step: &Step<'_>, ber: bool, log: &Path) -> Result<Value, String> {
        let mut args = line(&[
            &self.level_probe,
            &step.output(),
            &self.pki.join("root.der"),
            &self.at.to_string(),
            &level(step.name),
            &"1",
        ]);
        if ber {
            args.push("cms".into());
        }
        if let Some(detached) = self.detached(step.case) {
            args.extend(line(&[&"--detached", &detached]));
        }
        let run = self.corpus.command(&args, log)?;
        let mut outcome = xml_sec_outcome(&String::from_utf8_lossy(&run.stdout));
        if !run.success() {
            outcome["structure"] = refusal("", &String::from_utf8_lossy(&run.stderr)).into();
        }
        Ok(outcome)
    }

    /// Runs every step of `case` and returns what was observed.
    fn lifecycle(&self, case: Case) -> Result<Value, String> {
        let directory = self.results.join(case.name());
        let evidence = directory.join("evidence");
        // Empty until B-LT: earlier steps are given no status at all.
        std::fs::create_dir_all(&evidence).map_err(|error| error.to_string())?;
        let mut steps = Vec::new();
        let mut previous: Option<PathBuf> = None;
        let mut created: Option<String> = None;
        let mut previous_text: Option<String> = None;
        for (name, actor) in case.steps() {
            if name == "lt" || name == "lta" {
                // Strictly after the token it follows, at one-second resolution.
                std::thread::sleep(Duration::from_secs(1));
                if name == "lt" {
                    self.evidence(case, &evidence)?;
                }
            }
            let step = Step {
                case,
                name,
                actor,
                directory: &directory,
                evidence: &evidence,
            };
            let made = self.make(&step, previous.as_deref())?;
            let mut row = Map::new();
            row.insert("step".into(), name.into());
            row.insert("by".into(), actor.name().into());
            row.insert("made".into(), made.clone());
            if made != "made" {
                steps.push(Value::Object(row));
                break;
            }
            let output = step.output();
            let text = xml::read(&output)?;
            let created = created.get_or_insert_with(|| text.clone());
            let earlier = previous_text.as_deref().unwrap_or(created);
            row.insert(
                "preserved".into(),
                preserved(created, earlier, &text)?.into(),
            );
            row.insert("validated".into(), self.validate(&step)?);
            steps.push(Value::Object(row));
            previous = Some(output);
            previous_text = Some(text);
        }
        Ok(json!({ "case": case.name(), "steps": steps }))
    }
}

/// The versioned expectations, beside the corpus.
fn expectations_path(corpus: &Corpus) -> PathBuf {
    corpus.package().join("lifecycle/expectations.json")
}

/// Every deviation of `observed` from `expected`, keyed by case.
pub(crate) fn compare(expected: &Value, observed: &[Value]) -> Vec<String> {
    let mut found = Vec::new();
    for row in observed {
        let name = row["case"].as_str().unwrap_or_default();
        let Some(steps) = expected["cases"][name]["steps"].as_array() else {
            found.push(format!("{name}: no expectation"));
            continue;
        };
        let actual = row["steps"].as_array().map_or(&[][..], Vec::as_slice);
        if steps.len() != actual.len() {
            found.push(format!(
                "{name}: {} steps expected, {} observed",
                steps.len(),
                actual.len()
            ));
        }
        for (index, (step, observed)) in steps.iter().zip(actual).enumerate() {
            deviations(step, observed, &format!("{name}[{index}]"), &mut found);
        }
    }
    if let Some(cases) = expected["cases"].as_object() {
        for name in cases.keys() {
            if !observed.iter().any(|row| row["case"] == name.as_str()) {
                found.push(format!("{name}: expected but not run"));
            }
        }
    }
    found
}

/// Runs every lifecycle and compares it with the expectations.
pub(crate) fn execute(corpus: &Corpus, results: &Path, record: bool) -> Result<(), String> {
    if results.exists() {
        return Err("results already exist; select a fresh --results directory".into());
    }
    std::fs::create_dir_all(results).map_err(|error| error.to_string())?;
    super::dss::build(corpus, &results.join("dss-build"))?;
    let run = Run {
        corpus,
        results: results.to_owned(),
        pki: results.join("pki"),
        classpath: super::dss::classpath(corpus)?,
        lifecycle_probe: corpus.build_example(
            "lifecycle_probe",
            &["produce"],
            Build::Dev,
            &results.join("lifecycle-probe-build"),
        )?,
        level_probe: corpus.build_example(
            "level_probe",
            &[],
            Build::Dev,
            &results.join("level-probe-build"),
        )?,
        at: now()? + 86_400,
    };
    run.issue()?;
    let mut observed = Vec::new();
    for case in cases() {
        let row = run.lifecycle(case)?;
        println!("{row}");
        observed.push(row);
    }
    write_json(
        &results.join("summary.json"),
        &Value::Array(observed.clone()),
    )?;
    let path = expectations_path(corpus);
    if record {
        let cases: Map<String, Value> = observed
            .iter()
            .map(|row| {
                let name = row["case"].as_str().unwrap_or_default().to_owned();
                (name, json!({ "steps": row["steps"] }))
            })
            .collect();
        // The reviewed explanations outlive a new recording.
        let notes = xml::read(&path)
            .ok()
            .and_then(|text| serde_json::from_str::<Value>(&text).ok())
            .map_or(Value::Null, |previous| previous["notes"].clone());
        return write_json(
            &path,
            &json!({ "dss": "6.5.1", "notes": notes, "cases": cases }),
        );
    }
    let expected: Value = serde_json::from_str(&xml::read(&path)?)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let found = compare(&expected, &observed);
    if !found.is_empty() {
        return Err(format!(
            "lifecycle outcomes differ from {}:\n{}",
            path.display(),
            found.join("\n")
        ));
    }
    println!(
        "EU DSS lifecycle: {} cases in both directions match {}",
        observed.len(),
        path.display()
    );
    Ok(())
}

pub(crate) fn run(corpus: &Corpus, args: &[String]) -> Result<(), crate::repo::Failure> {
    let usage = "usage: xades lifecycle [--results DIR] [--record] | [--results DIR] --bench SAMPLES [--warmups COUNT] [--cold SAMPLES] [--cases PACKAGING-ALGORITHM,...]";
    let mut results = None;
    let mut record = false;
    let (mut samples, mut warmups, mut cold, mut cases) = (None, None, None, None);
    let mut args = args.iter();
    let count = |value: Option<&String>| {
        value
            .and_then(|value| crate::bench::sample_count(value, 100_000))
            .and_then(|count| usize::try_from(count).ok())
            .ok_or(usage)
    };
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--results" => results = Some(absolute(args.next().ok_or(usage)?)?),
            "--record" => record = true,
            "--bench" => samples = Some(count(args.next())?),
            "--warmups" => warmups = Some(count(args.next())?),
            "--cold" => cold = Some(count(args.next())?),
            "--cases" => cases = Some(args.next().ok_or(usage)?.clone()),
            _ => return Err(usage.into()),
        }
    }
    let Some(samples) = samples else {
        if warmups.is_some() || cold.is_some() || cases.is_some() {
            return Err(usage.into());
        }
        let results = results.unwrap_or_else(|| corpus.root.join("target/xades-lifecycle-results"));
        return Ok(execute(corpus, &results, record)?);
    };
    if record {
        return Err(usage.into());
    }
    let options = bench::Options {
        samples,
        // Enough runs for the JVM's compiler to settle before the samples.
        warmups: warmups.unwrap_or(100),
        cold: cold.unwrap_or(3),
        cases: bench::selected(cases.as_deref())?,
    };
    let results = results.unwrap_or_else(|| corpus.root.join("target/xades-lifecycle-bench"));
    Ok(bench::execute(corpus, &results, &options)?)
}
