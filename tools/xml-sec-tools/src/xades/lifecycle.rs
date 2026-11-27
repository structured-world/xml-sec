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
use super::{Build, Corpus, DS, SP, absolute, line, read, write, write_json, xml};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
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

/// The shape of the B-B document: one signature in one of the four
/// packagings, or one of the signature forms DSS's signature tests make
/// (parallel signatures, a countersignature and a nested one, a detached
/// signature over two files, inclusive canonicalization, DSS's indented
/// serialization, a signed `KeyInfo`, chosen namespace prefixes, and a
/// detached, internally detached or two-file detached signature countersigned).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Packaging {
    Enveloped,
    Enveloping,
    InternallyDetached,
    Detached,
    Parallel,
    Countersigned,
    CountersignedNested,
    DetachedMultiple,
    Inclusive,
    PrettyPrint,
    SignedKeyInfo,
    CustomPrefixes,
    CountersignedDetached,
    CountersignedInternallyDetached,
    CountersignedDetachedMultiple,
}

impl Packaging {
    pub(crate) const ALL: [Self; 4] = [
        Self::Enveloped,
        Self::Enveloping,
        Self::InternallyDetached,
        Self::Detached,
    ];

    /// The signature forms, each run with an RSA signer and CRL evidence.
    pub(crate) const FORMS: [Self; 11] = [
        Self::Parallel,
        Self::Countersigned,
        Self::CountersignedNested,
        Self::DetachedMultiple,
        Self::Inclusive,
        Self::PrettyPrint,
        Self::SignedKeyInfo,
        Self::CustomPrefixes,
        Self::CountersignedDetached,
        Self::CountersignedInternallyDetached,
        Self::CountersignedDetachedMultiple,
    ];

    /// The case name part; for a form also the name both probes take.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Enveloped => "enveloped",
            Self::Enveloping => "enveloping",
            Self::InternallyDetached => "internally-detached",
            Self::Detached => "detached",
            Self::Parallel => "parallel",
            Self::Countersigned => "countersigned",
            Self::CountersignedNested => "countersigned-nested",
            Self::DetachedMultiple => "detached-multiple",
            Self::Inclusive => "inclusive",
            Self::PrettyPrint => "pretty-print",
            Self::SignedKeyInfo => "signed-key-info",
            Self::CustomPrefixes => "custom-prefixes",
            Self::CountersignedDetached => "countersigned-detached",
            Self::CountersignedInternallyDetached => "countersigned-internally-detached",
            Self::CountersignedDetachedMultiple => "countersigned-detached-multiple",
        }
    }

    /// DSS's `SignaturePackaging` constant; none for a form, which DSS's
    /// `FormProbe` makes by name.
    fn dss(self) -> Option<&'static str> {
        match self {
            Self::Enveloped => Some("ENVELOPED"),
            Self::Enveloping => Some("ENVELOPING"),
            Self::InternallyDetached => Some("INTERNALLY_DETACHED"),
            Self::Detached => Some("DETACHED"),
            _ => None,
        }
    }

    /// The detached files the references of this shape name.
    fn detached(self) -> &'static [&'static str] {
        match self {
            Self::Detached | Self::CountersignedDetached => &["detached.txt"],
            Self::DetachedMultiple | Self::CountersignedDetachedMultiple => {
                &["detached.txt", "detached-2.txt"]
            }
            _ => &[],
        }
    }

    /// Whether xml-sec makes this shape: DSS's indented serialization is
    /// DSS's own choice, which xml-sec only reads and augments.
    fn made_by(self, actor: Actor) -> bool {
        self != Self::PrettyPrint || actor == Actor::Dss
    }
}

/// The signature algorithm of the B-B signature and the signer key it needs.
/// The forms beyond RSA and ECDSA P-256 with SHA-256 are the algorithms DSS's
/// signature tests sign with (RSASSA-PSS, ECDSA on P-384/P-521, Ed25519,
/// Ed448, DSA, RSA with SHA-512).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Algorithm {
    Rsa,
    Ec,
    RsaSha512,
    RsaPss,
    EcP384,
    EcP521,
    EcSha3,
    Ed25519,
    Ed448,
    Dsa,
}

impl Algorithm {
    /// Every algorithm beyond the two the full packaging matrix runs.
    pub(crate) const MORE: [Self; 8] = [
        Self::RsaSha512,
        Self::RsaPss,
        Self::EcP384,
        Self::EcP521,
        Self::EcSha3,
        Self::Ed25519,
        Self::Ed448,
        Self::Dsa,
    ];

    /// The case name part, and the name `lifecycle_probe create` takes.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Rsa => "rsa",
            Self::Ec => "ec",
            Self::RsaSha512 => "rsa-sha512",
            Self::RsaPss => "rsa-pss",
            Self::EcP384 => "ec-p384",
            Self::EcP521 => "ec-p521",
            Self::EcSha3 => "ec-sha3-512",
            Self::Ed25519 => "ed25519",
            Self::Ed448 => "ed448",
            Self::Dsa => "dsa",
        }
    }

    /// The certificate and key names of the signer in the run's PKI: the
    /// RSA methods share one RSA key, the P-256 methods one EC key.
    fn signer(self) -> &'static str {
        match self {
            Self::Rsa | Self::RsaSha512 | Self::RsaPss => "signer",
            Self::Ec | Self::EcSha3 => "signer-ec",
            Self::EcP384 => "signer-ec384",
            Self::EcP521 => "signer-ec521",
            Self::Ed25519 => "signer-ed25519",
            Self::Ed448 => "signer-ed448",
            Self::Dsa => "signer-dsa",
        }
    }

    /// DSS's `SignatureAlgorithm` constant of the same method.
    fn dss(self) -> &'static str {
        match self {
            Self::Rsa => "RSA_SHA256",
            Self::Ec => "ECDSA_SHA256",
            Self::RsaSha512 => "RSA_SHA512",
            Self::RsaPss => "RSA_SSA_PSS_SHA256_MGF1",
            Self::EcP384 => "ECDSA_SHA384",
            Self::EcP521 => "ECDSA_SHA512",
            Self::EcSha3 => "ECDSA_SHA3_512",
            Self::Ed25519 => "ED25519",
            Self::Ed448 => "ED448",
            Self::Dsa => "DSA_SHA256",
        }
    }

    /// The `openssl req -newkey` arguments of a signer key this algorithm
    /// needs beyond the levels PKI's RSA keys, with the subject's name; none
    /// for a method that shares another's key. DSA keys come from the run's
    /// `dsa.param`.
    fn key(self) -> Option<(&'static [&'static str], &'static str)> {
        match self {
            Self::Rsa | Self::RsaSha512 | Self::RsaPss | Self::EcSha3 => None,
            Self::Ec => Some((&["ec", "-pkeyopt", "ec_paramgen_curve:P-256"], "EC")),
            Self::EcP384 => Some((&["ec", "-pkeyopt", "ec_paramgen_curve:P-384"], "EC P-384")),
            Self::EcP521 => Some((&["ec", "-pkeyopt", "ec_paramgen_curve:P-521"], "EC P-521")),
            Self::Ed25519 => Some((&["ed25519"], "Ed25519")),
            Self::Ed448 => Some((&["ed448"], "Ed448")),
            Self::Dsa => Some((&["dsa:dsa.param"], "DSA")),
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
/// evidence, one revoked signer, each further algorithm over an enveloping
/// signature as DSS's algorithm tests sign it, and each signature form, in
/// both directions where both implementations make the form.
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
        for algorithm in Algorithm::MORE {
            cases.push(Case {
                first,
                packaging: Packaging::Enveloping,
                algorithm,
                evidence: Evidence::Crl,
            });
        }
        for packaging in Packaging::FORMS {
            if packaging.made_by(first) {
                cases.push(Case {
                    first,
                    packaging,
                    algorithm: Algorithm::Rsa,
                    evidence: Evidence::Crl,
                });
            }
        }
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

/// The key of one part of a signature: the `Id` of the `Signature` that owns
/// it (empty for none) and its ordinal among that signature's parts of the
/// same name, so a step that adds a signature or a countersignature never
/// shifts the parts of another.
type PartKey = (String, usize);

/// The expanded names from a signature part up to the `ds:Signature` that
/// owns it, nearest first.
type PartPath = &'static [(&'static str, &'static str)];

/// `SignedInfo`, a child of its `Signature` (`XMLDSig` 1.1 §4.1).
const SIGNED_INFO: PartPath = &[(DS, "SignedInfo"), (DS, "Signature")];
/// `SignatureValue`, a child of its `Signature`.
const SIGNATURE_VALUE: PartPath = &[(DS, "SignatureValue"), (DS, "Signature")];
/// `UnsignedSignatureProperties` in the qualifying properties a `ds:Object`
/// of its signature holds (EN 319 132-1 §4.3).
const UNSIGNED_SIGNATURE_PROPERTIES: PartPath = &[
    (SP, "UnsignedSignatureProperties"),
    (SP, "UnsignedProperties"),
    (SP, "QualifyingProperties"),
    (DS, "Object"),
    (DS, "Signature"),
];

/// Every element of `document` at `path`, keyed by its owning signature.
fn parts<'a, 'input>(
    document: &'a xml_sec::XmlDomDocument<'input>,
    path: PartPath,
) -> Vec<(PartKey, xml::Node<'a, 'input>)> {
    let is = |node: xml::Node<'_, '_>, (namespace, local): (&str, &str)| {
        node.is_element()
            && node.tag_name().namespace() == Some(namespace)
            && node.tag_name().name() == local
    };
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    document
        .root_element()
        .descendants()
        .filter_map(|node| {
            let mut current = node;
            for (index, step) in path.iter().enumerate() {
                if !is(current, *step) {
                    return None;
                }
                if index + 1 < path.len() {
                    current = current.parent()?;
                }
            }
            Some((node, current))
        })
        .map(|(node, signature)| {
            let owner = signature.attribute("Id").unwrap_or_default().to_owned();
            let ordinal = counts.entry(owner.clone()).or_default();
            let key = (owner, *ordinal);
            *ordinal += 1;
            (key, node)
        })
        .collect()
}

/// The exclusive canonical form of every property of each
/// `UnsignedSignatureProperties` of `text`, keyed by its owning signature. An
/// archive timestamp covers this form (EN 319 132-1 §5.5.2), so a serializer
/// may drop a redundant namespace declaration without changing what it covers.
fn unsigned_properties(text: &str) -> Result<BTreeMap<PartKey, Vec<Vec<u8>>>, String> {
    let document = xml::parse(text, "lifecycle document")?;
    let algorithm = C14nAlgorithm::new(C14nMode::Exclusive1_0, false);
    let mut found = BTreeMap::new();
    for (key, properties) in parts(&document, UNSIGNED_SIGNATURE_PROPERTIES) {
        let canonical = properties
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
            .collect::<Result<Vec<_>, String>>()?;
        found.insert(key, canonical);
    }
    Ok(found)
}

/// The octets of the first signature value of `text`, which tell DSS's
/// short P-521 encoding (130 octets) from the `XMLDSig` 1.1 §6.4.3 one (132).
fn signature_octets(text: &str) -> Result<usize, String> {
    let document = xml::parse(text, "created document")?;
    let (_, value) = parts(&document, SIGNATURE_VALUE)
        .into_iter()
        .next()
        .ok_or("the created document has no SignatureValue")?;
    let encoded: String = value.children().filter_map(xml::Node::text).collect();
    Ok(super::corpus::base64(&encoded)?.len())
}

/// Whether `later` keeps every signature of `created` byte for byte and every
/// unsigned property of `previous` canonically unchanged and in place, for
/// each signature matched by its `Id`: a step only appends properties.
pub(crate) fn preserved(created: &str, previous: &str, later: &str) -> Result<bool, String> {
    let (created_document, later_document) = (
        xml::parse(created, "created document")?,
        xml::parse(later, "lifecycle document")?,
    );
    for path in [SIGNED_INFO, SIGNATURE_VALUE] {
        let earlier = parts(&created_document, path);
        if earlier.is_empty() {
            return Ok(false);
        }
        let now: BTreeMap<PartKey, &str> = parts(&later_document, path)
            .into_iter()
            .map(|(key, node)| (key, &later[node.range()]))
            .collect();
        for (key, node) in earlier {
            if now.get(&key) != Some(&&created[node.range()]) {
                return Ok(false);
            }
        }
    }
    let now = unsigned_properties(later)?;
    Ok(unsigned_properties(previous)?
        .iter()
        .all(|(key, earlier)| now.get(key).is_some_and(|later| later.starts_with(earlier))))
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
    let mut outcome = json!({
        "crypto": signature,
        "structure": structure,
        // xml-sec reports statuses; whether they are usable is the caller's
        // reading, so there is no trust verdict to compare.
        "trust": "not assessed",
    });
    // A document with several signatures (parallel ones, countersignatures)
    // reports each after the first, in the order the probe lists them.
    let others: Vec<Value> = output
        .split("signature: ")
        .skip(2)
        .map(|chunk| {
            let reading = xml_sec_outcome(&format!("signature: {chunk}"));
            json!({ "crypto": reading["crypto"], "structure": reading["structure"] })
        })
        .collect();
    if !others.is_empty() {
        outcome["others"] = others.into();
    }
    outcome
}

/// `outcome` with the structure of the BER reading `ber` of the same
/// document beside each signature's structure, the later signatures' too.
pub(crate) fn with_ber(mut outcome: Value, ber: &Value) -> Value {
    outcome["structure_ber"] = ber["structure"].clone();
    // `get_mut`, not indexing: indexing would insert a null `others`.
    if let Some(others) = outcome.get_mut("others").and_then(Value::as_array_mut) {
        for (index, other) in others.iter_mut().enumerate() {
            other["structure_ber"] = ber["others"][index]["structure"].clone();
        }
    }
    outcome
}

/// Each signature's building-block verdicts in `facts`, in document order:
/// the verdict of every compared block, without the fact it reads.
pub(crate) fn our_verdicts(facts: &Value) -> Vec<Value> {
    facts["signatures"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|signature| {
            let blocks = super::upstream::our_blocks(signature);
            Value::Object(
                blocks
                    .into_iter()
                    .map(|(name, verdict)| (name, verdict["verdict"].clone()))
                    .collect(),
            )
        })
        .collect()
}

/// `outcome` with the first of `blocks` beside the first signature and each
/// later one beside the signature it reads.
pub(crate) fn with_blocks(mut outcome: Value, blocks: Vec<Value>) -> Value {
    let mut blocks = blocks.into_iter();
    outcome["blocks"] = blocks.next().unwrap_or(Value::Null);
    if let Some(others) = outcome.get_mut("others").and_then(Value::as_array_mut) {
        for other in others {
            other["blocks"] = blocks.next().unwrap_or(Value::Null);
        }
    }
    outcome
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
    // Every signature after the first, parallel ones and countersignatures,
    // as the simple report lists them, each with the cryptographic result of
    // the diagnostic signature of the same token.
    let others: Vec<Value> = output
        .lines()
        .filter(|line| line.contains(" format="))
        .skip(1)
        .map(|line| {
            let field = |name: &str| {
                line.split(' ')
                    .find_map(|word| word.strip_prefix(&format!("{name}=")))
                    .unwrap_or_default()
                    .to_owned()
            };
            let token = line.split(' ').next().unwrap_or_default();
            let crypto = xml::below(root, "Signature", None)
                .find(|node| {
                    node.attribute("Id") == Some(token)
                        && xml::child(*node, "BasicSignature").is_some()
                })
                .map_or(
                    "absent",
                    |node| {
                        if intact(node) { "intact" } else { "broken" }
                    },
                );
            json!({
                "crypto": crypto,
                "structure": field("format"),
                "trust": format!("{}/{}", field("indication"), field("subindication")),
            })
        })
        .collect();
    let mut outcome = json!({
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
    });
    if !others.is_empty() {
        outcome["others"] = others.into();
    }
    // Each signature's building-block conclusions, matched by its token in
    // the order the simple report lists the signatures.
    let signatures = super::upstream::dss_signatures_of(
        &diagnostic_text,
        &xml::read(&reports.join("detailed.xml"))?,
        &xml::read(&reports.join("simple.xml"))?,
        &["SIGNATURE", "COUNTER_SIGNATURE"],
    )?;
    let blocks = output
        .lines()
        .filter(|line| line.contains(" format="))
        .map(|line| {
            let token = line.split(' ').next().unwrap_or_default();
            signatures
                .iter()
                .find(|signature| signature["token"] == token)
                .map_or(Value::Null, |signature| signature["blocks"].clone())
        })
        .collect();
    Ok(with_blocks(outcome, blocks))
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
    /// The probe whose facts give xml-sec's building-block verdicts.
    corpus_probe: PathBuf,
    /// The validation instant of every step, after every token of the run.
    at: u64,
}

const TSA_CONFIG: &str = "[tsa]\ndefault_tsa=lifecycle\n[lifecycle]\nserial=PKI/tsa.serial\ncrypto_device=builtin\nsigner_cert=PKI/tsa.pem\nsigner_key=PKI/tsa.key\nsigner_digest=sha256\ndefault_policy=1.3.6.1.4.1.13762.3\ndigests=sha256\naccuracy=secs:1\nclock_precision_digits=0\nordering=no\ntsa_name=no\ness_cert_id_chain=no\ness_cert_id_alg=sha256\n";

/// DSS signs an internally detached document through its root's `Id`.
const DATA: &str =
    "<Document Id=\"document\"><Data Id=\"payload\">Lifecycle payload</Data></Document>";
const DETACHED: &str = "Lifecycle detached payload\n";
const SECOND_DETACHED: &str = "Lifecycle second detached payload\n";

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
            "genpkey",
            "-genparam",
            "-algorithm",
            "DSA",
            "-pkeyopt",
            "dsa_paramgen_bits:2048",
            // XMLDSig 1.1 §6.4.1 requires DSA-SHA256 with (L, N) = (2048, 256);
            // OpenSSL's default N for 2048 is 224.
            "-pkeyopt",
            "dsa_paramgen_q_bits:256",
            "-out",
            "dsa.param",
        ])?;
        // Every signer key beyond the levels PKI's RSA keys.
        let keyed: Vec<_> = Algorithm::MORE
            .into_iter()
            .chain([Algorithm::Ec])
            .filter_map(|algorithm| algorithm.key().map(|key| (algorithm.signer(), key)))
            .collect();
        for (signer, (newkey, label)) in &keyed {
            let (key, request, subject) = (
                format!("{signer}.key"),
                format!("{signer}.csr"),
                format!("/CN=xml-sec XAdES Lifecycle {label} Signer"),
            );
            let mut args = vec!["req", "-newkey"];
            args.extend_from_slice(newkey);
            args.extend([
                "-nodes", "-keyout", &key, "-out", &request, "-subj", &subject,
            ]);
            generator.openssl(&args)?;
        }
        // The CAs first: a certificate is signed by its issuer's final key.
        for (name, issuer, _, extensions) in CERTIFICATES {
            if name != "outsider" {
                self.certify(&generator, name, issuer, extensions)?;
            }
        }
        let (_, issuer, _, extensions) = CERTIFICATES[1];
        for (signer, _) in &keyed {
            self.certify(&generator, signer, issuer, extensions)?;
        }
        let mut chain = read(&self.pki.join("issuer.pem"))?;
        chain.extend(read(&self.pki.join("root.pem"))?);
        write(&self.pki.join("chain.pem"), chain)?;
        let stores = ["signer"]
            .into_iter()
            .chain(keyed.iter().map(|(signer, _)| *signer))
            .map(|signer| (signer, "signer"))
            .chain([("tsa", "tsa")]);
        for (name, alias) in stores {
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
        for algorithm in [Algorithm::Rsa, Algorithm::Ec]
            .into_iter()
            .chain(Algorithm::MORE)
        {
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
        self.inputs(&generator.der("root")?)
    }

    /// The trust anchor, the TSA's configuration and the signed data every
    /// lifecycle reads.
    fn inputs(&self, root: &[u8]) -> Result<(), String> {
        // The corpus probe reads its trust anchors from a directory: the root
        // alone, the anchor every other validation takes.
        let anchors = self.results.join("anchors");
        std::fs::create_dir_all(&anchors).map_err(|error| error.to_string())?;
        write(&anchors.join("0.der"), root)?;
        write(&self.pki.join("root.der"), root)?;
        write(&self.pki.join("tsa.serial"), "01\n")?;
        let pki = self.pki.display().to_string();
        write(&self.pki.join("tsa.cnf"), TSA_CONFIG.replace("PKI", &pki))?;
        write(&self.pki.join("data.xml"), DATA)?;
        // DSS's FormProbe reads the forms' document under this name.
        write(&self.pki.join("document.xml"), DATA)?;
        write(&self.pki.join("detached-2.txt"), SECOND_DETACHED)?;
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

    /// What the B-B signature signs: the first detached file, or the XML data
    /// (a detached signature over two files finds the second beside it).
    fn data(&self, case: Case) -> PathBuf {
        self.pki.join(
            case.packaging
                .detached()
                .first()
                .copied()
                .unwrap_or("data.xml"),
        )
    }

    /// The detached objects a validator or augmenter needs.
    fn detached(&self, case: Case) -> Vec<PathBuf> {
        case.packaging
            .detached()
            .iter()
            .map(|file| self.pki.join(file))
            .collect()
    }

    fn java(&self, class: &str) -> Vec<OsString> {
        super::dss::java(&self.classpath, class, &[])
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

    /// DSS's B-B signature of `case` at Unix time `time` into `output`: a
    /// packaging through `SignProbe`, a form through `FormProbe`.
    fn dss_create(&self, case: Case, time: u64, output: &Path) -> Vec<OsString> {
        let store = self.pki.join(format!("{}.p12", case.algorithm.signer()));
        if let Some(packaging) = case.packaging.dss() {
            let mut args = self.java("SignProbe");
            args.extend(line(&[
                &store,
                &packaging,
                &self.data(case),
                &time.to_string(),
                &output,
                &case.algorithm.dss(),
            ]));
            return args;
        }
        // The PKI directory holds document.xml and both detached files.
        let mut args = self.java("FormProbe");
        args.extend(line(&[
            &store,
            &case.packaging.name(),
            &self.pki,
            &time.to_string(),
            &output,
        ]));
        args
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
            (Actor::Dss, "b") => self.dss_create(case, time, &output),
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
                for detached in self.detached(case) {
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
                args.extend(self.detached(case).into_iter().map(Into::into));
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
                args.extend(self.detached(case).into_iter().map(Into::into));
                let run = self.corpus.require(&args, &log)?;
                dss_outcome(&String::from_utf8_lossy(&run.stdout), &reports)
            }
            Actor::XmlSec => {
                let outcome = self.xml_sec_reading(step, false, &log)?;
                // The same document with unmarked tokens read as BER: the
                // two readings differ only for a token that is not DER.
                let ber = self.xml_sec_reading(step, true, &reports.with_extension("ber"))?;
                let blocks = self.xml_sec_blocks(step, &reports.with_extension("facts"))?;
                Ok(with_blocks(with_ber(outcome, &ber), blocks))
            }
        }
    }

    /// xml-sec's EN 319 102-1 building-block verdicts for each signature of
    /// the output of `step`, in document order, from the corpus probe's facts
    /// under the conformant `XAdES` profile, which admits the transforms and
    /// URIs the lifecycle's own verification admits (DSS signs an enveloped
    /// document through an `XPath` Filter 2.0 transform).
    fn xml_sec_blocks(&self, step: &Step<'_>, log: &Path) -> Result<Vec<Value>, String> {
        let anchors = self.results.join("anchors");
        let mut args = line(&[
            &self.corpus_probe,
            &"facts",
            &step.output(),
            &anchors,
            &self.at.to_string(),
            &super::upstream::PROFILES[2].1,
        ]);
        for detached in self.detached(step.case) {
            args.extend(line(&[&"--detached", &detached]));
        }
        let run = self.corpus.require(&args, log)?;
        let facts: Value = serde_json::from_slice(&run.stdout)
            .map_err(|error| format!("corpus probe facts: {error}"))?;
        Ok(our_verdicts(&facts))
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
        for detached in self.detached(step.case) {
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
            if name == "b" {
                // A reviewed alternative may hold only for one encoding width.
                row.insert("signature_octets".into(), signature_octets(created)?.into());
            }
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

/// The recorded expectations a new recording keeps the reviewed notes and
/// alternatives of; none before the first recording. A file that exists but
/// does not read or parse is an error and stays untouched.
fn previous_expectations(path: &Path) -> Result<Value, String> {
    if !path.exists() {
        return Ok(Value::Null);
    }
    serde_json::from_str(&xml::read(path)?).map_err(|error| format!("{}: {error}", path.display()))
}

/// Every deviation of `observed` from `expected`, keyed by case.
pub(crate) fn compare(expected: &Value, observed: &[Value]) -> Vec<String> {
    let mut found = Vec::new();
    for row in observed {
        let name = row["case"].as_str().unwrap_or_default();
        let case = &expected["cases"][name];
        let Some(steps) = case["steps"].as_array() else {
            found.push(format!("{name}: no expectation"));
            continue;
        };
        let actual = row["steps"].as_array().map_or(&[][..], Vec::as_slice);
        let differences = |steps: &[Value]| {
            let mut differences = Vec::new();
            if steps.len() != actual.len() {
                differences.push(format!(
                    "{name}: {} steps expected, {} observed",
                    steps.len(),
                    actual.len()
                ));
            }
            for (index, (step, observed)) in steps.iter().zip(actual).enumerate() {
                deviations(
                    step,
                    observed,
                    &format!("{name}[{index}]"),
                    &mut differences,
                );
            }
            differences
        };
        // A reviewed alternative outcome, such as one the other side's
        // randomized encoding produces now and then, matches as well.
        let primary = differences(steps);
        let alternative = case["alternatives"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|alternative| alternative["steps"].as_array())
            .any(|steps| differences(steps).is_empty());
        if !alternative {
            found.extend(primary);
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

/// The recorded expectation of one case from its `previous` expectation and
/// the `observed` steps: an observation one of the reviewed alternatives
/// already describes keeps the expectation as it was, so a run that met the
/// alternative never replaces the expected outcome; any other observation
/// becomes the expected outcome for review, keeping the alternatives.
pub(crate) fn recorded_case(previous: &Value, observed: &Value) -> Value {
    let alternatives = &previous["alternatives"];
    let reviewed = alternatives
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|alternative| alternative["steps"].as_array())
        .any(|steps| {
            let actual = observed.as_array().map_or(&[][..], Vec::as_slice);
            let mut found = Vec::new();
            for (index, (step, observed)) in steps.iter().zip(actual).enumerate() {
                deviations(step, observed, &index.to_string(), &mut found);
            }
            steps.len() == actual.len() && found.is_empty()
        });
    if reviewed {
        return previous.clone();
    }
    let mut case = json!({ "steps": observed });
    if !alternatives.is_null() {
        case["alternatives"] = alternatives.clone();
    }
    case
}

/// Runs every lifecycle and compares it with the expectations.
pub(crate) fn execute(corpus: &Corpus, results: &Path, record: bool) -> Result<(), String> {
    if results.exists() {
        return Err("results already exist; select a fresh --results directory".into());
    }
    std::fs::create_dir_all(results).map_err(|error| error.to_string())?;
    let super::dss::Built { release, classpath } =
        super::dss::build(corpus, &results.join("dss-build"))?;
    let run = Run {
        corpus,
        results: results.to_owned(),
        pki: results.join("pki"),
        classpath,
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
        corpus_probe: corpus.build_example(
            "corpus_probe",
            &[],
            Build::Dev,
            &results.join("corpus-probe-build"),
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
        // The reviewed explanations and alternatives outlive a new recording;
        // `dss` names the release the outcomes were recorded against.
        let previous = previous_expectations(&path)?;
        let cases: Map<String, Value> = observed
            .iter()
            .map(|row| {
                let name = row["case"].as_str().unwrap_or_default().to_owned();
                let case = recorded_case(&previous["cases"][&name], &row["steps"]);
                (name, case)
            })
            .collect();
        let notes = previous["notes"].clone();
        return write_json(
            &path,
            &json!({ "dss": release.dss, "notes": notes, "cases": cases }),
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
