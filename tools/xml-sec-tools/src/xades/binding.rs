//! `xades binding [--output DIR] [--analyze | --strict-policy | --generate]`:
//! reproduces two `XAdES` binding discrepancies between xml-sec and EU DSS
//! without changing either engine, on independently signed minimal inputs.

use super::corpus::base64;
use super::dss::{classpath, maven, tools};
use super::{
    Corpus, DS, EXC, SP, absolute, compare, debug_buffer, digest, line, read, write, write_json,
    xml,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Map, Value, json};
use std::path::Path;

/// One investigation input: its `Target`, the certificates its
/// `SigningCertificateV2` references, and whether binding must hold.
struct Case {
    name: &'static str,
    target: Option<&'static str>,
    certificates: &'static [&'static str],
    expected: bool,
}

const CASES: [Case; 9] = [
    Case {
        name: "control",
        target: Some("#sig"),
        certificates: &["signer"],
        expected: true,
    },
    Case {
        name: "target-payload",
        target: Some("#payload"),
        certificates: &["signer"],
        expected: false,
    },
    Case {
        name: "target-unresolved",
        target: Some("#absent"),
        certificates: &["signer"],
        expected: false,
    },
    Case {
        name: "target-absent",
        target: None,
        certificates: &["signer"],
        expected: false,
    },
    Case {
        name: "cert-root",
        target: Some("#sig"),
        certificates: &["root"],
        expected: false,
    },
    Case {
        name: "cert-intermediate",
        target: Some("#sig"),
        certificates: &["intermediate"],
        expected: false,
    },
    Case {
        name: "cert-unmatched",
        target: Some("#sig"),
        certificates: &["unmatched"],
        expected: false,
    },
    Case {
        name: "cert-root-then-signer",
        target: Some("#sig"),
        certificates: &["root", "signer"],
        expected: false,
    },
    Case {
        name: "cert-signer-then-root",
        target: Some("#sig"),
        certificates: &["signer", "root"],
        expected: true,
    },
];

fn require(condition: bool, reason: impl Into<String>) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(reason.into())
    }
}

/// An unsigned `XAdES` template. EN 319 132-1 V1.3.1 §§4.3.1, 4.4.2, 5.2.2;
/// no `XPath`, Filter2 or `xml:base`, so binding behavior is independent of
/// transform semantics.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub(crate) fn template(
    package: &Path,
    target: Option<&str>,
    certificates: &[&str],
) -> Result<String, String> {
    use sha2::Digest as _;
    let der = |name: &str| read(&package.join(format!("fixtures/baseline/{name}.der")));
    let mut references = String::new();
    for name in certificates {
        let digest = if *name == "unmatched" {
            vec![0; 32]
        } else {
            sha2::Sha256::digest(der(name)?).to_vec()
        };
        references.push_str(
            r#"<x:Cert><x:CertDigest><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>"#,
        );
        references.push_str(&STANDARD.encode(digest));
        references.push_str("</ds:DigestValue></x:CertDigest></x:Cert>");
    }
    let mut key_info = String::new();
    for name in ["signer", "intermediate"] {
        key_info.push_str("<ds:X509Certificate>");
        key_info.push_str(&STANDARD.encode(der(name)?));
        key_info.push_str("</ds:X509Certificate>");
    }
    let target = target
        .map(|target| format!(r#" Target="{target}""#))
        .unwrap_or_default();
    Ok(format!(
        r##"<r><Data Id="payload">x</Data><ds:Signature xmlns:ds="{DS}" Id="sig"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{EXC}"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference Id="sig-data" URI="#payload"><ds:Transforms><ds:Transform Algorithm="{EXC}"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference><ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#sp"><ds:Transforms><ds:Transform Algorithm="{EXC}"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:KeyInfo><ds:X509Data>{key_info}</ds:X509Data></ds:KeyInfo><ds:Object><x:QualifyingProperties xmlns:x="{SP}"{target}><x:SignedProperties Id="sp"><x:SignedSignatureProperties><x:SigningTime>2026-10-18T12:00:00Z</x:SigningTime><x:SigningCertificateV2>{references}</x:SigningCertificateV2></x:SignedSignatureProperties><x:SignedDataObjectProperties><x:DataObjectFormat ObjectReference="#sig-data"><x:MimeType>text/xml</x:MimeType></x:DataObjectFormat></x:SignedDataObjectProperties></x:SignedProperties></x:QualifyingProperties></ds:Object></ds:Signature></r>"##
    ))
}

/// Compact certificate-selection evidence; full DSS reports stay local.
pub(crate) fn binding_facts(path: &Path) -> Result<Map<String, Value>, String> {
    let text = xml::read(path)?;
    let mut facts = Map::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("{}: not a key=value line: {line}", path.display()))?;
        if key != "structural_policy" {
            facts.insert(key.into(), value.into());
        }
    }
    Ok(facts)
}

/// Keeps the oracle's octets independently of the ignored stdout capture.
fn capture_native_octets(directory: &Path) -> Result<(), String> {
    let name = directory
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let stdout = read(&directory.join("libxmlsec.stdout"))?;
    let blocks = super::corpus::after_each(&stdout, b"= REFERENCE VERIFICATION CONTEXT\n");
    require(
        blocks.len() == 2,
        format!("incomplete native Reference diagnostics: {name}"),
    )?;
    for (index, block) in blocks.into_iter().enumerate() {
        let expected = debug_buffer(block, "PreDigest")?
            .ok_or_else(|| format!("missing native Reference octets: {name}/{index}"))?;
        write(
            &directory.join(format!("expected-reference-{index}.bin")),
            expected,
        )?;
    }
    let signed_info = debug_buffer(&stdout, "PreSigned")?
        .ok_or_else(|| format!("missing native SignedInfo: {name}"))?;
    write(&directory.join("expected-signedinfo.bin"), signed_info)
}

/// Independent byte checks, so a bad signature fixture cannot mask binding behavior.
pub(crate) fn analyze_octets(output: &Path) -> Result<(), String> {
    let summary: Value = serde_json::from_str(&xml::read(&output.join("summary.json"))?)
        .map_err(|error| error.to_string())?;
    let mut evidence = Vec::new();
    for case in summary["cases"].as_array().into_iter().flatten() {
        let name = case["name"].as_str().ok_or("case without a name")?;
        let directory = output.join(name);
        let values = xml::digest_values(&xml::read(&directory.join("signed.xml"))?, name)?;
        require(
            values.len() == 2,
            format!("incomplete Reference inputs: {name}"),
        )?;
        let mut references = Vec::new();
        for (index, value) in values.iter().enumerate() {
            let expected = read(&directory.join(format!("expected-reference-{index}.bin")))?;
            let actual = read(&directory.join(format!("rust/reference-{index}.bin")))?;
            let replay = read(&directory.join(format!("rust/replay-{index}.bin")))?;
            let mut result = compare(&expected, &actual);
            let written = base64(value)?;
            let written_hex = super::hex(&written);
            let matches = written_hex == digest(&actual);
            let replay = compare(&actual, &replay);
            require(
                result["status"] == "verified" && replay["status"] == "verified" && matches,
                format!("Reference/digest/replay mismatch: {name}/{index}"),
            )?;
            result.insert("digest_value_hex".into(), written_hex.into());
            result.insert("digest_matches".into(), matches.into());
            result.insert("replay".into(), Value::Object(replay));
            references.push(Value::Object(result));
        }
        let signed_info = compare(
            &read(&directory.join("expected-signedinfo.bin"))?,
            &read(&directory.join("rust/signature-0.bin"))?,
        );
        require(
            signed_info["status"] == "verified",
            format!("SignedInfo mismatch: {name}"),
        )?;
        evidence
            .push(json!({ "name": name, "references": references, "signed_info": signed_info }));
    }
    write_json(
        &output.join("octet-comparison.json"),
        &Value::Array(evidence.clone()),
    )?;
    println!(
        "verified: {} Reference pairs, digests and replay; {} SignedInfo pairs",
        evidence.len() * 2,
        evidence.len()
    );
    Ok(())
}

/// The three DSS reports of one validation.
struct Reports {
    simple: String,
    diagnostic: String,
    detailed: String,
}

impl Reports {
    fn read(directory: &Path) -> Result<Self, String> {
        Ok(Self {
            simple: xml::read(&directory.join("simple.xml"))?,
            diagnostic: xml::read(&directory.join("diagnostic.xml"))?,
            detailed: xml::read(&directory.join("detailed.xml"))?,
        })
    }
}

/// Indication, sub-indication and building-block conclusions of a report.
fn conclusions(reports: &Reports) -> Result<(Value, Value, Value), String> {
    let simple = xml::parse(&reports.simple, "simple report")?;
    let detailed = xml::parse(&reports.detailed, "detailed report")?;
    let signature = xml::child(simple.root_element(), "Signature")
        .ok_or("simple report without a Signature")?;
    let blocks = xml::signature_blocks(detailed.root_element())
        .ok_or("detailed report without signature blocks")?;
    let text = |path: &[&str]| xml::text_at(signature, path).map_or(Value::Null, Value::from);
    Ok((
        text(&["Indication"]),
        text(&["SubIndication"]),
        Value::Object(xml::conclusions(blocks, "Indication")),
    ))
}

/// Reruns DSS on the existing inputs with `StructuralValidation` WARN changed to FAIL.
fn strict_policy(corpus: &Corpus, output: &Path) -> Result<(), String> {
    let summary: Value = serde_json::from_str(&xml::read(&output.join("summary.json"))?)
        .map_err(|error| error.to_string())?;
    let package = corpus.package();
    let build = line(&[
        &maven(corpus),
        &"-B",
        &"-o",
        &"-f",
        &package.join("dss/pom.xml"),
        &format!(
            "-Dmaven.repo.local={}",
            tools(corpus).join("repository").display()
        ),
        &"compile",
    ]);
    corpus.require(&build, &output.join("dss-strict-build"))?;
    let classpath = classpath(corpus)?;
    let mut results = Vec::new();
    for case in summary["cases"].as_array().into_iter().flatten() {
        let name = case["name"].as_str().ok_or("case without a name")?;
        let directory = output.join(name);
        let result = directory.join("dss-structure-fail");
        if result.exists() {
            return Err(format!(
                "policy experiment already exists: {}",
                result.display()
            ));
        }
        let probe = line(&[
            &"java",
            &"-cp",
            &classpath,
            &"BindingProbe",
            &directory.join("signed.xml"),
            &package.join("fixtures/baseline/root.der"),
            &result,
            &"structure-fail",
        ]);
        corpus.require(&probe, &directory.join("dss-structure-fail-probe"))?;
        let (indication, subindication, blocks) = conclusions(&Reports::read(&result)?)?;
        results.push(json!({ "name": name, "indication": indication, "subindication": subindication, "blocks": blocks }));
    }
    let results = Value::Array(results);
    write_json(&output.join("strict-policy-summary.json"), &results)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&results).map_err(|error| error.to_string())?
    );
    Ok(())
}

/// Signs or restores one case, then runs libxmlsec1, the Rust probe and DSS on it.
fn investigate_case(corpus: &Corpus, case: &Case, setup: &Setup<'_>) -> Result<Value, String> {
    let package = corpus.package();
    let root_der = package.join("fixtures/baseline/root.der");
    let directory = setup.output.join(case.name);
    std::fs::create_dir(&directory)
        .map_err(|error| format!("create {}: {error}", directory.display()))?;
    let (source, signed) = (directory.join("template.xml"), directory.join("signed.xml"));
    write(&source, template(&package, case.target, case.certificates)?)?;
    if setup.generate {
        let credentials = ["signer.key", "signer.pem", "intermediate.pem"]
            .map(|name| package.join("fixtures").join(name).display().to_string())
            .join(",");
        let mut args = corpus.oracle_args("--sign");
        args.extend(line(&[
            &"--lax-key-search",
            &"--privkey-pem",
            &credentials,
            &"--output",
            &signed,
            &source,
        ]));
        corpus.require(&args, &directory.join("sign"))?;
    } else {
        let retained = package.join("dss-investigation").join(case.name);
        require(
            read(&source)? == read(&retained.join("template.xml"))?,
            format!("template differs from construction source: {}", case.name),
        )?;
        write(&signed, read(&retained.join("signed.xml"))?)?;
    }
    let mut verify = corpus.oracle_args("--verify");
    verify.push(signed.clone().into());
    corpus.require(&verify, &directory.join("libxmlsec"))?;
    capture_native_octets(&directory)?;
    let rust = directory.join("rust");
    corpus.require(
        &line(&[&setup.binary, &signed, &root_der, &rust, &"spec", &"-"]),
        &directory.join("rust-probe"),
    )?;
    let dss = directory.join("dss");
    let probe = line(&[
        &"java",
        &"-cp",
        &setup.classpath,
        &"BindingProbe",
        &signed,
        &root_der,
        &dss,
    ]);
    corpus.require(&probe, &directory.join("dss-probe"))?;
    let reports = Reports::read(&dss)?;
    let (indication, subindication, blocks) = conclusions(&reports)?;
    let simple = xml::parse(&reports.simple, "simple report")?;
    let format = xml::child(simple.root_element(), "Signature")
        .and_then(|signature| signature.attribute("SignatureFormat"));
    let diagnostic = xml::parse(&reports.diagnostic, "diagnostic report")?;
    let structure = xml::find(diagnostic.root_element(), "Signatures", "Signature")
        .and_then(|signature| xml::child(signature, "StructuralValidation"))
        .ok_or_else(|| format!("no DSS structural validation: {}", case.name))?
        .attribute("valid");
    let result = xml::read(&rust.join("result.txt"))?;
    let bound = result.contains("xades=Ok(Assessed((true, true)))");
    require(
        result.contains("all_valid=true\n"),
        format!("not a valid XMLDSig fixture: {}", case.name),
    )?;
    require(
        bound == case.expected,
        format!("Rust disagrees with normative case: {}", case.name),
    )?;
    let finding = result
        .lines()
        .find(|line| line.starts_with("xades="))
        .ok_or_else(|| format!("no XAdES finding: {}", case.name))?;
    Ok(json!({
        "name": case.name,
        "target": case.target,
        "cert_references": case.certificates,
        "expected_bb": case.expected,
        "fixture_sha256": digest(&read(&signed)?),
        "rust_bb": bound,
        "rust_xml_dsig_status": "verified",
        "native_xml_dsig_status": "verified",
        "dss_binding_facts": binding_facts(&dss.join("binding-facts.txt"))?,
        "rust_finding": finding,
        "dss_format": format,
        "dss_indication": indication,
        "dss_subindication": subindication,
        "dss_structure": structure,
        "dss_blocks": blocks,
    }))
}

/// What every investigated case shares.
struct Setup<'a> {
    output: &'a Path,
    binary: &'a Path,
    classpath: &'a str,
    generate: bool,
}

/// Runs every case into a new `output` directory and checks its octets.
fn investigate(corpus: &Corpus, output: &Path, generate: bool) -> Result<(), String> {
    if output.exists() {
        return Err(
            "investigation evidence already exists; preserve or archive it before rerunning".into(),
        );
    }
    std::fs::create_dir_all(output)
        .map_err(|error| format!("create {}: {error}", output.display()))?;
    let binary = corpus.build_probe(&output.join("rust-build"))?;
    let mvn = maven(corpus);
    require(
        mvn.exists(),
        "first bootstrap the pinned oracle with `xades dss`",
    )?;
    let package = corpus.package();
    let tools = tools(corpus);
    let build = line(&[
        &mvn,
        &"-B",
        &"-o",
        &"-f",
        &package.join("dss/pom.xml"),
        &format!("-Dmaven.repo.local={}", tools.join("repository").display()),
        &"compile",
        &"dependency:build-classpath",
        &format!(
            "-Dmdep.outputFile={}",
            tools.join("classpath.txt").display()
        ),
    ]);
    corpus.require(&build, &output.join("dss-build"))?;
    let classpath = classpath(corpus)?;
    let setup = Setup {
        output,
        binary: &binary,
        classpath: &classpath,
        generate,
    };
    let summary = CASES
        .iter()
        .map(|case| investigate_case(corpus, case, &setup))
        .collect::<Result<Vec<Value>, String>>()?;
    // Target is outside SignedProperties: each Target-only change keeps the
    // same SignatureValue and reference digests, with no broken-crypto fixture.
    let mut signature_values = std::collections::BTreeSet::new();
    for name in [
        "control",
        "target-payload",
        "target-unresolved",
        "target-absent",
    ] {
        let text = xml::read(&output.join(name).join("signed.xml"))?;
        let document = xml::parse(&text, name)?;
        let value = xml::below(document.root_element(), "SignatureValue", Some(DS))
            .next()
            .map(|node| node.text().unwrap_or_default().to_owned());
        signature_values.insert(value);
    }
    require(
        signature_values.len() == 1,
        "Target-only mutations changed SignatureValue",
    )?;
    let mut certificates = Map::new();
    for name in ["signer", "intermediate", "root"] {
        let der = read(&package.join(format!("fixtures/baseline/{name}.der")))?;
        certificates.insert(name.into(), digest(&der).into());
    }
    write_json(
        &output.join("summary.json"),
        &json!({
            "cases": summary,
            "certificate_sha256": certificates,
            "target_only_signature_values_identical": true,
        }),
    )?;
    analyze_octets(output)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&summary).map_err(|error| error.to_string())?
    );
    Ok(())
}

/// Which part of the investigation runs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Retained,
    Generate,
    Analyze,
    StrictPolicy,
}

pub(crate) fn execute(corpus: &Corpus, output: &Path, strict: bool) -> Result<(), String> {
    if strict {
        strict_policy(corpus, output)
    } else {
        investigate(corpus, output, false)
    }
}

pub(crate) fn run(corpus: &Corpus, args: &[String]) -> Result<(), crate::repo::Failure> {
    let usage = "usage: xades binding [--output DIR] [--analyze | --strict-policy | --generate]";
    let mut output = corpus.root.join("target/xades-binding");
    let mut mode = Mode::Retained;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let selected = match arg.as_str() {
            "--output" => {
                output = absolute(args.next().ok_or(usage)?)?;
                continue;
            }
            "--analyze" => Mode::Analyze,
            "--strict-policy" => Mode::StrictPolicy,
            "--generate" => Mode::Generate,
            _ => return Err(usage.into()),
        };
        if mode != Mode::Retained {
            return Err(usage.into());
        }
        mode = selected;
    }
    Ok(match mode {
        Mode::Analyze => analyze_octets(&output),
        Mode::StrictPolicy => strict_policy(corpus, &output),
        Mode::Generate => investigate(corpus, &output, true),
        Mode::Retained => investigate(corpus, &output, false),
    }?)
}
