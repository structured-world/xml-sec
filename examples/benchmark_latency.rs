//! Individual-operation latency samples without an instrumented allocator.
#[path = "../benches/support/mod.rs"]
mod support;

use std::{error::Error, fmt::Write as _, time::Instant};
use support::{Engine, Fixture, OPERATIONS, SHAPES, Spec};
use xml_sec::XmlBackend;

const PHASES: [&str; 4] = [
    "projection",
    "plan_compile",
    "plan_execute",
    "policy_validate",
];

fn percentile(sorted: &[u128], percent: usize) -> u128 {
    sorted[(percent * sorted.len()).div_ceil(100) - 1]
}

fn measure(
    fixture: &Fixture,
    operation: &str,
    projection: Option<&xml_sec::benchmark_support::Projection<'_>>,
    policy: &xml_sec::policy::VerificationPolicy,
) -> (u128, usize) {
    // Per-sample preparation is excluded, just as Divan's with_inputs excludes it.
    let mut plan = match operation {
        "plan_compile" | "plan_execute" => Some(xml_sec::benchmark_support::Plan::new(
            fixture.spec.units.min(64),
        )),
        _ => None,
    };
    if operation == "plan_execute" {
        plan.as_mut().expect("plan").compile();
    }
    let start = Instant::now();
    let bytes = match operation {
        "projection" => {
            std::hint::black_box(
                projection
                    .expect("prepared projection")
                    .project()
                    .expect("project"),
            );
            fixture.unsigned.len()
        }
        "plan_compile" => {
            plan.as_mut().expect("plan").compile();
            0
        }
        "plan_execute" => {
            plan.as_ref().expect("plan").execute();
            0
        }
        "policy_validate" => {
            policy.validate().expect("policy");
            policy
                .check_signature_algorithm(xml_sec::xmldsig::SignatureAlgorithm::RsaSha256)
                .expect("permitted");
            0
        }
        _ => fixture.run(operation),
    };
    std::hint::black_box(&plan);
    (start.elapsed().as_nanos(), std::hint::black_box(bytes))
}

/// Report-only `f64` from two exact 32-bit limbs with a single rounding.
fn real<T>(value: T) -> f64
where
    u64: TryFrom<T>,
    <u64 as TryFrom<T>>::Error: std::fmt::Debug,
{
    let bytes = u64::try_from(value)
        .expect("benchmark counters fit 64 bits")
        .to_le_bytes();
    let low = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let high = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    f64::from(high) * 4_294_967_296.0 + f64::from(low)
}

/// Write the shared keys, templates and cases consumed by external CLIs.
fn export(directory: &std::path::Path) -> Result<(), Box<dyn Error>> {
    std::fs::create_dir(directory)?;
    std::fs::write(
        directory.join("private.pem"),
        include_bytes!("../tests/fixtures/keys/rsa/rsa-2048-key.pem"),
    )?;
    std::fs::write(
        directory.join("public.pem"),
        include_bytes!("../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"),
    )?;
    let aes = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0x42; 32]);
    std::fs::write(
        directory.join("keys.xml"),
        format!(
            "<Keys xmlns=\"http://www.aleksey.com/xmlsec/2002\"><KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><KeyName>bench</KeyName><KeyValue><AESKeyValue xmlns=\"http://www.aleksey.com/xmlsec/2002\">{aes}</AESKeyValue></KeyValue></KeyInfo></Keys>"
        ),
    )?;
    std::fs::write(
        directory.join("encryption.xml"),
        "<EncryptedData xmlns=\"http://www.w3.org/2001/04/xmlenc#\"><EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes256-gcm\"/><KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><KeyName>bench</KeyName></KeyInfo><CipherData><CipherValue/></CipherData></EncryptedData>",
    )?;
    let mut cases = Vec::new();
    for spec in support::specs().filter(|s| {
        matches!(s.engine, Engine::RustCrypto)
            && s.backend == XmlBackend::Xmloxide
            && [0, 1, 2, 3, 7].contains(&s.shape)
    }) {
        let fixture = Fixture::new(spec);
        let name = format!("{}-{}", SHAPES[spec.shape], spec.units);
        // A named, caller-supplied key avoids differing CLI defaults for
        // missing KeyInfo; KeyInfo is outside the signed payload/SignedInfo.
        let key_info = "<ds:KeyInfo><ds:KeyName>bench</ds:KeyName></ds:KeyInfo></ds:Signature>";
        std::fs::write(
            directory.join(format!("{name}.template.xml")),
            fixture.template.replace("</ds:Signature>", key_info),
        )?;
        std::fs::write(
            directory.join(format!("{name}.signed.xml")),
            fixture.signed.replace("</ds:Signature>", key_info),
        )?;
        // All CLIs receive the same octets, not different XML reserializations.
        std::fs::write(
            directory.join(format!("{name}.plain.xml")),
            format!("<?xml version=\"1.0\"?>{}", fixture.unsigned),
        )?;
        cases.push(
            serde_json::json!({"name": name, "shape": SHAPES[spec.shape], "units": spec.units}),
        );
    }
    export_scenarios(directory, &mut cases)?;
    std::fs::write(
        directory.join("cases.json"),
        serde_json::to_vec_pretty(&cases)?,
    )?;
    Ok(())
}

const XMLDSIG: &str = "http://www.w3.org/2000/09/xmldsig#";

/// An empty `Signature` template: RSA-SHA256 over `reference_uri` after `transforms`,
/// with the signing key named `bench`.
fn signature_template(reference_uri: &str, transforms: &str) -> String {
    format!(
        "<ds:Signature xmlns:ds=\"{XMLDSIG}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><ds:Reference URI=\"{reference_uri}\"><ds:Transforms>{transforms}</ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:KeyName>bench</ds:KeyName></ds:KeyInfo></ds:Signature>"
    )
}

/// Main user scenarios shared by every engine: SAML-shaped verification with an X.509
/// chain, element encryption with RSA-OAEP key transport, and an XSLT-transformed
/// Reference. Every file is plain input; each engine produces its own outputs.
fn export_scenarios(
    directory: &std::path::Path,
    cases: &mut Vec<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    // A leaf certificate for the signing key, its intermediate CA and the root CA,
    // rewritten as bare PEM blocks so every engine's loader reads them.
    let mut leaf_der = Vec::new();
    for (name, source) in [
        (
            "leaf.pem",
            include_str!("../tests/fixtures/keys/rsa/rsa-2048-cert.pem"),
        ),
        (
            "intermediate.pem",
            include_str!("../tests/fixtures/keys/ca2cert.pem"),
        ),
        (
            "root.pem",
            include_str!("../tests/fixtures/keys/cacert.pem"),
        ),
    ] {
        let certificate = pem::parse_many(source)?
            .into_iter()
            .find(|block| block.tag() == "CERTIFICATE")
            .ok_or("fixture has no certificate")?;
        if name == "leaf.pem" {
            leaf_der = certificate.contents().to_vec();
        }
        std::fs::write(directory.join(name), pem::encode(&certificate))?;
    }
    let leaf = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &leaf_der);
    // KeyInfo sits inside the Signature that the enveloped transform removes, so a
    // verifier input may carry the certificate instead of the signer's key name.
    std::fs::write(
        directory.join("x509-keyinfo.xml"),
        format!(
            "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{leaf}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>"
        ),
    )?;
    std::fs::write(
        directory.join("element.template.xml"),
        "<xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes256-gcm\"/><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/></xenc:EncryptionMethod><ds:KeyInfo><ds:KeyName>recipient</ds:KeyName></ds:KeyInfo><xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedData>",
    )?;
    for units in [16, 256] {
        let mut attributes = String::new();
        let mut items = String::new();
        for index in 0..units {
            write!(
                attributes,
                "<saml:Attribute Name=\"attribute-{index}\"><saml:AttributeValue>value</saml:AttributeValue></saml:Attribute>"
            )?;
            write!(items, "<Item n=\"{index}\">value</Item>")?;
        }
        let enveloped = "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>";
        std::fs::write(
            directory.join(format!("assertion-{units}.template.xml")),
            format!(
                "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"response\" Version=\"2.0\" IssueInstant=\"2026-01-01T00:00:00Z\"><saml:Issuer>https://idp.example.invalid</saml:Issuer><saml:Assertion ID=\"assertion\" Version=\"2.0\" IssueInstant=\"2026-01-01T00:00:00Z\"><saml:Issuer>https://idp.example.invalid</saml:Issuer>{}<saml:Subject><saml:NameID>user@example.invalid</saml:NameID></saml:Subject><saml:AttributeStatement>{attributes}</saml:AttributeStatement></saml:Assertion></samlp:Response>",
                signature_template("#assertion", enveloped)
            ),
        )?;
        let payment =
            format!("<Payment Id=\"payment\"><Card>4111111111111111</Card>{items}</Payment>");
        std::fs::write(
            directory.join(format!("element-{units}.plain.xml")),
            &payment,
        )?;
        std::fs::write(
            directory.join(format!("order-{units}.plain.xml")),
            format!(
                "<Order><Customer>benchmark@example.invalid</Customer>{payment}<Note>kept</Note></Order>"
            ),
        )?;
        let stylesheet = "<ds:Transform Algorithm=\"http://www.w3.org/TR/1999/REC-xslt-19991116\"><xsl:stylesheet xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\" version=\"1.0\"><xsl:output method=\"xml\" omit-xml-declaration=\"yes\"/><xsl:template match=\"/\"><out><xsl:for-each select=\"//Item\"><v n=\"{@n}\"><xsl:value-of select=\".\"/></v></xsl:for-each></out></xsl:template></xsl:stylesheet></ds:Transform>";
        std::fs::write(
            directory.join(format!("xslt-{units}.template.xml")),
            format!(
                "<Catalog><List Id=\"list\">{items}</List>{}</Catalog>",
                signature_template("#list", stylesheet)
            ),
        )?;
        for scenario in ["assertion", "element", "element_in_place", "xslt"] {
            cases.push(serde_json::json!({"name": format!("{scenario}-{units}"), "scenario": scenario, "units": units}));
        }
    }
    Ok(())
}

/// Print every measurable operation, shape, backend and provider combination.
fn list() {
    for spec in support::specs() {
        let backend = match spec.backend {
            XmlBackend::Xmloxide => "xmloxide",
            XmlBackend::Roxmltree => "roxmltree",
            XmlBackend::Differential => "differential",
        };
        let provider = match spec.engine {
            Engine::RustCrypto => "rustcrypto",
            #[cfg(feature = "aws-lc-fips")]
            Engine::AwsLcFips => "aws-lc-fips",
        };
        for operation in OPERATIONS.into_iter().chain(PHASES) {
            if operation == "projection" && spec.backend == XmlBackend::Differential {
                continue;
            }
            println!(
                "{operation} {} {} {backend} {provider}",
                SHAPES[spec.shape], spec.units
            );
        }
    }
}

/// One validated measurement request from the command line.
struct Request<'a> {
    operation: &'a str,
    spec: Spec,
    samples: usize,
}

fn parse_request(args: &[String]) -> Result<Request<'_>, Box<dyn Error>> {
    if args.len() != 6 {
        return Err("usage: benchmark_latency <operation> <shape> <units> <backend> <provider> <samples> (or --list)".into());
    }
    let operation = args[0].as_str();
    if !OPERATIONS.contains(&operation) && !PHASES.contains(&operation) {
        return Err("unknown operation".into());
    }
    let shape = SHAPES
        .iter()
        .position(|shape| *shape == args[1])
        .ok_or("unknown shape")?;
    let units = args[2].parse::<usize>()?;
    if ![16, 256].contains(&units) {
        return Err("units must be 16 or 256".into());
    }
    let backend = match args[3].as_str() {
        "xmloxide" => XmlBackend::Xmloxide,
        "roxmltree" => XmlBackend::Roxmltree,
        "differential" => XmlBackend::Differential,
        _ => return Err("unknown backend".into()),
    };
    let engine = match args[4].as_str() {
        "rustcrypto" => Engine::RustCrypto,
        #[cfg(feature = "aws-lc-fips")]
        "aws-lc-fips" => Engine::AwsLcFips,
        _ => return Err("unavailable provider".into()),
    };
    if operation == "projection" && backend == XmlBackend::Differential {
        return Err("projection requires one backend, not differential parsing".into());
    }
    let samples = args[5].parse::<usize>()?;
    if !(1..=100_000).contains(&samples) {
        return Err("samples must be 1..=100000".into());
    }
    Ok(Request {
        operation,
        spec: Spec {
            shape,
            units,
            backend,
            engine,
        },
        samples,
    })
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() == 2 && args[0] == "--export" {
        return export(std::path::Path::new(&args[1]));
    }
    if args == ["--list"] {
        list();
        return Ok(());
    }
    let Request {
        operation,
        spec,
        samples,
    } = parse_request(&args)?;
    let (units, backend) = (spec.units, spec.backend);
    let fixture = Fixture::new(spec);
    let projection = if operation == "projection" {
        Some(xml_sec::benchmark_support::Projection::new(
            &fixture.unsigned,
            backend,
        )?)
    } else {
        None
    };
    let policy = xml_sec::policy::VerificationPolicy {
        signature_algorithms: Some(
            [xml_sec::xmldsig::SignatureAlgorithm::RsaSha256]
                .into_iter()
                .collect(),
        ),
        ..Default::default()
    };
    for _ in 0..8 {
        std::hint::black_box(measure(&fixture, operation, projection.as_ref(), &policy));
    }
    let mut timings = Vec::with_capacity(samples);
    let mut output_bytes = 0;
    for _ in 0..samples {
        let (elapsed, bytes) = measure(&fixture, operation, projection.as_ref(), &policy);
        output_bytes = bytes;
        timings.push(elapsed);
    }
    let total: u128 = timings.iter().sum();
    let raw = timings.clone();
    timings.sort_unstable();
    // Nearest-rank order statistics, not percentiles of batched iteration averages.
    let input_bytes = if ["plan_compile", "plan_execute", "policy_validate"].contains(&operation) {
        0
    } else {
        fixture.input_bytes(operation)
    };
    let amplification = if ["c14n", "sign", "encrypt", "decrypt"].contains(&operation) {
        Some(real(output_bytes) / real(input_bytes))
    } else {
        None
    };
    println!(
        "{}",
        serde_json::json!({
            "schema": 1, "operation": operation, "shape": args[1], "units": units,
            "backend": args[3], "provider": args[4], "samples": samples,
            "plan_references": if operation.starts_with("plan_") { Some(units.min(64)) } else { None },
            "os": std::env::consts::OS, "arch": std::env::consts::ARCH,
            "allocator": "system-uninstrumented", "setup_and_warmup_excluded": true,
            "validation_included": true, "input_bytes": input_bytes, "output_bytes": output_bytes,
            "output_amplification": amplification, "p50_ns": percentile(&timings, 50),
            "p95_ns": percentile(&timings, 95), "p99_ns": percentile(&timings, 99), "raw_ns": raw,
            "operations_per_second": real(samples) * 1e9 / real(total),
            "input_bytes_per_second": real(input_bytes) * real(samples) * 1e9 / real(total)
        })
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn nearest_rank_handles_single_and_non_hundred_sample_counts() {
        // Tail percentiles use individual order statistics, including small smoke samples.
        assert_eq!(super::percentile(&[7], 99), 7);
        assert_eq!(super::percentile(&[10, 20, 30], 50), 20);
        assert_eq!(super::percentile(&[10, 20, 30], 95), 30);
        let values: Vec<_> = (1..=100).collect();
        assert_eq!(super::percentile(&values, 99), 99);
    }
}
