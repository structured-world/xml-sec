//! `xades fixtures --augmentation`: the B-T augmentation fixtures of
//! `crates/xml-sec-xades`. OpenSSL issues the signer chain and a TSA under the
//! same intermediate. The `augment_probe` example writes the timestamp
//! requests of a B-B signature xml-sec creates, and the OpenSSL TSA answers
//! them, so no response is produced by xml-sec.

use super::fixtures::Generator;
use super::levels::TSA_CONFIG;
use super::{Corpus, line, read, write};

const TSA_EXTENSIONS: &str = "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n";

/// Each request the probe writes and the response the TSA gives to it.
const ANSWERED: [(&str, &str); 2] = [
    ("request.tsq", "response.tsr"),
    ("request-no-nonce.tsq", "response-no-nonce.tsr"),
];

/// The TSA's reply to `query`, as a whole DER `TimeStampResp`.
fn reply(generator: &Generator, query: &str, response: &str) -> Result<(), String> {
    generator.write_tsa()?;
    generator.openssl(&[
        "ts",
        "-reply",
        "-config",
        "tsa.cnf",
        "-queryfile",
        query,
        "-out",
        response,
    ])?;
    write(
        &generator.output.join(response),
        read(&generator.work.join(response))?,
    )
}

impl Generator {
    fn write_tsa(&self) -> Result<(), String> {
        write(&self.work.join("tsa.serial"), "01\n")?;
        write(&self.work.join("tsa.cnf"), TSA_CONFIG)
    }
}

/// Issues the chain and the TSA, then writes the requests and every response.
pub(crate) fn generate(corpus: &Corpus, generator: &Generator) -> Result<(), String> {
    for directory in [&generator.output, &generator.work] {
        std::fs::create_dir_all(directory)
            .map_err(|error| format!("create {}: {error}", directory.display()))?;
    }
    generator.issue()?;
    generator.certify(
        "tsa",
        "intermediate",
        "/CN=xml-sec XAdES Test TSA",
        TSA_EXTENSIONS,
    )?;
    for certificate in ["root", "intermediate", "signer", "tsa"] {
        write(
            &generator.output.join(format!("{certificate}.der")),
            generator.der(certificate)?,
        )?;
    }
    write(
        &generator.output.join("signer.key"),
        read(&generator.work.join("signer.key"))?,
    )?;
    corpus.require(
        &line(&[
            &"cargo",
            &"run",
            &"-q",
            &"-p",
            &"xml-sec-xades",
            &"--features",
            &"produce",
            &"--example",
            &"augment_probe",
            &"--",
            &"request",
            &generator.output,
            &generator.work,
        ]),
        &generator.work.join("augment-probe"),
    )?;
    for name in ["request.tsq", "request-policy.tsq", "request-no-nonce.tsq"] {
        write(
            &generator.output.join(name),
            read(&generator.work.join(name))?,
        )?;
    }
    for (query, response) in ANSWERED {
        reply(generator, query, response)?;
    }
    // A token over other data, and a rejection: the TSA issues only SHA-256
    // imprints (RFC 3161 §2.4.2 badAlg).
    write(&generator.work.join("other.txt"), "Other data\n")?;
    for (digest, query, response) in [
        ("-sha256", "other.tsq", "response-other-imprint.tsr"),
        ("-sha512", "rejected.tsq", "response-rejected.tsr"),
    ] {
        generator.openssl(&[
            "ts",
            "-query",
            "-data",
            "other.txt",
            digest,
            "-cert",
            "-no_nonce",
            "-out",
            query,
        ])?;
        reply(generator, query, response)?;
    }
    Ok(())
}
