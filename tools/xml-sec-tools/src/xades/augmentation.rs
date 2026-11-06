//! `xades fixtures --augmentation`: the B-T augmentation fixtures of
//! `crates/xml-sec-xades`. OpenSSL issues the signer chain and a TSA under the
//! same intermediate. The `augment_probe` example writes the timestamp
//! requests of a B-B signature xml-sec creates, and the OpenSSL TSA answers
//! them, so no response is produced by xml-sec.

use super::fixtures::Generator;
use super::levels::TSA_CONFIG;
use super::{Corpus, line, read, write};

const TSA_EXTENSIONS: &str = "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n";

/// Each request the probe writes, the response the TSA gives to it, and
/// whether its token states the accuracy RFC 3161 §2.4.2 makes optional.
const ANSWERED: [(&str, &str, bool); 3] = [
    ("request.tsq", "response.tsr", true),
    ("request-no-nonce.tsq", "response-no-nonce.tsr", true),
    ("request-no-nonce.tsq", "response-no-accuracy.tsr", false),
];

/// The TSA's reply to `query`, as a whole DER `TimeStampResp`.
fn reply(generator: &Generator, query: &str, response: &str, accuracy: bool) -> Result<(), String> {
    let config = if accuracy {
        TSA_CONFIG.to_owned()
    } else {
        TSA_CONFIG.replace("accuracy=secs:1\n", "")
    };
    write(&generator.work.join("tsa.serial"), "01\n")?;
    write(&generator.work.join("tsa.cnf"), config)?;
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
    for (query, response, accuracy) in ANSWERED {
        reply(generator, query, response, accuracy)?;
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
        reply(generator, query, response, true)?;
    }
    Ok(())
}
