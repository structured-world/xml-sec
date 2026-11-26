//! `xades fixtures --augmentation`: the augmentation fixtures of
//! `crates/xml-sec-xades`. OpenSSL issues the signer chain, a TSA under the
//! same intermediate and an empty CRL of each CA. The `augment_probe` example
//! writes the timestamp requests of a B-B signature xml-sec creates, then,
//! from the responses so far, those of its first archive timestamp and of
//! that archive's renewal; the OpenSSL TSA answers every one, so no response
//! is produced by xml-sec. `xades fixtures --content` issues the same PKI for
//! the content timestamps of a new signature.

use super::fixtures::Generator;
use super::levels::{Levels, TSA_CONFIG};
use super::{Corpus, line, read, write};

const TSA_EXTENSIONS: &str = "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n";

/// Each request the probe writes, the response the TSA gives to it, and
/// whether its token states the accuracy RFC 3161 §2.4.2 makes optional.
const ANSWERED: [(&str, &str, bool); 3] = [
    ("request.tsq", "response.tsr", true),
    ("request-no-nonce.tsq", "response-no-nonce.tsr", true),
    ("request-no-nonce.tsq", "response-no-accuracy.tsr", false),
];

/// The TSA's reply to `query`, as a whole DER `TimeStampResp`. OpenSSL
/// advances `tsa.serial`, so every token of one run has its own serial number
/// (RFC 3161 §2.4.2).
fn reply(generator: &Generator, query: &str, response: &str, accuracy: bool) -> Result<(), String> {
    let config = if accuracy {
        TSA_CONFIG.to_owned()
    } else {
        TSA_CONFIG.replace("accuracy=secs:1\n", "")
    };
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

/// Runs `augment_probe ACTION OUTPUT WORK` over the fixtures written so far.
fn probe(corpus: &Corpus, generator: &Generator, action: &str) -> Result<(), String> {
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
            &action,
            &generator.output,
            &generator.work,
        ]),
        &generator.work.join(format!("augment-probe-{action}")),
    )?;
    Ok(())
}

/// Issues the signer chain and a TSA under the same intermediate, and writes
/// the certificates and the signer's key.
fn issue_with_tsa(generator: &Generator) -> Result<(), String> {
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
    write(&generator.work.join("tsa.serial"), "01\n")
}

/// `xades fixtures --content`: the content timestamp and refresh fixtures.
/// The probe writes the requests of a new signature's content timestamps,
/// computed before it is signed, and the signature timestamp request of a
/// B-B signature; the OpenSSL TSA answers each one. Two generations of each
/// CA's CRL let a B-LT signature take fresher statuses.
pub(crate) fn content(corpus: &Corpus, generator: &Generator) -> Result<(), String> {
    issue_with_tsa(generator)?;
    // Two generations of each CA's CRL: a signature takes B-LT with the first
    // and has the second added by a refresh.
    let levels = Levels { generator };
    for issuer in ["root", "intermediate"] {
        write(
            &generator.output.join(format!("{issuer}.crl")),
            levels.crl(issuer)?,
        )?;
        write(
            &generator.output.join(format!("{issuer}-next.crl")),
            levels.next_crl(issuer)?,
        )?;
    }
    probe(corpus, generator, "content-request")?;
    for (query, response) in [
        ("content-all.tsq", "content-all.tsr"),
        ("content-individual.tsq", "content-individual.tsr"),
        ("content-changing.tsq", "content-changing.tsr"),
        ("signature.tsq", "signature.tsr"),
    ] {
        write(
            &generator.output.join(query),
            read(&generator.work.join(query))?,
        )?;
        reply(generator, query, response, true)?;
    }
    Ok(())
}

/// Issues the chain and the TSA, then writes the requests and every response.
pub(crate) fn generate(corpus: &Corpus, generator: &Generator) -> Result<(), String> {
    issue_with_tsa(generator)?;
    let levels = Levels { generator };
    for issuer in ["root", "intermediate"] {
        write(
            &generator.output.join(format!("{issuer}.crl")),
            levels.crl(issuer)?,
        )?;
    }
    probe(corpus, generator, "request")?;
    for name in ["request.tsq", "request-policy.tsq", "request-no-nonce.tsq"] {
        write(
            &generator.output.join(name),
            read(&generator.work.join(name))?,
        )?;
    }
    for (query, response, accuracy) in ANSWERED {
        reply(generator, query, response, accuracy)?;
    }
    // Each archive request needs the response to the one before it.
    for (action, query, response) in [
        ("archive-request", "archive.tsq", "archive.tsr"),
        ("renewal-request", "renewal.tsq", "renewal.tsr"),
    ] {
        probe(corpus, generator, action)?;
        write(
            &generator.output.join(query),
            read(&generator.work.join(query))?,
        )?;
        reply(generator, query, response, true)?;
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
