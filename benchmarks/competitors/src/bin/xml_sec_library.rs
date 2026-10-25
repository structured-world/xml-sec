//! xml-sec through its Rust API, configured as the competitors are for each workload.

use rsa::{RsaPrivateKey, RsaPublicKey};
use std::collections::HashSet;
use std::process::ExitCode;
use xml_sec::policy::{
    DecryptionPolicy, EncryptionPolicy, SigningPolicy, TransformPolicy, VerificationPolicy,
    XsltStylesheetSemantics,
};
use xml_sec::provider::RustCryptoProvider;
use xml_sec::rsa_encoding::{RsaPrivateKeyEncoding as _, RsaPublicKeyEncoding as _};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DsigStatus, KeyResolverConfig, KeyTrustEvidence, RsaSigningKey,
    SignContext, SignatureAlgorithm, VerificationKey, VerifyContext, VerifyResult,
    X509CertificateKeyInfoWriter,
};
use xml_sec::xmlenc::{
    DataEncryptionAlgorithm, DecryptContext, DocumentEncryptionOptions, EncryptedDataBuilder,
    EncryptionRecipient, KeyTransportAlgorithm, OaepDigestAlgorithm, PrivateKeyDecryptor,
    RsaOaepParameters,
};
use xml_sec::{IdAttributeRegistration, XmlDocument};
use xml_sec_competitor_bench::{Args, Boundary, Outcome, measure};

const SAML_ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

fn main() -> ExitCode {
    xml_sec_competitor_bench::main("xml-sec", execute)
}

/// Signature and reference results alone do not authorize a key; every valid
/// sample also requires the configured trust (chain or caller-supplied key).
fn accepted(result: &VerifyResult) -> bool {
    matches!(result.status, DsigStatus::Valid)
        && matches!(
            result.key_trust,
            KeyTrustEvidence::ValidatedX509(_) | KeyTrustEvidence::CallerTrusted
        )
}

/// libxmlsec1 reads a stylesheet as serialized `<Transform>` content; signers
/// and verifiers must agree on it to produce interoperable XSLT digests.
fn transforms() -> TransformPolicy {
    TransformPolicy {
        xslt_stylesheet_semantics: XsltStylesheetSemantics::Libxmlsec1,
        ..TransformPolicy::default()
    }
}

/// RSA-OAEP with MGF1-SHA1 is the one key transport all three engines share
/// (Bergshamra implements only SHA-1 OAEP), so the request permits exactly it.
fn oaep() -> RsaOaepParameters {
    RsaOaepParameters {
        algorithm: KeyTransportAlgorithm::RsaOaepMgf1p,
        digest: OaepDigestAlgorithm::Sha1,
        mgf_digest: OaepDigestAlgorithm::Sha1,
        label: Vec::new(),
    }
}

fn execute(args: &Args) -> Result<Outcome, String> {
    let ids = [
        IdAttributeRegistration::scoped("ID", "Assertion", Some(SAML_ASSERTION)),
        IdAttributeRegistration::scoped("Id", "List", None),
        IdAttributeRegistration::scoped("Id", "Payment", None),
    ];
    let input = args.input_text()?;
    match (args.scenario.as_str(), args.operation.as_str()) {
        ("assertion" | "xslt", "sign") => sign(args, &ids, &input),
        ("assertion" | "xslt", "verify" | "reject") => verify(args, &ids, &input),
        ("element" | "element_in_place", "encrypt") => encrypt(args, &input),
        ("element" | "element_in_place", "decrypt") => decrypt(args, &input),
        _ => Ok(Outcome::Unsupported("no such workload operation")),
    }
}

fn sign(args: &Args, ids: &[IdAttributeRegistration], input: &str) -> Result<Outcome, String> {
    let key = RsaSigningKey::from_pkcs8_pem(&args.corpus_text("private.pem")?)
        .map_err(|error| error.to_string())?;
    let writer = X509CertificateKeyInfoWriter::from_pem(&args.corpus_text("leaf.pem")?)
        .map_err(|error| error.to_string())?;
    let policy = SigningPolicy {
        transforms: transforms(),
        ..SigningPolicy::default()
    };
    let provider = RustCryptoProvider;
    let mut context = SignContext::new(&key)
        .policy(policy.clone())
        .provider(&provider)
        .id_attributes(ids);
    // The SAML template carries an empty X509Data that the signer fills.
    if args.scenario == "assertion" {
        context = context.key_info_writer(&writer);
    }
    let measurement = match args.boundary {
        Boundary::Parse => measure(
            args.samples,
            || Ok::<_, String>(()),
            |()| {
                context
                    .sign_template(input)
                    .map_err(|error| error.to_string())
            },
            |signed: &String| Some(signed.as_bytes().to_vec()),
        )?,
        Boundary::Prepared => measure(
            args.samples,
            || XmlDocument::parse_with_policy(input, &policy).map_err(|error| error.to_string()),
            |mut document| {
                context
                    .sign_document(&mut document)
                    .map(|()| document)
                    .map_err(|error| error.to_string())
            },
            |document: &XmlDocument| Some(document.as_xml().as_bytes().to_vec()),
        )?,
    };
    Ok(Outcome::Measured(measurement))
}

fn verify(args: &Args, ids: &[IdAttributeRegistration], input: &str) -> Result<Outcome, String> {
    let der = |name: &str| -> Result<Vec<u8>, String> {
        let text = args.corpus_text(name)?;
        let block = pem::parse(text).map_err(|error| format!("{name}: {error}"))?;
        Ok(block.into_contents())
    };
    let resolver = DefaultKeyResolver::new(KeyResolverConfig {
        lookup_certs: vec![der("intermediate.pem")?],
        trusted_certs: vec![der("root.pem")?],
        ..KeyResolverConfig::default()
    });
    let key = VerificationKey {
        algorithm: SignatureAlgorithm::RsaSha256,
        public_key_bytes: der("public.pem")?,
        certificate_der: None,
        name: None,
    };
    let mut policy = VerificationPolicy {
        transforms: transforms(),
        ..VerificationPolicy::default()
    };
    // The document's own certificate establishes trust only through a path to
    // the configured root, as for the other engines' trusted-root settings.
    policy.key_trust.verify_x509_chains = true;
    let provider = RustCryptoProvider;
    let context = VerifyContext::new()
        .policy(policy.clone())
        .provider(&provider)
        .id_attributes(ids);
    // The assertion is trusted through its certificate chain, the XSLT
    // reference through the application's own public key.
    let context = if args.scenario == "assertion" {
        context.key_resolver(&resolver)
    } else {
        context.key(&key)
    };
    if args.operation == "reject" {
        // A processing error refuses the input as surely as an invalid status.
        return Ok(match context.verify(input) {
            Ok(result) if accepted(&result) => Outcome::Accepted,
            _ => Outcome::Rejected,
        });
    }
    let check = |result: VerifyResult| {
        if accepted(&result) {
            Ok(())
        } else {
            Err(format!("not accepted: {:?}", result.status))
        }
    };
    let measurement = match args.boundary {
        Boundary::Parse => measure(
            args.samples,
            || Ok::<_, String>(()),
            |()| {
                context
                    .verify(input)
                    .map_err(|error| error.to_string())
                    .and_then(check)
            },
            |()| None,
        )?,
        Boundary::Prepared => {
            let document = XmlDocument::parse_with_policy(input, &policy)
                .map_err(|error| error.to_string())?;
            measure(
                args.samples,
                || Ok::<_, String>(()),
                |()| {
                    context
                        .verify_document(&document)
                        .map_err(|error| error.to_string())
                        .and_then(check)
                },
                |()| None,
            )?
        }
    };
    Ok(Outcome::Measured(measurement))
}

fn encrypt(args: &Args, input: &str) -> Result<Outcome, String> {
    let recipient = RsaPublicKey::from_public_key_pem(&args.corpus_text("public.pem")?)
        .map_err(|error| error.to_string())?;
    let policy = EncryptionPolicy {
        data_algorithms: Some(HashSet::from([DataEncryptionAlgorithm::Aes256Gcm])),
        key_transport_algorithms: Some(HashSet::from([KeyTransportAlgorithm::RsaOaepMgf1p])),
        oaep_digests: Some(HashSet::from([OaepDigestAlgorithm::Sha1])),
        ..EncryptionPolicy::default()
    };
    let builder = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes256Gcm)
        .policy(policy.clone())
        .add_recipient(
            EncryptionRecipient::rsa_oaep(recipient)
                .oaep_parameters(oaep())
                .key_name("recipient"),
        );
    // A standalone element is the document root; in place it is `Payment`.
    let options = DocumentEncryptionOptions {
        element_id: (args.scenario == "element_in_place").then_some("payment"),
    };
    let measurement = match args.boundary {
        Boundary::Parse if args.scenario == "element" => measure(
            args.samples,
            || Ok::<_, String>(()),
            |()| {
                builder
                    .encrypt_xml(input)
                    .map(|result| result.encrypted_data_xml)
                    .map_err(|error| error.to_string())
            },
            |encrypted: &String| Some(encrypted.as_bytes().to_vec()),
        )?,
        Boundary::Parse => measure(
            args.samples,
            || Ok::<_, String>(()),
            |()| {
                builder
                    .encrypt_document(input, options)
                    .map_err(|error| error.to_string())
            },
            |encrypted: &String| Some(encrypted.as_bytes().to_vec()),
        )?,
        Boundary::Prepared => measure(
            args.samples,
            || XmlDocument::parse_with_policy(input, &policy).map_err(|error| error.to_string()),
            |mut document| {
                builder
                    .encrypt_owned_document(&mut document, options)
                    .map(|()| document)
                    .map_err(|error| error.to_string())
            },
            |document: &XmlDocument| Some(document.as_xml().as_bytes().to_vec()),
        )?,
    };
    Ok(Outcome::Measured(measurement))
}

fn decrypt(args: &Args, input: &str) -> Result<Outcome, String> {
    let key = RsaPrivateKey::from_pkcs8_pem(&args.corpus_text("private.pem")?)
        .map_err(|error| error.to_string())?;
    let resolver = PrivateKeyDecryptor::new(key);
    let policy = DecryptionPolicy {
        data_algorithms: Some(HashSet::from([DataEncryptionAlgorithm::Aes256Gcm])),
        key_transport_algorithms: Some(HashSet::from([KeyTransportAlgorithm::RsaOaepMgf1p])),
        oaep_digests: Some(HashSet::from([OaepDigestAlgorithm::Sha1])),
        ..DecryptionPolicy::default()
    };
    let provider = RustCryptoProvider;
    let context = DecryptContext::new(&resolver)
        .policy(policy.clone())
        .provider(&provider);
    let measurement = match args.boundary {
        Boundary::Parse => measure(
            args.samples,
            || Ok::<_, String>(()),
            |()| {
                context
                    .decrypt_document(input, None)
                    .map_err(|error| error.to_string())
            },
            |plain: &String| Some(plain.as_bytes().to_vec()),
        )?,
        Boundary::Prepared => measure(
            args.samples,
            || XmlDocument::parse_with_policy(input, &policy).map_err(|error| error.to_string()),
            |mut document| {
                context
                    .decrypt_owned_document(&mut document, None)
                    .map(|()| document)
                    .map_err(|error| error.to_string())
            },
            |document: &XmlDocument| Some(document.as_xml().as_bytes().to_vec()),
        )?,
    };
    Ok(Outcome::Measured(measurement))
}
