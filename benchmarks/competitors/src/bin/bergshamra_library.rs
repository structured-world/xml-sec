//! Bergshamra through its Rust API, configured as its CLI configures each workload.

use bergshamra_dsig::DsigContext;
use bergshamra_enc::EncContext;
use bergshamra_keys::KeysManager;
use bergshamra_keys::loader::{load_pem_auto, load_x509_cert_pem};
use std::process::ExitCode;
use xml_sec_competitor_bench::{Args, Boundary, Outcome, measure};

fn main() -> ExitCode {
    xml_sec_competitor_bench::main("bergshamra", execute)
}

fn execute(args: &Args) -> Result<Outcome, String> {
    match (
        args.scenario.as_str(),
        args.operation.as_str(),
        args.boundary,
    ) {
        ("assertion", "sign", _) => Ok(Outcome::Unsupported(
            "leaves the template X509Data empty; the signer certificate is never written",
        )),
        ("xslt", _, _) => Ok(Outcome::Unsupported(
            "implements a minimal XSLT subset that does not evaluate this stylesheet",
        )),
        ("element_in_place", "encrypt", _) => Ok(Outcome::Unsupported(
            "encrypts a template-supplied payload; it cannot replace an element inside its document",
        )),
        ("element" | "element_in_place", "encrypt" | "decrypt", Boundary::Prepared) => Ok(
            Outcome::Unsupported("encryption and decryption accept serialized XML only"),
        ),
        ("assertion", "verify" | "reject", _) => verify(args),
        ("element", "encrypt", Boundary::Parse) => encrypt(args),
        ("element" | "element_in_place", "decrypt", Boundary::Parse) => decrypt(args),
        _ => Ok(Outcome::Unsupported("no such workload operation")),
    }
}

fn certificate_der(args: &Args, name: &str) -> Result<Vec<u8>, String> {
    let block = pem::parse(args.corpus_text(name)?).map_err(|error| format!("{name}: {error}"))?;
    Ok(block.into_contents())
}

fn certificate_key(args: &Args, name: &str) -> Result<bergshamra_keys::Key, String> {
    load_x509_cert_pem(args.corpus_text(name)?.as_bytes())
        .map_err(|error| format!("{name}: {error}"))
}

/// `verify --trusted root --untrusted intermediate --enabled-key-data x509 --strict`.
fn verify(args: &Args) -> Result<Outcome, String> {
    let mut keys = KeysManager::new();
    keys.add_key(certificate_key(args, "intermediate.pem")?);
    keys.add_key(certificate_key(args, "root.pem")?);
    keys.add_trusted_cert(certificate_der(args, "root.pem")?);
    keys.add_untrusted_cert(certificate_der(args, "intermediate.pem")?);
    let mut context = DsigContext::new_permissive(keys);
    context.enabled_key_data_x509 = true;
    context.strict_verification = true;
    let input = args.input_text()?;
    if args.operation == "reject" {
        // A processing error refuses the input as surely as an invalid result.
        return Ok(match bergshamra_dsig::verify::verify(&context, &input) {
            Ok(result) if result.is_valid() => Outcome::Accepted,
            _ => Outcome::Rejected,
        });
    }
    let check = |result: bergshamra_dsig::VerifyResult| {
        if result.is_valid() {
            Ok(())
        } else {
            Err(format!("not accepted: {result:?}"))
        }
    };
    let measurement = match args.boundary {
        Boundary::Parse => measure(
            args.samples,
            || Ok::<_, String>(()),
            |()| {
                bergshamra_dsig::verify::verify(&context, &input)
                    .map_err(|error| error.to_string())
                    .and_then(check)
            },
            |()| None,
        )?,
        Boundary::Prepared => {
            let document = uppsala::parse(&input).map_err(|error| error.to_string())?;
            measure(
                args.samples,
                || Ok::<_, String>(()),
                |()| {
                    bergshamra_dsig::verify::verify_document(&context, &document)
                        .map_err(|error| error.to_string())
                        .and_then(check)
                },
                |()| None,
            )?
        }
    };
    Ok(Outcome::Measured(measurement))
}

/// `encrypt element.template.xml --data INPUT --cert leaf.pem`.
fn encrypt(args: &Args) -> Result<Outcome, String> {
    let mut keys = KeysManager::new();
    keys.add_key(certificate_key(args, "leaf.pem")?);
    let context = EncContext::new(keys);
    let template = args.corpus_text("element.template.xml")?;
    let data = args.input_text()?;
    let measurement = measure(
        args.samples,
        || Ok::<_, String>(()),
        |()| {
            bergshamra_enc::encrypt::encrypt(&context, &template, data.as_bytes())
                .map_err(|error| error.to_string())
        },
        |encrypted: &String| Some(encrypted.as_bytes().to_vec()),
    )?;
    Ok(Outcome::Measured(measurement))
}

/// `decrypt INPUT --key private.pem`.
fn decrypt(args: &Args) -> Result<Outcome, String> {
    let mut keys = KeysManager::new();
    let private = args.corpus_text("private.pem")?;
    keys.add_key(load_pem_auto(private.as_bytes(), None).map_err(|error| error.to_string())?);
    let context = EncContext::new(keys);
    let input = args.input_text()?;
    let measurement = measure(
        args.samples,
        || Ok::<_, String>(()),
        |()| {
            bergshamra_enc::decrypt::decrypt_to_bytes(&context, &input)
                .map_err(|error| error.to_string())
        },
        |plain: &Vec<u8>| Some(plain.clone()),
    )?;
    Ok(Outcome::Measured(measurement))
}
