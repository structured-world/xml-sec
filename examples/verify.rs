//! Verify an XMLDSig document whose `<KeyInfo>` embeds an X.509 certificate.
//!
//! Run with `cargo run --example verify --all-features -- signed.xml`. The
//! default resolver accepts the document's embedded certificate without chain
//! validation; production callers should configure explicit trust anchors with
//! `KeyResolverConfig` when the certificate is not already pinned by policy.

use xml_sec::xmldsig::{DefaultKeyResolver, DsigStatus, VerifyContext};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: cargo run --example verify --all-features -- <signed.xml>");
        std::process::exit(2);
    };
    let xml = std::fs::read_to_string(path)?;
    let resolver = DefaultKeyResolver::default();
    let result = VerifyContext::new().key_resolver(&resolver).verify(&xml)?;

    match result.status {
        DsigStatus::Valid => println!("signature is valid"),
        DsigStatus::Invalid(reason) => {
            eprintln!("signature is invalid: {reason:?}");
            std::process::exit(1);
        }
        _ => {
            eprintln!("signature returned an unknown validation status");
            std::process::exit(1);
        }
    }
    Ok(())
}
