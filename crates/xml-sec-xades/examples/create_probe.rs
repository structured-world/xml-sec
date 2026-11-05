//! B-B signatures of every packaging mode, created through the public API for
//! independent validation.
//!
//! `create_probe FIXTURES OUTPUT` signs with `FIXTURES/signer.key` and the
//! `signer.der`/`intermediate.der` chain, assesses each result against
//! `FIXTURES/root.der` at Unix time 1800000000, and writes one document per
//! case to `OUTPUT`, with the detached data as `OUTPUT/detached.txt`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use structured_asn1::memory::{Memory, MemoryAccount};
use xml_sec::XmlDocument;
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::policy::{Instant, SigningPolicy, VerificationPolicy};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, KeyResolverConfig, ObjectContent, ObjectElement,
    RsaSigningKey, SignatureAlgorithm, UriTypeSet, VerificationRequest, VerifyContext,
};
use xml_sec_xades::{
    Assessment, Countersignature, DataObject, Envelope, Request, Signer, countersign, create,
};

const DOCUMENT: &str = "<Document><Data Id=\"payload\">Created payload</Data></Document>";
const DETACHED: &[u8] = b"Detached payload\n";
const TIME: &str = "2026-10-18T12:00:00Z";

fn read(directory: &Path, name: &str) -> Result<Vec<u8>, String> {
    std::fs::read(directory.join(name)).map_err(|error| format!("read {name}: {error}"))
}

fn main() -> Result<(), String> {
    let mut args = std::env::args_os().skip(1).map(PathBuf::from);
    let (Some(fixtures), Some(output), None) = (args.next(), args.next(), args.next()) else {
        return Err("usage: create_probe FIXTURES OUTPUT".into());
    };
    let root = read(&fixtures, "root.der")?;
    let signer_der = read(&fixtures, "signer.der")?;
    let intermediate = read(&fixtures, "intermediate.der")?;
    let key_pem = String::from_utf8(read(&fixtures, "signer.key")?)
        .map_err(|error| format!("signer.key: {error}"))?;
    let key = RsaSigningKey::from_pkcs8_pem(&key_pem).map_err(|error| error.to_string())?;
    let mut signing = SigningPolicy::default();
    signing.uris.references = UriTypeSet::ALL;
    let chain: [&[u8]; 2] = [&signer_der, &intermediate];
    let signer = Signer {
        key: &key,
        provider: xml_sec::provider::default_provider(),
        policy: &signing,
        chain: &chain,
        method: SignatureAlgorithm::RsaSha256,
        digest: DigestAlgorithm::Sha256,
        canonicalization: C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
    };
    let mut verification = VerificationPolicy::default();
    verification.key_trust.verify_x509_chains = true;
    verification.key_trust.verification_time = Instant::new(1_800_000_000, 0);
    verification.uris.references = UriTypeSet::ALL;
    let resolver = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: vec![root.clone()],
        ..KeyResolverConfig::default()
    });
    let context = VerifyContext::new()
        .policy(verification)
        .key_resolver(&resolver);
    let resources = BTreeMap::from([("detached.txt".to_owned(), DETACHED.to_vec())]);
    let request = VerificationRequest {
        external_resources: Some(&resources),
        ..VerificationRequest::default()
    };
    let assessment = Assessment {
        context: &context,
        request: &request,
        certificates: &[&root],
    };
    let element = ObjectElement::parse("<Data>Enveloped object</Data>", &signing)
        .map_err(|error| error.to_string())?;
    std::fs::create_dir_all(&output).map_err(|error| error.to_string())?;
    std::fs::write(output.join("detached.txt"), DETACHED).map_err(|error| error.to_string())?;
    for (name, signatures) in cases(element) {
        let document = sign(&signer, &assessment, &resources, name, signatures)?;
        std::fs::write(output.join(format!("{name}.xml")), document.as_xml())
            .map_err(|error| error.to_string())?;
        println!("{name}");
    }
    Ok(())
}

/// The signatures of one case: each new signature's ID and data objects.
type Signatures = Vec<(&'static str, Vec<DataObject<'static>>)>;

fn document_object(envelope: Envelope) -> DataObject<'static> {
    DataObject::Document {
        mime_type: "text/xml",
        envelope,
    }
}

fn cases(element: ObjectElement) -> Vec<(&'static str, Signatures)> {
    let one = |objects| vec![("sig", objects)];
    vec![
        ("enveloped", one(vec![document_object(Envelope::Enveloped)])),
        (
            "enveloping",
            one(vec![
                DataObject::Enveloping {
                    content: ObjectContent::Text("Enveloping text".to_owned()),
                    mime_type: "text/plain",
                },
                DataObject::Enveloping {
                    content: ObjectContent::Element(element),
                    mime_type: "text/xml",
                },
            ]),
        ),
        (
            "internally-detached",
            one(vec![DataObject::Element {
                id: "payload",
                mime_type: "text/xml",
            }]),
        ),
        (
            "detached",
            one(vec![DataObject::Detached {
                uri: "detached.txt",
                mime_type: "text/plain",
            }]),
        ),
        (
            "parallel",
            vec![
                (
                    "first",
                    vec![document_object(Envelope::ExcludingSignatures)],
                ),
                (
                    "second",
                    vec![document_object(Envelope::ExcludingSignatures)],
                ),
            ],
        ),
        (
            "countersigned",
            one(vec![document_object(Envelope::ExcludingSignatures)]),
        ),
    ]
}

/// Create every signature of one case, then countersign `sig` in the
/// countersigned case.
fn sign(
    signer: &Signer<'_>,
    assessment: &Assessment<'_, '_>,
    resources: &BTreeMap<String, Vec<u8>>,
    name: &str,
    signatures: Signatures,
) -> Result<XmlDocument, String> {
    let work = Memory::new(Arc::new(MemoryAccount::new(1 << 26, 1 << 30)));
    let mut document = XmlDocument::parse(DOCUMENT).map_err(|error| error.to_string())?;
    for (id, objects) in signatures {
        let request = Request {
            id,
            signing_time: TIME,
            objects,
            parent: None,
            resources: Some(resources),
            id_attributes: &[],
        };
        create(&mut document, signer, request, assessment, &work)
            .map_err(|error| format!("{name} {id}: {error}"))?;
    }
    if name == "countersigned" {
        let countersignature = Countersignature {
            parent: "sig",
            id: "counter",
            signing_time: TIME,
            id_attributes: &[],
        };
        countersign(&mut document, signer, &countersignature, assessment, &work)
            .map_err(|error| format!("{name}: {error}"))?;
    }
    Ok(document)
}
