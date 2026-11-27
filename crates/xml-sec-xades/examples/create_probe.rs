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
use xml_sec::policy::{Instant, ManifestProcessing, SigningPolicy, VerificationPolicy};
use xml_sec::xmldsig::{
    DefaultKeyResolver, DigestAlgorithm, KeyResolverConfig, ObjectContent, ObjectElement,
    RsaSigningKey, SignatureAlgorithm, Transform, UriTypeSet, VerificationRequest, VerifyContext,
    XPathExpression, XPathFilter, XPathFilterOperation, XsltStylesheet,
};
use xml_sec_xades::properties::Properties;
use xml_sec_xades::{
    Assessment, Countersignature, DataObject, Envelope, ManifestEntry, Placement, Prefixes,
    Request, Signer, SuppliedEntry, countersign, create,
};

/// The payload carries a comment, which only the `reference-comments` case signs.
const DOCUMENT: &str =
    "<Document><Data Id=\"payload\">Created <!--signed note--> payload</Data></Document>";
const DETACHED: &[u8] = b"Detached payload\n";
const SECOND_DETACHED: &[u8] = b"Second detached payload\n";
/// Detached XML a reference canonicalizes, as DSS's detached transform tests do.
const DETACHED_XML: &[u8] =
    b"<Detached xmlns=\"urn:detached\"><Item Id=\"item\">Payload</Item><Other/></Detached>";
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
    // A signed Manifest's digests are computed and checked by both operations.
    signing.manifest_processing = ManifestProcessing::Process;
    let chain: [&[u8]; 2] = [&signer_der, &intermediate];
    let signer = Signer {
        key: &key,
        provider: xml_sec::provider::default_provider(),
        policy: &signing,
        chain: &chain,
        method: SignatureAlgorithm::RsaSha256,
        digest: DigestAlgorithm::Sha256,
        canonicalization: C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
        prefixes: xml_sec_xades::Prefixes::default(),
    };
    let mut verification = VerificationPolicy::default();
    verification.key_trust.verify_x509_chains = true;
    verification.key_trust.verification_time = Instant::new(1_800_000_000, 0);
    verification.uris.references = UriTypeSet::ALL;
    verification.manifest_processing = ManifestProcessing::Process;
    let resolver = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: vec![root.clone()],
        ..KeyResolverConfig::default()
    });
    let context = VerifyContext::new()
        .policy(verification)
        .key_resolver(&resolver);
    let resources = BTreeMap::from([
        ("detached.txt".to_owned(), DETACHED.to_vec()),
        ("detached-2.txt".to_owned(), SECOND_DETACHED.to_vec()),
        // Not detached.xml: that is the signed document of the detached case.
        ("detached-data.xml".to_owned(), DETACHED_XML.to_vec()),
    ]);
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
    // The same signer with inclusive canonicalization of SignedInfo.
    let inclusive = Signer {
        canonicalization: C14nAlgorithm::new(C14nMode::Inclusive1_0, false),
        ..signer
    };
    // The same signer writing other prefixes, and the default namespaces.
    let prefixed = Signer {
        prefixes: Prefixes {
            ds: "dsig",
            xades: "xa",
        },
        canonicalization: C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
        ..signer
    };
    let unprefixed = Signer {
        prefixes: Prefixes { ds: "", xades: "" },
        canonicalization: C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
        ..signer
    };
    std::fs::create_dir_all(&output).map_err(|error| error.to_string())?;
    for (name, content) in &resources {
        std::fs::write(output.join(name), content).map_err(|error| error.to_string())?;
    }
    for (name, signatures) in cases(element) {
        let signer = match name {
            "inclusive" => &inclusive,
            "prefixes" => &prefixed,
            "empty-prefix" => &unprefixed,
            _ => &signer,
        };
        let document = sign(signer, &assessment, &resources, name, signatures)?;
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
        (
            "countersigned-nested",
            one(vec![document_object(Envelope::ExcludingSignatures)]),
        ),
        (
            "detached-multiple",
            one(vec![
                DataObject::Detached {
                    uri: "detached.txt",
                    mime_type: "text/plain",
                },
                DataObject::Detached {
                    uri: "detached-2.txt",
                    mime_type: "text/plain",
                },
            ]),
        ),
        ("inclusive", one(vec![document_object(Envelope::Enveloped)])),
    ]
    .into_iter()
    .chain(composed_references())
    .chain(shaped())
    .chain(custom_manifests())
    .collect()
}

/// One signature per serialization or structure choice: prefixes,
/// placement, a signed Manifest, a signed `KeyInfo`.
fn shaped() -> Vec<(&'static str, Signatures)> {
    let one = |objects| vec![("sig", objects)];
    vec![
        (
            "prefixes",
            one(vec![document_object(Envelope::ExcludingSignatures)]),
        ),
        (
            "empty-prefix",
            one(vec![document_object(Envelope::ExcludingSignatures)]),
        ),
        (
            "placement-first-child",
            one(vec![document_object(Envelope::ExcludingSignatures)]),
        ),
        (
            "placement-before",
            one(vec![document_object(Envelope::ExcludingSignatures)]),
        ),
        (
            "placement-after",
            one(vec![document_object(Envelope::ExcludingSignatures)]),
        ),
        (
            "placement-last-child",
            one(vec![document_object(Envelope::ExcludingSignatures)]),
        ),
        (
            "reference-detached-xml",
            one(vec![DataObject::Reference {
                uri: "detached-data.xml",
                transforms: vec![exclusive()],
                mime_type: "text/xml",
            }]),
        ),
        (
            "manifest",
            one(vec![manifest(
                "manifest",
                vec![file("detached.txt"), file("detached-2.txt")],
                Vec::new(),
            )]),
        ),
        // Two Manifests in one signature, each listing one file.
        (
            "manifest-multiple",
            one(vec![
                manifest("manifest-1", vec![file("detached.txt")], Vec::new()),
                manifest("manifest-2", vec![file("detached-2.txt")], Vec::new()),
            ]),
        ),
        (
            "signed-key-info",
            one(vec![
                document_object(Envelope::ExcludingSignatures),
                DataObject::KeyInfo {
                    mime_type: "text/xml",
                },
            ]),
        ),
    ]
}

/// One signature per Manifest the caller shapes: entries with transforms,
/// and a Manifest built outside the signature.
fn custom_manifests() -> Vec<(&'static str, Signatures)> {
    let one = |objects| vec![("sig", objects)];
    vec![
        // Entries with transforms of their own, as DSS's custom Manifest
        // references: the document without the signature, an XPath and a
        // Filter 2.0 selection of detached XML; the reference to the
        // Manifest canonicalizes it exclusively.
        (
            "manifest-transforms",
            one(vec![manifest(
                "manifest",
                vec![
                    ManifestEntry {
                        uri: "",
                        transforms: vec![Transform::Enveloped, exclusive()],
                        mime_type: "text/xml",
                    },
                    ManifestEntry {
                        uri: "detached-data.xml",
                        // Attribute predicates, as DSS's own, read no value
                        // the signing operation fills.
                        transforms: vec![Transform::XPath(XPathExpression::new(
                            "ancestor-or-self::*[@Id='item']",
                        ))],
                        mime_type: "text/xml",
                    },
                    ManifestEntry {
                        uri: "detached-data.xml",
                        transforms: vec![
                            Transform::XPathFilter2(vec![XPathFilter::new(
                                XPathFilterOperation::Intersect,
                                XPathExpression::new("//*[@Id='item']"),
                            )]),
                            exclusive(),
                        ],
                        mime_type: "text/xml",
                    },
                ],
                vec![exclusive()],
            )]),
        ),
        // A Manifest built outside the signature, as DSS's external Manifest
        // signs one, with the reference to it canonicalized by C14N 1.1.
        (
            "manifest-supplied",
            one(vec![DataObject::SuppliedManifest {
                manifest: ObjectElement::parse(SUPPLIED_MANIFEST, &SigningPolicy::default())
                    .expect("the supplied Manifest is one element"),
                entries: vec![
                    SuppliedEntry {
                        id: "supplied-file",
                        mime_type: "text/plain",
                    },
                    SuppliedEntry {
                        id: "supplied-xml",
                        mime_type: "text/xml",
                    },
                ],
                transforms: vec![Transform::C14n(C14nAlgorithm::new(
                    C14nMode::Inclusive1_1,
                    false,
                ))],
                mime_type: "text/xml",
            }]),
        ),
    ]
}

/// One signature per reference the caller composes.
fn composed_references() -> Vec<(&'static str, Signatures)> {
    let one = |objects| vec![("sig", objects)];
    vec![
        (
            "reference-filter2",
            one(vec![composed(
                "",
                vec![
                    Transform::XPathFilter2(vec![XPathFilter::new(
                        XPathFilterOperation::Subtract,
                        XPathExpression::new("/descendant::ds:Signature").with_namespace("ds", DS),
                    )]),
                    exclusive(),
                ],
            )]),
        ),
        (
            "reference-xpath",
            one(vec![composed(
                "",
                vec![
                    Transform::XPath(
                        XPathExpression::new("not(ancestor-or-self::ds:Signature)")
                            .with_namespace("ds", DS),
                    ),
                    exclusive(),
                ],
            )]),
        ),
        (
            "reference-by-id",
            one(vec![composed("#payload", Vec::new())]),
        ),
        (
            "reference-comments",
            one(vec![composed(
                "#xpointer(id('payload'))",
                vec![Transform::C14n(C14nAlgorithm::new(
                    C14nMode::Exclusive1_0,
                    true,
                ))],
            )]),
        ),
        (
            "object-base64",
            one(vec![DataObject::Object {
                id: "image",
                content: ObjectContent::Text("SGVsbG8gYmFzZTY0".to_owned()),
                encoding: Some("http://www.w3.org/2000/09/xmldsig#base64"),
                transforms: vec![Transform::Base64Decode],
                mime_type: "image/png",
            }]),
        ),
        (
            "reference-xslt",
            one(vec![composed(
                "#payload",
                vec![Transform::Xslt(
                    XsltStylesheet::new(STYLESHEET).expect("the stylesheet is one xsl:stylesheet"),
                )],
            )]),
        ),
    ]
}

const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
/// Signs the text of the payload, as DSS's XSLT test does with its own sheet.
const STYLESHEET: &str = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="."/></xsl:template></xsl:stylesheet>"#;

/// A Manifest of two detached files, built outside the signature; signing
/// processing Manifests fills its digests.
const SUPPLIED_MANIFEST: &str = concat!(
    "<ds:Manifest xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"supplied\">",
    "<ds:Reference Id=\"supplied-file\" URI=\"detached.txt\">",
    "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
    "<ds:DigestValue/></ds:Reference>",
    "<ds:Reference Id=\"supplied-xml\" URI=\"detached-data.xml\">",
    "<ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
    "</ds:Transforms>",
    "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha512\"/>",
    "<ds:DigestValue/></ds:Reference></ds:Manifest>"
);

/// A Manifest entry naming a detached text file, digested as it is.
fn file(uri: &'static str) -> ManifestEntry<'static> {
    ManifestEntry {
        uri,
        transforms: Vec::new(),
        mime_type: "text/plain",
    }
}

fn manifest(
    id: &'static str,
    entries: Vec<ManifestEntry<'static>>,
    transforms: Vec<Transform>,
) -> DataObject<'static> {
    DataObject::Manifest {
        id,
        entries,
        transforms,
        mime_type: "text/xml",
    }
}

fn exclusive() -> Transform {
    Transform::C14n(C14nAlgorithm::new(C14nMode::Exclusive1_0, false))
}

/// A reference the caller composes over the document holding the signature.
fn composed(uri: &'static str, transforms: Vec<Transform>) -> DataObject<'static> {
    DataObject::Reference {
        uri,
        transforms,
        mime_type: "text/xml",
    }
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
            placement: match name {
                "placement-first-child" => Placement::FirstChildOf("payload"),
                "placement-before" => Placement::Before("payload"),
                "placement-after" => Placement::After("payload"),
                "placement-last-child" => Placement::LastChildOf("payload"),
                _ => Placement::DocumentEnd,
            },
            resources: Some(resources),
            id_attributes: &[],
            properties: Properties::default(),
        };
        create(&mut document, signer, request, assessment, &work)
            .map_err(|error| format!("{name} {id}: {error}"))?;
    }
    // A countersignature of `sig`, and in the nested case one of it in turn.
    let chain: &[(&str, &str)] = match name {
        "countersigned" => &[("sig", "counter")],
        "countersigned-nested" => &[("sig", "counter"), ("counter", "counter-nested")],
        _ => &[],
    };
    for (parent, id) in chain {
        let countersignature = Countersignature {
            parent,
            id,
            signing_time: TIME,
            id_attributes: &[],
            properties: Properties::default(),
        };
        countersign(&mut document, signer, &countersignature, assessment, &work)
            .map_err(|error| format!("{name} {id}: {error}"))?;
    }
    Ok(document)
}
