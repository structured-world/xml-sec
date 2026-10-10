//! Shared deterministic workloads and correctness checks for every measurement mode.

use std::{collections::HashMap, sync::Arc};
use xml_sec::{
    XmlBackend, XmlDocument,
    c14n::{C14nAlgorithm, C14nMode, canonicalize_document},
    policy::{ManifestProcessing, SigningPolicy, VerificationPolicy},
    provider::{CryptoProvider, RustCryptoProvider},
    xmldsig::{
        DigestAlgorithm, ReferenceBuilder, RsaSigningKey, SignContext, SignatureAlgorithm,
        SignatureBuilder, SigningKey, UriTypeSet, VerificationKey, VerifyContext,
    },
    xmlenc::{
        DataEncryptionAlgorithm, DecryptContext, DecryptedContent, EncryptedDataBuilder,
        SymmetricKeyDecryptor,
    },
};

pub const SHAPES: [&str; 8] = [
    "saml",
    "namespaces",
    "text",
    "attributes",
    "multi_signature",
    "nested_manifest",
    "external",
    "adversarial",
];
pub const OPERATIONS: [&str; 8] = [
    "parse",
    "c14n",
    "sign",
    "verify",
    "verify_retained",
    "verify_reject",
    "encrypt",
    "decrypt",
];

#[derive(Clone, Copy, Debug)]
pub enum Engine {
    RustCrypto,
    #[cfg(feature = "aws-lc-fips")]
    AwsLcFips,
}

#[derive(Clone, Copy)]
pub struct Spec {
    pub shape: usize,
    pub units: usize,
    pub backend: XmlBackend,
    pub engine: Engine,
}

impl std::fmt::Debug for Spec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct(SHAPES[self.shape])
            .field("units", &self.units)
            .field("backend", &self.backend)
            .field("engine", &self.engine)
            .finish()
    }
}

pub fn specs() -> impl Iterator<Item = Spec> {
    let engines = [
        Engine::RustCrypto,
        #[cfg(feature = "aws-lc-fips")]
        Engine::AwsLcFips,
    ];
    XmlBackend::available().flat_map(move |backend| {
        engines.into_iter().flat_map(move |engine| {
            (0..SHAPES.len()).flat_map(move |shape| {
                [16, 256].map(move |units| Spec {
                    shape,
                    units,
                    backend,
                    engine,
                })
            })
        })
    })
}

fn body(shape: usize, units: usize) -> String {
    let mut xml = String::from("<Envelope><Payload Id=\"payload\">");
    match SHAPES[shape] {
        "saml" => {
            xml.push_str("<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\"><saml:Subject><saml:NameID>benchmark@example.invalid</saml:NameID></saml:Subject><saml:AttributeStatement>");
            for i in 0..units {
                xml.push_str(&format!("<saml:Attribute Name=\"attribute-{i}\"><saml:AttributeValue>value</saml:AttributeValue></saml:Attribute>"));
            }
            xml.push_str("</saml:AttributeStatement></saml:Assertion>");
        }
        "namespaces" => {
            for i in 0..units {
                xml.push_str(&format!("<n:v xmlns:n=\"urn:bench:{i}\" xmlns:a=\"urn:attribute:{i}\" a:x=\"v\"><n:child/></n:v>"));
            }
        }
        "attributes" => {
            for i in 0..units {
                xml.push_str(&format!("<v a=\"{i}\" b=\"value\" c=\"&amp;&quot;&#xA;\" d=\"4\" e=\"5\" f=\"6\" g=\"7\" h=\"8\"/>"));
            }
        }
        "adversarial" => {
            xml.push_str(&"<n>".repeat(120));
            xml.push_str(&"&lt;&amp;&#xD;".repeat(units));
            xml.push_str(&"</n>".repeat(120));
        }
        _ => xml.push_str(&"<v>deterministic text &amp; escaping</v>".repeat(units)),
    }
    xml.push_str("</Payload></Envelope>");
    xml
}

pub struct Fixture {
    pub spec: Spec,
    pub unsigned: String,
    pub template: String,
    pub signed: String,
    pub document: XmlDocument,
    rejected_document: XmlDocument,
    pub canonical: Vec<u8>,
    pub encrypted: String,
    pub provider: Arc<dyn CryptoProvider>,
    key: Box<dyn SigningKey>,
    verification_key: VerificationKey,
    sign_policy: SigningPolicy,
    verify_policy: VerificationPolicy,
    resources: HashMap<String, Vec<u8>>,
    decryptor: SymmetricKeyDecryptor,
}

impl Fixture {
    pub fn input_bytes(&self, operation: &str) -> usize {
        let xml_bytes = match operation {
            "verify" | "verify_retained" | "verify_reject" | "c14n" => self.signed.len(),
            "sign" => self.template.len(),
            "decrypt" => self.encrypted.len(),
            _ => self.unsigned.len(),
        };
        let external_bytes =
            if ["sign", "verify", "verify_retained", "verify_reject"].contains(&operation) {
                self.resources.values().map(Vec::len).sum()
            } else {
                0
            };
        xml_bytes + external_bytes
    }

    pub fn new(spec: Spec) -> Self {
        let (provider, key): (Arc<dyn CryptoProvider>, Box<dyn SigningKey>) = match spec.engine {
            Engine::RustCrypto => (
                Arc::new(RustCryptoProvider),
                Box::new(
                    RsaSigningKey::from_pkcs8_pem(include_str!(
                        "../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
                    ))
                    .expect("test key"),
                ),
            ),
            #[cfg(feature = "aws-lc-fips")]
            Engine::AwsLcFips => {
                let der = pem::parse(include_str!(
                    "../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
                ))
                .expect("test PEM")
                .into_contents();
                (
                    Arc::new(xml_sec::provider::AwsLcFipsProvider),
                    Box::new(
                        xml_sec::provider::AwsLcSigningKey::from_pkcs8_der(
                            SignatureAlgorithm::RsaSha256,
                            &der,
                        )
                        .expect("native test key"),
                    ),
                )
            }
        };
        let verification_key = VerificationKey {
            algorithm: SignatureAlgorithm::RsaSha256,
            public_key_bytes: key
                .public_key_info()
                .expect("public metadata")
                .spki_der()
                .expect("SPKI")
                .to_vec(),
            certificate_der: None,
            name: None,
        };
        let unsigned = body(spec.shape, spec.units);
        let mut sign_policy = SigningPolicy::default();
        let mut verify_policy = VerificationPolicy::default();
        let mut resources = HashMap::new();
        let uri = match SHAPES[spec.shape] {
            "nested_manifest" => {
                sign_policy.manifest_processing = ManifestProcessing::Process;
                verify_policy.manifest_processing = ManifestProcessing::Process;
                "#outer"
            }
            "external" => {
                sign_policy.uris.references = UriTypeSet::ALL;
                verify_policy.uris.references = UriTypeSet::ALL;
                resources.insert("urn:bench:external".into(), vec![b'x'; spec.units * 128]);
                "urn:bench:external"
            }
            _ => "#payload",
        };
        let algorithm = C14nAlgorithm::new(C14nMode::Exclusive1_0, false);
        let signature = SignatureBuilder::new(algorithm, SignatureAlgorithm::RsaSha256)
            .ns_prefix("ds")
            .signature_id("signature-0")
            .add_reference(ReferenceBuilder::new(DigestAlgorithm::Sha256).uri(uri))
            .build_template_with_policy(&sign_policy)
            .expect("template");
        let signature = if SHAPES[spec.shape] == "nested_manifest" {
            let reference = |uri| {
                format!(
                    "<ds:Reference URI=\"{uri}\"><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue/></ds:Reference>"
                )
            };
            signature.replace("</ds:Signature>", &format!("<ds:Object><ds:Manifest Id=\"outer\">{}</ds:Manifest><ds:Manifest Id=\"inner\">{}</ds:Manifest></ds:Object></ds:Signature>", reference("#inner"), reference("#payload")))
        } else {
            signature
        };
        let mut template = unsigned.replace("</Envelope>", &format!("{signature}</Envelope>"));
        let count = if SHAPES[spec.shape] == "multi_signature" {
            4
        } else {
            1
        };
        for index in 1..count {
            template = template.replace(
                "</Envelope>",
                &format!(
                    "{}</Envelope>",
                    signature.replace("signature-0", &format!("signature-{index}"))
                ),
            );
        }
        let mut signed = template.clone();
        for index in 0..count {
            signed = SignContext::new(key.as_ref())
                .policy(sign_policy.clone())
                .provider(provider.as_ref())
                .xml_backend(spec.backend)
                .external_resources(&resources)
                .start_node_id(&format!("signature-{index}"))
                .sign_template(&signed)
                .expect("signing workload");
        }
        let document =
            XmlDocument::parse_with_backend(signed.clone(), spec.backend).expect("signed document");
        let mut corrupted = signed.clone();
        let offset = corrupted
            .find("<ds:SignatureValue>")
            .expect("signature value")
            + "<ds:SignatureValue>".len();
        let replacement = if corrupted.as_bytes()[offset] == b'A' {
            "B"
        } else {
            "A"
        };
        corrupted.replace_range(offset..offset + 1, replacement);
        let rejected_document = XmlDocument::parse_with_backend(corrupted, spec.backend)
            .expect("corrupted signature remains XML");
        let canonical = canonicalize_document(
            &document,
            &C14nAlgorithm::new(C14nMode::Inclusive1_0, false),
        )
        .expect("canonical workload");
        let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes256Gcm)
            .provider(provider.clone())
            .xml_backend(spec.backend)
            .direct_key(vec![0x42; 32])
            .encrypt_xml(&unsigned)
            .expect("encryption workload")
            .encrypted_data_xml;
        let fixture = Self {
            spec,
            unsigned,
            template,
            signed,
            document,
            rejected_document,
            canonical,
            encrypted,
            provider,
            key,
            verification_key,
            sign_policy,
            verify_policy,
            resources,
            decryptor: SymmetricKeyDecryptor::new(vec![0x42; 32]),
        };
        // Never report timings for a corpus that only compiles or returns invalid evidence.
        fixture.run("verify_retained");
        fixture.run("verify_reject");
        fixture.run("decrypt");
        fixture
    }

    fn signer(&self) -> SignContext<'_> {
        SignContext::new(self.key.as_ref())
            .provider(self.provider.as_ref())
            .xml_backend(self.spec.backend)
            .policy(self.sign_policy.clone())
            .external_resources(&self.resources)
    }

    fn verifier(&self) -> VerifyContext<'_> {
        VerifyContext::new()
            .key(&self.verification_key)
            .provider(self.provider.as_ref())
            .xml_backend(self.spec.backend)
            .policy(self.verify_policy.clone())
            .external_resources(&self.resources)
    }

    pub fn run(&self, operation: &str) -> usize {
        match operation {
            "parse" => {
                let document = XmlDocument::parse_with_backend(&*self.unsigned, self.spec.backend)
                    .expect("parse");
                std::hint::black_box(document);
                self.unsigned.len()
            }
            "c14n" => {
                let bytes = canonicalize_document(
                    &self.document,
                    &C14nAlgorithm::new(C14nMode::Inclusive1_0, false),
                )
                .expect("C14N");
                assert_eq!(bytes, self.canonical);
                bytes.len()
            }
            "sign" => {
                let mut signed = self.template.clone();
                let count = if SHAPES[self.spec.shape] == "multi_signature" {
                    4
                } else {
                    1
                };
                for index in 0..count {
                    signed = self
                        .signer()
                        .start_node_id(&format!("signature-{index}"))
                        .sign_template(&signed)
                        .expect("sign");
                }
                assert_eq!(signed, self.signed);
                signed.len()
            }
            "verify" => {
                let document = XmlDocument::parse_with_backend(&*self.signed, self.spec.backend)
                    .expect("parse signed");
                assert!(
                    self.verifier()
                        .verify_all(&document)
                        .expect("verify")
                        .all_valid()
                );
                self.signed.len()
            }
            "verify_retained" => {
                assert!(
                    self.verifier()
                        .verify_all(&self.document)
                        .expect("verify retained")
                        .all_valid()
                );
                self.signed.len()
            }
            "verify_reject" => {
                assert!(
                    !self
                        .verifier()
                        .verify_all(&self.rejected_document)
                        .expect("invalid signature evidence")
                        .all_valid()
                );
                self.signed.len()
            }
            "encrypt" => EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes256Gcm)
                .provider(self.provider.clone())
                .xml_backend(self.spec.backend)
                .direct_key(vec![0x42; 32])
                .encrypt_xml(&self.unsigned)
                .expect("encrypt")
                .encrypted_data_xml
                .len(),
            "decrypt" => {
                let content = DecryptContext::new(&self.decryptor)
                    .provider(self.provider.as_ref())
                    .xml_backend(self.spec.backend)
                    .decrypt(&self.encrypted)
                    .expect("decrypt");
                match content {
                    DecryptedContent::Xml(xml) => {
                        assert_eq!(xml, self.unsigned);
                        xml.len()
                    }
                    _ => panic!("expected XML"),
                }
            }
            _ => panic!("unknown operation"),
        }
    }
}
