# Verifying a PTB Digital Calibration Certificate

A PTB Digital Calibration Certificate (DCC, namespace `https://ptb.de/dcc`)
carries its optional XML Signatures as the last children of
`dcc:digitalCalibrationCertificate`. The form the
[PTB DCC wiki](https://wiki.dcc.ptb.de/en/dsSignature) describes signs the
whole certificate: inclusive C14N, a `Reference URI=""` with the
`enveloped-signature` transform and an RSA signature method.

A valid signature alone does not tell an application that the parts it reads
are signed. A signature may cover one `measurementResult` and leave the rest of
the certificate unsigned. The application therefore names the elements it
relies on, usually the `administrativeData` and `measurementResults` rings, as
expected targets. Verification accepts the certificate only when an authorized
signature covers each of them. The DCC schema gives these rings no ID, so the
application locates them by name and takes their identities from the document
view.

```rust
use std::error::Error;

use xml_sec::policy::VerificationPolicy;
use xml_sec::xmldsig::{DefaultKeyResolver, KeyResolverConfig, VerificationRequest, VerifyContext};
use xml_sec::{NodeIdentity, XmlDocument};

const DCC: &str = "https://ptb.de/dcc";

/// The child of the certificate root named `local`, by identity.
fn ring(document: &XmlDocument, local: &str) -> Result<NodeIdentity, Box<dyn Error>> {
    document.with_view(|view| {
        let ring = view
            .document()
            .root_element()
            .children()
            .find(|node| {
                node.is_element()
                    && node.tag_name().namespace() == Some(DCC)
                    && node.tag_name().name() == local
            })
            .ok_or("the certificate has no such ring")?;
        Ok(view.identity_of(ring)?)
    })
}

fn certificate_der(path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(pem::parse(std::fs::read(path)?)?.into_contents())
}

fn dcc_is_signed(xml: String, root: &str, issuer: &str) -> Result<bool, Box<dyn Error>> {
    let mut policy = VerificationPolicy::default();
    // Trust comes from the laboratory's certificate path, not from KeyInfo alone.
    policy.key_trust.verify_x509_chains = true;
    let resolver = DefaultKeyResolver::new(KeyResolverConfig {
        trusted_certs: vec![certificate_der(root)?],
        lookup_certs: vec![certificate_der(issuer)?],
        ..KeyResolverConfig::default()
    });
    let document = XmlDocument::parse_with_policy(xml, &policy)?;
    let targets = [
        ring(&document, "administrativeData")?,
        ring(&document, "measurementResults")?,
    ];
    let request = VerificationRequest {
        expected_targets: &targets,
        ..VerificationRequest::default()
    };
    let evidence = VerifyContext::new()
        .policy(policy)
        .key_resolver(&resolver)
        .verify_request(&document, &request)?;
    Ok(evidence.accepted(&document)?)
}

# fn main() -> Result<(), Box<dyn Error>> {
let fixtures = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
let root = format!("{fixtures}/keys/cacert.pem");
let issuer = format!("{fixtures}/keys/ca2cert.pem");
let signed = std::fs::read_to_string(format!(
    "{fixtures}/xmldsig/dcc/signed-calibration-certificate.xml"
))?;
assert!(dcc_is_signed(signed.clone(), &root, &issuer)?);

// A measured value changed after signing is no longer covered.
let changed = signed.replace("<si:value>273.16</si:value>", "<si:value>273.17</si:value>");
assert_ne!(changed, signed);
assert!(!dcc_is_signed(changed, &root, &issuer)?);
# Ok(())
# }
```

`accepted` is the decision. A document without a Signature, a signature by a
key outside the trusted path, a digest mismatch or a reference that leaves an
expected ring uncovered all return `false`. A verification report is still
returned, so the application can tell these cases apart.

Revocation is checked when the application supplies the laboratory's CRLs in
`KeyResolverConfig::crls` and sets `policy.key_trust.check_crls`. The
application also supplies the UTC history that CRL time checks need, through
`VerifyContext::utc_facts`. The library reads no schema, DTD, CRL or other
resource itself.

The wiki's example uses RSA-SHA1 with a SHA-1 digest. The default policy
refuses RSA-SHA1. An application that must accept such certificates adds
`SignatureAlgorithm::RsaSha1` to `policy.key_trust.allowed_legacy_signature_algorithms`.
A document type declaration, such as one naming the W3C XML Signature DTD, is
refused unless `policy.xml.allow_internal_dtd` admits it. Even then the external
DTD is never read; DCC documents do not need it.

Schema (XSD) validation of the certificate is the application's choice and
stays outside this library.
