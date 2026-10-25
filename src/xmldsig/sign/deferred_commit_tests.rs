use super::*;
use crate::policy::PolicyViolation;
use std::sync::Mutex;

/// Records the canonical `SignedInfo` it is asked to sign.
#[derive(Default)]
struct RecordingSigningKey {
    canonical_signed_info: Mutex<Vec<u8>>,
}

impl RecordingSigningKey {
    fn recorded(&self) -> Vec<u8> {
        self.canonical_signed_info
            .lock()
            .expect("recording lock is never poisoned")
            .clone()
    }
}

impl SigningKey for RecordingSigningKey {
    fn sign(
        &self,
        _algorithm: SignatureAlgorithm,
        canonical_signed_info: &[u8],
    ) -> Result<Vec<u8>, SigningKeyError> {
        canonical_signed_info.clone_into(
            &mut self
                .canonical_signed_info
                .lock()
                .expect("recording lock is never poisoned"),
        );
        Ok(vec![0x5a; 256])
    }

    fn public_key_info(&self) -> Result<SigningPublicKeyInfo, SigningKeyError> {
        Ok(SigningPublicKeyInfo::Rsa {
            spki_der: Vec::new(),
            modulus: vec![0x80; 256],
            exponent: vec![1, 0, 1],
        })
    }
}

const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const EXCLUSIVE: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const INCLUSIVE: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

fn reference(uri: &str, transforms: &str, digest_value: &str) -> String {
    let transforms = if transforms.is_empty() {
        String::new()
    } else {
        format!("<ds:Transforms>{transforms}</ds:Transforms>")
    };
    format!(
        r#"<ds:Reference URI="{uri}">{transforms}<ds:DigestMethod Algorithm="{SHA256}"/>{digest_value}</ds:Reference>"#
    )
}

fn template(c14n: &str, references: &str, signature_value: &str, object: &str) -> String {
    format!(
        r#"<root xmlns:a="urn:a"><payload Id="payload" a:note="x &lt; y">text &amp; more</payload><other Id="other"><a:leaf/></other><ds:Signature xmlns:ds="{DS}"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{c14n}"/><ds:SignatureMethod Algorithm="{RSA_SHA256}"/>{references}</ds:SignedInfo>{signature_value}{object}</ds:Signature></root>"#
    )
}

fn enveloped() -> String {
    format!(
        r#"<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="{EXCLUSIVE}"/>"#
    )
}

/// Templates covering every digest path: deferred digests with tree-based
/// dependency analysis, deferred digests after placeholder analysis (`XPath`),
/// committed levels (nested `Manifest`s) and pre-filled `DigestValue`s.
fn cases() -> Vec<(&'static str, String, crate::policy::SigningPolicy)> {
    let default_policy = crate::policy::SigningPolicy::default();
    let manifest_policy = crate::policy::SigningPolicy {
        manifest_processing: crate::policy::ManifestProcessing::Process,
        ..crate::policy::SigningPolicy::default()
    };
    let subtree_references = [
        reference("", &enveloped(), "<ds:DigestValue/>"),
        reference("#payload", "", "<ds:DigestValue></ds:DigestValue>"),
        reference(
            "#other",
            &format!(r#"<ds:Transform Algorithm="{INCLUSIVE}"/>"#),
            "<ds:DigestValue/>",
        ),
    ]
    .concat();
    let xpath_reference = reference(
        "#payload",
        r#"<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>true()</ds:XPath></ds:Transform>"#,
        "<ds:DigestValue/>",
    );
    let manifests = format!(
        r#"<ds:Object><ds:Manifest Id="outer">{}</ds:Manifest><ds:Manifest Id="inner">{}</ds:Manifest></ds:Object>"#,
        reference("#inner", "", "<ds:DigestValue/>"),
        reference("#payload", "", "<ds:DigestValue/>"),
    );
    vec![
        (
            "exclusive subtree references",
            template(EXCLUSIVE, &subtree_references, "<ds:SignatureValue/>", ""),
            default_policy.clone(),
        ),
        (
            "inclusive subtree references",
            template(INCLUSIVE, &subtree_references, "<ds:SignatureValue/>", ""),
            default_policy.clone(),
        ),
        (
            "xpath reference",
            template(EXCLUSIVE, &xpath_reference, "<ds:SignatureValue/>", ""),
            default_policy.clone(),
        ),
        (
            "nested manifests",
            template(
                EXCLUSIVE,
                &reference("#outer", "", "<ds:DigestValue/>"),
                "<ds:SignatureValue/>",
                &manifests,
            ),
            manifest_policy,
        ),
        (
            "pre-filled values",
            template(
                EXCLUSIVE,
                &reference("", &enveloped(), "<ds:DigestValue>AAAA</ds:DigestValue>"),
                "<ds:SignatureValue>AAAA</ds:SignatureValue>",
                "",
            ),
            default_policy,
        ),
    ]
}

fn independent_canonical_signed_info(
    signed: &str,
    policy: &crate::policy::SigningPolicy,
) -> Vec<u8> {
    let document = XmlDocument::parse(signed).expect("signed output must parse");
    let mut budgets = SigningOperationBudgets::from_resources(&policy.resources);
    canonicalize_signed_info(&document, policy, &mut budgets, 0, &[])
        .expect("signed output SignedInfo must canonicalize")
        .2
}

#[test]
fn text_projection_matches_the_committed_document() {
    // String entry points serialize the final generation without parsing it,
    // while retained documents commit through a parse. Both must yield the
    // same bytes for every digest path.
    for (name, xml, policy) in cases() {
        let key = RecordingSigningKey::default();
        let context = SignContext::new(&key).policy(policy);
        let text = context
            .sign_template(&xml)
            .unwrap_or_else(|error| panic!("{name}: text signing failed: {error:?}"));
        let mut document = XmlDocument::parse(xml.as_str()).expect("fixture must parse");
        context
            .sign_document(&mut document)
            .unwrap_or_else(|error| panic!("{name}: document signing failed: {error:?}"));
        assert_eq!(text, document.as_xml(), "{name}");
        assert!(!text.contains("<ds:DigestValue/>"), "{name}");
        assert!(!text.contains("AAAA"), "{name}");
    }
}

#[test]
fn signed_canonical_signed_info_matches_the_final_document() {
    // Deferred digests are spliced into the canonical SignedInfo instead of
    // being committed first. The bytes handed to the key must equal the
    // canonical SignedInfo of the document that is finally emitted, which
    // is what a verifier reconstructs.
    for (name, xml, policy) in cases() {
        let key = RecordingSigningKey::default();
        let signed = SignContext::new(&key)
            .policy(policy.clone())
            .sign_template(&xml)
            .unwrap_or_else(|error| panic!("{name}: signing failed: {error:?}"));
        let signed_bytes = key.recorded();
        assert!(!signed_bytes.is_empty(), "{name}");
        assert_eq!(
            String::from_utf8(signed_bytes).expect("canonical XML is UTF-8"),
            String::from_utf8(independent_canonical_signed_info(&signed, &policy))
                .expect("canonical XML is UTF-8"),
            "{name}"
        );
    }
}

#[test]
fn projected_node_count_matches_the_commit_parse() {
    // The text projection replaces the commit parse's node-limit check. At
    // the smallest limit the committed document accepts, the projection must
    // accept too, and one node below it both must refuse with the node limit.
    let (_, xml, policy) = cases().swap_remove(0);
    let sign = |max_xml_nodes: usize, text: bool| {
        let mut limited = policy.clone();
        limited.resources.max_xml_nodes = max_xml_nodes;
        let context = SignContext::new(&FixedSigningKeyForLimits).policy(limited);
        if text {
            context.sign_template(&xml).map(|_| ())
        } else {
            let mut document = XmlDocument::parse(xml.as_str()).expect("fixture must parse");
            context.sign_document(&mut document)
        }
    };
    let (mut low, mut high) = (1, 10_000);
    while low < high {
        let middle = low + (high - low) / 2;
        if sign(middle, false).is_ok() {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    let minimum = low;
    sign(minimum, true).expect("projection must accept the committed node count");
    for text in [true, false] {
        let error = sign(minimum - 1, text).expect_err("one node below the commit must refuse");
        assert!(
            matches!(
                error,
                SigningError::Policy(PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_NODES,
                    ..
                })
            ),
            "text={text}: {error:?}"
        );
    }
}

struct FixedSigningKeyForLimits;

impl SigningKey for FixedSigningKeyForLimits {
    fn sign(
        &self,
        _algorithm: SignatureAlgorithm,
        _canonical_signed_info: &[u8],
    ) -> Result<Vec<u8>, SigningKeyError> {
        Ok(vec![0x5a; 256])
    }

    fn public_key_info(&self) -> Result<SigningPublicKeyInfo, SigningKeyError> {
        Ok(SigningPublicKeyInfo::Rsa {
            spki_der: Vec::new(),
            modulus: vec![0x80; 256],
            exponent: vec![1, 0, 1],
        })
    }
}
