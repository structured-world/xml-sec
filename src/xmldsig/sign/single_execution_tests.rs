use super::*;
use crate::xmldsig::transforms::take_transform_chains_started;

const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const EXCLUSIVE: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const XPATH: &str = "http://www.w3.org/TR/1999/REC-xpath-19991116";
const BASE64: &str = "http://www.w3.org/2000/09/xmldsig#base64";

struct FixedKey;

impl SigningKey for FixedKey {
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

fn reference(uri: &str, transforms: &str) -> String {
    let transforms = if transforms.is_empty() {
        String::new()
    } else {
        format!("<ds:Transforms>{transforms}</ds:Transforms>")
    };
    format!(
        r#"<ds:Reference URI="{uri}">{transforms}<ds:DigestMethod Algorithm="{SHA256}"/><ds:DigestValue/></ds:Reference>"#
    )
}

fn template(references: &str, object: &str) -> String {
    format!(
        r#"<root><payload Id="payload"><item n="1">one</item><item n="2">two</item></payload><other Id="other">x</other><data Id="data">aGVsbG8=</data><ds:Signature xmlns:ds="{DS}"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{EXCLUSIVE}"/><ds:SignatureMethod Algorithm="{RSA_SHA256}"/>{references}</ds:SignedInfo><ds:SignatureValue/>{object}</ds:Signature></root>"#
    )
}

fn transform(algorithm: &str, body: &str) -> String {
    format!(r#"<ds:Transform Algorithm="{algorithm}">{body}</ds:Transform>"#)
}

/// Signs `xml`, returning the output and how many transform chains it ran.
fn sign_counting(xml: &str, policy: crate::policy::SigningPolicy) -> (String, usize) {
    take_transform_chains_started();
    let signed = SignContext::new(&FixedKey)
        .policy(policy)
        .sign_template(xml)
        .expect("template must sign");
    (signed, take_transform_chains_started())
}

/// The `SignedInfo` digests recomputed from the final document, where every
/// mutable value already holds what a verifier will read.
fn assert_digests_match_final_document(signed: &str, policy: &crate::policy::SigningPolicy) {
    let expected = compute_prepared_reference_digest_values_with_options(
        signed,
        TransformOptions::default(),
        Some(policy),
        crate::provider::default_provider(),
        &TransformExecutionBudget::default(),
        0,
        &[],
    )
    .expect("signed output must digest");
    let actual = signed
        .split("<ds:DigestValue>")
        .skip(1)
        .map(|rest| {
            rest.split("</ds:DigestValue>")
                .next()
                .expect("closed value")
        })
        .take(expected.len())
        .collect::<Vec<_>>();
    let expected = expected
        .iter()
        .map(|digest| digest.digest_value.as_str())
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
}

#[test]
fn an_independent_reference_executes_its_transforms_once() {
    // A Reference whose output reads no value the signature fills is
    // digested from its dependency-analysis execution: the current-tree
    // analysis (subtree transforms) and the placeholder analysis (a
    // structural XPath) must not execute the chain again for the digest.
    let policy = crate::policy::SigningPolicy::default();
    let cases = [
        (
            "subtree references",
            template(
                &[
                    reference("#payload", &transform(EXCLUSIVE, "")),
                    reference("#other", ""),
                ]
                .concat(),
                "",
            ),
        ),
        (
            "structural xpath",
            template(
                &reference(
                    "#payload",
                    &transform(XPATH, "<ds:XPath>not(self::comment())</ds:XPath>"),
                ),
                "",
            ),
        ),
    ];
    for (name, xml) in cases {
        let references = xml.matches("<ds:Reference ").count();
        let (signed, chains) = sign_counting(&xml, policy.clone());
        assert_eq!(chains, references, "{name}");
        assert_digests_match_final_document(&signed, &policy);
    }
}

#[cfg(feature = "xslt")]
#[test]
fn an_xslt_reference_executes_its_stylesheet_once() {
    // The benchmark shape: one XSLT Reference over a list. XSLT reads only
    // its input octets, so the current tree decides its dependencies without
    // parsing a placeholder copy, and the digest comes from that execution.
    let stylesheet = r#"<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><xsl:template match="/"><out><xsl:for-each select="//item"><v n="{@n}"><xsl:value-of select="."/></v></xsl:for-each></out></xsl:template></xsl:stylesheet>"#;
    let xml = template(
        &reference(
            "#payload",
            &transform("http://www.w3.org/TR/1999/REC-xslt-19991116", stylesheet),
        ),
        "",
    );
    let policy = crate::policy::SigningPolicy::default();
    take_placeholder_analyses();
    let (signed, chains) = sign_counting(&xml, policy.clone());
    assert_eq!((chains, take_placeholder_analyses()), (1, 0));
    assert_digests_match_final_document(&signed, &policy);
}

#[test]
fn only_a_value_testing_transform_needs_the_placeholder_copy() {
    // Base64 decodes the text of whole selected subtrees, so the current tree
    // decides its dependencies. An XPath filter can test any node, so its
    // analysis still runs on a copy with placeholder values.
    let policy = crate::policy::SigningPolicy::default();
    let cases = [
        ("base64", reference("#data", &transform(BASE64, "")), 0),
        (
            "xpath",
            reference(
                "#payload",
                &transform(XPATH, "<ds:XPath>not(self::comment())</ds:XPath>"),
            ),
            1,
        ),
    ];
    for (name, references, placeholder_analyses) in cases {
        let xml = template(&references, "");
        take_placeholder_analyses();
        let (signed, chains) = sign_counting(&xml, policy.clone());
        assert_eq!(
            (chains, take_placeholder_analyses()),
            (1, placeholder_analyses),
            "{name}"
        );
        assert_digests_match_final_document(&signed, &policy);
    }
}

struct Writer(&'static str);

impl KeyInfoWriter for Writer {
    fn write_key_info(&self, _: &dyn SigningKey) -> Result<String, KeyInfoWriteError> {
        Ok(self.0.to_owned())
    }
}

#[test]
fn a_writer_key_info_spends_no_canonical_bytes_on_discarded_analysis() {
    // The least canonical allowance that signs is the same with or without the
    // writer's KeyInfo, which no Reference covers: an analysis made before a
    // KeyInfo that can change resolution would be discarded, so its
    // canonicalization must not be charged to the operation.
    let xml = template(&reference("#payload", &transform(EXCLUSIVE, "")), "")
        .replace("<ds:SignatureValue/>", "<ds:SignatureValue/><ds:KeyInfo/>");
    let least_allowance = |writer: Option<&Writer>| {
        let signs = |max_canonicalized_bytes: usize| {
            let mut policy = crate::policy::SigningPolicy::default();
            policy.resources.max_canonicalized_bytes = max_canonicalized_bytes;
            let context = SignContext::new(&FixedKey).policy(policy);
            match writer {
                Some(writer) => context.key_info_writer(writer).sign_template(&xml),
                None => context.sign_template(&xml),
            }
            .is_ok()
        };
        let (mut low, mut high) = (1, 64 * 1024);
        while low < high {
            let middle = low + (high - low) / 2;
            if signs(middle) {
                high = middle;
            } else {
                low = middle + 1;
            }
        }
        low
    };
    let without = least_allowance(None);
    for writer in [
        Writer("<ds:KeyName xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">signer</ds:KeyName>"),
        Writer(
            "<ds:KeyName xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"writer\">signer</ds:KeyName>",
        ),
    ] {
        assert_eq!(least_allowance(Some(&writer)), without, "{}", writer.0);
    }
}

#[test]
fn a_reference_that_reads_another_digest_executes_again() {
    // `#outer` covers a Manifest whose Reference covers another Manifest:
    // each depends on the DigestValue below it, so only the innermost one is
    // final at analysis. Three analyses plus two later digests.
    let manifests = format!(
        r#"<ds:Object><ds:Manifest Id="outer">{}</ds:Manifest><ds:Manifest Id="inner">{}</ds:Manifest></ds:Object>"#,
        reference("#inner", ""),
        reference("#payload", ""),
    );
    let xml = template(&reference("#outer", ""), &manifests);
    let policy = crate::policy::SigningPolicy {
        manifest_processing: crate::policy::ManifestProcessing::Process,
        ..crate::policy::SigningPolicy::default()
    };
    let (signed, chains) = sign_counting(&xml, policy.clone());
    assert_eq!(chains, 5);
    assert_digests_match_final_document(&signed, &policy);
}

#[test]
fn a_reference_with_a_value_reading_xpath_after_octets_executes_again() {
    // After canonicalization the chain's dependencies are settled from the
    // octets, but a later XPath that reads character data is not proven
    // independent of values outside them, so its digest is recomputed.
    let xml = template(
        &reference(
            "#payload",
            &[
                transform(EXCLUSIVE, ""),
                transform(
                    XPATH,
                    "<ds:XPath>string-length(string(.)) &gt;= 0</ds:XPath>",
                ),
            ]
            .concat(),
        ),
        "",
    );
    let policy = crate::policy::SigningPolicy::default();
    let (signed, chains) = sign_counting(&xml, policy.clone());
    assert_eq!(chains, 2);
    assert_digests_match_final_document(&signed, &policy);
}
