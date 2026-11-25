//! The DSS validation policy of one `XAdES` profile: DSS's own default policy
//! of the release under test, with every cryptographic constraint replaced
//! by what the compiled profile accepts, so both validators decide under the
//! same algorithm and key-size rules.

use super::super::xml;
use serde_json::Value;
use std::fmt::Write as _;

/// Every hash DSS names that a certificate, revocation or timestamp signature
/// may use: the profiles restrict those by key size only.
const CERTIFICATE_HASHES: [&str; 8] = [
    "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SHA3-256", "SHA3-384", "SHA3-512",
];

/// One `Cryptographic` constraint element: families, hashes and minimum
/// sizes, none of them expiring (the profiles have no time dimension).
/// DSS's policy keeps one digest list for the signature's hash and the
/// reference digests alike, so `hashes` admits a hash a signature suite needs
/// even where the profile refuses it as a reference digest; a reference the
/// profile refuses for that reason is a reviewed policy difference, which the
/// ETSI process over xml-sec's facts keeps by presenting it as unknown.
fn cryptographic(families: &[String], hashes: &[String], minimum: &Value) -> String {
    let mut families = families.to_vec();
    // XMLDSig 1.1 §6.4.3 writes ECDSA values as r || s, which DSS names
    // PLAIN-ECDSA; DER-encoded values in timestamps and certificates are ECDSA.
    if families.iter().any(|family| family == "ECDSA") {
        families.push("PLAIN-ECDSA".into());
    }
    let size = |family: &str| {
        let base = if family == "PLAIN-ECDSA" {
            "ECDSA"
        } else {
            family
        };
        minimum[base].as_u64().unwrap_or(0)
    };
    let names = |items: &[String]| -> String {
        items.iter().fold(String::new(), |mut text, item| {
            write!(text, "<Algo>{item}</Algo>").expect("writing to a String cannot fail");
            text
        })
    };
    let sized = families.iter().fold(String::new(), |mut text, family| {
        write!(text, "<Algo Size=\"{}\">{family}</Algo>", size(family))
            .expect("writing to a String cannot fail");
        text
    });
    format!(
        "<Cryptographic Level=\"FAIL\">\
         <AcceptableEncryptionAlgo>{}</AcceptableEncryptionAlgo>\
         <MiniPublicKeySize>{sized}</MiniPublicKeySize>\
         <AcceptableDigestAlgo>{}</AcceptableDigestAlgo>\
         <AlgoExpirationDate Level=\"FAIL\" Format=\"yyyy-MM-dd\">{}{sized}</AlgoExpirationDate>\
         </Cryptographic>",
        names(&families),
        names(hashes),
        names(hashes),
    )
}

/// Whether a `Cryptographic` element constrains a certificate, revocation or
/// timestamp signature rather than the signature being validated.
fn about_certificates(element: xml::Node<'_, '_>) -> bool {
    let parent = element.parent();
    let name = parent.map(|parent| parent.tag_name().name().to_owned());
    if matches!(
        name.as_deref(),
        Some("SigningCertificate" | "CACertificate")
    ) {
        return true;
    }
    // The basic constraints of timestamps and revocation data.
    parent
        .and_then(xml::Node::parent)
        .is_some_and(|grand| matches!(grand.tag_name().name(), "Timestamp" | "Revocation"))
}

/// `template` (DSS's `policy/constraint.xml`) with every `Cryptographic`
/// element replaced under `constraints`, the output of the probe's
/// `constraints` mode.
pub(crate) fn policy(template: &str, constraints: &Value) -> Result<String, String> {
    let strings = |value: &Value| -> Vec<String> {
        value
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect()
    };
    let families = strings(&constraints["signature"]["families"]);
    let hashes = strings(&constraints["signature"]["hashes"]);
    if families.is_empty() || hashes.is_empty() {
        return Err(format!("the profile accepts no signature: {constraints}"));
    }
    let minimum = &constraints["minimum_bits"];
    let certificate_hashes: Vec<String> = CERTIFICATE_HASHES
        .iter()
        .map(|hash| (*hash).to_owned())
        .collect();
    let signature = cryptographic(&families, &hashes, minimum);
    let certificates = cryptographic(&families, &certificate_hashes, minimum);
    let document = xml::parse(template, "DSS validation policy")?;
    let mut ranges: Vec<(std::ops::Range<usize>, &str)> =
        xml::below(document.root_element(), "Cryptographic", None)
            .map(|element| {
                let replacement = if about_certificates(element) {
                    certificates.as_str()
                } else {
                    signature.as_str()
                };
                (element.range(), replacement)
            })
            .collect();
    if ranges.is_empty() {
        return Err("the DSS policy has no Cryptographic constraint".into());
    }
    ranges.sort_by_key(|(range, _)| std::cmp::Reverse(range.start));
    let mut text = template.to_owned();
    for (range, replacement) in ranges {
        text.replace_range(range, replacement);
    }
    Ok(text)
}
