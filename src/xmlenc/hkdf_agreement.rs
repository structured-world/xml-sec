//! RFC 9231 HKDF XML adapter, distinct from libxmlsec1's HKDFParams layout.

use super::parse::{bounded_simple_text_with_limit, require_element, validate_metadata_len};
use super::types::{XMLDSIG_NS, XMLENC_NS};
use super::{KeyDerivationMethod, KeyEstablishmentBudget, XmlEncError, map_document_error};
use crate::document::{
    DocumentParseSettings, XmlParseWorkBudget, parse_borrowed_with_settings_and_budget,
};
use crate::xml::dom::Node;

const MORE: &str = "http://www.w3.org/2021/04/xmldsig-more#";
const HKDF: &str = "http://www.w3.org/2021/04/xmldsig-more#hkdf";

/// Normalized RFC 9231 HKDF invocation, with optional XML-supplied IKM.
///
/// RFC 9231 section 2.8.1 permits IKM to be absent when known out of band.
/// Salt and KA-Nonce are hexadecimal in this profile, not base64. Parsing
/// neither authorizes execution nor selects a security policy.
pub struct HkdfAgreement {
    method: KeyDerivationMethod,
    ikm: Option<zeroize::Zeroizing<Vec<u8>>>,
}

impl core::fmt::Debug for HkdfAgreement {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("HkdfAgreement")
            .field("method", &self.method)
            .field("has_embedded_ikm", &self.ikm.is_some())
            .finish()
    }
}

impl HkdfAgreement {
    /// Borrow normalized parameters without exposing embedded initial key material.
    pub fn key_derivation_method(&self) -> &KeyDerivationMethod {
        &self.method
    }

    /// Derive with XML-supplied IKM or an explicit out-of-band request value.
    /// Supplying both is an ambiguous request and is rejected, never overridden.
    pub fn derive_key(
        &self,
        output_len: usize,
        external_ikm: Option<&[u8]>,
        provider: &dyn crate::provider::CryptoProvider,
        budget: &mut KeyEstablishmentBudget<'_>,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, XmlEncError> {
        let ikm = match (&self.ikm, external_ikm) {
            (Some(ikm), None) => ikm.as_slice(),
            (None, Some(ikm)) => ikm,
            (None, None) => return Err(XmlEncError::MissingRequired("HKDF initial key material")),
            (Some(_), Some(_)) => return Err(invalid("HKDF initial key material supplied twice")),
        };
        self.method.derive_key(output_len, provider, ikm, budget)
    }
}

/// Parse RFC 9231 section 2.8.1 using the operation-selected backend and policy.
/// This is a parameter adapter, not an asymmetric AgreementMethod resolver.
pub fn parse_hkdf_agreement_method(
    xml: &str,
    policy: &crate::policy::DecryptionPolicy,
    backend: crate::XmlBackend,
) -> Result<HkdfAgreement, XmlEncError> {
    policy.validate()?;
    policy.resources.validate_xml_document_len(xml.len())?;
    let settings =
        DocumentParseSettings::from_policy(&policy.xml, &policy.resources).with_backend(backend);
    let budget = XmlParseWorkBudget::from_resources(&policy.resources);
    let document = parse_borrowed_with_settings_and_budget(xml, settings, Some(&budget))
        .map_err(|error| map_document_error(error, settings))?;
    parse_node(
        document.root_element(),
        policy.resources.max_encryption_metadata_bytes,
    )
}

pub(super) fn parse_node(node: Node<'_, '_>, maximum: usize) -> Result<HkdfAgreement, XmlEncError> {
    require_element(node, XMLENC_NS, "AgreementMethod")?;
    // RFC 9231's illustrative example lowercases "algorithm", but the XML
    // Security wire attribute is case-sensitive Algorithm. No casing fallback.
    // https://www.rfc-editor.org/rfc/rfc9231.html#section-2.8.1
    // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-AgreementMethod
    let algorithm = node
        .attribute("Algorithm")
        .ok_or(XmlEncError::MissingRequired("AgreementMethod Algorithm"))?;
    validate_metadata_len(algorithm.len(), maximum)?;
    if algorithm != HKDF {
        return Err(XmlEncError::UnsupportedAlgorithm(algorithm.into()));
    }
    let mut digest = None;
    let mut salt = None;
    let mut info = None;
    let mut ikm = None;
    let mut size = None;
    for child in node.children() {
        if child.is_text()
            && child
                .text()
                .is_some_and(|text| !text.bytes().all(xml_space))
        {
            return Err(invalid("HKDF AgreementMethod contains character data"));
        }
        if !child.is_element() {
            continue;
        }
        match (child.tag_name().namespace(), child.tag_name().name()) {
            (Some(XMLDSIG_NS), "DigestMethod") if digest.is_none() => {
                if child.children().any(|node| {
                    node.is_element()
                        || (node.is_text()
                            && node.text().is_some_and(|text| !text.bytes().all(xml_space)))
                }) {
                    return Err(invalid("HKDF DigestMethod parameters are unsupported"));
                }
                let value = child
                    .attribute("Algorithm")
                    .ok_or(XmlEncError::MissingRequired("DigestMethod Algorithm"))?;
                validate_metadata_len(value.len(), maximum)?;
                // The normative field selects the hash function; the RFC's
                // example names HMAC-SHA256 instead. Both identify the same
                // underlying HKDF hash, unlike an arbitrary signature URI.
                // RFC 9231 section 2.8.1: hash function and worked example.
                use crate::xmldsig::{DigestAlgorithm as D, SignatureAlgorithm as S};
                let prf = match D::from_uri(value) {
                    Some(D::Sha1) => S::HmacSha1,
                    Some(D::Sha224) => S::HmacSha224,
                    Some(D::Sha256) => S::HmacSha256,
                    Some(D::Sha384) => S::HmacSha384,
                    Some(D::Sha512) => S::HmacSha512,
                    _ => match S::from_uri(value) {
                        Some(
                            prf @ (S::HmacSha1
                            | S::HmacSha224
                            | S::HmacSha256
                            | S::HmacSha384
                            | S::HmacSha512),
                        ) => prf,
                        _ => return Err(XmlEncError::UnsupportedAlgorithm(value.into())),
                    },
                };
                digest = Some(prf.uri().to_owned());
            }
            (Some(MORE), "Salt") if salt.is_none() => salt = Some(hex_text(child, maximum)?),
            (Some(XMLENC_NS), "KA-Nonce") if info.is_none() => {
                info = Some(hex_text(child, maximum)?)
            }
            (Some(XMLENC_NS), "OriginatorKeyInfo") if ikm.is_none() => {
                ikm = Some(zeroize::Zeroizing::new(hex_text(child, maximum)?))
            }
            (Some(XMLENC_NS), "KeySize") if size.is_none() => {
                // RFC 9231 section 2.8.1's RFC 5869 A.1 example sets KeySize=42
                // for L=42 OCTETS. This profile's field is not EncryptionMethod's
                // KeySize in bits. Preserve the profile rather than dividing by 8.
                let text = bounded_simple_text_with_limit(child, "HKDF KeySize", maximum)?;
                let text = trim_xml_space(&text);
                if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(invalid(
                        "HKDF KeySize must be a positive decimal octet count",
                    ));
                }
                size = Some(
                    text.parse::<usize>()
                        .ok()
                        .filter(|value| *value != 0)
                        .ok_or_else(|| invalid("HKDF KeySize exceeds platform width or is zero"))?,
                );
            }
            _ => {
                return Err(invalid(
                    "unexpected or duplicate HKDF AgreementMethod parameter",
                ));
            }
        }
    }
    // RFC 9231 section 2.8.1 makes salt and info optional. RFC 5869
    // sections 2.2-2.3 define absent salt as HashLen zeros and absent info as
    // empty. The HMAC primitive's empty key has the same zero-padded key block.
    let method = KeyDerivationMethod::hkdf(
        digest.ok_or(XmlEncError::MissingRequired("HKDF DigestMethod"))?,
        salt.unwrap_or_default(),
        info.unwrap_or_default(),
        size.ok_or(XmlEncError::MissingRequired("HKDF KeySize"))?,
    );
    Ok(HkdfAgreement { method, ikm })
}

fn xml_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}
fn trim_xml_space(text: &str) -> &str {
    text.trim_matches(|value| matches!(value, ' ' | '\t' | '\r' | '\n'))
}
fn invalid(message: &str) -> XmlEncError {
    XmlEncError::InvalidStructure(message.into())
}

fn hex_text(node: Node<'_, '_>, maximum: usize) -> Result<Vec<u8>, XmlEncError> {
    // Validate all text fragments before reserving the one decoded buffer.
    // Entity/CDATA/comment boundaries do not require an intermediate secret
    // String, and whitespace is allowed only around the hexBinary value.
    let mut text_bytes = 0usize;
    let mut digits = 0usize;
    let mut trailing_space = false;
    for child in node.children() {
        if child.is_element() {
            return Err(invalid("HKDF hex parameter contains an element"));
        }
        if !child.is_text() {
            continue;
        }
        let text = child.text().unwrap_or_default();
        text_bytes = text_bytes
            .checked_add(text.len())
            .ok_or_else(|| invalid("HKDF hex parameter length overflow"))?;
        validate_metadata_len(text_bytes, maximum)?;
        for byte in text.bytes() {
            if xml_space(byte) {
                if digits != 0 {
                    trailing_space = true;
                }
            } else if byte.is_ascii_hexdigit() && !trailing_space {
                digits += 1;
            } else {
                return Err(invalid("HKDF parameter must be hexadecimal octets"));
            }
        }
    }
    if !digits.is_multiple_of(2) {
        return Err(invalid("HKDF parameter must be hexadecimal octets"));
    }
    let mut bytes = Vec::with_capacity(digits / 2);
    let digit = |value: u8| {
        if value <= b'9' {
            value - b'0'
        } else {
            (value | 32) - b'a' + 10
        }
    };
    let mut high = None;
    for child in node.children().filter(Node::is_text) {
        for byte in child.text().unwrap_or_default().bytes() {
            if xml_space(byte) {
                continue;
            }
            match high.take() {
                Some(value) => bytes.push(value | digit(byte)),
                None => high = Some(digit(byte) << 4),
            }
        }
    }
    debug_assert!(high.is_none());
    Ok(bytes)
}
