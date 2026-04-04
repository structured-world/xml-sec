//! Parsing of XMLDSig `<Signature>` and `<SignedInfo>` elements.
//!
//! Implements strict child order enforcement per
//! [XMLDSig §4.1](https://www.w3.org/TR/xmldsig-core1/#sec-Signature):
//!
//! ```text
//! <Signature>
//!   <SignedInfo>
//!     <CanonicalizationMethod Algorithm="..."/>
//!     <SignatureMethod Algorithm="..."/>
//!     <Reference URI="..." Id="..." Type="...">+
//!   </SignedInfo>
//!   <SignatureValue>...</SignatureValue>
//!   <KeyInfo>?
//!   <Object>*
//! </Signature>
//! ```

use roxmltree::{Document, Node};

use super::digest::DigestAlgorithm;
use super::transforms::{self, Transform};
use crate::c14n::C14nAlgorithm;

/// XMLDSig namespace URI.
pub(crate) const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
/// XMLDSig 1.1 namespace URI.
pub(crate) const XMLDSIG11_NS: &str = "http://www.w3.org/2009/xmldsig11#";
const MAX_DER_ENCODED_KEY_VALUE_LEN: usize = 8192;
const MAX_DER_ENCODED_KEY_VALUE_TEXT_LEN: usize = 65_536;
const MAX_DER_ENCODED_KEY_VALUE_BASE64_LEN: usize = MAX_DER_ENCODED_KEY_VALUE_LEN.div_ceil(3) * 4;

/// Signature algorithms supported for signing and verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    /// RSA with SHA-1. **Verify-only** — signing disabled.
    RsaSha1,
    /// RSA with SHA-256 (most common in SAML).
    RsaSha256,
    /// RSA with SHA-384.
    RsaSha384,
    /// RSA with SHA-512.
    RsaSha512,
    /// ECDSA P-256 with SHA-256.
    EcdsaP256Sha256,
    /// XMLDSig `ecdsa-sha384` URI.
    ///
    /// The variant name is historical.
    ///
    /// Verification currently accepts this XMLDSig URI for P-384 and for the
    /// donor P-521 interop case.
    EcdsaP384Sha384,
}

impl SignatureAlgorithm {
    /// Parse from an XML algorithm URI.
    #[must_use]
    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1" => Some(Self::RsaSha1),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => Some(Self::RsaSha256),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => Some(Self::RsaSha384),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => Some(Self::RsaSha512),
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256" => Some(Self::EcdsaP256Sha256),
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384" => Some(Self::EcdsaP384Sha384),
            _ => None,
        }
    }

    /// Return the XML namespace URI.
    #[must_use]
    pub fn uri(self) -> &'static str {
        match self {
            Self::RsaSha1 => "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            Self::RsaSha256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            Self::RsaSha384 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
            Self::RsaSha512 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
            Self::EcdsaP256Sha256 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
            Self::EcdsaP384Sha384 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
        }
    }

    /// Whether this algorithm is allowed for signing (not just verification).
    #[must_use]
    pub fn signing_allowed(self) -> bool {
        !matches!(self, Self::RsaSha1)
    }
}

/// Parsed `<SignedInfo>` element.
#[derive(Debug)]
pub struct SignedInfo {
    /// Canonicalization method for SignedInfo itself.
    pub c14n_method: C14nAlgorithm,
    /// Signature algorithm.
    pub signature_method: SignatureAlgorithm,
    /// One or more `<Reference>` elements.
    pub references: Vec<Reference>,
}

/// Parsed `<Reference>` element.
#[derive(Debug)]
pub struct Reference {
    /// URI attribute (e.g., `""`, `"#_assert1"`).
    pub uri: Option<String>,
    /// Id attribute.
    pub id: Option<String>,
    /// Type attribute.
    pub ref_type: Option<String>,
    /// Transform chain.
    pub transforms: Vec<Transform>,
    /// Digest algorithm.
    pub digest_method: DigestAlgorithm,
    /// Raw digest value (base64-decoded).
    pub digest_value: Vec<u8>,
}

/// Parsed `<KeyInfo>` element.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct KeyInfo {
    /// Sources discovered under `<KeyInfo>` in document order.
    pub sources: Vec<KeyInfoSource>,
}

/// Top-level key material source parsed from `<KeyInfo>`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyInfoSource {
    /// `<KeyName>` source.
    KeyName(String),
    /// `<KeyValue>` source.
    KeyValue(KeyValueInfo),
    /// `<X509Data>` source.
    X509Data(X509DataInfo),
    /// `dsig11:DEREncodedKeyValue` source (base64-decoded DER bytes).
    DerEncodedKeyValue(Vec<u8>),
}

/// Parsed `<KeyValue>` dispatch result.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyValueInfo {
    /// `<RSAKeyValue>`.
    RsaKeyValue,
    /// `<ECKeyValue>`.
    EcKeyValue,
    /// Any other `<KeyValue>` child not yet supported by this phase.
    Unsupported(String),
}

/// Parsed `<X509Data>` children (dispatch-only in P2-001).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct X509DataInfo {
    /// Number of `<X509Certificate>` children.
    pub certificate_count: usize,
    /// Number of `<X509SubjectName>` children.
    pub subject_name_count: usize,
    /// Number of `<X509IssuerSerial>` children.
    pub issuer_serial_count: usize,
    /// Number of `<X509SKI>` children.
    pub ski_count: usize,
    /// Number of `<X509CRL>` children.
    pub crl_count: usize,
    /// Number of `<X509Digest>` children.
    pub digest_count: usize,
}

/// Errors during XMLDSig element parsing.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// Missing required element.
    #[error("missing required element: <{element}>")]
    MissingElement {
        /// Name of the missing element.
        element: &'static str,
    },

    /// Invalid structure (wrong child order, unexpected element, etc.).
    #[error("invalid structure: {0}")]
    InvalidStructure(String),

    /// Unsupported algorithm URI.
    #[error("unsupported algorithm: {uri}")]
    UnsupportedAlgorithm {
        /// The unrecognized algorithm URI.
        uri: String,
    },

    /// Base64 decode error.
    #[error("base64 decode error: {0}")]
    Base64(String),

    /// DigestValue length did not match the declared DigestMethod.
    #[error(
        "digest length mismatch for {algorithm}: expected {expected} bytes, got {actual} bytes"
    )]
    DigestLengthMismatch {
        /// Digest algorithm URI/name used for diagnostics.
        algorithm: &'static str,
        /// Expected decoded digest length in bytes.
        expected: usize,
        /// Actual decoded digest length in bytes.
        actual: usize,
    },

    /// Transform parsing error.
    #[error("transform error: {0}")]
    Transform(#[from] super::types::TransformError),
}

/// Find the first `<ds:Signature>` element in the document.
#[must_use]
pub fn find_signature_node<'a>(doc: &'a Document<'a>) -> Option<Node<'a, 'a>> {
    doc.descendants().find(|n| {
        n.is_element()
            && n.tag_name().name() == "Signature"
            && n.tag_name().namespace() == Some(XMLDSIG_NS)
    })
}

/// Parse a `<ds:SignedInfo>` element.
///
/// Enforces strict child order per XMLDSig spec:
/// `<CanonicalizationMethod>` → `<SignatureMethod>` → `<Reference>`+
pub fn parse_signed_info(signed_info_node: Node) -> Result<SignedInfo, ParseError> {
    verify_ds_element(signed_info_node, "SignedInfo")?;

    let mut children = element_children(signed_info_node);

    // 1. CanonicalizationMethod (required, first)
    let c14n_node = children.next().ok_or(ParseError::MissingElement {
        element: "CanonicalizationMethod",
    })?;
    verify_ds_element(c14n_node, "CanonicalizationMethod")?;
    let c14n_uri = required_algorithm_attr(c14n_node, "CanonicalizationMethod")?;
    let mut c14n_method =
        C14nAlgorithm::from_uri(c14n_uri).ok_or_else(|| ParseError::UnsupportedAlgorithm {
            uri: c14n_uri.to_string(),
        })?;
    if let Some(prefix_list) = parse_inclusive_prefixes(c14n_node)? {
        if c14n_method.mode() == crate::c14n::C14nMode::Exclusive1_0 {
            c14n_method = c14n_method.with_prefix_list(&prefix_list);
        } else {
            return Err(ParseError::UnsupportedAlgorithm {
                uri: c14n_uri.to_string(),
            });
        }
    }

    // 2. SignatureMethod (required, second)
    let sig_method_node = children.next().ok_or(ParseError::MissingElement {
        element: "SignatureMethod",
    })?;
    verify_ds_element(sig_method_node, "SignatureMethod")?;
    let sig_uri = required_algorithm_attr(sig_method_node, "SignatureMethod")?;
    let signature_method =
        SignatureAlgorithm::from_uri(sig_uri).ok_or_else(|| ParseError::UnsupportedAlgorithm {
            uri: sig_uri.to_string(),
        })?;

    // 3. One or more Reference elements
    let mut references = Vec::new();
    for child in children {
        verify_ds_element(child, "Reference")?;
        references.push(parse_reference(child)?);
    }
    if references.is_empty() {
        return Err(ParseError::MissingElement {
            element: "Reference",
        });
    }

    Ok(SignedInfo {
        c14n_method,
        signature_method,
        references,
    })
}

/// Parse a single `<ds:Reference>` element.
///
/// Structure: `<Transforms>?` → `<DigestMethod>` → `<DigestValue>`
pub(crate) fn parse_reference(reference_node: Node) -> Result<Reference, ParseError> {
    let uri = reference_node.attribute("URI").map(String::from);
    let id = reference_node.attribute("Id").map(String::from);
    let ref_type = reference_node.attribute("Type").map(String::from);

    let mut children = element_children(reference_node);

    // Optional <Transforms>
    let mut transforms = Vec::new();
    let mut next = children.next().ok_or(ParseError::MissingElement {
        element: "DigestMethod",
    })?;

    if next.tag_name().name() == "Transforms" && next.tag_name().namespace() == Some(XMLDSIG_NS) {
        transforms = transforms::parse_transforms(next)?;
        next = children.next().ok_or(ParseError::MissingElement {
            element: "DigestMethod",
        })?;
    }

    // Required <DigestMethod>
    verify_ds_element(next, "DigestMethod")?;
    let digest_uri = required_algorithm_attr(next, "DigestMethod")?;
    let digest_method =
        DigestAlgorithm::from_uri(digest_uri).ok_or_else(|| ParseError::UnsupportedAlgorithm {
            uri: digest_uri.to_string(),
        })?;

    // Required <DigestValue>
    let digest_value_node = children.next().ok_or(ParseError::MissingElement {
        element: "DigestValue",
    })?;
    verify_ds_element(digest_value_node, "DigestValue")?;
    let mut digest_b64 = String::new();
    for child in digest_value_node.children() {
        if child.is_element() {
            return Err(ParseError::InvalidStructure(
                "DigestValue must not contain element children".into(),
            ));
        }
        if child.is_text()
            && let Some(text) = child.text()
        {
            digest_b64.push_str(text);
        }
    }
    let digest_value = base64_decode_digest(&digest_b64, digest_method)?;

    // No more children expected
    if let Some(unexpected) = children.next() {
        return Err(ParseError::InvalidStructure(format!(
            "unexpected element <{}> after <DigestValue> in <Reference>",
            unexpected.tag_name().name()
        )));
    }

    Ok(Reference {
        uri,
        id,
        ref_type,
        transforms,
        digest_method,
        digest_value,
    })
}

/// Parse `<ds:KeyInfo>` and dispatch supported child sources.
///
/// Supported source elements:
/// - `<ds:KeyName>`
/// - `<ds:KeyValue>` (dispatch to RSA vs EC by child element name)
/// - `<ds:X509Data>`
/// - `<dsig11:DEREncodedKeyValue>`
///
/// Unknown elements are ignored (lax processing), matching XMLDSig behavior.
pub fn parse_key_info(key_info_node: Node) -> Result<KeyInfo, ParseError> {
    verify_ds_element(key_info_node, "KeyInfo")?;
    ensure_no_non_whitespace_text(key_info_node, "KeyInfo")?;

    let mut sources = Vec::new();
    for child in element_children(key_info_node) {
        match (child.tag_name().namespace(), child.tag_name().name()) {
            (Some(XMLDSIG_NS), "KeyName") => {
                ensure_no_element_children(child, "KeyName")?;
                let key_name = collect_text_content(child);
                sources.push(KeyInfoSource::KeyName(key_name));
            }
            (Some(XMLDSIG_NS), "KeyValue") => {
                let key_value = parse_key_value_dispatch(child)?;
                sources.push(KeyInfoSource::KeyValue(key_value));
            }
            (Some(XMLDSIG_NS), "X509Data") => {
                let x509 = parse_x509_data_dispatch(child)?;
                sources.push(KeyInfoSource::X509Data(x509));
            }
            (Some(XMLDSIG11_NS), "DEREncodedKeyValue") => {
                ensure_no_element_children(child, "DEREncodedKeyValue")?;
                let der = decode_base64_xml_children(child)?;
                sources.push(KeyInfoSource::DerEncodedKeyValue(der));
            }
            _ => {}
        }
    }

    Ok(KeyInfo { sources })
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Iterate only element children (skip text, comments, PIs).
fn element_children<'a>(node: Node<'a, 'a>) -> impl Iterator<Item = Node<'a, 'a>> {
    node.children().filter(|n| n.is_element())
}

/// Verify that a node is a `<ds:{expected_name}>` element.
fn verify_ds_element(node: Node, expected_name: &'static str) -> Result<(), ParseError> {
    if !node.is_element() {
        return Err(ParseError::InvalidStructure(format!(
            "expected element <{expected_name}>, got non-element node"
        )));
    }
    let tag = node.tag_name();
    if tag.name() != expected_name || tag.namespace() != Some(XMLDSIG_NS) {
        return Err(ParseError::InvalidStructure(format!(
            "expected <ds:{expected_name}>, got <{}{}>",
            tag.namespace()
                .map(|ns| format!("{{{ns}}}"))
                .unwrap_or_default(),
            tag.name()
        )));
    }
    Ok(())
}

/// Get the required `Algorithm` attribute from an element.
fn required_algorithm_attr<'a>(
    node: Node<'a, 'a>,
    element_name: &'static str,
) -> Result<&'a str, ParseError> {
    node.attribute("Algorithm").ok_or_else(|| {
        ParseError::InvalidStructure(format!("missing Algorithm attribute on <{element_name}>"))
    })
}

/// Parse the `PrefixList` attribute from an `<ec:InclusiveNamespaces>` child of
/// `<CanonicalizationMethod>`, if present.
///
/// This mirrors transform parsing for Exclusive C14N and keeps SignedInfo
/// canonicalization parameters lossless.
fn parse_inclusive_prefixes(node: Node) -> Result<Option<String>, ParseError> {
    const EXCLUSIVE_C14N_NS_URI: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

    for child in node.children() {
        if child.is_element() {
            let tag = child.tag_name();
            if tag.name() == "InclusiveNamespaces" && tag.namespace() == Some(EXCLUSIVE_C14N_NS_URI)
            {
                return child
                    .attribute("PrefixList")
                    .map(str::to_string)
                    .ok_or_else(|| {
                        ParseError::InvalidStructure(
                            "missing PrefixList attribute on <InclusiveNamespaces>".into(),
                        )
                    })
                    .map(Some);
            }
        }
    }

    Ok(None)
}

fn parse_key_value_dispatch(node: Node) -> Result<KeyValueInfo, ParseError> {
    verify_ds_element(node, "KeyValue")?;
    ensure_no_non_whitespace_text(node, "KeyValue")?;

    let mut children = element_children(node);
    let Some(first_child) = children.next() else {
        return Err(ParseError::InvalidStructure(
            "KeyValue must contain exactly one key-value child".into(),
        ));
    };
    if children.next().is_some() {
        return Err(ParseError::InvalidStructure(
            "KeyValue must contain exactly one key-value child".into(),
        ));
    }

    match (
        first_child.tag_name().namespace(),
        first_child.tag_name().name(),
    ) {
        (Some(XMLDSIG_NS), "RSAKeyValue") => Ok(KeyValueInfo::RsaKeyValue),
        (Some(XMLDSIG_NS), "ECKeyValue") | (Some(XMLDSIG11_NS), "ECKeyValue") => {
            Ok(KeyValueInfo::EcKeyValue)
        }
        (_, child_name) => Ok(KeyValueInfo::Unsupported(child_name.to_string())),
    }
}

fn parse_x509_data_dispatch(node: Node) -> Result<X509DataInfo, ParseError> {
    verify_ds_element(node, "X509Data")?;
    ensure_no_non_whitespace_text(node, "X509Data")?;

    let mut info = X509DataInfo::default();
    let mut saw_child = false;
    for child in element_children(node) {
        saw_child = true;
        match (child.tag_name().namespace(), child.tag_name().name()) {
            (Some(XMLDSIG_NS), "X509Certificate") => info.certificate_count += 1,
            (Some(XMLDSIG_NS), "X509SubjectName") => info.subject_name_count += 1,
            (Some(XMLDSIG_NS), "X509IssuerSerial") => info.issuer_serial_count += 1,
            (Some(XMLDSIG_NS), "X509SKI") => info.ski_count += 1,
            (Some(XMLDSIG_NS), "X509CRL") => info.crl_count += 1,
            (Some(XMLDSIG11_NS), "X509Digest") => info.digest_count += 1,
            _ => {}
        }
    }

    if !saw_child {
        return Err(ParseError::InvalidStructure(
            "X509Data must contain at least one child element".into(),
        ));
    }

    Ok(info)
}

/// Base64-decode a digest value string, stripping whitespace.
///
/// XMLDSig allows whitespace within base64 content (line-wrapped encodings).
fn base64_decode_digest(b64: &str, digest_method: DigestAlgorithm) -> Result<Vec<u8>, ParseError> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    let mut cleaned = String::with_capacity(b64.len());
    for ch in b64.chars() {
        if matches!(ch, ' ' | '\t' | '\r' | '\n') {
            continue;
        }
        if ch.is_ascii_whitespace() {
            return Err(ParseError::Base64(format!(
                "invalid XML whitespace U+{:04X} in DigestValue",
                u32::from(ch)
            )));
        }
        cleaned.push(ch);
    }
    let digest = STANDARD
        .decode(&cleaned)
        .map_err(|e| ParseError::Base64(e.to_string()))?;
    let expected = digest_method.output_len();
    let actual = digest.len();
    if actual != expected {
        return Err(ParseError::DigestLengthMismatch {
            algorithm: digest_method.uri(),
            expected,
            actual,
        });
    }
    Ok(digest)
}

fn decode_base64_xml_children(node: Node<'_, '_>) -> Result<Vec<u8>, ParseError> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    let mut cleaned = String::new();
    let mut raw_text_len = 0usize;
    for text in node
        .children()
        .filter(|child| child.is_text())
        .filter_map(|child| child.text())
    {
        for ch in text.chars() {
            if raw_text_len.saturating_add(ch.len_utf8()) > MAX_DER_ENCODED_KEY_VALUE_TEXT_LEN {
                return Err(ParseError::InvalidStructure(
                    "DEREncodedKeyValue exceeds maximum allowed text length".into(),
                ));
            }
            raw_text_len = raw_text_len.saturating_add(ch.len_utf8());
            if matches!(ch, ' ' | '\t' | '\r' | '\n') {
                continue;
            }
            if ch.is_ascii_whitespace() {
                return Err(ParseError::Base64(format!(
                    "invalid XML whitespace U+{:04X} in base64 text",
                    u32::from(ch)
                )));
            }
            cleaned.push(ch);
            if cleaned.len() > MAX_DER_ENCODED_KEY_VALUE_BASE64_LEN {
                return Err(ParseError::InvalidStructure(
                    "DEREncodedKeyValue exceeds maximum allowed length".into(),
                ));
            }
        }
    }

    let der = STANDARD
        .decode(&cleaned)
        .map_err(|e| ParseError::Base64(e.to_string()))?;
    if der.len() > MAX_DER_ENCODED_KEY_VALUE_LEN {
        return Err(ParseError::InvalidStructure(
            "DEREncodedKeyValue exceeds maximum allowed length".into(),
        ));
    }
    Ok(der)
}

fn collect_text_content(node: Node<'_, '_>) -> String {
    node.children()
        .filter_map(|child| child.is_text().then(|| child.text()).flatten())
        .collect()
}

fn ensure_no_element_children(node: Node<'_, '_>, element_name: &str) -> Result<(), ParseError> {
    if node.children().any(|child| child.is_element()) {
        return Err(ParseError::InvalidStructure(format!(
            "{element_name} must not contain child elements"
        )));
    }
    Ok(())
}

fn ensure_no_non_whitespace_text(node: Node<'_, '_>, element_name: &str) -> Result<(), ParseError> {
    for child in node.children().filter(|child| child.is_text()) {
        if let Some(text) = child.text()
            && !is_xml_whitespace_only(text)
        {
            return Err(ParseError::InvalidStructure(format!(
                "{element_name} must not contain non-whitespace mixed content"
            )));
        }
    }
    Ok(())
}

fn is_xml_whitespace_only(text: &str) -> bool {
    text.chars()
        .all(|ch| matches!(ch, ' ' | '\t' | '\r' | '\n'))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests use trusted XML fixtures")]
mod tests {
    use super::*;
    use base64::Engine;

    // ── SignatureAlgorithm ───────────────────────────────────────────

    #[test]
    fn signature_algorithm_from_uri_rsa_sha256() {
        assert_eq!(
            SignatureAlgorithm::from_uri("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),
            Some(SignatureAlgorithm::RsaSha256)
        );
    }

    #[test]
    fn signature_algorithm_from_uri_rsa_sha1() {
        assert_eq!(
            SignatureAlgorithm::from_uri("http://www.w3.org/2000/09/xmldsig#rsa-sha1"),
            Some(SignatureAlgorithm::RsaSha1)
        );
    }

    #[test]
    fn signature_algorithm_from_uri_ecdsa_sha256() {
        assert_eq!(
            SignatureAlgorithm::from_uri("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"),
            Some(SignatureAlgorithm::EcdsaP256Sha256)
        );
    }

    #[test]
    fn signature_algorithm_from_uri_unknown() {
        assert_eq!(
            SignatureAlgorithm::from_uri("http://example.com/unknown"),
            None
        );
    }

    #[test]
    fn signature_algorithm_uri_round_trip() {
        for algo in [
            SignatureAlgorithm::RsaSha1,
            SignatureAlgorithm::RsaSha256,
            SignatureAlgorithm::RsaSha384,
            SignatureAlgorithm::RsaSha512,
            SignatureAlgorithm::EcdsaP256Sha256,
            SignatureAlgorithm::EcdsaP384Sha384,
        ] {
            assert_eq!(
                SignatureAlgorithm::from_uri(algo.uri()),
                Some(algo),
                "round-trip failed for {algo:?}"
            );
        }
    }

    #[test]
    fn rsa_sha1_verify_only() {
        assert!(!SignatureAlgorithm::RsaSha1.signing_allowed());
        assert!(SignatureAlgorithm::RsaSha256.signing_allowed());
        assert!(SignatureAlgorithm::EcdsaP256Sha256.signing_allowed());
    }

    // ── find_signature_node ──────────────────────────────────────────

    #[test]
    fn find_signature_in_saml() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
            <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:SignedInfo/>
            </ds:Signature>
        </samlp:Response>"#;
        let doc = Document::parse(xml).unwrap();
        let sig = find_signature_node(&doc);
        assert!(sig.is_some());
        assert_eq!(sig.unwrap().tag_name().name(), "Signature");
    }

    #[test]
    fn find_signature_missing() {
        let xml = "<root><child/></root>";
        let doc = Document::parse(xml).unwrap();
        assert!(find_signature_node(&doc).is_none());
    }

    #[test]
    fn find_signature_ignores_wrong_namespace() {
        let xml = r#"<root><Signature xmlns="http://example.com/fake"/></root>"#;
        let doc = Document::parse(xml).unwrap();
        assert!(find_signature_node(&doc).is_none());
    }

    // ── parse_key_info: dispatch parsing ──────────────────────────────

    #[test]
    fn parse_key_info_dispatches_supported_children() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"
                              xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">
            <KeyName>idp-signing-key</KeyName>
            <KeyValue>
                <RSAKeyValue>
                    <Modulus>AQAB</Modulus>
                    <Exponent>AQAB</Exponent>
                </RSAKeyValue>
            </KeyValue>
            <X509Data>
                <X509Certificate>MIIB</X509Certificate>
                <X509SubjectName>CN=Example</X509SubjectName>
            </X509Data>
            <dsig11:DEREncodedKeyValue>AQIDBA==</dsig11:DEREncodedKeyValue>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let key_info = parse_key_info(doc.root_element()).unwrap();
        assert_eq!(key_info.sources.len(), 4);

        assert_eq!(
            key_info.sources[0],
            KeyInfoSource::KeyName("idp-signing-key".to_string())
        );
        assert_eq!(
            key_info.sources[1],
            KeyInfoSource::KeyValue(KeyValueInfo::RsaKeyValue)
        );
        assert_eq!(
            key_info.sources[2],
            KeyInfoSource::X509Data(X509DataInfo {
                certificate_count: 1,
                subject_name_count: 1,
                issuer_serial_count: 0,
                ski_count: 0,
                crl_count: 0,
                digest_count: 0,
            })
        );
        assert_eq!(
            key_info.sources[3],
            KeyInfoSource::DerEncodedKeyValue(vec![1, 2, 3, 4])
        );
    }

    #[test]
    fn parse_key_info_ignores_unknown_children() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <Foo>bar</Foo>
            <KeyName>ok</KeyName>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let key_info = parse_key_info(doc.root_element()).unwrap();
        assert_eq!(key_info.sources, vec![KeyInfoSource::KeyName("ok".into())]);
    }

    #[test]
    fn parse_key_info_keyvalue_requires_single_child() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <KeyValue/>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let err = parse_key_info(doc.root_element()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidStructure(_)));
    }

    #[test]
    fn parse_key_info_x509data_must_not_be_empty() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <X509Data/>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let err = parse_key_info(doc.root_element()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidStructure(_)));
    }

    #[test]
    fn parse_key_info_der_encoded_key_value_rejects_invalid_base64() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"
                              xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">
            <dsig11:DEREncodedKeyValue>%%%invalid%%%</dsig11:DEREncodedKeyValue>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let err = parse_key_info(doc.root_element()).unwrap_err();
        assert!(matches!(err, ParseError::Base64(_)));
    }

    #[test]
    fn parse_key_info_dispatches_dsig11_ec_keyvalue() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"
                              xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">
            <KeyValue>
                <dsig11:ECKeyValue/>
            </KeyValue>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let key_info = parse_key_info(doc.root_element()).unwrap();
        assert_eq!(
            key_info.sources,
            vec![KeyInfoSource::KeyValue(KeyValueInfo::EcKeyValue)]
        );
    }

    #[test]
    fn parse_key_info_keeps_unsupported_keyvalue_child_as_marker() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <KeyValue>
                <DSAKeyValue/>
            </KeyValue>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let key_info = parse_key_info(doc.root_element()).unwrap();
        assert_eq!(
            key_info.sources,
            vec![KeyInfoSource::KeyValue(KeyValueInfo::Unsupported(
                "DSAKeyValue".into()
            ))]
        );
    }

    #[test]
    fn parse_key_info_rejects_keyname_with_child_elements() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <KeyName>ok<foo/></KeyName>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let err = parse_key_info(doc.root_element()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidStructure(_)));
    }

    #[test]
    fn parse_key_info_preserves_keyname_text_without_trimming() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <KeyName>  signing key  </KeyName>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let key_info = parse_key_info(doc.root_element()).unwrap();
        assert_eq!(
            key_info.sources,
            vec![KeyInfoSource::KeyName("  signing key  ".into())]
        );
    }

    #[test]
    fn parse_key_info_rejects_non_whitespace_mixed_content() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">oops<KeyName>k</KeyName></KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let err = parse_key_info(doc.root_element()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidStructure(_)));
    }

    #[test]
    fn parse_key_info_rejects_nbsp_as_non_xml_whitespace_mixed_content() {
        let xml = "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\u{00A0}<KeyName>k</KeyName></KeyInfo>";
        let doc = Document::parse(xml).unwrap();

        let err = parse_key_info(doc.root_element()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidStructure(_)));
    }

    #[test]
    fn parse_key_info_der_encoded_key_value_rejects_oversized_payload() {
        let oversized =
            base64::engine::general_purpose::STANDARD
                .encode(vec![0u8; MAX_DER_ENCODED_KEY_VALUE_LEN + 1]);
        let xml = format!(
            "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:dsig11=\"http://www.w3.org/2009/xmldsig11#\"><dsig11:DEREncodedKeyValue>{oversized}</dsig11:DEREncodedKeyValue></KeyInfo>"
        );
        let doc = Document::parse(&xml).unwrap();

        let err = parse_key_info(doc.root_element()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidStructure(_)));
    }

    // ── parse_signed_info: happy path ────────────────────────────────

    #[test]
    fn parse_signed_info_rsa_sha256_with_reference() {
        let xml = r#"<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <Reference URI="">
                <Transforms>
                    <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                </Transforms>
                <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</DigestValue>
            </Reference>
        </SignedInfo>"#;
        let doc = Document::parse(xml).unwrap();
        let si = parse_signed_info(doc.root_element()).unwrap();

        assert_eq!(si.signature_method, SignatureAlgorithm::RsaSha256);
        assert_eq!(si.references.len(), 1);

        let r = &si.references[0];
        assert_eq!(r.uri.as_deref(), Some(""));
        assert_eq!(r.digest_method, DigestAlgorithm::Sha256);
        assert_eq!(r.digest_value, vec![0u8; 32]);
        assert_eq!(r.transforms.len(), 2);
    }

    #[test]
    fn parse_signed_info_multiple_references() {
        let xml = r##"<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
            <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>
            <Reference URI="#a">
                <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</DigestValue>
            </Reference>
            <Reference URI="#b">
                <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                <DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAA=</DigestValue>
            </Reference>
        </SignedInfo>"##;
        let doc = Document::parse(xml).unwrap();
        let si = parse_signed_info(doc.root_element()).unwrap();

        assert_eq!(si.signature_method, SignatureAlgorithm::EcdsaP256Sha256);
        assert_eq!(si.references.len(), 2);
        assert_eq!(si.references[0].uri.as_deref(), Some("#a"));
        assert_eq!(si.references[0].digest_method, DigestAlgorithm::Sha256);
        assert_eq!(si.references[1].uri.as_deref(), Some("#b"));
        assert_eq!(si.references[1].digest_method, DigestAlgorithm::Sha1);
    }

    #[test]
    fn parse_reference_without_transforms() {
        // Transforms element is optional
        let xml = r##"<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <Reference URI="#obj">
                <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</DigestValue>
            </Reference>
        </SignedInfo>"##;
        let doc = Document::parse(xml).unwrap();
        let si = parse_signed_info(doc.root_element()).unwrap();

        assert!(si.references[0].transforms.is_empty());
    }

    #[test]
    fn parse_reference_with_all_attributes() {
        let xml = r##"<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <Reference URI="#data" Id="ref1" Type="http://www.w3.org/2000/09/xmldsig#Object">
                <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</DigestValue>
            </Reference>
        </SignedInfo>"##;
        let doc = Document::parse(xml).unwrap();
        let si = parse_signed_info(doc.root_element()).unwrap();
        let r = &si.references[0];

        assert_eq!(r.uri.as_deref(), Some("#data"));
        assert_eq!(r.id.as_deref(), Some("ref1"));
        assert_eq!(
            r.ref_type.as_deref(),
            Some("http://www.w3.org/2000/09/xmldsig#Object")
        );
    }

    #[test]
    fn parse_reference_absent_uri() {
        // URI attribute is optional per spec
        let xml = r#"<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <Reference>
                <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</DigestValue>
            </Reference>
        </SignedInfo>"#;
        let doc = Document::parse(xml).unwrap();
        let si = parse_signed_info(doc.root_element()).unwrap();
        assert!(si.references[0].uri.is_none());
    }

    #[test]
    fn parse_signed_info_preserves_inclusive_prefixes() {
        let xml = r#"<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"
                                 xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#">
            <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
                <ec:InclusiveNamespaces PrefixList="ds saml #default"/>
            </CanonicalizationMethod>
            <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <Reference URI="">
                <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</DigestValue>
            </Reference>
        </SignedInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let si = parse_signed_info(doc.root_element()).unwrap();
        assert!(si.c14n_method.inclusive_prefixes().contains("ds"));
        assert!(si.c14n_method.inclusive_prefixes().contains("saml"));
        assert!(si.c14n_method.inclusive_prefixes().contains(""));
    }

    // ── parse_signed_info: error cases ───────────────────────────────

    #[test]
    fn missing_canonicalization_method() {
        let xml = r#"<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <Reference URI="">
                <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <DigestValue>dGVzdA==</DigestValue>
            </Reference>
        </SignedInfo>"#;
        let doc = Document::parse(xml).unwrap();
        let result = parse_signed_info(doc.root_element());
        assert!(result.is_err());
        // SignatureMethod is first child but expected CanonicalizationMethod
        assert!(matches!(
            result.unwrap_err(),
            ParseError::InvalidStructure(_)
        ));
    }

    #[test]
    fn missing_signature_method() {
        let xml = r#"<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <Reference URI="">
                <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <DigestValue>dGVzdA==</DigestValue>
            </Reference>
        </SignedInfo>"#;
        let doc = Document::parse(xml).unwrap();
        let result = parse_signed_info(doc.root_element());
        assert!(result.is_err());
        // Reference is second child but expected SignatureMethod
        assert!(matches!(
            result.unwrap_err(),
            ParseError::InvalidStructure(_)
        ));
    }

    #[test]
    fn no_references() {
        let xml = r#"<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        </SignedInfo>"#;
        let doc = Document::parse(xml).unwrap();
        let result = parse_signed_info(doc.root_element());
        assert!(matches!(
            result.unwrap_err(),
            ParseError::MissingElement {
                element: "Reference"
            }
        ));
    }

    #[test]
    fn unsupported_c14n_algorithm() {
        let xml = r#"<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <CanonicalizationMethod Algorithm="http://example.com/bogus-c14n"/>
            <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <Reference URI="">
                <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <DigestValue>dGVzdA==</DigestValue>
            </Reference>
        </SignedInfo>"#;
        let doc = Document::parse(xml).unwrap();
        let result = parse_signed_info(doc.root_element());
        assert!(matches!(
            result.unwrap_err(),
            ParseError::UnsupportedAlgorithm { .. }
        ));
    }

    #[test]
    fn unsupported_signature_algorithm() {
        let xml = r#"<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <SignatureMethod Algorithm="http://example.com/bogus-sign"/>
            <Reference URI="">
                <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <DigestValue>dGVzdA==</DigestValue>
            </Reference>
        </SignedInfo>"#;
        let doc = Document::parse(xml).unwrap();
        let result = parse_signed_info(doc.root_element());
        assert!(matches!(
            result.unwrap_err(),
            ParseError::UnsupportedAlgorithm { .. }
        ));
    }

    #[test]
    fn unsupported_digest_algorithm() {
        let xml = r#"<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <Reference URI="">
                <DigestMethod Algorithm="http://example.com/bogus-digest"/>
                <DigestValue>dGVzdA==</DigestValue>
            </Reference>
        </SignedInfo>"#;
        let doc = Document::parse(xml).unwrap();
        let result = parse_signed_info(doc.root_element());
        assert!(matches!(
            result.unwrap_err(),
            ParseError::UnsupportedAlgorithm { .. }
        ));
    }

    #[test]
    fn missing_digest_method() {
        let xml = r#"<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <Reference URI="">
                <DigestValue>dGVzdA==</DigestValue>
            </Reference>
        </SignedInfo>"#;
        let doc = Document::parse(xml).unwrap();
        let result = parse_signed_info(doc.root_element());
        // DigestValue is not DigestMethod
        assert!(result.is_err());
    }

    #[test]
    fn missing_digest_value() {
        let xml = r#"<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <Reference URI="">
                <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
            </Reference>
        </SignedInfo>"#;
        let doc = Document::parse(xml).unwrap();
        let result = parse_signed_info(doc.root_element());
        assert!(matches!(
            result.unwrap_err(),
            ParseError::MissingElement {
                element: "DigestValue"
            }
        ));
    }

    #[test]
    fn invalid_base64_digest_value() {
        let xml = r#"<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <Reference URI="">
                <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <DigestValue>!!!not-base64!!!</DigestValue>
            </Reference>
        </SignedInfo>"#;
        let doc = Document::parse(xml).unwrap();
        let result = parse_signed_info(doc.root_element());
        assert!(matches!(result.unwrap_err(), ParseError::Base64(_)));
    }

    #[test]
    fn digest_value_length_must_match_digest_method() {
        let xml = r#"<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <Reference URI="">
                <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <DigestValue>dGVzdA==</DigestValue>
            </Reference>
        </SignedInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let result = parse_signed_info(doc.root_element());
        assert!(matches!(
            result.unwrap_err(),
            ParseError::DigestLengthMismatch {
                algorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
                expected: 32,
                actual: 4,
            }
        ));
    }

    #[test]
    fn inclusive_prefixes_on_inclusive_c14n_is_rejected() {
        let xml = r#"<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"
                                 xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#">
            <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315">
                <ec:InclusiveNamespaces PrefixList="ds"/>
            </CanonicalizationMethod>
            <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <Reference URI="">
                <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                <DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAA=</DigestValue>
            </Reference>
        </SignedInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let result = parse_signed_info(doc.root_element());
        assert!(matches!(
            result.unwrap_err(),
            ParseError::UnsupportedAlgorithm { .. }
        ));
    }

    #[test]
    fn extra_element_after_digest_value() {
        let xml = r#"<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <Reference URI="">
                <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</DigestValue>
                <Unexpected/>
            </Reference>
        </SignedInfo>"#;
        let doc = Document::parse(xml).unwrap();
        let result = parse_signed_info(doc.root_element());
        assert!(matches!(
            result.unwrap_err(),
            ParseError::InvalidStructure(_)
        ));
    }

    #[test]
    fn digest_value_with_element_child_is_rejected() {
        let xml = r#"<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <Reference URI="">
                <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                <DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAA=<Junk/>AAAA</DigestValue>
            </Reference>
        </SignedInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let result = parse_signed_info(doc.root_element());
        assert!(matches!(
            result.unwrap_err(),
            ParseError::InvalidStructure(_)
        ));
    }

    #[test]
    fn wrong_namespace_on_signed_info() {
        let xml = r#"<SignedInfo xmlns="http://example.com/fake">
            <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </SignedInfo>"#;
        let doc = Document::parse(xml).unwrap();
        let result = parse_signed_info(doc.root_element());
        assert!(matches!(
            result.unwrap_err(),
            ParseError::InvalidStructure(_)
        ));
    }

    // ── Whitespace-wrapped base64 ────────────────────────────────────

    #[test]
    fn base64_with_whitespace() {
        let xml = r#"<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
            <Reference URI="">
                <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                <DigestValue>
                    AAAAAAAA
                    AAAAAAAAAAAAAAAAAAA=
                </DigestValue>
            </Reference>
        </SignedInfo>"#;
        let doc = Document::parse(xml).unwrap();
        let si = parse_signed_info(doc.root_element()).unwrap();
        assert_eq!(si.references[0].digest_value, vec![0u8; 20]);
    }

    #[test]
    fn base64_decode_digest_accepts_xml_whitespace_chars() {
        let digest =
            base64_decode_digest("AAAA\tAAAA\rAAAA\nAAAA AAAAAAAAAAA=", DigestAlgorithm::Sha1)
                .expect("XML whitespace in DigestValue must be accepted");
        assert_eq!(digest, vec![0u8; 20]);
    }

    #[test]
    fn base64_decode_digest_rejects_non_xml_ascii_whitespace() {
        let err = base64_decode_digest(
            "AAAA\u{000C}AAAAAAAAAAAAAAAAAAAAAAA=",
            DigestAlgorithm::Sha1,
        )
        .expect_err("form-feed/vertical-tab in DigestValue must be rejected");
        assert!(matches!(err, ParseError::Base64(_)));
    }

    // ── Real-world SAML structure ────────────────────────────────────

    #[test]
    fn saml_response_signed_info() {
        let xml = r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference URI="#_resp1">
                    <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>ZmFrZQ==</ds:SignatureValue>
        </ds:Signature>"##;
        let doc = Document::parse(xml).unwrap();

        // Find SignedInfo within Signature
        let sig_node = doc.root_element();
        let signed_info_node = sig_node
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "SignedInfo")
            .unwrap();

        let si = parse_signed_info(signed_info_node).unwrap();
        assert_eq!(si.signature_method, SignatureAlgorithm::RsaSha256);
        assert_eq!(si.references.len(), 1);
        assert_eq!(si.references[0].uri.as_deref(), Some("#_resp1"));
        assert_eq!(si.references[0].transforms.len(), 2);
        assert_eq!(si.references[0].digest_value, vec![0u8; 32]);
    }
}
