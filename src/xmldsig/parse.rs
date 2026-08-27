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

use der::{
    Decode,
    asn1::{Ia5StringRef, ObjectIdentifier},
};
use roxmltree::{Document, Node};
use std::collections::BTreeMap;
use x509_cert::ext::pkix::name::DirectoryString;
use x509_cert::name::Name;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::FromDer;
use x509_parser::public_key::PublicKey;
use x509_parser::x509::X509Name;

#[cfg(test)]
use super::digest::compute_digest;
use super::digest::{DigestAlgorithm, compute_digest_with_provider, constant_time_eq};
use super::transforms::{self, Transform};
use super::whitespace::{
    XmlBase64NormalizeLimitedError, is_xml_whitespace_only, normalize_xml_base64_text,
    normalize_xml_base64_text_with_limit,
};
use super::x509::certificate_signature_matches_with_provider;
use crate::c14n::C14nAlgorithm;
use crate::c14n::xml_base::{
    XmlBaseResolutionBudget, resolve_uri_from_node_with_document_base_with_budget,
};

pub(crate) use crate::hard_limits::SIGNATURE_REFERENCE_CEILING as MAX_REFERENCES_PER_SIGNATURE;
#[cfg(test)]
use crate::hard_limits::X509_CHAIN_DEPTH_CEILING as MAX_X509_CHAIN_DEPTH;

/// XMLDSig namespace URI.
pub(crate) const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
/// XMLDSig 1.1 namespace URI.
pub(crate) const XMLDSIG11_NS: &str = "http://www.w3.org/2009/xmldsig11#";
const MAX_DER_ENCODED_KEY_VALUE_LEN: usize = 8192;
const MAX_DER_ENCODED_KEY_VALUE_TEXT_LEN: usize = 65_536;
const MAX_DER_ENCODED_KEY_VALUE_BASE64_LEN: usize = MAX_DER_ENCODED_KEY_VALUE_LEN.div_ceil(3) * 4;
const MAX_KEY_NAME_TEXT_LEN: usize = 4096;
const MAX_KEY_INFO_CHILD_COUNT: usize = 64;
const MAX_HMAC_OUTPUT_LENGTH_TEXT_LEN: usize = 32;
const MAX_RETRIEVAL_XPATH_TEXT_LEN: usize = 256;
const MAX_RSA_MODULUS_LEN: usize = 1024;
const MAX_RSA_EXPONENT_LEN: usize = 8;
pub(crate) const EC_P256_OID: &str = "1.2.840.10045.3.1.7";
pub(crate) const EC_P384_OID: &str = "1.3.132.0.34";
pub(crate) const EC_P521_OID: &str = "1.3.132.0.35";
const MAX_EC_PUBLIC_KEY_LEN: usize = 133;
const MAX_X509_BASE64_TEXT_LEN: usize = 262_144;
const MAX_X509_BASE64_NORMALIZED_LEN: usize = MAX_X509_BASE64_TEXT_LEN;
pub(crate) const MAX_X509_DECODED_BINARY_LEN: usize =
    MAX_X509_BASE64_NORMALIZED_LEN.div_ceil(4) * 3;
const MAX_X509_SUBJECT_NAME_TEXT_LEN: usize = 16_384;
const MAX_X509_ISSUER_NAME_TEXT_LEN: usize = 16_384;
const MAX_X509_SERIAL_NUMBER_RAW_TEXT_LEN: usize = 16_384;
// RFC 5280 requires consumers to handle a 20-octet unsigned serial magnitude.
// DER may add a leading sign-padding octet; XML Schema permits insignificant
// leading decimal zeroes.
const MAX_X509_SERIAL_NUMBER_VALUE_DIGITS: usize = 49;
const MAX_X509_SERIAL_NUMBER_BYTES: usize = 20;
const MAX_X509_DATA_ENTRY_COUNT: usize = 64;
pub(crate) const MAX_X509_DATA_TOTAL_BINARY_LEN: usize = 1_048_576;

/// Signature algorithms supported for signing and verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// DSA with SHA-1. Legacy algorithm disabled for signing by default.
    DsaSha1,
    /// DSA with SHA-256 as defined by XMLDSig 1.1.
    DsaSha256,
    /// HMAC with SHA-1. Legacy algorithm disabled for signing by default.
    HmacSha1,
    /// HMAC with SHA-224.
    HmacSha224,
    /// HMAC with SHA-256.
    HmacSha256,
    /// HMAC with SHA-384.
    HmacSha384,
    /// HMAC with SHA-512.
    HmacSha512,
    /// RSA with SHA-1. Legacy algorithm disabled for signing by default.
    RsaSha1,
    /// RSA with SHA-224.
    RsaSha224,
    /// RSA with SHA-256 (most common in SAML).
    RsaSha256,
    /// RSA with SHA-384.
    RsaSha384,
    /// RSA with SHA-512.
    RsaSha512,
    /// ECDSA with SHA-1; the key selects the elliptic curve.
    EcdsaSha1,
    /// ECDSA with SHA-224; the key selects the elliptic curve.
    EcdsaSha224,
    /// ECDSA with SHA-256; the key selects the elliptic curve.
    EcdsaSha256,
    /// ECDSA with SHA-384; the key selects the elliptic curve.
    EcdsaSha384,
    /// ECDSA with SHA-512; the key selects the elliptic curve.
    EcdsaSha512,
}

impl SignatureAlgorithm {
    /// Fixed XMLDSig component width for DSA's `r || s` representation.
    pub(crate) const fn dsa_component_len(self) -> Option<usize> {
        match self {
            Self::DsaSha1 => Some(20),
            Self::DsaSha256 => Some(32),
            _ => None,
        }
    }

    /// Return the full HMAC output width for HMAC algorithms.
    #[must_use]
    pub const fn hmac_output_bits(self) -> Option<usize> {
        match self {
            Self::HmacSha1 => Some(160),
            Self::HmacSha224 => Some(224),
            Self::HmacSha256 => Some(256),
            Self::HmacSha384 => Some(384),
            Self::HmacSha512 => Some(512),
            _ => None,
        }
    }

    /// Parse from an XML algorithm URI.
    #[must_use]
    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            "http://www.w3.org/2000/09/xmldsig#dsa-sha1" => Some(Self::DsaSha1),
            "http://www.w3.org/2009/xmldsig11#dsa-sha256" => Some(Self::DsaSha256),
            "http://www.w3.org/2000/09/xmldsig#hmac-sha1" => Some(Self::HmacSha1),
            "http://www.w3.org/2001/04/xmldsig-more#hmac-sha224" => Some(Self::HmacSha224),
            "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256" => Some(Self::HmacSha256),
            "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384" => Some(Self::HmacSha384),
            "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512" => Some(Self::HmacSha512),
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1" => Some(Self::RsaSha1),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224" => Some(Self::RsaSha224),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => Some(Self::RsaSha256),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => Some(Self::RsaSha384),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => Some(Self::RsaSha512),
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1" => Some(Self::EcdsaSha1),
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224" => Some(Self::EcdsaSha224),
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256" => Some(Self::EcdsaSha256),
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384" => Some(Self::EcdsaSha384),
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512" => Some(Self::EcdsaSha512),
            _ => None,
        }
    }

    /// Return the XML namespace URI.
    #[must_use]
    pub fn uri(self) -> &'static str {
        match self {
            Self::DsaSha1 => "http://www.w3.org/2000/09/xmldsig#dsa-sha1",
            Self::DsaSha256 => "http://www.w3.org/2009/xmldsig11#dsa-sha256",
            Self::HmacSha1 => "http://www.w3.org/2000/09/xmldsig#hmac-sha1",
            Self::HmacSha224 => "http://www.w3.org/2001/04/xmldsig-more#hmac-sha224",
            Self::HmacSha256 => "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
            Self::HmacSha384 => "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384",
            Self::HmacSha512 => "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512",
            Self::RsaSha1 => "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            Self::RsaSha224 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224",
            Self::RsaSha256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            Self::RsaSha384 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
            Self::RsaSha512 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
            Self::EcdsaSha1 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1",
            Self::EcdsaSha224 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224",
            Self::EcdsaSha256 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
            Self::EcdsaSha384 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
            Self::EcdsaSha512 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
        }
    }

    /// Whether this algorithm is allowed for signing (not just verification).
    #[must_use]
    pub fn signing_allowed(self) -> bool {
        !matches!(
            self,
            Self::RsaSha1 | Self::DsaSha1 | Self::HmacSha1 | Self::EcdsaSha1
        )
    }
}

/// Parsed `<SignedInfo>` element.
#[derive(Debug)]
#[non_exhaustive]
pub struct SignedInfo {
    /// Canonicalization method for SignedInfo itself.
    pub c14n_method: C14nAlgorithm,
    /// Signature algorithm.
    pub signature_method: SignatureAlgorithm,
    /// Optional byte-aligned HMAC output length in bits.
    pub hmac_output_length_bits: Option<usize>,
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

impl KeyInfo {
    /// Count key material that parsing has already materialized as candidates.
    ///
    /// This is a cardinality preflight, not a consumed resolver-work counter:
    /// resolution separately counts every candidate it actually inspects,
    /// including embedded material and caller-owned stores.
    pub(crate) fn embedded_candidate_count(&self) -> usize {
        self.sources.iter().fold(0usize, |count, source| {
            count.saturating_add(match source {
                KeyInfoSource::KeyValue(_) | KeyInfoSource::DerEncodedKeyValue(_) => 1,
                KeyInfoSource::X509Data(info) => info.certificates.len(),
                KeyInfoSource::KeyName(_)
                | KeyInfoSource::RetrievalMethod { .. }
                | KeyInfoSource::KeyInfoReference { .. } => 0,
            })
        })
    }
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
    /// `<RetrievalMethod>` URI and optional type URI.
    RetrievalMethod {
        /// RFC 3986-resolved resource identity. Same-document fragments remain unchanged.
        uri: String,
        /// Declared resource type.
        resource_type: Option<String>,
        /// Supported transform shape declared by the retrieval method.
        transforms: RetrievalMethodTransforms,
    },
    /// XMLDSig 1.1 reference to another `KeyInfo` element.
    KeyInfoReference {
        /// RFC 3986-resolved resource identity.
        uri: String,
    },
}

/// Transform forms accepted on `<RetrievalMethod>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RetrievalMethodTransforms {
    /// No transform chain is present.
    None,
    /// Filter a same-document node-set to one `ds:X509Data`-rooted subtree.
    X509DataNodeSetFilter {
        /// Original expression retained for operation policy accounting.
        expression: String,
        /// Namespace axis visible from the XPath parameter element.
        namespaces: BTreeMap<String, String>,
    },
    /// A transform chain attached to a RetrievalMethod type this implementation
    /// does not materialize. Resolvers may ignore this advisory key source and
    /// continue with later `<KeyInfo>` children.
    Unsupported,
}

/// Parsed `<KeyValue>` dispatch result.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyValueInfo {
    /// `<DSAKeyValue>` public parameters.
    Dsa {
        /// Optional prime modulus P, present only together with Q.
        p: Option<Vec<u8>>,
        /// Optional prime divisor Q, present only together with P.
        q: Option<Vec<u8>>,
        /// Optional generator G.
        g: Option<Vec<u8>>,
        /// Public value Y.
        y: Vec<u8>,
    },
    /// `<RSAKeyValue>` with unsigned big-endian CryptoBinary parameters.
    Rsa {
        /// RSA modulus.
        modulus: Vec<u8>,
        /// RSA public exponent.
        exponent: Vec<u8>,
    },
    /// `dsig11:ECKeyValue` with a supported named curve and SEC1 public point.
    Ec {
        /// Bare named-curve OID, without the XMLDSig `urn:oid:` prefix.
        curve_oid: String,
        /// Uncompressed SEC1 point (`0x04 || x || y`).
        public_key: Vec<u8>,
    },
    /// `dsig11:ECKeyValue` with unusable curve or point data.
    InvalidEcKeyValue,
    /// Any other `<KeyValue>` child not yet supported by this phase.
    Unsupported {
        /// Namespace URI of the unsupported child, when present.
        namespace: Option<String>,
        /// Local name of the unsupported child element.
        local_name: String,
    },
}

/// Parsed `<X509Data>` children.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct X509DataInfo {
    /// DER-encoded certificates from `<X509Certificate>`.
    ///
    /// This vector has a 1:1 index correspondence with `parsed_certificates`.
    pub certificates: Vec<Vec<u8>>,
    /// Text values from `<X509SubjectName>`.
    pub subject_names: Vec<String>,
    /// `(IssuerName, SerialNumber)` tuples from `<X509IssuerSerial>`.
    pub issuer_serials: Vec<(String, String)>,
    /// Raw bytes from `<X509SKI>`.
    pub skis: Vec<Vec<u8>>,
    /// DER-encoded CRLs from `<X509CRL>`.
    pub crls: Vec<Vec<u8>>,
    /// `(Algorithm URI, digest bytes)` tuples from `dsig11:X509Digest`.
    pub digests: Vec<(String, Vec<u8>)>,
    /// Parsed metadata for each `<X509Certificate>` entry.
    ///
    /// This vector has a 1:1 index correspondence with `certificates`.
    pub parsed_certificates: Vec<ParsedX509Certificate>,
    /// Ordered certificate indexes, starting with the signing certificate.
    pub certificate_chain: Vec<usize>,
}

/// Parsed X.509 certificate details extracted from DER.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParsedX509Certificate {
    /// Subject distinguished name.
    pub subject_dn: String,
    /// Issuer distinguished name.
    pub issuer_dn: String,
    /// Certificate serial number bytes.
    pub serial_number: Vec<u8>,
    /// Uppercase hexadecimal certificate serial number without separators.
    pub serial_number_hex: String,
    /// Subject Key Identifier extension bytes (if present).
    pub subject_key_identifier: Option<Vec<u8>>,
    /// Parsed certificate public key material.
    pub public_key: X509PublicKeyInfo,
}

/// Public key material extracted from certificate SubjectPublicKeyInfo.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum X509PublicKeyInfo {
    /// RSA public key (`modulus`, `exponent`).
    Rsa {
        /// Unsigned big-endian RSA modulus (`n`), normalized without leading zeroes.
        modulus: Vec<u8>,
        /// Unsigned big-endian RSA public exponent (`e`), normalized without leading zeroes.
        exponent: Vec<u8>,
    },
    /// EC public key (`curve_oid`, encoded point bytes).
    Ec {
        /// Named-curve OID from SubjectPublicKeyInfo parameters.
        curve_oid: String,
        /// Encoded EC point bytes from SubjectPublicKeyInfo.
        public_key: Vec<u8>,
    },
    /// Public key algorithm is present but not parsed into a concrete key type.
    Unsupported {
        /// SubjectPublicKeyInfo algorithm OID.
        algorithm_oid: String,
    },
}

/// Errors during XMLDSig element parsing.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// The default low-level parsing policy rejected bounded input.
    #[error("XMLDSig policy violation: {0}")]
    Policy(#[from] crate::policy::PolicyViolation),

    /// The selected cryptographic provider could not evaluate parsed key metadata.
    #[error("cryptographic provider error: {0}")]
    Provider(#[from] crate::provider::ProviderError),

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
    parse_signed_info_with_xpath_budget(
        signed_info_node,
        &mut transforms::XPathSignatureParseBudget::default(),
    )
}

pub(crate) fn parse_signed_info_with_xpath_budget(
    signed_info_node: Node,
    xpath_budget: &mut transforms::XPathSignatureParseBudget,
) -> Result<SignedInfo, ParseError> {
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
    let hmac_output_length_bits = parse_hmac_output_length(sig_method_node, signature_method)?;

    // 3. One or more Reference elements
    let mut references = Vec::new();
    for child in children {
        verify_ds_element(child, "Reference")?;
        if references.len() == crate::hard_limits::SIGNATURE_REFERENCE_CEILING {
            return Err(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::SIGNATURE_REFERENCES,
                maximum: crate::hard_limits::SIGNATURE_REFERENCE_CEILING,
                actual: references.len().saturating_add(1),
            }
            .into());
        }
        references.push(parse_reference_with_xpath_budget(child, xpath_budget)?);
    }
    if references.is_empty() {
        return Err(ParseError::MissingElement {
            element: "Reference",
        });
    }

    Ok(SignedInfo {
        c14n_method,
        signature_method,
        hmac_output_length_bits,
        references,
    })
}

fn parse_hmac_output_length(
    node: Node<'_, '_>,
    algorithm: SignatureAlgorithm,
) -> Result<Option<usize>, ParseError> {
    ensure_no_non_whitespace_text(node, "SignatureMethod")?;
    let mut children = element_children(node);
    let Some(child) = children.next() else {
        return Ok(None);
    };
    let Some(maximum_bits) = algorithm.hmac_output_bits() else {
        return Err(ParseError::InvalidStructure(
            "SignatureMethod parameters do not match the selected algorithm".into(),
        ));
    };
    if child.tag_name().namespace() != Some(XMLDSIG_NS)
        || child.tag_name().name() != "HMACOutputLength"
        || children.next().is_some()
    {
        return Err(ParseError::InvalidStructure(
            "SignatureMethod parameters do not match the selected algorithm".into(),
        ));
    }
    ensure_no_element_children(child, "HMACOutputLength")?;
    let text =
        collect_text_content_bounded(child, MAX_HMAC_OUTPUT_LENGTH_TEXT_LEN, "HMACOutputLength")?;
    let bits = text
        .trim()
        .parse::<usize>()
        .map_err(|_| ParseError::InvalidStructure("invalid HMACOutputLength".into()))?;
    // XMLDSig 1.1 section 6.3.1 requires HMAC truncation to end on a
    // byte boundary because SignatureValue is encoded as complete octets:
    // https://www.w3.org/TR/xmldsig-core1/#sec-HMAC
    if bits == 0 || bits > maximum_bits || !bits.is_multiple_of(8) {
        return Err(ParseError::InvalidStructure(format!(
            "HMACOutputLength must be a positive byte-aligned value no greater than {maximum_bits}"
        )));
    }
    Ok(Some(bits))
}

/// Parse a single `<ds:Reference>` element.
///
/// Structure: `<Transforms>?` → `<DigestMethod>` → `<DigestValue>`
pub fn parse_reference(reference_node: Node) -> Result<Reference, ParseError> {
    parse_reference_with_xpath_budget(
        reference_node,
        &mut transforms::XPathSignatureParseBudget::default(),
    )
}

pub(crate) fn parse_reference_with_xpath_budget(
    reference_node: Node,
    xpath_budget: &mut transforms::XPathSignatureParseBudget,
) -> Result<Reference, ParseError> {
    verify_ds_element(reference_node, "Reference")?;
    ensure_no_non_whitespace_text(reference_node, "Reference")?;
    let uri = reference_node.attribute("URI").map(String::from);
    let id = reference_node.attribute("Id").map(String::from);
    let ref_type = reference_node.attribute("Type").map(String::from);

    let mut children = element_children(reference_node);

    // Optional <Transforms>
    let mut transforms = Vec::new();
    let mut transform_error = None;
    let (transforms_node, digest_method_node) =
        reference_transforms_and_digest_method(&mut children)?;

    if let Some(transforms_node) = transforms_node {
        match transforms::parse_transforms_with_budget(transforms_node, xpath_budget) {
            Ok(parsed) => transforms = parsed,
            Err(error) => transform_error = Some(error),
        }
    }

    // Required <DigestMethod>
    let digest_uri = required_algorithm_attr(digest_method_node, "DigestMethod")?;
    let digest_method =
        DigestAlgorithm::from_uri(digest_uri).ok_or_else(|| ParseError::UnsupportedAlgorithm {
            uri: digest_uri.to_string(),
        })?;

    // Required <DigestValue>
    let digest_value_node = children.next().ok_or(ParseError::MissingElement {
        element: "DigestValue",
    })?;
    verify_ds_element(digest_value_node, "DigestValue")?;
    let digest_value = decode_digest_value_children(digest_value_node, digest_method)?;

    // No more children expected
    if let Some(unexpected) = children.next() {
        return Err(ParseError::InvalidStructure(format!(
            "unexpected element <{}> after <DigestValue> in <Reference>",
            unexpected.tag_name().name()
        )));
    }

    // Validate the complete Reference before reporting an unsupported transform.
    // This prevents malformed DigestMethod/DigestValue content from being
    // downgraded to a non-fatal unsupported Manifest transform result.
    if let Some(error) = transform_error {
        return Err(ParseError::Transform(error));
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

pub(crate) fn reference_digest_method(
    reference_node: Node<'_, '_>,
) -> Result<DigestAlgorithm, ParseError> {
    verify_ds_element(reference_node, "Reference")?;
    let mut children = element_children(reference_node);
    let (_, digest_method_node) = reference_transforms_and_digest_method(&mut children)?;
    let uri = required_algorithm_attr(digest_method_node, "DigestMethod")?;
    DigestAlgorithm::from_uri(uri).ok_or_else(|| ParseError::UnsupportedAlgorithm {
        uri: uri.to_owned(),
    })
}

fn reference_transforms_and_digest_method<'a, 'input>(
    children: &mut impl Iterator<Item = Node<'a, 'input>>,
) -> Result<(Option<Node<'a, 'input>>, Node<'a, 'input>), ParseError> {
    let first = children.next().ok_or(ParseError::MissingElement {
        element: "DigestMethod",
    })?;
    let transforms_node = is_ds_element(first, "Transforms").then_some(first);
    let digest_method_node = if transforms_node.is_some() {
        children.next().ok_or(ParseError::MissingElement {
            element: "DigestMethod",
        })?
    } else {
        first
    };
    verify_ds_element(digest_method_node, "DigestMethod")?;
    Ok((transforms_node, digest_method_node))
}

/// Parse `<ds:KeyInfo>` and dispatch supported child sources.
///
/// Supported source elements:
/// - `<ds:KeyName>`
/// - `<ds:KeyValue>` (dispatch by child QName; RSA and `dsig11:ECKeyValue` are parsed)
/// - `<ds:X509Data>`
/// - `<dsig11:DEREncodedKeyValue>`
///
/// Unknown top-level `<KeyInfo>` children are ignored (lax processing), while
/// unknown XMLDSig-owned (`ds:*` / `dsig11:*`) children inside `<X509Data>` are
/// rejected fail-closed.
/// `<X509Data>` may still be empty or contain only non-XMLDSig extension children.
pub fn parse_key_info(key_info_node: Node) -> Result<KeyInfo, ParseError> {
    parse_key_info_with_provider(key_info_node, crate::provider::default_provider())
}

pub(crate) fn parse_key_info_with_provider(
    key_info_node: Node,
    provider: &dyn crate::provider::CryptoProvider,
) -> Result<KeyInfo, ParseError> {
    let xml_base_budget = XmlBaseResolutionBudget::default();
    parse_key_info_with_policy_budgets(
        key_info_node,
        provider,
        &xml_base_budget,
        &crate::policy::ResourcePolicy::default(),
    )
}

pub(crate) fn parse_key_info_with_policy_budgets(
    key_info_node: Node,
    provider: &dyn crate::provider::CryptoProvider,
    xml_base_budget: &XmlBaseResolutionBudget,
    resources: &crate::policy::ResourcePolicy,
) -> Result<KeyInfo, ParseError> {
    parse_key_info_with_policy_budgets_and_document_base(
        key_info_node,
        provider,
        xml_base_budget,
        resources,
        None,
    )
}

pub(crate) fn parse_key_info_with_policy_budgets_and_document_base(
    key_info_node: Node,
    provider: &dyn crate::provider::CryptoProvider,
    xml_base_budget: &XmlBaseResolutionBudget,
    resources: &crate::policy::ResourcePolicy,
    document_base: Option<&str>,
) -> Result<KeyInfo, ParseError> {
    verify_ds_element(key_info_node, "KeyInfo")?;
    ensure_no_non_whitespace_text(key_info_node, "KeyInfo")?;

    let mut sources = Vec::new();
    let mut x509_total_binary_len = 0usize;
    // KeyInfo is parsed before source selection, so preflight the cardinality
    // of every embedded key before decoding or algorithm-specific parsing.
    // This does not consume the resolver's inspected-candidate work budget.
    let mut embedded_candidate_preflight_count = 0usize;
    for (index, child) in element_children(key_info_node).enumerate() {
        if index >= MAX_KEY_INFO_CHILD_COUNT {
            return Err(ParseError::InvalidStructure(
                "KeyInfo contains too many child elements".into(),
            ));
        }
        match (child.tag_name().namespace(), child.tag_name().name()) {
            (Some(XMLDSIG_NS), "KeyName") => {
                ensure_no_element_children(child, "KeyName")?;
                let key_name =
                    collect_text_content_bounded(child, MAX_KEY_NAME_TEXT_LEN, "KeyName")?;
                sources.push(KeyInfoSource::KeyName(key_name));
            }
            (Some(XMLDSIG_NS), "KeyValue") => {
                charge_embedded_key_candidate(&mut embedded_candidate_preflight_count, resources)?;
                let key_value = parse_key_value_dispatch(child)?;
                sources.push(KeyInfoSource::KeyValue(key_value));
            }
            (Some(XMLDSIG_NS), "X509Data") => {
                let x509 = parse_x509_data_dispatch_with_budget_and_provider(
                    child,
                    &mut x509_total_binary_len,
                    &mut embedded_candidate_preflight_count,
                    provider,
                    resources,
                )?;
                sources.push(KeyInfoSource::X509Data(x509));
            }
            (Some(XMLDSIG_NS), "RetrievalMethod") => {
                ensure_no_non_whitespace_text(child, "RetrievalMethod")?;
                let lexical_uri = child.attribute("URI").ok_or_else(|| {
                    ParseError::InvalidStructure("RetrievalMethod requires URI".into())
                })?;
                if lexical_uri.len() > MAX_KEY_NAME_TEXT_LEN {
                    return Err(ParseError::InvalidStructure(
                        "RetrievalMethod URI exceeds maximum length".into(),
                    ));
                }
                let uri = if lexical_uri.is_empty() || lexical_uri.starts_with('#') {
                    lexical_uri.to_owned()
                } else {
                    // RetrievalMethod is parsed independently from later key
                    // materialization, so retain its resolved resource identity.
                    resolve_uri_from_node_with_document_base_with_budget(
                        child,
                        lexical_uri,
                        document_base,
                        xml_base_budget,
                    )
                    .map_err(|error| ParseError::InvalidStructure(error.to_string()))?
                };
                let resource_type = child.attribute("Type");
                if resource_type.is_some_and(|value| value.len() > MAX_KEY_NAME_TEXT_LEN) {
                    return Err(ParseError::InvalidStructure(
                        "RetrievalMethod Type exceeds maximum length".into(),
                    ));
                }
                let resource_type = resource_type.map(str::to_owned);
                let transforms = if resource_type.as_deref()
                    == Some("http://www.w3.org/2000/09/xmldsig#X509Data")
                {
                    parse_retrieval_method_transforms(child, resources)?
                } else if element_children(child).next().is_some() {
                    RetrievalMethodTransforms::Unsupported
                } else {
                    RetrievalMethodTransforms::None
                };
                sources.push(KeyInfoSource::RetrievalMethod {
                    uri,
                    resource_type,
                    transforms,
                });
            }
            (Some(XMLDSIG11_NS), "DEREncodedKeyValue") => {
                charge_embedded_key_candidate(&mut embedded_candidate_preflight_count, resources)?;
                ensure_no_element_children(child, "DEREncodedKeyValue")?;
                let der = decode_der_encoded_key_value_base64(child)?;
                sources.push(KeyInfoSource::DerEncodedKeyValue(der));
            }
            (Some(XMLDSIG11_NS), "KeyInfoReference") => {
                ensure_no_element_children(child, "KeyInfoReference")?;
                ensure_no_non_whitespace_text(child, "KeyInfoReference")?;
                let lexical_uri = child.attribute("URI").ok_or_else(|| {
                    ParseError::InvalidStructure("KeyInfoReference requires URI".into())
                })?;
                if lexical_uri.is_empty() || lexical_uri.len() > MAX_KEY_NAME_TEXT_LEN {
                    return Err(ParseError::InvalidStructure(
                        "KeyInfoReference URI must be non-empty and bounded".into(),
                    ));
                }
                let uri = if lexical_uri.starts_with('#') {
                    lexical_uri.to_owned()
                } else {
                    resolve_uri_from_node_with_document_base_with_budget(
                        child,
                        lexical_uri,
                        document_base,
                        xml_base_budget,
                    )
                    .map_err(|error| ParseError::InvalidStructure(error.to_string()))?
                };
                sources.push(KeyInfoSource::KeyInfoReference { uri });
            }
            _ => {}
        }
    }

    Ok(KeyInfo { sources })
}

fn charge_embedded_key_candidate(
    embedded_key_candidates: &mut usize,
    resources: &crate::policy::ResourcePolicy,
) -> Result<(), ParseError> {
    *embedded_key_candidates = embedded_key_candidates.saturating_add(1);
    resources.validate_key_candidates(*embedded_key_candidates)?;
    Ok(())
}

fn parse_retrieval_method_transforms(
    node: Node<'_, '_>,
    resources: &crate::policy::ResourcePolicy,
) -> Result<RetrievalMethodTransforms, ParseError> {
    let mut children = element_children(node);
    let Some(transforms) = children.next() else {
        return Ok(RetrievalMethodTransforms::None);
    };
    if children.next().is_some()
        || transforms.tag_name().namespace() != Some(XMLDSIG_NS)
        || transforms.tag_name().name() != "Transforms"
    {
        return Err(ParseError::InvalidStructure(
            "RetrievalMethod accepts only one optional ds:Transforms child".into(),
        ));
    }
    ensure_no_non_whitespace_text(transforms, "Transforms")?;
    let mut transform_children = element_children(transforms);
    let transform = transform_children.next().ok_or_else(|| {
        ParseError::InvalidStructure("RetrievalMethod Transforms must not be empty".into())
    })?;
    if transform_children.next().is_some()
        || transform.tag_name().namespace() != Some(XMLDSIG_NS)
        || transform.tag_name().name() != "Transform"
        || transform.attribute("Algorithm") != Some(transforms::XPATH_TRANSFORM_URI)
    {
        return Err(ParseError::InvalidStructure(
            "unsupported RetrievalMethod transform chain".into(),
        ));
    }
    ensure_no_non_whitespace_text(transform, "Transform")?;
    let mut parameters = element_children(transform);
    let xpath = parameters.next().ok_or_else(|| {
        ParseError::InvalidStructure("RetrievalMethod XPath parameter is missing".into())
    })?;
    if parameters.next().is_some()
        || xpath.tag_name().namespace() != Some(XMLDSIG_NS)
        || xpath.tag_name().name() != "XPath"
    {
        return Err(ParseError::InvalidStructure(
            "unsupported RetrievalMethod transform chain".into(),
        ));
    }
    ensure_no_element_children(xpath, "XPath")?;
    let expression =
        collect_text_content_bounded(xpath, MAX_RETRIEVAL_XPATH_TEXT_LEN, "RetrievalMethod XPath")?;
    let normalized_expression = expression.trim();
    let selects_x509_data = normalized_expression
        .strip_prefix("ancestor-or-self::")
        .and_then(|step| step.split_once(':'))
        .is_some_and(|(prefix, local)| {
            local == "X509Data" && xpath.lookup_namespace_uri(Some(prefix)) == Some(XMLDSIG_NS)
        });
    if !selects_x509_data {
        return Err(ParseError::InvalidStructure(
            "unsupported RetrievalMethod XPath selection".into(),
        ));
    }
    let namespaces = transforms::collect_xpath_namespaces_with_resources(xpath, resources)?;
    Ok(RetrievalMethodTransforms::X509DataNodeSetFilter {
        expression,
        namespaces,
    })
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

/// Verify that a node is a `<dsig11:{expected_name}>` element.
fn verify_dsig11_element(node: Node, expected_name: &'static str) -> Result<(), ParseError> {
    if !node.is_element() {
        return Err(ParseError::InvalidStructure(format!(
            "expected element <{expected_name}>, got non-element node"
        )));
    }
    let tag = node.tag_name();
    if tag.name() != expected_name || tag.namespace() != Some(XMLDSIG11_NS) {
        return Err(ParseError::InvalidStructure(format!(
            "expected <dsig11:{expected_name}>, got <{}{}>",
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
        (Some(XMLDSIG_NS), "RSAKeyValue") => parse_rsa_key_value(first_child),
        (Some(XMLDSIG_NS), "DSAKeyValue") => parse_dsa_key_value(first_child),
        (Some(XMLDSIG11_NS), "ECKeyValue") => parse_ec_key_value(first_child),
        (namespace, child_name) => Ok(KeyValueInfo::Unsupported {
            namespace: namespace.map(str::to_string),
            local_name: child_name.to_string(),
        }),
    }
}

fn parse_dsa_key_value(node: Node<'_, '_>) -> Result<KeyValueInfo, ParseError> {
    verify_ds_element(node, "DSAKeyValue")?;
    ensure_no_non_whitespace_text(node, "DSAKeyValue")?;
    let children = element_children(node).collect::<Vec<_>>();
    let mut index = 0;
    let p = take_dsa_crypto_binary(&children, &mut index, "P")?;
    let q = take_dsa_crypto_binary(&children, &mut index, "Q")?;
    if p.is_some() != q.is_some() {
        return Err(ParseError::InvalidStructure(
            "DSAKeyValue P and Q must be present together".into(),
        ));
    }
    let g = take_dsa_crypto_binary(&children, &mut index, "G")?;
    let y = take_dsa_crypto_binary(&children, &mut index, "Y")?
        .ok_or_else(|| ParseError::InvalidStructure("DSAKeyValue requires Y".into()))?;
    let _j = take_dsa_crypto_binary(&children, &mut index, "J")?;
    let seed = take_dsa_crypto_binary(&children, &mut index, "Seed")?;
    let counter = take_dsa_crypto_binary(&children, &mut index, "PgenCounter")?;
    if seed.is_some() != counter.is_some() {
        return Err(ParseError::InvalidStructure(
            "DSAKeyValue Seed and PgenCounter must be present together".into(),
        ));
    }
    if index != children.len() {
        return Err(ParseError::InvalidStructure(
            "DSAKeyValue children do not match the XMLDSig schema order".into(),
        ));
    }
    Ok(KeyValueInfo::Dsa { p, q, g, y })
}

fn take_dsa_crypto_binary(
    children: &[Node<'_, '_>],
    index: &mut usize,
    name: &'static str,
) -> Result<Option<Vec<u8>>, ParseError> {
    let Some(&child) = children.get(*index) else {
        return Ok(None);
    };
    if !is_ds_element(child, name) {
        return Ok(None);
    }
    *index += 1;
    ensure_no_element_children(child, name)?;
    decode_crypto_binary(child, name, MAX_RSA_MODULUS_LEN).map(Some)
}

fn is_ds_element(node: Node<'_, '_>, name: &str) -> bool {
    node.tag_name().namespace() == Some(XMLDSIG_NS) && node.tag_name().name() == name
}

fn parse_ec_key_value(node: Node<'_, '_>) -> Result<KeyValueInfo, ParseError> {
    verify_dsig11_element(node, "ECKeyValue")?;
    ensure_no_non_whitespace_text(node, "ECKeyValue")?;

    let mut children = element_children(node);
    let Some(named_curve_node) = children.next() else {
        return Ok(KeyValueInfo::InvalidEcKeyValue);
    };
    if named_curve_node.tag_name().namespace() == Some(XMLDSIG11_NS)
        && named_curve_node.tag_name().name() == "ECParameters"
    {
        return Ok(KeyValueInfo::Unsupported {
            namespace: Some(XMLDSIG11_NS.to_string()),
            local_name: "ECKeyValue".into(),
        });
    }
    if named_curve_node.tag_name().namespace() != Some(XMLDSIG11_NS)
        || named_curve_node.tag_name().name() != "NamedCurve"
    {
        return Ok(KeyValueInfo::InvalidEcKeyValue);
    }
    ensure_no_element_children(named_curve_node, "NamedCurve")?;
    ensure_no_non_whitespace_text(named_curve_node, "NamedCurve")?;
    let Some((curve_oid, expected_public_key_len)) =
        (match parse_ec_named_curve_oid(named_curve_node) {
            Ok(curve) => curve,
            Err(_) => return Ok(KeyValueInfo::InvalidEcKeyValue),
        })
    else {
        return Ok(KeyValueInfo::Unsupported {
            namespace: Some(XMLDSIG11_NS.to_string()),
            local_name: "ECKeyValue".into(),
        });
    };

    let Some(public_key_node) = children.next() else {
        return Ok(KeyValueInfo::InvalidEcKeyValue);
    };
    if public_key_node.tag_name().namespace() != Some(XMLDSIG11_NS)
        || public_key_node.tag_name().name() != "PublicKey"
    {
        return Ok(KeyValueInfo::InvalidEcKeyValue);
    }
    ensure_no_element_children(public_key_node, "PublicKey")?;
    if children.next().is_some() {
        return Ok(KeyValueInfo::InvalidEcKeyValue);
    }

    let public_key = match decode_crypto_binary(public_key_node, "PublicKey", MAX_EC_PUBLIC_KEY_LEN)
    {
        Ok(public_key) => public_key,
        Err(_) => return Ok(KeyValueInfo::InvalidEcKeyValue),
    };
    if validate_ec_public_key_point(&public_key, expected_public_key_len).is_err() {
        return Ok(KeyValueInfo::InvalidEcKeyValue);
    }

    Ok(KeyValueInfo::Ec {
        curve_oid,
        public_key,
    })
}

fn parse_ec_named_curve_oid(node: Node<'_, '_>) -> Result<Option<(String, usize)>, ParseError> {
    let uri = node.attribute("URI").ok_or_else(|| {
        ParseError::InvalidStructure("ECKeyValue NamedCurve must include URI attribute".into())
    })?;
    let curve_oid = uri.strip_prefix("urn:oid:").unwrap_or(uri);
    if curve_oid.is_empty() {
        return Err(ParseError::InvalidStructure(
            "ECKeyValue NamedCurve URI must not be empty".into(),
        ));
    }
    let Some(public_key_len) = ec_public_key_len(curve_oid) else {
        return Ok(None);
    };
    Ok(Some((curve_oid.to_string(), public_key_len)))
}

fn ec_public_key_len(curve_oid: &str) -> Option<usize> {
    match curve_oid {
        EC_P256_OID => Some(65),
        EC_P384_OID => Some(97),
        EC_P521_OID => Some(133),
        _ => None,
    }
}

fn validate_ec_public_key_point(public_key: &[u8], expected_len: usize) -> Result<(), ParseError> {
    if public_key.len() != expected_len {
        return Err(ParseError::InvalidStructure(
            "ECKeyValue PublicKey length does not match NamedCurve".into(),
        ));
    }
    if public_key.first().copied() != Some(0x04) {
        return Err(ParseError::InvalidStructure(
            "ECKeyValue PublicKey must be an uncompressed SEC1 point".into(),
        ));
    }
    Ok(())
}

fn parse_rsa_key_value(node: Node<'_, '_>) -> Result<KeyValueInfo, ParseError> {
    verify_ds_element(node, "RSAKeyValue")?;
    ensure_no_non_whitespace_text(node, "RSAKeyValue")?;

    let mut children = element_children(node);
    let modulus_node = children.next().ok_or_else(|| {
        ParseError::InvalidStructure("RSAKeyValue requires Modulus and Exponent".into())
    })?;
    verify_ds_element(modulus_node, "Modulus")?;
    ensure_no_element_children(modulus_node, "Modulus")?;

    let exponent_node = children.next().ok_or_else(|| {
        ParseError::InvalidStructure("RSAKeyValue requires Modulus and Exponent".into())
    })?;
    verify_ds_element(exponent_node, "Exponent")?;
    ensure_no_element_children(exponent_node, "Exponent")?;
    if children.next().is_some() {
        return Err(ParseError::InvalidStructure(
            "RSAKeyValue must contain exactly Modulus followed by Exponent".into(),
        ));
    }

    Ok(KeyValueInfo::Rsa {
        modulus: decode_crypto_binary(modulus_node, "Modulus", MAX_RSA_MODULUS_LEN)?,
        exponent: decode_crypto_binary(exponent_node, "Exponent", MAX_RSA_EXPONENT_LEN)?,
    })
}

fn decode_crypto_binary(
    node: Node<'_, '_>,
    element_name: &'static str,
    max_decoded_len: usize,
) -> Result<Vec<u8>, ParseError> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    let max_base64_len = max_decoded_len.div_ceil(3) * 4;
    let mut cleaned = String::with_capacity(max_base64_len);
    for text in node
        .children()
        .filter(|child| child.is_text())
        .filter_map(|child| child.text())
    {
        normalize_xml_base64_text_with_limit(text, &mut cleaned, max_base64_len).map_err(
            |err| match err {
                XmlBase64NormalizeLimitedError::InvalidWhitespace(err) => {
                    ParseError::Base64(format!(
                        "invalid XML whitespace U+{:04X} in {element_name}",
                        err.invalid_byte
                    ))
                }
                XmlBase64NormalizeLimitedError::TooLong(_) => ParseError::InvalidStructure(
                    format!("{element_name} exceeds maximum allowed base64 length"),
                ),
            },
        )?;
    }

    let value = STANDARD
        .decode(&cleaned)
        .map_err(|err| ParseError::Base64(format!("{element_name}: {err}")))?;
    if value.is_empty() {
        return Err(ParseError::InvalidStructure(format!(
            "{element_name} must not be empty"
        )));
    }
    if value.len() > max_decoded_len {
        return Err(ParseError::InvalidStructure(format!(
            "{element_name} exceeds maximum allowed binary length"
        )));
    }
    Ok(value)
}

pub(crate) fn parse_x509_data_dispatch_with_budget_and_provider(
    node: Node,
    total_binary_len: &mut usize,
    embedded_key_candidates: &mut usize,
    provider: &dyn crate::provider::CryptoProvider,
    resources: &crate::policy::ResourcePolicy,
) -> Result<X509DataInfo, ParseError> {
    verify_ds_element(node, "X509Data")?;
    ensure_no_non_whitespace_text(node, "X509Data")?;

    let mut info = X509DataInfo::default();
    for child in element_children(node) {
        match (child.tag_name().namespace(), child.tag_name().name()) {
            (Some(XMLDSIG_NS), "X509Certificate") => {
                charge_embedded_key_candidate(embedded_key_candidates, resources)?;
                ensure_no_element_children(child, "X509Certificate")?;
                ensure_x509_data_entry_budget(&info)?;
                let cert = decode_x509_base64(child, "X509Certificate")?;
                add_x509_data_usage(total_binary_len, cert.len())?;
                let parsed_cert = parse_x509_certificate(cert.as_slice())?;
                info.parsed_certificates.push(parsed_cert);
                info.certificates.push(cert);
            }
            (Some(XMLDSIG_NS), "X509SubjectName") => {
                ensure_no_element_children(child, "X509SubjectName")?;
                ensure_x509_data_entry_budget(&info)?;
                let subject_name = collect_text_content_bounded(
                    child,
                    MAX_X509_SUBJECT_NAME_TEXT_LEN,
                    "X509SubjectName",
                )?;
                info.subject_names.push(subject_name);
            }
            (Some(XMLDSIG_NS), "X509IssuerSerial") => {
                ensure_x509_data_entry_budget(&info)?;
                let issuer_serial = parse_x509_issuer_serial(child)?;
                info.issuer_serials.push(issuer_serial);
            }
            (Some(XMLDSIG_NS), "X509SKI") => {
                ensure_no_element_children(child, "X509SKI")?;
                ensure_x509_data_entry_budget(&info)?;
                let ski = decode_x509_base64(child, "X509SKI")?;
                add_x509_data_usage(total_binary_len, ski.len())?;
                info.skis.push(ski);
            }
            (Some(XMLDSIG_NS), "X509CRL") => {
                ensure_no_element_children(child, "X509CRL")?;
                ensure_x509_data_entry_budget(&info)?;
                let crl = decode_x509_base64(child, "X509CRL")?;
                add_x509_data_usage(total_binary_len, crl.len())?;
                info.crls.push(crl);
            }
            (Some(XMLDSIG11_NS), "X509Digest") => {
                ensure_no_element_children(child, "X509Digest")?;
                ensure_x509_data_entry_budget(&info)?;
                let algorithm = required_algorithm_attr(child, "X509Digest")?;
                let digest = decode_x509_base64(child, "X509Digest")?;
                add_x509_data_usage(total_binary_len, digest.len())?;
                info.digests.push((algorithm.to_string(), digest));
            }
            (Some(XMLDSIG_NS), child_name) | (Some(XMLDSIG11_NS), child_name) => {
                return Err(ParseError::InvalidStructure(format!(
                    "X509Data contains unsupported XMLDSig child element <{child_name}>"
                )));
            }
            _ => {}
        }
    }

    info.certificate_chain = build_x509_certificate_chain(&info, provider)?;
    Ok(info)
}

fn build_x509_certificate_chain(
    info: &X509DataInfo,
    provider: &dyn crate::provider::CryptoProvider,
) -> Result<Vec<usize>, ParseError> {
    if info.parsed_certificates.is_empty() {
        return Ok(Vec::new());
    }

    let signing_idx = select_x509_signing_certificate(info, provider)?;
    build_x509_certificate_chain_from(info, signing_idx, provider).map_err(ParseError::from)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum X509ChainBuildError {
    InconsistentMetadata,
    DepthExceeded,
    Cycle,
    IssuerSignatureMismatch,
    AmbiguousIssuer,
    UnsupportedSignatureAlgorithm { oid: String },
    Provider(crate::provider::ProviderError),
}

impl From<X509ChainBuildError> for ParseError {
    fn from(error: X509ChainBuildError) -> Self {
        let reason = match error {
            X509ChainBuildError::InconsistentMetadata => {
                "X509Data certificate metadata is inconsistent"
            }
            X509ChainBuildError::DepthExceeded => {
                "X509Data certificate chain exceeds maximum depth"
            }
            X509ChainBuildError::Cycle => "X509Data certificate chain contains a cycle",
            X509ChainBuildError::IssuerSignatureMismatch => {
                "X509Data issuer candidates do not verify the certificate signature"
            }
            X509ChainBuildError::AmbiguousIssuer => {
                "X509Data certificate chain contains ambiguous issuer certificates"
            }
            X509ChainBuildError::UnsupportedSignatureAlgorithm { oid } => {
                return Self::InvalidStructure(format!(
                    "X509Data certificate chain uses unsupported signature algorithm {oid}"
                ));
            }
            X509ChainBuildError::Provider(error) => return Self::Provider(error),
        };
        Self::InvalidStructure(reason.into())
    }
}

/// Order an available certificate pool from a preselected signing certificate.
pub(crate) fn build_x509_certificate_chain_from(
    info: &X509DataInfo,
    signing_idx: usize,
    provider: &dyn crate::provider::CryptoProvider,
) -> Result<Vec<usize>, X509ChainBuildError> {
    if signing_idx >= info.parsed_certificates.len()
        || info.parsed_certificates.len() != info.certificates.len()
    {
        return Err(X509ChainBuildError::InconsistentMetadata);
    }
    let mut chain = vec![signing_idx];

    loop {
        let current_idx = *chain
            .last()
            .expect("chain starts with signing certificate index");
        let current = &info.parsed_certificates[current_idx];
        if distinguished_names_equal(&current.subject_dn, &current.issuer_dn) {
            break;
        }

        let candidates = info
            .parsed_certificates
            .iter()
            .enumerate()
            .filter(|(idx, cert)| {
                *idx != current_idx
                    && distinguished_names_equal(&cert.subject_dn, &current.issuer_dn)
            })
            .map(|(idx, _)| idx)
            .collect::<Vec<_>>();

        let issuer_idx = match candidates.as_slice() {
            [] => break,
            [issuer_idx] => *issuer_idx,
            _ => {
                let mut verified = Vec::new();
                let mut unsupported_oid = None;
                for issuer_idx in candidates {
                    match certificate_signature_matches_with_provider(
                        &info.certificates[current_idx],
                        &info.certificates[issuer_idx],
                        provider,
                    ) {
                        Ok(true) => verified.push(issuer_idx),
                        Ok(false) => {}
                        Err(super::X509ChainError::Provider(
                            crate::provider::ProviderError::Unsupported {
                                operation: crate::provider::ProviderOperation::VerifyCertificate,
                                algorithm: Some(oid),
                            },
                        )) => {
                            unsupported_oid.get_or_insert(oid);
                        }
                        Err(super::X509ChainError::Provider(error)) => {
                            return Err(X509ChainBuildError::Provider(error));
                        }
                        Err(super::X509ChainError::UnsupportedSignatureAlgorithm { oid }) => {
                            unsupported_oid.get_or_insert(oid);
                        }
                        Err(_) => return Err(X509ChainBuildError::IssuerSignatureMismatch),
                    }
                }
                match verified.as_slice() {
                    [issuer_idx] => *issuer_idx,
                    [] => {
                        if let Some(oid) = unsupported_oid {
                            return Err(X509ChainBuildError::UnsupportedSignatureAlgorithm { oid });
                        }
                        return Err(X509ChainBuildError::IssuerSignatureMismatch);
                    }
                    _ => return Err(X509ChainBuildError::AmbiguousIssuer),
                }
            }
        };
        if chain.contains(&issuer_idx) {
            return Err(X509ChainBuildError::Cycle);
        }
        if chain.len() == crate::hard_limits::X509_CHAIN_DEPTH_CEILING {
            return Err(X509ChainBuildError::DepthExceeded);
        }
        chain.push(issuer_idx);
    }

    Ok(chain)
}

/// Enumerate signature-valid certificate paths that terminate at a certificate
/// in the trusted prefix. Trust and certificate policy are intentionally not
/// assigned here; callers must fully validate every returned candidate.
pub(crate) fn build_x509_certificate_paths_to_trusted_prefix(
    info: &X509DataInfo,
    signing_idx: usize,
    trusted_prefix_len: usize,
    max_depth: usize,
    max_candidate_paths: usize,
    provider: &dyn crate::provider::CryptoProvider,
) -> Result<Vec<Vec<usize>>, X509ChainBuildError> {
    if trusted_prefix_len > info.certificates.len() {
        return Err(X509ChainBuildError::InconsistentMetadata);
    }
    build_x509_certificate_paths(
        info,
        signing_idx,
        |index| index < trusted_prefix_len,
        false,
        max_depth,
        max_candidate_paths,
        provider,
    )
}

/// Enumerate signature-valid paths that reach any candidate selector target.
/// A matching intermediate is retained as a candidate and traversal continues
/// so callers can test selector categories against every longer path as well.
pub(crate) fn build_x509_certificate_paths_to_selector_targets(
    info: &X509DataInfo,
    signing_idx: usize,
    targets: &[usize],
    max_depth: usize,
    max_candidate_paths: usize,
    provider: &dyn crate::provider::CryptoProvider,
) -> Result<Vec<Vec<usize>>, X509ChainBuildError> {
    if targets
        .iter()
        .any(|index| *index >= info.certificates.len())
    {
        return Err(X509ChainBuildError::InconsistentMetadata);
    }
    build_x509_certificate_paths(
        info,
        signing_idx,
        |index| targets.contains(&index),
        true,
        max_depth,
        max_candidate_paths,
        provider,
    )
}

fn build_x509_certificate_paths(
    info: &X509DataInfo,
    signing_idx: usize,
    is_terminal: impl Fn(usize) -> bool,
    continue_after_terminal: bool,
    max_depth: usize,
    max_candidate_paths: usize,
    provider: &dyn crate::provider::CryptoProvider,
) -> Result<Vec<Vec<usize>>, X509ChainBuildError> {
    if signing_idx >= info.parsed_certificates.len()
        || info.parsed_certificates.len() != info.certificates.len()
    {
        return Err(X509ChainBuildError::InconsistentMetadata);
    }
    if max_candidate_paths == 0 {
        return Err(X509ChainBuildError::AmbiguousIssuer);
    }

    let mut pending = vec![vec![signing_idx]];
    let mut completed = Vec::new();
    let mut generated_paths = 1usize;
    let mut depth_exceeded = false;
    let mut unsupported_oid = None;
    let mut issuer_cache = vec![None; info.parsed_certificates.len()];
    while let Some(path) = pending.pop() {
        let current_idx = *path
            .last()
            .expect("candidate path starts with signing certificate index");
        if is_terminal(current_idx) {
            completed.push(path.clone());
            if !continue_after_terminal {
                continue;
            }
        }
        if path.len() == max_depth {
            depth_exceeded = true;
            continue;
        }

        let current = &info.parsed_certificates[current_idx];
        if issuer_cache[current_idx].is_none() {
            let mut verified = Vec::new();
            for (issuer_idx, issuer) in info.parsed_certificates.iter().enumerate() {
                if !distinguished_names_equal(&issuer.subject_dn, &current.issuer_dn) {
                    continue;
                }
                match certificate_signature_matches_with_provider(
                    &info.certificates[current_idx],
                    &info.certificates[issuer_idx],
                    provider,
                ) {
                    Ok(true) => verified.push(issuer_idx),
                    Ok(false) => {}
                    Err(super::X509ChainError::Provider(
                        crate::provider::ProviderError::Unsupported {
                            operation: crate::provider::ProviderOperation::VerifyCertificate,
                            algorithm: Some(oid),
                        },
                    )) => {
                        // Provider capability can depend on the issuer SPKI,
                        // so retain the diagnostic but try every same-DN key.
                        unsupported_oid.get_or_insert(oid);
                        continue;
                    }
                    Err(super::X509ChainError::Provider(error)) => {
                        return Err(X509ChainBuildError::Provider(error));
                    }
                    Err(super::X509ChainError::UnsupportedSignatureAlgorithm { oid }) => {
                        // The mapper rejected this child's AlgorithmIdentifier;
                        // no issuer candidate can alter it on the current path.
                        unsupported_oid.get_or_insert(oid);
                        break;
                    }
                    Err(_) => return Err(X509ChainBuildError::IssuerSignatureMismatch),
                }
            }
            issuer_cache[current_idx] = Some(verified);
        }
        let issuers = issuer_cache[current_idx]
            .as_ref()
            .expect("issuer cache entry was initialized");
        let issuers = issuers
            .iter()
            .copied()
            .filter(|issuer_idx| !path.contains(issuer_idx))
            .collect::<Vec<_>>();
        if generated_paths.saturating_add(issuers.len()) > max_candidate_paths {
            return Err(X509ChainBuildError::AmbiguousIssuer);
        }
        generated_paths += issuers.len();
        for issuer_idx in issuers {
            let mut candidate = path.clone();
            candidate.push(issuer_idx);
            pending.push(candidate);
        }
    }

    if completed.is_empty() {
        if let Some(oid) = unsupported_oid {
            return Err(X509ChainBuildError::UnsupportedSignatureAlgorithm { oid });
        }
        if depth_exceeded {
            return Err(X509ChainBuildError::DepthExceeded);
        }
    }
    Ok(completed)
}

fn select_x509_signing_certificate(
    info: &X509DataInfo,
    provider: &dyn crate::provider::CryptoProvider,
) -> Result<usize, ParseError> {
    let has_lookup_identifiers = x509_data_has_lookup_identifiers(info);
    let mut candidates = Vec::new();
    if has_lookup_identifiers {
        for (idx, (parsed, der)) in info
            .parsed_certificates
            .iter()
            .zip(&info.certificates)
            .enumerate()
        {
            if x509_certificate_matches_any_selector(info, parsed, der, provider)? {
                candidates.push(idx);
            }
        }
        if !x509_selector_categories_match_chain(info, provider)? {
            return Err(ParseError::InvalidStructure(
                "X509Data lookup identifiers do not match the embedded certificate chain".into(),
            ));
        }
    }

    match candidates.as_slice() {
        [idx] => return Ok(*idx),
        [] if has_lookup_identifiers => {
            return Err(ParseError::InvalidStructure(
                "X509Data lookup identifiers do not match any embedded certificate".into(),
            ));
        }
        [] => {}
        _ => {}
    }

    let leaf_candidates = info
        .parsed_certificates
        .iter()
        .enumerate()
        .filter(|(_, cert)| {
            !distinguished_names_equal(&cert.subject_dn, &cert.issuer_dn)
                && !info
                    .parsed_certificates
                    .iter()
                    .any(|other| distinguished_names_equal(&other.issuer_dn, &cert.subject_dn))
        })
        .map(|(idx, _)| idx)
        .collect::<Vec<_>>();

    let selected_leaves = leaf_candidates
        .iter()
        .filter(|idx| !has_lookup_identifiers || candidates.contains(idx))
        .copied()
        .collect::<Vec<_>>();

    match selected_leaves.as_slice() {
        [idx] => Ok(*idx),
        [] if !has_lookup_identifiers => Ok(0),
        [] => Err(ParseError::InvalidStructure(
            "X509Data lookup identifiers match multiple certificates without a unique signing certificate"
                .into(),
        )),
        _ => Err(ParseError::InvalidStructure(
            if has_lookup_identifiers {
                "X509Data lookup identifiers match multiple certificates"
            } else {
                "X509Data contains multiple possible signing certificates"
            }
            .into(),
        )),
    }
}

pub(crate) fn x509_data_has_lookup_identifiers(info: &X509DataInfo) -> bool {
    !info.subject_names.is_empty()
        || !info.issuer_serials.is_empty()
        || !info.skis.is_empty()
        || !info.digests.is_empty()
}

pub(crate) fn x509_certificate_matches_any_selector(
    info: &X509DataInfo,
    certificate: &ParsedX509Certificate,
    certificate_der: &[u8],
    provider: &dyn crate::provider::CryptoProvider,
) -> Result<bool, ParseError> {
    let subject_match = info
        .subject_names
        .iter()
        .any(|subject| distinguished_names_equal(subject, &certificate.subject_dn));
    let mut issuer_serial_match = false;
    for (issuer, serial) in &info.issuer_serials {
        let serial_hex = x509_serial_decimal_to_hex(serial).ok_or_else(|| {
            ParseError::InvalidStructure(
                "X509Data lookup identifiers contain an invalid serial number".into(),
            )
        })?;
        issuer_serial_match |= distinguished_names_equal(issuer, &certificate.issuer_dn)
            && serial_hex == certificate.serial_number_hex;
    }
    let ski_match = certificate
        .subject_key_identifier
        .as_ref()
        .is_some_and(|certificate_ski| info.skis.iter().any(|ski| ski == certificate_ski));
    let mut digest_match = false;
    for (algorithm_uri, expected) in &info.digests {
        let algorithm = DigestAlgorithm::from_uri(algorithm_uri).ok_or_else(|| {
            ParseError::UnsupportedAlgorithm {
                uri: algorithm_uri.clone(),
            }
        })?;
        digest_match |= constant_time_eq(
            &compute_digest_with_provider(provider, algorithm, certificate_der)?,
            expected,
        );
    }
    Ok(subject_match || issuer_serial_match || ski_match || digest_match)
}

/// Match every selector asserted by `X509Data` against one configured certificate.
///
/// This supports XMLDSig lookup-only `X509Data`, where the document identifies a
/// certificate without embedding it. All selector values are constraints and must
/// match the same candidate certificate.
pub fn x509_certificate_matches_selectors(
    info: &X509DataInfo,
    certificate_der: &[u8],
    provider: &dyn crate::provider::CryptoProvider,
) -> Result<bool, ParseError> {
    let mut candidate = info.clone();
    candidate.certificates = vec![certificate_der.to_vec()];
    candidate.parsed_certificates = vec![parse_x509_certificate(certificate_der)?];
    candidate.certificate_chain = vec![0];
    x509_selector_categories_match_chain(&candidate, provider)
}

pub(crate) fn x509_selector_categories_match_chain(
    info: &X509DataInfo,
    provider: &dyn crate::provider::CryptoProvider,
) -> Result<bool, ParseError> {
    let subject_match = info.subject_names.iter().all(|subject| {
        info.parsed_certificates
            .iter()
            .any(|certificate| distinguished_names_equal(subject, &certificate.subject_dn))
    });

    let mut issuer_serial_match = true;
    for (issuer, serial) in &info.issuer_serials {
        let serial_hex = x509_serial_decimal_to_hex(serial).ok_or_else(|| {
            ParseError::InvalidStructure(
                "X509Data lookup identifiers contain an invalid serial number".into(),
            )
        })?;
        issuer_serial_match &= info.parsed_certificates.iter().any(|certificate| {
            distinguished_names_equal(issuer, &certificate.issuer_dn)
                && serial_hex == certificate.serial_number_hex
        });
    }

    let ski_match = info.skis.iter().all(|ski| {
        info.parsed_certificates.iter().any(|certificate| {
            certificate
                .subject_key_identifier
                .as_ref()
                .is_some_and(|certificate_ski| ski == certificate_ski)
        })
    });

    let mut digest_match = true;
    for (algorithm_uri, expected) in &info.digests {
        let algorithm = DigestAlgorithm::from_uri(algorithm_uri).ok_or_else(|| {
            ParseError::UnsupportedAlgorithm {
                uri: algorithm_uri.clone(),
            }
        })?;
        let mut category_match = false;
        for certificate in &info.certificates {
            category_match |= constant_time_eq(
                &compute_digest_with_provider(provider, algorithm, certificate)?,
                expected,
            );
        }
        digest_match &= category_match;
    }

    Ok(subject_match && issuer_serial_match && ski_match && digest_match)
}

fn x509_attribute_values_equal(
    left: &x509_cert::attr::AttributeTypeAndValue,
    right: &x509_cert::attr::AttributeTypeAndValue,
) -> bool {
    if left.oid != right.oid {
        return false;
    }
    const EMAIL_ADDRESS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.1");
    const DOMAIN_COMPONENT: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("0.9.2342.19200300.100.1.25");
    if left.oid == EMAIL_ADDRESS {
        let (Ok(left), Ok(right)) = (
            Ia5StringRef::try_from(&left.value),
            Ia5StringRef::try_from(&right.value),
        ) else {
            return false;
        };
        let (Some((left_local, left_domain)), Some((right_local, right_domain))) = (
            left.as_str().rsplit_once('@'),
            right.as_str().rsplit_once('@'),
        ) else {
            return false;
        };
        return left_local == right_local && left_domain.eq_ignore_ascii_case(right_domain);
    }
    if left.oid == DOMAIN_COMPONENT {
        let (Ok(left), Ok(right)) = (
            Ia5StringRef::try_from(&left.value),
            Ia5StringRef::try_from(&right.value),
        ) else {
            return false;
        };
        return left.as_str().eq_ignore_ascii_case(right.as_str());
    }
    match (
        DirectoryString::try_from(&left.value),
        DirectoryString::try_from(&right.value),
    ) {
        (Ok(left), Ok(right)) => {
            // RFC 5280 section 7.1 requires caseIgnoreMatch with LDAP/X.520
            // string preparation for PrintableString and UTF8String names.
            let Ok(left) =
                x520_stringprep::x520_stringprep_to_case_ignore_string(left.value().as_ref())
            else {
                return false;
            };
            let Ok(right) =
                x520_stringprep::x520_stringprep_to_case_ignore_string(right.value().as_ref())
            else {
                return false;
            };
            left.trim_matches(' ') == right.trim_matches(' ')
        }
        _ => left.value == right.value,
    }
}

fn x509_rdns_equal(
    left: &x509_cert::name::RelativeDistinguishedName,
    right: &x509_cert::name::RelativeDistinguishedName,
) -> bool {
    if left.len() != right.len() {
        return false;
    }
    // A DN is an ordered RDN sequence, but each individual RDN is a set.
    let right = right.iter().collect::<Vec<_>>();
    let mut matched = vec![false; right.len()];
    left.iter().all(|left_attribute| {
        right
            .iter()
            .enumerate()
            .find(|(index, right_attribute)| {
                !matched[*index] && x509_attribute_values_equal(left_attribute, right_attribute)
            })
            .is_some_and(|(index, _)| {
                matched[index] = true;
                true
            })
    })
}

fn trailing_whitespace_is_escaped(value: &str) -> bool {
    let Some((&last, prefix)) = value.as_bytes().split_last() else {
        return false;
    };
    if !matches!(last, b' ' | b'\t' | b'\r' | b'\n') {
        return false;
    }
    prefix
        .iter()
        .rev()
        .take_while(|byte| **byte == b'\\')
        .count()
        % 2
        == 1
}

fn parse_distinguished_name(value: &str) -> Option<Name> {
    let mut normalized = String::with_capacity(value.len());
    let mut chars = value
        .trim_start_matches([' ', '\t', '\r', '\n'])
        .chars()
        .peekable();
    let mut escaped = false;

    while let Some(ch) = chars.next() {
        if escaped {
            normalized.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            normalized.push(ch);
            escaped = true;
            continue;
        }
        if matches!(ch, ',' | '+') {
            while normalized
                .chars()
                .next_back()
                .is_some_and(|last| matches!(last, ' ' | '\t' | '\r' | '\n'))
                && !trailing_whitespace_is_escaped(&normalized)
            {
                normalized.pop();
            }
            normalized.push(ch);
            while chars
                .next_if(|next| matches!(next, ' ' | '\t' | '\r' | '\n'))
                .is_some()
            {}
            continue;
        }
        normalized.push(ch);
    }

    while normalized
        .chars()
        .next_back()
        .is_some_and(|last| matches!(last, ' ' | '\t' | '\r' | '\n'))
        && !trailing_whitespace_is_escaped(&normalized)
    {
        normalized.pop();
    }
    normalized.parse().ok()
}

pub(crate) fn distinguished_names_equal(left: &str, right: &str) -> bool {
    parse_distinguished_name(left)
        .zip(parse_distinguished_name(right))
        .is_some_and(|(left, right)| {
            left.len() == right.len()
                && left
                    .iter_rdn()
                    .zip(right.iter_rdn())
                    .all(|(left, right)| x509_rdns_equal(left, right))
        })
}

pub(crate) fn distinguished_name_within_subtree(name: &str, subtree: &str) -> bool {
    parse_distinguished_name(name)
        .zip(parse_distinguished_name(subtree))
        .is_some_and(|(name, subtree)| {
            subtree.len() <= name.len()
                && name
                    .iter_rdn()
                    .zip(subtree.iter_rdn())
                    .all(|(name, subtree)| x509_rdns_equal(name, subtree))
        })
}

fn ensure_x509_data_entry_budget(info: &X509DataInfo) -> Result<(), ParseError> {
    let total_entries = info.certificates.len()
        + info.subject_names.len()
        + info.issuer_serials.len()
        + info.skis.len()
        + info.crls.len()
        + info.digests.len();
    if total_entries >= MAX_X509_DATA_ENTRY_COUNT {
        return Err(ParseError::InvalidStructure(
            "X509Data contains too many entries".into(),
        ));
    }
    Ok(())
}

fn add_x509_data_usage(total_binary_len: &mut usize, delta: usize) -> Result<(), ParseError> {
    *total_binary_len = total_binary_len.checked_add(delta).ok_or_else(|| {
        ParseError::InvalidStructure("X509Data exceeds maximum allowed total binary length".into())
    })?;
    if *total_binary_len > MAX_X509_DATA_TOTAL_BINARY_LEN {
        return Err(ParseError::InvalidStructure(
            "X509Data exceeds maximum allowed total binary length".into(),
        ));
    }
    Ok(())
}

fn decode_x509_base64(
    node: Node<'_, '_>,
    element_name: &'static str,
) -> Result<Vec<u8>, ParseError> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    let mut cleaned = String::new();
    let mut raw_text_len = 0usize;
    for text in node
        .children()
        .filter(|child| child.is_text())
        .filter_map(|child| child.text())
    {
        if raw_text_len.saturating_add(text.len()) > MAX_X509_BASE64_TEXT_LEN {
            return Err(ParseError::InvalidStructure(format!(
                "{element_name} exceeds maximum allowed text length"
            )));
        }
        raw_text_len = raw_text_len.saturating_add(text.len());
        normalize_xml_base64_text(text, &mut cleaned).map_err(|err| {
            ParseError::Base64(format!(
                "invalid XML whitespace U+{:04X} in {element_name}",
                err.invalid_byte
            ))
        })?;
        if cleaned.len() > MAX_X509_BASE64_NORMALIZED_LEN {
            return Err(ParseError::InvalidStructure(format!(
                "{element_name} exceeds maximum allowed base64 length"
            )));
        }
    }

    let decoded = STANDARD
        .decode(&cleaned)
        .map_err(|e| ParseError::Base64(format!("{element_name}: {e}")))?;
    if decoded.is_empty() {
        return Err(ParseError::InvalidStructure(format!(
            "{element_name} must not be empty"
        )));
    }
    if decoded.len() > MAX_X509_DECODED_BINARY_LEN {
        return Err(ParseError::InvalidStructure(format!(
            "{element_name} exceeds maximum allowed binary length"
        )));
    }
    Ok(decoded)
}

pub(crate) fn parse_x509_certificate(cert_der: &[u8]) -> Result<ParsedX509Certificate, ParseError> {
    let (rest, cert) =
        x509_parser::certificate::X509Certificate::from_der(cert_der).map_err(|err| {
            ParseError::InvalidStructure(format!("X509Certificate is not valid DER X.509: {err}"))
        })?;
    if !rest.is_empty() {
        return Err(ParseError::InvalidStructure(
            "X509Certificate contains trailing bytes after DER certificate".into(),
        ));
    }

    // x509-parser displays the DER RDN sequence in storage order, while
    // XMLDSig names follow RFC 4514 and serialize that sequence in reverse.
    // Normalize at the certificate boundary so matching remains ordered and
    // cannot confuse a DN with another hierarchy containing reversed RDNs.
    let subject_dn = x509_name_to_rfc4514(cert.subject())?;
    let issuer_dn = x509_name_to_rfc4514(cert.issuer())?;
    let serial_number = cert.tbs_certificate.raw_serial().to_vec();
    let serial_number_hex = format_x509_serial_value_hex(&serial_number);

    let subject_key_identifier = cert.extensions().iter().find_map(|ext| {
        if let ParsedExtension::SubjectKeyIdentifier(ski) = ext.parsed_extension() {
            Some(ski.0.to_vec())
        } else {
            None
        }
    });

    let spki = cert.public_key();
    let public_key = match spki.parsed().map_err(|err| {
        ParseError::InvalidStructure(format!("X509Certificate public key parse error: {err}"))
    })? {
        PublicKey::RSA(rsa) => {
            let modulus = trim_leading_zeroes(rsa.modulus);
            let exponent = trim_leading_zeroes(rsa.exponent);
            if modulus.is_empty() || exponent.is_empty() {
                return Err(ParseError::InvalidStructure(
                    "X509Certificate RSA key contains empty modulus or exponent".into(),
                ));
            }
            X509PublicKeyInfo::Rsa { modulus, exponent }
        }
        PublicKey::EC(ec_point) => {
            let Some(params) = spki.algorithm.parameters.as_ref() else {
                return Err(ParseError::InvalidStructure(
                    "X509Certificate EC key is missing curve parameters".into(),
                ));
            };

            match params.as_oid() {
                Ok(oid) => X509PublicKeyInfo::Ec {
                    curve_oid: oid.to_id_string(),
                    public_key: ec_point.data().to_vec(),
                },
                Err(_) => X509PublicKeyInfo::Unsupported {
                    algorithm_oid: spki.algorithm.algorithm.to_id_string(),
                },
            }
        }
        _ => X509PublicKeyInfo::Unsupported {
            algorithm_oid: spki.algorithm.algorithm.to_id_string(),
        },
    };

    Ok(ParsedX509Certificate {
        subject_dn,
        issuer_dn,
        serial_number,
        serial_number_hex,
        subject_key_identifier,
        public_key,
    })
}

pub(crate) fn x509_name_to_rfc4514(name: &X509Name<'_>) -> Result<String, ParseError> {
    let name = Name::from_der(name.as_raw()).map_err(|error| {
        ParseError::InvalidStructure(format!(
            "X509Certificate distinguished name is invalid DER: {error}"
        ))
    })?;
    Ok(name.to_string())
}

fn format_x509_serial_hex(serial: &[u8]) -> String {
    serial
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>()
}

fn format_x509_serial_value_hex(serial: &[u8]) -> String {
    let first_non_zero = serial
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(serial.len());
    let canonical = if first_non_zero == serial.len() {
        &[0]
    } else {
        &serial[first_non_zero..]
    };
    format_x509_serial_hex(canonical)
}

fn x509_serial_decimal_to_hex(serial: &str) -> Option<String> {
    let serial = serial.trim();
    let serial = serial.strip_prefix('+').unwrap_or(serial);
    let serial = serial.trim_start_matches('0');
    let serial = if serial.is_empty() { "0" } else { serial };
    if serial.len() > MAX_X509_SERIAL_NUMBER_VALUE_DIGITS
        || !serial.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }

    let mut bytes = [0_u8; MAX_X509_SERIAL_NUMBER_BYTES];
    for digit in serial.bytes().map(|byte| byte - b'0') {
        let mut carry = u16::from(digit);
        for byte in bytes.iter_mut().rev() {
            let value = u16::from(*byte) * 10 + carry;
            *byte = value as u8;
            carry = value >> 8;
        }
        if carry != 0 {
            return None;
        }
    }

    if bytes.iter().all(|byte| *byte == 0) {
        return None;
    }

    Some(format_x509_serial_value_hex(&bytes))
}

fn trim_leading_zeroes(bytes: &[u8]) -> Vec<u8> {
    let first_non_zero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    bytes[first_non_zero..].to_vec()
}

fn parse_x509_issuer_serial(node: Node<'_, '_>) -> Result<(String, String), ParseError> {
    verify_ds_element(node, "X509IssuerSerial")?;
    ensure_no_non_whitespace_text(node, "X509IssuerSerial")?;

    let children = element_children(node).collect::<Vec<_>>();
    if children.len() != 2 {
        return Err(ParseError::InvalidStructure(
            "X509IssuerSerial must contain exactly X509IssuerName then X509SerialNumber".into(),
        ));
    }
    if !matches!(
        (
            children[0].tag_name().namespace(),
            children[0].tag_name().name()
        ),
        (Some(XMLDSIG_NS), "X509IssuerName")
    ) {
        return Err(ParseError::InvalidStructure(
            "X509IssuerSerial must contain X509IssuerName as the first child element".into(),
        ));
    }
    if !matches!(
        (
            children[1].tag_name().namespace(),
            children[1].tag_name().name()
        ),
        (Some(XMLDSIG_NS), "X509SerialNumber")
    ) {
        return Err(ParseError::InvalidStructure(
            "X509IssuerSerial must contain X509SerialNumber as the second child element".into(),
        ));
    }

    let issuer_node = children[0];
    ensure_no_element_children(issuer_node, "X509IssuerName")?;
    let issuer_name =
        collect_text_content_bounded(issuer_node, MAX_X509_ISSUER_NAME_TEXT_LEN, "X509IssuerName")?;

    let serial_node = children[1];
    ensure_no_element_children(serial_node, "X509SerialNumber")?;
    let serial_number = collect_x509_serial_number(serial_node)?;
    if issuer_name.trim().is_empty() {
        return Err(ParseError::InvalidStructure(
            "X509IssuerSerial requires non-empty X509IssuerName and X509SerialNumber".into(),
        ));
    }

    Ok((issuer_name, serial_number))
}

/// Base64-decode a digest value string, stripping whitespace.
///
/// XMLDSig allows whitespace within base64 content (line-wrapped encodings).
fn base64_decode_digest(b64: &str, digest_method: DigestAlgorithm) -> Result<Vec<u8>, ParseError> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    let expected = digest_method.output_len();
    let max_base64_len = expected.div_ceil(3) * 4;
    let mut cleaned = String::with_capacity(b64.len().min(max_base64_len));
    normalize_xml_base64_text(b64, &mut cleaned).map_err(|err| {
        ParseError::Base64(format!(
            "invalid XML whitespace U+{:04X} in DigestValue",
            err.invalid_byte
        ))
    })?;
    if cleaned.len() > max_base64_len {
        return Err(ParseError::Base64(
            "DigestValue exceeds maximum allowed base64 length".into(),
        ));
    }
    let digest = STANDARD
        .decode(&cleaned)
        .map_err(|e| ParseError::Base64(e.to_string()))?;
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

fn decode_digest_value_children(
    digest_value_node: Node<'_, '_>,
    digest_method: DigestAlgorithm,
) -> Result<Vec<u8>, ParseError> {
    let max_base64_len = digest_method.output_len().div_ceil(3) * 4;
    let mut cleaned = String::with_capacity(max_base64_len);

    for child in digest_value_node.children() {
        if child.is_element() {
            return Err(ParseError::InvalidStructure(
                "DigestValue must not contain element children".into(),
            ));
        }
        if let Some(text) = child.text() {
            normalize_xml_base64_text(text, &mut cleaned).map_err(|err| {
                ParseError::Base64(format!(
                    "invalid XML whitespace U+{:04X} in DigestValue",
                    err.invalid_byte
                ))
            })?;
            if cleaned.len() > max_base64_len {
                return Err(ParseError::Base64(
                    "DigestValue exceeds maximum allowed base64 length".into(),
                ));
            }
        }
    }

    base64_decode_digest(&cleaned, digest_method)
}

fn decode_der_encoded_key_value_base64(node: Node<'_, '_>) -> Result<Vec<u8>, ParseError> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    let mut cleaned = String::new();
    let mut raw_text_len = 0usize;
    for text in node
        .children()
        .filter(|child| child.is_text())
        .filter_map(|child| child.text())
    {
        if raw_text_len.saturating_add(text.len()) > MAX_DER_ENCODED_KEY_VALUE_TEXT_LEN {
            return Err(ParseError::InvalidStructure(
                "DEREncodedKeyValue exceeds maximum allowed text length".into(),
            ));
        }
        raw_text_len = raw_text_len.saturating_add(text.len());
        normalize_xml_base64_text(text, &mut cleaned).map_err(|err| {
            ParseError::Base64(format!(
                "invalid XML whitespace U+{:04X} in base64 text",
                err.invalid_byte
            ))
        })?;
        if cleaned.len() > MAX_DER_ENCODED_KEY_VALUE_BASE64_LEN {
            return Err(ParseError::InvalidStructure(
                "DEREncodedKeyValue exceeds maximum allowed length".into(),
            ));
        }
    }

    let der = STANDARD
        .decode(&cleaned)
        .map_err(|e| ParseError::Base64(e.to_string()))?;
    if der.is_empty() {
        return Err(ParseError::InvalidStructure(
            "DEREncodedKeyValue must not be empty".into(),
        ));
    }
    if der.len() > MAX_DER_ENCODED_KEY_VALUE_LEN {
        return Err(ParseError::InvalidStructure(
            "DEREncodedKeyValue exceeds maximum allowed length".into(),
        ));
    }
    Ok(der)
}

fn collect_text_content_bounded(
    node: Node<'_, '_>,
    max_len: usize,
    element_name: &'static str,
) -> Result<String, ParseError> {
    let mut text = String::new();
    for chunk in node
        .children()
        .filter_map(|child| child.is_text().then(|| child.text()).flatten())
    {
        if text.len().saturating_add(chunk.len()) > max_len {
            return Err(ParseError::InvalidStructure(format!(
                "{element_name} exceeds maximum allowed text length"
            )));
        }
        text.push_str(chunk);
    }
    Ok(text)
}

fn collect_x509_serial_number(node: Node<'_, '_>) -> Result<String, ParseError> {
    let mut serial = String::with_capacity(MAX_X509_SERIAL_NUMBER_VALUE_DIGITS);
    let mut raw_text_len = 0usize;
    let mut trailing_whitespace = false;
    let mut explicit_positive = false;
    let mut saw_digit = false;

    for chunk in node
        .children()
        .filter_map(|child| child.is_text().then(|| child.text()).flatten())
    {
        raw_text_len = raw_text_len.saturating_add(chunk.len());
        if raw_text_len > MAX_X509_SERIAL_NUMBER_RAW_TEXT_LEN {
            return Err(ParseError::InvalidStructure(
                "X509SerialNumber exceeds maximum allowed text length".into(),
            ));
        }
        for byte in chunk.bytes() {
            if matches!(byte, b' ' | b'\t' | b'\r' | b'\n') {
                trailing_whitespace |= explicit_positive || saw_digit;
                continue;
            }
            if byte == b'+' && !saw_digit && !explicit_positive && !trailing_whitespace {
                explicit_positive = true;
                continue;
            }
            if trailing_whitespace || !byte.is_ascii_digit() {
                return Err(ParseError::InvalidStructure(
                    "invalid X509SerialNumber decimal value".into(),
                ));
            }
            saw_digit = true;
            if byte == b'0' && serial.is_empty() {
                continue;
            }
            if serial.len() == MAX_X509_SERIAL_NUMBER_VALUE_DIGITS {
                return Err(ParseError::InvalidStructure(
                    "X509SerialNumber exceeds maximum allowed decimal value".into(),
                ));
            }
            serial.push(char::from(byte));
        }
    }

    if !saw_digit {
        return Err(ParseError::InvalidStructure(
            "X509IssuerSerial requires non-empty X509IssuerName and X509SerialNumber".into(),
        ));
    }
    if serial.is_empty() {
        serial.push('0');
    }
    if x509_serial_decimal_to_hex(&serial).is_none() {
        return Err(ParseError::InvalidStructure(
            "invalid X509SerialNumber decimal value or RFC 5280 range".into(),
        ));
    }

    Ok(serial)
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

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests use trusted XML fixtures")]
mod tests {
    use super::*;
    use crate::xmldsig::TransformError;
    use base64::Engine;

    fn fixture_rsa_cert_base64() -> String {
        fixture_cert_base64("../../tests/fixtures/keys/rsa/rsa-2048-cert.pem")
    }

    fn fixture_cert_base64(path: &str) -> String {
        match path {
            "../../tests/fixtures/keys/rsa/rsa-2048-cert.pem" => {
                include_str!("../../tests/fixtures/keys/rsa/rsa-2048-cert.pem")
            }
            "../../tests/fixtures/keys/rsa/rsa-4096-cert.pem" => {
                include_str!("../../tests/fixtures/keys/rsa/rsa-4096-cert.pem")
            }
            "../../tests/fixtures/keys/ca2cert.pem" => {
                include_str!("../../tests/fixtures/keys/ca2cert.pem")
            }
            "../../tests/fixtures/keys/cacert.pem" => {
                include_str!("../../tests/fixtures/keys/cacert.pem")
            }
            _ => unreachable!("unknown certificate fixture"),
        }
        .lines()
        .skip_while(|line| *line != "-----BEGIN CERTIFICATE-----")
        .skip(1)
        .take_while(|line| *line != "-----END CERTIFICATE-----")
        .collect::<String>()
    }

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
            Some(SignatureAlgorithm::EcdsaSha256)
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
            SignatureAlgorithm::DsaSha1,
            SignatureAlgorithm::HmacSha1,
            SignatureAlgorithm::RsaSha1,
            SignatureAlgorithm::RsaSha256,
            SignatureAlgorithm::RsaSha384,
            SignatureAlgorithm::RsaSha512,
            SignatureAlgorithm::EcdsaSha256,
            SignatureAlgorithm::EcdsaSha384,
        ] {
            assert_eq!(
                SignatureAlgorithm::from_uri(algo.uri()),
                Some(algo),
                "round-trip failed for {algo:?}"
            );
        }
    }

    #[test]
    fn legacy_algorithms_are_verify_only() {
        assert!(!SignatureAlgorithm::DsaSha1.signing_allowed());
        assert!(!SignatureAlgorithm::HmacSha1.signing_allowed());
        assert!(!SignatureAlgorithm::RsaSha1.signing_allowed());
        assert!(SignatureAlgorithm::RsaSha256.signing_allowed());
        assert!(SignatureAlgorithm::EcdsaSha256.signing_allowed());
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
    fn key_info_candidate_budget_precedes_key_value_parsing() {
        // A denied embedded candidate must fail before malformed key material
        // reaches the algorithm-specific parser.
        let document = Document::parse(
            r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <KeyValue><RSAKeyValue><Modulus>AQAB</Modulus></RSAKeyValue></KeyValue>
            </KeyInfo>"#,
        )
        .expect("fixed KeyInfo fixture must parse as XML");
        let resources = crate::policy::ResourcePolicy {
            max_key_candidates: 0,
            ..crate::policy::ResourcePolicy::default()
        };

        let error = parse_key_info_with_policy_budgets(
            document.root_element(),
            crate::provider::default_provider(),
            &XmlBaseResolutionBudget::default(),
            &resources,
        )
        .expect_err("candidate policy must reject KeyValue before RSA parsing");

        assert!(matches!(
            error,
            ParseError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::KEY_CANDIDATES,
                maximum: 0,
                actual: 1,
            })
        ));
    }

    #[test]
    fn key_info_candidate_budget_precedes_der_key_decoding() {
        // Candidate accounting must reject DEREncodedKeyValue before retaining
        // or base64-decoding its attacker-controlled text.
        let document = Document::parse(
            r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"
                       xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">
                <dsig11:DEREncodedKeyValue>%%%invalid%%%</dsig11:DEREncodedKeyValue>
            </KeyInfo>"#,
        )
        .expect("fixed KeyInfo fixture must parse as XML");
        let resources = crate::policy::ResourcePolicy {
            max_key_candidates: 0,
            ..crate::policy::ResourcePolicy::default()
        };

        let error = parse_key_info_with_policy_budgets(
            document.root_element(),
            crate::provider::default_provider(),
            &XmlBaseResolutionBudget::default(),
            &resources,
        )
        .expect_err("candidate policy must reject DEREncodedKeyValue before decoding");

        assert!(matches!(
            error,
            ParseError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::KEY_CANDIDATES,
                maximum: 0,
                actual: 1,
            })
        ));
    }

    #[test]
    fn key_info_embedded_candidate_count_matches_materialized_key_kinds() {
        // Only materialized cryptographic candidates belong to the parser
        // preflight; names and unresolved RetrievalMethods become work later.
        let key_info = KeyInfo {
            sources: vec![
                KeyInfoSource::KeyName("configured-key".into()),
                KeyInfoSource::KeyValue(KeyValueInfo::Unsupported {
                    namespace: Some(XMLDSIG_NS.into()),
                    local_name: "FutureKeyValue".into(),
                }),
                KeyInfoSource::DerEncodedKeyValue(vec![1]),
                KeyInfoSource::X509Data(X509DataInfo {
                    certificates: vec![vec![2], vec![3]],
                    ..X509DataInfo::default()
                }),
                KeyInfoSource::RetrievalMethod {
                    uri: "urn:certificate".into(),
                    resource_type: None,
                    transforms: RetrievalMethodTransforms::None,
                },
            ],
        };

        assert_eq!(key_info.embedded_candidate_count(), 4);
    }

    #[test]
    fn parse_key_info_dispatches_supported_children() {
        let cert_base64 = fixture_rsa_cert_base64();
        let expected_cert = base64::engine::general_purpose::STANDARD
            .decode(&cert_base64)
            .expect("fixture PEM must contain valid base64");
        let cert_digest = base64::engine::general_purpose::STANDARD
            .encode(compute_digest(DigestAlgorithm::Sha256, &expected_cert));
        let xml = format!(
            r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"
                              xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">
            <KeyName>idp-signing-key</KeyName>
            <KeyValue>
                <RSAKeyValue>
                    <Modulus>AQAB</Modulus>
                    <Exponent>AQAB</Exponent>
                </RSAKeyValue>
            </KeyValue>
            <X509Data>
                <X509Certificate>{cert_base64}</X509Certificate>
                <X509SubjectName>CN=Test Key rsa-2048,O=XML Security Library (http://www.aleksey.com/xmlsec),ST=California,C=US</X509SubjectName>
                <X509IssuerSerial>
                    <X509IssuerName>Email=xmlsec@aleksey.com,CN=Aleksey Sanin,OU=Second level CA,O=XML Security Library (http://www.aleksey.com/xmlsec),ST=California,C=US</X509IssuerName>
                    <X509SerialNumber>680572598617295163017172295025714171905498632019</X509SerialNumber>
                </X509IssuerSerial>
                <X509SKI>bcOXN/nsVl8GatRbcKrPbzIbw0Y=</X509SKI>
                <X509CRL>BAUGBw==</X509CRL>
                <dsig11:X509Digest Algorithm="http://www.w3.org/2001/04/xmlenc#sha256">{cert_digest}</dsig11:X509Digest>
            </X509Data>
            <dsig11:DEREncodedKeyValue>AQIDBA==</dsig11:DEREncodedKeyValue>
        </KeyInfo>"#
        );
        let doc = Document::parse(&xml).unwrap();

        let key_info = parse_key_info(doc.root_element()).unwrap();
        assert_eq!(key_info.sources.len(), 4);

        assert_eq!(
            key_info.sources[0],
            KeyInfoSource::KeyName("idp-signing-key".to_string())
        );
        assert_eq!(
            key_info.sources[1],
            KeyInfoSource::KeyValue(KeyValueInfo::Rsa {
                modulus: vec![1, 0, 1],
                exponent: vec![1, 0, 1],
            })
        );
        let x509_info = match &key_info.sources[2] {
            KeyInfoSource::X509Data(x509) => x509,
            other => panic!("expected X509Data source, got {other:?}"),
        };
        assert_eq!(x509_info.certificates, vec![expected_cert]);
        assert_eq!(
            x509_info.subject_names,
            vec![
                "CN=Test Key rsa-2048,O=XML Security Library (http://www.aleksey.com/xmlsec),ST=California,C=US"
                    .to_string()
            ]
        );
        assert_eq!(
            x509_info.issuer_serials,
            vec![(
                "Email=xmlsec@aleksey.com,CN=Aleksey Sanin,OU=Second level CA,O=XML Security Library (http://www.aleksey.com/xmlsec),ST=California,C=US".to_string(),
                "680572598617295163017172295025714171905498632019".to_string()
            )]
        );
        assert_eq!(
            x509_info.skis,
            vec![vec![
                109, 195, 151, 55, 249, 236, 86, 95, 6, 106, 212, 91, 112, 170, 207, 111, 50, 27,
                195, 70
            ]]
        );
        assert_eq!(x509_info.crls, vec![vec![4, 5, 6, 7]]);
        assert_eq!(
            x509_info.digests,
            vec![(
                "http://www.w3.org/2001/04/xmlenc#sha256".to_string(),
                compute_digest(DigestAlgorithm::Sha256, &x509_info.certificates[0])
            )]
        );
        assert_eq!(x509_info.parsed_certificates.len(), 1);
        assert_eq!(x509_info.certificate_chain, vec![0]);
        let parsed_cert = &x509_info.parsed_certificates[0];
        assert!(!parsed_cert.subject_dn.is_empty());
        assert!(!parsed_cert.issuer_dn.is_empty());
        assert_eq!(
            parsed_cert.serial_number_hex,
            "7735EE487F6862DAF1B3956D961CCB0FA6F34F53"
        );
        assert!(parsed_cert.subject_key_identifier.is_some());
        assert!(matches!(
            parsed_cert.public_key,
            X509PublicKeyInfo::Rsa { .. }
        ));

        assert_eq!(
            key_info.sources[3],
            KeyInfoSource::DerEncodedKeyValue(vec![1, 2, 3, 4])
        );
    }

    #[test]
    fn parse_rsa_key_value_preserves_wrapped_crypto_binary() {
        // CryptoBinary is unsigned big-endian data and XML whitespace is insignificant.
        let xml = r##"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <KeyValue><RSAKeyValue>
                <Modulus> AQID
BA== </Modulus>
                <Exponent> AQAB </Exponent>
            </RSAKeyValue></KeyValue>
        </KeyInfo>"##;
        let doc = Document::parse(xml).unwrap();

        assert_eq!(
            parse_key_info(doc.root_element()).unwrap().sources,
            vec![KeyInfoSource::KeyValue(KeyValueInfo::Rsa {
                modulus: vec![1, 2, 3, 4],
                exponent: vec![1, 0, 1],
            })]
        );
    }

    #[test]
    fn parse_rsa_key_value_rejects_reordered_parameters() {
        // XMLDSig defines Modulus followed by Exponent; accepting reordered input is ambiguous.
        let xml = r##"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <KeyValue><RSAKeyValue>
                <Exponent>AQAB</Exponent><Modulus>AQID</Modulus>
            </RSAKeyValue></KeyValue>
        </KeyInfo>"##;
        let doc = Document::parse(xml).unwrap();

        assert!(matches!(
            parse_key_info(doc.root_element()),
            Err(ParseError::InvalidStructure(_))
        ));
    }

    #[test]
    fn parse_rsa_key_value_rejects_missing_exponent() {
        // Both RSA public parameters are required to construct a usable key.
        let xml = r##"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <KeyValue><RSAKeyValue><Modulus>AQID</Modulus></RSAKeyValue></KeyValue>
        </KeyInfo>"##;
        let doc = Document::parse(xml).unwrap();

        assert!(matches!(
            parse_key_info(doc.root_element()),
            Err(ParseError::InvalidStructure(_))
        ));
    }

    #[test]
    fn parse_rsa_key_value_rejects_duplicate_exponent() {
        // RSAKeyValue has a closed two-child schema; duplicate parameters are invalid.
        let xml = r##"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <KeyValue><RSAKeyValue>
                <Modulus>AQID</Modulus><Exponent>AQAB</Exponent><Exponent>AQAB</Exponent>
            </RSAKeyValue></KeyValue>
        </KeyInfo>"##;
        let doc = Document::parse(xml).unwrap();

        assert!(matches!(
            parse_key_info(doc.root_element()),
            Err(ParseError::InvalidStructure(_))
        ));
    }

    #[test]
    fn parse_rsa_key_value_rejects_wrong_parameter_namespace() {
        // Local names from an extension namespace must not be treated as XMLDSig parameters.
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#" xmlns:bad="urn:bad">
            <KeyValue><RSAKeyValue>
                <bad:Modulus>AQID</bad:Modulus><Exponent>AQAB</Exponent>
            </RSAKeyValue></KeyValue>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        assert!(matches!(
            parse_key_info(doc.root_element()),
            Err(ParseError::InvalidStructure(_))
        ));
    }

    #[test]
    fn parse_rsa_key_value_rejects_nested_crypto_binary() {
        // CryptoBinary values are text-only and must not hide extension elements.
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <KeyValue><RSAKeyValue>
                <Modulus><chunk>AQID</chunk></Modulus><Exponent>AQAB</Exponent>
            </RSAKeyValue></KeyValue>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        assert!(matches!(
            parse_key_info(doc.root_element()),
            Err(ParseError::InvalidStructure(_))
        ));
    }

    #[test]
    fn parse_rsa_key_value_rejects_malformed_base64() {
        // Malformed key parameters must be processing errors, not unresolved keys.
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <KeyValue><RSAKeyValue>
                <Modulus>%%%%</Modulus><Exponent>AQAB</Exponent>
            </RSAKeyValue></KeyValue>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        assert!(matches!(
            parse_key_info(doc.root_element()),
            Err(ParseError::Base64(_))
        ));
    }

    #[test]
    fn parse_rsa_key_value_rejects_oversized_exponent_before_decode() {
        // Bound normalized text before allocation or integer construction.
        let exponent = "A".repeat(MAX_RSA_EXPONENT_LEN.div_ceil(3) * 4 + 1);
        let xml = format!(
            r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <KeyValue><RSAKeyValue>
                    <Modulus>AQID</Modulus><Exponent>{exponent}</Exponent>
                </RSAKeyValue></KeyValue>
            </KeyInfo>"#
        );
        let doc = Document::parse(&xml).unwrap();

        assert!(matches!(
            parse_key_info(doc.root_element()),
            Err(ParseError::InvalidStructure(_))
        ));
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
    fn parse_key_info_accepts_empty_x509data() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <X509Data/>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let key_info = parse_key_info(doc.root_element()).unwrap();
        assert_eq!(
            key_info.sources,
            vec![KeyInfoSource::X509Data(X509DataInfo::default())]
        );
    }

    #[test]
    fn parse_key_info_rejects_unknown_xmlsig_child_in_x509data() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <X509Data>
                <Foo/>
            </X509Data>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let err = parse_key_info(doc.root_element()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidStructure(_)));
    }

    #[test]
    fn parse_key_info_rejects_unknown_xmlsig11_child_in_x509data() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"
                              xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">
            <X509Data>
                <dsig11:Foo/>
            </X509Data>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let err = parse_key_info(doc.root_element()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidStructure(_)));
    }

    #[test]
    fn parse_key_info_rejects_x509_issuer_serial_without_required_children() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <X509Data>
                <X509IssuerSerial>
                    <X509IssuerName>CN=CA</X509IssuerName>
                </X509IssuerSerial>
            </X509Data>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let err = parse_key_info(doc.root_element()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidStructure(_)));
    }

    #[test]
    fn parse_key_info_rejects_x509_issuer_serial_with_duplicate_issuer_name() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <X509Data>
                <X509IssuerSerial>
                    <X509IssuerName>CN=CA-1</X509IssuerName>
                    <X509IssuerName>CN=CA-2</X509IssuerName>
                    <X509SerialNumber>42</X509SerialNumber>
                </X509IssuerSerial>
            </X509Data>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let err = parse_key_info(doc.root_element()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidStructure(_)));
    }

    #[test]
    fn parse_key_info_rejects_x509_issuer_serial_with_duplicate_serial_number() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <X509Data>
                <X509IssuerSerial>
                    <X509IssuerName>CN=CA</X509IssuerName>
                    <X509SerialNumber>1</X509SerialNumber>
                    <X509SerialNumber>2</X509SerialNumber>
                </X509IssuerSerial>
            </X509Data>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let err = parse_key_info(doc.root_element()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidStructure(_)));
    }

    #[test]
    fn parse_key_info_rejects_x509_issuer_serial_with_whitespace_only_values() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <X509Data>
                <X509IssuerSerial>
                    <X509IssuerName>   </X509IssuerName>
                    <X509SerialNumber>
                        
                    </X509SerialNumber>
                </X509IssuerSerial>
            </X509Data>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let err = parse_key_info(doc.root_element()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidStructure(_)));
    }

    #[test]
    fn parse_key_info_rejects_x509_issuer_serial_with_wrong_child_order() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <X509Data>
                <X509IssuerSerial>
                    <X509SerialNumber>42</X509SerialNumber>
                    <X509IssuerName>CN=CA</X509IssuerName>
                </X509IssuerSerial>
            </X509Data>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let err = parse_key_info(doc.root_element()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidStructure(_)));
    }

    #[test]
    fn parse_key_info_rejects_x509_issuer_serial_with_extra_child_element() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"
                              xmlns:foo="urn:example:foo">
            <X509Data>
                <X509IssuerSerial>
                    <X509IssuerName>CN=CA</X509IssuerName>
                    <X509SerialNumber>42</X509SerialNumber>
                    <foo:Extra/>
                </X509IssuerSerial>
            </X509Data>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let err = parse_key_info(doc.root_element()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidStructure(_)));
    }

    #[test]
    fn parse_key_info_rejects_x509_digest_without_algorithm() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"
                              xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">
            <X509Data>
                <dsig11:X509Digest>AQID</dsig11:X509Digest>
            </X509Data>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let err = parse_key_info(doc.root_element()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidStructure(_)));
    }

    #[test]
    fn parse_key_info_rejects_invalid_x509_certificate_base64() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <X509Data>
                <X509Certificate>%%%invalid%%%</X509Certificate>
            </X509Data>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let err = parse_key_info(doc.root_element()).unwrap_err();
        assert!(matches!(err, ParseError::Base64(_)));
    }

    #[test]
    fn parse_key_info_rejects_x509_data_exceeding_entry_budget() {
        let subjects = (0..(MAX_X509_DATA_ENTRY_COUNT + 1))
            .map(|idx| format!("<X509SubjectName>CN={idx}</X509SubjectName>"))
            .collect::<Vec<_>>()
            .join("");
        let xml = format!(
            "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data>{subjects}</X509Data></KeyInfo>"
        );
        let doc = Document::parse(&xml).unwrap();

        let err = parse_key_info(doc.root_element()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidStructure(_)));
    }

    #[test]
    fn parse_key_info_rejects_x509_data_exceeding_total_binary_budget() {
        let payload = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 190_000]);
        let entries = (0..6)
            .map(|_| format!("<X509SKI>{payload}</X509SKI>"))
            .collect::<Vec<_>>()
            .join("");
        let xml = format!(
            "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data>{entries}</X509Data></KeyInfo>"
        );
        let doc = Document::parse(&xml).unwrap();

        let err = parse_key_info(doc.root_element()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidStructure(_)));
    }

    #[test]
    fn parse_key_info_rejects_x509_certificate_with_invalid_der() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <X509Data>
                <X509Certificate>AQID</X509Certificate>
            </X509Data>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let err = parse_key_info(doc.root_element()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidStructure(_)));
    }

    #[test]
    fn parse_key_info_rejects_x509_certificate_with_trailing_der_bytes() {
        let mut cert = base64::engine::general_purpose::STANDARD
            .decode(fixture_rsa_cert_base64())
            .unwrap();
        cert.extend_from_slice(&[0x00, 0x01]);
        let cert_base64 = base64::engine::general_purpose::STANDARD.encode(cert);
        let xml = format!(
            r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data>
                    <X509Certificate>{cert_base64}</X509Certificate>
                </X509Data>
            </KeyInfo>"#
        );
        let doc = Document::parse(&xml).unwrap();

        let err = parse_key_info(doc.root_element()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidStructure(_)));
    }

    #[test]
    fn parse_key_info_marks_unsupported_spki_algorithm_as_unsupported() {
        let xml = include_str!(
            "../../tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/signature-x509-crt.xml"
        );
        let doc = Document::parse(xml).unwrap();
        let key_info_node = doc
            .descendants()
            .find(|node| {
                node.is_element()
                    && node.tag_name().namespace() == Some(XMLDSIG_NS)
                    && node.tag_name().name() == "KeyInfo"
            })
            .expect("fixture must contain ds:KeyInfo");

        let key_info = parse_key_info(key_info_node).expect("KeyInfo parse should succeed");
        let x509_info = match &key_info.sources[0] {
            KeyInfoSource::X509Data(x509) => x509,
            other => panic!("expected X509Data source, got {other:?}"),
        };
        assert_eq!(x509_info.certificates.len(), 1);
        assert_eq!(x509_info.parsed_certificates.len(), 1);
        assert_eq!(x509_info.certificate_chain, vec![0]);
        let parsed_cert = &x509_info.parsed_certificates[0];
        assert!(!parsed_cert.subject_dn.is_empty());
        assert!(!parsed_cert.issuer_dn.is_empty());
        assert!(parsed_cert.subject_key_identifier.is_some());
        assert!(matches!(
            parsed_cert.public_key,
            X509PublicKeyInfo::Unsupported { .. }
        ));
    }

    #[test]
    fn parse_key_info_orders_x509_certificate_chain_from_signing_cert() {
        let root = fixture_cert_base64("../../tests/fixtures/keys/cacert.pem");
        let intermediate = fixture_cert_base64("../../tests/fixtures/keys/ca2cert.pem");
        let leaf = fixture_cert_base64("../../tests/fixtures/keys/rsa/rsa-2048-cert.pem");
        let xml = format!(
            r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data>
                    <X509Certificate>{root}</X509Certificate>
                    <X509Certificate>{intermediate}</X509Certificate>
                    <X509Certificate>{leaf}</X509Certificate>
                </X509Data>
            </KeyInfo>"#
        );
        let doc = Document::parse(&xml).unwrap();

        let key_info = parse_key_info(doc.root_element()).unwrap();
        let x509_info = match &key_info.sources[0] {
            KeyInfoSource::X509Data(x509) => x509,
            other => panic!("expected X509Data source, got {other:?}"),
        };

        assert_eq!(x509_info.certificate_chain, vec![2, 1, 0]);
    }

    #[test]
    fn chain_builder_matches_x509_equivalent_distinguished_names() {
        // RFC 5280 name chaining uses X.501 matching rather than the lexical
        // RFC 4514 rendering. Case differences in DirectoryString values must
        // not disconnect an otherwise valid configured path.
        let certificates = [
            fixture_cert_base64("../../tests/fixtures/keys/rsa/rsa-2048-cert.pem"),
            fixture_cert_base64("../../tests/fixtures/keys/ca2cert.pem"),
            fixture_cert_base64("../../tests/fixtures/keys/cacert.pem"),
        ]
        .map(|encoded| {
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .unwrap()
        })
        .to_vec();
        let mut parsed_certificates = certificates
            .iter()
            .map(|certificate| parse_x509_certificate(certificate).unwrap())
            .collect::<Vec<_>>();
        parsed_certificates[0].issuer_dn = parsed_certificates[1].subject_dn.to_ascii_lowercase();
        parsed_certificates[1].issuer_dn = parsed_certificates[2].subject_dn.to_ascii_lowercase();
        let info = X509DataInfo {
            certificates,
            parsed_certificates,
            ..X509DataInfo::default()
        };

        assert_eq!(
            select_x509_signing_certificate(&info, crate::provider::default_provider()).unwrap(),
            0
        );
        assert_eq!(
            build_x509_certificate_chain_from(&info, 0, crate::provider::default_provider())
                .unwrap(),
            vec![0, 1, 2]
        );
    }

    #[test]
    fn parse_key_info_uses_issuer_serial_to_select_x509_signing_certificate() {
        let root = fixture_cert_base64("../../tests/fixtures/keys/cacert.pem");
        let intermediate = fixture_cert_base64("../../tests/fixtures/keys/ca2cert.pem");
        let leaf = fixture_cert_base64("../../tests/fixtures/keys/rsa/rsa-2048-cert.pem");
        let xml = format!(
            r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data>
                    <X509IssuerSerial>
                        <X509IssuerName>Email=xmlsec@aleksey.com,CN=Aleksey Sanin,OU=Second level CA,O=XML Security Library (http://www.aleksey.com/xmlsec),ST=California,C=US</X509IssuerName>
                        <X509SerialNumber>680572598617295163017172295025714171905498632019</X509SerialNumber>
                    </X509IssuerSerial>
                    <X509Certificate>{root}</X509Certificate>
                    <X509Certificate>{intermediate}</X509Certificate>
                    <X509Certificate>{leaf}</X509Certificate>
                </X509Data>
            </KeyInfo>"#
        );
        let doc = Document::parse(&xml).unwrap();

        let key_info = parse_key_info(doc.root_element()).unwrap();
        let x509_info = match &key_info.sources[0] {
            KeyInfoSource::X509Data(x509) => x509,
            other => panic!("expected X509Data source, got {other:?}"),
        };

        assert_eq!(x509_info.certificate_chain, vec![2, 1, 0]);
    }

    #[test]
    fn parse_key_info_allows_selectors_for_multiple_chain_members() {
        // X509Data may identify both the signing leaf and another certificate
        // in its chain; the unique leaf must remain the signing certificate.
        let root = fixture_cert_base64("../../tests/fixtures/keys/cacert.pem");
        let intermediate = fixture_cert_base64("../../tests/fixtures/keys/ca2cert.pem");
        let leaf = fixture_cert_base64("../../tests/fixtures/keys/rsa/rsa-2048-cert.pem");
        let xml = format!(
            r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data>
                    <X509SubjectName>CN=Test Key rsa-2048,O=XML Security Library (http://www.aleksey.com/xmlsec),ST=California,C=US</X509SubjectName>
                    <X509SKI>0X0XrEVCio75sBcl1TxymJ2IOiU=</X509SKI>
                    <X509Certificate>{root}</X509Certificate>
                    <X509Certificate>{intermediate}</X509Certificate>
                    <X509Certificate>{leaf}</X509Certificate>
                </X509Data>
            </KeyInfo>"#
        );
        let doc = Document::parse(&xml).unwrap();

        let key_info = parse_key_info(doc.root_element()).unwrap();
        let x509_info = match &key_info.sources[0] {
            KeyInfoSource::X509Data(x509) => x509,
            other => panic!("expected X509Data source, got {other:?}"),
        };

        assert_eq!(x509_info.certificate_chain, vec![2, 1, 0]);
    }

    #[test]
    fn parse_key_info_uses_decimal_issuer_serial_to_select_x509_signing_certificate() {
        let serial = "680572598617295163017172295025714171905498632019";
        let padded_serial = format!("{}{}", "0".repeat(64), serial);
        assert_eq!(
            x509_serial_decimal_to_hex(&padded_serial).as_deref(),
            Some("7735EE487F6862DAF1B3956D961CCB0FA6F34F53")
        );
        let root = fixture_cert_base64("../../tests/fixtures/keys/cacert.pem");
        let intermediate = fixture_cert_base64("../../tests/fixtures/keys/ca2cert.pem");
        let leaf = fixture_cert_base64("../../tests/fixtures/keys/rsa/rsa-2048-cert.pem");
        let other_leaf = fixture_cert_base64("../../tests/fixtures/keys/rsa/rsa-4096-cert.pem");
        let xml = format!(
            r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data>
                    <X509IssuerSerial>
                        <X509IssuerName>Email=xmlsec@aleksey.com,CN=Aleksey Sanin,OU=Second level CA,O=XML Security Library (http://www.aleksey.com/xmlsec),ST=California,C=US</X509IssuerName>
                        <X509SerialNumber>{padded_serial}</X509SerialNumber>
                    </X509IssuerSerial>
                    <X509Certificate>{root}</X509Certificate>
                    <X509Certificate>{intermediate}</X509Certificate>
                    <X509Certificate>{leaf}</X509Certificate>
                    <X509Certificate>{other_leaf}</X509Certificate>
                </X509Data>
            </KeyInfo>"#
        );
        let doc = Document::parse(&xml).unwrap();

        let key_info = parse_key_info(doc.root_element()).unwrap();
        let x509_info = match &key_info.sources[0] {
            KeyInfoSource::X509Data(x509) => x509,
            other => panic!("expected X509Data source, got {other:?}"),
        };

        assert_eq!(x509_info.certificate_chain, vec![2, 1, 0]);
    }

    #[test]
    fn parse_key_info_rejects_ambiguous_x509_signing_certificate_candidates() {
        let first_leaf = fixture_cert_base64("../../tests/fixtures/keys/rsa/rsa-2048-cert.pem");
        let second_leaf = fixture_cert_base64("../../tests/fixtures/keys/rsa/rsa-4096-cert.pem");
        let xml = format!(
            r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data>
                    <X509Certificate>{first_leaf}</X509Certificate>
                    <X509Certificate>{second_leaf}</X509Certificate>
                </X509Data>
            </KeyInfo>"#
        );
        let doc = Document::parse(&xml).unwrap();

        let err = parse_key_info(doc.root_element()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidStructure(_)));
    }

    #[test]
    fn parse_key_info_rejects_unmatched_x509_lookup_identifier() {
        let cert = fixture_cert_base64("../../tests/fixtures/keys/rsa/rsa-2048-cert.pem");
        let xml = format!(
            r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data>
                    <X509SubjectName>CN=Not The Embedded Certificate</X509SubjectName>
                    <X509Certificate>{cert}</X509Certificate>
                </X509Data>
            </KeyInfo>"#
        );
        let doc = Document::parse(&xml).unwrap();

        let err = parse_key_info(doc.root_element()).unwrap_err();
        assert!(
            matches!(err, ParseError::InvalidStructure(message) if message.contains("lookup identifiers"))
        );
    }

    #[test]
    fn parse_key_info_rejects_partially_matched_selector_category() {
        // Every selector value is an asserted lookup constraint; one matching
        // SubjectName must not mask another value absent from the chain.
        let cert = fixture_cert_base64("../../tests/fixtures/keys/rsa/rsa-2048-cert.pem");
        let xml = format!(
            r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data>
                    <X509SubjectName>CN=Test Key rsa-2048,O=XML Security Library (http://www.aleksey.com/xmlsec),ST=California,C=US</X509SubjectName>
                    <X509SubjectName>CN=Not In The Embedded Chain</X509SubjectName>
                    <X509Certificate>{cert}</X509Certificate>
                </X509Data>
            </KeyInfo>"#
        );
        let doc = Document::parse(&xml).unwrap();

        let err = parse_key_info(doc.root_element()).unwrap_err();
        assert!(
            matches!(err, ParseError::InvalidStructure(message) if message.contains("lookup identifiers"))
        );
    }

    #[test]
    fn parse_key_info_rejects_malformed_issuer_serial_even_with_matching_subject() {
        // Lexically invalid serials must fail while parsing X509IssuerSerial,
        // before another selector or embedded certificate can mask them.
        let cert = fixture_cert_base64("../../tests/fixtures/keys/rsa/rsa-2048-cert.pem");
        let xml = format!(
            r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data>
                    <X509SubjectName>CN=Test Key rsa-2048,O=XML Security Library (http://www.aleksey.com/xmlsec),ST=California,C=US</X509SubjectName>
                    <X509IssuerSerial>
                        <X509IssuerName>Email=xmlsec@aleksey.com,CN=Aleksey Sanin,OU=Second level CA,O=XML Security Library (http://www.aleksey.com/xmlsec),ST=California,C=US</X509IssuerName>
                        <X509SerialNumber>not-a-decimal-serial</X509SerialNumber>
                    </X509IssuerSerial>
                    <X509Certificate>{cert}</X509Certificate>
                </X509Data>
            </KeyInfo>"#
        );
        let doc = Document::parse(&xml).unwrap();

        let err = parse_key_info(doc.root_element()).unwrap_err();
        assert!(
            matches!(err, ParseError::InvalidStructure(message) if message.contains("invalid X509SerialNumber"))
        );
    }

    #[test]
    fn parse_key_info_rejects_unmatched_ski_even_with_matching_subject() {
        let cert = fixture_cert_base64("../../tests/fixtures/keys/rsa/rsa-2048-cert.pem");
        let xml = format!(
            r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data>
                    <X509SubjectName>CN=Test Key rsa-2048,O=XML Security Library (http://www.aleksey.com/xmlsec),ST=California,C=US</X509SubjectName>
                    <X509SKI>AQIDBA==</X509SKI>
                    <X509Certificate>{cert}</X509Certificate>
                </X509Data>
            </KeyInfo>"#
        );
        let doc = Document::parse(&xml).unwrap();

        let err = parse_key_info(doc.root_element()).unwrap_err();
        assert!(
            matches!(err, ParseError::InvalidStructure(message) if message.contains("lookup identifiers"))
        );
    }

    #[test]
    fn parse_key_info_rejects_lookup_hints_for_different_certificates() {
        let first_cert = fixture_cert_base64("../../tests/fixtures/keys/rsa/rsa-2048-cert.pem");
        let second_cert = fixture_cert_base64("../../tests/fixtures/keys/rsa/rsa-4096-cert.pem");
        let xml = format!(
            r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data>
                    <X509SubjectName>CN=Test Key rsa-2048,O=XML Security Library (http://www.aleksey.com/xmlsec),ST=California,C=US</X509SubjectName>
                    <X509SKI>60zMLKCfzQ3qnXAzABzRNpdgQ8Q=</X509SKI>
                    <X509Certificate>{first_cert}</X509Certificate>
                    <X509Certificate>{second_cert}</X509Certificate>
                </X509Data>
            </KeyInfo>"#
        );
        let doc = Document::parse(&xml).unwrap();

        let err = parse_key_info(doc.root_element()).unwrap_err();
        assert!(
            matches!(err, ParseError::InvalidStructure(message) if message.contains("lookup identifiers match multiple certificates"))
        );
    }

    #[test]
    fn configured_certificate_matching_requires_every_x509_selector_category() {
        // A configured certificate is the lookup candidate for selector-only
        // X509Data. Every asserted category must match that same certificate.
        let certificate = base64::engine::general_purpose::STANDARD
            .decode(fixture_rsa_cert_base64())
            .unwrap();
        let parsed = parse_x509_certificate(&certificate).unwrap();
        let digest = compute_digest_with_provider(
            crate::provider::default_provider(),
            DigestAlgorithm::Sha256,
            &certificate,
        )
        .unwrap();
        let matching = X509DataInfo {
            subject_names: vec![parsed.subject_dn.clone()],
            issuer_serials: vec![(
                parsed.issuer_dn.clone(),
                "680572598617295163017172295025714171905498632019".into(),
            )],
            skis: vec![parsed.subject_key_identifier.clone().unwrap()],
            digests: vec![(DigestAlgorithm::Sha256.uri().into(), digest)],
            ..X509DataInfo::default()
        };

        assert!(
            x509_certificate_matches_selectors(
                &matching,
                &certificate,
                crate::provider::default_provider()
            )
            .unwrap()
        );
        for mismatching in [
            X509DataInfo {
                subject_names: vec!["CN=other".into()],
                ..matching.clone()
            },
            X509DataInfo {
                issuer_serials: vec![(parsed.issuer_dn.clone(), "1".into())],
                ..matching.clone()
            },
            X509DataInfo {
                skis: vec![vec![0]],
                ..matching.clone()
            },
            X509DataInfo {
                digests: vec![(DigestAlgorithm::Sha256.uri().into(), vec![0; 32])],
                ..matching.clone()
            },
        ] {
            assert!(
                !x509_certificate_matches_selectors(
                    &mismatching,
                    &certificate,
                    crate::provider::default_provider()
                )
                .unwrap()
            );
        }
    }

    #[test]
    fn build_x509_certificate_chain_rejects_chain_exceeding_max_depth() {
        let parsed_certificates: Vec<ParsedX509Certificate> = (0..=MAX_X509_CHAIN_DEPTH)
            .map(|idx| ParsedX509Certificate {
                subject_dn: format!("CN=cert-{idx}"),
                issuer_dn: if idx == MAX_X509_CHAIN_DEPTH {
                    format!("CN=cert-{idx}")
                } else {
                    format!("CN=cert-{}", idx + 1)
                },
                serial_number: vec![u8::try_from(idx).unwrap()],
                serial_number_hex: format!("{idx:02X}"),
                subject_key_identifier: None,
                public_key: X509PublicKeyInfo::Unsupported {
                    algorithm_oid: "1.2.3.4".into(),
                },
            })
            .collect();
        let certificates = vec![Vec::new(); parsed_certificates.len()];
        let info = X509DataInfo {
            certificates,
            parsed_certificates,
            ..X509DataInfo::default()
        };

        let err =
            build_x509_certificate_chain(&info, crate::provider::default_provider()).unwrap_err();
        assert!(
            matches!(err, ParseError::InvalidStructure(message) if message.contains("maximum depth"))
        );
    }

    #[test]
    fn x509_serial_hex_strips_der_sign_extension_zeroes() {
        assert_eq!(format_x509_serial_value_hex(&[0x00, 0xFF]), "FF");
        assert_eq!(format_x509_serial_value_hex(&[0x00, 0x7F]), "7F");
        assert_eq!(format_x509_serial_value_hex(&[0x00, 0x00]), "00");
    }

    #[test]
    fn x509_serial_decimal_parser_enforces_rfc5280_positive_range() {
        // A 20-octet unsigned magnitude may need a 21st DER sign-padding
        // octet. The decimal selector denotes the value, not its DER encoding.
        let max_serial = "1461501637330902918203684832716283019655932542975";
        assert_eq!(
            x509_serial_decimal_to_hex(max_serial),
            Some("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".into())
        );
        assert_eq!(
            x509_serial_decimal_to_hex("730750818665451459101842416358141509827966271488"),
            Some("8000000000000000000000000000000000000000".into())
        );
        assert_eq!(
            x509_serial_decimal_to_hex("0000000000000000000000000000000000000000000000001"),
            Some("01".into())
        );
        assert_eq!(
            x509_serial_decimal_to_hex("00000000000000000000000000000000000000000000000001"),
            Some("01".into())
        );
        assert_eq!(x509_serial_decimal_to_hex("+1"), Some("01".into()));

        for invalid in [
            "",
            "0",
            "000",
            "+0",
            "++1",
            "-1",
            "1a",
            "1461501637330902918203684832716283019655932542976",
        ] {
            assert_eq!(
                x509_serial_decimal_to_hex(invalid),
                None,
                "invalid serial {invalid:?} must be rejected"
            );
        }
    }

    #[test]
    fn parse_x509_serial_normalizes_boundary_whitespace_and_rejects_overflow() {
        // XML Schema collapses integer whitespace before validation; the
        // normalized value must still obey the RFC 5280 positive range.
        let max_serial = "1461501637330902918203684832716283019655932542975";
        let valid = format!(
            "<KeyInfo xmlns=\"{XMLDSIG_NS}\"><X509Data><X509IssuerSerial><X509IssuerName>CN=issuer</X509IssuerName><X509SerialNumber>\n {max_serial}\t</X509SerialNumber></X509IssuerSerial></X509Data></KeyInfo>"
        );
        let doc = Document::parse(&valid).unwrap();
        let parsed = parse_key_info(doc.root_element()).unwrap();
        let KeyInfoSource::X509Data(x509) = &parsed.sources[0] else {
            panic!("expected X509Data source");
        };
        assert_eq!(x509.issuer_serials[0].1, max_serial);

        let explicit_positive = valid.replace(max_serial, "+42");
        let doc = Document::parse(&explicit_positive).unwrap();
        let parsed = parse_key_info(doc.root_element()).unwrap();
        let KeyInfoSource::X509Data(x509) = &parsed.sources[0] else {
            panic!("expected X509Data source");
        };
        assert_eq!(x509.issuer_serials[0].1, "42");

        let overflow = valid.replace(
            max_serial,
            "1461501637330902918203684832716283019655932542976",
        );
        let doc = Document::parse(&overflow).unwrap();
        assert!(matches!(
            parse_key_info(doc.root_element()),
            Err(ParseError::InvalidStructure(message))
                if message.contains("invalid X509SerialNumber")
        ));
    }

    #[test]
    fn issuer_selector_matches_a_sign_padded_twenty_octet_serial() {
        // Selector decimal text represents the unsigned magnitude; the DER
        // sign-padding octet must not make the same certificate unmatchable.
        let serial_hex = "8000000000000000000000000000000000000000";
        let info = X509DataInfo {
            issuer_serials: vec![(
                "CN=issuer".into(),
                "730750818665451459101842416358141509827966271488".into(),
            )],
            parsed_certificates: vec![ParsedX509Certificate {
                subject_dn: "CN=leaf".into(),
                issuer_dn: "CN=issuer".into(),
                serial_number: [vec![0, 0x80], vec![0; 19]].concat(),
                serial_number_hex: serial_hex.into(),
                subject_key_identifier: None,
                public_key: X509PublicKeyInfo::Unsupported {
                    algorithm_oid: "1.2.3.4".into(),
                },
            }],
            ..X509DataInfo::default()
        };

        assert!(
            x509_selector_categories_match_chain(&info, crate::provider::default_provider())
                .unwrap()
        );
    }

    #[test]
    fn distinguished_name_matching_preserves_rdn_order() {
        // RFC 4514 permits alternate encodings within an RDN, but reversing
        // the RDN sequence identifies a different hierarchical name.
        assert!(distinguished_names_equal(
            "CN=leaf, O=example",
            "CN=leaf,O=example"
        ));
        assert!(!distinguished_names_equal(
            "CN=leaf,O=example",
            "O=example,CN=leaf"
        ));
    }

    #[test]
    fn distinguished_name_matching_applies_x520_string_preparation() {
        // RFC 5280 requires caseIgnoreMatch with insignificant-space handling
        // for DirectoryString values rather than exact ASN.1 value equality.
        assert!(distinguished_names_equal(
            "CN=  TEST   key  ,O=Example",
            "CN=test key,O=example"
        ));
        assert!(distinguished_names_equal(
            "CN=Straße,O=Example",
            "CN=STRASSE,O=EXAMPLE"
        ));
        assert!(distinguished_names_equal(
            "CN=test+OU=security,O=example",
            "OU=SECURITY+CN=TEST,O=EXAMPLE"
        ));
        assert!(!distinguished_names_equal(
            "1.2.3.4=#040141,O=example",
            "1.2.3.4=#040142,O=example"
        ));
    }

    #[test]
    fn distinguished_name_matching_applies_ia5_matching_rules() {
        // RFC 5280 emailAddress matching preserves the local part while the
        // domain is case-insensitive; domainComponent is case-insensitive too.
        assert!(distinguished_names_equal(
            "EMAIL=ops@EXAMPLE.COM,DC=EXAMPLE,DC=COM",
            "EMAIL=ops@example.com,DC=example,DC=com"
        ));
        assert!(!distinguished_names_equal(
            "EMAIL=OPS@example.com,DC=example,DC=com",
            "EMAIL=ops@example.com,DC=example,DC=com"
        ));
    }

    #[test]
    fn distinguished_name_matching_handles_rfc4514_escaped_values() {
        // Certificate values containing RFC 4514 separators and boundary spaces
        // must remain one attribute when matched against an XMLDSig selector.
        let value = " leading,plus+equals=slash\\trailing ";
        let mut params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, value);
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key).unwrap();
        let parsed = parse_x509_certificate(certificate.der()).unwrap();

        assert_eq!(
            parsed.subject_dn,
            r"CN=\ leading\,plus\+equals=slash\\trailing\ "
        );
        assert!(distinguished_names_equal(
            r"CN=\ leading\,plus\+equals=slash\\trailing\ ",
            &parsed.subject_dn
        ));
        assert!(distinguished_names_equal(
            "\n  CN=\\ leading\\,plus\\+equals=slash\\\\trailing\\ \n",
            &parsed.subject_dn
        ));
    }

    #[test]
    fn distinguished_name_trailing_escape_covers_all_xml_whitespace() {
        // The normalizer strips all four XML whitespace characters, so escape
        // detection must preserve each one consistently at RDN boundaries.
        for whitespace in [' ', '\t', '\r', '\n'] {
            assert!(trailing_whitespace_is_escaped(&format!(
                "CN=value\\{whitespace}"
            )));
            assert!(!trailing_whitespace_is_escaped(&format!(
                "CN=value{whitespace}"
            )));
        }
    }

    #[test]
    fn parse_key_info_accepts_large_textual_x509_entries_within_entry_budget() {
        let issuer_name = "C".repeat(MAX_X509_ISSUER_NAME_TEXT_LEN);
        let serial_number = "0".repeat(MAX_X509_SERIAL_NUMBER_VALUE_DIGITS - 1) + "1";
        let issuer_serials = (0..52)
            .map(|_| {
                format!(
                    "<X509IssuerSerial><X509IssuerName>{issuer_name}</X509IssuerName><X509SerialNumber>{serial_number}</X509SerialNumber></X509IssuerSerial>"
                )
            })
            .collect::<Vec<_>>()
            .join("");
        let xml = format!(
            "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data>{issuer_serials}</X509Data></KeyInfo>"
        );
        let doc = Document::parse(&xml).unwrap();

        let key_info = parse_key_info(doc.root_element()).unwrap();
        let parsed = match &key_info.sources[0] {
            KeyInfoSource::X509Data(x509) => x509,
            _ => panic!("expected X509Data source"),
        };
        assert_eq!(parsed.issuer_serials.len(), 52);
    }

    #[test]
    fn parse_key_info_bounds_raw_x509_serial_text() {
        // Leading zeroes are lexically valid, but their raw XML representation
        // remains bounded independently from the canonical certificate value.
        let serial = "0".repeat(MAX_X509_SERIAL_NUMBER_RAW_TEXT_LEN + 1);
        let xml = format!(
            "<KeyInfo xmlns=\"{XMLDSIG_NS}\"><X509Data><X509IssuerSerial><X509IssuerName>CN=issuer</X509IssuerName><X509SerialNumber>{serial}</X509SerialNumber></X509IssuerSerial></X509Data></KeyInfo>"
        );
        let doc = Document::parse(&xml).unwrap();

        let error = parse_key_info(doc.root_element()).unwrap_err();

        assert!(matches!(
            error,
            ParseError::InvalidStructure(reason)
                if reason == "X509SerialNumber exceeds maximum allowed text length"
        ));
    }

    #[test]
    fn parse_key_info_accepts_x509data_with_only_foreign_namespace_children() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"
                              xmlns:foo="urn:example:foo">
            <X509Data>
                <foo:Bar/>
            </X509Data>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let key_info = parse_key_info(doc.root_element()).unwrap();
        assert_eq!(
            key_info.sources,
            vec![KeyInfoSource::X509Data(X509DataInfo::default())]
        );
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
    fn parse_key_info_der_encoded_key_value_accepts_xml_whitespace() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"
                              xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">
            <dsig11:DEREncodedKeyValue>
                AQID
                BA==
            </dsig11:DEREncodedKeyValue>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let key_info = parse_key_info(doc.root_element()).unwrap();
        assert_eq!(
            key_info.sources,
            vec![KeyInfoSource::DerEncodedKeyValue(vec![1, 2, 3, 4])]
        );
    }

    #[test]
    fn parse_key_info_dispatches_dsig11_ec_keyvalue() {
        let public_key = "BJ/yaXNlq4FRObyJCBhb5jAz8GVzinK3bBGLjSDfjbJwNfydtgjnlS4EsDmxSRhWyJWq6GIqy5wvnaiARK04uB4=";
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"
                              xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">
            <KeyValue>
                <dsig11:ECKeyValue>
                    <dsig11:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/>
                    <dsig11:PublicKey>BJ/yaXNlq4FRObyJCBhb5jAz8GVzinK3bBGLjSDfjbJwNfydtgjnlS4EsDmxSRhWyJWq6GIqy5wvnaiARK04uB4=</dsig11:PublicKey>
                </dsig11:ECKeyValue>
            </KeyValue>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();
        let expected_public_key = base64::engine::general_purpose::STANDARD
            .decode(public_key)
            .expect("fixture EC point must be valid base64");

        let key_info = parse_key_info(doc.root_element()).unwrap();
        assert_eq!(
            key_info.sources,
            vec![KeyInfoSource::KeyValue(KeyValueInfo::Ec {
                curve_oid: "1.2.840.10045.3.1.7".into(),
                public_key: expected_public_key,
            })]
        );
    }

    #[test]
    fn parse_ec_key_value_accepts_bare_curve_oid() {
        use base64::Engine;

        let encoded_public_key = "BO/yd/OZzDfjX4qivDY/vsUIuh6KWAxoxW5P4ukvwd+T6pVljWsX2UBJNNy5MdhTwB8e2YwB8kUbJwdsAS/XGi/fz8unFrs+lVlAgIs6s/xBYFbfUoRiAacD2SpVDe6XBA==";
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"
                              xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">
            <KeyValue>
                <dsig11:ECKeyValue>
                    <dsig11:NamedCurve URI="1.3.132.0.34"/>
                    <dsig11:PublicKey>BO/yd/OZzDfjX4qivDY/vsUIuh6KWAxoxW5P4ukvwd+T6pVljWsX2UBJNNy5MdhTwB8e2YwB8kUbJwdsAS/XGi/fz8unFrs+lVlAgIs6s/xBYFbfUoRiAacD2SpVDe6XBA==</dsig11:PublicKey>
                </dsig11:ECKeyValue>
            </KeyValue>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();
        let expected_public_key = base64::engine::general_purpose::STANDARD
            .decode(encoded_public_key)
            .unwrap();

        let sources = parse_key_info(doc.root_element()).unwrap().sources;

        assert!(matches!(
            &sources[0],
            KeyInfoSource::KeyValue(KeyValueInfo::Ec { curve_oid, public_key })
                if curve_oid == EC_P384_OID && public_key == &expected_public_key
        ));
    }

    #[test]
    fn parse_ec_key_value_marks_ec_parameters_as_unsupported() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"
                              xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">
            <KeyValue>
                <dsig11:ECKeyValue>
                    <dsig11:ECParameters/>
                    <dsig11:PublicKey>BA==</dsig11:PublicKey>
                </dsig11:ECKeyValue>
            </KeyValue>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let key_info = parse_key_info(doc.root_element()).unwrap();
        assert_eq!(
            key_info.sources,
            vec![KeyInfoSource::KeyValue(KeyValueInfo::Unsupported {
                namespace: Some(XMLDSIG11_NS.to_string()),
                local_name: "ECKeyValue".into(),
            })]
        );
    }

    #[test]
    fn parse_ec_key_value_marks_unsupported_curve_as_unsupported() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"
                              xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">
            <KeyValue>
                <dsig11:ECKeyValue>
                    <dsig11:NamedCurve URI="urn:oid:1.3.132.0.36"/>
                    <dsig11:PublicKey>BA==</dsig11:PublicKey>
                </dsig11:ECKeyValue>
            </KeyValue>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let key_info = parse_key_info(doc.root_element()).unwrap();
        assert_eq!(
            key_info.sources,
            vec![KeyInfoSource::KeyValue(KeyValueInfo::Unsupported {
                namespace: Some(XMLDSIG11_NS.to_string()),
                local_name: "ECKeyValue".into(),
            })]
        );
    }

    #[test]
    fn parse_ec_key_value_marks_missing_named_curve_uri_invalid() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"
                              xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">
            <KeyValue>
                <dsig11:ECKeyValue>
                    <dsig11:NamedCurve/>
                    <dsig11:PublicKey>BA==</dsig11:PublicKey>
                </dsig11:ECKeyValue>
            </KeyValue>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let key_info = parse_key_info(doc.root_element()).unwrap();
        assert_eq!(
            key_info.sources,
            vec![KeyInfoSource::KeyValue(KeyValueInfo::InvalidEcKeyValue)]
        );
    }

    #[test]
    fn parse_ec_key_value_marks_reordered_children_invalid() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"
                              xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">
            <KeyValue>
                <dsig11:ECKeyValue>
                    <dsig11:PublicKey>BJ/yaXNlq4FRObyJCBhb5jAz8GVzinK3bBGLjSDfjbJwNfydtgjnlS4EsDmxSRhWyJWq6GIqy5wvnaiARK04uB4=</dsig11:PublicKey>
                    <dsig11:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/>
                </dsig11:ECKeyValue>
            </KeyValue>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let key_info = parse_key_info(doc.root_element()).unwrap();
        assert_eq!(
            key_info.sources,
            vec![KeyInfoSource::KeyValue(KeyValueInfo::InvalidEcKeyValue)]
        );
    }

    #[test]
    fn parse_ec_key_value_marks_non_uncompressed_point_invalid() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"
                              xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">
            <KeyValue>
                <dsig11:ECKeyValue>
                    <dsig11:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/>
                    <dsig11:PublicKey>Ap/yaXNlq4FRObyJCBhb5jAz8GVzinK3bBGLjSDfjbJwNfydtgjnlS4EsDmxSRhWyJWq6GIqy5wvnaiARK04uB4=</dsig11:PublicKey>
                </dsig11:ECKeyValue>
            </KeyValue>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let key_info = parse_key_info(doc.root_element()).unwrap();
        assert_eq!(
            key_info.sources,
            vec![KeyInfoSource::KeyValue(KeyValueInfo::InvalidEcKeyValue)]
        );
    }

    #[test]
    fn parse_key_info_marks_ds_namespace_ec_keyvalue_as_unsupported() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <KeyValue>
                <ECKeyValue/>
            </KeyValue>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let key_info = parse_key_info(doc.root_element()).unwrap();
        assert_eq!(
            key_info.sources,
            vec![KeyInfoSource::KeyValue(KeyValueInfo::Unsupported {
                namespace: Some(XMLDSIG_NS.to_string()),
                local_name: "ECKeyValue".into(),
            })]
        );
    }

    #[test]
    fn parse_key_info_keeps_unsupported_keyvalue_child_as_marker() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <KeyValue>
                <FutureKeyValue/>
            </KeyValue>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let key_info = parse_key_info(doc.root_element()).unwrap();
        assert_eq!(
            key_info.sources,
            vec![KeyInfoSource::KeyValue(KeyValueInfo::Unsupported {
                namespace: Some(XMLDSIG_NS.to_string()),
                local_name: "FutureKeyValue".into(),
            })]
        );
    }

    #[test]
    fn parse_key_info_accepts_supported_x509_retrieval_xpath() {
        // Merlin's same-document RetrievalMethod selects only X509Data nodes.
        let xml = r##"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
          <RetrievalMethod Type="http://www.w3.org/2000/09/xmldsig#X509Data" URI="#keys">
            <Transforms><Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
              <XPath xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">ancestor-or-self::dsig:X509Data</XPath>
            </Transform></Transforms>
          </RetrievalMethod>
        </KeyInfo>"##;
        let doc = Document::parse(xml).unwrap();

        let key_info = parse_key_info(doc.root_element()).unwrap();
        assert!(matches!(
            key_info.sources.as_slice(),
            [KeyInfoSource::RetrievalMethod {
                uri,
                resource_type: Some(resource_type),
                transforms: RetrievalMethodTransforms::X509DataNodeSetFilter { .. },
            }] if uri == "#keys"
                && resource_type == "http://www.w3.org/2000/09/xmldsig#X509Data"
        ));
    }

    #[test]
    fn retrieval_xpath_namespace_binding_policy_precedes_materialization() {
        // RetrievalMethod must reject inherited namespace bindings before
        // cloning their prefix and URI into the retained transform model.
        let xml = r##"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
          <RetrievalMethod Type="http://www.w3.org/2000/09/xmldsig#X509Data" URI="#keys">
            <Transforms><Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
              <XPath xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">ancestor-or-self::dsig:X509Data</XPath>
            </Transform></Transforms>
          </RetrievalMethod>
        </KeyInfo>"##;
        let document = Document::parse(xml).expect("fixed KeyInfo fixture must parse");
        let resources = crate::policy::ResourcePolicy {
            max_xpath_namespace_bindings: 0,
            ..crate::policy::ResourcePolicy::default()
        };

        let error = parse_key_info_with_policy_budgets(
            document.root_element(),
            crate::provider::default_provider(),
            &XmlBaseResolutionBudget::default(),
            &resources,
        )
        .expect_err("zero namespace bindings must reject RetrievalMethod XPath");

        assert!(matches!(
            error,
            ParseError::Transform(TransformError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XPATH_NAMESPACE_BINDINGS,
                    maximum: 0,
                    actual: 1,
                }
            ))
        ));
    }

    #[test]
    fn retrieval_xpath_namespace_byte_policy_precedes_materialization() {
        // The aggregate namespace byte limit applies to borrowed prefix and URI
        // text before either attacker-controlled string is allocated.
        let xml = r##"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
          <RetrievalMethod Type="http://www.w3.org/2000/09/xmldsig#X509Data" URI="#keys">
            <Transforms><Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
              <XPath xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">ancestor-or-self::dsig:X509Data</XPath>
            </Transform></Transforms>
          </RetrievalMethod>
        </KeyInfo>"##;
        let document = Document::parse(xml).expect("fixed KeyInfo fixture must parse");
        let resources = crate::policy::ResourcePolicy {
            max_xpath_namespace_bytes: 0,
            ..crate::policy::ResourcePolicy::default()
        };

        let error = parse_key_info_with_policy_budgets(
            document.root_element(),
            crate::provider::default_provider(),
            &XmlBaseResolutionBudget::default(),
            &resources,
        )
        .expect_err("zero namespace bytes must reject RetrievalMethod XPath");

        assert!(matches!(
            error,
            ParseError::Transform(TransformError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XPATH_NAMESPACE_BYTES,
                    maximum: 0,
                    actual,
                }
            )) if actual == "dsig".len() + XMLDSIG_NS.len()
        ));
    }

    #[test]
    fn parse_key_info_rejects_oversized_retrieval_method_type() {
        // Type is advisory, but retaining it must not allocate unbounded
        // attacker-controlled KeyInfo metadata before resolution.
        let oversized_type = "x".repeat(MAX_KEY_NAME_TEXT_LEN + 1);
        let xml = format!(
            r##"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><RetrievalMethod URI="#key" Type="{oversized_type}"/></KeyInfo>"##
        );
        let document = Document::parse(&xml).unwrap();

        assert!(matches!(
            parse_key_info(document.root_element()),
            Err(ParseError::InvalidStructure(reason))
                if reason == "RetrievalMethod Type exceeds maximum length"
        ));
    }

    #[test]
    fn parse_key_info_bounds_retrieval_method_xml_base_chain() {
        // RetrievalMethod resolves its resource identity during parsing, so it
        // must use the same bounded XML Base algorithm as Reference lookup.
        let mut xml =
            format!(r#"<KeyInfo xmlns="{XMLDSIG_NS}"><RetrievalMethod URI="key.der"/></KeyInfo>"#);
        for _ in 0..65 {
            xml = format!(r#"<n xml:base="segment/">{xml}</n>"#);
        }
        let document = Document::parse(&xml).unwrap();
        let key_info = document
            .descendants()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "KeyInfo")))
            .unwrap();

        assert!(matches!(
            parse_key_info(key_info),
            Err(ParseError::InvalidStructure(reason))
                if reason.contains("XML Base resolution")
        ));
    }

    #[test]
    fn parse_key_info_normalizes_external_retrieval_without_xml_base() {
        // RetrievalMethod stores the resolved identity used for caller-map
        // lookup, including RFC 3986 normalization when no base is declared.
        let xml = format!(
            r#"<KeyInfo xmlns="{XMLDSIG_NS}"><RetrievalMethod URI="https://example.test/a/../key.der"/></KeyInfo>"#
        );
        let document = Document::parse(&xml).unwrap();
        let key_info = parse_key_info(document.root_element()).unwrap();

        assert!(matches!(
            key_info.sources.as_slice(),
            [KeyInfoSource::RetrievalMethod { uri, .. }]
                if uri == "https://example.test/key.der"
        ));
    }

    #[test]
    fn parse_key_info_absolute_retrieval_bypasses_xml_base_chain() {
        // Absolute RetrievalMethod identities do not inherit xml:base, so an
        // otherwise excessive ancestor chain must not reject them.
        let mut xml = format!(
            r#"<KeyInfo xmlns="{XMLDSIG_NS}"><RetrievalMethod URI="https://example.test/a/../key.der"/></KeyInfo>"#
        );
        for _ in 0..65 {
            xml = format!(r#"<n xml:base="segment/">{xml}</n>"#);
        }
        let document = Document::parse(&xml).unwrap();
        let key_info_node = document
            .descendants()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "KeyInfo")))
            .unwrap();
        let key_info = parse_key_info(key_info_node)
            .expect("absolute RetrievalMethod must not consume ancestor-base budget");

        assert!(matches!(
            key_info.sources.as_slice(),
            [KeyInfoSource::RetrievalMethod { uri, .. }]
                if uri == "https://example.test/key.der"
        ));
    }

    #[test]
    fn parse_key_info_accepts_namespace_equivalent_retrieval_xpath_prefix() {
        let xml = r##"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
          <RetrievalMethod Type="http://www.w3.org/2000/09/xmldsig#X509Data" URI="#keys">
            <Transforms><Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
              <XPath xmlns:ds="http://www.w3.org/2000/09/xmldsig#">ancestor-or-self::ds:X509Data</XPath>
            </Transform></Transforms>
          </RetrievalMethod>
        </KeyInfo>"##;
        let doc = Document::parse(xml).unwrap();

        assert!(matches!(
            parse_key_info(doc.root_element())
                .unwrap()
                .sources
                .as_slice(),
            [KeyInfoSource::RetrievalMethod {
                transforms: RetrievalMethodTransforms::X509DataNodeSetFilter { .. },
                ..
            }]
        ));
    }

    #[test]
    fn parse_key_info_reads_complete_retrieval_xpath_text() {
        // XML comments split character data into multiple text nodes; all chunks
        // still belong to the XPath parameter's string-value.
        let valid = r##"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
          <RetrievalMethod Type="http://www.w3.org/2000/09/xmldsig#X509Data" URI="#keys">
            <Transforms><Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
              <XPath xmlns:ds="http://www.w3.org/2000/09/xmldsig#">ancestor-or-self::ds:X509<!-- split -->Data</XPath>
            </Transform></Transforms>
          </RetrievalMethod>
        </KeyInfo>"##;
        let document = Document::parse(valid).unwrap();
        assert!(parse_key_info(document.root_element()).is_ok());

        let unsupported =
            valid.replace("X509<!-- split -->Data", "X509Data<!-- split -->[false()]");
        let document = Document::parse(&unsupported).unwrap();
        assert!(matches!(
            parse_key_info(document.root_element()),
            Err(ParseError::InvalidStructure(reason))
                if reason == "unsupported RetrievalMethod XPath selection"
        ));
    }

    #[test]
    fn parse_dsa_key_value_accepts_schema_optional_parameters_and_rejects_half_pair() {
        let key_info = |parameters: &str| {
            format!(
                r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><KeyValue><DSAKeyValue>
                {parameters}
                </DSAKeyValue></KeyValue></KeyInfo>"#
            )
        };
        for parameters in [
            "<Y>AQ==</Y>",
            "<G>AQ==</G><Y>AQ==</Y>",
            "<P>AQ==</P><Q>AQ==</Q><Y>AQ==</Y>",
            "<P>AQ==</P><Q>AQ==</Q><G>AQ==</G><Y>AQ==</Y><J>AQ==</J>",
            "<Y>AQ==</Y><Seed>AQ==</Seed><PgenCounter>AQ==</PgenCounter>",
            "<Y>AQ==</Y><J>AQ==</J><Seed>AQ==</Seed><PgenCounter>AQ==</PgenCounter>",
        ] {
            let xml = key_info(parameters);
            let doc = Document::parse(&xml).unwrap();
            assert!(matches!(
                parse_key_info(doc.root_element())
                    .unwrap()
                    .sources
                    .as_slice(),
                [KeyInfoSource::KeyValue(KeyValueInfo::Dsa { .. })]
            ));
        }

        for invalid_parameters in [
            "<P>AQ==</P><Y>AQ==</Y>",
            "<Q>AQ==</Q><Y>AQ==</Y>",
            "<Y>AQ==</Y><Seed>AQ==</Seed>",
            "<Y>AQ==</Y><PgenCounter>AQ==</PgenCounter>",
        ] {
            let xml = key_info(invalid_parameters);
            let doc = Document::parse(&xml).unwrap();
            assert!(matches!(
                parse_key_info(doc.root_element()),
                Err(ParseError::InvalidStructure(_))
            ));
        }
    }

    #[test]
    fn parse_dsa_crypto_binary_ignores_comment_nodes() {
        // XML comments split simple content without contributing to its string value.
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <KeyValue><DSAKeyValue><Y>AQ<!-- split -->ID</Y></DSAKeyValue></KeyValue>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        assert!(matches!(
            parse_key_info(doc.root_element())
                .unwrap()
                .sources
                .as_slice(),
            [KeyInfoSource::KeyValue(KeyValueInfo::Dsa { y, .. })] if y == &[1, 2, 3]
        ));
    }

    #[test]
    fn parse_rsa_crypto_binary_ignores_comment_nodes() {
        // The shared CryptoBinary decoder must apply XML simple-content semantics to every key type.
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <KeyValue><RSAKeyValue>
                <Modulus>AQ<!-- split -->ID</Modulus><Exponent>Aw==</Exponent>
            </RSAKeyValue></KeyValue>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        assert!(matches!(
            parse_key_info(doc.root_element())
                .unwrap()
                .sources
                .as_slice(),
            [KeyInfoSource::KeyValue(KeyValueInfo::Rsa { modulus, exponent })]
                if modulus == &[1, 2, 3] && exponent == &[3]
        ));
    }

    #[test]
    fn parse_key_info_preserves_advisory_unsupported_retrieval_transform() {
        // Unsupported RetrievalMethod types are advisory key sources. Their
        // transform syntax must not hide a later source the resolver can use.
        let xml = r##"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
          <RetrievalMethod URI="#keys" Type="urn:vendor:key"><Transforms>
            <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#base64"/>
          </Transforms></RetrievalMethod>
          <KeyName>fallback</KeyName>
        </KeyInfo>"##;
        let doc = Document::parse(xml).unwrap();

        let key_info = parse_key_info(doc.root_element())
            .expect("unsupported advisory retrieval must not reject all KeyInfo sources");
        assert!(matches!(
            key_info.sources.as_slice(),
            [
                KeyInfoSource::RetrievalMethod { resource_type: Some(resource_type), .. },
                KeyInfoSource::KeyName(name),
            ] if resource_type == "urn:vendor:key" && name == "fallback"
        ));
    }

    #[test]
    fn parse_key_info_rejects_excessive_child_sources() {
        // KeyInfo extensions are lax, but their parse work remains bounded.
        let children = (0..=64)
            .map(|index| format!(r#"<extension xmlns="urn:test" index="{index}"/>"#))
            .collect::<String>();
        let xml =
            format!(r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">{children}</KeyInfo>"#);
        let document = Document::parse(&xml).unwrap();

        assert!(matches!(
            parse_key_info(document.root_element()),
            Err(ParseError::InvalidStructure(reason))
                if reason == "KeyInfo contains too many child elements"
        ));
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
    fn parse_key_info_rejects_oversized_keyname_text() {
        let oversized = "A".repeat(4097);
        let xml = format!(
            "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><KeyName>{oversized}</KeyName></KeyInfo>"
        );
        let doc = Document::parse(&xml).unwrap();

        let err = parse_key_info(doc.root_element()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidStructure(_)));
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

    #[test]
    fn parse_key_info_der_encoded_key_value_rejects_empty_payload() {
        let xml = r#"<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"
                              xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">
            <dsig11:DEREncodedKeyValue>
                
            </dsig11:DEREncodedKeyValue>
        </KeyInfo>"#;
        let doc = Document::parse(xml).unwrap();

        let err = parse_key_info(doc.root_element()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidStructure(_)));
    }

    #[test]
    fn parse_key_info_der_encoded_key_value_non_xml_ascii_whitespace_is_not_parseable_xml() {
        let xml = "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:dsig11=\"http://www.w3.org/2009/xmldsig11#\"><dsig11:DEREncodedKeyValue>\u{000C}</dsig11:DEREncodedKeyValue></KeyInfo>";
        assert!(Document::parse(xml).is_err());
    }

    // ── parse_signed_info: happy path ────────────────────────────────

    #[test]
    fn parse_hmac_output_length_reads_all_text_nodes() {
        // A comment may split valid simple content without changing its value.
        let xml = r#"<SignatureMethod xmlns="http://www.w3.org/2000/09/xmldsig#">
            <HMACOutputLength>8<!-- split -->0</HMACOutputLength>
        </SignatureMethod>"#;
        let document = Document::parse(xml).unwrap();

        assert_eq!(
            parse_hmac_output_length(document.root_element(), SignatureAlgorithm::HmacSha1)
                .unwrap(),
            Some(80)
        );
    }

    #[test]
    fn hmac_sha256_accepts_byte_aligned_output_length() {
        let document = Document::parse(
            r#"<ds:SignatureMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"><ds:HMACOutputLength>128</ds:HMACOutputLength></ds:SignatureMethod>"#,
        )
        .unwrap();
        let algorithm =
            SignatureAlgorithm::from_uri("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256")
                .expect("HMAC-SHA256 must be recognized");

        assert_eq!(
            parse_hmac_output_length(document.root_element(), algorithm).unwrap(),
            Some(128)
        );
    }

    #[test]
    fn parse_hmac_output_length_rejects_hidden_suffix_text() {
        // Reading only the first text node would misinterpret 800 bits as 80.
        let xml = r#"<SignatureMethod xmlns="http://www.w3.org/2000/09/xmldsig#">
            <HMACOutputLength>80<!-- split -->0</HMACOutputLength>
        </SignatureMethod>"#;
        let document = Document::parse(xml).unwrap();

        assert!(matches!(
            parse_hmac_output_length(document.root_element(), SignatureAlgorithm::HmacSha1),
            Err(ParseError::InvalidStructure(reason))
                if reason == "HMACOutputLength must be a positive byte-aligned value no greater than 160"
        ));
    }

    #[test]
    fn parse_hmac_output_length_rejects_non_octet_truncation() {
        // XMLDSig 1.1 section 6.3.1 requires a byte boundary even though the
        // HMACOutputLength schema represents the value as a bit count.
        let xml = r#"<SignatureMethod xmlns="http://www.w3.org/2000/09/xmldsig#">
            <HMACOutputLength>81</HMACOutputLength>
        </SignatureMethod>"#;
        let document = Document::parse(xml).unwrap();

        assert!(matches!(
            parse_hmac_output_length(document.root_element(), SignatureAlgorithm::HmacSha1),
            Err(ParseError::InvalidStructure(reason))
                if reason == "HMACOutputLength must be a positive byte-aligned value no greater than 160"
        ));
    }

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

        assert_eq!(si.signature_method, SignatureAlgorithm::EcdsaSha256);
        assert_eq!(si.references.len(), 2);
        assert_eq!(si.references[0].uri.as_deref(), Some("#a"));
        assert_eq!(si.references[0].digest_method, DigestAlgorithm::Sha256);
        assert_eq!(si.references[1].uri.as_deref(), Some("#b"));
        assert_eq!(si.references[1].digest_method, DigestAlgorithm::Sha1);
    }

    #[test]
    fn parse_signed_info_rejects_too_many_references() {
        // Reference processing shares signature-wide resource budgets, so the
        // parser must bound cardinality before retaining attacker-controlled entries.
        let references = (0..=MAX_REFERENCES_PER_SIGNATURE)
            .map(|index| {
                format!(
                    r##"<Reference URI="#item-{index}">
                        <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</DigestValue>
                    </Reference>"##
                )
            })
            .collect::<String>();
        let xml = format!(
            r#"<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                {references}
            </SignedInfo>"#
        );
        let document = Document::parse(&xml).expect("fixed oversized fixture must parse");

        let error = parse_signed_info(document.root_element())
            .expect_err("the parser must reject the 65th Reference");

        assert!(matches!(
            error,
            ParseError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::SIGNATURE_REFERENCES,
                maximum: MAX_REFERENCES_PER_SIGNATURE,
                actual: 65,
            })
        ));
    }

    #[test]
    fn parse_signed_info_bounds_xpath_expressions_across_references() {
        // Per-reference limits alone permit an attacker to retain and compile
        // thousands of XPath programs before signature verification begins.
        let filters = r#"<XPath xmlns="http://www.w3.org/2002/06/xmldsig-filter2" Filter="intersect">true()</XPath>"#
            .repeat(64);
        let filter_transform = format!(
            r#"<Transform Algorithm="http://www.w3.org/2002/06/xmldsig-filter2">{filters}</Transform>"#
        );
        let reference = |index, transforms: &str| {
            format!(
                r##"<Reference URI="#item-{index}">
                        <Transforms>{transforms}</Transforms>
                        <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</DigestValue>
                    </Reference>"##
            )
        };
        let signed_info = |references: &str| {
            format!(
                r#"<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                {references}
            </SignedInfo>"#
            )
        };

        let max_reference = reference(0, &filter_transform.repeat(64));
        let boundary_xml = signed_info(&max_reference);
        let boundary_document =
            Document::parse(&boundary_xml).expect("fixed boundary fixture must parse");
        parse_signed_info(boundary_document.root_element())
            .expect("one maximum-shaped Reference must remain accepted");

        let extra_transform = r#"<Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><XPath>true()</XPath></Transform>"#;
        let xml = signed_info(&format!("{max_reference}{}", reference(1, extra_transform)));
        let document = Document::parse(&xml).expect("fixed aggregate fixture must parse");

        let error = parse_signed_info(document.root_element())
            .expect_err("signature-wide XPath expression count must be bounded");

        assert!(matches!(
            error,
            ParseError::Transform(TransformError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: "XPath expressions",
                    ..
                }
            ))
        ));
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

    #[test]
    fn base64_decode_digest_rejects_oversized_base64_before_decode() {
        let err = base64_decode_digest("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", DigestAlgorithm::Sha1)
            .expect_err("oversized DigestValue base64 must fail before decode");
        match err {
            ParseError::Base64(message) => {
                assert!(
                    message.contains("DigestValue exceeds maximum allowed base64 length"),
                    "unexpected message: {message}"
                );
            }
            other => panic!("expected ParseError::Base64, got {other:?}"),
        }
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
