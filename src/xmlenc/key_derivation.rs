//! XML KDF syntax normalized into the provider's single parameter contract.

use crate::document::{
    DocumentParseSettings, XmlParseWorkBudget, parse_borrowed_with_settings_and_budget,
};
use crate::provider::{KdfContext, KdfParameters};
use crate::xml::dom::Node;

use super::parse::{
    bounded_simple_text_with_limit, decode_bounded_base64_text, require_element as require,
    validate_metadata_len,
};
use super::types::{XMLDSIG_NS, XMLENC11_NS};
use super::{XmlEncError, map_document_error};

mod serialize;

const MORE_NS: &str = "http://www.w3.org/2021/04/xmldsig-more#";
const CONCAT: &str = "http://www.w3.org/2009/xmlenc11#ConcatKDF";
const PBKDF2: &str = "http://www.w3.org/2009/xmlenc11#pbkdf2";
const HKDF: &str = "http://www.w3.org/2021/04/xmldsig-more#hkdf";

/// Identity/context field in XMLEnc's ConcatKDF OtherInfo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConcatKdfField {
    /// AlgorithmID, interpreted by the application.
    AlgorithmId,
    /// Originator's PartyUInfo.
    PartyUInfo,
    /// Recipient's PartyVInfo.
    PartyVInfo,
    /// Supplementary public information.
    SuppPubInfo,
    /// Supplementary private information.
    SuppPrivInfo,
}

/// Parsed XML key-derivation parameters, without private key material.
///
/// Parsing does not grant permission to derive a key. The enclosing operation
/// must validate its compiled policy, reserve work and gate provider execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDerivationMethod {
    algorithm: String,
    digest: String,
    salt: Vec<u8>,
    context: Vec<u8>,
    context_bits: Option<usize>,
    concat_fields: [Option<(usize, usize)>; 5],
    iterations: u64,
    key_length: Option<usize>,
}

impl KeyDerivationMethod {
    pub(super) fn validate_metadata(&self, maximum: usize) -> Result<(), XmlEncError> {
        serialize::validate_metadata(self, maximum)
    }
    /// Serialize public KDF parameters without secret key material. The exact
    /// escaped output length is checked before allocating the output buffer.
    /// Field boundaries and significant ConcatKDF bits survive transport.
    pub fn to_xml(&self, resources: &crate::policy::ResourcePolicy) -> Result<String, XmlEncError> {
        serialize::serialize(self, resources)
    }
    pub(super) fn hkdf(digest: String, salt: Vec<u8>, context: Vec<u8>, key_length: usize) -> Self {
        Self {
            algorithm: HKDF.into(),
            digest,
            salt,
            context,
            context_bits: None,
            concat_fields: [None; 5],
            iterations: 0,
            key_length: Some(key_length),
        }
    }
    /// Execute parsed parameters under the enclosing operation's shared
    /// allowance. Explicit XML KeyLength must match the consuming cipher.
    pub fn derive_key(
        &self,
        output_len: usize,
        provider: &dyn crate::provider::CryptoProvider,
        secret: &[u8],
        budget: &mut super::KeyEstablishmentBudget<'_>,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, XmlEncError> {
        budget.derive_key(provider, &self.parameters(output_len)?, secret)
    }
    /// Borrow one original ConcatKDF field as significant bits, without copying
    /// its bytes. None distinguishes omission from an explicitly empty field.
    ///
    /// XMLEnc 1.1 section 5.4.1 requires application-specific validation of the
    /// algorithm and party identities. Combining OtherInfo must not erase the
    /// boundaries needed for that check.
    pub fn concat_field_bits(
        &self,
        field: ConcatKdfField,
    ) -> Option<impl Iterator<Item = bool> + '_> {
        let index = match field {
            ConcatKdfField::AlgorithmId => 0,
            ConcatKdfField::PartyUInfo => 1,
            ConcatKdfField::PartyVInfo => 2,
            ConcatKdfField::SuppPubInfo => 3,
            ConcatKdfField::SuppPrivInfo => 4,
        };
        let (start, length) = self.concat_fields[index]?;
        Some((start..start + length).map(|bit| self.context[bit / 8] & (1 << (7 - bit % 8)) != 0))
    }
    /// Bind the requested key width supplied by EncryptionMethod. An explicit
    /// XML KeyLength must agree; it is not an override of the consuming cipher.
    pub fn parameters(&self, output_len: usize) -> Result<KdfParameters<'_>, XmlEncError> {
        if output_len == 0 || self.key_length.is_some_and(|length| length != output_len) {
            return Err(invalid(
                "KDF KeyLength does not match the consuming algorithm",
            ));
        }
        Ok(KdfParameters {
            algorithm: &self.algorithm,
            digest: Some(&self.digest),
            salt: &self.salt,
            info: match self.context_bits {
                Some(bit_len) => KdfContext::Bits {
                    bytes: &self.context,
                    bit_len,
                },
                None => KdfContext::Octets(&self.context),
            },
            iterations: self.iterations,
            output_len,
        })
    }
}

/// Parse a standalone xenc11:KeyDerivationMethod with the same XML and metadata
/// bounds as the containing decryption operation. No resource is fetched and
/// no provider or key resolver is invoked by this function.
pub fn parse_key_derivation_method(
    xml: &str,
    policy: &crate::policy::DecryptionPolicy,
) -> Result<KeyDerivationMethod, XmlEncError> {
    parse_key_derivation_method_with_backend(xml, policy, crate::XmlBackend::default())
}

/// Parse KDF parameters using the operation-selected XML backend.
pub fn parse_key_derivation_method_with_backend(
    xml: &str,
    policy: &crate::policy::DecryptionPolicy,
    backend: crate::XmlBackend,
) -> Result<KeyDerivationMethod, XmlEncError> {
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

pub(super) fn parse_node(
    node: Node<'_, '_>,
    maximum: usize,
) -> Result<KeyDerivationMethod, XmlEncError> {
    require(node, XMLENC11_NS, "KeyDerivationMethod")?;
    let algorithm = attribute(node, "Algorithm", maximum)?;
    let parameters = single_child(node)?;
    element_content(parameters)?;
    let mut result = KeyDerivationMethod {
        algorithm: algorithm.to_owned(),
        digest: String::new(),
        salt: Vec::new(),
        context: Vec::new(),
        context_bits: None,
        concat_fields: [None; 5],
        iterations: 0,
        key_length: None,
    };
    match algorithm {
        CONCAT => {
            require(parameters, XMLENC11_NS, "ConcatKDFParams")?;
            result.digest = algorithm_child(
                single_child(parameters)?,
                XMLDSIG_NS,
                "DigestMethod",
                maximum,
            )?;
            // XMLEnc 1.1 section 5.4.1: concatenate the original UNPADDED
            // bit strings, not hexBinary storage or each attribute's prefix.
            // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-ConcatKDF
            let fields = [
                "AlgorithmID",
                "PartyUInfo",
                "PartyVInfo",
                "SuppPubInfo",
                "SuppPrivInfo",
            ]
            .map(|name| parameters.attribute(name));
            let (bytes, bits, boundaries) = concat_context(fields, maximum)?;
            result.context = bytes;
            result.context_bits = Some(bits);
            result.concat_fields = boundaries;
        }
        PBKDF2 => {
            require(parameters, XMLENC11_NS, "PBKDF2-params")?;
            let mut children = parameters.children().filter(Node::is_element);
            let salt = next(&mut children, XMLENC11_NS, "Salt")?;
            let specified = single_child(salt)?;
            if specified.has_tag_name((XMLENC11_NS, "OtherSource")) {
                // This is an algorithm invocation, not a URI or a salt value.
                // Do not silently treat unsupported derivation as empty salt.
                return Err(XmlEncError::UnsupportedAlgorithm(
                    attribute(specified, "Algorithm", maximum)?.to_owned(),
                ));
            }
            require(specified, XMLENC11_NS, "Specified")?;
            result.salt = decode_bounded_base64_text(specified, "Specified", maximum)?;
            result.iterations = positive(
                next(&mut children, XMLENC11_NS, "IterationCount")?,
                "IterationCount",
                maximum,
            )?;
            // XML's KeyLength and PRF are REQUIRED, unlike ASN.1 defaults.
            // XMLEnc 1.1 section 5.4.2:
            // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-PBKDF2
            result.key_length = Some(
                usize::try_from(positive(
                    next(&mut children, XMLENC11_NS, "KeyLength")?,
                    "KeyLength",
                    maximum,
                )?)
                .map_err(|_| invalid("KeyLength exceeds platform width"))?,
            );
            result.digest = algorithm_child(
                next(&mut children, XMLENC11_NS, "PRF")?,
                XMLENC11_NS,
                "PRF",
                maximum,
            )?;
            if children.next().is_some() {
                return Err(invalid("unexpected PBKDF2 parameter"));
            }
        }
        HKDF => {
            // libxmlsec1's HKDFParams profile is distinct from RFC 9231
            // section 2.8.1's AgreementMethod layout and hex encodings.
            // https://www.rfc-editor.org/rfc/rfc9231.html#section-2.8.1
            require(parameters, MORE_NS, "HKDFParams")?;
            let mut children = parameters.children().filter(Node::is_element).peekable();
            result.digest = algorithm_child(
                next(&mut children, MORE_NS, "PRF")?,
                MORE_NS,
                "PRF",
                maximum,
            )?;
            if children
                .peek()
                .is_some_and(|node| node.has_tag_name((MORE_NS, "Salt")))
            {
                result.salt = decode_bounded_base64_text(
                    next(&mut children, MORE_NS, "Salt")?,
                    "Salt",
                    maximum,
                )?;
            }
            if children
                .peek()
                .is_some_and(|node| node.has_tag_name((MORE_NS, "Info")))
            {
                result.context = decode_bounded_base64_text(
                    next(&mut children, MORE_NS, "Info")?,
                    "Info",
                    maximum,
                )?;
            }
            if children
                .peek()
                .is_some_and(|node| node.has_tag_name((MORE_NS, "KeyLength")))
            {
                result.key_length = Some(
                    usize::try_from(positive(
                        next(&mut children, MORE_NS, "KeyLength")?,
                        "KeyLength",
                        maximum,
                    )?)
                    .map_err(|_| invalid("KeyLength exceeds platform width"))?,
                );
            }
            if children.next().is_some() {
                return Err(invalid("unexpected HKDF parameter"));
            }
        }
        _ => return Err(XmlEncError::UnsupportedAlgorithm(algorithm.to_owned())),
    }
    Ok(result)
}

fn invalid(message: &str) -> XmlEncError {
    XmlEncError::InvalidStructure(message.into())
}

fn single_child<'a>(node: Node<'a, 'a>) -> Result<Node<'a, 'a>, XmlEncError> {
    element_content(node)?;
    let mut children = node.children().filter(Node::is_element);
    let child = children
        .next()
        .ok_or(XmlEncError::MissingRequired("KDF parameters"))?;
    if children.next().is_some() {
        return Err(invalid("expected exactly one KDF parameter element"));
    }
    Ok(child)
}

fn element_content(node: Node<'_, '_>) -> Result<(), XmlEncError> {
    for child in node.children() {
        if child.is_text()
            && child.text().is_some_and(|text| {
                !text
                    .bytes()
                    .all(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
            })
        {
            return Err(invalid("KDF parameter container contains character data"));
        }
    }
    Ok(())
}

fn next<'a>(
    children: &mut impl Iterator<Item = Node<'a, 'a>>,
    namespace: &str,
    name: &'static str,
) -> Result<Node<'a, 'a>, XmlEncError> {
    let node = children.next().ok_or(XmlEncError::MissingRequired(name))?;
    require(node, namespace, name)?;
    Ok(node)
}

fn attribute<'a>(node: Node<'a, 'a>, name: &str, maximum: usize) -> Result<&'a str, XmlEncError> {
    let value = node
        .attribute(name)
        .ok_or_else(|| invalid(&format!("missing {name}")))?;
    validate_metadata_len(value.len(), maximum)?;
    Ok(value)
}

fn algorithm_child(
    node: Node<'_, '_>,
    namespace: &str,
    name: &str,
    maximum: usize,
) -> Result<String, XmlEncError> {
    require(node, namespace, name)?;
    element_content(node)?;
    if node.children().any(|child| child.is_element()) {
        return Err(invalid("unsupported digest/PRF parameters"));
    }
    Ok(attribute(node, "Algorithm", maximum)?.to_owned())
}

fn positive(node: Node<'_, '_>, field: &'static str, maximum: usize) -> Result<u64, XmlEncError> {
    let text = bounded_simple_text_with_limit(node, field, maximum)?;
    let value = text.trim_matches([' ', '\t', '\r', '\n']);
    let value = value.strip_prefix('+').unwrap_or(value);
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid("KDF integer must be positive"));
    }
    let number = value
        .parse::<u64>()
        .map_err(|_| invalid("KDF integer exceeds u64"))?;
    if number == 0 {
        return Err(invalid("KDF integer must be positive"));
    }
    Ok(number)
}

fn nibble(byte: u8) -> Result<u8, XmlEncError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(invalid("invalid ConcatKDF hexBinary")),
    }
}

fn hex_byte(bytes: &[u8]) -> Result<u8, XmlEncError> {
    Ok(nibble(bytes[0])? * 16 + nibble(bytes[1])?)
}

fn concat_field(value: &str, maximum: usize) -> Result<(&[u8], usize), XmlEncError> {
    validate_metadata_len(value.len(), maximum)?;
    let hex = value.trim_matches([' ', '\t', '\r', '\n']).as_bytes();
    if hex.is_empty() {
        return Ok((hex, 0));
    }
    if !hex.len().is_multiple_of(2) {
        return Err(invalid("odd ConcatKDF hexBinary length"));
    }
    let padding = hex_byte(&hex[..2])? as usize;
    let payload = &hex[2..];
    if padding > 7 || payload.is_empty() && padding != 0 {
        return Err(invalid("invalid ConcatKDF padding count"));
    }
    for pair in payload.as_chunks::<2>().0 {
        hex_byte(pair)?;
    }
    if padding != 0 && hex_byte(&payload[payload.len() - 2..])? & ((1 << padding) - 1) != 0 {
        return Err(invalid("nonzero ConcatKDF padding bits"));
    }
    Ok((payload, payload.len() / 2 * 8 - padding))
}

type ConcatContext = (Vec<u8>, usize, [Option<(usize, usize)>; 5]);

fn concat_context(fields: [Option<&str>; 5], maximum: usize) -> Result<ConcatContext, XmlEncError> {
    let mut total = 0usize;
    let mut boundaries = [None; 5];
    // Validate every field and calculate capacity before allocating anything.
    for (index, field) in fields.iter().enumerate() {
        let Some(value) = field else {
            continue;
        };
        let (_, bits) = concat_field(value, maximum)?;
        boundaries[index] = Some((total, bits));
        total = total
            .checked_add(bits)
            .ok_or_else(|| invalid("ConcatKDF context overflow"))?;
    }
    validate_metadata_len(total.div_ceil(8), maximum)?;
    let mut output = vec![0; total.div_ceil(8)];
    let mut offset = 0;
    for value in fields.into_iter().flatten() {
        let (hex, bits) = concat_field(value, maximum)?;
        let mut remaining = bits;
        for pair in hex.as_chunks::<2>().0 {
            let byte = hex_byte(pair)?;
            let shift = offset % 8;
            let index = offset / 8;
            output[index] |= byte >> shift;
            if shift != 0 && index + 1 < output.len() {
                output[index + 1] |= byte << (8 - shift);
            }
            let consumed = remaining.min(8);
            offset += consumed;
            remaining -= consumed;
        }
    }
    Ok((output, total, boundaries))
}
