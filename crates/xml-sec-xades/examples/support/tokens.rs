//! What the probes read from a document's own text: base64 values and the
//! authorities of its timestamp tokens.

use std::convert::Infallible;
use std::sync::Arc;

use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Oid, Parser};
use structured_cms::timestamp::{Accuracy, PolicyAccuracy, Token};
use xml_sec_xades::AuthorityAccuracy;

/// The `XMLDSig` namespace.
pub const DS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// The ETSI `XAdES` namespaces: TS 101 903 V1.1.1 and V1.2.2, and the V1.3.2
/// and V1.4.1 namespaces EN 319 132-1 section 4.2 uses.
pub const XADES: [&str; 4] = [
    "http://uri.etsi.org/01903/v1.1.1#",
    "http://uri.etsi.org/01903/v1.2.2#",
    "http://uri.etsi.org/01903/v1.3.2#",
    "http://uri.etsi.org/01903/v1.4.1#",
];

/// Whether `node` is an element named `local` in one of the `XAdES`
/// namespaces.
pub fn is_xades(node: &roxmltree::Node<'_, '_>, local: &str) -> bool {
    node.is_element()
        && node.tag_name().name() == local
        && node
            .tag_name()
            .namespace()
            .is_some_and(|namespace| XADES.contains(&namespace))
}

/// A base64 field of a signature, by its expanded element names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    /// `ds:X509Certificate` (`XMLDSig` 1.1 section 4.5.4) and `XAdES`
    /// `EncapsulatedX509Certificate` (EN 319 132-1 section 5.4.2).
    Certificate,
    /// The `XAdES` element of this local name: `EncapsulatedTimeStamp`
    /// (EN 319 132-1 section 5.1.4.3), `EncapsulatedCRLValue` or
    /// `EncapsulatedOCSPValue` (section 5.4.3).
    Xades(&'static str),
}

impl Field {
    /// A timestamp token's field.
    pub const TIMESTAMP: Self = Self::Xades("EncapsulatedTimeStamp");

    /// Whether `node` is an element of this field. An application element
    /// that only shares a suffix or a local name in another namespace is not,
    /// nor is a token, CRL or OCSP value outside a signature's
    /// `QualifyingProperties` (EN 319 132-1 section 4.3.5), such as a
    /// payload element that reuses the name: its content is no token to read.
    fn holds(self, node: &roxmltree::Node<'_, '_>) -> bool {
        match self {
            Self::Certificate => {
                (node.is_element()
                    && node.tag_name().name() == "X509Certificate"
                    && node.tag_name().namespace() == Some(DS))
                    || is_xades(node, "EncapsulatedX509Certificate")
            }
            Self::Xades(local) => {
                is_xades(node, local)
                    && node
                        .ancestors()
                        .any(|ancestor| is_xades(&ancestor, "QualifyingProperties"))
            }
        }
    }
}

/// The character content of a simple-content element: its text and CDATA
/// children in order, comments and processing instructions left out, as the
/// XML Infoset gives an element's characters. None for an element with an
/// element child, which carries no simple value.
pub fn simple_text(node: roxmltree::Node<'_, '_>) -> Option<String> {
    let mut text = String::new();
    for child in node.children() {
        if child.is_element() {
            return None;
        }
        // The parser has already replaced character references, `&#13;`
        // included (XML 1.0 section 4.1), and reads CDATA as text.
        if let Some(part) = child.is_text().then(|| child.text()).flatten() {
            text.push_str(part);
        }
    }
    Some(text)
}

/// The base64 value of `node` (XML Schema `base64Binary`, whitespace
/// collapsed), or why it is no such value.
pub fn base64(node: roxmltree::Node<'_, '_>) -> Result<Vec<u8>, String> {
    let text = simple_text(node).ok_or("the element has element content")?;
    let compact: String = text
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    structured_base64::STANDARD
        .decode(compact.as_bytes())
        .map_err(|error| format!("{error:?}"))
}

/// Every base64 value of `field` in `text`.
pub fn values(text: &str, field: Field) -> Vec<Vec<u8>> {
    values_at(text, field)
        .into_iter()
        .map(|(_, value)| value)
        .collect()
}

/// [`values`], each with its element's place in document order, the order
/// [`node_order`] gives every element of `text`. An element an entity
/// supplies is where the entity is referenced, not where it is declared.
/// Only elements count: the same text in a comment, a processing
/// instruction or an attribute is no value. A document that does not parse
/// carries none.
pub fn values_at(text: &str, field: Field) -> Vec<(usize, Vec<u8>)> {
    encoded_at(text, field)
        .into_iter()
        .filter_map(|(at, value)| Some((at, value.ok()?)))
        .collect()
}

/// Every element of `field` in `text` with its place in document order and
/// its decoded value, or why it does not decode.
pub fn encoded_at(text: &str, field: Field) -> Vec<(usize, Result<Vec<u8>, String>)> {
    let Ok(document) = roxmltree::Document::parse_with_options(
        text,
        roxmltree::ParsingOptions {
            allow_dtd: true,
            ..roxmltree::ParsingOptions::default()
        },
    ) else {
        return Vec::new();
    };
    document
        .descendants()
        .filter(|node| field.holds(node))
        .map(|element| (node_order(element), base64(element)))
        .collect()
}

/// The place of `node` in document order: the parser numbers the nodes of
/// one parse in the order it reads them, entity replacement text included.
pub fn node_order(node: roxmltree::Node<'_, '_>) -> usize {
    node.id().get_usize()
}

/// A DER certificate and a token's encoded policy identifier.
pub type Authority = (Vec<u8>, Vec<u8>);

/// Each certificate a readable token or the document carries, with that
/// token's policy; and why each other token could not be read. One unreadable
/// token takes nothing from the readable ones.
pub fn token_authorities(text: &str, carried: &[Vec<u8>]) -> (Vec<Authority>, Vec<String>) {
    let mut found = Vec::new();
    let mut failures = Vec::new();
    for (_, token) in encoded_at(text, Field::TIMESTAMP) {
        // A token whose base64 does not decode is as unreadable as one whose
        // CMS does not parse.
        let token = match token {
            Ok(token) => token,
            Err(error) => {
                failures.push(format!("the token's base64 does not decode: {error}"));
                continue;
            }
        };
        match token_policy_and_certificates(&token) {
            Ok((policy, own)) => {
                for certificate in own.into_iter().chain(carried.iter().cloned()) {
                    found.push((certificate, policy.clone()));
                }
            }
            Err(error) => failures.push(error),
        }
    }
    (found, failures)
}

/// The policy and own certificates of one DER timestamp `token`.
fn token_policy_and_certificates(token: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>), String> {
    let parser = Parser::ber(Memory::new(Arc::new(MemoryAccount::new(1 << 24, 1 << 28))));
    let token = Token::read(&parser, token, 0).map_err(|error| format!("{error:?}"))?;
    let parent = parser.read(&[], 0).map_err(|error| format!("{error:?}"))?;
    let policy = token
        .with_info(&parent, |info, _, _| {
            Ok::<_, Infallible>(info.policy().as_bytes().to_vec())
        })
        .map_err(|error| format!("{error:?}"))?;
    let own = token
        .message()
        .certificates()
        .iter()
        .map(|parsed| parsed.as_bytes().to_vec())
        .collect();
    Ok((policy, own))
}

/// `seconds` stated as the accuracy of every authority, for tokens that omit
/// the field: an interoperability setting for test corpora, never a trust
/// decision (RFC 3161 §2.4.2).
pub fn stated(
    authorities: &[Authority],
    seconds: u64,
) -> Result<Vec<AuthorityAccuracy<'_>>, String> {
    let mut accuracies = Vec::with_capacity(authorities.len());
    for (authority, policy) in authorities {
        accuracies.push(AuthorityAccuracy {
            authority,
            stated: PolicyAccuracy::new(Oid::from_bytes(policy), Accuracy::new(seconds, 0, 0))
                .map_err(|error| error.to_string())?,
        });
    }
    Ok(accuracies)
}
