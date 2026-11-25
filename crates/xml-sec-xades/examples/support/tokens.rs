//! What the probes read from a document's own text: base64 values and the
//! authorities of its timestamp tokens.

use std::convert::Infallible;
use std::sync::Arc;

use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Oid, Parser};
use structured_cms::timestamp::{Accuracy, PolicyAccuracy, Token};
use xml_sec_xades::AuthorityAccuracy;

/// Every base64 value of an element whose name ends with `tag`.
pub fn values(text: &str, tag: &str) -> Vec<Vec<u8>> {
    values_at(text, tag)
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
pub fn values_at(text: &str, tag: &str) -> Vec<(usize, Vec<u8>)> {
    let Ok(document) = roxmltree::Document::parse_with_options(
        text,
        roxmltree::ParsingOptions {
            allow_dtd: true,
            ..roxmltree::ParsingOptions::default()
        },
    ) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for element in document
        .descendants()
        .filter(|node| node.is_element() && node.tag_name().name().ends_with(tag))
    {
        // The parser has already replaced character references, `&#13;`
        // included (XML 1.0 section 4.1).
        let compact: String = element
            .descendants()
            .filter(roxmltree::Node::is_text)
            .filter_map(|node| node.text())
            .flat_map(str::chars)
            .filter(|character| !character.is_ascii_whitespace())
            .collect();
        if let Ok(value) = structured_base64::STANDARD.decode(compact.as_bytes()) {
            found.push((node_order(element), value));
        }
    }
    found
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
    for token in values(text, "EncapsulatedTimeStamp") {
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
