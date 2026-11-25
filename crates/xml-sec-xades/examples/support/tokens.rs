//! What the probes read from a document's own text: base64 values and the
//! authorities of its timestamp tokens.

use std::convert::Infallible;
use std::sync::Arc;

use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Oid, Parser};
use structured_cms::timestamp::{Accuracy, PolicyAccuracy, Token};
use xml_sec_xades::AuthorityAccuracy;

/// `text` with its XML character references (XML 1.0 §4.1, `&#13;` and
/// `&#xD;` as signers write line breaks in base64) replaced by the
/// characters they name; any other text stays as it is.
pub fn character_references(text: &str) -> String {
    let mut found = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("&#") {
        found.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        // The digits are scanned once and the `;` must follow them, so text
        // with many unterminated references is read in one pass.
        let (hex, digits_start) = match after.as_bytes().first() {
            Some(b'x' | b'X') => (true, 1),
            _ => (false, 0),
        };
        let digits_end = digits_start
            + after[digits_start..]
                .bytes()
                .take_while(|byte| {
                    if hex {
                        byte.is_ascii_hexdigit()
                    } else {
                        byte.is_ascii_digit()
                    }
                })
                .count();
        let decoded = (after.as_bytes().get(digits_end) == Some(&b';'))
            .then_some(())
            .and_then(|()| {
                let digits = &after[digits_start..digits_end];
                let value = u32::from_str_radix(digits, if hex { 16 } else { 10 }).ok()?;
                Some((char::from_u32(value)?, digits_end))
            });
        if let Some((character, end)) = decoded {
            found.push(character);
            rest = &after[end + 1..];
        } else {
            found.push_str("&#");
            rest = after;
        }
    }
    found.push_str(rest);
    found
}

/// Every base64 value of an element whose name ends with `tag`.
pub fn values(text: &str, tag: &str) -> Vec<Vec<u8>> {
    values_at(text, tag)
        .into_iter()
        .map(|(_, value)| value)
        .collect()
}

/// [`values`], each with the byte offset of its element in `text`, which
/// orders the elements as the document does.
pub fn values_at(text: &str, tag: &str) -> Vec<(usize, Vec<u8>)> {
    let mut found = Vec::new();
    for (start, _) in text.match_indices(tag) {
        let closing = text[..start]
            .rfind('<')
            .is_some_and(|tag| text[tag..].starts_with("</"));
        let Some(open) = text[start..].find('>').filter(|_| !closing) else {
            continue;
        };
        let body = start + open + 1;
        let Some(end) = text[body..].find('<') else {
            continue;
        };
        let compact: String = character_references(&text[body..body + end])
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect();
        if let Ok(value) = structured_base64::STANDARD.decode(compact.as_bytes()) {
            found.push((start, value));
        }
    }
    found
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
