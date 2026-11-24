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
fn character_references(text: &str) -> String {
    let mut found = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("&#") {
        found.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let decoded = after.find(';').and_then(|end| {
            let digits = &after[..end];
            let value = match digits.strip_prefix(['x', 'X']) {
                Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                None => digits.parse().ok()?,
            };
            Some((char::from_u32(value)?, end))
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
            found.push(value);
        }
    }
    found
}

/// A DER certificate and a token's encoded policy identifier.
pub type Authority = (Vec<u8>, Vec<u8>);

/// Each certificate a token or the document carries, with the token's policy.
pub fn token_authorities(text: &str, carried: &[Vec<u8>]) -> Result<Vec<Authority>, String> {
    let mut found = Vec::new();
    for token in values(text, "EncapsulatedTimeStamp") {
        let parser = Parser::ber(Memory::new(Arc::new(MemoryAccount::new(1 << 24, 1 << 28))));
        let token = Token::read(&parser, &token, 0).map_err(|error| format!("{error:?}"))?;
        let parent = parser.read(&[], 0).map_err(|error| format!("{error:?}"))?;
        let policy = token
            .with_info(&parent, |info, _, _| {
                Ok::<_, Infallible>(info.policy().as_bytes().to_vec())
            })
            .map_err(|error| format!("{error:?}"))?;
        let own = token.message().certificates().iter();
        for certificate in own.map(|parsed| parsed.as_bytes().to_vec()) {
            found.push((certificate, policy.clone()));
        }
        for certificate in carried {
            found.push((certificate.clone(), policy.clone()));
        }
    }
    Ok(found)
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
