use crate::{Error, Result};

pub(crate) fn is_ncname(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    is_ncname_start(first) && chars.all(is_ncname_char)
}

pub(crate) const fn is_xml_whitespace(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\r' | '\n')
}

/// Trim only the `S` characters shared by XML 1.0 and XPath 1.0.
pub(crate) fn trim_xml_whitespace(value: &str) -> &str {
    value.trim_matches(is_xml_whitespace)
}

/// A URI fragment whose percent escapes have been validated as UTF-8.
pub(crate) struct ValidatedXPointerFragment<'a> {
    source: &'a str,
    decoded_len: Option<usize>,
}

impl<'a> ValidatedXPointerFragment<'a> {
    pub(crate) fn new(source: &'a str) -> Result<Self> {
        if !source.as_bytes().contains(&b'%') {
            return Ok(Self {
                source,
                decoded_len: None,
            });
        }

        let bytes = source.as_bytes();
        let mut cursor = 0usize;
        let mut decoded_len = 0usize;
        let mut scalar = [0_u8; 4];
        while cursor < bytes.len() {
            scalar[0] = next_percent_decoded_byte(bytes, &mut cursor)?;
            let width = match scalar[0] {
                0x00..=0x7f => 1,
                0xc2..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf4 => 4,
                _ => return Err(invalid_xpointer_utf8()),
            };
            for byte in &mut scalar[1..width] {
                *byte = next_percent_decoded_byte(bytes, &mut cursor)?;
            }
            if std::str::from_utf8(&scalar[..width]).is_err() {
                return Err(invalid_xpointer_utf8());
            }
            decoded_len = decoded_len
                .checked_add(width)
                .ok_or_else(|| Error::Unsupported("URI fragment decoded length overflow".into()))?;
        }
        Ok(Self {
            source,
            decoded_len: Some(decoded_len),
        })
    }

    pub(crate) const fn decoded_len(&self) -> Option<usize> {
        self.decoded_len
    }

    pub(crate) const fn source(&self) -> &'a str {
        self.source
    }

    pub(crate) fn equals(&self, candidate: &str) -> bool {
        if self.decoded_len.is_none() {
            return self.source == candidate;
        }
        let mut candidate = candidate.as_bytes().iter().copied();
        let mut cursor = 0usize;
        let bytes = self.source.as_bytes();
        while cursor < bytes.len() {
            let byte = decoded_byte_after_validation(bytes, &mut cursor);
            if candidate.next() != Some(byte) {
                return false;
            }
        }
        candidate.next().is_none()
    }

    pub(crate) fn write_decoded_bytes(&self, output: &mut Vec<u8>) {
        let mut cursor = 0usize;
        let bytes = self.source.as_bytes();
        while cursor < bytes.len() {
            output.push(decoded_byte_after_validation(bytes, &mut cursor));
        }
    }
}

fn next_percent_decoded_byte(bytes: &[u8], cursor: &mut usize) -> Result<u8> {
    let byte = bytes
        .get(*cursor)
        .copied()
        .ok_or_else(|| Error::Unsupported("URI fragment has a truncated percent escape".into()))?;
    if byte != b'%' {
        *cursor += 1;
        return Ok(byte);
    }
    let encoded = bytes
        .get(*cursor + 1..*cursor + 3)
        .ok_or_else(|| Error::Unsupported("URI fragment has a truncated percent escape".into()))?;
    if !encoded.iter().all(u8::is_ascii_hexdigit) {
        return Err(Error::Unsupported(
            "URI fragment has an invalid percent escape".into(),
        ));
    }
    *cursor += 3;
    Ok((hex_value(encoded[0]) << 4) | hex_value(encoded[1]))
}

fn decoded_byte_after_validation(bytes: &[u8], cursor: &mut usize) -> u8 {
    let byte = bytes[*cursor];
    if byte != b'%' {
        *cursor += 1;
        return byte;
    }
    let decoded = (hex_value(bytes[*cursor + 1]) << 4) | hex_value(bytes[*cursor + 2]);
    *cursor += 3;
    decoded
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => unreachable!("validated percent escape contains only hexadecimal digits"),
    }
}

fn invalid_xpointer_utf8() -> Error {
    // XPointer Framework appendix B encodes pointer characters as UTF-8 octets; RFC 3986
    // section 2.1 defines each percent triplet as one encoded octet.
    // https://www.w3.org/TR/xptr-framework/#escaping
    // https://www.rfc-editor.org/rfc/rfc3986#section-2.1
    Error::Unsupported("URI fragment percent escapes are not valid UTF-8".into())
}

/// Returns the contents of exactly one XPath 1.0 `Literal` token.
///
/// XPath 1.0 production [29] does not provide quote escaping: the delimiting quote cannot occur
/// inside the token. https://www.w3.org/TR/1999/REC-xpath-19991116/#NT-Literal
pub(crate) fn xpath_string_literal(value: &str) -> Option<&str> {
    let value = value.trim_matches(is_xml_whitespace);
    let quote @ ('\'' | '"') = value.chars().next()? else {
        return None;
    };
    let literal = value.strip_prefix(quote)?.strip_suffix(quote)?;
    (!literal.contains(quote)).then_some(literal)
}

/// Removes XPath's abbreviated attribute axis and its permitted `ExprWhitespace`.
///
/// XSLT 1.0 section 5.2 admits `@` as the attribute-axis abbreviation in Pattern steps and
/// incorporates XPath `ExprWhitespace`. https://www.w3.org/TR/1999/REC-xslt-19991116#patterns
pub(crate) fn strip_xpath_attribute_axis(value: &str) -> Option<&str> {
    value
        .strip_prefix('@')
        .map(|value| value.trim_start_matches(is_xml_whitespace))
}

// XML 1.0 Fifth Edition section 2.2, production [2], defines the scalar values admitted by the
// semantic XML model: https://www.w3.org/TR/xml/#charsets
pub(crate) const fn is_xml10_character(character: char) -> bool {
    matches!(
        character,
        '\u{9}' | '\u{A}' | '\u{D}' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}'
    )
}

// Entity names use XML Name rather than namespace-constrained NCName, so colons remain legal:
// XML 1.0 Fifth Edition section 2.3, production [5]: https://www.w3.org/TR/xml/#NT-Name
pub(crate) fn is_xml_name(value: &str) -> bool {
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    (first == ':' || is_ncname_start(first))
        && characters.all(|character| character == ':' || is_ncname_char(character))
}

pub(crate) fn unicode_decimal_value(character: char) -> Option<u32> {
    const ZEROES: &[char] = &[
        '0', '٠', '۰', '०', '০', '੦', '૦', '୦', '௦', '౦', '೦', '൦', '๐', '໐', '༠', '၀', '០', '᠐',
        'ᥐ', '᧐', '᮰', '᱀', '꘠', '꣐', '꩐', '０',
    ];
    ZEROES.iter().find_map(|zero| {
        let offset = u32::from(character).checked_sub(u32::from(*zero))?;
        (offset <= 9).then_some(offset)
    })
}

pub(crate) fn is_ncname_start(ch: char) -> bool {
    matches!(
        ch,
        'A'..='Z'
            | '_'
            | 'a'..='z'
            | '\u{C0}'..='\u{D6}'
            | '\u{D8}'..='\u{F6}'
            | '\u{F8}'..='\u{2FF}'
            | '\u{370}'..='\u{37D}'
            | '\u{37F}'..='\u{1FFF}'
            | '\u{200C}'..='\u{200D}'
            | '\u{2070}'..='\u{218F}'
            | '\u{2C00}'..='\u{2FEF}'
            | '\u{3001}'..='\u{D7FF}'
            | '\u{F900}'..='\u{FDCF}'
            | '\u{FDF0}'..='\u{FFFD}'
            | '\u{10000}'..='\u{EFFFF}'
    )
}

pub(crate) fn is_ncname_char(ch: char) -> bool {
    is_ncname_start(ch)
        || matches!(
            ch,
            '-' | '.' | '0'..='9' | '\u{B7}' | '\u{0300}'..='\u{036F}' | '\u{203F}'..='\u{2040}'
        )
}

#[cfg(test)]
mod tests {
    use super::ValidatedXPointerFragment;

    #[test]
    fn truncated_multibyte_xpointer_escape_is_rejected_without_panicking() {
        // A complete leading UTF-8 octet still needs encoded continuation octets. The validator
        // must report a truncated fragment rather than indexing beyond the source buffer.
        for fragment in ["%C3", "%F0%9F"] {
            assert!(
                ValidatedXPointerFragment::new(fragment).is_err(),
                "accepted truncated XPointer fragment {fragment}"
            );
        }
    }
}
