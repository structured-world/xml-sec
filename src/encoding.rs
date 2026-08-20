//! XML byte-encoding detection shared by process and transform boundaries.

use std::borrow::Cow;

/// Error returned when XML octets cannot be decoded as required by XML 1.0.
#[derive(Debug, thiserror::Error)]
pub enum XmlEncodingError {
    /// A BOM-marked UTF-16 document ended in a partial code unit.
    #[error("UTF-16 XML input has an odd byte length")]
    OddUtf16Length,
    /// UTF-16 code units did not form valid Unicode scalar values.
    #[error("invalid UTF-16 XML input: {0}")]
    InvalidUtf16(#[from] std::string::FromUtf16Error),
    /// A UTF-16 BOM contradicted the encoding declared by the document.
    #[error("UTF-16 XML BOM conflicts with declared encoding {0}")]
    ConflictingDeclaration(String),
    /// Unmarked input was not valid UTF-8.
    #[error("XML input is neither BOM-marked UTF-16 nor valid UTF-8: {0}")]
    InvalidUtf8(#[from] std::str::Utf8Error),
}

/// Decode XML 1.0 octets encoded as UTF-8 or BOM-marked UTF-16.
///
/// UTF-16 input becomes UTF-8-backed Rust text, so its XML declaration is
/// normalized to `UTF-8`; a contradictory declaration fails closed.
pub fn decode_xml_octets(bytes: &[u8]) -> Result<Cow<'_, str>, XmlEncodingError> {
    let (utf16, little_endian) = if let Some(payload) = bytes.strip_prefix(&[0xff, 0xfe]) {
        (Some(payload), true)
    } else if let Some(payload) = bytes.strip_prefix(&[0xfe, 0xff]) {
        (Some(payload), false)
    } else {
        (None, false)
    };
    if let Some(payload) = utf16 {
        if payload.len() % 2 != 0 {
            return Err(XmlEncodingError::OddUtf16Length);
        }
        let code_units = payload.chunks_exact(2).map(|chunk| {
            let bytes = [chunk[0], chunk[1]];
            if little_endian {
                u16::from_le_bytes(bytes)
            } else {
                u16::from_be_bytes(bytes)
            }
        });
        let decoded = String::from_utf16(&code_units.collect::<Vec<_>>())?;
        return normalize_transcoded_declaration(decoded).map(Cow::Owned);
    }

    let payload = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    std::str::from_utf8(payload)
        .map(Cow::Borrowed)
        .map_err(XmlEncodingError::from)
}

fn normalize_transcoded_declaration(mut xml: String) -> Result<String, XmlEncodingError> {
    let Some(declaration_end) = xml.strip_prefix("<?xml").and_then(|rest| rest.find("?>")) else {
        return Ok(xml);
    };
    let declaration_end = "<?xml".len() + declaration_end;
    let declaration = &xml.as_bytes()[..declaration_end];
    let Some(name_start) = declaration
        .windows("encoding".len())
        .position(|candidate| candidate == b"encoding")
    else {
        return Ok(xml);
    };
    let mut cursor = name_start + "encoding".len();
    while declaration.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    if declaration.get(cursor) != Some(&b'=') {
        return Ok(xml);
    }
    cursor += 1;
    while declaration.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    let Some(&quote @ (b'\'' | b'"')) = declaration.get(cursor) else {
        return Ok(xml);
    };
    let value_start = cursor + 1;
    let Some(relative_end) = declaration[value_start..]
        .iter()
        .position(|byte| *byte == quote)
    else {
        return Ok(xml);
    };
    let value_end = value_start + relative_end;
    let declared = &xml[value_start..value_end];
    if !matches_ignore_ascii_case(declared, &["UTF-16", "UTF-16LE", "UTF-16BE"]) {
        return Err(XmlEncodingError::ConflictingDeclaration(declared.into()));
    }
    xml.replace_range(value_start..value_end, "UTF-8");
    Ok(xml)
}

fn matches_ignore_ascii_case(value: &str, expected: &[&str]) -> bool {
    expected
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcoding_normalizes_utf16_declarations() {
        // Once code units become a Rust string, subsequent serializers emit
        // UTF-8 bytes; the declaration must describe that representation.
        for declaration in [
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?>",
            "<?xml version='1.0' encoding = 'utf-16le'?>",
        ] {
            let mut bytes = vec![0xff, 0xfe];
            bytes.extend(
                format!("{declaration}<root/>")
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes),
            );
            let decoded = decode_xml_octets(&bytes).expect("valid UTF-16 XML declaration");
            assert!(
                decoded.contains("encoding=\"UTF-8\"") || decoded.contains("encoding = 'UTF-8'")
            );
        }
    }

    #[test]
    fn transcoding_rejects_a_conflicting_declaration() {
        let mut bytes = vec![0xff, 0xfe];
        bytes.extend(
            "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><root/>"
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        );
        assert!(matches!(
            decode_xml_octets(&bytes),
            Err(XmlEncodingError::ConflictingDeclaration(_))
        ));
    }
}
