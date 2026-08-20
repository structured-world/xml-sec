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
    /// The detected XML byte encoding contradicted the document declaration.
    #[error("XML byte encoding conflicts with declared encoding {0}")]
    ConflictingDeclaration(String),
    /// Unmarked input was not valid UTF-8.
    #[error("XML input is neither BOM-marked UTF-16 nor valid UTF-8: {0}")]
    InvalidUtf8(#[from] std::str::Utf8Error),
}

#[derive(Clone, Copy)]
enum Utf16ByteOrder {
    LittleEndian,
    BigEndian,
}

/// Decode XML 1.0 octets encoded as UTF-8 or BOM-marked UTF-16.
///
/// UTF-16 input becomes UTF-8-backed Rust text, so its XML declaration is
/// normalized to `UTF-8`; a contradictory encoding or explicit byte order
/// fails closed.
pub fn decode_xml_octets(bytes: &[u8]) -> Result<Cow<'_, str>, XmlEncodingError> {
    let utf16 = if let Some(payload) = bytes.strip_prefix(&[0xff, 0xfe]) {
        Some((payload, Utf16ByteOrder::LittleEndian))
    } else {
        bytes
            .strip_prefix(&[0xfe, 0xff])
            .map(|payload| (payload, Utf16ByteOrder::BigEndian))
    };
    if let Some((payload, byte_order)) = utf16 {
        if payload.len() % 2 != 0 {
            return Err(XmlEncodingError::OddUtf16Length);
        }
        let code_units = payload.chunks_exact(2).map(|chunk| {
            let bytes = [chunk[0], chunk[1]];
            if matches!(byte_order, Utf16ByteOrder::LittleEndian) {
                u16::from_le_bytes(bytes)
            } else {
                u16::from_be_bytes(bytes)
            }
        });
        let decoded = String::from_utf16(&code_units.collect::<Vec<_>>())?;
        return normalize_transcoded_declaration(decoded, byte_order).map(Cow::Owned);
    }

    let payload = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    let xml = std::str::from_utf8(payload)?;
    if let Some(range) = declared_encoding_range(xml)
        && !xml[range.clone()].eq_ignore_ascii_case("UTF-8")
    {
        return Err(XmlEncodingError::ConflictingDeclaration(xml[range].into()));
    }
    Ok(Cow::Borrowed(xml))
}

fn normalize_transcoded_declaration(
    mut xml: String,
    byte_order: Utf16ByteOrder,
) -> Result<String, XmlEncodingError> {
    let Some(declared_range) = declared_encoding_range(&xml) else {
        return Ok(xml);
    };
    let declared = &xml[declared_range.clone()];
    let declaration_matches = declared.eq_ignore_ascii_case("UTF-16")
        || declared.eq_ignore_ascii_case(match byte_order {
            Utf16ByteOrder::LittleEndian => "UTF-16LE",
            Utf16ByteOrder::BigEndian => "UTF-16BE",
        });
    if !declaration_matches {
        return Err(XmlEncodingError::ConflictingDeclaration(declared.into()));
    }
    xml.replace_range(declared_range, "UTF-8");
    Ok(xml)
}

fn declared_encoding_range(xml: &str) -> Option<std::ops::Range<usize>> {
    let declaration_end = xml
        .strip_prefix("<?xml")?
        .find("?>")?
        .checked_add("<?xml".len())?;
    let declaration = &xml.as_bytes()[..declaration_end];
    let name_start = declaration
        .windows("encoding".len())
        .position(|candidate| candidate == b"encoding")?;
    let mut cursor = name_start + "encoding".len();
    while declaration.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    if declaration.get(cursor) != Some(&b'=') {
        return None;
    }
    cursor += 1;
    while declaration.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    let &quote @ (b'\'' | b'"') = declaration.get(cursor)? else {
        return None;
    };
    let value_start = cursor + 1;
    let relative_end = declaration[value_start..]
        .iter()
        .position(|byte| *byte == quote)?;
    let value_end = value_start + relative_end;
    Some(value_start..value_end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcoding_normalizes_utf16_declarations() {
        // Once code units become a Rust string, subsequent serializers emit
        // UTF-8 bytes; the declaration must describe that representation.
        for (bom, encode, declaration) in [
            (
                [0xff, 0xfe],
                u16::to_le_bytes as fn(u16) -> [u8; 2],
                "<?xml version=\"1.0\" encoding=\"UTF-16\"?>",
            ),
            (
                [0xff, 0xfe],
                u16::to_le_bytes as fn(u16) -> [u8; 2],
                "<?xml version='1.0' encoding = 'utf-16le'?>",
            ),
            (
                [0xfe, 0xff],
                u16::to_be_bytes as fn(u16) -> [u8; 2],
                "<?xml version=\"1.0\" encoding=\"UTF-16BE\"?>",
            ),
        ] {
            let mut bytes = bom.to_vec();
            bytes.extend(
                format!("{declaration}<root/>")
                    .encode_utf16()
                    .flat_map(encode),
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

        for (bom, encode, declared) in [
            (
                [0xff, 0xfe],
                u16::to_le_bytes as fn(u16) -> [u8; 2],
                "UTF-16BE",
            ),
            (
                [0xfe, 0xff],
                u16::to_be_bytes as fn(u16) -> [u8; 2],
                "UTF-16LE",
            ),
        ] {
            let mut bytes = bom.to_vec();
            bytes.extend(
                format!("<?xml version=\"1.0\" encoding=\"{declared}\"?><root/>")
                    .encode_utf16()
                    .flat_map(encode),
            );
            assert!(matches!(
                decode_xml_octets(&bytes),
                Err(XmlEncodingError::ConflictingDeclaration(_))
            ));
        }
    }

    #[test]
    fn utf8_input_requires_a_matching_encoding_declaration() {
        // Successful UTF-8 decoding is not sufficient when the XML declaration
        // tells downstream processors to interpret the same octets differently.
        for valid in [
            br#"<?xml version="1.0" encoding="UTF-8"?><root/>"#.as_slice(),
            br#"<?xml version='1.0' encoding = 'utf-8'?><root/>"#.as_slice(),
            b"<root/>".as_slice(),
        ] {
            decode_xml_octets(valid).expect("UTF-8 declaration must match UTF-8 octets");
        }

        for declared in ["UTF-16", "ISO-8859-1"] {
            let xml = format!("<?xml version=\"1.0\" encoding=\"{declared}\"?><root>\u{e9}</root>");
            assert!(matches!(
                decode_xml_octets(xml.as_bytes()),
                Err(XmlEncodingError::ConflictingDeclaration(value)) if value == declared
            ));
        }
    }
}
