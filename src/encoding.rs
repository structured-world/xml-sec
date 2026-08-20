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
    /// BOM-less UTF-16 input omitted the required explicit byte-order declaration.
    #[error("BOM-less UTF-16 XML input requires an explicit UTF-16LE or UTF-16BE declaration")]
    MissingUtf16Declaration,
    /// Input without an XML UTF-16 signature was not valid UTF-8.
    #[error("XML input is neither declared UTF-16 nor valid UTF-8: {0}")]
    InvalidUtf8(#[from] std::str::Utf8Error),
}

#[derive(Clone, Copy)]
enum Utf16ByteOrder {
    LittleEndian,
    BigEndian,
}

/// Decode XML 1.0 octets encoded as UTF-8 or UTF-16.
///
/// UTF-16 is recognized from a BOM or the XML declaration byte signature.
/// BOM-less input must declare the matching explicit `UTF-16LE` or `UTF-16BE`
/// encoding. Transcoded declarations are normalized to `UTF-8` because the
/// returned Rust text is subsequently serialized as UTF-8.
pub fn decode_xml_octets(bytes: &[u8]) -> Result<Cow<'_, str>, XmlEncodingError> {
    let utf16 = if let Some(payload) = bytes.strip_prefix(&[0xff, 0xfe]) {
        Some((payload, Utf16ByteOrder::LittleEndian, false))
    } else if let Some(payload) = bytes.strip_prefix(&[0xfe, 0xff]) {
        Some((payload, Utf16ByteOrder::BigEndian, false))
    } else if bytes.starts_with(&[0x3c, 0x00, 0x3f, 0x00]) {
        Some((bytes, Utf16ByteOrder::LittleEndian, true))
    } else if bytes.starts_with(&[0x00, 0x3c, 0x00, 0x3f]) {
        Some((bytes, Utf16ByteOrder::BigEndian, true))
    } else {
        None
    };
    if let Some((payload, byte_order, requires_explicit_byte_order)) = utf16 {
        if payload.len() % 2 != 0 {
            return Err(XmlEncodingError::OddUtf16Length);
        }
        let (chunks, remainder) = payload.as_chunks::<2>();
        debug_assert!(remainder.is_empty());
        let code_units = chunks.iter().map(|bytes| {
            if matches!(byte_order, Utf16ByteOrder::LittleEndian) {
                u16::from_le_bytes(*bytes)
            } else {
                u16::from_be_bytes(*bytes)
            }
        });
        let decoded = String::from_utf16(&code_units.collect::<Vec<_>>())?;
        return normalize_transcoded_declaration(decoded, byte_order, requires_explicit_byte_order)
            .map(Cow::Owned);
    }

    let payload = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    let xml = std::str::from_utf8(payload)?;
    if let Some(range) = declared_encoding_range(xml)
        && !encoding_label_matches(&xml[range.clone()], "UTF-8")
    {
        return Err(XmlEncodingError::ConflictingDeclaration(xml[range].into()));
    }
    Ok(Cow::Borrowed(xml))
}

fn normalize_transcoded_declaration(
    mut xml: String,
    byte_order: Utf16ByteOrder,
    requires_explicit_byte_order: bool,
) -> Result<String, XmlEncodingError> {
    let Some(declared_range) = declared_encoding_range(&xml) else {
        return if requires_explicit_byte_order {
            Err(XmlEncodingError::MissingUtf16Declaration)
        } else {
            Ok(xml)
        };
    };
    let declared = &xml[declared_range.clone()];
    let explicit_encoding = match byte_order {
        Utf16ByteOrder::LittleEndian => "UTF-16LE",
        Utf16ByteOrder::BigEndian => "UTF-16BE",
    };
    let declaration_matches = encoding_label_matches(declared, explicit_encoding)
        || (!requires_explicit_byte_order && encoding_label_matches(declared, "UTF-16"));
    if !declaration_matches {
        return Err(XmlEncodingError::ConflictingDeclaration(declared.into()));
    }
    xml.replace_range(declared_range, "UTF-8");
    Ok(xml)
}

fn declared_encoding_range(xml: &str) -> Option<std::ops::Range<usize>> {
    const PREFIX: &str = "<?xml";
    let rest = xml.strip_prefix(PREFIX)?;
    if !rest.as_bytes().first().is_some_and(u8::is_ascii_whitespace) {
        return None;
    }
    let declaration = rest.as_bytes().get(..rest.find("?>")?)?;
    let mut cursor = 0;
    while cursor < declaration.len() {
        while declaration.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        let name_start = cursor;
        while declaration.get(cursor).is_some_and(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b':' | b'-' | b'.')
        }) {
            cursor += 1;
        }
        if cursor == name_start {
            return None;
        }
        let name = &declaration[name_start..cursor];
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
        let value_end = value_start
            + declaration[value_start..]
                .iter()
                .position(|byte| *byte == quote)?;
        if name == b"encoding" {
            return Some((PREFIX.len() + value_start)..(PREFIX.len() + value_end));
        }
        cursor = value_end + 1;
        if declaration
            .get(cursor)
            .is_some_and(|byte| !byte.is_ascii_whitespace())
        {
            return None;
        }
    }
    None
}

fn encoding_label_matches(actual: &str, canonical: &str) -> bool {
    actual.eq_ignore_ascii_case(canonical)
        || matches!(canonical,
            "UTF-8" if actual.eq_ignore_ascii_case("UTF8")
        )
        || matches!(canonical,
            "UTF-16" if actual.eq_ignore_ascii_case("UTF16")
        )
        || matches!(canonical,
            "UTF-16LE" if actual.eq_ignore_ascii_case("UTF16LE")
        )
        || matches!(canonical,
            "UTF-16BE" if actual.eq_ignore_ascii_case("UTF16BE")
        )
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
    fn bomless_utf16_requires_an_explicit_matching_byte_order() {
        // XML 1.0 Appendix F permits byte-signature autodetection, while
        // section 4.3.3 still requires generic UTF-16 to carry a BOM.
        for (encode, declared) in [
            (u16::to_le_bytes as fn(u16) -> [u8; 2], "UTF-16LE"),
            (u16::to_be_bytes as fn(u16) -> [u8; 2], "UTF-16BE"),
        ] {
            let bytes = format!("<?xml version=\"1.0\" encoding=\"{declared}\"?><root/>")
                .encode_utf16()
                .flat_map(encode)
                .collect::<Vec<_>>();
            let decoded = decode_xml_octets(&bytes).expect("explicit-endian UTF-16 must decode");
            assert!(decoded.contains("encoding=\"UTF-8\""));
        }

        for (encode, declared) in [
            (u16::to_le_bytes as fn(u16) -> [u8; 2], "UTF-16"),
            (u16::to_le_bytes as fn(u16) -> [u8; 2], "UTF-16BE"),
            (u16::to_be_bytes as fn(u16) -> [u8; 2], "UTF-16LE"),
        ] {
            let bytes = format!("<?xml version=\"1.0\" encoding=\"{declared}\"?><root/>")
                .encode_utf16()
                .flat_map(encode)
                .collect::<Vec<_>>();
            assert!(matches!(
                decode_xml_octets(&bytes),
                Err(XmlEncodingError::ConflictingDeclaration(value)) if value == declared
            ));
        }

        let missing = "<?xml version=\"1.0\"?><root/>"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert!(matches!(
            decode_xml_octets(&missing),
            Err(XmlEncodingError::MissingUtf16Declaration)
        ));
    }

    #[test]
    fn utf8_input_requires_a_matching_encoding_declaration() {
        // Successful UTF-8 decoding is not sufficient when the XML declaration
        // tells downstream processors to interpret the same octets differently.
        for valid in [
            br#"<?xml version="1.0" encoding="UTF-8"?><root/>"#.as_slice(),
            br#"<?xml version='1.0' encoding = 'utf-8'?><root/>"#.as_slice(),
            br#"<?xml version='1.0' encoding='UTF8'?><root/>"#.as_slice(),
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

    #[test]
    fn declaration_detection_ignores_processing_instructions_and_similar_names() {
        // Only the XML declaration's exact encoding pseudo-attribute controls
        // byte decoding; processing instructions and longer names are content.
        for xml in [
            r#"<?xml-stylesheet encoding="ISO-8859-1"?><root/>"#,
            r#"<?xml version="1.0" data-encoding="ISO-8859-1"?><root/>"#,
        ] {
            decode_xml_octets(xml.as_bytes()).expect("non-declaration text must be ignored");
        }
    }
}
