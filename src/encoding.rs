//! XML byte-encoding detection shared by process and transform boundaries.

use std::borrow::Cow;

pub use xml_sec_xml_input::Error as XmlEncodingError;

/// Decode XML 1.0 octets into the backend-neutral Unicode parser contract.
///
/// UTF-8 input remains borrowed. Other declared XML encodings are decoded
/// strictly and their declaration is normalized to UTF-8 before parsing.
pub fn decode_xml_octets(bytes: &[u8]) -> Result<Cow<'_, str>, XmlEncodingError> {
    xml_sec_xml_input::decode_xml(bytes, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16_bytes(xml: &str, little_endian: bool, bom: bool) -> Vec<u8> {
        let mut bytes = if bom {
            if little_endian {
                vec![0xff, 0xfe]
            } else {
                vec![0xfe, 0xff]
            }
        } else {
            Vec::new()
        };
        bytes.extend(xml.encode_utf16().flat_map(|value| {
            if little_endian {
                value.to_le_bytes()
            } else {
                value.to_be_bytes()
            }
        }));
        bytes
    }

    #[test]
    fn transcoding_normalizes_non_utf8_declarations() {
        for bytes in [
            utf16_bytes(
                "<?xml version=\"1.0\" encoding=\"UTF-16\"?><root/>",
                true,
                true,
            ),
            utf16_bytes(
                "<?xml version='1.0' encoding='UTF-16BE'?><root/>",
                false,
                true,
            ),
            b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><root>caf\xe9</root>".to_vec(),
        ] {
            let decoded = decode_xml_octets(&bytes).expect("declared XML encoding must decode");
            assert!(decoded.contains("encoding=\"UTF-8\"") || decoded.contains("encoding='UTF-8'"));
        }
    }

    #[test]
    fn declared_single_byte_xml_is_transcoded_strictly() {
        // XML permits declared encodings beyond its mandatory UTF-8/UTF-16 baseline.
        let latin1 = b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><root>caf\xe9</root>";
        let decoded = decode_xml_octets(latin1).expect("declared Latin-1 XML must decode");
        assert!(decoded.contains("<root>café</root>"));
        assert!(decoded.contains("encoding=\"UTF-8\""));
    }

    #[test]
    fn byte_signatures_and_declarations_must_agree() {
        let conflicting = utf16_bytes(
            "<?xml version=\"1.0\" encoding=\"UTF-16BE\"?><root/>",
            true,
            true,
        );
        assert!(matches!(
            decode_xml_octets(&conflicting),
            Err(XmlEncodingError::ConflictingEncoding(_))
        ));

        let bomless_generic = utf16_bytes(
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?><root/>",
            true,
            false,
        );
        assert!(matches!(
            decode_xml_octets(&bomless_generic),
            Err(XmlEncodingError::MissingUtf16ByteOrder)
        ));
    }

    #[test]
    fn utf8_is_borrowed_and_malformed_bytes_are_rejected() {
        let xml = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><root/>";
        assert!(matches!(decode_xml_octets(xml), Ok(Cow::Borrowed(_))));
        assert!(decode_xml_octets(b"<root>\xff</root>").is_err());
    }

    #[test]
    fn declaration_detection_ignores_other_processing_instructions() {
        for xml in [
            r#"<?xml-stylesheet encoding="ISO-8859-1"?><root/>"#,
            r#"<root data-encoding="ISO-8859-1"/>"#,
        ] {
            decode_xml_octets(xml.as_bytes()).expect("ordinary content does not select encoding");
        }
    }
}
