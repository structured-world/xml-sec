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
    /// Unmarked input was not valid UTF-8.
    #[error("XML input is neither BOM-marked UTF-16 nor valid UTF-8: {0}")]
    InvalidUtf8(#[from] std::str::Utf8Error),
}

/// Decode XML 1.0 octets encoded as UTF-8 or BOM-marked UTF-16.
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
        return String::from_utf16(&code_units.collect::<Vec<_>>())
            .map(Cow::Owned)
            .map_err(XmlEncodingError::from);
    }

    let payload = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    std::str::from_utf8(payload)
        .map(Cow::Borrowed)
        .map_err(XmlEncodingError::from)
}
