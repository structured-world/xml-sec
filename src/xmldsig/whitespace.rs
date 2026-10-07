//! Internal XML whitespace helpers shared across XMLDSig parsing and verification.

/// Borrow XML text and validate its exact decoded size without normalizing it
/// into a second heap buffer. Callers reserve this size before calling decode.
pub(crate) struct XmlBase64Payload<'a, 'input> {
    node: crate::xml::dom::Node<'a, 'input>,
    pub(crate) decoded_len: usize,
    pub(crate) normalized_len: usize,
    pub(crate) text_len: usize,
    #[cfg(feature = "xmlenc")]
    tail: [u8; 4],
}

impl<'a, 'input> XmlBase64Payload<'a, 'input> {
    pub(crate) fn new(node: crate::xml::dom::Node<'a, 'input>) -> Result<Self, &'static str> {
        Self::bounded(node, usize::MAX, usize::MAX)
    }

    pub(crate) fn bounded(
        node: crate::xml::dom::Node<'a, 'input>,
        max_text: usize,
        max_normalized: usize,
    ) -> Result<Self, &'static str> {
        let mut normalized_len = 0_usize;
        let mut padding = 0_usize;
        let mut text_len = 0_usize;
        #[cfg(feature = "xmlenc")]
        let mut tail = [0; 4];
        for child in node.children() {
            if child.is_element() {
                return Err("unexpected nested element");
            }
            if !child.is_text() {
                continue;
            }
            let text = child.text().unwrap_or_default();
            if text.len() > max_text - text_len {
                return Err("maximum allowed text length");
            }
            text_len = text_len
                .checked_add(text.len())
                .ok_or("base64 size overflow")?;
            for byte in text.bytes() {
                if matches!(byte, b' ' | b'\t' | b'\r' | b'\n') {
                    continue;
                }
                if normalized_len >= max_normalized {
                    return Err("maximum allowed base64 length");
                }
                if byte == b'=' {
                    padding += 1;
                    if padding > 2 {
                        return Err("invalid base64 padding");
                    }
                } else if padding != 0
                    || !matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/')
                {
                    return Err("invalid base64 character or XML whitespace");
                }
                #[cfg(feature = "xmlenc")]
                {
                    tail[normalized_len % 4] = byte;
                }
                normalized_len = normalized_len
                    .checked_add(1)
                    .ok_or("base64 size overflow")?;
            }
        }
        if !normalized_len.is_multiple_of(4) {
            return Err("invalid base64 length");
        }
        let decoded_len = (normalized_len / 4 * 3)
            .checked_sub(padding)
            .ok_or("invalid base64 padding")?;
        Ok(Self {
            node,
            decoded_len,
            normalized_len,
            text_len,
            #[cfg(feature = "xmlenc")]
            tail,
        })
    }

    pub(crate) fn decode(&self) -> Result<Vec<u8>, &'static str> {
        let mut output = vec![0; self.decoded_len];
        self.decode_into(&mut output)?;
        Ok(output)
    }

    /// Validate padding bits without allocating a decoded ciphertext copy.
    #[cfg(feature = "xmlenc")]
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        use base64::Engine as _;
        // Lexical preflight already checked every character and frame length.
        // Only the final quartet can contain padding or unused trailing bits.
        if self.normalized_len != 0 {
            base64::engine::general_purpose::STANDARD
                .decode_slice(self.tail, &mut [0; 3])
                .map_err(|_| "invalid base64 padding or trailing bits")?;
        }
        Ok(())
    }

    /// Retain only the normalized wire value after allocation-free validation.
    #[cfg(feature = "xmlenc")]
    pub(crate) fn normalized(&self) -> Result<String, &'static str> {
        self.validate()?;
        let mut value = String::with_capacity(self.normalized_len);
        for byte in self.normalized_bytes() {
            value.push(char::from(byte));
        }
        Ok(value)
    }

    fn normalized_bytes(&self) -> impl Iterator<Item = u8> + '_ {
        self.node
            .children()
            .filter(|child| child.is_text())
            .filter_map(|child| child.text())
            .flat_map(str::bytes)
            .filter(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
    }

    pub(crate) fn decode_into(&self, output: &mut [u8]) -> Result<(), &'static str> {
        use std::io::Read as _;
        let input = self.normalized_bytes();
        let mut decoder = base64::read::DecoderReader::new(
            Base64ByteReader(input),
            &base64::engine::general_purpose::STANDARD,
        );
        decoder
            .read_exact(output)
            .map_err(|_| "invalid base64 padding or trailing bits")?;
        let mut eof = [0];
        if decoder
            .read(&mut eof)
            .map_err(|_| "invalid base64 padding or trailing bits")?
            != 0
        {
            return Err("invalid base64 length");
        }
        Ok(())
    }
}

struct Base64ByteReader<I>(I);

impl<I: Iterator<Item = u8>> std::io::Read for Base64ByteReader<I> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let mut written = 0;
        for slot in buffer {
            let Some(byte) = self.0.next() else {
                break;
            };
            *slot = byte;
            written += 1;
        }
        Ok(written)
    }
}

/// Return `true` when the text contains only XML 1.0 whitespace chars.
#[inline]
pub(crate) fn is_xml_whitespace_only(text: &str) -> bool {
    text.chars()
        .all(|ch| matches!(ch, ' ' | '\t' | '\r' | '\n'))
}

/// Error returned when non-XML ASCII whitespace appears in base64 text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct XmlBase64NormalizeError {
    /// Offending ASCII byte.
    pub invalid_byte: u8,
    /// Offset in the normalized output where the byte was encountered.
    pub normalized_offset: usize,
}

/// Error returned when normalized base64 text exceeds its caller-supplied bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct XmlBase64LengthError {
    /// Maximum allowed normalized byte length.
    pub max_len: usize,
}

/// Append base64 bytes after removing XML whitespace.
///
/// `accept` controls caller-specific alphabet validation. Non-XML ASCII
/// whitespace is always rejected so every XMLDSig base64 path follows XML's
/// four-character whitespace definition rather than Rust's broader one.
pub(crate) fn normalize_xml_base64_bytes(
    bytes: &[u8],
    normalized: &mut Vec<u8>,
    accept: impl Fn(u8) -> bool,
) -> Result<(), XmlBase64NormalizeError> {
    visit_xml_base64_bytes(bytes, normalized.len(), &accept, |byte| {
        normalized.push(byte);
    })
}

fn visit_xml_base64_bytes(
    bytes: &[u8],
    initial_offset: usize,
    accept: &impl Fn(u8) -> bool,
    mut visit: impl FnMut(u8),
) -> Result<(), XmlBase64NormalizeError> {
    let mut accepted = 0_usize;
    for &byte in bytes {
        if matches!(byte, b' ' | b'\t' | b'\r' | b'\n') {
            continue;
        }
        if byte.is_ascii_whitespace() || !accept(byte) {
            return Err(XmlBase64NormalizeError {
                invalid_byte: byte,
                normalized_offset: initial_offset + accepted,
            });
        }
        visit(byte);
        accepted += 1;
    }
    Ok(())
}

/// Normalize base64 text by stripping XML whitespace and rejecting other ASCII whitespace.
pub(crate) fn normalize_xml_base64_text(
    text: &str,
    normalized: &mut String,
) -> Result<(), XmlBase64NormalizeError> {
    normalize_xml_base64_text_with_limit(text, normalized, usize::MAX).map_err(|err| match err {
        XmlBase64NormalizeLimitedError::InvalidWhitespace(err) => err,
        XmlBase64NormalizeLimitedError::TooLong(_) => unreachable!("unbounded normalization"),
    })
}

/// Normalize base64 text while enforcing a maximum normalized byte length.
pub(crate) fn normalize_xml_base64_text_with_limit(
    text: &str,
    normalized: &mut String,
    max_len: usize,
) -> Result<(), XmlBase64NormalizeLimitedError> {
    for ch in text.chars() {
        if matches!(ch, ' ' | '\t' | '\r' | '\n') {
            continue;
        }
        if ch.is_ascii_whitespace() {
            let mut utf8 = [0_u8; 4];
            let encoded = ch.encode_utf8(&mut utf8);
            let invalid_byte = encoded.as_bytes()[0];
            return Err(XmlBase64NormalizeLimitedError::InvalidWhitespace(
                XmlBase64NormalizeError {
                    invalid_byte,
                    normalized_offset: normalized.len(),
                },
            ));
        }
        if normalized.len() + ch.len_utf8() > max_len {
            return Err(XmlBase64NormalizeLimitedError::TooLong(
                XmlBase64LengthError { max_len },
            ));
        }
        normalized.push(ch);
    }
    Ok(())
}

/// Error returned by bounded XML base64 normalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum XmlBase64NormalizeLimitedError {
    /// Non-XML ASCII whitespace was found.
    InvalidWhitespace(XmlBase64NormalizeError),
    /// Normalized output would exceed the supplied bound.
    TooLong(XmlBase64LengthError),
}

impl From<XmlBase64NormalizeError> for XmlBase64NormalizeLimitedError {
    fn from(err: XmlBase64NormalizeError) -> Self {
        Self::InvalidWhitespace(err)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        XmlBase64NormalizeLimitedError, normalize_xml_base64_bytes, normalize_xml_base64_text,
        normalize_xml_base64_text_with_limit,
    };

    #[test]
    fn borrowed_base64_stream_crosses_text_and_decoder_buffer_boundaries() {
        // Text/comment boundaries and the decoder's internal chunk size must
        // not become Base64 framing boundaries or require a normalized copy.
        use base64::Engine as _;
        let bytes = vec![7; 4097];
        let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
        let xml = format!(
            "<value> {}<!--boundary-->{}\n</value>",
            &encoded[..3],
            &encoded[3..]
        );
        let document = crate::xml::dom::Document::parse(&xml).expect("segmented Base64 XML");
        let payload =
            super::XmlBase64Payload::new(document.root_element()).expect("valid Base64 frame");
        assert_eq!(payload.decoded_len, bytes.len());
        let decoded = payload.decode().expect("segmented stream decodes");
        assert_eq!(decoded.capacity(), bytes.len());
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn borrowed_base64_rejects_noncanonical_padding_and_non_xml_whitespace() {
        // Invalid trailing bits are checked by the stream decoder even when
        // lexical preflight accepts the alphabet and exact decoded length.
        for encoded in ["AR==", "AQJ=", "AQ==AQ==", "AQID\u{a0}", "AQI"] {
            let xml = format!("<value>{encoded}</value>");
            let document =
                crate::xml::dom::Document::parse(&xml).expect("invalid Base64 in valid XML");
            let result = super::XmlBase64Payload::new(document.root_element())
                .and_then(|payload| payload.decode());
            assert!(result.is_err(), "{encoded}");
        }
    }

    #[test]
    fn bounded_base64_normalization_rejects_before_growth() {
        let mut normalized = String::from("ABCD");

        let err = normalize_xml_base64_text_with_limit(" E", &mut normalized, 4)
            .expect_err("bounded normalization must reject before appending past the cap");

        assert!(matches!(err, XmlBase64NormalizeLimitedError::TooLong(_)));
        assert_eq!(normalized, "ABCD");
    }

    #[test]
    fn unbounded_base64_normalization_preserves_existing_behavior() {
        let mut normalized = String::new();

        normalize_xml_base64_text(" A\tB\r\nC ", &mut normalized)
            .expect("XML whitespace must be stripped from base64 text");

        assert_eq!(normalized, "ABC");
    }

    #[test]
    fn byte_normalization_applies_caller_alphabet_policy() {
        // The shared XML whitespace pass must report the same normalized
        // offset whether rejection comes from whitespace or caller policy.
        let mut normalized = Vec::new();
        let err = normalize_xml_base64_bytes(b" A\tB!", &mut normalized, |byte| {
            byte.is_ascii_alphanumeric()
        })
        .expect_err("caller must be able to reject a non-alphabet byte");

        assert_eq!(normalized, b"AB");
        assert_eq!(err.invalid_byte, b'!');
        assert_eq!(err.normalized_offset, 2);
    }
}
