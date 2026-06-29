//! Internal XML whitespace helpers shared across XMLDSig parsing and verification.

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
        XmlBase64NormalizeLimitedError, normalize_xml_base64_text,
        normalize_xml_base64_text_with_limit,
    };

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
}
