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

/// Normalize base64 text by stripping XML whitespace and rejecting other ASCII whitespace.
pub(crate) fn normalize_xml_base64_text(
    text: &str,
    normalized: &mut String,
) -> Result<(), XmlBase64NormalizeError> {
    for ch in text.chars() {
        if matches!(ch, ' ' | '\t' | '\r' | '\n') {
            continue;
        }
        if ch.is_ascii_whitespace() {
            let invalid_byte =
                u8::try_from(u32::from(ch)).expect("ASCII whitespace always fits into u8");
            return Err(XmlBase64NormalizeError {
                invalid_byte,
                normalized_offset: normalized.len(),
            });
        }
        normalized.push(ch);
    }
    Ok(())
}
