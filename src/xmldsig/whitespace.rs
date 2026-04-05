//! Internal XML whitespace helpers shared across XMLDSig parsing and verification.

/// Return `true` when the text contains only XML 1.0 whitespace chars.
#[inline]
pub(crate) fn is_xml_whitespace_only(text: &str) -> bool {
    text.chars()
        .all(|ch| matches!(ch, ' ' | '\t' | '\r' | '\n'))
}
