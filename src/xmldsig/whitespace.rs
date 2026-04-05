#[inline]
pub(crate) fn is_xml_whitespace_only(text: &str) -> bool {
    text.chars()
        .all(|ch| matches!(ch, ' ' | '\t' | '\r' | '\n'))
}
