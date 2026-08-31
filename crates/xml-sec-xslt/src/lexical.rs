pub(crate) fn is_ncname(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    is_ncname_start(first) && chars.all(is_ncname_char)
}

pub(crate) const fn is_xml_whitespace(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\r' | '\n')
}

// XML 1.0 Fifth Edition section 2.2, production [2], defines the scalar values admitted by the
// semantic XML model: https://www.w3.org/TR/xml/#charsets
pub(crate) const fn is_xml10_character(character: char) -> bool {
    matches!(
        character,
        '\u{9}' | '\u{A}' | '\u{D}' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}'
    )
}

// Entity names use XML Name rather than namespace-constrained NCName, so colons remain legal:
// XML 1.0 Fifth Edition section 2.3, production [5]: https://www.w3.org/TR/xml/#NT-Name
pub(crate) fn is_xml_name(value: &str) -> bool {
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    (first == ':' || is_ncname_start(first))
        && characters.all(|character| character == ':' || is_ncname_char(character))
}

pub(crate) fn unicode_decimal_value(character: char) -> Option<u32> {
    const ZEROES: &[char] = &[
        '0', '٠', '۰', '०', '০', '੦', '૦', '୦', '௦', '౦', '೦', '൦', '๐', '໐', '༠', '၀', '០', '᠐',
        'ᥐ', '᧐', '᮰', '᱀', '꘠', '꣐', '꩐', '０',
    ];
    ZEROES.iter().find_map(|zero| {
        let offset = u32::from(character).checked_sub(u32::from(*zero))?;
        (offset <= 9).then_some(offset)
    })
}

pub(crate) fn is_ncname_start(ch: char) -> bool {
    matches!(
        ch,
        'A'..='Z'
            | '_'
            | 'a'..='z'
            | '\u{C0}'..='\u{D6}'
            | '\u{D8}'..='\u{F6}'
            | '\u{F8}'..='\u{2FF}'
            | '\u{370}'..='\u{37D}'
            | '\u{37F}'..='\u{1FFF}'
            | '\u{200C}'..='\u{200D}'
            | '\u{2070}'..='\u{218F}'
            | '\u{2C00}'..='\u{2FEF}'
            | '\u{3001}'..='\u{D7FF}'
            | '\u{F900}'..='\u{FDCF}'
            | '\u{FDF0}'..='\u{FFFD}'
            | '\u{10000}'..='\u{EFFFF}'
    )
}

pub(crate) fn is_ncname_char(ch: char) -> bool {
    is_ncname_start(ch)
        || matches!(
            ch,
            '-' | '.' | '0'..='9' | '\u{B7}' | '\u{0300}'..='\u{036F}' | '\u{203F}'..='\u{2040}'
        )
}
