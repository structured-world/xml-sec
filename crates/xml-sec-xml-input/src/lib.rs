//! Backend-neutral XML byte encoding detection and strict transcoding.

#![deny(unsafe_code)]

use std::{borrow::Cow, ops::Range};

pub mod lexical;

/// Failure while converting external bytes into the Unicode XML parser contract.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The byte signature selected an encoding that this implementation cannot decode.
    #[error("unsupported XML byte encoding `{0}`")]
    UnsupportedByteEncoding(&'static str),
    /// An encoding label was not recognized.
    #[error("unsupported XML encoding `{0}`")]
    UnsupportedEncoding(String),
    /// Resolver metadata, a byte signature, and the XML declaration disagreed.
    #[error("XML byte encoding conflicts with declared or selected encoding `{0}`")]
    ConflictingEncoding(String),
    /// The XML declaration was malformed before parsing could begin.
    #[error("malformed XML encoding declaration: {0}")]
    MalformedDeclaration(&'static str),
    /// The selected decoder rejected malformed input instead of replacing it.
    #[error("XML input contains invalid {0} bytes")]
    InvalidBytes(&'static str),
    /// A BOM-less UTF-16 document did not identify its byte order.
    #[error("BOM-less UTF-16 XML input requires an explicit UTF-16LE or UTF-16BE declaration")]
    MissingUtf16ByteOrder,
    /// A UTF-32 document did not identify its byte order through metadata or its signature.
    #[error("UTF-32 XML input requires a UTF-32LE/UTF-32BE encoding or byte-order signature")]
    MissingUtf32ByteOrder,
    /// A UTF-16 code unit was truncated.
    #[error("{0} XML input has an odd byte length")]
    InvalidUtf16Length(&'static str),
    /// A UTF-32 code unit was truncated.
    #[error("{0} XML input byte length is not divisible by four")]
    InvalidUtf32Length(&'static str),
    /// Decoded UTF-8 would exceed the caller's materialization ceiling.
    #[error("decoded XML exceeds the maximum size of {maximum} bytes: at least {actual} bytes")]
    DecodedLimit { maximum: usize, actual: usize },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SelectedEncoding {
    Standard(&'static encoding_rs::Encoding),
    Utf32Le,
    Utf32Be,
    Ascii,
    Registered(IanaSingleByteEncoding),
}

impl SelectedEncoding {
    fn name(self) -> &'static str {
        match self {
            Self::Standard(encoding) => encoding.name(),
            Self::Utf32Le => "UTF-32LE",
            Self::Utf32Be => "UTF-32BE",
            Self::Ascii => "US-ASCII",
            Self::Registered(encoding) => encoding.name(),
        }
    }

    fn is_utf8(self) -> bool {
        matches!(self, Self::Standard(encoding) if encoding == encoding_rs::UTF_8)
    }
}

/// Strict IANA single-byte repertoire shared by XML input and XSLT output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IanaSingleByteEncoding {
    Latin1,
    Latin5,
    Iso8859_11,
    Tis620,
}

impl IanaSingleByteEncoding {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Latin1 => "ISO-8859-1",
            Self::Latin5 => "ISO-8859-9",
            Self::Iso8859_11 => "ISO-8859-11",
            Self::Tis620 => "TIS-620",
        }
    }

    #[must_use]
    pub fn decode_byte(self, byte: u8) -> Option<char> {
        match self {
            Self::Latin1 => Some(char::from(byte)),
            Self::Latin5 => Some(match byte {
                0xD0 => '\u{011E}',
                0xDD => '\u{0130}',
                0xDE => '\u{015E}',
                0xF0 => '\u{011F}',
                0xFD => '\u{0131}',
                0xFE => '\u{015F}',
                _ => char::from(byte),
            }),
            Self::Iso8859_11 | Self::Tis620 => match byte {
                0x00..=0x7F => Some(char::from(byte)),
                0xA0 if self == Self::Iso8859_11 => Some('\u{00A0}'),
                0xA1..=0xDA | 0xE0..=0xFB => char::from_u32(u32::from(byte) + 0x0D60),
                0xDF => Some('\u{0E3F}'),
                _ => None,
            },
        }
    }

    #[must_use]
    pub fn encode_char(self, character: char) -> Option<u8> {
        match self {
            Self::Latin1 => u8::try_from(u32::from(character)).ok(),
            Self::Latin5 => match character {
                '\u{011E}' => Some(0xD0),
                '\u{0130}' => Some(0xDD),
                '\u{015E}' => Some(0xDE),
                '\u{011F}' => Some(0xF0),
                '\u{0131}' => Some(0xFD),
                '\u{015F}' => Some(0xFE),
                _ => u8::try_from(u32::from(character))
                    .ok()
                    .filter(|byte| !matches!(byte, 0xD0 | 0xDD | 0xDE | 0xF0 | 0xFD | 0xFE)),
            },
            Self::Iso8859_11 | Self::Tis620 => match u32::from(character) {
                value @ 0x00..=0x7F => Some(value as u8),
                0xA0 if self == Self::Iso8859_11 => Some(0xA0),
                value @ 0x0E01..=0x0E3A | value @ 0x0E40..=0x0E5B => {
                    u8::try_from(value - 0x0D60).ok()
                }
                0x0E3F => Some(0xDF),
                _ => None,
            },
        }
    }
}

/// Resolve labels whose IANA meaning differs from WHATWG-compatible decoders.
#[must_use]
pub fn registered_single_byte_encoding(label: &str) -> Option<IanaSingleByteEncoding> {
    if is_latin1_encoding_label(label) {
        return Some(IanaSingleByteEncoding::Latin1);
    }
    if matches_ascii_case(
        label,
        &[
            "iso-ir-148",
            "iso88599",
            "iso-8859-9",
            "iso_8859-9",
            "latin5",
            "csisolatin5",
            "iso_8859-9:1989",
        ],
    ) {
        return Some(IanaSingleByteEncoding::Latin5);
    }
    if matches_ascii_case(label, &["iso8859-11", "iso-8859-11"]) {
        return Some(IanaSingleByteEncoding::Iso8859_11);
    }
    label
        .eq_ignore_ascii_case("tis-620")
        .then_some(IanaSingleByteEncoding::Tis620)
}

/// Return whether a WHATWG label lookup preserves the caller's requested legacy encoding.
///
/// WHATWG redirects many ISO labels to Windows code pages. Callers that promise exact IANA
/// semantics must either implement those repertoires explicitly or reject the redirected label.
#[must_use]
pub fn legacy_label_matches_encoding(
    label: &str,
    encoding: &'static encoding_rs::Encoding,
) -> bool {
    let canonical = encoding.name();
    let Some(code_page) = canonical.strip_prefix("windows-") else {
        return true;
    };
    label.eq_ignore_ascii_case(canonical)
        || label
            .get(2..)
            .is_some_and(|suffix| label[..2].eq_ignore_ascii_case("cp") && suffix == code_page)
        || label
            .get(4..)
            .is_some_and(|suffix| label[..4].eq_ignore_ascii_case("x-cp") && suffix == code_page)
}

/// Decode XML bytes according to XML 1.0 encoding detection rules.
///
/// `explicit_encoding` is trusted resolver metadata. It is checked against the
/// byte signature and XML declaration rather than silently overriding either.
/// UTF-8 input is borrowed when no declaration rewrite is required; other
/// encodings are strictly transcoded and their declaration is normalized.
pub fn decode_xml<'a>(
    bytes: &'a [u8],
    explicit_encoding: Option<&str>,
) -> Result<Cow<'a, str>, Error> {
    decode_xml_bounded(bytes, explicit_encoding, usize::MAX)
}

/// Decode XML while preventing either the transcoded or normalized UTF-8
/// representation from growing beyond `maximum_decoded_bytes`.
pub fn decode_xml_bounded<'a>(
    bytes: &'a [u8],
    explicit_encoding: Option<&str>,
    maximum_decoded_bytes: usize,
) -> Result<Cow<'a, str>, Error> {
    let physical = physical_encoding(bytes)?;
    let ascii_declaration = if physical.is_none() {
        declaration_from_ascii_bytes(bytes)?
    } else {
        None
    };
    let explicit_utf16 = explicit_encoding.is_some_and(is_generic_utf16);
    let explicit_utf32 = explicit_encoding.is_some_and(is_generic_utf32);
    let explicit = explicit_encoding
        .filter(|_| !explicit_utf16 && !explicit_utf32)
        .map(parse_encoding)
        .transpose()?;
    if explicit_utf16 && !physical.is_some_and(|(encoding, _)| is_utf16_encoding(encoding)) {
        return Err(Error::MissingUtf16ByteOrder);
    }
    if explicit_utf32 && !physical.is_some_and(|(encoding, _)| is_utf32_encoding(encoding)) {
        return Err(Error::MissingUtf32ByteOrder);
    }
    let declared_before_decode = ascii_declaration
        .as_ref()
        .map(|(_, label)| parse_encoding(label))
        .transpose()?;
    let selected = explicit
        .or(physical.map(|(encoding, _)| encoding))
        .or(declared_before_decode)
        .unwrap_or(SelectedEncoding::Standard(encoding_rs::UTF_8));

    if let Some((physical, _)) = physical
        && !encodings_compatible(selected, physical, true)
    {
        return Err(Error::ConflictingEncoding(selected.name().into()));
    }
    if let Some(declared) = declared_before_decode
        && !encodings_compatible(selected, declared, false)
    {
        return Err(Error::ConflictingEncoding(declared.name().into()));
    }

    let bom_len = physical.map_or(0, |(_, bom_len)| bom_len);
    let mut decoded = decode_selected(&bytes[bom_len..], selected, maximum_decoded_bytes)?;
    let declaration = declaration_from_text(&decoded)?;
    if let Some(range) = &declaration {
        let label = &decoded[range.clone()];
        if is_generic_utf16(label) {
            let has_utf16_bom = physical.is_some_and(|(encoding, bom_len)| {
                bom_len > 0
                    && matches!(encoding, SelectedEncoding::Standard(value)
                        if value == encoding_rs::UTF_16LE || value == encoding_rs::UTF_16BE)
            });
            if !has_utf16_bom {
                return Err(Error::MissingUtf16ByteOrder);
            }
        } else if is_generic_utf32(label) {
            if !physical.is_some_and(|(encoding, _)| is_utf32_encoding(encoding)) {
                return Err(Error::MissingUtf32ByteOrder);
            }
        } else {
            let declared = parse_encoding(label)?;
            if !encodings_compatible(selected, declared, false) {
                return Err(Error::ConflictingEncoding(label.into()));
            }
        }
    } else if explicit_encoding.is_none()
        && physical.is_some_and(|(encoding, bom_len)| {
            bom_len == 0
                && matches!(encoding, SelectedEncoding::Standard(value)
                    if value == encoding_rs::UTF_16LE || value == encoding_rs::UTF_16BE)
        })
    {
        return Err(Error::MissingUtf16ByteOrder);
    }

    if !selected.is_utf8()
        && let Some(range) = declaration
    {
        let normalized_len = decoded
            .len()
            .saturating_sub(range.len())
            .saturating_add("UTF-8".len());
        if normalized_len > maximum_decoded_bytes {
            return Err(Error::DecodedLimit {
                maximum: maximum_decoded_bytes,
                actual: normalized_len,
            });
        }
        decoded.to_mut().replace_range(range, "UTF-8");
    }
    Ok(decoded)
}

/// Decode a non-XML text resource using an explicit character encoding.
pub fn decode_text<'a>(bytes: &'a [u8], encoding: &str) -> Result<Cow<'a, str>, Error> {
    decode_text_bounded(bytes, encoding, usize::MAX)
}

/// Decode a non-XML text resource under a retained-byte ceiling.
pub fn decode_text_bounded<'a>(
    bytes: &'a [u8],
    encoding: &str,
    maximum_decoded_bytes: usize,
) -> Result<Cow<'a, str>, Error> {
    if is_generic_utf16(encoding) {
        // RFC 2781 section 3.3 requires a byte-order signature when the generic UTF-16
        // label is used. Consume that signature before exposing text to the caller.
        // https://www.rfc-editor.org/rfc/rfc2781.html#section-3.3
        if let Some(payload) = bytes.strip_prefix(&[0xFF, 0xFE]) {
            return decode_selected(
                payload,
                SelectedEncoding::Standard(encoding_rs::UTF_16LE),
                maximum_decoded_bytes,
            );
        }
        if let Some(payload) = bytes.strip_prefix(&[0xFE, 0xFF]) {
            return decode_selected(
                payload,
                SelectedEncoding::Standard(encoding_rs::UTF_16BE),
                maximum_decoded_bytes,
            );
        }
        return Err(Error::MissingUtf16ByteOrder);
    }
    decode_selected(bytes, parse_encoding(encoding)?, maximum_decoded_bytes)
}

fn physical_encoding(bytes: &[u8]) -> Result<Option<(SelectedEncoding, usize)>, Error> {
    let prefix = bytes.get(..4).unwrap_or(bytes);
    // XML 1.0 Appendix F defines UCS-4 BOMs and initial `<` signatures. The two
    // unusual octet orders are recognized but intentionally unsupported.
    // https://www.w3.org/TR/xml/#sec-guessing
    match prefix {
        [0x00, 0x00, 0xFE, 0xFF] => return Ok(Some((SelectedEncoding::Utf32Be, 4))),
        [0xFF, 0xFE, 0x00, 0x00] => return Ok(Some((SelectedEncoding::Utf32Le, 4))),
        [0x00, 0x00, 0x00, b'<'] => return Ok(Some((SelectedEncoding::Utf32Be, 0))),
        [b'<', 0x00, 0x00, 0x00] => return Ok(Some((SelectedEncoding::Utf32Le, 0))),
        [0x00, 0x00, 0xFF, 0xFE]
        | [0xFE, 0xFF, 0x00, 0x00]
        | [0x00, 0x00, b'<', 0x00]
        | [0x00, b'<', 0x00, 0x00] => {
            return Err(Error::UnsupportedByteEncoding("UTF-32 unusual byte order"));
        }
        _ => {}
    }
    if prefix == [0x4C, 0x6F, 0xA7, 0x94] {
        return Err(Error::UnsupportedByteEncoding("EBCDIC"));
    }
    if let Some((encoding, length)) = encoding_rs::Encoding::for_bom(bytes) {
        return Ok(Some((SelectedEncoding::Standard(encoding), length)));
    }
    Ok(match prefix {
        [0x00, b'<', 0x00, b'?'] => Some((SelectedEncoding::Standard(encoding_rs::UTF_16BE), 0)),
        [b'<', 0x00, b'?', 0x00] => Some((SelectedEncoding::Standard(encoding_rs::UTF_16LE), 0)),
        _ => None,
    })
}

fn parse_encoding(label: &str) -> Result<SelectedEncoding, Error> {
    if matches_ascii_case(label, &["utf-32le", "utf32le"]) {
        return Ok(SelectedEncoding::Utf32Le);
    }
    if matches_ascii_case(label, &["utf-32be", "utf32be"]) {
        return Ok(SelectedEncoding::Utf32Be);
    }
    if matches_ascii_case(label, &["us-ascii", "ascii"]) {
        return Ok(SelectedEncoding::Ascii);
    }
    // The IANA-registered labels below name the same ISO-8859-1 repertoire;
    // WHATWG-style lookup would incorrectly map them to Windows-1252. `latin-1`
    // is retained as the already-supported punctuation variant.
    // https://www.iana.org/assignments/character-sets/character-sets.xhtml
    if let Some(encoding) = registered_single_byte_encoding(label) {
        return Ok(SelectedEncoding::Registered(encoding));
    }
    // WHATWG aliases these IANA encodings to Windows extensions with different C1 bytes.
    // XML 1.0 section 4.3.3 requires registered labels to retain their IANA meaning.
    // https://www.w3.org/TR/xml/#charencoding
    encoding_rs::Encoding::for_label(label.as_bytes())
        .map(SelectedEncoding::Standard)
        .ok_or_else(|| Error::UnsupportedEncoding(label.into()))
}

/// Return whether `label` selects strict ISO-8859-1 semantics.
///
/// This intentionally does not use WHATWG label matching, which maps these
/// XML encoding names to Windows-1252 instead of the registered repertoire.
#[must_use]
pub fn is_latin1_encoding_label(label: &str) -> bool {
    matches_ascii_case(
        label,
        &[
            "iso_8859-1:1987",
            "iso-ir-100",
            "iso_8859-1",
            "iso-8859-1",
            "latin1",
            "latin-1",
            "l1",
            "ibm819",
            "cp819",
            "csisolatin1",
        ],
    )
}

fn decode_selected<'a>(
    bytes: &'a [u8],
    encoding: SelectedEncoding,
    maximum: usize,
) -> Result<Cow<'a, str>, Error> {
    if matches!(
        encoding,
        SelectedEncoding::Utf32Le | SelectedEncoding::Utf32Be
    ) {
        return decode_utf32(bytes, encoding, maximum).map(Cow::Owned);
    }
    if encoding == SelectedEncoding::Ascii {
        if bytes.iter().any(|byte| !byte.is_ascii()) {
            return Err(Error::InvalidBytes("US-ASCII"));
        }
        let decoded = std::str::from_utf8(bytes).expect("seven-bit US-ASCII is always valid UTF-8");
        if decoded.len() > maximum {
            return Err(Error::DecodedLimit {
                maximum,
                actual: decoded.len(),
            });
        }
        return Ok(Cow::Borrowed(decoded));
    }
    if matches!(encoding, SelectedEncoding::Registered(_)) {
        return decode_registered_single_byte(bytes, encoding, maximum).map(Cow::Owned);
    }
    let SelectedEncoding::Standard(encoding) = encoding else {
        unreachable!("special-case encodings returned above")
    };
    if encoding == encoding_rs::UTF_8 {
        let decoded = std::str::from_utf8(bytes).map_err(|_| Error::InvalidBytes("UTF-8"))?;
        if decoded.len() > maximum {
            return Err(Error::DecodedLimit {
                maximum,
                actual: decoded.len(),
            });
        }
        return Ok(Cow::Borrowed(decoded));
    }
    if (encoding == encoding_rs::UTF_16LE || encoding == encoding_rs::UTF_16BE)
        && !bytes.len().is_multiple_of(2)
    {
        return Err(Error::InvalidUtf16Length(encoding.name()));
    }

    let mut decoder = encoding.new_decoder_without_bom_handling();
    let mut remaining = bytes;
    let mut decoded = String::with_capacity(bytes.len().min(maximum));
    let mut buffer = [0_u8; 4096];
    loop {
        let (result, read, written) =
            decoder.decode_to_utf8_without_replacement(remaining, &mut buffer, true);
        let actual = decoded.len().saturating_add(written);
        if actual > maximum {
            return Err(Error::DecodedLimit { maximum, actual });
        }
        decoded.push_str(
            std::str::from_utf8(&buffer[..written])
                .expect("encoding_rs emits valid UTF-8 into the output buffer"),
        );
        remaining = &remaining[read..];
        match result {
            encoding_rs::DecoderResult::InputEmpty => return Ok(Cow::Owned(decoded)),
            encoding_rs::DecoderResult::OutputFull => {}
            encoding_rs::DecoderResult::Malformed(_, _) => {
                return Err(Error::InvalidBytes(encoding.name()));
            }
        }
    }
}

fn decode_registered_single_byte(
    bytes: &[u8],
    encoding: SelectedEncoding,
    maximum: usize,
) -> Result<String, Error> {
    let mut decoded = String::with_capacity(bytes.len().min(maximum));
    for &byte in bytes {
        let character = match encoding {
            SelectedEncoding::Registered(encoding) => encoding
                .decode_byte(byte)
                .ok_or_else(|| Error::InvalidBytes(encoding.name()))?,
            _ => unreachable!("registered single-byte decoder receives a matching encoding"),
        };
        let actual = decoded.len().saturating_add(character.len_utf8());
        if actual > maximum {
            return Err(Error::DecodedLimit { maximum, actual });
        }
        decoded.push(character);
    }
    Ok(decoded)
}

fn decode_utf32(bytes: &[u8], encoding: SelectedEncoding, maximum: usize) -> Result<String, Error> {
    if !bytes.len().is_multiple_of(4) {
        return Err(Error::InvalidUtf32Length(encoding.name()));
    }
    let mut decoded = String::with_capacity(bytes.len().min(maximum));
    let (units, remainder) = bytes.as_chunks::<4>();
    debug_assert!(remainder.is_empty());
    for &unit in units {
        let scalar = match encoding {
            SelectedEncoding::Utf32Le => u32::from_le_bytes(unit),
            SelectedEncoding::Utf32Be => u32::from_be_bytes(unit),
            _ => unreachable!("UTF-32 decoder receives an explicit byte order"),
        };
        let character = char::from_u32(scalar).ok_or(Error::InvalidBytes(encoding.name()))?;
        let actual = decoded.len().saturating_add(character.len_utf8());
        if actual > maximum {
            return Err(Error::DecodedLimit { maximum, actual });
        }
        decoded.push(character);
    }
    Ok(decoded)
}

fn encodings_compatible(
    selected: SelectedEncoding,
    candidate: SelectedEncoding,
    physical: bool,
) -> bool {
    selected == candidate
        || (physical
            && matches!(selected, SelectedEncoding::Standard(value) if value == encoding_rs::UTF_8)
            && matches!(candidate, SelectedEncoding::Standard(value) if value == encoding_rs::UTF_8))
}

fn is_utf16_encoding(encoding: SelectedEncoding) -> bool {
    matches!(encoding, SelectedEncoding::Standard(value)
        if value == encoding_rs::UTF_16LE || value == encoding_rs::UTF_16BE)
}

fn is_utf32_encoding(encoding: SelectedEncoding) -> bool {
    matches!(
        encoding,
        SelectedEncoding::Utf32Le | SelectedEncoding::Utf32Be
    )
}

fn declaration_from_ascii_bytes(bytes: &[u8]) -> Result<Option<(Range<usize>, &str)>, Error> {
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    if !bytes.starts_with(b"<?xml") {
        return Ok(None);
    }
    let end = bytes
        .windows(2)
        .position(|window| window == b"?>")
        .map(|index| index + 2)
        .ok_or(Error::MalformedDeclaration("unterminated declaration"))?;
    // XML encoding declarations are ASCII for every supported
    // ASCII-compatible encoding, regardless of the following document bytes.
    let prefix = std::str::from_utf8(&bytes[..end])
        .map_err(|_| Error::MalformedDeclaration("declaration is not ASCII-compatible"))?;
    declaration_from_text(prefix).map(|range| {
        range.map(|range| {
            let label = &prefix[range.clone()];
            (range, label)
        })
    })
}

fn declaration_from_text(xml: &str) -> Result<Option<Range<usize>>, Error> {
    let Some(rest) = xml.strip_prefix("<?xml") else {
        return Ok(None);
    };
    if !rest.as_bytes().first().is_some_and(u8::is_ascii_whitespace) {
        return Ok(None);
    }
    let end = rest
        .find("?>")
        .ok_or(Error::MalformedDeclaration("unterminated declaration"))?;
    let declaration = &rest.as_bytes()[..end];
    let mut cursor = 0;
    while cursor < declaration.len() {
        while declaration.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if cursor == declaration.len() {
            break;
        }
        let name_start = cursor;
        while declaration.get(cursor).is_some_and(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b':' | b'-' | b'.')
        }) {
            cursor += 1;
        }
        if cursor == name_start {
            return Err(Error::MalformedDeclaration("invalid pseudo-attribute"));
        }
        let name = &declaration[name_start..cursor];
        while declaration.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if declaration.get(cursor) != Some(&b'=') {
            return Err(Error::MalformedDeclaration("missing `=`"));
        }
        cursor += 1;
        while declaration.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        let &quote @ (b'\'' | b'"') = declaration
            .get(cursor)
            .ok_or(Error::MalformedDeclaration("missing quoted value"))?
        else {
            return Err(Error::MalformedDeclaration("value is not quoted"));
        };
        let value_start = cursor + 1;
        let value_end = value_start
            + declaration[value_start..]
                .iter()
                .position(|byte| *byte == quote)
                .ok_or(Error::MalformedDeclaration("unterminated value"))?;
        if name == b"encoding" {
            return Ok(Some((5 + value_start)..(5 + value_end)));
        }
        cursor = value_end + 1;
        if declaration
            .get(cursor)
            .is_some_and(|byte| !byte.is_ascii_whitespace())
        {
            return Err(Error::MalformedDeclaration("missing whitespace"));
        }
    }
    Ok(None)
}

fn is_generic_utf16(label: &str) -> bool {
    label.eq_ignore_ascii_case("UTF-16") || label.eq_ignore_ascii_case("UTF16")
}

fn is_generic_utf32(label: &str) -> bool {
    label.eq_ignore_ascii_case("UTF-32") || label.eq_ignore_ascii_case("UTF32")
}

fn matches_ascii_case(value: &str, candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::{Error, decode_text, decode_xml, decode_xml_bounded};

    fn encode_utf32(source: &str, little_endian: bool) -> Vec<u8> {
        source
            .chars()
            .flat_map(|character| {
                let value = u32::from(character);
                if little_endian {
                    value.to_le_bytes()
                } else {
                    value.to_be_bytes()
                }
            })
            .collect()
    }

    #[test]
    fn utf8_without_a_rewritten_declaration_stays_borrowed() {
        let bytes = b"<root>ok</root>";
        assert!(matches!(decode_xml(bytes, None), Ok(Cow::Borrowed(_))));
    }

    #[test]
    fn generic_utf16_uses_the_bom_byte_order() {
        let source = "<?xml version=\"1.0\" encoding=\"UTF-16\"?><root>lambda</root>";
        let mut bytes = vec![0xFE, 0xFF];
        bytes.extend(source.encode_utf16().flat_map(u16::to_be_bytes));
        let decoded = decode_xml(&bytes, Some("UTF-16")).expect("BOM selects UTF-16BE");
        assert!(decoded.contains("encoding=\"UTF-8\""));
        assert!(decoded.contains("<root>lambda</root>"));
    }

    #[test]
    fn utf32_bom_and_initial_signatures_select_byte_order() {
        // XML 1.0 Appendix F defines both UCS-4 BOMs and the BOM-less `<` signatures.
        // https://www.w3.org/TR/xml/#sec-guessing
        let source = "<?xml version=\"1.0\" encoding=\"UTF-32\"?><root>lambda</root>";
        for (little_endian, bom) in [
            (false, [0x00, 0x00, 0xFE, 0xFF]),
            (true, [0xFF, 0xFE, 0x00, 0x00]),
        ] {
            let mut bytes = bom.to_vec();
            bytes.extend(encode_utf32(source, little_endian));
            let decoded = decode_xml(&bytes, None).expect("UTF-32 BOM selects byte order");
            assert!(decoded.contains("encoding=\"UTF-8\""));
            assert!(decoded.contains("<root>lambda</root>"));
        }

        for little_endian in [false, true] {
            let bytes = encode_utf32("<root>lambda</root>", little_endian);
            assert_eq!(
                decode_xml(&bytes, None).expect("initial signature selects UTF-32 byte order"),
                "<root>lambda</root>"
            );
        }
    }

    #[test]
    fn utf32_rejects_truncation_invalid_scalars_and_conflicting_metadata() {
        let mut truncated = vec![0x00, 0x00, 0xFE, 0xFF];
        truncated.extend([0x00, 0x00, 0x00]);
        assert!(decode_xml(&truncated, None).is_err());

        let mut surrogate = vec![0x00, 0x00, 0xFE, 0xFF];
        surrogate.extend(0xD800_u32.to_be_bytes());
        assert!(matches!(
            decode_xml(&surrogate, None),
            Err(Error::InvalidBytes("UTF-32BE"))
        ));

        let mut little_endian = vec![0xFF, 0xFE, 0x00, 0x00];
        little_endian.extend(encode_utf32("<root/>", true));
        assert!(matches!(
            decode_xml(&little_endian, Some("UTF-32BE")),
            Err(Error::ConflictingEncoding(_))
        ));
    }

    #[test]
    fn utf32_decoding_obeys_the_utf8_materialization_limit() {
        let mut bytes = vec![0x00, 0x00, 0xFE, 0xFF];
        bytes.extend(encode_utf32("<root>lambda</root>", false));
        assert!(matches!(
            decode_xml_bounded(&bytes, None, 8),
            Err(Error::DecodedLimit { maximum: 8, .. })
        ));
    }

    #[test]
    fn bomless_generic_utf16_is_rejected_as_ambiguous() {
        let bytes = "<?xml version=\"1.0\" encoding=\"UTF-16\"?><root/>"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert!(matches!(
            decode_xml(&bytes, Some("UTF-16")),
            Err(Error::MissingUtf16ByteOrder)
        ));
    }

    #[test]
    fn explicit_utf16_byte_order_decodes_a_declarationless_resource() {
        let bytes = "<root>lambda</root>"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(
            decode_xml(&bytes, Some("UTF-16LE")).unwrap(),
            "<root>lambda</root>"
        );
    }

    #[test]
    fn generic_utf16_text_requires_and_consumes_a_byte_order_mark() {
        let text = "lambda";
        let mut little = vec![0xFF, 0xFE];
        little.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        let mut big = vec![0xFE, 0xFF];
        big.extend(text.encode_utf16().flat_map(u16::to_be_bytes));

        assert_eq!(decode_text(&little, "UTF-16").unwrap(), text);
        assert_eq!(decode_text(&big, "UTF-16").unwrap(), text);
        assert!(matches!(
            decode_text(&little[2..], "UTF-16"),
            Err(Error::MissingUtf16ByteOrder)
        ));
    }

    #[test]
    fn trusted_metadata_cannot_conflict_with_a_bom() {
        assert!(matches!(
            decode_xml(&[0xFF, 0xFE, b'A', 0], Some("UTF-8")),
            Err(Error::ConflictingEncoding(_))
        ));
    }

    #[test]
    fn latin1_and_windows_1252_keep_distinct_c1_semantics() {
        // Every IANA label must select the exact registered repertoire rather than the
        // WHATWG replacement decoder used for HTML compatibility.
        for alias in [
            "ISO_8859-1:1987",
            "iso-ir-100",
            "ISO_8859-1",
            "ISO-8859-1",
            "latin1",
            "l1",
            "IBM819",
            "CP819",
            "csISOLatin1",
        ] {
            assert_eq!(
                decode_text(&[0x80], alias).unwrap(),
                "\u{80}",
                "IANA alias {alias} must retain ISO-8859-1 C1 semantics"
            );
        }
        assert_eq!(decode_text(&[0x80], "windows-1252").unwrap(), "€");
    }

    #[test]
    fn iana_single_byte_encodings_do_not_inherit_windows_extensions() {
        // XML 1.0 section 4.3.3 requires IANA labels to retain their registered meaning.
        // https://www.w3.org/TR/xml/#charencoding
        assert_eq!(decode_text(&[0x80], "ISO-8859-9").unwrap(), "\u{80}");
        assert_eq!(decode_text(&[0x80], "iso88599").unwrap(), "\u{80}");
        assert_eq!(decode_text(&[0xD0, 0xFD], "ISO-8859-9").unwrap(), "Ğı");
        assert_eq!(decode_text(&[0x80], "windows-1254").unwrap(), "€");

        assert_eq!(decode_text(&[0xA0], "ISO-8859-11").unwrap(), "\u{A0}");
        assert!(matches!(
            decode_text(&[0x80], "TIS-620"),
            Err(Error::InvalidBytes("TIS-620"))
        ));
        assert!(matches!(
            decode_text(&[0xA0], "TIS-620"),
            Err(Error::InvalidBytes("TIS-620"))
        ));
        assert_eq!(decode_text(&[0xA1, 0xFB], "TIS-620").unwrap(), "ก๛");
        assert_eq!(decode_text(&[0x80], "windows-874").unwrap(), "€");
    }

    #[test]
    fn us_ascii_rejects_non_ascii_bytes() {
        // WHATWG aliases US-ASCII to Windows-1252, but XML's declared encoding
        // contract permits only seven-bit bytes for this label.
        assert!(matches!(
            decode_text(&[0x80], "US-ASCII"),
            Err(Error::InvalidBytes("US-ASCII"))
        ));
        assert_eq!(
            decode_text(b"plain ASCII", "US-ASCII").unwrap(),
            "plain ASCII"
        );
    }

    #[test]
    fn transcoded_and_normalized_representations_are_both_bounded() {
        let bytes = b"<?xml version=\"1.0\" encoding=\"GBK\"?><root/>";
        let exact = decode_xml(bytes, None).expect("GBK declaration is supported");
        assert!(matches!(
            decode_xml_bounded(bytes, None, exact.len() - 1),
            Err(Error::DecodedLimit { .. })
        ));
        assert_eq!(decode_xml_bounded(bytes, None, exact.len()).unwrap(), exact);
    }

    #[test]
    fn declaration_detection_is_not_limited_to_a_short_prefix() {
        let whitespace = " ".repeat(2_048);
        let source = format!("<?xml{whitespace}encoding=\"ISO-8859-1\"?><root>caf\u{e9}</root>");
        let bytes = source
            .chars()
            .map(|character| u8::try_from(u32::from(character)).unwrap())
            .collect::<Vec<_>>();
        assert!(decode_xml(&bytes, None).unwrap().contains("café"));
    }

    #[test]
    fn declaration_allows_whitespace_before_its_terminator() {
        let source = b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?><root>caf\xe9</root>";
        assert!(decode_xml(source, None).unwrap().contains("café"));
    }

    #[test]
    fn unsupported_xml_signatures_fail_explicitly() {
        assert!(matches!(
            decode_xml(&[0x4C, 0x6F, 0xA7, 0x94], None),
            Err(Error::UnsupportedByteEncoding("EBCDIC"))
        ));
    }

    #[test]
    fn truncated_utf16_reports_the_code_unit_boundary() {
        assert!(matches!(
            decode_xml(&[0xff, 0xfe, 0], None),
            Err(Error::InvalidUtf16Length("UTF-16LE"))
        ));
    }
}
