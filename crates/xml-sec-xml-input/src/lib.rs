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
    /// A UTF-16 code unit was truncated.
    #[error("{0} XML input has an odd byte length")]
    InvalidUtf16Length(&'static str),
    /// Decoded UTF-8 would exceed the caller's materialization ceiling.
    #[error("decoded XML exceeds the maximum size of {maximum} bytes: at least {actual} bytes")]
    DecodedLimit { maximum: usize, actual: usize },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SelectedEncoding {
    Standard(&'static encoding_rs::Encoding),
    Ascii,
    Latin1,
}

impl SelectedEncoding {
    fn name(self) -> &'static str {
        match self {
            Self::Standard(encoding) => encoding.name(),
            Self::Ascii => "US-ASCII",
            Self::Latin1 => "ISO-8859-1",
        }
    }

    fn is_utf8(self) -> bool {
        matches!(self, Self::Standard(encoding) if encoding == encoding_rs::UTF_8)
    }
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
    let explicit = explicit_encoding
        .filter(|_| !explicit_utf16)
        .map(parse_encoding)
        .transpose()?;
    if explicit_utf16 && !physical.is_some_and(|(encoding, _)| is_utf16_encoding(encoding)) {
        return Err(Error::MissingUtf16ByteOrder);
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
    decode_selected(bytes, parse_encoding(encoding)?, maximum_decoded_bytes)
}

fn physical_encoding(bytes: &[u8]) -> Result<Option<(SelectedEncoding, usize)>, Error> {
    let prefix = bytes.get(..4).unwrap_or(bytes);
    if matches!(prefix, [0x00, 0x00, 0xFE, 0xFF] | [0xFF, 0xFE, 0x00, 0x00])
        || matches!(prefix, [0x00, 0x00, 0x00, b'<'] | [b'<', 0x00, 0x00, 0x00])
    {
        return Err(Error::UnsupportedByteEncoding("UTF-32"));
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
    if matches_ascii_case(label, &["us-ascii", "ascii"]) {
        return Ok(SelectedEncoding::Ascii);
    }
    // The IANA-registered labels below name the same ISO-8859-1 repertoire;
    // WHATWG-style lookup would incorrectly map them to Windows-1252. `latin-1`
    // is retained as the already-supported punctuation variant.
    // https://www.iana.org/assignments/character-sets/character-sets.xhtml
    if is_latin1_encoding_label(label) {
        return Ok(SelectedEncoding::Latin1);
    }
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
    if encoding == SelectedEncoding::Latin1 {
        let mut decoded = String::with_capacity(bytes.len().min(maximum));
        for byte in bytes {
            let character = char::from(*byte);
            let actual = decoded.len().saturating_add(character.len_utf8());
            if actual > maximum {
                return Err(Error::DecodedLimit { maximum, actual });
            }
            decoded.push(character);
        }
        return Ok(Cow::Owned(decoded));
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

fn matches_ascii_case(value: &str, candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::{Error, decode_text, decode_xml, decode_xml_bounded};

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
            decode_xml(&[0, 0, 0, b'<'], None),
            Err(Error::UnsupportedByteEncoding("UTF-32"))
        ));
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
