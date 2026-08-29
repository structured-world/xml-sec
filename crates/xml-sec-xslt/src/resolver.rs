use crate::{Error, Result};

/// Stable caller-defined identity for resolved bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResourceIdentity(pub String);

/// Why the engine is resolving a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ResolvePurpose {
    Include,
    Import,
    Document,
    XInclude,
}

/// Immutable bytes and provenance supplied by a caller-owned resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedResource {
    pub canonical_uri: String,
    pub identity: ResourceIdentity,
    pub bytes: Vec<u8>,
    pub media_type: Option<String>,
    pub encoding: Option<String>,
}

/// Explicit resource boundary used by compilation and execution.
pub trait Resolver: Send + Sync {
    fn resolve(
        &self,
        uri: &str,
        base_uri: Option<&str>,
        purpose: ResolvePurpose,
    ) -> Result<ResolvedResource>;
}

pub(crate) fn decode_resource(bytes: &[u8], explicit: Option<&str>) -> Result<String> {
    let (encoding, bom_len) = resource_decode_parameters(bytes, explicit)?;
    if encoding == ResourceEncoding::Latin1 {
        return Ok(bytes[bom_len..]
            .iter()
            .map(|byte| char::from(*byte))
            .collect());
    }
    let ResourceEncoding::Standard(encoding) = encoding else {
        unreachable!("Latin-1 decoding returned above")
    };
    let (decoded, _, had_errors) = encoding.decode(&bytes[bom_len..]);
    if had_errors {
        return Err(invalid_resource_bytes(encoding.name()));
    }
    Ok(decoded.into_owned())
}

pub(crate) fn decoded_resource_len(bytes: &[u8], explicit: Option<&str>) -> Result<usize> {
    let (encoding, bom_len) = resource_decode_parameters(bytes, explicit)?;
    if encoding == ResourceEncoding::Latin1 {
        return bytes[bom_len..].iter().try_fold(0usize, |length, byte| {
            length
                .checked_add(if byte.is_ascii() { 1 } else { 2 })
                .ok_or_else(|| {
                    Error::Xml("decoded ISO-8859-1 resource length overflows usize".into())
                })
        });
    }
    let ResourceEncoding::Standard(encoding) = encoding else {
        unreachable!("Latin-1 length returned above")
    };
    let mut decoder = encoding.new_decoder_without_bom_handling();
    let mut remaining = &bytes[bom_len..];
    let mut decoded_len = 0usize;
    let mut buffer = [0u8; 4096];
    loop {
        let (result, read, written) =
            decoder.decode_to_utf8_without_replacement(remaining, &mut buffer, true);
        decoded_len = decoded_len.checked_add(written).ok_or_else(|| {
            Error::Xml(format!(
                "decoded {} resource length overflows usize",
                encoding.name()
            ))
        })?;
        remaining = &remaining[read..];
        match result {
            encoding_rs::DecoderResult::InputEmpty => return Ok(decoded_len),
            encoding_rs::DecoderResult::OutputFull => {}
            encoding_rs::DecoderResult::Malformed(_, _) => {
                return Err(invalid_resource_bytes(encoding.name()));
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ResourceEncoding {
    Standard(&'static encoding_rs::Encoding),
    Latin1,
}

fn invalid_resource_bytes(encoding: &str) -> Error {
    Error::Xml(format!(
        "external resource contains invalid {encoding} bytes"
    ))
}

fn resource_decode_parameters(
    bytes: &[u8],
    explicit: Option<&str>,
) -> Result<(ResourceEncoding, usize)> {
    if let Some(label) = explicit {
        Ok((resource_encoding(label)?, 0))
    } else {
        detect_xml_encoding(bytes)
    }
}

fn detect_xml_encoding(bytes: &[u8]) -> Result<(ResourceEncoding, usize)> {
    let prefix = bytes.get(..4).unwrap_or(bytes);
    if matches!(prefix, [0x00, 0x00, 0xFE, 0xFF] | [0xFF, 0xFE, 0x00, 0x00])
        || matches!(prefix, [0x00, 0x00, 0x00, b'<'] | [b'<', 0x00, 0x00, 0x00])
    {
        return Err(Error::Xml("unsupported resource encoding `UTF-32`".into()));
    }
    if prefix == [0x4C, 0x6F, 0xA7, 0x94] {
        return Err(Error::Xml(
            "unsupported EBCDIC XML resource encoding".into(),
        ));
    }
    if let Some((encoding, bom_len)) = encoding_rs::Encoding::for_bom(bytes) {
        return Ok((ResourceEncoding::Standard(encoding), bom_len));
    }
    match prefix {
        [0x00, b'<', 0x00, b'?'] => {
            return Ok((ResourceEncoding::Standard(encoding_rs::UTF_16BE), 0));
        }
        [b'<', 0x00, b'?', 0x00] => {
            return Ok((ResourceEncoding::Standard(encoding_rs::UTF_16LE), 0));
        }
        _ => {}
    }
    let encoding = xml_declaration_encoding(bytes)?
        .map(resource_encoding)
        .transpose()?
        .unwrap_or(ResourceEncoding::Standard(encoding_rs::UTF_8));
    Ok((encoding, 0))
}

fn xml_declaration_encoding(bytes: &[u8]) -> Result<Option<&str>> {
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    if !bytes.starts_with(b"<?xml") {
        return Ok(None);
    }
    let end = bytes
        .windows(2)
        .position(|window| window == b"?>")
        .ok_or_else(|| Error::Xml("unterminated XML declaration".into()))?;
    let declaration = std::str::from_utf8(&bytes[..end])
        .map_err(|_| Error::Xml("XML declaration is not ASCII-compatible".into()))?;
    let Some(offset) = declaration.find("encoding") else {
        return Ok(None);
    };
    let before = declaration[..offset].chars().next_back();
    if !before.is_some_and(char::is_whitespace) {
        return Ok(None);
    }
    let value = declaration[offset + "encoding".len()..].trim_start();
    let value = value
        .strip_prefix('=')
        .ok_or_else(|| Error::Xml("malformed XML encoding declaration".into()))?
        .trim_start();
    let quote = value
        .chars()
        .next()
        .filter(|quote| matches!(quote, '\'' | '"'))
        .ok_or_else(|| Error::Xml("XML encoding declaration must be quoted".into()))?;
    let value = &value[quote.len_utf8()..];
    let end = value
        .find(quote)
        .ok_or_else(|| Error::Xml("unterminated XML encoding declaration".into()))?;
    let label = &value[..end];
    if label.is_empty()
        || !label.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
    {
        return Err(Error::Xml(format!("invalid XML encoding name `{label}`")));
    }
    Ok(Some(label))
}

fn resource_encoding(label: &str) -> Result<ResourceEncoding> {
    if label.eq_ignore_ascii_case("iso-8859-1")
        || label.eq_ignore_ascii_case("latin1")
        || label.eq_ignore_ascii_case("latin-1")
    {
        return Ok(ResourceEncoding::Latin1);
    }
    encoding_rs::Encoding::for_label(label.as_bytes())
        .map(ResourceEncoding::Standard)
        .ok_or_else(|| Error::Xml(format!("unsupported resource encoding `{label}`")))
}

/// Resolver that denies every external resource.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoResolver;

impl Resolver for NoResolver {
    fn resolve(
        &self,
        uri: &str,
        _base_uri: Option<&str>,
        _purpose: ResolvePurpose,
    ) -> Result<ResolvedResource> {
        Err(crate::Error::Resolver {
            uri: uri.to_owned(),
            message: "external resource access is not configured".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::decode_resource;

    #[test]
    fn xml_encoding_detection_covers_declarations_initial_patterns_and_errors() {
        // External XML must follow the XML encoding autodetection contract when resolver metadata
        // is absent, while unsupported labels and encodings fail instead of decoding lossy text.
        let latin1 = b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><root>caf\xe9</root>";
        assert_eq!(
            decode_resource(latin1, None).expect("Latin-1 declaration is supported"),
            "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><root>café</root>"
        );
        assert_eq!(
            decode_resource(&[0x80], Some("ISO-8859-1"))
                .expect("Latin-1 metadata preserves the C1 range"),
            "\u{80}"
        );
        assert_eq!(
            decode_resource(&[0x80], Some("windows-1252"))
                .expect("Windows-1252 remains a distinct supported encoding"),
            "€"
        );

        let utf16 = "<?xml version=\"1.0\"?><root>λ</root>"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert!(
            decode_resource(&utf16, None)
                .expect("UTF-16 initial pattern is detected")
                .contains("λ")
        );

        assert!(decode_resource(b"<?xml encoding=\"X-UNKNOWN\"?><root/>", None).is_err());
        assert!(decode_resource(&[0, 0, 0, b'<'], None).is_err());
    }
}
