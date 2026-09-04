use crate::Result;

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
    /// Resolve one URI reference and return stable provenance with its bytes.
    ///
    /// Path-like fallback resolution preserves lexical `..` segments. A resolver
    /// that maps the result onto a filesystem must canonicalize it and enforce its
    /// configured root boundary before reading any bytes.
    fn resolve(
        &self,
        uri: &str,
        base_uri: Option<&str>,
        purpose: ResolvePurpose,
    ) -> Result<ResolvedResource>;
}

pub(crate) fn resolve_uri_reference(base: Option<&str>, reference: &str) -> Result<String> {
    if let Ok(absolute) = url::Url::parse(reference) {
        return Ok(absolute.to_string());
    }
    if let Some(base) = base {
        if let Ok(joined) = url::Url::parse(base).and_then(|base| base.join(reference)) {
            return Ok(joined.to_string());
        }
        if reference.is_empty() {
            return Ok(base
                .split_once('#')
                .map_or(base, |(document, _)| document)
                .to_owned());
        }
        if reference.starts_with('#') {
            let document = base.split_once('#').map_or(base, |(document, _)| document);
            return Ok(format!("{document}{reference}"));
        }
        if reference.starts_with('?') {
            let document = base.split(['?', '#']).next().unwrap_or(base);
            return Ok(format!("{document}{reference}"));
        }
        if reference.starts_with('/') {
            return Ok(reference.to_owned());
        }
        let base_path = base.split(['?', '#']).next().unwrap_or(base);
        if let Some((directory, _)) = base_path.rsplit_once('/') {
            return Ok(format!("{directory}/{reference}"));
        }
    }
    Ok(reference.to_owned())
}

pub(crate) fn decode_resource(
    bytes: &[u8],
    explicit: Option<&str>,
    parsed_xml: bool,
    maximum_decoded_bytes: usize,
) -> std::result::Result<String, xml_sec_xml_input::Error> {
    let decoded = if parsed_xml {
        xml_sec_xml_input::decode_xml_bounded(bytes, explicit, maximum_decoded_bytes)
    } else {
        xml_sec_xml_input::decode_text_bounded(
            bytes,
            explicit.unwrap_or("UTF-8"),
            maximum_decoded_bytes,
        )
    };
    decoded.map(|value| value.into_owned())
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
    use super::{decode_resource, resolve_uri_reference};

    #[test]
    fn path_like_resolution_preserves_root_absolute_references() {
        // URL joining and filesystem-like fallback both preserve an absolute target.
        assert_eq!(
            resolve_uri_reference(Some("tmp/styles/main.xsl"), "/shared/base.xsl")
                .expect("path resolution succeeds"),
            "/shared/base.xsl"
        );
    }

    #[test]
    fn path_like_resolution_preserves_document_for_same_document_references() {
        // Fragment- and query-only references address the current document. Directory fallback
        // must not replace its filename when the base is not parseable as an absolute URL.
        assert_eq!(
            resolve_uri_reference(Some("styles/main.xsl"), "#part")
                .expect("fragment resolution succeeds"),
            "styles/main.xsl#part"
        );
        assert_eq!(
            resolve_uri_reference(Some("main.xsl#old"), "?mode=compact")
                .expect("query resolution succeeds"),
            "main.xsl?mode=compact"
        );
        assert_eq!(
            resolve_uri_reference(Some("main.xsl?old=yes#part"), "#new")
                .expect("fragment replacement succeeds"),
            "main.xsl?old=yes#new"
        );
    }

    #[test]
    fn path_like_resolution_ignores_query_and_fragment_slashes() {
        assert_eq!(
            resolve_uri_reference(Some("styles/main.xsl?mirror=/old/file#part"), "sub/")
                .expect("path resolution succeeds"),
            "styles/sub/"
        );
    }

    #[test]
    fn explicit_encoding_cannot_be_overridden_by_a_conflicting_bom() {
        // Resolver metadata is authoritative. Both metering and materialization
        // must reject UTF-16 bytes when the caller selected UTF-8.
        let utf16 = [0xFF, 0xFE, b'A', 0x00];
        assert!(decode_resource(&utf16, Some("UTF-8"), true, usize::MAX).is_err());
    }

    #[test]
    fn xml_encoding_detection_covers_declarations_initial_patterns_and_errors() {
        // External XML must follow the XML encoding autodetection contract when resolver metadata
        // is absent, while unsupported labels and encodings fail instead of decoding lossy text.
        let latin1 = b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><root>caf\xe9</root>";
        assert_eq!(
            decode_resource(latin1, None, true, usize::MAX)
                .expect("Latin-1 declaration is supported"),
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root>café</root>"
        );
        assert_eq!(
            decode_resource(&[0x80], Some("ISO-8859-1"), false, usize::MAX)
                .expect("Latin-1 metadata preserves the C1 range"),
            "\u{80}"
        );
        assert_eq!(
            decode_resource(&[0x80], Some("windows-1252"), false, usize::MAX)
                .expect("Windows-1252 remains a distinct supported encoding"),
            "€"
        );

        let utf16 = "<?xml version=\"1.0\" encoding=\"UTF-16LE\"?><root>λ</root>"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert!(
            decode_resource(&utf16, None, true, usize::MAX)
                .expect("UTF-16 initial pattern is detected")
                .contains("λ")
        );

        assert!(
            decode_resource(
                b"<?xml encoding=\"X-UNKNOWN\"?><root/>",
                None,
                true,
                usize::MAX,
            )
            .is_err()
        );
        assert!(matches!(
            decode_resource(&[0, 0, 0, b'<'], None, true, usize::MAX),
            Err(xml_sec_xml_input::Error::MissingUtf32ByteOrder)
        ));
        assert!(decode_resource(&[0, 0, b'<', 0], None, true, usize::MAX).is_err());
    }

    #[test]
    fn decoded_resource_limit_is_enforced_during_materialization() {
        // The resolver boundary must reject expansion before retaining an
        // oversized decoded String; a separate sizing decode would double work.
        let latin1 = b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><root>caf\xe9</root>";
        let expected = decode_resource(latin1, None, true, usize::MAX)
            .expect("the Latin-1 fixture must decode");
        assert!(decode_resource(latin1, None, true, expected.len() - 1).is_err());
        let materialized = expected
            .len()
            .saturating_add("ISO-8859-1".len() - "UTF-8".len());
        assert_eq!(
            decode_resource(latin1, None, true, materialized)
                .expect("the exact materialization budget must be accepted"),
            expected
        );
    }
}
