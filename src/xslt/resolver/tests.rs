use super::{decode_resource, resolve_uri_reference};

#[test]
fn default_denials_preserve_the_policy_error_category() {
    // Missing capabilities are not missing resources: neither fallback nor transport retry
    // may reinterpret the default denial, irrespective of request or retained provenance.
    use super::{
        AccessDenialReason, NoResolver, ResolvePurpose, ResolveRequest, Resolver, ResourceAccess,
        ResourceIdentity,
    };
    let request = ResolveRequest::new("resource.xml", None, ResolvePurpose::Document);
    let identity = ResourceIdentity("immutable-resource".into());
    for access in [
        ResourceAccess::Request(request),
        ResourceAccess::Retained {
            request,
            identity: &identity,
        },
        ResourceAccess::Dependency(&identity),
    ] {
        let error = NoResolver
            .authorize(access)
            .expect_err("default resolver denies every capability");
        assert_eq!(error.kind(), crate::ErrorKind::Policy);
        assert!(matches!(
            error,
            crate::Error::ResourceAccessDenied {
                reason: AccessDenialReason::NotGranted,
                ..
            }
        ));
        assert!(matches!(
            access.denied(AccessDenialReason::Expired),
            crate::Error::ResourceAccessDenied {
                reason: AccessDenialReason::Expired,
                ..
            }
        ));
    }
    assert_eq!(
        NoResolver
            .resolve(request)
            .expect_err("direct acquisition is also denied")
            .kind(),
        crate::ErrorKind::Policy
    );
}

#[test]
fn path_like_resolution_preserves_root_absolute_references() {
    // URL joining and filesystem-like fallback both preserve an absolute target.
    assert_eq!(
        resolve_uri_reference(Some("tmp/styles/main.xsl"), "/shared/base.xsl"),
        "/shared/base.xsl"
    );
}

#[test]
fn path_like_resolution_preserves_document_for_same_document_references() {
    // Fragment- and query-only references address the current document. Directory fallback
    // must not replace its filename when the base is not parseable as an absolute URL.
    assert_eq!(
        resolve_uri_reference(Some("styles/main.xsl"), "#part"),
        "styles/main.xsl#part"
    );
    assert_eq!(
        resolve_uri_reference(Some("main.xsl#old"), "?mode=compact"),
        "main.xsl?mode=compact"
    );
    assert_eq!(
        resolve_uri_reference(Some("main.xsl?old=yes#part"), "#new"),
        "main.xsl?old=yes#new"
    );
}

#[test]
fn path_like_resolution_ignores_query_and_fragment_slashes() {
    assert_eq!(
        resolve_uri_reference(Some("styles/main.xsl?mirror=/old/file#part"), "sub/"),
        "styles/sub/"
    );
}

#[test]
fn rootless_absolute_base_preserves_its_scheme_and_path() {
    // XML Base section 4 delegates this merge to RFC 3986 section 5.2.2: a relative
    // reference inherits the scheme and merges with the rootless base path.
    assert_eq!(
        resolve_uri_reference(Some("memory:styles/main.xsl"), "../modules/shared.xsl"),
        "memory:modules/shared.xsl"
    );
    assert_eq!(
        resolve_uri_reference(Some("memory:main.xsl?old=yes#part"), "modules/"),
        "memory:modules/"
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
        decode_resource(latin1, None, true, usize::MAX).expect("Latin-1 declaration is supported"),
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
        Err(xml_sec_xml_input::Error::MissingEncodingDeclaration(
            "UTF-32"
        ))
    ));
    assert!(decode_resource(&[0, 0, b'<', 0], None, true, usize::MAX).is_err());
}

#[test]
fn decoded_resource_limit_is_enforced_during_materialization() {
    // The resolver boundary must reject expansion before retaining an
    // oversized decoded String; a separate sizing decode would double work.
    let latin1 = b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><root>caf\xe9</root>";
    let expected =
        decode_resource(latin1, None, true, usize::MAX).expect("the Latin-1 fixture must decode");
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
