use super::*;

/// Documents whose limits the lexical pass that records source positions
/// checks: with a DOCTYPE, entities and attribute defaults count where they
/// expand, in content and in attribute values. The last has no DOCTYPE, for
/// a backend that reads positions from the pass whatever the document.
const DOCUMENTS: &[&str] = &[
    concat!(
        r#"<!DOCTYPE r [<!ENTITY e "<a/>t<b xmlns:p='urn:p'><c/></b>">]>"#,
        "<r>&e;x&e;<d>&e;</d></r>"
    ),
    concat!(
        r#"<!DOCTYPE r [<!ATTLIST c xmlns:d CDATA 'urn:d'><!ENTITY none "">]>"#,
        r#"<r xmlns="urn:r"><c><c xmlns="&none;"/></c></r>"#
    ),
    concat!(
        r#"<!DOCTYPE r [<!ENTITY v "v&w;"><!ENTITY w "w">]>"#,
        r#"<!--c--><?p d?><r a="&v;" b='&amp;'>&v;<![CDATA[x]]>&w;</r>"#
    ),
    concat!(
        "<?xml version=\"1.0\"?>\n<!-- c -->\n",
        r#"<r xmlns:a="urn:a">a&amp;b<e/><f xmlns="">g</f></r>"#,
        "\n<!--z-->"
    ),
];

fn settings(
    backend: XmlBackend,
    nodes: u32,
    depth: usize,
    bindings: usize,
) -> DocumentParseSettings {
    DocumentParseSettings {
        backend,
        allow_dtd: true,
        nodes_limit: nodes,
        depth_limit: depth,
        namespace_bindings_limit: bindings,
        max_bytes: 1 << 20,
    }
}

/// The backend and the node, depth and namespace-binding limits of `settings`.
fn limits(settings: DocumentParseSettings) -> (XmlBackend, u32, usize, usize) {
    (
        settings.backend,
        settings.nodes_limit,
        settings.depth_limit,
        settings.namespace_bindings_limit,
    )
}

/// The limit refusal the scan itself makes for `xml`, before the backend
/// receives the document.
fn scan_refusal(xml: &str, settings: DocumentParseSettings) -> Option<String> {
    let mut pass = LimitPass::new(settings, None, NativeXmlStorage).expect("the pass sets up");
    let parsed = Document::parse_observed_with_backend(
        xml,
        parsing_options(settings),
        settings.backend,
        &mut pass,
    );
    let refusal = pass
        .run
        .counter
        .refusal()
        .map(|refusal| format!("{:?}", limit_refusal(refusal)));
    assert!(refusal.is_none() || parsed.is_err(), "{xml}");
    refusal
}

#[test]
fn the_scan_refuses_each_limit_where_the_limit_pass_does() {
    // The pass that records source positions checks the limits in place of
    // a separate pass before it. For every document, backend that reads the
    // positions, and value of each limit from none past what the document
    // needs, the parse must refuse with the error the separate pass reports,
    // from the scan, or accept with the same peak bindings.
    // Differential mode also compares the backends' source ranges, which
    // differ for markup an entity expands; the limits are each backend's.
    for backend in XmlBackend::available().filter(|backend| *backend != XmlBackend::Differential) {
        let (mut refusals, mut acceptances) = (0, 0);
        for &xml in DOCUMENTS {
            #[cfg(feature = "xml-backend-xmloxide")]
            if backend.records_positions(xml) {
                continue;
            }
            let cases = (0..40)
                .map(|nodes| settings(backend, nodes, 64, 64))
                .chain((0..6).map(|depth| settings(backend, u32::MAX, depth, 64)))
                .chain((0..5).map(|bindings| settings(backend, u32::MAX, 64, bindings)));
            for case in cases {
                let expected = preflight_document_limits(xml, case, None)
                    .map_err(|error| format!("{error:?}"));
                let actual = XmlDocument::parse_with_settings(xml.to_owned(), case)
                    .map(|document| document.with_view(|view| view.parsed.peak_namespace_bindings))
                    .map_err(|error| format!("{error:?}"));
                assert_eq!(actual, expected, "{xml}: {:?}", limits(case));
                assert_eq!(
                    scan_refusal(xml, case),
                    actual.as_ref().err().cloned(),
                    "{xml}: {:?}",
                    limits(case)
                );
                refusals += usize::from(actual.is_err());
                acceptances += usize::from(actual.is_ok());
            }
        }
        // Both outcomes must occur for the comparison to mean anything.
        assert!(
            refusals >= 20 && acceptances >= 20,
            "{backend:?}: {refusals} refusals, {acceptances} acceptances"
        );
    }
}

#[test]
fn a_document_declaring_a_dtd_records_it_from_the_one_parse() {
    // Whether the source requires its DTD comes from the parse itself; a
    // comment that only mentions a DOCTYPE declares none.
    for (xml, declares) in [
        ("<!DOCTYPE r><r/>", true),
        (r#"<!DOCTYPE r [<!ENTITY e "x">]><r>&e;</r>"#, true),
        ("<!-- <!DOCTYPE r> --><r/>", false),
        ("<r/>", false),
    ] {
        for backend in XmlBackend::available() {
            let parse = settings(backend, u32::MAX, 64, 64);
            let (_, doctype) = build_cell_recording(xml.to_owned(), parse, None, 0)
                .unwrap_or_else(|error| panic!("{xml}: {backend:?}: {error:?}"));
            assert_eq!(doctype, declares, "{xml}: {backend:?}");
        }
    }
}
