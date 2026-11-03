use super::*;

/// Documents without a DOCTYPE that exercise every construct the limits count:
/// prolog and epilog markup, runs of text, references and CDATA, whitespace
/// inside and outside the document element, empty elements, and namespace
/// declarations that bind, rebind, undeclare and go out of scope.
const DOCUMENTS: &[&str] = &[
    "<r/>",
    concat!(
        "<?xml version=\"1.0\"?>\n<!-- c --><?pi data?>\n",
        "<r>a&amp;b<![CDATA[c]]>&#65;<!--x-->d<e/>  <f>g</f></r>\n",
        "<!--after--> <?end?>\n"
    ),
    concat!(
        r#"<r xmlns="urn:d" xmlns:a="urn:a"><a:c xmlns:a="urn:b" xmlns:b="urn:c">"#,
        r#"<d xmlns=""/><e xmlns:a="urn:a"/></a:c><a:f/></r>"#
    ),
    concat!(
        "<a><b><c><d/><d>t</d></c></b><b xmlns:p='urn:p'>",
        "<c xmlns:q='urn:q'><d xmlns:r='urn:r'/></c></b></a>"
    ),
    "<r>\n  <x/>\n  text <![CDATA[]]> &lt; <y/>\n</r>",
    "<r><!--c--><![CDATA[x]]><?p d?><e/>t&#10;<![CDATA[y]]></r>",
];

fn settings(nodes: u32, depth: usize, bindings: usize) -> DocumentParseSettings {
    DocumentParseSettings {
        backend: XmlBackend::Xmloxide,
        allow_dtd: false,
        nodes_limit: nodes,
        depth_limit: depth,
        namespace_bindings_limit: bindings,
        max_bytes: 1 << 20,
    }
}

/// The node, depth and namespace-binding limits of `settings`.
fn limits(settings: DocumentParseSettings) -> (u32, usize, usize) {
    (
        settings.nodes_limit,
        settings.depth_limit,
        settings.namespace_bindings_limit,
    )
}

/// The refusal the parser itself makes for `xml`, before any projection could
/// refuse it again.
fn parser_refusal(xml: &str, settings: DocumentParseSettings) -> Option<String> {
    let options = crate::parser_xmloxide::parser::ParseOptions::default();
    let (parsed, counter) = crate::parser_xmloxide::parser::parse_str_enforcing_limits(
        xml,
        &options,
        parse_limits(settings),
    )
    .expect("the counter sets up");
    let refusal = counter
        .refusal()
        .map(|refusal| format!("{:?}", limit_refusal(refusal)));
    assert_eq!(
        parsed.is_err(),
        refusal.is_some(),
        "{xml}: {:?}",
        limits(settings)
    );
    refusal
}

/// Parse `xml` with the limits in the parser, returning the peak namespace
/// bindings or the refusal.
fn parsed(xml: &str, settings: DocumentParseSettings) -> Result<usize, String> {
    assert!(settings.backend.records_positions(xml));
    XmlDocument::parse_with_settings(xml.to_owned(), settings)
        .map(|document| document.with_view(|view| view.parsed.peak_namespace_bindings))
        .map_err(|error| format!("{error:?}"))
}

#[test]
fn the_parser_refuses_each_limit_where_the_limit_pass_does() {
    // The limit pass before the parser is gone where the parser enforces the
    // limits as it reads. For every document and every value of each limit,
    // from none past what the document needs, the parse must refuse with the
    // error the limit pass reported, or accept with the same peak bindings.
    let mut refusals = 0;
    for xml in DOCUMENTS {
        let cases = (0..48)
            .map(|nodes| settings(nodes, 64, 64))
            .chain((0..8).map(|depth| settings(u32::MAX, depth, 64)))
            .chain((0..6).map(|bindings| settings(u32::MAX, 64, bindings)));
        for case in cases {
            let expected =
                preflight_document_limits(xml, case, None).map_err(|error| format!("{error:?}"));
            let actual = parsed(xml, case);
            assert_eq!(actual, expected, "{xml}: {:?}", limits(case));
            // The parser refuses before it allocates, not a later stage.
            assert_eq!(
                parser_refusal(xml, case),
                actual.as_ref().err().cloned(),
                "{xml}: {:?}",
                limits(case)
            );
            refusals += usize::from(actual.is_err());
        }
    }
    // Both outcomes must occur for the comparison to mean anything.
    assert!(refusals > 50, "{refusals} refusals");
}

#[test]
fn an_element_past_two_limits_is_refused_for_the_first_the_pass_checked() {
    // An element applies its declarations, then counts as a node, then as a
    // level of nesting; the first limit it passes in that order is reported.
    let xml = "<a><b xmlns:p='urn:p'/></a>";
    for (case, expected) in [
        (
            settings(2, 1, 0),
            XmlDocumentError::Parse(ParseError::NamespaceBindingLimitReached {
                maximum: 0,
                actual: 1,
            }),
        ),
        (
            settings(2, 1, 1),
            XmlDocumentError::Parse(ParseError::NodesLimitReached),
        ),
        (
            settings(3, 1, 1),
            XmlDocumentError::DocumentTooDeep {
                maximum: 1,
                actual: 2,
            },
        ),
    ] {
        assert_eq!(
            parsed(xml, case),
            Err(format!("{expected:?}")),
            "{:?}",
            limits(case)
        );
    }
    // A policy depth equal to the parser's own nesting ceiling is still the
    // policy refusal, not the ceiling's.
    let ceiling = crate::hard_limits::XML_DOCUMENT_DEPTH_CEILING;
    let deep = format!(
        "{}{}",
        "<n>".repeat(ceiling + 1),
        "</n>".repeat(ceiling + 1)
    );
    let expected = XmlDocumentError::DocumentTooDeep {
        maximum: ceiling,
        actual: ceiling + 1,
    };
    assert_eq!(
        parsed(&deep, settings(u32::MAX, ceiling, 64)),
        Err(format!("{expected:?}"))
    );
}

#[test]
fn policy_limits_refuse_at_one_over_through_the_public_entry() {
    // Exact boundaries through the policy entry point: a document needing N
    // of a resource is accepted at N and refused at N - 1.
    let xml = "<r xmlns:a='urn:a'><c><d/></c>text<!--c--></r>";
    let mut policy = crate::policy::VerificationPolicy::default();
    let parse = |policy: &crate::policy::VerificationPolicy| {
        XmlDocument::parse_with_policy_and_backend(xml.to_owned(), policy, XmlBackend::Xmloxide)
            .map(drop)
            .map_err(|error| format!("{error:?}"))
    };
    let refused = |error: XmlDocumentError| Err(format!("{error:?}"));
    // Root, r, c, d, text and comment.
    policy.resources.max_xml_nodes = 6;
    assert_eq!(parse(&policy), Ok(()));
    policy.resources.max_xml_nodes = 5;
    assert_eq!(
        parse(&policy),
        refused(XmlDocumentError::Parse(ParseError::NodesLimitReached))
    );
    policy = crate::policy::VerificationPolicy::default();
    policy.resources.max_xml_depth = 3;
    assert_eq!(parse(&policy), Ok(()));
    policy.resources.max_xml_depth = 2;
    assert_eq!(
        parse(&policy),
        refused(XmlDocumentError::DocumentTooDeep {
            maximum: 2,
            actual: 3,
        })
    );
    policy = crate::policy::VerificationPolicy::default();
    policy.resources.max_xml_namespace_bindings = 1;
    assert_eq!(parse(&policy), Ok(()));
    policy.resources.max_xml_namespace_bindings = 0;
    assert_eq!(
        parse(&policy),
        refused(XmlDocumentError::Parse(
            ParseError::NamespaceBindingLimitReached {
                maximum: 0,
                actual: 1,
            }
        ))
    );
}
