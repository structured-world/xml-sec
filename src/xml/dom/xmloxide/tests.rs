use super::*;
use crate::xml::dom::Node;

fn parse(xml: &str) -> Result<Document<'_>, ParseError> {
    let preflight = LexicalPreflight::scan(xml, true)?;
    XmloxideBackend::parse(
        xml,
        ParsingOptions {
            allow_dtd: true,
            ..ParsingOptions::default()
        },
        &preflight,
    )
}

/// The parser now supplies every range of the tree it builds, so its ranges
/// must be those the lexical scan records for the other backend: the
/// differential parse compares both trees, node by node, with their ranges.
/// Where an entity expands to markup the backends have always reported text
/// ranges differently, so those documents are checked against xmloxide's own
/// contract below instead.
#[cfg(feature = "xml-backend-roxmltree")]
#[test]
fn the_tree_has_the_ranges_the_scan_records() {
    let documents = [
        "<r/>",
        "<r></r>",
        "<r ></r >",
        "<r a='1' b=\"2\"><c/>text<d>more</d>tail</r>",
        "<?xml version='1.0'?>\n<!-- before --><?pi data?>\n<r/>\n<!-- after --><?pi?>\n",
        "<r>a&amp;b&#65;c&#x42;</r>",
        "<r>&lt;</r>",
        "<r>one<![CDATA[two]]>three<![CDATA[]]></r>",
        "<r><!--c--><?p q?>x<!--d-->y</r>",
        "<r>\r\n line\r second\n</r>",
        "<r>  <a/>  <b>  </b>  </r>",
        "<r>\u{20AC}<\u{00E9}/>\u{1F600}</r>",
        "<p:r xmlns:p='u'><p:c p:a='1'/></p:r>",
        "<!DOCTYPE r><r>x</r>",
        "<!DOCTYPE r [<!ENTITY e 'mid'>]><r>a&e;b</r>",
        "<!DOCTYPE r [<!ENTITY e ''>]><r>a&e;b</r>",
        "<!DOCTYPE r [<!ENTITY i '<i/>'><!ENTITY o 'x&i;y'>]><r>&o;<c/></r>",
        "<!DOCTYPE r [<!ATTLIST r id ID #IMPLIED>]><r id=' a '><c/></r>",
    ];
    for xml in documents {
        Document::parse_with_options_and_backend(
            xml,
            ParsingOptions {
                allow_dtd: true,
                ..ParsingOptions::default()
            },
            crate::xml::dom::XmlBackend::Differential,
        )
        .unwrap_or_else(|error| panic!("{xml}: {error:?}"));
    }
}

/// Without a DOCTYPE no scan precedes the parser, so the parser alone must
/// refuse what the scanner refused: a document only the scanner stopped
/// would now be accepted.
#[test]
fn the_parser_refuses_what_the_lexical_scan_refused() {
    let malformed = [
        "",
        "   ",
        "text",
        "text<r/>",
        "<r/>text",
        "<r/><s/>",
        "<r>",
        "</r>",
        "<r></s>",
        "<r/",
        "<r a/>",
        "<r a=1/>",
        "<r a='1'b='2'/>",
        "<r a='1' a='2'/>",
        "<r a='<'/>",
        "<r a='&'/>",
        "<r a='&bad;'/>",
        "<r a='\u{1}'/>",
        "<1r/>",
        "<:r/>",
        "<r:/>",
        "<a:b:c/>",
        "<r xmlns:p='u' p:a='1' p:a='2'/>",
        "<r>&</r>",
        "<r>&bad;</r>",
        "<r>&#0;</r>",
        "<r>&#xD800;</r>",
        "<r>&#x110000;</r>",
        "<r>&#xZ;</r>",
        "<r>]]></r>",
        "<r>\u{1}</r>",
        "<r>\u{FFFE}</r>",
        "<r><![CDATA[</r>",
        "<r><![cdata[x]]></r>",
        "<!--",
        "<!-- a -- b --><r/>",
        "<!-- a ---><r/>",
        "<r><!-- \u{1} --></r>",
        "<?pi",
        "<?xml?><r/>",
        "<?XML version='1.0'?><r/>",
        "<?xml version='1.1'?><r/>",
        "<?xml version='2.0'?><r/>",
        "<?xml version='1.'?><r/>",
        "<?xml encoding='UTF-8'?><r/>",
        "<?xml version='1.0' standalone='maybe'?><r/>",
        "<?xml version='1.0' encoding=''?><r/>",
        "<?xml version='1.0' foo='bar'?><r/>",
        " <?xml version='1.0'?><r/>",
        "<r/><?xml version='1.0'?>",
        "<r><?xml version='1.0'?></r>",
        "<\u{1680}/>",
        "<r\u{1}/>",
        "<!ELEMENT r ANY><r/>",
        "<!doctype r><r/>",
    ];
    let unscanned = LexicalPreflight::unscanned(Native);
    let mut gaps = alloc::vec::Vec::new();
    for xml in malformed {
        if LexicalPreflight::scan(xml, false).is_err()
            && XmloxideBackend::parse(xml, ParsingOptions::default(), &unscanned).is_ok()
        {
            gaps.push(xml);
        }
    }
    assert!(gaps.is_empty(), "only the scanner refused: {gaps:?}");
}

/// A document without the literal `<!DOCTYPE` skips the scan that enforces
/// `allow_dtd`, so the parser must not read a DOCTYPE in any other case: the
/// keyword is case-sensitive (XML 1.0 production 28, "no case folding" in
/// 1.2), and anything else is not well-formed.
#[test]
fn a_doctype_keyword_in_another_case_is_refused_without_a_scan() {
    for xml in [
        "<!doctype r><r/>",
        "<!DocType r><r/>",
        "<!doctype r [<!ENTITY e 'x'>]><r>&e;</r>",
        "<!DOCTYPe r [<!ENTITY e 'x'>]><r>&e;</r>",
    ] {
        assert!(
            Document::parse_with_options(xml, ParsingOptions::default()).is_err(),
            "{xml}"
        );
        assert!(
            XmloxideBackend::parse(
                xml,
                ParsingOptions {
                    allow_dtd: true,
                    ..ParsingOptions::default()
                },
                &LexicalPreflight::unscanned(Native),
            )
            .is_err(),
            "{xml}"
        );
    }
}

/// The arena is reserved for the nodes a document has, not for its bytes: a
/// document of one large text node fits a budget that holds the text, where
/// an arena of one node per 30 source bytes would not.
#[cfg(feature = "xmldsig")]
#[test]
fn a_text_heavy_document_reserves_the_arena_for_its_nodes() {
    use super::super::storage::Accounted;
    use structured_asn1::memory::{Memory, MemoryAccount};
    const TEXT: usize = 1 << 20;
    let xml = alloc::format!("<r>{}</r>", "x".repeat(TEXT));
    let limits = ParseLimits {
        nodes: u32::MAX,
        depth: 64,
        namespace_bindings: 64,
    };
    // Twice the text covers its copy while it grows; the arena of the
    // previous estimate alone (about 35 thousand nodes) is larger than that.
    let memory = Memory::new(alloc::sync::Arc::new(MemoryAccount::new(2 * TEXT, 1 << 28)));
    let (document, _) = XmloxideBackend::parse_enforcing_limits_in(
        &xml,
        ParsingOptions::default(),
        limits,
        Accounted(&memory),
    )
    .unwrap_or_else(|_| panic!("a {TEXT}-byte text document fits {} bytes", 2 * TEXT));
    assert_eq!(document.root_element().text().map(str::len), Some(TEXT));
}

#[test]
fn replacement_text_nodes_take_the_reference_range() {
    // Nodes read from an entity's replacement text have no span of their own
    // in the document: they take the reference's, which no edit may split.
    let xml = "<!DOCTYPE r [<!ENTITY e \"<a id='x'>t</a>\">]><r>p&e;q</r>";
    let document = parse(xml).expect("a well-formed document");
    let reference = xml.find("&e;").expect("the reference");
    let root = document.root_element();
    let children = root.children().collect::<alloc::vec::Vec<_>>();
    assert_eq!(children.len(), 3);
    assert_eq!(children[0].text(), Some("p"));
    assert!(children[0].has_actionable_range());
    assert_eq!(children[1].tag_name().name(), "a");
    assert_eq!(children[1].range(), reference..reference + 3);
    assert!(!children[1].has_actionable_range());
    assert_eq!(children[1].text(), Some("t"));
    assert_eq!(children[2].text(), Some("q"));
    assert!(children[2].has_actionable_range());
}

#[test]
fn text_around_a_reference_is_one_node_over_every_token() {
    // Adjacent text, a reference's text and the text after it fold into one
    // node whose range spans all three, and that no edit may split.
    let xml = "<!DOCTYPE r [<!ENTITY e 'mid'>]><r>a&e;b</r>";
    let document = parse(xml).expect("a well-formed document");
    let start = xml.find("a&e;b").expect("the content");
    let root = document.root_element();
    let children = root.children().collect::<alloc::vec::Vec<_>>();
    assert_eq!(children.len(), 1);
    assert_eq!(children[0].text(), Some("amidb"));
    assert_eq!(children[0].range(), start..start + 5);
    assert!(!children[0].has_actionable_range());
}

#[test]
fn a_nested_reference_takes_the_range_of_the_outermost() {
    let xml = "<!DOCTYPE r [<!ENTITY i '<i/>'><!ENTITY o 'x&i;y'>]><r>&o;<c/></r>";
    let document = parse(xml).expect("a well-formed document");
    let outer = xml.find("&o;").expect("the reference");
    let root = document.root_element();
    let names = root
        .descendants()
        .filter(Node::is_element)
        .map(|node| (node.tag_name().name(), node.range()))
        .collect::<alloc::vec::Vec<_>>();
    let c = xml.find("<c/>").expect("the sibling");
    assert_eq!(
        names,
        [
            ("r", root.range()),
            ("i", outer..outer + 3),
            ("c", c..c + 4),
        ]
    );
}

/// The element names in the subtree of `node`, itself first.
fn element_names<'a>(node: Node<'a, '_>) -> alloc::vec::Vec<&'a str> {
    node.descendants()
        .filter(Node::is_element)
        .map(|node| node.tag_name().name())
        .collect()
}

#[test]
fn an_element_read_from_a_replacement_text_closes_its_subtree() {
    // Each element's subtree ends where its content does, inside an
    // expansion as outside one, so its descendants are exactly its content.
    let xml = "<!DOCTYPE r [<!ENTITY e '<a><b/></a>'>]><r>&e;<c/></r>";
    let document = parse(xml).expect("a well-formed document");
    let root = document.root_element();
    assert_eq!(element_names(root), ["r", "a", "b", "c"]);
    let a = root.first_element_child().expect("the expanded element");
    assert_eq!(element_names(a), ["a", "b"]);
}

#[test]
fn an_empty_replacement_leaves_an_empty_text() {
    // As before the parser built the tree, an empty replacement keeps an
    // empty text in place of the reference.
    let xml = "<!DOCTYPE r [<!ENTITY e ''>]><r><a/>&e;<b/></r>";
    let document = parse(xml).expect("a well-formed document");
    let root = document.root_element();
    let texts = root
        .children()
        .filter(Node::is_text)
        .map(Node::text)
        .collect::<alloc::vec::Vec<_>>();
    assert_eq!(texts, [Some("")]);
}
