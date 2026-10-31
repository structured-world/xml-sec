use super::*;
use crate::parser_xmloxide::parser::{ParseOptions, parse_str_recording_positions};

fn options() -> ParseOptions {
    crate::xml::dom::xmloxide::backend_options()
}

/// The parser's sidecar stands in for the scanner's, so both must describe a
/// document with the same nodes at the same offsets.
#[test]
fn recorded_positions_match_the_lexical_scan() {
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
    ];
    for xml in documents {
        let scanned = LexicalPreflight::scan(xml, false).expect("the scanner accepts it");
        let (_, recorded) =
            parse_str_recording_positions(xml, &options()).expect("the parser accepts it");
        let describe = |nodes: &[SourceNode]| {
            nodes
                .iter()
                .map(|node| (node.kind, node.range.clone()))
                .collect::<alloc::vec::Vec<_>>()
        };
        assert_eq!(describe(&recorded), describe(&scanned.nodes), "{xml}");
    }
}

/// Without a DOCTYPE the scanner no longer runs, so the parser alone must refuse
/// what it refused: a document only the scanner stopped would now be accepted.
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
    let mut gaps = alloc::vec::Vec::new();
    for xml in malformed {
        if LexicalPreflight::scan(xml, false).is_err()
            && parse_str_recording_positions(xml, &options()).is_ok()
        {
            gaps.push(xml);
        }
    }
    assert!(gaps.is_empty(), "only the scanner refused: {gaps:?}");
}
