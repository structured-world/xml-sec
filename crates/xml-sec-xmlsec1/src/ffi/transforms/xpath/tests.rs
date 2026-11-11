//! The `XPath` family over a parsed document, where the result differs from
//! libxmlsec1 by following the specifications.

use super::{execute, xpath2};
use crate::ffi::nodeset::{xmlSecNodeSetContains, xmlSecNodeSetDestroy, xmlSecNodeSetGetChildren};
use crate::ffi::parser::xmlSecParseMemory;
use crate::ffi::transforms::ctx::{xmlSecTransformCtxCreate, xmlSecTransformCtxDestroy};
use crate::ffi::transforms::{xmlSecTransformCreate, xmlSecTransformDestroy};
use crate::ffi::tree::nodes;
use crate::ffi::xmltree::xmlSecFindNode;
use xml_sec_libxml2::document::free as xmlFreeDoc;

/// A Filter 2.0 union cannot add nodes outside the input: the output is the
/// input intersected with the filter (`XPath` Filter 2.0 section 3.4), where
/// libxmlsec1 unions into the input itself.
#[test]
fn filter2_union_stays_within_the_input() {
    let xml = b"<r xmlns:f='http://www.w3.org/2002/06/xmldsig-filter2'><a>x</a><b>y</b>\
                <t><f:XPath Filter='union'>//b</f:XPath></t></r>";
    // SAFETY: the document, node sets, transform and context are used while
    // live; the input set owns the result ring and is destroyed last.
    unsafe {
        let doc = xmlSecParseMemory(xml.as_ptr(), xml.len(), 0);
        assert!(!doc.is_null());
        let root = nodes::first_child(doc);
        let find =
            |name: &std::ffi::CStr| xmlSecFindNode(root, name.as_ptr().cast(), std::ptr::null());
        let (a, b, t) = (find(c"a"), find(c"b"), find(c"t"));
        assert!(!a.is_null() && !b.is_null() && !t.is_null());
        let ctx = xmlSecTransformCtxCreate();
        let transform = xmlSecTransformCreate(xpath2());
        let read = (*xpath2()).read_node.expect("Filter 2.0 reads its element");
        assert_eq!(read(transform, t, ctx), 0);
        let input = xmlSecNodeSetGetChildren(doc, a, 1, 0);
        (*transform).here_node = t;
        (*transform).in_nodes = input;
        assert_eq!(execute(transform, 1, ctx), 0);
        let output = (*transform).out_nodes;
        assert_ne!(xmlSecNodeSetContains(output, nodes::first_child(a), a), 0);
        assert_eq!(xmlSecNodeSetContains(output, b, root), 0);
        xmlSecTransformDestroy(transform);
        xmlSecNodeSetDestroy(input);
        xmlSecTransformCtxDestroy(ctx);
        xmlFreeDoc(doc);
    }
}

/// `here()` is the element bearing the expression (`XMLDSig` 1.1 section
/// 6.6.3: the parent of the text node holding it), the `ds:XPath` child, not
/// the enclosing transform element, as libxmlsec1 also binds it.
#[test]
fn here_is_the_element_holding_the_expression() {
    let xml = b"<r xmlns:ds='http://www.w3.org/2000/09/xmldsig#'><a>x</a>\
                <ds:Transform><ds:XPath>local-name(here()) = 'XPath'</ds:XPath></ds:Transform></r>";
    // SAFETY: as above.
    unsafe {
        let doc = xmlSecParseMemory(xml.as_ptr(), xml.len(), 0);
        assert!(!doc.is_null());
        let root = nodes::first_child(doc);
        let a = xmlSecFindNode(root, c"a".as_ptr().cast(), std::ptr::null());
        let t = xmlSecFindNode(
            root,
            c"Transform".as_ptr().cast(),
            c"http://www.w3.org/2000/09/xmldsig#".as_ptr().cast(),
        );
        assert!(!a.is_null() && !t.is_null());
        let ctx = xmlSecTransformCtxCreate();
        let transform = xmlSecTransformCreate(super::xpath());
        let read = (*super::xpath())
            .read_node
            .expect("XPath reads its element");
        assert_eq!(read(transform, t, ctx), 0);
        let input = xmlSecNodeSetGetChildren(doc, a, 1, 0);
        (*transform).here_node = t;
        (*transform).in_nodes = input;
        assert_eq!(execute(transform, 1, ctx), 0);
        let output = (*transform).out_nodes;
        assert_ne!(xmlSecNodeSetContains(output, a, root), 0);
        xmlSecTransformDestroy(transform);
        xmlSecNodeSetDestroy(input);
        xmlSecTransformCtxDestroy(ctx);
        xmlFreeDoc(doc);
    }
}
