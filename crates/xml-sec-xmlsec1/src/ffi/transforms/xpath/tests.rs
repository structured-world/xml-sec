//! The `XPath` family over a parsed document, where the result differs from
//! libxmlsec1 by following the specifications.

use super::{execute, xpath2};
use crate::ffi::nodeset::{xmlSecNodeSetContains, xmlSecNodeSetDestroy, xmlSecNodeSetGetChildren};
use crate::ffi::parser::xmlSecParseMemory;
use crate::ffi::transforms::ctx::{xmlSecTransformCtxCreate, xmlSecTransformCtxDestroy};
use crate::ffi::transforms::{xmlSecTransformCreate, xmlSecTransformDestroy};
use crate::ffi::tree::xmlFreeDoc;
use crate::ffi::xmltree::xmlSecFindNode;

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
        let root = (*doc).children;
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
        assert_ne!(xmlSecNodeSetContains(output, (*a).children, a), 0);
        assert_eq!(xmlSecNodeSetContains(output, b, root), 0);
        xmlSecTransformDestroy(transform);
        xmlSecNodeSetDestroy(input);
        xmlSecTransformCtxDestroy(ctx);
        xmlFreeDoc(doc);
    }
}
