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

/// A chain that signs evaluates its expressions under the signing policy's
/// `max_xpath_expressions`: with none admitted for signing, the `XPath`
/// transform before a signing transform is refused before it evaluates,
/// while the same chain verifying, under a verification policy that admits
/// expressions, evaluates it.
#[test]
fn the_expression_count_follows_the_policy_of_the_operation() {
    crate::ffi::tests::own_process();
    crate::ffi::policy::republish(
        |_| {},
        |signing| signing.resources.max_xpath_expressions = 0,
    )
    .expect("the library policy compiles");
    let xml = b"<r xmlns:ds='http://www.w3.org/2000/09/xmldsig#'><a>x</a>\
                <ds:Transform><ds:XPath>true()</ds:XPath></ds:Transform></r>";
    for (operation, expected) in [
        (crate::ffi::transforms::OPERATION_SIGN, -1),
        (crate::ffi::transforms::OPERATION_VERIFY, 0),
    ] {
        // SAFETY: the document, node sets, transforms and context are used
        // while live and released here.
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
            let ctx = xmlSecTransformCtxCreate();
            let transform =
                crate::ffi::transforms::ctx::xmlSecTransformCtxCreateAndAppend(ctx, super::xpath());
            let signature = crate::ffi::transforms::ctx::xmlSecTransformCtxCreateAndAppend(
                ctx,
                crate::ffi::transforms::signatures::rsa_sha256(),
            );
            (*signature).operation = operation;
            let read = (*super::xpath())
                .read_node
                .expect("XPath reads its element");
            assert_eq!(read(transform, t, ctx), 0);
            let input = xmlSecNodeSetGetChildren(doc, a, 1, 0);
            (*transform).here_node = t;
            (*transform).in_nodes = input;
            assert_eq!(
                execute(transform, 1, ctx),
                expected,
                "operation {operation}"
            );
            // The input set owns the result ring: the transform goes first.
            xmlSecTransformCtxDestroy(ctx);
            xmlSecNodeSetDestroy(input);
            xmlFreeDoc(doc);
        }
    }
}

/// The context's `xpathOpsLimit` narrows the evaluation work of its
/// expressions: a limit below the transform's work refuses it, while the
/// initial limit and zero, which lifts it, leave the policy's.
#[test]
fn the_xpath_ops_limit_narrows_the_evaluation_work() {
    let xml = b"<r xmlns:ds='http://www.w3.org/2000/09/xmldsig#'><a>x<b/><c/></a>\
                <ds:Transform><ds:XPath>count(ancestor-or-self::*) &gt; 0</ds:XPath></ds:Transform></r>";
    for (limit, expected) in [(None, 0), (Some(1), -1), (Some(0), 0)] {
        // SAFETY: the document, node sets, transform and context are used
        // while live and released here.
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
            let ctx = xmlSecTransformCtxCreate();
            assert_eq!((*ctx).xpath_ops_limit, 1_000_000);
            if let Some(limit) = limit {
                (*ctx).xpath_ops_limit = limit;
            }
            let transform = xmlSecTransformCreate(super::xpath());
            let read = (*super::xpath())
                .read_node
                .expect("XPath reads its element");
            assert_eq!(read(transform, t, ctx), 0);
            let input = xmlSecNodeSetGetChildren(doc, a, 1, 0);
            (*transform).here_node = t;
            (*transform).in_nodes = input;
            assert_eq!(execute(transform, 1, ctx), expected, "limit {limit:?}");
            xmlSecTransformDestroy(transform);
            xmlSecNodeSetDestroy(input);
            xmlSecTransformCtxDestroy(ctx);
            xmlFreeDoc(doc);
        }
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
