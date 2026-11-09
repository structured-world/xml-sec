//! The transform object model without a document: registry contents and
//! order, klass lookups, object sizes, binary chains through the default
//! push and pop methods, and refusals. Chains over trees are compared with
//! libxmlsec1 by the differential C programs.

use super::builtin::{base64, mem_buf};
use super::ctx::{
    xmlSecTransformCtxBinaryExecute, xmlSecTransformCtxCreate, xmlSecTransformCtxCreateAndAppend,
    xmlSecTransformCtxDestroy,
};
use super::{
    OPERATION_ENCODE, USAGE_DSIG_TRANSFORM, XmlSecTransformKlass, xmlSecTransformIdListFindByHref,
    xmlSecTransformIdListFindByName, xmlSecTransformIdsGet, xmlSecTransformIdsInit,
    xmlSecTransformIdsShutdown,
};
use crate::ffi::buffer::{xmlSecBufferGetData, xmlSecBufferGetSize};
use crate::ffi::list::{xmlSecPtrListGetItem, xmlSecPtrListGetSize};
use std::ffi::CStr;

fn name(klass: *const XmlSecTransformKlass) -> String {
    // SAFETY: built-in klass names are static NUL-terminated strings.
    unsafe { CStr::from_ptr((*klass).name.cast()) }
        .to_string_lossy()
        .into_owned()
}

/// The registry holds libxmlsec1's defaults in its order, and lookups by
/// href and name respect the usage mask.
#[test]
fn registry_holds_the_defaults_in_order() {
    // SAFETY: the registry is used by this test alone (one process per test).
    unsafe {
        assert_eq!(xmlSecTransformIdsInit(), 0);
        let ids = xmlSecTransformIdsGet();
        let names: Vec<String> = (0..xmlSecPtrListGetSize(ids))
            .map(|pos| name(xmlSecPtrListGetItem(ids, pos).cast()))
            .collect();
        assert_eq!(
            names,
            [
                "base64",
                "enveloped-signature",
                "c14n",
                "c14n-with-comments",
                "c14n11",
                "c14n11-with-comments",
                "exc-c14n",
                "exc-c14n-with-comments",
                "xpath",
                "xpath2",
                "xpointer",
                "relationship",
            ]
        );
        let href = c"http://www.w3.org/2000/09/xmldsig#base64".as_ptr().cast();
        assert_eq!(
            xmlSecTransformIdListFindByHref(ids, href, USAGE_DSIG_TRANSFORM),
            base64()
        );
        assert!(xmlSecTransformIdListFindByHref(ids, href, 0x0004).is_null());
        assert_eq!(
            xmlSecTransformIdListFindByName(ids, c"base64".as_ptr().cast(), USAGE_DSIG_TRANSFORM),
            base64()
        );
        xmlSecTransformIdsShutdown();
        assert_eq!(xmlSecPtrListGetSize(ids), 0);
    }
}

/// A binary chain through Base64 encoding runs through the default push
/// methods into the memory-buffer terminal that becomes the result.
#[test]
fn binary_chain_encodes_base64() {
    // SAFETY: the context and its transforms are used while live.
    unsafe {
        let ctx = xmlSecTransformCtxCreate();
        assert!(!ctx.is_null());
        let encoder = xmlSecTransformCtxCreateAndAppend(ctx, base64());
        assert!(!encoder.is_null());
        (*encoder).operation = OPERATION_ENCODE;
        assert_eq!(
            xmlSecTransformCtxBinaryExecute(ctx, b"foobar".as_ptr(), 6),
            0
        );
        let result = (*ctx).result;
        let text =
            std::slice::from_raw_parts(xmlSecBufferGetData(result), xmlSecBufferGetSize(result));
        assert_eq!(text, b"Zm9vYmFy");
        assert!(std::ptr::eq((*(*ctx).last).id, mem_buf()));
        xmlSecTransformCtxDestroy(ctx);
    }
}
