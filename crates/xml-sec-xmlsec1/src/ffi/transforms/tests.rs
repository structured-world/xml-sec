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

/// Base64 first in a chain receives the text of the input node set, not its
/// canonical XML (`XMLDSig` 1.1 section 6.6.2), as it does after a node-set
/// transform.
#[test]
fn base64_first_decodes_the_text_of_xml_input() {
    let xml = b"<r>Zm9v<s>YmFy</s></r>";
    // SAFETY: the document, node set and context are used while live.
    unsafe {
        let doc = crate::ffi::parser::xmlSecParseMemory(xml.as_ptr(), xml.len(), 0);
        assert!(!doc.is_null());
        let nodes = crate::ffi::nodeset::xmlSecNodeSetGetChildren(doc, std::ptr::null_mut(), 1, 0);
        let ctx = xmlSecTransformCtxCreate();
        assert!(!xmlSecTransformCtxCreateAndAppend(ctx, base64()).is_null());
        assert_eq!(super::ctx::xmlSecTransformCtxXmlExecute(ctx, nodes), 0);
        let result = (*ctx).result;
        let text =
            std::slice::from_raw_parts(xmlSecBufferGetData(result), xmlSecBufferGetSize(result));
        assert_eq!(text, b"foobar");
        xmlSecTransformCtxDestroy(ctx);
        crate::ffi::nodeset::xmlSecNodeSetDestroy(nodes);
        crate::ffi::tree::xmlFreeDoc(doc);
    }
}

/// A chunk size of 0, written by a caller into the public context field,
/// fails the push instead of appending nothing forever.
#[test]
fn zero_chunk_size_fails_the_default_push() {
    // SAFETY: the context and its transform are used while live.
    unsafe {
        let ctx = xmlSecTransformCtxCreate();
        let transform = xmlSecTransformCtxCreateAndAppend(ctx, base64());
        (*ctx).binary_chunk_size = 0;
        let pushed = super::xmlSecTransformDefaultPushBin(transform, b"Zm9v".as_ptr(), 4, 1, ctx);
        assert_eq!(pushed, -1);
        xmlSecTransformCtxDestroy(ctx);
    }
}

/// A chain longer than the policy's transforms-per-reference limit is
/// refused before it runs, as the core refuses such a reference; one at the
/// limit runs.
#[test]
fn a_chain_beyond_the_policy_limit_is_refused() {
    let limit = crate::ffi::policy::verification()
        .expect("the library policy compiles")
        .resources
        .max_transforms_per_reference;
    // Decoders over empty input: every stage passes on nothing, so the run
    // costs the chain alone.
    let run = |transforms: usize| {
        // SAFETY: the context and its transforms are used while live.
        unsafe {
            let ctx = xmlSecTransformCtxCreate();
            for _ in 0..transforms {
                assert!(!xmlSecTransformCtxCreateAndAppend(ctx, base64()).is_null());
            }
            let status = xmlSecTransformCtxBinaryExecute(ctx, b"".as_ptr(), 0);
            xmlSecTransformCtxDestroy(ctx);
            status
        }
    };
    assert_eq!(run(limit), 0);
    assert_eq!(run(limit + 1), -1);
}

/// The library's policy runs the core's OPC relationship transform: the
/// selected relationships, sorted by Id, with the default `TargetMode` and
/// without comments (ISO/IEC 29500-2 section 13.2.4.24, step 3), where
/// libxmlsec1 writes a comment as an empty `comment` element.
#[test]
fn library_policy_runs_the_relationship_transform() {
    use xml_sec::xmldsig::transforms::{
        RelationshipSelector, Transform, execute_transforms_with_policy,
    };
    use xml_sec::xmldsig::types::{NodeSet, TransformData};

    let policy = crate::ffi::policy::verification().expect("the library policy compiles");
    let document = xml_sec::XmlDocument::parse(
        "<Relationships xmlns='http://schemas.openxmlformats.org/package/2006/relationships'>\
         <Relationship Id='rId3' Type='urn:t:c' Target='c.xml'/><!-- note -->\
         <Relationship Id='rId1' Type='urn:t:a' Target='a.xml' TargetMode='External'/>\
         <Relationship Id='rId2' Type='urn:t:b' Target='b.xml'/>\
         </Relationships>",
    )
    .expect("parse");
    let transforms = [
        Transform::Relationship(vec![
            RelationshipSelector::SourceId("rId3".into()),
            RelationshipSelector::SourceId("rId1".into()),
        ]),
        Transform::C14n(xml_sec::c14n::C14nAlgorithm::new(
            xml_sec::c14n::C14nMode::Inclusive1_0,
            false,
        )),
    ];
    let output = document.with_view(|view| {
        let document = view.document();
        execute_transforms_with_policy(
            document.root(),
            TransformData::NodeSet(NodeSet::entire_document_without_comments(document)?),
            &transforms,
            policy,
        )
    });
    let output = String::from_utf8(output.expect("relationship transform")).expect("UTF-8");
    assert_eq!(
        output,
        "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
         <Relationship Id=\"rId1\" Target=\"a.xml\" TargetMode=\"External\" Type=\"urn:t:a\">\
         </Relationship><Relationship Id=\"rId3\" Target=\"c.xml\" TargetMode=\"Internal\" \
         Type=\"urn:t:c\"></Relationship></Relationships>"
    );
}
