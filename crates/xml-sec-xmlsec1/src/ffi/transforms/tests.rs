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
    OPERATION_DECODE, OPERATION_ENCODE, USAGE_DSIG_TRANSFORM, XmlSecTransformKlass,
    xmlSecTransformIdListFindByHref, xmlSecTransformIdListFindByName, xmlSecTransformIdsGet,
    xmlSecTransformIdsInit, xmlSecTransformIdsShutdown,
};
use crate::ffi::buffer::{xmlSecBufferGetData, xmlSecBufferGetSize};
use crate::ffi::list::{xmlSecPtrListGetItem, xmlSecPtrListGetSize};
use crate::ffi::tree::nodes;
use std::ffi::{CStr, c_int};

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
                "xpointer-legacy",
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

/// A reset drops the parent key info context with the run: it belongs to the
/// caller that set it for one run and must not reach the next one.
#[test]
fn a_reset_forgets_the_parent_key_info_context() {
    // SAFETY: the context is created and destroyed here; the parent pointer
    // is only stored, never dereferenced.
    unsafe {
        let ctx = xmlSecTransformCtxCreate();
        let mut parent = 0_u8;
        (*ctx).parent_key_info_ctx = (&raw mut parent).cast();
        super::ctx::xmlSecTransformCtxReset(ctx);
        assert!((*ctx).parent_key_info_ctx.is_null());
        xmlSecTransformCtxDestroy(ctx);
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
        xml_sec_libxml2::document::free(doc);
    }
}

/// A transform read from its node keeps the operation its klass's
/// initializer chose: the public readers name none, so a Base64 transform
/// read from XML decodes, as libxmlsec1's reader leaves it.
#[test]
fn a_transform_read_from_xml_keeps_its_klass_operation() {
    let xml = br#"<Transform xmlns="http://www.w3.org/2000/09/xmldsig#" Algorithm="http://www.w3.org/2000/09/xmldsig#base64"/>"#;
    // SAFETY: the document and context are used while live.
    unsafe {
        assert_eq!(xmlSecTransformIdsInit(), 0);
        let doc = crate::ffi::parser::xmlSecParseMemory(xml.as_ptr(), xml.len(), 0);
        assert!(!doc.is_null());
        let ctx = xmlSecTransformCtxCreate();
        let transform = super::ctx::xmlSecTransformCtxNodeRead(
            ctx,
            nodes::first_child(doc),
            USAGE_DSIG_TRANSFORM,
        );
        assert!(!transform.is_null());
        assert_eq!((*transform).operation, OPERATION_DECODE);
        assert_eq!(xmlSecTransformCtxBinaryExecute(ctx, b"QQ==".as_ptr(), 4), 0);
        let result = (*ctx).result;
        let text =
            std::slice::from_raw_parts(xmlSecBufferGetData(result), xmlSecBufferGetSize(result));
        assert_eq!(text, b"A");
        xmlSecTransformCtxDestroy(ctx);
        xml_sec_libxml2::document::free(doc);
        xmlSecTransformIdsShutdown();
    }
}

/// Adjacent text and CDATA nodes of a tree are one text node in the
/// canonical form (Canonical XML 1.0 section 2.1): the whole document
/// canonicalizes, and a node set selecting only part of that text is refused
/// rather than canonicalized as all of it or none of it.
#[test]
fn adjacent_text_and_cdata_canonicalize_as_one_text() {
    let xml = b"<r>a<![CDATA[b]]>c</r>";
    // SAFETY: the document, node sets and contexts are used while live.
    unsafe {
        // The core keeps the CDATA section as its own node.
        let doc = crate::ffi::parser::xmlSecParseMemory(xml.as_ptr(), xml.len(), 0);
        assert!(!doc.is_null());
        let run = |nodes| {
            let ctx = xmlSecTransformCtxCreate();
            assert!(!xmlSecTransformCtxCreateAndAppend(ctx, super::builtin::incl_c14n()).is_null());
            let status = super::ctx::xmlSecTransformCtxXmlExecute(ctx, nodes);
            let output = if status == 0 {
                let result = (*ctx).result;
                std::slice::from_raw_parts(xmlSecBufferGetData(result), xmlSecBufferGetSize(result))
                    .to_vec()
            } else {
                Vec::new()
            };
            xmlSecTransformCtxDestroy(ctx);
            (status, output)
        };
        let whole = crate::ffi::nodeset::xmlSecNodeSetGetChildren(doc, std::ptr::null_mut(), 1, 0);
        assert_eq!(run(whole), (0, b"<r>abc</r>".to_vec()));
        crate::ffi::nodeset::xmlSecNodeSetDestroy(whole);
        let root = nodes::first_child(doc);
        let listed = nodes::node_set(root);
        nodes::node_set_add(listed, nodes::first_child(root)).expect("a live node");
        let part =
            crate::ffi::nodeset::xmlSecNodeSetCreate(doc, listed, crate::ffi::nodeset::NORMAL);
        assert_eq!(run(part).0, -1);
        crate::ffi::nodeset::xmlSecNodeSetDestroy(part);
        xml_sec_libxml2::document::free(doc);
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

/// An element of `size` octets: whitespace runs within libxml2's text-node
/// ceiling between empty elements, so only the octet count matters.
fn document_of(size: usize) -> Vec<u8> {
    const UNIT: usize = 1024;
    let mut xml = b"<r>".to_vec();
    while size - 4 - xml.len() >= UNIT {
        xml.resize(xml.len() + UNIT - 4, b' ');
        xml.extend_from_slice(b"<a/>");
    }
    xml.resize(size - 4, b' ');
    xml.extend_from_slice(b"</r>");
    xml
}

/// The parser klass parses at most the policy's document size, counted
/// over every push of one document; the halves of a document one octet
/// over the limit are refused although each fits.
#[test]
fn xml_parser_push_is_bounded_by_the_document_limit() {
    let limit = crate::ffi::policy::verification()
        .expect("the library policy compiles")
        .resources
        .max_xml_document_bytes;
    let run = |xml: &[u8]| {
        // SAFETY: the context and its transform are used while live.
        unsafe {
            let ctx = xmlSecTransformCtxCreate();
            let parser = xmlSecTransformCtxCreateAndAppend(ctx, super::parser::xml_parser());
            let (head, tail) = xml.split_at(xml.len() / 2);
            let first = super::xmlSecTransformPushBin(parser, head.as_ptr(), head.len(), 0, ctx);
            let status = if first < 0 {
                first
            } else {
                super::xmlSecTransformPushBin(parser, tail.as_ptr(), tail.len(), 1, ctx)
            };
            xmlSecTransformCtxDestroy(ctx);
            status
        }
    };
    assert_eq!(run(&document_of(limit)), 0);
    assert_eq!(run(&document_of(limit + 1)), -1);
}

/// The parse work a document costs is its decoding and the decoded text the
/// parser reads, not its encoded length: a UTF-16 document of 2016 octets
/// that decodes to 3007 octets of UTF-8 costs more than a 4000-octet
/// allowance, though its encoded length fits it.
#[test]
fn xml_parser_charges_the_decoded_text_it_parses() {
    crate::ffi::tests::own_process();
    crate::ffi::policy::republish(
        |verification| verification.resources.max_xml_parse_work_bytes = 4000,
        |_| {},
    )
    .expect("the library policy compiles");
    let mut xml = vec![0xff, 0xfe];
    let text: String = core::iter::once("<r>")
        .chain(core::iter::repeat_n("\u{0800}", 1000))
        .chain(core::iter::once("</r>"))
        .collect();
    xml.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
    assert_eq!(xml.len(), 2016);
    // SAFETY: the context and its transform are used while live.
    unsafe {
        let ctx = xmlSecTransformCtxCreate();
        let parser = xmlSecTransformCtxCreateAndAppend(ctx, super::parser::xml_parser());
        let status = super::xmlSecTransformPushBin(parser, xml.as_ptr(), xml.len(), 1, ctx);
        xmlSecTransformCtxDestroy(ctx);
        assert_eq!(status, -1);
    }
}

/// The parser klass popping its input reads at most the policy's document
/// size from the previous transform.
#[test]
fn xml_parser_pop_is_bounded_by_the_document_limit() {
    let limit = crate::ffi::policy::verification()
        .expect("the library policy compiles")
        .resources
        .max_xml_document_bytes;
    let run = |xml: &[u8]| {
        // SAFETY: the context, its transforms and the popped node set are
        // used while live.
        unsafe {
            let ctx = xmlSecTransformCtxCreate();
            let source = xmlSecTransformCtxCreateAndAppend(ctx, mem_buf());
            let parser = xmlSecTransformCtxCreateAndAppend(ctx, super::parser::xml_parser());
            assert_eq!(
                crate::ffi::buffer::xmlSecBufferAppend(
                    &raw mut (*source).in_buf,
                    xml.as_ptr(),
                    xml.len()
                ),
                0
            );
            let mut nodes = std::ptr::null_mut();
            let status = super::xmlSecTransformPopXml(parser, &raw mut nodes, ctx);
            if !nodes.is_null() {
                crate::ffi::nodeset::xmlSecNodeSetDestroy(nodes);
            }
            xmlSecTransformCtxDestroy(ctx);
            status
        }
    };
    assert_eq!(run(&document_of(limit)), 0);
    assert_eq!(run(&document_of(limit + 1)), -1);
}

/// The parser klass parses under the library policy, whose depth limit stays
/// in force while the core builds the tree.
#[test]
fn xml_parser_keeps_the_policy_depth_limit() {
    let mut xml = b"<a>".repeat(1000);
    xml.extend(b"</a>".repeat(1000));
    // SAFETY: the context and its transform are used while live.
    unsafe {
        let ctx = xmlSecTransformCtxCreate();
        let parser = xmlSecTransformCtxCreateAndAppend(ctx, super::parser::xml_parser());
        let status = super::xmlSecTransformPushBin(parser, xml.as_ptr(), xml.len(), 1, ctx);
        assert_eq!(status, -1);
        xmlSecTransformCtxDestroy(ctx);
    }
}

/// Base64 output of one run is bounded by the policy, shared by every
/// Base64 transform of the chain as the core shares it across a reference's
/// transforms: output at the limit passes, one group more is refused, and
/// an encoder and a decoder that each fit are refused together.
#[test]
fn base64_output_is_bounded_per_run() {
    let limit = crate::ffi::policy::verification()
        .expect("the library policy compiles")
        .resources
        .max_base64_transform_output_bytes;
    let run = |operations: &[c_int], input: &[u8]| {
        // SAFETY: the context and its transforms are used while live.
        unsafe {
            let ctx = xmlSecTransformCtxCreate();
            for operation in operations {
                let transform = xmlSecTransformCtxCreateAndAppend(ctx, base64());
                (*transform).operation = *operation;
            }
            let status = xmlSecTransformCtxBinaryExecute(ctx, input.as_ptr(), input.len());
            xmlSecTransformCtxDestroy(ctx);
            status
        }
    };
    let groups = limit / 3;
    assert_eq!(run(&[OPERATION_DECODE], &b"AAAA".repeat(groups)), 0);
    assert_eq!(run(&[OPERATION_DECODE], &b"AAAA".repeat(groups + 1)), -1);
    // 4/3 of the raw input encoded plus the raw input decoded again.
    let raw = vec![0u8; limit / 9 * 4];
    assert_eq!(run(&[OPERATION_ENCODE], &raw), 0);
    assert_eq!(run(&[OPERATION_ENCODE, OPERATION_DECODE], &raw), -1);
}

/// A Base64 limit refusing work spends the operation's budget: the run is
/// marked so the work it is part of (a key read trying recipients in turn)
/// ends rather than trying more under the same allowance.
#[test]
fn a_base64_limit_refusal_ends_the_operation() {
    // A two-octet output limit under a far larger input limit: `AAAA` asks
    // for three octets, so the output limit alone refuses it.
    crate::ffi::tests::own_process();
    let limit = 2;
    crate::ffi::policy::republish(
        |verification| {
            verification.resources.max_base64_transform_output_bytes = limit;
            verification.resources.max_base64_transform_input_bytes = 1024;
        },
        |_| {},
    )
    .expect("the library policy compiles");
    // SAFETY: the context and its transform are used while live.
    unsafe {
        let ctx = xmlSecTransformCtxCreate();
        assert!(!xmlSecTransformCtxCreateAndAppend(ctx, base64()).is_null());
        let input = b"AAAA";
        assert_eq!(
            xmlSecTransformCtxBinaryExecute(ctx, input.as_ptr(), input.len()),
            -1
        );
        assert_eq!(
            super::ctx::run_budget(ctx).refused_by,
            Some(super::ctx::Limit {
                name: "max_base64_transform_output_bytes",
                max: limit,
            }),
            "the refusal ends the operation, naming its limit"
        );
        xmlSecTransformCtxDestroy(ctx);
    }
}

/// Base64 input of one run is bounded by the policy even when it decodes
/// to nothing.
#[test]
fn base64_input_is_bounded_per_run() {
    let limit = crate::ffi::policy::verification()
        .expect("the library policy compiles")
        .resources
        .max_base64_transform_input_bytes;
    let run = |input: &[u8]| {
        // SAFETY: the context and its transform are used while live.
        unsafe {
            let ctx = xmlSecTransformCtxCreate();
            assert!(!xmlSecTransformCtxCreateAndAppend(ctx, base64()).is_null());
            let status = xmlSecTransformCtxBinaryExecute(ctx, input.as_ptr(), input.len());
            xmlSecTransformCtxDestroy(ctx);
            status
        }
    };
    assert_eq!(run(&vec![b'\n'; limit]), 0);
    assert_eq!(run(&vec![b'\n'; limit + 1]), -1);
}

/// A bare-name fragment is an id inside an `id('...')` literal, so a name
/// that would close the literal or change the pointer's scheme data is
/// refused instead of selecting more than one element; numeric ids, which
/// an `XPointer` shorthand cannot name, still select.
#[test]
fn bare_fragment_cannot_break_out_of_the_id_literal() {
    let xml = b"<r/>";
    // SAFETY: the document and contexts are used while live.
    unsafe {
        let doc = crate::ffi::parser::xmlSecParseMemory(xml.as_ptr(), xml.len(), 0);
        assert!(!doc.is_null());
        let set = |uri: &CStr| {
            let ctx = xmlSecTransformCtxCreate();
            let status = super::ctx::xmlSecTransformCtxSetUri(
                ctx,
                uri.as_ptr().cast(),
                nodes::first_child(doc),
            );
            xmlSecTransformCtxDestroy(ctx);
            status
        };
        assert_eq!(set(c"#111"), 0);
        assert_eq!(set(c"#x')|//Secret|id('"), -1);
        assert_eq!(set(c"#x)"), -1);
        assert_eq!(set(c"#x^"), -1);
        xml_sec_libxml2::document::free(doc);
    }
}

/// The relationship klass transforms the node set it receives, as the core
/// canonicalizes its node-set input first: a relationship a preceding
/// filter removed stays removed although a selector names it.
#[test]
fn relationship_transform_keeps_the_incoming_selection() {
    let xml =
        b"<Relationships xmlns='http://schemas.openxmlformats.org/package/2006/relationships'>\
        <Relationship Id='rId1' Type='urn:t:a' Target='a.xml'/>\
        <Relationship Id='rId3' Type='urn:t:c' Target='c.xml'/>\
        </Relationships>";
    let selectors =
        b"<Transform xmlns:m='http://schemas.openxmlformats.org/package/2006/digital-signature'>\
        <m:RelationshipReference SourceId='rId1'/><m:RelationshipReference SourceId='rId3'/>\
        </Transform>";
    // SAFETY: the documents, node set and context are used while live.
    unsafe {
        let doc = crate::ffi::parser::xmlSecParseMemory(xml.as_ptr(), xml.len(), 0);
        let template =
            crate::ffi::parser::xmlSecParseMemory(selectors.as_ptr(), selectors.len(), 0);
        assert!(!doc.is_null() && !template.is_null());
        let root = nodes::first_child(doc);
        let first = crate::ffi::xmltree::next_element(nodes::first_child(root));
        let excluded = crate::ffi::xmltree::next_element(nodes::next(first));
        // Everything but the rId3 relationship.
        let selection = crate::ffi::nodeset::xmlSecNodeSetGetChildren(doc, excluded, 0, 1);
        let ctx = xmlSecTransformCtxCreate();
        let transform = xmlSecTransformCtxCreateAndAppend(ctx, super::relationship::relationship());
        let read = (*super::relationship::relationship())
            .read_node
            .expect("the klass reads its node");
        assert_eq!(read(transform, nodes::first_child(template), ctx), 0);
        assert_eq!(super::ctx::xmlSecTransformCtxXmlExecute(ctx, selection), 0);
        let result = (*ctx).result;
        let output = String::from_utf8(
            std::slice::from_raw_parts(xmlSecBufferGetData(result), xmlSecBufferGetSize(result))
                .to_vec(),
        )
        .expect("UTF-8");
        assert!(output.contains("rId1"), "{output}");
        assert!(!output.contains("rId3"), "{output}");
        xmlSecTransformCtxDestroy(ctx);
        crate::ffi::nodeset::xmlSecNodeSetDestroy(selection);
        xml_sec_libxml2::document::free(template);
        xml_sec_libxml2::document::free(doc);
    }
}

/// The reasons reported while a test runs.
static REASONS: std::sync::Mutex<Vec<std::ffi::c_int>> = std::sync::Mutex::new(Vec::new());

unsafe extern "C" fn record(
    _file: *const std::ffi::c_char,
    _line: std::ffi::c_int,
    _func: *const std::ffi::c_char,
    _object: *const std::ffi::c_char,
    _subject: *const std::ffi::c_char,
    reason: std::ffi::c_int,
    _message: *const std::ffi::c_char,
) {
    REASONS.lock().expect("one test thread").push(reason);
}

/// The Relationship transform is an XML Signature transform: a chain that
/// encrypts what it produces is refused as not implemented when it runs,
/// the first point at which the chain knows it encrypts.
#[test]
fn an_encryption_chain_refuses_the_relationship_transform() {
    let xml =
        b"<Relationships xmlns='http://schemas.openxmlformats.org/package/2006/relationships'>\
        <Relationship Id='rId1' Type='urn:t:a' Target='a.xml'/></Relationships>";
    let selectors =
        b"<Transform xmlns:m='http://schemas.openxmlformats.org/package/2006/digital-signature'>\
        <m:RelationshipReference SourceId='rId1'/></Transform>";
    // SAFETY: the documents, node set, key and context are used while live.
    unsafe {
        let doc = crate::ffi::parser::xmlSecParseMemory(xml.as_ptr(), xml.len(), 0);
        let template =
            crate::ffi::parser::xmlSecParseMemory(selectors.as_ptr(), selectors.len(), 0);
        assert!(!doc.is_null() && !template.is_null());
        let selection =
            crate::ffi::nodeset::xmlSecNodeSetGetChildren(doc, nodes::first_child(doc), 0, 0);
        let ctx = xmlSecTransformCtxCreate();
        let transform = xmlSecTransformCtxCreateAndAppend(ctx, super::relationship::relationship());
        let read = (*super::relationship::relationship())
            .read_node
            .expect("the klass reads its node");
        assert_eq!(read(transform, nodes::first_child(template), ctx), 0);
        let cipher = xmlSecTransformCtxCreateAndAppend(ctx, super::ciphers::aes128_cbc());
        (*cipher).operation = super::OPERATION_ENCRYPT;
        let info = crate::ffi::keyinfo::xmlSecKeyInfoCtxCreate(std::ptr::null_mut());
        let key = crate::ffi::keys::xmlSecKeyCreate();
        let bytes = [0x5a_u8; 16];
        assert_eq!(
            crate::ffi::keysdata::xmlSecKeyDataBinRead(
                crate::ffi::symkeys::aes(),
                key.cast(),
                bytes.as_ptr(),
                bytes.len(),
                info.cast(),
            ),
            0
        );
        assert_eq!(super::xmlSecTransformSetKey(cipher, key.cast()), 0);
        REASONS.lock().expect("one test thread").clear();
        crate::ffi::errors::xmlSecErrorsSetCallback(Some(
            record as crate::ffi::errors::ErrorsCallback,
        ));
        let executed = super::ctx::xmlSecTransformCtxXmlExecute(ctx, selection);
        crate::ffi::errors::xmlSecErrorsClearCallback();
        let reasons = REASONS.lock().expect("one test thread").clone();
        assert_eq!(executed, -1, "{reasons:?}");
        assert!(
            reasons.contains(&crate::ffi::errors::R_NOT_IMPLEMENTED),
            "{reasons:?}"
        );
        crate::ffi::keys::xmlSecKeyDestroy(key);
        crate::ffi::keyinfo::xmlSecKeyInfoCtxDestroy(info);
        xmlSecTransformCtxDestroy(ctx);
        crate::ffi::nodeset::xmlSecNodeSetDestroy(selection);
        xml_sec_libxml2::document::free(template);
        xml_sec_libxml2::document::free(doc);
    }
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
            &*policy,
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
