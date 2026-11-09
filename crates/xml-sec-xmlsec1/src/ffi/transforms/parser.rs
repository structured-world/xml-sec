//! The XML parser klass: the binary-to-XML adapter, which parses its input
//! octets into a libxml2 document with the library's parser options and
//! passes on that document as a tree node set it owns.

use std::ffi::{c_int, c_void};

use super::super::nodeset::{TREE, XmlSecNodeSet, xmlSecNodeSetCreate, xmlSecNodeSetDocDestroy};
use super::super::parser::{
    ParserCtxt, free_ctxt, options, prepare_ctxt, push_input, take_doc, xmlCreatePushParserCtxt,
    xmlParseChunk, xmlParseDocument,
};
use super::super::tree::xmlFreeDoc;
use super::builtin::klass;
use super::io::xmlSecTransformCreateInputBuffer;
use super::{
    STATUS_FINISHED, STATUS_NONE, STATUS_WORKING, USAGE_DSIG_TRANSFORM, WithContext,
    XmlSecTransform, XmlSecTransformCtx, XmlSecTransformKlass, context, xmlSecTransformPushXml,
};

use xml_sec_libxml2::ffi::libxml2::{
    self, xml_free_input_stream as xmlFreeInputStream,
    xml_free_parser_input_buffer as xmlFreeParserInputBuffer,
    xml_new_io_input_stream as xmlNewIOInputStream, xml_new_parser_ctxt as xmlNewParserCtxt,
};

/// `XML_CHAR_ENCODING_NONE`: libxml2 detects the encoding.
const ENCODING_NONE: c_int = 0;

static XML_PARSER: XmlSecTransformKlass = XmlSecTransformKlass {
    finalize: Some(finalize),
    push_bin: Some(push_bin),
    pop_xml: Some(pop_xml),
    ..klass(
        size_of::<WithContext<ParserCtxt>>(),
        c"xml-parser".as_ptr().cast(),
        std::ptr::null(),
        USAGE_DSIG_TRANSFORM,
    )
};

/// The XML parser klass, the automatic binary-to-XML adapter.
pub(crate) fn xml_parser() -> *const XmlSecTransformKlass {
    &raw const XML_PARSER
}

/// `xmlSecTransformXmlParserGetKlass`.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformXmlParserGetKlass() -> *const XmlSecTransformKlass {
    xml_parser()
}

/// The push parser of an XML parser transform; the object's tail starts
/// zeroed, so a fresh transform has none.
///
/// # Safety
/// `transform` is null or a valid transform.
unsafe fn push_parser<'a>(transform: *mut XmlSecTransform) -> Option<&'a mut ParserCtxt> {
    // SAFETY: an XML parser transform's tail is its push parser.
    unsafe { context::<ParserCtxt>(transform, xml_parser()) }
}

unsafe extern "C" fn finalize(transform: *mut XmlSecTransform) {
    // SAFETY: an XML parser transform being destroyed.
    if let Some(slot) = unsafe { push_parser(transform) } {
        if !slot.is_null() {
            // SAFETY: the push parser this transform created, with the
            // libxml2 that was available then.
            unsafe { free_ctxt(*slot) };
        }
        *slot = std::ptr::null_mut();
    }
}

/// A tree node set that owns `doc`, freeing `doc` when one cannot be made.
///
/// # Safety
/// `doc` is a live document the caller gives up.
unsafe fn owning(doc: *mut c_void) -> *mut XmlSecNodeSet {
    // SAFETY: by the caller's contract.
    unsafe {
        let nodes = xmlSecNodeSetCreate(doc.cast(), std::ptr::null_mut(), TREE);
        if nodes.is_null() {
            xmlFreeDoc(doc.cast());
            return nodes;
        }
        xmlSecNodeSetDocDestroy(nodes);
        nodes
    }
}

/// Feeds pushed octets to the push parser; the final call finishes the
/// document and pushes it on.
unsafe extern "C" fn push_bin(
    transform: *mut XmlSecTransform,
    data: *const u8,
    size: usize,
    last: c_int,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    // SAFETY: an XML parser transform in a live chain; `data` holds `size`
    // bytes.
    unsafe {
        let Some(slot) = push_parser(transform) else {
            return -1;
        };
        if ctx.is_null() {
            return -1;
        }
        let object = &mut *transform;
        match object.status {
            STATUS_NONE => {
                if !slot.is_null() || !libxml2::available() {
                    return -1;
                }
                *slot = xmlCreatePushParserCtxt(
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                );
                if slot.is_null() {
                    return -1;
                }
                prepare_ctxt(*slot, options());
                object.status = STATUS_WORKING;
            }
            STATUS_WORKING => {}
            STATUS_FINISHED => return 0,
            _ => return -1,
        }
        if !data.is_null() && size > 0 {
            let Ok(len) = c_int::try_from(size) else {
                return -1;
            };
            if xmlParseChunk(*slot, data.cast(), len, 0) != 0 {
                return -1;
            }
        }
        if last == 0 {
            return 0;
        }
        if xmlParseChunk(*slot, std::ptr::null(), 0, 1) != 0 {
            return -1;
        }
        let doc = take_doc(*slot);
        if doc.is_null() {
            return -1;
        }
        object.out_nodes = owning(doc.cast());
        if object.out_nodes.is_null() {
            return -1;
        }
        if !object.next.is_null() && xmlSecTransformPushXml(object.next, object.out_nodes, ctx) < 0
        {
            return -1;
        }
        object.status = STATUS_FINISHED;
        0
    }
}

/// Parses everything the previous transform pops, as one document.
unsafe extern "C" fn pop_xml(
    transform: *mut XmlSecTransform,
    nodes: *mut *mut XmlSecNodeSet,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    // SAFETY: an XML parser transform in a live chain; `nodes` is writable.
    unsafe {
        if push_parser(transform).is_none() || nodes.is_null() || ctx.is_null() {
            return -1;
        }
        let object = &mut *transform;
        match object.status {
            STATUS_NONE => object.status = STATUS_WORKING,
            STATUS_WORKING => {}
            STATUS_FINISHED => {
                nodes.write(std::ptr::null_mut());
                return 0;
            }
            _ => return -1,
        }
        if object.prev.is_null() || !libxml2::available() {
            return -1;
        }
        let input = xmlSecTransformCreateInputBuffer(object.prev, ctx);
        if input.is_null() {
            return -1;
        }
        let parser = xmlNewParserCtxt();
        if parser.is_null() {
            xmlFreeParserInputBuffer(input);
            return -1;
        }
        prepare_ctxt(parser, options());
        let stream = xmlNewIOInputStream(parser, input, ENCODING_NONE);
        if stream.is_null() {
            free_ctxt(parser);
            xmlFreeParserInputBuffer(input);
            return -1;
        }
        if push_input(parser, stream) < 0 {
            xmlFreeInputStream(stream);
            free_ctxt(parser);
            return -1;
        }
        if xmlParseDocument(parser) < 0 {
            free_ctxt(parser);
            return -1;
        }
        let doc = take_doc(parser);
        free_ctxt(parser);
        let result = owning(doc.cast());
        if result.is_null() {
            return -1;
        }
        nodes.write(result);
        object.status = STATUS_FINISHED;
        0
    }
}
