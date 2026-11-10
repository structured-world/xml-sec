//! The XML parser klass: the binary-to-XML adapter, which parses its input
//! octets into a libxml2 document with the library's parser options (less
//! `XML_PARSE_HUGE`) and passes on that document as a tree node set it owns.
//! A document is at most the policy's document size, counted over its pushes
//! or its pops.

use std::ffi::{c_char, c_int, c_void};

use super::super::errors::{self, check, here};
use super::super::nodeset::{TREE, XmlSecNodeSet, xmlSecNodeSetCreate, xmlSecNodeSetDocDestroy};
use super::super::parser::{
    ParserCtxt, free_ctxt, prepare_ctxt, push_input, take_doc, transform_options,
    xmlCreatePushParserCtxt, xmlParseChunk, xmlParseDocument,
};
use super::super::policy;
use super::super::tree::xmlFreeDoc;
use super::builtin::klass;
use super::ctx::{Limit, charge};
use super::io::bounded_input_buffer;
use super::{
    STATUS_FINISHED, STATUS_NONE, STATUS_WORKING, USAGE_DSIG_TRANSFORM, WithContext,
    XmlSecTransform, XmlSecTransformCtx, XmlSecTransformKlass, context_or, xmlSecTransformPushXml,
};

use xml_sec_libxml2::ffi::libxml2::{
    self, xml_free_input_stream as xmlFreeInputStream,
    xml_free_parser_input_buffer as xmlFreeParserInputBuffer,
    xml_new_io_input_stream as xmlNewIOInputStream, xml_new_parser_ctxt as xmlNewParserCtxt,
};

/// `XML_CHAR_ENCODING_NONE`: libxml2 detects the encoding.
const ENCODING_NONE: c_int = 0;

/// The release, as `LIBXML_VERSION`, from which `xmlNewIOInputStream` frees
/// its buffer when it fails.
const INPUT_ADOPTED_ON_FAILURE: u32 = 21300;

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

/// The push parser of the XML parser transform `$transform` (null until the
/// first push), after libxmlsec1's assertion inside the entry point `$func`,
/// or `$ret`.
macro_rules! push_parser_or {
    ($transform:expr, $func:literal $(, $ret:expr)?) => {
        context_or!(
            $transform,
            ParserCtxt,
            xml_parser(),
            $func,
            c"xmlSecTransformCheckId(transform, xmlSecTransformXmlParserId)"
            $(, $ret)?
        )
    };
}

unsafe extern "C" fn finalize(transform: *mut XmlSecTransform) {
    let slot = push_parser_or!(transform, "xmlSecParserFinalize");
    if !slot.is_null() {
        // SAFETY: the push parser this transform created, with the libxml2
        // that was available then.
        unsafe { free_ctxt(*slot) };
    }
    *slot = std::ptr::null_mut();
}

/// A tree node set that owns `doc`, freeing `doc` when one cannot be made
/// (reported for the transform `name` names at `here`).
///
/// # Safety
/// `doc` is a live document the caller gives up.
unsafe fn owning(doc: *mut c_void, here: errors::Here, name: *const c_char) -> *mut XmlSecNodeSet {
    // SAFETY: by the caller's contract.
    unsafe {
        let nodes = xmlSecNodeSetCreate(doc.cast(), std::ptr::null_mut(), TREE);
        if nodes.is_null() {
            errors::internal(here, name, c"xmlSecNodeSetCreate");
            xmlFreeDoc(doc.cast());
            return nodes;
        }
        xmlSecNodeSetDocDestroy(nodes);
        nodes
    }
}

/// The name of the XML parser klass for a report.
fn name() -> *const c_char {
    c"xml-parser".as_ptr()
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
    let slot = push_parser_or!(transform, "xmlSecParserPushBin", -1);
    check!(
        !ctx.is_null(),
        "xmlSecParserPushBin",
        c"transformCtx != NULL",
        -1
    );
    let here = here!("xmlSecParserPushBin");
    // SAFETY: an XML parser transform in a live chain; `data` holds `size`
    // bytes.
    unsafe {
        let object = &mut *transform;
        match object.status {
            STATUS_NONE => {
                if !slot.is_null() {
                    errors::assertion(here, c"ctx->parserCtx == NULL");
                    return -1;
                }
                if !libxml2::available() {
                    errors::no_libxml2(here);
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
                    errors::xml_failed(here, name(), c"xmlCreatePushParserCtxt");
                    return -1;
                }
                prepare_ctxt(*slot, transform_options());
                object.status = STATUS_WORKING;
            }
            STATUS_WORKING => {}
            STATUS_FINISHED => return 0,
            status => {
                errors::invalid_status(here, name(), status);
                return -1;
            }
        }
        if slot.is_null() {
            errors::assertion(here, c"ctx->parserCtx != NULL");
            return -1;
        }
        if !data.is_null() && size > 0 {
            let Some(policy) = policy::verification_at(here) else {
                return -1;
            };
            // The octets of this document pushed so far live in `reserved0`,
            // as the object's tail is libxmlsec1's single parser pointer.
            let mut pushed = object.reserved0.addr();
            let limit = Limit {
                name: "max_xml_document_bytes",
                max: policy.resources.max_xml_document_bytes,
            };
            if charge(&mut pushed, size, limit, here, name()).is_none() {
                return -1;
            }
            object.reserved0 = std::ptr::without_provenance_mut(pushed);
            let Ok(len) = c_int::try_from(size) else {
                errors::size_to_int_impossible(here, size);
                return -1;
            };
            if xmlParseChunk(*slot, data.cast(), len, 0) != 0 {
                errors::xml_failed_with(here, name(), c"xmlParseChunk", &format!("size={len}"));
                return -1;
            }
        }
        if last == 0 {
            return 0;
        }
        let finished = xmlParseChunk(*slot, std::ptr::null(), 0, 1) == 0;
        let doc = if finished {
            take_doc(*slot)
        } else {
            std::ptr::null_mut()
        };
        if doc.is_null() {
            errors::xml_failed(here, name(), c"xmlParseChunk");
            return -1;
        }
        object.out_nodes = owning(doc.cast(), here, name());
        if object.out_nodes.is_null() {
            return -1;
        }
        if !object.next.is_null() && xmlSecTransformPushXml(object.next, object.out_nodes, ctx) < 0
        {
            errors::internal(here, name(), c"xmlSecTransformPushXml");
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
    push_parser_or!(transform, "xmlSecParserPopXml", -1);
    check!(!nodes.is_null(), "xmlSecParserPopXml", c"nodes != NULL", -1);
    check!(
        !ctx.is_null(),
        "xmlSecParserPopXml",
        c"transformCtx != NULL",
        -1
    );
    let here = here!("xmlSecParserPopXml");
    // SAFETY: an XML parser transform in a live chain; `nodes` is writable.
    unsafe {
        let object = &mut *transform;
        match object.status {
            STATUS_NONE => object.status = STATUS_WORKING,
            STATUS_WORKING => {}
            STATUS_FINISHED => {
                nodes.write(std::ptr::null_mut());
                return 0;
            }
            status => {
                errors::invalid_status(here, name(), status);
                return -1;
            }
        }
        let Some(policy) = policy::verification_at(here) else {
            return -1;
        };
        if object.prev.is_null() {
            errors::report(
                here,
                name(),
                std::ptr::null(),
                errors::R_INVALID_TRANSFORM,
                "prev transform=\"NULL\"",
            );
            return -1;
        }
        if !libxml2::available() {
            errors::no_libxml2(here);
            return -1;
        }
        let limit = Limit {
            name: "max_xml_document_bytes",
            max: policy.resources.max_xml_document_bytes,
        };
        let input = bounded_input_buffer(
            object.prev,
            ctx,
            limit,
            here!("xmlSecTransformCreateInputBuffer"),
        );
        if input.is_null() {
            errors::internal(here, name(), c"xmlSecTransformCreateInputBuffer");
            return -1;
        }
        let parser = xmlNewParserCtxt();
        if parser.is_null() {
            errors::xml_failed(here, name(), c"xmlNewParserCtxt");
            xmlFreeParserInputBuffer(input);
            return -1;
        }
        prepare_ctxt(parser, transform_options());
        let stream = xmlNewIOInputStream(parser, input, ENCODING_NONE);
        if stream.is_null() {
            errors::xml_failed(here, name(), c"xmlNewIOInputStream");
            free_ctxt(parser);
            // From libxml2 2.13 a failed `xmlNewIOInputStream` frees the
            // buffer itself (`xmlNewInputInternal`); before, it stays ours.
            if libxml2::version().is_some_and(|version| version < INPUT_ADOPTED_ON_FAILURE) {
                xmlFreeParserInputBuffer(input);
            }
            return -1;
        }
        if push_input(parser, stream) < 0 {
            errors::xml_failed(here, name(), c"xmlCtxtPushInput");
            xmlFreeInputStream(stream);
            free_ctxt(parser);
            return -1;
        }
        if xmlParseDocument(parser) < 0 {
            errors::xml_failed(here, name(), c"xmlParseDocument");
            free_ctxt(parser);
            return -1;
        }
        let doc = take_doc(parser);
        free_ctxt(parser);
        let result = owning(doc.cast(), here, name());
        if result.is_null() {
            return -1;
        }
        nodes.write(result);
        object.status = STATUS_FINISHED;
        0
    }
}
