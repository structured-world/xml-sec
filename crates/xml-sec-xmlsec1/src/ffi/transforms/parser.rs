//! The XML parser klass: the binary-to-XML adapter, which parses its input
//! octets into a libxml2 document and passes on that document as a tree node
//! set it owns.
//!
//! With libxmlsec1's default options the core parses the octets under the
//! library's policy, as `xmlSecParseMemory` does; options a caller set keep
//! libxml2's push parser, whose options they are.

use std::ffi::{c_int, c_void};

use super::super::nodeset::{TREE, XmlSecNodeSet, xmlSecNodeSetCreate, xmlSecNodeSetDocDestroy};
use super::super::parser::{
    ParserCtxt, core_parses, options, parse_with_core, xmlCreatePushParserCtxt, xmlParseChunk,
    xmlParseDocument, xs_xmlsec1_free_ctxt, xs_xmlsec1_prepare_ctxt, xs_xmlsec1_push_input,
    xs_xmlsec1_take_doc,
};
use super::super::tree::xmlFreeDoc;
use super::builtin::klass;
use super::io::xmlSecTransformCreateInputBuffer;
use super::{
    STATUS_FINISHED, STATUS_NONE, STATUS_WORKING, USAGE_DSIG_TRANSFORM, WithContext,
    XmlSecTransform, XmlSecTransformCtx, XmlSecTransformKlass, context, xmlSecTransformPopBin,
    xmlSecTransformPushXml,
};

unsafe extern "C" {
    fn xmlNewParserCtxt() -> ParserCtxt;
    fn xmlNewIOInputStream(ctxt: ParserCtxt, input: *mut c_void, encoding: c_int) -> *mut c_void;
    fn xmlFreeInputStream(input: *mut c_void);
    fn xmlFreeParserInputBuffer(input: *mut c_void);
}

/// `XML_CHAR_ENCODING_NONE`: libxml2 detects the encoding.
const ENCODING_NONE: c_int = 0;

/// The octets a pop reads from the previous transform at a time.
const POP_CHUNK: usize = 4096;

/// What a pushing XML parser transform has received so far.
enum Pending {
    /// Octets the core parses once the last one arrives.
    Core(Vec<u8>),
    /// libxml2's push parser, under the options a caller set.
    Libxml(ParserCtxt),
}

static XML_PARSER: XmlSecTransformKlass = XmlSecTransformKlass {
    finalize: Some(finalize),
    push_bin: Some(push_bin),
    pop_xml: Some(pop_xml),
    ..klass(
        size_of::<WithContext<*mut Pending>>(),
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

/// What an XML parser transform has received; the object's tail starts
/// zeroed, so a fresh transform has nothing.
///
/// # Safety
/// `transform` is null or a valid transform.
unsafe fn pending<'a>(transform: *mut XmlSecTransform) -> Option<&'a mut *mut Pending> {
    // SAFETY: an XML parser transform's tail is its pending input.
    unsafe { context::<*mut Pending>(transform, xml_parser()) }
}

unsafe extern "C" fn finalize(transform: *mut XmlSecTransform) {
    // SAFETY: an XML parser transform being destroyed.
    if let Some(slot) = unsafe { pending(transform) } {
        if !slot.is_null() {
            // SAFETY: the box this transform created and still owns.
            if let Pending::Libxml(parser) = *unsafe { Box::from_raw(*slot) } {
                // SAFETY: the push parser this transform created.
                unsafe { xs_xmlsec1_free_ctxt(parser) };
            }
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

/// The input for a transform that starts pushing, or `None` when libxml2
/// cannot create its parser.
///
/// # Safety
/// Callable at any time.
unsafe fn start() -> Option<Pending> {
    if core_parses() {
        return Some(Pending::Core(Vec::new()));
    }
    // SAFETY: a fresh push parser, prepared before its first chunk.
    unsafe {
        let parser = xmlCreatePushParserCtxt(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
            0,
            std::ptr::null(),
        );
        if parser.is_null() {
            return None;
        }
        xs_xmlsec1_prepare_ctxt(parser, options());
        Some(Pending::Libxml(parser))
    }
}

/// Receives pushed octets; the final call parses the document and pushes it
/// on.
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
        let Some(slot) = pending(transform) else {
            return -1;
        };
        if ctx.is_null() {
            return -1;
        }
        let object = &mut *transform;
        match object.status {
            STATUS_NONE => {
                if !slot.is_null() {
                    return -1;
                }
                let Some(input) = start() else {
                    return -1;
                };
                *slot = Box::into_raw(Box::new(input));
                object.status = STATUS_WORKING;
            }
            STATUS_WORKING if !slot.is_null() => {}
            STATUS_FINISHED => return 0,
            _ => return -1,
        }
        let octets = if data.is_null() || size == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts(data, size)
        };
        let doc = match &mut **slot {
            Pending::Core(bytes) => {
                if bytes.try_reserve(octets.len()).is_err() {
                    return -1;
                }
                bytes.extend_from_slice(octets);
                if last == 0 {
                    return 0;
                }
                parse_with_core(bytes)
            }
            Pending::Libxml(parser) => {
                if !octets.is_empty() {
                    let Ok(len) = c_int::try_from(octets.len()) else {
                        return -1;
                    };
                    if xmlParseChunk(*parser, octets.as_ptr().cast(), len, 0) != 0 {
                        return -1;
                    }
                }
                if last == 0 {
                    return 0;
                }
                if xmlParseChunk(*parser, std::ptr::null(), 0, 1) != 0 {
                    return -1;
                }
                xs_xmlsec1_take_doc(*parser)
            }
        };
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

/// Everything `prev` pops, until it reports the end; `None` on its failure.
///
/// # Safety
/// `prev` is a transform of the live chain of `ctx`.
unsafe fn pop_all(prev: *mut XmlSecTransform, ctx: *mut XmlSecTransformCtx) -> Option<Vec<u8>> {
    let mut bytes: Vec<u8> = Vec::new();
    loop {
        bytes.try_reserve(POP_CHUNK).ok()?;
        let start = bytes.len();
        let mut read = 0;
        // SAFETY: the spare capacity holds `POP_CHUNK` writable bytes, of
        // which the pop initializes the first `read`.
        unsafe {
            if xmlSecTransformPopBin(
                prev,
                bytes.as_mut_ptr().add(start),
                POP_CHUNK,
                &raw mut read,
                ctx,
            ) < 0
                || read > POP_CHUNK
            {
                return None;
            }
            bytes.set_len(start + read);
        }
        if read == 0 {
            return Some(bytes);
        }
    }
}

/// Parses everything libxml2 reads from `prev`, under the options a caller
/// set.
///
/// # Safety
/// `prev` is a transform of the live chain of `ctx`.
unsafe fn parse_popped_with_libxml(
    prev: *mut XmlSecTransform,
    ctx: *mut XmlSecTransformCtx,
) -> *mut c_void {
    // SAFETY: by the caller's contract; every libxml2 object is freed on its
    // failure path.
    unsafe {
        let input = xmlSecTransformCreateInputBuffer(prev, ctx);
        if input.is_null() {
            return std::ptr::null_mut();
        }
        let parser = xmlNewParserCtxt();
        if parser.is_null() {
            xmlFreeParserInputBuffer(input);
            return std::ptr::null_mut();
        }
        xs_xmlsec1_prepare_ctxt(parser, options());
        let stream = xmlNewIOInputStream(parser, input, ENCODING_NONE);
        if stream.is_null() {
            xs_xmlsec1_free_ctxt(parser);
            xmlFreeParserInputBuffer(input);
            return std::ptr::null_mut();
        }
        if xs_xmlsec1_push_input(parser, stream) < 0 {
            xmlFreeInputStream(stream);
            xs_xmlsec1_free_ctxt(parser);
            return std::ptr::null_mut();
        }
        if xmlParseDocument(parser) < 0 {
            xs_xmlsec1_free_ctxt(parser);
            return std::ptr::null_mut();
        }
        let doc = xs_xmlsec1_take_doc(parser);
        xs_xmlsec1_free_ctxt(parser);
        doc.cast()
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
        if pending(transform).is_none() || nodes.is_null() || ctx.is_null() {
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
        if object.prev.is_null() {
            return -1;
        }
        let doc = if core_parses() {
            let Some(bytes) = pop_all(object.prev, ctx) else {
                return -1;
            };
            parse_with_core(&bytes).cast()
        } else {
            parse_popped_with_libxml(object.prev, ctx)
        };
        if doc.is_null() {
            return -1;
        }
        let result = owning(doc);
        if result.is_null() {
            return -1;
        }
        nodes.write(result);
        object.status = STATUS_FINISHED;
        0
    }
}
