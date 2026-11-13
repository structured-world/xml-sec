//! The XML parser klass: the binary-to-XML adapter, which parses its input
//! octets with the core under the library policy and passes on that
//! document as a tree node set it owns. A document is at most the policy's
//! document size, counted over its pushes or its pops.

use std::ffi::{c_char, c_int};

use xml_sec_libxml2::ffi::io::{input_content, input_free, input_read};

use super::super::errors::{self, check, here};
use super::super::nodeset::{TREE, XmlSecNodeSet, xmlSecNodeSetCreate, xmlSecNodeSetDocDestroy};
use super::super::parser::parse_under;
use super::super::policy;
use super::super::tree::XmlDoc;
use super::builtin::klass;
use super::ctx::{Limit, charge, run_scope};
use super::io::bounded_input_buffer;
use super::{
    STATUS_FINISHED, STATUS_NONE, STATUS_WORKING, USAGE_DSIG_TRANSFORM, WithContext,
    XmlSecTransform, XmlSecTransformCtx, XmlSecTransformKlass, context_or, xmlSecTransformPushXml,
};

/// The octets pushed so far, until the final push parses them.
type Pushed = Vec<u8>;

/// How many octets each read from the previous transform asks for.
const READ_CHUNK: usize = 4096;

static XML_PARSER: XmlSecTransformKlass = XmlSecTransformKlass {
    finalize: Some(finalize),
    push_bin: Some(push_bin),
    pop_xml: Some(pop_xml),
    ..klass(
        size_of::<WithContext<*mut Pushed>>(),
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

/// The pushed octets of the XML parser transform `$transform` (null until
/// the first push), after libxmlsec1's assertion inside the entry point
/// `$func`, or `$ret`.
macro_rules! pushed_or {
    ($transform:expr, $func:literal $(, $ret:expr)?) => {
        context_or!(
            $transform,
            *mut Pushed,
            xml_parser(),
            $func,
            c"xmlSecTransformCheckId(transform, xmlSecTransformXmlParserId)"
            $(, $ret)?
        )
    };
}

unsafe extern "C" fn finalize(transform: *mut XmlSecTransform) {
    let slot = pushed_or!(transform, "xmlSecParserFinalize");
    if !slot.is_null() {
        // SAFETY: the octets the first push leaked.
        drop(unsafe { Box::from_raw(*slot) });
    }
    *slot = std::ptr::null_mut();
}

/// A tree node set that owns `doc`, freeing `doc` when one cannot be made
/// (reported for the transform `name` names at `here`).
fn owning(doc: *mut XmlDoc, here: errors::Here, name: *const c_char) -> *mut XmlSecNodeSet {
    // SAFETY: the node set takes no node list; the document is ours.
    unsafe {
        let nodes = xmlSecNodeSetCreate(doc, std::ptr::null_mut(), TREE);
        if nodes.is_null() {
            errors::internal(here, name, c"xmlSecNodeSetCreate");
            xml_sec_libxml2::document::free(doc);
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

/// The limit on the octets of one document.
fn document_limit(resources: &xml_sec::policy::ResourcePolicy) -> Limit {
    Limit {
        name: "max_xml_document_bytes",
        max: resources.max_xml_document_bytes,
    }
}

/// Collects pushed octets; the final call parses the document and pushes
/// it on.
unsafe extern "C" fn push_bin(
    transform: *mut XmlSecTransform,
    data: *const u8,
    size: usize,
    last: c_int,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    let slot = pushed_or!(transform, "xmlSecParserPushBin", -1);
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
                *slot = Box::into_raw(Box::default());
                object.status = STATUS_WORKING;
            }
            STATUS_WORKING => {}
            STATUS_FINISHED => return 0,
            status => {
                errors::invalid_status(here, name(), status);
                return -1;
            }
        }
        let Some(pushed) = slot.as_mut() else {
            errors::assertion(here, c"ctx->parserCtx != NULL");
            return -1;
        };
        let Some((pinned, served)) = run_scope(ctx, here) else {
            return -1;
        };
        let operation = pinned.of(served);
        if !data.is_null() && size > 0 {
            let mut count = pushed.len();
            let limit = document_limit(operation.resources());
            if charge(&mut count, size, limit, here, name()).is_none() {
                return -1;
            }
            pushed.extend_from_slice(std::slice::from_raw_parts(data, size));
        }
        if last == 0 {
            return 0;
        }
        let doc =
            policy::with_document_policy!(operation, |policy| parse_under(pushed, here, policy));
        if doc.is_null() {
            return -1;
        }
        object.out_nodes = owning(doc, here, name());
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
    pushed_or!(transform, "xmlSecParserPopXml", -1);
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
        let Some((pinned, side)) = run_scope(ctx, here) else {
            return -1;
        };
        let operation = pinned.of(side);
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
        // Reads past the document limit fail inside the buffer.
        let input = bounded_input_buffer(
            object.prev,
            ctx,
            document_limit(operation.resources()),
            here!("xmlSecTransformCreateInputBuffer"),
        );
        if input.is_null() {
            errors::internal(here, name(), c"xmlSecTransformCreateInputBuffer");
            return -1;
        }
        let read = loop {
            match input_read(input, READ_CHUNK) {
                0 => break input_content(input),
                count if count < 0 => break None,
                _ => {}
            }
        };
        input_free(input);
        let Some(bytes) = read else {
            errors::xml_failed(here, name(), c"xmlParserInputBufferRead");
            return -1;
        };
        let doc =
            policy::with_document_policy!(operation, |policy| parse_under(&bytes, here, policy));
        if doc.is_null() {
            return -1;
        }
        let result = owning(doc, here, name());
        if result.is_null() {
            return -1;
        }
        nodes.write(result);
        object.status = STATUS_FINISHED;
        0
    }
}
