//! The OPC Relationship klass (ISO/IEC 29500-2 section 13.2.4.24).
//!
//! The transform element's `RelationshipReference` and
//! `RelationshipsGroupReference` children select relationships by `SourceId`
//! and `SourceType`; the output is the core's relationship transform of the
//! input node set followed by its canonicalization, as the core produces it
//! for a reference.

use std::ffi::{CStr, c_char, c_int, c_void};

use xml_sec::XmlDocument;
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::xmldsig::transforms::{
    RelationshipSelector, Transform, execute_transforms_with_policy,
};
use xml_sec::xmldsig::types::TransformData;
use xml_sec_libxml2::ffi::{LibxmlTree, XmlNode};

use super::super::errors::{self, check, here};
use super::super::nodeset::XmlSecNodeSet;
use super::super::strings::{
    xmlSecHrefRelationship, xmlSecNameRelationship, xmlSecNodeRelationshipReference,
    xmlSecRelationshipAttrSourceId, xmlSecRelationshipReferenceNs,
};
use super::super::tree::{readable, xmlGetProp};
use super::super::xmltree::xmlSecCheckNodeName;
use super::super::{free, policy};
use super::builtin::{PopTarget, klass, pop_rendered, push_rendered, selected_octets};
use super::io::xmlOutputBufferWrite;
use super::{
    USAGE_DSIG_TRANSFORM, WithContext, XmlSecTransform, XmlSecTransformCtx, XmlSecTransformKlass,
    context_or,
};

/// The selectors of one transform, owned through the object's tail.
type Selectors = Vec<RelationshipSelector>;

static RELATIONSHIP: XmlSecTransformKlass = XmlSecTransformKlass {
    initialize: Some(initialize),
    finalize: Some(finalize),
    read_node: Some(read_node),
    push_xml: Some(push_xml),
    pop_bin: Some(pop_bin),
    ..klass(
        size_of::<WithContext<*mut Selectors>>(),
        xmlSecNameRelationship.as_ptr(),
        xmlSecHrefRelationship.as_ptr(),
        USAGE_DSIG_TRANSFORM,
    )
};

/// The Relationship klass.
pub(crate) fn relationship() -> *const XmlSecTransformKlass {
    &raw const RELATIONSHIP
}

/// The name of the Relationship klass for a report.
fn name() -> *const c_char {
    xmlSecNameRelationship.as_ptr().cast()
}

/// The selectors of the Relationship transform `$transform`, after
/// libxmlsec1's assertion inside the entry point `$func`, or `$ret`.
macro_rules! selectors_or {
    ($transform:expr, $func:literal $(, $ret:expr)?) => {
        context_or!(
            $transform,
            *mut Selectors,
            relationship(),
            $func,
            c"xmlSecTransformCheckId(transform, xmlSecTransformRelationshipId)"
            $(, $ret)?
        )
    };
}

unsafe extern "C" fn initialize(transform: *mut XmlSecTransform) -> c_int {
    let slot = selectors_or!(transform, "xmlSecRelationshipInitialize", -1);
    *slot = Box::into_raw(Box::default());
    0
}

unsafe extern "C" fn finalize(transform: *mut XmlSecTransform) {
    let slot = selectors_or!(transform, "xmlSecRelationshipFinalize");
    if !slot.is_null() {
        // SAFETY: the selectors `initialize` leaked.
        drop(unsafe { Box::from_raw(*slot) });
    }
    *slot = std::ptr::null_mut();
}

/// The value of attribute `name` of `node`, or why it has none.
///
/// # Safety
/// `node` is a live element.
unsafe fn attribute(node: *mut XmlNode, name: *const u8) -> Result<String, &'static str> {
    // SAFETY: by the caller's contract; the copy is freed after reading.
    unsafe {
        let value = xmlGetProp(node, name);
        if value.is_null() {
            return Err("empty");
        }
        let text = CStr::from_ptr(value.cast())
            .to_str()
            .map(str::to_owned)
            .map_err(|_| "not UTF-8");
        free(value.cast());
        text
    }
}

/// Reads the selectors: every `RelationshipReference` needs its `SourceId`,
/// every `RelationshipsGroupReference` its `SourceType`; other children are
/// skipped.
unsafe extern "C" fn read_node(
    transform: *mut XmlSecTransform,
    node: *mut XmlNode,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    let slot = selectors_or!(transform, "xmlSecRelationshipReadNode", -1);
    check!(
        !node.is_null(),
        "xmlSecRelationshipReadNode",
        c"node != NULL",
        -1
    );
    check!(
        !ctx.is_null(),
        "xmlSecRelationshipReadNode",
        c"transformCtx != NULL",
        -1
    );
    check!(
        !slot.is_null(),
        "xmlSecRelationshipReadNode",
        c"ctx != NULL",
        -1
    );
    let here = here!("xmlSecRelationshipReadNode");
    // SAFETY: a Relationship transform and a live element of its document.
    unsafe {
        let list = &mut **slot;
        let mut current = (*node).children;
        while !current.is_null() {
            let ns = xmlSecRelationshipReferenceNs.as_ptr();
            if xmlSecCheckNodeName(current, xmlSecNodeRelationshipReference.as_ptr(), ns) != 0 {
                let name = xmlSecRelationshipAttrSourceId.as_ptr();
                match attribute(current, name) {
                    Ok(id) => list.push(RelationshipSelector::SourceId(id)),
                    Err(reason) => {
                        let name = CStr::from_ptr(name.cast());
                        errors::invalid_node_attribute(
                            here,
                            current,
                            name,
                            std::ptr::null(),
                            reason,
                        );
                        return -1;
                    }
                }
            } else if xmlSecCheckNodeName(
                current,
                c"RelationshipsGroupReference".as_ptr().cast(),
                ns,
            ) != 0
            {
                match attribute(current, c"SourceType".as_ptr().cast()) {
                    Ok(kind) => list.push(RelationshipSelector::SourceType(kind)),
                    Err(reason) => {
                        errors::invalid_node_attribute(
                            here,
                            current,
                            c"SourceType",
                            std::ptr::null(),
                            reason,
                        );
                        return -1;
                    }
                }
            }
            current = (*current).next;
        }
        0
    }
}

/// Writes the transform's output for the document of `nodes` to the libxml2
/// output buffer `out`.
///
/// # Safety
/// `nodes` is a live node set over a live document; `out` is a live output
/// buffer.
unsafe fn render(selectors: &Selectors, nodes: *mut XmlSecNodeSet, out: *mut c_void) -> c_int {
    let here = here!("xmlSecTransformRelationshipExecute");
    let Some(policy) = policy::verification_at(here) else {
        return -1;
    };
    if !readable() {
        errors::no_libxml2(here);
        return -1;
    }
    // SAFETY: by the caller's contract.
    let doc = unsafe { (*nodes).doc };
    // The core runs the transform in place of libxmlsec1's node-list walk;
    // its error is the cause.
    let failed = |error: &str| {
        errors::internal_with(
            here,
            name(),
            c"xmlSecTransformRelationshipProcessNodeList",
            error,
        );
    };
    // SAFETY: the node set's document is live for the call.
    let Some(tree) = (unsafe { LibxmlTree::new(doc) }) else {
        failed("the document cannot be read");
        return -1;
    };
    let document = match XmlDocument::from_external_tree(Box::new(tree), policy) {
        Ok(document) => document,
        Err(error) => {
            failed(&error.to_string());
            return -1;
        }
    };
    // ISO/IEC 29500-2 section 13.2.4.24 follows the transform with
    // canonicalization; the core requires it in the same chain.
    let transforms = [
        Transform::Relationship(selectors.clone()),
        Transform::C14n(C14nAlgorithm::new(C14nMode::Inclusive1_0, false)),
    ];
    // The input is the node set received, converted to octets as the core
    // converts a relationship transform's node-set input, so what a
    // preceding filter removed stays removed.
    let bytes = document.with_view(|view| {
        // SAFETY: `nodes` is over the document `view` projects.
        let Some(input) = (unsafe { selected_octets(view, nodes, &policy.resources) }) else {
            return Err("the input node set cannot be canonicalized".to_owned());
        };
        execute_transforms_with_policy(
            view.document().root(),
            TransformData::Binary(input),
            &transforms,
            policy,
        )
        .map_err(|error| error.to_string())
    });
    let bytes = match bytes {
        Ok(bytes) => bytes,
        Err(error) => {
            failed(&error);
            return -1;
        }
    };
    for chunk in bytes.chunks(c_int::MAX.unsigned_abs() as usize) {
        let len = c_int::try_from(chunk.len()).expect("a chunk is at most c_int::MAX bytes");
        // SAFETY: a live output buffer by the caller's contract.
        if unsafe { xmlOutputBufferWrite(out, len, chunk.as_ptr().cast()) } < 0 {
            errors::xml_failed(here, name(), c"xmlOutputBufferWriteString");
            return -1;
        }
    }
    0
}

unsafe extern "C" fn push_xml(
    transform: *mut XmlSecTransform,
    nodes: *mut XmlSecNodeSet,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    let slot = selectors_or!(transform, "xmlSecTransformRelationshipPushXml", -1);
    // SAFETY: the selectors `initialize` created, or null.
    let Some(list) = (unsafe { slot.as_ref() }) else {
        errors::assertion(here!("xmlSecTransformRelationshipPushXml"), c"ctx != NULL");
        return -1;
    };
    let render = |nodes, out| {
        // SAFETY: the node set and the output buffer are live for the call.
        unsafe { render(list, nodes, out) }
    };
    // SAFETY: a Relationship transform, its chain and context.
    unsafe {
        push_rendered(
            transform,
            nodes,
            ctx,
            (render, c"xmlSecTransformRelationshipExecute"),
            here!("xmlSecTransformRelationshipPushXml"),
        )
    }
}

unsafe extern "C" fn pop_bin(
    transform: *mut XmlSecTransform,
    data: *mut u8,
    max_size: usize,
    size: *mut usize,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    let slot = selectors_or!(transform, "xmlSecTransformRelationshipPopBin", -1);
    // SAFETY: the selectors `initialize` created, or null.
    let Some(list) = (unsafe { slot.as_ref() }) else {
        errors::assertion(here!("xmlSecTransformRelationshipPopBin"), c"ctx != NULL");
        return -1;
    };
    let render = |nodes, out| {
        // SAFETY: the node set and the output buffer are live for the call.
        unsafe { render(list, nodes, out) }
    };
    let target = PopTarget {
        data,
        max_size,
        size,
    };
    // SAFETY: a Relationship transform, its chain and context. libxmlsec1
    // names this rendering step `xmlC14NExecute` in its report.
    unsafe {
        pop_rendered(
            transform,
            target,
            ctx,
            (render, c"xmlC14NExecute"),
            here!("xmlSecTransformRelationshipPopBin"),
        )
    }
}
