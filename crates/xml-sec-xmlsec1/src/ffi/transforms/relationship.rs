//! The OPC Relationship klass (ISO/IEC 29500-2 section 13.2.4.24).
//!
//! The transform element's `RelationshipReference` and
//! `RelationshipsGroupReference` children select relationships by `SourceId`
//! and `SourceType`; the output is the core's relationship transform of the
//! input node set followed by its canonicalization, as the core produces it
//! for a reference.

use std::ffi::{CStr, c_int, c_void};

use xml_sec::XmlDocument;
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::xmldsig::transforms::{
    RelationshipSelector, Transform, execute_transforms_with_policy,
};
use xml_sec::xmldsig::types::TransformData;
use xml_sec_libxml2::ffi::{LibxmlTree, XmlNode};

use super::super::nodeset::XmlSecNodeSet;
use super::super::strings::{
    xmlSecHrefRelationship, xmlSecNameRelationship, xmlSecNodeRelationshipReference,
    xmlSecRelationshipAttrSourceId, xmlSecRelationshipReferenceNs,
};
use super::super::tree::{readable, xmlGetProp};
use super::super::xmltree::xmlSecCheckNodeName;
use super::super::{free, policy};
use super::builtin::{klass, pop_rendered, push_rendered, selected_octets};
use super::io::xmlOutputBufferWrite;
use super::{
    USAGE_DSIG_TRANSFORM, WithContext, XmlSecTransform, XmlSecTransformCtx, XmlSecTransformKlass,
    context,
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

/// The selectors of a Relationship transform.
///
/// # Safety
/// `transform` is null or a valid transform.
unsafe fn selectors<'a>(transform: *mut XmlSecTransform) -> Option<&'a mut *mut Selectors> {
    // SAFETY: a Relationship transform's tail is its selectors.
    unsafe { context::<*mut Selectors>(transform, relationship()) }
}

unsafe extern "C" fn initialize(transform: *mut XmlSecTransform) -> c_int {
    // SAFETY: a fresh Relationship transform.
    match unsafe { selectors(transform) } {
        Some(slot) => {
            *slot = Box::into_raw(Box::default());
            0
        }
        None => -1,
    }
}

unsafe extern "C" fn finalize(transform: *mut XmlSecTransform) {
    // SAFETY: a Relationship transform being destroyed.
    if let Some(slot) = unsafe { selectors(transform) } {
        if !slot.is_null() {
            // SAFETY: the selectors `initialize` leaked.
            drop(unsafe { Box::from_raw(*slot) });
        }
        *slot = std::ptr::null_mut();
    }
}

/// The value of attribute `name` of `node`.
///
/// # Safety
/// `node` is a live element.
unsafe fn attribute(node: *mut XmlNode, name: *const u8) -> Option<String> {
    // SAFETY: by the caller's contract; the copy is freed after reading.
    unsafe {
        let value = xmlGetProp(node, name);
        if value.is_null() {
            return None;
        }
        let text = CStr::from_ptr(value.cast())
            .to_str()
            .ok()
            .map(str::to_owned);
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
    // SAFETY: a Relationship transform and a live element of its document.
    unsafe {
        let Some(slot) = selectors(transform) else {
            return -1;
        };
        if node.is_null() || ctx.is_null() || slot.is_null() {
            return -1;
        }
        let list = &mut **slot;
        let mut current = (*node).children;
        while !current.is_null() {
            let ns = xmlSecRelationshipReferenceNs.as_ptr();
            if xmlSecCheckNodeName(current, xmlSecNodeRelationshipReference.as_ptr(), ns) != 0 {
                let Some(id) = attribute(current, xmlSecRelationshipAttrSourceId.as_ptr()) else {
                    return -1;
                };
                list.push(RelationshipSelector::SourceId(id));
            } else if xmlSecCheckNodeName(
                current,
                c"RelationshipsGroupReference".as_ptr().cast(),
                ns,
            ) != 0
            {
                let Some(kind) = attribute(current, c"SourceType".as_ptr().cast()) else {
                    return -1;
                };
                list.push(RelationshipSelector::SourceType(kind));
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
    let Some(policy) = policy::verification() else {
        return -1;
    };
    // SAFETY: by the caller's contract.
    let doc = unsafe { (*nodes).doc };
    if doc.is_null() || !readable() {
        return -1;
    }
    // SAFETY: the node set's document is live for the call.
    let Some(tree) = (unsafe { LibxmlTree::new(doc) }) else {
        return -1;
    };
    let Ok(document) = XmlDocument::from_external_tree(Box::new(tree), policy) else {
        return -1;
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
        let input = unsafe { selected_octets(view, nodes, &policy.resources) }?;
        execute_transforms_with_policy(
            view.document().root(),
            TransformData::Binary(input),
            &transforms,
            policy,
        )
        .ok()
    });
    let Some(bytes) = bytes else {
        return -1;
    };
    for chunk in bytes.chunks(c_int::MAX.unsigned_abs() as usize) {
        let Ok(len) = c_int::try_from(chunk.len()) else {
            return -1;
        };
        // SAFETY: a live output buffer by the caller's contract.
        if unsafe { xmlOutputBufferWrite(out, len, chunk.as_ptr().cast()) } < 0 {
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
    // SAFETY: a Relationship transform, its chain and context.
    unsafe {
        let Some(slot) = selectors(transform) else {
            return -1;
        };
        let Some(list) = slot.as_ref() else {
            return -1;
        };
        push_rendered(transform, nodes, ctx, |nodes, out| render(list, nodes, out))
    }
}

unsafe extern "C" fn pop_bin(
    transform: *mut XmlSecTransform,
    data: *mut u8,
    max_size: usize,
    size: *mut usize,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    // SAFETY: a Relationship transform, its chain and context.
    unsafe {
        let Some(slot) = selectors(transform) else {
            return -1;
        };
        let Some(list) = slot.as_ref() else {
            return -1;
        };
        pop_rendered(transform, data, max_size, size, ctx, |nodes, out| {
            render(list, nodes, out)
        })
    }
}
