//! `xmlsec/templates.h`: building signature, encryption and `KeyInfo`
//! templates in the caller's tree as libxmlsec1 builds them, element by
//! element with the line feeds of [`xmlSecAddChild`].

use std::ffi::{CStr, c_int};

use xml_sec_libxml2::ffi::tree::{
    xsDocCopyNode, xsDocGetRootElement, xsFreeDoc, xsFreeNode, xsNewDocNode, xsNewNs, xsReadMemory,
    xsSetNs, xsSetProp, xsUnlinkNode,
};

use super::base64::xmlSecBase64Encode;
use super::errors::{self, Here, check, here};
use super::parser::xmlSecParserGetDefaultOptions;
use super::strings::{
    xmlSecAttrAlgorithm, xmlSecAttrEncoding, xmlSecAttrFilter, xmlSecAttrId, xmlSecAttrMimeType,
    xmlSecAttrPrefixList, xmlSecAttrRecipient, xmlSecAttrTarget, xmlSecAttrType, xmlSecAttrURI,
    xmlSecDSig11Ns, xmlSecDSigNs, xmlSecEnc11Ns, xmlSecEncNs, xmlSecNodeCanonicalizationMethod,
    xmlSecNodeCipherData, xmlSecNodeCipherReference, xmlSecNodeCipherValue,
    xmlSecNodeDataReference, xmlSecNodeDigestMethod, xmlSecNodeDigestValue,
    xmlSecNodeEncryptedData, xmlSecNodeEncryptedKey, xmlSecNodeEncryptionMethod,
    xmlSecNodeEncryptionProperties, xmlSecNodeEncryptionProperty, xmlSecNodeHMACOutputLength,
    xmlSecNodeInclusiveNamespaces, xmlSecNodeKeyInfo, xmlSecNodeKeyName, xmlSecNodeKeyReference,
    xmlSecNodeKeyValue, xmlSecNodeManifest, xmlSecNodeObject, xmlSecNodeReference,
    xmlSecNodeReferenceList, xmlSecNodeRetrievalMethod, xmlSecNodeRsaMGF, xmlSecNodeRsaOAEPparams,
    xmlSecNodeSignature, xmlSecNodeSignatureMethod, xmlSecNodeSignatureProperties,
    xmlSecNodeSignatureValue, xmlSecNodeSignedInfo, xmlSecNodeTransform, xmlSecNodeTransforms,
    xmlSecNodeX509CRL, xmlSecNodeX509Certificate, xmlSecNodeX509Data, xmlSecNodeX509Digest,
    xmlSecNodeX509IssuerName, xmlSecNodeX509IssuerSerial, xmlSecNodeX509SKI,
    xmlSecNodeX509SerialNumber, xmlSecNodeX509SubjectName, xmlSecNodeXPath, xmlSecNodeXPointer,
    xmlSecNsExcC14N, xmlSecXPath2Ns, xmlSecXPointerNs,
};
use super::transforms::XmlSecTransformKlass;
use super::tree::{XmlDoc, XmlNode, c_text, name_for_report, nodes, xmlStrEqual};
use super::xmltree::{
    xmlSecAddChild, xmlSecAddNextSibling, xmlSecAddPrevSibling, xmlSecFindChild,
    xmlSecGetNextElementNode, xmlSecNodeEncodeAndSetContent, xmlSecReplaceContent,
};
use super::{contain, free};

/// libxml2's `XML_PARSE_PEDANTIC`.
const XML_PARSE_PEDANTIC: c_int = 1 << 7;
/// libxml2's `XML_PARSE_NODICT`.
const XML_PARSE_NODICT: c_int = 1 << 12;

/// A static name or namespace of the library.
fn name(text: &'static [u8]) -> *const u8 {
    text.as_ptr()
}

/// The text of a static name, for a report.
fn text(value: &'static [u8]) -> &'static str {
    CStr::from_bytes_with_nul(value)
        .ok()
        .and_then(|value| value.to_str().ok())
        .unwrap_or("NULL")
}

/// Sets the attribute `attr` of `node` to `value` when `value` is set,
/// ignoring libxml2's result as libxmlsec1 does for optional attributes.
///
/// # Safety
/// `node` is a live node; `value` is null or NUL-terminated.
unsafe fn optional(node: *mut XmlNode, attr: &'static [u8], value: *const u8) {
    if !value.is_null() {
        // SAFETY: by the caller's contract.
        unsafe { xsSetProp(node, name(attr), value) };
    }
}

/// Sets the `Algorithm` attribute of `node` to `href`; false with
/// libxmlsec1's report when libxml2 cannot.
///
/// # Safety
/// `node` is a live node; `href` is null or NUL-terminated.
unsafe fn set_algorithm(node: *mut XmlNode, href: *const u8, here: Here) -> bool {
    // SAFETY: by the caller's contract.
    if unsafe { xsSetProp(node, name(&xmlSecAttrAlgorithm), href) }.is_null() {
        errors::xml_failed_with(here, std::ptr::null(), c"xmlSetProp", "name=Algorithm");
        return false;
    }
    true
}

/// Appends the element `node` in namespace `ns` to `parent`, reporting a
/// failure as the failed call `failed`.
///
/// # Safety
/// `parent` is a live node.
unsafe fn add(
    parent: *mut XmlNode,
    node: &'static [u8],
    ns: &'static [u8],
    failed: &CStr,
    here: Here,
) -> *mut XmlNode {
    // SAFETY: by the caller's contract; the names are static.
    let cur = unsafe { xmlSecAddChild(parent, name(node), name(ns)) };
    if cur.is_null() {
        errors::internal(here, std::ptr::null(), failed);
    }
    cur
}

/// `xmlNodeSetContent(node, content)` for content without markup, whose
/// outcome libxmlsec1 does not read.
fn set_content(node: *mut XmlNode, content: &str) {
    if nodes::set_content(node, content).is_err() {
        // libxml2's setter returns nothing libxmlsec1 reads.
    }
}

/// Detaches and frees a partly built element.
///
/// # Safety
/// `node` is a live node.
unsafe fn discard(node: *mut XmlNode) {
    // SAFETY: by the caller's contract.
    unsafe {
        xsUnlinkNode(node);
        xsFreeNode(node);
    }
}

/// Whether `parent` already has the child `node` in namespace `ns`, which
/// libxmlsec1 reports.
///
/// # Safety
/// `parent` is a live node.
unsafe fn present(
    parent: *mut XmlNode,
    node: &'static [u8],
    ns: &'static [u8],
    here: Here,
) -> bool {
    // SAFETY: by the caller's contract.
    unsafe {
        if xmlSecFindChild(parent, name(node), name(ns)).is_null() {
            return false;
        }
        errors::node_already_present(
            here,
            parent,
            CStr::from_bytes_with_nul(node).unwrap_or(c"NULL"),
            std::ptr::null(),
        );
    }
    true
}

/// The child `node` of `parent` that a template function needs, reported
/// as not found when absent.
///
/// # Safety
/// `parent` is a live node.
unsafe fn required(
    parent: *mut XmlNode,
    node: &'static [u8],
    ns: &'static [u8],
    here: Here,
) -> *mut XmlNode {
    // SAFETY: by the caller's contract.
    unsafe {
        let found = xmlSecFindChild(parent, name(node), name(ns));
        if found.is_null() {
            errors::node_not_found(
                here,
                c"xmlSecFindChild",
                parent,
                CStr::from_bytes_with_nul(node).unwrap_or(c"NULL"),
                std::ptr::null(),
            );
        }
        found
    }
}

/// The klass `id`'s href after libxmlsec1's assertions `id != NULL` and
/// `id->href != NULL` at `here`.
///
/// # Safety
/// `id` is null or a transform klass.
unsafe fn href_of(
    id: *const XmlSecTransformKlass,
    here: Here,
    null: &CStr,
    no_href: &CStr,
) -> Option<*const u8> {
    // SAFETY: by the caller's contract.
    let Some(klass) = (unsafe { id.as_ref() }) else {
        errors::assertion(here, null);
        return None;
    };
    if klass.href.is_null() {
        errors::assertion(here, no_href);
        return None;
    }
    Some(klass.href)
}

// ----------------------------------------------------------------------------
// <dsig:Signature/>

/// `xmlSecTmplSignatureCreate`: [`xmlSecTmplSignatureCreateNsPref`] with the
/// default namespace.
///
/// # Safety
/// As for [`xmlSecTmplSignatureCreateNsPref`].
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplSignatureCreate(
    doc: *mut XmlDoc,
    c14n_method_id: *const XmlSecTransformKlass,
    sign_method_id: *const XmlSecTransformKlass,
    id: *const u8,
) -> *mut XmlNode {
    // SAFETY: by the caller's contract.
    unsafe {
        xmlSecTmplSignatureCreateNsPref(doc, c14n_method_id, sign_method_id, id, std::ptr::null())
    }
}

/// `xmlSecTmplSignatureCreateNsPref`: a detached `<Signature>` declaring the
/// `XMLDSig` namespace with `ns_prefix`, holding `SignedInfo` with its
/// canonicalization and signature methods and an empty `SignatureValue`.
///
/// # Safety
/// `doc` is null or a live document; the klasses are null or transform
/// klasses; `id` and `ns_prefix` are null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplSignatureCreateNsPref(
    doc: *mut XmlDoc,
    c14n_method_id: *const XmlSecTransformKlass,
    sign_method_id: *const XmlSecTransformKlass,
    id: *const u8,
    ns_prefix: *const u8,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        let here = here!("xmlSecTmplSignatureCreateNsPref");
        // SAFETY: the klasses are null or transform klasses.
        let Some(c14n) = (unsafe {
            href_of(
                c14n_method_id,
                here,
                c"c14nMethodId != NULL",
                c"c14nMethodId->href != NULL",
            )
        }) else {
            return std::ptr::null_mut();
        };
        // SAFETY: as above.
        let Some(sign) = (unsafe {
            href_of(
                sign_method_id,
                here,
                c"signMethodId != NULL",
                c"signMethodId->href != NULL",
            )
        }) else {
            return std::ptr::null_mut();
        };
        // SAFETY: handles are validated by each call; the node is freed on
        // every failure.
        unsafe {
            let sign_node = xsNewDocNode(
                doc,
                std::ptr::null_mut(),
                name(&xmlSecNodeSignature),
                std::ptr::null(),
            );
            if sign_node.is_null() {
                errors::xml_failed_with(here, std::ptr::null(), c"xmlNewDocNode", "node=Signature");
                return std::ptr::null_mut();
            }
            let ns = xsNewNs(sign_node, name(&xmlSecDSigNs), ns_prefix);
            if ns.is_null() {
                errors::xml_failed_with(
                    here,
                    std::ptr::null(),
                    c"xmlNewNs",
                    &format!("ns={}", text(&xmlSecDSigNs)),
                );
                xsFreeNode(sign_node);
                return std::ptr::null_mut();
            }
            xsSetNs(sign_node, ns);
            optional(sign_node, b"Id\0", id);
            let built = (|| {
                let signed_info = add(
                    sign_node,
                    &xmlSecNodeSignedInfo,
                    &xmlSecDSigNs,
                    c"xmlSecAddChild(xmlSecNodeSignedInfo)",
                    here,
                );
                if signed_info.is_null()
                    || add(
                        sign_node,
                        &xmlSecNodeSignatureValue,
                        &xmlSecDSigNs,
                        c"xmlSecAddChild(xmlSecNodeSignatureValue)",
                        here,
                    )
                    .is_null()
                {
                    return false;
                }
                let c14n_node = add(
                    signed_info,
                    &xmlSecNodeCanonicalizationMethod,
                    &xmlSecDSigNs,
                    c"xmlSecAddChild(xmlSecNodeCanonicalizationMethod)",
                    here,
                );
                if c14n_node.is_null() || !set_algorithm(c14n_node, c14n, here) {
                    return false;
                }
                let sign_method = add(
                    signed_info,
                    &xmlSecNodeSignatureMethod,
                    &xmlSecDSigNs,
                    c"xmlSecAddChild(xmlSecNodeSignatureMethod)",
                    here,
                );
                !sign_method.is_null() && set_algorithm(sign_method, sign, here)
            })();
            if !built {
                xsFreeNode(sign_node);
                return std::ptr::null_mut();
            }
            sign_node
        }
    })
}

/// `xmlSecTmplSignatureEnsureKeyInfo`: the `KeyInfo` of `sign_node`, added
/// after `SignatureValue` when absent, with `Id` set when `id` is set.
///
/// # Safety
/// `sign_node` is null or a live node; `id` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplSignatureEnsureKeyInfo(
    sign_node: *mut XmlNode,
    id: *const u8,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !sign_node.is_null(),
            "xmlSecTmplSignatureEnsureKeyInfo",
            c"signNode != NULL",
            std::ptr::null_mut()
        );
        let here = here!("xmlSecTmplSignatureEnsureKeyInfo");
        // SAFETY: `sign_node` is live.
        unsafe {
            let mut res = xmlSecFindChild(sign_node, name(&xmlSecNodeKeyInfo), name(&xmlSecDSigNs));
            if res.is_null() {
                let value = required(sign_node, &xmlSecNodeSignatureValue, &xmlSecDSigNs, here);
                if value.is_null() {
                    return std::ptr::null_mut();
                }
                res = xmlSecAddNextSibling(value, name(&xmlSecNodeKeyInfo), name(&xmlSecDSigNs));
                if res.is_null() {
                    errors::internal(
                        here,
                        std::ptr::null(),
                        c"xmlSecAddNextSibling(xmlSecNodeKeyInfo)",
                    );
                    return std::ptr::null_mut();
                }
            }
            optional(res, &xmlSecAttrId, id);
            res
        }
    })
}

/// A `<Reference>` appended to `parent` with its attributes, its digest
/// method and an empty `DigestValue`.
///
/// # Safety
/// `parent` is a live node; `digest` is NUL-terminated; the attributes are
/// null or NUL-terminated.
unsafe fn add_reference(
    parent: *mut XmlNode,
    digest: *const u8,
    id: *const u8,
    uri: *const u8,
    kind: *const u8,
    here: Here,
) -> *mut XmlNode {
    // SAFETY: by the caller's contract; a partial reference is removed.
    unsafe {
        let res = add(
            parent,
            &xmlSecNodeReference,
            &xmlSecDSigNs,
            c"xmlSecAddChild(xmlSecNodeReference)",
            here,
        );
        if res.is_null() {
            return res;
        }
        optional(res, &xmlSecAttrId, id);
        optional(res, &xmlSecAttrType, kind);
        optional(res, &xmlSecAttrURI, uri);
        let method = add(
            res,
            &xmlSecNodeDigestMethod,
            &xmlSecDSigNs,
            c"xmlSecAddChild(xmlSecNodeDigestMethod)",
            here,
        );
        if method.is_null()
            || !set_algorithm(method, digest, here)
            || add(
                res,
                &xmlSecNodeDigestValue,
                &xmlSecDSigNs,
                c"xmlSecAddChild(xmlSecNodeDigestValue)",
                here,
            )
            .is_null()
        {
            discard(res);
            return std::ptr::null_mut();
        }
        res
    }
}

/// `xmlSecTmplSignatureAddReference`: a `<Reference>` in the `SignedInfo`
/// of `sign_node`.
///
/// # Safety
/// `sign_node` is null or a live node; `digest_method_id` null or a
/// transform klass; the attributes null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplSignatureAddReference(
    sign_node: *mut XmlNode,
    digest_method_id: *const XmlSecTransformKlass,
    id: *const u8,
    uri: *const u8,
    kind: *const u8,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !sign_node.is_null(),
            "xmlSecTmplSignatureAddReference",
            c"signNode != NULL",
            std::ptr::null_mut()
        );
        let here = here!("xmlSecTmplSignatureAddReference");
        // SAFETY: a transform klass or null.
        let Some(digest) = (unsafe {
            href_of(
                digest_method_id,
                here,
                c"digestMethodId != NULL",
                c"digestMethodId->href != NULL",
            )
        }) else {
            return std::ptr::null_mut();
        };
        // SAFETY: `sign_node` is live.
        unsafe {
            let signed_info = required(sign_node, &xmlSecNodeSignedInfo, &xmlSecDSigNs, here);
            if signed_info.is_null() {
                return std::ptr::null_mut();
            }
            add_reference(
                signed_info,
                digest,
                id,
                uri,
                kind,
                here!("xmlSecTmplAddReference"),
            )
        }
    })
}

/// `xmlSecTmplSignatureAddObject`: an `<Object>` appended to `sign_node`.
///
/// # Safety
/// `sign_node` is null or a live node; the attributes null or
/// NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplSignatureAddObject(
    sign_node: *mut XmlNode,
    id: *const u8,
    mime_type: *const u8,
    encoding: *const u8,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !sign_node.is_null(),
            "xmlSecTmplSignatureAddObject",
            c"signNode != NULL",
            std::ptr::null_mut()
        );
        let here = here!("xmlSecTmplSignatureAddObject");
        // SAFETY: `sign_node` is live.
        unsafe {
            let res = add(
                sign_node,
                &xmlSecNodeObject,
                &xmlSecDSigNs,
                c"xmlSecAddChild(xmlSecNodeObject)",
                here,
            );
            if !res.is_null() {
                optional(res, &xmlSecAttrId, id);
                optional(res, &xmlSecAttrMimeType, mime_type);
                optional(res, &xmlSecAttrEncoding, encoding);
            }
            res
        }
    })
}

/// The child `node` of the `SignedInfo` of `sign_node`.
///
/// # Safety
/// `sign_node` is a live node.
unsafe fn signed_info_child(
    sign_node: *mut XmlNode,
    node: &'static [u8],
    here: Here,
) -> *mut XmlNode {
    // SAFETY: by the caller's contract.
    unsafe {
        let signed_info = required(sign_node, &xmlSecNodeSignedInfo, &xmlSecDSigNs, here);
        if signed_info.is_null() {
            return signed_info;
        }
        xmlSecFindChild(signed_info, name(node), name(&xmlSecDSigNs))
    }
}

/// `xmlSecTmplSignatureGetSignMethodNode`: the `SignatureMethod` of
/// `sign_node`.
///
/// # Safety
/// `sign_node` is null or a live node.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplSignatureGetSignMethodNode(
    sign_node: *mut XmlNode,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !sign_node.is_null(),
            "xmlSecTmplSignatureGetSignMethodNode",
            c"signNode != NULL",
            std::ptr::null_mut()
        );
        // SAFETY: `sign_node` is live.
        unsafe {
            signed_info_child(
                sign_node,
                &xmlSecNodeSignatureMethod,
                here!("xmlSecTmplSignatureGetSignMethodNode"),
            )
        }
    })
}

/// `xmlSecTmplSignatureGetC14NMethodNode`: the `CanonicalizationMethod` of
/// `sign_node`.
///
/// # Safety
/// `sign_node` is null or a live node.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplSignatureGetC14NMethodNode(
    sign_node: *mut XmlNode,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !sign_node.is_null(),
            "xmlSecTmplSignatureGetC14NMethodNode",
            c"signNode != NULL",
            std::ptr::null_mut()
        );
        // SAFETY: `sign_node` is live.
        unsafe {
            signed_info_child(
                sign_node,
                &xmlSecNodeCanonicalizationMethod,
                here!("xmlSecTmplSignatureGetC14NMethodNode"),
            )
        }
    })
}

/// A `<Transform>` of algorithm `href` in the `Transforms` child of
/// `parent` (namespace `transforms_ns`), created at the end when absent.
///
/// # Safety
/// `parent` is a live node; `href` is NUL-terminated.
unsafe fn add_transform(
    parent: *mut XmlNode,
    transforms: *mut XmlNode,
    transforms_ns: &'static [u8],
    href: *const u8,
    here: Here,
) -> *mut XmlNode {
    // SAFETY: by the caller's contract.
    unsafe {
        let transforms = if transforms.is_null() {
            let added = add(
                parent,
                &xmlSecNodeTransforms,
                transforms_ns,
                c"xmlSecAddChild(xmlSecNodeTransforms)",
                here,
            );
            if added.is_null() {
                return added;
            }
            added
        } else {
            transforms
        };
        let res = add(
            transforms,
            &xmlSecNodeTransform,
            &xmlSecDSigNs,
            c"xmlSecAddChild(xmlSecNodeTransform)",
            here,
        );
        if res.is_null() {
            return res;
        }
        if !set_algorithm(res, href, here) {
            discard(res);
            return std::ptr::null_mut();
        }
        res
    }
}

/// `xmlSecTmplReferenceAddTransform`: a `<Transform>` in the `Transforms`
/// of `reference_node`, which is created before its first element child
/// when absent.
///
/// # Safety
/// `reference_node` is null or a live node; `transform_id` null or a
/// transform klass.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplReferenceAddTransform(
    reference_node: *mut XmlNode,
    transform_id: *const XmlSecTransformKlass,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !reference_node.is_null(),
            "xmlSecTmplReferenceAddTransform",
            c"referenceNode != NULL",
            std::ptr::null_mut()
        );
        let here = here!("xmlSecTmplReferenceAddTransform");
        // SAFETY: a transform klass or null.
        let Some(href) = (unsafe {
            href_of(
                transform_id,
                here,
                c"transformId != NULL",
                c"transformId->href != NULL",
            )
        }) else {
            return std::ptr::null_mut();
        };
        // SAFETY: `reference_node` is live.
        unsafe {
            let mut transforms = xmlSecFindChild(
                reference_node,
                name(&xmlSecNodeTransforms),
                name(&xmlSecDSigNs),
            );
            if transforms.is_null() {
                let first = xmlSecGetNextElementNode(nodes::first_child(reference_node));
                if !first.is_null() {
                    transforms = xmlSecAddPrevSibling(
                        first,
                        name(&xmlSecNodeTransforms),
                        name(&xmlSecDSigNs),
                    );
                    if transforms.is_null() {
                        errors::internal(
                            here,
                            std::ptr::null(),
                            c"xmlSecAddPrevSibling(xmlSecNodeTransforms)",
                        );
                        return std::ptr::null_mut();
                    }
                }
            }
            add_transform(reference_node, transforms, &xmlSecDSigNs, href, here)
        }
    })
}

/// `xmlSecTmplObjectAddSignProperties`: a `<SignatureProperties>` appended
/// to `object_node`.
///
/// # Safety
/// `object_node` is null or a live node; the attributes null or
/// NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplObjectAddSignProperties(
    object_node: *mut XmlNode,
    id: *const u8,
    target: *const u8,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !object_node.is_null(),
            "xmlSecTmplObjectAddSignProperties",
            c"objectNode != NULL",
            std::ptr::null_mut()
        );
        let here = here!("xmlSecTmplObjectAddSignProperties");
        // SAFETY: `object_node` is live.
        unsafe {
            let res = add(
                object_node,
                &xmlSecNodeSignatureProperties,
                &xmlSecDSigNs,
                c"xmlSecAddChild(xmlSecNodeSignatureProperties)",
                here,
            );
            if !res.is_null() {
                optional(res, &xmlSecAttrId, id);
                optional(res, &xmlSecAttrTarget, target);
            }
            res
        }
    })
}

/// `xmlSecTmplObjectAddManifest`: a `<Manifest>` appended to `object_node`.
///
/// # Safety
/// `object_node` is null or a live node; `id` null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplObjectAddManifest(
    object_node: *mut XmlNode,
    id: *const u8,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !object_node.is_null(),
            "xmlSecTmplObjectAddManifest",
            c"objectNode != NULL",
            std::ptr::null_mut()
        );
        let here = here!("xmlSecTmplObjectAddManifest");
        // SAFETY: `object_node` is live.
        unsafe {
            let res = add(
                object_node,
                &xmlSecNodeManifest,
                &xmlSecDSigNs,
                c"xmlSecAddChild(xmlSecNodeManifest)",
                here,
            );
            if !res.is_null() {
                optional(res, &xmlSecAttrId, id);
            }
            res
        }
    })
}

/// `xmlSecTmplManifestAddReference`: a `<Reference>` appended to
/// `manifest_node`.
///
/// # Safety
/// As for [`xmlSecTmplSignatureAddReference`], for `manifest_node`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplManifestAddReference(
    manifest_node: *mut XmlNode,
    digest_method_id: *const XmlSecTransformKlass,
    id: *const u8,
    uri: *const u8,
    kind: *const u8,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        let here = here!("xmlSecTmplAddReference");
        check!(
            !manifest_node.is_null(),
            "xmlSecTmplAddReference",
            c"parentNode != NULL",
            std::ptr::null_mut()
        );
        // SAFETY: a transform klass or null.
        let Some(digest) = (unsafe {
            href_of(
                digest_method_id,
                here,
                c"digestMethodId != NULL",
                c"digestMethodId->href != NULL",
            )
        }) else {
            return std::ptr::null_mut();
        };
        // SAFETY: `manifest_node` is live.
        unsafe { add_reference(manifest_node, digest, id, uri, kind, here) }
    })
}

// ----------------------------------------------------------------------------
// <enc:EncryptedData/> and <enc:EncryptedKey/>

/// Adds the `EncryptionMethod` (when `method` is set) and `CipherData`
/// children of an encrypted element.
///
/// # Safety
/// `parent` is a live node; `method` null or a transform klass.
unsafe fn prepare_enc_data(parent: *mut XmlNode, method: *const XmlSecTransformKlass) -> bool {
    let here = here!("xmlSecTmplPrepareEncData");
    // SAFETY: by the caller's contract.
    unsafe {
        if let Some(klass) = method.as_ref() {
            if klass.href.is_null() {
                errors::assertion(
                    here,
                    c"(encMethodId == NULL) || (encMethodId->href != NULL)",
                );
                return false;
            }
            let cur = add(
                parent,
                &xmlSecNodeEncryptionMethod,
                &xmlSecEncNs,
                c"xmlSecAddChild(xmlSecNodeEncryptionMethod)",
                here,
            );
            if cur.is_null() || !set_algorithm(cur, klass.href, here) {
                return false;
            }
        }
        !add(
            parent,
            &xmlSecNodeCipherData,
            &xmlSecEncNs,
            c"xmlSecAddChild(xmlSecNodeCipherData)",
            here,
        )
        .is_null()
    }
}

/// `xmlSecTmplEncDataCreate`: a detached `<EncryptedData>` with its
/// attributes, its encryption method when `enc_method_id` is set and an
/// empty `CipherData`.
///
/// # Safety
/// `doc` is null or a live document; `enc_method_id` null or a transform
/// klass; the attributes null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplEncDataCreate(
    doc: *mut XmlDoc,
    enc_method_id: *const XmlSecTransformKlass,
    id: *const u8,
    kind: *const u8,
    mime_type: *const u8,
    encoding: *const u8,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        let here = here!("xmlSecTmplEncDataCreate");
        // SAFETY: handles are validated by each call; the node is freed on
        // failure.
        unsafe {
            let enc_node = xsNewDocNode(
                doc,
                std::ptr::null_mut(),
                name(&xmlSecNodeEncryptedData),
                std::ptr::null(),
            );
            if enc_node.is_null() {
                errors::xml_failed_with(
                    here,
                    std::ptr::null(),
                    c"xmlNewDocNode",
                    "node=EncryptedData",
                );
                return std::ptr::null_mut();
            }
            let ns = xsNewNs(enc_node, name(&xmlSecEncNs), std::ptr::null());
            if ns.is_null() {
                errors::xml_failed_with(
                    here,
                    std::ptr::null(),
                    c"xmlNewNs",
                    &format!("ns={}", text(&xmlSecEncNs)),
                );
                // libxmlsec1 leaks the node here; it is freed instead.
                xsFreeNode(enc_node);
                return std::ptr::null_mut();
            }
            xsSetNs(enc_node, ns);
            optional(enc_node, &xmlSecAttrId, id);
            optional(enc_node, &xmlSecAttrType, kind);
            optional(enc_node, &xmlSecAttrMimeType, mime_type);
            optional(enc_node, &xmlSecAttrEncoding, encoding);
            if !prepare_enc_data(enc_node, enc_method_id) {
                xsFreeNode(enc_node);
                return std::ptr::null_mut();
            }
            enc_node
        }
    })
}

/// `xmlSecTmplEncDataEnsureKeyInfo`: the `KeyInfo` of `enc_node`, added
/// before `CipherData` when absent, with `Id` set when `id` is set.
///
/// # Safety
/// `enc_node` is null or a live node; `id` null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplEncDataEnsureKeyInfo(
    enc_node: *mut XmlNode,
    id: *const u8,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !enc_node.is_null(),
            "xmlSecTmplEncDataEnsureKeyInfo",
            c"encNode != NULL",
            std::ptr::null_mut()
        );
        let here = here!("xmlSecTmplEncDataEnsureKeyInfo");
        // SAFETY: `enc_node` is live.
        unsafe {
            let mut res = xmlSecFindChild(enc_node, name(&xmlSecNodeKeyInfo), name(&xmlSecDSigNs));
            if res.is_null() {
                let cipher_data = required(enc_node, &xmlSecNodeCipherData, &xmlSecEncNs, here);
                if cipher_data.is_null() {
                    return std::ptr::null_mut();
                }
                res = xmlSecAddPrevSibling(
                    cipher_data,
                    name(&xmlSecNodeKeyInfo),
                    name(&xmlSecDSigNs),
                );
                if res.is_null() {
                    errors::internal(
                        here,
                        std::ptr::null(),
                        c"xmlSecAddPrevSibling(xmlSecNodeKeyInfo)",
                    );
                    return std::ptr::null_mut();
                }
            }
            optional(res, &xmlSecAttrId, id);
            res
        }
    })
}

/// `xmlSecTmplEncDataEnsureEncProperties`: the `EncryptionProperties` of
/// `enc_node`, appended when absent, with `Id` set when `id` is set.
///
/// # Safety
/// `enc_node` is null or a live node; `id` null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplEncDataEnsureEncProperties(
    enc_node: *mut XmlNode,
    id: *const u8,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !enc_node.is_null(),
            "xmlSecTmplEncDataEnsureEncProperties",
            c"encNode != NULL",
            std::ptr::null_mut()
        );
        let here = here!("xmlSecTmplEncDataEnsureEncProperties");
        // SAFETY: `enc_node` is live.
        unsafe {
            let mut res = xmlSecFindChild(
                enc_node,
                name(&xmlSecNodeEncryptionProperties),
                name(&xmlSecEncNs),
            );
            if res.is_null() {
                res = add(
                    enc_node,
                    &xmlSecNodeEncryptionProperties,
                    &xmlSecEncNs,
                    c"xmlSecAddChild(xmlSecNodeEncryptionProperties)",
                    here,
                );
                if res.is_null() {
                    return res;
                }
            }
            optional(res, &xmlSecAttrId, id);
            res
        }
    })
}

/// `xmlSecTmplEncDataAddEncProperty`: an `<EncryptionProperty>` in the
/// `EncryptionProperties` of `enc_node`.
///
/// # Safety
/// `enc_node` is null or a live node; the attributes null or
/// NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplEncDataAddEncProperty(
    enc_node: *mut XmlNode,
    id: *const u8,
    target: *const u8,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !enc_node.is_null(),
            "xmlSecTmplEncDataAddEncProperty",
            c"encNode != NULL",
            std::ptr::null_mut()
        );
        let here = here!("xmlSecTmplEncDataAddEncProperty");
        // SAFETY: `enc_node` is live.
        unsafe {
            let props = xmlSecTmplEncDataEnsureEncProperties(enc_node, std::ptr::null());
            if props.is_null() {
                errors::internal(
                    here,
                    std::ptr::null(),
                    c"xmlSecTmplEncDataEnsureEncProperties",
                );
                return props;
            }
            let res = add(
                props,
                &xmlSecNodeEncryptionProperty,
                &xmlSecEncNs,
                c"xmlSecAddChild(xmlSecNodeEncryptionProperty)",
                here,
            );
            if !res.is_null() {
                optional(res, &xmlSecAttrId, id);
                optional(res, &xmlSecAttrTarget, target);
            }
            res
        }
    })
}

/// The `CipherData` child `want` of `enc_node` when its sibling form
/// `other` is absent, appended when missing.
///
/// # Safety
/// `enc_node` is a live node.
unsafe fn ensure_cipher(
    enc_node: *mut XmlNode,
    want: &'static [u8],
    other: &'static [u8],
    failed: &CStr,
    here: Here,
) -> *mut XmlNode {
    // SAFETY: by the caller's contract.
    unsafe {
        let cipher_data = required(enc_node, &xmlSecNodeCipherData, &xmlSecEncNs, here);
        if cipher_data.is_null() || present(cipher_data, other, &xmlSecEncNs, here) {
            return std::ptr::null_mut();
        }
        let res = xmlSecFindChild(cipher_data, name(want), name(&xmlSecEncNs));
        if !res.is_null() {
            return res;
        }
        add(cipher_data, want, &xmlSecEncNs, failed, here)
    }
}

/// `xmlSecTmplEncDataEnsureCipherValue`: the `CipherValue` of the
/// `CipherData` of `enc_node`; refused when it holds a `CipherReference`.
///
/// # Safety
/// `enc_node` is null or a live node.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplEncDataEnsureCipherValue(
    enc_node: *mut XmlNode,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !enc_node.is_null(),
            "xmlSecTmplEncDataEnsureCipherValue",
            c"encNode != NULL",
            std::ptr::null_mut()
        );
        // SAFETY: `enc_node` is live.
        unsafe {
            ensure_cipher(
                enc_node,
                &xmlSecNodeCipherValue,
                &xmlSecNodeCipherReference,
                c"xmlSecAddChild(xmlSecNodeCipherValue)",
                here!("xmlSecTmplEncDataEnsureCipherValue"),
            )
        }
    })
}

/// `xmlSecTmplEncDataEnsureCipherReference`: the `CipherReference` of the
/// `CipherData` of `enc_node` with `URI` set when `uri` is set; refused when
/// it holds a `CipherValue`.
///
/// # Safety
/// `enc_node` is null or a live node; `uri` null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplEncDataEnsureCipherReference(
    enc_node: *mut XmlNode,
    uri: *const u8,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !enc_node.is_null(),
            "xmlSecTmplEncDataEnsureCipherReference",
            c"encNode != NULL",
            std::ptr::null_mut()
        );
        // SAFETY: `enc_node` is live.
        unsafe {
            let res = ensure_cipher(
                enc_node,
                &xmlSecNodeCipherReference,
                &xmlSecNodeCipherValue,
                c"xmlSecAddChild(xmlSecNodeCipherReference)",
                here!("xmlSecTmplEncDataEnsureCipherReference"),
            );
            if !res.is_null() {
                optional(res, &xmlSecAttrURI, uri);
            }
            res
        }
    })
}

/// `xmlSecTmplEncDataGetEncMethodNode`: the `EncryptionMethod` of
/// `enc_node`.
///
/// # Safety
/// `enc_node` is null or a live node.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplEncDataGetEncMethodNode(
    enc_node: *mut XmlNode,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !enc_node.is_null(),
            "xmlSecTmplEncDataGetEncMethodNode",
            c"encNode != NULL",
            std::ptr::null_mut()
        );
        // SAFETY: `enc_node` is live.
        unsafe {
            xmlSecFindChild(
                enc_node,
                name(&xmlSecNodeEncryptionMethod),
                name(&xmlSecEncNs),
            )
        }
    })
}

/// `xmlSecTmplCipherReferenceAddTransform`: a `<Transform>` in the `XMLEnc`
/// `Transforms` of `cipher_reference_node`.
///
/// # Safety
/// `cipher_reference_node` is null or a live node; `transform_id` null or
/// a transform klass.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplCipherReferenceAddTransform(
    cipher_reference_node: *mut XmlNode,
    transform_id: *const XmlSecTransformKlass,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !cipher_reference_node.is_null(),
            "xmlSecTmplCipherReferenceAddTransform",
            c"cipherReferenceNode != NULL",
            std::ptr::null_mut()
        );
        let here = here!("xmlSecTmplCipherReferenceAddTransform");
        // SAFETY: a transform klass or null.
        let Some(href) = (unsafe {
            href_of(
                transform_id,
                here,
                c"transformId != NULL",
                c"transformId->href != NULL",
            )
        }) else {
            return std::ptr::null_mut();
        };
        // SAFETY: `cipher_reference_node` is live.
        unsafe {
            let transforms = xmlSecFindChild(
                cipher_reference_node,
                name(&xmlSecNodeTransforms),
                name(&xmlSecEncNs),
            );
            add_transform(cipher_reference_node, transforms, &xmlSecEncNs, href, here)
        }
    })
}

/// A reference `node` with `URI` set when `uri` is set, in the
/// `ReferenceList` of `enc_node`.
///
/// # Safety
/// `enc_node` is a live node; `uri` null or NUL-terminated.
unsafe fn add_list_reference(
    enc_node: *mut XmlNode,
    node: &'static [u8],
    failed: &CStr,
    uri: *const u8,
    here: Here,
) -> *mut XmlNode {
    // SAFETY: by the caller's contract.
    unsafe {
        let mut list =
            xmlSecFindChild(enc_node, name(&xmlSecNodeReferenceList), name(&xmlSecEncNs));
        if list.is_null() {
            list = add(
                enc_node,
                &xmlSecNodeReferenceList,
                &xmlSecEncNs,
                c"xmlSecAddChild(xmlSecNodeReferenceList)",
                here,
            );
            if list.is_null() {
                return list;
            }
        }
        let res = add(list, node, &xmlSecEncNs, failed, here);
        if res.is_null() || uri.is_null() {
            return res;
        }
        if xsSetProp(res, name(&xmlSecAttrURI), uri).is_null() {
            errors::xml_failed_with(here, std::ptr::null(), c"xmlSetProp", "name=URI");
            discard(res);
            return std::ptr::null_mut();
        }
        res
    }
}

/// `xmlSecTmplReferenceListAddDataReference`: a `<DataReference>` in the
/// `ReferenceList` of `enc_node`.
///
/// # Safety
/// `enc_node` is null or a live node; `uri` null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplReferenceListAddDataReference(
    enc_node: *mut XmlNode,
    uri: *const u8,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !enc_node.is_null(),
            "xmlSecTmplReferenceListAddDataReference",
            c"encNode != NULL",
            std::ptr::null_mut()
        );
        // SAFETY: `enc_node` is live.
        unsafe {
            add_list_reference(
                enc_node,
                &xmlSecNodeDataReference,
                c"xmlSecAddChild(xmlSecNodeDataReference)",
                uri,
                here!("xmlSecTmplReferenceListAddDataReference"),
            )
        }
    })
}

/// `xmlSecTmplReferenceListAddKeyReference`: a `<KeyReference>` in the
/// `ReferenceList` of `enc_node`.
///
/// # Safety
/// `enc_node` is null or a live node; `uri` null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplReferenceListAddKeyReference(
    enc_node: *mut XmlNode,
    uri: *const u8,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !enc_node.is_null(),
            "xmlSecTmplReferenceListAddKeyReference",
            c"encNode != NULL",
            std::ptr::null_mut()
        );
        // SAFETY: `enc_node` is live.
        unsafe {
            add_list_reference(
                enc_node,
                &xmlSecNodeKeyReference,
                c"xmlSecAddChild(xmlSecNodeKeyReference)",
                uri,
                here!("xmlSecTmplReferenceListAddKeyReference"),
            )
        }
    })
}

// ----------------------------------------------------------------------------
// <dsig:KeyInfo/> and <dsig:X509Data/>

/// An element `node` appended to `parent` whose escaped content is `value`
/// when set.
///
/// # Safety
/// `parent` is a live node; `value` null or NUL-terminated.
unsafe fn add_text(
    parent: *mut XmlNode,
    node: &'static [u8],
    failed: &CStr,
    value: *const u8,
    here: Here,
) -> *mut XmlNode {
    // SAFETY: by the caller's contract.
    unsafe {
        let res = add(parent, node, &xmlSecDSigNs, failed, here);
        if !res.is_null() && !value.is_null() && xmlSecNodeEncodeAndSetContent(res, value) < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecNodeEncodeAndSetContent");
            return std::ptr::null_mut();
        }
        res
    }
}

/// `xmlSecTmplKeyInfoAddKeyName`: a `<KeyName>` holding `name_` when set,
/// appended to `key_info_node`.
///
/// # Safety
/// `key_info_node` is null or a live node; `name_` null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplKeyInfoAddKeyName(
    key_info_node: *mut XmlNode,
    name_: *const u8,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !key_info_node.is_null(),
            "xmlSecTmplKeyInfoAddKeyName",
            c"keyInfoNode != NULL",
            std::ptr::null_mut()
        );
        // SAFETY: `key_info_node` is live.
        unsafe {
            add_text(
                key_info_node,
                &xmlSecNodeKeyName,
                c"xmlSecAddChild(xmlSecNodeKeyName)",
                name_,
                here!("xmlSecTmplKeyInfoAddKeyName"),
            )
        }
    })
}

/// `xmlSecTmplKeyInfoAddKeyValue`: a `<KeyValue>` appended to
/// `key_info_node`.
///
/// # Safety
/// `key_info_node` is null or a live node.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplKeyInfoAddKeyValue(
    key_info_node: *mut XmlNode,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !key_info_node.is_null(),
            "xmlSecTmplKeyInfoAddKeyValue",
            c"keyInfoNode != NULL",
            std::ptr::null_mut()
        );
        // SAFETY: `key_info_node` is live.
        unsafe {
            add(
                key_info_node,
                &xmlSecNodeKeyValue,
                &xmlSecDSigNs,
                c"xmlSecAddChild(xmlSecNodeKeyValue)",
                here!("xmlSecTmplKeyInfoAddKeyValue"),
            )
        }
    })
}

/// `xmlSecTmplKeyInfoAddX509Data`: an `<X509Data>` appended to
/// `key_info_node`.
///
/// # Safety
/// `key_info_node` is null or a live node.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplKeyInfoAddX509Data(
    key_info_node: *mut XmlNode,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !key_info_node.is_null(),
            "xmlSecTmplKeyInfoAddX509Data",
            c"keyInfoNode != NULL",
            std::ptr::null_mut()
        );
        // SAFETY: `key_info_node` is live.
        unsafe {
            add(
                key_info_node,
                &xmlSecNodeX509Data,
                &xmlSecDSigNs,
                c"xmlSecAddChild(xmlSecNodeX509Data)",
                here!("xmlSecTmplKeyInfoAddX509Data"),
            )
        }
    })
}

/// `xmlSecTmplKeyInfoAddRetrievalMethod`: a `<RetrievalMethod>` with its
/// attributes appended to `key_info_node`.
///
/// # Safety
/// `key_info_node` is null or a live node; the attributes null or
/// NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplKeyInfoAddRetrievalMethod(
    key_info_node: *mut XmlNode,
    uri: *const u8,
    kind: *const u8,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !key_info_node.is_null(),
            "xmlSecTmplKeyInfoAddRetrievalMethod",
            c"keyInfoNode != NULL",
            std::ptr::null_mut()
        );
        let here = here!("xmlSecTmplKeyInfoAddRetrievalMethod");
        // SAFETY: `key_info_node` is live.
        unsafe {
            let res = add(
                key_info_node,
                &xmlSecNodeRetrievalMethod,
                &xmlSecDSigNs,
                c"xmlSecAddChild(xmlSecNodeRetrievalMethod)",
                here,
            );
            if !res.is_null() {
                optional(res, &xmlSecAttrURI, uri);
                optional(res, &xmlSecAttrType, kind);
            }
            res
        }
    })
}

/// `xmlSecTmplRetrievalMethodAddTransform`: a `<Transform>` in the
/// `Transforms` of `retr_method_node`.
///
/// # Safety
/// `retr_method_node` is null or a live node; `transform_id` null or a
/// transform klass.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplRetrievalMethodAddTransform(
    retr_method_node: *mut XmlNode,
    transform_id: *const XmlSecTransformKlass,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !retr_method_node.is_null(),
            "xmlSecTmplRetrievalMethodAddTransform",
            c"retrMethodNode != NULL",
            std::ptr::null_mut()
        );
        let here = here!("xmlSecTmplRetrievalMethodAddTransform");
        // SAFETY: a transform klass or null.
        let Some(href) = (unsafe {
            href_of(
                transform_id,
                here,
                c"transformId != NULL",
                c"transformId->href != NULL",
            )
        }) else {
            return std::ptr::null_mut();
        };
        // SAFETY: `retr_method_node` is live.
        unsafe {
            let transforms = xmlSecFindChild(
                retr_method_node,
                name(&xmlSecNodeTransforms),
                name(&xmlSecDSigNs),
            );
            add_transform(retr_method_node, transforms, &xmlSecDSigNs, href, here)
        }
    })
}

/// `xmlSecTmplKeyInfoAddEncryptedKey`: an `<EncryptedKey>` with its
/// attributes, encryption method and `CipherData` appended to
/// `key_info_node`.
///
/// # Safety
/// `key_info_node` is null or a live node; `enc_method_id` null or a
/// transform klass; the attributes null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplKeyInfoAddEncryptedKey(
    key_info_node: *mut XmlNode,
    enc_method_id: *const XmlSecTransformKlass,
    id: *const u8,
    kind: *const u8,
    recipient: *const u8,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !key_info_node.is_null(),
            "xmlSecTmplKeyInfoAddEncryptedKey",
            c"keyInfoNode != NULL",
            std::ptr::null_mut()
        );
        let here = here!("xmlSecTmplKeyInfoAddEncryptedKey");
        // SAFETY: `key_info_node` is live; a partial element is removed.
        unsafe {
            let res = add(
                key_info_node,
                &xmlSecNodeEncryptedKey,
                &xmlSecEncNs,
                c"xmlSecAddChild(xmlSecNodeEncryptedKey)",
                here,
            );
            if res.is_null() {
                return res;
            }
            optional(res, &xmlSecAttrId, id);
            optional(res, &xmlSecAttrType, kind);
            optional(res, &xmlSecAttrRecipient, recipient);
            if !prepare_enc_data(res, enc_method_id) {
                discard(res);
                return std::ptr::null_mut();
            }
            res
        }
    })
}

/// A single child `node` in namespace `ns` appended to `parent`; refused
/// when `parent` already has one.
///
/// # Safety
/// `parent` is a live node.
unsafe fn add_once(
    parent: *mut XmlNode,
    node: &'static [u8],
    ns: &'static [u8],
    failed: &CStr,
    here: Here,
) -> *mut XmlNode {
    // SAFETY: by the caller's contract.
    unsafe {
        if present(parent, node, ns, here) {
            return std::ptr::null_mut();
        }
        add(parent, node, ns, failed, here)
    }
}

macro_rules! x509_child {
    ($func:ident, $name:literal, $node:ident, $failed:literal, $doc:literal) => {
        #[doc = concat!("`", $name, "`: ", $doc)]
        ///
        /// # Safety
        /// `x509_data_node` is null or a live node.
        #[unsafe(no_mangle)]
        pub(crate) unsafe extern "C" fn $func(x509_data_node: *mut XmlNode) -> *mut XmlNode {
            contain(std::ptr::null_mut(), || {
                check!(
                    !x509_data_node.is_null(),
                    $name,
                    c"x509DataNode != NULL",
                    std::ptr::null_mut()
                );
                // SAFETY: `x509_data_node` is live.
                unsafe { add_once(x509_data_node, &$node, &xmlSecDSigNs, $failed, here!($name)) }
            })
        }
    };
}

x509_child!(
    xmlSecTmplX509DataAddIssuerSerial,
    "xmlSecTmplX509DataAddIssuerSerial",
    xmlSecNodeX509IssuerSerial,
    c"xmlSecAddChild(xmlSecNodeX509IssuerSerial)",
    "the only `<X509IssuerSerial>` of `x509_data_node`."
);
x509_child!(
    xmlSecTmplX509DataAddSubjectName,
    "xmlSecTmplX509DataAddSubjectName",
    xmlSecNodeX509SubjectName,
    c"xmlSecAddChild(xmlSecNodeX509SubjectName)",
    "the only `<X509SubjectName>` of `x509_data_node`."
);
x509_child!(
    xmlSecTmplX509DataAddSKI,
    "xmlSecTmplX509DataAddSKI",
    xmlSecNodeX509SKI,
    c"xmlSecAddChild(xmlSecNodeX509SKI)",
    "the only `<X509SKI>` of `x509_data_node`."
);
x509_child!(
    xmlSecTmplX509DataAddCertificate,
    "xmlSecTmplX509DataAddCertificate",
    xmlSecNodeX509Certificate,
    c"xmlSecAddChild(xmlSecNodeX509Certificate)",
    "the only `<X509Certificate>` of `x509_data_node`."
);
x509_child!(
    xmlSecTmplX509DataAddCRL,
    "xmlSecTmplX509DataAddCRL",
    xmlSecNodeX509CRL,
    c"xmlSecAddChild(xmlSecNodeX509CRL)",
    "the only `<X509CRL>` of `x509_data_node`."
);

/// `xmlSecTmplX509DataAddDigest`: the only `XMLDSig` 1.1 `<X509Digest>` of
/// `x509_data_node`, of algorithm `digest_algorithm`.
///
/// # Safety
/// `x509_data_node` is null or a live node; `digest_algorithm` null or
/// NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplX509DataAddDigest(
    x509_data_node: *mut XmlNode,
    digest_algorithm: *const u8,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !x509_data_node.is_null(),
            "xmlSecTmplX509DataAddDigest",
            c"x509DataNode != NULL",
            std::ptr::null_mut()
        );
        check!(
            !digest_algorithm.is_null(),
            "xmlSecTmplX509DataAddDigest",
            c"digestAlgorithm != NULL",
            std::ptr::null_mut()
        );
        let here = here!("xmlSecTmplX509DataAddDigest");
        // SAFETY: `x509_data_node` is live; a partial element is removed.
        unsafe {
            let res = add_once(
                x509_data_node,
                &xmlSecNodeX509Digest,
                &xmlSecDSig11Ns,
                c"xmlSecAddChild(xmlSecNodeX509Digest)",
                here,
            );
            if !res.is_null() && !set_algorithm(res, digest_algorithm, here) {
                discard(res);
                return std::ptr::null_mut();
            }
            res
        }
    })
}

/// `xmlSecTmplX509IssuerSerialAddIssuerName`: the only `<X509IssuerName>`
/// of `x509_issuer_serial_node`, holding `issuer_name` when set.
///
/// # Safety
/// `x509_issuer_serial_node` is null or a live node; `issuer_name` null or
/// NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplX509IssuerSerialAddIssuerName(
    x509_issuer_serial_node: *mut XmlNode,
    issuer_name: *const u8,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !x509_issuer_serial_node.is_null(),
            "xmlSecTmplX509IssuerSerialAddIssuerName",
            c"x509IssuerSerialNode != NULL",
            std::ptr::null_mut()
        );
        let here = here!("xmlSecTmplX509IssuerSerialAddIssuerName");
        // SAFETY: the node is live.
        unsafe {
            if present(
                x509_issuer_serial_node,
                &xmlSecNodeX509IssuerName,
                &xmlSecDSigNs,
                here,
            ) {
                return std::ptr::null_mut();
            }
            add_text(
                x509_issuer_serial_node,
                &xmlSecNodeX509IssuerName,
                c"xmlSecAddChild(xmlSecNodeX509IssuerName)",
                issuer_name,
                here,
            )
        }
    })
}

/// `xmlSecTmplX509IssuerSerialAddSerialNumber`: the only
/// `<X509SerialNumber>` of `x509_issuer_serial_node`, holding `serial` when
/// set.
///
/// # Safety
/// `x509_issuer_serial_node` is null or a live node; `serial` null or
/// NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplX509IssuerSerialAddSerialNumber(
    x509_issuer_serial_node: *mut XmlNode,
    serial: *const u8,
) -> *mut XmlNode {
    contain(std::ptr::null_mut(), || {
        check!(
            !x509_issuer_serial_node.is_null(),
            "xmlSecTmplX509IssuerSerialAddSerialNumber",
            c"x509IssuerSerialNode != NULL",
            std::ptr::null_mut()
        );
        let here = here!("xmlSecTmplX509IssuerSerialAddSerialNumber");
        // SAFETY: the node is live.
        unsafe {
            if present(
                x509_issuer_serial_node,
                &xmlSecNodeX509SerialNumber,
                &xmlSecDSigNs,
                here,
            ) {
                return std::ptr::null_mut();
            }
            add_text(
                x509_issuer_serial_node,
                &xmlSecNodeX509SerialNumber,
                c"xmlSecAddChild(xmlSecNodeX509SerialNumber)",
                serial,
                here,
            )
        }
    })
}

// ----------------------------------------------------------------------------
// <dsig:Transform/> content

/// `xmlSecTmplTransformAddHmacOutputLength`: the only `<HMACOutputLength>`
/// of `transform_node`, holding `bits_len` in decimal.
///
/// # Safety
/// `transform_node` is null or a live node.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplTransformAddHmacOutputLength(
    transform_node: *mut XmlNode,
    bits_len: usize,
) -> c_int {
    contain(-1, || {
        check!(
            !transform_node.is_null(),
            "xmlSecTmplTransformAddHmacOutputLength",
            c"transformNode != NULL",
            -1
        );
        check!(
            bits_len > 0,
            "xmlSecTmplTransformAddHmacOutputLength",
            c"bitsLen > 0",
            -1
        );
        let here = here!("xmlSecTmplTransformAddHmacOutputLength");
        // SAFETY: `transform_node` is live; the content is NUL-terminated.
        unsafe {
            let cur = add_once(
                transform_node,
                &xmlSecNodeHMACOutputLength,
                &xmlSecDSigNs,
                c"xmlSecAddChild(xmlSecNodeHMACOutputLength)",
                here,
            );
            if cur.is_null() {
                return -1;
            }
            set_content(cur, &bits_len.to_string());
        }
        0
    })
}

/// `xmlSecTmplTransformAddRsaOaepParam`: the only `<OAEPparams>` of
/// `transform_node`, holding the Base64 of `size` bytes of `buf`.
///
/// # Safety
/// `transform_node` is null or a live node; `buf` null or holding `size`
/// bytes.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplTransformAddRsaOaepParam(
    transform_node: *mut XmlNode,
    buf: *const u8,
    size: usize,
) -> c_int {
    contain(-1, || {
        check!(
            !transform_node.is_null(),
            "xmlSecTmplTransformAddRsaOaepParam",
            c"transformNode != NULL",
            -1
        );
        check!(
            !buf.is_null(),
            "xmlSecTmplTransformAddRsaOaepParam",
            c"buf != NULL",
            -1
        );
        check!(
            size > 0,
            "xmlSecTmplTransformAddRsaOaepParam",
            c"size > 0",
            -1
        );
        let here = here!("xmlSecTmplTransformAddRsaOaepParam");
        // SAFETY: `transform_node` is live and `buf` holds `size` bytes; the
        // encoding is freed here.
        unsafe {
            let node = add_once(
                transform_node,
                &xmlSecNodeRsaOAEPparams,
                &xmlSecEncNs,
                c"xmlSecAddChild(xmlSecNodeRsaOAEPparams)",
                here,
            );
            if node.is_null() {
                return -1;
            }
            let base64 = xmlSecBase64Encode(buf, size, 0);
            if base64.is_null() {
                errors::internal_with(
                    here,
                    std::ptr::null(),
                    c"xmlSecBase64Encode",
                    &format!("size={size}"),
                );
                return -1;
            }
            if let Some(text) = c_text(base64) {
                set_content(node, text);
            }
            free(base64.cast());
        }
        0
    })
}

/// The only child `node` in namespace `ns` of `transform_node`, with its
/// `Algorithm` set to `algorithm`.
///
/// # Safety
/// `transform_node` is a live node; `algorithm` null or NUL-terminated.
unsafe fn add_algorithm_child(
    transform_node: *mut XmlNode,
    node: &'static [u8],
    ns: &'static [u8],
    failed: &CStr,
    algorithm: *const u8,
    here: Here,
) -> c_int {
    // SAFETY: by the caller's contract; a partial element is removed.
    unsafe {
        let cur = add_once(transform_node, node, ns, failed, here);
        if cur.is_null() {
            return -1;
        }
        if !set_algorithm(cur, algorithm, here) {
            discard(cur);
            return -1;
        }
    }
    0
}

/// `xmlSecTmplTransformAddRsaMgf`: the only `XMLEnc` 1.1 `<MGF>` of
/// `transform_node`, of algorithm `algorithm`.
///
/// # Safety
/// `transform_node` is null or a live node; `algorithm` null or
/// NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplTransformAddRsaMgf(
    transform_node: *mut XmlNode,
    algorithm: *const u8,
) -> c_int {
    contain(-1, || {
        check!(
            !transform_node.is_null(),
            "xmlSecTmplTransformAddRsaMgf",
            c"transformNode != NULL",
            -1
        );
        // SAFETY: `transform_node` is live.
        unsafe {
            add_algorithm_child(
                transform_node,
                &xmlSecNodeRsaMGF,
                &xmlSecEnc11Ns,
                c"xmlSecAddChild(xmlSecNodeRsaMgf)",
                algorithm,
                here!("xmlSecTmplTransformAddRsaMgf"),
            )
        }
    })
}

/// `xmlSecTmplTransformAddRsaDigest`: the only `<DigestMethod>` of
/// `transform_node`, of algorithm `algorithm`.
///
/// # Safety
/// `transform_node` is null or a live node; `algorithm` null or
/// NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplTransformAddRsaDigest(
    transform_node: *mut XmlNode,
    algorithm: *const u8,
) -> c_int {
    contain(-1, || {
        check!(
            !transform_node.is_null(),
            "xmlSecTmplTransformAddRsaDigest",
            c"transformNode != NULL",
            -1
        );
        // SAFETY: `transform_node` is live.
        unsafe {
            add_algorithm_child(
                transform_node,
                &xmlSecNodeDigestMethod,
                &xmlSecDSigNs,
                c"xmlSecAddChild(xmlSecNodeDigestMethod)",
                algorithm,
                here!("xmlSecTmplTransformAddRsaDigest"),
            )
        }
    })
}

/// `xmlSecTmplTransformAddXsltStylesheet`: replaces the content of
/// `transform_node` with the stylesheet `xslt`, parsed with the parser's
/// default options and pedantic checks.
///
/// # Safety
/// `transform_node` is null or a live node; `xslt` null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplTransformAddXsltStylesheet(
    transform_node: *mut XmlNode,
    xslt: *const u8,
) -> c_int {
    contain(-1, || {
        check!(
            !transform_node.is_null(),
            "xmlSecTmplTransformAddXsltStylesheet",
            c"transformNode != NULL",
            -1
        );
        check!(
            !xslt.is_null(),
            "xmlSecTmplTransformAddXsltStylesheet",
            c"xslt != NULL",
            -1
        );
        let here = here!("xmlSecTmplTransformAddXsltStylesheet");
        // SAFETY: `xslt` is NUL-terminated.
        let len = unsafe { CStr::from_ptr(xslt.cast()) }.to_bytes().len();
        let Ok(len) = c_int::try_from(len) else {
            errors::size_to_int_impossible(here, len);
            return -1;
        };
        // SAFETY: handles are validated by each call; `xslt` holds `len`
        // bytes; the parsed document is freed here once its root is copied
        // into the document of `transform_node`, where libxml2 moves it.
        unsafe {
            let doc = xsReadMemory(
                xslt.cast(),
                len,
                std::ptr::null(),
                std::ptr::null(),
                xmlSecParserGetDefaultOptions() | XML_PARSE_PEDANTIC | XML_PARSE_NODICT,
            );
            if doc.is_null() {
                errors::xml_failed(here, std::ptr::null(), c"xmlReadMemory");
                return -1;
            }
            let root = xsDocCopyNode(xsDocGetRootElement(doc), nodes::doc(transform_node), 1);
            xsFreeDoc(doc);
            if root.is_null() || xmlSecReplaceContent(transform_node, root) < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecReplaceContent");
                xsFreeNode(root);
                return -1;
            }
        }
        0
    })
}

/// `xmlSecTmplTransformAddC14NInclNamespaces`: the only Exclusive C14N
/// `<InclusiveNamespaces>` of `transform_node`, with `PrefixList` set to
/// `prefix_list`.
///
/// # Safety
/// `transform_node` is null or a live node; `prefix_list` null or
/// NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplTransformAddC14NInclNamespaces(
    transform_node: *mut XmlNode,
    prefix_list: *const u8,
) -> c_int {
    contain(-1, || {
        check!(
            !transform_node.is_null(),
            "xmlSecTmplTransformAddC14NInclNamespaces",
            c"transformNode != NULL",
            -1
        );
        check!(
            !prefix_list.is_null(),
            "xmlSecTmplTransformAddC14NInclNamespaces",
            c"prefixList != NULL",
            -1
        );
        let here = here!("xmlSecTmplTransformAddC14NInclNamespaces");
        // SAFETY: `transform_node` is live.
        unsafe {
            if present(
                transform_node,
                &xmlSecNodeInclusiveNamespaces,
                &xmlSecNsExcC14N,
                here,
            ) {
                return -1;
            }
            let cur = xmlSecAddChild(
                transform_node,
                name(&xmlSecNodeInclusiveNamespaces),
                name(&xmlSecNsExcC14N),
            );
            if cur.is_null() {
                errors::internal(
                    here,
                    name_for_report(transform_node).as_ptr(),
                    c"xmlSecAddChild(xmlSecNodeInclusiveNamespaces)",
                );
                return -1;
            }
            xsSetProp(cur, name(&xmlSecAttrPrefixList), prefix_list);
        }
        0
    })
}

/// Declares the prefix/href pairs of the null-terminated `ns_list` on
/// `parent`, `#default` meaning the default namespace.
///
/// # Safety
/// `parent` is a live node; `ns_list` a null-terminated list of
/// NUL-terminated strings.
unsafe fn write_ns_list(parent: *mut XmlNode, ns_list: *const *const u8) -> c_int {
    let here = here!("xmlSecTmplNodeWriteNsList");
    // SAFETY: by the caller's contract, every entry up to the terminator is
    // readable.
    unsafe {
        let mut ptr = ns_list;
        while !(*ptr).is_null() {
            let prefix = if xmlStrEqual(c"#default".as_ptr().cast(), *ptr) != 0 {
                std::ptr::null()
            } else {
                *ptr
            };
            ptr = ptr.add(1);
            let href = *ptr;
            if href.is_null() {
                errors::invalid_data(here, std::ptr::null(), "unexpected end of ns list");
                return -1;
            }
            if xsNewNs(parent, href, prefix).is_null() {
                let shown = if prefix.is_null() {
                    "NULL".into()
                } else {
                    CStr::from_ptr(prefix.cast()).to_string_lossy()
                };
                errors::xml_failed_with(
                    here,
                    std::ptr::null(),
                    c"xmlNewNs",
                    &format!("prefix={shown}"),
                );
                return -1;
            }
            ptr = ptr.add(1);
        }
    }
    0
}

/// An expression element `node` in namespace `ns` with the escaped
/// `expression` and the namespaces of `ns_list` declared on it.
///
/// # Safety
/// `node` is a live node; `expression` NUL-terminated; `ns_list` null or a
/// null-terminated list.
unsafe fn fill_expression(
    node: *mut XmlNode,
    expression: *const u8,
    ns_list: *const *const u8,
    here: Here,
) -> c_int {
    // SAFETY: by the caller's contract.
    unsafe {
        if xmlSecNodeEncodeAndSetContent(node, expression) < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecNodeEncodeAndSetContent");
            return -1;
        }
        if ns_list.is_null() {
            0
        } else {
            write_ns_list(node, ns_list)
        }
    }
}

/// `xmlSecTmplTransformAddXPath`: the only `XMLDSig` `<XPath>` of
/// `transform_node`, holding `expression` with the namespaces of `ns_list`.
///
/// # Safety
/// `transform_node` is null or a live node; `expression` null or
/// NUL-terminated; `ns_list` null or a null-terminated list.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplTransformAddXPath(
    transform_node: *mut XmlNode,
    expression: *const u8,
    ns_list: *const *const u8,
) -> c_int {
    contain(-1, || {
        check!(
            !transform_node.is_null(),
            "xmlSecTmplTransformAddXPath",
            c"transformNode != NULL",
            -1
        );
        check!(
            !expression.is_null(),
            "xmlSecTmplTransformAddXPath",
            c"expression != NULL",
            -1
        );
        let here = here!("xmlSecTmplTransformAddXPath");
        // SAFETY: `transform_node` is live.
        unsafe {
            let node = add_once(
                transform_node,
                &xmlSecNodeXPath,
                &xmlSecDSigNs,
                c"xmlSecAddChild(xmlSecNodeXPath)",
                here,
            );
            if node.is_null() {
                return -1;
            }
            fill_expression(node, expression, ns_list, here)
        }
    })
}

/// `xmlSecTmplTransformAddXPath2`: an `XPath` Filter 2.0 `<XPath>` of filter
/// `kind` appended to `transform_node`, holding `expression` with the
/// namespaces of `ns_list`.
///
/// # Safety
/// `transform_node` is null or a live node; `kind` and `expression` null or
/// NUL-terminated; `ns_list` null or a null-terminated list.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplTransformAddXPath2(
    transform_node: *mut XmlNode,
    kind: *const u8,
    expression: *const u8,
    ns_list: *const *const u8,
) -> c_int {
    contain(-1, || {
        check!(
            !transform_node.is_null(),
            "xmlSecTmplTransformAddXPath2",
            c"transformNode != NULL",
            -1
        );
        check!(
            !kind.is_null(),
            "xmlSecTmplTransformAddXPath2",
            c"type != NULL",
            -1
        );
        check!(
            !expression.is_null(),
            "xmlSecTmplTransformAddXPath2",
            c"expression != NULL",
            -1
        );
        let here = here!("xmlSecTmplTransformAddXPath2");
        // SAFETY: `transform_node` is live.
        unsafe {
            let node = add(
                transform_node,
                &xmlSecNodeXPath,
                &xmlSecXPath2Ns,
                c"xmlSecAddChild(xmlSecNodeXPath)",
                here,
            );
            if node.is_null() {
                return -1;
            }
            xsSetProp(node, name(&xmlSecAttrFilter), kind);
            fill_expression(node, expression, ns_list, here)
        }
    })
}

/// `xmlSecTmplTransformAddXPointer`: the only `<XPointer>` of
/// `transform_node`, holding `expression` with the namespaces of `ns_list`.
///
/// # Safety
/// `transform_node` is null or a live node; `expression` null or
/// NUL-terminated; `ns_list` null or a null-terminated list.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTmplTransformAddXPointer(
    transform_node: *mut XmlNode,
    expression: *const u8,
    ns_list: *const *const u8,
) -> c_int {
    contain(-1, || {
        check!(
            !expression.is_null(),
            "xmlSecTmplTransformAddXPointer",
            c"expression != NULL",
            -1
        );
        check!(
            !transform_node.is_null(),
            "xmlSecTmplTransformAddXPointer",
            c"transformNode != NULL",
            -1
        );
        let here = here!("xmlSecTmplTransformAddXPointer");
        // SAFETY: `transform_node` is live.
        unsafe {
            let node = add_once(
                transform_node,
                &xmlSecNodeXPointer,
                &xmlSecXPointerNs,
                c"xmlSecAddChild(xmlSecNodeXPointer)",
                here,
            );
            if node.is_null() {
                return -1;
            }
            fill_expression(node, expression, ns_list, here)
        }
    })
}
