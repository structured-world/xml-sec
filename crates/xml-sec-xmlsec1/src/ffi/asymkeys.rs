//! The built-in provider's asymmetric key-data klasses: RSA, DSA and EC
//! public keys in their `KeyValue` children (`RSAKeyValue`, `DSAKeyValue`,
//! `dsig11:ECKeyValue`), members of the built-in crypto table.
//!
//! An object holds the key as the core's provider-neutral key value. The
//! XML is read by the core's key-value reader over the element's projected
//! subtree and the components are validated as key resolution validates
//! them; key strength is the operation policy's decision when the key is
//! used. libxmlsec1's `PrivateExponent`/`X` extension children are not read:
//! private keys come from key files, never from XML.

use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_void};

use xml_sec::xmldsig::{KeyValueInfo, parse_key_value_child};
use xml_sec_libxml2::ffi::tree::xsSetProp;
use zeroize::Zeroizing;

use super::base64::{xmlSecBase64Encode, xmlSecBase64GetDefaultLineSize};
use super::buffer::{
    XmlSecBuffer, xmlSecBufferBase64NodeContentRead, xmlSecBufferFinalize, xmlSecBufferGetData,
    xmlSecBufferGetSize, xmlSecBufferInitialize,
};
use super::errors::{self, Here, here};
use super::keyinfo::{MODE_READ, MODE_WRITE, XmlSecKeyInfoCtx, read_policy};
use super::keys::{
    TYPE_PRIVATE, TYPE_PUBLIC, TYPE_UNKNOWN, XmlSecKey, XmlSecKeyReq, xmlSecKeyGetValue,
    xmlSecKeyReqMatchKeyValue, xmlSecKeySetValue,
};
use super::keysdata::{
    USAGE_KEY_INFO_NODE, USAGE_KEY_VALUE_NODE, USAGE_READ_FROM_FILE,
    USAGE_RETRIEVAL_METHOD_NODE_XML, XmlSecKeyData, XmlSecKeyDataKlass, check_id, data_valid,
    xmlSecKeyDataCreate, xmlSecKeyDataDestroy, xmlSecKeyDataGetSize,
};
use super::strings::{
    xmlSecAttrURI, xmlSecDSig11Ns, xmlSecDSigNs, xmlSecHrefDSAKeyValue, xmlSecHrefECKeyValue,
    xmlSecHrefRSAKeyValue, xmlSecNameDEREncodedKeyValue, xmlSecNameDSAKeyValue,
    xmlSecNameECKeyValue, xmlSecNameRSAKeyValue, xmlSecNodeDEREncodedKeyValue, xmlSecNodeDSAG,
    xmlSecNodeDSAKeyValue, xmlSecNodeDSAP, xmlSecNodeDSAQ, xmlSecNodeDSAY, xmlSecNodeECKeyValue,
    xmlSecNodeNamedCurve, xmlSecNodePublicKey, xmlSecNodeRSAExponent, xmlSecNodeRSAKeyValue,
    xmlSecNodeRSAModulus,
};
use super::transforms::klass_text;
use super::tree::{XmlNode, c_text, nodes};
use super::xmltree::{xmlSecAddChild, xmlSecGetDefaultLineFeed, xmlSecGetNextElementNode};
use super::{contain, free, write_stream};

/// An asymmetric key-data object: the key data and its key material, null
/// until one is set.
#[repr(C)]
struct AsymmetricData {
    data: XmlSecKeyData,
    material: *mut Material,
}

/// The key of an asymmetric key-data object.
#[derive(Clone)]
pub(crate) struct Material {
    /// The public key.
    pub(crate) value: KeyValueInfo,
    /// The PKCS#8 DER of the private key, when the key holds one.
    pub(crate) private: Option<Zeroizing<Vec<u8>>>,
}

/// The key family a klass holds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    Rsa,
    Dsa,
    Ec,
}

impl Family {
    /// libxmlsec1's reader and writer helpers of the family, which name the
    /// failures the klass methods report.
    fn read_here(self) -> Here {
        match self {
            Self::Rsa => here!("xmlSecKeyDataRsaXmlRead"),
            Self::Dsa => here!("xmlSecKeyDataDsaXmlRead"),
            Self::Ec => here!("xmlSecKeyDataEcXmlRead"),
        }
    }

    fn write_here(self) -> Here {
        match self {
            Self::Rsa => here!("xmlSecKeyDataRsaXmlWrite"),
            Self::Dsa => here!("xmlSecKeyDataDsaXmlWrite"),
            Self::Ec => here!("xmlSecKeyDataEcXmlWrite"),
        }
    }

    /// Whether `value` is a key of this family.
    fn holds(self, value: &KeyValueInfo) -> bool {
        matches!(
            (self, value),
            (Self::Rsa, KeyValueInfo::Rsa { .. })
                | (Self::Dsa, KeyValueInfo::Dsa { .. })
                | (Self::Ec, KeyValueInfo::Ec { .. })
        )
    }
}

/// A klass of the family whose `KeyValue` child is `node` in `ns`.
const fn klass(
    name: &'static [u8],
    href: &'static [u8],
    node: &'static [u8],
    ns: &'static [u8],
) -> XmlSecKeyDataKlass {
    XmlSecKeyDataKlass {
        klass_size: size_of::<XmlSecKeyDataKlass>(),
        obj_size: size_of::<AsymmetricData>(),
        name: name.as_ptr(),
        usage: USAGE_READ_FROM_FILE | USAGE_KEY_VALUE_NODE | USAGE_RETRIEVAL_METHOD_NODE_XML,
        href: href.as_ptr(),
        data_node_name: node.as_ptr(),
        data_node_ns: ns.as_ptr(),
        initialize: Some(initialize),
        duplicate: Some(duplicate),
        finalize: Some(finalize),
        // Key generation is not a capability of the built-in provider.
        generate: None,
        get_type: Some(get_type),
        get_size: Some(get_size),
        deprecated0: std::ptr::null_mut(),
        xml_read: Some(xml_read),
        xml_write: Some(xml_write),
        bin_read: None,
        bin_write: None,
        debug_dump: Some(debug_dump),
        debug_xml_dump: Some(debug_xml_dump),
        reserved0: std::ptr::null_mut(),
        reserved1: std::ptr::null_mut(),
    }
}

static RSA: XmlSecKeyDataKlass = klass(
    &xmlSecNameRSAKeyValue,
    &xmlSecHrefRSAKeyValue,
    &xmlSecNodeRSAKeyValue,
    &xmlSecDSigNs,
);
static DSA: XmlSecKeyDataKlass = klass(
    &xmlSecNameDSAKeyValue,
    &xmlSecHrefDSAKeyValue,
    &xmlSecNodeDSAKeyValue,
    &xmlSecDSigNs,
);
static EC: XmlSecKeyDataKlass = klass(
    &xmlSecNameECKeyValue,
    &xmlSecHrefECKeyValue,
    &xmlSecNodeECKeyValue,
    &xmlSecDSig11Ns,
);

/// The family of klass `id`, `None` for any other klass.
fn family(id: *const XmlSecKeyDataKlass) -> Option<Family> {
    [(&RSA, Family::Rsa), (&DSA, Family::Dsa), (&EC, Family::Ec)]
        .into_iter()
        .find_map(|(klass, family)| std::ptr::eq(klass, id).then_some(family))
}

/// The object of valid key data of one of these klasses.
///
/// # Safety
/// `data` is null or a key-data object.
unsafe fn object<'a>(data: *mut XmlSecKeyData) -> Option<&'a mut AsymmetricData> {
    // SAFETY: by the caller's contract; a valid object of these klasses has
    // the asymmetric layout.
    unsafe {
        (data_valid(data) && family((*data).id).is_some())
            .then(|| &mut *data.cast::<AsymmetricData>())
    }
}

/// The key value of `data`, if it is key data of these klasses holding one.
///
/// # Safety
/// As for [`object`].
pub(crate) unsafe fn value_of<'a>(data: *mut XmlSecKeyData) -> Option<&'a KeyValueInfo> {
    // SAFETY: by the caller's contract.
    unsafe { material_of(data) }.map(|material| &material.value)
}

/// The key material of `data`, if it is key data of these klasses holding
/// a key.
///
/// # Safety
/// As for [`object`].
pub(crate) unsafe fn material_of<'a>(data: *mut XmlSecKeyData) -> Option<&'a Material> {
    // SAFETY: by the caller's contract; a non-null material is the object's.
    unsafe { object(data).and_then(|object| object.material.as_ref()) }
}

/// New key data of the klass of `material`'s family holding it; null after
/// a report when it cannot be created.
pub(crate) fn adopt(material: Material) -> *mut XmlSecKeyData {
    let klass: &XmlSecKeyDataKlass = match material.value {
        KeyValueInfo::Rsa { .. } => &RSA,
        KeyValueInfo::Dsa { .. } => &DSA,
        _ => &EC,
    };
    // SAFETY: a klass of this module.
    unsafe {
        let data = xmlSecKeyDataCreate(klass);
        if let Some(object) = object(data) {
            replace(object, material);
        }
        data
    }
}

/// The name of klass `id` for a report.
///
/// # Safety
/// `id` is null or a klass.
unsafe fn klass_name(id: *const XmlSecKeyDataKlass) -> *const c_char {
    // SAFETY: by the caller's contract.
    unsafe { id.as_ref() }.map_or(std::ptr::null(), |klass| klass.name.cast())
}

unsafe extern "C" fn initialize(data: *mut XmlSecKeyData) -> c_int {
    contain(-1, || {
        // SAFETY: the registry passes key data of these klasses.
        let Some(object) = (unsafe { object(data) }) else {
            errors::assertion(
                here!("xmlSecKeyDataInitialize"),
                c"xmlSecKeyDataIsValid(data)",
            );
            return -1;
        };
        object.material = std::ptr::null_mut();
        0
    })
}

unsafe extern "C" fn duplicate(dst: *mut XmlSecKeyData, src: *mut XmlSecKeyData) -> c_int {
    contain(-1, || {
        // SAFETY: the registry passes key data of these klasses.
        let (Some(target), Some(source)) = (unsafe { object(dst) }, unsafe { object(src) }) else {
            errors::assertion(
                here!("xmlSecKeyDataDuplicate"),
                c"xmlSecKeyDataIsValid(dst) && xmlSecKeyDataIsValid(src)",
            );
            return -1;
        };
        // SAFETY: a non-null material is the source's own.
        if let Some(material) = unsafe { source.material.as_ref() } {
            replace(target, material.clone());
        }
        0
    })
}

unsafe extern "C" fn finalize(data: *mut XmlSecKeyData) {
    contain((), || {
        // SAFETY: the registry passes key data of these klasses.
        if let Some(object) = unsafe { object(data) } {
            release(object);
        }
    });
}

/// Makes `material` the key of `object`, releasing the previous one.
fn replace(object: &mut AsymmetricData, material: Material) {
    release(object);
    object.material = Box::into_raw(Box::new(material));
}

/// Releases the key of `object`; a private key is zeroized.
fn release(object: &mut AsymmetricData) {
    if !object.material.is_null() {
        // SAFETY: a non-null material was boxed by `replace` and is owned
        // here.
        drop(unsafe { Box::from_raw(object.material) });
        object.material = std::ptr::null_mut();
    }
}

/// `getType`: a public key, with its private key when the object holds one.
unsafe extern "C" fn get_type(data: *mut XmlSecKeyData) -> c_uint {
    contain(TYPE_UNKNOWN, || {
        // SAFETY: the registry passes key data of these klasses.
        match unsafe { material_of(data) } {
            Some(Material {
                private: Some(_), ..
            }) => TYPE_PUBLIC | TYPE_PRIVATE,
            Some(_) => TYPE_PUBLIC,
            None => TYPE_UNKNOWN,
        }
    })
}

/// The bit length of an unsigned big-endian magnitude.
fn bit_length(bytes: &[u8]) -> usize {
    let start = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    match bytes.get(start..) {
        Some([first, rest @ ..]) => rest.len() * 8 + (8 - first.leading_zeros() as usize),
        _ => 0,
    }
}

/// `getSize`: the RSA modulus, DSA prime or EC curve size in bits.
unsafe extern "C" fn get_size(data: *mut XmlSecKeyData) -> usize {
    contain(0, || {
        // SAFETY: the registry passes key data of these klasses.
        match unsafe { value_of(data) } {
            Some(KeyValueInfo::Rsa { modulus, .. }) => bit_length(modulus),
            Some(KeyValueInfo::Dsa { p: Some(p), .. }) => bit_length(p),
            // A named curve's size is its order's (SEC 2 section 2).
            Some(KeyValueInfo::Ec { curve_oid, .. }) => match curve_oid.as_str() {
                "1.2.840.10045.3.1.7" => 256,
                "1.3.132.0.34" => 384,
                "1.3.132.0.35" => 521,
                _ => 0,
            },
            _ => 0,
        }
    })
}

/// `xmlNodeSetContent(node, content)` for content without markup; a refused
/// edit is the write's failure, not a success over an empty element.
fn set_content(node: *mut XmlNode, content: &str) -> Result<(), &'static CStr> {
    nodes::set_content(node, content).map_err(|_| c"xmlNodeSetContent")
}

/// The key value the core reads from the key-value element `node`, under the
/// policy of the read with `ctx`.
///
/// # Safety
/// `node` is a live element of a live document; `ctx` is a context.
unsafe fn read_value(
    here: Here,
    node: *mut XmlNode,
    ctx: *mut XmlSecKeyInfoCtx,
) -> Result<KeyValueInfo, String> {
    // SAFETY: by the caller's contract.
    let pinned = unsafe { read_policy(ctx, here) }.ok_or("the library policy is unavailable")?;
    let document = xml_sec_libxml2::document::subtree(node, &*pinned.verification)
        .map_err(|error| error.to_string())?;
    document.with_view(|view| {
        parse_key_value_child(
            view.document().root_element(),
            &pinned.verification.resources,
        )
        .map_err(|error| error.to_string())
    })
}

/// `xmlRead`: the key value element `node` as the value of `key`, which
/// must have none yet.
unsafe extern "C" fn xml_read(
    id: *const XmlSecKeyDataKlass,
    key: *mut c_void,
    node: *mut c_void,
    ctx: *mut c_void,
) -> c_int {
    let (key, node, ctx) = (
        key.cast::<XmlSecKey>(),
        node.cast::<XmlNode>(),
        ctx.cast::<XmlSecKeyInfoCtx>(),
    );
    contain(-1, || {
        let Some(family) = family(id) else {
            errors::assertion(here!("xmlSecKeyDataXmlRead"), c"id != NULL");
            return -1;
        };
        let here = family.read_here();
        for (missing, expression) in [
            (key.is_null(), c"key != NULL"),
            (node.is_null(), c"node != NULL"),
            (ctx.is_null(), c"keyInfoCtx != NULL"),
        ] {
            if missing {
                errors::assertion(here, expression);
                return -1;
            }
        }
        // SAFETY: a klass of this module.
        let object_name = unsafe { klass_name(id) };
        // SAFETY: a key.
        if !unsafe { xmlSecKeyGetValue(key) }.is_null() {
            errors::other(
                here,
                errors::R_INVALID_KEY_DATA,
                object_name,
                Some("key already has a value"),
            );
            return -1;
        }
        // SAFETY: a live element of a live document.
        let value = match unsafe { read_value(here, node, ctx) } {
            Ok(value) if family.holds(&value) => value,
            Ok(_) => {
                errors::internal_with(
                    here,
                    object_name,
                    c"parse_key_value_child",
                    "the element is not a key of the klass",
                );
                return -1;
            }
            Err(error) => {
                errors::internal_with(here, object_name, c"parse_key_value_child", &error);
                return -1;
            }
        };
        if let Err(error) = value.to_spki_der() {
            errors::internal_with(
                here,
                object_name,
                c"KeyValueInfo::to_spki_der",
                &error.to_string(),
            );
            return -1;
        }
        // SAFETY: a klass of this module and a key that adopts the object.
        unsafe {
            let data = xmlSecKeyDataCreate(id);
            let Some(object) = object(data) else {
                errors::internal(here, object_name, c"xmlSecKeyDataCreate");
                return -1;
            };
            replace(
                object,
                Material {
                    value,
                    private: None,
                },
            );
            install_value(here, object_name, key, data, &raw mut (*ctx).key_req)
        }
    })
}

/// Appends to `parent` the child `name` in `ns` holding the Base64 of
/// `bytes` between line feeds, as libxmlsec1 writes a key component.
///
/// # Safety
/// `parent` is a live element of a live document.
unsafe fn write_component(
    parent: *mut XmlNode,
    name: &[u8],
    ns: &[u8],
    bytes: &[u8],
) -> Result<(), &'static CStr> {
    // SAFETY: by the caller's contract; the encoded text is freed here.
    unsafe {
        let child = xmlSecAddChild(parent, name.as_ptr(), ns.as_ptr());
        if child.is_null() {
            return Err(c"xmlSecAddChild");
        }
        let line_feed = c_text(xmlSecGetDefaultLineFeed()).unwrap_or_default();
        let text = xmlSecBase64Encode(
            bytes.as_ptr(),
            bytes.len(),
            xmlSecBase64GetDefaultLineSize(),
        );
        if text.is_null() {
            // libxmlsec1 has set the leading line feed by then.
            set_content(child, line_feed)?;
            return Err(c"xmlSecBase64Encode");
        }
        let encoded = c_text(text).unwrap_or_default();
        // The line feed, the Base64 and the line feed, which libxmlsec1 sets
        // and appends in three calls that end as this one text.
        let set = set_content(child, &format!("{line_feed}{encoded}{line_feed}"));
        free(text.cast());
        set
    }
}

/// Writes the children of the key-value element `node` for `value`.
///
/// # Safety
/// `node` is a live element of a live document.
unsafe fn write_value(node: *mut XmlNode, value: &KeyValueInfo) -> Result<(), &'static CStr> {
    // SAFETY: by the caller's contract.
    unsafe {
        match value {
            KeyValueInfo::Rsa { modulus, exponent } => {
                write_component(node, &xmlSecNodeRSAModulus, &xmlSecDSigNs, modulus)?;
                write_component(node, &xmlSecNodeRSAExponent, &xmlSecDSigNs, exponent)
            }
            KeyValueInfo::Dsa {
                p: Some(p),
                q: Some(q),
                g: Some(g),
                y,
            } => {
                for (name, bytes) in [
                    (&xmlSecNodeDSAP[..], p),
                    (&xmlSecNodeDSAQ[..], q),
                    (&xmlSecNodeDSAG[..], g),
                    (&xmlSecNodeDSAY[..], y),
                ] {
                    write_component(node, name, &xmlSecDSigNs, bytes)?;
                }
                Ok(())
            }
            KeyValueInfo::Ec {
                curve_oid,
                public_key,
            } => {
                let curve =
                    xmlSecAddChild(node, xmlSecNodeNamedCurve.as_ptr(), xmlSecDSig11Ns.as_ptr());
                if curve.is_null() {
                    return Err(c"xmlSecAddChild");
                }
                // XMLDSig 1.1 section 4.5.2.3.1 names the curve by a URN of
                // its OID (RFC 3061).
                let uri =
                    CString::new(format!("urn:oid:{curve_oid}")).map_err(|_| c"xmlSetProp")?;
                if xsSetProp(curve, xmlSecAttrURI.as_ptr(), uri.as_ptr().cast()).is_null() {
                    return Err(c"xmlSetProp");
                }
                write_component(node, &xmlSecNodePublicKey, &xmlSecDSig11Ns, public_key)
            }
            _ => Err(c"KeyValueInfo"),
        }
    }
}

/// `xmlWrite`: the value of `key` as the children of `node`, when the
/// context asks for a public or private key.
unsafe extern "C" fn xml_write(
    id: *const XmlSecKeyDataKlass,
    key: *mut c_void,
    node: *mut c_void,
    ctx: *mut c_void,
) -> c_int {
    let (key, node, ctx) = (
        key.cast::<XmlSecKey>(),
        node.cast::<XmlNode>(),
        ctx.cast::<XmlSecKeyInfoCtx>(),
    );
    contain(-1, || {
        let Some(family) = family(id) else {
            errors::assertion(here!("xmlSecKeyDataXmlWrite"), c"id != NULL");
            return -1;
        };
        let here = family.write_here();
        for (missing, expression) in [
            (key.is_null(), c"key != NULL"),
            (node.is_null(), c"node != NULL"),
            (ctx.is_null(), c"keyInfoCtx != NULL"),
        ] {
            if missing {
                errors::assertion(here, expression);
                return -1;
            }
        }
        // SAFETY: a context.
        if unsafe { (*ctx).key_req.key_type } & (TYPE_PUBLIC | TYPE_PRIVATE) == 0 {
            return 0;
        }
        // SAFETY: a klass of this module.
        let object_name = unsafe { klass_name(id) };
        // SAFETY: a key.
        let data = unsafe { xmlSecKeyGetValue(key) };
        if data.is_null() {
            errors::other(
                here,
                errors::R_INVALID_KEY_DATA,
                object_name,
                Some("key has no value"),
            );
            return -1;
        }
        // SAFETY: the key's key data.
        let material = unsafe { check_id(data, id).then(|| material_of(data)).flatten() };
        let Some(material) = material else {
            errors::internal(here, object_name, c"xmlSecKeyDataCheckId");
            return -1;
        };
        // libxmlsec1 writes RSA's PrivateExponent and DSA's X when the
        // context asks for the private key and the key holds one. Those
        // components are not written here, so the request fails before the
        // node is edited instead of producing a public-only value.
        // SAFETY: a context.
        let private_requested = unsafe { (*ctx).key_req.key_type } & TYPE_PRIVATE != 0;
        if private_requested && material.private.is_some() && family != Family::Ec {
            errors::other(
                here,
                errors::R_INVALID_KEY_DATA,
                object_name,
                Some("private key components are not written"),
            );
            return -1;
        }
        let value = &material.value;
        // SAFETY: a live element of a live document.
        if let Err(failed) = unsafe { write_value(node, value) } {
            errors::internal(here, object_name, failed);
            return -1;
        }
        0
    })
}

/// `debugDump`: the klass name and key size; the key itself is not printed.
unsafe extern "C" fn debug_dump(data: *mut XmlSecKeyData, output: *mut c_void) {
    contain((), || {
        // SAFETY: the dispatcher passes valid key data and a C stream.
        unsafe {
            let name = klass_text((*(*data).id).name);
            let size = xmlSecKeyDataGetSize(data);
            write_stream(output, &format!("=== {name} key: size = {size}\n"));
        }
    });
}

/// `debugXmlDump`: the element name and key size as an XML element.
unsafe extern "C" fn debug_xml_dump(data: *mut XmlSecKeyData, output: *mut c_void) {
    contain((), || {
        // SAFETY: the dispatcher passes valid key data and a C stream.
        unsafe {
            let name = klass_text((*(*data).id).data_node_name);
            let size = xmlSecKeyDataGetSize(data);
            write_stream(output, &format!("<{name}Key size=\"{size}\"/>\n"));
        }
    });
}

// ----------------------------------------------------------------------------
// DEREncodedKeyValue

/// `dsig11:DEREncodedKeyValue` (`XMLDSig` 1.1 section 4.5.9): a public key as
/// its Base64 DER `SubjectPublicKeyInfo`, read into the klass of its family.
static DER_ENCODED_KEY_VALUE: XmlSecKeyDataKlass = XmlSecKeyDataKlass {
    klass_size: size_of::<XmlSecKeyDataKlass>(),
    obj_size: size_of::<XmlSecKeyData>(),
    name: xmlSecNameDEREncodedKeyValue.as_ptr(),
    usage: USAGE_KEY_INFO_NODE | USAGE_RETRIEVAL_METHOD_NODE_XML,
    href: std::ptr::null(),
    data_node_name: xmlSecNodeDEREncodedKeyValue.as_ptr(),
    data_node_ns: xmlSecDSig11Ns.as_ptr(),
    initialize: None,
    duplicate: None,
    finalize: None,
    generate: None,
    get_type: None,
    get_size: None,
    deprecated0: std::ptr::null_mut(),
    xml_read: Some(der_xml_read),
    xml_write: Some(der_xml_write),
    bin_read: None,
    bin_write: None,
    debug_dump: None,
    debug_xml_dump: None,
    reserved0: std::ptr::null_mut(),
    reserved1: std::ptr::null_mut(),
};

/// libxmlsec1's assertions on a `DEREncodedKeyValue` method in `mode` at
/// `here`; false after reporting the first that fails.
///
/// # Safety
/// `ctx` is null or a `KeyInfo` context.
unsafe fn der_arguments(
    here: Here,
    id: *const XmlSecKeyDataKlass,
    key: *mut XmlSecKey,
    node: *mut XmlNode,
    ctx: *mut XmlSecKeyInfoCtx,
    mode: c_int,
) -> bool {
    // SAFETY: a non-null context by the caller's contract.
    let in_mode = !ctx.is_null() && unsafe { (*ctx).mode } == mode;
    let checks: [(bool, &CStr); 5] = [
        (
            std::ptr::eq(id, &raw const DER_ENCODED_KEY_VALUE),
            c"id == xmlSecKeyDataDEREncodedKeyValueId",
        ),
        (!key.is_null(), c"key != NULL"),
        (!node.is_null(), c"node != NULL"),
        (!ctx.is_null(), c"keyInfoCtx != NULL"),
        (
            in_mode,
            if mode == MODE_READ {
                c"keyInfoCtx->mode == xmlSecKeyInfoModeRead"
            } else {
                c"keyInfoCtx->mode == xmlSecKeyInfoModeWrite"
            },
        ),
    ];
    for (holds, expression) in checks {
        if !holds {
            errors::assertion(here, expression);
            return false;
        }
    }
    true
}

/// `xmlRead`: the SPKI the element holds as the value of `key`, of the
/// klass of its key family; an empty element is no key and no error, as in
/// a template.
unsafe extern "C" fn der_xml_read(
    id: *const XmlSecKeyDataKlass,
    key: *mut c_void,
    node: *mut c_void,
    ctx: *mut c_void,
) -> c_int {
    let (key, node, ctx) = (
        key.cast::<XmlSecKey>(),
        node.cast::<XmlNode>(),
        ctx.cast::<XmlSecKeyInfoCtx>(),
    );
    contain(-1, || {
        let here = here!("xmlSecKeyDataDEREncodedKeyValueXmlRead");
        // SAFETY: the context is null or a context.
        if !unsafe { der_arguments(here, id, key, node, ctx, MODE_READ) } {
            return -1;
        }
        let object_name = xmlSecNameDEREncodedKeyValue.as_ptr().cast::<c_char>();
        // A key that already has a value keeps it, as the other key-value
        // readers keep it: replacing it would leave a key resolved from one
        // source (a manager entry, say) holding another source's material.
        // SAFETY: a key.
        if !unsafe { xmlSecKeyGetValue(key) }.is_null() {
            errors::other(
                here,
                errors::R_INVALID_KEY_DATA,
                object_name,
                Some("key already has a value"),
            );
            return -1;
        }
        // SAFETY: a live element; its children are live.
        let child = unsafe { xmlSecGetNextElementNode(nodes::first_child(node)) };
        if !child.is_null() {
            // SAFETY: a live node.
            unsafe { errors::unexpected_node(here, child, object_name) };
            return -1;
        }
        // SAFETY: a context, checked above.
        let Some(pinned) = (unsafe { read_policy(ctx, here) }) else {
            return -1;
        };
        let policy = &pinned.verification;
        let mut buffer = std::mem::MaybeUninit::<XmlSecBuffer>::zeroed();
        let buffer = buffer.as_mut_ptr();
        // SAFETY: a zeroed buffer is initialized here and finalized below;
        // the node is a live element.
        unsafe {
            if xmlSecBufferInitialize(buffer, 256) < 0 {
                errors::internal(here, object_name, c"xmlSecBufferInitialize");
                return -1;
            }
            let result = der_adopt(
                here,
                key,
                node,
                buffer,
                &policy.resources,
                &raw mut (*ctx).key_req,
            );
            xmlSecBufferFinalize(buffer);
            result
        }
    })
}

/// Reads the Base64 content of `node` into `buffer` and makes the SPKI it
/// holds the value of `key`, when it meets `req`.
///
/// # Safety
/// `key` is a key, `node` a live element, `buffer` an initialized buffer and
/// `req` initialized requirements.
unsafe fn der_adopt(
    here: Here,
    key: *mut XmlSecKey,
    node: *mut XmlNode,
    buffer: *mut XmlSecBuffer,
    resources: &xml_sec::policy::ResourcePolicy,
    req: *mut XmlSecKeyReq,
) -> c_int {
    let object_name = xmlSecNameDEREncodedKeyValue.as_ptr().cast::<c_char>();
    if !super::keyinfo::key_value_within(here, object_name, node, resources) {
        return -1;
    }
    // SAFETY: by the caller's contract.
    unsafe {
        if xmlSecBufferBase64NodeContentRead(buffer, node) < 0 {
            errors::internal(here, object_name, c"xmlSecBufferBase64NodeContentRead");
            return -1;
        }
        let size = xmlSecBufferGetSize(buffer);
        if size == 0 {
            return 0;
        }
        let spki = std::slice::from_raw_parts(xmlSecBufferGetData(buffer), size);
        let value = match KeyValueInfo::from_spki_der(spki, resources) {
            Ok(value) => value,
            Err(error) => {
                errors::internal_with(
                    here,
                    object_name,
                    c"KeyValueInfo::from_spki_der",
                    &format!("size={size}; {error}"),
                );
                return -1;
            }
        };
        let data = adopt(Material {
            value,
            private: None,
        });
        if data.is_null() {
            errors::internal(here, object_name, c"xmlSecKeyDataCreate");
            return -1;
        }
        install_value(here, object_name, key, data, req)
    }
}

/// Makes `data` the value of `key` when it meets `req`; a value the
/// requirements refuse is released and the key keeps none, so a later
/// candidate of the same `KeyInfo` can still supply it. libxmlsec1 installs
/// the first value whatever it is and then fails the next reader with "key
/// already has a value".
///
/// # Safety
/// `key` is a key without a value, `data` key data it may adopt, `req`
/// initialized requirements.
unsafe fn install_value(
    here: Here,
    object_name: *const c_char,
    key: *mut XmlSecKey,
    data: *mut XmlSecKeyData,
    req: *mut XmlSecKeyReq,
) -> c_int {
    // SAFETY: by the caller's contract.
    unsafe {
        if xmlSecKeyReqMatchKeyValue(req, data) != 1 {
            xmlSecKeyDataDestroy(data);
            return 0;
        }
        if xmlSecKeySetValue(key, data) < 0 {
            errors::internal(here, object_name, c"xmlSecKeySetValue");
            xmlSecKeyDataDestroy(data);
            return -1;
        }
    }
    0
}

/// `xmlWrite`: the SPKI of the key's public key as the Base64 content of
/// `node`.
unsafe extern "C" fn der_xml_write(
    id: *const XmlSecKeyDataKlass,
    key: *mut c_void,
    node: *mut c_void,
    ctx: *mut c_void,
) -> c_int {
    let (key, node, ctx) = (
        key.cast::<XmlSecKey>(),
        node.cast::<XmlNode>(),
        ctx.cast::<XmlSecKeyInfoCtx>(),
    );
    contain(-1, || {
        let here = here!("xmlSecKeyDataDEREncodedKeyValueXmlWrite");
        // SAFETY: the context is null or a context.
        if !unsafe { der_arguments(here, id, key, node, ctx, MODE_WRITE) } {
            return -1;
        }
        let object_name = xmlSecNameDEREncodedKeyValue.as_ptr().cast::<c_char>();
        // SAFETY: a key; its value is null or key data.
        let value = unsafe { value_of(xmlSecKeyGetValue(key)) };
        let Some(spki) = value.and_then(|value| value.to_spki_der().ok()) else {
            errors::internal(here, object_name, c"KeyValueInfo::to_spki_der");
            return -1;
        };
        // SAFETY: the SPKI bytes and a live element; the text is freed here.
        unsafe {
            let text =
                xmlSecBase64Encode(spki.as_ptr(), spki.len(), xmlSecBase64GetDefaultLineSize());
            if text.is_null() {
                errors::internal(here, object_name, c"xmlSecBase64Encode");
                return -1;
            }
            // xmlNodeAddContent; a refused edit is the write's failure, not a
            // success with no key written.
            let added =
                c_text(text).is_some_and(|encoded| nodes::add_content(node, encoded).is_ok());
            free(text.cast());
            if !added {
                errors::xml_failed(here, object_name, c"xmlNodeAddContent");
                return -1;
            }
        }
        0
    })
}

macro_rules! getters {
    ($($name:ident => $klass:ident;)*) => {
        $(
            #[doc = concat!("The built-in table's `", stringify!($klass), "` klass.")]
            pub(crate) extern "C" fn $name() -> *const XmlSecKeyDataKlass {
                &raw const $klass
            }
        )*
    };
}

getters! {
    rsa => RSA;
    dsa => DSA;
    ec => EC;
    der_encoded_key_value => DER_ENCODED_KEY_VALUE;
}
