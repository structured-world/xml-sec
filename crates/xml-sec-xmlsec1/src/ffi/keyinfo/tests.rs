//! `KeyInfo` processing honours the context's flags and enabled list where
//! they decide what is read or written.

use xml_sec_libxml2::ffi::tree::{xsDocGetRootElement, xsFreeDoc, xsReadMemory};

use super::{MODE_WRITE, xmlSecKeyInfoCtxCreate, xmlSecKeyInfoCtxDestroy, xmlSecKeyInfoNodeRead};
use crate::ffi::errors;
use crate::ffi::keys::{
    TYPE_SYMMETRIC, xmlSecKeyCreate, xmlSecKeyDestroy, xmlSecKeyGetValue, xmlSecKeySetName,
    xmlSecKeySetValue,
};
use crate::ffi::keysdata::{
    xmlSecKeyDataBinaryValueSetBuffer, xmlSecKeyDataCreate, xmlSecKeyDataIdsInit,
    xmlSecKeyDataValueGetKlass, xmlSecKeyDataXmlRead, xmlSecKeyDataXmlWrite,
};
use crate::ffi::keysmngr::{
    xmlSecKeyStoreCreate, xmlSecKeysMngrAdoptKeysStore, xmlSecKeysMngrCreate,
    xmlSecKeysMngrDestroy, xmlSecSimpleKeysStoreGetKlass,
};
use crate::ffi::list::xmlSecPtrListAdd;
use crate::ffi::tree::{XmlDoc, nodes};
use crate::ffi::{asymkeys, symkeys};

/// `XMLSEC_KEYINFO_FLAGS_KEYNAME_STOP_ON_UNKNOWN`.
const KEYNAME_STOP_ON_UNKNOWN: u32 = 0x0000_0004;

fn parse(xml: &str) -> *mut XmlDoc {
    // SAFETY: the bytes and their length.
    let doc = unsafe {
        xsReadMemory(
            xml.as_ptr().cast(),
            i32::try_from(xml.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        )
    };
    assert!(!doc.is_null(), "the document parses");
    doc
}

/// The reasons of the reports received, in order.
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
    REASONS.lock().expect("reasons").push(reason);
}

/// Reads the `KeyInfo` element of `xml` with `ctx` and returns the result
/// and the reasons reported meanwhile.
///
/// # Safety
/// `ctx` is a reading context.
unsafe fn read_reported(
    xml: &str,
    ctx: *mut super::XmlSecKeyInfoCtx,
) -> (std::ffi::c_int, Vec<std::ffi::c_int>) {
    let doc = parse(xml);
    // SAFETY: the callback has the callback's signature; the key and the
    // document are released here.
    unsafe {
        REASONS.lock().expect("reasons").clear();
        errors::xmlSecErrorsSetCallback(Some(record as errors::ErrorsCallback));
        let key = xmlSecKeyCreate();
        let read = xmlSecKeyInfoNodeRead(xsDocGetRootElement(doc), key, ctx);
        xmlSecKeyDestroy(key);
        xsFreeDoc(doc);
        (read, REASONS.lock().expect("reasons").clone())
    }
}

#[test]
fn a_retrieval_method_reaches_only_the_uri_classes_policy_admits_for_keys() {
    // The library admits every URI class for a signature's references but
    // only same-document ones for key retrieval: an external RetrievalMethod
    // is refused for its class before anything is dereferenced.
    // SAFETY: a context created and destroyed here.
    unsafe {
        assert_eq!(xmlSecKeyDataIdsInit(), 0);
        let ctx = xmlSecKeyInfoCtxCreate(std::ptr::null_mut());
        let enabled = &raw mut (*ctx).enabled_key_data;
        let retrieval = crate::ffi::keysdata::xmlSecKeyDataRetrievalMethodGetKlass();
        assert_eq!(xmlSecPtrListAdd(enabled, retrieval.cast_mut().cast()), 0);
        assert_eq!(
            xmlSecPtrListAdd(enabled, asymkeys::rsa().cast_mut().cast()),
            0
        );
        let (read, reasons) = read_reported(
            "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><RetrievalMethod \
             URI=\"http://example.com/key\" \
             Type=\"http://www.w3.org/2000/09/xmldsig#RSAKeyValue\"/></KeyInfo>",
            ctx,
        );
        assert_eq!(read, -1);
        assert_eq!(reasons.first(), Some(&errors::R_INVALID_URI_TYPE));
        xmlSecKeyInfoCtxDestroy(ctx);
    }
}

#[test]
fn key_info_reference_depth_is_bounded_by_policy_whatever_the_context_says() {
    // A KeyInfo referring to itself recurses until a bound stops it: the
    // policy's depth limit, not the far higher level the caller set.
    // SAFETY: a context created and destroyed here.
    unsafe {
        assert_eq!(xmlSecKeyDataIdsInit(), 0);
        let ctx = xmlSecKeyInfoCtxCreate(std::ptr::null_mut());
        (*ctx).max_key_info_reference_level = 1000;
        let (read, reasons) = read_reported(
            "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\" \
             xmlns:dsig11=\"http://www.w3.org/2009/xmldsig11#\" xml:id=\"self\">\
             <dsig11:KeyInfoReference URI=\"#self\"/></KeyInfo>",
            ctx,
        );
        assert_eq!(read, -1);
        assert_eq!(reasons.first(), Some(&errors::R_INVALID_SIZE));
        xmlSecKeyInfoCtxDestroy(ctx);
    }
}

#[test]
fn an_unknown_key_name_stops_the_read_when_the_flag_asks() {
    // keyinfo.h: XMLSEC_KEYINFO_FLAGS_KEYNAME_STOP_ON_UNKNOWN aborts on a
    // name the keys manager does not know, rather than reading on.
    let doc = parse(
        "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><KeyName>alice</KeyName></KeyInfo>",
    );
    // SAFETY: objects created and destroyed here.
    unsafe {
        assert_eq!(xmlSecKeyDataIdsInit(), 0);
        let mngr = xmlSecKeysMngrCreate();
        let store = xmlSecKeyStoreCreate(xmlSecSimpleKeysStoreGetKlass());
        assert_eq!(xmlSecKeysMngrAdoptKeysStore(mngr, store), 0);
        let ctx = xmlSecKeyInfoCtxCreate(mngr);
        let key = xmlSecKeyCreate();
        assert_eq!(xmlSecKeyInfoNodeRead(xsDocGetRootElement(doc), key, ctx), 0);
        (*ctx).flags = KEYNAME_STOP_ON_UNKNOWN;
        assert_eq!(
            xmlSecKeyInfoNodeRead(xsDocGetRootElement(doc), key, ctx),
            -1
        );
        xmlSecKeyDestroy(key);
        xmlSecKeyInfoCtxDestroy(ctx);
        xmlSecKeysMngrDestroy(mngr);
        xsFreeDoc(doc);
    }
}

#[test]
fn a_der_encoded_key_value_does_not_replace_a_key_already_found() {
    // A key resolved earlier (a manager entry, say) keeps its material: a
    // later DEREncodedKeyValue is refused, as the other value readers refuse.
    const PEM: &str = include_str!("../../../../../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    let body: String = PEM
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let doc = parse(&format!(
        "<DEREncodedKeyValue xmlns=\"http://www.w3.org/2009/xmldsig11#\">{body}</DEREncodedKeyValue>"
    ));
    // SAFETY: objects created and destroyed here.
    unsafe {
        assert_eq!(xmlSecKeyDataIdsInit(), 0);
        let ctx = xmlSecKeyInfoCtxCreate(std::ptr::null_mut());
        let key = xmlSecKeyCreate();
        let data = xmlSecKeyDataCreate(symkeys::hmac());
        assert_eq!(
            xmlSecKeyDataBinaryValueSetBuffer(data, b"secret".as_ptr(), 6),
            0
        );
        assert_eq!(xmlSecKeySetValue(key, data), 0);
        let read = xmlSecKeyDataXmlRead(
            asymkeys::der_encoded_key_value(),
            key.cast(),
            xsDocGetRootElement(doc).cast(),
            ctx.cast(),
        );
        assert_eq!(read, -1);
        assert_eq!(xmlSecKeyGetValue(key), data, "the found value stays");
        xmlSecKeyDestroy(key);
        xmlSecKeyInfoCtxDestroy(ctx);
        xsFreeDoc(doc);
    }
}

#[test]
fn a_key_value_of_a_klass_the_enabled_list_leaves_out_is_not_written() {
    // An enabled list of KeyValue and RSA admits an RSA value: an HMAC
    // secret is not written, though the requirement admits symmetric keys.
    let doc = parse("<KeyValue xmlns=\"http://www.w3.org/2000/09/xmldsig#\"/>");
    // SAFETY: objects created and destroyed here.
    unsafe {
        assert_eq!(xmlSecKeyDataIdsInit(), 0);
        let ctx = xmlSecKeyInfoCtxCreate(std::ptr::null_mut());
        (*ctx).mode = MODE_WRITE;
        (*ctx).key_req.key_type = TYPE_SYMMETRIC;
        let enabled = &raw mut (*ctx).enabled_key_data;
        assert_eq!(
            xmlSecPtrListAdd(enabled, xmlSecKeyDataValueGetKlass().cast_mut().cast()),
            0
        );
        assert_eq!(
            xmlSecPtrListAdd(enabled, asymkeys::rsa().cast_mut().cast()),
            0
        );
        let key = xmlSecKeyCreate();
        let data = xmlSecKeyDataCreate(symkeys::hmac());
        assert_eq!(
            xmlSecKeyDataBinaryValueSetBuffer(data, b"secret".as_ptr(), 6),
            0
        );
        assert_eq!(xmlSecKeySetValue(key, data), 0);
        assert_eq!(xmlSecKeySetName(key, c"k".as_ptr().cast()), 0);
        let node = xsDocGetRootElement(doc);
        assert_eq!(
            xmlSecKeyDataXmlWrite(
                xmlSecKeyDataValueGetKlass(),
                key.cast(),
                node.cast(),
                ctx.cast()
            ),
            0
        );
        assert!(nodes::first_child(node).is_null(), "nothing is written");
        xmlSecKeyDestroy(key);
        xmlSecKeyInfoCtxDestroy(ctx);
        xsFreeDoc(doc);
    }
}
