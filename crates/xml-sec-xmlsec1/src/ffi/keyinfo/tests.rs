//! `KeyInfo` processing honours the context's flags and enabled list where
//! they decide what is read or written.

use xml_sec::policy::KeySourceKind;
use xml_sec::xmldsig::UriTypeSet;
use xml_sec_libxml2::ffi::tree::{xsDocGetRootElement, xsFreeDoc, xsReadMemory};

use super::{MODE_WRITE, xmlSecKeyInfoCtxCreate, xmlSecKeyInfoCtxDestroy, xmlSecKeyInfoNodeRead};
use crate::ffi::errors;
use crate::ffi::keys::{
    TYPE_SYMMETRIC, xmlSecKeyCreate, xmlSecKeyDestroy, xmlSecKeyGetName, xmlSecKeyGetValue,
    xmlSecKeySetName, xmlSecKeySetValue,
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
use crate::ffi::policy;
use crate::ffi::tests::own_process;
use crate::ffi::transforms::io::{xmlSecIOInit, xmlSecIORegisterCallbacks, xmlSecIOShutdown};
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
    own_process();
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
    own_process();
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
fn a_key_source_the_policy_denies_is_refused() {
    // The verification policy's key sources decide what a document may use,
    // whatever klasses the context enables: a denied KeyName fails the read.
    own_process();
    let xml =
        "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><KeyName>alice</KeyName></KeyInfo>";
    // SAFETY: a context created and destroyed here.
    unsafe {
        assert_eq!(xmlSecKeyDataIdsInit(), 0);
        let ctx = xmlSecKeyInfoCtxCreate(std::ptr::null_mut());
        assert_eq!(
            read_reported(xml, ctx).0,
            0,
            "KeyName is permitted by default"
        );
        policy::republish(
            |verification| verification.key_sources.remove(KeySourceKind::KeyName),
            |_| {},
        )
        .expect("the library policy compiles");
        let (read, reasons) = read_reported(xml, ctx);
        assert_eq!(read, -1);
        assert_eq!(reasons.first(), Some(&errors::R_KEYDATA_DISABLED));
        xmlSecKeyInfoCtxDestroy(ctx);
    }
}

/// What the external resource the reference reads holds.
const REFERENCED: &str =
    "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><KeyName>alice</KeyName></KeyInfo>";
/// The octets of [`REFERENCED`] not yet read.
static SENT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

unsafe extern "C" fn matches(_uri: *const std::ffi::c_char) -> std::ffi::c_int {
    1
}

/// Opens the resource and, as another thread could at that moment,
/// republishes a policy under which the resource is too large to read.
unsafe extern "C" fn open_and_republish(_uri: *const std::ffi::c_char) -> *mut std::ffi::c_void {
    SENT.store(0, std::sync::atomic::Ordering::Relaxed);
    policy::republish(
        |verification| verification.resources.max_external_resource_bytes = 1,
        |_| {},
    )
    .expect("the library policy compiles");
    std::ptr::NonNull::<u8>::dangling().as_ptr().cast()
}

unsafe extern "C" fn read_resource(
    _context: *mut std::ffi::c_void,
    buffer: *mut std::ffi::c_char,
    len: std::ffi::c_int,
) -> std::ffi::c_int {
    let sent = SENT.load(std::sync::atomic::Ordering::Relaxed);
    let rest = &REFERENCED.as_bytes()[sent..];
    let count = rest
        .len()
        .min(usize::try_from(len).expect("a non-negative length"));
    // SAFETY: the transform passes `len` writable bytes.
    unsafe { std::ptr::copy_nonoverlapping(rest.as_ptr(), buffer.cast(), count) };
    SENT.store(sent + count, std::sync::atomic::Ordering::Relaxed);
    std::ffi::c_int::try_from(count).expect("at most `len` octets")
}

unsafe extern "C" fn close(_context: *mut std::ffi::c_void) -> std::ffi::c_int {
    0
}

#[test]
fn a_key_info_read_keeps_the_policy_it_started_under() {
    // A policy republished while a KeyInfo read follows a reference reaches
    // neither the chain the reference runs nor the rest of the read.
    own_process();
    policy::republish(
        |verification| verification.uris.key_info_references = UriTypeSet::ALL,
        |_| {},
    )
    .expect("the library policy compiles");
    // SAFETY: the callback list, the context and the key are used by this
    // test alone and released here.
    unsafe {
        assert_eq!(xmlSecKeyDataIdsInit(), 0);
        assert_eq!(xmlSecIOInit(), 0);
        assert_eq!(
            xmlSecIORegisterCallbacks(
                Some(matches),
                Some(open_and_republish),
                Some(read_resource),
                Some(close)
            ),
            0
        );
        let ctx = xmlSecKeyInfoCtxCreate(std::ptr::null_mut());
        let doc = parse(
            "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\" \
             xmlns:dsig11=\"http://www.w3.org/2009/xmldsig11#\">\
             <dsig11:KeyInfoReference URI=\"test:key\"/></KeyInfo>",
        );
        let key = xmlSecKeyCreate();
        assert_eq!(xmlSecKeyInfoNodeRead(xsDocGetRootElement(doc), key, ctx), 0);
        let name = xmlSecKeyGetName(key);
        assert!(!name.is_null(), "the referenced KeyName is read");
        assert_eq!(std::ffi::CStr::from_ptr(name.cast()).to_bytes(), b"alice");
        xmlSecKeyDestroy(key);
        xsFreeDoc(doc);
        xmlSecKeyInfoCtxDestroy(ctx);
        xmlSecIOShutdown();
    }
}

/// An empty `KeyInfo`, which finds no key, so a read goes on to the next
/// reference.
const EMPTY: &str = "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"/>";
/// The octets of [`EMPTY`] not yet read from the open resource.
static EMPTY_SENT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

unsafe extern "C" fn open_empty(_uri: *const std::ffi::c_char) -> *mut std::ffi::c_void {
    EMPTY_SENT.store(0, std::sync::atomic::Ordering::Relaxed);
    std::ptr::NonNull::<u8>::dangling().as_ptr().cast()
}

unsafe extern "C" fn read_empty(
    _context: *mut std::ffi::c_void,
    buffer: *mut std::ffi::c_char,
    len: std::ffi::c_int,
) -> std::ffi::c_int {
    let sent = EMPTY_SENT.load(std::sync::atomic::Ordering::Relaxed);
    let rest = &EMPTY.as_bytes()[sent..];
    let count = rest
        .len()
        .min(usize::try_from(len).expect("a non-negative length"));
    // SAFETY: the transform passes `len` writable bytes.
    unsafe { std::ptr::copy_nonoverlapping(rest.as_ptr(), buffer.cast(), count) };
    EMPTY_SENT.store(sent + count, std::sync::atomic::Ordering::Relaxed);
    std::ffi::c_int::try_from(count).expect("at most `len` octets")
}

#[test]
fn the_references_of_one_read_share_its_resource_budget() {
    // Each reference fits the per-resource limit, but one read may not take
    // more than the aggregate limit across all of them: the second resource
    // passes it, so the read fails.
    own_process();
    let size = EMPTY.len();
    policy::republish(
        |verification| {
            verification.uris.key_info_references = UriTypeSet::ALL;
            verification.resources.max_external_resource_bytes = size;
            verification.resources.max_external_resource_total_bytes = size + size / 2;
        },
        |_| {},
    )
    .expect("the library policy compiles");
    let two = "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\" \
               xmlns:dsig11=\"http://www.w3.org/2009/xmldsig11#\">\
               <dsig11:KeyInfoReference URI=\"test:a\"/>\
               <dsig11:KeyInfoReference URI=\"test:b\"/></KeyInfo>";
    let one = "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\" \
               xmlns:dsig11=\"http://www.w3.org/2009/xmldsig11#\">\
               <dsig11:KeyInfoReference URI=\"test:a\"/></KeyInfo>";
    // SAFETY: the callback list and the context are used by this test alone
    // and released here.
    unsafe {
        assert_eq!(xmlSecKeyDataIdsInit(), 0);
        assert_eq!(xmlSecIOInit(), 0);
        assert_eq!(
            xmlSecIORegisterCallbacks(
                Some(matches),
                Some(open_empty),
                Some(read_empty),
                Some(close)
            ),
            0
        );
        let ctx = xmlSecKeyInfoCtxCreate(std::ptr::null_mut());
        assert_eq!(read_reported(one, ctx).0, 0, "one resource fits");
        assert_eq!(read_reported(two, ctx).0, -1, "two pass the aggregate");
        assert_eq!(read_reported(one, ctx).0, 0, "a new read starts afresh");
        xmlSecKeyInfoCtxDestroy(ctx);
        xmlSecIOShutdown();
    }
}

#[test]
fn a_key_reference_opens_its_uri_under_the_key_reference_classes() {
    // A policy admitting external key references while keeping a
    // signature's references in the document still reads the key
    // reference: the open follows the classes admitted for keys.
    own_process();
    policy::republish(
        |verification| {
            verification.uris.key_info_references = UriTypeSet::ALL;
            verification.uris.references = UriTypeSet::SAME_DOCUMENT;
        },
        |_| {},
    )
    .expect("the library policy compiles");
    let xml = "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\" \
               xmlns:dsig11=\"http://www.w3.org/2009/xmldsig11#\">\
               <dsig11:KeyInfoReference URI=\"test:a\"/></KeyInfo>";
    // SAFETY: the callback list and the context are used by this test alone
    // and released here.
    unsafe {
        assert_eq!(xmlSecKeyDataIdsInit(), 0);
        assert_eq!(xmlSecIOInit(), 0);
        assert_eq!(
            xmlSecIORegisterCallbacks(
                Some(matches),
                Some(open_empty),
                Some(read_empty),
                Some(close)
            ),
            0
        );
        let ctx = xmlSecKeyInfoCtxCreate(std::ptr::null_mut());
        let (read, reasons) = read_reported(xml, ctx);
        assert_eq!((read, reasons), (0, Vec::new()));
        xmlSecKeyInfoCtxDestroy(ctx);
        xmlSecIOShutdown();
    }
}

#[test]
fn a_der_encoded_key_value_past_the_resource_limit_is_refused_before_decoding() {
    // The encoded text is bounded by what it can decode to, against the
    // per-resource limit, before any buffer is sized for it.
    const PEM: &str = include_str!("../../../../../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem");
    own_process();
    let body: String = PEM
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    policy::republish(
        |verification| verification.resources.max_external_resource_bytes = 64,
        |_| {},
    )
    .expect("the library policy compiles");
    let doc = parse(&format!(
        "<DEREncodedKeyValue xmlns=\"http://www.w3.org/2009/xmldsig11#\">{body}</DEREncodedKeyValue>"
    ));
    // SAFETY: objects created and destroyed here; the callback has the
    // callback's signature.
    unsafe {
        assert_eq!(xmlSecKeyDataIdsInit(), 0);
        REASONS.lock().expect("reasons").clear();
        errors::xmlSecErrorsSetCallback(Some(record as errors::ErrorsCallback));
        let ctx = xmlSecKeyInfoCtxCreate(std::ptr::null_mut());
        let key = xmlSecKeyCreate();
        let read = xmlSecKeyDataXmlRead(
            asymkeys::der_encoded_key_value(),
            key.cast(),
            xsDocGetRootElement(doc).cast(),
            ctx.cast(),
        );
        assert_eq!(read, -1);
        assert_eq!(
            REASONS.lock().expect("reasons").first(),
            Some(&errors::R_INVALID_SIZE)
        );
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
