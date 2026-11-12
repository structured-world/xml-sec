//! Copying or setting a key's members onto themselves leaves them as they
//! were: each operation would otherwise free what it then reads or keeps.

use std::ffi::CStr;

use super::{
    XmlSecKeyReq, XmlSecKeyUseWith, xmlSecKeyAdoptData, xmlSecKeyCopy, xmlSecKeyCreate,
    xmlSecKeyDestroy, xmlSecKeyGetName, xmlSecKeyGetValue, xmlSecKeyReqCopy, xmlSecKeyReqFinalize,
    xmlSecKeyReqInitialize, xmlSecKeySetName, xmlSecKeySetValue, xmlSecKeyUseWithCopy,
    xmlSecKeyUseWithCreate, xmlSecKeyUseWithDestroy,
};
use crate::ffi::keysdata::{xmlSecKeyDataBinaryValueSetBuffer, xmlSecKeyDataCreate};
use crate::ffi::list::{xmlSecPtrListAdd, xmlSecPtrListGetSize};
use crate::ffi::symkeys;

/// A key named `name` holding an HMAC value.
///
/// # Safety
/// The caller destroys the key.
unsafe fn hmac_key(name: &CStr) -> *mut super::XmlSecKey {
    // SAFETY: a klass of the built-in table; the key adopts the data.
    unsafe {
        let key = xmlSecKeyCreate();
        let data = xmlSecKeyDataCreate(symkeys::hmac());
        assert_eq!(
            xmlSecKeyDataBinaryValueSetBuffer(data, b"secret".as_ptr(), 6),
            0
        );
        assert_eq!(xmlSecKeySetValue(key, data), 0);
        assert_eq!(xmlSecKeySetName(key, name.as_ptr().cast()), 0);
        key
    }
}

#[test]
fn a_use_with_record_copied_onto_itself_keeps_its_strings() {
    // The setter frees the strings it is given before reading them.
    // SAFETY: a record created and destroyed here.
    unsafe {
        let record: *mut XmlSecKeyUseWith =
            xmlSecKeyUseWithCreate(c"app".as_ptr().cast(), c"id".as_ptr().cast());
        assert_eq!(xmlSecKeyUseWithCopy(record, record), 0);
        assert_eq!(CStr::from_ptr((*record).application.cast()), c"app");
        assert_eq!(CStr::from_ptr((*record).identifier.cast()), c"id");
        xmlSecKeyUseWithDestroy(record);
    }
}

#[test]
fn requirements_copied_onto_themselves_keep_their_records() {
    // Copying a list into itself would append to it while reading it.
    // SAFETY: requirements initialized and finalized here.
    unsafe {
        let mut req = std::mem::MaybeUninit::<XmlSecKeyReq>::uninit();
        let req = req.as_mut_ptr();
        assert_eq!(xmlSecKeyReqInitialize(req), 0);
        let record = xmlSecKeyUseWithCreate(c"a".as_ptr().cast(), c"b".as_ptr().cast());
        assert_eq!(
            xmlSecPtrListAdd(&raw mut (*req).key_use_with_list, record.cast()),
            0
        );
        assert_eq!(xmlSecKeyReqCopy(req, req), 0);
        assert_eq!(xmlSecPtrListGetSize(&raw mut (*req).key_use_with_list), 1);
        xmlSecKeyReqFinalize(req);
    }
}

#[test]
fn a_key_copied_onto_itself_keeps_its_name_and_value() {
    // Emptying the destination first would destroy the source.
    // SAFETY: a key created and destroyed here.
    unsafe {
        let key = hmac_key(c"named");
        assert_eq!(xmlSecKeyCopy(key, key), 0);
        assert_eq!(CStr::from_ptr(xmlSecKeyGetName(key).cast()), c"named");
        assert!(!xmlSecKeyGetValue(key).is_null());
        xmlSecKeyDestroy(key);
    }
}

#[test]
fn setting_or_adopting_a_value_the_key_owns_keeps_it() {
    // Destroying the old value before storing the same pointer, or listing
    // the value a second time, leaves freed or doubly owned data.
    // SAFETY: a key created and destroyed here.
    unsafe {
        let key = hmac_key(c"k");
        let value = xmlSecKeyGetValue(key);
        assert_eq!(xmlSecKeySetValue(key, value), 0);
        assert_eq!(xmlSecKeyAdoptData(key, value), 0);
        assert_eq!(xmlSecKeyGetValue(key), value);
        assert!(
            (*key).data_list.is_null() || xmlSecPtrListGetSize((*key).data_list) == 0,
            "the value is not listed as further data"
        );
        xmlSecKeyDestroy(key);
    }
}

#[test]
fn a_key_store_klass_too_small_for_its_object_is_refused() {
    // A store klass whose object cannot hold the store header, or which has
    // no name, is refused before anything is allocated or written.
    use crate::ffi::keysmngr::{XmlSecKeyStore, XmlSecKeyStoreKlass, xmlSecKeyStoreCreate};
    let klass = |obj_size: usize, name: *const u8| XmlSecKeyStoreKlass {
        klass_size: size_of::<XmlSecKeyStoreKlass>(),
        obj_size,
        name,
        initialize: None,
        finalize: None,
        find_key: None,
        find_key_from_x509_data: None,
        reserved0: std::ptr::null_mut(),
    };
    let short = klass(size_of::<XmlSecKeyStore>() - 1, c"short".as_ptr().cast());
    let unnamed = klass(size_of::<XmlSecKeyStore>(), std::ptr::null());
    // SAFETY: klasses that outlive the calls; nothing is created.
    unsafe {
        assert!(xmlSecKeyStoreCreate(&raw const short).is_null());
        assert!(xmlSecKeyStoreCreate(&raw const unnamed).is_null());
    }
}
