//! Copying or setting a key's members onto themselves leaves them as they
//! were: each operation would otherwise free what it then reads or keeps.

use std::ffi::CStr;

use super::{
    XmlSecKeyReq, XmlSecKeyUseWith, xmlSecKeyAdoptData, xmlSecKeyCopy, xmlSecKeyCreate,
    xmlSecKeyDestroy, xmlSecKeyGetName, xmlSecKeyGetValue, xmlSecKeyReqCopy, xmlSecKeyReqFinalize,
    xmlSecKeyReqInitialize, xmlSecKeySetName, xmlSecKeySetNameEx, xmlSecKeySetValue,
    xmlSecKeyUseWithCopy, xmlSecKeyUseWithCreate, xmlSecKeyUseWithDestroy, xmlSecKeyUseWithSet,
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
fn a_name_set_from_the_keys_own_name_survives() {
    // The setters read their input before releasing what the key holds:
    // the key's own name, or a part of it, is a valid input.
    // SAFETY: a key created and destroyed here.
    unsafe {
        let key = hmac_key(c"ab");
        assert_eq!(xmlSecKeySetName(key, xmlSecKeyGetName(key)), 0);
        assert_eq!(CStr::from_ptr(xmlSecKeyGetName(key).cast()), c"ab");
        assert_eq!(xmlSecKeySetNameEx(key, xmlSecKeyGetName(key), 1), 0);
        assert_eq!(CStr::from_ptr(xmlSecKeyGetName(key).cast()), c"a");
        xmlSecKeyDestroy(key);
    }
}

#[test]
fn use_with_fields_set_from_each_other_survive() {
    // Swapping the record's own strings must not read a freed one.
    // SAFETY: a record created and destroyed here.
    unsafe {
        let record = xmlSecKeyUseWithCreate(c"ab".as_ptr().cast(), c"cd".as_ptr().cast());
        assert_eq!(
            xmlSecKeyUseWithSet(record, (*record).identifier, (*record).application),
            0
        );
        assert_eq!(CStr::from_ptr((*record).application.cast()), c"cd");
        assert_eq!(CStr::from_ptr((*record).identifier.cast()), c"ab");
        xmlSecKeyUseWithDestroy(record);
    }
}

#[test]
fn a_bounded_name_reads_only_up_to_its_nul() {
    // `name_size` bounds the read; a NUL before it ends the name, and the
    // bytes past the NUL need not exist.
    let name = b"ab\0";
    // SAFETY: a key created and destroyed here; the name has a NUL within
    // the allocation, as the contract requires.
    unsafe {
        let key = hmac_key(c"k");
        assert_eq!(xmlSecKeySetNameEx(key, name.as_ptr(), 1024), 0);
        assert_eq!(CStr::from_ptr(xmlSecKeyGetName(key).cast()), c"ab");
        xmlSecKeyDestroy(key);
    }
}

#[test]
fn copied_requirements_replace_the_destination_records() {
    // The destination ends with the source's records only, as libxmlsec1
    // empties it before copying.
    // SAFETY: requirements initialized and finalized here.
    unsafe {
        let mut dst = std::mem::MaybeUninit::<XmlSecKeyReq>::uninit();
        let mut src = std::mem::MaybeUninit::<XmlSecKeyReq>::uninit();
        let (dst, src) = (dst.as_mut_ptr(), src.as_mut_ptr());
        assert_eq!(xmlSecKeyReqInitialize(dst), 0);
        assert_eq!(xmlSecKeyReqInitialize(src), 0);
        let old = xmlSecKeyUseWithCreate(c"a".as_ptr().cast(), c"1".as_ptr().cast());
        let new = xmlSecKeyUseWithCreate(c"b".as_ptr().cast(), c"2".as_ptr().cast());
        assert_eq!(
            xmlSecPtrListAdd(&raw mut (*dst).key_use_with_list, old.cast()),
            0
        );
        assert_eq!(
            xmlSecPtrListAdd(&raw mut (*src).key_use_with_list, new.cast()),
            0
        );
        assert_eq!(xmlSecKeyReqCopy(dst, src), 0);
        assert_eq!(xmlSecPtrListGetSize(&raw mut (*dst).key_use_with_list), 1);
        xmlSecKeyReqFinalize(dst);
        xmlSecKeyReqFinalize(src);
    }
}

#[test]
fn a_store_the_manager_already_owns_is_adopted_again_unchanged() {
    // Adopting the store the manager returns, or a data store it holds,
    // keeps it: releasing it first would leave the manager a freed store.
    use crate::ffi::keysdata::{
        XmlSecKeyDataStore, XmlSecKeyDataStoreKlass, xmlSecKeyDataStoreCreate,
    };
    use crate::ffi::keysmngr::{
        xmlSecKeyStoreCreate, xmlSecKeysMngrAdoptDataStore, xmlSecKeysMngrAdoptKeysStore,
        xmlSecKeysMngrCreate, xmlSecKeysMngrDestroy, xmlSecKeysMngrGetDataStore,
        xmlSecKeysMngrGetKeysStore, xmlSecSimpleKeysStoreGetKlass,
    };
    let data_klass = XmlSecKeyDataStoreKlass {
        klass_size: size_of::<XmlSecKeyDataStoreKlass>(),
        obj_size: size_of::<XmlSecKeyDataStore>(),
        name: c"test-data-store".as_ptr().cast(),
        initialize: None,
        finalize: None,
        reserved0: std::ptr::null_mut(),
        reserved1: std::ptr::null_mut(),
    };
    // SAFETY: a manager and stores created here, the klass outliving them.
    unsafe {
        let mngr = xmlSecKeysMngrCreate();
        let store = xmlSecKeyStoreCreate(xmlSecSimpleKeysStoreGetKlass());
        assert_eq!(xmlSecKeysMngrAdoptKeysStore(mngr, store), 0);
        let owned = xmlSecKeysMngrGetKeysStore(mngr);
        assert_eq!(xmlSecKeysMngrAdoptKeysStore(mngr, owned), 0);
        assert_eq!(xmlSecKeysMngrGetKeysStore(mngr), store);
        let data = xmlSecKeyDataStoreCreate(&raw const data_klass);
        assert_eq!(xmlSecKeysMngrAdoptDataStore(mngr, data), 0);
        let held = xmlSecKeysMngrGetDataStore(mngr, (&raw const data_klass).cast());
        assert_eq!(xmlSecKeysMngrAdoptDataStore(mngr, held), 0);
        assert_eq!(
            xmlSecKeysMngrGetDataStore(mngr, (&raw const data_klass).cast()),
            data
        );
        xmlSecKeysMngrDestroy(mngr);
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
