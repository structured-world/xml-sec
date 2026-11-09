//! Key-data klass registry and binary values without a C caller; custom
//! klasses and stores are compared with libxmlsec1 by the differential C
//! program.

use std::ffi::CStr;

use super::{
    XmlSecKeyDataKlass, xmlSecKeyDataIdListFindByName, xmlSecKeyDataIdsGet,
    xmlSecKeyDataIdsGetEnabled, xmlSecKeyDataIdsInit, xmlSecKeyDataIdsShutdown,
};
use crate::ffi::list::{xmlSecPtrListGetItem, xmlSecPtrListGetSize};

/// The names of the klasses in a registry list.
///
/// # Safety
/// `list` is an initialized key-data klass list.
unsafe fn names(list: *mut crate::ffi::list::XmlSecPtrList) -> Vec<String> {
    // SAFETY: by the caller's contract; klass names are static strings.
    unsafe {
        (0..xmlSecPtrListGetSize(list))
            .map(|pos| {
                let klass = xmlSecPtrListGetItem(list, pos).cast::<XmlSecKeyDataKlass>();
                CStr::from_ptr((*klass).name.cast())
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }
}

/// The registry holds libxmlsec1's `KeyInfo` child klasses in its order;
/// `KeyValue` and the experimental encapsulation mechanism are registered
/// but not enabled, so lookups in the enabled list miss them.
#[test]
fn registry_enables_all_defaults_but_key_value_and_encapsulation() {
    // SAFETY: this test owns the registries for its process.
    unsafe {
        assert_eq!(xmlSecKeyDataIdsInit(), 0);
        assert_eq!(
            names(xmlSecKeyDataIdsGet()),
            [
                "key-name",
                "retrieval-method",
                "key-info-reference",
                "enc-key",
                "agreement-method",
                "derived-key",
                "encapsulation-mechanism",
                "key-value",
            ]
        );
        assert_eq!(names(xmlSecKeyDataIdsGetEnabled()).len(), 6);
        let any = 0xFFFFF;
        assert!(
            !xmlSecKeyDataIdListFindByName(
                xmlSecKeyDataIdsGet(),
                c"key-value".as_ptr().cast(),
                any
            )
            .is_null()
        );
        assert!(
            xmlSecKeyDataIdListFindByName(
                xmlSecKeyDataIdsGetEnabled(),
                c"key-value".as_ptr().cast(),
                any
            )
            .is_null()
        );
        xmlSecKeyDataIdsShutdown();
        assert_eq!(xmlSecPtrListGetSize(xmlSecKeyDataIdsGet()), 0);
    }
}
