//! The pointer list against libxmlsec1's semantics: item ownership through
//! the klass, positions, growth and refusals.

use super::{
    XmlSecPtrList, XmlSecPtrListKlass, xmlSecPtrListAdd, xmlSecPtrListCopy, xmlSecPtrListCreate,
    xmlSecPtrListDestroy, xmlSecPtrListDuplicate, xmlSecPtrListEmpty, xmlSecPtrListFinalize,
    xmlSecPtrListGetItem, xmlSecPtrListGetSize, xmlSecPtrListInitialize, xmlSecPtrListInsert,
    xmlSecPtrListPopLast, xmlSecPtrListRemove, xmlSecPtrListRemoveAndReturn, xmlSecPtrListSet,
    xmlSecStringListGetKlass,
};
use std::ffi::{CStr, c_char, c_void};
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Items destroyed by [`COUNTING`].
static DESTROYED: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn count_destroy(_item: *mut c_void) {
    DESTROYED.fetch_add(1, Ordering::Relaxed);
}

/// A klass that records destruction and does not duplicate.
static COUNTING: XmlSecPtrListKlass = XmlSecPtrListKlass {
    name: c"counting".as_ptr().cast(),
    duplicate_item: None,
    destroy_item: Some(count_destroy),
    debug_dump_item: None,
    debug_xml_dump_item: None,
};

/// A distinct non-null item value; never dereferenced by the counting klass.
fn item(value: usize) -> *mut c_void {
    std::ptr::without_provenance_mut(value)
}

/// The items of `list` in order.
fn items(list: *mut XmlSecPtrList) -> Vec<usize> {
    // SAFETY: the list is live and every position is in range.
    unsafe {
        (0..xmlSecPtrListGetSize(list))
            .map(|pos| xmlSecPtrListGetItem(list, pos).addr())
            .collect()
    }
}

/// Items keep their positions through insertions and removals; removal
/// destroys an item, removal-and-return hands it back undestroyed.
#[test]
fn positions_and_ownership() {
    // SAFETY: the klass is static and the list is used while live.
    unsafe {
        let list = xmlSecPtrListCreate(&raw const COUNTING);
        assert!(!list.is_null());
        for value in [1, 2, 3] {
            assert_eq!(xmlSecPtrListAdd(list, item(value)), 0);
        }
        assert_eq!(xmlSecPtrListInsert(list, item(9), 1), 0);
        assert_eq!(xmlSecPtrListInsert(list, item(8), 100), 0);
        assert_eq!(items(list), [1, 9, 2, 3, 8]);
        assert_eq!(xmlSecPtrListRemove(list, 1), 0);
        assert_eq!(DESTROYED.load(Ordering::Relaxed), 1);
        assert_eq!(xmlSecPtrListRemoveAndReturn(list, 0).addr(), 1);
        assert_eq!(xmlSecPtrListPopLast(list).addr(), 8);
        assert_eq!(DESTROYED.load(Ordering::Relaxed), 1);
        assert_eq!(xmlSecPtrListSet(list, item(5), 0), 0);
        assert_eq!(DESTROYED.load(Ordering::Relaxed), 2);
        assert_eq!(items(list), [5, 3]);
        // Out-of-range positions are refused without touching items.
        assert!(xmlSecPtrListGetItem(list, 2).is_null());
        assert_eq!(xmlSecPtrListSet(list, item(6), 2), -1);
        assert_eq!(xmlSecPtrListRemove(list, 2), -1);
        assert!(xmlSecPtrListRemoveAndReturn(list, 2).is_null());
        xmlSecPtrListDestroy(list);
        assert_eq!(DESTROYED.load(Ordering::Relaxed), 4);
    }
}

/// Growth happens when the size reaches the allocation, from the default
/// 64 items, and storage survives growth.
#[test]
fn growth_keeps_items() {
    // SAFETY: the klass is static and the list is used while live.
    unsafe {
        let list = xmlSecPtrListCreate(&raw const COUNTING);
        for value in 1..=200 {
            assert_eq!(xmlSecPtrListAdd(list, item(value)), 0);
        }
        assert_eq!((*list).used, 200);
        assert!((*list).max > 200);
        assert_eq!(items(list), (1..=200).collect::<Vec<_>>());
        xmlSecPtrListEmpty(list);
        assert_eq!(((*list).used, (*list).max), (0, 0));
        assert!((*list).data.is_null());
        assert_eq!(DESTROYED.load(Ordering::Relaxed), 200);
        assert!(xmlSecPtrListPopLast(list).is_null());
        xmlSecPtrListDestroy(list);
    }
}

/// The strings klass duplicates items with libxml2's allocator on copy, so
/// both lists own separate strings.
#[test]
fn string_lists_duplicate_their_items() {
    // SAFETY: the strings are libxml2-allocated through the klass itself,
    // and the lists are used while live.
    unsafe {
        let klass = xmlSecStringListGetKlass();
        assert_eq!(CStr::from_ptr((*klass).name.cast()), c"strings-list");
        let list = xmlSecPtrListCreate(klass);
        let duplicate = (*klass).duplicate_item.expect("strings duplicate");
        let owned = duplicate(c"first".as_ptr().cast_mut().cast());
        assert_eq!(xmlSecPtrListAdd(list, owned), 0);
        let copy = xmlSecPtrListDuplicate(list);
        assert!(!copy.is_null());
        let original = xmlSecPtrListGetItem(list, 0);
        let copied = xmlSecPtrListGetItem(copy, 0);
        assert_ne!(original, copied);
        assert_eq!(CStr::from_ptr(copied.cast::<c_char>()), c"first");
        xmlSecPtrListDestroy(list);
        assert_eq!(
            CStr::from_ptr(xmlSecPtrListGetItem(copy, 0).cast::<c_char>()),
            c"first"
        );
        xmlSecPtrListDestroy(copy);
    }
}

/// Lists of different klasses are not copied into each other, and a klass
/// without a duplicate method copies the pointers.
#[test]
fn copy_checks_the_klass() {
    // SAFETY: both klasses are static and the lists are used while live.
    unsafe {
        let counting = xmlSecPtrListCreate(&raw const COUNTING);
        let strings = xmlSecPtrListCreate(xmlSecStringListGetKlass());
        xmlSecPtrListAdd(counting, item(4));
        assert_eq!(xmlSecPtrListCopy(strings, counting), -1);
        let other = xmlSecPtrListCreate(&raw const COUNTING);
        assert_eq!(xmlSecPtrListCopy(other, counting), 0);
        assert_eq!(items(other), [4]);
        xmlSecPtrListDestroy(other);
        xmlSecPtrListDestroy(counting);
        xmlSecPtrListDestroy(strings);
    }
}

/// A list the caller owns is initialized in place and zeroed when
/// finalized; a list without a klass is refused everywhere.
#[test]
fn caller_owned_and_invalid_lists() {
    let mut storage = MaybeUninit::<XmlSecPtrList>::uninit();
    let list = storage.as_mut_ptr();
    // SAFETY: `storage` is writable memory of a list's size.
    unsafe {
        assert_eq!(xmlSecPtrListInitialize(list, std::ptr::null()), -1);
        assert_eq!(xmlSecPtrListInitialize(list, &raw const COUNTING), 0);
        assert_eq!(xmlSecPtrListAdd(list, item(1)), 0);
        xmlSecPtrListFinalize(list);
        assert!((*list).id.is_null());
        // The finalized list has no klass and is refused.
        assert_eq!(xmlSecPtrListAdd(list, item(2)), -1);
        assert_eq!(xmlSecPtrListGetSize(list), 0);
        assert!(xmlSecPtrListCreate(std::ptr::null()).is_null());
        assert_eq!(xmlSecPtrListAdd(std::ptr::null_mut(), item(1)), -1);
    }
}
