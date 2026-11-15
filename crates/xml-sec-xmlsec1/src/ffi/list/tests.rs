//! The pointer list against libxmlsec1's semantics: item ownership through
//! the klass, positions, growth and refusals.

use super::{
    XmlSecPtrList, XmlSecPtrListKlass, xmlSecPtrListAdd, xmlSecPtrListCopy, xmlSecPtrListCreate,
    xmlSecPtrListDestroy, xmlSecPtrListDuplicate, xmlSecPtrListEmpty, xmlSecPtrListFinalize,
    xmlSecPtrListGetItem, xmlSecPtrListGetSize, xmlSecPtrListInitialize, xmlSecPtrListInsert,
    xmlSecPtrListPopLast, xmlSecPtrListRemove, xmlSecPtrListRemoveAndReturn, xmlSecPtrListSet,
    xmlSecPtrListSort, xmlSecStringListGetKlass,
};
use std::cell::Cell;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::mem::MaybeUninit;

thread_local! {
    /// Items destroyed by [`COUNTING`] on this thread: each test runs on its
    /// own thread, so the count is the test's own however tests overlap.
    static DESTROYED: Cell<usize> = const { Cell::new(0) };
}

unsafe extern "C" fn count_destroy(_item: *mut c_void) {
    DESTROYED.with(|count| count.set(count.get() + 1));
}

/// The items [`COUNTING`] destroyed in this test.
fn destroyed() -> usize {
    DESTROYED.with(Cell::get)
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
        assert_eq!(destroyed(), 1);
        assert_eq!(xmlSecPtrListRemoveAndReturn(list, 0).addr(), 1);
        assert_eq!(xmlSecPtrListPopLast(list).addr(), 8);
        assert_eq!(destroyed(), 1);
        assert_eq!(xmlSecPtrListSet(list, item(5), 0), 0);
        assert_eq!(destroyed(), 2);
        assert_eq!(items(list), [5, 3]);
        // Out-of-range positions are refused without touching items.
        assert!(xmlSecPtrListGetItem(list, 2).is_null());
        assert_eq!(xmlSecPtrListSet(list, item(6), 2), -1);
        assert_eq!(xmlSecPtrListRemove(list, 2), -1);
        assert!(xmlSecPtrListRemoveAndReturn(list, 2).is_null());
        xmlSecPtrListDestroy(list);
        assert_eq!(destroyed(), 4);
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
        assert_eq!(destroyed(), 200);
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

/// A klass that neither duplicates nor destroys: its lists share pointers.
static BORROWING: XmlSecPtrListKlass = XmlSecPtrListKlass {
    name: c"borrowing".as_ptr().cast(),
    duplicate_item: None,
    destroy_item: None,
    debug_dump_item: None,
    debug_xml_dump_item: None,
};

/// Lists of different klasses are not copied into each other; a klass that
/// destroys items it cannot duplicate is not copyable, since both lists would
/// destroy each item; a klass with neither method copies the pointers, and a
/// list copied to itself is unchanged.
#[test]
fn copy_checks_the_klass() {
    // SAFETY: the klasses are static and the lists are used while live.
    unsafe {
        let counting = xmlSecPtrListCreate(&raw const COUNTING);
        let strings = xmlSecPtrListCreate(xmlSecStringListGetKlass());
        xmlSecPtrListAdd(counting, item(4));
        assert_eq!(xmlSecPtrListCopy(strings, counting), -1);
        let other = xmlSecPtrListCreate(&raw const COUNTING);
        assert_eq!(xmlSecPtrListCopy(other, counting), -1);
        assert_eq!(items(other), Vec::<usize>::new());
        let shared = xmlSecPtrListCreate(&raw const BORROWING);
        let copy = xmlSecPtrListCreate(&raw const BORROWING);
        xmlSecPtrListAdd(shared, item(7));
        assert_eq!(xmlSecPtrListCopy(copy, shared), 0);
        assert_eq!(items(copy), [7]);
        assert_eq!(xmlSecPtrListCopy(shared, shared), 0);
        assert_eq!(items(shared), [7]);
        for list in [other, counting, strings, shared, copy] {
            xmlSecPtrListDestroy(list);
        }
    }
}

thread_local! {
    /// Duplications [`FAILING`] still makes before it fails.
    static DUPLICATES_LEFT: Cell<usize> = const { Cell::new(0) };
}

unsafe extern "C" fn failing_duplicate(item: *mut c_void) -> *mut c_void {
    DUPLICATES_LEFT.with(|left| match left.get() {
        0 => std::ptr::null_mut(),
        n => {
            left.set(n - 1);
            item
        }
    })
}

/// A klass whose duplication fails after a set number of items.
static FAILING: XmlSecPtrListKlass = XmlSecPtrListKlass {
    name: c"failing".as_ptr().cast(),
    duplicate_item: Some(failing_duplicate),
    destroy_item: Some(count_destroy),
    debug_dump_item: None,
    debug_xml_dump_item: None,
};

/// A copy that fails partway destroys the copies it made and leaves the
/// destination with the items it had.
#[test]
fn a_failed_copy_leaves_the_destination_as_it_was() {
    // SAFETY: the klass is static and the lists are used while live.
    unsafe {
        let source = xmlSecPtrListCreate(&raw const FAILING);
        let target = xmlSecPtrListCreate(&raw const FAILING);
        for value in [1, 2, 3] {
            xmlSecPtrListAdd(source, item(value));
        }
        xmlSecPtrListAdd(target, item(9));
        DUPLICATES_LEFT.with(|left| left.set(2));
        assert_eq!(xmlSecPtrListCopy(target, source), -1);
        assert_eq!(items(target), [9]);
        assert_eq!(destroyed(), 2, "the two copies made are destroyed");
        xmlSecPtrListDestroy(source);
        xmlSecPtrListDestroy(target);
    }
}

unsafe extern "C" fn by_value(left: *mut c_void, right: *mut c_void) -> c_int {
    match left.addr().cmp(&right.addr()) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}

/// Sorting orders the items by the comparison; lists of zero and one items
/// need none, and a missing comparison is refused.
#[test]
fn sort_orders_the_items() {
    // SAFETY: the klass is static and the list is used while live.
    unsafe {
        let list = xmlSecPtrListCreate(&raw const BORROWING);
        assert_eq!(xmlSecPtrListSort(list, Some(by_value)), 0);
        xmlSecPtrListAdd(list, item(5));
        assert_eq!(xmlSecPtrListSort(list, Some(by_value)), 0);
        for value in [3, 9, 1, 7, 3, 8] {
            xmlSecPtrListAdd(list, item(value));
        }
        assert_eq!(xmlSecPtrListSort(list, None), -1);
        assert_eq!(xmlSecPtrListSort(list, Some(by_value)), 0);
        assert_eq!(items(list), [1, 3, 3, 5, 7, 8, 9]);
        xmlSecPtrListDestroy(list);
    }
}

/// Reading past the end answers null without a report.
#[test]
fn reading_past_the_end_is_null() {
    // SAFETY: the klass is static and the list is used while live.
    unsafe {
        let list = xmlSecPtrListCreate(&raw const BORROWING);
        assert!(xmlSecPtrListGetItem(list, 0).is_null());
        xmlSecPtrListAdd(list, item(1));
        assert!(xmlSecPtrListGetItem(list, 1).is_null());
        xmlSecPtrListDestroy(list);
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
