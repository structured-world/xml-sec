//! `xmlsec/keysmngr.h`: keys managers, the key store klass protocol and the
//! simple keys store, as libxmlsec1 defines them.
//!
//! A keys manager is a caller-owned object holding one key store and a list
//! of key-data stores; nothing about it is process-global. A key store is an
//! object of a store klass driven through its methods, so a caller's store
//! klass works as with libxmlsec1. The simple store keeps a list of keys and
//! finds a key by name and requirements.

use std::cell::Cell;
use std::ffi::{c_char, c_int, c_uint, c_void};

use super::errors::{self, check, here};
use super::keyinfo::{XmlSecKeyInfoCtx, read_policy, xmlSecKeyInfoNodeRead};
use super::keys::{
    XmlSecKey, xmlSecKeyCreate, xmlSecKeyDestroy, xmlSecKeyDuplicate, xmlSecKeyMatch,
    xmlSecKeyPtrListGetKlass,
};
use super::keysdata::{XmlSecKeyDataStore, xmlSecKeyDataStorePtrListGetKlass};
use super::list::{
    XmlSecPtrList, xmlSecPtrListAdd, xmlSecPtrListFinalize, xmlSecPtrListGetItem,
    xmlSecPtrListGetSize, xmlSecPtrListInitialize, xmlSecPtrListSet,
};
use super::policy;
use super::transforms::zero_list;
use super::tree::{XmlNode, nodes};
use super::{contain, free, malloc};

/// `XMLSEC_KEYINFO_FLAGS_LAX_KEY_SEARCH`.
const FLAGS_LAX_KEY_SEARCH: c_uint = 0x0000_8000;

/// `xmlSecGetKeyCallback`.
pub(crate) type GetKeyCallback =
    Option<unsafe extern "C" fn(*mut XmlNode, *mut XmlSecKeyInfoCtx) -> *mut XmlSecKey>;

/// `xmlSecKeysMngr`.
#[repr(C)]
pub(crate) struct XmlSecKeysMngr {
    pub(crate) keys_store: *mut XmlSecKeyStore,
    pub(crate) stores_list: XmlSecPtrList,
    pub(crate) get_key: GetKeyCallback,
}

/// `xmlSecKeyStore`.
#[repr(C)]
pub(crate) struct XmlSecKeyStore {
    pub(crate) id: *const XmlSecKeyStoreKlass,
    pub(crate) reserved0: *mut c_void,
    pub(crate) reserved1: *mut c_void,
}

/// `xmlSecKeyStoreKlass`.
#[repr(C)]
pub(crate) struct XmlSecKeyStoreKlass {
    pub(crate) klass_size: usize,
    pub(crate) obj_size: usize,
    pub(crate) name: *const u8,
    pub(crate) initialize: Option<unsafe extern "C" fn(*mut XmlSecKeyStore) -> c_int>,
    pub(crate) finalize: Option<unsafe extern "C" fn(*mut XmlSecKeyStore)>,
    pub(crate) find_key: Option<
        unsafe extern "C" fn(
            *mut XmlSecKeyStore,
            *const u8,
            *mut XmlSecKeyInfoCtx,
        ) -> *mut XmlSecKey,
    >,
    pub(crate) find_key_from_x509_data: Option<
        unsafe extern "C" fn(
            *mut XmlSecKeyStore,
            *mut c_void,
            *mut XmlSecKeyInfoCtx,
        ) -> *mut XmlSecKey,
    >,
    pub(crate) reserved0: *mut c_void,
}

// SAFETY: a klass is immutable static data: names with static storage and
// function pointers.
unsafe impl Sync for XmlSecKeyStoreKlass {}

/// libxmlsec1's `xmlSecKeyStoreIsValid`: a store of a complete, named klass.
///
/// # Safety
/// `store` is null or a store whose `id` is null or a klass.
unsafe fn store_valid<'a>(store: *mut XmlSecKeyStore) -> Option<&'a XmlSecKeyStoreKlass> {
    // SAFETY: by the caller's contract.
    unsafe {
        let klass = store.as_ref()?.id.as_ref()?;
        (klass.klass_size >= size_of::<XmlSecKeyStoreKlass>()
            && klass.obj_size >= size_of::<XmlSecKeyStore>()
            && !klass.name.is_null())
        .then_some(klass)
    }
}

/// The name of a store's klass for a report object.
fn store_name(klass: &XmlSecKeyStoreKlass) -> *const c_char {
    klass.name.cast()
}

// ----------------------------------------------------------------------------
// Keys manager

/// `xmlSecKeysMngrCreate`: an empty keys manager, released with
/// [`xmlSecKeysMngrDestroy`].
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeysMngrCreate() -> *mut XmlSecKeysMngr {
    contain(std::ptr::null_mut(), || {
        let here = here!("xmlSecKeysMngrCreate");
        let mngr = malloc(size_of::<XmlSecKeysMngr>()).cast::<XmlSecKeysMngr>();
        if mngr.is_null() {
            errors::malloc_failed(here, std::ptr::null(), size_of::<XmlSecKeysMngr>());
            return mngr;
        }
        // SAFETY: a fresh allocation of the manager's size; libxmlsec1 leaks
        // it when the list fails, it is freed instead.
        unsafe {
            mngr.write(XmlSecKeysMngr {
                keys_store: std::ptr::null_mut(),
                stores_list: zero_list(),
                get_key: None,
            });
            if xmlSecPtrListInitialize(
                &raw mut (*mngr).stores_list,
                xmlSecKeyDataStorePtrListGetKlass(),
            ) < 0
            {
                errors::internal(
                    here,
                    std::ptr::null(),
                    c"xmlSecPtrListInitialize(xmlSecKeyDataStorePtrListId)",
                );
                free(mngr.cast());
                return std::ptr::null_mut();
            }
        }
        mngr
    })
}

/// `xmlSecKeysMngrDestroy`: releases the manager, its key store and data
/// stores.
///
/// # Safety
/// `mngr` is null or a created manager.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeysMngrDestroy(mngr: *mut XmlSecKeysMngr) {
    contain((), || {
        check!(!mngr.is_null(), "xmlSecKeysMngrDestroy", c"mngr != NULL");
        // SAFETY: a created manager owning its stores.
        unsafe {
            if !(*mngr).keys_store.is_null() {
                xmlSecKeyStoreDestroy((*mngr).keys_store);
            }
            xmlSecPtrListFinalize(&raw mut (*mngr).stores_list);
            mngr.cast::<u8>()
                .write_bytes(0, size_of::<XmlSecKeysMngr>());
            free(mngr.cast());
        }
    });
}

/// `xmlSecKeysMngrFindKey`: a copy of the key store's key named `name` that
/// meets the context's requirements, or null; null without a key store.
///
/// # Safety
/// `mngr` is null or a manager; `name` null or NUL-terminated; `ctx` null
/// or a context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeysMngrFindKey(
    mngr: *mut XmlSecKeysMngr,
    name: *const u8,
    ctx: *mut XmlSecKeyInfoCtx,
) -> *mut XmlSecKey {
    contain(std::ptr::null_mut(), || {
        check!(
            !mngr.is_null(),
            "xmlSecKeysMngrFindKey",
            c"mngr != NULL",
            std::ptr::null_mut()
        );
        check!(
            !ctx.is_null(),
            "xmlSecKeysMngrFindKey",
            c"keyInfoCtx != NULL",
            std::ptr::null_mut()
        );
        // SAFETY: a manager and a context.
        unsafe {
            let store = (*mngr).keys_store;
            if store.is_null() {
                return std::ptr::null_mut();
            }
            xmlSecKeyStoreFindKey(store, name, ctx)
        }
    })
}

/// `xmlSecKeysMngrFindKeyFromX509Data`: the key store's key matching the
/// X.509 data value, or null; null without a key store.
///
/// # Safety
/// `mngr` is null or a manager; `x509_data` null or an X.509 data value;
/// `ctx` null or a context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeysMngrFindKeyFromX509Data(
    mngr: *mut XmlSecKeysMngr,
    x509_data: *mut c_void,
    ctx: *mut XmlSecKeyInfoCtx,
) -> *mut XmlSecKey {
    contain(std::ptr::null_mut(), || {
        check!(
            !mngr.is_null(),
            "xmlSecKeysMngrFindKeyFromX509Data",
            c"mngr != NULL",
            std::ptr::null_mut()
        );
        check!(
            !x509_data.is_null(),
            "xmlSecKeysMngrFindKeyFromX509Data",
            c"x509Data != NULL",
            std::ptr::null_mut()
        );
        check!(
            !ctx.is_null(),
            "xmlSecKeysMngrFindKeyFromX509Data",
            c"keyInfoCtx != NULL",
            std::ptr::null_mut()
        );
        // SAFETY: a manager, a value and a context.
        unsafe {
            let store = (*mngr).keys_store;
            if store.is_null() {
                return std::ptr::null_mut();
            }
            xmlSecKeyStoreFindKeyFromX509Data(store, x509_data, ctx)
        }
    })
}

/// `xmlSecKeysMngrAdoptKeysStore`: makes `store` the manager's key store,
/// releasing the previous one; the manager owns `store`.
///
/// # Safety
/// `mngr` is null or a manager; `store` null or a store it may own.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeysMngrAdoptKeysStore(
    mngr: *mut XmlSecKeysMngr,
    store: *mut XmlSecKeyStore,
) -> c_int {
    contain(-1, || {
        check!(
            !mngr.is_null(),
            "xmlSecKeysMngrAdoptKeysStore",
            c"mngr != NULL",
            -1
        );
        // SAFETY: null or a store.
        let valid = unsafe { store_valid(store) }.is_some();
        check!(
            valid,
            "xmlSecKeysMngrAdoptKeysStore",
            c"xmlSecKeyStoreIsValid(store)",
            -1
        );
        // SAFETY: a manager owning its store. The store it already owns is
        // kept, as libxmlsec1 1.3.13 does: releasing it would leave the
        // manager a freed store.
        unsafe {
            if std::ptr::eq((*mngr).keys_store, store) {
                return 0;
            }
            if !(*mngr).keys_store.is_null() {
                xmlSecKeyStoreDestroy((*mngr).keys_store);
            }
            (*mngr).keys_store = store;
        }
        0
    })
}

/// `xmlSecKeysMngrGetKeysStore`: the manager's key store.
///
/// # Safety
/// `mngr` is null or a manager.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeysMngrGetKeysStore(
    mngr: *mut XmlSecKeysMngr,
) -> *mut XmlSecKeyStore {
    contain(std::ptr::null_mut(), || {
        check!(
            !mngr.is_null(),
            "xmlSecKeysMngrGetKeysStore",
            c"mngr != NULL",
            std::ptr::null_mut()
        );
        // SAFETY: a manager.
        unsafe { (*mngr).keys_store }
    })
}

/// The position of the data store of klass `id` in the manager's list.
///
/// # Safety
/// `mngr` is a manager.
unsafe fn data_store_position(mngr: *mut XmlSecKeysMngr, id: *const c_void) -> Option<usize> {
    // SAFETY: by the caller's contract; the list holds data stores.
    unsafe {
        let list = &raw mut (*mngr).stores_list;
        (0..xmlSecPtrListGetSize(list)).find(|&pos| {
            xmlSecPtrListGetItem(list, pos)
                .cast::<XmlSecKeyDataStore>()
                .as_ref()
                .is_some_and(|store| std::ptr::eq(store.id.cast(), id))
        })
    }
}

/// `xmlSecKeysMngrAdoptDataStore`: puts `store` in the manager's data
/// stores in place of the store of its klass; the manager owns `store`.
///
/// # Safety
/// `mngr` is null or a manager; `store` null or a data store it may own.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeysMngrAdoptDataStore(
    mngr: *mut XmlSecKeysMngr,
    store: *mut XmlSecKeyDataStore,
) -> c_int {
    contain(-1, || {
        check!(
            !mngr.is_null(),
            "xmlSecKeysMngrAdoptDataStore",
            c"mngr != NULL",
            -1
        );
        // SAFETY: null or a data store.
        let valid = unsafe { super::keysdata::store_valid(store) };
        check!(
            valid,
            "xmlSecKeysMngrAdoptDataStore",
            c"xmlSecKeyDataStoreIsValid(store)",
            -1
        );
        // SAFETY: a manager and a valid data store. The store already held
        // is kept; another of its klass replaces it.
        unsafe {
            let list = &raw mut (*mngr).stores_list;
            match data_store_position(mngr, (*store).id.cast()) {
                Some(pos) if std::ptr::eq(xmlSecPtrListGetItem(list, pos), store.cast()) => 0,
                Some(pos) => xmlSecPtrListSet(list, store.cast(), pos),
                None => xmlSecPtrListAdd(list, store.cast()),
            }
        }
    })
}

/// `xmlSecKeysMngrGetDataStore`: the manager's data store of klass `id`, or
/// null.
///
/// # Safety
/// `mngr` is null or a manager; `id` null or a data store klass.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeysMngrGetDataStore(
    mngr: *mut XmlSecKeysMngr,
    id: *const c_void,
) -> *mut XmlSecKeyDataStore {
    contain(std::ptr::null_mut(), || {
        check!(
            !mngr.is_null(),
            "xmlSecKeysMngrGetDataStore",
            c"mngr != NULL",
            std::ptr::null_mut()
        );
        check!(
            !id.is_null(),
            "xmlSecKeysMngrGetDataStore",
            c"id != xmlSecKeyDataStoreIdUnknown",
            std::ptr::null_mut()
        );
        // SAFETY: a manager.
        unsafe {
            data_store_position(mngr, id).map_or(std::ptr::null_mut(), |pos| {
                xmlSecPtrListGetItem(&raw mut (*mngr).stores_list, pos).cast()
            })
        }
    })
}

/// `xmlSecKeysMngrGetKey`: the key read from `key_info_node` when it meets
/// the context's requirements, otherwise with
/// `XMLSEC_KEYINFO_FLAGS_LAX_KEY_SEARCH` any key of the context's keys
/// manager that does; null with libxmlsec1's report when there is none.
///
/// # Safety
/// `key_info_node` is null or a live node; `ctx` null or a context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeysMngrGetKey(
    key_info_node: *mut XmlNode,
    ctx: *mut XmlSecKeyInfoCtx,
) -> *mut XmlSecKey {
    contain(std::ptr::null_mut(), || {
        check!(
            !ctx.is_null(),
            "xmlSecKeysMngrGetKey",
            c"keyInfoCtx != NULL",
            std::ptr::null_mut()
        );
        let here = here!("xmlSecKeysMngrGetKey");
        // SAFETY: a context; a key not returned is released.
        unsafe {
            let key = xmlSecKeyCreate();
            if key.is_null() {
                errors::internal(here, std::ptr::null(), c"xmlSecKeyCreate");
                return key;
            }
            if !key_info_node.is_null() {
                if xmlSecKeyInfoNodeRead(key_info_node, key, ctx) < 0 {
                    let name = nodes::name(key_info_node).unwrap_or_else(|| "NULL".to_owned());
                    errors::internal_with(
                        here,
                        std::ptr::null(),
                        c"xmlSecKeyInfoNodeRead",
                        &format!("node={name}"),
                    );
                    xmlSecKeyDestroy(key);
                    return std::ptr::null_mut();
                }
                if !(*key).value.is_null()
                    && xmlSecKeyMatch(key, std::ptr::null(), &raw mut (*ctx).key_req) != 0
                {
                    return key;
                }
            }
            xmlSecKeyDestroy(key);
            lax_search(ctx)
        }
    })
}

/// The lax search of [`xmlSecKeysMngrGetKey`] after the node gave no key.
///
/// # Safety
/// `ctx` is a context.
unsafe fn lax_search(ctx: *mut XmlSecKeyInfoCtx) -> *mut XmlSecKey {
    let here = here!("xmlSecKeysMngrGetKey");
    // SAFETY: by the caller's contract.
    unsafe {
        if (*ctx).flags & FLAGS_LAX_KEY_SEARCH != 0 && !(*ctx).keys_mngr.is_null() {
            let key = xmlSecKeysMngrFindKey((*ctx).keys_mngr, std::ptr::null(), ctx);
            if key.is_null() {
                errors::internal(here, std::ptr::null(), c"xmlSecKeysMngrFindKey");
                return key;
            }
            if !(*key).value.is_null() {
                return key;
            }
            xmlSecKeyDestroy(key);
        }
    }
    errors::other(here, errors::R_KEY_NOT_FOUND, std::ptr::null(), None);
    std::ptr::null_mut()
}

// ----------------------------------------------------------------------------
// Key stores

/// `xmlSecKeyStoreCreate`: a new store of klass `id`, zeroed and
/// initialized by its klass, released with [`xmlSecKeyStoreDestroy`].
///
/// # Safety
/// `id` is null or a store klass that outlives the store.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyStoreCreate(
    id: *const XmlSecKeyStoreKlass,
) -> *mut XmlSecKeyStore {
    contain(std::ptr::null_mut(), || {
        check!(
            !id.is_null(),
            "xmlSecKeyStoreCreate",
            c"id != NULL",
            std::ptr::null_mut()
        );
        // SAFETY: a klass.
        let klass = unsafe { &*id };
        // The klass meets the contract a valid store needs before anything
        // is allocated: libxmlsec1 checks only a nonzero object size, which
        // lets a short object take the `id` write past its end and leaves a
        // store its destroy refuses, and leaks, when initialization fails.
        check!(
            klass.klass_size >= size_of::<XmlSecKeyStoreKlass>()
                && klass.obj_size >= size_of::<XmlSecKeyStore>()
                && !klass.name.is_null(),
            "xmlSecKeyStoreCreate",
            c"id->objSize > 0",
            std::ptr::null_mut()
        );
        let here = here!("xmlSecKeyStoreCreate");
        let store = malloc(klass.obj_size).cast::<XmlSecKeyStore>();
        if store.is_null() {
            errors::malloc_failed(here, store_name(klass), klass.obj_size);
            return store;
        }
        // SAFETY: a fresh allocation of the klass's object size.
        unsafe {
            store.cast::<u8>().write_bytes(0, klass.obj_size);
            (*store).id = id;
            if let Some(initialize) = klass.initialize
                && initialize(store) < 0
            {
                errors::internal(here, store_name(klass), c"id->initialize");
                xmlSecKeyStoreDestroy(store);
                return std::ptr::null_mut();
            }
        }
        store
    })
}

/// `xmlSecKeyStoreDestroy`: finalizes and releases a store.
///
/// # Safety
/// `store` is null or a created store.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyStoreDestroy(store: *mut XmlSecKeyStore) {
    contain((), || {
        // SAFETY: null or a store.
        let klass = unsafe { store_valid(store) };
        check!(
            klass.is_some(),
            "xmlSecKeyStoreDestroy",
            c"xmlSecKeyStoreIsValid(store)"
        );
        let Some(klass) = klass else { return };
        check!(
            klass.obj_size > 0,
            "xmlSecKeyStoreDestroy",
            c"store->id->objSize > 0"
        );
        // SAFETY: a store of its klass's object size.
        unsafe {
            if let Some(finalize) = klass.finalize {
                finalize(store);
            }
            store.cast::<u8>().write_bytes(0, klass.obj_size);
            free(store.cast());
        }
    });
}

/// `xmlSecKeyStoreFindKey`: the store klass's key for `name` and the
/// context's requirements, or null when the klass cannot find keys.
///
/// # Safety
/// `store` is null or a store; `name` null or NUL-terminated; `ctx` null or
/// a context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyStoreFindKey(
    store: *mut XmlSecKeyStore,
    name: *const u8,
    ctx: *mut XmlSecKeyInfoCtx,
) -> *mut XmlSecKey {
    contain(std::ptr::null_mut(), || {
        // SAFETY: null or a store.
        let klass = unsafe { store_valid(store) };
        check!(
            klass.is_some(),
            "xmlSecKeyStoreFindKey",
            c"xmlSecKeyStoreIsValid(store)",
            std::ptr::null_mut()
        );
        check!(
            !ctx.is_null(),
            "xmlSecKeyStoreFindKey",
            c"keyInfoCtx != NULL",
            std::ptr::null_mut()
        );
        // SAFETY: a valid store's method.
        klass
            .and_then(|klass| klass.find_key)
            .map_or(std::ptr::null_mut(), |find| unsafe {
                find(store, name, ctx)
            })
    })
}

/// `xmlSecKeyStoreFindKeyFromX509Data`: the store klass's key for the X.509
/// data value, or null when the klass cannot find keys that way.
///
/// # Safety
/// `store` is null or a store; `x509_data` null or an X.509 data value;
/// `ctx` null or a context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyStoreFindKeyFromX509Data(
    store: *mut XmlSecKeyStore,
    x509_data: *mut c_void,
    ctx: *mut XmlSecKeyInfoCtx,
) -> *mut XmlSecKey {
    contain(std::ptr::null_mut(), || {
        // SAFETY: null or a store.
        let klass = unsafe { store_valid(store) };
        check!(
            klass.is_some(),
            "xmlSecKeyStoreFindKeyFromX509Data",
            c"xmlSecKeyStoreIsValid(store)",
            std::ptr::null_mut()
        );
        check!(
            !x509_data.is_null(),
            "xmlSecKeyStoreFindKeyFromX509Data",
            c"x509Data != NULL",
            std::ptr::null_mut()
        );
        check!(
            !ctx.is_null(),
            "xmlSecKeyStoreFindKeyFromX509Data",
            c"keyInfoCtx != NULL",
            std::ptr::null_mut()
        );
        // SAFETY: a valid store's method.
        klass
            .and_then(|klass| klass.find_key_from_x509_data)
            .map_or(std::ptr::null_mut(), |find| unsafe {
                find(store, x509_data, ctx)
            })
    })
}

// ----------------------------------------------------------------------------
// The simple keys store

/// A simple keys store: the store followed by its list of keys.
#[repr(C)]
struct SimpleKeysStore {
    store: XmlSecKeyStore,
    keys: XmlSecPtrList,
}

static SIMPLE_KEYS_STORE: XmlSecKeyStoreKlass = XmlSecKeyStoreKlass {
    klass_size: size_of::<XmlSecKeyStoreKlass>(),
    obj_size: size_of::<SimpleKeysStore>(),
    name: c"simple-keys-store".as_ptr().cast(),
    initialize: Some(simple_initialize),
    finalize: Some(simple_finalize),
    find_key: Some(simple_find_key),
    find_key_from_x509_data: None,
    reserved0: std::ptr::null_mut(),
};

/// The keys of a simple store after libxmlsec1's id check `func` reports
/// against, or `None`.
///
/// # Safety
/// `store` is null or a store.
unsafe fn simple_keys(
    store: *mut XmlSecKeyStore,
    here: errors::Here,
) -> Option<*mut XmlSecPtrList> {
    // SAFETY: by the caller's contract.
    let ok = unsafe { store_valid(store) }
        .is_some_and(|klass| std::ptr::eq(klass, &raw const SIMPLE_KEYS_STORE));
    if !ok {
        errors::assertion(
            here,
            c"xmlSecKeyStoreCheckId(store, xmlSecSimpleKeysStoreId)",
        );
        return None;
    }
    // SAFETY: a simple store holds its list after the store.
    Some(unsafe { &raw mut (*store.cast::<SimpleKeysStore>()).keys })
}

/// Whether `list` is a list of keys, which libxmlsec1 asserts at `here`.
///
/// # Safety
/// `list` is a list.
unsafe fn keys_list(list: *mut XmlSecPtrList, here: errors::Here) -> bool {
    // SAFETY: by the caller's contract.
    let ok = unsafe { std::ptr::eq((*list).id, xmlSecKeyPtrListGetKlass()) };
    if !ok {
        errors::assertion(here, c"xmlSecPtrListCheckId(list, xmlSecKeyPtrListId)");
    }
    ok
}

unsafe extern "C" fn simple_initialize(store: *mut XmlSecKeyStore) -> c_int {
    let here = here!("xmlSecSimpleKeysStoreInitialize");
    // SAFETY: the klass calls with its store.
    unsafe {
        let Some(list) = simple_keys(store, here) else {
            return -1;
        };
        if xmlSecPtrListInitialize(list, xmlSecKeyPtrListGetKlass()) < 0 {
            errors::internal(
                here,
                (*(*store).id).name.cast(),
                c"xmlSecPtrListInitialize(xmlSecKeyPtrListId)",
            );
            return -1;
        }
    }
    0
}

unsafe extern "C" fn simple_finalize(store: *mut XmlSecKeyStore) {
    // SAFETY: the klass calls with its store.
    unsafe {
        if let Some(list) = simple_keys(store, here!("xmlSecSimpleKeysStoreFinalize")) {
            xmlSecPtrListFinalize(list);
        }
    }
}

unsafe extern "C" fn simple_find_key(
    store: *mut XmlSecKeyStore,
    name: *const u8,
    ctx: *mut XmlSecKeyInfoCtx,
) -> *mut XmlSecKey {
    let here = here!("xmlSecSimpleKeysStoreFindKey");
    // SAFETY: the klass calls with its store; the list holds keys.
    unsafe {
        let Some(list) = simple_keys(store, here) else {
            return std::ptr::null_mut();
        };
        if ctx.is_null() {
            errors::assertion(here, c"keyInfoCtx != NULL");
            return std::ptr::null_mut();
        }
        if !keys_list(list, here) {
            return std::ptr::null_mut();
        }
        let Some(pinned) = read_policy(ctx, here) else {
            return std::ptr::null_mut();
        };
        let max = pinned.verification.resources.max_key_candidates;
        // Every entry inspected is a key candidate of the read, charged to
        // the allowance all its searches share, as the core charges a named
        // lookup; a search outside a read is an operation of its own.
        let shared = policy::key_candidates((*ctx).reserved0);
        let mut tally = shared.map_or_default(Cell::get);
        let mut found = std::ptr::null_mut();
        for pos in 0..xmlSecPtrListGetSize(list) {
            if !tally.charge(max, here, (*(*store).id).name.cast()) {
                break;
            }
            let key = xmlSecPtrListGetItem(list, pos).cast::<XmlSecKey>();
            if !key.is_null() && xmlSecKeyMatch(key, name, &raw mut (*ctx).key_req) == 1 {
                found = xmlSecKeyDuplicate(key);
                break;
            }
        }
        if let Some(shared) = shared {
            shared.set(tally);
        }
        found
    }
}

/// `xmlSecSimpleKeysStoreGetKlass`: the simple keys store klass.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn xmlSecSimpleKeysStoreGetKlass() -> *const XmlSecKeyStoreKlass {
    &raw const SIMPLE_KEYS_STORE
}

/// `xmlSecSimpleKeysStoreAdoptKey`: adds `key` to the store, which owns it
/// on success.
///
/// # Safety
/// `store` is null or a store; `key` null or a key the store may own.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecSimpleKeysStoreAdoptKey(
    store: *mut XmlSecKeyStore,
    key: *mut XmlSecKey,
) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecSimpleKeysStoreAdoptKey");
        // SAFETY: null or a store.
        let Some(list) = (unsafe { simple_keys(store, here) }) else {
            return -1;
        };
        check!(
            !key.is_null(),
            "xmlSecSimpleKeysStoreAdoptKey",
            c"key != NULL",
            -1
        );
        // SAFETY: a simple store's list of keys.
        unsafe {
            if !keys_list(list, here) {
                return -1;
            }
            if xmlSecPtrListAdd(list, key.cast()) < 0 {
                errors::internal(here, (*(*store).id).name.cast(), c"xmlSecPtrListAdd");
                return -1;
            }
        }
        0
    })
}

/// `xmlSecSimpleKeysStoreGetKeys`: the store's list of keys.
///
/// # Safety
/// `store` is null or a store.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecSimpleKeysStoreGetKeys(
    store: *mut XmlSecKeyStore,
) -> *mut XmlSecPtrList {
    contain(std::ptr::null_mut(), || {
        let here = here!("xmlSecSimpleKeysStoreGetKeys");
        // SAFETY: null or a store.
        let Some(list) = (unsafe { simple_keys(store, here) }) else {
            return std::ptr::null_mut();
        };
        // SAFETY: a list.
        if unsafe { keys_list(list, here) } {
            list
        } else {
            std::ptr::null_mut()
        }
    })
}
