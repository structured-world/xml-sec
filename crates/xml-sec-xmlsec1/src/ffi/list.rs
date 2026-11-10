//! `xmlsec/list.h`: the pointer list whose klass owns its items.

use std::ffi::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

use super::errors::{self, check, here};
use super::{ALLOC_MODE_DOUBLE, contain, free, grown, malloc, realloc};

#[cfg(test)]
mod tests;

/// `xmlSecPtrDuplicateItemMethod`.
pub(crate) type DuplicateItem = Option<unsafe extern "C" fn(*mut c_void) -> *mut c_void>;
/// `xmlSecPtrDestroyItemMethod`.
pub(crate) type DestroyItem = Option<unsafe extern "C" fn(*mut c_void)>;
/// `xmlSecPtrDebugDumpItemMethod`; the stream is a C `FILE*`.
pub(crate) type DebugDumpItem = Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>;

/// `xmlSecPtrListKlass`.
#[repr(C)]
pub(crate) struct XmlSecPtrListKlass {
    pub(crate) name: *const u8,
    pub(crate) duplicate_item: DuplicateItem,
    pub(crate) destroy_item: DestroyItem,
    pub(crate) debug_dump_item: DebugDumpItem,
    pub(crate) debug_xml_dump_item: DebugDumpItem,
}

// SAFETY: a klass is immutable static data: a name with static storage and
// function pointers.
unsafe impl Sync for XmlSecPtrListKlass {}

/// `xmlSecPtrList`.
#[repr(C)]
pub(crate) struct XmlSecPtrList {
    pub(crate) id: *const XmlSecPtrListKlass,
    pub(crate) data: *mut *mut c_void,
    pub(crate) used: usize,
    pub(crate) max: usize,
    pub(crate) alloc_mode: c_int,
}

/// The allocation mode of lists initialized from now on.
static DEFAULT_ALLOC_MODE: AtomicI32 = AtomicI32::new(ALLOC_MODE_DOUBLE);
/// The smallest allocation of a list, in items.
static DEFAULT_INITIAL_SIZE: AtomicUsize = AtomicUsize::new(64);

/// `xmlSecPtrListIsValid`: non-null with a klass.
///
/// # Safety
/// `list` is null or points to a list.
unsafe fn valid<'a>(list: *mut XmlSecPtrList) -> Option<&'a mut XmlSecPtrList> {
    // SAFETY: the caller passes null or a list.
    unsafe { list.as_mut() }.filter(|list| !list.id.is_null())
}

/// The klass of a valid list.
///
/// # Safety
/// `list.id` points to a klass that outlives the list.
unsafe fn klass(list: &XmlSecPtrList) -> &XmlSecPtrListKlass {
    // SAFETY: by the caller's contract.
    unsafe { &*list.id }
}

/// The name of a klass for a report (`xmlSecPtrListKlassGetName`).
///
/// # Safety
/// `id` is null or a klass.
unsafe fn klass_name(id: *const XmlSecPtrListKlass) -> *const c_char {
    // SAFETY: by the caller's contract.
    unsafe { id.as_ref() }.map_or(std::ptr::null(), |klass| klass.name.cast())
}

/// Grows `list` to hold `size` items. Like libxmlsec1, it grows when `size`
/// reaches the allocation, not only when it exceeds it.
///
/// # Safety
/// `list` is a valid list.
unsafe fn ensure_size(list: &mut XmlSecPtrList, size: usize) -> c_int {
    if size < list.max {
        return 0;
    }
    // SAFETY: a valid list's klass outlives it.
    let name = unsafe { klass_name(list.id) };
    let initial = DEFAULT_INITIAL_SIZE.load(Ordering::Relaxed);
    // A size past the address space is an allocation libxmlsec1 could not
    // make either.
    let Some((new_size, bytes)) = grown(list.alloc_mode, size, initial)
        .and_then(|new_size| Some((new_size, new_size.checked_mul(size_of::<*mut c_void>())?)))
    else {
        errors::malloc_failed(here!("xmlSecPtrListEnsureSize"), name, usize::MAX);
        return -1;
    };
    let data = if list.data.is_null() {
        malloc(bytes)
    } else {
        // SAFETY: a non-null `data` is the list's libxml2 allocation.
        unsafe { realloc(list.data.cast::<c_void>(), bytes) }
    };
    if data.is_null() {
        errors::malloc_failed(here!("xmlSecPtrListEnsureSize"), name, bytes);
        return -1;
    }
    list.data = data.cast::<*mut c_void>();
    list.max = new_size;
    0
}

/// `xmlSecPtrListSetDefaultAllocMode`: the mode and smallest allocation of
/// lists initialized from now on. A zero size is refused.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecPtrListSetDefaultAllocMode(
    def_alloc_mode: c_int,
    def_initial_size: usize,
) {
    if def_initial_size == 0 {
        return;
    }
    DEFAULT_ALLOC_MODE.store(def_alloc_mode, Ordering::Relaxed);
    DEFAULT_INITIAL_SIZE.store(def_initial_size, Ordering::Relaxed);
}

/// `xmlSecPtrListInitialize`: makes `list` an empty list of klass `id`.
///
/// # Safety
/// `list` is null or points to writable memory of a list's size; `id` is
/// null or a klass that outlives the list.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecPtrListInitialize(
    list: *mut XmlSecPtrList,
    id: *const XmlSecPtrListKlass,
) -> c_int {
    contain(-1, || {
        check!(
            !id.is_null(),
            "xmlSecPtrListInitialize",
            c"id != xmlSecPtrListIdUnknown",
            -1
        );
        check!(
            !list.is_null(),
            "xmlSecPtrListInitialize",
            c"list != NULL",
            -1
        );
        // SAFETY: `list` is writable; the write does not read the old value.
        unsafe {
            list.write(XmlSecPtrList {
                id,
                data: std::ptr::null_mut(),
                used: 0,
                max: 0,
                alloc_mode: DEFAULT_ALLOC_MODE.load(Ordering::Relaxed),
            });
        }
        0
    })
}

/// `xmlSecPtrListFinalize`: destroys the items and releases the storage,
/// leaving the list zeroed (without a klass).
///
/// # Safety
/// `list` is null or a list.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecPtrListFinalize(list: *mut XmlSecPtrList) {
    contain((), || {
        check!(
            // SAFETY: the caller passes null or a list.
            unsafe { valid(list) }.is_some(),
            "xmlSecPtrListFinalize",
            c"xmlSecPtrListIsValid(list)",
        );
        // SAFETY: `list` is valid and writable.
        unsafe {
            xmlSecPtrListEmpty(list);
            list.write_bytes(0, 1);
        }
    });
}

/// `xmlSecPtrListCreate`: a new empty list of klass `id`, released with
/// [`xmlSecPtrListDestroy`]; null on failure.
///
/// # Safety
/// `id` is null or a klass that outlives the list.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecPtrListCreate(
    id: *const XmlSecPtrListKlass,
) -> *mut XmlSecPtrList {
    contain(std::ptr::null_mut(), || {
        check!(
            !id.is_null(),
            "xmlSecPtrListCreate",
            c"id != xmlSecPtrListIdUnknown",
            std::ptr::null_mut()
        );
        // SAFETY: `id` is a klass.
        let name = unsafe { klass_name(id) };
        let list = malloc(size_of::<XmlSecPtrList>()).cast::<XmlSecPtrList>();
        if list.is_null() {
            errors::malloc_failed(
                here!("xmlSecPtrListCreate"),
                name,
                size_of::<XmlSecPtrList>(),
            );
            return list;
        }
        // SAFETY: `list` is a fresh allocation of a list's size.
        if unsafe { xmlSecPtrListInitialize(list, id) } < 0 {
            errors::internal(
                here!("xmlSecPtrListCreate"),
                name,
                c"xmlSecPtrListInitialize",
            );
            // SAFETY: the allocation is ours and holds nothing.
            unsafe { free(list.cast::<c_void>()) };
            return std::ptr::null_mut();
        }
        list
    })
}

/// `xmlSecPtrListDestroy`: finalizes and frees a list from
/// [`xmlSecPtrListCreate`].
///
/// # Safety
/// `list` is null or came from [`xmlSecPtrListCreate`] and was not destroyed.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecPtrListDestroy(list: *mut XmlSecPtrList) {
    contain((), || {
        check!(
            // SAFETY: the caller passes null or a created list.
            unsafe { valid(list) }.is_some(),
            "xmlSecPtrListDestroy",
            c"xmlSecPtrListIsValid(list)",
        );
        // SAFETY: a valid created list is finalized, then its allocation freed.
        unsafe {
            xmlSecPtrListFinalize(list);
            free(list.cast::<c_void>());
        }
    });
}

/// `xmlSecPtrListEmpty`: destroys every item through the klass and
/// releases the storage.
///
/// # Safety
/// `list` is null or a list whose items its klass may destroy.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecPtrListEmpty(list: *mut XmlSecPtrList) {
    contain((), || {
        // SAFETY: the caller passes null or a list.
        let list = unsafe { valid(list) };
        check!(
            list.is_some(),
            "xmlSecPtrListEmpty",
            c"xmlSecPtrListIsValid(list)",
        );
        let Some(list) = list else { return };
        // SAFETY: the list's klass outlives it.
        if let Some(destroy) = unsafe { klass(list) }.destroy_item {
            for pos in 0..list.used {
                check!(
                    !list.data.is_null(),
                    "xmlSecPtrListEmpty",
                    c"list->data != NULL",
                );
                // SAFETY: `pos < used <= max` items are stored at `data`.
                let item = unsafe { list.data.add(pos).read() };
                if !item.is_null() {
                    // SAFETY: the klass owns its non-null items.
                    unsafe { destroy(item) };
                }
            }
        }
        if list.max > 0 {
            check!(
                !list.data.is_null(),
                "xmlSecPtrListEmpty",
                c"list->data != NULL",
            );
            // SAFETY: `data` holds `max >= used` items and is the list's
            // libxml2 allocation.
            unsafe {
                list.data.write_bytes(0, list.used);
                free(list.data.cast::<c_void>());
            }
        }
        list.max = 0;
        list.used = 0;
        list.data = std::ptr::null_mut();
    });
}

/// `xmlSecPtrListCopy`: appends `src`'s items to `dst`, duplicated through
/// the klass when it can, otherwise as the same pointers.
///
/// # Safety
/// Each pointer is null or a list.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecPtrListCopy(
    dst: *mut XmlSecPtrList,
    src: *mut XmlSecPtrList,
) -> c_int {
    contain(-1, || {
        // SAFETY: the caller passes null or lists.
        let (dst, src) = unsafe { (valid(dst), valid(src)) };
        check!(
            dst.is_some(),
            "xmlSecPtrListCopy",
            c"xmlSecPtrListIsValid(dst)",
            -1
        );
        check!(
            src.is_some(),
            "xmlSecPtrListCopy",
            c"xmlSecPtrListIsValid(src)",
            -1
        );
        let (Some(dst), Some(src)) = (dst, src) else {
            return -1;
        };
        check!(
            dst.id == src.id,
            "xmlSecPtrListCopy",
            c"dst->id == src->id",
            -1
        );
        // SAFETY: both lists share a klass that outlives them.
        let name = unsafe { klass_name(src.id) };
        // SAFETY: `dst` is valid.
        let grown = dst
            .used
            .checked_add(src.used)
            .filter(|total| unsafe { ensure_size(dst, *total) } >= 0);
        if grown.is_none() {
            errors::internal_with(
                here!("xmlSecPtrListCopy"),
                name,
                c"xmlSecPtrListEnsureSize",
                &format!("size={}", src.used),
            );
            return -1;
        }
        // SAFETY: both lists share a klass that outlives them.
        let duplicate = unsafe { klass(dst) }.duplicate_item;
        for index in 0..src.used {
            check!(
                !src.data.is_null(),
                "xmlSecPtrListCopy",
                c"src->data != NULL",
                -1
            );
            check!(
                !dst.data.is_null(),
                "xmlSecPtrListCopy",
                c"dst->data != NULL",
                -1
            );
            // SAFETY: `index < src.used` items are stored at `src.data`.
            let item = unsafe { src.data.add(index).read() };
            let copied = match duplicate {
                Some(duplicate) if !item.is_null() => {
                    // SAFETY: the klass duplicates its own items.
                    let copied = unsafe { duplicate(item) };
                    if copied.is_null() {
                        errors::internal(here!("xmlSecPtrListCopy"), name, c"duplicateItem");
                        return -1;
                    }
                    copied
                }
                _ => item,
            };
            // SAFETY: `dst.used < total <= max` after growing.
            unsafe { dst.data.add(dst.used).write(copied) };
            dst.used += 1;
        }
        0
    })
}

/// `xmlSecPtrListDuplicate`: a new list with copies of `list`'s items.
///
/// # Safety
/// `list` is null or a list.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecPtrListDuplicate(
    list: *mut XmlSecPtrList,
) -> *mut XmlSecPtrList {
    contain(std::ptr::null_mut(), || {
        // SAFETY: the caller passes null or a list.
        let source = unsafe { valid(list) };
        check!(
            source.is_some(),
            "xmlSecPtrListDuplicate",
            c"xmlSecPtrListIsValid(list)",
            std::ptr::null_mut()
        );
        let Some(source) = source else {
            return std::ptr::null_mut();
        };
        // SAFETY: the klass outlives the list.
        let name = unsafe { klass_name(source.id) };
        // SAFETY: the klass outlives both lists.
        let copy = unsafe { xmlSecPtrListCreate(source.id) };
        if copy.is_null() {
            errors::internal(
                here!("xmlSecPtrListDuplicate"),
                name,
                c"xmlSecPtrListCreate",
            );
            return copy;
        }
        // SAFETY: both are valid lists of one klass.
        if unsafe { xmlSecPtrListCopy(copy, list) } < 0 {
            errors::internal(here!("xmlSecPtrListDuplicate"), name, c"xmlSecPtrListCopy");
            // SAFETY: `copy` is our created list.
            unsafe { xmlSecPtrListDestroy(copy) };
            return std::ptr::null_mut();
        }
        copy
    })
}

/// `xmlSecPtrListGetSize`: the number of items, 0 for an invalid list.
///
/// # Safety
/// `list` is null or a list.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecPtrListGetSize(list: *mut XmlSecPtrList) -> usize {
    contain(0, || {
        // SAFETY: the caller passes null or a list.
        let list = unsafe { valid(list) };
        check!(
            list.is_some(),
            "xmlSecPtrListGetSize",
            c"xmlSecPtrListIsValid(list)",
            0
        );
        list.map_or(0, |list| list.used)
    })
}

/// The valid list `list` with an item at `pos`, after libxmlsec1's checks of
/// the entry point `$func`, or `$ret`.
macro_rules! item_list {
    ($list:expr, $pos:expr, $func:literal, $ret:expr) => {{
        // SAFETY: the caller passes null or a list.
        let list = unsafe { valid($list) };
        check!(list.is_some(), $func, c"xmlSecPtrListIsValid(list)", $ret);
        let Some(list) = list else { return $ret };
        check!(!list.data.is_null(), $func, c"list->data != NULL", $ret);
        check!($pos < list.used, $func, c"pos < list->use", $ret);
        list
    }};
}

/// `xmlSecPtrListGetItem`: the item at `pos`, null when out of range.
///
/// # Safety
/// `list` is null or a list.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecPtrListGetItem(
    list: *mut XmlSecPtrList,
    pos: usize,
) -> *mut c_void {
    contain(std::ptr::null_mut(), || {
        let list = item_list!(list, pos, "xmlSecPtrListGetItem", std::ptr::null_mut());
        // SAFETY: `pos < used` items are stored at `data`.
        unsafe { list.data.add(pos).read() }
    })
}

/// Grows `list` by one item; the new size, or `None` after reporting the
/// failure as the entry point at `here`.
///
/// # Safety
/// `list` is a valid list.
unsafe fn grow_by_one(list: &mut XmlSecPtrList, here: errors::Here) -> Option<usize> {
    let size = list
        .used
        .checked_add(1)
        // SAFETY: by the caller's contract.
        .filter(|size| unsafe { ensure_size(list, *size) } >= 0);
    if size.is_none() {
        errors::internal_with(
            here,
            // SAFETY: a valid list's klass outlives it.
            unsafe { klass_name(list.id) },
            c"xmlSecPtrListEnsureSize",
            &format!("size={}", list.used.wrapping_add(1)),
        );
    }
    size
}

/// `xmlSecPtrListAdd`: appends `item`, which the list now owns.
///
/// # Safety
/// `list` is null or a list.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecPtrListAdd(
    list: *mut XmlSecPtrList,
    item: *mut c_void,
) -> c_int {
    contain(-1, || {
        // SAFETY: the caller passes null or a list.
        let list = unsafe { valid(list) };
        check!(
            list.is_some(),
            "xmlSecPtrListAdd",
            c"xmlSecPtrListIsValid(list)",
            -1
        );
        let Some(list) = list else { return -1 };
        // SAFETY: `list` is valid; after growing `used < max`.
        unsafe {
            let Some(size) = grow_by_one(list, here!("xmlSecPtrListAdd")) else {
                return -1;
            };
            list.data.add(list.used).write(item);
            list.used = size;
        }
        0
    })
}

/// `xmlSecPtrListInsert`: inserts `item` at `pos`, or appends it when `pos`
/// is past the end.
///
/// # Safety
/// `list` is null or a list.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecPtrListInsert(
    list: *mut XmlSecPtrList,
    item: *mut c_void,
    pos: usize,
) -> c_int {
    contain(-1, || {
        // SAFETY: the caller passes null or a list.
        let list = unsafe { valid(list) };
        check!(
            list.is_some(),
            "xmlSecPtrListInsert",
            c"xmlSecPtrListIsValid(list)",
            -1
        );
        let Some(list) = list else { return -1 };
        // SAFETY: `list` is valid; after growing `used < max`, so the
        // shifted range `pos + 1..=used` fits.
        unsafe {
            let Some(size) = grow_by_one(list, here!("xmlSecPtrListInsert")) else {
                return -1;
            };
            let at = pos.min(list.used);
            list.data
                .add(at)
                .copy_to(list.data.add(at + 1), list.used - at);
            list.data.add(at).write(item);
            list.used = size;
        }
        0
    })
}

/// `xmlSecPtrListSet`: replaces the item at `pos`, destroying the old one.
///
/// # Safety
/// `list` is null or a list.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecPtrListSet(
    list: *mut XmlSecPtrList,
    item: *mut c_void,
    pos: usize,
) -> c_int {
    contain(-1, || {
        let list = item_list!(list, pos, "xmlSecPtrListSet", -1);
        // SAFETY: `pos < used`; the klass owns the replaced item.
        unsafe {
            let slot = list.data.add(pos);
            let old = slot.read();
            if let Some(destroy) = klass(list).destroy_item
                && !old.is_null()
            {
                destroy(old);
            }
            slot.write(item);
        }
        0
    })
}

/// Removes the item at `pos`, shifting the rest; returns it.
///
/// # Safety
/// `list` is a valid list with `pos < used` and non-null data.
unsafe fn take(list: &mut XmlSecPtrList, pos: usize) -> *mut c_void {
    // SAFETY: `pos < used` items are stored at `data`; the shift stays
    // inside them.
    unsafe {
        let item = list.data.add(pos).read();
        list.data
            .add(pos + 1)
            .copy_to(list.data.add(pos), list.used - pos - 1);
        list.used -= 1;
        list.data.add(list.used).write(std::ptr::null_mut());
        item
    }
}

/// `xmlSecPtrListRemove`: destroys the item at `pos` and shifts the rest.
///
/// # Safety
/// `list` is null or a list.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecPtrListRemove(list: *mut XmlSecPtrList, pos: usize) -> c_int {
    contain(-1, || {
        let list = item_list!(list, pos, "xmlSecPtrListRemove", -1);
        // SAFETY: `pos < used` and the klass owns the removed item.
        unsafe {
            let item = list.data.add(pos).read();
            if let Some(destroy) = klass(list).destroy_item
                && !item.is_null()
            {
                destroy(item);
            }
            take(list, pos);
        }
        0
    })
}

/// `xmlSecPtrListRemoveAndReturn`: removes the item at `pos` without
/// destroying it and returns it to the caller.
///
/// # Safety
/// `list` is null or a list.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecPtrListRemoveAndReturn(
    list: *mut XmlSecPtrList,
    pos: usize,
) -> *mut c_void {
    contain(std::ptr::null_mut(), || {
        let list = item_list!(
            list,
            pos,
            "xmlSecPtrListRemoveAndReturn",
            std::ptr::null_mut()
        );
        // SAFETY: `pos < used` with non-null data.
        unsafe { take(list, pos) }
    })
}

/// `xmlSecPtrListPopLast`: removes and returns the last item, null when the
/// list is empty.
///
/// # Safety
/// `list` is null or a list.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecPtrListPopLast(list: *mut XmlSecPtrList) -> *mut c_void {
    contain(std::ptr::null_mut(), || {
        // SAFETY: the caller passes null or a list.
        let checked = unsafe { valid(list) };
        check!(
            checked.is_some(),
            "xmlSecPtrListPopLast",
            c"xmlSecPtrListIsValid(list)",
            std::ptr::null_mut()
        );
        let Some(tail) = checked.and_then(|checked| checked.used.checked_sub(1)) else {
            return std::ptr::null_mut();
        };
        // SAFETY: `list` is a valid list.
        unsafe { xmlSecPtrListRemoveAndReturn(list, tail) }
    })
}

/// Writes `header`, each non-null item through `dump`, then `footer`, after
/// libxmlsec1's checks of the entry point `func`.
///
/// # Safety
/// `list` is null or a list; `output` is null or a C stream.
unsafe fn dump_items(
    list: *mut XmlSecPtrList,
    output: *mut c_void,
    here: errors::Here,
    text: impl Fn(usize) -> (String, &'static str),
    dump: impl Fn(&XmlSecPtrListKlass) -> DebugDumpItem,
) {
    // SAFETY: by the caller's contract; the items precede `used`.
    unsafe {
        let Some(checked) = valid(list) else {
            errors::assertion(here, c"xmlSecPtrListIsValid(list)");
            return;
        };
        if output.is_null() {
            errors::assertion(here, c"output != NULL");
            return;
        }
        let (header, footer) = text(checked.used);
        super::write_stream(output, &header);
        if let Some(item_dump) = checked.id.as_ref().and_then(dump) {
            for pos in 0..checked.used {
                if checked.data.is_null() {
                    errors::assertion(here, c"list->data != NULL");
                    return;
                }
                let item = checked.data.add(pos).read();
                if !item.is_null() {
                    item_dump(item, output);
                }
            }
        }
        super::write_stream(output, footer);
    }
}

/// `xmlSecPtrListDebugDump`: the size, then each item by its klass.
///
/// # Safety
/// `list` is null or a list; `output` is null or a C stream.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecPtrListDebugDump(
    list: *mut XmlSecPtrList,
    output: *mut c_void,
) {
    contain((), || {
        // SAFETY: by the caller's contract.
        unsafe {
            dump_items(
                list,
                output,
                here!("xmlSecPtrListDebugDump"),
                |used| (format!("=== list size: {used}\n"), ""),
                |klass| klass.debug_dump_item,
            );
        }
    });
}

/// `xmlSecPtrListDebugXmlDump`: the size, then each item by its klass, in
/// XML.
///
/// # Safety
/// `list` is null or a list; `output` is null or a C stream.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecPtrListDebugXmlDump(
    list: *mut XmlSecPtrList,
    output: *mut c_void,
) {
    contain((), || {
        // SAFETY: by the caller's contract.
        unsafe {
            dump_items(
                list,
                output,
                here!("xmlSecPtrListDebugXmlDump"),
                |used| (format!("<List size=\"{used}\">\n"), "</List>\n"),
                |klass| klass.debug_xml_dump_item,
            );
        }
    });
}

/// Duplicates a string item with libxml2's allocator.
unsafe extern "C" fn string_duplicate(item: *mut c_void) -> *mut c_void {
    if item.is_null() {
        errors::assertion(here!("xmlSecStringListDuplicateItem"), c"ptr != NULL");
        return item;
    }
    // SAFETY: a strings-list item is a NUL-terminated string.
    let text = unsafe { std::ffi::CStr::from_ptr(item.cast::<c_char>()) }.to_bytes_with_nul();
    let copy = malloc(text.len());
    if !copy.is_null() {
        // SAFETY: `copy` holds `text.len()` bytes.
        unsafe { text.as_ptr().copy_to(copy.cast::<u8>(), text.len()) };
    }
    copy
}

/// Frees a string item.
unsafe extern "C" fn string_destroy(item: *mut c_void) {
    if item.is_null() {
        errors::assertion(here!("xmlSecStringListDestroyItem"), c"ptr != NULL");
        return;
    }
    // SAFETY: a strings-list item is a libxml2 allocation the list owns.
    unsafe { free(item) };
}

/// The strings list klass: items are libxml2-allocated strings.
static STRING_LIST_KLASS: XmlSecPtrListKlass = XmlSecPtrListKlass {
    name: c"strings-list".as_ptr().cast::<u8>(),
    duplicate_item: Some(string_duplicate),
    destroy_item: Some(string_destroy),
    debug_dump_item: None,
    debug_xml_dump_item: None,
};

/// `xmlSecStringListGetKlass`: the klass of lists of strings.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecStringListGetKlass() -> *const XmlSecPtrListKlass {
    &raw const STRING_LIST_KLASS
}
