//! The caller's libxml2, found in the running process.
//!
//! The libxmlsec1 surface is built on libxml2's types, so a program using it
//! has libxml2 loaded already; this crate does not link its own. The functions
//! the bridge and the libxmlsec1-compatible library call are resolved once by
//! name in the process, together with libxml2's allocator, and only when the
//! loaded release is one whose leading structure members match the
//! declarations of [`super`]. Each wrapper below keeps the libxml2 function's
//! C signature under a snake-case name.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::sync::OnceLock;

use super::{XmlAttr, XmlDoc, XmlNode, XmlNodeSet, XmlNs};

/// The oldest libxml2 release, as `LIBXML_VERSION`, whose leading structure
/// members match the declarations.
const OLDEST: u32 = 20900;
/// The first release the declarations are not known to match: libxml2 3.
const NEXT_MAJOR: u32 = 30000;

/// The libxml2 output callback type `xmlOutputWriteCallback`.
pub type WriteCallback = unsafe extern "C" fn(*mut c_void, *const c_char, c_int) -> c_int;
/// The libxml2 input callback type `xmlInputReadCallback`.
pub type ReadCallback = unsafe extern "C" fn(*mut c_void, *mut c_char, c_int) -> c_int;
/// The libxml2 close callback type shared by input and output buffers.
pub type CloseCallback = unsafe extern "C" fn(*mut c_void) -> c_int;

type FreeFn = unsafe extern "C" fn(*mut c_void);
type MallocFn = unsafe extern "C" fn(usize) -> *mut c_void;
type ReallocFn = unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void;
type VersionFn = unsafe extern "C" fn() -> *const *const c_char;
type InputFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;
type OptionsFn = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;

/// The address of the NUL-terminated `name` in the process, or null.
fn symbol(name: &str) -> *mut c_void {
    debug_assert!(name.ends_with('\0'));
    #[cfg(unix)]
    {
        // SAFETY: `RTLD_DEFAULT` searches the global scope of the process;
        // the name is NUL-terminated and only read.
        unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr().cast()) }
    }
    #[cfg(not(unix))]
    {
        // Resolution over Windows modules is not implemented: no libxml2.
        let _ = name;
        std::ptr::null_mut()
    }
}

/// The release the loaded libxml2 reports in `xmlParserVersion`, as
/// `LIBXML_VERSION`.
fn loaded_version() -> Option<u32> {
    // Threaded releases before 2.12 reach the variable through a function.
    let accessor = symbol("__xmlParserVersion\0");
    let variable = if accessor.is_null() {
        symbol("xmlParserVersion\0")
            .cast::<*const c_char>()
            .cast_const()
    } else {
        // SAFETY: libxml2's accessor of this name takes no argument and
        // returns the address of `xmlParserVersion`.
        unsafe { std::mem::transmute::<*mut c_void, VersionFn>(accessor)() }
    };
    if variable.is_null() {
        return None;
    }
    // SAFETY: `xmlParserVersion` is a static pointer to a NUL-terminated
    // string of digits, such as "21309".
    let text = unsafe {
        let text = variable.read();
        if text.is_null() {
            return None;
        }
        CStr::from_ptr(text)
    };
    let digits = text.to_bytes();
    let end = digits
        .iter()
        .position(|byte| !byte.is_ascii_digit())
        .unwrap_or(digits.len());
    std::str::from_utf8(&digits[..end]).ok()?.parse().ok()
}

macro_rules! functions {
    ($( $(#[$doc:meta])* $wrapper:ident = $name:literal fn($($arg:ident: $ty:ty),* $(,)?) $(-> $ret:ty)?; )*) => {
        /// The required functions, resolved together.
        struct Functions {
            $( $wrapper: unsafe extern "C" fn($($ty),*) $(-> $ret)?, )*
        }

        impl Functions {
            fn resolve() -> Option<Self> {
                Some(Self {
                    $( $wrapper: {
                        let address = symbol(concat!($name, "\0"));
                        if address.is_null() {
                            return None;
                        }
                        // SAFETY: the address is libxml2's function of this
                        // name, whose C signature the declaration repeats.
                        unsafe {
                            std::mem::transmute::<*mut c_void, unsafe extern "C" fn($($ty),*) $(-> $ret)?>(address)
                        }
                    }, )*
                })
            }
        }

        $(
            $(#[$doc])*
            #[doc = concat!("The caller's `", $name, "`.")]
            ///
            /// # Safety
            /// The arguments meet libxml2's contract for the function, and the
            /// calling entry point found [`available`] true.
            pub unsafe fn $wrapper($($arg: $ty),*) $(-> $ret)? {
                // SAFETY: by the caller's contract.
                unsafe { (loaded().functions.$wrapper)($($arg),*) }
            }
        )*
    };
}

functions! {
    xml_new_doc_node = "xmlNewDocNode" fn(doc: *mut XmlDoc, ns: *mut XmlNs, name: *const u8, content: *const u8) -> *mut XmlNode;
    xml_new_ns = "xmlNewNs" fn(node: *mut XmlNode, href: *const u8, prefix: *const u8) -> *mut XmlNs;
    xml_new_ns_prop = "xmlNewNsProp" fn(node: *mut XmlNode, ns: *mut XmlNs, name: *const u8, value: *const u8) -> *mut XmlAttr;
    xml_new_doc_text = "xmlNewDocText" fn(doc: *const XmlDoc, content: *const u8) -> *mut XmlNode;
    xml_new_doc_comment = "xmlNewDocComment" fn(doc: *mut XmlDoc, content: *const u8) -> *mut XmlNode;
    xml_new_doc_pi = "xmlNewDocPI" fn(doc: *mut XmlDoc, name: *const u8, content: *const u8) -> *mut XmlNode;
    xml_search_ns = "xmlSearchNs" fn(doc: *mut XmlDoc, node: *mut XmlNode, prefix: *const u8) -> *mut XmlNs;
    xml_unlink_node = "xmlUnlinkNode" fn(node: *mut XmlNode);
    xml_free_node = "xmlFreeNode" fn(node: *mut XmlNode);
    xml_free_doc = "xmlFreeDoc" fn(doc: *mut XmlDoc);
    xml_is_id = "xmlIsID" fn(doc: *mut XmlDoc, element: *mut XmlNode, attribute: *mut XmlAttr) -> c_int;
    xml_add_id = "xmlAddID" fn(context: *mut c_void, doc: *mut XmlDoc, value: *const u8, attribute: *mut XmlAttr) -> *mut c_void;
    xml_get_id = "xmlGetID" fn(doc: *mut XmlDoc, id: *const u8) -> *mut XmlAttr;
    xml_get_prop = "xmlGetProp" fn(node: *mut XmlNode, name: *const u8) -> *mut u8;
    xml_node_get_content = "xmlNodeGetContent" fn(node: *mut XmlNode) -> *mut u8;
    xml_node_add_content = "xmlNodeAddContent" fn(node: *mut XmlNode, content: *const u8);
    xml_str_equal = "xmlStrEqual" fn(left: *const u8, right: *const u8) -> c_int;
    xml_xpath_node_set_create = "xmlXPathNodeSetCreate" fn(node: *mut XmlNode) -> *mut XmlNodeSet;
    xml_xpath_node_set_add = "xmlXPathNodeSetAdd" fn(set: *mut XmlNodeSet, node: *mut XmlNode) -> c_int;
    xml_xpath_node_set_add_ns = "xmlXPathNodeSetAddNs" fn(set: *mut XmlNodeSet, node: *mut XmlNode, ns: *mut XmlNs) -> c_int;
    xml_xpath_node_set_contains = "xmlXPathNodeSetContains" fn(set: *mut XmlNodeSet, node: *mut XmlNode) -> c_int;
    xml_xpath_free_node_set = "xmlXPathFreeNodeSet" fn(set: *mut XmlNodeSet);
    /// 1 when `first` precedes `second` in document order, -1 when it
    /// follows, 0 for the same node, -2 when they cannot be ordered.
    xml_xpath_cmp_nodes = "xmlXPathCmpNodes" fn(first: *mut XmlNode, second: *mut XmlNode) -> c_int;
    xml_init_parser = "xmlInitParser" fn();
    xml_new_parser_ctxt = "xmlNewParserCtxt" fn() -> *mut c_void;
    xml_free_parser_ctxt = "xmlFreeParserCtxt" fn(ctxt: *mut c_void);
    xml_ctxt_use_options = "xmlCtxtUseOptions" fn(ctxt: *mut c_void, options: c_int) -> c_int;
    xml_create_file_parser_ctxt = "xmlCreateFileParserCtxt" fn(filename: *const c_char) -> *mut c_void;
    xml_create_memory_parser_ctxt = "xmlCreateMemoryParserCtxt" fn(buffer: *const c_char, size: c_int) -> *mut c_void;
    xml_create_push_parser_ctxt = "xmlCreatePushParserCtxt" fn(sax: *mut c_void, user: *mut c_void, chunk: *const c_char, size: c_int, filename: *const c_char) -> *mut c_void;
    xml_parse_chunk = "xmlParseChunk" fn(ctxt: *mut c_void, chunk: *const c_char, size: c_int, terminate: c_int) -> c_int;
    xml_parse_document = "xmlParseDocument" fn(ctxt: *mut c_void) -> c_int;
    xml_new_io_input_stream = "xmlNewIOInputStream" fn(ctxt: *mut c_void, input: *mut c_void, encoding: c_int) -> *mut c_void;
    xml_free_input_stream = "xmlFreeInputStream" fn(input: *mut c_void);
    xml_parser_input_buffer_create_io = "xmlParserInputBufferCreateIO" fn(read: Option<ReadCallback>, close: Option<CloseCallback>, context: *mut c_void, encoding: c_int) -> *mut c_void;
    xml_free_parser_input_buffer = "xmlFreeParserInputBuffer" fn(input: *mut c_void);
    xml_output_buffer_create_io = "xmlOutputBufferCreateIO" fn(write: Option<WriteCallback>, close: Option<CloseCallback>, context: *mut c_void, encoder: *mut c_void) -> *mut c_void;
    xml_output_buffer_write = "xmlOutputBufferWrite" fn(out: *mut c_void, len: c_int, data: *const c_char) -> c_int;
    xml_output_buffer_write_string = "xmlOutputBufferWriteString" fn(out: *mut c_void, text: *const c_char) -> c_int;
    xml_output_buffer_close = "xmlOutputBufferClose" fn(out: *mut c_void) -> c_int;
}

/// Where libxml2 keeps one of its global variables, read on every use as the
/// names of libxml2's headers read it, so a value the caller sets later (an
/// allocator, an error handler) is the one used. `xmlMemGet` is not used for
/// the allocator: some vendor builds (macOS) return failure from it.
enum Global<T> {
    /// The global itself.
    Address(*const T),
    /// The accessor of threaded releases before 2.12, whose headers define
    /// the name as a call to it; it returns the calling thread's slot.
    Accessor(unsafe extern "C" fn() -> *const T),
}

// SAFETY: the pointers are libxml2's process-wide globals and accessor,
// valid for the life of the process and read as libxml2's callers read them.
unsafe impl<T> Send for Global<T> {}
// SAFETY: as above.
unsafe impl<T> Sync for Global<T> {}

impl<T: Copy> Global<T> {
    /// libxml2's global `name`, reached through `accessor` where the release
    /// has one; `None` when neither exists.
    ///
    /// # Safety
    /// `T` is the type of the global.
    unsafe fn resolve(name: &str, accessor: &str) -> Option<Self> {
        let through = symbol(accessor);
        if through.is_null() {
            let global = symbol(name).cast::<T>().cast_const();
            return (!global.is_null()).then_some(Self::Address(global));
        }
        // SAFETY: the accessor takes no argument and returns the global's
        // address.
        Some(Self::Accessor(unsafe {
            std::mem::transmute::<*mut c_void, unsafe extern "C" fn() -> *const T>(through)
        }))
    }

    /// The value the global holds now; `None` when an accessor returns no
    /// slot.
    ///
    /// # Safety
    /// `T` is the type of the global.
    unsafe fn get(&self) -> Option<T> {
        let global = match self {
            Self::Address(global) => *global,
            // SAFETY: libxml2's accessor, callable on any thread.
            Self::Accessor(accessor) => unsafe { accessor() },
        };
        // SAFETY: the global holds a value of type `T`.
        unsafe { global.as_ref() }.copied()
    }
}

/// libxml2's allocator global `name`, which must hold a function.
///
/// # Safety
/// `F` is the function pointer type of the global.
unsafe fn allocator<F: Copy>(name: &str, accessor: &str) -> Option<Global<Option<F>>> {
    // SAFETY: by the caller's contract.
    unsafe {
        let global = Global::<Option<F>>::resolve(name, accessor)?;
        global.get().flatten().map(|_| global)
    }
}

/// libxml2's `xmlGenericErrorFunc`.
type GenericErrorFn = unsafe extern "C" fn(*mut c_void, *const c_char, ...);

/// The resolved libxml2.
struct Loaded {
    version: u32,
    functions: Functions,
    free: Global<Option<FreeFn>>,
    malloc: Global<Option<MallocFn>>,
    realloc: Global<Option<ReallocFn>>,
    /// `xmlGenericError` and `xmlGenericErrorContext`.
    generic_error: Option<(Global<Option<GenericErrorFn>>, Global<*mut c_void>)>,
    /// `xmlCtxtSetOptions`, from libxml2 2.13 on.
    set_options: Option<OptionsFn>,
    /// `xmlCtxtPushInput` (2.14 on) or, before it, `inputPush`.
    push_input: Option<InputFn>,
}

impl Loaded {
    fn resolve() -> Option<Self> {
        let version = loaded_version()?;
        if !(OLDEST..NEXT_MAJOR).contains(&version) {
            return None;
        }
        let functions = Functions::resolve()?;
        // SAFETY: each name is libxml2's allocator global of that type, or
        // the accessor threaded releases before 2.12 reach it through.
        let (free, malloc, realloc) = unsafe {
            (
                allocator::<FreeFn>("xmlFree\0", "__xmlFree\0")?,
                allocator::<MallocFn>("xmlMalloc\0", "__xmlMalloc\0")?,
                allocator::<ReallocFn>("xmlRealloc\0", "__xmlRealloc\0")?,
            )
        };
        // SAFETY: libxml2's generic error handler and its context, or the
        // accessors threaded releases before 2.12 reach them through.
        let generic_error = unsafe {
            Global::resolve("xmlGenericError\0", "__xmlGenericError\0").zip(Global::resolve(
                "xmlGenericErrorContext\0",
                "__xmlGenericErrorContext\0",
            ))
        };
        let optional = |name: &str| {
            let address = symbol(name);
            (!address.is_null()).then_some(address)
        };
        Some(Self {
            version,
            functions,
            free,
            malloc,
            realloc,
            generic_error,
            // SAFETY: `xmlCtxtSetOptions(xmlParserCtxtPtr, int) -> int`.
            set_options: optional("xmlCtxtSetOptions\0")
                .map(|address| unsafe { std::mem::transmute::<*mut c_void, OptionsFn>(address) }),
            // SAFETY: both take a parser context and an input stream and
            // return an int.
            push_input: optional("xmlCtxtPushInput\0")
                .or_else(|| optional("inputPush\0"))
                .map(|address| unsafe { std::mem::transmute::<*mut c_void, InputFn>(address) }),
        })
    }
}

/// The resolved libxml2, resolving it on first use; a failed resolution is
/// retried, since libxml2 may be loaded later than this library.
fn load() -> Option<&'static Loaded> {
    static LOADED: OnceLock<Loaded> = OnceLock::new();
    if let Some(loaded) = LOADED.get() {
        return Some(loaded);
    }
    // A test process plays the C caller, which has libxml2 loaded.
    #[cfg(any(test, feature = "test-support"))]
    super::testing::load_system_libxml2();
    let loaded = Loaded::resolve()?;
    Some(LOADED.get_or_init(|| loaded))
}

// A plain `expect` for a programmer invariant: `clippy::expect_used` is not
// enabled here, so a `#[expect]` for it would itself fail the build.
fn loaded() -> &'static Loaded {
    load().expect("the calling entry point checked that libxml2 is available")
}

/// Whether a libxml2 release this crate supports is loaded in the process,
/// with every function the crate calls. Entry points refuse to touch a tree
/// otherwise.
#[must_use]
pub fn available() -> bool {
    load().is_some()
}

/// The loaded libxml2 release as `LIBXML_VERSION` (for example 21309), when
/// [`available`].
#[must_use]
pub fn version() -> Option<u32> {
    load().map(|loaded| loaded.version)
}

/// Allocates with the caller's libxml2 allocator (`xmlMalloc`).
///
/// # Safety
/// [`available`] is true.
#[must_use]
pub unsafe fn xml_malloc(size: usize) -> *mut c_void {
    // SAFETY: libxml2's allocator accepts any size and reports failure as
    // null; a cleared global is a failed allocation.
    unsafe {
        loaded()
            .malloc
            .get()
            .flatten()
            .map_or(std::ptr::null_mut(), |malloc| malloc(size))
    }
}

/// Resizes with the caller's libxml2 allocator (`xmlRealloc`).
///
/// # Safety
/// [`available`] is true; `mem` is null or came from [`xml_malloc`] or this
/// function and was not freed.
pub unsafe fn xml_realloc(mem: *mut c_void, size: usize) -> *mut c_void {
    // SAFETY: by the caller's contract; a cleared global is a failed
    // resize, which leaves `mem` as it was.
    unsafe {
        loaded()
            .realloc
            .get()
            .flatten()
            .map_or(std::ptr::null_mut(), |realloc| realloc(mem, size))
    }
}

/// Frees with the caller's libxml2 allocator (`xmlFree`).
///
/// # Safety
/// [`available`] is true; `mem` is null or a live allocation of libxml2's
/// allocator.
pub unsafe fn xml_free(mem: *mut c_void) {
    // SAFETY: by the caller's contract. libxml2 never clears the global; were
    // it cleared, no function could free `mem`, which then stays allocated.
    if let Some(free) = unsafe { loaded().free.get() }.flatten() {
        // SAFETY: as above.
        unsafe { free(mem) }
    }
}

/// Writes `message` through libxml2's current generic error handler
/// (`xmlGenericError(xmlGenericErrorContext, "%s", message)`), as libxml2's
/// callers report errors; nothing when the release has no handler.
///
/// # Safety
/// [`available`] is true.
pub unsafe fn xml_generic_error(message: &CStr) {
    let Some((handler, context)) = &loaded().generic_error else {
        return;
    };
    // SAFETY: the globals hold libxml2's handler and its context; the handler
    // takes a printf format, and "%s" consumes exactly the one string passed.
    unsafe {
        if let Some(Some(handler)) = handler.get() {
            let context = context.get().unwrap_or(std::ptr::null_mut());
            handler(context, c"%s".as_ptr(), message.as_ptr());
        }
    }
}

/// `xmlCtxtSetOptions`, or `None` on a release before 2.13, which lacks it.
///
/// # Safety
/// [`available`] is true; `ctxt` is a live parser context.
pub unsafe fn xml_ctxt_set_options(ctxt: *mut c_void, options: c_int) -> Option<c_int> {
    // SAFETY: by the caller's contract.
    loaded()
        .set_options
        .map(|set| unsafe { set(ctxt, options) })
}

/// Pushes `input` on the parser context: `xmlCtxtPushInput`, or `inputPush`
/// on a release without it; -1 when the release has neither.
///
/// # Safety
/// [`available`] is true; `ctxt` is a live parser context and `input` a live
/// input stream it adopts on success.
pub unsafe fn xml_ctxt_push_input(ctxt: *mut c_void, input: *mut c_void) -> c_int {
    // SAFETY: by the caller's contract.
    loaded()
        .push_input
        .map_or(-1, |push| unsafe { push(ctxt, input) })
}
