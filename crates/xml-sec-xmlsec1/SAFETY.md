# Safety of the xmlsec1 compatibility library

`src/ffi.rs` and its submodules are the crate's only `unsafe` code. They export
libxmlsec1's functions under their own names, read and write the C structures
of `include/xmlsec/`, and allocate on the library heap of `xml-sec-libxml2`.
Document trees are never reached through a pointer: every node, node set and
I/O buffer is an opaque handle of `xml-sec-libxml2`, validated on each use
(its `SAFETY.md`).

## What callers guarantee

These are libxmlsec1's own preconditions, which its documentation states per
function:

1. A pointer argument is null or points to an object of the declared type that
   is live for the call: a buffer, list or klass the library created or the
   caller initialized with the matching `Initialize` function.
2. A pointer with a length is readable (or writable) for that many bytes and
   does not alias the object it is copied into, unless the function says so.
3. Objects the library returns are released with the matching `Destroy`
   function, strings and data with `xsFree`; objects the caller initialized
   are released with `Finalize`.
4. One object is used by one thread at a time, as in libxmlsec1. The process
   defaults (`xmlSec*SetDefaultAllocMode`) and the report callbacks may be set
   from any thread.
5. The process-global lists (the transform and key-data registries, the input
   callbacks, the loaded crypto libraries) change only during initialization
   and shutdown, while no operation reads them, as libxmlsec1 requires; the
   crypto table installed by `xmlSecCryptoDLSetFunctions` outlives its use.
   `xmlSecInit` and `xmlSecShutdown` serialize against each other, and a
   second `xmlSecInit` without a shutdown releases the lists it replaces.
6. Callbacks the caller registers (report, input, klass methods, crypto table
   methods) are functions of their declared signatures, callable while
   registered.

## What the library checks

- A null object where libxmlsec1 asserts a valid one returns libxmlsec1's
  failure value (`-1`, `NULL` or `0`) without reading through it.
- Sizes are computed with checked arithmetic: a request whose size would
  overflow fails instead of wrapping to a small allocation.
- Positions are checked against the item count before an item is read.

## What the library guarantees

- Memory handed to the caller, and the data inside structures the caller can
  reach, comes from the library heap (`xsMalloc`/`xsRealloc`) and is released
  only with `xsFree`. The library links no C library besides the platform's C
  runtime, compiles no C and resolves no symbol at run time.
- No function reads a file, a URL or an external entity itself; documents are
  parsed from bytes by the core under the library policy.
- The bytes of a buffer between its size and its allocation are zero, as
  libxmlsec1 keeps them.
- The Rust declarations of the C structures equal the layouts of the crate's
  headers (checked by the crate's tests, which compile and run
  `tests/layout.c`); the headers equal libxmlsec1's with the library's tree
  header in place of libxml2's and the functions it does not offer left out
  (checked by `xml-sec-tools xmlsec1-headers --check`).
- No unwinding crosses the boundary: every exported function runs its body
  under `catch_unwind`, reports a panic as an internal error and returns its
  failure value.
- A report callback is called during the call that fails, on the calling
  thread, and may call the library again.
