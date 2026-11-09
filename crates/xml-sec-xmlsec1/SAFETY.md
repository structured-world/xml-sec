# Safety of the xmlsec1 compatibility library

`src/ffi.rs` and its submodules are the crate's only `unsafe` code. They export
libxmlsec1's functions under their own names, read and write the C structures
of `include/xmlsec/`, and allocate with libxml2's allocator.

## What callers guarantee

These are libxmlsec1's own preconditions, which its documentation states per
function:

1. A pointer argument is null or points to an object of the declared type that
   is live for the call: a buffer, list or klass the library created or the
   caller initialized with the matching `Initialize` function.
2. A pointer with a length is readable (or writable) for that many bytes and
   does not alias the object it is copied into, unless the function says so.
3. Objects the library returns are released with the matching `Destroy`
   function, strings and data with `xmlFree`; objects the caller initialized
   are released with `Finalize`.
4. One object is used by one thread at a time, as in libxmlsec1. The process
   defaults (`xmlSec*SetDefaultAllocMode`) may be set from any thread.

## What the library checks

- A null object where libxmlsec1 asserts a valid one returns libxmlsec1's
  failure value (`-1`, `NULL` or `0`) without reading through it.
- Sizes are computed with checked arithmetic: a request whose size would
  overflow fails instead of wrapping to a small allocation.
- Positions are checked against the item count before an item is read.

## What the library guarantees

- Memory handed to the caller, and the data inside structures the caller can
  reach, comes from libxml2's `xmlMalloc`/`xmlRealloc` and is released only
  with `xmlFree`, through `src/shim.c`, so a caller-installed libxml2 allocator
  owns it.
- The bytes of a buffer between its size and its allocation are zero, as
  libxmlsec1 keeps them.
- The Rust declarations of the C structures equal the layouts of the crate's
  headers (checked by the crate's tests against `src/layout.c`); the headers
  equal libxmlsec1's (checked by `xml-sec-tools xmlsec1-headers --check`).
- No unwinding crosses the boundary: every exported function runs its body
  under `catch_unwind` and returns its failure value on a panic.
