# Safety of the document-tree library

`src/ffi.rs` and its submodules are the crate's only code with `unsafe`. They
are the C boundary: they read the strings and buffers C code passes, write
the outputs it provides, call the callbacks it installs, and hand out heap
memory. The tree itself is never reached through a pointer: documents are
core `OwnedTree`s kept in the handle table (`src/handles.rs`, safe code), and
every tree pointer C code holds is a handle value, never an address. The
clean C API it reexports keeps its own contract
([`xml-sec-capi/SAFETY.md`](../xml-sec-capi/SAFETY.md)); this file records
what this library adds.

## What callers guarantee

1. Strings passed as `const xmlChar *` or `const char *` are null or
   NUL-terminated; buffers hold the length passed with them.
2. Output pointers are null or writable.
3. Memory passed to `xsFree` or `xsRealloc` is null or a live block one of the
   library's functions returned, released once, as with `free`.
4. Callbacks installed for I/O buffers or the generic error channel are
   callable with the context given with them until the buffer is closed or the
   handler replaced. A generic error handler is the installing thread's own,
   as libxml2's is.
5. While a call on a clean C API document handle runs, no other code changes
   its tree.

## What the library checks

- Every tree handle (`xmlDocPtr`, `xmlNodePtr`, `xmlNsPtr`, `xmlAttrPtr`,
  `xmlNodeSetPtr`, I/O buffer) is looked up in its table before use. A value
  that names nothing live (null, forged, a freed node or document, a removed
  attribute or declaration) is refused with null, 0 or -1; none is
  dereferenced, so a stale or forged handle cannot reach freed memory.
- Handle values and document numbers come from a counter that never repeats,
  so a stale handle never names a later object.
- Each document has its own lock, so work on one document does not wait for
  another. Locks are taken in one order, a document's and then the handle
  table's for a short step, never the other way, so they cannot deadlock. A
  change and the dropping of the handles it ended happen under one hold of
  the document's lock, so a removed attribute's handle never names a later
  attribute of the same name.
- Documents are parsed by the core under the library policy, with its limits
  enforced while parsing; no file, URL or external entity is read.

## What the library guarantees

- No C code writes into the tree's memory: every change is a core tree edit,
  validated like any other.
- Strings returned for the caller to own are copies on the C heap; strings
  libxmlsec1 returns as `const xmlChar *` into the tree are copies the
  document keeps until it is freed.
- No lock is held while a caller's callback runs, so a callback may call the
  library again.
- No unwinding crosses the boundary: every exported function runs under
  `catch_unwind`.
- The library links no C library besides the platform's C runtime and
  resolves no symbol at run time.
